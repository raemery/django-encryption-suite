"""What a data key rotation's fence does to everything around it.

Reads and writes while it stands, the deletion path meeting a rotation in
flight, the rewrap pass reaching both keysets, and the identity a rotation
records.
"""

from __future__ import annotations

from io import StringIO

import pytest
from django.core.files.base import ContentFile
from django.core.management import call_command
from django.db import transaction
from django.test import RequestFactory

from encryption_suite import deletion, lifecycle, rotation
from encryption_suite.adapters.silos.context import override_current_silo
from encryption_suite.engine import EncryptionEngine
from encryption_suite.exceptions import DekReencryptionInProgressError
from encryption_suite.fields import is_undecryptable, strict_mode
from encryption_suite.models import DataEncryptionKey, DekRotation, DekRotationWorkItem, KeyLifecycleEvent
from encryption_suite.registry import get_engine
from encryption_suite.silo_ref import SiloRef
from tests.rotation_helpers import (
    dek,
    make_document,
    make_note,
    make_team,
    open_rotation,
    read_document,
    read_note,
    run,
    run_fenced,
    tamper_author,
    uid,
)
from tests.testapp.models import Document, Note

pytestmark = pytest.mark.django_db


@pytest.fixture(autouse=True)
def _no_wait(monkeypatch):
    monkeypatch.setattr(rotation, "_sleep", lambda seconds: None)
    EncryptionEngine.invalidate_cache()
    yield
    EncryptionEngine.invalidate_cache()


def _fenced_with_outstanding_row(team):
    """A rotation left open by a row that will not convert, and that row."""
    make_note(team, title="good")
    bad = make_note(team, title="bad")
    tamper_author(bad)
    run_fenced("--silo-uid", uid(team), "--purpose", "field")
    return bad


# ---------------------------------------------------------------------------
# Reads and writes while the fence stands
# ---------------------------------------------------------------------------


def test_a_fenced_field_read_yields_the_fallback_with_the_typed_error():
    team = make_team()
    note = make_note(team)
    open_rotation(team)

    EncryptionEngine.invalidate_cache()
    with override_current_silo(team):
        loaded = Note.objects.get(pk=note.pk)
        assert is_undecryptable(loaded.title)
        assert isinstance(loaded.encryption_suite_errors["title"], DekReencryptionInProgressError)


def test_a_fenced_field_read_raises_under_strict():
    team = make_team()
    note = make_note(team)
    open_rotation(team)

    EncryptionEngine.invalidate_cache()
    with override_current_silo(team), strict_mode(), pytest.raises(DekReencryptionInProgressError):
        Note.objects.get(pk=note.pk).title  # noqa: B018


def test_a_fenced_write_raises_and_a_new_row_cannot_land_encrypted_data():
    team = make_team()
    make_note(team)
    open_rotation(team)

    EncryptionEngine.invalidate_cache()
    with override_current_silo(team), pytest.raises(DekReencryptionInProgressError), transaction.atomic():
        Note.objects.create(team=team, title="written during the sweep")
    assert Note.objects.count() == 1


def test_the_fence_is_not_negative_cached():
    """It lifts at the swap, so remembering it past then would keep reads dark."""
    from encryption_suite.dek_cache import dek_cache

    team = make_team()
    make_note(team)
    open_rotation(team)
    EncryptionEngine.invalidate_cache()
    with override_current_silo(team):
        Note.objects.get().title  # noqa: B018
    assert not dek_cache("default")._failures


def test_a_fenced_file_probe_returns_false():
    team = make_team()
    document = make_document(team)
    open_rotation(team, "file")

    EncryptionEngine.invalidate_cache()
    with override_current_silo(team):
        assert Document.objects.get(pk=document.pk).upload.probe() is False


def test_the_handled_file_view_answers_retry_shaped_while_fenced():
    from encryption_suite.file_download_view_helper import serve_encrypted_file_handled

    team = make_team()
    document = make_document(team)
    open_rotation(team, "file")

    EncryptionEngine.invalidate_cache()
    with override_current_silo(team):
        response = serve_encrypted_file_handled(
            RequestFactory().get("/"), Document.objects.get(pk=document.pk), "upload", mode="inline"
        )
    assert response.status_code == 503
    assert b"Unable to decrypt" not in response.content


def test_the_drf_handler_does_not_invite_a_retry_of_the_fence():
    """A sweep runs on human time: it can stall, fail, or need a manual rollback.

    So the fence is a conflict, not a wait. A client renders the message and
    stops; that a rotation is the reason is carried by the slug, which is an
    operator's question rather than something a client can act on.
    """
    from encryption_suite.contrib.drf import api_exception_handler
    from encryption_suite.exceptions import GENERIC_ENCRYPT_DECRYPT_UNAVAILABLE_MESSAGE

    response = api_exception_handler(DekReencryptionInProgressError(GENERIC_ENCRYPT_DECRYPT_UNAVAILABLE_MESSAGE), {})

    assert response.status_code == 409
    assert response.data["code"] == "dek_reencryption_in_progress"


def test_a_field_rotation_leaves_file_content_readable():
    """Filenames are field data and go dark; the blobs themselves do not."""
    team = make_team()
    make_note(team)
    document = make_document(team, b"still here")
    open_rotation(team, "field")

    EncryptionEngine.invalidate_cache()
    with override_current_silo(team):
        loaded = Document.objects.get(pk=document.pk)
        assert is_undecryptable(loaded.upload_name)
        with loaded.upload.open("rb") as handle:
            assert handle.read() == b"still here"


# ---------------------------------------------------------------------------
# Deletion meets a rotation in flight
# ---------------------------------------------------------------------------


def test_scheduling_mid_rotation_keeps_the_rotation_and_a_restore_returns_to_it():
    team = make_team()
    bad = _fenced_with_outstanding_row(team)
    row = dek(team)
    items = DekRotationWorkItem.objects.count()

    deletion.schedule_dek_deletion(row, trigger=lifecycle.TRIGGER_DIRECT, os_login_user="op")
    row.refresh_from_db()
    assert row.status == lifecycle.STATUS_DELETION_SCHEDULED
    assert DekRotation.objects.filter(dek=row).exists()
    assert DekRotationWorkItem.objects.count() == items
    # Scheduling is intent: no rotation verb is recorded for it.
    assert not KeyLifecycleEvent.objects.filter(dek=row, event=lifecycle.EVENT_ROTATION_ABANDONED).exists()

    deletion.restore_dek(row, trigger=lifecycle.TRIGGER_DIRECT, os_login_user="op")
    row.refresh_from_db()
    assert row.status == lifecycle.STATUS_REENCRYPTING

    tamper_author(bad, "ann")
    output = run("--silo-uid", uid(team), "--purpose", "field")
    assert "Rotated:" in output
    assert read_note(bad.pk, team) == ("bad", "body")


def test_deleting_the_silo_mid_rotation_schedules_the_rotating_key(configured_owner_prefix):
    team = make_team()
    _fenced_with_outstanding_row(team)
    # Silo-exclusive from here on, so the key encryption key is scheduled too.
    configured_owner_prefix("kms_")

    scheduled = deletion.schedule_deletion(SiloRef("default", uid(team)))

    row = dek(team)
    assert row in scheduled
    assert row.status == lifecycle.STATUS_DELETION_SCHEDULED
    assert row.kek in scheduled


def test_the_purge_abandons_an_open_rotation_before_it_shreds(settings):
    settings.ENCRYPTION = {
        **settings.ENCRYPTION,
        "KEY_DELETION_WINDOW_DAYS": 0,
        "KEY_DELETION_CAN_RENDER_DATA_INACCESSIBLE": True,
    }
    team = make_team()
    _fenced_with_outstanding_row(team)
    row = dek(team)
    deletion.schedule_dek_deletion(row, trigger=lifecycle.TRIGGER_DIRECT, os_login_user="op")

    deletion.purge_expired_deks(trigger=lifecycle.TRIGGER_DIRECT, os_login_user="op")

    row.refresh_from_db()
    assert row.status == lifecycle.STATUS_DELETED
    assert not DekRotation.objects.exists()
    assert not DekRotationWorkItem.objects.exists()
    verbs = list(
        KeyLifecycleEvent.objects.filter(dek=row).order_by("created_at", "id").values_list("event", "reason", "trigger")
    )
    abandoned = verbs.index(
        (lifecycle.EVENT_ROTATION_ABANDONED, lifecycle.REASON_DEK_DELETED, lifecycle.TRIGGER_DIRECT)
    )
    assert verbs[abandoned + 1][0] == lifecycle.EVENT_DELETED
    # Exactly one open and one close for the rotation.
    assert [v for v, _r, _t in verbs].count(lifecycle.EVENT_ROTATION_STARTED) == 1
    assert [v for v, _r, _t in verbs].count(lifecycle.EVENT_ROTATION_ABANDONED) == 1


def test_a_key_whose_last_dependent_is_a_rotation_row_is_still_in_use():
    from django.utils import timezone

    from encryption_suite.admin_lifecycle import KeyEncryptionKeyAdmin

    team = make_team()
    make_note(team)
    _row, rotation_row = open_rotation(team)
    kek = rotation_row.kek
    # Only the rotation row holds material under this key now.
    DataEncryptionKey.objects.filter(kek=kek).update(encrypted_keyset=b"")

    assert deletion._kek_still_in_use(kek, timezone.now())
    assert KeyEncryptionKeyAdmin._live_keyset_count(kek) == 1


# ---------------------------------------------------------------------------
# The rewrap pass reaches both keysets
# ---------------------------------------------------------------------------


def _reencrypt_keys():
    out, err = StringIO(), StringIO()
    call_command("reencrypt_keys", stdout=out, stderr=err)
    return out.getvalue() + err.getvalue()


def test_reencrypt_keys_mid_rotation_moves_both_keysets():
    team = make_team()
    bad = _fenced_with_outstanding_row(team)
    row, pending = dek(team), DekRotation.objects.get()
    old_row_keyset, old_incoming = bytes(row.encrypted_keyset), bytes(pending.encrypted_keyset)

    _reencrypt_keys()

    row.refresh_from_db()
    pending.refresh_from_db()
    assert bytes(row.encrypted_keyset) != old_row_keyset
    assert bytes(pending.encrypted_keyset) != old_incoming

    tamper_author(bad, "ann")
    run("--silo-uid", uid(team), "--purpose", "field")
    row.refresh_from_db()
    assert row.kek_id == pending.kek_id
    assert read_note(bad.pk, team) == ("bad", "body")


def test_a_swap_landing_between_a_rewraps_unwrap_and_its_lock_makes_the_rewrap_skip(monkeypatch):
    """The case a correctly held lock does not cover: the count is what catches it."""
    team = make_team()
    note = make_note(team)
    original_swap = rotation.Rotator._swap

    class Interrupted(Exception):
        pass

    monkeypatch.setattr(rotation.Rotator, "_swap", lambda self, row, converted: (_ for _ in ()).throw(Interrupted()))
    with pytest.raises(Interrupted):
        run("--silo-uid", uid(team), "--purpose", "field")
    monkeypatch.setattr(rotation.Rotator, "_swap", original_swap)
    incoming = bytes(DekRotation.objects.get().encrypted_keyset)

    adapter_class = type(get_engine().silo_kms_adapter)
    original_encrypt = adapter_class.encrypt_key
    swapped = []

    def encrypt_then_swap(self, plaintext, silo_uid):
        result = original_encrypt(self, plaintext, silo_uid)
        if not swapped:
            swapped.append(True)
            run("--silo-uid", uid(team), "--purpose", "field")
        return result

    monkeypatch.setattr(adapter_class, "encrypt_key", encrypt_then_swap)
    output = _reencrypt_keys()

    assert "concurrently re-encrypted" in output
    row = dek(team)
    assert bytes(row.encrypted_keyset) == incoming
    assert read_note(note.pk, team) == ("title", "body")


# ---------------------------------------------------------------------------
# Identity
# ---------------------------------------------------------------------------


def test_a_rotation_records_the_operator_who_opened_it():
    team = make_team()
    _fenced_with_outstanding_row(team)

    pending = DekRotation.objects.get()
    assert str(pending.os_user)
    assert pending.user_id is None


def test_an_empty_list_lands_empty_identity_columns(settings):
    settings.ENCRYPTION = {**settings.ENCRYPTION, "USER_IDENTITY": {"KEY_LIFECYCLE_EVENTS": []}}
    team = make_team()
    _fenced_with_outstanding_row(team)

    assert DekRotation.objects.get().os_user_id is None
    started = KeyLifecycleEvent.objects.get(event=lifecycle.EVENT_ROTATION_STARTED)
    assert started.os_user_id is None and started.user_id is None


def test_a_rotation_shares_the_ledger_rows_os_user(settings):
    """One value, one row: the rotation and its ledger event point at the same one."""
    team = make_team()
    _fenced_with_outstanding_row(team)

    started = KeyLifecycleEvent.objects.get(event=lifecycle.EVENT_ROTATION_STARTED)
    assert DekRotation.objects.get().os_user_id == started.os_user_id


def test_every_rotation_log_line_pairs_open_with_close(caplog):
    team = make_team()
    make_note(team)

    with caplog.at_level("INFO", logger="encryption_suite"):
        run("--silo-uid", uid(team), "--purpose", "field")

    opened = [r for r in caplog.records if "event=rotation_started" in r.getMessage()]
    closed = [r for r in caplog.records if "event=rotated" in r.getMessage()]
    assert len(opened) == len(closed) == 1
    for record in opened + closed:
        message = record.getMessage()
        assert f'silo="default:{uid(team)}" purpose=field' in message
        assert "os_user=" in message
        assert record.levelname == "WARNING"


# ---------------------------------------------------------------------------
# Data key version counting
# ---------------------------------------------------------------------------


def test_reviving_a_tombstone_counts_the_version_on():
    team = make_team()
    make_note(team)
    DataEncryptionKey.objects.filter(pk=dek(team).pk).update(
        encrypted_keyset=b"", status=lifecycle.STATUS_DELETED, dek_key_version=3
    )

    get_engine().generate_and_store_keyset(team)

    assert dek(team).dek_key_version == 4


def test_a_document_uploaded_after_the_swap_uses_the_new_key():
    team = make_team()
    make_document(team)
    run("--silo-uid", uid(team), "--purpose", "file")

    EncryptionEngine.invalidate_cache()
    with override_current_silo(team):
        later = Document(team=team, upload=ContentFile(b"after", name="after.txt"))
        later.save()

    assert read_document(later.pk, team) == b"after"
