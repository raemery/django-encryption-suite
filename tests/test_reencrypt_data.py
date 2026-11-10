"""reencrypt_data: a data key rotation from opening to swap, and every way it can end.

Each test drives the command against real tables (``tests.testapp``) and then
reads the data back the way the application would. The wait before conversion
is real code measured from the rotation row, and is skipped here by replacing
the sleep it calls.
"""

from __future__ import annotations

import pytest
from django.core.management.base import CommandError

from encryption_suite import lifecycle, rotation, rotation_items
from encryption_suite.adapters.silos.context import override_current_silo
from encryption_suite.engine import EncryptionEngine
from encryption_suite.fields import is_undecryptable
from encryption_suite.models import DataEncryptionKey, DekRotation, DekRotationWorkItem, KeyLifecycleEvent
from tests.rotation_helpers import (
    dek,
    make_document,
    make_note,
    make_team,
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
def waits(monkeypatch):
    slept = []
    monkeypatch.setattr(rotation, "_sleep", slept.append)
    EncryptionEngine.invalidate_cache()
    yield slept
    EncryptionEngine.invalidate_cache()


def _events(row, verb):
    return list(KeyLifecycleEvent.objects.filter(dek=row, event=verb).order_by("created_at", "id"))


def test_a_field_rotation_moves_every_row_and_swaps_the_key(waits):
    team = make_team()
    notes = [make_note(team, title=f"t{i}", body=f"b{i}") for i in range(3)]
    before = dek(team)
    old_keyset = bytes(before.encrypted_keyset)

    output = run("--silo-uid", uid(team), "--purpose", "field")

    assert f"Rotated: default:{uid(team)} [field] — 6 item(s) converted" in output
    after = dek(team)
    assert after.status == lifecycle.STATUS_ACTIVE
    assert bytes(after.encrypted_keyset) != old_keyset
    assert after.dek_key_version == before.dek_key_version + 1
    assert after.reencryption_count == before.reencryption_count + 1
    assert after.key_material_last_generated_at > before.key_material_last_generated_at
    assert not DekRotation.objects.exists()
    assert not DekRotationWorkItem.objects.exists()
    for i, note in enumerate(notes):
        assert read_note(note.pk, team) == (f"t{i}", f"b{i}")
    # The wait was served, measured from the rotation row.
    assert len(waits) == 1 and 0 < waits[0] <= rotation.wait_seconds()


def test_the_ledger_opens_and_closes_the_rotation_once_each():
    team = make_team()
    make_note(team)

    run("--silo-uid", uid(team), "--purpose", "field")

    row = dek(team)
    started, rotated = _events(row, lifecycle.EVENT_ROTATION_STARTED), _events(row, lifecycle.EVENT_ROTATED)
    assert len(started) == 1 and len(rotated) == 1
    for event in started + rotated:
        assert event.trigger == lifecycle.TRIGGER_AUTOMATED
        assert event.reason == ""
        assert event.os_user_id is not None


def test_a_file_rotation_rewrites_each_blob_and_deletes_the_old_one():
    team = make_team()
    document = make_document(team, b"quarterly numbers")
    old_name = document.upload.name
    storage = Document._meta.get_field("upload").storage

    output = run("--silo-uid", uid(team), "--purpose", "file")

    assert f"Rotated: default:{uid(team)} [file]" in output
    document.refresh_from_db()
    assert document.upload.name != old_name
    assert not storage.exists(old_name)
    assert read_document(document.pk, team) == b"quarterly numbers"
    assert dek(team, "file").dek_key_version == 2


def test_every_purpose_rotates_fields_then_files():
    team = make_team()
    note = make_note(team)
    document = make_document(team)

    output = run("--silo-uid", uid(team))

    # Each purpose names only the template its own key comes from.
    field_opened, file_opened = (line for line in output.splitlines() if line.startswith("Opened:"))
    assert "field_aead=" in field_opened and "file_streaming_aead" not in field_opened
    assert "file_streaming_aead=" in file_opened and "field_aead" not in file_opened
    assert output.index("[field] — ") < output.index("[file] — ")
    assert read_note(note.pk, team) == ("title", "body")
    assert read_document(document.pk, team) == b"file content"


def test_every_silo_is_rotated_without_a_silo_uid():
    teams = [make_team("a"), make_team("b")]
    notes = [make_note(team) for team in teams]

    run("--purpose", "field")

    for team, note in zip(teams, notes, strict=True):
        assert dek(team).dek_key_version == 2
        assert read_note(note.pk, team) == ("title", "body")


def test_a_row_a_default_manager_hides_is_converted_like_any_other():
    from encryption_suite.adapters.silos.context import override_current_silo
    from tests.testapp.models import HiddenNote

    team = make_team()
    with override_current_silo(team):
        hidden = HiddenNote.objects.create(team=team, hidden=True, secret="kept")
    assert not HiddenNote.objects.filter(pk=hidden.pk).exists()

    run("--silo-uid", uid(team), "--purpose", "field")

    EncryptionEngine.invalidate_cache()
    with override_current_silo(team):
        assert HiddenNote._base_manager.get(pk=hidden.pk).secret == "kept"


# ---------------------------------------------------------------------------
# A row that will not convert
# ---------------------------------------------------------------------------


def test_a_tampered_row_is_reported_and_the_rest_still_convert():
    team = make_team()
    good = make_note(team, title="good")
    bad = make_note(team, title="bad")
    old_keyset = bytes(dek(team).encrypted_keyset)
    tamper_author(bad)
    # Fail-closed before the rotation ever runs: the bound column moved.
    assert all(is_undecryptable(value) for value in read_note(bad.pk, team))

    output = run_fenced("--silo-uid", uid(team), "--purpose", "field")

    assert "2 outstanding" in output
    assert f"testapp.Note pk={bad.pk} title — field_decryption_failed" in output
    assert "--abort" in output
    row = dek(team)
    # The swap refused: the key is still fenced and still the old material.
    assert row.status == lifecycle.STATUS_REENCRYPTING
    assert bytes(row.encrypted_keyset) == old_keyset
    converted = DekRotationWorkItem.objects.filter(object_pk=str(good.pk), converted_at__isnull=False)
    assert converted.count() == 2


def test_repairing_the_row_and_rerunning_lets_the_swap_proceed():
    team = make_team()
    good, bad = make_note(team, title="good"), make_note(team, title="bad")
    tamper_author(bad)
    run_fenced("--silo-uid", uid(team), "--purpose", "field")

    tamper_author(bad, "ann")
    output = run("--silo-uid", uid(team), "--purpose", "field")

    assert "Rotated:" in output
    assert read_note(good.pk, team) == ("good", "body")
    assert read_note(bad.pk, team) == ("bad", "body")
    assert len(_events(dek(team), lifecycle.EVENT_ROTATION_STARTED)) == 1


def test_a_row_moved_to_another_silo_is_refused_rather_than_laundered():
    """The ciphertext is bound to its original silo; converting it would need that key."""
    home, other = make_team("home"), make_team("other")
    moved = make_note(home, title="moved")
    make_note(other)
    Note.objects.filter(pk=moved.pk).update(team=other)

    output = run_fenced("--silo-uid", uid(other), "--purpose", "field")

    assert f"testapp.Note pk={moved.pk} title — field_decryption_failed" in output
    assert dek(other).status == lifecycle.STATUS_REENCRYPTING


def test_the_report_names_an_empty_bound_column_without_values(caplog):
    team = make_team()
    bad = make_note(team, author="ann")
    tamper_author(bad, "")

    output = run_fenced("--silo-uid", uid(team), "--purpose", "field")

    assert "aad: team_id=<populated>,author=<empty>" in output


def test_show_aad_values_prints_them_to_stdout_and_never_to_the_log(caplog):
    team = make_team()
    bad = make_note(team)
    tamper_author(bad, "mallory")

    with caplog.at_level("DEBUG", logger="encryption_suite"):
        output = run_fenced("--silo-uid", uid(team), "--purpose", "field", "--show-aad-values")

    assert "author=mallory" in output
    assert "mallory" not in caplog.text
    assert "author=<populated>" in caplog.text


def test_the_rotation_log_line_carries_values_only_under_log_aad_values(settings, caplog):
    settings.ENCRYPTION = {**settings.ENCRYPTION, "LOG_AAD_VALUES": True}
    team = make_team()
    bad = make_note(team)
    tamper_author(bad, "mallory")

    with caplog.at_level("ERROR", logger="encryption_suite.rotation"):
        output = run_fenced("--silo-uid", uid(team), "--purpose", "field")

    assert "author=mallory" in caplog.text
    # The terminal report is governed by the flag, not the setting.
    assert "author=<populated>" in output


def test_the_closing_line_counts_what_the_run_reencrypted(caplog):
    team = make_team()
    notes = [make_note(team, title=f"t{i}") for i in range(3)]

    with caplog.at_level("INFO", logger="encryption_suite"):
        run("--silo-uid", uid(team), "--purpose", "field")

    (rotated,) = [r.getMessage() for r in caplog.records if f"event={lifecycle.EVENT_ROTATED}" in r.getMessage()]
    # Two encrypted fields on each note, each re-encrypted once.
    assert f"reencrypted={2 * len(notes)}" in rotated


def test_the_abandoned_line_counts_what_the_run_moved_back(caplog):
    team = make_team()
    make_note(team, title="good")
    tamper_author(make_note(team, title="bad"))
    run_fenced("--silo-uid", uid(team), "--purpose", "field")

    with caplog.at_level("INFO", logger="encryption_suite"):
        run("--silo-uid", uid(team), "--purpose", "field", "--abort")

    (abandoned,) = [
        r.getMessage() for r in caplog.records if f"event={lifecycle.EVENT_ROTATION_ABANDONED}" in r.getMessage()
    ]
    assert "moved_back=2" in abandoned


def test_a_rotation_writes_no_per_value_decrypt_entries_under_log_decrypts(settings, caplog):
    """A conversion holds the keysets itself, so it never reaches the logged decrypt path.

    Which is what makes the counts above the only record of the values a
    rotation read: a control worded as one entry per decrypt gets none of them.
    """
    settings.ENCRYPTION = {**settings.ENCRYPTION, "LOG_DECRYPTS": True}
    team = make_team()
    note = make_note(team)
    make_document(team)

    with caplog.at_level("INFO", logger="encryption_suite"):
        run("--silo-uid", uid(team), "--purpose", "all")

    assert "was decrypted." not in caplog.text
    # An ordinary read of the same data still writes one.
    caplog.clear()
    with caplog.at_level("INFO", logger="encryption_suite"):
        read_note(note.pk, team)
    assert "An encrypted field value was decrypted." in caplog.text


def test_abort_returns_the_silo_to_its_old_key_with_every_row_readable():
    team = make_team()
    good, bad = make_note(team, title="good"), make_note(team, title="bad")
    old_keyset = bytes(dek(team).encrypted_keyset)
    tamper_author(bad)
    run_fenced("--silo-uid", uid(team), "--purpose", "field")

    output = run("--silo-uid", uid(team), "--purpose", "field", "--abort")

    assert "Abandoned:" in output and "2 item(s) moved back" in output
    row = dek(team)
    assert row.status == lifecycle.STATUS_ACTIVE
    assert bytes(row.encrypted_keyset) == old_keyset
    assert row.dek_key_version == 1
    assert not DekRotation.objects.exists() and not DekRotationWorkItem.objects.exists()
    assert read_note(good.pk, team) == ("good", "body")
    tamper_author(bad, "ann")
    assert read_note(bad.pk, team) == ("bad", "body")
    (abandoned,) = _events(row, lifecycle.EVENT_ROTATION_ABANDONED)
    assert abandoned.reason == "" and abandoned.trigger == lifecycle.TRIGGER_AUTOMATED


def test_abort_on_unconvertible_ends_the_run_active_rather_than_fenced():
    team = make_team()
    make_note(team, title="good")
    bad = make_note(team, title="bad")
    document = make_document(team)
    tamper_author(bad)

    output = run("--silo-uid", uid(team), "--abort-on-unconvertible")

    assert dek(team).status == lifecycle.STATUS_ACTIVE
    (abandoned,) = _events(dek(team), lifecycle.EVENT_ROTATION_ABANDONED)
    assert abandoned.reason == lifecycle.REASON_UNCONVERTIBLE_ROWS
    # It ends the run, not just the purpose: files were never started.
    assert "[file]" not in output
    assert not _events(dek(team, "file"), lifecycle.EVENT_ROTATION_STARTED)
    assert read_document(document.pk, team) == b"file content"


def test_a_purpose_left_outstanding_stops_the_next_from_starting():
    team = make_team()
    bad = make_note(team)
    make_document(team)
    tamper_author(bad)

    output = run_fenced("--silo-uid", uid(team))

    assert "[file]" not in output.split("Stopped with the fence up")[0].replace(f"{uid(team)} [field]", "")
    assert dek(team, "file").status == lifecycle.STATUS_ACTIVE


# ---------------------------------------------------------------------------
# Interruption and recovery
# ---------------------------------------------------------------------------


class Interrupted(Exception):
    """Stands in for a process killed mid-run: nothing in the command catches it."""


def test_an_interrupted_sweep_resumes_forward_without_converting_a_row_twice(monkeypatch):
    team = make_team()
    notes = [make_note(team, title=f"t{i}") for i in range(3)]
    calls: list[int] = []
    original = rotation_items.ItemConverter._convert_field

    def flaky(self, item, *args, **kwargs):
        calls.append(item.pk)
        if len(calls) == 3:
            raise Interrupted
        return original(self, item, *args, **kwargs)

    monkeypatch.setattr(rotation_items.ItemConverter, "_convert_field", flaky)
    with pytest.raises(Interrupted):
        run("--silo-uid", uid(team), "--purpose", "field")
    first = list(calls)
    calls.clear()

    def counted(self, item, *args, **kwargs):
        calls.append(item.pk)
        return original(self, item, *args, **kwargs)

    monkeypatch.setattr(rotation_items.ItemConverter, "_convert_field", counted)
    run("--silo-uid", uid(team), "--purpose", "field")

    assert not set(first[:2]) & set(calls)
    assert len(calls) == 4
    for i, note in enumerate(notes):
        assert read_note(note.pk, team) == (f"t{i}", "body")
    row = dek(team)
    assert len(_events(row, lifecycle.EVENT_ROTATION_STARTED)) == 1
    assert len(_events(row, lifecycle.EVENT_ROTATED)) == 1


def test_a_run_killed_before_the_swap_is_finished_by_the_rerun_without_rebuilding(monkeypatch):
    team = make_team()
    note = make_note(team)
    original_swap = rotation.Rotator._swap

    def killed(self, dek_row, converted):
        raise Interrupted

    monkeypatch.setattr(rotation.Rotator, "_swap", killed)
    with pytest.raises(Interrupted):
        run("--silo-uid", uid(team), "--purpose", "field")
    assert dek(team).status == lifecycle.STATUS_REENCRYPTING
    items_before = list(DekRotationWorkItem.objects.values_list("pk", flat=True))

    monkeypatch.setattr(rotation.Rotator, "_swap", original_swap)
    rebuilt = []
    monkeypatch.setattr(rotation.Rotator, "_build_worklist", lambda *a, **k: rebuilt.append(True))
    run("--silo-uid", uid(team), "--purpose", "field")

    assert not rebuilt
    assert items_before
    assert dek(team).status == lifecycle.STATUS_ACTIVE
    assert read_note(note.pk, team) == ("title", "body")


def test_a_run_killed_during_the_wait_rebuilds_an_incomplete_worklist(monkeypatch, waits):
    team = make_team()
    note = make_note(team)
    monkeypatch.setattr(rotation, "_sleep", lambda seconds: (_ for _ in ()).throw(Interrupted()))
    with pytest.raises(Interrupted):
        run("--silo-uid", uid(team), "--purpose", "field")
    assert not DekRotation.objects.get().worklist_complete
    # A stray item from a half-built list is discarded, not read as work.
    DekRotationWorkItem.objects.create(dek=dek(team), model_label="testapp.Note", object_pk="999999", field_name="body")

    monkeypatch.setattr(rotation, "_sleep", waits.append)
    run("--silo-uid", uid(team), "--purpose", "field")

    assert waits, "the rerun re-derives the wait rather than skipping it"
    assert read_note(note.pk, team) == ("title", "body")


def test_an_interrupted_abort_continues_backward_on_a_plain_rerun(monkeypatch):
    team = make_team()
    goods = [make_note(team, title=f"g{i}") for i in range(3)]
    bad = make_note(team, title="bad")
    tamper_author(bad)
    run_fenced("--silo-uid", uid(team), "--purpose", "field")
    original = rotation_items.ItemConverter._convert_field
    calls = []

    def flaky(self, item, *args, forward, **kwargs):
        calls.append(forward)
        if len(calls) == 2:
            raise Interrupted
        return original(self, item, *args, forward=forward, **kwargs)

    monkeypatch.setattr(rotation_items.ItemConverter, "_convert_field", flaky)
    with pytest.raises(Interrupted):
        run("--silo-uid", uid(team), "--purpose", "field", "--abort")
    monkeypatch.setattr(rotation_items.ItemConverter, "_convert_field", original)
    assert DekRotation.objects.get().rolling_back

    # No --abort this time: the rerun follows the flag, not the command line.
    output = run("--silo-uid", uid(team), "--purpose", "field")

    assert "Abandoned:" in output
    assert dek(team).status == lifecycle.STATUS_ACTIVE
    for i, note in enumerate(goods):
        assert read_note(note.pk, team) == (f"g{i}", "body")
    assert not _events(dek(team), lifecycle.EVENT_ROTATED)
    assert len(_events(dek(team), lifecycle.EVENT_ROTATION_ABANDONED)) == 1


def test_a_target_retired_mid_sweep_closes_its_item_and_the_swap_proceeds(monkeypatch):
    team = make_team()
    keep, retire = make_note(team, title="keep"), make_note(team, title="retire")
    original = rotation.Rotator._build_worklist

    def build_then_delete(self, *args, **kwargs):
        original(self, *args, **kwargs)
        Note.objects.filter(pk=retire.pk).delete()

    monkeypatch.setattr(rotation.Rotator, "_build_worklist", build_then_delete)
    run("--silo-uid", uid(team), "--purpose", "field")

    assert dek(team).status == lifecycle.STATUS_ACTIVE
    assert read_note(keep.pk, team) == ("keep", "body")


def test_aborting_a_rotation_that_carries_a_retired_target_still_reaches_active(monkeypatch):
    team = make_team()
    keep, retire, bad = make_note(team, title="keep"), make_note(team, title="retire"), make_note(team)
    tamper_author(bad)
    original = rotation.Rotator._build_worklist

    def build_then_delete(self, *args, **kwargs):
        original(self, *args, **kwargs)
        Note.objects.filter(pk=retire.pk).delete()

    monkeypatch.setattr(rotation.Rotator, "_build_worklist", build_then_delete)
    run_fenced("--silo-uid", uid(team), "--purpose", "field")

    run("--silo-uid", uid(team), "--purpose", "field", "--abort")

    assert dek(team).status == lifecycle.STATUS_ACTIVE
    assert read_note(keep.pk, team) == ("keep", "body")


def test_a_row_that_leaves_the_silo_closes_and_the_swap_proceeds(monkeypatch):
    """Its ciphertext belongs to the other silo's key now, so it is not this rotation's to convert."""
    home, other = make_team("home"), make_team("other")
    staying, leaving = make_note(home, title="staying"), make_note(home, title="leaving")
    original = rotation.Rotator._build_worklist

    def build_then_move(self, *args, **kwargs):
        original(self, *args, **kwargs)
        Note.objects.filter(pk=leaving.pk).update(team=other)

    before = Note.objects.filter(pk=leaving.pk).values_list("title", flat=True)[0]
    monkeypatch.setattr(rotation.Rotator, "_build_worklist", build_then_move)
    run("--silo-uid", uid(home), "--purpose", "field")

    assert dek(home).status == lifecycle.STATUS_ACTIVE
    assert read_note(staying.pk, home) == ("staying", "body")
    # Untouched: converting it would have put the other silo's row on this key.
    assert Note.objects.filter(pk=leaving.pk).values_list("title", flat=True)[0] == before


def test_a_repaired_row_lets_a_rerun_swap():
    """The report says to correct the assignment and rerun; this is that."""
    home, other = make_team("home"), make_team("other")
    moved = make_note(home, title="moved")
    make_note(other, title="native")
    Note.objects.filter(pk=moved.pk).update(team=other)
    run_fenced("--silo-uid", uid(other), "--purpose", "field")

    Note.objects.filter(pk=moved.pk).update(team=home)
    output = run("--silo-uid", uid(other), "--purpose", "field")

    assert "Rotated:" in output
    assert dek(other).status == lifecycle.STATUS_ACTIVE
    assert read_note(moved.pk, home) == ("moved", "body")


def test_the_failure_line_leaves_out_aad_for_a_model_that_binds_none(caplog):
    from tests.testapp.models import HiddenNote

    home, other = make_team("home"), make_team("other")
    # The other silo needs a key of its own before it can be rotated.
    make_note(other, title="native")
    with override_current_silo(home):
        note = HiddenNote.objects.create(team=home, secret="kept")
    HiddenNote.objects.filter(pk=note.pk).update(team=other)

    with caplog.at_level("ERROR", logger="encryption_suite.rotation"):
        run_fenced("--silo-uid", uid(other), "--purpose", "field")

    (failure,) = [r.getMessage() for r in caplog.records if "could not be converted" in r.getMessage()]
    assert "testapp.HiddenNote" in failure and "aad=" not in failure


def test_a_long_run_of_missing_targets_stops_rather_than_closing_them(monkeypatch):
    monkeypatch.setattr(rotation, "MAX_CONSECUTIVE_MISSES", 2)
    team = make_team()
    for i in range(3):
        make_note(team, title=f"t{i}")
    original = rotation.Rotator._build_worklist

    def build_then_lose_everything(self, *args, **kwargs):
        original(self, *args, **kwargs)
        Note.objects.all().delete()

    monkeypatch.setattr(rotation.Rotator, "_build_worklist", build_then_lose_everything)
    output = run_fenced("--silo-uid", uid(team), "--purpose", "field")

    assert "no longer exist" in output
    assert DekRotationWorkItem.objects.filter(converted_at__isnull=True).count() == 6
    assert dek(team).status == lifecycle.STATUS_REENCRYPTING


# ---------------------------------------------------------------------------
# Files that fail
# ---------------------------------------------------------------------------


def _storage():
    return Document._meta.get_field("upload").storage


def test_a_truncated_blob_is_caught_before_the_pointer_moves(monkeypatch):
    from django.core.files.base import ContentFile

    team = make_team()
    # Larger than one streaming segment, so a truncated copy still decrypts
    # cleanly up to where it stops — which is the case verification exists for.
    content = bytes(range(256)) * 20000
    document = make_document(team, content)
    original_name = document.upload.name
    storage_class = type(_storage())
    original_save_raw = storage_class._save_raw

    def truncating(self, name, content_file):
        data = content_file.read()
        return original_save_raw(self, name, ContentFile(data[: len(data) // 2], name=name))

    monkeypatch.setattr(storage_class, "_save_raw", truncating)
    output = run_fenced("--silo-uid", uid(team), "--purpose", "file")

    assert "file_decryption_failed" in output
    document.refresh_from_db()
    assert document.upload.name == original_name
    assert _storage().exists(original_name)

    monkeypatch.setattr(storage_class, "_save_raw", original_save_raw)
    run("--silo-uid", uid(team), "--purpose", "file")
    assert read_document(document.pk, team) == content


def test_a_storage_failure_clears_on_a_rerun_alone(monkeypatch):
    from django.core.files.storage import FileSystemStorage

    team = make_team()
    document = make_document(team, b"survives")

    def unreachable(self, name, content):
        raise OSError("bucket unreachable")

    # The backend beneath the encryption mixin, so the failure goes through the
    # mixin's own normalization the way a real outage would.
    original = FileSystemStorage._save
    monkeypatch.setattr(FileSystemStorage, "_save", unreachable)
    output = run_fenced("--silo-uid", uid(team), "--purpose", "file")
    assert "file_storage_error" in output

    monkeypatch.setattr(FileSystemStorage, "_save", original)
    run("--silo-uid", uid(team), "--purpose", "file")
    assert read_document(document.pk, team) == b"survives"


# ---------------------------------------------------------------------------
# Dry runs, which must leave no trace
# ---------------------------------------------------------------------------


def _trace():
    return (
        DekRotation.objects.count(),
        DekRotationWorkItem.objects.count(),
        KeyLifecycleEvent.objects.count(),
        list(DataEncryptionKey.objects.values_list("status", "encrypted_keyset")),
    )


def test_a_dry_run_reports_silos_models_and_counts_and_changes_nothing(waits):
    team = make_team()
    make_note(team)
    make_note(team)
    before = _trace()

    output = run("--silo-uid", uid(team), "--purpose", "field", "--dry-run")

    assert "[dry-run] Model: testapp.Note (filtered on team)" in output
    assert f"[dry-run] Would rotate: default:{uid(team)} [field]" in output
    assert "testapp.Note: 2 row(s) now" in output
    assert f"idle wait of {rotation.wait_seconds()}s" in output
    assert _trace() == before
    assert not waits


def test_a_dry_run_names_a_uid_that_resolves_to_nothing():
    output = run("--silo-uid", "group-999999", "--dry-run")

    assert "group-999999 resolves to no silo" in output
    assert "silo_for_uid()" in output


def test_a_real_run_refuses_a_uid_that_resolves_to_nothing():
    team = make_team()
    make_note(team)

    with pytest.raises(CommandError, match="silo_for_uid"):
        run("--silo-uid", "group-999999")


def test_a_dry_run_with_a_rotation_open_reprints_the_outstanding_report():
    team = make_team()
    bad = make_note(team)
    tamper_author(bad)
    run_fenced("--silo-uid", uid(team), "--purpose", "field")
    before = _trace()

    output = run("--silo-uid", uid(team), "--purpose", "field", "--dry-run")

    assert "Open rotation:" in output and "2 item(s) outstanding" in output
    assert f"testapp.Note pk={bad.pk} body — field_decryption_failed" in output
    assert _trace() == before


def test_a_dry_run_abort_reports_what_a_rollback_would_reverse_and_reverses_nothing():
    team = make_team()
    make_note(team, title="good")
    bad = make_note(team)
    tamper_author(bad)
    run_fenced("--silo-uid", uid(team), "--purpose", "field")
    before = _trace()

    output = run("--silo-uid", uid(team), "--purpose", "field", "--dry-run", "--abort")

    assert "Would roll back:" in output and "2 item(s)" in output
    assert _trace() == before


def _finished(caplog) -> str:
    (line,) = [r.getMessage() for r in caplog.records if "command finished" in r.getMessage()]
    return line


def test_the_run_closes_on_one_line_of_its_own(caplog):
    """The rotation's lines close each rotation; this one closes the command.

    On a run over several silos those are different things, and on a run that
    rotated nothing the command's line is the only one there is.
    """
    team = make_team()
    make_note(team)
    make_document(team)

    with caplog.at_level("INFO", logger="encryption_suite"):
        run("--silo-uid", uid(team), "--purpose", "all")

    line = _finished(caplog)
    assert "command=reencrypt_data key_set=default dry_run=False abort=False purpose=all" in line
    assert f'silo="{uid(team)}"' in line
    # The index purpose is attempted too, and skipped: this silo holds no
    # indexed row, so it was never given an index key.
    assert "rotated=2 abandoned=0 skipped=1 fenced=0 failed=0" in line
    assert "os_user=" in line


def test_a_dry_run_closes_with_the_counts_it_previewed(caplog):
    team = make_team()
    make_note(team)

    with caplog.at_level("INFO", logger="encryption_suite"):
        run("--silo-uid", uid(team), "--purpose", "all", "--dry-run")

    # One purpose would rotate; the other has no data key to rotate.
    line = _finished(caplog)
    assert "dry_run=True" in line
    assert "rotated=1 abandoned=0 skipped=2 fenced=0 failed=0" in line


def test_a_run_that_stops_with_the_fence_up_still_closes(caplog):
    team = make_team()
    make_note(team, title="good")
    tamper_author(make_note(team, title="bad"))

    with caplog.at_level("INFO", logger="encryption_suite"):
        run_fenced("--silo-uid", uid(team), "--purpose", "field")

    # Stopping with the fence up is an ending the command reached on purpose, so
    # it closes: an unmatched opening line means a run that died instead.
    line = _finished(caplog)
    assert "rotated=0 abandoned=0 skipped=0 fenced=1 failed=0" in line
