"""``reencrypt_keys`` attempts only the DEKs a rewrap can actually succeed on.

A rewrap needs a live keyset and a live key encryption key. A purged DEK has had
its ``encrypted_keyset`` cleared to empty, a scheduled one is blocked from
encrypt and decrypt for its restore window, and a DEK whose KEK has been retired
has nothing left to unwrap it. Handing any of them to the KMS buys a provider
error in place of work that was never possible, and counting those as failures
buries the one result that means something.

A DEK on a KMS no block names is skipped for the same reason the engine's read
path refuses one: there is nothing to unwrap it with. One on another configured
KMS is unwrapped there and wrapped onto ``SILO_KEY_STORES`` — the move between KMSs.

Also covers the funnel: the command drives the KMS adapter directly, so a raw
provider error has to be translated here or it reaches the operator
untranslated and with no error-code slug.
"""

from __future__ import annotations

from dataclasses import replace
from io import StringIO
from unittest.mock import patch

import pytest
from django.contrib.auth.models import Group
from django.core.management import call_command
from django.core.management.base import CommandError

from encryption_suite import lifecycle
from encryption_suite.engine import EncryptionEngine
from encryption_suite.models import DataEncryptionKey, KeyEncryptionKey
from encryption_suite.registry import get_engine
from tests.factories import make_kek
from tests.key_set_settings import key_sets


@pytest.fixture(autouse=True)
def _clear_cache():
    EncryptionEngine.invalidate_cache()
    yield
    EncryptionEngine.invalidate_cache()


def _uid(silo):
    return get_engine().silo_adapter.get_silo_uid(silo)


def _make_dek() -> DataEncryptionKey:
    group = Group.objects.create(name="acme")
    get_engine().generate_and_store_keyset(group)
    return DataEncryptionKey.objects.get(silo_uid=_uid(group))


def _run(*args) -> str:
    out, err = StringIO(), StringIO()
    call_command("reencrypt_keys", *args, stdout=out, stderr=err)
    return out.getvalue() + err.getvalue()


@pytest.mark.django_db
def test_active_dek_is_rewrapped():
    dek = _make_dek()

    assert "Re-encrypted:" in _run()

    dek.refresh_from_db()
    assert dek.reencryption_count == 2


@pytest.mark.django_db
def test_the_reencryption_names_the_operator_who_ran_the_command(monkeypatch):
    """A command run has no logged-in user, but always has an OS login account."""
    from encryption_suite.models import KeyLifecycleEvent

    monkeypatch.setenv("SUDO_USER", "alice")
    dek = _make_dek()

    _run()

    event = KeyLifecycleEvent.objects.get(dek=dek, event=lifecycle.EVENT_REENCRYPTED)
    assert event.trigger == lifecycle.TRIGGER_AUTOMATED
    assert str(event.os_user).startswith("alice → ")
    assert event.user_id is None


@pytest.mark.django_db
@pytest.mark.parametrize("status", [lifecycle.STATUS_DELETION_SCHEDULED, lifecycle.STATUS_DELETED])
def test_non_active_dek_is_not_attempted(status):
    dek = _make_dek()
    DataEncryptionKey.objects.filter(pk=dek.pk).update(status=status)

    output = _run()

    assert "Done. Re-encrypted: 0, Skipped: 0, Failed: 0." in output
    dek.refresh_from_db()
    assert dek.reencryption_count == 1


@pytest.mark.django_db
def test_purged_dek_is_never_handed_an_empty_keyset_to_the_kms():
    # The shape that made AWS reject the call: a tombstone whose keyset is empty.
    dek = _make_dek()
    DataEncryptionKey.objects.filter(pk=dek.pk).update(status=lifecycle.STATUS_DELETED, encrypted_keyset=b"")

    with patch.object(get_engine().silo_kms_adapter, "decrypt_key") as decrypt:
        _run()

    decrypt.assert_not_called()


@pytest.mark.django_db
def test_dek_whose_kek_is_retired_is_skipped_not_failed():
    dek = _make_dek()
    KeyEncryptionKey.objects.update_or_create(
        kek_resource_name=dek.kek.kek_resource_name,
        key_store=dek.kek.key_store,
        defaults={"status": lifecycle.STATUS_DELETION_SCHEDULED},
    )

    output = _run()

    assert "Skipped:" in output
    assert lifecycle.STATUS_DELETION_SCHEDULED in output
    assert "Skipped: 1" in output
    assert "Failed: 0" in output


@pytest.mark.django_db
def test_dek_on_an_unconfigured_kms_is_never_handed_to_any_adapter():
    # The shape a run pointed at the wrong settings module produces: every row
    # names a KMS no block in this configuration carries.
    dek = _make_dek()
    dek.kek = make_kek(dek.kek.kek_resource_name + "-elsewhere", "some-other-kms")
    dek.save(update_fields=["kek"])

    with patch.object(get_engine().silo_kms_adapter, "decrypt_key") as decrypt:
        output = _run()

    decrypt.assert_not_called()
    assert "some-other-kms" in output
    assert "--settings=" in output
    assert "Skipped: 1" in output
    assert "Failed: 0" in output


def _move_silo_kms_to_other(settings):
    """Add a second block, "other", and point the default key set at it — a move between KMSs."""
    from encryption_suite import registry

    blocks = dict(settings.ENCRYPTION["KMS_KEY_STORES"])
    blocks["other"] = {**blocks["local"], "OPTIONS": {"SHARED_KEK_ID": "other-test-kek"}}
    settings.ENCRYPTION = {
        **settings.ENCRYPTION,
        "KMS_KEY_STORES": blocks,
        "KEY_SETS": key_sets(default="other"),
    }
    registry.reset()


@pytest.mark.django_db
def test_a_row_on_another_kms_moves_onto_silo_kms(settings):
    """Unwrapped through the KMS its row names, wrapped through the key set's store; the old row stays."""
    group = Group.objects.create(name="acme")
    stored = get_engine().encrypt("secret", silo=group)
    dek = DataEncryptionKey.objects.get(silo_uid=_uid(group))
    old_kek = dek.kek
    _move_silo_kms_to_other(settings)

    preview = _run("--dry-run")
    assert "[dry-run] Converting: key store local -> other" in preview
    output = _run()

    assert "key store local -> other" in output
    # No arrow: a cp1252 console cannot encode one, and the failed write would
    # count a committed rewrap as failed.
    assert "→" not in output
    dek.refresh_from_db()
    assert (dek.kek.key_store, dek.kek.kek_resource_name) == ("other", "other-test-kek")
    assert KeyEncryptionKey.objects.filter(pk=old_kek.pk).exists()
    EncryptionEngine.invalidate_cache()
    assert get_engine().decrypt(stored, silo=group) == "secret"


@pytest.mark.django_db
def test_rows_still_on_the_old_kms_keep_reading_before_the_move(settings):
    """Pointing the key set elsewhere moves nothing: existing rows read through the KMS they name."""
    group = Group.objects.create(name="acme")
    stored = get_engine().encrypt("secret", silo=group)
    _move_silo_kms_to_other(settings)
    EncryptionEngine.invalidate_cache()

    assert get_engine().decrypt(stored, silo=group) == "secret"
    assert DataEncryptionKey.objects.get(silo_uid=_uid(group)).kek.key_store == "local"


def _point_stores_at(settings, default):
    """Point the default key set at the store *default*, or at a dict of extra key set to store name."""
    from encryption_suite import registry

    if isinstance(default, dict):
        sets = key_sets(default=default.get("default", "local"), **{k: v for k, v in default.items() if k != "default"})
    else:
        sets = key_sets(default=default)
    settings.ENCRYPTION = {**settings.ENCRYPTION, "KEY_SETS": sets}
    registry.reset()
    EncryptionEngine.invalidate_cache()


@pytest.mark.django_db
def test_a_single_set_kind_moves_from_an_env_store_to_a_kms_store(settings):
    """The swap is a settings change and a run: repoint the set's store, then ``reencrypt_keys``."""
    _point_stores_at(settings, "login")
    group = Group.objects.create(name="acme")
    stored = get_engine().encrypt("secret", silo=group)
    dek = DataEncryptionKey.objects.get(silo_uid=_uid(group))
    assert dek.kek.key_store == "login"

    _point_stores_at(settings, "local")
    _run()

    dek.refresh_from_db()
    assert dek.kek.key_store == "local"
    assert get_engine().decrypt(stored, silo=group) == "secret"


@pytest.mark.django_db
def test_a_kind_with_two_key_sets_moves_only_the_set_whose_store_changed(settings, monkeypatch):
    """The pass filters by key set, so the rows already on the other set's store are never mistaken for it."""
    monkeypatch.setattr("encryption_suite.rotation_targets.key_sets_in_use", lambda: {"default", "archive"})
    _point_stores_at(settings, {"default": "login", "archive": "login"})
    group = Group.objects.create(name="acme")
    engine = get_engine()
    first = engine.encrypt("on the default set", silo=group)
    second = engine.encrypt("on the archive set", silo=group, key_set="archive")

    _point_stores_at(settings, {"default": "local", "archive": "login"})
    _run()

    rows = {row.key_set: row for row in DataEncryptionKey.objects.select_related("kek").filter(silo_uid=_uid(group))}
    assert rows["default"].kek.key_store == "local"
    assert rows["archive"].kek.key_store == "login"
    engine = get_engine()
    assert engine.decrypt(first, silo=group) == "on the default set"
    assert engine.decrypt(second, silo=group, key_set="archive") == "on the archive set"


@pytest.mark.django_db
def test_a_key_set_with_no_store_refuses_the_whole_run_before_any_row_moves(settings, monkeypatch):
    """Stores are resolved up front, so an earlier key set's pass is never left done while a later one fails."""
    from encryption_suite import registry

    monkeypatch.setattr("encryption_suite.rotation_targets.key_sets_in_use", lambda: {"default", "archive"})
    _point_stores_at(settings, "login")
    group = Group.objects.create(name="acme")
    get_engine().encrypt("secret", silo=group)
    dek = DataEncryptionKey.objects.get(silo_uid=_uid(group))
    settings.ENCRYPTION = {**settings.ENCRYPTION, "KEY_SETS": key_sets(default="local", archive="nowhere")}
    registry.reset()
    EncryptionEngine.invalidate_cache()

    with pytest.raises(CommandError, match="Nothing was re-encrypted"):
        _run("--key-set", "all")

    dek.refresh_from_db()
    assert dek.kek.key_store == "login"


@pytest.mark.django_db
def test_dry_run_previews_the_same_decisions_as_the_real_run():
    dek = _make_dek()
    KeyEncryptionKey.objects.update_or_create(
        kek_resource_name=dek.kek.kek_resource_name,
        key_store=dek.kek.key_store,
        defaults={"status": lifecycle.STATUS_DELETION_SCHEDULED},
    )

    output = _run("--dry-run")

    assert "Would re-encrypt" not in output
    assert "[dry-run] Skipped:" in output
    assert "Skipped: 1" in output
    dek.refresh_from_db()
    assert dek.reencryption_count == 1


@pytest.mark.django_db
def test_provider_error_is_funnelled_and_carries_a_slug():
    _make_dek()

    # A raw provider failure, as any SDK-backed adapter might raise. Without the
    # funnel this reaches stderr as the bare exception text, untyped and unslugged.
    out, err = StringIO(), StringIO()
    with patch.object(get_engine().silo_kms_adapter, "decrypt_key", side_effect=RuntimeError("SDK exploded")):
        # A failed row makes the run exit non-zero, after the summary.
        with pytest.raises(CommandError, match="1 data encryption key"):
            call_command("reencrypt_keys", stdout=out, stderr=err)
    output = out.getvalue() + err.getvalue()

    assert "Failed: 1" in output
    # The error-code slug is the language-neutral grep handle for the operator.
    assert "[kek_unavailable]" in output
    # A management command is an operator surface, so it reports exc.detail —
    # the KEK, the silo, and the provider's own words. The generic user message
    # is what a *view* would show; printing it here would tell an operator
    # nothing they could act on.
    assert "SDK exploded" in output
    assert 'kek="local-test-kek"' in output
    assert "Encryption and decryption are unavailable for this data." not in output


@pytest.mark.django_db
def test_rows_already_on_the_current_key_version_are_skipped(monkeypatch):
    """Re-wrapping a row that is already current buys nothing.

    It costs a KMS round trip per row and bumps the re-encryption count for a
    change nobody made — which is what made a run after an unrelated rotation
    look like it had done work. Only providers that record a version can answer
    this; the rest report "" and are always re-wrapped, as before.
    """
    dek = _make_dek()
    DataEncryptionKey.objects.filter(pk=dek.pk).update(kek_key_version="v1")
    adapter = get_engine().silo_kms_adapter
    monkeypatch.setattr(type(adapter), "current_kek_version", lambda self, silo_uid: "v1", raising=False)

    output = _run()

    assert "already wrapped by the current key version" in output
    assert DataEncryptionKey.objects.get(pk=dek.pk).reencryption_count == dek.reencryption_count


@pytest.mark.django_db
def test_a_row_on_an_older_version_is_still_re_encrypted(monkeypatch):
    # "1" is the row's real version, so it still unwraps; the provider claims a
    # newer one, so the row is not skipped as current.
    dek = _make_dek()
    adapter = get_engine().silo_kms_adapter
    monkeypatch.setattr(type(adapter), "current_kek_version", lambda self, silo_uid: "2", raising=False)

    output = _run()

    assert "Re-encrypted: 1" in output
    assert DataEncryptionKey.objects.get(pk=dek.pk).reencryption_count == dek.reencryption_count + 1


def _unwrap_whatever_the_label(monkeypatch, adapter):
    """Unwrap under the suite's one real version, whatever version a test relabeled the wrap with.

    The relabeling exists to drive the success line. Without this the command's
    check of the new wrap would refuse it, rightly: on the env adapter a wrap
    recorded under a version that did not make it never unwraps again.
    """
    original = type(adapter).decrypt_key

    def decrypt_key(self, ciphertext, metadata, silo_ref):
        return original(self, ciphertext, replace(metadata, kek_key_version="1"), silo_ref)

    monkeypatch.setattr(type(adapter), "decrypt_key", decrypt_key)


def _wrap_under_version(monkeypatch, adapter, version):
    """Make the adapter report *version* as the one that wrapped each row."""
    original = type(adapter).encrypt_key

    def encrypt_key(self, plaintext, silo_uid):
        ciphertext, metadata = original(self, plaintext, silo_uid)
        return ciphertext, replace(metadata, kek_key_version=version)

    monkeypatch.setattr(type(adapter), "encrypt_key", encrypt_key)
    _unwrap_whatever_the_label(monkeypatch, adapter)


@pytest.mark.django_db
def test_the_success_line_names_the_write_count_and_the_key_version(monkeypatch):
    """The count is not a key version, and reporting it as "v4" read like one.

    A provider that reports no version says nothing about one, rather than
    printing an empty field.
    """
    adapter = get_engine().silo_kms_adapter
    _make_dek()
    _wrap_under_version(monkeypatch, adapter, "3")

    assert "-> write 2, key version 3" in _run()


@pytest.mark.django_db
def test_a_provider_without_versions_reports_only_the_write_count(monkeypatch):
    _make_dek()
    adapter = get_engine().silo_kms_adapter
    wrap = type(adapter).encrypt_key

    def _versionless(self, plaintext, silo_uid):
        ciphertext, metadata = wrap(self, plaintext, silo_uid)
        return ciphertext, replace(metadata, kek_key_version="")

    monkeypatch.setattr(type(adapter), "current_kek_version", lambda self, silo_uid: "", raising=False)
    monkeypatch.setattr(type(adapter), "encrypt_key", _versionless)
    _unwrap_whatever_the_label(monkeypatch, adapter)

    output = _run()

    assert "-> write 2" in output
    assert "key version" not in output


@pytest.mark.django_db
def test_a_wrap_that_lands_on_an_older_version_says_so(monkeypatch):
    """Some providers choose the version server-side, and their metadata can move
    ahead of their crypto — Cloud KMS is eventually consistent after a rotation.

    The rewrap is real and the row records the version that actually wrapped it,
    but without this the run looks like it accomplished nothing: the count moves
    and the key version does not.
    """
    adapter = get_engine().silo_kms_adapter
    _make_dek()
    monkeypatch.setattr(type(adapter), "current_kek_version", lambda self, silo_uid: "3", raising=False)
    _wrap_under_version(monkeypatch, adapter, "2")

    output = _run()

    assert "key version 2 (provider has not moved to 3 yet — rerun later)" in output
    assert DataEncryptionKey.objects.get().kek_key_version == "2"


@pytest.mark.django_db
def test_a_probe_failure_leaves_the_success_line_alone(monkeypatch):
    """A broken probe must not turn a successful rewrap into a reported one."""

    def _boom(self, silo_uid):
        raise RuntimeError("probe down")

    adapter = get_engine().silo_kms_adapter
    _make_dek()
    monkeypatch.setattr(type(adapter), "current_kek_version", _boom, raising=False)
    _wrap_under_version(monkeypatch, adapter, "2")

    output = _run()

    assert "-> write 2, key version 2" in output
    assert "rerun later" not in output


@pytest.mark.django_db
def test_the_closing_line_carries_the_counts_and_the_operator(monkeypatch, caplog):
    """A scheduled run's console goes nowhere, so the log is the record that it ran."""
    monkeypatch.setenv("SUDO_USER", "alice")
    _make_dek()
    other = Group.objects.create(name="retired")
    get_engine().generate_and_store_keyset(other)
    retired = DataEncryptionKey.objects.get(silo_uid=_uid(other))
    # Its own key encryption key, so retiring it leaves the first row rewrappable:
    # both silos resolve to one KEK name under the test template.
    retired.kek = make_kek(retired.kek.kek_resource_name + "-retired", retired.kek.key_store)
    retired.save(update_fields=["kek"])
    KeyEncryptionKey.objects.filter(pk=retired.kek.pk).update(status=lifecycle.STATUS_DELETION_SCHEDULED)

    with caplog.at_level("INFO", logger="encryption_suite"):
        _run()

    (closing,) = [r.getMessage() for r in caplog.records if "finished" in r.getMessage()]
    assert "dry_run=False" in closing
    assert 'silo="all"' in closing
    assert "reencrypted=1 skipped=1 failed=0" in closing
    assert 'os_user="alice' in closing


@pytest.mark.django_db
def test_a_dry_run_closes_its_own_line(caplog):
    """The preview decided the same rows; a run nobody can prove ran is worth as little."""
    _make_dek()

    with caplog.at_level("INFO", logger="encryption_suite"):
        _run("--dry-run")

    (closing,) = [r.getMessage() for r in caplog.records if "finished" in r.getMessage()]
    assert "dry_run=True" in closing
    assert "reencrypted=1 skipped=0 failed=0" in closing


def _run_expecting_one_failure() -> str:
    out, err = StringIO(), StringIO()
    with pytest.raises(CommandError, match="1 data encryption key"):
        call_command("reencrypt_keys", stdout=out, stderr=err)
    return out.getvalue() + err.getvalue()


def _assert_old_wrap_kept(dek, before: bytes) -> None:
    after = DataEncryptionKey.objects.get(pk=dek.pk)
    assert bytes(after.encrypted_keyset) == before
    assert after.reencryption_count == dek.reencryption_count
    EncryptionEngine.invalidate_cache()
    assert get_engine().decrypt(get_engine().encrypt("still readable", silo=dek.silo_ref), silo=dek.silo_ref)


@pytest.mark.django_db
def test_a_new_wrap_that_cannot_be_unwrapped_is_not_saved(monkeypatch):
    """The rewrap overwrites the only wrapped copy, so an unusable one must never replace it."""
    dek = _make_dek()
    before = bytes(dek.encrypted_keyset)
    adapter = get_engine().silo_kms_adapter
    original = type(adapter).encrypt_key

    def encrypt_key(self, plaintext, silo_uid):
        _ciphertext, metadata = original(self, plaintext, silo_uid)
        return b"not a wrapped key", metadata

    monkeypatch.setattr(type(adapter), "encrypt_key", encrypt_key)

    output = _run_expecting_one_failure()

    assert "Failed: 1" in output
    assert "[kek_unavailable]" in output
    _assert_old_wrap_kept(dek, before)


@pytest.mark.django_db
def test_a_new_wrap_of_different_key_material_is_not_saved(monkeypatch, caplog):
    dek = _make_dek()
    before = bytes(dek.encrypted_keyset)
    adapter = get_engine().silo_kms_adapter
    original = type(adapter).encrypt_key

    def encrypt_key(self, plaintext, silo_uid):
        return original(self, plaintext + b"!", silo_uid)

    monkeypatch.setattr(type(adapter), "encrypt_key", encrypt_key)

    with caplog.at_level("ERROR", logger="encryption_suite"):
        output = _run_expecting_one_failure()

    assert "Failed: 1" in output
    (line,) = [r for r in caplog.records if "did not unwrap to the key it was made from" in r.getMessage()]
    assert "error_code=kek_unavailable" in line.getMessage()
    assert line.exc_info is None
    _assert_old_wrap_kept(dek, before)
