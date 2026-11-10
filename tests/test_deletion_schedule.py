"""Tests for ``schedule_deletion`` / ``restore_deletion`` — the soft-delete window.

Scheduling flips a silo's DEK rows (and any silo-exclusive KEK) to
``deletion_scheduled`` inside the window without destroying anything; restore
reverses it. Covers disposition branching, the PURPOSE_TEST skip, idempotency,
the audit marker, and the error funnel.
"""

from __future__ import annotations

import logging

import pytest

from encryption_suite import lifecycle
from encryption_suite.deletion import restore_deletion, schedule_deletion
from encryption_suite.exceptions import EncryptionConfigurationError, KekDeletionRecordError
from encryption_suite.models import DataEncryptionKey, KeyEncryptionKey
from encryption_suite.silo_ref import SiloRef
from tests.factories import make_kek

_PROVIDER = "fly"
_PREFIX = "kek_"


class _FakeStrategy:
    def __init__(self, *, disposition=KeyEncryptionKey.DISPOSITION_SILO_EXCLUSIVE, owner_prefix=_PREFIX, raises=None):
        self._disposition = disposition
        self._owner_prefix = owner_prefix
        self._raises = raises

    def kek_disposition(self, silo_uid):
        if self._raises is not None:
            raise self._raises
        return self._disposition

    def owner_prefix(self):
        return self._owner_prefix


@pytest.fixture
def patch_strategy(monkeypatch, configured_kms):
    def _apply(strategy):
        configured_kms(_PROVIDER, silo_kms=False)
        monkeypatch.setattr("encryption_suite.registry.get_kek_strategy_adapter", lambda name=None: strategy)

    return _apply


def _make_dek_row(uid, purpose=DataEncryptionKey.PURPOSE_FIELD):
    return DataEncryptionKey.objects.create(
        key_set="default",
        silo_uid=uid,
        purpose=purpose,
        silo_label="team",
        encrypted_keyset=b"x",
        kek=make_kek(_PREFIX + uid, _PROVIDER),
    )


@pytest.mark.django_db
def test_schedules_dek_and_silo_exclusive_kek(patch_strategy):
    patch_strategy(_FakeStrategy())
    _make_dek_row("team1", DataEncryptionKey.PURPOSE_FIELD)
    _make_dek_row("team1", DataEncryptionKey.PURPOSE_FILE)

    scheduled = schedule_deletion(SiloRef("default", "team1"))

    # Two DEK rows + one KMS key (both DEKs share the same KEK).
    assert len(scheduled) == 3
    deks = DataEncryptionKey.objects.filter(silo_uid="team1")
    assert {d.status for d in deks} == {lifecycle.STATUS_DELETION_SCHEDULED}
    assert all(d.undeletable_until is not None for d in deks)
    # Material is untouched — scheduling destroys nothing.
    assert all(bytes(d.encrypted_keyset) == b"x" for d in deks)

    kek = KeyEncryptionKey.objects.get(key_store=_PROVIDER, kek_resource_name=_PREFIX + "team1")
    assert kek.status == lifecycle.STATUS_DELETION_SCHEDULED
    assert kek.disposition == KeyEncryptionKey.DISPOSITION_SILO_EXCLUSIVE
    assert kek.owner_prefix == _PREFIX
    # A scheduled event was recorded on each row.
    assert kek.events.filter(event=lifecycle.EVENT_DELETION_SCHEDULED).exists()


@pytest.mark.django_db
def test_shared_disposition_schedules_dek_only(patch_strategy):
    patch_strategy(_FakeStrategy(disposition=KeyEncryptionKey.DISPOSITION_SHARED, owner_prefix=None))
    _make_dek_row("team1")

    scheduled = schedule_deletion(SiloRef("default", "team1"))

    # Only the DEK row — a shared KEK is never scheduled by one silo's deletion.
    # Its row exists either way (the data key references it); what matters is
    # that the row is left active.
    assert len(scheduled) == 1
    kek = KeyEncryptionKey.objects.get(kek_resource_name=_PREFIX + "team1")
    assert kek.status == lifecycle.STATUS_ACTIVE
    dek = DataEncryptionKey.objects.get(silo_uid="team1")
    assert dek.status == lifecycle.STATUS_DELETION_SCHEDULED


@pytest.mark.django_db
def test_no_active_rows_returns_empty(patch_strategy):
    patch_strategy(_FakeStrategy())
    assert schedule_deletion(SiloRef("default", "ghost")) == []


@pytest.mark.django_db
def test_purpose_test_rows_are_skipped(patch_strategy):
    patch_strategy(_FakeStrategy())
    _make_dek_row("team1", DataEncryptionKey.PURPOSE_TEST)

    assert schedule_deletion(SiloRef("default", "team1")) == []
    dek = DataEncryptionKey.objects.get(silo_uid="team1")
    assert dek.status == lifecycle.STATUS_ACTIVE


@pytest.mark.django_db
def test_idempotent_no_reschedule(patch_strategy):
    patch_strategy(_FakeStrategy())
    _make_dek_row("team1")

    first = schedule_deletion(SiloRef("default", "team1"))
    second = schedule_deletion(SiloRef("default", "team1"))

    assert len(first) == 2  # DEK + KEK
    assert second == []  # already scheduled — nothing re-touched


@pytest.mark.django_db
def test_already_scheduled_kek_is_still_annotated_as_orphaned(patch_strategy):
    """A KEK scheduled by another path first, whose silo is then deleted.

    Scheduling and the orphan observation are independent facts, and the status
    guard governs only the first. Skipping both left the row reading
    ``deletion_scheduled`` beside ``is_orphaned = False`` — two columns
    contradicting each other, with no ledger event explaining the flag — until
    the next reconcile happened to run.
    """
    patch_strategy(_FakeStrategy())
    _make_dek_row("team1")
    kek = KeyEncryptionKey.objects.get(kek_resource_name=_PREFIX + "team1")
    # Scheduled directly, while the silo is still alive: not an orphan yet.
    kek.status = lifecycle.STATUS_DELETION_SCHEDULED
    kek.save(update_fields=["status"])
    assert kek.is_orphaned is False

    schedule_deletion(SiloRef("default", "team1"))

    kek.refresh_from_db()
    assert kek.is_orphaned is True
    assert kek.events.filter(event=lifecycle.EVENT_SILO_NOT_FOUND).count() == 1
    # Still scheduled exactly once — the guard did its real job.
    assert kek.events.filter(event=lifecycle.EVENT_DELETION_SCHEDULED).count() == 0
    assert kek.status == lifecycle.STATUS_DELETION_SCHEDULED


@pytest.mark.django_db
def test_already_orphaned_kek_is_not_reannotated(patch_strategy):
    """The annotation moves only when the answer changes, on this path too."""
    patch_strategy(_FakeStrategy())
    _make_dek_row("team1")
    kek = KeyEncryptionKey.objects.get(kek_resource_name=_PREFIX + "team1")
    kek.status = lifecycle.STATUS_DELETION_SCHEDULED
    kek.is_orphaned = True
    kek.save(update_fields=["status", "is_orphaned"])

    schedule_deletion(SiloRef("default", "team1"))

    kek.refresh_from_db()
    assert kek.events.filter(event=lifecycle.EVENT_SILO_NOT_FOUND).count() == 0


@pytest.mark.django_db
def test_restore_reverses_both_sides(patch_strategy):
    patch_strategy(_FakeStrategy())
    _make_dek_row("team1")
    schedule_deletion(SiloRef("default", "team1"))

    restored = restore_deletion(SiloRef("default", "team1"), trigger=lifecycle.TRIGGER_DIRECT)

    assert len(restored) == 2  # DEK + KEK
    dek = DataEncryptionKey.objects.get(silo_uid="team1")
    assert dek.status == lifecycle.STATUS_ACTIVE
    assert dek.undeletable_until is None
    kek = KeyEncryptionKey.objects.get(kek_resource_name=_PREFIX + "team1")
    assert kek.status == lifecycle.STATUS_ACTIVE
    assert dek.events.filter(event=lifecycle.EVENT_RESTORED).exists()


@pytest.mark.django_db
def test_success_logs_the_scheduling(patch_strategy, caplog):
    patch_strategy(_FakeStrategy())
    _make_dek_row("team1")

    with caplog.at_level(logging.INFO, logger="encryption_suite.deletion"):
        schedule_deletion(SiloRef("default", "team1"))

    assert "event=deletion_scheduled" in caplog.text
    assert 'silo="default:team1"' in caplog.text


@pytest.mark.django_db
def test_raw_error_funnels_to_typed_error_with_clean_log(patch_strategy, caplog):
    patch_strategy(_FakeStrategy(raises=RuntimeError("db exploded")))
    _make_dek_row("team1")

    with caplog.at_level(logging.ERROR, logger="encryption_suite.deletion"):
        with pytest.raises(KekDeletionRecordError) as ei:
            schedule_deletion(SiloRef("default", "team1"))

    assert isinstance(ei.value.__cause__, RuntimeError)
    assert "error_code=kek_deletion_record_failed" in caplog.text
    record = next(r for r in caplog.records if "error_code=kek_deletion_record_failed" in r.getMessage())
    assert record.exc_info is None  # logger.error, not logger.exception — no traceback


@pytest.mark.django_db
def test_typed_error_passes_through_untouched(patch_strategy):
    patch_strategy(_FakeStrategy(raises=EncryptionConfigurationError("bad config")))
    _make_dek_row("team1")

    with pytest.raises(EncryptionConfigurationError):
        schedule_deletion(SiloRef("default", "team1"))


@pytest.mark.django_db
def test_scheduling_logs_at_warning(patch_strategy, caplog):
    """The schedule is the last notice before material can be destroyed.

    Production log levels commonly cut INFO, and the soft-delete window exists so
    someone can intervene — an event nobody sees cannot be intervened on. By the
    time the shred logs, the moment to act has passed.
    """
    import logging

    patch_strategy(_FakeStrategy(disposition=KeyEncryptionKey.DISPOSITION_SILO_EXCLUSIVE, owner_prefix=_PREFIX))
    _make_dek_row("team1")

    with caplog.at_level(logging.WARNING, logger="encryption_suite.deletion"):
        schedule_deletion(SiloRef("default", "team1"))

    line = next(r for r in caplog.records if "event=deletion_scheduled" in r.getMessage())
    assert line.levelno == logging.WARNING
