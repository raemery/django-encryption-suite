"""The data-encryption-key half of KEY_DELETION_CAN_RENDER_DATA_INACCESSIBLE.

Shredding a keyset is irreversible and has no provider window behind it, so by
default the purge refuses when the silo it belongs to still exists — or when the
silo adapter cannot say whether it does. Refusing on *cannot say* is deliberate:
the alternative is destroying data on a question nobody answered.

The three refusals are named apart because the remedies differ — delete the silo,
implement ``silo_exists()``, or fix whatever raised.
"""

from __future__ import annotations

import datetime

import pytest
from django.conf import settings
from django.test import override_settings
from django.utils import timezone

from encryption_suite import lifecycle
from encryption_suite.deletion import (
    RETAIN_SILO_CHECK_FAILED,
    RETAIN_SILO_LIVE,
    RETAIN_SILO_UNKNOWN,
    purge_expired_deks,
)
from encryption_suite.models import DataEncryptionKey
from tests.factories import make_kek, make_user

_PAST = timezone.now() - datetime.timedelta(days=1)


class _Adapter:
    """Silo adapter stub answering only what the gate asks."""

    prevents_key_delete = False

    def __init__(self, answer):
        self._answer = answer

    def silo_exists(self, silo_uid):
        if isinstance(self._answer, Exception):
            raise self._answer
        return self._answer


@pytest.fixture
def silo_answer(monkeypatch):
    def _apply(answer):
        monkeypatch.setattr("encryption_suite.registry.get_silo_adapter", lambda key_set="default": _Adapter(answer))

    return _apply


def _allow_data_loss(value=True):
    return override_settings(ENCRYPTION={**settings.ENCRYPTION, "KEY_DELETION_CAN_RENDER_DATA_INACCESSIBLE": value})


def _scheduled_dek(uid="team-1"):
    row = DataEncryptionKey.objects.create(
        key_set="default",
        silo_uid=uid,
        purpose=DataEncryptionKey.PURPOSE_FIELD,
        silo_label="team",
        encrypted_keyset=b"wrapped-dek",
        kek=make_kek("kek_" + uid, "local"),
    )
    row.record_event(lifecycle.EVENT_DELETION_SCHEDULED, trigger=lifecycle.TRIGGER_DIRECT, undeletable_until=_PAST)
    return row


@pytest.mark.django_db
class TestGateRefuses:
    def test_a_live_silo_blocks_the_shred(self, silo_answer):
        silo_answer(True)
        row = _scheduled_dek()

        summary = purge_expired_deks(trigger=lifecycle.TRIGGER_DIRECT)

        row.refresh_from_db()
        assert bytes(row.encrypted_keyset) == b"wrapped-dek"
        assert summary.purged == 0
        assert summary.retained == 1
        assert summary.retain_reasons == {RETAIN_SILO_LIVE}

    def test_an_unanswerable_adapter_blocks_the_shred(self, silo_answer):
        # A composite or custom adapter with neither iter_silos nor silo_exists.
        silo_answer(None)
        row = _scheduled_dek()

        summary = purge_expired_deks(trigger=lifecycle.TRIGGER_DIRECT)

        row.refresh_from_db()
        assert bytes(row.encrypted_keyset) == b"wrapped-dek"
        assert summary.retain_reasons == {RETAIN_SILO_UNKNOWN}

    def test_a_raising_adapter_is_reported_apart_from_cannot_say(self, silo_answer):
        # Transient failure, not a capability limit: worth retrying, not code.
        silo_answer(RuntimeError("database is down"))
        row = _scheduled_dek()

        summary = purge_expired_deks(trigger=lifecycle.TRIGGER_DIRECT)

        row.refresh_from_db()
        assert bytes(row.encrypted_keyset) == b"wrapped-dek"
        assert summary.retain_reasons == {RETAIN_SILO_CHECK_FAILED}

    def test_a_refusal_leaves_the_row_retryable(self, silo_answer):
        """Every refusal on this side is transient — a live silo, or an adapter
        that could not answer — so the row stays scheduled for the next run."""
        silo_answer(True)
        row = _scheduled_dek()

        purge_expired_deks(trigger=lifecycle.TRIGGER_DIRECT)

        row.refresh_from_db()
        assert row.status == lifecycle.STATUS_DELETION_SCHEDULED

    def test_a_refusal_is_recorded_in_the_ledger(self, silo_answer):
        """The attempt is a fact even though the status does not move: without it,
        nothing distinguishes a key nobody tried to destroy from one refused
        repeatedly."""
        silo_answer(True)
        row = _scheduled_dek()

        purge_expired_deks(trigger=lifecycle.TRIGGER_DIRECT, user=make_user("alice"))

        event = row.events.get(event=lifecycle.EVENT_DELETION_FAILED)
        assert event.reason == RETAIN_SILO_LIVE
        assert event.user_id is not None

    def test_a_raising_adapter_logs_a_warning(self, silo_answer, caplog):
        import logging

        silo_answer(RuntimeError("database is down"))
        _scheduled_dek()

        with caplog.at_level(logging.WARNING, logger="encryption_suite.deletion"):
            purge_expired_deks(trigger=lifecycle.TRIGGER_DIRECT)

        assert "reason=silo_check_failed" in caplog.text
        assert "Traceback" not in caplog.text  # one clean line, no stack into the package


@pytest.mark.django_db
class TestGatePasses:
    def test_a_deleted_silo_shreds_normally(self, silo_answer):
        """The ordinary teardown path: the silo is gone, so nothing is at risk."""
        silo_answer(False)
        row = _scheduled_dek()

        summary = purge_expired_deks(trigger=lifecycle.TRIGGER_DIRECT)

        row.refresh_from_db()
        assert bytes(row.encrypted_keyset) == b""
        assert summary.purged == 1
        assert summary.retained == 0

    def test_the_setting_skips_the_gate_entirely(self, silo_answer):
        """The erasure case: make live data unreadable, keep the record."""
        silo_answer(True)
        row = _scheduled_dek()

        with _allow_data_loss():
            summary = purge_expired_deks(trigger=lifecycle.TRIGGER_DIRECT)

        row.refresh_from_db()
        assert bytes(row.encrypted_keyset) == b""
        assert summary.purged == 1

    def test_the_setting_also_covers_an_unanswerable_adapter(self, silo_answer):
        silo_answer(None)
        row = _scheduled_dek()

        with _allow_data_loss():
            purge_expired_deks(trigger=lifecycle.TRIGGER_DIRECT)

        row.refresh_from_db()
        assert bytes(row.encrypted_keyset) == b""


@pytest.mark.django_db
class TestDryRun:
    def test_preview_reports_the_refusal_and_its_reason(self, silo_answer):
        silo_answer(True)
        _scheduled_dek()

        summary = purge_expired_deks(trigger=lifecycle.TRIGGER_DIRECT, dry_run=True)

        assert [(verb, reason) for verb, _label, reason in summary.details] == [("RETAIN", RETAIN_SILO_LIVE)]
        assert summary.purged == 0

    def test_preview_agrees_with_the_real_run(self, silo_answer):
        silo_answer(False)
        _scheduled_dek()

        preview = purge_expired_deks(trigger=lifecycle.TRIGGER_DIRECT, dry_run=True)
        real = purge_expired_deks(trigger=lifecycle.TRIGGER_DIRECT)

        assert [verb for verb, _label, _reason in preview.details] == ["SHRED"]
        assert preview.purged == real.purged == 1


@pytest.mark.django_db
def test_a_typed_error_is_not_logged_twice(silo_answer, caplog):
    """A silo adapter that cannot enumerate raises SiloEnumerationError, which the
    helper that raised it already logged with its own slug. One failure, one line."""
    import logging

    from encryption_suite.exceptions import SiloEnumerationError

    silo_answer(SiloEnumerationError("cannot enumerate"))
    _scheduled_dek()

    with caplog.at_level(logging.WARNING, logger="encryption_suite.deletion"):
        summary = purge_expired_deks(trigger=lifecycle.TRIGGER_DIRECT)

    assert summary.retain_reasons == {RETAIN_SILO_CHECK_FAILED}
    assert "could not say whether this silo still exists" not in caplog.text
