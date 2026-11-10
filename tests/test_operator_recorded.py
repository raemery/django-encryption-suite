"""Tests for operator-recorded ledger entries.

Covers the shared writer ``KeyLifecycleEvent.record_by_operator`` (the single entry
point behind both the ``record_key_event`` command and the KMS Keys admin
actions) and the command itself. The cardinal property under test: a manual
record is always marked with the stable ``recorded_by_operator`` reason and an
actor, so it can never be mistaken for a tooling-verified event. Recording is
row-first — the durable :class:`KeyEncryptionKey` row exists before its event.
"""

from __future__ import annotations

import os

import pytest
from django.core.management import call_command
from django.core.management.base import CommandError

from encryption_suite import lifecycle
from encryption_suite.models import KeyEncryptionKey, KeyLifecycleEvent
from tests.factories import make_kek_row, make_user

_KEK = "alias/es-prod-team-9"


def _kek(name=_KEK, provider="fly"):
    return make_kek_row(
        key_store=provider,
        kek_resource_name=name,
    )


@pytest.mark.django_db
class TestRecordOutOfBand:
    def test_records_a_deleted_kek_event(self):
        row = _kek()
        alice = make_user("alice")
        ev = KeyLifecycleEvent.record_by_operator(row, lifecycle.EVENT_DELETED, user=alice)
        assert ev.event == lifecycle.EVENT_DELETED
        assert ev.key_kind == lifecycle.KIND_KEY_ENCRYPTION_KEY
        assert ev.kek_id == row.pk
        assert ev.user_id == alice.pk
        assert ev.trigger == lifecycle.TRIGGER_DIRECT
        assert ev.reason == KeyLifecycleEvent.REASON_RECORDED_BY_OPERATOR
        assert ev.kek_resource_name == _KEK

    def test_caller_supplied_reason_is_ignored(self):
        # The reason is owned by the writer — a caller cannot disguise a manual
        # record as something else by passing its own reason.
        row = _kek()
        ev = KeyLifecycleEvent.record_by_operator(
            row, lifecycle.EVENT_DELETED, user=make_user("alice"), reason="tooling_verified"
        )
        assert ev.reason == KeyLifecycleEvent.REASON_RECORDED_BY_OPERATOR

    def test_records_a_scheduled_deletion_with_effective_date(self):
        import datetime as dt

        from django.utils import timezone

        row = _kek()
        when = timezone.make_aware(dt.datetime(2026, 7, 10))
        ev = KeyLifecycleEvent.record_by_operator(
            row, lifecycle.EVENT_DELETION_SCHEDULED, user=make_user("alice"), undeletable_until=when
        )
        assert ev.event == lifecycle.EVENT_DELETION_SCHEDULED
        assert ev.effective_at == when
        assert ev.reason == KeyLifecycleEvent.REASON_RECORDED_BY_OPERATOR

    def test_non_manual_verb_is_rejected(self):
        # deletion_failed / re-encryption are tooling-internal, never manual acts.
        row = _kek()
        with pytest.raises(ValueError):
            KeyLifecycleEvent.record_by_operator(row, lifecycle.EVENT_DELETION_FAILED, user=make_user("alice"))

    def test_an_attestation_with_nobody_attached_is_rejected(self):
        row = _kek()
        with pytest.raises(ValueError):
            KeyLifecycleEvent.record_by_operator(row, lifecycle.EVENT_DELETED)

    def test_an_attestation_is_logged_as_well_as_recorded(self, caplog, settings):
        """The row is the only evidence, so a line beside it is worth having.

        Nothing else in the package witnesses the act: it happened in the
        provider's console, and the application is taking somebody's word.
        """
        import logging

        settings.ENCRYPTION = {**settings.ENCRYPTION, "USER_IDENTITY": {"LOGS": ["user_id", "ip_address"]}}
        row = _kek()
        alice = make_user("alice")
        with caplog.at_level(logging.INFO, logger="encryption_suite.models"):
            KeyLifecycleEvent.record_by_operator(row, lifecycle.EVENT_DELETED, user=alice, user_ip="198.51.100.7")

        line = caplog.records[0].getMessage()
        assert f"event={lifecycle.EVENT_DELETED}" in line
        assert f"user_id={alice.pk}" in line
        assert "ip_address=198.51.100.7" in line
        assert caplog.records[0].levelno == logging.INFO

    def test_an_attestation_with_nothing_listed_lands_unattributed(self, settings):
        """The list is a posture about identities, not about the key event."""
        settings.ENCRYPTION = {**settings.ENCRYPTION, "USER_IDENTITY": {"KEY_LIFECYCLE_EVENTS": []}}
        row = _kek()
        ev = KeyLifecycleEvent.record_by_operator(row, lifecycle.EVENT_DELETED, user=make_user("alice"))
        assert ev.reason == KeyLifecycleEvent.REASON_RECORDED_BY_OPERATOR
        assert (ev.user_id, ev.os_user_id) == (None, None)


@pytest.mark.django_db
class TestRecordKeyEventCommand:
    """The command takes no ``--actor``: the identity is always the OS login
    account of whoever ran it. ``SUDO_USER`` is set here so the recorded value is
    deterministic without reaching for the real password database."""

    @pytest.fixture(autouse=True)
    def _os_user(self, monkeypatch):
        monkeypatch.setenv("SUDO_USER", "alice")

    def test_records_a_kek_deletion(self):
        call_command(
            "record_key_event",
            "--event",
            "deleted",
            "--kek-resource-name",
            _KEK,
            "--key-store",
            "local",
        )
        # Row created in the KMS and recorded by an operator, with its deleted event.
        row = KeyEncryptionKey.objects.get(kek_resource_name=_KEK)
        ev = row.events.get()
        assert ev.event == lifecycle.EVENT_DELETED
        assert str(ev.os_user).startswith("alice → ")
        assert ev.reason == KeyLifecycleEvent.REASON_RECORDED_BY_OPERATOR

    def test_records_a_scheduled_deletion(self):
        call_command(
            "record_key_event",
            "--event",
            "deletion_scheduled",
            "--kek-resource-name",
            _KEK,
            "--key-store",
            "local",
        )
        assert KeyLifecycleEvent.objects.get().event == lifecycle.EVENT_DELETION_SCHEDULED

    def test_kms_defaults_to_silo_kms(self):
        call_command("record_key_event", "--event", "deleted", "--kek-resource-name", _KEK)
        assert KeyEncryptionKey.objects.get(kek_resource_name=_KEK).key_store == "local"

    def test_an_unconfigured_kms_name_is_refused(self):
        # A row naming a KMS no block carries could never be acted on.
        with pytest.raises(CommandError, match="not a configured key store"):
            call_command("record_key_event", "--event", "deleted", "--kek-resource-name", _KEK, "--key-store", "fly")
        assert not KeyEncryptionKey.objects.exists()

    def test_sudo_user_names_the_person_not_the_account_escalated_into(self):
        call_command(
            "record_key_event",
            "--event",
            "created",
            "--kek-resource-name",
            _KEK,
            "--key-store",
            "local",
        )
        assert str(KeyLifecycleEvent.objects.get().os_user).startswith("alice → ")

    @pytest.mark.skipif(os.name != "posix", reason="no password database off POSIX; the value is env-derived there")
    def test_environment_cannot_forge_the_login_account(self, monkeypatch):
        # getpass.getuser() reads USER/LOGNAME first, so it would return "ceo"
        # here. The command reads the password database instead.
        monkeypatch.delenv("SUDO_USER", raising=False)
        monkeypatch.setenv("USER", "ceo")
        monkeypatch.setenv("LOGNAME", "ceo")
        call_command(
            "record_key_event",
            "--event",
            "created",
            "--kek-resource-name",
            _KEK,
            "--key-store",
            "local",
        )
        assert "ceo" not in str(KeyLifecycleEvent.objects.get().os_user)

    def test_an_existing_key_is_reused_rather_than_duplicated(self):
        make_kek_row(key_store="local", kek_resource_name=_KEK)
        call_command(
            "record_key_event",
            "--event",
            "deleted",
            "--kek-resource-name",
            _KEK,
            "--key-store",
            "local",
        )
        assert KeyEncryptionKey.objects.filter(kek_resource_name=_KEK).count() == 1

    def test_resource_name_is_required(self):
        with pytest.raises(CommandError):
            call_command("record_key_event", "--event", "deleted", "--key-store", "local")
        assert not KeyLifecycleEvent.objects.exists()

    def test_actor_cannot_be_supplied(self):
        # Dropped deliberately: the recorded identity is the account that ran the
        # command, which the deployment can verify. Naming anyone else would be
        # hearsay the ledger cannot stand behind.
        with pytest.raises(CommandError):
            call_command(
                "record_key_event",
                "--event",
                "deleted",
                "--kek-resource-name",
                _KEK,
                "--key-store",
                "local",
                "--actor",
                "alice",
            )

    def test_the_run_closes_on_a_line_saying_whether_the_row_landed(self, caplog):
        with caplog.at_level("INFO", logger="encryption_suite"):
            call_command(
                "record_key_event",
                "--event",
                "deleted",
                "--kek-resource-name",
                _KEK,
                "--key-store",
                "local",
            )

        (line,) = [r.getMessage() for r in caplog.records if "command finished" in r.getMessage()]
        assert f'event=deleted kek="{_KEK}" recorded=1' in line
        assert 'os_user="alice' in line

    def test_a_refused_run_closes_with_nothing_recorded(self, monkeypatch, caplog):
        """The ledger row is this command's record, so a run that wrote none needs the line."""
        monkeypatch.setattr("encryption_suite.user_context.get_os_user", lambda: "")

        with caplog.at_level("INFO", logger="encryption_suite"):
            with pytest.raises(CommandError):
                call_command(
                    "record_key_event",
                    "--event",
                    "deleted",
                    "--kek-resource-name",
                    _KEK,
                    "--key-store",
                    "local",
                )

        (line,) = [r.getMessage() for r in caplog.records if "command finished" in r.getMessage()]
        assert "recorded=0" in line
        assert not KeyLifecycleEvent.objects.exists()
