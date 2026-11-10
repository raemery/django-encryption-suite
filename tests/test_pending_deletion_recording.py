"""A provider-reported pending deletion outlives the request that discovered it.

`ensure_kek` reads the key's state to refuse it, so the fact is already in hand.
Recording it means the key's row stops claiming `active` until someone reproduces
the failure — and reconcile can start flagging it as overdue drift once the
provider's date passes.
"""

from __future__ import annotations

import datetime

import pytest
from django.utils import timezone

from encryption_suite import lifecycle
from encryption_suite.adapters.keks.provisioners import AbstractKekProvisioner
from encryption_suite.exceptions import KekPendingDeletionError
from encryption_suite.models import KeyEncryptionKey, KeyLifecycleEvent
from encryption_suite.registry import get_engine
from tests.factories import make_kek_row

_EFFECTIVE = datetime.datetime(2026, 8, 4, tzinfo=datetime.UTC)


class _PendingProvisioner(AbstractKekProvisioner):
    def __init__(self):
        super().__init__({})

    def ensure_kek(self, kek_resource_name, silo_ref):
        raise KekPendingDeletionError(
            f"FakeProvisioner: KEK '{kek_resource_name}' is scheduled for deletion. "
            "Cancel the deletion at the provider (`aws kms cancel-key-deletion`).",
            effective_at=_EFFECTIVE,
        )

    def describe(self):
        return "FakeProvisioner"


@pytest.fixture
def pending(monkeypatch):
    monkeypatch.setattr("encryption_suite.registry.get_kek_provisioner", lambda name=None: _PendingProvisioner())
    return get_engine()


@pytest.mark.django_db
def test_records_deletion_requested_with_the_providers_date(pending, tenant):
    with pytest.raises(KekPendingDeletionError):
        pending.generate_and_store_keyset(tenant)

    row = KeyEncryptionKey.objects.get()
    assert row.status == lifecycle.STATUS_DELETION_REQUESTED
    assert row.kms_deletion_at == _EFFECTIVE
    event = row.events.get(event=lifecycle.EVENT_DELETION_REQUESTED)
    # Not our act and not machine-verified by us — only observed.
    assert event.reason == KeyLifecycleEvent.REASON_OBSERVED_AT_PROVIDER


@pytest.mark.django_db
def test_repeated_attempts_do_not_append_an_event_each_time(pending, tenant):
    for _ in range(3):
        with pytest.raises(KekPendingDeletionError):
            pending.generate_and_store_keyset(tenant)

    row = KeyEncryptionKey.objects.get()
    assert row.events.filter(event=lifecycle.EVENT_DELETION_REQUESTED).count() == 1


@pytest.mark.django_db
def test_the_error_stays_catchable_as_kek_not_provisioned(pending, tenant):
    from encryption_suite.exceptions import KekNotProvisionedError

    with pytest.raises(KekNotProvisionedError):
        pending.generate_and_store_keyset(tenant)


@pytest.mark.django_db
def test_operator_message_is_generic_and_detail_is_operator_text(pending, tenant, caplog):
    with caplog.at_level("ERROR", logger="encryption_suite.engine"), pytest.raises(KekPendingDeletionError) as excinfo:
        pending.generate_and_store_keyset(tenant)

    exc = excinfo.value
    assert "cancel-key-deletion" not in str(exc)
    # The excellent operator line survives, under the more precise slug.
    line = next(r.getMessage() for r in caplog.records if "kek_pending_deletion" in r.getMessage())
    assert "cancel-key-deletion" in line
    assert "scheduled for deletion" in line


@pytest.mark.django_db
def test_a_restore_can_be_recorded_by_an_operator(db):
    """The counterpart act: someone canceled the deletion in the KMS."""
    row = make_kek_row(key_store="local", kek_resource_name="kek-1")
    row.record_event(
        lifecycle.EVENT_DELETION_REQUESTED, trigger=lifecycle.TRIGGER_DIRECT, kms_deletion_at=timezone.now()
    )

    KeyLifecycleEvent.record_by_operator(row, lifecycle.EVENT_RESTORED, os_login_user="alice (uid 1000)")

    row.refresh_from_db()
    assert row.status == lifecycle.STATUS_ACTIVE
    event = row.events.filter(event=lifecycle.EVENT_RESTORED).latest("created_at")
    # Pinned as an attestation, never mistaken for machine evidence.
    assert event.reason == KeyLifecycleEvent.REASON_RECORDED_BY_OPERATOR


@pytest.mark.django_db
def test_the_test_console_records_it_too(pending, monkeypatch, caplog):
    """The console provisions through the same funnel, so it records the same fact.

    Found live on Azure: the console called the provisioner directly, so a
    refusal left no row state and no log line — only the exception class name in
    the audit trail. The console reaching for its own copy of the call was the
    defect; sharing the funnel is the fix.
    """
    import logging

    from encryption_suite import test_console as tc
    from encryption_suite.registry import get_kms_adapter

    provisioner = _PendingProvisioner()
    with caplog.at_level(logging.ERROR, logger="encryption_suite.engine"):
        with pytest.raises(KekPendingDeletionError):
            tc.full_aead_roundtrip(get_kms_adapter(), provisioner, b"payload")

    row = KeyEncryptionKey.objects.get()
    assert row.status == lifecycle.STATUS_DELETION_REQUESTED
    assert row.kms_deletion_at == _EFFECTIVE
    assert any("error_code=kek_pending_deletion" in r.getMessage() for r in caplog.records)
