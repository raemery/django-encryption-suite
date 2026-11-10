"""Recording what an operator did at the provider, from the KEK changelist.

The three actions attest an act this application did not perform and cannot
verify. Each one is a state change, so a row already standing where the verb
would put it has nothing to record: a second "deleted" appends an attestation at
a later date, reading as a second deletion, while the transition funnel leaves
the row alone — so the ledger and the row would disagree about whether anything
happened.
"""

from __future__ import annotations

import pytest
from django.contrib.admin.sites import AdminSite
from django.contrib.auth.models import User
from django.contrib.messages.storage.fallback import FallbackStorage
from django.test import RequestFactory

from encryption_suite import lifecycle
from encryption_suite.admin_lifecycle import KeyEncryptionKeyAdmin
from encryption_suite.models import KeyEncryptionKey, KeyLifecycleEvent
from tests.factories import make_kek_row


@pytest.fixture
def model_admin():
    return KeyEncryptionKeyAdmin(KeyEncryptionKey, AdminSite())


@pytest.fixture
def post_request():
    request = RequestFactory().post("/admin/")
    request.user = User.objects.create(username="alice", is_staff=True)
    request.session = {}
    request._messages = FallbackStorage(request)
    return request


def _row(name, status=None):
    row = make_kek_row(key_store="fly", kek_resource_name=name)
    if status is not None:
        row.record_event(status, trigger=lifecycle.TRIGGER_DIRECT)
    return row


@pytest.mark.django_db
def test_recording_a_key_already_deleted_records_nothing(model_admin, post_request):
    row = _row("kek-gone", lifecycle.EVENT_DELETED)
    before = KeyLifecycleEvent.objects.filter(kek=row).count()

    model_admin.record_deleted_in_kms(post_request, KeyEncryptionKey.objects.filter(pk=row.pk))

    assert KeyLifecycleEvent.objects.filter(kek=row).count() == before
    row.refresh_from_db()
    assert row.status == lifecycle.STATUS_DELETED


@pytest.mark.django_db
def test_a_selection_records_what_it_can_and_skips_the_rest(model_admin, post_request):
    fresh = _row("kek-live")
    settled = _row("kek-gone", lifecycle.EVENT_DELETED)

    model_admin.record_deleted_in_kms(post_request, KeyEncryptionKey.objects.all())

    assert KeyLifecycleEvent.objects.filter(kek=fresh, event=lifecycle.EVENT_DELETED).count() == 1
    assert KeyLifecycleEvent.objects.filter(kek=settled, event=lifecycle.EVENT_DELETED).count() == 1
    messages = [str(m) for m in post_request._messages]
    assert any("Recorded 1" in m for m in messages)
    assert any("Skipped 1" in m for m in messages)


@pytest.mark.django_db
def test_recording_a_deletion_request_twice_records_once(model_admin, post_request):
    row = _row("kek-requested")

    for _ in range(2):
        model_admin.record_requested_in_kms(post_request, KeyEncryptionKey.objects.filter(pk=row.pk))

    assert KeyLifecycleEvent.objects.filter(kek=row, event=lifecycle.EVENT_DELETION_REQUESTED).count() == 1


@pytest.mark.django_db
def test_recording_a_cancellation_on_an_active_key_records_nothing(model_admin, post_request):
    """``restored`` lands on active, so an active key has nothing to cancel."""
    row = _row("kek-live")

    model_admin.record_restored_in_kms(post_request, KeyEncryptionKey.objects.filter(pk=row.pk))

    assert not KeyLifecycleEvent.objects.filter(kek=row, event=lifecycle.EVENT_RESTORED).exists()


@pytest.mark.django_db
def test_a_cancellation_is_recorded_on_a_key_the_provider_was_deleting(model_admin, post_request):
    row = _row("kek-requested", lifecycle.EVENT_DELETION_REQUESTED)

    model_admin.record_restored_in_kms(post_request, KeyEncryptionKey.objects.filter(pk=row.pk))

    assert KeyLifecycleEvent.objects.filter(kek=row, event=lifecycle.EVENT_RESTORED).count() == 1
    row.refresh_from_db()
    assert row.status == lifecycle.STATUS_ACTIVE
