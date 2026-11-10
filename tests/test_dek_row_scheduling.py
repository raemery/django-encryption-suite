"""Row-scoped scheduling and restore for DataEncryptionKey rows.

The changelist acts on *rows*: scheduling a data encryption key must never
schedule a KMS key. Only a real silo deletion cascades that far, through
``deletion.schedule_deletion``, so that a deleted tenant's exclusive KMS key is
not left stranded on the provider. These tests pin the boundary in both
directions, plus the soft-delete window the schedule writes.
"""

from __future__ import annotations

import datetime

import pytest
from django.utils import timezone

from encryption_suite import lifecycle
from encryption_suite.deletion import restore_dek, schedule_dek_deletion
from encryption_suite.models import DataEncryptionKey, KeyLifecycleEvent
from tests.factories import make_kek, make_kek_row, make_user

_KEK = "alias/es-prod-team-1"


def _make_row(silo_uid="team-1", purpose=DataEncryptionKey.PURPOSE_FIELD):
    return DataEncryptionKey.objects.create(
        key_set="default",
        silo_uid=silo_uid,
        purpose=purpose,
        silo_label="team",
        encrypted_keyset=b"x",
        kek=make_kek(_KEK, "fly"),
    )


@pytest.mark.django_db
def test_schedule_marks_the_row_and_records_who_asked():
    row = _make_row()
    alice = make_user("alice")

    schedule_dek_deletion(row, trigger=lifecycle.TRIGGER_DIRECT, user=alice)

    row.refresh_from_db()
    assert row.status == lifecycle.STATUS_DELETION_SCHEDULED
    assert row.undeletable_until is not None
    event = KeyLifecycleEvent.objects.get(dek=row, event=lifecycle.EVENT_DELETION_SCHEDULED)
    assert event.user_id == alice.pk
    assert event.trigger == lifecycle.TRIGGER_DIRECT


@pytest.mark.django_db
def test_schedule_honors_the_configured_window(settings):
    settings.ENCRYPTION = {**settings.ENCRYPTION, "KEY_DELETION_WINDOW_DAYS": 3}
    row = _make_row()
    before = timezone.now()

    schedule_dek_deletion(row, trigger=lifecycle.TRIGGER_DIRECT)

    row.refresh_from_db()
    delta = row.undeletable_until - before
    assert datetime.timedelta(days=3) <= delta <= datetime.timedelta(days=3, minutes=1)


@pytest.mark.django_db
def test_schedule_never_touches_a_kek():
    # The whole point of the row-scoped path: an operator scheduling one key row
    # must not drag the KMS key along, however the disposition is configured.
    kek = make_kek_row(key_store="fly", kek_resource_name=_KEK)
    row = _make_row()

    schedule_dek_deletion(row, trigger=lifecycle.TRIGGER_DIRECT, user=make_user("alice"))

    kek.refresh_from_db()
    assert kek.status == lifecycle.STATUS_ACTIVE
    assert kek.undeletable_until is None
    assert not KeyLifecycleEvent.objects.filter(kek=kek).exists()


@pytest.mark.django_db
def test_schedule_leaves_the_silos_other_rows_alone():
    field_row = _make_row(purpose=DataEncryptionKey.PURPOSE_FIELD)
    file_row = _make_row(purpose=DataEncryptionKey.PURPOSE_FILE)

    schedule_dek_deletion(field_row, trigger=lifecycle.TRIGGER_DIRECT, user=make_user("alice"))

    file_row.refresh_from_db()
    assert file_row.status == lifecycle.STATUS_ACTIVE


@pytest.mark.django_db
def test_restore_reverses_exactly_what_was_scheduled():
    kek = make_kek_row(key_store="fly", kek_resource_name=_KEK)
    row = _make_row()
    schedule_dek_deletion(row, trigger=lifecycle.TRIGGER_DIRECT, user=make_user("alice"))

    restore_dek(row, trigger=lifecycle.TRIGGER_DIRECT, user=make_user("bob"))

    row.refresh_from_db()
    kek.refresh_from_db()
    assert row.status == lifecycle.STATUS_ACTIVE
    assert row.undeletable_until is None
    assert kek.status == lifecycle.STATUS_ACTIVE
    assert KeyLifecycleEvent.objects.filter(dek=row, event=lifecycle.EVENT_RESTORED).exists()


@pytest.mark.django_db
def test_the_admin_reads_who_scheduled_from_the_ledger():
    """There is one record of who acted, and the key row is not a second copy.

    The row used to carry the name in a column of its own, filled beside the
    ledger event that already held it. Two records of one act can part, and that
    one stored a decrypted username as text where the ledger stores a reference.
    """
    from django.contrib.admin.sites import AdminSite

    from encryption_suite.admin import DataEncryptionKeyAdmin

    row = _make_row()
    model_admin = DataEncryptionKeyAdmin(DataEncryptionKey, AdminSite())
    assert model_admin.scheduled_deletion_by(row) == ""

    schedule_dek_deletion(row, trigger=lifecycle.TRIGGER_DIRECT, user=make_user("alice"))

    assert model_admin.scheduled_deletion_by(row) == "alice"
