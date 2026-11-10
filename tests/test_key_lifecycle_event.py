"""Tests for the KeyLifecycleEvent record.

Covers the creation-event emits (``created`` from the engine, ``reencrypted``
from ``reencrypt_keys``), the create-only guard, the always-present timestamp,
and who an admin-initiated purge records. Uses the configured test engine
(auth.Group silo, the suite's "local" KMS block with its one shared KEK).
"""

from __future__ import annotations

import datetime

import pytest
from django.contrib.auth.models import Group
from django.core.management import call_command
from django.utils import timezone

from encryption_suite import deletion, lifecycle
from encryption_suite.adapters.keks.provisioners import AbstractKekProvisioner, DeleteOutcome
from encryption_suite.engine import EncryptionEngine
from encryption_suite.models import DataEncryptionKey, KeyEncryptionKey, KeyLifecycleEvent
from encryption_suite.registry import get_engine
from encryption_suite.silo_ref import SiloRef
from tests.factories import make_kek, make_kek_row, make_user

_PAST = timezone.now() - datetime.timedelta(days=1)


@pytest.fixture(autouse=True)
def _clear_cache():
    EncryptionEngine.invalidate_cache()
    yield
    EncryptionEngine.invalidate_cache()


def _uid(silo):
    """Silo UID as the configured adapter formats it (e.g. 'group-1')."""
    return get_engine().silo_adapter.get_silo_uid(silo)


@pytest.mark.django_db
def test_generate_and_store_keyset_emits_dek_created():
    g = Group.objects.create(name="acme")
    get_engine().generate_and_store_keyset(g)

    ev = KeyLifecycleEvent.objects.get(silo_uid=_uid(g), event=lifecycle.EVENT_CREATED, dek__isnull=False)
    assert ev.key_kind == lifecycle.KIND_DATA_ENCRYPTION_KEY
    assert ev.dek.purpose == DataEncryptionKey.PURPOSE_FIELD
    assert ev.user_id is None  # ambient provision names nobody under the default scope
    assert ev.trigger == lifecycle.TRIGGER_INDIRECT
    assert ev.reason == lifecycle.REASON_SILO_CREATED
    assert ev.created_at is not None  # timestamp always captured


@pytest.mark.django_db
def test_dek_created_emitted_only_on_create():
    g = Group.objects.create(name="acme")
    eng = get_engine()
    eng.generate_and_store_keyset(g)
    eng.generate_and_store_keyset(g)  # finds the active key and stores nothing

    assert (
        KeyLifecycleEvent.objects.filter(silo_uid=_uid(g), event=lifecycle.EVENT_CREATED, dek__isnull=False).count()
        == 1
    )


@pytest.mark.django_db
def test_reencrypt_emits_dek_rewrapped():
    g = Group.objects.create(name="acme")
    get_engine().generate_and_store_keyset(g)

    call_command("reencrypt_keys")

    assert KeyLifecycleEvent.objects.filter(silo_uid=_uid(g), event=lifecycle.EVENT_REENCRYPTED).exists()


@pytest.mark.django_db
def test_dek_created_captures_the_current_user(settings):
    """Under all_acts, an ambient creation names the user the request set."""
    from encryption_suite.user_context import override_current_user

    settings.ENCRYPTION = {
        **settings.ENCRYPTION,
        "USER_IDENTITY": {"SCOPE": "all_acts", "KEY_LIFECYCLE_EVENTS": ["user_id"]},
    }
    bob = make_user("bob")
    g = Group.objects.create(name="acme")
    with override_current_user(bob.pk):
        get_engine().generate_and_store_keyset(g)

    ev = KeyLifecycleEvent.objects.get(silo_uid=_uid(g), event=lifecycle.EVENT_CREATED, dek__isnull=False)
    assert ev.user_id == bob.pk


@pytest.mark.django_db
def test_the_default_scope_records_no_ambient_user():
    """Under `privileged_acts`, a populated context still attributes nobody."""
    from encryption_suite.user_context import override_current_user

    bob = make_user("bob")
    g = Group.objects.create(name="acme")
    with override_current_user(bob.pk):
        get_engine().generate_and_store_keyset(g)

    ev = KeyLifecycleEvent.objects.get(silo_uid=_uid(g), event=lifecycle.EVENT_CREATED, dek__isnull=False)
    assert ev.user_id is None


@pytest.mark.django_db
def test_an_empty_list_records_no_identity_at_all(settings):
    from encryption_suite.user_context import override_current_user

    settings.ENCRYPTION = {
        **settings.ENCRYPTION,
        "USER_IDENTITY": {"SCOPE": "all_acts", "KEY_LIFECYCLE_EVENTS": []},
    }
    bob = make_user("bob")
    g = Group.objects.create(name="acme")
    with override_current_user(bob.pk, "203.0.113.9"):
        get_engine().generate_and_store_keyset(g)

    ev = KeyLifecycleEvent.objects.get(silo_uid=_uid(g), event=lifecycle.EVENT_CREATED, dek__isnull=False)
    assert (ev.user_id, ev.os_user_id, ev.ip_address_id) == (None, None, None)


class _FakeDeleteProvisioner(AbstractKekProvisioner):
    supports_delete = True

    def __init__(self):
        super().__init__({})

    def ensure_kek(self, kek_resource_name, silo_ref):  # pragma: no cover
        pass

    def _do_delete_kek(self, kek_resource_name, silo_ref):
        # Immediate provider (Fly-style): the delete is confirmed at once.
        return DeleteOutcome(scheduled=False, effective_at=datetime.datetime(2026, 6, 20, tzinfo=datetime.UTC))


def _schedule_expired_pair(uid, *, user=None):
    """Create an expired-window DEK + its silo-exclusive KMS key, both scheduled."""
    sek = DataEncryptionKey.objects.create(
        key_set="default",
        silo_uid=uid,
        purpose=DataEncryptionKey.PURPOSE_FIELD,
        silo_label="team",
        encrypted_keyset=b"x",
        kek=make_kek(f"kek_{uid}", "fly"),
    )
    sek.record_event(
        lifecycle.EVENT_DELETION_SCHEDULED, trigger=lifecycle.TRIGGER_DIRECT, undeletable_until=_PAST, user=user
    )
    kek = make_kek_row(
        key_store="fly",
        kek_resource_name=f"kek_{uid}",
        disposition=KeyEncryptionKey.DISPOSITION_SILO_EXCLUSIVE,
        owner_prefix="kek_",
    )
    kek.record_event(
        lifecycle.EVENT_DELETION_SCHEDULED,
        trigger=lifecycle.TRIGGER_DIRECT,
        undeletable_until=_PAST,
        silo_ref=SiloRef("default", uid),
        user=user,
    )
    return sek, kek


@pytest.fixture
def fly_kms(configured_kms, monkeypatch):
    """Configure the "fly" KMS the expired pairs name, with a provisioner that deletes."""
    configured_kms("fly", silo_kms=False)
    monkeypatch.setattr("encryption_suite.registry.get_kek_provisioner", lambda name=None: _FakeDeleteProvisioner())


@pytest.mark.django_db
def test_purge_records_who_asked(configured_owner_prefix, fly_kms):
    # Admin-initiated purge records who did it on both the KMS-key deletion and
    # the shared-key shred.
    configured_owner_prefix("kek_")
    sek, kek = _schedule_expired_pair("team1")

    alice = make_user("alice")
    deletion.purge_expired_deks(trigger=lifecycle.TRIGGER_DIRECT, user=alice)
    deletion.purge_expired_keks(trigger=lifecycle.TRIGGER_DIRECT, user=alice)

    assert kek.events.get(event=lifecycle.EVENT_DELETED).user_id == alice.pk
    assert sek.events.get(event=lifecycle.EVENT_DELETED).user_id == alice.pk


@pytest.mark.django_db
def test_purge_records_nobody_when_no_identity_is_given(configured_owner_prefix, fly_kms):
    configured_owner_prefix("kek_")
    sek, kek = _schedule_expired_pair("team2")

    deletion.purge_expired_deks(trigger=lifecycle.TRIGGER_DIRECT)
    deletion.purge_expired_keks(trigger=lifecycle.TRIGGER_DIRECT)

    assert kek.events.get(event=lifecycle.EVENT_DELETED).user_id is None  # custom tooling may pass none


@pytest.mark.django_db
def test_first_encrypt_records_a_discovered_kek_event(tenant):
    """Every key encryption key gets a first-sighting entry, whoever created it.

    `discovered` here because the test settings configure no provisioner, so the
    engine did not make this key — it found one already in the KMS. A provisioner
    that reports creating the key records `created` instead.
    """
    get_engine().generate_and_store_keyset(tenant)

    kek = KeyEncryptionKey.objects.get()
    # A set, not a list: both land in the same instant and the ledger orders by
    # timestamp, so their relative order is not deterministic.
    # Born backed: the key is recorded, plus the silo state it is born with.
    assert {e.event for e in kek.events.all()} == {lifecycle.EVENT_DISCOVERED, lifecycle.EVENT_SILO_FOUND}
    # Status-neutral — the row is born active from the field default.
    assert kek.status == lifecycle.STATUS_ACTIVE


@pytest.mark.django_db
def test_a_kek_the_provisioner_made_records_created(tenant, monkeypatch):
    """The ledger reports what happened.

    A provisioner that made the key on this call is a fact the engine is told,
    not one it has to infer — recording ``discovered`` for it understated what
    the deployment knew, and read as if an operator's key had been found.
    """
    engine = get_engine()
    monkeypatch.setattr(
        "encryption_suite.engine.ensure_kek_provisioned", lambda kms, prov, uid, **identity: ("kek-1", True)
    )

    engine.generate_and_store_keyset(tenant)

    kek = KeyEncryptionKey.objects.get()
    # A set, not a list: both events land in the same instant and the ledger
    # orders by timestamp, so their relative order is not deterministic.
    assert {e.event for e in kek.events.all()} == {lifecycle.EVENT_CREATED, lifecycle.EVENT_SILO_FOUND}
    assert kek.status == lifecycle.STATUS_ACTIVE


@pytest.mark.django_db
def test_a_shared_kek_is_only_discovered_once(tenant):
    """The event belongs to the key, not to each keyset wrapped under it.

    The test settings use SharedKekStrategy, so both silos resolve to one KEK.
    """
    engine = get_engine()
    engine.generate_and_store_keyset(tenant)
    engine.generate_and_store_keyset(Group.objects.create(name="beta"))

    assert DataEncryptionKey.objects.count() == 2
    kek = KeyEncryptionKey.objects.get()
    assert kek.events.filter(event=lifecycle.EVENT_DISCOVERED).count() == 1


@pytest.mark.django_db
def test_recording_deleted_clears_the_orphan_annotation():
    """A key that is gone is not an orphan.

    "Orphaned" asks whether a key still standing has anything depending on it.
    Once the key is destroyed there is nothing to adopt and nothing to clean up,
    so a surviving ``True`` reports work that cannot be done. Cleared in the
    transition funnel because both reconcile annotations skip terminal rows —
    nothing else would ever revisit the flag.
    """
    g = Group.objects.create(name="acme")
    get_engine().generate_and_store_keyset(g)
    dek = DataEncryptionKey.objects.get(silo_uid=_uid(g))
    DataEncryptionKey.objects.filter(pk=dek.pk).update(is_orphaned=True)
    dek.refresh_from_db()

    dek.record_event(lifecycle.EVENT_DELETED, trigger=lifecycle.TRIGGER_DIRECT)

    dek.refresh_from_db()
    assert dek.status == lifecycle.STATUS_DELETED
    assert dek.is_orphaned is False


@pytest.mark.django_db
def test_the_same_rule_applies_to_a_key_encryption_key():
    kek = make_kek_row(
        key_store="local",
        kek_resource_name="local-team-acme",
        is_orphaned=True,
    )

    kek.record_event(lifecycle.EVENT_DELETED, trigger=lifecycle.TRIGGER_DIRECT)

    kek.refresh_from_db()
    assert kek.status == lifecycle.STATUS_DELETED
    assert kek.is_orphaned is False


@pytest.mark.django_db
def test_a_non_terminal_transition_leaves_the_annotation_alone():
    """Scheduling is not deleting: a scheduled orphan is still an orphan."""
    kek = make_kek_row(
        key_store="local",
        kek_resource_name="local-team-acme",
        is_orphaned=True,
    )

    kek.record_event(lifecycle.EVENT_DELETION_SCHEDULED, trigger=lifecycle.TRIGGER_DIRECT)

    kek.refresh_from_db()
    assert kek.status == lifecycle.STATUS_DELETION_SCHEDULED
    assert kek.is_orphaned is True


@pytest.mark.django_db
def test_an_unconfigured_kms_skip_logs_at_warning(configured_owner_prefix, caplog):
    """A purge that skipped everything looks like a purge with nothing to do.

    The usual cause is a run pointed at the wrong settings module, which is
    exactly the state an operator would want to notice in a log read afterwards —
    and INFO is the level some deployments never keep. The pair names "fly",
    which no block in the test settings carries.
    """
    import logging

    configured_owner_prefix("kek_")
    _schedule_expired_pair("team1")

    with caplog.at_level(logging.WARNING, logger="encryption_suite.deletion"):
        deletion.purge_expired_keks(trigger=lifecycle.TRIGGER_DIRECT)

    line = next(r for r in caplog.records if "reason=kms_not_configured" in r.getMessage())
    assert line.levelno == logging.WARNING
    assert "key_store=fly" in line.getMessage()


@pytest.mark.django_db
def test_a_block_that_cannot_be_built_skips_its_keys_rather_than_aborting(
    configured_owner_prefix, configured_kms, monkeypatch, caplog
):
    """One broken block holds up its own keys, never the whole purge.

    The admin action calls this directly, so a raise here would be a 500 and the
    keys on every other KMS would stay queued with it.
    """
    import logging

    from encryption_suite.exceptions import GENERIC_ENCRYPT_DECRYPT_UNAVAILABLE_MESSAGE, EncryptionConfigurationError

    def _unbuildable(name=None):
        raise EncryptionConfigurationError(GENERIC_ENCRYPT_DECRYPT_UNAVAILABLE_MESSAGE, detail="bad options")

    configured_kms("fly", silo_kms=False)
    monkeypatch.setattr("encryption_suite.registry.get_kek_provisioner", _unbuildable)
    configured_owner_prefix("kek_")
    _sek, kek = _schedule_expired_pair("team1")

    with caplog.at_level(logging.WARNING, logger="encryption_suite.deletion"):
        summary = deletion.purge_expired_keks(trigger=lifecycle.TRIGGER_DIRECT)

    assert summary.skipped == 1
    kek.refresh_from_db()
    assert kek.status == lifecycle.STATUS_DELETION_SCHEDULED
    line = next(r for r in caplog.records if "reason=kms_not_buildable" in r.getMessage())
    assert line.levelno == logging.WARNING
