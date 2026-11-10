"""Engine behavior for the DataEncryptionKey soft-delete window (step 2).

Covers the read/write blocks while a DEK is scheduled, the hard read error once
purged, and the revival of a reused tombstone on the encrypt path.
"""

from __future__ import annotations

import pytest

from encryption_suite import lifecycle
from encryption_suite.adapters.keks.provisioners import AbstractKekProvisioner
from encryption_suite.exceptions import DekDeletedError, DekDeletionScheduledError
from encryption_suite.models import DataEncryptionKey, KeyEncryptionKey
from encryption_suite.registry import get_engine
from encryption_suite.silo_ref import SiloRef


@pytest.fixture(autouse=True)
def _clear_primitive_cache():
    """The engine's primitive cache is process-global and outlives the DB
    rollback; clear it so a stale cached primitive can't mask a missing row."""
    from encryption_suite.engine import EncryptionEngine

    EncryptionEngine.invalidate_cache()
    yield
    EncryptionEngine.invalidate_cache()


@pytest.fixture
def provisioned(silo_context):
    """Encrypt once so a field DEK is provisioned for the current silo."""
    engine = get_engine()
    token = engine.encrypt("secret")
    silo_uid = engine.silo_adapter.get_silo_uid(silo_context)
    return engine, silo_uid, token


def _schedule(silo_uid):
    sek = DataEncryptionKey.objects.get(silo_uid=silo_uid, purpose=DataEncryptionKey.PURPOSE_FIELD)
    from django.utils import timezone

    sek.record_event(
        lifecycle.EVENT_DELETION_SCHEDULED, trigger=lifecycle.TRIGGER_DIRECT, undeletable_until=timezone.now()
    )
    get_engine().invalidate_cache(SiloRef("default", silo_uid))
    return sek


def _purge(sek):
    sek.encrypted_keyset = b""
    sek.save(update_fields=["encrypted_keyset"])
    sek.record_event(lifecycle.EVENT_DELETED, trigger=lifecycle.TRIGGER_DIRECT)
    get_engine().invalidate_cache(SiloRef(sek.key_set, sek.silo_uid))


def test_decrypt_blocked_while_scheduled(provisioned):
    engine, silo_uid, token = provisioned
    _schedule(silo_uid)
    with pytest.raises(DekDeletionScheduledError):
        engine.decrypt(token)


def test_encrypt_blocked_while_scheduled(provisioned):
    engine, silo_uid, _ = provisioned
    _schedule(silo_uid)
    with pytest.raises(DekDeletionScheduledError):
        engine.encrypt("more")


def test_decrypt_hard_fails_on_tombstone(provisioned):
    engine, silo_uid, token = provisioned
    _purge(_schedule(silo_uid))
    with pytest.raises(DekDeletedError):
        engine.decrypt(token)


def test_encrypt_revives_tombstone(provisioned):
    engine, silo_uid, _ = provisioned
    _purge(_schedule(silo_uid))

    # A reused silo UID transparently gets a fresh DEK on the next encrypt.
    new_token = engine.encrypt("after-revival")
    assert engine.decrypt(new_token) == "after-revival"

    sek = DataEncryptionKey.objects.get(silo_uid=silo_uid, purpose=DataEncryptionKey.PURPOSE_FIELD)
    assert sek.status == lifecycle.STATUS_ACTIVE
    assert sek.undeletable_until is None
    assert sek.encrypted_keyset  # fresh wrapped material
    # The revival wrote a fresh `created` event onto the tombstone row.
    assert sek.events.filter(event=lifecycle.EVENT_CREATED).count() >= 2


def test_known_kek_row_recorded_on_provision(provisioned):
    engine, silo_uid, _ = provisioned
    sek = DataEncryptionKey.objects.get(silo_uid=silo_uid, purpose=DataEncryptionKey.PURPOSE_FIELD)
    row = KeyEncryptionKey.objects.get(key_store=sek.kek.key_store, kek_resource_name=sek.kek.kek_resource_name)
    assert row.status == lifecycle.STATUS_ACTIVE


@pytest.mark.django_db
class TestKeyEncryptionKeyRowIsWrittenWithTheDataKey:
    """The relation is created on the wrap path, not backfilled afterwards.

    Both directions matter to an operator: a key created by hand in the KMS is
    adopted automatically on first encrypt, and a *missing* key leaves no rows at
    all rather than a half-written pair claiming a key exists.
    """

    def test_a_key_made_outside_the_application_is_adopted(self, tenant, silo_context):
        from encryption_suite.models import DataEncryptionKey
        from encryption_suite.registry import get_engine

        get_engine().encrypt("secret", silo=silo_context)

        dek = DataEncryptionKey.objects.get(purpose=DataEncryptionKey.PURPOSE_FIELD)
        assert dek.kek_id is not None
        # No provisioner is configured in the test settings, so the ledger records
        # that the key was found already there — not that this deployment made it.
        assert dek.kek.events.filter(event=lifecycle.EVENT_DISCOVERED).exists()

    def test_a_failed_wrap_leaves_no_rows_behind(self, tenant, silo_context, monkeypatch):
        from encryption_suite.exceptions import EncryptionError
        from encryption_suite.models import DataEncryptionKey, KeyEncryptionKey
        from encryption_suite.registry import get_engine

        engine = get_engine()

        def _no_key(*args, **kwargs):
            raise RuntimeError("KMS: key not found")

        monkeypatch.setattr(engine.silo_kms_adapter, "encrypt_key", _no_key)

        with pytest.raises(EncryptionError):
            engine.encrypt("secret", silo=silo_context)

        # The KEK row is written after a successful wrap, so a missing key cannot
        # leave a row asserting that one exists.
        assert not DataEncryptionKey.objects.exists()
        assert not KeyEncryptionKey.objects.exists()


@pytest.mark.django_db
class TestTheFirstSightingVerbRecordsWhatHappened:
    """The verb is reported by the provisioner, not inferred from settings.

    A deployment with a provisioner configured used to claim it made every key
    it recorded — including one an operator created by hand, which is the case
    where the answer matters most: it is what says whether destroying the key is
    this deployment's business.
    """

    class _Provisioner(AbstractKekProvisioner):
        def __init__(self, *, creates):
            super().__init__({})
            self._creates = creates

        def ensure_kek(self, kek_resource_name, silo_ref):
            return self._creates

    def _record(self, monkeypatch, *, creates):
        from encryption_suite.registry import get_engine

        provisioner = self._Provisioner(creates=creates)
        monkeypatch.setattr("encryption_suite.registry.get_kek_provisioner", lambda name=None: provisioner)
        return get_engine()

    def test_a_key_this_call_created_records_created(self, tenant, silo_context, monkeypatch):
        from encryption_suite.models import DataEncryptionKey

        self._record(monkeypatch, creates=True).encrypt("secret", silo=silo_context)

        dek = DataEncryptionKey.objects.get(purpose=DataEncryptionKey.PURPOSE_FIELD)
        assert dek.kek.events.filter(event=lifecycle.EVENT_CREATED).exists()

    def test_a_key_found_already_there_records_discovered(self, tenant, silo_context, monkeypatch):
        from encryption_suite.models import DataEncryptionKey

        self._record(monkeypatch, creates=False).encrypt("secret", silo=silo_context)

        dek = DataEncryptionKey.objects.get(purpose=DataEncryptionKey.PURPOSE_FIELD)
        assert dek.kek.events.filter(event=lifecycle.EVENT_DISCOVERED).exists()
