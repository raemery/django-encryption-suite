"""Tests for the admin test-console KEK deletion (test_console.delete_test_key).

Drives the delete/retain decision against the test DB with a fake strategy and
provisioner — verifying the deletion gates, the in-use guard, de-duplication by
stored KEK name, and that the PURPOSE_TEST DEK rows are always removed.
"""

from __future__ import annotations

import datetime

import pytest
from django.utils import timezone

from encryption_suite import test_console as tc
from encryption_suite.adapters.keks.provisioners import AbstractKekProvisioner, DeleteOutcome
from encryption_suite.models import DataEncryptionKey, KeyEncryptionKey
from tests.adapters import FakeKmsAdapterBase
from tests.factories import make_dek, make_kek, make_kek_row

EXCLUSIVE = KeyEncryptionKey.DISPOSITION_SILO_EXCLUSIVE
SHARED = KeyEncryptionKey.DISPOSITION_SHARED
_PREFIX = "kek-"


class _FakeStrategy:
    def __init__(self, disposition, owner_prefix):
        self._disposition = disposition
        self._owner_prefix = owner_prefix

    def kek_disposition(self, uid):
        return self._disposition

    def owner_prefix(self):
        return self._owner_prefix


class _FakeAdapter(FakeKmsAdapterBase):
    """Only needs to expose the strategy — deletion reads the stored KEK name."""

    def __init__(self, strategy):
        self._strategy = strategy

    @property
    def kek_strategy(self):
        return self._strategy


class _FakeProvisioner(AbstractKekProvisioner):
    supports_delete = True

    def __init__(self, *, supports_delete=True, scheduled=False):
        super().__init__({})
        self.supports_delete = supports_delete
        self.deleted = []
        self._scheduled = scheduled

    def ensure_kek(self, kek_resource_name, silo_ref):  # pragma: no cover
        pass

    def _do_delete_kek(self, kek_resource_name, silo_ref):
        self.deleted.append(kek_resource_name)
        return DeleteOutcome(scheduled=self._scheduled, effective_at=_EFFECTIVE)


_EFFECTIVE = timezone.now() + datetime.timedelta(days=7)


@pytest.fixture(autouse=True)
def _fake_kms_is_configured(configured_kms):
    configured_kms("fake", silo_kms=False)


def _delete(adapter, prov):
    """Run the console delete with the "fake" KMS's adapter and provisioner faked."""
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr("encryption_suite.registry.get_kms_adapter", lambda name=None: adapter)
        mp.setattr("encryption_suite.registry.get_kek_provisioner", lambda name=None: prov)
        return tc.delete_test_key()


def _make_test_rows(kek_name=None):
    """Create a PURPOSE_TEST row per sentinel. If *kek_name* is given, both rows
    share that KEK name (the shared/local case); otherwise each gets a distinct
    per-silo name."""
    for uid in (tc._field_uid(), tc._file_uid()):
        DataEncryptionKey.objects.create(
            key_set="default",
            silo_uid=uid,
            purpose=DataEncryptionKey.PURPOSE_TEST,
            silo_label="admin_test_console",
            encrypted_keyset=b"x",
            kek=make_kek(kek_name or (_PREFIX + uid), "fake"),
        )


def _make_kms_rows():
    """A KeyEncryptionKey row per sentinel KEK, as the console's create path records."""
    for uid in (tc._field_uid(), tc._file_uid()):
        make_kek_row(key_store="fake", kek_resource_name=_PREFIX + uid)


@pytest.mark.django_db
def test_create_records_the_kek_row():
    # The console drives the adapter directly, so it must record the KeyEncryptionKey row
    # itself — otherwise a test key is missing from the KMS Keys page until a
    # reconcile pass happens to discover it.
    from encryption_suite import registry

    tc.full_aead_roundtrip(registry.get_kms_adapter(), None, b"payload")

    row = DataEncryptionKey.objects.get(silo_uid=tc._field_uid(), purpose=DataEncryptionKey.PURPOSE_TEST)
    assert KeyEncryptionKey.objects.filter(pk=row.kek_id).exists()


@pytest.mark.django_db
def test_exclusive_owned_kek_is_deleted_and_rows_removed():
    adapter = _FakeAdapter(_FakeStrategy(EXCLUSIVE, _PREFIX))
    prov = _FakeProvisioner()
    _make_test_rows()

    result = _delete(adapter, prov)

    assert result["deks_deleted"] == 2
    assert result["deks_retained"] == 0
    assert all(k["deleted"] for k in result["keks"])
    assert set(prov.deleted) == {_PREFIX + uid for uid in (tc._field_uid(), tc._file_uid())}
    # The console hard-deletes its own rows — a scoped exception to the
    # rows-are-never-deleted rule, so the next run starts from a clean slate.
    assert not DataEncryptionKey.objects.filter(purpose=DataEncryptionKey.PURPOSE_TEST).exists()


@pytest.mark.django_db
def test_shared_kek_name_is_deduped_and_deleted_once():
    # Both test rows name the SAME KEK (shared strategy / local adapter) → one
    # KEK entry, one delete call.
    adapter = _FakeAdapter(_FakeStrategy(EXCLUSIVE, _PREFIX))
    prov = _FakeProvisioner()
    _make_test_rows(kek_name=_PREFIX + "shared")

    result = _delete(adapter, prov)

    assert len(result["keks"]) == 1
    assert prov.deleted == [_PREFIX + "shared"]
    assert result["deks_deleted"] == 2  # both rows still removed


@pytest.mark.django_db
def test_shared_disposition_retains_kek():
    adapter = _FakeAdapter(_FakeStrategy(SHARED, None))
    prov = _FakeProvisioner()
    _make_test_rows()

    result = _delete(adapter, prov)

    assert prov.deleted == []
    assert all(k["retained_reason"] == "shared_or_opaque_disposition" for k in result["keks"])
    assert result["deks_deleted"] == 2  # rows always removed


@pytest.mark.django_db
def test_deleted_kek_loses_its_kek_row():
    adapter = _FakeAdapter(_FakeStrategy(EXCLUSIVE, _PREFIX))
    prov = _FakeProvisioner()
    _make_test_rows()
    _make_kms_rows()

    _delete(adapter, prov)

    assert not KeyEncryptionKey.objects.filter(key_store="fake").exists()


@pytest.mark.django_db
def test_a_refused_kek_loses_its_kek_row():
    # Refused, but no real silo's DEK names it: the row is the console's own
    # record, and nothing would ever revisit it once the test DEK rows are gone.
    adapter = _FakeAdapter(_FakeStrategy(SHARED, None))
    prov = _FakeProvisioner()
    _make_test_rows()
    _make_kms_rows()

    result = _delete(adapter, prov)

    assert prov.deleted == []
    assert all(k["record_deleted"] for k in result["keks"])
    assert not KeyEncryptionKey.objects.filter(key_store="fake").exists()


@pytest.mark.django_db
def test_an_in_use_kek_keeps_its_kek_row():
    # The console's UID resolved to a real silo's key, so the row is that key's
    # record, not the console's.
    adapter = _FakeAdapter(_FakeStrategy(EXCLUSIVE, _PREFIX))
    prov = _FakeProvisioner()
    _make_test_rows(kek_name=_PREFIX + "shared")
    make_dek("team-1", kek=make_kek(_PREFIX + "shared", "fake"))

    result = _delete(adapter, prov)

    assert result["keks"][0]["record_deleted"] is False
    assert KeyEncryptionKey.objects.filter(key_store="fake", kek_resource_name=_PREFIX + "shared").exists()
    assert not DataEncryptionKey.objects.filter(purpose=DataEncryptionKey.PURPOSE_TEST).exists()


@pytest.mark.django_db
def test_a_provider_error_keeps_the_kek_row():
    # The key's state is unknown, and the row is the only record of it.
    class _FailingProvisioner(_FakeProvisioner):
        def _do_delete_kek(self, kek_resource_name, silo_ref):
            raise RuntimeError("provider down")

    adapter = _FakeAdapter(_FakeStrategy(EXCLUSIVE, _PREFIX))
    _make_test_rows()

    result = _delete(adapter, _FailingProvisioner())

    assert all(k["error"] and not k["record_deleted"] for k in result["keks"])
    assert KeyEncryptionKey.objects.filter(key_store="fake").count() == 2


@pytest.mark.django_db
def test_a_row_still_referenced_elsewhere_is_kept_without_undoing_the_cleanup():
    from encryption_suite.models import DekRotation

    adapter = _FakeAdapter(_FakeStrategy(SHARED, None))
    _make_test_rows(kek_name=_PREFIX + "shared")
    kek = KeyEncryptionKey.objects.get(kek_resource_name=_PREFIX + "shared")
    DekRotation.objects.create(dek=make_dek("team-1"), kek=kek, encrypted_keyset=b"x", started_at=timezone.now())

    result = _delete(adapter, _FakeProvisioner())

    assert result["keks"][0]["record_deleted"] is False
    assert KeyEncryptionKey.objects.filter(pk=kek.pk).exists()
    assert not DataEncryptionKey.objects.filter(purpose=DataEncryptionKey.PURPOSE_TEST).exists()


@pytest.mark.django_db
def test_in_use_guard_retains_kek_referenced_by_other_silo():
    adapter = _FakeAdapter(_FakeStrategy(EXCLUSIVE, _PREFIX))
    prov = _FakeProvisioner()
    _make_test_rows()
    # A real (non-test) silo whose DEK is wrapped by the SAME KEK as a sentinel.
    shared_uid = sorted(tc._reserved_test_uids())[0]
    DataEncryptionKey.objects.create(
        key_set="default",
        silo_uid="team-1",
        purpose=DataEncryptionKey.PURPOSE_FIELD,
        silo_label="team",
        encrypted_keyset=b"x",
        kek=make_kek(_PREFIX + shared_uid, "fake"),
    )

    result = _delete(adapter, prov)

    guarded = next(k for k in result["keks"] if k["kek_resource_name"] == _PREFIX + shared_uid)
    assert guarded["deleted"] is False
    assert guarded["retained_reason"] == "in_use_by_other_silo"
    assert (_PREFIX + shared_uid) not in prov.deleted


@pytest.mark.django_db
def test_no_provisioner_retains():
    adapter = _FakeAdapter(_FakeStrategy(EXCLUSIVE, _PREFIX))
    _make_test_rows()

    result = _delete(adapter, None)

    assert all(k["retained_reason"] == "no_provisioner" for k in result["keks"])
    assert result["deks_deleted"] == 2


@pytest.mark.django_db
def test_only_provisioned_sentinels_are_processed():
    # Provision a row for just ONE sentinel; the un-provisioned sentinel must be
    # skipped entirely — no delete fired, no entry in the result.
    adapter = _FakeAdapter(_FakeStrategy(EXCLUSIVE, _PREFIX))
    prov = _FakeProvisioner()
    field_uid = tc._field_uid()
    DataEncryptionKey.objects.create(
        key_set="default",
        silo_uid=field_uid,
        purpose=DataEncryptionKey.PURPOSE_TEST,
        silo_label="admin_test_console",
        encrypted_keyset=b"x",
        kek=make_kek(_PREFIX + field_uid, "fake"),
    )

    result = _delete(adapter, prov)

    assert [k["kek_resource_name"] for k in result["keks"]] == [_PREFIX + field_uid]
    assert prov.deleted == [_PREFIX + field_uid]  # only the provisioned key


@pytest.mark.django_db
def test_provisioner_cannot_delete_retains():
    adapter = _FakeAdapter(_FakeStrategy(EXCLUSIVE, _PREFIX))
    prov = _FakeProvisioner(supports_delete=False)
    _make_test_rows()

    result = _delete(adapter, prov)

    assert prov.deleted == []
    assert all(k["retained_reason"] == "provisioner_cannot_delete" for k in result["keks"])


def test_format_retain_reasons_joins_lazy_labels():
    # Regression: the deletion message joined gettext_lazy proxies directly,
    # raising "TypeError: ... __proxy__ found". The helper must str()-coerce them.
    from encryption_suite.deletion import format_retain_reasons

    text = format_retain_reasons(
        ["provisioner_cannot_delete", "shared_or_opaque_disposition", "provisioner_cannot_delete"]
    )
    assert isinstance(text, str)
    assert "key deletion is not enabled for this provisioner" in text
    assert "shared or operator-supplied key" in text


def test_format_retain_reasons_falls_back_to_unknown_slug():
    from encryption_suite.deletion import format_retain_reasons

    assert format_retain_reasons(["some_new_slug"]) == "some_new_slug"


@pytest.mark.django_db
def test_create_records_a_created_event_for_the_test_key():
    """The console bypasses the engine, so it must write the DEK's birth event
    itself — otherwise a test key lives and dies with no history at all."""
    from encryption_suite import lifecycle, registry
    from encryption_suite.models import KeyLifecycleEvent

    tc.full_aead_roundtrip(registry.get_kms_adapter(), None, b"payload")

    row = DataEncryptionKey.objects.get(silo_uid=tc._field_uid(), purpose=DataEncryptionKey.PURPOSE_TEST)
    assert [e.event for e in row.events.all()] == [lifecycle.EVENT_CREATED]
    assert KeyLifecycleEvent.objects.filter(dek=row).exists()


@pytest.mark.django_db
def test_reusing_the_key_does_not_repeat_the_created_event():
    from encryption_suite import lifecycle, registry

    adapter = registry.get_kms_adapter()
    tc.full_aead_roundtrip(adapter, None, b"one")
    tc.full_aead_roundtrip(adapter, None, b"two")

    row = DataEncryptionKey.objects.get(silo_uid=tc._field_uid(), purpose=DataEncryptionKey.PURPOSE_TEST)
    assert row.events.filter(event=lifecycle.EVENT_CREATED).count() == 1


@pytest.mark.django_db
def test_a_row_from_another_crypto_backend_is_discarded_despite_its_events():
    """Recording history makes the row PROTECT-guarded, so the discard path has
    to clear its events first — the cost of having a ledger at all."""
    from encryption_suite import registry
    from encryption_suite.models import KeyLifecycleEvent

    adapter = registry.get_kms_adapter()
    tc.full_aead_roundtrip(adapter, None, b"payload")
    stale = DataEncryptionKey.objects.get(silo_uid=tc._field_uid(), purpose=DataEncryptionKey.PURPOSE_TEST)
    assert KeyLifecycleEvent.objects.filter(dek=stale).exists()
    stale.crypto_backend = "some-other-backend"
    stale.save(update_fields=["crypto_backend"])

    # Would raise ProtectedError if the events were not cleared first.
    tc.full_aead_roundtrip(adapter, None, b"payload")

    fresh = DataEncryptionKey.objects.get(silo_uid=tc._field_uid(), purpose=DataEncryptionKey.PURPOSE_TEST)
    assert fresh.pk != stale.pk
    assert not KeyLifecycleEvent.objects.filter(dek_id=stale.pk).exists()


@pytest.mark.django_db
def test_cleanup_removes_the_test_rows_and_their_history():
    """The console's deliberate exception to rows-are-never-deleted: cleanup
    leaves no test key rows and no test key history behind.

    The key encryption key's row goes too: deletion is refused here, but no real
    silo's key names it, so it is the console's own record.
    """
    from encryption_suite import registry
    from encryption_suite.models import KeyEncryptionKey, KeyLifecycleEvent

    adapter = registry.get_kms_adapter()
    tc.full_aead_roundtrip(adapter, None, b"payload")
    dek_pks = list(
        DataEncryptionKey.objects.filter(purpose=DataEncryptionKey.PURPOSE_TEST).values_list("pk", flat=True)
    )
    assert KeyLifecycleEvent.objects.filter(dek_id__in=dek_pks).exists()

    tc.delete_test_key()

    assert not DataEncryptionKey.objects.filter(purpose=DataEncryptionKey.PURPOSE_TEST).exists()
    assert not KeyLifecycleEvent.objects.filter(dek_id__in=dek_pks).exists()
    assert not KeyEncryptionKey.objects.exists()


@pytest.mark.django_db
def test_scheduled_provider_deletion_still_removes_the_kek_row():
    """A console key leaves no tombstone, scheduled or not.

    Every provider with a deletion window (AWS, GCP, Azure) reports ``scheduled``,
    so keeping the row in that case would have kept one for almost every console
    delete — and permanently, since the DEK rows and events that give it meaning
    go in the same transaction. The console's sentinel keys are the standing
    exception to the rows-are-never-deleted rule, and this is where it applies.

    The trade is deliberate: for the length of the provider's window that key
    exists with no row, so reconcile may list it as an orphan carrying its
    pending-deletion state. True, and it clears itself when the provider
    finishes.
    """
    adapter = _FakeAdapter(_FakeStrategy(EXCLUSIVE, _PREFIX))
    prov = _FakeProvisioner(scheduled=True)
    _make_test_rows()
    _make_kms_rows()

    result = _delete(adapter, prov)

    assert all(k["deleted"] for k in result["keks"])
    assert KeyEncryptionKey.objects.count() == 0


@pytest.mark.django_db
def test_immediate_provider_deletion_still_removes_the_kek_row():
    """Nothing survives at the provider, so nothing needs to survive here."""
    adapter = _FakeAdapter(_FakeStrategy(EXCLUSIVE, _PREFIX))
    prov = _FakeProvisioner(scheduled=False)
    _make_test_rows()
    _make_kms_rows()

    _delete(adapter, prov)

    assert not KeyEncryptionKey.objects.exists()


@pytest.mark.django_db
def test_both_console_tests_share_one_key_encryption_key():
    """One test KEK, not one per test.

    Both console rows still need distinct sentinel UIDs — a DEK row is unique on
    (silo_uid, purpose) and both are PURPOSE_TEST — but the KMS calls are made
    under a single UID, so a deployment provisions and pays for one test key.
    """
    from encryption_suite import registry

    adapter = registry.get_kms_adapter()
    tc.full_aead_roundtrip(adapter, None, b"payload")
    tc.full_streaming_roundtrip(adapter, None, b"payload")

    rows = DataEncryptionKey.objects.filter(purpose=DataEncryptionKey.PURPOSE_TEST)
    assert rows.count() == 2
    assert len({r.silo_uid for r in rows}) == 2  # distinct row keys
    assert len({r.kek_id for r in rows}) == 1  # one key
    assert KeyEncryptionKey.objects.count() == 1


@pytest.mark.django_db
def test_each_key_set_gets_its_own_test_rows():
    """Testing one key set leaves another's test keys in place: the rows carry the key set."""
    from encryption_suite import registry

    tc.full_aead_roundtrip(registry.get_kms_adapter("local"), None, b"payload", key_set="default")
    tc.full_aead_roundtrip(registry.get_kms_adapter("login"), None, b"payload", key_set="system")

    rows = set(
        DataEncryptionKey.objects.filter(purpose=DataEncryptionKey.PURPOSE_TEST).values_list("key_set", "silo_uid")
    )
    assert rows == {("default", "enctestfieldkey"), ("system", "enctestfieldkey")}


@pytest.mark.django_db
def test_two_key_sets_on_one_store_make_two_row_pairs_under_one_key(settings):
    """The key encryption key depends on the store and the console uid, so key sets sharing a store share it."""
    from encryption_suite import registry

    settings.ENCRYPTION = {
        **settings.ENCRYPTION,
        "KEY_SETS": {
            **settings.ENCRYPTION["KEY_SETS"],
            "other": {"silo": "tests.silo.GroupSiloAdapter", "key_store": "local"},
        },
    }
    adapter = registry.get_kms_adapter("local")
    for key_set in ("default", "other"):
        tc.full_aead_roundtrip(adapter, None, b"payload", key_set=key_set)
        tc.full_streaming_roundtrip(adapter, None, b"payload", key_set=key_set)

    rows = DataEncryptionKey.objects.filter(purpose=DataEncryptionKey.PURPOSE_TEST)
    assert rows.count() == 4
    assert {r.key_set for r in rows} == {"default", "other"}
    assert len({r.kek_id for r in rows}) == 1
    assert KeyEncryptionKey.objects.count() == 1


@pytest.mark.django_db
def test_the_env_store_test_kek_is_kept_off_the_shared_kek():
    """An env store resolves every UID to shared, which real silos use, so
    the console records its own key under the bare test KEK UID — same material."""
    from encryption_suite import registry

    result = tc.full_aead_roundtrip(registry.get_kms_adapter("login"), None, b"payload", key_set="system")

    assert result["matches"]
    row = DataEncryptionKey.objects.select_related("kek").get(key_set="system", silo_uid="enctestfieldkey")
    assert (row.kek.key_store, row.kek.kek_resource_name) == ("login", "enctestkey")
    assert not KeyEncryptionKey.objects.filter(kek_resource_name="shared").exists()


@pytest.mark.django_db
def test_delete_reports_every_kms_it_processed():
    from encryption_suite import registry

    tc.full_aead_roundtrip(registry.get_kms_adapter("local"), None, b"payload", key_set="default")
    tc.full_aead_roundtrip(registry.get_kms_adapter("login"), None, b"payload", key_set="system")

    result = tc.delete_test_key()

    assert result["key_stores"] == ["local", "login"]
    assert not DataEncryptionKey.objects.filter(purpose=DataEncryptionKey.PURPOSE_TEST).exists()
