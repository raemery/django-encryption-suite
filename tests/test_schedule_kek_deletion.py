"""Tests for the "Schedule deletion" re-verification.

The KMS Keys "schedule deletion" action only schedules a key after an
*independent* server-side re-verification —
:func:`encryption_suite.reconcile_service.run_reconcile` rebuilds the reconcile
report from scratch (live KMS enumeration, never ledger inference) and the action
schedules only ``report.kms_orphan_keks`` when
``report.can_auto_delete_kms_orphans`` holds. These tests pin the cardinal rule:
a degraded detection (silo or KMS enumeration off, no owner prefix, or a
provisioner that cannot delete) authorizes *no* deletion, so the deletable set is
empty.
"""

from __future__ import annotations

import pytest

from encryption_suite.models import DataEncryptionKey
from encryption_suite.reconcile_service import run_reconcile
from tests.adapters import FakeKmsAdapterBase
from tests.factories import make_kek

_PREFIX = "alias/es-prod-"
_PROVIDER = "fly"
_LIVE = ["team-1", "team-2"]
_ORPHAN_KEK = _PREFIX + "team-9"  # a KEK on the KMS whose silo is gone


class _FakeSilo:
    def __init__(self, *, supports_enumeration=True, uids=_LIVE, raises=False):
        self.supports_enumeration = supports_enumeration
        self._uids = uids
        self._raises = raises

    def iter_silos(self):
        if self._raises:
            raise RuntimeError("enumeration blew up")
        return list(self._uids)

    def get_silo_uid(self, s):
        return s


class _FakeStrategy:
    def __init__(self, *, owner_prefix=_PREFIX):
        self._owner_prefix = owner_prefix

    def owner_prefix(self):
        return self._owner_prefix

    def get_kek_id(self, ref):
        return _PREFIX + ref.uid


class _FakeProvisioner:
    def __init__(self, *, supports_enumeration=True, supports_delete=True, names=None):
        self.supports_enumeration = supports_enumeration
        self.supports_delete = supports_delete
        self._names = names if names is not None else [_PREFIX + u for u in _LIVE] + [_ORPHAN_KEK]

    def list_kek_names(self, owner_prefix):
        return list(self._names)


class _FakeKms(FakeKmsAdapterBase):
    kms_provider = _PROVIDER


@pytest.fixture(autouse=True)
def _fake_kms_is_silo_kms(configured_kms):
    configured_kms(_PROVIDER)


@pytest.fixture
def patch_registry(monkeypatch):
    def _apply(*, silo=None, strategy=None, provisioner=None, kms=None):
        monkeypatch.setattr("encryption_suite.registry.get_silo_adapter", lambda key_set="default": silo or _FakeSilo())
        monkeypatch.setattr(
            "encryption_suite.registry.get_kek_strategy_adapter", lambda name=None: strategy or _FakeStrategy()
        )
        monkeypatch.setattr(
            "encryption_suite.registry.get_kek_provisioner", lambda name=None: provisioner or _FakeProvisioner()
        )
        monkeypatch.setattr("encryption_suite.registry.get_kms_adapter", lambda name=None: kms or _FakeKms())

    return _apply


def _deletable():
    """Mirror the admin view's gate: queue ``kms_orphan_keks`` only when the
    reconcile actually ran and the provisioner can delete."""
    result = run_reconcile()
    report = result.report
    deletable = set(report.kms_orphan_keks) if report.can_auto_delete_kms_orphans else set()
    return deletable, result.owner_prefix, result.key_store


@pytest.mark.django_db
def test_fully_capable_returns_the_orphan(patch_registry):
    patch_registry()
    deletable, owner_prefix, provider = _deletable()
    assert deletable == {_ORPHAN_KEK}
    assert owner_prefix == _PREFIX
    assert provider == _PROVIDER


@pytest.mark.django_db
def test_silo_enumeration_off_authorizes_nothing(patch_registry):
    # No trustworthy live set => KMS reconcile cannot run => no deletable orphans.
    patch_registry(silo=_FakeSilo(supports_enumeration=False))
    deletable, _prefix, _provider = _deletable()
    assert deletable == set()


@pytest.mark.django_db
def test_silo_enumeration_raises_authorizes_nothing(patch_registry):
    patch_registry(silo=_FakeSilo(raises=True))
    deletable, _prefix, _provider = _deletable()
    assert deletable == set()


@pytest.mark.django_db
def test_kms_enumeration_off_authorizes_nothing(patch_registry):
    patch_registry(provisioner=_FakeProvisioner(supports_enumeration=False))
    deletable, _prefix, _provider = _deletable()
    assert deletable == set()


@pytest.mark.django_db
def test_no_owner_prefix_authorizes_nothing(patch_registry):
    # Shared / KEK_MAP configs derive no prefix => ownership unprovable.
    patch_registry(strategy=_FakeStrategy(owner_prefix=None))
    deletable, owner_prefix, _provider = _deletable()
    assert deletable == set()
    assert owner_prefix == ""  # None coerced to "" for the queue row's CharField


@pytest.mark.django_db
def test_provisioner_cannot_delete_authorizes_nothing(patch_registry):
    # Detection ran, but the provisioner cannot delete => report-only, not actionable.
    patch_registry(provisioner=_FakeProvisioner(supports_delete=False))
    deletable, _prefix, _provider = _deletable()
    assert deletable == set()


@pytest.mark.django_db
def test_live_silo_kek_is_not_an_orphan(patch_registry):
    # A KEK that still backs a live silo must never be offered for deletion,
    # even though it carries the owner prefix.
    patch_registry(provisioner=_FakeProvisioner(names=[_PREFIX + u for u in _LIVE]))
    deletable, _prefix, _provider = _deletable()
    assert deletable == set()


@pytest.mark.django_db
def test_kek_of_an_existing_test_key_is_not_an_orphan(patch_registry):
    # The sentinel UIDs are reserved so no real silo resolves to them, which would
    # make a live test KEK a permanent false orphan — and, worse, selectable for
    # scheduled deletion on the KMS Keys changelist. While the test key exists,
    # its KEK counts as expected.
    from encryption_suite.test_console import _field_uid

    test_kek = _PREFIX + _field_uid()  # _FakeStrategy maps uid -> _PREFIX + uid
    DataEncryptionKey.objects.create(
        key_set="default",
        silo_uid=_field_uid(),
        purpose=DataEncryptionKey.PURPOSE_TEST,
        silo_label="admin_test_console",
        encrypted_keyset=b"x",
        kek=make_kek(test_kek, _PROVIDER),
    )
    patch_registry(provisioner=_FakeProvisioner(names=[_PREFIX + u for u in _LIVE] + [_ORPHAN_KEK, test_kek]))

    result = run_reconcile()

    assert _ORPHAN_KEK in result.report.kms_orphan_keks
    assert test_kek not in result.report.kms_orphan_keks


@pytest.mark.django_db
def test_leftover_test_kek_with_no_rows_is_an_orphan(patch_registry):
    # The other half of the rule: a test KEK whose rows are gone (the console's
    # delete could not remove it at the provider) is a genuine leftover that
    # keeps costing money, so it must surface in the orphan report.
    from encryption_suite.test_console import _field_uid

    test_kek = _PREFIX + _field_uid()
    patch_registry(provisioner=_FakeProvisioner(names=[_PREFIX + u for u in _LIVE] + [test_kek]))

    result = run_reconcile()

    assert test_kek in result.report.kms_orphan_keks


@pytest.mark.django_db
def test_stored_dek_does_not_mask_a_kms_orphan(patch_registry):
    # A leftover DEK row for the dead silo must not change the KMS-side verdict:
    # the key is orphaned on the provider regardless of stale DB rows.
    DataEncryptionKey.objects.create(
        key_set="default",
        silo_uid="team-9",
        purpose=DataEncryptionKey.PURPOSE_FIELD,
        silo_label="team",
        encrypted_keyset=b"x",
        kek=make_kek(_ORPHAN_KEK, _PROVIDER),
    )
    patch_registry()
    deletable, _prefix, _provider = _deletable()
    assert deletable == {_ORPHAN_KEK}
