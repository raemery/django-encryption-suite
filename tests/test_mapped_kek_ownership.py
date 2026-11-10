"""One ownership rule for mapped keys.

A key is owned when its name carries the store's ``KEK_TEMPLATE`` prefix, or when it
is a ``KEK_MAP`` value and ``KEK_MAP_DESTROYABLE`` is set. Every place that asks
(the deletion gates, both schedule paths, the purge drift check, ``reencrypt_keys
--provision``) reads that one rule.
"""

from __future__ import annotations

import datetime

import pytest
from django.core.management.base import CommandError
from django.utils import timezone

from encryption_suite import lifecycle, registry
from encryption_suite.adapters.keks.provisioners import AbstractKekProvisioner, DeleteOutcome
from encryption_suite.deletion import (
    PURGE_DELETED,
    PURGE_RETAINED,
    RETAIN_NOT_OWNED,
    RETAIN_SHARED_DISPOSITION,
    _purge_kek,
    _silo_kek_gates,
    evaluate_deletion,
    live_owner_prefix,
    schedule_kek_deletion,
)
from encryption_suite.exceptions import KekDeleteError
from encryption_suite.management.commands.reencrypt_keys import Command
from encryption_suite.models import DataEncryptionKey
from encryption_suite.silo_ref import SiloRef
from tests.factories import make_dek, make_kek

_STORE = "mapped"
_PREFIX = "team-"
_MAPPED = "ocid1.key.oc1..aaa"
_EFFECTIVE = timezone.now() + datetime.timedelta(days=7)


class _Provisioner(AbstractKekProvisioner):
    supports_delete = True

    def __init__(self):
        super().__init__({})
        self.deleted = []

    def ensure_kek(self, kek_resource_name, silo_ref):  # pragma: no cover
        pass

    def _do_delete_kek(self, kek_resource_name, silo_ref):
        self.deleted.append(kek_resource_name)
        return DeleteOutcome(scheduled=True, effective_at=_EFFECTIVE)


@pytest.fixture
def configure_store(settings):
    """Install the ``mapped`` store with the given ``OPTIONS``; return its adapter."""

    def _apply(**options):
        encryption = dict(settings.ENCRYPTION)
        encryption["KMS_KEY_STORES"] = {
            **encryption["KMS_KEY_STORES"],
            _STORE: {
                "ADAPTER": "tests.adapters.UnversionedTestKmsAdapter",
                "KEK_STRATEGY_ADAPTER": "encryption_suite.adapters.keks.PerSiloKekStrategy",
                "OPTIONS": options,
            },
        }
        settings.ENCRYPTION = encryption
        registry.reset()
        return registry.get_kms_adapter(_STORE)

    return _apply


def _template_and_map(**extra):
    return {"KEK_TEMPLATE": f"{_PREFIX}{{silo_uid}}", "KEK_MAP": {"7": _MAPPED}, **extra}


# --- the rule ------------------------------------------------------------------


def test_a_destroyable_map_marks_its_values_owned(configure_store):
    adapter = configure_store(**_template_and_map(KEK_MAP_DESTROYABLE=True))

    assert adapter.owned_mapped_kek_names() == {_MAPPED}
    assert adapter.mapped_kek_names() == {_MAPPED}


def test_an_unflagged_map_owns_nothing(configure_store):
    adapter = configure_store(**_template_and_map())

    assert adapter.owned_mapped_kek_names() == frozenset()
    assert adapter.mapped_kek_names() == {_MAPPED}


def test_a_destroyable_mapped_key_without_the_prefix_passes_the_gates(configure_store):
    adapter = configure_store(**_template_and_map(KEK_MAP_DESTROYABLE=True))
    strategy = adapter.kek_strategy

    eligible, reason = evaluate_deletion(
        strategy.kek_disposition_for_name(_MAPPED, adapter.owner_prefix()),
        adapter.owner_prefix(),
        _Provisioner(),
        _MAPPED,
        owned_names=adapter.owned_mapped_kek_names(),
    )

    assert (eligible, reason) == (True, "")


def test_the_prefix_alone_no_longer_stands_in_for_a_mapped_key(configure_store):
    """Without the opt-in, a mapped key is shared and the disposition gate refuses it."""
    adapter = configure_store(**_template_and_map())
    disposition = adapter.kek_strategy.kek_disposition_for_name(_MAPPED, adapter.owner_prefix())

    assert evaluate_deletion(disposition, adapter.owner_prefix(), _Provisioner(), _MAPPED) == (
        False,
        RETAIN_SHARED_DISPOSITION,
    )


def test_a_key_that_is_neither_prefixed_nor_opted_in_is_not_owned(configure_store):
    adapter = configure_store(**_template_and_map(KEK_MAP_DESTROYABLE=True))

    eligible, reason = evaluate_deletion(
        "silo_exclusive",
        adapter.owner_prefix(),
        _Provisioner(),
        "someone-elses-key",
        owned_names=adapter.owned_mapped_kek_names(),
    )

    assert (eligible, reason) == (False, RETAIN_NOT_OWNED)


def test_a_store_with_a_map_and_no_template_deletes_a_destroyable_mapped_key(configure_store):
    adapter = configure_store(KEK_MAP={"7": _MAPPED}, KEK_MAP_DESTROYABLE=True)
    provisioner = _Provisioner()

    assert adapter.owner_prefix() is None
    provisioner.delete_kek(
        _MAPPED, SiloRef("default", "7"), owner_prefix=None, owned_names=adapter.owned_mapped_kek_names()
    )

    assert provisioner.deleted == [_MAPPED]


def test_the_provisioner_refuses_a_mapped_key_it_was_not_told_is_owned(configure_store):
    configure_store(KEK_MAP={"7": _MAPPED}, KEK_MAP_DESTROYABLE=True)
    provisioner = _Provisioner()

    with pytest.raises(KekDeleteError):
        provisioner.delete_kek(_MAPPED, SiloRef("default", "7"), owner_prefix=None)
    assert provisioner.deleted == []


# --- both schedule paths and the purge ------------------------------------------


@pytest.mark.django_db
def test_both_schedule_paths_snapshot_the_same_prefix_and_the_purge_sees_no_drift(configure_store, monkeypatch):
    configure_store(**_template_and_map(KEK_MAP_DESTROYABLE=True))
    provisioner = _Provisioner()
    monkeypatch.setattr("encryption_suite.registry.get_kek_provisioner", lambda name=None: provisioner)
    dek = make_dek("7", kek_resource_name=_MAPPED, key_store=_STORE)

    _disposition, silo_path_prefix = _silo_kek_gates([dek], SiloRef("default", "7"))[_STORE]
    row = make_kek(_MAPPED, _STORE)
    live = live_owner_prefix(_STORE, kek_name=_MAPPED)
    schedule_kek_deletion(row, owner_prefix=live, trigger=lifecycle.TRIGGER_DIRECT)
    row.refresh_from_db()

    assert silo_path_prefix == row.owner_prefix == _PREFIX
    DataEncryptionKey.objects.all().delete()
    outcome, reason = _purge_kek(row, live_owner_prefix=live, trigger=lifecycle.TRIGGER_DIRECT, dry_run=True)
    assert (outcome, reason) == (PURGE_DELETED, "")


@pytest.mark.django_db
def test_an_unflagged_mapped_key_is_still_retained_as_shared(configure_store, monkeypatch):
    configure_store(**_template_and_map())
    monkeypatch.setattr("encryption_suite.registry.get_kek_provisioner", lambda name=None: _Provisioner())
    row = make_kek(_MAPPED, _STORE)
    live = live_owner_prefix(_STORE, kek_name=_MAPPED)

    assert live == ""
    schedule_kek_deletion(row, owner_prefix=live, trigger=lifecycle.TRIGGER_DIRECT)
    row.refresh_from_db()
    outcome, reason = _purge_kek(row, live_owner_prefix=live, trigger=lifecycle.TRIGGER_DIRECT, dry_run=True)

    assert row.disposition == "shared"
    assert (outcome, reason) == (PURGE_RETAINED, RETAIN_SHARED_DISPOSITION)


# --- reencrypt_keys --provision --------------------------------------------------


@pytest.mark.django_db
def test_provision_accepts_mapped_keys_that_lack_the_prefix(configure_store):
    adapter = configure_store(**_template_and_map(KEK_MAP_DESTROYABLE=True))
    make_dek("7", kek_resource_name=_MAPPED, key_store=_STORE)
    make_dek("8", kek_resource_name=f"{_PREFIX}8", key_store=_STORE)

    Command()._check_owner_prefix(DataEncryptionKey.objects.all(), adapter, _Provisioner())


@pytest.mark.django_db
def test_provision_still_refuses_a_template_key_whose_prefix_changed(configure_store):
    adapter = configure_store(**_template_and_map(KEK_MAP_DESTROYABLE=True))
    make_dek("7", kek_resource_name=_MAPPED, key_store=_STORE)
    make_dek("8", kek_resource_name="old-8", key_store=_STORE)

    with pytest.raises(CommandError, match="old-8"):
        Command()._check_owner_prefix(DataEncryptionKey.objects.all(), adapter, _Provisioner())


# --- reconcile -------------------------------------------------------------------


class _ProbingProvisioner(_Provisioner):
    supports_state_check = True

    def __init__(self):
        super().__init__()
        self.probed = []

    def _do_describe_kek_state(self, kek_resource_name):
        from encryption_suite.adapters.keks.provisioners import KekState

        self.probed.append(kek_resource_name)
        return KekState(state=KekState.PENDING_DELETION, effective_at=_EFFECTIVE)


@pytest.mark.django_db
def test_an_owned_mapped_key_is_probed_for_a_provider_deletion_window():
    from encryption_suite.reconcile_service import _sync_keks

    make_kek(_MAPPED, _STORE)
    provisioner = _ProbingProvisioner()

    findings = _sync_keks(
        key_store=_STORE,
        owner_prefix=_PREFIX,
        live_names=set(),
        orphan_names=set(),
        owned_mapped_names=frozenset({_MAPPED}),
        provisioner=provisioner,
    )

    assert provisioner.probed == [_MAPPED]
    assert findings.observed_pending == [_MAPPED]
    assert findings.drift_missing == []


@pytest.mark.django_db
def test_an_unowned_mapped_key_is_not_probed():
    from encryption_suite.reconcile_service import _sync_keks

    make_kek(_MAPPED, _STORE)
    provisioner = _ProbingProvisioner()

    _sync_keks(key_store=_STORE, owner_prefix=_PREFIX, live_names=set(), orphan_names=set(), provisioner=provisioner)

    assert provisioner.probed == []
