"""AzureKekProvisioner creation, deletion, enumeration and state checks.

The provisioner talks to Key Vault through the azure-keyvault-keys SDK, so the
fake replaces the ``KeyClient`` and records every call — the ``azure`` extra is
not a test dependency. Deletion here is Key Vault's soft delete, which is the
same shape as an AWS key in its pending window: unusable at once, recoverable
until the provider finishes the job, and only then gone from the listing.
"""

from __future__ import annotations

import datetime

import pytest

from encryption_suite.adapters.keks.provisioners import KekState
from encryption_suite.adapters.keks.provisioners_azure import AzureKekProvisioner
from encryption_suite.exceptions import (
    EncryptionConfigurationError,
    KekDeleteError,
    KekEnumerationError,
    KekPendingDeletionError,
)
from encryption_suite.silo_ref import SiloRef

_VAULT = "https://es-prod.vault.azure.net"
_PREFIX = "keys/es-prod-"
_NAME = _PREFIX + "team-1"
_PURGE = datetime.datetime(2026, 8, 8, 12, 0, tzinfo=datetime.UTC)


class _NotFound(Exception):
    """Stands in for azure-core's ResourceNotFoundError."""


class _Key:
    def __init__(self, name, *, version="v1", recoverable_days=7):
        self.name = name
        self.id = f"{_VAULT}/keys/{name}/{version}"
        self.recoverable_days = recoverable_days


class _DeletedKey(_Key):
    def __init__(self, name, *, purge_date=_PURGE, **kwargs):
        super().__init__(name, **kwargs)
        self.scheduled_purge_date = purge_date


class _Poller:
    def __init__(self, deleted):
        self._deleted = deleted

    def result(self):
        return self._deleted


class _FakeVault:
    """Stands in for ``azure.keyvault.keys.KeyClient``.

    *keys* and *deleted* name the vault's live and soft-deleted halves.
    ``soft_delete`` off makes a deletion immediate, as on a vault without the
    protection, which Key Vault signals by reporting no purge date.
    """

    def __init__(self, *, keys=(), deleted=(), soft_delete=True, recoverable_days=7):
        self.keys = {name: _Key(name, recoverable_days=recoverable_days) for name in keys}
        self.deleted = {name: _DeletedKey(name) for name in deleted}
        self.soft_delete = soft_delete
        self.recoverable_days = recoverable_days
        self.calls: list[tuple] = []
        self.created: list[dict] = []
        self.policies: list[tuple] = []

    def get_key(self, name, version=None):
        self.calls.append(("get_key", name))
        if name not in self.keys:
            raise _NotFound(name)
        return self.keys[name]

    def get_deleted_key(self, name):
        self.calls.append(("get_deleted_key", name))
        if name not in self.deleted:
            raise _NotFound(name)
        return self.deleted[name]

    def begin_delete_key(self, name):
        self.calls.append(("begin_delete_key", name))
        if name not in self.keys:
            raise _NotFound(name)
        del self.keys[name]
        if not self.soft_delete:
            return _Poller(_DeletedKey(name, purge_date=None))
        self.deleted[name] = _DeletedKey(name)
        return _Poller(self.deleted[name])

    def create_oct_key(self, name, *, size=None, hardware_protected=None, key_operations=None, tags=None):
        self.calls.append(("create_oct_key", name))
        self.created.append(
            {
                "name": name,
                "size": size,
                "hardware_protected": hardware_protected,
                "key_operations": key_operations,
                "tags": tags,
            }
        )
        self.keys[name] = _Key(name, recoverable_days=self.recoverable_days)
        return self.keys[name]

    def update_key_rotation_policy(self, name, policy):
        self.calls.append(("update_key_rotation_policy", name))
        self.policies.append((name, policy))
        return policy

    def list_properties_of_keys(self):
        self.calls.append(("list_properties_of_keys", None))
        return list(self.keys.values())

    def list_deleted_keys(self):
        self.calls.append(("list_deleted_keys", None))
        return list(self.deleted.values())

    def verbs(self):
        return [verb for verb, _name in self.calls]


def _provisioner(vault, **options):
    prov = AzureKekProvisioner({"AZURE_VAULT_ENDPOINT": _VAULT, **options})
    prov._client = vault
    # azure-core is not a test dependency; the provisioner reads its not-found
    # class through this hook precisely so it stays replaceable.
    prov._not_found_error = lambda: _NotFound
    return prov


class TestEnsure:
    def test_creates_a_symmetric_hsm_key(self):
        # Symmetric because AzureKeyVaultAdapter wraps with AES-GCM, the only
        # Key Vault algorithm that takes associated data.
        vault = _FakeVault()
        prov = _provisioner(vault)

        prov.ensure_kek("es-prod-team-1", SiloRef("default", "team-1"))

        assert vault.created[0]["hardware_protected"] is True
        assert vault.created[0]["size"] == 256
        assert vault.created[0]["key_operations"] == ["encrypt", "decrypt"]

    def test_accepts_the_vault_qualified_name(self):
        # Deletion and reconcile hand back what the row stores, not the bare
        # template result.
        vault = _FakeVault(keys=["es-prod-team-1"])
        prov = _provisioner(vault)

        prov.ensure_kek(_NAME, SiloRef("default", "team-1"))

        assert vault.created == []

    def test_an_existing_key_is_not_recreated(self):
        vault = _FakeVault(keys=["es-prod-team-1"])
        prov = _provisioner(vault)

        prov.ensure_kek("es-prod-team-1", SiloRef("default", "team-1"))

        assert vault.created == []

    def test_tags_are_applied_at_creation(self):
        vault = _FakeVault()
        prov = _provisioner(vault, TAGS={"owner": "platform"})

        prov.ensure_kek("es-prod-team-1", SiloRef("default", "team-1"))

        assert vault.created[0]["tags"] == {"owner": "platform"}

    def test_a_deleted_key_holding_the_name_refuses_with_its_purge_date(self):
        # Key Vault reserves the name for the retention period and will not
        # create over it — and that key is absent from the vault listing, so the
        # raw conflict names something the operator cannot see.
        vault = _FakeVault(deleted=["es-prod-team-1"])
        prov = _provisioner(vault)

        with pytest.raises(KekPendingDeletionError) as ei:
            prov.ensure_kek("es-prod-team-1", SiloRef("default", "team-1"))

        assert ei.value.effective_at == _PURGE
        assert vault.created == []

    def test_a_standard_vault_rejection_names_the_sku(self):
        class _StandardVault(_FakeVault):
            def create_oct_key(self, name, **kwargs):
                raise RuntimeError("The key type oct-HSM is not supported in this key vault SKU")

        prov = _provisioner(_StandardVault())

        with pytest.raises(RuntimeError) as ei:
            prov.ensure_kek("es-prod-team-1", SiloRef("default", "team-1"))

        assert "Premium" in str(ei.value)

    def test_an_unrelated_creation_failure_is_left_alone(self):
        # Only the SKU case is rewritten; everything else reaches the engine
        # funnel with the provider's own wording.
        class _BrokenVault(_FakeVault):
            def create_oct_key(self, name, **kwargs):
                raise RuntimeError("vault 503")

        prov = _provisioner(_BrokenVault())

        with pytest.raises(RuntimeError) as ei:
            prov.ensure_kek("es-prod-team-1", SiloRef("default", "team-1"))

        assert str(ei.value) == "vault 503"


class TestRotationPolicy:
    def test_no_policy_written_when_unconfigured(self):
        vault = _FakeVault()
        prov = _provisioner(vault)

        prov.ensure_kek("es-prod-team-1", SiloRef("default", "team-1"))

        assert vault.policies == []

    def test_days_are_rendered_as_an_iso_duration(self, monkeypatch):
        # KEK_ROTATION_PERIOD_DAYS is provider-neutral; Key Vault takes ISO 8601
        # where Cloud KMS takes seconds.
        vault = _FakeVault()
        prov = _provisioner(vault, KEK_ROTATION_PERIOD_DAYS=180)
        recorded = {}

        def _apply(client, key_name):
            recorded["days"] = prov.rotation_period_days()

        monkeypatch.setattr(prov, "_apply_rotation_policy", _apply)
        prov.ensure_kek("es-prod-team-1", SiloRef("default", "team-1"))

        assert recorded["days"] == 180

    def test_a_period_under_the_vault_floor_is_refused_at_construction(self):
        # Key Vault refuses a rotation interval under 7 days.
        with pytest.raises(EncryptionConfigurationError):
            AzureKekProvisioner({"AZURE_VAULT_ENDPOINT": _VAULT, "KEK_ROTATION_PERIOD_DAYS": 1})


class TestDelete:
    def test_deletes_and_reports_the_purge_date(self):
        vault = _FakeVault(keys=["es-prod-team-1"])
        prov = _provisioner(vault)

        outcome = prov.delete_kek(_NAME, SiloRef("default", "team-1"), owner_prefix=_PREFIX)

        assert ("begin_delete_key", "es-prod-team-1") in vault.calls
        assert outcome.scheduled is True
        assert outcome.effective_at == _PURGE

    def test_a_key_already_deleted_reports_its_existing_date(self):
        vault = _FakeVault(deleted=["es-prod-team-1"])
        prov = _provisioner(vault)

        outcome = prov.delete_kek(_NAME, SiloRef("default", "team-1"), owner_prefix=_PREFIX)

        assert outcome.scheduled is True
        assert outcome.effective_at == _PURGE

    def test_a_key_already_gone_counts_as_deleted(self):
        prov = _provisioner(_FakeVault())

        outcome = prov.delete_kek(_NAME, SiloRef("default", "team-1"), owner_prefix=_PREFIX)

        assert outcome.scheduled is False

    def test_a_vault_without_soft_delete_reports_an_immediate_deletion(self):
        vault = _FakeVault(keys=["es-prod-team-1"], soft_delete=False)
        prov = _provisioner(vault)

        outcome = prov.delete_kek(_NAME, SiloRef("default", "team-1"), owner_prefix=_PREFIX)

        assert outcome.scheduled is False
        assert vault.deleted == {}

    def test_an_unowned_key_is_refused_before_the_vault_is_touched(self):
        vault = _FakeVault(keys=["other-team-1"])
        prov = _provisioner(vault)

        with pytest.raises(KekDeleteError):
            prov.delete_kek(f"{_VAULT}/keys/other-team-1", SiloRef("default", "team-1"), owner_prefix=_PREFIX)

        assert vault.calls == []

    def test_a_provider_error_is_funneled(self):
        class _Exploding(_FakeVault):
            def begin_delete_key(self, name):
                raise RuntimeError("vault 503")

        prov = _provisioner(_Exploding(keys=["es-prod-team-1"]))

        with pytest.raises(KekDeleteError) as ei:
            prov.delete_kek(_NAME, SiloRef("default", "team-1"), owner_prefix=_PREFIX)

        assert isinstance(ei.value.__cause__, RuntimeError)

    def test_deleting_clears_the_ensured_cache(self):
        # Otherwise a silo encrypting again after its key was deleted would skip
        # provisioning and fail at the wrap.
        vault = _FakeVault(keys=["es-prod-team-1"])
        prov = _provisioner(vault)
        prov.ensure_kek("es-prod-team-1", SiloRef("default", "team-1"))

        prov.delete_kek(_NAME, SiloRef("default", "team-1"), owner_prefix=_PREFIX)

        assert "es-prod-team-1" not in prov._ensured


class TestDeletionWindowOption:
    def test_the_provider_window_option_is_refused(self):
        # It cannot reach Azure: the period is the vault's
        # softDeleteRetentionInDays, fixed at vault creation. Accepting it would
        # let an operator believe they had shortened something they had not.
        with pytest.raises(EncryptionConfigurationError):
            AzureKekProvisioner({"AZURE_VAULT_ENDPOINT": _VAULT, "PROVIDER_DELETION_WINDOW_DAYS": 7})

    def test_a_missing_purge_date_falls_back_to_the_vault_retention(self):
        vault = _FakeVault(keys=["es-prod-team-1"], recoverable_days=30)
        prov = _provisioner(vault)

        fallback = prov._purge_date(None)

        assert 29 < (fallback - datetime.datetime.now(datetime.UTC)).total_seconds() / 86400 <= 30

    def test_an_unreadable_retention_falls_back_to_the_key_vault_default(self):
        class _Blind(_FakeVault):
            def list_properties_of_keys(self):
                raise RuntimeError("vault 403")

        prov = _provisioner(_Blind())

        fallback = prov._purge_date(None)

        assert 89 < (fallback - datetime.datetime.now(datetime.UTC)).total_seconds() / 86400 <= 90


class TestState:
    def test_a_live_key_is_active(self):
        prov = _provisioner(_FakeVault(keys=["es-prod-team-1"]))

        assert prov.describe_kek_state(_NAME).state == KekState.ACTIVE

    def test_a_deleted_key_is_pending_with_its_purge_date(self):
        prov = _provisioner(_FakeVault(deleted=["es-prod-team-1"]))

        state = prov.describe_kek_state(_NAME)

        assert state.state == KekState.PENDING_DELETION
        assert state.effective_at == _PURGE

    def test_a_key_in_neither_half_is_unknown(self):
        # Purged, or unreadable by this identity — neither is evidence of health.
        prov = _provisioner(_FakeVault())

        assert prov.describe_kek_state(_NAME).state == KekState.UNKNOWN

    def test_a_probe_failure_degrades_to_unknown(self):
        class _Exploding(_FakeVault):
            def get_key(self, name, version=None):
                raise RuntimeError("vault 503")

        prov = _provisioner(_Exploding())

        assert prov.describe_kek_state(_NAME).state == KekState.UNKNOWN


class TestEnumeration:
    def test_lists_live_keys_as_vault_qualified_names(self):
        vault = _FakeVault(keys=["es-prod-team-1", "es-prod-team-2"])
        prov = _provisioner(vault)

        assert sorted(prov.list_kek_names(_PREFIX)) == [_PREFIX + "team-1", _PREFIX + "team-2"]

    def test_the_version_is_stripped_so_names_match_the_rows(self):
        # Key Vault ids carry a version; the key encryption key rows never do.
        prov = _provisioner(_FakeVault(keys=["es-prod-team-1"]))

        assert prov.list_kek_names(_PREFIX) == [_NAME]

    def test_deleted_keys_are_still_listed(self):
        # The deletion has not completed while the key is recoverable, exactly as
        # an AWS key stays visible through its pending window.
        vault = _FakeVault(keys=["es-prod-team-1"], deleted=["es-prod-team-2"])
        prov = _provisioner(vault)

        assert sorted(prov.list_kek_names(_PREFIX)) == [_PREFIX + "team-1", _PREFIX + "team-2"]

    def test_a_purged_key_drops_out(self):
        # The listing losing the key is what confirms the deletion completed.
        prov = _provisioner(_FakeVault())

        assert prov.list_kek_names(_PREFIX) == []

    def test_keys_outside_the_owner_prefix_are_filtered_out(self):
        vault = _FakeVault(keys=["es-prod-team-1", "someone-elses-key"])
        prov = _provisioner(vault)

        assert prov.list_kek_names(_PREFIX) == [_NAME]

    def test_a_provider_error_is_funneled(self):
        class _Exploding(_FakeVault):
            def list_properties_of_keys(self):
                raise RuntimeError("vault 503")

        prov = _provisioner(_Exploding())

        with pytest.raises(KekEnumerationError):
            prov.list_kek_names(_PREFIX)


class TestConfiguration:
    def test_the_vault_url_is_required(self):
        with pytest.raises(EncryptionConfigurationError):
            AzureKekProvisioner({})

    def test_capabilities(self):
        assert AzureKekProvisioner.supports_delete is True
        assert AzureKekProvisioner.supports_enumeration is True
        assert AzureKekProvisioner.supports_state_check is True
        assert AzureKekProvisioner.supports_tagging is True
        assert AzureKekProvisioner.supports_rotation_policy is True
        assert AzureKekProvisioner.minimum_rotation_days == 7
        # No provider deletion window: the vault owns that period.
        assert AzureKekProvisioner.minimum_deletion_window_days is None


class TestRotationPolicyFailure:
    """A policy that cannot be written must be loud, not fatal and not silent."""

    class _RefusingVault(_FakeVault):
        def update_key_rotation_policy(self, name, policy):
            raise RuntimeError("Forbidden: the caller lacks keys/rotate")

    def test_the_key_is_still_usable(self, caplog):
        # The key exists and encrypts; failing a tenant's first save over
        # metadata would be the worse outcome.
        vault = self._RefusingVault()
        prov = _provisioner(vault, KEK_ROTATION_PERIOD_DAYS=180)

        prov.ensure_kek("es-prod-team-1", SiloRef("default", "team-1"))

        assert "es-prod-team-1" in vault.keys
        assert "es-prod-team-1" in prov._ensured

    def test_it_logs_a_warning_naming_the_key(self, caplog):
        # The retry finds the key already present and never reattempts the
        # policy, so this line is the only notice the operator ever gets.
        import logging

        prov = _provisioner(self._RefusingVault(), KEK_ROTATION_PERIOD_DAYS=180)
        with caplog.at_level(logging.WARNING, logger="encryption_suite.adapters.keks.provisioners_azure"):
            prov.ensure_kek("es-prod-team-1", SiloRef("default", "team-1"))

        line = next(r for r in caplog.records if "will not rotate on its own" in r.getMessage())
        assert line.levelno == logging.WARNING
        assert "es-prod-team-1" in line.getMessage()
        assert "Crypto Officer" in line.getMessage()


def test_the_listing_matches_what_the_adapter_records():
    """The provisioner and the adapter must name a key identically.

    They derive the name independently — the adapter from the strategy, the
    provisioner from what the vault returns — and reconcile compares one against
    the other. A disagreement does not fail loudly: the listing is filtered by
    the owner prefix, so a mismatched form filters out entirely and every key
    reads as having vanished from the provider.
    """
    from encryption_suite.adapters.keks.strategies import PerSiloKekStrategy
    from encryption_suite.adapters.key_stores.azure import AzureKeyVaultAdapter

    options = {"AZURE_VAULT_ENDPOINT": _VAULT, "KEK_TEMPLATE": "es-prod-{silo_uid}"}
    adapter = AzureKeyVaultAdapter(options, AzureKeyVaultAdapter.build_strategy(PerSiloKekStrategy, options))
    prov = _provisioner(_FakeVault(keys=["es-prod-team--1"]))

    listed = prov.list_kek_names(adapter.owner_prefix())

    assert listed == [adapter.resolve_kek_name(SiloRef("default", "team-1"))]
