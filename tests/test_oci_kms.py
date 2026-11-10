"""Unit tests for the OCI Vault KMS adapter, credential strategies, and provisioner.

These exercise the pure logic that does not require the ``oci`` SDK or a live
vault: credential-strategy selection, inline api_key config building, the
display-name → OCID selection rule, the adapter's resolve-and-cache behavior,
the provisioner's ensure-once / OCID-passthrough behavior, and its deletion,
state and enumeration paths. The seams that touch the SDK
(``_lookup_ocid_by_name``, the provisioner's ``_list_keys``,
``_find_key_by_name``, ``_create_key`` and ``_schedule_deletion``) are patched
per instance.
"""

from __future__ import annotations

import datetime
from types import SimpleNamespace

import pytest
from django.core.exceptions import ImproperlyConfigured
from django.utils import timezone

from encryption_suite.adapters.credentials.oci import (
    OciApiKeyStrategy,
    OciInstancePrincipalStrategy,
    OciOkeWorkloadIdentityStrategy,
    OciResourcePrincipalStrategy,
    build_oci_credential_strategy,
)
from encryption_suite.adapters.keks.provisioners import KekState
from encryption_suite.adapters.keks.provisioners_oci import OciKekProvisioner
from encryption_suite.adapters.keks.strategies import PerSiloKekStrategy
from encryption_suite.adapters.key_stores.oci import OCIVaultAdapter, _is_key_ocid, _select_key_ocid
from encryption_suite.exceptions import EncryptionConfigurationError, KekPendingDeletionError
from encryption_suite.silo_ref import SiloRef

_CRYPTO = "https://abc-crypto.kms.ca-toronto-1.oraclecloud.com"
_MGMT = "https://abc-management.kms.ca-toronto-1.oraclecloud.com"
_COMPARTMENT = "ocid1.compartment.oc1..aaaa"


def _key(name, state, ocid):
    return SimpleNamespace(display_name=name, lifecycle_state=state, id=ocid)


# ---------------------------------------------------------------------------
# build_oci_credential_strategy
# ---------------------------------------------------------------------------


class TestCredentialStrategyFactory:
    @pytest.mark.parametrize(
        "name,cls",
        [
            ("api_key", OciApiKeyStrategy),
            ("instance_principal", OciInstancePrincipalStrategy),
            ("resource_principal", OciResourcePrincipalStrategy),
            ("oke_workload_identity", OciOkeWorkloadIdentityStrategy),
        ],
    )
    def test_selects_each_strategy(self, name, cls):
        assert isinstance(build_oci_credential_strategy({"CREDENTIAL_STRATEGY": name}), cls)

    def test_defaults_to_api_key(self):
        assert isinstance(build_oci_credential_strategy({}), OciApiKeyStrategy)

    def test_unknown_strategy_raises(self):
        # str(exc) is the generic user-safe message; the detail is on .detail.
        with pytest.raises(EncryptionConfigurationError) as excinfo:
            build_oci_credential_strategy({"CREDENTIAL_STRATEGY": "nope"})
        assert "Unknown CREDENTIAL_STRATEGY" in excinfo.value.detail


# ---------------------------------------------------------------------------
# OciApiKeyStrategy — inline credentials
# ---------------------------------------------------------------------------


class TestInlineApiKey:
    _COMPLETE = {
        "OCI_TENANCY_OCID": "ocid1.tenancy.oc1..t",
        "OCI_USER_OCID": "ocid1.user.oc1..u",
        "OCI_FINGERPRINT": "aa:bb:cc",
        "OCI_REGION": "ca-toronto-1",
        "OCI_PRIVATE_KEY_CONTENT": "-----BEGIN PRIVATE KEY-----\nx\n-----END PRIVATE KEY-----\n",
    }

    def test_inline_not_requested_when_absent(self):
        assert OciApiKeyStrategy({})._inline_requested() is False

    def test_inline_requested_when_any_field_present(self):
        assert OciApiKeyStrategy({"OCI_TENANCY_OCID": "x"})._inline_requested() is True

    def test_complete_inline_builds_config(self):
        config = OciApiKeyStrategy(self._COMPLETE)._inline_config()
        assert config["tenancy"] == "ocid1.tenancy.oc1..t"
        assert config["user"] == "ocid1.user.oc1..u"
        assert config["fingerprint"] == "aa:bb:cc"
        assert config["region"] == "ca-toronto-1"
        assert config["key_content"].startswith("-----BEGIN PRIVATE KEY-----")
        assert "pass_phrase" not in config

    def test_passphrase_included_when_set(self):
        opts = {**self._COMPLETE, "OCI_PRIVATE_KEY_PASSPHRASE": "secret"}
        assert OciApiKeyStrategy(opts)._inline_config()["pass_phrase"] == "secret"

    def test_partial_inline_raises_listing_missing(self):
        opts = {"OCI_TENANCY_OCID": "x", "OCI_USER_OCID": "y"}
        with pytest.raises(EncryptionConfigurationError) as exc:
            OciApiKeyStrategy(opts)._inline_config()
        msg = exc.value.detail
        assert "OCI_FINGERPRINT" in msg
        assert "OCI_REGION" in msg
        assert "OCI_PRIVATE_KEY_CONTENT" in msg


# ---------------------------------------------------------------------------
# _is_key_ocid / _select_key_ocid
# ---------------------------------------------------------------------------


class TestKeyOcidHelpers:
    def test_is_key_ocid(self):
        assert _is_key_ocid("ocid1.key.oc1.ca-toronto-1.abc") is True
        assert _is_key_ocid("encryption_suite-team_3a1") is False

    def test_select_returns_enabled(self):
        keys = [_key("ck-1", "ENABLED", "ocid1.key.A")]
        assert _select_key_ocid(keys, "ck-1", _COMPARTMENT) == "ocid1.key.A"

    def test_select_prefers_enabled_over_creating(self):
        keys = [
            _key("ck-1", "CREATING", "ocid1.key.B"),
            _key("ck-1", "ENABLED", "ocid1.key.A"),
        ]
        assert _select_key_ocid(keys, "ck-1", _COMPARTMENT) == "ocid1.key.A"

    def test_select_accepts_creating_when_no_enabled(self):
        keys = [_key("ck-1", "CREATING", "ocid1.key.B")]
        assert _select_key_ocid(keys, "ck-1", _COMPARTMENT) == "ocid1.key.B"

    def test_select_ignores_other_names_and_dead_states(self):
        keys = [
            _key("other", "ENABLED", "ocid1.key.X"),
            _key("ck-1", "DELETED", "ocid1.key.Y"),
        ]
        with pytest.raises(ImproperlyConfigured, match="no usable OCI key named 'ck-1'"):
            _select_key_ocid(keys, "ck-1", _COMPARTMENT)

    def test_select_rejects_ambiguous_names(self):
        keys = [
            _key("ck-1", "ENABLED", "ocid1.key.A"),
            _key("ck-1", "ENABLED", "ocid1.key.B"),
        ]
        with pytest.raises(ImproperlyConfigured, match="multiple distinct OCI keys"):
            _select_key_ocid(keys, "ck-1", _COMPARTMENT)


# ---------------------------------------------------------------------------
# OCIVaultAdapter._resolve_key_ocid
# ---------------------------------------------------------------------------


def _adapter():
    options = {
        "OCI_VAULT_CRYPTO_ENDPOINT": _CRYPTO,
        "OCI_VAULT_MANAGEMENT_ENDPOINT": _MGMT,
        "OCI_COMPARTMENT_OCID": _COMPARTMENT,
        "KEK_TEMPLATE": "ck-{silo_uid}",
    }
    return OCIVaultAdapter(options, PerSiloKekStrategy(options))


class TestResolveKeyOcid:
    def test_ocid_passes_through_without_lookup(self):
        adapter = _adapter()

        def _boom(name):
            raise AssertionError("lookup should not run for an OCID")

        adapter._lookup_ocid_by_name = _boom
        assert adapter._resolve_key_ocid("ocid1.key.oc1.abc") == "ocid1.key.oc1.abc"

    def test_name_resolved_and_cached(self):
        adapter = _adapter()
        calls = []

        def _lookup(name):
            calls.append(name)
            return "ocid1.key.RESOLVED"

        adapter._lookup_ocid_by_name = _lookup
        assert adapter._resolve_key_ocid("ck-team1") == "ocid1.key.RESOLVED"
        # Second call hits the per-process cache; no second lookup.
        assert adapter._resolve_key_ocid("ck-team1") == "ocid1.key.RESOLVED"
        assert calls == ["ck-team1"]


class TestRecordedName:
    """Rows record the display name, not the OCID it resolves to."""

    def test_canonical_name_is_the_identifier_verbatim(self):
        # An OCID is server-assigned, so an owner prefix has no OCID form at
        # all: canonicalizing to OCIDs would leave the ownership gate comparing
        # a display-name prefix against OCID-shaped names and matching nothing.
        adapter = _adapter()
        prefix = adapter.kek_strategy.owner_prefix()

        assert adapter.canonical_kek_name("ck-team1") == "ck-team1"
        assert adapter.resolve_kek_name(SiloRef("default", "team1")).startswith(adapter.canonical_kek_name(prefix))

    def test_decrypt_resolves_a_stored_display_name(self):
        adapter = _adapter()
        adapter._lookup_ocid_by_name = lambda name: "ocid1.key.RESOLVED"

        assert adapter._resolve_key_ocid("ck-team1") == "ocid1.key.RESOLVED"


class TestAssociatedData:
    def test_binds_silo_uid(self):
        assert OCIVaultAdapter._associated_data(SiloRef("default", "cktestaead")) == {
            "silo_uid": "default:cktestaead",
            "purpose": "dek",
        }

    def test_empty_uid_rejected(self):
        with pytest.raises(ValueError, match="non-empty"):
            OCIVaultAdapter._associated_data(SiloRef("default", ""))


# ---------------------------------------------------------------------------
# OciKekProvisioner.ensure_kek
# ---------------------------------------------------------------------------


def _provisioner():
    return OciKekProvisioner(
        {
            "OCI_VAULT_MANAGEMENT_ENDPOINT": _MGMT,
            "OCI_COMPARTMENT_OCID": _COMPARTMENT,
        }
    )


class TestProvisioner:
    def test_requires_endpoint_and_compartment(self):
        # EncryptionConfigurationError (a EncryptionError) — not a bare
        # ValueError — so a consuming view's ``except EncryptionError`` around
        # save() catches this misconfiguration on the write path instead of
        # letting it escape as a 500. Construction happens in the registry,
        # outside the engine's error funnel, so the typed error is the only
        # thing that makes it consistent with the field/file/admin paths.
        # str(exc) is the generic user-safe message; the operator detail (the
        # option names) is on .detail, not leaked to end users.
        with pytest.raises(EncryptionConfigurationError) as excinfo:
            OciKekProvisioner({})
        assert "OCI_VAULT_MANAGEMENT_ENDPOINT" in excinfo.value.detail
        assert "OCI_VAULT_MANAGEMENT_ENDPOINT" not in str(excinfo.value)

    def test_ocid_is_a_noop(self):
        prov = _provisioner()
        prov._find_key_by_name = lambda name, states=None: (_ for _ in ()).throw(AssertionError("must not list"))
        prov._create_key = lambda name, uid: (_ for _ in ()).throw(AssertionError("must not create"))
        prov.ensure_kek("ocid1.key.oc1.ca-toronto-1.abc", SiloRef("default", "team:1"))

    def test_creates_when_missing_then_caches(self):
        prov = _provisioner()
        created = []
        prov._find_key_by_name = lambda name, states=None: None
        prov._create_key = lambda name, uid: created.append((name, uid))

        prov.ensure_kek("ck-team1", SiloRef("default", "team:1"))
        prov.ensure_kek("ck-team1", SiloRef("default", "team:1"))  # cached — no second create
        assert created == [("ck-team1", SiloRef("default", "team:1"))]

    def test_skips_create_when_already_present(self):
        prov = _provisioner()
        prov._find_key_by_name = lambda name, states=None: _key(name, "ENABLED", "ocid1.key.A")
        prov._create_key = lambda name, uid: (_ for _ in ()).throw(AssertionError("must not create"))
        prov.ensure_kek("ck-team1", SiloRef("default", "team:1"))

    def test_provision_timeout_defaults_to_60(self):
        assert _provisioner()._provision_timeout == 60

    def test_provision_timeout_is_configurable(self):
        prov = OciKekProvisioner(
            {
                "OCI_VAULT_MANAGEMENT_ENDPOINT": _MGMT,
                "OCI_COMPARTMENT_OCID": _COMPARTMENT,
                "OCI_KEY_PROVISION_TIMEOUT_SECONDS": 120,
            }
        )
        assert prov._provision_timeout == 120

    def test_refuses_to_create_over_a_key_awaiting_deletion(self):
        # OCI does not enforce unique display names, so creating here would
        # leave two keys answering to one name and only one of them holding the
        # material that decrypts what came before.
        prov = _provisioner()
        prov._list_keys = lambda: [_key("ck-team1", "PENDING_DELETION", "ocid1.key.A")]
        prov._create_key = lambda name, uid: pytest.fail("must not create over a pending key")

        with pytest.raises(KekPendingDeletionError) as excinfo:
            prov.ensure_kek("ck-team1", SiloRef("default", "team:1"))
        assert "cancel-deletion" in str(excinfo.value.detail or excinfo.value)


# ---------------------------------------------------------------------------
# _find_key_by_name — the shared lookup behind provisioning, deletion and state
# ---------------------------------------------------------------------------


class TestFindKeyByName:
    def test_finds_a_live_key(self):
        prov = _provisioner()
        prov._list_keys = lambda: [_key("ck-team1", "ENABLED", "ocid1.key.A")]

        assert prov._find_key_by_name("ck-team1").id == "ocid1.key.A"

    def test_ignores_a_pending_key_by_default(self):
        # The default state filter is "already exists", which a key inside OCI's
        # deletion window is not — it cannot be used.
        prov = _provisioner()
        prov._list_keys = lambda: [_key("ck-team1", "PENDING_DELETION", "ocid1.key.A")]

        assert prov._find_key_by_name("ck-team1") is None

    def test_refuses_an_ambiguous_name(self):
        prov = _provisioner()
        prov._list_keys = lambda: [
            _key("ck-team1", "ENABLED", "ocid1.key.A"),
            _key("ck-team1", "ENABLED", "ocid1.key.B"),
        ]

        with pytest.raises(RuntimeError, match="multiple distinct OCI keys"):
            prov._find_key_by_name("ck-team1")


# ---------------------------------------------------------------------------
# Deletion
# ---------------------------------------------------------------------------

_OWNER_PREFIX = "ck-"


class TestDelete:
    def test_schedules_deletion_at_the_configured_window(self):
        prov = OciKekProvisioner(
            {
                "OCI_VAULT_MANAGEMENT_ENDPOINT": _MGMT,
                "OCI_COMPARTMENT_OCID": _COMPARTMENT,
                "PROVIDER_DELETION_WINDOW_DAYS": 30,
            }
        )
        prov._list_keys = lambda: [_key("ck-team1", "ENABLED", "ocid1.key.A")]
        scheduled = []

        def _schedule(key_ocid, when):
            scheduled.append((key_ocid, when))
            return when

        prov._schedule_deletion = _schedule
        outcome = prov.delete_kek("ck-team1", SiloRef("default", "team-1"), owner_prefix=_OWNER_PREFIX)

        # Addressed by OCID: ScheduleKeyDeletion does not take a display name.
        assert scheduled[0][0] == "ocid1.key.A"
        assert outcome.scheduled is True
        assert 29 <= (outcome.effective_at - timezone.now()).days <= 30

    def test_a_test_console_key_gets_the_provider_minimum(self):
        prov = OciKekProvisioner(
            {
                "OCI_VAULT_MANAGEMENT_ENDPOINT": _MGMT,
                "OCI_COMPARTMENT_OCID": _COMPARTMENT,
                "PROVIDER_DELETION_WINDOW_DAYS": 30,
            }
        )
        prov._list_keys = lambda: [_key("ck-enctestkey", "ENABLED", "ocid1.key.A")]
        prov._schedule_deletion = lambda key_ocid, when: when

        outcome = prov.delete_kek("ck-enctestkey", SiloRef("default", "enctestkey"), owner_prefix=_OWNER_PREFIX)

        assert 6 <= (outcome.effective_at - timezone.now()).days <= 7

    def test_an_absent_key_counts_as_deleted(self):
        prov = _provisioner()
        prov._list_keys = lambda: []
        prov._schedule_deletion = lambda key_ocid, when: pytest.fail("nothing to schedule")

        outcome = prov.delete_kek("ck-team1", SiloRef("default", "team-1"), owner_prefix=_OWNER_PREFIX)

        assert outcome.scheduled is False

    def test_an_already_scheduled_key_reports_its_existing_date(self):
        when = timezone.now() + datetime.timedelta(days=3)
        prov = _provisioner()
        prov._list_keys = lambda: [
            SimpleNamespace(
                display_name="ck-team1",
                lifecycle_state="PENDING_DELETION",
                id="ocid1.key.A",
                time_of_deletion=when,
            )
        ]
        prov._schedule_deletion = lambda key_ocid, w: pytest.fail("already scheduled")

        outcome = prov.delete_kek("ck-team1", SiloRef("default", "team-1"), owner_prefix=_OWNER_PREFIX)

        assert outcome.scheduled is True
        assert outcome.effective_at == when

    def test_deleting_clears_the_ensured_cache(self):
        # Otherwise a silo recreated under the same name would skip provisioning
        # and encrypt against a key that is on its way out.
        prov = _provisioner()
        prov._list_keys = lambda: []
        prov._ensured.add("ck-team1")

        prov.delete_kek("ck-team1", SiloRef("default", "team-1"), owner_prefix=_OWNER_PREFIX)

        assert "ck-team1" not in prov._ensured


class TestDeletionTimeFromSummary:
    """``ListKeys`` summaries carry no ``time_of_deletion``; ``GetKey`` does.

    Every pending-deletion path starts from the listing, so reading the field off
    a summary yields ``None`` and the caller silently falls back to a date it
    computed itself — which need not match the one OCI is holding. Seen live
    2026-08-03.
    """

    def _provisioner_with_get_key(self, when):
        prov = _provisioner()
        prov._list_keys = lambda: [_key("ck-team1", "PENDING_DELETION", "ocid1.key.A")]
        prov._get_client = lambda: SimpleNamespace(
            get_key=lambda ocid: SimpleNamespace(data=SimpleNamespace(time_of_deletion=when))
        )
        return prov

    def test_state_probe_reports_the_providers_own_date(self):
        when = timezone.now() + datetime.timedelta(days=5)

        state = self._provisioner_with_get_key(when).describe_kek_state("ck-team1")

        assert state.effective_at == when

    def test_delete_of_an_already_scheduled_key_reports_it_too(self):
        when = timezone.now() + datetime.timedelta(days=5)
        prov = self._provisioner_with_get_key(when)

        outcome = prov.delete_kek("ck-team1", SiloRef("default", "team-1"), owner_prefix=_OWNER_PREFIX)

        assert outcome.effective_at == when

    def test_provisioning_refusal_carries_the_date(self):
        when = timezone.now() + datetime.timedelta(days=5)
        prov = self._provisioner_with_get_key(when)
        prov._create_key = lambda name, uid: pytest.fail("must not create over a pending key")

        with pytest.raises(KekPendingDeletionError) as excinfo:
            prov.ensure_kek("ck-team1", SiloRef("default", "team-1"))
        assert excinfo.value.effective_at == when

    def test_a_failed_lookup_falls_back_to_the_configured_window(self):
        # Advisory reads must degrade, never raise: an approximate date beats an
        # exception on a probe.
        prov = _provisioner()
        prov._list_keys = lambda: [_key("ck-team1", "PENDING_DELETION", "ocid1.key.A")]

        def _boom():
            raise RuntimeError("management endpoint unreachable")

        prov._get_client = _boom
        state = prov.describe_kek_state("ck-team1")

        assert state.is_pending_deletion is True
        assert 6 <= (state.effective_at - timezone.now()).days <= 7


class TestDescribeKekState:
    def test_live_key_is_active(self):
        prov = _provisioner()
        prov._list_keys = lambda: [_key("ck-team1", "ENABLED", "ocid1.key.A")]

        assert prov.describe_kek_state("ck-team1").state == KekState.ACTIVE

    def test_scheduled_key_reports_pending_with_its_date(self):
        when = timezone.now() + datetime.timedelta(days=5)
        prov = _provisioner()
        prov._list_keys = lambda: [
            SimpleNamespace(
                display_name="ck-team1",
                lifecycle_state="PENDING_DELETION",
                id="ocid1.key.A",
                time_of_deletion=when,
            )
        ]
        state = prov.describe_kek_state("ck-team1")

        assert state.is_pending_deletion is True
        assert state.effective_at == when

    def test_an_unknown_name_is_not_reported_as_active(self):
        # It may already be destroyed, or unreadable by this identity; neither is
        # evidence the key is healthy.
        prov = _provisioner()
        prov._list_keys = lambda: []

        assert prov.describe_kek_state("ck-team1").state == KekState.UNKNOWN

    def test_a_failed_probe_degrades_to_unknown(self):
        prov = _provisioner()

        def _boom():
            raise RuntimeError("service unavailable")

        prov._list_keys = _boom

        assert prov.describe_kek_state("ck-team1").state == KekState.UNKNOWN


class TestEnumeration:
    def test_lists_display_names_including_pending_keys(self):
        # A key inside the deletion window has not been destroyed yet, and its
        # name dropping out of this listing is what confirms that it was.
        prov = _provisioner()
        prov._list_keys = lambda: [
            _key("ck-team1", "ENABLED", "ocid1.key.A"),
            _key("ck-team2", "PENDING_DELETION", "ocid1.key.B"),
            _key("ck-team3", "DELETED", "ocid1.key.C"),
        ]

        assert prov.list_kek_names(_OWNER_PREFIX) == ["ck-team1", "ck-team2"]

    def test_foreign_keys_are_filtered_out(self):
        prov = _provisioner()
        prov._list_keys = lambda: [
            _key("ck-team1", "ENABLED", "ocid1.key.A"),
            _key("someone-elses-key", "ENABLED", "ocid1.key.B"),
        ]

        assert prov.list_kek_names(_OWNER_PREFIX) == ["ck-team1"]

    def test_a_duplicated_name_is_listed_once(self):
        # Reconcile works in names; the ambiguity is refused where it matters,
        # at resolution and deletion.
        prov = _provisioner()
        prov._list_keys = lambda: [
            _key("ck-team1", "ENABLED", "ocid1.key.A"),
            _key("ck-team1", "ENABLED", "ocid1.key.B"),
        ]

        assert prov.list_kek_names(_OWNER_PREFIX) == ["ck-team1"]


# ---------------------------------------------------------------------------
# Automatic rotation — the schedule rides the create call, and degrades when the
# vault cannot run one
# ---------------------------------------------------------------------------


def _rotating_provisioner(days=90):
    return OciKekProvisioner(
        {
            "OCI_VAULT_MANAGEMENT_ENDPOINT": _MGMT,
            "OCI_COMPARTMENT_OCID": _COMPARTMENT,
            "KEK_ROTATION_PERIOD_DAYS": days,
        }
    )


class _Rejected(Exception):
    """Stands in for oci.exceptions.ServiceError, which carries a ``status``."""

    def __init__(self, status):
        super().__init__(f"HTTP {status}")
        self.status = status


class TestRotationPolicy:
    def test_the_interval_goes_on_the_create_call(self):
        prov = _rotating_provisioner()
        sent = []
        prov._send_create = lambda name, uid, days: sent.append(days) or "ocid1.key.A"
        prov._wait_until_enabled = lambda key_id: None

        prov._create_key("ck-team1", "team:1")

        assert sent == [90]

    def test_no_option_sends_no_schedule(self):
        prov = _provisioner()
        sent = []
        prov._send_create = lambda name, uid, days: sent.append(days) or "ocid1.key.A"
        prov._wait_until_enabled = lambda key_id: None

        prov._create_key("ck-team1", "team:1")

        assert sent == [None]

    def test_a_refused_schedule_still_creates_the_key(self, caplog):
        # A standard vault cannot run automatic rotation. Failing the encrypt
        # would cost that deployment every key it ever provisions, so the key is
        # created without the schedule and the WARNING is the only signal.
        prov = _rotating_provisioner()
        attempts = []

        def _send(name, uid, days):
            attempts.append(days)
            if days:
                raise _Rejected(400)
            return "ocid1.key.A"

        prov._send_create = _send
        prov._find_key_by_name = lambda name, states=None: None
        prov._wait_until_enabled = lambda key_id: None

        with caplog.at_level("WARNING"):
            prov._create_key("ck-team1", "team:1")

        assert attempts == [90, None]
        assert "will not rotate on its own" in caplog.text
        assert "virtual private vault" in caplog.text

    def test_a_key_the_failed_call_did_create_is_adopted_not_duplicated(self, caplog):
        # OCI does not enforce unique display names, so a blind retry after an
        # ambiguous failure could leave two keys behind one name — only one of
        # which holds the material that decrypts what came after.
        prov = _rotating_provisioner()
        attempts = []

        def _send(name, uid, days):
            attempts.append(days)
            raise _Rejected(400)

        prov._send_create = _send
        prov._find_key_by_name = lambda name, states=None: _key(name, "ENABLED", "ocid1.key.EXISTING")
        waited = []
        prov._wait_until_enabled = waited.append

        with caplog.at_level("WARNING"):
            prov._create_key("ck-team1", "team:1")

        assert attempts == [90]
        assert waited == ["ocid1.key.EXISTING"]

    def test_a_failure_that_is_not_a_rejection_is_raised(self):
        # Authorization, throttling and the rest are not rotation problems;
        # retrying would only report the same error one call later.
        prov = _rotating_provisioner()

        def _send(name, uid, days):
            raise _Rejected(401)

        prov._send_create = _send

        with pytest.raises(_Rejected):
            prov._create_key("ck-team1", "team:1")

    def test_a_rejection_without_a_schedule_configured_is_raised(self):
        prov = _provisioner()

        def _send(name, uid, days):
            raise _Rejected(400)

        prov._send_create = _send

        with pytest.raises(_Rejected):
            prov._create_key("ck-team1", "team:1")

    def test_an_out_of_range_interval_is_refused_at_construction(self):
        # OCI takes 60 to 365 days. Refused here so ``manage.py check`` reports
        # it at deploy rather than the create call failing for the first tenant.
        with pytest.raises(EncryptionConfigurationError):
            _rotating_provisioner(days=30)
        with pytest.raises(EncryptionConfigurationError):
            _rotating_provisioner(days=400)
