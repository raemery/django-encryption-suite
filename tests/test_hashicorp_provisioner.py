"""Unit tests for the HashiCorp Vault KEK provisioner's ``ensure_kek``.

The provisioner talks to the Vault HTTP API through ``_request`` (the seam
where the transport lives). These tests patch ``_request`` on each instance
and assert against the method / path / body the public method passes to it,
so they verify the GET-first probe and the create fall-through without a
live Vault.

The GET-first probe is not strictly required for correctness — Vault
Transit's ``POST /transit/keys/{name}`` is idempotent and does not rotate or
replace key material — but it matches the other REST provisioners (keeps
CreateKey out of the audit log for known keys) and these tests pin that
behavior. Non-404 errors must propagate raw so the engine's
``_ensure_kek`` funnel can translate them.
"""

from __future__ import annotations

import urllib.error

import pytest

from encryption_suite.adapters.keks.provisioners_hashicorp import HashiCorpVaultKekProvisioner
from encryption_suite.silo_ref import SiloRef

_ADDR = "https://vault.example.test:8200"


class _RecordingTransport:
    """Stand-in for ``_request``. Records calls; returns canned responses.

    Provide a list of ``(status, body_dict_or_exception)`` pairs. Each call
    pops the next response; an exception payload is raised, otherwise the
    dict is returned (``status`` is informational only).
    """

    def __init__(self, responses):
        self._responses = list(responses)
        self.calls: list[tuple[str, str, dict | None]] = []

    def __call__(self, method: str, path: str, body):
        self.calls.append((method, path, body))
        if not self._responses:
            raise AssertionError(f"Unexpected extra call: {method} {path} {body!r}")
        _status, payload = self._responses.pop(0)
        if isinstance(payload, BaseException):
            raise payload
        return payload


def _http(code: int, path: str = "transit/keys/dck_team_42") -> urllib.error.HTTPError:
    return urllib.error.HTTPError(url=path, code=code, msg="x", hdrs=None, fp=None)


def _provisioner(**extra) -> HashiCorpVaultKekProvisioner:
    return HashiCorpVaultKekProvisioner({"VAULT_ENDPOINT": _ADDR, **extra})


# ---------------------------------------------------------------------------
# Construction
# ---------------------------------------------------------------------------


class TestHashiCorpVaultKekProvisionerInit:
    def test_requires_vault_addr(self):
        # str(exc) is the generic user-safe message; the operator detail
        # (naming VAULT_ENDPOINT) is on .detail, not leaked to end users.
        with pytest.raises(ValueError) as excinfo:
            HashiCorpVaultKekProvisioner({})
        assert "VAULT_ENDPOINT" in excinfo.value.detail

    def test_default_mount(self):
        assert _provisioner()._mount == "transit"

    def test_custom_mount_strips_slashes(self):
        assert _provisioner(VAULT_MOUNT_PATH="/kv-transit/")._mount == "kv-transit"


# ---------------------------------------------------------------------------
# ensure_kek behavior
# ---------------------------------------------------------------------------


class TestHashiCorpVaultKekProvisionerEnsureKek:
    def test_skips_when_already_in_cache(self, monkeypatch):
        prov = _provisioner()
        prov._ensured.add("dck_team_42")

        transport = _RecordingTransport([])  # any call would assert
        monkeypatch.setattr(prov, "_request", transport)

        prov.ensure_kek("dck_team_42", SiloRef("default", "test:42"))
        assert transport.calls == []

    def test_get_200_caches_and_skips_create(self, monkeypatch):
        prov = _provisioner()
        transport = _RecordingTransport([(200, {"data": {"name": "dck_team_42"}})])
        monkeypatch.setattr(prov, "_request", transport)

        prov.ensure_kek("dck_team_42", SiloRef("default", "test:42"))

        assert len(transport.calls) == 1
        method, path, body = transport.calls[0]
        assert method == "GET"
        assert path == "transit/keys/dck_team_42"
        assert body is None
        assert "dck_team_42" in prov._ensured

    def test_get_404_triggers_create_with_defaults(self, monkeypatch):
        prov = _provisioner()
        transport = _RecordingTransport(
            [
                (404, _http(404)),
                (200, {}),
            ]
        )
        monkeypatch.setattr(prov, "_request", transport)

        prov.ensure_kek("dck_team_42", SiloRef("default", "test:42"))

        assert len(transport.calls) == 2

        method_get, path_get, body_get = transport.calls[0]
        assert method_get == "GET"
        assert path_get == "transit/keys/dck_team_42"
        assert body_get is None

        method_post, path_post, body_post = transport.calls[1]
        assert method_post == "POST"
        assert path_post == "transit/keys/dck_team_42"
        assert body_post == {
            "type": "aes256-gcm96",
            "exportable": False,
            "allow_plaintext_backup": False,
            "derived": False,
        }

        assert "dck_team_42" in prov._ensured

    def test_create_body_uses_configured_options(self, monkeypatch):
        prov = _provisioner(
            KEY_TYPE="rsa-4096",
            EXPORTABLE=True,
            ALLOW_PLAINTEXT_BACKUP=True,
            DERIVED=True,
        )
        transport = _RecordingTransport([(404, _http(404)), (200, {})])
        monkeypatch.setattr(prov, "_request", transport)

        prov.ensure_kek("k", SiloRef("default", "g"))

        _method, _path, body = transport.calls[1]
        assert body == {
            "type": "rsa-4096",
            "exportable": True,
            "allow_plaintext_backup": True,
            "derived": True,
        }

    def test_full_url_name_is_normalized(self, monkeypatch):
        prov = _provisioner()
        transport = _RecordingTransport([(200, {})])
        monkeypatch.setattr(prov, "_request", transport)

        # Strategy may pass a full URL of the form "{addr}/{mount}/{name}"
        # (matching the KMS adapter's stored kek_resource_name); only the bare
        # key name should be used for the API path.
        prov.ensure_kek(f"{_ADDR}/transit/dck_team_42", SiloRef("default", "test:42"))

        _method, path, _body = transport.calls[0]
        assert path == "transit/keys/dck_team_42"
        assert "dck_team_42" in prov._ensured

    def test_non_404_get_error_propagates_and_does_not_cache(self, monkeypatch):
        prov = _provisioner()
        transport = _RecordingTransport([(500, _http(500))])
        monkeypatch.setattr(prov, "_request", transport)

        with pytest.raises(urllib.error.HTTPError) as excinfo:
            prov.ensure_kek("k", SiloRef("default", "g"))
        assert excinfo.value.code == 500
        assert "k" not in prov._ensured

    def test_create_failure_does_not_cache(self, monkeypatch):
        prov = _provisioner()
        transport = _RecordingTransport([(404, _http(404)), (500, _http(500))])
        monkeypatch.setattr(prov, "_request", transport)

        with pytest.raises(urllib.error.HTTPError):
            prov.ensure_kek("k", SiloRef("default", "g"))
        assert "k" not in prov._ensured

    def test_describe_includes_addr_and_mount(self):
        out = _provisioner().describe()
        assert _ADDR in out
        assert "transit" in out


# ---------------------------------------------------------------------------
# Capabilities
# ---------------------------------------------------------------------------


class TestCapabilities:
    def test_class_attribute_reports_deletion_as_implemented(self):
        # The class attribute is the delete contract table's ledger: it records
        # that _do_delete_kek exists here, independent of any deployment config.
        assert HashiCorpVaultKekProvisioner.supports_delete is True

    def test_instance_reports_deletion_off_by_default(self):
        # Transit's per-key deletion_allowed latch is false on a new key, so
        # deleting from here overrides a provider-side protection and has to be
        # asked for.
        assert _provisioner().supports_delete is False

    def test_instance_reports_deletion_on_when_the_option_is_set(self):
        assert _provisioner(ALWAYS_ALLOW_KEY_DELETION=True).supports_delete is True

    def test_enumeration_is_supported(self):
        assert HashiCorpVaultKekProvisioner.supports_enumeration is True

    def test_state_check_stays_unsupported(self):
        # With no deletion window a key is present or gone, which enumeration
        # already answers.
        assert HashiCorpVaultKekProvisioner.supports_state_check is False

    def test_no_deletion_window_is_declared(self):
        assert HashiCorpVaultKekProvisioner.minimum_deletion_window_days is None


# ---------------------------------------------------------------------------
# Deletion
# ---------------------------------------------------------------------------


class TestDeletionGate:
    def test_purge_gate_retains_when_the_option_is_off(self):
        from encryption_suite.deletion import RETAIN_PROVISIONER_CANNOT_DELETE, evaluate_deletion
        from encryption_suite.models import KeyEncryptionKey

        eligible, reason = evaluate_deletion(
            KeyEncryptionKey.DISPOSITION_SILO_EXCLUSIVE,
            "dck_",
            _provisioner(),
            "dck_team_42",
        )
        assert eligible is False
        assert reason == RETAIN_PROVISIONER_CANNOT_DELETE

    def test_delete_kek_refuses_before_calling_the_provider(self, monkeypatch):
        from encryption_suite.exceptions import KekDeleteError

        prov = _provisioner()
        transport = _RecordingTransport([])  # any call would assert
        monkeypatch.setattr(prov, "_request", transport)

        with pytest.raises(KekDeleteError):
            prov.delete_kek("dck_team_42", SiloRef("default", "test:42"), owner_prefix="dck_")
        assert transport.calls == []


class TestDelete:
    def test_arms_the_latch_then_deletes(self, monkeypatch):
        prov = _provisioner(ALWAYS_ALLOW_KEY_DELETION=True)
        transport = _RecordingTransport([(200, {}), (204, {})])
        monkeypatch.setattr(prov, "_request", transport)

        outcome = prov.delete_kek("dck_team_42", SiloRef("default", "test:42"), owner_prefix="dck_")

        assert transport.calls[0] == ("POST", "transit/keys/dck_team_42/config", {"deletion_allowed": True})
        assert transport.calls[1] == ("DELETE", "transit/keys/dck_team_42", None)
        # Immediate and irreversible: nothing to wait for and nothing to purge.
        assert outcome.scheduled is False
        assert outcome.effective_at is not None

    def test_a_qualified_resource_name_is_reduced_to_the_key_name(self, monkeypatch):
        prov = _provisioner(ALWAYS_ALLOW_KEY_DELETION=True)
        transport = _RecordingTransport([(200, {}), (204, {})])
        monkeypatch.setattr(prov, "_request", transport)

        # Straight to the provider call: the ownership gate above it compares
        # against the recorded name space, which is what this reduction feeds.
        prov._do_delete_kek(f"{_ADDR}/transit/dck_team_42", "test:42")

        assert transport.calls[1] == ("DELETE", "transit/keys/dck_team_42", None)

    def test_forgets_the_key_so_a_recreate_provisions_again(self, monkeypatch):
        prov = _provisioner(ALWAYS_ALLOW_KEY_DELETION=True)
        prov._ensured.add("dck_team_42")
        transport = _RecordingTransport([(200, {}), (204, {})])
        monkeypatch.setattr(prov, "_request", transport)

        prov.delete_kek("dck_team_42", SiloRef("default", "test:42"), owner_prefix="dck_")

        assert "dck_team_42" not in prov._ensured

    def test_already_absent_counts_as_deleted(self, monkeypatch):
        prov = _provisioner(ALWAYS_ALLOW_KEY_DELETION=True)
        transport = _RecordingTransport([(200, {}), (404, _http(404))])
        monkeypatch.setattr(prov, "_request", transport)

        outcome = prov.delete_kek("dck_team_42", SiloRef("default", "test:42"), owner_prefix="dck_")

        assert outcome.scheduled is False

    def test_other_provider_errors_become_delete_errors(self, monkeypatch):
        from encryption_suite.exceptions import KekDeleteError

        prov = _provisioner(ALWAYS_ALLOW_KEY_DELETION=True)
        transport = _RecordingTransport([(200, {}), (403, _http(403))])
        monkeypatch.setattr(prov, "_request", transport)

        with pytest.raises(KekDeleteError):
            prov.delete_kek("dck_team_42", SiloRef("default", "test:42"), owner_prefix="dck_")


# ---------------------------------------------------------------------------
# Enumeration
# ---------------------------------------------------------------------------


class TestEnumeration:
    def test_lists_key_names_at_the_mount(self, monkeypatch):
        prov = _provisioner()
        transport = _RecordingTransport([(200, {"data": {"keys": ["dck_team_42", "other"]}})])
        monkeypatch.setattr(prov, "_request", transport)

        assert prov._do_list_kek_names("dck_") == ["dck_team_42", "other"]
        assert transport.calls[0] == ("GET", "transit/keys?list=true", None)

    def test_owner_prefix_filtering_is_applied_by_the_base(self, monkeypatch):
        prov = _provisioner()
        transport = _RecordingTransport([(200, {"data": {"keys": ["dck_team_42", "other"]}})])
        monkeypatch.setattr(prov, "_request", transport)

        assert prov.list_kek_names("dck_") == ["dck_team_42"]

    def test_an_empty_mount_answers_404_and_yields_no_names(self, monkeypatch):
        # Vault has no listing to return once the last key is gone, which is not
        # an error — reconcile must read it as "no keys", not as unavailable.
        prov = _provisioner()
        transport = _RecordingTransport([(404, _http(404))])
        monkeypatch.setattr(prov, "_request", transport)

        assert prov._do_list_kek_names("dck_") == []

    def test_other_listing_errors_propagate(self, monkeypatch):
        prov = _provisioner()
        transport = _RecordingTransport([(500, _http(500))])
        monkeypatch.setattr(prov, "_request", transport)

        with pytest.raises(urllib.error.HTTPError):
            prov._do_list_kek_names("dck_")


# ---------------------------------------------------------------------------
# Automatic rotation
# ---------------------------------------------------------------------------


class TestRotationPolicy:
    def test_declared_bounds(self):
        assert HashiCorpVaultKekProvisioner.supports_rotation_policy is True
        assert HashiCorpVaultKekProvisioner.minimum_rotation_days == 1
        assert HashiCorpVaultKekProvisioner.maximum_rotation_days is None

    def test_no_policy_is_written_when_unconfigured(self, monkeypatch):
        prov = _provisioner()
        transport = _RecordingTransport([(404, _http(404)), (200, {})])
        monkeypatch.setattr(prov, "_request", transport)

        prov.ensure_kek("dck_team_42", SiloRef("default", "test:42"))

        assert [c[1] for c in transport.calls] == ["transit/keys/dck_team_42"] * 2

    def test_configured_interval_is_written_in_seconds_after_creation(self, monkeypatch):
        prov = _provisioner(KEK_ROTATION_PERIOD_DAYS=30)
        transport = _RecordingTransport([(404, _http(404)), (200, {}), (200, {})])
        monkeypatch.setattr(prov, "_request", transport)

        prov.ensure_kek("dck_team_42", SiloRef("default", "test:42"))

        assert transport.calls[2] == (
            "POST",
            "transit/keys/dck_team_42/config",
            {"auto_rotate_period": 30 * 86400},
        )

    def test_no_policy_is_written_for_a_key_that_already_exists(self, monkeypatch):
        # The probe short-circuits before creation, so an existing key keeps
        # whatever schedule it has rather than having one reasserted per process.
        prov = _provisioner(KEK_ROTATION_PERIOD_DAYS=30)
        transport = _RecordingTransport([(200, {"data": {"name": "dck_team_42"}})])
        monkeypatch.setattr(prov, "_request", transport)

        prov.ensure_kek("dck_team_42", SiloRef("default", "test:42"))

        assert len(transport.calls) == 1

    def test_policy_failure_leaves_the_key_usable(self, monkeypatch):
        # A key that exists but rotates manually is a degradation, not a reason
        # to fail the encrypt that triggered provisioning.
        prov = _provisioner(KEK_ROTATION_PERIOD_DAYS=30)
        transport = _RecordingTransport([(404, _http(404)), (200, {}), (403, _http(403))])
        monkeypatch.setattr(prov, "_request", transport)

        assert prov.ensure_kek("dck_team_42", SiloRef("default", "test:42")) is True
        assert "dck_team_42" in prov._ensured

    def test_a_below_floor_interval_is_refused_at_construction(self):
        # The floor is 1 day, so only a nonsensical value can fall under it —
        # which is exactly the wiring mistake worth catching at deploy rather
        # than at the first tenant's provisioning call.
        from encryption_suite.exceptions import EncryptionConfigurationError

        with pytest.raises(EncryptionConfigurationError):
            _provisioner(KEK_ROTATION_PERIOD_DAYS=-1)
