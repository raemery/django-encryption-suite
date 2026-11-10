"""Tests for the configurable urllib request timeout (KMS_REQUEST_TIMEOUT_SECONDS).

The urllib-based KMS adapters and credential strategies honor a single,
provider-neutral ``KMS_REQUEST_TIMEOUT_SECONDS`` option in KMS_OPTIONS, falling back to
a 10-second default. SDK-backed adapters (AWS/Azure/OCI) are unaffected.
"""

from __future__ import annotations

from unittest.mock import patch

from encryption_suite.adapters._http import (
    DEFAULT_KMS_REQUEST_TIMEOUT,
    resolve_request_timeout,
)
from encryption_suite.adapters.credentials.hashicorp import HashiCorpVaultAppRoleStrategy
from encryption_suite.adapters.keks.strategies import PerSiloKekStrategy
from encryption_suite.adapters.key_stores.hashicorp import HashiCorpVaultAdapter
from encryption_suite.silo_ref import SiloRef


def _fake_resp(payload: dict):
    import json
    from unittest.mock import MagicMock

    resp = MagicMock()
    resp.read.return_value = json.dumps(payload).encode()
    resp.__enter__.return_value = resp
    resp.__exit__.return_value = False
    return resp


def test_resolve_request_timeout_default():
    assert resolve_request_timeout({}) == DEFAULT_KMS_REQUEST_TIMEOUT
    assert resolve_request_timeout({"KMS_REQUEST_TIMEOUT_SECONDS": None}) == DEFAULT_KMS_REQUEST_TIMEOUT


def test_resolve_request_timeout_explicit():
    assert resolve_request_timeout({"KMS_REQUEST_TIMEOUT_SECONDS": 2}) == 2
    assert resolve_request_timeout({"KMS_REQUEST_TIMEOUT_SECONDS": 0.5}) == 0.5


def test_adapter_default_timeout():
    opts = {
        "VAULT_ENDPOINT": "https://v.example.com:8200",
        "VAULT_TOKEN": "hvs.test",
        "KEK_TEMPLATE": "kms-{silo_uid}",
    }
    adapter = HashiCorpVaultAdapter(opts, PerSiloKekStrategy(opts))
    assert adapter._request_timeout == DEFAULT_KMS_REQUEST_TIMEOUT


def test_adapter_request_passes_configured_timeout():
    opts = {
        "VAULT_ENDPOINT": "https://v.example.com:8200",
        "VAULT_TOKEN": "hvs.test",
        "KEK_TEMPLATE": "kms-{silo_uid}",
        "KMS_REQUEST_TIMEOUT_SECONDS": 3,
    }
    adapter = HashiCorpVaultAdapter(opts, PerSiloKekStrategy(opts))
    assert adapter._request_timeout == 3

    captured = {}

    def _fake_urlopen(req, timeout, context):
        captured["timeout"] = timeout
        return _fake_resp({"data": {"ciphertext": "vault:v1:abc"}})

    with patch("urllib.request.urlopen", side_effect=_fake_urlopen):
        adapter.encrypt_key(b"plaintext", SiloRef("default", "team-1"))

    assert captured["timeout"] == 3


def test_credential_strategy_passes_configured_timeout():
    opts = {
        "VAULT_ENDPOINT": "https://v.example.com:8200",
        "VAULT_ROLE_ID": "r",
        "VAULT_SECRET_ID": "s",
        "KMS_REQUEST_TIMEOUT_SECONDS": 4,
    }
    strategy = HashiCorpVaultAppRoleStrategy(opts)

    captured = {}

    def _fake_urlopen(req, timeout, context):
        captured["timeout"] = timeout
        return _fake_resp({"auth": {"client_token": "hvs.x"}})

    with patch("urllib.request.urlopen", side_effect=_fake_urlopen):
        strategy.get_credentials()

    assert captured["timeout"] == 4
