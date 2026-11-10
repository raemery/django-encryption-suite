"""Unit tests for HashiCorp Vault credential strategies and adapter mount-path config."""

from __future__ import annotations

import json
from unittest.mock import patch

import pytest

from encryption_suite.adapters.credentials.hashicorp import (
    HashiCorpVaultAppRoleStrategy,
    HashiCorpVaultTokenStrategy,
)
from encryption_suite.adapters.keks.strategies import PerSiloKekStrategy
from encryption_suite.adapters.key_stores.base import KmsMetadata
from encryption_suite.adapters.key_stores.hashicorp import HashiCorpVaultAdapter
from encryption_suite.exceptions import EncryptionConfigurationError
from encryption_suite.silo_ref import SiloRef


def _fake_resp(payload: dict):
    """Return a context manager mimicking urlopen()'s return value."""

    class _CM:
        def __enter__(self_inner):
            return self_inner

        def __exit__(self_inner, *exc):
            return False

        def read(self_inner):
            return json.dumps(payload).encode()

    return _CM()


def test_token_strategy_returns_static_token():
    s = HashiCorpVaultTokenStrategy({"VAULT_TOKEN": "hvs.abc"})
    assert s.get_credentials() == "hvs.abc"


def test_approle_login_posts_role_and_secret_id():
    captured = {}

    def _fake_urlopen(req, timeout, context):
        captured["url"] = req.full_url
        captured["body"] = json.loads(req.data.decode())
        captured["headers"] = dict(req.headers)
        return _fake_resp({"auth": {"client_token": "hvs.client"}})

    s = HashiCorpVaultAppRoleStrategy(
        {
            "VAULT_ENDPOINT": "https://vault.example.com:8200",
            "VAULT_ROLE_ID": "role-uuid",
            "VAULT_SECRET_ID": "secret-uuid",
            "VAULT_NAMESPACE": "admin",
        }
    )
    with patch("urllib.request.urlopen", side_effect=_fake_urlopen):
        token = s.get_credentials()

    assert token == "hvs.client"
    assert captured["url"] == "https://vault.example.com:8200/v1/auth/approle/login"
    assert captured["body"] == {"role_id": "role-uuid", "secret_id": "secret-uuid"}
    assert captured["headers"]["X-vault-namespace"] == "admin"


def test_approle_caches_token_until_invalidate():
    calls = []

    def _fake_urlopen(req, timeout, context):
        calls.append(req.full_url)
        return _fake_resp({"auth": {"client_token": f"hvs.{len(calls)}"}})

    s = HashiCorpVaultAppRoleStrategy(
        {
            "VAULT_ENDPOINT": "https://v.example.com:8200",
            "VAULT_ROLE_ID": "r",
            "VAULT_SECRET_ID": "s",
        }
    )
    with patch("urllib.request.urlopen", side_effect=_fake_urlopen):
        assert s.get_credentials() == "hvs.1"
        assert s.get_credentials() == "hvs.1"
        s.invalidate()
        assert s.get_credentials() == "hvs.2"
    assert len(calls) == 2


def test_approle_reads_secret_id_from_file(tmp_path):
    secret_file = tmp_path / "sid"
    secret_file.write_text("file-secret\n")

    captured = {}

    def _fake_urlopen(req, timeout, context):
        captured["body"] = json.loads(req.data.decode())
        return _fake_resp({"auth": {"client_token": "hvs.x"}})

    s = HashiCorpVaultAppRoleStrategy(
        {
            "VAULT_ENDPOINT": "https://v.example.com:8200",
            "VAULT_ROLE_ID": "r",
            "VAULT_SECRET_ID_FILE": str(secret_file),
        }
    )
    with patch("urllib.request.urlopen", side_effect=_fake_urlopen):
        s.get_credentials()

    assert captured["body"]["secret_id"] == "file-secret"


def test_approle_missing_secret_id_raises():
    s = HashiCorpVaultAppRoleStrategy(
        {
            "VAULT_ENDPOINT": "https://v.example.com:8200",
            "VAULT_ROLE_ID": "r",
        }
    )
    with pytest.raises(EncryptionConfigurationError) as excinfo:
        s.get_credentials()
    assert "VAULT_SECRET_ID" in excinfo.value.detail


def test_approle_custom_mount_path():
    captured = {}

    def _fake_urlopen(req, timeout, context):
        captured["url"] = req.full_url
        return _fake_resp({"auth": {"client_token": "hvs.x"}})

    s = HashiCorpVaultAppRoleStrategy(
        {
            "VAULT_ENDPOINT": "https://v.example.com:8200",
            "VAULT_ROLE_ID": "r",
            "VAULT_SECRET_ID": "s",
            "VAULT_APPROLE_MOUNT": "approle-prod",
        }
    )
    with patch("urllib.request.urlopen", side_effect=_fake_urlopen):
        s.get_credentials()

    assert captured["url"].endswith("/v1/auth/approle-prod/login")


# ---------------------------------------------------------------------------
# HashiCorpVaultAdapter — VAULT_MOUNT_PATH
# ---------------------------------------------------------------------------


def _make_adapter(mount_path: str | None = None):
    opts = {
        "VAULT_ENDPOINT": "https://v.example.com:8200",
        "VAULT_TOKEN": "hvs.test",
        "KEK_TEMPLATE": "kms-{silo_uid}",
    }
    if mount_path is not None:
        opts["VAULT_MOUNT_PATH"] = mount_path
    return HashiCorpVaultAdapter(opts, PerSiloKekStrategy(opts))


def test_kms_default_mount_path_is_transit():
    adapter = _make_adapter()
    assert adapter._mount == "transit"


def test_kms_custom_mount_path_used_in_request_url():
    adapter = _make_adapter(mount_path="transit-prod")
    captured = {}

    def _fake_urlopen(req, timeout, context):
        captured["url"] = req.full_url
        return _fake_resp({"data": {"ciphertext": "vault:v1:abc"}})

    with patch("urllib.request.urlopen", side_effect=_fake_urlopen):
        _, meta = adapter.encrypt_key(b"plaintext", SiloRef("default", "team-1"))

    assert "/v1/transit-prod/encrypt/kms-team-1" in captured["url"]
    # The mount is part of the request path, never part of the recorded name:
    # rows carry the bare key name, which is what the provisioner lists and what
    # the owner prefix is a prefix of.
    assert meta.kek_resource_name == "kms-team-1"


def test_kms_decrypt_strips_mount_prefix_from_resource():
    adapter = _make_adapter(mount_path="transit-prod")

    def _fake_urlopen(req, timeout, context):
        # Vault returns base64-encoded plaintext.
        return _fake_resp({"data": {"plaintext": "cGxhaW50ZXh0"}})

    meta = KmsMetadata(
        kek_resource_name="https://v.example.com:8200/transit-prod/kms-team-1",
        kms_provider="hashicorp",
    )
    with patch("urllib.request.urlopen", side_effect=_fake_urlopen):
        result = adapter.decrypt_key(b"vault:v1:abc", meta, SiloRef("default", "team-1"))

    assert result == b"plaintext"


def test_kms_mount_path_strips_slashes():
    adapter = _make_adapter(mount_path="/transit-prod/")
    assert adapter._mount == "transit-prod"
