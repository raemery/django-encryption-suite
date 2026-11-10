"""Adapter-side tests for the HashiCorp Vault leg: recorded name space and key version."""

from __future__ import annotations

import json
from unittest.mock import patch

import pytest

from encryption_suite.adapters.keks.strategies import PerSiloKekStrategy, SharedKekStrategy
from encryption_suite.adapters.key_stores.base import KmsMetadata
from encryption_suite.adapters.key_stores.hashicorp import HashiCorpVaultAdapter, version_from_ciphertext
from encryption_suite.exceptions import EncryptionConfigurationError
from encryption_suite.silo_ref import SiloRef


def _fake_resp(payload: dict):
    class _CM:
        def __enter__(self_inner):
            return self_inner

        def __exit__(self_inner, *exc):
            return False

        def read(self_inner):
            return json.dumps(payload).encode()

    return _CM()


def _make_adapter(**extra):
    opts = {
        "VAULT_ENDPOINT": "https://v.example.com:8200",
        "VAULT_TOKEN": "hvs.test",
        "KEK_TEMPLATE": "kms-{silo_uid}",
        **extra,
    }
    return HashiCorpVaultAdapter(opts, PerSiloKekStrategy(opts))


class TestVersionFromCiphertext:
    @pytest.mark.parametrize(
        ("ciphertext", "expected"),
        [
            ("vault:v1:abc", "1"),
            ("vault:v12:abc", "12"),
            ("vault:v3:", "3"),
        ],
    )
    def test_reads_the_version_prefix(self, ciphertext, expected):
        assert version_from_ciphertext(ciphertext) == expected

    @pytest.mark.parametrize(
        "ciphertext",
        [
            "",
            "abc",
            "vault:abc",
            "notvault:v1:abc",
            "vault:vX:abc",
            "vault:v:abc",
        ],
    )
    def test_unexpected_shapes_yield_empty_rather_than_raising(self, ciphertext):
        # The version is recorded for reporting, so a prefix we do not recognize
        # must leave the wrap itself alone.
        assert version_from_ciphertext(ciphertext) == ""


class TestOneKekPerSilo:
    """Transit binds nothing into a wrap, so two silos must never resolve to one key."""

    def test_rejects_shared_kek_strategy(self):
        opts = {"VAULT_ENDPOINT": "https://v.example.com:8200", "VAULT_TOKEN": "hvs.test", "SHARED_KEK_ID": "k"}
        with pytest.raises(EncryptionConfigurationError) as excinfo:
            HashiCorpVaultAdapter(opts, SharedKekStrategy(opts))
        assert "SharedKekStrategy" in excinfo.value.detail

    def test_rejects_a_template_with_no_silo_placeholder(self):
        with pytest.raises(EncryptionConfigurationError) as excinfo:
            _make_adapter(KEK_TEMPLATE="kms-shared")
        assert "{silo_uid}" in excinfo.value.detail

    def test_rejects_a_map_naming_one_key_for_two_silos(self):
        with pytest.raises(EncryptionConfigurationError) as excinfo:
            _make_adapter(KEK_MAP={"team-1": "byok", "team-2": "byok"})
        assert "'byok'" in excinfo.value.detail

    def test_accepts_a_map_naming_each_key_once(self):
        _make_adapter(KEK_MAP={"team-1": "byok-1", "team-2": "byok-2"})


class TestRecordedNameSpace:
    def test_encrypt_records_the_bare_key_name(self):
        adapter = _make_adapter()
        with patch("urllib.request.urlopen", return_value=_fake_resp({"data": {"ciphertext": "vault:v2:abc"}})):
            _, meta = adapter.encrypt_key(b"plaintext", SiloRef("default", "team-1"))

        # Not "{addr}/{mount}/{name}": the provisioner lists bare names and the
        # owner prefix is a prefix of one, so a qualified form would match nothing.
        assert meta.kek_resource_name == "kms-team-1"
        assert meta.kek_key_version == "2"

    def test_recorded_name_starts_with_the_owner_prefix(self):
        adapter = _make_adapter()
        with patch("urllib.request.urlopen", return_value=_fake_resp({"data": {"ciphertext": "vault:v1:abc"}})):
            _, meta = adapter.encrypt_key(b"plaintext", SiloRef("default", "team-1"))

        assert meta.kek_resource_name.startswith(adapter.owner_prefix())

    def test_resolved_name_equals_the_recorded_name(self):
        # resolve_kek_name is compared against stored rows and the provisioner's
        # listing; drift between it and what encrypt_key records is the defect
        # this leg exists to avoid.
        adapter = _make_adapter()
        with patch("urllib.request.urlopen", return_value=_fake_resp({"data": {"ciphertext": "vault:v1:abc"}})):
            _, meta = adapter.encrypt_key(b"plaintext", SiloRef("default", "team-1"))

        assert adapter.resolve_kek_name(SiloRef("default", "team-1")) == meta.kek_resource_name

    def test_decrypt_accepts_a_legacy_qualified_resource_name(self):
        adapter = _make_adapter(VAULT_MOUNT_PATH="transit-prod")
        captured = {}

        def _fake_urlopen(req, timeout, context):
            captured["url"] = req.full_url
            return _fake_resp({"data": {"plaintext": "cGxhaW50ZXh0"}})

        legacy = "https://v.example.com:8200/transit-prod/kms-team-1"
        meta = KmsMetadata(kek_resource_name=legacy, kms_provider="hashicorp")
        with patch("urllib.request.urlopen", side_effect=_fake_urlopen):
            assert adapter.decrypt_key(b"vault:v1:abc", meta, SiloRef("default", "team-1")) == b"plaintext"

        assert captured["url"].endswith("/v1/transit-prod/decrypt/kms-team-1")

    def test_decrypt_accepts_a_bare_resource_name(self):
        adapter = _make_adapter()
        captured = {}

        def _fake_urlopen(req, timeout, context):
            captured["url"] = req.full_url
            return _fake_resp({"data": {"plaintext": "cGxhaW50ZXh0"}})

        meta = KmsMetadata(kek_resource_name="kms-team-1", kms_provider="hashicorp")
        with patch("urllib.request.urlopen", side_effect=_fake_urlopen):
            adapter.decrypt_key(b"vault:v1:abc", meta, SiloRef("default", "team-1"))

        assert captured["url"].endswith("/v1/transit/decrypt/kms-team-1")


class TestCurrentKekVersion:
    def test_reads_latest_version_from_key_metadata(self):
        adapter = _make_adapter()
        with patch("urllib.request.urlopen", return_value=_fake_resp({"data": {"latest_version": 4}})):
            assert adapter.current_kek_version(SiloRef("default", "team-1")) == "4"

    def test_result_is_cached_for_the_ttl(self):
        adapter = _make_adapter()
        calls = []

        def _fake_urlopen(req, timeout, context):
            calls.append(req.full_url)
            return _fake_resp({"data": {"latest_version": 4}})

        with patch("urllib.request.urlopen", side_effect=_fake_urlopen):
            adapter.current_kek_version(SiloRef("default", "team-1"))
            adapter.current_kek_version(SiloRef("default", "team-1"))

        assert len(calls) == 1

    def test_zero_ttl_re_reads_so_a_rotation_is_seen(self):
        # A rotation bumps the version while leaving the name alone; a worker that
        # cached forever would keep reporting a superseded version and
        # reencrypt_keys would skip the rows that need re-wrapping.
        adapter = _make_adapter(KEY_VERSION_TTL_SECONDS=0)
        versions = iter([{"data": {"latest_version": 4}}, {"data": {"latest_version": 5}}])

        def _fake_urlopen(req, timeout, context):
            return _fake_resp(next(versions))

        with patch("urllib.request.urlopen", side_effect=_fake_urlopen):
            assert adapter.current_kek_version(SiloRef("default", "team-1")) == "4"
            assert adapter.current_kek_version(SiloRef("default", "team-1")) == "5"

    def test_lookup_failure_yields_empty_and_does_not_raise(self):
        adapter = _make_adapter()
        with patch("urllib.request.urlopen", side_effect=OSError("vault unreachable")):
            assert adapter.current_kek_version(SiloRef("default", "team-1")) == ""

    def test_failure_is_cached_so_it_cannot_issue_a_request_per_row(self):
        adapter = _make_adapter()
        calls = []

        def _fake_urlopen(req, timeout, context):
            calls.append(req.full_url)
            raise OSError("vault unreachable")

        with patch("urllib.request.urlopen", side_effect=_fake_urlopen):
            adapter.current_kek_version(SiloRef("default", "team-1"))
            adapter.current_kek_version(SiloRef("default", "team-1"))

        assert len(calls) == 1
