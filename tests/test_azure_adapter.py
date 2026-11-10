"""AzureKeyVaultAdapter: AES-GCM wrapping, AAD binding, and version pinning.

Azure is the one provider whose ciphertext cannot tell the vault which key
version produced it, so the version travels on the row and unwrapping has to use
it. Key Vault also hands back the iv and authentication tag as separate values,
so the adapter frames all three into the single stored blob. Both are asserted
here against a fake SDK — the ``azure`` extra is not a test dependency.
"""

from __future__ import annotations

import sys
import types

import pytest

from encryption_suite.adapters.keks.strategies import PerSiloKekStrategy, SharedKekStrategy
from encryption_suite.adapters.key_stores.azure import AzureKeyVaultAdapter, _frame, _unframe
from encryption_suite.adapters.key_stores.base import KmsMetadata
from encryption_suite.silo_ref import SiloRef

_VAULT = "https://es-prod.vault.azure.net"
_OPTIONS = {"AZURE_VAULT_ENDPOINT": _VAULT, "KEK_TEMPLATE": "es-prod-{silo_uid}"}
_AAD = b"django-encryption-suite:dek:default:team-1"


class _FakeEncryptResult:
    def __init__(self, ciphertext, iv, tag):
        self.ciphertext = ciphertext
        self.iv = iv
        self.tag = tag


class _FakeDecryptResult:
    def __init__(self, plaintext):
        self.plaintext = plaintext


class _FakeVault:
    """Records every call the adapter makes, across both SDK clients."""

    def __init__(self, versions=None):
        # key name → the version the vault currently reports.
        self.versions = dict(versions or {"es-prod-team--1": "v1"})
        self.get_key_calls: list[str] = []
        self.encrypt_calls: list[tuple] = []
        self.decrypt_calls: list[tuple] = []

    def rotate(self, key_name, version):
        self.versions[key_name] = version


@pytest.fixture
def vault(monkeypatch):
    """Install a fake ``azure`` SDK for the duration of one test."""
    state = _FakeVault()

    class _FakeCryptographyClient:
        def __init__(self, key, credential):
            self.key_id = key

        def encrypt(self, algorithm, plaintext, *, additional_authenticated_data=None, **kwargs):
            state.encrypt_calls.append((self.key_id, algorithm, plaintext, additional_authenticated_data))
            # The fake "wraps" by tagging the plaintext with the key version and
            # the aad, so a decrypt under the wrong one is detectable.
            return _FakeEncryptResult(ciphertext=b"ct:" + plaintext, iv=b"i" * 12, tag=b"t" * 16)

        def decrypt(self, algorithm, ciphertext, *, iv=None, authentication_tag=None, **kwargs):
            aad = kwargs.get("additional_authenticated_data")
            state.decrypt_calls.append((self.key_id, algorithm, ciphertext, iv, authentication_tag, aad))
            expected_aad = getattr(state, "expected_aad", _AAD)
            if aad != expected_aad:
                raise RuntimeError("Key Vault: authentication tag mismatch")
            return _FakeDecryptResult(plaintext=ciphertext.removeprefix(b"ct:"))

    class _FakeKeyClient:
        def __init__(self, vault_url, credential):
            self.vault_url = vault_url

        def get_key(self, name, version=None):
            state.get_key_calls.append(name)
            properties = types.SimpleNamespace(version=state.versions[name])
            return types.SimpleNamespace(name=name, properties=properties)

    class _EncryptionAlgorithm:
        a256_gcm = "A256GCM"

    azure = types.ModuleType("azure")
    keyvault = types.ModuleType("azure.keyvault")
    keys = types.ModuleType("azure.keyvault.keys")
    crypto = types.ModuleType("azure.keyvault.keys.crypto")
    identity = types.ModuleType("azure.identity")

    keys.KeyClient = _FakeKeyClient
    crypto.CryptographyClient = _FakeCryptographyClient
    crypto.EncryptionAlgorithm = _EncryptionAlgorithm
    identity.DefaultAzureCredential = lambda *a, **kw: object()

    for name, module in [
        ("azure", azure),
        ("azure.keyvault", keyvault),
        ("azure.keyvault.keys", keys),
        ("azure.keyvault.keys.crypto", crypto),
        ("azure.identity", identity),
    ]:
        monkeypatch.setitem(sys.modules, name, module)
    return state


def _adapter(options=None, strategy_cls=PerSiloKekStrategy):
    options = {**_OPTIONS, **(options or {})}
    return AzureKeyVaultAdapter(options, AzureKeyVaultAdapter.build_strategy(strategy_cls, options))


class TestFraming:
    def test_round_trip(self):
        assert _unframe(_frame(b"i" * 12, b"t" * 16, b"ct")) == (b"i" * 12, b"t" * 16, b"ct")

    def test_lengths_other_than_the_common_ones_survive(self):
        # The frame is length-prefixed rather than fixed-width, so a vault that
        # returns a 16-byte iv is not silently misread.
        assert _unframe(_frame(b"i" * 16, b"t" * 12, b"ct")) == (b"i" * 16, b"t" * 12, b"ct")

    def test_a_blob_from_another_algorithm_is_refused(self):
        # An RSA-wrapped row, or one from a future format: better an explicit
        # refusal than bytes Key Vault rejects with a vaguer message.
        with pytest.raises(ValueError):
            _unframe(b"\x99 not a frame")

    def test_a_truncated_frame_is_refused(self):
        blob = _frame(b"i" * 12, b"t" * 16, b"ct")
        with pytest.raises(ValueError):
            _unframe(blob[:20])

    def test_an_empty_ciphertext_is_refused(self):
        with pytest.raises(ValueError):
            _unframe(_frame(b"i" * 12, b"t" * 16, b""))


class TestCanonicalName:
    def test_bare_name_is_qualified(self, vault):
        assert _adapter().canonical_kek_name("es-prod-team-1") == "keys/es-prod-team-1"

    def test_a_version_is_dropped(self, vault):
        # The key encryption key's identity is the key, not one rotation of it.
        assert _adapter().canonical_kek_name(f"{_VAULT}/keys/es-prod-team-1/v7") == "keys/es-prod-team-1"

    def test_idempotent(self, vault):
        adapter = _adapter()
        once = adapter.canonical_kek_name("es-prod-team-1")

        assert adapter.canonical_kek_name(once) == once

    def test_the_owner_prefix_stays_a_prefix(self, vault):
        adapter = _adapter()
        prefix = adapter.owner_prefix()

        assert prefix == "keys/es-prod-"
        assert adapter.canonical_kek_name("es-prod-team--1").startswith(prefix)


class TestWrap:
    def test_records_the_version_that_wrapped(self, vault):
        _, metadata = _adapter().encrypt_key(b"dek", SiloRef("default", "team-1"))

        # The name identifies the key; the version travels in its own field, so
        # the key encryption key's identity never varies per rotation.
        assert metadata.kek_resource_name == "keys/es-prod-team--1"
        assert metadata.kek_key_version == "v1"
        assert metadata.kms_provider == "azure"

    def test_binds_the_silo_uid_as_associated_data(self, vault):
        _adapter().encrypt_key(b"dek", SiloRef("default", "team-1"))

        assert vault.encrypt_calls[0][3] == _AAD

    def test_stores_iv_and_tag_with_the_ciphertext(self, vault):
        blob, _ = _adapter().encrypt_key(b"dek", SiloRef("default", "team-1"))

        assert _unframe(blob) == (b"i" * 12, b"t" * 16, b"ct:dek")

    def test_round_trips(self, vault):
        adapter = _adapter()
        blob, metadata = adapter.encrypt_key(b"dek", SiloRef("default", "team-1"))

        assert adapter.decrypt_key(blob, metadata, SiloRef("default", "team-1")) == b"dek"

    def test_a_shared_kek_is_allowed(self, vault):
        # AES-GCM takes associated data, so one key across silos keeps a
        # per-tenant boundary — unlike a wrap with no AAD parameter.
        options = {**_OPTIONS, "SHARED_KEK_ID": "es-prod-shared"}
        adapter = AzureKeyVaultAdapter(options, AzureKeyVaultAdapter.build_strategy(SharedKekStrategy, options))
        vault.versions["es-prod-shared"] = "v1"

        _, metadata = adapter.encrypt_key(b"dek", SiloRef("default", "team-1"))

        assert metadata.kek_resource_name == "keys/es-prod-shared"
        assert metadata.kek_key_version == "v1"
        assert vault.encrypt_calls[0][3] == _AAD


class TestUnwrapUsesTheRecordedVersion:
    def test_a_rotated_key_still_unwraps_old_rows(self, vault):
        # The point of recording the version: rotation adds a version, and every
        # DEK wrapped under the old one has to stay readable.
        adapter = _adapter()
        blob, metadata = adapter.encrypt_key(b"dek", SiloRef("default", "team-1"))
        vault.rotate("es-prod-team--1", "v2")

        assert adapter.decrypt_key(blob, metadata, SiloRef("default", "team-1")) == b"dek"
        assert vault.decrypt_calls[-1][0] == f"{_VAULT}/keys/es-prod-team--1/v1"

    def test_a_new_wrap_after_rotation_uses_the_new_version(self, vault):
        adapter = _adapter({"KEY_VERSION_TTL_SECONDS": 0})
        adapter.encrypt_key(b"dek", SiloRef("default", "team-1"))
        vault.rotate("es-prod-team--1", "v2")

        _, metadata = adapter.encrypt_key(b"dek", SiloRef("default", "team-1"))

        assert metadata.kek_key_version == "v2"
        assert metadata.kek_resource_name == "keys/es-prod-team--1"

    def test_a_row_with_no_version_falls_back_to_current(self, vault):
        # A row written before the key was ever rotated. Correct only while that
        # remains true, which is why wraps always record a version.
        adapter = _adapter()
        blob, _ = adapter.encrypt_key(b"dek", SiloRef("default", "team-1"))
        metadata = KmsMetadata(kek_resource_name="keys/es-prod-team--1", kms_provider="azure")

        assert adapter.decrypt_key(blob, metadata, SiloRef("default", "team-1")) == b"dek"
        assert vault.decrypt_calls[-1][0] == f"{_VAULT}/keys/es-prod-team--1/v1"


class TestAadBinding:
    def test_a_row_moved_to_another_silo_fails_to_decrypt(self, vault):
        adapter = _adapter()
        blob, metadata = adapter.encrypt_key(b"dek", SiloRef("default", "team-1"))

        with pytest.raises(RuntimeError):
            adapter.decrypt_key(blob, metadata, SiloRef("default", "team-2"))

    def test_the_aad_matches_the_other_providers(self, vault):
        # Byte-identical to what GCP sends as additionalAuthenticatedData and
        # AWS as its EncryptionContext, so the binding is the same claim.
        adapter = _adapter()
        adapter.encrypt_key(b"dek", SiloRef("default", "team-1"))

        assert vault.encrypt_calls[0][3] == adapter._wrap_aad(SiloRef("default", "team-1"))


class TestCurrentVersionLookup:
    def test_reused_within_the_ttl(self, vault):
        adapter = _adapter({"KEY_VERSION_TTL_SECONDS": 300})
        adapter.encrypt_key(b"dek", SiloRef("default", "team-1"))
        adapter.encrypt_key(b"dek", SiloRef("default", "team-1"))

        assert vault.get_key_calls == ["es-prod-team--1"]

    def test_refetched_once_the_ttl_expires(self, vault):
        # Without this a long-running worker keeps wrapping under the old
        # version after a rotation, leaving the rotation half-done.
        adapter = _adapter({"KEY_VERSION_TTL_SECONDS": 0})
        adapter.encrypt_key(b"dek", SiloRef("default", "team-1"))
        adapter.encrypt_key(b"dek", SiloRef("default", "team-1"))

        assert vault.get_key_calls == ["es-prod-team--1", "es-prod-team--1"]

    def test_a_pinned_version_skips_the_lookup(self, vault):
        adapter = _adapter({"AZURE_KEY_VERSION": "v9"})

        _, metadata = adapter.encrypt_key(b"dek", SiloRef("default", "team-1"))

        assert metadata.kek_key_version == "v9"
        assert vault.get_key_calls == []
