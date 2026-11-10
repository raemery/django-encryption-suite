"""Tests for the env key store adapter, one instance per ``ENV_KEY_STORES`` entry."""

import base64

import pytest
from django.test import override_settings

from encryption_suite.adapters.keks.strategies import SharedKekStrategy
from encryption_suite.adapters.key_stores.environment import EnvKeyStoreAdapter
from encryption_suite.checks import check_kms_settings
from encryption_suite.exceptions import EncryptionConfigurationError, KekNotProvisionedError
from encryption_suite.silo_ref import SiloRef

_V1 = base64.b64encode(b"\x01" * 32).decode()
_V2 = base64.b64encode(b"\x02" * 32).decode()
_TEAM_1 = SiloRef("default", "team-1")
_TEAM_2 = SiloRef("default", "team-2")


def _adapter(versions):
    options = {"SHARED_KEK_ID": "shared", "KEKS": versions}
    return EnvKeyStoreAdapter(options, EnvKeyStoreAdapter.build_strategy(SharedKekStrategy, options))


def _with_keks(versions, **settings):
    from django.conf import settings as django_settings

    return override_settings(
        ENCRYPTION={**django_settings.ENCRYPTION, "ENV_KEY_STORES": {"login": {"KEKS": versions}}}, **settings
    )


class TestVersions:
    def test_new_wraps_use_the_highest_version_and_record_it(self):
        adapter = _adapter({1: _V1, 2: _V2})
        _ciphertext, metadata = adapter.encrypt_key(b"dek", _TEAM_1)
        assert metadata.kek_key_version == "2"
        assert adapter.current_kek_version(_TEAM_1) == "2"

    def test_a_row_reads_under_the_version_it_recorded(self):
        ciphertext, metadata = _adapter({1: _V1}).encrypt_key(b"dek-plaintext", _TEAM_1)
        assert _adapter({1: _V1, 2: _V2}).decrypt_key(ciphertext, metadata, _TEAM_1) == b"dek-plaintext"

    def test_a_dropped_version_is_a_typed_error_naming_it(self, caplog):
        ciphertext, metadata = _adapter({1: _V1}).encrypt_key(b"dek", _TEAM_1)
        with pytest.raises(KekNotProvisionedError) as excinfo:
            _adapter({2: _V2}).decrypt_key(ciphertext, metadata, _TEAM_1)
        assert 'version "1"' in excinfo.value.detail
        assert "kek_not_provisioned" in caplog.text
        assert "KEKS" not in str(excinfo.value)

    def test_every_silo_resolves_to_one_key(self):
        adapter = _adapter({1: _V1})
        assert adapter.resolve_kek_name(_TEAM_1) == adapter.resolve_kek_name(_TEAM_2) == "shared"
        assert adapter.kek_strategy.kek_disposition(_TEAM_1) == "shared"


class TestConstruction:
    @pytest.mark.parametrize(
        "value",
        [
            {"1": _V1},
            {0: _V1},
            {True: _V1},
            {1: "not base64 !!!"},
            {1: base64.b64encode(b"short").decode()},
            "not a dict",
        ],
    )
    def test_a_badly_shaped_value_is_refused(self, value):
        with pytest.raises(EncryptionConfigurationError):
            _adapter(value)

    @pytest.mark.parametrize("debug", [True, False])
    def test_an_empty_value_is_refused_whatever_debug_says(self, debug):
        """There is no ephemeral key: a missing variable must never silently produce a new key."""
        with override_settings(DEBUG=debug), pytest.raises(EncryptionConfigurationError):
            _adapter({})

    def test_the_refusal_names_nothing_to_an_end_user(self):
        with pytest.raises(EncryptionConfigurationError) as excinfo:
            _adapter({})
        assert "KEKS" not in str(excinfo.value)
        assert "KEKS" in excinfo.value.detail


class TestWrapBinding:
    def test_a_wrapped_dek_does_not_unwrap_under_another_silo(self):
        adapter = _adapter({1: _V1})
        ciphertext, metadata = adapter.encrypt_key(b"dek-plaintext", SiloRef("default", "silo-1"))
        with pytest.raises(Exception):  # noqa: B017 — AESGCM raises InvalidTag
            adapter.decrypt_key(ciphertext, metadata, SiloRef("default", "silo-2"))

    def test_a_wrapped_dek_does_not_unwrap_under_another_kind_with_the_same_uid(self):
        adapter = _adapter({1: _V1})
        ciphertext, metadata = adapter.encrypt_key(b"dek-plaintext", SiloRef("default", "5"))
        with pytest.raises(Exception):  # noqa: B017 — AESGCM raises InvalidTag
            adapter.decrypt_key(ciphertext, metadata, SiloRef("user", "5"))

    def test_it_does_not_depend_on_the_crypto_backend(self):
        """The wrap is the key store's own AES-256-GCM, whatever CRYPTO_BACKEND is."""
        from django.conf import settings

        backend = "encryption_suite.adapters.crypto_backends.cryptography.CryptographyCryptoEngine"
        ciphertext, metadata = _adapter({1: _V1}).encrypt_key(b"dek-plaintext", _TEAM_1)
        with override_settings(ENCRYPTION={**settings.ENCRYPTION, "CRYPTO_BACKEND": backend}):
            assert _adapter({1: _V1}).decrypt_key(ciphertext, metadata, _TEAM_1) == b"dek-plaintext"

    def test_it_reports_no_kms_instance(self):
        assert _adapter({1: _V1}).describe_instance() is None


class TestDeployCheck:
    def test_a_bad_env_store_fails_manage_py_check(self):
        with _with_keks({1: "bm90LWEta2V5"}):
            errors = check_kms_settings(None)
        assert "encryption_suite.E039" in [error.id for error in errors]

    def test_an_empty_env_store_fails_manage_py_check(self):
        with _with_keks({}):
            errors = check_kms_settings(None)
        assert "encryption_suite.E039" in [error.id for error in errors]

    def test_a_per_silo_setting_on_an_env_store_is_refused(self):
        from django.conf import settings

        entry = {"KEKS": {1: _V1}, "KEK_TEMPLATE": "kek-{silo_uid}"}
        with override_settings(ENCRYPTION={**settings.ENCRYPTION, "ENV_KEY_STORES": {"login": entry}}):
            errors = check_kms_settings(None)
        assert "encryption_suite.E037" in [error.id for error in errors]

    def test_a_name_in_both_registries_is_refused(self):
        from django.conf import settings

        both = {**settings.ENCRYPTION["ENV_KEY_STORES"], "local": {"KEKS": {1: _V1}}}
        with override_settings(ENCRYPTION={**settings.ENCRYPTION, "ENV_KEY_STORES": both}):
            errors = check_kms_settings(None)
        assert "encryption_suite.E037" in [error.id for error in errors]

    def test_a_key_set_pointed_at_an_env_store_is_a_valid_configuration(self):
        from django.conf import settings

        from tests.key_set_settings import key_sets

        with override_settings(ENCRYPTION={**settings.ENCRYPTION, "KEY_SETS": key_sets(default="login")}):
            assert [e.id for e in check_kms_settings(None)] == []
