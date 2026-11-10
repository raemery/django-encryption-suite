"""Tests for the pluggable crypto backend abstraction (Phase A).

Covers the default Tink backend round-trip through the
:class:`~encryption_suite.adapters.crypto_backends.base.AbstractCryptoEngine`
interface, the ``crypto_backend`` marker written onto every
``DataEncryptionKey`` row, routing each row to the backend it records, the
refusal of a row whose backend no installation here can build or whose keyset
is not that backend's, and the deploy-time construction check (E005) for a
misconfigured backend.
"""

from __future__ import annotations

import copy
import logging

import pytest
from django.conf import settings
from django.test import override_settings

from encryption_suite import registry
from encryption_suite.adapters.crypto_backends.tink import TinkCryptoEngine
from encryption_suite.checks import check_kms_adapter_construction
from encryption_suite.engine import EncryptionEngine
from encryption_suite.exceptions import CryptoBackendMismatchError, EncryptionConfigurationError
from encryption_suite.models import DataEncryptionKey
from encryption_suite.registry import get_engine

ENGINE_LOGGER = "encryption_suite"


@pytest.fixture
def engine():
    eng = get_engine()
    EncryptionEngine.invalidate_cache()
    yield eng
    EncryptionEngine.invalidate_cache()


# ---------------------------------------------------------------------------
# Tink backend — standalone round-trip through the interface
# ---------------------------------------------------------------------------


def test_tink_backend_field_roundtrip():
    backend = TinkCryptoEngine({})
    dek = backend.generate_field_dek()
    primitive = backend.load_field_primitive(dek)
    ct = primitive.encrypt(b"hello", b"aad")
    assert primitive.decrypt(ct, b"aad") == b"hello"


def test_tink_backend_reports_backend_id():
    assert TinkCryptoEngine({}).backend_id == "tink"


def test_tink_backend_rejects_unknown_template():
    with pytest.raises(EncryptionConfigurationError):
        TinkCryptoEngine({"AEAD_KEY_TEMPLATE": "BOGUS"})
    with pytest.raises(EncryptionConfigurationError):
        TinkCryptoEngine({"STREAMING_AEAD_KEY_TEMPLATE": "BOGUS"})


# ---------------------------------------------------------------------------
# Backend marker — written onto field and file DEK rows
# ---------------------------------------------------------------------------


def test_field_dek_records_backend(engine, silo_context):
    engine.encrypt("a secret", silo=silo_context)
    row = DataEncryptionKey.objects.get(purpose=DataEncryptionKey.PURPOSE_FIELD)
    assert row.crypto_backend == "tink"


def test_file_dek_records_backend(engine, silo_context):
    engine.generate_and_store_file_keyset(silo_context)
    row = DataEncryptionKey.objects.get(purpose=DataEncryptionKey.PURPOSE_FILE)
    assert row.crypto_backend == "tink"


# ---------------------------------------------------------------------------
# _backend_for_row — unit
# ---------------------------------------------------------------------------


def test_each_shipped_backend_is_reachable_by_its_id(engine):
    assert engine._backend_for_row("tink", "gk-1") is engine.crypto_backend
    assert engine._backend_for_row("cryptography", "gk-1").backend_id == "cryptography"


def test_an_empty_stored_backend_uses_the_configured_one(engine):
    assert engine._backend_for_row("", "gk-1") is engine.crypto_backend


def test_an_unknown_backend_raises_and_logs_actionable_detail(engine, caplog):
    with caplog.at_level(logging.ERROR, logger=ENGINE_LOGGER):
        with pytest.raises(CryptoBackendMismatchError):
            engine._backend_for_row("homegrown", "gk-1")
    text = caplog.text
    assert "error_code=crypto_backend_mismatch" in text
    assert 'stored_backend="homegrown"' in text
    assert "DATABASE_URL" in text


# ---------------------------------------------------------------------------
# Integration — reads route by the recorded backend, on field and file paths
# ---------------------------------------------------------------------------


def test_a_row_reads_through_its_own_backend_after_crypto_backend_changes(engine, silo_context):
    """Changing CRYPTO_BACKEND decides new keys only; an existing key keeps reading."""
    stored = engine.encrypt("a field secret", silo=silo_context)
    cfg = copy.deepcopy(settings.ENCRYPTION)
    cfg["CRYPTO_BACKEND"] = "encryption_suite.adapters.crypto_backends.cryptography.CryptographyCryptoEngine"
    with override_settings(ENCRYPTION=cfg):
        registry.reset()
        EncryptionEngine.invalidate_cache()
        assert get_engine().decrypt(stored, silo=silo_context) == "a field secret"
    registry.reset()


def test_field_decrypt_path_guards_mismatch(engine, silo_context):
    engine.encrypt("a field secret", silo=silo_context)
    row = DataEncryptionKey.objects.get(purpose=DataEncryptionKey.PURPOSE_FIELD)
    row.crypto_backend = "cryptography"
    row.save(update_fields=["crypto_backend"])
    EncryptionEngine.invalidate_cache()

    with pytest.raises(CryptoBackendMismatchError):
        engine._decrypt_to_aead(row.silo_ref)


def test_file_decrypt_path_guards_mismatch(engine, silo_context):
    engine.generate_and_store_file_keyset(silo_context)
    row = DataEncryptionKey.objects.get(purpose=DataEncryptionKey.PURPOSE_FILE)
    row.crypto_backend = "cryptography"
    row.save(update_fields=["crypto_backend"])
    EncryptionEngine.invalidate_cache()

    with pytest.raises(CryptoBackendMismatchError):
        engine._decrypt_to_streaming_aead(row.silo_ref)


# ---------------------------------------------------------------------------
# Deploy-time construction check (E005)
# ---------------------------------------------------------------------------


def test_check_passes_for_default_backend():
    registry.reset()
    assert check_kms_adapter_construction(app_configs=None) == []


def test_check_flags_unknown_template():
    cfg = copy.deepcopy(settings.ENCRYPTION)
    cfg["CRYPTO_BACKEND_OPTIONS"] = {"AEAD_KEY_TEMPLATE": "BOGUS"}
    with override_settings(ENCRYPTION=cfg):
        registry.reset()
        errors = check_kms_adapter_construction(app_configs=None)
    assert "encryption_suite.E005" in {e.id for e in errors}


def test_check_flags_bad_backend_dotted_path():
    # A bad/missing dotted path (e.g. CRYPTO_BACKEND='fail' via a secret) makes
    # import_string raise ImportError; the check must report a clean E005 rather
    # than letting the ImportError escape as a raw traceback at deploy.
    cfg = copy.deepcopy(settings.ENCRYPTION)
    cfg["CRYPTO_BACKEND"] = "fail"
    with override_settings(ENCRYPTION=cfg):
        registry.reset()
        errors = check_kms_adapter_construction(app_configs=None)
    e005 = [e for e in errors if e.id == "encryption_suite.E005"]
    assert e005, {e.id for e in errors}
    # Message must name the offending setting, not just the bare import error.
    assert "CRYPTO_BACKEND" in e005[0].msg


def test_check_leaves_no_cached_backend():
    registry.reset()
    check_kms_adapter_construction(app_configs=None)
    assert registry._crypto_backend is None
