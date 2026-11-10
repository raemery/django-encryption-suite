"""Tests for ``EncryptionEngine._new_wrapped_keyset``.

The seam that generates DEK material and returns it wrapped, without deciding
where it lands. Both provisioning paths use it today; a caller that needs new
material somewhere other than the live ``DataEncryptionKey`` row uses the same
one, which is why the storage half is deliberately not in here.

Covers:
- the purpose picks the generator, so a file DEK is never minted for a field row
- an unknown purpose raises before the KMS is called at all
- a provider failure surfaces as a typed error, not the raw provider exception
- the wrapped bytes come back untouched, the metadata stamped with the KMS name
  the wrap went through, and nothing is persisted
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from encryption_suite.adapters.key_stores.base import KmsMetadata
from encryption_suite.exceptions import EncryptionError
from encryption_suite.models import DataEncryptionKey
from encryption_suite.registry import get_engine
from encryption_suite.silo_ref import SiloRef

pytestmark = pytest.mark.django_db

SILO_UID = SiloRef("default", "test:new-wrapped-keyset")
KEK_ID = "kek-for-new-wrapped-keyset"


def _metadata():
    return KmsMetadata(kek_resource_name=KEK_ID, kms_provider="local")


def test_field_purpose_uses_the_field_generator():
    engine = get_engine()
    with patch.object(engine.crypto_backend, "generate_field_dek", return_value=b"field-material") as field_gen:
        with patch.object(engine.crypto_backend, "generate_file_dek") as file_gen:
            with patch.object(
                engine.silo_kms_adapter, "encrypt_key", return_value=(b"wrapped", _metadata())
            ) as encrypt_key:
                result = engine._new_wrapped_keyset(SILO_UID, DataEncryptionKey.PURPOSE_FIELD, KEK_ID)

    assert result == (b"wrapped", KmsMetadata(kek_resource_name=KEK_ID, kms_provider="local", kms_name="local"))
    field_gen.assert_called_once_with()
    file_gen.assert_not_called()
    encrypt_key.assert_called_once_with(b"field-material", SILO_UID)


def test_file_purpose_uses_the_file_generator():
    engine = get_engine()
    with patch.object(engine.crypto_backend, "generate_file_dek", return_value=b"file-material") as file_gen:
        with patch.object(engine.crypto_backend, "generate_field_dek") as field_gen:
            with patch.object(
                engine.silo_kms_adapter, "encrypt_key", return_value=(b"wrapped", _metadata())
            ) as encrypt_key:
                result = engine._new_wrapped_keyset(SILO_UID, DataEncryptionKey.PURPOSE_FILE, KEK_ID)

    assert result[0] == b"wrapped"
    assert result[1].kms_name == "local"
    file_gen.assert_called_once_with()
    field_gen.assert_not_called()
    encrypt_key.assert_called_once_with(b"file-material", SILO_UID)


def test_unknown_purpose_raises_before_generating_or_wrapping():
    """A third purpose is a programming mistake, and must not quietly get field material."""
    engine = get_engine()
    with patch.object(engine.crypto_backend, "generate_field_dek") as field_gen:
        with patch.object(engine.crypto_backend, "generate_file_dek") as file_gen:
            with patch.object(engine.silo_kms_adapter, "encrypt_key") as encrypt_key:
                with pytest.raises(ValueError):
                    engine._new_wrapped_keyset(SILO_UID, DataEncryptionKey.PURPOSE_TEST, KEK_ID)

    field_gen.assert_not_called()
    file_gen.assert_not_called()
    encrypt_key.assert_not_called()


def test_provider_failure_surfaces_as_a_typed_error():
    """The engine funnel translates it; a raw provider exception reaching a caller is the defect."""
    engine = get_engine()
    with patch.object(engine.crypto_backend, "generate_field_dek", return_value=b"field-material"):
        with patch.object(engine.silo_kms_adapter, "encrypt_key", side_effect=RuntimeError("provider exploded")):
            with pytest.raises(EncryptionError) as excinfo:
                engine._new_wrapped_keyset(SILO_UID, DataEncryptionKey.PURPOSE_FIELD, KEK_ID)

    assert "provider exploded" not in str(excinfo.value)


def test_nothing_is_persisted():
    """The seam returns material; deciding where it lands belongs to the caller."""
    engine = get_engine()
    before = DataEncryptionKey.objects.count()
    with patch.object(engine.crypto_backend, "generate_field_dek", return_value=b"field-material"):
        with patch.object(engine.silo_kms_adapter, "encrypt_key", return_value=(b"wrapped", _metadata())):
            engine._new_wrapped_keyset(SILO_UID, DataEncryptionKey.PURPOSE_FIELD, KEK_ID)

    assert DataEncryptionKey.objects.count() == before
