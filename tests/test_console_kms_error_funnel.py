"""The admin test console funnels raw KMS provider errors into typed errors.

The test console drives the KMS adapter / KEK provisioner directly (not through
the engine), so without a funnel a provider failure would escape to the admin
view as a raw traceback. The guard routes any provider exception through the
engine's wrap/unwrap funnel, so the classification is identical to the field
and file paths — and provider-agnostic: a plain ``RuntimeError`` from any
SDK-backed adapter classifies the same as a Tink/gRPC or urllib error.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from encryption_suite import registry
from encryption_suite import test_console as tc
from encryption_suite.exceptions import EncryptionError, KekUnavailableError


@pytest.fixture
def kms_adapter(db):
    return registry.get_kms_adapter()


def test_unwrap_provider_error_funnels_to_kek_unavailable(kms_adapter):
    # Provision the test keyset first so the next call exercises the unwrap path.
    tc.full_aead_roundtrip(kms_adapter, None, b"seed")

    # A non-Tink, non-EncryptionError provider failure (as any SDK adapter
    # might raise) must classify as KekUnavailableError, not escape raw.
    with patch.object(kms_adapter, "decrypt_key", side_effect=RuntimeError("SDK exploded")):
        with pytest.raises(KekUnavailableError):
            tc.full_aead_roundtrip(kms_adapter, None, b"again")


def test_wrap_provider_error_funnels_to_encryption_suite_error(kms_adapter):
    # First-use provisioning runs encrypt_key; a provider failure there is
    # funnelled too, so the admin view never sees a raw provider traceback.
    with patch.object(kms_adapter, "encrypt_key", side_effect=RuntimeError("SDK exploded")):
        with pytest.raises(EncryptionError):
            tc.full_aead_roundtrip(kms_adapter, None, b"payload")
