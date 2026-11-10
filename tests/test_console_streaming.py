"""Regression tests for the full-path admin test-console streaming AEAD path.

A previous bug passed the field sentinel UID instead of the file sentinel UID to
``decrypt_key`` in ``_ensure_test_streaming``, producing an AAD mismatch that
surfaced as a Tink "Decryption failed" error on every streaming decrypt. The
round-trip test below exercises that path against the correct (file) sentinel.
"""

from __future__ import annotations

import pytest

from encryption_suite import registry
from encryption_suite import test_console as tc


@pytest.fixture
def kms_adapter(db):
    return registry.get_kms_adapter()


def test_streaming_roundtrip_in_single_call(kms_adapter):
    plaintext = b"streaming round trip payload"
    result = tc.full_streaming_roundtrip(kms_adapter, None, plaintext)
    assert result["matches"] is True
    assert result["plaintext"] == plaintext
    assert result["created_key"] is True


def test_streaming_provisioner_failure_is_translated(kms_adapter):
    """A raw provisioner error on the streaming create path funnels to a typed
    EncryptionError, matching the AEAD path.

    Without the ``_kms_error_guard`` around ``ensure_kek`` the raw provider
    error (e.g. a urllib ``HTTPError`` from an Infisical auth 404) escaped to
    the admin view as a stack trace, while the AEAD path rendered the generic
    translatable message. The guard makes both paths behave identically.
    """
    import urllib.error

    from encryption_suite.exceptions import EncryptionError

    class _FailingProvisioner:
        def describe(self):
            return "_FailingProvisioner"

        def ensure_kek(self, kek_id, silo_ref=None):
            raise urllib.error.HTTPError("https://app.infisical.com/api/v1/auth", 404, "Not Found", {}, None)

    with pytest.raises(EncryptionError):
        tc.full_streaming_roundtrip(kms_adapter, _FailingProvisioner(), b"payload")
