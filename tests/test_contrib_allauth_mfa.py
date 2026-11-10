"""The MFA adapter mixin: allauth's TOTP secret and recovery seed under the system silo."""

import base64

import pytest

from encryption_suite.conf import SYSTEM_SILO_UID
from encryption_suite.contrib.allauth import MFASecretEncryptionMixin
from encryption_suite.engine import EncryptionEngine, is_silo_value
from encryption_suite.models import DataEncryptionKey

pytestmark = pytest.mark.django_db


class _Adapter(MFASecretEncryptionMixin):
    pass


def test_a_secret_round_trips_under_the_system_silo():
    adapter = _Adapter()

    stored = adapter.encrypt("JBSWY3DPEHPK3PXP")

    assert is_silo_value(stored) and "JBSWY3DPEHPK3PXP" not in stored
    assert adapter.decrypt(stored) == "JBSWY3DPEHPK3PXP"
    assert DataEncryptionKey.objects.filter(silo_uid=SYSTEM_SILO_UID).exists()


def test_a_value_written_before_the_adapter_reads_back_unchanged():
    assert _Adapter().decrypt("JBSWY3DPEHPK3PXP") == "JBSWY3DPEHPK3PXP"


def test_an_unreadable_secret_becomes_a_random_one_that_fails(settings, caplog):
    from encryption_suite import registry

    adapter = _Adapter()
    stored = adapter.encrypt("JBSWY3DPEHPK3PXP")
    # The system key's ENV_KEY_STORES version is dropped: the key is there and cannot be used.
    settings.ENCRYPTION = {
        **settings.ENCRYPTION,
        "ENV_KEY_STORES": {"login": {"KEKS": {9: base64.b64encode(b"\x09" * 32).decode()}}},
    }
    registry.reset()
    EncryptionEngine.invalidate_cache()

    first, second = adapter.decrypt(stored), adapter.decrypt(stored)

    assert first != "JBSWY3DPEHPK3PXP" and first != second
    base64.b32decode(first)  # well formed for allauth's TOTP check
    assert "An MFA secret could not be read" in caplog.text
