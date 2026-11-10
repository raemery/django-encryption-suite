"""The system silo: the engine's silo for ``key_set="system"`` columns.

It needs no silo in the context, its keys go to whichever store ``SILO_KEY_STORES``
gives the field's ``key_set``, and its first use creates all of them at once whatever
``KEY_AUTO_PROVISION`` says: no model's creation signals the system silo, so with
that switch off its first write (a sign-up) would otherwise fail.
"""

import pytest
from django.conf import settings
from django.test import override_settings

from encryption_suite.conf import SYSTEM_SILO_UID
from encryption_suite.engine import SYSTEM_SILO
from encryption_suite.models import DataEncryptionKey
from encryption_suite.registry import get_engine, new_key_kms
from encryption_suite.silo_ref import SiloRef, silo_filter


def test_new_keys_follow_the_store_the_settings_give_the_key_set():
    assert new_key_kms("system") == "login"
    assert new_key_kms("default") == "local"
    sets = {**settings.ENCRYPTION["KEY_SETS"], "system_cold": {"silo": "system", "key_store": "local"}}
    with override_settings(ENCRYPTION={**settings.ENCRYPTION, "KEY_SETS": sets}):
        assert new_key_kms("system") == "login"
        assert new_key_kms("system_cold") == "local"


@pytest.mark.django_db
def test_a_system_value_round_trips_with_no_silo_in_the_context():
    engine = get_engine()

    stored = engine.encrypt("alice@example.com", silo=SYSTEM_SILO)

    assert engine.decrypt(stored, silo=SYSTEM_SILO) == "alice@example.com"
    row = DataEncryptionKey.objects.select_related("kek").get(
        key_set="system", silo_uid=SYSTEM_SILO_UID, purpose=DataEncryptionKey.PURPOSE_FIELD
    )
    assert row.silo_label == "system"
    assert row.kek.key_store == "login"


@pytest.mark.django_db
def test_a_system_value_in_a_set_on_a_kms_store_is_recorded_on_that_store():
    sets = {**settings.ENCRYPTION["KEY_SETS"], "system_cold": {"silo": "system", "key_store": "local"}}
    cold = SiloRef("system_cold", SYSTEM_SILO_UID)
    with override_settings(ENCRYPTION={**settings.ENCRYPTION, "KEY_SETS": sets}):
        stored = get_engine().encrypt("alice@example.com", silo=cold)

        row = DataEncryptionKey.objects.select_related("kek").get(
            **silo_filter(cold), purpose=DataEncryptionKey.PURPOSE_FIELD
        )
        assert row.kek.key_store == "local"
        assert get_engine().decrypt(stored, silo=cold) == "alice@example.com"


@pytest.mark.django_db
def test_the_system_silo_provisions_even_with_auto_provision_off():
    with override_settings(ENCRYPTION={**settings.ENCRYPTION, "KEY_AUTO_PROVISION": False}):
        stored = get_engine().encrypt("bob", silo=SYSTEM_SILO)

    assert DataEncryptionKey.objects.filter(**silo_filter(SYSTEM_SILO)).exists()
    assert stored


@pytest.mark.django_db
def test_a_scoped_silo_with_the_system_uid_is_a_different_silo(tenant, monkeypatch):
    """The kind is part of a silo's identity, so no uid is reserved: ``system`` under another kind is just a uid."""
    engine = get_engine()
    monkeypatch.setattr(engine.silo_adapter, "get_silo_uid", lambda silo: SYSTEM_SILO_UID)

    stored = engine.encrypt("secret", silo=tenant)

    assert engine.decrypt(stored, silo=tenant) == "secret"
    assert DataEncryptionKey.objects.filter(**silo_filter(SiloRef("default", SYSTEM_SILO_UID))).exists()
    assert not DataEncryptionKey.objects.filter(**silo_filter(SYSTEM_SILO)).exists()
