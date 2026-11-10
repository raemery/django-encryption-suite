"""``SILO_AUTO_KEY_CREATION`` and ``SILO_AUTO_KEY_DELETION`` name key sets and find the silo models through the adapter."""

from __future__ import annotations

import pytest
from django.apps import apps as django_apps
from django.conf import settings
from django.contrib.auth.models import Group
from django.db.models.signals import post_delete, post_save
from django.test import override_settings

from encryption_suite import lifecycle, registry
from encryption_suite.adapters.silos.base import AbstractSiloAdapter
from encryption_suite.models import DataEncryptionKey
from tests.key_set_settings import key_sets


class NoModelsAdapter(AbstractSiloAdapter):
    """An adapter that declares no silo models."""

    def get_current_silo(self):
        return None

    def get_silo_uid(self, silo) -> str:
        return str(silo)

    def get_silo_label(self) -> str:
        return "nothing"


def _config():
    return django_apps.get_app_config("encryption_suite")


def test_an_adapter_declares_its_silo_models_through_model_label():
    assert registry.get_silo_adapter("default").silo_model_labels == ("auth.Group",)


def test_an_adapter_with_no_model_label_declares_none():
    assert NoModelsAdapter().silo_model_labels == ()


def test_the_silo_models_of_a_key_set_come_from_its_adapter():
    assert _config()._silo_models("SILO_AUTO_KEY_CREATION", "default") == [Group]


def test_a_key_set_whose_adapter_declares_no_models_registers_nothing(caplog):
    sets = {**key_sets(), "other": {"silo": f"{__name__}.NoModelsAdapter", "key_store": "local"}}
    with override_settings(ENCRYPTION={**settings.ENCRYPTION, "KEY_SETS": sets}):
        registry.reset()
        models = _config()._silo_models("SILO_AUTO_KEY_CREATION", "other")
    registry.reset()

    assert models == []
    assert "declares no silo models" in caplog.text


@pytest.mark.django_db
def test_creating_a_silo_makes_the_listed_key_sets_field_key():
    sets = key_sets(archive="login")
    config = {**settings.ENCRYPTION, "KEY_SETS": sets, "SILO_AUTO_KEY_CREATION": ["archive"]}
    with override_settings(ENCRYPTION=config):
        registry.reset()
        _config()._register_auto_create_signals()
        try:
            group = Group.objects.create(name="auto")
            rows = DataEncryptionKey.objects.filter(silo_uid=f"group-{group.pk}")
            assert {(row.key_set, row.purpose) for row in rows} == {("archive", DataEncryptionKey.PURPOSE_FIELD)}
        finally:
            post_save.disconnect(sender=Group, dispatch_uid="encrypted_fields_auto_create_archive_auth.Group")
    registry.reset()


@pytest.mark.django_db
def test_deleting_a_silo_schedules_its_keys_in_every_key_set_of_the_adapter():
    from encryption_suite.registry import get_engine

    sets = key_sets(archive="login")
    config = {**settings.ENCRYPTION, "KEY_SETS": sets, "SILO_AUTO_KEY_DELETION": ["default"]}
    with override_settings(ENCRYPTION=config):
        registry.reset()
        group = Group.objects.create(name="doomed")
        engine = get_engine()
        engine.encrypt("one", silo=group)
        engine.encrypt("two", silo=group, key_set="archive")
        uid = f"group-{group.pk}"
        _config()._register_deletion_signals()
        try:
            group.delete()
            rows = DataEncryptionKey.objects.filter(silo_uid=uid, purpose=DataEncryptionKey.PURPOSE_FIELD)
            assert {(row.key_set, row.status) for row in rows} == {
                ("default", lifecycle.STATUS_DELETION_SCHEDULED),
                ("archive", lifecycle.STATUS_DELETION_SCHEDULED),
            }
        finally:
            post_delete.disconnect(
                sender=Group, dispatch_uid="encryption_suite_deletion_on_delete_tests.silo.GroupSiloAdapter_auth.Group"
            )
    registry.reset()
