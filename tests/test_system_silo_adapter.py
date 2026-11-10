"""The built-in system silo adapter, and the ``prevents_key_delete`` flag that gates key deletion."""

from __future__ import annotations

import pytest
from django.conf import settings
from django.core import checks
from django.test import override_settings

from encryption_suite import registry
from encryption_suite.adapters.silos.base import AbstractSiloAdapter
from encryption_suite.adapters.silos.system import SystemSiloAdapter
from encryption_suite.conf import SYSTEM_SILO_UID
from encryption_suite.deletion import RETAIN_SILO_LIVE, dek_retain_reason
from encryption_suite.silo_ref import SYSTEM_SILO_REF, SiloRef


def test_the_system_uid_is_system():
    assert SYSTEM_SILO_UID == "system"


def test_the_adapter_answers_for_the_one_silo():
    adapter = SystemSiloAdapter()

    silo = adapter.get_current_silo()

    assert silo == SYSTEM_SILO_REF
    assert adapter.get_silo_uid(silo) == "system"
    assert adapter.get_silo_label() == "system"
    assert adapter.supports_enumeration is True
    assert list(adapter.iter_silos()) == [SYSTEM_SILO_REF]
    assert adapter.silo_exists("system") is True
    assert adapter.silo_exists("team-1") is False
    assert adapter.silo_for_uid("system") == SYSTEM_SILO_REF
    assert adapter.silo_for_uid("team-1") is None
    assert adapter.describe_silo("system") == "System"
    assert adapter.supports_silo_data_lookup is True
    assert adapter.prevents_key_delete is True


def test_the_registry_returns_the_system_adapter_for_the_system_key_set():
    assert isinstance(registry.get_silo_adapter("system"), SystemSiloAdapter)


def test_the_system_adapter_shortcut_binds_any_key_set_to_the_system_adapter():
    sets = {**settings.ENCRYPTION["KEY_SETS"], "directory": {"silo": "system", "key_store": "login"}}
    with override_settings(ENCRYPTION={**settings.ENCRYPTION, "KEY_SETS": sets}):
        assert registry.get_silo_adapter("directory") is registry.get_silo_adapter("system")


def test_all_key_sets_lists_the_project_key_sets_and_system():
    key_sets = registry.all_key_sets()

    assert "system" in key_sets
    assert set(key_sets) == set(settings.ENCRYPTION["KEY_SETS"]) | {"system"}


def test_naming_another_adapter_for_the_system_key_set_is_refused():
    from encryption_suite.checks import check_kms_settings

    sets = {**settings.ENCRYPTION["KEY_SETS"], "system": {"silo": "x.Y", "key_store": "login"}}
    with override_settings(ENCRYPTION={**settings.ENCRYPTION, "KEY_SETS": sets}):
        errors = check_kms_settings(None)

    assert any("names the silo 'x.Y'" in error.msg for error in errors if isinstance(error, checks.CheckMessage))


def test_naming_the_system_adapter_for_the_system_key_set_is_accepted():
    from encryption_suite.checks import check_kms_settings

    sets = {**settings.ENCRYPTION["KEY_SETS"], "system": {"silo": "system", "key_store": "login"}}
    with override_settings(ENCRYPTION={**settings.ENCRYPTION, "KEY_SETS": sets}):
        errors = check_kms_settings(None)

    assert not any("names the silo" in error.msg for error in errors)


class _FlaggedAdapter:
    prevents_key_delete = True

    def silo_exists(self, silo_uid):
        return False


class _PlainAdapter:
    prevents_key_delete = False

    def silo_exists(self, silo_uid):
        return False


@pytest.mark.parametrize("allow", [False, True])
def test_the_system_silo_is_refused_with_the_override_on_or_off(allow):
    enc = {**settings.ENCRYPTION, "KEY_DELETION_CAN_RENDER_DATA_INACCESSIBLE": allow}
    with override_settings(ENCRYPTION=enc):
        assert dek_retain_reason(SYSTEM_SILO_REF) == RETAIN_SILO_LIVE


@pytest.mark.parametrize("allow", [False, True])
def test_a_flagged_adapter_is_refused_the_same_way(monkeypatch, allow):
    monkeypatch.setattr("encryption_suite.registry.get_silo_adapter", lambda key_set="default": _FlaggedAdapter())
    enc = {**settings.ENCRYPTION, "KEY_DELETION_CAN_RENDER_DATA_INACCESSIBLE": allow}

    with override_settings(ENCRYPTION=enc):
        assert dek_retain_reason(SiloRef("default", "team-1")) == RETAIN_SILO_LIVE


def test_an_unflagged_adapter_whose_silo_is_gone_is_not_refused(monkeypatch):
    monkeypatch.setattr("encryption_suite.registry.get_silo_adapter", lambda key_set="default": _PlainAdapter())

    assert dek_retain_reason(SiloRef("default", "team-1")) is None


def test_the_default_adapter_is_in_use():
    class _Plain(AbstractSiloAdapter):
        get_current_silo = get_silo_label = get_silo_uid = lambda self, *a: None

    assert _Plain().is_in_use() is True


def test_the_system_adapter_is_in_use_only_with_system_columns_or_keys(monkeypatch):
    adapter = SystemSiloAdapter()
    monkeypatch.setattr("encryption_suite.rotation_targets.system_key_sets_needed", lambda: [])
    monkeypatch.setattr("encryption_suite.models.DataEncryptionKey.objects.filter", lambda **kw: _Exists(False))
    assert adapter.is_in_use() is False

    monkeypatch.setattr("encryption_suite.models.DataEncryptionKey.objects.filter", lambda **kw: _Exists(True))
    assert adapter.is_in_use() is True

    monkeypatch.setattr("encryption_suite.models.DataEncryptionKey.objects.filter", lambda **kw: _Exists(False))
    monkeypatch.setattr("encryption_suite.rotation_targets.system_key_sets_needed", lambda: ["system"])
    assert adapter.is_in_use() is True


class _Exists:
    def __init__(self, value):
        self.value = value

    def exists(self):
        return self.value


def test_the_system_queryset_uses_the_base_manager_and_returns_every_row():
    class _Model:
        class _base_manager:
            @staticmethod
            def all():
                return "every row"

    assert SystemSiloAdapter().queryset_for_silo(_Model, "system") == "every row"
