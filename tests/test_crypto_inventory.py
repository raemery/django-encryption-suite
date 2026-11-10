"""The cryptographic inventory: counts and identifiers from settings and rows.

Built from rows on two KMSs, two backends and one KMS name no block configures;
rendered as text and as JSON. The JSON carries no field that could hold key
material or a silo UID, which an explicit allow-list of its keys pins.
"""

from __future__ import annotations

import json
from datetime import timedelta
from io import StringIO

import pytest
from django.contrib.auth.models import AnonymousUser
from django.core.exceptions import PermissionDenied
from django.core.management import call_command
from django.test import RequestFactory
from django.utils import timezone

from encryption_suite import lifecycle, registry
from encryption_suite.admin_inventory import inventory_view
from encryption_suite.engine import EncryptionEngine
from encryption_suite.inventory import build_inventory
from encryption_suite.models import DataEncryptionKey, KeyEncryptionKey
from tests.factories import make_kek
from tests.key_set_settings import key_sets
from tests.rotation_helpers import dek, make_document, make_note, make_team

pytestmark = pytest.mark.django_db

_PYCA = "encryption_suite.adapters.crypto_backends.cryptography.CryptographyCryptoEngine"


@pytest.fixture(autouse=True)
def _clear_cache():
    EncryptionEngine.invalidate_cache()
    yield
    EncryptionEngine.invalidate_cache()


def _configure(settings, **changes):
    settings.ENCRYPTION = {**settings.ENCRYPTION, **changes}
    registry.reset()
    EncryptionEngine.invalidate_cache()


def _estate(settings):
    """One silo on local/tink, one on other/pyca, and a KEK row on a KMS nothing configures."""
    old = make_team("old")
    make_note(old)
    make_document(old)
    blocks = dict(settings.ENCRYPTION["KMS_KEY_STORES"])
    blocks["other"] = {**blocks["local"], "OPTIONS": {"SHARED_KEK_ID": "other-test-kek"}}
    _configure(
        settings,
        KMS_KEY_STORES=blocks,
        KEY_SETS=key_sets(default="other"),
        CRYPTO_BACKEND=_PYCA,
        CRYPTO_BACKEND_OPTIONS={},
    )
    new = make_team("new")
    make_note(new)
    make_kek(key_store="retired", kek_resource_name="gone-kek")
    return old, new


def _groups(inventory):
    return {(g.purpose, g.cryptographic_engine, g.algorithm, g.key_store): g for g in inventory.data_encryption_keys}


def test_data_keys_are_grouped_by_purpose_backend_algorithm_and_kms(settings):
    old, new = _estate(settings)

    groups = _groups(build_inventory())

    assert groups[("field", "tink", "AES256_GCM", "local")].count == 1
    assert groups[("file", "tink", "AES256_GCM_HKDF_4KB", "local")].count == 1
    assert groups[("field", "cryptography", "AES256_GCM", "other")].count == 1
    oldest = groups[("field", "tink", "AES256_GCM", "local")].oldest_key_material_at
    assert oldest == dek(old).key_material_last_generated_at


def test_a_key_set_with_no_settings_entry_is_reported(settings):
    """A set retired or renamed in settings while keys exist under it, which no deploy check can see."""
    _estate(settings)
    assert all(group.in_settings for group in build_inventory().data_encryption_keys)

    _configure(settings, KEY_SETS=key_sets(renamed="other", default="nowhere"))

    groups = build_inventory().data_encryption_keys
    assert {group.key_set for group in groups} == {"default"}
    assert not any(group.in_settings for group in groups)


def test_new_keys_name_the_store_of_every_key_set(settings):
    _configure(settings, KEY_SETS=key_sets(extra="login"))

    stores = {c.key_set: c.key_store for c in build_inventory().configured_for_new_key_encryption_keys}

    assert stores == {"default": "local", "extra": "login", "system": "login"}


def test_new_keys_name_the_silo_adapter_of_every_key_set(settings):
    _configure(settings, KEY_SETS=key_sets(extra="login"))

    adapters = {c.key_set: c.silo_adapter for c in build_inventory().configured_for_new_key_encryption_keys}

    # The system key set shows its class path, in the same form as every other adapter.
    assert adapters == {
        "default": "tests.silo.GroupSiloAdapter",
        "extra": "tests.silo.GroupSiloAdapter",
        "system": "encryption_suite.adapters.silos.system.SystemSiloAdapter",
    }


def test_a_key_set_with_no_store_is_listed_with_a_blank_store(settings):
    _configure(settings, KEY_SETS=key_sets(system="nowhere"))

    stores = {c.key_set: c.key_store for c in build_inventory().configured_for_new_key_encryption_keys}

    assert stores["system"] == ""


def test_kms_entries_name_an_unconfigured_name(settings):
    _estate(settings)

    stores = {entry.key_store: entry for entry in build_inventory().key_stores}

    assert list(stores) == ["local", "other", "login", "retired"]
    assert stores["local"].data_encryption_key_count == 2 and stores["other"].data_encryption_key_count == 1
    assert stores["login"].kms_adapter == "encryption_suite.adapters.key_stores.environment.EnvKeyStoreAdapter"
    assert not stores["retired"].configured
    assert (stores["retired"].kms_adapter, stores["retired"].key_encryption_key_count) == ("", 1)


def test_kek_groups_count_every_status(settings):
    _estate(settings)
    KeyEncryptionKey.objects.filter(key_store="retired").update(status=lifecycle.STATUS_DELETED)

    keks = {(g.key_store, g.status): g.count for g in build_inventory().key_encryption_keys}

    assert keks[("retired", lifecycle.STATUS_DELETED)] == 1
    assert keks[("local", lifecycle.STATUS_ACTIVE)] >= 1


def test_deleted_and_test_console_keys_are_left_out(settings):
    team = make_team()
    make_note(team)
    DataEncryptionKey.objects.filter(pk=dek(team).pk).update(status=lifecycle.STATUS_DELETED)

    assert not [g for g in build_inventory().data_encryption_keys if g.key_store == "local"]


def test_overdue_is_counted_only_where_a_period_is_declared(settings):
    team = make_team()
    make_note(team)
    DataEncryptionKey.objects.filter(pk=dek(team).pk).update(
        key_material_last_generated_at=timezone.now() - timedelta(days=400)
    )

    assert _groups(build_inventory())[("field", "tink", "AES256_GCM", "local")].older_than_rotation_period is None
    _configure(settings, DEK_ROTATION_PERIOD_DAYS=365)
    assert _groups(build_inventory())[("field", "tink", "AES256_GCM", "local")].older_than_rotation_period == 1


def test_configured_for_new_keys_names_each_purposes_algorithm(settings):
    _configure(settings, CRYPTO_BACKEND=_PYCA, CRYPTO_BACKEND_OPTIONS={"AEAD": "CHACHA20_POLY1305"})

    configured = build_inventory().configured_for_new_data_encryption_keys

    assert configured.cryptographic_engine == "cryptography"
    assert dict(configured.algorithms) == {
        "field": "CHACHA20_POLY1305",
        "file": "CHACHA20_POLY1305_STREAM",
        "index": "HMAC_SHA256",
    }


def test_a_backend_that_cannot_be_built_is_reported_not_raised(settings):
    _configure(settings, CRYPTO_BACKEND=_PYCA, CRYPTO_BACKEND_OPTIONS={"AEAD": "ROT13"})

    configured = build_inventory().configured_for_new_data_encryption_keys

    assert configured.cryptographic_engine == ""
    assert configured.error_code


# The whole JSON surface. A key added here is a decision that it can never hold
# key material, a wrapped keyset or a silo UID.
_ALLOWED_KEYS = {
    "top": {
        "schema_version",
        "command",
        "started_at",
        "finished_at",
        "generated_at",
        "rotation_period_days",
        "key_stores",
        "key_encryption_keys",
        "configured_for_new_key_encryption_keys",
        "data_encryption_keys",
        "configured_for_new_data_encryption_keys",
    },
    "key_stores": {
        "key_store",
        "configured",
        "kms_adapter",
        "kek_strategy",
        "key_encryption_key_count",
        "data_encryption_key_count",
        "oldest_active_kek_at",
    },
    "key_encryption_keys": {"key_store", "status", "count"},
    "configured_for_new_key_encryption_keys": {"key_set", "key_store", "silo_adapter"},
    "data_encryption_keys": {
        "key_set",
        "in_settings",
        "purpose",
        "cryptographic_engine",
        "algorithm",
        "key_store",
        "count",
        "oldest_key_material_at",
        "older_than_rotation_period",
    },
    "configured_for_new_data_encryption_keys": {"cryptographic_engine", "options", "algorithms", "error_code"},
}


def _run(*args) -> str:
    out = StringIO()
    call_command("crypto_inventory", *args, stdout=out, stderr=StringIO())
    return out.getvalue()


def test_the_json_parses_and_carries_only_allowed_keys(settings):
    old, _new = _estate(settings)

    data = json.loads(_run("--format", "json"))

    assert set(data) == _ALLOWED_KEYS["top"]
    for section in (
        "key_stores",
        "key_encryption_keys",
        "configured_for_new_key_encryption_keys",
        "data_encryption_keys",
    ):
        assert data[section]
        for item in data[section]:
            assert set(item) == _ALLOWED_KEYS[section]
    new_data_keys = "configured_for_new_data_encryption_keys"
    assert set(data[new_data_keys]) == _ALLOWED_KEYS[new_data_keys]
    assert data["schema_version"] == 2
    assert f"group-{old.pk}" not in json.dumps(data)


def test_the_text_report_names_each_section_and_logs_that_it_ran(settings, caplog):
    _estate(settings)

    with caplog.at_level("WARNING", logger="encryption_suite.management.commands.crypto_inventory"):
        output = _run()

    # The page's headings, in the page's order.
    headings = (
        "Key management system (KMS)",
        "Key encryption keys (",
        "Configured for new key encryption keys",
        "Data encryption keys (",
        "Configured for new data encryption keys",
    )
    positions = [output.index(heading) for heading in headings]
    assert positions == sorted(positions)
    assert "retired\n    Not configured" in output
    assert "default / other" in output
    assert any("command=crypto_inventory" in record.getMessage() for record in caplog.records)


class _Staff(AnonymousUser):
    is_active = True
    is_staff = True

    def __init__(self, *granted):
        super().__init__()
        self._granted = set(granted)

    def has_perm(self, perm, obj=None):
        return perm in self._granted


def _request(*granted):
    request = RequestFactory().get("/admin/inventory/")
    request.user = _Staff(*granted)
    return request


def test_the_page_is_refused_without_its_permission():
    with pytest.raises(PermissionDenied):
        inventory_view(None, _request("encryption_suite.view_settings"))


def test_the_page_refuses_a_non_staff_holder():
    request = _request("encryption_suite.view_inventory")
    request.user.is_staff = False

    with pytest.raises(PermissionDenied):
        inventory_view(None, request)


def _urls(response) -> set[str]:
    context = response.context_data
    return {
        *(url for row in context["kms_rows"] for url in (row["kek_url"], row["dek_url"])),
        *(row["url"] for row in context["kek_rows"]),
        *(row["url"] for row in context["data_key_rows"]),
    }


def _engine_context(settings, backend):
    from django.contrib.admin import AdminSite

    from encryption_suite.admin import DataEncryptionKeyAdmin

    _configure(settings, CRYPTO_BACKEND=backend)
    return inventory_view(
        DataEncryptionKeyAdmin(DataEncryptionKey, AdminSite()), _request("encryption_suite.view_inventory")
    ).context_data


def test_the_engine_table_leaves_out_options_the_algorithm_column_already_says(settings):
    context = _engine_context(settings, _PYCA)

    # The cipher is the field algorithm; the segment size is the one option left, and it is a file option.
    assert [str(label) for label in context["engine_headers"]] == ["File segment size (bytes)"]
    rows = {row["purpose"]: row for row in context["engine_rows"]}
    assert list(rows) == ["field", "file", "index"]
    assert [rows[purpose]["extras"] for purpose in rows] == [[""], ["4096"], [""]]
    assert rows["index"]["engine"] == ""
    assert rows["field"]["engine"] == rows["file"]["engine"] != ""


def test_a_tink_engine_has_no_option_columns_left(settings):
    context = _engine_context(settings, "encryption_suite.adapters.crypto_backends.tink.TinkCryptoEngine")

    # Its options are the field and file templates, which are the algorithms.
    assert context["engine_headers"] == []
    assert all(row["extras"] == [] for row in context["engine_rows"])


def test_an_engine_that_cannot_be_built_shows_its_error_code(settings):
    context = _engine_context(settings, "no.such.Engine")

    assert context["engine_rows"][0]["engine"].startswith("[")
    assert context["engine_rows"][0]["purpose"] == ""


@pytest.mark.parametrize(
    ("granted", "linked"),
    [
        ((), False),
        (("encryption_suite.view_keyencryptionkey", "encryption_suite.view_dataencryptionkey"), True),
        (("encryption_suite.change_keyencryptionkey", "encryption_suite.change_dataencryptionkey"), True),
    ],
)
def test_counts_link_only_to_changelists_the_holder_can_open(settings, granted, linked):
    """The inventory permission opens the page, not the changelists its counts point at."""
    from django.contrib.admin import AdminSite

    from encryption_suite.admin import DataEncryptionKeyAdmin

    _estate(settings)

    response = inventory_view(
        DataEncryptionKeyAdmin(DataEncryptionKey, AdminSite()), _request("encryption_suite.view_inventory", *granted)
    )

    urls = _urls(response)
    assert all(urls) if linked else urls == {""}
