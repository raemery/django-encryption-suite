"""The Reconcile Keys page lists a row per silo and key set, across every silo kind.

A silo's keys are identified by its kind, its uid and the key set, so two key sets
of one silo are two rows, and the system silo is a row of its own. Every table that
lists a key says which kind and key set it is, so two rows are never alike.
"""

from __future__ import annotations

from datetime import timedelta

import pytest
from django.conf import settings
from django.contrib import admin as django_admin
from django.contrib.auth.models import AnonymousUser
from django.test import RequestFactory, override_settings
from django.utils import timezone

from encryption_suite.adapters.silos.system import SystemSiloAdapter
from encryption_suite.admin import DataEncryptionKeyAdmin
from encryption_suite.models import DataEncryptionKey, KeyEncryptionKey
from encryption_suite.silo_ref import SYSTEM_SILO_REF
from tests.adapters import FakeKmsAdapterBase
from tests.factories import make_kek
from tests.key_set_settings import key_sets

_PROVIDER = "fly"
_PREFIX = "alias/es-prod-"
_PURPOSES = (DataEncryptionKey.PURPOSE_FIELD, DataEncryptionKey.PURPOSE_FILE, DataEncryptionKey.PURPOSE_INDEX)


class _FakeSilo:
    supports_enumeration = True
    is_in_use = lambda self: True  # noqa: E731

    def iter_silos(self):
        return ["team-1"]

    def get_silo_uid(self, s):
        return s

    def get_silo_label(self):
        return "team"


class _FakeStrategy:
    def owner_prefix(self):
        return _PREFIX

    def get_kek_id(self, ref):
        return _PREFIX + ref.uid

    def kek_disposition(self, uid):
        return KeyEncryptionKey.DISPOSITION_SILO_EXCLUSIVE


class _FakeProvisioner:
    supports_delete = True
    supports_enumeration = True
    is_in_use = lambda self: True  # noqa: E731

    def list_kek_names(self, owner_prefix):
        return [_PREFIX + "team-1"]


class _FakeKms(FakeKmsAdapterBase):
    kms_provider = _PROVIDER


class _User(AnonymousUser):
    is_active = True
    is_staff = True
    is_superuser = True
    username = "alice"

    def has_perm(self, perm, obj=None):
        return True


@pytest.fixture(autouse=True)
def _wired(configured_kms, monkeypatch, settings):
    configured_kms(_PROVIDER)
    settings.ENCRYPTION = {**settings.ENCRYPTION, "KEY_SETS": key_sets(default=_PROVIDER, restricted=_PROVIDER)}
    monkeypatch.setattr(
        "encryption_suite.registry.get_silo_adapter",
        lambda key_set="default": SystemSiloAdapter() if key_set == "system" else _FakeSilo(),
    )
    monkeypatch.setattr("encryption_suite.registry.get_kek_strategy_adapter", lambda name=None: _FakeStrategy())
    monkeypatch.setattr("encryption_suite.registry.get_kek_provisioner", lambda name=None: _FakeProvisioner())
    monkeypatch.setattr("encryption_suite.registry.get_kms_adapter", lambda name=None: _FakeKms())
    monkeypatch.setattr(
        "encryption_suite.rotation_targets.key_sets_in_use",
        lambda: {"default", "restricted", "system"},
    )


def _dek(uid, purpose, *, key_set="default", **extra):
    return DataEncryptionKey.objects.create(
        silo_uid=uid,
        key_set=key_set,
        purpose=purpose,
        silo_label="team",
        encrypted_keyset=b"wrapped",
        kek=make_kek(_PREFIX + uid, _PROVIDER),
        **extra,
    )


def _context(key_store=_PROVIDER):
    request = RequestFactory().get("/reconcile-keys/", {"key_store": key_store})
    request.user = _User()
    return DataEncryptionKeyAdmin(DataEncryptionKey, django_admin.site).reconcile_keys_view(request).context_data


@pytest.mark.django_db
def test_two_key_sets_of_one_silo_are_two_rows():
    for purpose in _PURPOSES:
        _dek("team-1", purpose)  # the default set is complete; the restricted one has no keys

    rows = [r for r in _context()["rows"] if r["silo_uid"] == "team-1"]
    by_set = {r["key_set"]: r for r in rows}

    # Both key sets use the chosen store, so one view lists both rows.
    assert sorted(by_set) == ["default", "restricted"]
    assert by_set["default"]["needs_setup"] is False
    assert by_set["restricted"]["needs_setup"] is True
    assert by_set["restricted"]["missing_deks"]


@pytest.mark.django_db
def test_a_key_in_one_set_does_not_stand_in_for_the_other():
    for purpose in _PURPOSES:
        _dek("team-1", purpose, key_set="restricted", status="deletion_scheduled")
        _dek("team-1", purpose)

    by_set = {r["key_set"]: r for r in _context()["rows"] if r["silo_uid"] == "team-1"}

    assert by_set["default"]["blocked_status"] is None
    assert by_set["restricted"]["field_marker"]["state"] == "blocked"


@pytest.mark.django_db
def test_the_system_silo_is_a_row_and_is_never_an_orphan():
    from encryption_suite.conf import resolve_store

    for purpose in _PURPOSES:
        _dek(SYSTEM_SILO_REF.uid, purpose, key_set="system")

    context = _context(resolve_store("system"))

    system = [r for r in context["rows"] if r["key_set"] == "system"]
    assert [(r["silo_uid"], r["key_set"]) for r in system] == [(SYSTEM_SILO_REF.uid, "system")]
    assert context["orphan_rows"] == []


@pytest.mark.django_db
def test_an_orphan_row_names_its_key_set_and_flags_one_without_a_settings_entry():
    _dek("team-9", DataEncryptionKey.PURPOSE_FIELD, key_set="restricted")
    _dek("team-9", DataEncryptionKey.PURPOSE_FIELD, key_set="retired")

    # The page lists the rows wrapped on the chosen store, whatever their key set.
    rows = {r["key_set"]: r for r in _context()["orphan_rows"]}

    assert sorted(rows) == ["restricted", "retired"]
    assert rows["restricted"]["no_settings_entry"] is False
    assert rows["retired"]["no_settings_entry"] is True


@pytest.mark.django_db
def test_an_unknown_key_store_falls_back_to_the_default_keys_store():
    context = _context("nonesuch")

    assert context["key_store"] == _PROVIDER
    assert context["key_store_choices"][0] == {"key_store": _PROVIDER, "label": "fly (default, restricted)"}


@pytest.mark.django_db
def test_a_store_no_key_set_uses_is_listed_only_while_it_holds_keys(configured_kms):
    configured_kms("spare", silo_kms=False)

    assert "spare" not in [c["key_store"] for c in _context()["key_store_choices"]]

    make_kek("spare-kek", "spare")

    assert "spare" in [c["key_store"] for c in _context()["key_store_choices"]]
    # It has no key set, so its label names none.
    assert {"key_store": "spare", "label": "spare"} in _context()["key_store_choices"]


@pytest.mark.django_db
def test_a_store_that_rows_record_but_settings_do_not_configure_is_named():
    make_kek("gone-kek", "retired-store")

    assert _context()["unconfigured_stores"] == ["retired-store"]


@pytest.mark.django_db
def test_re_encryption_due_rows_name_their_key_set():
    stale = timezone.now() - timedelta(days=1)
    _dek("team-1", DataEncryptionKey.PURPOSE_FIELD, key_set="restricted", key_material_last_generated_at=stale)

    # Read at run time: the autouse fixture has already put its store in ENCRYPTION.
    with override_settings(ENCRYPTION={**settings.ENCRYPTION, "DEK_ROTATION_PERIOD_DAYS": 0}):
        overdue = _context()["overdue_keys"]

    assert [(row["silo_ref"].uid, row["key_set"]) for row in overdue] == [("team-1", "restricted")]


@pytest.mark.django_db
def test_re_encryption_due_tables_show_uid_and_key_set_in_separate_columns():
    from django.template.loader import render_to_string

    stale = timezone.now() - timedelta(days=1)
    _dek("team-1", DataEncryptionKey.PURPOSE_FIELD, key_material_last_generated_at=stale)

    with override_settings(ENCRYPTION={**settings.ENCRYPTION, "DEK_ROTATION_PERIOD_DAYS": 0}):
        context = _context()
    page = render_to_string("admin/encryption_suite/reconcile_keys.html", context)

    assert "<td>team-1</td>\n          <td>default</td>" in page
