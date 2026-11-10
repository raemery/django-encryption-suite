"""The silos table reports whether each key is *usable*, not only whether it exists.

A key scheduled for deletion still has a row here and, on a provider with a
deletion window, still exists and still lists at the KMS — but it will not
encrypt or decrypt. Reporting presence alone showed a silo as ready while its
crypto was already blocked, and nothing in the application noticed until a data
encryption key fell out of the per-process cache and reads began failing
somewhere unrelated to this page.

This is the page an operator consults before making a deletion decision, so a
blocked key reads as blocked, and names the status that blocks it.
"""

from __future__ import annotations

import pytest
from django.contrib import admin as django_admin
from django.contrib.auth.models import AnonymousUser
from django.test import RequestFactory

from encryption_suite import lifecycle
from encryption_suite.adapters.silos.system import SystemSiloAdapter
from encryption_suite.admin import DataEncryptionKeyAdmin
from encryption_suite.admin_reconcile import _key_marker
from encryption_suite.models import DataEncryptionKey, KeyEncryptionKey
from tests.adapters import FakeKmsAdapterBase
from tests.factories import make_kek, make_kek_row

_PROVIDER = "fly"
_PREFIX = "alias/es-prod-"
_UID = "team-1"
_KEK = _PREFIX + _UID


class _FakeSilo:
    supports_enumeration = True
    is_in_use = lambda self: True  # noqa: E731

    def iter_silos(self):
        return [_UID]

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
        return [_KEK]


class _FakeKms(FakeKmsAdapterBase):
    kms_provider = _PROVIDER


@pytest.fixture(autouse=True)
def _fake_kms_is_silo_kms(configured_kms):
    configured_kms(_PROVIDER)


class _User(AnonymousUser):
    is_active = True
    is_staff = True
    is_superuser = True
    username = "alice"

    # AnonymousUser answers False to every permission whatever its flags say,
    # and the page is gated on one.
    def has_perm(self, perm, obj=None):
        return True


@pytest.fixture
def wired(monkeypatch):
    monkeypatch.setattr(
        "encryption_suite.registry.get_silo_adapter",
        lambda key_set="default": SystemSiloAdapter() if key_set == "system" else _FakeSilo(),
    )
    monkeypatch.setattr("encryption_suite.registry.get_kek_strategy_adapter", lambda name=None: _FakeStrategy())
    monkeypatch.setattr("encryption_suite.registry.get_kek_provisioner", lambda name=None: _FakeProvisioner())
    monkeypatch.setattr("encryption_suite.registry.get_kms_adapter", lambda name=None: _FakeKms())


def _dek(purpose, status=lifecycle.STATUS_ACTIVE):
    return DataEncryptionKey.objects.create(
        key_set="default",
        silo_uid=_UID,
        purpose=purpose,
        silo_label="team",
        encrypted_keyset=b"wrapped",
        kek=make_kek(_KEK, _PROVIDER),
        status=status,
    )


def _kek(status=lifecycle.STATUS_ACTIVE):
    return make_kek_row(
        key_store=_PROVIDER,
        kek_resource_name=_KEK,
        status=status,
    )


def _silo_row():
    request = RequestFactory().get("/reconcile-keys/")
    request.user = _User()
    ma = DataEncryptionKeyAdmin(DataEncryptionKey, django_admin.site)
    context = ma.reconcile_keys_view(request).context_data
    return next(r for r in context["rows"] if r["silo_uid"] == _UID)


# --- the marker rule itself -------------------------------------------------


def test_a_present_active_key_reads_present():
    assert _key_marker(True, lifecycle.STATUS_ACTIVE)["state"] == "present"


def test_an_absent_key_reads_absent():
    assert _key_marker(False, None)["state"] == "absent"


@pytest.mark.parametrize(
    "status",
    [lifecycle.STATUS_DELETION_SCHEDULED, lifecycle.STATUS_DELETION_REQUESTED, lifecycle.STATUS_DELETED],
)
def test_a_present_but_retired_key_reads_blocked_and_names_the_status(status):
    marker = _key_marker(True, status)

    assert marker["state"] == "blocked"
    assert marker["status"] == status


def test_a_present_key_with_no_recorded_status_reads_present():
    # An unrecorded key is unremarkable — reconcile discovers one on this same
    # pass. Inventing a blocked state for it would report trouble that is absent.
    assert _key_marker(True, None)["state"] == "present"


# --- the rule as the page applies it ----------------------------------------


@pytest.mark.django_db
def test_a_healthy_silo_reads_ready(wired):
    _kek()
    _dek(DataEncryptionKey.PURPOSE_FIELD)
    _dek(DataEncryptionKey.PURPOSE_FILE)
    # The suite declares a blind-indexed silo column, so a silo is short of a key
    # until it has an index key too.
    _dek(DataEncryptionKey.PURPOSE_INDEX)

    row = _silo_row()

    assert row["kek_marker"]["state"] == "present"
    assert row["field_marker"]["state"] == "present"
    assert row["needs_setup"] is False
    assert row["blocked_status"] is None


@pytest.mark.django_db
def test_a_listed_kek_scheduled_for_deletion_does_not_read_ready(wired):
    """The reported case: every marker green while decryption was already failing."""
    _kek(status=lifecycle.STATUS_DELETION_REQUESTED)
    _dek(DataEncryptionKey.PURPOSE_FIELD)
    _dek(DataEncryptionKey.PURPOSE_FILE)
    # The suite declares a blind-indexed silo column, so a silo is short of a key
    # until it has an index key too.
    _dek(DataEncryptionKey.PURPOSE_INDEX)

    row = _silo_row()

    # Existence is still reported honestly: the key does list at the provider.
    assert row["kek_existence"]["present"] is True
    assert row["kek_marker"]["state"] == "blocked"
    assert row["blocked_status"] == lifecycle.STATUS_DELETION_REQUESTED
    # Not a setup problem — the remedy is to restore or replace, not to create.
    assert row["needs_setup"] is False


@pytest.mark.django_db
def test_a_scheduled_dek_blocks_the_silo_too(wired):
    _kek()
    _dek(DataEncryptionKey.PURPOSE_FIELD, status=lifecycle.STATUS_DELETION_SCHEDULED)
    _dek(DataEncryptionKey.PURPOSE_FILE)

    row = _silo_row()

    assert row["field_marker"]["state"] == "blocked"
    assert row["file_marker"]["state"] == "present"
    assert row["blocked_status"] == lifecycle.STATUS_DELETION_SCHEDULED
