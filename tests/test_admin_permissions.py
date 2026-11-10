"""Which permission reaches which admin screen, URL and action.

Two shapes are checked. The changelist actions go through Django's own filter
(``ModelAdmin.get_actions``), which both renders the drop-down and validates the
POSTed action name — so an action missing from this mapping cannot be run by
forging a form. The two custom screens are plain views and check their
permission themselves.

The destructive actions use a ``destroy`` verb rather than ``delete``: both
admins hard-code ``has_delete_permission`` to ``False`` to strip the admin's own
delete button, and that answer would otherwise hide every destructive action
from everyone.
"""

from __future__ import annotations

import pytest
from django.contrib.admin.sites import AdminSite
from django.contrib.auth.models import AnonymousUser
from django.core.exceptions import PermissionDenied
from django.test import RequestFactory

from encryption_suite import admin_reconcile, admin_test_console
from encryption_suite.admin import DataEncryptionKeyAdmin
from encryption_suite.admin_lifecycle import KeyEncryptionKeyAdmin
from encryption_suite.models import DataEncryptionKey, EncryptionTools, KeyEncryptionKey

DEK_ACTIONS = {
    "schedule_dek_deletion": "encryption_suite.delete_dataencryptionkey",
    "purge_expired_work": "encryption_suite.delete_dataencryptionkey",
    "restore_scheduled": "encryption_suite.change_dataencryptionkey",
}
KEK_ACTIONS = {
    "schedule_deletion": "encryption_suite.delete_keyencryptionkey",
    "purge_expired_work": "encryption_suite.delete_keyencryptionkey",
    "record_deleted_in_kms": "encryption_suite.delete_keyencryptionkey",
    "record_requested_in_kms": "encryption_suite.delete_keyencryptionkey",
    "restore_scheduled": "encryption_suite.change_keyencryptionkey",
    "record_restored_in_kms": "encryption_suite.change_keyencryptionkey",
}


class _Staff(AnonymousUser):
    """Active staff holding exactly the permissions it was built with."""

    is_active = True
    is_staff = True

    def __init__(self, *granted):
        super().__init__()
        self._granted = set(granted)

    def has_perm(self, perm, obj=None):
        return perm in self._granted


def _request(*granted):
    request = RequestFactory().get("/admin/")
    request.user = _Staff(*granted)
    return request


@pytest.fixture
def dek_admin():
    return DataEncryptionKeyAdmin(DataEncryptionKey, AdminSite())


@pytest.fixture
def kek_admin():
    return KeyEncryptionKeyAdmin(KeyEncryptionKey, AdminSite())


# ----------------------------------------------------------------------
# Actions
# ----------------------------------------------------------------------


@pytest.mark.parametrize(
    ("admin_fixture", "mapping"),
    [("dek_admin", DEK_ACTIONS), ("kek_admin", KEK_ACTIONS)],
)
def test_every_action_is_mapped_to_a_permission(admin_fixture, mapping, request):
    """No action is left ungated: an unmapped one would run for any staff member."""
    model_admin = request.getfixturevalue(admin_fixture)

    assert set(model_admin.actions) == set(mapping)


@pytest.mark.parametrize(
    ("admin_fixture", "mapping"),
    [("dek_admin", DEK_ACTIONS), ("kek_admin", KEK_ACTIONS)],
)
def test_an_action_is_offered_only_to_the_permission_that_maps_to_it(admin_fixture, mapping, request):
    model_admin = request.getfixturevalue(admin_fixture)

    for name, permission in mapping.items():
        offered = model_admin.get_actions(_request(permission))
        assert name in offered, f"{name} is hidden from {permission}"
        others = {other for other, perm in mapping.items() if perm != permission}
        assert not (others & set(offered)), f"{permission} reaches more than it maps to"


@pytest.mark.parametrize("admin_fixture", ["dek_admin", "kek_admin"])
def test_view_only_staff_is_offered_no_action(admin_fixture, request):
    model_admin = request.getfixturevalue(admin_fixture)

    assert model_admin.get_actions(_request("encryption_suite.view_dataencryptionkey")) == {}


def test_the_admins_own_delete_action_stays_stripped(dek_admin, kek_admin):
    """``destroy`` must not have re-enabled Django's bulk delete."""
    every = _request(
        "encryption_suite.delete_dataencryptionkey",
        "encryption_suite.delete_keyencryptionkey",
        "encryption_suite.change_dataencryptionkey",
        "encryption_suite.change_keyencryptionkey",
    )

    assert "delete_selected" not in dek_admin.get_actions(every)
    assert "delete_selected" not in kek_admin.get_actions(every)


@pytest.mark.parametrize("admin_fixture", ["dek_admin", "kek_admin"])
def test_a_row_stays_view_only_for_the_permission_that_runs_the_restore(admin_fixture, request):
    """The change permission runs actions; it still may not save a detail page."""
    model_admin = request.getfixturevalue(admin_fixture)
    changer = _request(f"encryption_suite.change_{model_admin.model._meta.model_name}")

    assert model_admin.has_change_permission(changer) is True
    assert model_admin.has_change_permission(changer, obj=object()) is False


# ----------------------------------------------------------------------
# Custom screens
# ----------------------------------------------------------------------

CONSOLE_VIEWS = (
    admin_test_console.test_console_view,
    admin_test_console.test_console_run_view,
    admin_test_console.test_console_delete_view,
)


@pytest.mark.parametrize("view", CONSOLE_VIEWS)
def test_the_console_is_refused_without_its_own_permission(view):
    """Holding every key permission is not console access — the grant is its own."""
    holder = _request(
        "encryption_suite.add_keyencryptionkey",
        "encryption_suite.delete_keyencryptionkey",
        "encryption_suite.delete_dataencryptionkey",
    )

    with pytest.raises(PermissionDenied):
        view(None, holder)


@pytest.mark.parametrize("view", CONSOLE_VIEWS)
def test_the_console_refuses_a_non_staff_holder(view):
    holder = _request("encryption_suite.run_test_console")
    holder.user.is_staff = False

    with pytest.raises(PermissionDenied):
        view(None, holder)


def test_reconcile_is_refused_without_its_own_permission():
    viewer = _request(
        "encryption_suite.view_dataencryptionkey",
        "encryption_suite.view_keyencryptionkey",
    )

    with pytest.raises(PermissionDenied):
        admin_reconcile.reconcile_keys_view(None, viewer)


def test_reconcile_refuses_a_non_staff_holder():
    holder = _request("encryption_suite.reconcile_keys")
    holder.user.is_staff = False

    with pytest.raises(PermissionDenied):
        admin_reconcile.reconcile_keys_view(None, holder)


def test_the_screen_permissions_have_a_home_of_their_own():
    """Both screens span both key models, so neither model carries their permissions."""
    meta = EncryptionTools._meta

    assert meta.managed is False
    assert meta.default_permissions == ()
    assert {codename for codename, _label in meta.permissions} == {
        "reconcile_keys",
        "run_test_console",
        "view_settings",
        "view_inventory",
    }
