"""The user-or-owner silo adapter: with nobody acting, a write goes to the row owner's silo."""

from __future__ import annotations

import pytest
from django.conf import settings
from django.contrib.auth import get_user_model
from django.db import connection, models
from django.test import override_settings

from encryption_suite import registry
from encryption_suite._internal import raw_cursor_fetch
from encryption_suite.adapters.silos.base import AbstractSiloAdapter
from encryption_suite.adapters.silos.user import ActingUserOrOwnerSiloAdapter
from encryption_suite.checks import check_row_silo_owner
from encryption_suite.engine import is_silo_value
from encryption_suite.exceptions import EncryptedFieldEncryptionError, EncryptionConfigurationError
from encryption_suite.fields import EncryptedCharField, is_undecryptable
from encryption_suite.models import DataEncryptionKey
from encryption_suite.user_context import override_current_user
from tests.key_set_settings import key_sets

ACTING = "encryption_suite.adapters.silos.user.ActingUserSiloAdapter"
OWNER = "encryption_suite.adapters.silos.user.ActingUserOrOwnerSiloAdapter"

pytestmark = pytest.mark.django_db(transaction=True)


class OwnedNote(models.Model):
    """A user's note in the ``user_owner`` key set, with a blind index."""

    owner = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, on_delete=models.CASCADE, related_name="+")
    body = EncryptedCharField(key_set="user_owner", max_length=200, null=True)
    handle = EncryptedCharField(key_set="user_owner", max_length=100, null=True, blind_index=True)

    class Meta:
        app_label = "tests"


class ActingNote(models.Model):
    """The same note in the ``user`` key set, which never falls back."""

    owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="+")
    body = EncryptedCharField(key_set="user", max_length=200, null=True)

    class Meta:
        app_label = "tests"


class TeamNote(models.Model):
    """A note in the ``default`` key set, on the test group adapter."""

    team = models.ForeignKey("auth.Group", on_delete=models.CASCADE, related_name="+")
    body = EncryptedCharField(max_length=200, null=True)

    class Meta:
        app_label = "tests"


class UnownedNote(models.Model):
    """No foreign key to the user table, so a row has no owner."""

    body = EncryptedCharField(key_set="user_owner", max_length=200, null=True)

    class Meta:
        app_label = "tests"


class TwoOwnerOwnedNote(models.Model):
    """Two foreign keys to the user table, which no introspection can choose between."""

    author = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="+")
    reviewer = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="+")
    body = EncryptedCharField(key_set="user_owner", max_length=200, null=True)

    class Meta:
        app_label = "tests"


_TABLES = (OwnedNote, ActingNote, TeamNote, UnownedNote)


@pytest.fixture
def user_key_sets():
    sets = {
        **key_sets(),
        "user": {"silo": ACTING, "key_store": "local"},
        "user_owner": {"silo": OWNER, "key_store": "local"},
    }
    with override_settings(ENCRYPTION={**settings.ENCRYPTION, "KEY_SETS": sets}):
        registry.reset()
        yield
    registry.reset()


@pytest.fixture
def tables(user_key_sets):
    with connection.schema_editor() as editor:
        for model in _TABLES:
            editor.create_model(model)
    try:
        yield
    finally:
        with connection.schema_editor() as editor:
            for model in _TABLES:
                editor.delete_model(model)


def _user(username):
    return get_user_model().objects.create_user(username=username, password="pw")


def _read_as(user, pk):
    with override_current_user(user.pk):
        return OwnedNote.objects.get(pk=pk).body


# --- identity ------------------------------------------------------------------


def test_the_label_and_uid_are_its_own(user_key_sets):
    user = _user("ann")
    adapter = ActingUserOrOwnerSiloAdapter()
    assert adapter.get_silo_label() == "user_owner"
    assert adapter.get_silo_uid(user) == f"user_owner-{user.pk}"
    assert adapter.silo_for_uid(f"user_owner-{user.pk}") == user
    assert adapter.silo_for_uid(f"user-{user.pk}") is None


def test_the_owner_of_a_user_row_is_the_user(user_key_sets):
    user = _user("ann")
    assert ActingUserOrOwnerSiloAdapter().silo_for_row(user) == user.pk
    # A user row the database has not numbered yet names no owner.
    assert ActingUserOrOwnerSiloAdapter().silo_for_row(get_user_model()(username="new")) is None


def test_the_owner_of_a_row_is_its_one_foreign_key(user_key_sets):
    user = _user("ann")
    adapter = ActingUserOrOwnerSiloAdapter()
    assert adapter.silo_for_row(OwnedNote(owner=user)) == user.pk
    assert adapter.silo_for_row(OwnedNote()) is None
    assert adapter.silo_for_row(UnownedNote()) is None
    assert adapter.silo_for_row(TwoOwnerOwnedNote(author=user, reviewer=user)) is None


def test_the_base_refuses_the_flag_without_the_method():
    class Incomplete(AbstractSiloAdapter):
        writes_to_row_silo_without_context = True

        def get_current_silo(self):
            return None

        def get_silo_uid(self, silo):
            return str(silo)

        def get_silo_label(self):
            return "incomplete"

    with pytest.raises(EncryptionConfigurationError):
        Incomplete().silo_for_row(object())


# --- the flag off --------------------------------------------------------------


def test_the_acting_user_adapter_refuses_a_write_with_nobody_acting(tables):
    with pytest.raises(EncryptionConfigurationError):
        ActingNote.objects.create(owner=_user("ann"), body="secret")


def test_a_team_adapter_refuses_a_write_with_no_team(tables, tenant):
    with pytest.raises(EncryptionConfigurationError):
        TeamNote.objects.create(team=tenant, body="secret")


def test_a_row_with_no_owner_is_refused_with_nobody_acting(tables):
    with pytest.raises(EncryptionConfigurationError):
        OwnedNote.objects.create(body="secret")
    with pytest.raises(EncryptionConfigurationError):
        UnownedNote.objects.create(body="secret")


# --- the flag on ---------------------------------------------------------------


def test_a_write_with_nobody_acting_goes_to_the_owner(tables):
    ann, bob = _user("ann"), _user("bob")
    note = OwnedNote.objects.create(owner=ann, body="ann's secret")

    [stored] = raw_cursor_fetch(OwnedNote, note.pk, ["body"])
    assert is_silo_value(stored)
    assert DataEncryptionKey.objects.filter(key_set="user_owner", silo_uid=f"user_owner-{ann.pk}").exists()
    assert _read_as(ann, note.pk) == "ann's secret"
    assert _read_as(bob, note.pk) != "ann's secret"


def test_a_read_with_nobody_acting_is_refused(tables):
    ann = _user("ann")
    note = OwnedNote.objects.create(owner=ann, body="ann's secret")
    # The instance just saved holds the ciphertext, and reading it does not fall back.
    assert is_undecryptable(note.body)
    assert is_undecryptable(OwnedNote.objects.get(pk=note.pk).body)


def test_an_acting_user_wins_over_the_owner(tables):
    ann, staff = _user("ann"), _user("staff")
    with override_current_user(staff.pk):
        note = OwnedNote.objects.create(owner=ann, body="written by staff")
    assert _read_as(staff, note.pk) == "written by staff"
    assert _read_as(ann, note.pk) != "written by staff"
    assert not DataEncryptionKey.objects.filter(key_set="user_owner", silo_uid=f"user_owner-{ann.pk}").exists()


def test_the_digest_is_computed_under_the_owners_silo(tables):
    ann, bob = _user("ann"), _user("bob")
    note = OwnedNote.objects.create(owner=ann, handle="ann-handle")
    with override_current_user(ann.pk):
        assert list(OwnedNote.objects.filter(handle="ann-handle").values_list("pk", flat=True)) == [note.pk]
    with override_current_user(bob.pk):
        assert not OwnedNote.objects.filter(handle="ann-handle").exists()


def test_bulk_create_with_nobody_acting_goes_to_the_owner(tables):
    ann = _user("ann")
    [note] = OwnedNote.objects.bulk_create([OwnedNote(owner=ann, body="bulk secret")])
    assert _read_as(ann, note.pk) == "bulk secret"


def test_queryset_update_with_nobody_acting_still_fails(tables):
    ann = _user("ann")
    with override_current_user(ann.pk):
        note = OwnedNote.objects.create(owner=ann, body="before")
    with pytest.raises(EncryptedFieldEncryptionError):
        OwnedNote.objects.filter(pk=note.pk).update(body="after")


# --- the check -----------------------------------------------------------------


def test_both_user_adapters_side_by_side_pass_the_system_checks(user_key_sets):
    from django.core.checks import ERROR, run_checks

    errors = [m for m in run_checks() if m.level >= ERROR and m.id.startswith("encryption_suite.")]
    registry.reset()
    assert errors == []


def _check_with(monkeypatch, *extra):
    from encryption_suite import rotation_targets

    real = rotation_targets.encrypted_models

    def with_extra(key_set="default"):
        yield from real(key_set)
        if key_set == "user_owner":
            for model in extra:
                yield model, ("body",), (), ()

    monkeypatch.setattr(rotation_targets, "encrypted_models", with_extra)
    return check_row_silo_owner(None)


def test_w061_reports_a_model_with_no_foreign_key(user_key_sets, monkeypatch):
    [found] = _check_with(monkeypatch, UnownedNote)
    assert found.id == "encryption_suite.W061"
    assert found.hint is None
    assert "'user_owner'" in found.msg
    assert f"tests.UnownedNote has no foreign key to {settings.AUTH_USER_MODEL}" in found.msg


def test_w061_reports_a_model_with_two_foreign_keys(user_key_sets, monkeypatch):
    [found] = _check_with(monkeypatch, TwoOwnerOwnedNote)
    assert found.id == "encryption_suite.W061"
    assert "tests.TwoOwnerOwnedNote has more than one foreign key" in found.msg


def test_w061_is_quiet_for_one_foreign_key_and_the_user_model(user_key_sets, monkeypatch):
    assert _check_with(monkeypatch, OwnedNote, get_user_model()) == []


def test_w061_is_quiet_without_the_flag(user_key_sets, monkeypatch):
    from encryption_suite import rotation_targets

    real = rotation_targets.encrypted_models

    def with_extra(key_set="default"):
        yield from real(key_set)
        if key_set == "user":
            yield UnownedNote, ("body",), (), ()

    monkeypatch.setattr(rotation_targets, "encrypted_models", with_extra)
    assert check_row_silo_owner(None) == []
