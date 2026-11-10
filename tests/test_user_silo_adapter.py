"""The user silo adapter: one silo per user, chosen by who is acting."""

from __future__ import annotations

from io import StringIO

import pytest
from django.conf import settings
from django.contrib.auth import get_user_model
from django.db import connection, models
from django.db.models.signals import post_delete, post_save
from django.test import RequestFactory, override_settings

from encryption_suite import lifecycle, registry
from encryption_suite._internal import raw_cursor_fetch
from encryption_suite.adapters.silos.context import override_current_silo
from encryption_suite.adapters.silos.user import ActingUserSiloAdapter
from encryption_suite.checks import check_silo_data_lookup, check_user_key_set_middleware
from encryption_suite.deletion import schedule_deletion
from encryption_suite.engine import is_silo_value
from encryption_suite.exceptions import EncryptionConfigurationError
from encryption_suite.fields import EncryptedCharField
from encryption_suite.models import DataEncryptionKey
from encryption_suite.registry import get_engine
from encryption_suite.silo_ref import AmbientSilo, SiloRef
from encryption_suite.user_context import (
    UserContextMiddleware,
    get_current_user,
    override_current_user,
    user_key_set_bound,
)
from tests.key_set_settings import key_sets

ADAPTER = "encryption_suite.adapters.silos.user.ActingUserSiloAdapter"

pytestmark = pytest.mark.django_db


class UserNote(models.Model):
    """A user's own note, in the ``user`` key set."""

    owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="+")
    body = EncryptedCharField(key_set="user", max_length=200, null=True)

    class Meta:
        app_label = "tests"


class TwoOwnerNote(models.Model):
    """Two foreign keys to the user table, which no introspection can choose between."""

    author = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="+")
    reviewer = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="+")
    body = EncryptedCharField(key_set="user", max_length=200, null=True)

    class Meta:
        app_label = "tests"


@pytest.fixture
def user_key_set():
    sets = {**key_sets(), "user": {"silo": ADAPTER, "key_store": "local"}}
    with override_settings(ENCRYPTION={**settings.ENCRYPTION, "KEY_SETS": sets}):
        registry.reset()
        yield
    registry.reset()


@pytest.fixture
def notes(user_key_set):
    with connection.schema_editor() as editor:
        editor.create_model(UserNote)
    try:
        yield UserNote
    finally:
        with connection.schema_editor() as editor:
            editor.delete_model(UserNote)


def _user(username):
    return get_user_model().objects.create_user(username=username, password="pw")


# --- identity ------------------------------------------------------------------


def test_the_uid_is_user_and_the_pk_for_an_instance_or_a_pk():
    user = _user("ann")
    adapter = ActingUserSiloAdapter()
    assert adapter.get_silo_uid(user) == f"user-{user.pk}"
    assert adapter.get_silo_uid(user.pk) == f"user-{user.pk}"
    assert adapter.get_silo_label() == "user"
    assert adapter.model_label == settings.AUTH_USER_MODEL
    assert adapter.silo_model_labels == (settings.AUTH_USER_MODEL,)


def test_point_queries_answer_by_pk():
    user = _user("ann")
    adapter = ActingUserSiloAdapter()
    uid = f"user-{user.pk}"
    assert adapter.silo_for_uid(uid) == user
    assert adapter.silo_exists(uid) is True
    assert adapter.silo_exists("user-999999") is False
    assert adapter.silo_exists("team-1") is False
    # A value the pk field cannot hold names no user.
    assert adapter.silo_for_uid("user-not-a-number") is None
    assert adapter.silo_exists("user-not-a-number") is False


def test_the_description_is_the_users_str():
    user = _user("ann")
    assert ActingUserSiloAdapter().describe_silo(f"user-{user.pk}") == str(user)
    assert ActingUserSiloAdapter().describe_silo("user-999999") == ""
    assert ActingUserSiloAdapter().describe_silo("team-1") == ""


def test_every_user_is_enumerated():
    users = [_user("ann"), _user("bob")]
    assert set(ActingUserSiloAdapter().iter_silos()) == set(users)


# --- the acting user -----------------------------------------------------------


def test_the_current_silo_is_the_acting_users_pk():
    adapter = ActingUserSiloAdapter()
    assert adapter.get_current_silo() is None
    with override_current_user(7):
        assert adapter.get_current_silo() == 7


def test_no_user_in_the_context_is_a_configuration_error(user_key_set):
    with pytest.raises(EncryptionConfigurationError):
        get_engine().encrypt("secret", silo=AmbientSilo("user"))


def test_the_user_adapter_and_a_team_adapter_do_not_share_a_context(user_key_set, tenant):
    engine = get_engine()
    with override_current_silo(tenant):
        # The team silo is set and no user is: the user key set still has no silo.
        with pytest.raises(EncryptionConfigurationError):
            engine.encrypt("secret", silo=AmbientSilo("user"))
        with override_current_user(5):
            engine.encrypt("mine", silo=AmbientSilo("user"))
            engine.encrypt("ours", silo=AmbientSilo("default"))
    uids = set(DataEncryptionKey.objects.values_list("silo_uid", flat=True))
    assert {"user-5", f"group-{tenant.pk}"} <= uids


# --- fields --------------------------------------------------------------------


@pytest.mark.django_db(transaction=True)
def test_a_field_round_trips_for_its_user_and_no_one_else(notes):
    ann, bob = _user("ann"), _user("bob")
    with override_current_user(ann.pk):
        note = notes.objects.create(owner=ann, body="ann's secret")
        assert notes.objects.get(pk=note.pk).body == "ann's secret"
    [stored] = raw_cursor_fetch(notes, note.pk, ["body"])
    assert is_silo_value(stored)
    assert "secret" not in stored
    assert DataEncryptionKey.objects.filter(key_set="user", silo_uid=f"user-{ann.pk}").exists()

    with override_current_user(bob.pk):
        assert notes.objects.get(pk=note.pk).body != "ann's secret"
    # With no user at all the read degrades to the fallback too.
    assert notes.objects.get(pk=note.pk).body != "ann's secret"


# --- the middleware ------------------------------------------------------------


def _seen_by_middleware(user):
    seen = {}

    def get_response(request):
        seen["pk"] = get_current_user().user_pk
        return None

    request = RequestFactory().get("/")
    request.user = user
    UserContextMiddleware(get_response)(request)
    return seen["pk"]


def test_the_middleware_fills_the_context_when_a_key_set_reads_it(user_key_set):
    user = _user("ann")
    assert user_key_set_bound() is True
    assert _seen_by_middleware(user) == user.pk


def test_the_middleware_leaves_the_context_empty_when_nothing_reads_it():
    user = _user("ann")
    with override_settings(ENCRYPTION={**settings.ENCRYPTION, "USER_IDENTITY": {}}):
        assert user_key_set_bound() is False
        assert _seen_by_middleware(user) is None


def test_turning_user_keys_on_does_not_turn_ledger_recording_on(user_key_set):
    from encryption_suite.user_context import recordable_context

    with override_current_user(5):
        assert recordable_context().user_pk is None


# --- checks --------------------------------------------------------------------


def test_w060_warns_when_the_middleware_is_missing(user_key_set):
    with override_settings(MIDDLEWARE=["django.contrib.auth.middleware.AuthenticationMiddleware"]):
        [found] = check_user_key_set_middleware(None)
    assert found.id == "encryption_suite.W060"
    assert "user" in found.msg


def test_w060_warns_when_the_middleware_is_above_authentication(user_key_set):
    above = [
        "encryption_suite.user_context.UserContextMiddleware",
        "django.contrib.auth.middleware.AuthenticationMiddleware",
    ]
    with override_settings(MIDDLEWARE=above):
        [found] = check_user_key_set_middleware(None)
    assert found.id == "encryption_suite.W060"


def test_w060_is_quiet_when_the_middleware_follows_authentication(user_key_set):
    below = [
        "django.contrib.auth.middleware.AuthenticationMiddleware",
        "encryption_suite.user_context.UserContextMiddleware",
    ]
    with override_settings(MIDDLEWARE=below):
        assert check_user_key_set_middleware(None) == []


def test_w060_is_quiet_when_no_key_set_reads_the_user():
    assert check_user_key_set_middleware(None) == []


def test_w053_reports_a_user_model_with_two_foreign_keys(user_key_set, monkeypatch):
    from encryption_suite import rotation_targets

    real = rotation_targets.encrypted_models

    def with_two_owner_note(key_set="default"):
        yield from real(key_set)
        if key_set == "user":
            yield TwoOwnerNote, ("body",), (), ()

    monkeypatch.setattr(rotation_targets, "encrypted_models", with_two_owner_note)
    [found] = check_silo_data_lookup(None)
    assert found.id == "encryption_suite.W053"
    assert "tests.TwoOwnerNote" in found.msg
    assert "more than one foreign key" in found.msg


# --- lifecycle -----------------------------------------------------------------


@pytest.mark.parametrize("store", ["local", "login"])
def test_creating_a_user_makes_its_field_key(store):
    sets = {**key_sets(), "user": {"silo": ADAPTER, "key_store": store}}
    config = {**settings.ENCRYPTION, "KEY_SETS": sets, "SILO_AUTO_KEY_CREATION": ["user"]}
    from django.apps import apps as django_apps

    with override_settings(ENCRYPTION=config):
        registry.reset()
        django_apps.get_app_config("encryption_suite")._register_auto_create_signals()
        try:
            user = _user("ann")
            rows = DataEncryptionKey.objects.filter(silo_uid=f"user-{user.pk}")
            assert {(row.key_set, row.purpose) for row in rows} == {("user", DataEncryptionKey.PURPOSE_FIELD)}
            assert {row.kek.key_store for row in rows.select_related("kek")} == {store}
        finally:
            post_save.disconnect(
                sender=get_user_model(),
                dispatch_uid=f"encrypted_fields_auto_create_user_{get_user_model()._meta.label}",
            )
    registry.reset()


def test_deleting_a_user_schedules_its_keys(user_key_set):
    from django.apps import apps as django_apps

    config = {**settings.ENCRYPTION, "SILO_AUTO_KEY_DELETION": ["user"]}
    with override_settings(ENCRYPTION=config):
        user = _user("ann")
        uid = f"user-{user.pk}"
        with override_current_user(user.pk):
            get_engine().encrypt("mine", silo=AmbientSilo("user"))
        django_apps.get_app_config("encryption_suite")._register_deletion_signals()
        try:
            user.delete()
        finally:
            post_delete.disconnect(
                sender=get_user_model(),
                dispatch_uid=f"encrypted_fields_auto_delete_user_{get_user_model()._meta.label}",
            )
        rows = DataEncryptionKey.objects.filter(silo_uid=uid, purpose=DataEncryptionKey.PURPOSE_FIELD)
        assert {row.status for row in rows} == {lifecycle.STATUS_DELETION_SCHEDULED}


def test_the_gate_refuses_a_live_users_shred_and_allows_a_deleted_ones(user_key_set):
    from encryption_suite.deletion import RETAIN_SILO_LIVE, dek_retain_reason

    user = _user("ann")
    ref = SiloRef("user", f"user-{user.pk}")
    assert dek_retain_reason(ref) == RETAIN_SILO_LIVE
    with override_settings(ENCRYPTION={**settings.ENCRYPTION, "KEY_DELETION_CAN_RENDER_DATA_INACCESSIBLE": True}):
        assert dek_retain_reason(ref) is None

    user.delete()
    assert dek_retain_reason(ref) is None


def test_scheduling_a_users_shred_marks_every_key_of_the_user(user_key_set):
    user = _user("ann")
    uid = f"user-{user.pk}"
    with override_current_user(user.pk):
        get_engine().encrypt("mine", silo=AmbientSilo("user"))
    schedule_deletion(SiloRef("user", uid))
    rows = DataEncryptionKey.objects.filter(silo_uid=uid, purpose=DataEncryptionKey.PURPOSE_FIELD)
    assert {row.status for row in rows} == {lifecycle.STATUS_DELETION_SCHEDULED}


def test_rows_are_found_by_the_single_foreign_key(user_key_set):
    from encryption_suite.rotation_targets import resolve_targets

    adapter = registry.get_silo_adapter("user")
    resolution = resolve_targets(adapter, models=[(UserNote, ("body",), (), ())])
    assert resolution.unresolved == []
    [target] = resolution.targets
    assert target.fk_name == "owner"


# --- provisioning and the migration helpers --------------------------------------


def test_setup_encryption_keys_provisions_every_user_of_the_key_set(user_key_set, monkeypatch):
    # Transient test models are not installed, so name the key set a field would declare.
    monkeypatch.setattr("encryption_suite.rotation_targets.key_sets_in_use", lambda: {"user"})
    from django.core.management import call_command

    users = [_user("ann"), _user("bob")]
    call_command("setup_encryption_keys", "--key-set", "user", stdout=StringIO(), stderr=StringIO())

    uids = set(DataEncryptionKey.objects.filter(key_set="user").values_list("silo_uid", flat=True))
    assert uids == {f"user-{user.pk}" for user in users}


def test_the_migration_helpers_build_the_uid_the_adapter_reads(user_key_set):
    from encryption_suite.migration_helpers import _resolve_silo_uid

    user = _user("ann")
    note = UserNote(owner=user)
    ref = _resolve_silo_uid(note, "owner", "pk", "user", "user")
    assert ref == SiloRef("user", ActingUserSiloAdapter().get_silo_uid(user))
