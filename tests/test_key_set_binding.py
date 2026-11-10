"""Key sets: how a key set resolves to an adapter and a store, and how two adapters keep their own keys."""

from __future__ import annotations

import copy
from contextlib import contextmanager
from contextvars import ContextVar

import pytest
from django.conf import settings
from django.test import override_settings

from encryption_suite import conf, registry
from encryption_suite.adapters.keks.strategies import PerSiloKekStrategy
from encryption_suite.adapters.key_stores.aws import AwsKmsAdapter
from encryption_suite.adapters.silos.base import AbstractSiloAdapter
from encryption_suite.checks import check_kms_settings
from encryption_suite.models import DataEncryptionKey
from encryption_suite.registry import get_engine
from encryption_suite.silo_ref import AmbientSilo, SiloRef, silo_filter, whole_silo_filter
from tests.key_set_settings import key_sets

_current_user: ContextVar = ContextVar("current_user", default=None)


class ActingUserSiloAdapter(AbstractSiloAdapter):
    """One silo per user: the uid is the user's pk, raw."""

    def get_current_silo(self):
        return _current_user.get()

    def get_silo_uid(self, silo) -> str:
        return str(silo)

    def get_silo_label(self) -> str:
        return "user"


@contextmanager
def as_user(pk):
    token = _current_user.set(pk)
    try:
        yield
    finally:
        _current_user.reset(token)


def _with_encryption(**overrides):
    config = copy.deepcopy(settings.ENCRYPTION)
    config.update(overrides)
    return override_settings(ENCRYPTION=config)


_USER_ADAPTER = f"{__name__}.ActingUserSiloAdapter"


# --- how a key set resolves to a named store ---------------------------------


def test_a_key_set_with_no_store_uses_the_only_store():
    sets = {
        "default": {"silo": "tests.silo.GroupSiloAdapter"},
        "archive": {"silo": "tests.silo.GroupSiloAdapter"},
    }
    with _with_encryption(KMS_KEY_STORES={}, KEY_SETS=sets):
        assert conf.resolve_store("default") == "login"
        assert conf.resolve_store("archive") == "login"


def test_each_key_set_names_its_own_store():
    with _with_encryption(KEY_SETS=key_sets(default="local", archive="login")):
        assert conf.resolve_store("default") == "local"
        assert conf.resolve_store("archive") == "login"
        assert conf.resolve_store("cold") is None
        assert "no entry for the key set 'cold'" in conf.store_problem("cold")


def test_several_stores_and_no_store_named_resolve_to_none():
    sets = {"default": {"silo": "tests.silo.GroupSiloAdapter"}}
    with _with_encryption(KEY_SETS=sets):
        assert conf.resolve_store("default") is None
        assert "has no 'key_store' to choose one" in conf.store_problem("default")


def test_a_store_that_is_not_configured_resolves_to_none():
    with _with_encryption(KEY_SETS=key_sets(default="nowhere")):
        assert conf.resolve_store("default") is None
        assert "names no configured store" in conf.store_problem("default")


def test_the_system_key_set_exists_with_no_entry():
    with _with_encryption(KEY_SETS={}, KMS_KEY_STORES={}):
        assert "system" in conf.key_set_names()
        assert conf.adapter_path("system") == conf.SYSTEM_ADAPTER
        assert conf.resolve_store("system") == "login"


# --- a second adapter keeps its own silos, keys and files --------------------


@pytest.fixture
def user_key_set():
    sets = {**key_sets(), "user": {"silo": _USER_ADAPTER, "key_store": "local"}}
    with _with_encryption(KEY_SETS=sets):
        registry.reset()
        yield
    registry.reset()


@pytest.mark.django_db
def test_the_same_uid_under_two_adapters_is_two_silos(user_key_set, tenant):
    """Identity is the key set and the uid, so ``5`` for a user is not ``5`` for a group."""
    engine = get_engine()
    group_uid = engine.silo_adapter.get_silo_uid(tenant)

    with as_user(group_uid):
        user_ciphertext = engine.encrypt("a user's secret", silo=AmbientSilo("user"))
    group_ciphertext = engine.encrypt("a group's secret", silo=tenant)

    rows = DataEncryptionKey.objects.filter(purpose=DataEncryptionKey.PURPOSE_FIELD, silo_uid=group_uid)
    assert {row.key_set for row in rows} == {"user", "default"}
    with as_user(group_uid):
        assert engine.decrypt(user_ciphertext, silo=AmbientSilo("user")) == "a user's secret"
    assert engine.decrypt(group_ciphertext, silo=tenant) == "a group's secret"


@pytest.mark.django_db
def test_one_key_sets_ciphertext_does_not_open_under_another(user_key_set, tenant):
    from encryption_suite.exceptions import EncryptedFieldDecryptionError

    engine = get_engine()
    uid = engine.silo_adapter.get_silo_uid(tenant)
    with as_user(uid):
        ciphertext = engine.encrypt("secret", silo=AmbientSilo("user"))
    engine.encrypt("another", silo=tenant)  # the group silo now has its own key

    with pytest.raises(EncryptedFieldDecryptionError):
        engine.decrypt(ciphertext, silo=tenant)


@pytest.mark.django_db
def test_no_user_in_the_context_is_a_configuration_error(user_key_set):
    from encryption_suite.exceptions import EncryptionConfigurationError

    with pytest.raises(EncryptionConfigurationError):
        get_engine().encrypt("secret", silo=AmbientSilo("user"))


@pytest.mark.django_db
def test_a_key_set_with_no_adapter_is_a_configuration_error():
    from encryption_suite.exceptions import EncryptionConfigurationError

    with pytest.raises(EncryptionConfigurationError):
        registry.get_silo_adapter("user")


@pytest.mark.django_db
def test_two_key_sets_in_one_silo_get_distinct_keys_on_their_own_stores(tenant):
    from encryption_suite.exceptions import EncryptedFieldDecryptionError

    with _with_encryption(KEY_SETS=key_sets(archive="login")):
        engine = get_engine()

        first = engine.encrypt("on the default set", silo=tenant)
        second = engine.encrypt("on the archive set", silo=tenant, key_set="archive")

        uid = f"group-{tenant.pk}"
        rows = {
            row.key_set: row
            for row in DataEncryptionKey.objects.select_related("kek").filter(
                silo_uid=uid, purpose=DataEncryptionKey.PURPOSE_FIELD
            )
        }
        assert set(rows) == {"default", "archive"}
        assert rows["default"].kek.key_store == "local"
        assert rows["archive"].kek.key_store == "login"
        assert engine.decrypt(first, silo=tenant) == "on the default set"
        assert engine.decrypt(second, silo=tenant, key_set="archive") == "on the archive set"
        # The sets are separate keys: the default set's cannot open the archive set's ciphertext.
        with pytest.raises(EncryptedFieldDecryptionError):
            engine.decrypt(second, silo=tenant)


# --- a silo is an adapter's, whatever number of key sets it has --------------


def test_key_sets_bound_to_one_adapter_share_its_instance():
    with _with_encryption(KEY_SETS=key_sets(archive="login")):
        registry.reset()
        assert registry.get_silo_adapter("default") is registry.get_silo_adapter("archive")
        groups = {tuple(members) for _adapter, members in registry.silo_adapter_groups()}
        assert groups == {("default", "archive"), ("system",)}
    registry.reset()


def test_the_whole_silo_filter_names_every_key_set_of_the_adapter():
    with _with_encryption(KEY_SETS=key_sets(archive="login")):
        selected = whole_silo_filter(SiloRef("default", "group-1"))

    assert selected == {"key_set__in": ["default", "archive"], "silo_uid": "group-1"}
    assert silo_filter(SiloRef("archive", "group-1")) == {"key_set": "archive", "silo_uid": "group-1"}


@pytest.mark.django_db
def test_scheduling_a_silo_covers_every_key_set_bound_to_its_adapter(tenant):
    from encryption_suite import lifecycle
    from encryption_suite.deletion import schedule_deletion

    with _with_encryption(KEY_SETS=key_sets(archive="login")):
        engine = get_engine()
        engine.encrypt("one", silo=tenant)
        engine.encrypt("two", silo=tenant, key_set="archive")
        uid = f"group-{tenant.pk}"

        schedule_deletion(SiloRef("default", uid))

        rows = DataEncryptionKey.objects.filter(silo_uid=uid, purpose=DataEncryptionKey.PURPOSE_FIELD)
        assert {row.key_set for row in rows} == {"default", "archive"}
        assert {row.status for row in rows} == {lifecycle.STATUS_DELETION_SCHEDULED}


# --- KEK naming per store ----------------------------------------------------


def _strategy(**options):
    return PerSiloKekStrategy(options)


def test_a_store_has_one_template_for_every_key_set():
    strategy = _strategy(KEK_TEMPLATE="alias/acme-team-{silo_uid}")

    assert strategy.get_kek_id(SiloRef("default", "42")) == "alias/acme-team-42"
    assert strategy.get_kek_id(SiloRef("archive", "42")) == "alias/acme-team-42"
    assert strategy.owner_prefix() == "alias/acme-team-"


def test_a_map_entry_for_a_silo_wins_over_the_template():
    strategy = _strategy(
        KEK_TEMPLATE="alias/acme-user-{silo_uid}",
        KEK_MAP={"5": "arn:aws:kms:us-east-1:111:alias/user-5"},
    )

    assert strategy.get_kek_id(SiloRef("user", "5")) == "arn:aws:kms:us-east-1:111:alias/user-5"
    assert strategy.get_kek_id(SiloRef("user", "6")) == "alias/acme-user-6"
    assert strategy.kek_disposition(SiloRef("user", "5")) == "shared"
    assert strategy.kek_disposition(SiloRef("user", "6")) == "silo_exclusive"


def test_a_store_with_neither_template_nor_map_is_a_configuration_error():
    from encryption_suite.exceptions import EncryptionConfigurationError

    with pytest.raises(EncryptionConfigurationError):
        _strategy().get_kek_id(SiloRef("user", "5"))


def test_a_store_served_only_by_the_map_has_no_owner_prefix():
    strategy = _strategy(KEK_MAP={"5": "arn:x"})

    assert strategy.owner_prefix() is None


def test_the_adapter_canonicalizes_the_stores_prefix():
    options = {"AWS_REGION": "us-east-1", "KEK_TEMPLATE": "alias/b-{silo_uid}"}
    strategy = AwsKmsAdapter.build_strategy(PerSiloKekStrategy, options)
    adapter = AwsKmsAdapter(options, strategy)

    assert adapter.owner_prefix() == "alias/b-"
    assert adapter.resolve_kek_name(SiloRef("user", "9")) == "alias/b-9"


# --- the deploy checks -------------------------------------------------------


def _per_silo_block(template):
    return {
        "ADAPTER": "encryption_suite.adapters.key_stores.aws.AwsKmsAdapter",
        "KEK_STRATEGY_ADAPTER": "encryption_suite.adapters.keks.PerSiloKekStrategy",
        "OPTIONS": {"AWS_REGION": "us-east-1", "KEK_TEMPLATE": template},
    }


def _check_ids(**overrides):
    with _with_encryption(**overrides):
        return {error.id for error in check_kms_settings(None)}


def test_overlapping_store_prefixes_are_refused():
    ids = _check_ids(
        KMS_KEY_STORES={
            "aws": _per_silo_block("alias/acme-{silo_uid}"),
            "aws2": _per_silo_block("alias/acme-user-{silo_uid}"),
        },
        KEY_SETS=key_sets(default="aws", user="aws2"),
    )

    assert "encryption_suite.E037" in ids


def test_prefix_free_templates_pass():
    ids = _check_ids(
        KMS_KEY_STORES={
            "aws": _per_silo_block("alias/acme-team-{silo_uid}"),
            "aws2": _per_silo_block("alias/acme-user-{silo_uid}"),
        },
        KEY_SETS=key_sets(default="aws", user="aws2"),
    )

    assert "encryption_suite.E037" not in ids


def test_a_store_a_key_set_reaches_needs_a_template_or_map():
    block = _per_silo_block("")
    block["OPTIONS"].pop("KEK_TEMPLATE")

    ids = _check_ids(KMS_KEY_STORES={"aws": block}, KEY_SETS=key_sets(default="aws"))

    assert "encryption_suite.E037" in ids


def test_a_nested_template_is_refused():
    ids = _check_ids(
        KMS_KEY_STORES={"aws": _per_silo_block({"scoped": "alias/acme-{silo_uid}"})},
        KEY_SETS=key_sets(default="aws"),
    )

    assert "encryption_suite.E037" in ids


def test_a_bad_key_set_name_is_refused():
    sets = {**key_sets(), "Scoped-Kind": {"silo": "tests.silo.GroupSiloAdapter", "key_store": "local"}}

    assert "encryption_suite.E038" in _check_ids(KEY_SETS=sets)


def test_a_key_set_name_over_the_length_limit_is_refused():
    sets = {**key_sets(), "a" * 33: {"silo": "tests.silo.GroupSiloAdapter", "key_store": "local"}}

    assert "encryption_suite.E038" in _check_ids(KEY_SETS=sets)


def test_a_key_set_without_an_adapter_is_refused():
    sets = {**key_sets(), "archive": {"key_store": "local"}}

    assert "encryption_suite.E038" in _check_ids(KEY_SETS=sets)


def test_a_key_sets_store_must_be_configured():
    assert "encryption_suite.E038" in _check_ids(KEY_SETS=key_sets(archive="nowhere"))


def test_a_key_set_entry_no_field_uses_is_allowed():
    assert "encryption_suite.E038" not in _check_ids(KEY_SETS=key_sets(unused="login"))


def test_a_malformed_key_set_is_refused_on_the_field():
    from encryption_suite.fields import EncryptedCharField, _check_key

    assert [error.id for error in _check_key(EncryptedCharField(key_set="Bad-Set"))] == ["encryption_suite.E041"]
    assert [error.id for error in _check_key(EncryptedCharField(key_set="a" * 33))] == ["encryption_suite.E041"]
    assert _check_key(EncryptedCharField(key_set="archive")) != []  # not declared in KEY_SETS
    with _with_encryption(KEY_SETS=key_sets(archive="login")):
        assert _check_key(EncryptedCharField(key_set="archive")) == []
