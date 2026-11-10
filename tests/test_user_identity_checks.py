"""Tests for the deploy-time system checks over ``USER_IDENTITY``.

Each check can only ever fail a deploy, so each needs a case proving it fires
and one proving a valid configuration passes.
"""

from __future__ import annotations

import copy

import pytest
from django.conf import settings
from django.test import override_settings

from encryption_suite.checks import check_env_store_needed, check_user_context_middleware, check_user_identity_settings
from encryption_suite.models import RecordedIPAddress, RecordedOSUser

AUTH_MIDDLEWARE = "django.contrib.auth.middleware.AuthenticationMiddleware"
USER_CONTEXT_MIDDLEWARE = "encryption_suite.user_context.UserContextMiddleware"
NO_ENV_STORE = {"ENV_KEY_STORES": {}}


def with_encryption(**overrides):
    """The test config plus *overrides* under ENCRYPTION."""
    config = copy.deepcopy(settings.ENCRYPTION)
    config.update(overrides)
    return override_settings(ENCRYPTION=config)


def with_identity(**identity):
    """The test config with ``USER_IDENTITY`` set to exactly *identity*."""
    return with_encryption(USER_IDENTITY=identity)


def ids(errors):
    return [e.id for e in errors]


# --- the shape of USER_IDENTITY -------------------------------------------


def test_the_suite_configuration_passes():
    assert check_user_identity_settings(app_configs=None) == []


def test_the_shipped_default_passes():
    config = {k: v for k, v in copy.deepcopy(settings.ENCRYPTION).items() if k != "USER_IDENTITY"}
    with override_settings(ENCRYPTION=config):
        assert check_user_identity_settings(app_configs=None) == []


def test_a_partial_dict_passes():
    """A key the project leaves out takes its default."""
    with with_identity(LOGS=["user_id"]):
        assert check_user_identity_settings(app_configs=None) == []


def test_a_value_that_is_not_a_dict_is_an_error():
    with with_encryption(USER_IDENTITY=["user_id"]):
        assert ids(check_user_identity_settings(app_configs=None)) == ["encryption_suite.E033"]


def test_an_unknown_key_is_an_error():
    with with_identity(LOG=["user_id"]):
        assert ids(check_user_identity_settings(app_configs=None)) == ["encryption_suite.E033"]


def test_a_list_that_is_not_a_list_is_one_error_not_one_per_character():
    with with_identity(LOGS="user_id"):
        assert ids(check_user_identity_settings(app_configs=None)) == ["encryption_suite.E033"]


# --- SCOPE and IP_PROXY_COUNT ----------------------------------------------


def test_unknown_scope_is_an_error():
    with with_identity(SCOPE="none"):
        assert ids(check_user_identity_settings(app_configs=None)) == ["encryption_suite.E029"]


@pytest.mark.parametrize("scope", ["all_acts", "privileged_acts"])
def test_every_valid_scope_passes(scope):
    with with_identity(SCOPE=scope):
        assert check_user_identity_settings(app_configs=None) == []


@pytest.mark.parametrize("count", [-1, True, "1"])
def test_a_proxy_count_that_is_not_a_count_is_an_error(count):
    """True is an int in Python and would silently mean one proxy."""
    with with_identity(IP_PROXY_COUNT=count):
        assert ids(check_user_identity_settings(app_configs=None)) == ["encryption_suite.E030"]


def test_zero_proxy_count_passes():
    with with_identity(IP_PROXY_COUNT=0):
        assert check_user_identity_settings(app_configs=None) == []


# --- the items -------------------------------------------------------------


def test_every_item_passes_in_the_list_it_belongs_to():
    with with_identity(
        KEY_LIFECYCLE_EVENTS=["user_id", "encrypted_ip_address", "encrypted_os_user"],
        LOGS=["user_id", "user_name", "user_str", "ip_address", "os_user"],
    ):
        assert check_user_identity_settings(app_configs=None) == []


@pytest.mark.parametrize(
    "identity",
    [
        {"KEY_LIFECYCLE_EVENTS": ["user"]},
        {"KEY_LIFECYCLE_EVENTS": ["user_name"]},
        {"KEY_LIFECYCLE_EVENTS": ["user_str"]},
        {"LOGS": ["encrypted_ip_address"]},
        {"LOGS": ["encrypted_os_user"]},
        {"LOGS": [None]},
    ],
)
def test_an_item_a_list_cannot_hold_is_an_error(identity):
    with with_identity(**identity):
        assert ids(check_user_identity_settings(app_configs=None)) == ["encryption_suite.E034"]


@pytest.mark.parametrize("pair", [("ip_address", "encrypted_ip_address"), ("os_user", "encrypted_os_user")])
def test_both_forms_of_one_value_is_an_error(pair):
    with with_identity(KEY_LIFECYCLE_EVENTS=list(pair)):
        assert ids(check_user_identity_settings(app_configs=None)) == ["encryption_suite.E035"]


def test_a_pair_a_list_cannot_hold_is_reported_once():
    """``LOGS`` cannot hold the encrypted half, so that is E034's alone."""
    with with_identity(LOGS=["ip_address", "encrypted_ip_address"]):
        assert ids(check_user_identity_settings(app_configs=None)) == ["encryption_suite.E034"]


# --- the all_acts middleware warning ---------------------------------------


def test_no_warning_under_the_default_scope():
    with with_identity(LOGS=["user_id"]), override_settings(MIDDLEWARE=[]):
        assert check_user_context_middleware(app_configs=None) == []


def test_no_warning_while_both_lists_are_empty():
    """Nothing reads the context, so a missing middleware loses nothing."""
    with with_identity(SCOPE="all_acts"), override_settings(MIDDLEWARE=[AUTH_MIDDLEWARE]):
        assert check_user_context_middleware(app_configs=None) == []


def test_all_acts_with_the_middleware_below_auth_passes():
    with (
        with_identity(SCOPE="all_acts", LOGS=["user_id"]),
        override_settings(MIDDLEWARE=[AUTH_MIDDLEWARE, USER_CONTEXT_MIDDLEWARE]),
    ):
        assert check_user_context_middleware(app_configs=None) == []


@pytest.mark.parametrize("identity", [{"LOGS": ["user_id"]}, {"KEY_LIFECYCLE_EVENTS": ["user_id"]}])
def test_all_acts_without_the_middleware_warns(identity):
    with with_identity(SCOPE="all_acts", **identity), override_settings(MIDDLEWARE=[AUTH_MIDDLEWARE]):
        assert ids(check_user_context_middleware(app_configs=None)) == ["encryption_suite.W052"]


def test_all_acts_with_the_middleware_above_auth_warns():
    with (
        with_identity(SCOPE="all_acts", LOGS=["user_id"]),
        override_settings(MIDDLEWARE=[USER_CONTEXT_MIDDLEWARE, AUTH_MIDDLEWARE]),
    ):
        assert ids(check_user_context_middleware(app_configs=None)) == ["encryption_suite.W052"]


def test_no_authentication_middleware_does_not_warn():
    """A project may authenticate some other way; only the ordering is unknown."""
    with (
        with_identity(SCOPE="all_acts", LOGS=["user_id"]),
        override_settings(MIDDLEWARE=[USER_CONTEXT_MIDDLEWARE]),
    ):
        assert check_user_context_middleware(app_configs=None) == []


# --- the env store the identity tables need ---------------------------------


@pytest.fixture
def only_the_identity_tables(monkeypatch):
    """A project declaring no system field of its own: only the package's tables are seen."""
    from django.apps import apps

    monkeypatch.setattr(apps, "get_models", lambda **kwargs: [RecordedIPAddress, RecordedOSUser])


def test_the_identity_tables_alone_need_no_env_store(only_the_identity_tables):
    """Every install has them; one that never encrypts must not need an env store for them."""
    with with_encryption(**NO_ENV_STORE, USER_IDENTITY={"KEY_LIFECYCLE_EVENTS": ["ip_address", "os_user"]}):
        assert check_env_store_needed(app_configs=None) == []


@pytest.mark.parametrize("item", ["encrypted_ip_address", "encrypted_os_user"])
def test_a_listed_encrypted_item_needs_an_env_store(only_the_identity_tables, item):
    with with_encryption(**NO_ENV_STORE, USER_IDENTITY={"KEY_LIFECYCLE_EVENTS": [item]}):
        errors = check_env_store_needed(app_configs=None)
    assert ids(errors) == ["encryption_suite.E040"]
    assert item in errors[0].msg


def test_a_listed_encrypted_item_passes_with_an_env_store(only_the_identity_tables):
    with with_identity(KEY_LIFECYCLE_EVENTS=["encrypted_ip_address"]):
        assert check_env_store_needed(app_configs=None) == []
