"""The read-only Encryption settings screen.

Its job is to answer the question the other screens raise and cannot settle —
why a ledger row names nobody, why another carries an address. Its risk is the
opposite one: a screen that prints settings must never print a credential, so
what may be shown is declared in ``conf`` beside the settings themselves, and
anything unclassified is hidden.
"""

from __future__ import annotations

import pytest
from django.contrib.admin.sites import AdminSite
from django.contrib.auth.models import AnonymousUser
from django.core.exceptions import PermissionDenied
from django.test import RequestFactory, override_settings

from encryption_suite import conf
from encryption_suite.admin import DataEncryptionKeyAdmin
from encryption_suite.admin_settings import (
    GROUP_LABELS,
    build_setting_groups,
    settings_view,
)
from encryption_suite.models import DataEncryptionKey

#: The required settings, so an ``override_settings`` block can add one key
#: without tripping the missing-required check in ``conf``.
_MINIMAL = {
    "KEY_SETS": {"default": {"silo": "tests.silo.FakeSiloAdapter", "key_store": "login"}},
}


def _block_value(options):
    """The settings screen's value for a ``KMS_KEY_STORES`` block holding *options*."""
    block = {"ADAPTER": "encryption_suite.adapters.key_stores.aws.AwsKmsAdapter", "OPTIONS": options}
    with override_settings(ENCRYPTION={**_MINIMAL, "KMS_KEY_STORES": {"aws": block}}):
        return _rows()['KMS_KEY_STORES["aws"]']["value"]


class _Staff(AnonymousUser):
    is_active = True
    is_staff = True

    def __init__(self, *granted):
        super().__init__()
        self._granted = set(granted)

    def has_perm(self, perm, obj=None):
        return perm in self._granted


def _request(*granted):
    request = RequestFactory().get("/admin/settings/")
    request.user = _Staff(*granted)
    return request


def _rows():
    return {row["name"]: row for group in build_setting_groups() for row in group["rows"]}


def test_every_package_setting_is_classified():
    """A new setting fails here until someone says where it goes and whether it shows.

    The screen itself decides nothing, so this is the only place the question is
    asked.
    """
    unclassified = sorted(set(conf.DEFAULTS) - set(conf.SETTING_CATALOG))
    assert not unclassified, f"settings missing from SETTING_CATALOG: {unclassified}"


def test_the_catalog_names_no_setting_that_does_not_exist():
    stray = sorted(set(conf.SETTING_CATALOG) - set(conf.DEFAULTS))
    assert not stray, f"catalog entries with no setting: {stray}"


def test_an_options_dict_hides_the_credential_and_shows_the_rest():
    """A naming template is not a secret, and hiding it costs the operator the answer."""
    value = _block_value({"KEK_TEMPLATE": "kms_{silo_uid}", "AWS_REGION": "us-east-1", "VAULT_TOKEN": "hunter2"})

    assert "hunter2" not in value
    assert "VAULT_TOKEN=(hidden)" in value
    assert "KEK_TEMPLATE=kms_{silo_uid}" in value
    assert "AWS_REGION=us-east-1" in value
    assert "ADAPTER=encryption_suite.adapters.key_stores.aws.AwsKmsAdapter" in value


def test_an_option_key_the_package_does_not_know_is_hidden():
    """No guard test stands behind this, so the unclassified case must fail safe."""
    value = _block_value({"NEW_ADAPTER_TOKEN": "hunter2"})

    assert "OPTIONS={NEW_ADAPTER_TOKEN=(hidden)}" in value


def test_each_block_is_its_own_row():
    blocks = {
        "aws": {"ADAPTER": "encryption_suite.adapters.key_stores.aws.AwsKmsAdapter"},
        "fly": {"ADAPTER": "encryption_suite.adapters.key_stores.fly.FlyKmsAdapter"},
    }
    with override_settings(ENCRYPTION={**_MINIMAL, "KMS_KEY_STORES": blocks}):
        rows = _rows()

    assert 'KMS_KEY_STORES["aws"]' in rows and 'KMS_KEY_STORES["fly"]' in rows
    assert "KMS_KEY_STORES" not in rows


def test_env_store_material_is_hidden_but_the_store_names_are_not():
    with override_settings(
        ENCRYPTION={**_MINIMAL, "ENV_KEY_STORES": {"login": {"KEKS": {1: "bWF0ZXJpYWw=", 2: "bW9yZQ=="}}}}
    ):
        row = _rows()["ENV_KEY_STORES"]

    assert "bWF0ZXJpYWw=" not in row["value"]
    assert row["redacted"] is True
    assert row["value"] == "login=(hidden)"


def test_a_nested_options_dict_is_classified_key_by_key_too():
    value = _block_value({"OIDC_SOURCE_OPTIONS": {"ENV_VAR": "OIDC_TOKEN", "VAULT_SECRET_ID": "hunter2"}})

    assert "hunter2" not in value
    assert "ENV_VAR=OIDC_TOKEN" in value
    assert "VAULT_SECRET_ID=(hidden)" in value


def test_a_setting_the_catalog_does_not_know_is_hidden_and_grouped_last():
    """A project's own key in the dict is exactly what nobody has vetted."""
    with override_settings(ENCRYPTION={**_MINIMAL, "SOMETHING_OF_OUR_OWN": "a-token"}):
        groups = build_setting_groups()
        row = _rows()["SOMETHING_OF_OUR_OWN"]

    assert "a-token" not in row["value"]
    assert row["redacted"] is True
    assert groups[-1]["rows"][-1]["name"] == "SOMETHING_OF_OUR_OWN"


def test_a_value_reads_as_configured_only_when_the_project_names_it():
    with override_settings(ENCRYPTION={**_MINIMAL, "DEK_CACHE_TTL": 60}):
        rows = _rows()

    assert rows["DEK_CACHE_TTL"]["is_configured"] is True
    assert rows["DEK_CACHE_TTL"]["value"] == "60"
    assert rows["KEY_DELETION_WINDOW_DAYS"]["is_configured"] is False


def test_a_partial_user_identity_shows_all_four_keys_it_runs_with():
    with override_settings(ENCRYPTION={**_MINIMAL, "USER_IDENTITY": {"LOGS": ["user_id", "os_user"]}}):
        row = _rows()["USER_IDENTITY"]

    assert row["is_configured"] is True
    assert row["value"] == (
        "IP_PROXY_COUNT=0, KEY_LIFECYCLE_EVENTS=(empty), LOGS=user_id, os_user, SCOPE=privileged_acts"
    )


def test_a_user_identity_that_is_not_a_dict_is_shown_as_it_stands():
    with override_settings(ENCRYPTION={**_MINIMAL, "USER_IDENTITY": ["user_id"]}):
        assert _rows()["USER_IDENTITY"]["value"] == "user_id"


def test_the_screen_is_refused_without_its_permission():
    with pytest.raises(PermissionDenied):
        settings_view(None, _request("encryption_suite.view_dataencryptionkey"))


def test_the_screen_refuses_a_non_staff_holder():
    request = _request("encryption_suite.view_settings")
    request.user.is_staff = False

    with pytest.raises(PermissionDenied):
        settings_view(None, request)


@pytest.mark.django_db
def test_the_screen_renders_for_a_holder():
    model_admin = DataEncryptionKeyAdmin(DataEncryptionKey, AdminSite())

    response = model_admin.settings_view(_request("encryption_suite.view_settings"))

    assert response.status_code == 200
    assert [group["label"] for group in response.context_data["groups"]]


# ----------------------------------------------------------------------
# Resolved file storage — the only rows reading outside the ENCRYPTION namespace
# ----------------------------------------------------------------------

_S3 = "storages.backends.s3.S3Storage"
_FILES = "django.core.files.storage.FileSystemStorage"


def _storage_rows():
    """The storage rows as the screen renders them — inside the storage group."""
    group = next(g for g in build_setting_groups() if g["label"] == GROUP_LABELS[conf.GROUP_STORAGE])
    return {str(row["name"]): row for row in group["rows"]}


def test_the_resolved_storage_sits_with_the_other_storage_settings():
    """The alias names an entry; these rows say what that entry turned out to be."""
    with override_settings(
        ENCRYPTION={**_MINIMAL, "STORAGE_ALIAS": "encrypted"},
        STORAGES={"default": {"BACKEND": _FILES}, "encrypted": {"BACKEND": _S3}},
    ):
        conf.enc_settings.reset()
        rows = _storage_rows()
    conf.enc_settings.reset()

    assert "STORAGE_ALIAS" in rows
    assert rows["STORAGES BACKEND"]["value"] == _S3
    assert rows["STORAGES alias in use"]["value"] == "encrypted"
    assert "STORAGE_ALIAS" in str(rows["STORAGES alias in use"]["source"])


def test_a_missing_alias_falls_back_to_default_and_says_so():
    """The fallback is silent in the code, so a typo puts files somewhere else quietly."""
    with override_settings(
        ENCRYPTION={**_MINIMAL, "STORAGE_ALIAS": "encrytped"},
        STORAGES={"default": {"BACKEND": _FILES}},
    ):
        conf.enc_settings.reset()
        rows = _storage_rows()
    conf.enc_settings.reset()

    assert rows["STORAGES BACKEND"]["value"] == _FILES
    assert rows["STORAGES alias in use"]["value"] == "default"
    assert "fallback" in str(rows["STORAGES alias in use"]["source"])


def test_no_entry_at_all_reports_the_packages_own_storage():
    with override_settings(ENCRYPTION={**_MINIMAL, "STORAGE_ALIAS": "encrypted"}, STORAGES={}):
        conf.enc_settings.reset()
        rows = _storage_rows()
    conf.enc_settings.reset()

    assert "none" in str(rows["STORAGES alias in use"]["value"])
    assert "STORAGES BACKEND" not in rows


def test_storage_options_show_where_files_go_and_hide_the_credentials():
    """OPTIONS are the backend's constructor arguments, so a secret sits beside a bucket."""
    with override_settings(
        ENCRYPTION={**_MINIMAL, "STORAGE_ALIAS": "encrypted"},
        STORAGES={
            "encrypted": {
                "BACKEND": _S3,
                "OPTIONS": {
                    "bucket_name": "private-files",
                    "endpoint_url": "https://fly.storage.tigris.dev",
                    "access_key": "AKIAEXAMPLE",
                    "secret_key": "hunter2",
                },
            }
        },
    ):
        conf.enc_settings.reset()
        options = _storage_rows()["STORAGES OPTIONS"]["value"]
    conf.enc_settings.reset()

    assert "bucket_name=private-files" in options
    assert "endpoint_url=https://fly.storage.tigris.dev" in options
    assert "hunter2" not in options
    assert "AKIAEXAMPLE" not in options
    assert "secret_key=(hidden)" in options
    assert "access_key=(hidden)" in options
