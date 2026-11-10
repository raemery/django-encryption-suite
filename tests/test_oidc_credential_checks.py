"""The OIDC credential check sits on the builder axis, with the other four.

Resolving ``OIDC_SOURCE`` calls ``build_oidc_source`` — the same construction
the credential strategy performs at request time — so it carries the same
exposure as the adapter and provisioner checks: it can fail over a missing
optional SDK or a changed library while the configuration is correct. That is
what ``STARTUP_CHECK_WARN_ONLY`` is for, and this check has to move with it or
a bench set up to deploy against a known-bad config still cannot deploy.
"""

from __future__ import annotations

from django.core.checks import ERROR, WARNING
from django.test import override_settings

from encryption_suite.checks import check_oidc_credential_config


def _block_config(**block):
    return {
        "KEY_SETS": {"default": {"silo": "tests.silo.GroupSiloAdapter", "key_store": "kms"}},
        "KMS_KEY_STORES": {"kms": {"ADAPTER": "x.Y", **block}},
    }


def _config(*, warn_only=False, **options):
    cfg = _block_config(OPTIONS={"CREDENTIAL_STRATEGY": "oidc", **options})
    if warn_only:
        cfg["STARTUP_CHECK_WARN_ONLY"] = True
    return cfg


def test_a_missing_source_is_an_error():
    with override_settings(ENCRYPTION=_config()):
        (error,) = check_oidc_credential_config(app_configs=None)

    assert error.id == "encryption_suite.E001"
    assert error.level == ERROR
    assert "OIDC_SOURCE is not set" in error.msg
    assert "ENCRYPTION['KMS_KEY_STORES']['kms']['OPTIONS']" in error.msg


def test_an_unresolvable_source_is_an_error():
    with override_settings(ENCRYPTION=_config(OIDC_SOURCE="not-a-real-source")):
        (error,) = check_oidc_credential_config(app_configs=None)

    assert error.id == "encryption_suite.E001"
    assert "not-a-real-source" in error.msg


def test_the_provisioner_half_reports_separately():
    cfg = _block_config(KEK_PROVISIONER_OPTIONS={"CREDENTIAL_STRATEGY": "oidc"})
    with override_settings(ENCRYPTION=cfg):
        (error,) = check_oidc_credential_config(app_configs=None)

    assert error.id == "encryption_suite.E002"
    assert "KEK_PROVISIONER_OPTIONS" in error.msg


def test_warn_only_downgrades_it_with_the_other_builders():
    """The same condition, said more quietly — and the number does not move."""
    with override_settings(ENCRYPTION=_config(warn_only=True)):
        (warning,) = check_oidc_credential_config(app_configs=None)

    assert warning.id == "encryption_suite.W001"
    assert warning.level == WARNING


def test_a_strategy_that_is_not_oidc_is_not_checked():
    cfg = _block_config(OPTIONS={"CREDENTIAL_STRATEGY": "iam_role"})
    with override_settings(ENCRYPTION=cfg):
        assert check_oidc_credential_config(app_configs=None) == []
