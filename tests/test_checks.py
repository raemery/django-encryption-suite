"""Tests for the deploy-time system check that constructs each configured KMS
block's adapter + KEK provisioner so a construction-time misconfiguration fails
``manage.py check`` instead of the first encrypt/decrypt request.
"""

from __future__ import annotations

import copy

from django.conf import settings
from django.core.checks import Error as CheckError
from django.core.checks import Warning as CheckWarning
from django.test import override_settings

from encryption_suite import registry
from encryption_suite.checks import check_kms_adapter_construction, check_kms_settings, tagging_warnings

#: A block that constructs cleanly, I/O-free, for each test to vary.
_BLOCK = {
    "ADAPTER": "encryption_suite.adapters.key_stores.environment.EnvKeyStoreAdapter",
    "KEK_STRATEGY_ADAPTER": "encryption_suite.adapters.keks.SharedKekStrategy",
    "OPTIONS": {"SHARED_KEK_ID": "k", "KEKS": {1: "3q2+7wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}},
}


def _cfg_with_block(name="kms", **block):
    """The suite's settings with one block, *name*, as the KMS store of every kind."""
    cfg = copy.deepcopy(settings.ENCRYPTION)
    cfg["KMS_KEY_STORES"] = {name: {**copy.deepcopy(_BLOCK), **block}}
    cfg["KEY_SETS"] = {"default": {**cfg["KEY_SETS"]["default"], "key_store": name}, "system": {"key_store": "login"}}
    return cfg


def _check(cfg):
    with override_settings(ENCRYPTION=cfg):
        registry.reset()
        return check_kms_adapter_construction(app_configs=None)


def _error_with_id(errors, check_id):
    matches = [e for e in errors if e.id == check_id]
    assert matches, {e.id for e in errors}
    return matches[0]


def test_passes_for_valid_config():
    registry.reset()
    assert check_kms_adapter_construction(app_configs=None) == []


def test_flags_shared_kek_incompatible_adapter():
    """An adapter whose wrap takes no AAD + SharedKekStrategy → E003 at check time."""
    errors = _check(
        _cfg_with_block(
            ADAPTER="encryption_suite.adapters.key_stores.infisical.InfisicalKmsAdapter",
            OPTIONS={"SHARED_KEK_ID": "00000000-0000-0000-0000-000000000000"},
        )
    )
    assert {e.id for e in errors} == {"encryption_suite.E003"}
    assert any("SharedKekStrategy" in e.msg for e in errors)


def test_azure_accepts_a_shared_kek():
    """Azure wraps with AES-GCM, which takes associated data, so sharing is safe.

    The silo UID is bound into every wrap, so a wrapped DEK moved between silos
    in the database fails to decrypt even though both silos use the one key.
    """
    errors = _check(
        _cfg_with_block(
            ADAPTER="encryption_suite.adapters.key_stores.azure.AzureKeyVaultAdapter",
            OPTIONS={"AZURE_VAULT_ENDPOINT": "https://vault.vault.azure.net", "SHARED_KEK_ID": "es-prod-shared"},
        )
    )
    assert errors == []


def test_flags_missing_provisioner_option():
    """An OCI provisioner with no options → E004 at check time."""
    errors = _check(
        _cfg_with_block(
            KEK_PROVISIONER_ADAPTER="encryption_suite.adapters.keks.provisioners_oci.OciKekProvisioner",
            KEK_PROVISIONER_OPTIONS={},
        )
    )
    assert "encryption_suite.E004" in {e.id for e in errors}


def test_each_block_is_checked_and_named(settings):
    """Every block is built, and a failure names the block it came from."""
    cfg = _cfg_with_block()
    cfg["KMS_KEY_STORES"]["broken"] = {**_BLOCK, "ADAPTER": "fail"}
    errors = _check(cfg)
    error = _error_with_id(errors, "encryption_suite.E003")
    assert "KMS_KEY_STORES['broken']" in error.msg
    assert len([e for e in errors if e.id == "encryption_suite.E003"]) == 1


def test_warn_only_downgrades_errors_to_warnings():
    """STARTUP_CHECK_WARN_ONLY reports the same problems as warnings, not errors."""
    from django.core.checks import WARNING

    cfg = _cfg_with_block(
        KEK_PROVISIONER_ADAPTER="encryption_suite.adapters.keks.provisioners_oci.OciKekProvisioner",
        KEK_PROVISIONER_OPTIONS={},
    )
    cfg["STARTUP_CHECK_WARN_ONLY"] = True
    errors = _check(cfg)
    assert errors
    assert all(e.level == WARNING for e in errors)


def test_check_leaves_no_cached_registry_state():
    """The check resets the registry so it does not prime singletons."""
    registry.reset()
    check_kms_adapter_construction(app_configs=None)
    assert registry._kms_adapters == {}
    assert registry._kek_provisioners == {}


# ---------------------------------------------------------------------------
# Bad dotted paths — import_string raises ImportError, reported as a CheckError
# rather than escaping as a raw traceback at deploy. One case per settable path.
# ---------------------------------------------------------------------------


def test_flags_bad_kms_adapter_path():
    errors = _check(_cfg_with_block(ADAPTER="fail"))
    assert "['ADAPTER']" in _error_with_id(errors, "encryption_suite.E003").msg


def test_flags_bad_kek_provisioner_path():
    errors = _check(_cfg_with_block(KEK_PROVISIONER_ADAPTER="fail"))
    assert "KEK_PROVISIONER_ADAPTER" in _error_with_id(errors, "encryption_suite.E004").msg


def test_flags_bad_kek_strategy_path():
    # KEK strategy is built inside the KMS adapter's construction path, so a bad
    # KEK_STRATEGY_ADAPTER dotted path surfaces under the KMS adapter's E003.
    errors = _check(_cfg_with_block(KEK_STRATEGY_ADAPTER="fail"))
    assert "KEK_STRATEGY_ADAPTER" in _error_with_id(errors, "encryption_suite.E003").msg


def test_flags_bad_silo_adapter_path():
    cfg = _cfg_with_block()
    cfg["KEY_SETS"]["default"]["silo"] = "fail"
    errors = _check(cfg)
    assert "KEY_SETS" in _error_with_id(errors, "encryption_suite.E006").msg


def test_flags_unknown_credential_strategy():
    # An unknown CREDENTIAL_STRATEGY is a name (not a dotted path), so it raises
    # EncryptionConfigurationError inside the KMS adapter __init__ and is
    # reported under the adapter's E003.
    errors = _check(
        _cfg_with_block(
            ADAPTER="encryption_suite.adapters.key_stores.azure.AzureKeyVaultAdapter",
            KEK_STRATEGY_ADAPTER="encryption_suite.adapters.keks.PerSiloKekStrategy",
            OPTIONS={
                "AZURE_VAULT_ENDPOINT": "https://vault.vault.azure.net",
                "KEK_TEMPLATE": "encryption_suite-{silo_uid}",
                "CREDENTIAL_STRATEGY": "bogus",
            },
        )
    )
    assert "encryption_suite.E003" in {e.id for e in errors}
    assert any("CREDENTIAL_STRATEGY" in e.msg for e in errors)


# ---------------------------------------------------------------------------
# KMS settings shape (E037 / E038)
# ---------------------------------------------------------------------------


def _settings_errors(cfg):
    with override_settings(ENCRYPTION=cfg):
        return check_kms_settings(None)


def test_kms_settings_pass_for_valid_config():
    assert check_kms_settings(None) == []


def test_kms_key_stores_must_be_a_dict():
    cfg = _cfg_with_block()
    cfg["KMS_KEY_STORES"] = ["kms"]
    assert "encryption_suite.E037" in {e.id for e in _settings_errors(cfg)}


def test_a_block_needs_an_adapter():
    cfg = _cfg_with_block()
    del cfg["KMS_KEY_STORES"]["kms"]["ADAPTER"]
    assert "encryption_suite.E037" in {e.id for e in _settings_errors(cfg)}


def test_an_entry_must_name_a_configured_store():
    cfg = _cfg_with_block()
    cfg["KEY_SETS"]["default"]["key_store"] = "nowhere"
    assert {e.id for e in _settings_errors(cfg)} == {"encryption_suite.E038"}


def test_a_key_set_a_field_uses_must_resolve():
    """Several stores and no entry choosing one: the fields that use the key set have no store."""
    cfg = _cfg_with_block()
    cfg["KMS_KEY_STORES"]["second"] = copy.deepcopy(_BLOCK)
    cfg["KEY_SETS"] = {"default": {"silo": cfg["KEY_SETS"]["default"]["silo"]}}
    assert "encryption_suite.E038" in {e.id for e in _settings_errors(cfg)}


# ---------------------------------------------------------------------------
# Tags (W051)
# ---------------------------------------------------------------------------


def _tags_check(**provisioner_options):
    with override_settings(ENCRYPTION=_cfg_with_block(KEK_PROVISIONER_OPTIONS=provisioner_options)):
        registry.reset()
        return tagging_warnings(registry.get_kek_provisioner(), "kms")


def test_tags_check_silent_when_nothing_configured():
    assert _tags_check() == []


def test_tags_check_warns_when_provisioner_cannot_tag():
    """The block's default provisioner is NullKekProvisioner, which writes no tags."""
    messages = _tags_check(TAGS={"ManagedBy": "encryption-suite", "Environment": "prod"})

    assert [m.id for m in messages] == ["encryption_suite.W051"]
    assert "NullKekProvisioner" in messages[0].msg
    assert "KMS_KEY_STORES']['kms']" in messages[0].msg


def test_tags_check_never_blocks_a_deploy():
    """Warning, not Error: an undeliverable tag is not a broken deployment."""
    messages = _tags_check(TAGS={"ManagedBy": "encryption-suite"})

    assert all(isinstance(m, CheckWarning) for m in messages)
    assert not any(isinstance(m, CheckError) for m in messages)


def test_tags_check_notices_defined_tags_alone():
    messages = _tags_check(DEFINED_TAGS={"Operations": {"CostCenter": "42"}})

    assert [m.id for m in messages] == ["encryption_suite.W051"]


def test_tags_check_silent_for_a_tagging_provisioner():
    cfg = _cfg_with_block(
        KEK_PROVISIONER_ADAPTER="encryption_suite.adapters.keks.provisioners_aws.AwsKekProvisioner",
        KEK_PROVISIONER_OPTIONS={"AWS_REGION": "us-east-1", "TAGS": {"Environment": "prod"}},
    )
    with override_settings(ENCRYPTION=cfg):
        registry.reset()
        assert tagging_warnings(registry.get_kek_provisioner(), "kms") == []


def test_the_provisioner_is_constructed_once_per_check_run(monkeypatch):
    """One construction, so one log line for one misconfiguration.

    The tagging warning used to live in its own check that built the provisioner
    itself. Django runs checks in registration order, so on a bad config the
    provisioner was built twice — and the config helpers log as they raise, so
    ``manage.py check`` reported the problem once and logged it twice.
    """
    builds = []
    original = registry.get_kek_provisioner

    def _counting(name=None):
        builds.append(name)
        return original(name)

    monkeypatch.setattr(registry, "get_kek_provisioner", _counting)
    registry.reset()
    check_kms_adapter_construction(app_configs=None)

    assert len(builds) == len(settings.ENCRYPTION["KMS_KEY_STORES"])


def test_a_failing_provisioner_logs_once_per_check_run(caplog):
    """And the failing case, which is the one that actually duplicated."""
    import logging

    cfg = _cfg_with_block(
        KEK_PROVISIONER_ADAPTER="encryption_suite.adapters.keks.provisioners_gcp.GcpKekProvisioner",
        KEK_PROVISIONER_OPTIONS={"TAGS": {"app": "x"}},  # missing every required option
    )
    with override_settings(ENCRYPTION=cfg):
        registry.reset()
        with caplog.at_level(logging.ERROR):
            errors = check_kms_adapter_construction(app_configs=None)

    assert "encryption_suite.E004" in {e.id for e in errors}
    provisioner_lines = [r for r in caplog.records if "GcpKekProvisioner requires" in r.getMessage()]
    assert len(provisioner_lines) == 1
