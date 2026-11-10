"""Drift guard + behavior tests for the stable error-code slugs.

Every concrete ``EncryptionError`` subclass must carry a unique, non-empty
``code`` slug, and the full set is frozen here so adding/renaming/removing a code
is a deliberate act that fails CI until this map (and the docs) are updated.
Slugs are append-only from the first release: never rename or reuse a shipped
slug, because a consumer may have branched on it. Nothing has shipped yet, so a
slug may still be corrected here — and this map is what makes that a deliberate
act rather than a drift.
"""

from __future__ import annotations

import pytest

from encryption_suite._internal import operator_error_text
from encryption_suite.exceptions import (
    EncryptionError,
    KekUnavailableError,
    log_and_raise_configuration_error,
)

# Frozen source of truth: class name -> stable slug. Append-only.
EXPECTED_CODES = {
    "EncryptionConfigurationError": "configuration_error",
    "MissingDekError": "missing_dek",
    "KekNotProvisionedError": "kek_not_provisioned",
    "KekPendingDeletionError": "kek_pending_deletion",
    "KekDeleteError": "kek_delete_failed",
    "SiloEnumerationError": "silo_enumeration_unavailable",
    "KekEnumerationError": "kek_enumeration_unavailable",
    "KekDeletionRecordError": "kek_deletion_record_failed",
    "KeyIdentityImmutableError": "key_identity_immutable",
    "KmsProviderMismatchError": "kms_provider_mismatch",
    "CryptoBackendMismatchError": "crypto_backend_mismatch",
    "FieldAlreadyEncryptedError": "field_already_encrypted",
    "EncryptedFieldEncryptionError": "field_encryption_failed",
    "EncryptedFieldDecryptionError": "field_decryption_failed",
    "EncryptedFileEncryptionError": "file_encryption_failed",
    "EncryptedFileDecryptionError": "file_decryption_failed",
    "EncryptedFileStorageError": "file_storage_error",
    "KekUnavailableError": "kek_unavailable",
    "DekDeletionScheduledError": "dek_deletion_scheduled",
    "DekDeletedError": "dek_deleted",
    "DekReencryptionInProgressError": "dek_reencryption_in_progress",
}


def _all_subclasses(cls):
    for sub in cls.__subclasses__():
        # A failed lookup's form-visible copy repeats its parent's code by design
        # (see as_lookup_error); it is not a class of its own to register.
        if getattr(sub, "_lookup_variant", False):
            continue
        # Only the package's own classes carry registered codes. Tests define
        # throwaway subclasses that stay in __subclasses__() until the garbage
        # collector frees them, which would make these checks order-dependent.
        if sub.__module__.split(".")[0] != "encryption_suite":
            continue
        yield sub
        yield from _all_subclasses(sub)


def test_every_subclass_has_a_nonempty_code():
    missing = [c.__name__ for c in _all_subclasses(EncryptionError) if not getattr(c, "code", "")]
    assert not missing, f"EncryptionError subclasses without a code slug: {missing}"


def test_codes_are_unique():
    codes = [c.code for c in _all_subclasses(EncryptionError) if c.code]
    dupes = {c for c in codes if codes.count(c) > 1}
    assert not dupes, f"Duplicate error-code slugs: {dupes}"


def test_code_map_matches_frozen_set():
    # Append-only guard: the live classes must match EXPECTED_CODES exactly.
    # A new/renamed/removed code fails here until this map (and docs) are updated.
    live = {c.__name__: c.code for c in _all_subclasses(EncryptionError) if c.code}
    assert live == EXPECTED_CODES


def test_base_class_has_no_code():
    assert EncryptionError.code == ""


def test_operator_error_text_prepends_code():
    text = operator_error_text(KekUnavailableError("unavailable"))
    assert text.startswith("[kek_unavailable] ")


def test_operator_error_text_uses_code_with_config_detail():
    import logging

    logger = logging.getLogger("encryption_suite.tests")
    with pytest.raises(EncryptionError) as ei:
        log_and_raise_configuration_error(logger, "operator detail here")
    text = operator_error_text(ei.value)
    assert text == "[configuration_error] operator detail here"


def test_operator_error_text_plain_exception_has_no_prefix():
    assert operator_error_text(ValueError("boom")) == "boom"


def test_operator_error_text_names_an_exception_with_no_text():
    from cryptography.exceptions import InvalidTag

    assert operator_error_text(InvalidTag()) == "InvalidTag"


def test_config_funnel_log_carries_slug(caplog):
    import logging

    logger = logging.getLogger("encryption_suite.tests")
    with caplog.at_level(logging.ERROR, logger="encryption_suite.tests"):
        with pytest.raises(EncryptionError):
            log_and_raise_configuration_error(logger, "bad option XYZ")
    assert 'error_code=configuration_error detail="bad option XYZ"' in caplog.text
