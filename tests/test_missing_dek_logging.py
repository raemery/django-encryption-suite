"""Regression tests for missing-DEK log placement.

A missing DEK is logged ERROR only where it is *terminal* — a read, or an
encrypt with KEY_AUTO_PROVISION off. On the auto-provision encrypt path a
missing DEK is an expected first-use signal (the engine creates the DEK), so it
must NOT be logged as an error, and the provision lock's re-check must not
double-log it. See engine `_decrypt_to_aead` / `_lazy_provision`.
"""

from __future__ import annotations

import io
import logging
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from encryption_suite.adapters.silos.context import override_current_silo
from encryption_suite.exceptions import MissingDekError
from encryption_suite.registry import get_engine
from encryption_suite.storage import _NonClosingWriter

pytestmark = pytest.mark.django_db

ENGINE_LOGGER = "encryption_suite"


def _missing_dek_errors(caplog):
    return [
        r.getMessage()
        for r in caplog.records
        if r.levelno == logging.ERROR
        and r.name.startswith(ENGINE_LOGGER)
        and "error_code=missing_dek" in r.getMessage()
    ]


def test_autoprovision_first_field_encrypt_logs_no_missing_dek_error(caplog):
    engine = get_engine()
    gk = SimpleNamespace(pk="md-field-first-use")
    with override_current_silo(gk):
        with caplog.at_level(logging.INFO, logger=ENGINE_LOGGER):
            engine.encrypt("secret", silo=gk)

    # No ERROR for the expected first-use miss …
    assert _missing_dek_errors(caplog) == []
    # … and the creation line is emitted exactly once (no lock re-check
    # duplicate), naming the act that caused it.
    (created,) = _created_lines(caplog)
    assert created.startswith("A data key was created on the silo's first encryption.")
    assert 'event=created reason=first_encryption silo="default:group-md-field-first-use" purpose=field kek=' in created


def _created_lines(caplog):
    return [
        r.getMessage()
        for r in caplog.records
        if r.levelno == logging.INFO
        and r.name.startswith(ENGINE_LOGGER)
        and "event=created" in r.getMessage()
        and "A data key was created" in r.getMessage()
    ]


def test_a_silo_created_key_says_so_and_names_its_silo_purpose_and_kek(caplog):
    """The signal's key is identified like every other data key line, never by the silo row's pk."""
    engine = get_engine()
    gk = SimpleNamespace(pk="md-silo-created")
    with caplog.at_level(logging.INFO, logger=ENGINE_LOGGER):
        engine.generate_and_store_keyset(gk)

    (created,) = _created_lines(caplog)
    assert created.startswith("A data key was created for a newly created silo.")
    assert 'reason=silo_created silo="default:group-md-silo-created" purpose=field kek="local-test-kek"' in created
    assert "pk=" not in created


def test_a_first_file_encryption_logs_a_file_key_creation(caplog):
    engine = get_engine()
    gk = SimpleNamespace(pk="md-file-created")
    with override_current_silo(gk), caplog.at_level(logging.INFO, logger=ENGINE_LOGGER):
        engine.encrypt_file(io.BytesIO(b"data"), _NonClosingWriter(io.BytesIO()))

    (created,) = _created_lines(caplog)
    assert "reason=first_encryption" in created and "purpose=file" in created


def test_a_key_created_by_a_command_carries_no_reason_and_names_the_operator(caplog):
    engine = get_engine()
    gk = SimpleNamespace(pk="md-command-created")
    with caplog.at_level(logging.INFO, logger=ENGINE_LOGGER):
        engine.generate_and_store_keyset(gk, trigger="automated", reason="", os_login_user="op (uid 1000)")

    (created,) = _created_lines(caplog)
    assert created.startswith("A data key was created for this silo.")
    assert "reason=none" in created and 'os_user="op (uid 1000)"' in created


def test_autoprovision_first_file_encrypt_logs_no_missing_dek_error(caplog):
    engine = get_engine()
    gk = SimpleNamespace(pk="md-file-first-use")
    with override_current_silo(gk):
        with caplog.at_level(logging.INFO, logger=ENGINE_LOGGER):
            engine.encrypt_file(io.BytesIO(b"data"), _NonClosingWriter(io.BytesIO()))

    assert _missing_dek_errors(caplog) == []


def test_encrypt_without_autoprovision_logs_single_missing_dek_error(caplog):
    engine = get_engine()
    gk = SimpleNamespace(pk="md-no-autoprovision")
    with override_current_silo(gk):
        with patch("encryption_suite.engine.enc_settings.KEY_AUTO_PROVISION", False):
            with caplog.at_level(logging.ERROR, logger=ENGINE_LOGGER):
                with pytest.raises(MissingDekError):
                    engine.encrypt("secret", silo=gk)

    # Terminal miss: logged exactly once (not zero, not the old double).
    assert len(_missing_dek_errors(caplog)) == 1


def test_decrypt_missing_dek_logs_single_error(caplog):
    """Read path is always terminal — a missing DEK logs exactly one ERROR."""
    engine = get_engine()
    gk = SimpleNamespace(pk="md-read-miss")
    # Encrypt under a provisioned silo to get a well-formed ciphertext …
    with override_current_silo(gk):
        ciphertext = engine.encrypt("secret", silo=gk)

    # … then read it back for a silo that has no DEK row.
    other = SimpleNamespace(pk="md-read-miss-other")
    with override_current_silo(other):
        with caplog.at_level(logging.ERROR, logger=ENGINE_LOGGER):
            with pytest.raises(MissingDekError):
                engine.decrypt(ciphertext, silo=other)

    assert len(_missing_dek_errors(caplog)) == 1
