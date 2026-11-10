"""Tests for LOG_DECRYPTS success-log behavior.

Covers:
- Field decrypt success: logged at INFO using describe_decryption_scope format
  (silo + field, no row_identity — intentional PII-minimization choice).
- File decrypt success: logged at INFO using describe_decryption_scope format
    (silo + field, no row_identity).
- Both entries are suppressed when LOG_DECRYPTS is False (default).
"""

from __future__ import annotations

import io
import logging
from unittest.mock import patch

import pytest

from encryption_suite.registry import get_engine
from encryption_suite.storage import _NonClosingWriter

pytestmark = pytest.mark.django_db

ENGINE_LOGGER = "encryption_suite"


@pytest.fixture
def gk():
    from types import SimpleNamespace

    from encryption_suite.adapters.silos.context import override_current_silo

    silo = SimpleNamespace(pk="audit-tests")
    with override_current_silo(silo):
        yield silo


# ---------------------------------------------------------------------------
# Field decrypt success log
# ---------------------------------------------------------------------------


def test_field_decrypt_success_log_emitted_when_enabled(gk, caplog):
    engine = get_engine()
    plaintext = "sensitive value"
    ciphertext = engine.encrypt(plaintext, silo=gk)

    with patch("encryption_suite.engine.enc_settings.LOG_DECRYPTS", True):
        with caplog.at_level(logging.INFO, logger=ENGINE_LOGGER):
            engine.decrypt(ciphertext, silo=gk, field_name="myapp.Patient.ssn")

    info_records = [r for r in caplog.records if r.levelno == logging.INFO and r.name.startswith(ENGINE_LOGGER)]
    assert len(info_records) == 1
    msg = info_records[0].getMessage()
    assert msg.startswith("An encrypted field value was decrypted. ")
    assert "silo=" in msg
    assert 'field="myapp.Patient.ssn"' in msg


def test_field_decrypt_success_log_omits_row_identity(gk, caplog):
    """row_identity must not appear in success log — it may contain PII."""
    engine = get_engine()
    ciphertext = engine.encrypt("value", silo=gk)

    with patch("encryption_suite.engine.enc_settings.LOG_DECRYPTS", True):
        with caplog.at_level(logging.INFO, logger=ENGINE_LOGGER):
            engine.decrypt(
                ciphertext,
                silo=gk,
                field_name="myapp.Record.note",
                row_identity="pk=99,dob=1980-01-01",
            )

    msgs = [r.getMessage() for r in caplog.records if r.name.startswith(ENGINE_LOGGER) and r.levelno == logging.INFO]
    assert msgs, "Expected at least one INFO entry"
    assert not any("pk=99" in m or "1980-01-01" in m for m in msgs)


def test_field_decrypt_success_log_suppressed_by_default(gk, caplog):
    engine = get_engine()
    ciphertext = engine.encrypt("value", silo=gk)

    # LOG_DECRYPTS defaults to False in test settings
    with caplog.at_level(logging.INFO, logger=ENGINE_LOGGER):
        engine.decrypt(ciphertext, silo=gk, field_name="myapp.Patient.ssn")

    info_records = [
        r
        for r in caplog.records
        if r.levelno == logging.INFO and r.name.startswith(ENGINE_LOGGER) and "decrypted" in r.getMessage()
    ]
    assert info_records == []


# ---------------------------------------------------------------------------
# File decrypt success log
# ---------------------------------------------------------------------------


def test_file_decrypt_success_log_emitted_when_enabled(gk, caplog):
    engine = get_engine()
    ct_buf = io.BytesIO()
    engine.encrypt_file(io.BytesIO(b"file contents"), _NonClosingWriter(ct_buf))
    ct_buf.seek(0)

    with patch("encryption_suite.engine.enc_settings.LOG_DECRYPTS", True):
        with caplog.at_level(logging.INFO, logger=ENGINE_LOGGER):
            stream = engine.open_decrypting_stream(
                ct_buf,
                b"",
                row_identity="pk=7,status=active",
                field_name="myapp.Record.scan",
            )
            stream.read()

    info_records = [r for r in caplog.records if r.levelno == logging.INFO and r.name.startswith(ENGINE_LOGGER)]
    assert len(info_records) == 1
    msg = info_records[0].getMessage()
    assert msg.startswith("An encrypted file was decrypted. ")
    assert "silo=" in msg
    assert 'field="myapp.Record.scan"' in msg


def test_file_decrypt_success_log_omits_row_identity(gk, caplog):
    """row_identity must not appear in the file success log."""
    engine = get_engine()
    ct_buf = io.BytesIO()
    engine.encrypt_file(io.BytesIO(b"data"), _NonClosingWriter(ct_buf))
    ct_buf.seek(0)

    with patch("encryption_suite.engine.enc_settings.LOG_DECRYPTS", True):
        with caplog.at_level(logging.INFO, logger=ENGINE_LOGGER):
            stream = engine.open_decrypting_stream(
                ct_buf,
                b"",
                row_identity="pk=7,status=active",
                field_name="myapp.Record.scan",
            )
            stream.read()

    msgs = [r.getMessage() for r in caplog.records if r.name.startswith(ENGINE_LOGGER) and r.levelno == logging.INFO]
    assert msgs, "Expected at least one INFO entry"
    assert not any("pk=7" in m or "status=active" in m for m in msgs)


def test_file_decrypt_success_log_suppressed_by_default(gk, caplog):
    engine = get_engine()
    ct_buf = io.BytesIO()
    engine.encrypt_file(io.BytesIO(b"data"), _NonClosingWriter(ct_buf))
    ct_buf.seek(0)

    with caplog.at_level(logging.INFO, logger=ENGINE_LOGGER):
        stream = engine.open_decrypting_stream(ct_buf, b"")
        stream.read()

    info_records = [
        r
        for r in caplog.records
        if r.levelno == logging.INFO and r.name.startswith(ENGINE_LOGGER) and "decrypted" in r.getMessage()
    ]
    assert info_records == []
