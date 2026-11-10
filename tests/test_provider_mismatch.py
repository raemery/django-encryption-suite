"""Tests for routing by the recorded KMS name, and the provider-error log summary.

Every unwrap routes through the KMS the key encryption key row names. The guard
fires when no ``KMS_KEY_STORES`` block carries that name — the classic symptom of
a ``DATABASE_URL`` pointing at a database from a different deployment, or a
block renamed or removed while rows still use it. It covers field and file
decrypt paths alike. ``_summarize_provider_error`` keeps SDK error bodies from
flooding the log.
"""

from __future__ import annotations

import email.message
import io
import logging
import urllib.error
from types import SimpleNamespace

import pytest

from encryption_suite.engine import (
    _MAX_PROVIDER_ERROR_DETAIL,
    EncryptionEngine,
    _summarize_provider_error,
)
from encryption_suite.exceptions import KmsProviderMismatchError
from encryption_suite.registry import get_engine
from tests.factories import make_kek

ENGINE_LOGGER = "encryption_suite"


@pytest.fixture
def engine():
    eng = get_engine()
    EncryptionEngine.invalidate_cache()
    yield eng
    EncryptionEngine.invalidate_cache()


# ---------------------------------------------------------------------------
# kms_adapter_for_kek — unit (no DB)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("stored", ["gcp", "azure", "aws", "", "Local"])
def test_an_unconfigured_name_raises(engine, stored):
    kek = SimpleNamespace(key_store=stored, kek_resource_name="projects/p/keys/k")
    with pytest.raises(KmsProviderMismatchError):
        engine.kms_adapter_for_kek(kek, "gk-1")


def test_a_configured_name_routes_to_its_own_adapter(engine, configured_kms):
    from encryption_suite.registry import get_kms_adapter

    configured_kms("other", silo_kms=False)
    for name in ("local", "other"):
        kek = SimpleNamespace(key_store=name, kek_resource_name="r")
        adapter = engine.kms_adapter_for_kek(kek, "gk-1")
        assert adapter is get_kms_adapter(name)
        assert adapter.kms_name == name


@pytest.mark.parametrize("debug", [True, False])
def test_an_env_store_is_reachable_whatever_debug_says(engine, settings, debug):
    """A key on an env store is reachable whatever DEBUG says: there is no ephemeral stand-in."""
    settings.DEBUG = debug
    kek = SimpleNamespace(key_store="login", kek_resource_name="shared")
    assert engine.kms_adapter_for_kek(kek, "gk-1").kms_name == "login"


def test_an_unconfigured_name_logs_actionable_detail(engine, caplog):
    kek = SimpleNamespace(key_store="gcp", kek_resource_name="projects/p/keys/k")
    with caplog.at_level(logging.ERROR, logger=ENGINE_LOGGER):
        with pytest.raises(KmsProviderMismatchError):
            engine.kms_adapter_for_kek(kek, "gk-1")
    text = caplog.text
    assert "error_code=kms_provider_mismatch" in text
    assert 'stored_key_store="gcp"' in text
    assert "projects/p/keys/k" in text
    assert "DATABASE_URL" in text


# ---------------------------------------------------------------------------
# Integration — the guard fires on both the field and the file decrypt path
# ---------------------------------------------------------------------------


def test_field_decrypt_path_guards_mismatch(engine, silo_context):
    from encryption_suite.models import DataEncryptionKey

    engine.encrypt("a field secret", silo=silo_context)
    row = DataEncryptionKey.objects.get(purpose=DataEncryptionKey.PURPOSE_FIELD)
    # Simulate a database from a different deployment: the row points at a key
    # encryption key on a KMS this configuration has no block for.
    row.kek = make_kek("projects/p/keys/k", "gcp")
    row.save(update_fields=["kek"])
    EncryptionEngine.invalidate_cache()

    with pytest.raises(KmsProviderMismatchError):
        engine._decrypt_to_aead(row.silo_ref)


def test_file_decrypt_path_guards_mismatch(engine, silo_context):
    from encryption_suite.models import DataEncryptionKey

    engine.generate_and_store_file_keyset(silo_context)
    row = DataEncryptionKey.objects.get(purpose=DataEncryptionKey.PURPOSE_FILE)
    row.kek = make_kek("projects/p/keys/k", "gcp")
    row.save(update_fields=["kek"])
    EncryptionEngine.invalidate_cache()

    with pytest.raises(KmsProviderMismatchError):
        engine._decrypt_to_streaming_aead(row.silo_ref)


# ---------------------------------------------------------------------------
# _summarize_provider_error — provider-agnostic, body-truncating log helper
# ---------------------------------------------------------------------------


class _FakeResponse:
    """Duck-types the requests-style ``exc.response`` (Azure / IBM / botocore)."""

    def __init__(self, status_code, reason, text):
        self.status_code = status_code
        self.reason = reason
        self.text = text


def test_summary_uses_response_status_and_truncates_body():
    body = "<html><body>" + "x" * 500 + "</body></html>"
    exc = RuntimeError("opaque")
    exc.response = _FakeResponse(404, "Not Found", body)

    out = _summarize_provider_error(exc)
    assert out.startswith("HTTP 404 Not Found:")
    assert "…(truncated)" in out
    assert len(out) <= len("HTTP 404 Not Found: ") + _MAX_PROVIDER_ERROR_DETAIL + len(" …(truncated)")


def test_summary_handles_urllib_httperror():
    exc = urllib.error.HTTPError(
        "https://kms.example.com/x", 403, "Forbidden", email.message.Message(), io.BytesIO(b"")
    )
    out = _summarize_provider_error(exc)
    assert "403" in out


class _AzureResponse:
    """Duck-types Azure's ``HttpResponse``: ``text`` is a *method*, not a str."""

    def __init__(self, status_code, reason, text):
        self.status_code = status_code
        self.reason = reason
        self._text = text

    def text(self, encoding=None):
        return self._text


def test_summary_handles_callable_text_method():
    # Regression: Azure's response.text is a method; the summarizer must call it
    # rather than treating the bound method as the body (which crashed with
    # "'function' object has no attribute 'split'").
    body = "<html>" + "x" * 400 + "</html>"
    exc = RuntimeError("Operation returned an invalid status 'Not Found'")
    exc.response = _AzureResponse(404, "Not Found", body)

    out = _summarize_provider_error(exc)
    assert out.startswith("HTTP 404 Not Found:")
    assert "…(truncated)" in out


def test_summary_ignores_text_method_that_raises():
    exc = RuntimeError("boom")

    class _Resp:
        status_code = 404
        reason = "Not Found"

        def text(self):
            raise ValueError("decode failed")

    exc.response = _Resp()
    out = _summarize_provider_error(exc)
    # Falls back to str(exc) for the body; must not raise.
    assert out.startswith("HTTP 404 Not Found:")
    assert "boom" in out


def test_summary_falls_back_to_plain_str():
    assert _summarize_provider_error(RuntimeError("something short")) == "something short"


def test_summary_collapses_whitespace():
    assert _summarize_provider_error(RuntimeError("line1\n   line2\tline3")) == "line1 line2 line3"


# ---------------------------------------------------------------------------
# kek_resource_mismatch_hint — same-provider, different-coordinates hint
# ---------------------------------------------------------------------------


def _gcp_adapter(location="us-east4"):
    from encryption_suite.adapters.key_stores.gcp import GcpKmsAdapter

    # The hint method reads only self.options, so bypass the SDK-touching ctor.
    adapter = object.__new__(GcpKmsAdapter)
    adapter.options = {"GCP_PROJECT_ID": "proj", "GCP_KMS_LOCATION": location, "GCP_KMS_KEY_RING": "ring"}
    return adapter


def _aws_adapter(region="us-east-1"):
    from encryption_suite.adapters.key_stores.aws import AwsKmsAdapter

    adapter = object.__new__(AwsKmsAdapter)
    adapter.options = {"AWS_REGION": region}
    return adapter


def test_gcp_hint_flags_different_location():
    adapter = _gcp_adapter(location="us-east4")
    stored = "projects/proj/locations/global/keyRings/ring/cryptoKeys/k"
    hint = adapter.kek_resource_mismatch_hint(stored)
    assert hint is not None
    assert "locations/global" in hint
    assert "us-east4" in hint


def test_gcp_hint_flags_different_project():
    adapter = _gcp_adapter()
    stored = "projects/other/locations/us-east4/keyRings/ring/cryptoKeys/k"
    assert adapter.kek_resource_mismatch_hint(stored) is not None


def test_gcp_hint_silent_for_same_ring_rotated_key():
    adapter = _gcp_adapter()
    stored = "projects/proj/locations/us-east4/keyRings/ring/cryptoKeys/rotated-key-2"
    assert adapter.kek_resource_mismatch_hint(stored) is None


def test_gcp_hint_silent_for_bare_key_name():
    # Encrypt-side logs pass the key name, not a full resource path.
    assert _gcp_adapter().kek_resource_mismatch_hint("encryption_suite-team-1") is None


def test_aws_hint_flags_different_region():
    adapter = _aws_adapter(region="us-east-1")
    stored = "arn:aws:kms:eu-west-1:123456789012:key/abc"
    hint = adapter.kek_resource_mismatch_hint(stored)
    assert hint is not None
    assert "eu-west-1" in hint and "us-east-1" in hint


def test_aws_hint_silent_for_same_region():
    adapter = _aws_adapter(region="us-east-1")
    stored = "arn:aws:kms:us-east-1:123456789012:key/abc"
    assert adapter.kek_resource_mismatch_hint(stored) is None


def test_aws_hint_silent_for_non_arn():
    assert _aws_adapter().kek_resource_mismatch_hint("alias/my-key") is None


def test_default_adapter_emits_no_hint(engine):
    # The suite's adapter has no resource coordinates, so never hints.
    assert engine.silo_kms_adapter.kek_resource_mismatch_hint("anything") is None


def test_engine_appends_hint_to_operational_failure_log(engine, silo_context, caplog):
    from unittest.mock import patch

    from encryption_suite.exceptions import KekUnavailableError
    from encryption_suite.models import DataEncryptionKey

    engine.encrypt("v", silo=silo_context)
    row = DataEncryptionKey.objects.get(purpose=DataEncryptionKey.PURPOSE_FIELD)
    EncryptionEngine.invalidate_cache()

    hint = "stored KEK is in region 'eu-west-1'"
    with patch.object(engine.silo_kms_adapter, "kek_resource_mismatch_hint", return_value=hint):
        with patch.object(engine.silo_kms_adapter, "decrypt_key", side_effect=RuntimeError("AccessDenied")):
            with caplog.at_level(logging.ERROR, logger=ENGINE_LOGGER):
                with pytest.raises(KekUnavailableError):
                    engine._decrypt_to_aead(row.silo_ref)

    assert f'possible_cause="{hint}"' in caplog.text
