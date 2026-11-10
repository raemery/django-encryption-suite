"""Tests for HTTP error body enrichment on the urllib-based call paths.

A bare ``urllib.error.HTTPError`` stringifies to just ``HTTP Error 403:
Forbidden``; ``urlopen_with_detail`` folds the response body — where providers
put the actionable detail (which IAM permission, which resource) — into the
exception message so the package's ``%s`` logs and the admin test console
surface it.
"""

from __future__ import annotations

import email.message
import io
import urllib.error
import urllib.request
from unittest.mock import patch

import pytest

from encryption_suite.adapters._http import _MAX_HTTP_ERROR_DETAIL, _USER_AGENT, urlopen_with_detail


def _req(url: str = "https://kms.example.com/x") -> urllib.request.Request:
    return urllib.request.Request(url)


def _http_error(body: bytes, code: int = 403, msg: str = "Forbidden") -> urllib.error.HTTPError:
    return urllib.error.HTTPError("https://kms.example.com/x", code, msg, email.message.Message(), io.BytesIO(body))


def test_success_passes_through():
    sentinel = object()
    with patch("urllib.request.urlopen", return_value=sentinel):
        assert urlopen_with_detail(_req(), timeout=1) is sentinel


def test_enriches_message_with_response_body():
    body = b'{"error": {"message": "Permission \'cloudkms.cryptoKeyVersions.useToDecrypt\' denied"}}'
    with patch("urllib.request.urlopen", side_effect=_http_error(body)):
        with pytest.raises(urllib.error.HTTPError) as ei:
            urlopen_with_detail(_req(), timeout=1)
    text = str(ei.value)
    assert "403" in text
    assert "useToDecrypt" in text


def test_status_code_preserved_for_branching():
    with patch("urllib.request.urlopen", side_effect=_http_error(b"nope", code=404)):
        with pytest.raises(urllib.error.HTTPError) as ei:
            urlopen_with_detail(_req(), timeout=1)
    assert ei.value.code == 404


def test_empty_body_leaves_message_unchanged():
    with patch("urllib.request.urlopen", side_effect=_http_error(b"")):
        with pytest.raises(urllib.error.HTTPError) as ei:
            urlopen_with_detail(_req(), timeout=1)
    assert str(ei.value) == "HTTP Error 403: Forbidden"


def test_oversized_body_is_truncated():
    body = b"x" * (_MAX_HTTP_ERROR_DETAIL + 500)
    with patch("urllib.request.urlopen", side_effect=_http_error(body)):
        with pytest.raises(urllib.error.HTTPError) as ei:
            urlopen_with_detail(_req(), timeout=1)
    assert "…(truncated)" in str(ei.value)
    # message = "Forbidden: " + capped body + " …(truncated)"
    assert len(ei.value.msg) <= _MAX_HTTP_ERROR_DETAIL + len("Forbidden: ") + len(" …(truncated)")


# ---------------------------------------------------------------------------
# User-Agent injection — WAFs (e.g. Cloudflare on IBM Key Protect) 403 the
# standard library's default ``Python-urllib/x`` agent, so the package sets its own.
# ---------------------------------------------------------------------------


def test_injects_user_agent_when_absent():
    seen = {}

    def _capture(req, timeout, context=None):
        seen["ua"] = req.get_header("User-agent")
        return object()

    with patch("urllib.request.urlopen", side_effect=_capture):
        urlopen_with_detail(_req(), timeout=1)

    assert seen["ua"] == _USER_AGENT
    assert seen["ua"].startswith("django-encryption-suite")


def test_preserves_caller_user_agent():
    seen = {}

    def _capture(req, timeout, context=None):
        seen["ua"] = req.get_header("User-agent")
        return object()

    req = _req()
    req.add_header("User-Agent", "custom/9.9")
    with patch("urllib.request.urlopen", side_effect=_capture):
        urlopen_with_detail(req, timeout=1)

    assert seen["ua"] == "custom/9.9"
