"""Unit tests for OIDC token sources.

Focus: FlySocketTokenSource, whose response handling broke in the field —
Fly returns the signed JWT as the raw response body, not wrapped as JSON.
"""

from __future__ import annotations

import http.client

import pytest

from encryption_suite.adapters.credentials.oidc_sources import (
    FlySocketTokenSource,
    build_oidc_source,
)

_JWT = "eyJhbGciOiJSUzI1NiJ9.eyJhdWQiOiJ2YXVsdCJ9.c2lnbmF0dXJl"


class _FakeResp:
    def __init__(self, status: int, body: str) -> None:
        self.status = status
        self._body = body.encode("utf-8")

    def read(self) -> bytes:
        return self._body


def _patch_conn(monkeypatch, resp: _FakeResp, captured: dict | None = None):
    """Patch HTTPConnection so no real Unix socket is opened.

    FlySocketTokenSource's inner _UnixHTTP overrides only connect(); request(),
    getresponse(), and close() are inherited, so patching the base class here
    intercepts the whole exchange without touching the socket.
    """

    def fake_request(self, method, url, body=None, headers=None):
        if captured is not None:
            captured.update(method=method, url=url, body=body, headers=headers)

    monkeypatch.setattr(http.client.HTTPConnection, "request", fake_request)
    monkeypatch.setattr(http.client.HTTPConnection, "getresponse", lambda self: resp)
    monkeypatch.setattr(http.client.HTTPConnection, "close", lambda self: None)


def test_fly_returns_raw_jwt_body(monkeypatch):
    """Fly's actual behavior: the body IS the JWT (not {"token": ...})."""
    _patch_conn(monkeypatch, _FakeResp(200, _JWT))
    assert FlySocketTokenSource().get_token("vault") == _JWT


def test_fly_strips_whitespace(monkeypatch):
    _patch_conn(monkeypatch, _FakeResp(200, f"  {_JWT}\n"))
    assert FlySocketTokenSource().get_token("vault") == _JWT


def test_fly_accepts_json_wrapped_token(monkeypatch):
    """Defensive: tolerate a {"token": "..."} response shape too."""
    _patch_conn(monkeypatch, _FakeResp(200, f'{{"token": "{_JWT}"}}'))
    assert FlySocketTokenSource().get_token("vault") == _JWT


def test_fly_non_200_raises(monkeypatch):
    _patch_conn(monkeypatch, _FakeResp(403, "forbidden"))
    with pytest.raises(RuntimeError, match="HTTP 403"):
        FlySocketTokenSource().get_token("vault")


def test_fly_posts_requested_audience(monkeypatch):
    captured: dict = {}
    _patch_conn(monkeypatch, _FakeResp(200, _JWT), captured)
    FlySocketTokenSource().get_token("my-aud")
    assert captured["method"] == "POST"
    assert captured["url"] == "/v1/tokens/oidc"
    assert b"my-aud" in captured["body"]


def test_build_oidc_source_fly_needs_no_options():
    src = build_oidc_source("fly", {})
    assert isinstance(src, FlySocketTokenSource)


def test_fly_socket_that_never_answers_times_out(monkeypatch):
    """A hung socket raises after the timeout instead of blocking the refresh lock forever."""
    import socket

    seen = {}

    class _HungSocket:
        def __init__(self, family, kind):
            pass

        def settimeout(self, value):
            seen["timeout"] = value

        def connect(self, path):
            seen["path"] = path
            raise TimeoutError("timed out")

        def close(self):
            pass

    monkeypatch.setattr(socket, "AF_UNIX", getattr(socket, "AF_UNIX", 1), raising=False)
    monkeypatch.setattr(socket, "socket", _HungSocket)

    with pytest.raises(TimeoutError):
        FlySocketTokenSource(socket_path="/tmp/fly.sock", timeout=2.5).get_token("vault")

    assert seen == {"timeout": 2.5, "path": "/tmp/fly.sock"}


def test_fly_socket_timeout_defaults_to_the_kms_request_timeout():
    from encryption_suite.adapters._http import DEFAULT_KMS_REQUEST_TIMEOUT

    assert FlySocketTokenSource()._timeout == DEFAULT_KMS_REQUEST_TIMEOUT
