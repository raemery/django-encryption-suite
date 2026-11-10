"""Tests for the encryption_suite_rotate_hashicorp_approle management command."""

from __future__ import annotations

import json
from io import StringIO
from unittest.mock import patch

import pytest
from django.core.management import CommandError, call_command


def _fake_resp(payload: dict):
    class _CM:
        def __enter__(self_inner):
            return self_inner

        def __exit__(self_inner, *exc):
            return False

        def read(self_inner):
            return json.dumps(payload).encode()

    return _CM()


def _run(role: str = "encryption_suite", **opts):
    out = StringIO()
    call_command(
        "encryption_suite_rotate_hashicorp_approle",
        f"--role={role}",
        stdout=out,
        **opts,
    )
    return out.getvalue()


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.setenv("VAULT_ADDR", "https://v.example.com:8200")
    monkeypatch.setenv("VAULT_TOKEN", "hvs.admin")
    monkeypatch.delenv("VAULT_NAMESPACE", raising=False)


def test_requires_vault_addr(monkeypatch):
    monkeypatch.delenv("VAULT_ADDR", raising=False)
    with pytest.raises(CommandError, match="VAULT_ADDR"):
        _run()


def test_requires_admin_token(monkeypatch):
    monkeypatch.delenv("VAULT_TOKEN", raising=False)
    with pytest.raises(CommandError, match="VAULT_TOKEN"):
        _run()


def test_emits_secret_id_json():
    captured = {}

    def _fake_urlopen(req, timeout):
        captured["url"] = req.full_url
        captured["headers"] = dict(req.headers)
        captured["method"] = req.get_method()
        return _fake_resp(
            {
                "data": {
                    "secret_id": "sid-xyz",
                    "secret_id_accessor": "acc-1",
                    "secret_id_ttl": 0,
                    "secret_id_num_uses": 0,
                }
            }
        )

    with patch("urllib.request.urlopen", side_effect=_fake_urlopen):
        out = _run()

    result = json.loads(out)
    assert result["secret_id"] == "sid-xyz"
    assert result["secret_id_accessor"] == "acc-1"
    assert captured["url"] == "https://v.example.com:8200/v1/auth/approle/role/encryption_suite/secret-id"
    assert captured["method"] == "POST"
    assert captured["headers"]["X-vault-token"] == "hvs.admin"


def test_passes_namespace_header(monkeypatch):
    monkeypatch.setenv("VAULT_NAMESPACE", "admin")
    captured = {}

    def _fake_urlopen(req, timeout):
        captured["headers"] = dict(req.headers)
        return _fake_resp({"data": {"secret_id": "s"}})

    with patch("urllib.request.urlopen", side_effect=_fake_urlopen):
        _run()

    assert captured["headers"]["X-vault-namespace"] == "admin"


def test_wrap_flag_sets_wrap_ttl_header_and_returns_wrap_info():
    captured = {}

    def _fake_urlopen(req, timeout):
        captured["headers"] = dict(req.headers)
        return _fake_resp(
            {
                "wrap_info": {
                    "token": "hvs.wrap",
                    "ttl": 300,
                    "accessor": "wrap-acc",
                    "creation_path": "auth/approle/role/encryption_suite/secret-id",
                }
            }
        )

    with patch("urllib.request.urlopen", side_effect=_fake_urlopen):
        out = _run(wrap=True, wrap_ttl="5m")

    assert captured["headers"]["X-vault-wrap-ttl"] == "5m"
    result = json.loads(out)
    assert result["wrapping_token"] == "hvs.wrap"
    assert result["wrapping_token_ttl"] == 300


def test_custom_approle_mount():
    captured = {}

    def _fake_urlopen(req, timeout):
        captured["url"] = req.full_url
        return _fake_resp({"data": {"secret_id": "s"}})

    with patch("urllib.request.urlopen", side_effect=_fake_urlopen):
        _run(approle_mount="approle-prod")

    assert "/v1/auth/approle-prod/role/" in captured["url"]


def test_vault_error_surfaces_as_command_error():
    import urllib.error

    def _fake_urlopen(req, timeout):
        raise urllib.error.HTTPError(url=req.full_url, code=403, msg="Forbidden", hdrs=None, fp=None)

    with patch("urllib.request.urlopen", side_effect=_fake_urlopen):
        with pytest.raises(CommandError, match="403"):
            _run()


def test_the_run_closes_on_a_line_naming_the_accessor_and_never_the_secret(caplog):
    """No ledger row and a secret printed to stdout: the two lines are the record.

    The accessor identifies the secret-id Vault now holds without being usable to
    authenticate as it.
    """

    def _fake_urlopen(req, timeout):
        return _fake_resp({"data": {"secret_id": "sid-xyz", "secret_id_accessor": "acc-1"}})

    with caplog.at_level("INFO", logger="encryption_suite"):
        with patch("urllib.request.urlopen", side_effect=_fake_urlopen):
            _run()

    (line,) = [r.getMessage() for r in caplog.records if "command finished" in r.getMessage()]
    assert 'role="encryption_suite"' in line
    assert "wrapped=False issued=1" in line
    assert 'accessor="acc-1"' in line
    assert "sid-xyz" not in caplog.text
    assert "hvs.admin" not in caplog.text


def test_a_run_vault_refused_closes_with_nothing_issued(monkeypatch, caplog):
    monkeypatch.delenv("VAULT_TOKEN", raising=False)

    with caplog.at_level("INFO", logger="encryption_suite"):
        with pytest.raises(CommandError):
            _run()

    (line,) = [r.getMessage() for r in caplog.records if "command finished" in r.getMessage()]
    assert "issued=0" in line
