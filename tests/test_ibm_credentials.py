"""Unit tests for IBM Cloud credential strategies (api_key, iam_assume,
container, vpc_instance)."""

from __future__ import annotations

import json
import sys
import types
import urllib.parse
from unittest.mock import patch

import pytest

from encryption_suite.adapters.credentials.ibm import (
    IbmApiKeyStrategy,
    IbmContainerStrategy,
    IbmIamAssumeStrategy,
    IbmVpcInstanceStrategy,
)
from encryption_suite.exceptions import EncryptionConfigurationError

_IAM_URL = "https://iam.cloud.ibm.com/identity/token"


def _fake_resp(payload: dict):
    """Return a context manager mimicking urlopen()'s return value."""

    class _CM:
        def __enter__(self_inner):
            return self_inner

        def __exit__(self_inner, *exc):
            return False

        def read(self_inner):
            return json.dumps(payload).encode()

    return _CM()


def _form(req) -> dict:
    """Decode a urlencoded request body into a flat dict."""
    return {k: v[0] for k, v in urllib.parse.parse_qs(req.data.decode()).items()}


# ---------------------------------------------------------------------------
# api_key
# ---------------------------------------------------------------------------


def test_api_key_exchanges_for_bearer_token():
    captured = {}

    def _fake_urlopen(req, timeout, context):
        captured["url"] = req.full_url
        captured["body"] = _form(req)
        return _fake_resp({"access_token": "tok-1", "expires_in": 3600})

    s = IbmApiKeyStrategy({"IBM_API_KEY": "my-key"})
    with patch("urllib.request.urlopen", side_effect=_fake_urlopen):
        assert s.get_credentials() == "tok-1"

    assert captured["url"] == _IAM_URL
    assert captured["body"]["grant_type"] == "urn:ibm:params:oauth:grant-type:apikey"
    assert captured["body"]["apikey"] == "my-key"


def test_api_key_missing_raises():
    s = IbmApiKeyStrategy({})
    with patch.dict("os.environ", {}, clear=True), pytest.raises(EncryptionConfigurationError) as excinfo:
        s.get_credentials()
    assert "IBM_API_KEY" in excinfo.value.detail


# ---------------------------------------------------------------------------
# iam_assume — two-step exchange
# ---------------------------------------------------------------------------


def _assume_urlopen(calls):
    """Fake urlopen distinguishing the apikey grant from the assume grant."""

    def _fake(req, timeout, context):
        body = _form(req)
        calls.append(body)
        if body["grant_type"].endswith("apikey"):
            return _fake_resp({"access_token": "initial-tok", "expires_in": 3600})
        return _fake_resp({"access_token": "profile-tok", "expires_in": 3600})

    return _fake


def test_iam_assume_two_step_exchange_with_profile_id():
    calls: list[dict] = []
    s = IbmIamAssumeStrategy({"IBM_API_KEY": "my-key", "IBM_TRUSTED_PROFILE_ID": "Profile-abc"})
    with patch("urllib.request.urlopen", side_effect=_assume_urlopen(calls)):
        token = s.get_credentials()

    assert token == "profile-tok"
    assert len(calls) == 2
    # Step 1: api key grant.
    assert calls[0]["grant_type"] == "urn:ibm:params:oauth:grant-type:apikey"
    assert calls[0]["apikey"] == "my-key"
    # Step 2: assume grant carries the initial token and the profile selector.
    assert calls[1]["grant_type"] == "urn:ibm:params:oauth:grant-type:assume"
    assert calls[1]["access_token"] == "initial-tok"
    assert calls[1]["profile_id"] == "Profile-abc"


@pytest.mark.parametrize(
    ("option", "param", "value"),
    [
        ("IBM_TRUSTED_PROFILE_CRN", "profile_crn", "crn:v1:bluemix:..."),
        ("IBM_TRUSTED_PROFILE_NAME", "profile_name", "my-profile"),
    ],
)
def test_iam_assume_profile_selectors(option, param, value):
    calls: list[dict] = []
    s = IbmIamAssumeStrategy({"IBM_API_KEY": "k", option: value})
    with patch("urllib.request.urlopen", side_effect=_assume_urlopen(calls)):
        s.get_credentials()
    assert calls[1][param] == value


def test_iam_assume_caches_until_invalidate():
    calls: list[dict] = []
    s = IbmIamAssumeStrategy({"IBM_API_KEY": "k", "IBM_TRUSTED_PROFILE_ID": "P"})
    with patch("urllib.request.urlopen", side_effect=_assume_urlopen(calls)):
        assert s.get_credentials() == "profile-tok"
        assert s.get_credentials() == "profile-tok"  # cached, no new calls
        assert len(calls) == 2
        s.invalidate()
        s.get_credentials()  # re-runs both steps
    assert len(calls) == 4


def test_iam_assume_no_profile_selector_raises_at_construction():
    with patch.dict("os.environ", {}, clear=True), pytest.raises(EncryptionConfigurationError) as excinfo:
        IbmIamAssumeStrategy({"IBM_API_KEY": "k"})
    assert "exactly one" in excinfo.value.detail


def test_iam_assume_multiple_profile_selectors_raises_at_construction():
    with pytest.raises(EncryptionConfigurationError) as excinfo:
        IbmIamAssumeStrategy(
            {
                "IBM_API_KEY": "k",
                "IBM_TRUSTED_PROFILE_ID": "P",
                "IBM_TRUSTED_PROFILE_NAME": "also-set",
            }
        )
    assert "exactly one" in excinfo.value.detail


# ---------------------------------------------------------------------------
# container / vpc_instance — SDK-backed (ibm-cloud-sdk-core), via the [ibm] extra
# ---------------------------------------------------------------------------


def _install_fake_ibm_sdk(monkeypatch, capture=None, token="profile-token"):
    """Inject a stand-in ibm_cloud_sdk_core.authenticators so the SDK-backed
    strategies can be exercised without the real extra installed."""

    class _TokenManager:
        def __init__(self):
            self.access_token = "cached"
            self.expire_time = 999
            self.refresh_time = 999

        def get_token(self):
            return token

    class _Base:
        def __init__(self, **kwargs):
            if capture is not None:
                capture.clear()
                capture.update(kwargs)
            self.token_manager = _TokenManager()

    auth_mod = types.ModuleType("ibm_cloud_sdk_core.authenticators")
    auth_mod.ContainerAuthenticator = type("ContainerAuthenticator", (_Base,), {})
    auth_mod.VPCInstanceAuthenticator = type("VPCInstanceAuthenticator", (_Base,), {})
    parent = types.ModuleType("ibm_cloud_sdk_core")
    parent.authenticators = auth_mod
    monkeypatch.setitem(sys.modules, "ibm_cloud_sdk_core", parent)
    monkeypatch.setitem(sys.modules, "ibm_cloud_sdk_core.authenticators", auth_mod)


def test_container_builds_profile_id_and_returns_token(monkeypatch):
    cap = {}
    _install_fake_ibm_sdk(monkeypatch, capture=cap, token="ctok")
    s = IbmContainerStrategy({"IBM_TRUSTED_PROFILE_ID": "Profile-abc"})
    assert cap == {"iam_profile_id": "Profile-abc"}
    assert s.get_credentials() == "ctok"


def test_container_uses_profile_name_and_cr_filename(monkeypatch):
    cap = {}
    _install_fake_ibm_sdk(monkeypatch, capture=cap)
    IbmContainerStrategy({"IBM_TRUSTED_PROFILE_NAME": "tp", "IBM_CR_TOKEN_FILENAME": "/run/cr/token"})
    assert cap == {"iam_profile_name": "tp", "cr_token_filename": "/run/cr/token"}


def test_container_requires_profile(monkeypatch):
    _install_fake_ibm_sdk(monkeypatch)
    with patch.dict("os.environ", {}, clear=True), pytest.raises(EncryptionConfigurationError) as excinfo:
        IbmContainerStrategy({})
    assert "IBM_TRUSTED_PROFILE_ID" in excinfo.value.detail


def test_container_missing_sdk_raises_with_extra_hint(monkeypatch):
    monkeypatch.setitem(sys.modules, "ibm_cloud_sdk_core", None)  # forces ImportError
    with pytest.raises(EncryptionConfigurationError) as excinfo:
        IbmContainerStrategy({"IBM_TRUSTED_PROFILE_ID": "Profile-abc"})
    assert "django-encryption-suite[ibm]" in excinfo.value.detail


def test_vpc_instance_with_profile_id(monkeypatch):
    cap = {}
    _install_fake_ibm_sdk(monkeypatch, capture=cap, token="vtok")
    s = IbmVpcInstanceStrategy({"IBM_TRUSTED_PROFILE_ID": "Profile-xyz"})
    assert cap == {"iam_profile_id": "Profile-xyz"}
    assert s.get_credentials() == "vtok"


def test_vpc_instance_with_crn(monkeypatch):
    cap = {}
    _install_fake_ibm_sdk(monkeypatch, capture=cap)
    IbmVpcInstanceStrategy({"IBM_TRUSTED_PROFILE_CRN": "crn:v1:bluemix:..."})
    assert cap == {"iam_profile_crn": "crn:v1:bluemix:..."}


def test_vpc_instance_default_profile_when_none(monkeypatch):
    cap = {}
    _install_fake_ibm_sdk(monkeypatch, capture=cap)
    with patch.dict("os.environ", {}, clear=True):
        IbmVpcInstanceStrategy({})
    assert cap == {}  # no profile kwarg -> VSI's default linked profile


def test_vpc_instance_rejects_both_id_and_crn(monkeypatch):
    _install_fake_ibm_sdk(monkeypatch)
    with pytest.raises(EncryptionConfigurationError) as excinfo:
        IbmVpcInstanceStrategy({"IBM_TRUSTED_PROFILE_ID": "P", "IBM_TRUSTED_PROFILE_CRN": "crn:..."})
    assert "at most one" in excinfo.value.detail


def test_invalidate_resets_token_manager(monkeypatch):
    _install_fake_ibm_sdk(monkeypatch)
    s = IbmContainerStrategy({"IBM_TRUSTED_PROFILE_ID": "Profile-abc"})
    s.invalidate()
    assert s._auth.token_manager.access_token is None
    assert s._auth.token_manager.expire_time == 0
