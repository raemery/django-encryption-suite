"""Unit tests for the Fly.io KMS adapter and KEK provisioner.

Both components dial the local ``/.fly/api`` Unix socket, which does
not exist in the test environment. Behavioral tests therefore patch
``_request`` (the seam where the HTTP transport lives) on each
instance and assert against the path / body the public methods pass
to it. This keeps the tests cross-platform and lets us verify the
wire shape — base64 encoding, AAD inclusion, URL paths, request
bodies — without spinning up a real Unix server.
"""

from __future__ import annotations

import base64
import json
import urllib.error

import pytest

from encryption_suite.adapters.keks.provisioners_fly import FlyKmsKekProvisioner
from encryption_suite.adapters.keks.strategies import (
    PerSiloKekStrategy,
    SharedKekStrategy,
)
from encryption_suite.adapters.key_stores.base import KmsMetadata
from encryption_suite.adapters.key_stores.fly import FlyKmsAdapter
from encryption_suite.silo_ref import SiloRef

_AAD = b"django-encryption-suite:dek:default:test:1"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _RecordingTransport:
    """Stand-in for ``_request``. Records calls; returns canned responses.

    Provide a list of ``(status, body_dict_or_exception)`` pairs to
    ``responses``. Each call pops the next response. If the response is
    an exception subclass, it is raised; otherwise the body dict is
    returned (and ``status`` is informational only).
    """

    def __init__(self, responses):
        self._responses = list(responses)
        self.calls: list[tuple[str, str, dict | None]] = []

    def __call__(self, method: str, path: str, body):
        self.calls.append((method, path, body))
        if not self._responses:
            raise AssertionError(f"Unexpected extra call: {method} {path} {body!r}")
        _status, payload = self._responses.pop(0)
        if isinstance(payload, BaseException):
            raise payload
        return payload


def _http_404(path: str = "/v1/apps/test-app/secretkeys/key") -> urllib.error.HTTPError:
    return urllib.error.HTTPError(url=path, code=404, msg="Not Found", hdrs=None, fp=None)


def _http_500(path: str = "/v1/apps/test-app/secretkeys/key") -> urllib.error.HTTPError:
    return urllib.error.HTTPError(url=path, code=500, msg="Server Error", hdrs=None, fp=None)


# ---------------------------------------------------------------------------
# FlyKmsAdapter — construction
# ---------------------------------------------------------------------------


class TestFlyKmsAdapterInit:
    def test_requires_fly_app_name(self):
        # str(exc) is the generic user-safe message; the operator detail
        # (naming FLY_APP_NAME) is on .detail, not leaked to end users.
        with pytest.raises(ValueError) as excinfo:
            FlyKmsAdapter(
                {"SHARED_KEK_ID": "k"},
                SharedKekStrategy({"SHARED_KEK_ID": "k"}),
            )
        assert "FLY_APP_NAME" in excinfo.value.detail

    def test_default_socket_path(self):
        adapter = FlyKmsAdapter(
            {"FLY_APP_NAME": "test-app", "SHARED_KEK_ID": "k"},
            SharedKekStrategy({"SHARED_KEK_ID": "k"}),
        )
        assert adapter._socket_path == "/.fly/api"

    def test_custom_socket_path(self):
        adapter = FlyKmsAdapter(
            {
                "FLY_APP_NAME": "test-app",
                "SHARED_KEK_ID": "k",
                "FLY_SOCKET_PATH": "/tmp/fake.sock",
            },
            SharedKekStrategy({"SHARED_KEK_ID": "k"}),
        )
        assert adapter._socket_path == "/tmp/fake.sock"

    def test_a_socket_that_never_answers_times_out(self, monkeypatch):
        """KMS_REQUEST_TIMEOUT_SECONDS reaches the Unix socket, so a hung /.fly/api raises instead of blocking."""
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
        adapter = FlyKmsAdapter(
            {
                "FLY_APP_NAME": "test-app",
                "SHARED_KEK_ID": "k",
                "FLY_SOCKET_PATH": "/tmp/fake.sock",
                "KMS_REQUEST_TIMEOUT_SECONDS": 3,
            },
            SharedKekStrategy({"SHARED_KEK_ID": "k"}),
        )

        with pytest.raises(TimeoutError):
            adapter._request("POST", "/v1/apps/test-app/secretkeys/k/encrypt", {})

        assert seen == {"timeout": 3, "path": "/tmp/fake.sock"}


# ---------------------------------------------------------------------------
# FlyKmsAdapter — encrypt / decrypt
# ---------------------------------------------------------------------------


@pytest.fixture
def shared_adapter():
    """An adapter wired to a shared KEK ``encryption_suite`` in app ``test-app``."""
    options = {"FLY_APP_NAME": "test-app", "SHARED_KEK_ID": "encryption_suite"}
    return FlyKmsAdapter(options, SharedKekStrategy(options))


@pytest.fixture
def per_silo_adapter():
    options = {
        "FLY_APP_NAME": "test-app",
        "KEK_TEMPLATE": "dck_{silo_uid}",
    }
    return FlyKmsAdapter(options, FlyKmsAdapter.build_strategy(PerSiloKekStrategy, options))


class TestFlyKmsAdapterEncrypt:
    def test_returns_ciphertext_and_metadata(self, shared_adapter, monkeypatch):
        canned_ct = b"\x01\x02\x03\x04"
        transport = _RecordingTransport(
            [
                (200, {"ciphertext": base64.b64encode(canned_ct).decode()}),
            ]
        )
        monkeypatch.setattr(shared_adapter, "_request", transport)

        ciphertext, metadata = shared_adapter.encrypt_key(b"plain", SiloRef("default", "test:1"))

        assert ciphertext == canned_ct
        assert isinstance(metadata, KmsMetadata)
        assert metadata.kms_provider == "fly"
        assert metadata.kek_resource_name == "encryption_suite"

    def test_request_path_uses_app_name_and_resolved_key(self, per_silo_adapter, monkeypatch):
        transport = _RecordingTransport(
            [
                (200, {"ciphertext": base64.b64encode(b"x").decode()}),
            ]
        )
        monkeypatch.setattr(per_silo_adapter, "_request", transport)

        per_silo_adapter.encrypt_key(b"p", SiloRef("default", "test_42"))

        method, path, body = transport.calls[0]
        assert method == "POST"
        # UID "test_42" has underscore escaped for Fly: "test__42"
        assert path == "/v1/apps/test-app/secretkeys/dck_test__42/encrypt"
        assert body is not None

    def test_plaintext_is_base64_encoded(self, shared_adapter, monkeypatch):
        transport = _RecordingTransport(
            [
                (200, {"ciphertext": base64.b64encode(b"x").decode()}),
            ]
        )
        monkeypatch.setattr(shared_adapter, "_request", transport)

        plaintext = b"hello world\n"
        shared_adapter.encrypt_key(plaintext, SiloRef("default", "test:1"))

        _method, _path, body = transport.calls[0]
        assert base64.b64decode(body["plaintext"]) == plaintext

    def test_aad_is_attached_and_base64_encoded(self, shared_adapter, monkeypatch):
        transport = _RecordingTransport(
            [
                (200, {"ciphertext": base64.b64encode(b"x").decode()}),
            ]
        )
        monkeypatch.setattr(shared_adapter, "_request", transport)

        shared_adapter.encrypt_key(b"p", SiloRef("default", "test:1"))

        _method, _path, body = transport.calls[0]
        assert "associated_data" in body
        assert base64.b64decode(body["associated_data"]) == _AAD


class TestFlyKmsAdapterDecrypt:
    def test_returns_plaintext(self, shared_adapter, monkeypatch):
        plaintext = b"plain bytes"
        transport = _RecordingTransport(
            [
                (200, {"plaintext": base64.b64encode(plaintext).decode()}),
            ]
        )
        monkeypatch.setattr(shared_adapter, "_request", transport)

        metadata = KmsMetadata(kek_resource_name="encryption_suite", kms_provider="fly")
        result = shared_adapter.decrypt_key(b"\x00\x01", metadata, SiloRef("default", "test:1"))

        assert result == plaintext

    def test_request_path_uses_metadata_kek_name(self, shared_adapter, monkeypatch):
        transport = _RecordingTransport(
            [
                (200, {"plaintext": base64.b64encode(b"x").decode()}),
            ]
        )
        monkeypatch.setattr(shared_adapter, "_request", transport)

        metadata = KmsMetadata(kek_resource_name="dck_team_42", kms_provider="fly")
        shared_adapter.decrypt_key(b"\x00", metadata, SiloRef("default", "test:1"))

        _method, path, _body = transport.calls[0]
        assert path == "/v1/apps/test-app/secretkeys/dck_team_42/decrypt"

    def test_ciphertext_is_base64_encoded(self, shared_adapter, monkeypatch):
        transport = _RecordingTransport(
            [
                (200, {"plaintext": base64.b64encode(b"x").decode()}),
            ]
        )
        monkeypatch.setattr(shared_adapter, "_request", transport)

        ciphertext = b"\xff\xee\xdd\xcc"
        metadata = KmsMetadata(kek_resource_name="encryption_suite", kms_provider="fly")
        shared_adapter.decrypt_key(ciphertext, metadata, SiloRef("default", "test:1"))

        _method, _path, body = transport.calls[0]
        assert base64.b64decode(body["ciphertext"]) == ciphertext

    def test_aad_matches_encrypt_aad(self, shared_adapter, monkeypatch):
        transport = _RecordingTransport(
            [
                (200, {"plaintext": base64.b64encode(b"x").decode()}),
            ]
        )
        monkeypatch.setattr(shared_adapter, "_request", transport)

        metadata = KmsMetadata(kek_resource_name="encryption_suite", kms_provider="fly")
        shared_adapter.decrypt_key(b"\x00", metadata, SiloRef("default", "test:1"))

        _method, _path, body = transport.calls[0]
        assert base64.b64decode(body["associated_data"]) == _AAD


class TestFlyKmsAdapterRoundTripShape:
    """Encrypt and decrypt must agree on the AAD they bind to ciphertexts."""

    def test_encrypt_and_decrypt_use_identical_aad(self, shared_adapter, monkeypatch):
        seen_aads: list[bytes] = []

        def transport(method, path, body):
            seen_aads.append(base64.b64decode(body["associated_data"]))
            if path.endswith("/encrypt"):
                return {"ciphertext": base64.b64encode(b"x").decode()}
            return {"plaintext": base64.b64encode(b"y").decode()}

        monkeypatch.setattr(shared_adapter, "_request", transport)

        shared_adapter.encrypt_key(b"p", SiloRef("default", "test:1"))
        metadata = KmsMetadata(kek_resource_name="encryption_suite", kms_provider="fly")
        shared_adapter.decrypt_key(b"c", metadata, SiloRef("default", "test:1"))

        assert len(seen_aads) == 2
        assert seen_aads[0] == seen_aads[1] == _AAD


# ---------------------------------------------------------------------------
# FlyKmsAdapter — error mapping
# ---------------------------------------------------------------------------


class TestFlyKmsAdapterErrors:
    def test_404_is_kek_not_found(self, shared_adapter):
        exc = _http_404()
        assert shared_adapter.is_kek_not_found_error(exc) is True

    def test_500_is_not_kek_not_found(self, shared_adapter):
        exc = _http_500()
        assert shared_adapter.is_kek_not_found_error(exc) is False

    def test_unrelated_exception_is_not_kek_not_found(self, shared_adapter):
        assert shared_adapter.is_kek_not_found_error(RuntimeError("x")) is False

    def test_404_propagates_through_encrypt(self, shared_adapter, monkeypatch):
        transport = _RecordingTransport([(404, _http_404())])
        monkeypatch.setattr(shared_adapter, "_request", transport)

        with pytest.raises(urllib.error.HTTPError) as excinfo:
            shared_adapter.encrypt_key(b"p", SiloRef("default", "test:1"))
        assert excinfo.value.code == 404


# ---------------------------------------------------------------------------
# FlyKmsAdapter — describe_kek
# ---------------------------------------------------------------------------


class TestFlyKmsAdapterDescribe:
    def test_describes_template(self):
        options = {
            "FLY_APP_NAME": "test-app",
            "KEK_TEMPLATE": "dck_{silo_uid}",
        }
        adapter = FlyKmsAdapter(options, FlyKmsAdapter.build_strategy(PerSiloKekStrategy, options))
        out = adapter.describe_kek()
        assert "test-app" in out
        assert "dck_{silo_uid}" in out

    def test_describes_map(self):
        options = {
            "FLY_APP_NAME": "test-app",
            "KEK_MAP": {"a": "k1", "b": "k2"},
        }
        adapter = FlyKmsAdapter(options, FlyKmsAdapter.build_strategy(PerSiloKekStrategy, options))
        out = adapter.describe_kek()
        assert "test-app" in out
        assert "2 mapped keys" in out


# ---------------------------------------------------------------------------
# FlyKmsKekProvisioner — construction and validation
# ---------------------------------------------------------------------------


class TestFlyKmsKekProvisionerInit:
    def test_requires_fly_app_name(self):
        with pytest.raises(ValueError) as excinfo:
            FlyKmsKekProvisioner({})
        assert "FLY_APP_NAME" in excinfo.value.detail

    def test_default_key_type(self):
        prov = FlyKmsKekProvisioner({"FLY_APP_NAME": "test-app"})
        assert prov._key_type == "xaes256gcm"

    def test_custom_key_type(self):
        prov = FlyKmsKekProvisioner({"FLY_APP_NAME": "test-app", "KEY_TYPE": "something_else"})
        assert prov._key_type == "something_else"

    def test_default_api_base_url(self):
        prov = FlyKmsKekProvisioner({"FLY_APP_NAME": "test-app"})
        assert prov._base_url == "https://api.machines.dev"

    def test_custom_api_base_url_strips_trailing_slash(self):
        prov = FlyKmsKekProvisioner({"FLY_APP_NAME": "test-app", "FLY_API_ENDPOINT": "https://example.test/"})
        assert prov._base_url == "https://example.test"


class TestFlyKmsKekProvisionerNameValidation:
    @pytest.mark.parametrize(
        "bad_name",
        [
            "team-1",  # hyphen
            "team.42",  # dot
            "team/42",  # slash
            "team:42",  # colon
            "",  # empty
            "team 42",  # space
            "team\n42",  # newline
        ],
    )
    def test_rejects_invalid_names(self, bad_name):
        prov = FlyKmsKekProvisioner({"FLY_APP_NAME": "test-app"})
        with pytest.raises(ValueError, match="not a valid Fly secretkey name"):
            prov.ensure_kek(bad_name, SiloRef("default", "gk"))

    @pytest.mark.parametrize(
        "good_name",
        [
            "team_1",
            "team42",
            "TEAM_42",
            "dck_test_app_team_42",
            "a",
            "0",
            "_",
        ],
    )
    def test_accepts_valid_names(self, good_name, monkeypatch):
        prov = FlyKmsKekProvisioner({"FLY_APP_NAME": "test-app"})
        # GET returns 200 → no /generate; valid name should pass through.
        transport = _RecordingTransport([(200, {})])
        monkeypatch.setattr(prov, "_request", transport)
        prov.ensure_kek(good_name, SiloRef("default", "gk"))


# ---------------------------------------------------------------------------
# FlyKmsKekProvisioner — ensure_kek behavior
# ---------------------------------------------------------------------------


class TestFlyKmsKekProvisionerEnsureKek:
    def test_skips_when_already_in_cache(self, monkeypatch):
        prov = FlyKmsKekProvisioner({"FLY_APP_NAME": "test-app"})
        prov._ensured.add("dck_team_42")

        transport = _RecordingTransport([])  # any call would assert
        monkeypatch.setattr(prov, "_request", transport)

        prov.ensure_kek("dck_team_42", SiloRef("default", "test:42"))
        assert transport.calls == []

    def test_get_200_caches_and_skips_generate(self, monkeypatch):
        prov = FlyKmsKekProvisioner({"FLY_APP_NAME": "test-app"})
        transport = _RecordingTransport([(200, {})])
        monkeypatch.setattr(prov, "_request", transport)

        prov.ensure_kek("dck_team_42", SiloRef("default", "test:42"))

        assert len(transport.calls) == 1
        method, path, _body = transport.calls[0]
        assert method == "GET"
        assert path == "/v1/apps/test-app/secretkeys/dck_team_42"
        assert "dck_team_42" in prov._ensured

    def test_get_404_triggers_generate_with_xaes256gcm(self, monkeypatch):
        prov = FlyKmsKekProvisioner({"FLY_APP_NAME": "test-app"})
        transport = _RecordingTransport(
            [
                (404, _http_404("/v1/apps/test-app/secretkeys/dck_team_42")),
                (201, {"name": "dck_team_42", "type": "xaes256gcm"}),
            ]
        )
        monkeypatch.setattr(prov, "_request", transport)

        prov.ensure_kek("dck_team_42", SiloRef("default", "test:42"))

        assert len(transport.calls) == 2

        method_get, path_get, body_get = transport.calls[0]
        assert method_get == "GET"
        assert path_get == "/v1/apps/test-app/secretkeys/dck_team_42"
        assert body_get is None

        method_gen, path_gen, body_gen = transport.calls[1]
        assert method_gen == "POST"
        assert path_gen == "/v1/apps/test-app/secretkeys/dck_team_42/generate"
        assert body_gen == {"type": "xaes256gcm"}

        assert "dck_team_42" in prov._ensured

    def test_generate_uses_configured_key_type(self, monkeypatch):
        prov = FlyKmsKekProvisioner({"FLY_APP_NAME": "test-app", "KEY_TYPE": "custom"})
        transport = _RecordingTransport(
            [
                (404, _http_404()),
                (201, {}),
            ]
        )
        monkeypatch.setattr(prov, "_request", transport)

        prov.ensure_kek("k", SiloRef("default", "g"))

        _method, _path, body = transport.calls[1]
        assert body == {"type": "custom"}

    def test_non_404_get_error_propagates(self, monkeypatch):
        prov = FlyKmsKekProvisioner({"FLY_APP_NAME": "test-app"})
        transport = _RecordingTransport([(500, _http_500())])
        monkeypatch.setattr(prov, "_request", transport)

        with pytest.raises(urllib.error.HTTPError) as excinfo:
            prov.ensure_kek("k", SiloRef("default", "g"))
        assert excinfo.value.code == 500
        assert "k" not in prov._ensured

    def test_generate_failure_does_not_cache(self, monkeypatch):
        prov = FlyKmsKekProvisioner({"FLY_APP_NAME": "test-app"})
        transport = _RecordingTransport(
            [
                (404, _http_404()),
                (500, _http_500()),
            ]
        )
        monkeypatch.setattr(prov, "_request", transport)

        with pytest.raises(urllib.error.HTTPError):
            prov.ensure_kek("k", SiloRef("default", "g"))
        assert "k" not in prov._ensured

    def test_describe_includes_app_name(self):
        prov = FlyKmsKekProvisioner({"FLY_APP_NAME": "test-app"})
        assert "test-app" in prov.describe()


# ---------------------------------------------------------------------------
# FlyKmsKekProvisioner — enumeration (reconcile, KMS half)
# ---------------------------------------------------------------------------


class TestFlyKmsKekProvisionerListKekNames:
    _PREFIX = "dck_"

    def test_supports_enumeration(self):
        assert FlyKmsKekProvisioner({"FLY_APP_NAME": "test-app"}).supports_enumeration is True

    def test_list_uses_collection_path(self, monkeypatch):
        prov = FlyKmsKekProvisioner({"FLY_APP_NAME": "test-app"})
        transport = _RecordingTransport([(200, [])])
        monkeypatch.setattr(prov, "_request", transport)

        prov._do_list_kek_names(self._PREFIX)

        method, path, body = transport.calls[0]
        assert method == "GET"
        assert path == "/v1/apps/test-app/secretkeys"
        assert body is None

    def test_extracts_names_from_array_payload(self, monkeypatch):
        prov = FlyKmsKekProvisioner({"FLY_APP_NAME": "test-app"})
        transport = _RecordingTransport([(200, [{"name": "dck_team_1", "type": "xaes256gcm"}, {"name": "dck_team_2"}])])
        monkeypatch.setattr(prov, "_request", transport)

        assert prov._do_list_kek_names(self._PREFIX) == ["dck_team_1", "dck_team_2"]

    def test_extracts_names_from_wrapped_payload(self, monkeypatch):
        # Tolerate a wrapper object around the array.
        prov = FlyKmsKekProvisioner({"FLY_APP_NAME": "test-app"})
        transport = _RecordingTransport([(200, {"secret_keys": [{"name": "dck_team_1"}]})])
        monkeypatch.setattr(prov, "_request", transport)

        assert prov._do_list_kek_names(self._PREFIX) == ["dck_team_1"]

    def test_ignores_items_without_a_name(self, monkeypatch):
        prov = FlyKmsKekProvisioner({"FLY_APP_NAME": "test-app"})
        transport = _RecordingTransport([(200, [{"type": "x"}, {"name": "dck_team_1"}, "junk"])])
        monkeypatch.setattr(prov, "_request", transport)

        assert prov._do_list_kek_names(self._PREFIX) == ["dck_team_1"]

    def test_base_list_kek_names_filters_by_owner_prefix(self, monkeypatch):
        # The public template method drops any name lacking the owner prefix,
        # even if the Fly app also holds unrelated keys.
        prov = FlyKmsKekProvisioner({"FLY_APP_NAME": "test-app"})
        transport = _RecordingTransport(
            [(200, [{"name": "dck_team_1"}, {"name": "encryption_suite"}, {"name": "other_key"}])]
        )
        monkeypatch.setattr(prov, "_request", transport)

        assert prov.list_kek_names(self._PREFIX) == ["dck_team_1"]

    def test_empty_response_yields_no_names(self, monkeypatch):
        prov = FlyKmsKekProvisioner({"FLY_APP_NAME": "test-app"})
        transport = _RecordingTransport([(200, {})])
        monkeypatch.setattr(prov, "_request", transport)

        assert prov._do_list_kek_names(self._PREFIX) == []


# ---------------------------------------------------------------------------
# FlyKmsKekProvisioner — _request HTTP layer
#
# Unlike the FlyKmsAdapter, the provisioner talks to the public Fly Machines
# API over HTTPS with a bearer token (the local /.fly/api socket forbids
# secretkey creation). These tests patch ``urllib.request.urlopen`` to verify
# the token requirement and the URL/header shape.
# ---------------------------------------------------------------------------


class _FakeResponse:
    def __init__(self, body: bytes = b""):
        self._body = body

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class TestFlyKmsKekProvisionerRequest:
    def test_missing_token_raises_runtime_error(self, monkeypatch):
        monkeypatch.delenv("FLY_API_TOKEN", raising=False)
        prov = FlyKmsKekProvisioner({"FLY_APP_NAME": "test-app"})
        with pytest.raises(RuntimeError, match="FLY_API_TOKEN"):
            prov._request("GET", "/v1/apps/test-app/secretkeys/k", None)

    def test_get_sends_bearer_token_to_public_api(self, monkeypatch):
        monkeypatch.setenv("FLY_API_TOKEN", "tok_abc")
        prov = FlyKmsKekProvisioner({"FLY_APP_NAME": "test-app"})

        captured = {}

        def fake_urlopen(req, timeout, context):
            captured["url"] = req.full_url
            captured["method"] = req.get_method()
            captured["headers"] = dict(req.header_items())
            captured["body"] = req.data
            return _FakeResponse(b'{"name": "k"}')

        monkeypatch.setattr(
            "encryption_suite.adapters.keks.provisioners_fly.urllib.request.urlopen",
            fake_urlopen,
        )

        result = prov._request("GET", "/v1/apps/test-app/secretkeys/k", None)

        assert result == {"name": "k"}
        assert captured["url"] == "https://api.machines.dev/v1/apps/test-app/secretkeys/k"
        assert captured["method"] == "GET"
        # Header keys are title-cased by urllib.
        assert captured["headers"]["Authorization"] == "Bearer tok_abc"
        assert "Content-type" not in captured["headers"]
        assert captured["body"] is None

    def test_post_serializes_body_and_sets_content_type(self, monkeypatch):
        monkeypatch.setenv("FLY_API_TOKEN", "tok_abc")
        prov = FlyKmsKekProvisioner({"FLY_APP_NAME": "test-app"})

        captured = {}

        def fake_urlopen(req, timeout, context):
            captured["url"] = req.full_url
            captured["method"] = req.get_method()
            captured["headers"] = dict(req.header_items())
            captured["body"] = req.data
            return _FakeResponse(b"{}")

        monkeypatch.setattr(
            "encryption_suite.adapters.keks.provisioners_fly.urllib.request.urlopen",
            fake_urlopen,
        )

        prov._request(
            "POST",
            "/v1/apps/test-app/secretkeys/k/generate",
            {"type": "xaes256gcm"},
        )

        assert captured["method"] == "POST"
        assert captured["url"].endswith("/secretkeys/k/generate")
        assert captured["headers"]["Content-type"] == "application/json"
        assert json.loads(captured["body"]) == {"type": "xaes256gcm"}

    def test_uses_configured_base_url(self, monkeypatch):
        monkeypatch.setenv("FLY_API_TOKEN", "tok_abc")
        prov = FlyKmsKekProvisioner({"FLY_APP_NAME": "test-app", "FLY_API_ENDPOINT": "https://example.test"})
        captured = {}

        def fake_urlopen(req, timeout, context):
            captured["url"] = req.full_url
            return _FakeResponse(b"{}")

        monkeypatch.setattr(
            "encryption_suite.adapters.keks.provisioners_fly.urllib.request.urlopen",
            fake_urlopen,
        )

        prov._request("GET", "/v1/apps/test-app/secretkeys/k", None)
        assert captured["url"].startswith("https://example.test/")
