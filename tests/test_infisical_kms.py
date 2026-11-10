"""Unit tests for the Infisical KMS adapter and KEK provisioner.

Both components talk to the Infisical REST API over HTTPS, which is not
reachable in the test environment. Behavioral tests patch the HTTP seams
(``_request`` / ``_get_key_by_name`` on the adapter, ``_api`` on the
provisioner) and assert against the URLs, bodies, and the name → UUID
resolution the public methods drive.
"""

from __future__ import annotations

import base64
import urllib.error

import pytest
from django.core.exceptions import ImproperlyConfigured

from encryption_suite.adapters.keks.provisioners_infisical import InfisicalKekProvisioner
from encryption_suite.adapters.keks.strategies import (
    PerSiloKekStrategy,
    SharedKekStrategy,
)
from encryption_suite.adapters.key_stores.base import KmsMetadata
from encryption_suite.adapters.key_stores.infisical import InfisicalKmsAdapter, _is_uuid
from encryption_suite.exceptions import (
    EncryptionConfigurationError,
    KekDeleteError,
    KekEnumerationError,
)
from encryption_suite.silo_ref import SiloRef

_UUID = "9f3a8e1b-1234-4abc-89de-0123456789ab"
_UUID2 = "1c2d3e4f-aaaa-4bbb-8ccc-dddddddddddd"


def _http_404(url: str = "https://app.infisical.com/api/v1/kms/keys/key-name/x") -> urllib.error.HTTPError:
    return urllib.error.HTTPError(url=url, code=404, msg="Not Found", hdrs=None, fp=None)


def _http_500(url: str = "https://app.infisical.com/api/v1/kms/keys") -> urllib.error.HTTPError:
    return urllib.error.HTTPError(url=url, code=500, msg="Server Error", hdrs=None, fp=None)


def _token_options(**extra) -> dict:
    """Base options using the static-token strategy so construction makes no HTTP call."""
    return {"CREDENTIAL_STRATEGY": "token", "INFISICAL_TOKEN": "tok", **extra}


def _adapter(**extra) -> InfisicalKmsAdapter:
    options = _token_options(**extra)
    strategy = InfisicalKmsAdapter.build_strategy(PerSiloKekStrategy, options)
    return InfisicalKmsAdapter(options, strategy)


# ---------------------------------------------------------------------------
# _is_uuid
# ---------------------------------------------------------------------------


class TestIsUuid:
    def test_accepts_canonical_uuid(self):
        assert _is_uuid(_UUID) is True

    @pytest.mark.parametrize("value", ["encryption-suite-team-1", "team_1", "", "9f3a8e1b", _UUID + "x"])
    def test_rejects_non_uuid(self, value):
        assert _is_uuid(value) is False


# ---------------------------------------------------------------------------
# Construction
# ---------------------------------------------------------------------------


class TestInfisicalKmsAdapterInit:
    def test_rejects_shared_kek_strategy(self):
        # Construction-time guard: a EncryptionConfigurationError (not the
        # Django ImproperlyConfigured it used to raise) so a consuming view's
        # ``except EncryptionError`` catches it instead of 500ing. str(exc) is
        # the generic user-safe message; the operator detail is on .detail.
        options = _token_options(SHARED_KEK_ID="k")
        with pytest.raises(EncryptionConfigurationError) as excinfo:
            InfisicalKmsAdapter(options, SharedKekStrategy(options))
        assert "SharedKekStrategy" in excinfo.value.detail

    def test_rejects_a_template_with_no_silo_placeholder(self):
        # One key for every silo, reached without SharedKekStrategy.
        with pytest.raises(EncryptionConfigurationError) as excinfo:
            _adapter(KEK_TEMPLATE="encryption-suite-shared")
        assert "{silo_uid}" in excinfo.value.detail

    def test_rejects_a_map_naming_one_key_for_two_silos(self):
        with pytest.raises(EncryptionConfigurationError) as excinfo:
            _adapter(KEK_MAP={"team:1": _UUID, "team:2": _UUID})
        assert _UUID in excinfo.value.detail

    def test_accepts_a_map_naming_each_key_once(self):
        _adapter(KEK_MAP={"team:1": _UUID, "team:2": _UUID2})

    def test_default_site_url(self):
        adapter = _adapter(KEK_MAP={"team:1": _UUID})
        assert adapter._site_url == "https://app.infisical.com"

    def test_custom_site_url_strips_trailing_slash(self):
        adapter = _adapter(KEK_MAP={"team:1": _UUID}, INFISICAL_ENDPOINT="https://infisical.example.com/")
        assert adapter._site_url == "https://infisical.example.com"

    def test_slug_sanitization_for_template(self):
        adapter = _adapter(KEK_TEMPLATE="encryption-suite-{silo_uid}", INFISICAL_PROJECT_ID="proj")
        # colon -> "z3a" (letter escape + lowercase hex) keeps the name valid
        assert adapter._resolve_kek_id(SiloRef("default", "team:42")) == "encryption-suite-teamz3a42"

    def test_a_hyphen_in_the_uid_does_not_produce_a_doubled_hyphen(self):
        # Regression, found live 2026-08-03. With a "-" escape, sanitize_uid
        # doubles it to stay reversible, so the ordinary UID "team-1" rendered as
        # "team--1" — and Infisical refuses two hyphens in a row. That rejected
        # every real tenant at key creation while the hyphen-free test-console
        # sentinels kept provisioning, so the bench read healthy until the first
        # team was created. A letter escape leaves "-" an ordinary character.
        adapter = _adapter(KEK_TEMPLATE="encryption-suite-{silo_uid}", INFISICAL_PROJECT_ID="proj")

        name = adapter._resolve_kek_id(SiloRef("default", "team-1"))

        assert name == "encryption-suite-team-1"
        assert "--" not in name

    def test_an_escaped_leading_character_does_not_start_the_name_with_a_hyphen(self):
        # The other half of Infisical's naming rule: a name may not begin with a
        # hyphen. Every escape sequence starts with the letter, so an escaped
        # first character cannot introduce one — nor collide with a KEK_TEMPLATE
        # prefix ending in "-" to make a doubled hyphen at the join.
        adapter = _adapter(KEK_TEMPLATE="{silo_uid}", INFISICAL_PROJECT_ID="proj")

        name = adapter._resolve_kek_id(SiloRef("default", "Team-1"))

        assert not name.startswith("-")
        assert name == "z54eam-1"

    def test_the_escape_character_itself_stays_reversible(self):
        # A literal "z" doubles, so "zebra" cannot be read as an escape sequence
        # and distinct UIDs stay distinct.
        adapter = _adapter(KEK_TEMPLATE="encryption-suite-{silo_uid}", INFISICAL_PROJECT_ID="proj")

        assert adapter._resolve_kek_id(SiloRef("default", "zebra-1")) == "encryption-suite-zzebra-1"

    @pytest.mark.parametrize("silo_uid", ["team--1", "team-"])
    def test_a_uid_whose_own_hyphens_break_the_rule_is_refused(self, silo_uid):
        # Hyphens already in the UID pass through untouched, so a UID holding "--"
        # or ending in "-" still renders a name Infisical rejects. The shipped silo
        # adapters cannot produce either, so this guards custom adapters — and it
        # turns an opaque 422 (whose message quotes only the character class the
        # name already satisfies) into something an operator can act on.
        adapter = _adapter(KEK_TEMPLATE="encryption-suite-{silo_uid}", INFISICAL_PROJECT_ID="proj")

        with pytest.raises(EncryptionConfigurationError) as excinfo:
            adapter._resolve_kek_id(SiloRef("default", silo_uid))

        assert "hyphen" in excinfo.value.detail

    def test_a_kek_map_uuid_is_not_subjected_to_the_name_rule(self):
        # A UUID contains hyphens by construction and is never a key *name*.
        adapter = _adapter(KEK_MAP={"team:1": _UUID}, INFISICAL_PROJECT_ID="proj")

        assert adapter._resolve_kek_id(SiloRef("default", "team:1")) == _UUID


# ---------------------------------------------------------------------------
# encrypt — KEK_MAP (UUID, no lookup)
# ---------------------------------------------------------------------------


class TestEncryptWithUuidMap:
    def test_uses_uuid_directly_without_lookup(self, monkeypatch):
        adapter = _adapter(KEK_MAP={"team:1": _UUID})

        calls = []

        def fake_request(action, body, key_id):
            calls.append((action, key_id, body))
            return {"ciphertext": "CT"}

        # A name lookup must never happen in UUID mode.
        def fail_lookup(name):
            raise AssertionError(f"unexpected name lookup for {name!r}")

        monkeypatch.setattr(adapter, "_request", fake_request)
        monkeypatch.setattr(adapter, "_get_key_by_name", fail_lookup)

        ciphertext, metadata = adapter.encrypt_key(b"plain", SiloRef("default", "team:1"))

        assert ciphertext == b"CT"
        assert metadata.kms_provider == "infisical"
        # A KEK_MAP entry is already a UUID, so the identifier recorded is that UUID.
        assert metadata.kek_resource_name == _UUID
        action, key_id, body = calls[0]
        assert action == "encrypt"
        assert key_id == _UUID
        assert base64.b64decode(body["plaintext"]) == b"plain"


# ---------------------------------------------------------------------------
# encrypt — KEK_TEMPLATE (name resolved to UUID)
# ---------------------------------------------------------------------------


class TestEncryptWithTemplateName:
    def test_resolves_name_to_uuid_then_encrypts(self, monkeypatch):
        adapter = _adapter(KEK_TEMPLATE="encryption-suite-{silo_uid}", INFISICAL_PROJECT_ID="proj")

        lookups = []
        requests = []

        def fake_lookup(name):
            lookups.append(name)
            return {"id": _UUID}

        def fake_request(action, body, key_id):
            requests.append((action, key_id))
            return {"ciphertext": "CT"}

        monkeypatch.setattr(adapter, "_get_key_by_name", fake_lookup)
        monkeypatch.setattr(adapter, "_request", fake_request)

        _ct, metadata = adapter.encrypt_key(b"p", SiloRef("default", "team:1"))

        assert lookups == ["encryption-suite-teamz3a1"]
        assert requests[0] == ("encrypt", _UUID)
        # The name — not the UUID it resolved to — is what is stored, so the
        # ownership gate and reconcile can compare it against the owner prefix.
        assert metadata.kek_resource_name == "encryption-suite-teamz3a1"

    def test_name_to_uuid_resolution_is_cached(self, monkeypatch):
        adapter = _adapter(KEK_TEMPLATE="encryption-suite-{silo_uid}", INFISICAL_PROJECT_ID="proj")

        lookups = []
        monkeypatch.setattr(adapter, "_get_key_by_name", lambda name: lookups.append(name) or {"id": _UUID})
        monkeypatch.setattr(adapter, "_request", lambda action, body, key_id: {"ciphertext": "CT"})

        adapter.encrypt_key(b"p", SiloRef("default", "team:1"))
        adapter.encrypt_key(b"p", SiloRef("default", "team:1"))

        assert lookups == ["encryption-suite-teamz3a1"]  # second encrypt hits the cache

    def test_response_id_nested_under_key(self, monkeypatch):
        adapter = _adapter(KEK_TEMPLATE="encryption-suite-{silo_uid}", INFISICAL_PROJECT_ID="proj")
        monkeypatch.setattr(adapter, "_get_key_by_name", lambda name: {"key": {"id": _UUID}})
        monkeypatch.setattr(adapter, "_request", lambda action, body, key_id: {"ciphertext": "CT"})

        _ct, metadata = adapter.encrypt_key(b"p", SiloRef("default", "team:1"))
        assert metadata.kek_resource_name == "encryption-suite-teamz3a1"

    def test_template_without_project_id_raises(self, monkeypatch):
        adapter = _adapter(KEK_TEMPLATE="encryption-suite-{silo_uid}")  # no INFISICAL_PROJECT_ID
        # _get_key_by_name is the real method here; it must reject the missing project id.
        with pytest.raises(ImproperlyConfigured, match="INFISICAL_PROJECT_ID"):
            adapter.encrypt_key(b"p", SiloRef("default", "team:1"))


# ---------------------------------------------------------------------------
# decrypt
# ---------------------------------------------------------------------------


class TestDecrypt:
    def test_extracts_uuid_from_resource_name(self, monkeypatch):
        adapter = _adapter(KEK_MAP={"team:1": _UUID})

        calls = []

        def fake_request(action, body, key_id):
            calls.append((action, key_id))
            return {"plaintext": base64.b64encode(b"plain").decode()}

        monkeypatch.setattr(adapter, "_request", fake_request)

        metadata = KmsMetadata(
            kek_resource_name=f"https://app.infisical.com/api/v1/kms/keys/{_UUID}",
            kms_provider="infisical",
        )
        result = adapter.decrypt_key(b"CT", metadata, SiloRef("default", "team:1"))

        assert result == b"plain"
        assert calls[0] == ("decrypt", _UUID)

    def test_a_recorded_uuid_needs_no_name_lookup(self, monkeypatch):
        adapter = _adapter(KEK_TEMPLATE="encryption-suite-{silo_uid}", INFISICAL_PROJECT_ID="proj")
        monkeypatch.setattr(
            adapter, "_get_key_by_name", lambda name: (_ for _ in ()).throw(AssertionError("no lookup on decrypt"))
        )
        monkeypatch.setattr(
            adapter, "_request", lambda action, body, key_id: {"plaintext": base64.b64encode(b"x").decode()}
        )

        metadata = KmsMetadata(
            kek_resource_name=f"https://app.infisical.com/api/v1/kms/keys/{_UUID}",
            kms_provider="infisical",
        )
        assert adapter.decrypt_key(b"CT", metadata, SiloRef("default", "team:1")) == b"x"

    def test_a_recorded_name_resolves_to_its_uuid(self, monkeypatch):
        # What KEK_TEMPLATE deployments record since names became the stored
        # name space: decrypt has to resolve one back to a UUID to call the API.
        adapter = _adapter(KEK_TEMPLATE="encryption-suite-{silo_uid}", INFISICAL_PROJECT_ID="proj")

        calls = []
        monkeypatch.setattr(adapter, "_get_key_by_name", lambda name: calls.append(name) or {"id": _UUID})
        monkeypatch.setattr(
            adapter,
            "_request",
            lambda action, body, key_id: calls.append(key_id) or {"plaintext": base64.b64encode(b"x").decode()},
        )

        metadata = KmsMetadata(kek_resource_name="encryption-suite-teamz3a1", kms_provider="infisical")

        assert adapter.decrypt_key(b"CT", metadata, SiloRef("default", "team:1")) == b"x"
        assert calls == ["encryption-suite-teamz3a1", _UUID]


# ---------------------------------------------------------------------------
# describe_kek
# ---------------------------------------------------------------------------


class TestDescribeKek:
    def test_describes_map(self):
        adapter = _adapter(KEK_MAP={"a": _UUID, "b": _UUID2})
        assert "2 mapped keys" in adapter.describe_kek()

    def test_describes_template(self):
        adapter = _adapter(KEK_TEMPLATE="encryption-suite-{silo_uid}", INFISICAL_PROJECT_ID="proj")
        out = adapter.describe_kek()
        assert "encryption-suite-{silo_uid}" in out


# ---------------------------------------------------------------------------
# Provisioner — construction
# ---------------------------------------------------------------------------


class TestInfisicalKekProvisionerInit:
    def test_requires_project_id(self):
        with pytest.raises(EncryptionConfigurationError) as excinfo:
            InfisicalKekProvisioner(_token_options())
        assert "INFISICAL_PROJECT_ID" in excinfo.value.detail

    def test_defaults(self):
        prov = InfisicalKekProvisioner(_token_options(INFISICAL_PROJECT_ID="proj"))
        assert prov._site_url == "https://app.infisical.com"
        assert prov._algorithm == "aes-256-gcm"

    def test_describe_includes_project(self):
        prov = InfisicalKekProvisioner(_token_options(INFISICAL_PROJECT_ID="proj"))
        assert "proj" in prov.describe()


# ---------------------------------------------------------------------------
# Provisioner — ensure_kek
# ---------------------------------------------------------------------------


def _provisioner(**extra) -> InfisicalKekProvisioner:
    return InfisicalKekProvisioner(_token_options(INFISICAL_PROJECT_ID="proj", **extra))


class TestInfisicalKekProvisionerEnsureKek:
    def test_existing_key_is_not_recreated(self, monkeypatch):
        prov = _provisioner()
        calls = []

        def fake_api(method, url, body):
            calls.append((method, url, body))
            return {"id": _UUID}  # GET succeeds

        monkeypatch.setattr(prov, "_api", fake_api)
        prov.ensure_kek("encryption-suite-team-1", SiloRef("default", "team:1"))

        assert len(calls) == 1
        method, url, body = calls[0]
        assert method == "GET"
        assert "/kms/keys/key-name/encryption-suite-team-1" in url
        assert "projectId=proj" in url
        assert "encryption-suite-team-1" in prov._ensured

    def test_missing_key_is_created(self, monkeypatch):
        prov = _provisioner()
        calls = []

        def fake_api(method, url, body):
            calls.append((method, url, body))
            if method == "GET":
                raise _http_404()
            return {"id": _UUID}  # POST create

        monkeypatch.setattr(prov, "_api", fake_api)
        prov.ensure_kek("encryption-suite-team-1", SiloRef("default", "team:1"))

        assert len(calls) == 2
        assert calls[0][0] == "GET"
        method, url, body = calls[1]
        assert method == "POST"
        assert url == "https://app.infisical.com/api/v1/kms/keys"
        assert body == {
            "projectId": "proj",
            "name": "encryption-suite-team-1",
            "encryptionAlgorithm": "aes-256-gcm",
        }
        assert "encryption-suite-team-1" in prov._ensured

    def test_create_includes_description_when_set(self, monkeypatch):
        prov = _provisioner(KEY_DESCRIPTION="per-tenant KEK")
        bodies = []

        def fake_api(method, url, body):
            if method == "GET":
                raise _http_404()
            bodies.append(body)
            return {"id": _UUID}

        monkeypatch.setattr(prov, "_api", fake_api)
        prov.ensure_kek("encryption-suite-team-1", SiloRef("default", "team:1"))
        assert bodies[0]["description"] == "per-tenant KEK"

    def test_custom_algorithm(self, monkeypatch):
        prov = _provisioner(ENCRYPTION_ALGORITHM="aes-128-gcm")
        bodies = []

        def fake_api(method, url, body):
            if method == "GET":
                raise _http_404()
            bodies.append(body)
            return {"id": _UUID}

        monkeypatch.setattr(prov, "_api", fake_api)
        prov.ensure_kek("encryption-suite-team-1", SiloRef("default", "team:1"))
        assert bodies[0]["encryptionAlgorithm"] == "aes-128-gcm"

    def test_skips_when_already_ensured(self, monkeypatch):
        prov = _provisioner()
        prov._ensured.add("encryption-suite-team-1")
        monkeypatch.setattr(prov, "_api", lambda *a: (_ for _ in ()).throw(AssertionError("no call expected")))
        prov.ensure_kek("encryption-suite-team-1", SiloRef("default", "team:1"))

    def test_normalizes_full_resource_url(self, monkeypatch):
        prov = _provisioner()
        seen = []

        def fake_api(method, url, body):
            seen.append((method, url))
            return {"id": _UUID}

        monkeypatch.setattr(prov, "_api", fake_api)
        prov.ensure_kek(
            "https://app.infisical.com/api/v1/kms/keys/encryption-suite-team-1", SiloRef("default", "team:1")
        )
        # The bare name is extracted for the by-name lookup.
        assert "/kms/keys/key-name/encryption-suite-team-1" in seen[0][1]

    def test_create_race_is_tolerated(self, monkeypatch):
        prov = _provisioner()
        # GET 404 -> POST fails (another worker created it) -> re-GET succeeds.
        seq = [
            ("GET", _http_404()),
            ("POST", _http_500()),
            ("GET", {"id": _UUID}),
        ]
        idx = {"i": 0}

        def fake_api(method, url, body):
            expected_method, payload = seq[idx["i"]]
            idx["i"] += 1
            assert method == expected_method
            if isinstance(payload, BaseException):
                raise payload
            return payload

        monkeypatch.setattr(prov, "_api", fake_api)
        prov.ensure_kek("encryption-suite-team-1", SiloRef("default", "team:1"))
        assert "encryption-suite-team-1" in prov._ensured

    def test_create_failure_without_race_propagates(self, monkeypatch):
        prov = _provisioner()
        # GET 404 -> POST 500 -> re-GET also 404 (key really not there) -> raise.
        seq = [_http_404(), _http_500(), _http_404()]
        idx = {"i": 0}

        def fake_api(method, url, body):
            payload = seq[idx["i"]]
            idx["i"] += 1
            raise payload

        monkeypatch.setattr(prov, "_api", fake_api)
        with pytest.raises(urllib.error.HTTPError) as excinfo:
            prov.ensure_kek("encryption-suite-team-1", SiloRef("default", "team:1"))
        assert excinfo.value.code == 500
        assert "encryption-suite-team-1" not in prov._ensured

    def test_non_404_get_error_propagates(self, monkeypatch):
        prov = _provisioner()
        monkeypatch.setattr(prov, "_api", lambda method, url, body: (_ for _ in ()).throw(_http_500()))
        with pytest.raises(urllib.error.HTTPError) as excinfo:
            prov.ensure_kek("encryption-suite-team-1", SiloRef("default", "team:1"))
        assert excinfo.value.code == 500


class TestInfisicalKekProvisionerDelete:
    """Deletion is immediate on Infisical — there is no window to schedule into."""

    def test_resolves_the_name_then_deletes_the_uuid(self, monkeypatch):
        prov = _provisioner()
        prov._ensured.add("encryption-suite-team-1")
        calls = []

        def fake_api(method, url, body):
            calls.append((method, url))
            return {"key": {"id": _UUID}}

        monkeypatch.setattr(prov, "_api", fake_api)
        outcome = prov._do_delete_kek("encryption-suite-team-1", "team:1")

        assert calls[0][0] == "GET"
        assert "/kms/keys/key-name/encryption-suite-team-1" in calls[0][1]
        assert calls[1] == ("DELETE", f"https://app.infisical.com/api/v1/kms/keys/{_UUID}")
        # No waiting period, so the key is gone as the call returns.
        assert outcome.scheduled is False
        # The cache must not keep vouching for a key that no longer exists.
        assert "encryption-suite-team-1" not in prov._ensured

    def test_an_absent_key_counts_as_deleted(self, monkeypatch):
        prov = _provisioner()
        monkeypatch.setattr(prov, "_api", lambda method, url, body: (_ for _ in ()).throw(_http_404()))

        outcome = prov._do_delete_kek("encryption-suite-team-1", "team:1")

        assert outcome.scheduled is False

    def test_a_delete_error_propagates(self, monkeypatch):
        prov = _provisioner()

        def fake_api(method, url, body):
            if method == "GET":
                return {"id": _UUID}
            raise _http_500()

        monkeypatch.setattr(prov, "_api", fake_api)
        with pytest.raises(urllib.error.HTTPError) as excinfo:
            prov._do_delete_kek("encryption-suite-team-1", "team:1")
        assert excinfo.value.code == 500

    def test_deletion_is_refused_without_an_owner_prefix(self, monkeypatch):
        # The public entry point, so the ownership gate is in play: a KEK_MAP
        # deployment derives no prefix and must not be able to delete.
        prov = _provisioner()
        monkeypatch.setattr(prov, "_api", lambda *a: (_ for _ in ()).throw(AssertionError("no call expected")))

        with pytest.raises(KekDeleteError):
            prov.delete_kek("encryption-suite-team-1", SiloRef("default", "team:1"), owner_prefix=None)


class TestInfisicalKekProvisionerEnumeration:
    def test_lists_key_names(self, monkeypatch):
        prov = _provisioner()
        calls = []

        def fake_api(method, url, body):
            calls.append(url)
            return {
                "keys": [
                    {"id": _UUID, "name": "encryption-suite-team-1"},
                    {"id": _UUID2, "name": "encryption-suite-team-2"},
                ],
                "totalCount": 2,
            }

        monkeypatch.setattr(prov, "_api", fake_api)

        assert prov._do_list_kek_names("encryption-suite-") == [
            "encryption-suite-team-1",
            "encryption-suite-team-2",
        ]
        assert "projectId=proj" in calls[0]
        # The prefix is passed as the API's search filter to keep the paging short.
        assert "search=encryption-suite-" in calls[0]

    def test_pages_until_the_total_is_reached(self, monkeypatch):
        prov = _provisioner()
        pages = [
            {"keys": [{"name": f"encryption-suite-team-{i}"} for i in range(100)], "totalCount": 101},
            {"keys": [{"name": "encryption-suite-team-100"}], "totalCount": 101},
        ]
        offsets = []

        def fake_api(method, url, body):
            offsets.append(url)
            return pages[len(offsets) - 1]

        monkeypatch.setattr(prov, "_api", fake_api)
        names = prov._do_list_kek_names("encryption-suite-")

        assert len(names) == 101
        assert "offset=0" in offsets[0]
        assert "offset=100" in offsets[1]

    def test_a_short_page_ends_the_loop_even_without_a_total(self, monkeypatch):
        # A totalCount the server omits must not spin the loop forever.
        prov = _provisioner()
        calls = []

        def fake_api(method, url, body):
            calls.append(url)
            return {"keys": [{"name": "encryption-suite-team-1"}]}

        monkeypatch.setattr(prov, "_api", fake_api)

        assert prov._do_list_kek_names("encryption-suite-") == ["encryption-suite-team-1"]
        assert len(calls) == 1

    def test_enumeration_is_refused_without_an_owner_prefix(self, monkeypatch):
        prov = _provisioner()
        monkeypatch.setattr(prov, "_api", lambda *a: (_ for _ in ()).throw(AssertionError("no call expected")))

        with pytest.raises(KekEnumerationError):
            prov.list_kek_names(None)


class TestKeyVersion:
    """The key's current material version, recorded on each wrap.

    Advisory only — Infisical resolves the wrapping version from the ciphertext,
    so decrypt never reads it. It exists so ``reencrypt_keys`` can skip rows
    already on current material, and so "is anything still on the retired
    version?" is answerable without unwrapping every row. That matters more here
    than elsewhere: Infisical exposes no way to list or delete individual
    versions, so the database is the only place that answer lives.
    """

    def test_the_version_is_recorded_on_encrypt(self, monkeypatch):
        adapter = _adapter(KEK_TEMPLATE="encryption-suite-{silo_uid}", INFISICAL_PROJECT_ID="proj")
        monkeypatch.setattr(adapter, "_get_key_by_name", lambda name: {"id": _UUID, "version": 2})
        monkeypatch.setattr(adapter, "_request", lambda action, body, key_id: {"ciphertext": "CT"})

        _ct, metadata = adapter.encrypt_key(b"p", SiloRef("default", "team:1"))

        # Stringified: the column is provider-neutral and other providers use
        # non-numeric version identifiers.
        assert metadata.kek_key_version == "2"

    def test_the_version_rides_the_name_lookup(self, monkeypatch):
        # The by-name response carries both the UUID and the version, so a wrap
        # must not pay a second round trip for it.
        adapter = _adapter(KEK_TEMPLATE="encryption-suite-{silo_uid}", INFISICAL_PROJECT_ID="proj")
        lookups = []
        monkeypatch.setattr(
            adapter, "_get_key_by_name", lambda name: lookups.append(name) or {"id": _UUID, "version": 2}
        )
        monkeypatch.setattr(adapter, "_request", lambda action, body, key_id: {"ciphertext": "CT"})

        adapter.encrypt_key(b"p", SiloRef("default", "team:1"))
        adapter.encrypt_key(b"p", SiloRef("default", "team:1"))

        assert len(lookups) == 1

    def test_a_version_nested_under_key_is_read(self, monkeypatch):
        adapter = _adapter(KEK_TEMPLATE="encryption-suite-{silo_uid}", INFISICAL_PROJECT_ID="proj")
        monkeypatch.setattr(adapter, "_get_key_by_name", lambda name: {"key": {"id": _UUID, "version": 7}})
        monkeypatch.setattr(adapter, "_request", lambda action, body, key_id: {"ciphertext": "CT"})

        _ct, metadata = adapter.encrypt_key(b"p", SiloRef("default", "team:1"))

        assert metadata.kek_key_version == "7"

    def test_a_missing_version_degrades_to_unknown(self, monkeypatch):
        # A response without the field must not fail the encrypt: an unknown
        # version makes reencrypt_keys re-wrap every row, which is the safe way
        # to be wrong.
        adapter = _adapter(KEK_TEMPLATE="encryption-suite-{silo_uid}", INFISICAL_PROJECT_ID="proj")
        monkeypatch.setattr(adapter, "_get_key_by_name", lambda name: {"id": _UUID})
        monkeypatch.setattr(adapter, "_request", lambda action, body, key_id: {"ciphertext": "CT"})

        _ct, metadata = adapter.encrypt_key(b"p", SiloRef("default", "team:1"))

        assert metadata.kek_key_version == ""

    def test_a_kek_map_uuid_reports_no_version(self, monkeypatch):
        # Addressed by id, and the by-name endpoint is the only key lookup wired
        # here, so there is nothing to read. Must not attempt a name lookup.
        adapter = _adapter(KEK_MAP={"team:1": _UUID}, INFISICAL_PROJECT_ID="proj")
        monkeypatch.setattr(
            adapter, "_get_key_by_name", lambda name: (_ for _ in ()).throw(AssertionError("no lookup expected"))
        )
        monkeypatch.setattr(adapter, "_request", lambda action, body, key_id: {"ciphertext": "CT"})

        _ct, metadata = adapter.encrypt_key(b"p", SiloRef("default", "team:1"))

        assert metadata.kek_key_version == ""
        assert adapter.current_kek_version(SiloRef("default", "team:1")) == ""

    def test_current_kek_version_reports_the_provider_value(self, monkeypatch):
        adapter = _adapter(KEK_TEMPLATE="encryption-suite-{silo_uid}", INFISICAL_PROJECT_ID="proj")
        monkeypatch.setattr(adapter, "_get_key_by_name", lambda name: {"id": _UUID, "version": 3})

        assert adapter.current_kek_version(SiloRef("default", "team:1")) == "3"

    def test_a_rotation_is_noticed_once_the_ttl_expires(self, monkeypatch):
        # The whole point of the short TTL: a rotation bumps the version while
        # leaving the name and UUID alone, so a permanent cache would keep
        # stamping rows with material the provider has moved past.
        adapter = _adapter(
            KEK_TEMPLATE="encryption-suite-{silo_uid}",
            INFISICAL_PROJECT_ID="proj",
            KEY_VERSION_TTL_SECONDS=0,
        )
        versions = iter([{"id": _UUID, "version": 1}, {"id": _UUID, "version": 2}])
        monkeypatch.setattr(adapter, "_get_key_by_name", lambda name: next(versions))

        assert adapter.current_kek_version(SiloRef("default", "team:1")) == "1"
        assert adapter.current_kek_version(SiloRef("default", "team:1")) == "2"

    def test_a_lookup_failure_does_not_fail_the_encrypt(self, monkeypatch):
        # The reachable shape: the UUID is already cached from an earlier wrap, so
        # encrypt needs no name lookup, but the version TTL has expired and the
        # refresh fails. The version is an optimization, so losing it must not
        # cost an encrypt.
        adapter = _adapter(
            KEK_TEMPLATE="encryption-suite-{silo_uid}",
            INFISICAL_PROJECT_ID="proj",
            KEY_VERSION_TTL_SECONDS=0,
        )
        adapter._name_to_id["encryption-suite-teamz3a1"] = _UUID
        monkeypatch.setattr(adapter, "_request", lambda action, body, key_id: {"ciphertext": "CT"})
        monkeypatch.setattr(adapter, "_get_key_by_name", lambda name: (_ for _ in ()).throw(_http_500()))

        ciphertext, metadata = adapter.encrypt_key(b"p", SiloRef("default", "team:1"))

        assert ciphertext == b"CT"
        assert metadata.kek_key_version == ""


class TestStaleKeyIdRecovery:
    """A key recreated under the same name gets a new UUID; the cache must heal.

    Infisical addresses crypto by UUID and deletes immediately with no waiting
    period, so a name can be freed and re-provisioned within seconds while a
    running process still holds the dead UUID. Reproduced live 2026-08-03 by
    deleting the admin test console's keys and re-running its tests without
    restarting the app — the console's sentinel names are fixed, so they are
    always reused.
    """

    def _adapter_with_cached_id(self, monkeypatch, stale=_UUID, fresh=_UUID2):
        adapter = _adapter(KEK_TEMPLATE="encryption-suite-{silo_uid}", INFISICAL_PROJECT_ID="proj")
        # Primed as if an earlier wrap had resolved the name, then the key was
        # deleted and recreated behind this process's back.
        adapter._name_to_id["encryption-suite-teamz3a1"] = stale
        monkeypatch.setattr(adapter, "_get_key_by_name", lambda name: {"id": fresh, "version": 1})
        return adapter

    def test_encrypt_re_resolves_and_retries_once(self, monkeypatch):
        adapter = self._adapter_with_cached_id(monkeypatch)
        seen = []

        def fake_request(action, body, key_id):
            seen.append(key_id)
            if key_id == _UUID:
                raise _http_404()
            return {"ciphertext": "CT"}

        monkeypatch.setattr(adapter, "_request", fake_request)

        ciphertext, metadata = adapter.encrypt_key(b"p", SiloRef("default", "team:1"))

        assert ciphertext == b"CT"
        assert seen == [_UUID, _UUID2]
        # The refreshed UUID replaces the dead one, so the next call is direct.
        assert adapter._name_to_id["encryption-suite-teamz3a1"] == _UUID2
        assert metadata.kek_resource_name == "encryption-suite-teamz3a1"

    def test_decrypt_re_resolves_and_retries_once(self, monkeypatch):
        adapter = self._adapter_with_cached_id(monkeypatch)
        seen = []

        def fake_request(action, body, key_id):
            seen.append(key_id)
            if key_id == _UUID:
                raise _http_404()
            return {"plaintext": base64.b64encode(b"plain").decode()}

        monkeypatch.setattr(adapter, "_request", fake_request)

        metadata = KmsMetadata(kek_resource_name="encryption-suite-teamz3a1", kms_provider="infisical")

        assert adapter.decrypt_key(b"CT", metadata, SiloRef("default", "team:1")) == b"plain"
        assert seen == [_UUID, _UUID2]

    def test_the_retry_happens_at_most_once(self, monkeypatch):
        # A key that is genuinely gone must not spin: two attempts, then the
        # error propagates.
        adapter = self._adapter_with_cached_id(monkeypatch)
        seen = []

        def always_404(action, body, key_id):
            seen.append(key_id)
            raise _http_404()

        monkeypatch.setattr(adapter, "_request", always_404)

        with pytest.raises(urllib.error.HTTPError) as excinfo:
            adapter.encrypt_key(b"p", SiloRef("default", "team:1"))

        assert excinfo.value.code == 404
        assert len(seen) == 2

    def test_a_non_404_is_not_retried(self, monkeypatch):
        # Only a 404 distinguishes "stale cache" from "provider trouble".
        adapter = self._adapter_with_cached_id(monkeypatch)
        seen = []

        def always_500(action, body, key_id):
            seen.append(key_id)
            raise _http_500()

        monkeypatch.setattr(adapter, "_request", always_500)

        with pytest.raises(urllib.error.HTTPError) as excinfo:
            adapter.encrypt_key(b"p", SiloRef("default", "team:1"))

        assert excinfo.value.code == 500
        assert len(seen) == 1

    def test_a_kek_map_uuid_is_not_re_resolved(self, monkeypatch):
        # A UUID was never resolved from a name, so there is nothing stale to
        # drop and a 404 means exactly what it says.
        adapter = _adapter(KEK_MAP={"team:1": _UUID}, INFISICAL_PROJECT_ID="proj")
        seen = []

        def always_404(action, body, key_id):
            seen.append(key_id)
            raise _http_404()

        monkeypatch.setattr(adapter, "_request", always_404)
        monkeypatch.setattr(
            adapter, "_get_key_by_name", lambda name: (_ for _ in ()).throw(AssertionError("no lookup expected"))
        )

        with pytest.raises(urllib.error.HTTPError):
            adapter.encrypt_key(b"p", SiloRef("default", "team:1"))

        assert len(seen) == 1

    def test_no_extra_calls_on_the_healthy_path(self, monkeypatch):
        # The whole point: a cached UUID costs a dict lookup, not a round trip.
        adapter = self._adapter_with_cached_id(monkeypatch)
        monkeypatch.setattr(
            adapter, "_get_key_by_name", lambda name: (_ for _ in ()).throw(AssertionError("no lookup expected"))
        )
        seen = []

        def fake_request(action, body, key_id):
            seen.append(key_id)
            return {"ciphertext": "CT"}

        monkeypatch.setattr(adapter, "_request", fake_request)

        adapter.encrypt_key(b"p", SiloRef("default", "team:1"))
        adapter.encrypt_key(b"p", SiloRef("default", "team:1"))

        assert seen == [_UUID, _UUID]
