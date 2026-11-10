"""Tests for the IBM Key Protect adapter's name space, versioning and resolution.

Key Protect addresses keys by UUID, not by the human-readable name that
``KEK_TEMPLATE`` produces, so the adapter resolves name->UUID before wrap/unwrap
and the provisioner checks existence by listing (not by a name GET, which always
404s and would otherwise recreate duplicates). Rows record the *name*, because a
server-assigned UUID has no owner prefix to compare against.
"""

from __future__ import annotations

import json
import urllib.error
from unittest.mock import patch

import pytest

from encryption_suite.adapters.keks.provisioners_ibm import IbmKekProvisioner
from encryption_suite.adapters.keks.strategies import PerSiloKekStrategy
from encryption_suite.adapters.key_stores.ibm import (
    IbmKmsAdapter,
    _looks_like_uuid,
    find_key_by_name,
    is_deleted,
    key_name,
    version_id,
)
from encryption_suite.exceptions import EncryptionConfigurationError
from encryption_suite.silo_ref import SiloRef

_UUID = "53008d3e-8fa4-4de3-be83-836c3376773f"
_OTHER_UUID = "11111111-2222-3333-4444-555555555555"
_VERSION = "02fd6835-6001-4482-a892-13bd2085f75d"


def _resp(payload: dict):
    class _CM:
        def __enter__(self_inner):
            return self_inner

        def __exit__(self_inner, *exc):
            return False

        def read(self_inner):
            return json.dumps(payload).encode()

    return _CM()


def _http_error(code: int) -> urllib.error.HTTPError:
    return urllib.error.HTTPError("https://x", code, "boom", {}, None)


def _list_page(*keys, total: int | None = None):
    return {"metadata": {"collectionTotal": len(keys) if total is None else total}, "resources": list(keys)}


def _key(name: str, key_id: str = _UUID, **extra):
    return {"name": name, "id": key_id, **extra}


# ---------------------------------------------------------------------------
# find_key_by_name
# ---------------------------------------------------------------------------


def test_resolves_name_across_pages():
    pages = [
        _list_page(*[_key("other", "x")] * 200, total=400),
        _list_page(_key("wanted"), total=400),
    ]

    def _get(path):
        return pages[0] if "offset=0" in path else pages[1]

    assert find_key_by_name(_get, "wanted")["id"] == _UUID


def test_missing_name_returns_none():
    def _get(_path):
        return _list_page(_key("other", "x"))

    assert find_key_by_name(_get, "absent") is None


def test_deleted_key_is_not_resolved():
    """A deleted key stays listed for 30 days; resolving to it would wrap nothing."""

    def _get(_path):
        return _list_page(_key("wanted", deleted=True))

    assert find_key_by_name(_get, "wanted") is None


def test_a_recreated_name_resolves_to_the_live_key():
    # The deleted one is listed first, which is what a naive first-match would take.
    def _get(_path):
        return _list_page(_key("wanted", _OTHER_UUID, deleted=True), _key("wanted", _UUID))

    assert find_key_by_name(_get, "wanted")["id"] == _UUID


def test_destroyed_state_counts_as_deleted_without_the_flag():
    # 24 hours after deletion the key reaches state 5; older responses may report
    # only that, so the state is read as well as the flag.
    assert is_deleted({"state": 5})
    assert is_deleted({"deleted": True})
    assert not is_deleted({"state": 1})
    assert not is_deleted({})


def test_looks_like_uuid():
    assert _looks_like_uuid(_UUID)
    assert not _looks_like_uuid("encryption_suite-team1")


def test_key_name_reduces_a_resource_url():
    assert key_name(f"https://us-east.kms.cloud.ibm.com/api/v2/keys/{_UUID}") == _UUID
    assert key_name("encryption_suite-team1") == "encryption_suite-team1"


def test_version_id_reads_both_envelopes():
    assert version_id({"keyVersion": {"id": _VERSION}}) == _VERSION
    assert version_id({}) == ""
    assert version_id({"keyVersion": None}) == ""


# ---------------------------------------------------------------------------
# IbmKmsAdapter — wrap/unwrap address by UUID, rows record the name
# ---------------------------------------------------------------------------


_OPTS = {
    "IBM_INSTANCE_ID": "inst-1",
    "IBM_REGION": "us-east",
    "IBM_API_KEY": "k",
    "KEK_TEMPLATE": "encryption_suite-{silo_uid}",
}


def _adapter(**overrides):
    opts = {**_OPTS, **overrides}
    return IbmKmsAdapter(opts, IbmKmsAdapter.build_strategy(PerSiloKekStrategy, opts))


class _Provider:
    """A stand-in Key Protect that records calls and serves one live key."""

    def __init__(self, *, keys=None, wrap_version=_VERSION, stale_status=410):
        self.keys = [_key("encryption_suite-team1")] if keys is None else keys
        self.wrap_version = wrap_version
        # 410 is what Key Protect actually returns for a soft-deleted key; 404 is
        # the purged/absent case. Both must drive the same recovery.
        self.stale_status = stale_status
        self.lists = 0
        self.gets = 0
        self.wrap_urls: list[str] = []
        self.unwrap_urls: list[str] = []
        self.stale_uuids: set[str] = set()

    def __call__(self, req, timeout, context=None):
        url = req.full_url
        method = req.get_method()
        if "identity/token" in url:
            return _resp({"access_token": "t", "expires_in": 3600})
        if "/actions/wrap" in url:
            self.wrap_urls.append(url)
            self._reject_if_stale(url)
            return _resp({"ciphertext": "CIPHER", "keyVersion": {"id": self.wrap_version}})
        if "/actions/unwrap" in url:
            self.unwrap_urls.append(url)
            self._reject_if_stale(url)
            return _resp({"plaintext": "ZGVr"})
        if "/api/v2/keys?" in url and method == "GET":
            self.lists += 1
            return _resp(_list_page(*self.keys))
        if "/api/v2/keys/" in url and method == "GET":
            self.gets += 1
            key_id = url.rsplit("/", 1)[-1]
            match = [k for k in self.keys if k["id"] == key_id]
            if not match:
                raise _http_error(404)
            return _resp(_list_page(match[0]))
        raise AssertionError(f"unexpected {method} {url}")

    def _reject_if_stale(self, url: str) -> None:
        if any(stale in url for stale in self.stale_uuids):
            raise _http_error(self.stale_status)


def test_encrypt_resolves_name_and_wraps_by_uuid():
    provider = _Provider()
    adapter = _adapter()
    with patch("urllib.request.urlopen", side_effect=provider):
        ct, meta = adapter.encrypt_key(b"dek", SiloRef("default", "team1"))

    assert ct == b"CIPHER"
    assert f"/keys/{_UUID}/actions/wrap" in provider.wrap_urls[0]


def test_the_row_records_the_key_name_not_its_uuid():
    """The owner prefix is a name prefix, so a UUID on the row matches nothing."""
    provider = _Provider()
    adapter = _adapter()
    with patch("urllib.request.urlopen", side_effect=provider):
        _, meta = adapter.encrypt_key(b"dek", SiloRef("default", "team1"))

    assert meta.kek_resource_name == "encryption_suite-team1"
    assert meta.kek_resource_name.startswith(adapter.owner_prefix())


def test_canonical_name_is_prefix_preserving():
    adapter = _adapter()

    assert adapter.canonical_kek_name("encryption_suite-") == "encryption_suite-"
    assert adapter.resolve_kek_name(SiloRef("default", "team1")) == "encryption_suite-team1"


def test_encrypt_records_the_version_the_wrap_reported():
    provider = _Provider()
    with patch("urllib.request.urlopen", side_effect=provider):
        _, meta = _adapter().encrypt_key(b"dek", SiloRef("default", "team1"))

    assert meta.kek_key_version == _VERSION


def test_a_wrap_without_a_version_records_an_empty_one():
    provider = _Provider(wrap_version="")
    with patch("urllib.request.urlopen", side_effect=provider):
        _, meta = _adapter().encrypt_key(b"dek", SiloRef("default", "team1"))

    # Empty means "unknown", which makes reencrypt_keys re-wrap rather than skip —
    # the safe direction.
    assert meta.kek_key_version == ""


def test_resolution_is_cached_across_calls():
    provider = _Provider()
    adapter = _adapter()
    with patch("urllib.request.urlopen", side_effect=provider):
        adapter.encrypt_key(b"a", SiloRef("default", "team1"))
        adapter.encrypt_key(b"b", SiloRef("default", "team1"))

    assert provider.lists == 1  # second encrypt uses the cached UUID


def test_decrypt_reads_a_legacy_resource_url():
    """Rows written before the adapter recorded names still unwrap."""
    from encryption_suite.adapters.key_stores.base import KmsMetadata

    provider = _Provider()
    metadata = KmsMetadata(
        kek_resource_name=f"https://us-east.kms.cloud.ibm.com/api/v2/keys/{_UUID}",
        kms_provider="ibm",
    )
    with patch("urllib.request.urlopen", side_effect=provider):
        plaintext = _adapter().decrypt_key(b"CIPHER", metadata, SiloRef("default", "team1"))

    assert plaintext == b"dek"
    # Addressed by the UUID straight from the URL — no listing needed.
    assert provider.lists == 0
    assert f"/keys/{_UUID}/actions/unwrap" in provider.unwrap_urls[0]


def test_an_over_long_name_is_refused_with_the_provider_limit():
    """Key Protect refuses a name outside 2-90 characters; say so before it does."""
    adapter = _adapter()

    with pytest.raises(EncryptionConfigurationError) as exc_info:
        adapter.resolve_kek_name(SiloRef("default", "t" * 100))
    assert "90-character limit" in exc_info.value.detail


# ---------------------------------------------------------------------------
# Key version reads
# ---------------------------------------------------------------------------


def test_current_version_comes_from_the_resolution_listing():
    provider = _Provider(keys=[_key("encryption_suite-team1", keyVersion={"id": _VERSION})])
    with patch("urllib.request.urlopen", side_effect=provider):
        version = _adapter().current_kek_version(SiloRef("default", "team1"))

    assert version == _VERSION
    # The listing already carried it, so no second lookup by id.
    assert provider.gets == 0


def test_current_version_falls_back_to_the_key_metadata():
    # A listing that omits keyVersion leaves the cache holding "", so the id
    # lookup is what answers.
    provider = _Provider(keys=[_key("encryption_suite-team1")])
    provider.keys[0].pop("keyVersion", None)
    adapter = _adapter()
    with patch("urllib.request.urlopen", side_effect=provider):
        adapter._forget_key("encryption_suite-team1")
        provider.keys[0]["keyVersion"] = {"id": _VERSION}
        # Resolution caches "" off the listing only when the field is absent at
        # that moment; here it is present by the time the id lookup runs.
        version = adapter.current_kek_version(SiloRef("default", "team1"))

    assert version == _VERSION


def test_a_failed_version_lookup_degrades_to_empty():
    def _fake(req, timeout, context=None):
        if "identity/token" in req.full_url:
            return _resp({"access_token": "t", "expires_in": 3600})
        raise _http_error(500)

    with patch("urllib.request.urlopen", side_effect=_fake):
        assert _adapter().current_kek_version(SiloRef("default", "team1")) == ""


def test_the_version_cache_expires():
    provider = _Provider(keys=[_key("encryption_suite-team1", keyVersion={"id": _VERSION})])
    adapter = _adapter(KEY_VERSION_TTL_SECONDS=0)
    with patch("urllib.request.urlopen", side_effect=provider):
        adapter.current_kek_version(SiloRef("default", "team1"))
        first = provider.lists
        provider.keys[0]["keyVersion"] = {"id": "rotated"}
        # A zero TTL expires the cached version, but the UUID cache is permanent,
        # so the re-read is the metadata GET rather than another listing.
        assert adapter.current_kek_version(SiloRef("default", "team1")) == "rotated"

    assert provider.lists == first
    assert provider.gets >= 1


def test_the_wrap_response_refreshes_the_cached_version():
    provider = _Provider(keys=[_key("encryption_suite-team1", keyVersion={"id": "stale"})], wrap_version=_VERSION)
    adapter = _adapter()
    with patch("urllib.request.urlopen", side_effect=provider):
        adapter.encrypt_key(b"dek", SiloRef("default", "team1"))
        # The wrap is authoritative about which version it used, so it wins over
        # the version the listing reported.
        assert adapter.current_kek_version(SiloRef("default", "team1")) == _VERSION


# ---------------------------------------------------------------------------
# Stale name->UUID recovery
# ---------------------------------------------------------------------------


class TestStaleKeyIdRecovery:
    """A key recreated under the same name gets a new UUID; the cache must notice."""

    @pytest.mark.parametrize("status", [410, 404])
    def test_a_stale_uuid_re_resolves_and_retries_once(self, status):
        """410 is the live case — Key Protect soft-deletes, so the dead UUID still
        exists and wrapping with it is *Gone* rather than *Not Found*. 404 covers a
        purged key. Observed live 2026-08-03: only 410 ever occurred, and handling
        404 alone left the recovery dead code."""
        provider = _Provider(stale_status=status)
        adapter = _adapter()
        with patch("urllib.request.urlopen", side_effect=provider):
            adapter.encrypt_key(b"dek", SiloRef("default", "team1"))
            # The key is deleted and recreated: same name, new UUID.
            provider.stale_uuids.add(_UUID)
            provider.keys = [_key("encryption_suite-team1", _OTHER_UUID)]
            ct, meta = adapter.encrypt_key(b"dek", SiloRef("default", "team1"))

        assert ct == b"CIPHER"
        assert f"/keys/{_OTHER_UUID}/actions/wrap" in provider.wrap_urls[-1]
        assert meta.kek_resource_name == "encryption_suite-team1"

    def test_unwrap_recovers_too(self):
        """Decrypt runs through the same path, so a reused name must not strand reads."""
        from encryption_suite.adapters.key_stores.base import KmsMetadata

        provider = _Provider()
        adapter = _adapter()
        metadata = KmsMetadata(kek_resource_name="encryption_suite-team1", kms_provider="ibm")
        with patch("urllib.request.urlopen", side_effect=provider):
            adapter.encrypt_key(b"dek", SiloRef("default", "team1"))
            provider.stale_uuids.add(_UUID)
            provider.keys = [_key("encryption_suite-team1", _OTHER_UUID)]
            plaintext = adapter.decrypt_key(b"CIPHER", metadata, SiloRef("default", "team1"))

        assert plaintext == b"dek"
        assert f"/keys/{_OTHER_UUID}/actions/unwrap" in provider.unwrap_urls[-1]

    def test_the_retry_does_not_loop(self):
        """A name that is genuinely gone fails after exactly one retry."""
        provider = _Provider()
        adapter = _adapter()
        with patch("urllib.request.urlopen", side_effect=provider):
            adapter.encrypt_key(b"dek", SiloRef("default", "team1"))
            provider.stale_uuids.add(_UUID)
            before = len(provider.wrap_urls)
            with pytest.raises(urllib.error.HTTPError):
                adapter.encrypt_key(b"dek", SiloRef("default", "team1"))

        assert len(provider.wrap_urls) - before == 2

    def test_an_unrelated_status_is_not_retried(self):
        calls = {"wrap": 0}

        def _fake(req, timeout, context=None):
            url = req.full_url
            if "identity/token" in url:
                return _resp({"access_token": "t", "expires_in": 3600})
            if "/actions/wrap" in url:
                calls["wrap"] += 1
                raise _http_error(500)
            return _resp(_list_page(_key("encryption_suite-team1")))

        with patch("urllib.request.urlopen", side_effect=_fake):
            with pytest.raises(urllib.error.HTTPError):
                _adapter().encrypt_key(b"dek", SiloRef("default", "team1"))

        assert calls["wrap"] == 1

    def test_a_kek_map_uuid_is_never_re_resolved(self):
        """Nothing was resolved from a name, so a 404 means what it says."""
        calls = {"wrap": 0, "list": 0}

        def _fake(req, timeout, context=None):
            url = req.full_url
            if "identity/token" in url:
                return _resp({"access_token": "t", "expires_in": 3600})
            if "/actions/wrap" in url:
                calls["wrap"] += 1
                raise _http_error(404)
            calls["list"] += 1
            return _resp(_list_page())

        opts = {**_OPTS, "KEK_MAP": {"team1": _UUID}}
        del opts["KEK_TEMPLATE"]
        adapter = IbmKmsAdapter(opts, IbmKmsAdapter.build_strategy(PerSiloKekStrategy, opts))
        with patch("urllib.request.urlopen", side_effect=_fake):
            with pytest.raises(urllib.error.HTTPError):
                adapter.encrypt_key(b"dek", SiloRef("default", "team1"))

        assert calls["wrap"] == 1
        assert calls["list"] == 0

    def test_the_healthy_path_costs_no_extra_calls(self):
        provider = _Provider()
        adapter = _adapter()
        with patch("urllib.request.urlopen", side_effect=provider):
            adapter.encrypt_key(b"a", SiloRef("default", "team1"))
            adapter.encrypt_key(b"b", SiloRef("default", "team1"))

        assert provider.lists == 1
        assert len(provider.wrap_urls) == 2


# ---------------------------------------------------------------------------
# IbmKekProvisioner — list before create (no duplicate keys)
# ---------------------------------------------------------------------------


def _provisioner(**overrides):
    return IbmKekProvisioner({"IBM_INSTANCE_ID": "inst-1", "IBM_REGION": "us-east", "IBM_API_KEY": "k", **overrides})


def test_provisioner_skips_create_when_name_exists():
    posted = []

    def _fake(req, timeout, context=None):
        url = req.full_url
        if "identity/token" in url:
            return _resp({"access_token": "t", "expires_in": 3600})
        if req.get_method() == "POST" and url.endswith("/api/v2/keys"):
            posted.append(url)
            return _resp({})
        if "/api/v2/keys" in url and req.get_method() == "GET":
            return _resp(_list_page(_key("encryption_suite-team1")))
        raise AssertionError(url)

    with patch("urllib.request.urlopen", side_effect=_fake):
        _provisioner().ensure_kek("encryption_suite-team1", SiloRef("default", "team1"))

    assert posted == []  # adopted the existing key, created nothing


def test_provisioner_creates_when_name_absent():
    posted = []

    def _fake(req, timeout, context=None):
        url = req.full_url
        if "identity/token" in url:
            return _resp({"access_token": "t", "expires_in": 3600})
        if req.get_method() == "POST" and url.endswith("/api/v2/keys"):
            posted.append(json.loads(req.data.decode()))
            return _resp(_list_page(_key("encryption_suite-team1")))
        if "/api/v2/keys" in url and req.get_method() == "GET":
            return _resp(_list_page(total=0))
        raise AssertionError(url)

    with patch("urllib.request.urlopen", side_effect=_fake):
        _provisioner().ensure_kek("encryption_suite-team1", SiloRef("default", "team1"))

    assert len(posted) == 1
    assert posted[0]["resources"][0]["name"] == "encryption_suite-team1"


def test_provisioner_recreates_a_name_whose_key_was_deleted():
    """A deleted key keeps its name listed; treating that as present would never
    re-provision, leaving every encrypt for that silo failing."""
    posted = []

    def _fake(req, timeout, context=None):
        url = req.full_url
        if "identity/token" in url:
            return _resp({"access_token": "t", "expires_in": 3600})
        if req.get_method() == "POST" and url.endswith("/api/v2/keys"):
            posted.append(json.loads(req.data.decode()))
            return _resp(_list_page(_key("encryption_suite-team1")))
        if "/api/v2/keys" in url and req.get_method() == "GET":
            return _resp(_list_page(_key("encryption_suite-team1", deleted=True)))
        raise AssertionError(url)

    with patch("urllib.request.urlopen", side_effect=_fake):
        assert _provisioner().ensure_kek("encryption_suite-team1", SiloRef("default", "team1")) is True

    assert len(posted) == 1
