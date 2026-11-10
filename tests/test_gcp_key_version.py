"""Cloud KMS key versions: recorded on wrap, and read back to skip rewraps.

Cloud KMS names the version it used in the encrypt response. Unlike Azure the
version is not needed to unwrap — a Cloud KMS ciphertext carries its own version
and symmetric decrypt takes the key path — so it is recorded so operators can
tell which rows still sit on an old version, and so ``reencrypt_keys`` can skip
rows already on the primary.
"""

from __future__ import annotations

import base64

import pytest

from encryption_suite.adapters.keks.strategies import PerSiloKekStrategy
from encryption_suite.adapters.key_stores.gcp import GcpKmsAdapter, _version_from_resource
from encryption_suite.silo_ref import SiloRef

_RING = "projects/p/locations/us-central1/keyRings/r"
_KEY = f"{_RING}/cryptoKeys/es-prod-team-1"
_OPTIONS = {
    "GCP_PROJECT_ID": "p",
    "GCP_KMS_LOCATION": "us-central1",
    "GCP_KMS_KEY_RING": "r",
    "KEK_TEMPLATE": "es-prod-{silo_uid}",
}


def _adapter(**overrides):
    options = {**_OPTIONS, **overrides}
    return GcpKmsAdapter(options, GcpKmsAdapter.build_strategy(PerSiloKekStrategy, options))


class _Recorder:
    """Stands in for ``_request``, recording calls and replaying canned bodies."""

    def __init__(self, *responses):
        self.responses = list(responses)
        self.calls = []

    def __call__(self, url, body=None):
        self.calls.append((url, body))
        return self.responses.pop(0) if len(self.responses) > 1 else self.responses[0]


class TestVersionFromResource:
    def test_trailing_version_id(self):
        assert _version_from_resource(f"{_KEY}/cryptoKeyVersions/3") == "3"

    @pytest.mark.parametrize("value", ["", _KEY, "nonsense"])
    def test_anything_without_a_version_yields_empty(self, value):
        # A guessed version would be worse than none: it would let a rewrap be
        # skipped on the strength of a value nothing verified.
        assert _version_from_resource(value) == ""


class TestEncryptRecordsTheVersion:
    def test_version_from_the_encrypt_response(self):
        adapter = _adapter()
        adapter._request = _Recorder(
            {
                "ciphertext": base64.b64encode(b"wrapped").decode(),
                "name": f"{_KEY}/cryptoKeyVersions/7",
            }
        )

        ciphertext, metadata = adapter.encrypt_key(b"keyset", SiloRef("default", "team-1"))

        assert ciphertext == b"wrapped"
        assert metadata.kek_resource_name == _KEY
        assert metadata.kek_key_version == "7"

    def test_a_response_without_a_name_records_no_version(self):
        # Degrades to the pre-change behavior — every row rewrapped — rather
        # than failing a wrap over a field that only informs an optimization.
        adapter = _adapter()
        adapter._request = _Recorder({"ciphertext": base64.b64encode(b"wrapped").decode()})

        _, metadata = adapter.encrypt_key(b"keyset", SiloRef("default", "team-1"))

        assert metadata.kek_key_version == ""


class TestCurrentKekVersion:
    def test_reports_the_keys_primary_version(self):
        adapter = _adapter()
        recorder = _Recorder({"primary": {"name": f"{_KEY}/cryptoKeyVersions/4"}})
        adapter._request = recorder

        assert adapter.current_kek_version(SiloRef("default", "team-1")) == "4"
        assert recorder.calls == [(f"https://cloudkms.googleapis.com/v1/{_KEY}", None)]

    def test_a_key_with_no_primary_yields_empty(self):
        # Asymmetric keys have no primary version. The caller treats "" as
        # "cannot tell", which means rewrap — safe.
        adapter = _adapter()
        adapter._request = _Recorder({})

        assert adapter.current_kek_version(SiloRef("default", "team-1")) == ""

    def test_repeat_lookups_are_cached(self):
        # Re-encrypting a whole deployment asks once per row; without the cache
        # that is a KMS round trip per row just to decide whether to skip it.
        adapter = _adapter()
        recorder = _Recorder({"primary": {"name": f"{_KEY}/cryptoKeyVersions/4"}})
        adapter._request = recorder

        assert [adapter.current_kek_version(SiloRef("default", "team-1")) for _ in range(3)] == ["4", "4", "4"]
        assert len(recorder.calls) == 1

    def test_the_cache_expires(self):
        # Rotation moves the primary, and a worker that never looked again would
        # keep reporting the version before the rotation.
        adapter = _adapter(KEY_VERSION_TTL_SECONDS=0)
        recorder = _Recorder(
            {"primary": {"name": f"{_KEY}/cryptoKeyVersions/4"}},
            {"primary": {"name": f"{_KEY}/cryptoKeyVersions/5"}},
        )
        adapter._request = recorder

        assert adapter.current_kek_version(SiloRef("default", "team-1")) == "4"
        assert adapter.current_kek_version(SiloRef("default", "team-1")) == "5"

    def test_each_silo_is_cached_separately(self):
        adapter = _adapter()
        recorder = _Recorder(
            {"primary": {"name": f"{_KEY}/cryptoKeyVersions/4"}},
            {"primary": {"name": f"{_RING}/cryptoKeys/es-prod-team-2/cryptoKeyVersions/9"}},
        )
        adapter._request = recorder

        assert adapter.current_kek_version(SiloRef("default", "team-1")) == "4"
        assert adapter.current_kek_version(SiloRef("default", "team-2")) == "9"
