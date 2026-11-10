"""
GCP Cloud KMS adapter.

Requires the ``gcp`` extra: ``pip install django-encryption-suite[gcp]``

Each silo gets its own Cloud KMS key within the configured key ring,
resolved via ``KEK_TEMPLATE`` or ``KEK_MAP`` in ``OPTIONS``.  The
template value is the key **name** only — the project, location, and key ring
are taken from their own options.

Example: ``KEK_TEMPLATE = {"scoped": "encryption_suite-{silo_uid}"}`` resolves to
``projects/P/locations/L/keyRings/R/cryptoKeys/encryption_suite-team-42``.

Credential strategy is selected via OPTIONS['CREDENTIAL_STRATEGY']:
  "oidc"                — GcpWorkloadIdentityStrategy (OIDC token source
                          selected via the required OIDC_SOURCE option)
  "adc"                 — GcpAdcStrategy
  "service_account_key" — GcpServiceAccountKeyStrategy

If CREDENTIAL_STRATEGY is not set, the adapter defaults to ``adc``. The
``oidc`` strategy must be opted into explicitly along with an OIDC_SOURCE.

See ``adapters.credentials.gcp`` and ``adapters.credentials.oidc_sources``
for strategy details and required options.

Required OPTIONS keys (all strategies):
  GCP_PROJECT_ID    : str   e.g. "my-project"
  GCP_KMS_LOCATION  : str   e.g. "global" or "us-central1"
  GCP_KMS_KEY_RING  : str
  KEK_TEMPLATE      : str   e.g. "encryption_suite-{silo_uid}"
                              (or KEK_MAP for explicit mapping)

Optional:
  KEY_VERSION_TTL_SECONDS : int  default 300. How long the key's primary
                              version is cached when answering "would a new wrap
                              use a different version than this row records?"
"""

from __future__ import annotations

import base64
import json
import threading
import time

from ..._logging import get_logger
from ...exceptions import log_and_raise_configuration_error
from .._http import urlopen_with_detail
from ..credentials.gcp import GcpAdcStrategy, GcpServiceAccountKeyStrategy, GcpWorkloadIdentityStrategy
from ..credentials.oidc_sources import build_oidc_source
from .base import AbstractKmsAdapter, KmsMetadata

logger = get_logger(__name__)

_PROVIDER = "gcp"

_DEFAULT_KEY_VERSION_TTL_SECONDS = 300


def _version_from_resource(resource: str) -> str:
    """Return the trailing version id of a CryptoKeyVersion resource path.

    ``.../cryptoKeys/K/cryptoKeyVersions/3`` yields ``"3"``. Anything else —
    an absent field, a key path with no version — yields ``""``, because a
    version this function had to guess at would be worse than none.
    """
    marker = "/cryptoKeyVersions/"
    if marker not in resource:
        return ""
    return resource.rsplit(marker, 1)[-1]


class GcpKmsAdapter(AbstractKmsAdapter):
    """
    GCP Cloud KMS adapter.

    Delegates authentication entirely to the configured credential strategy.
    Key encryption and decryption operations call the Cloud KMS REST API
    directly using the bearer token returned by the strategy.
    """

    kms_provider = _PROVIDER
    _INSTANCE_OPTION_KEYS = ("GCP_KMS_KEY_RING", "GCP_KMS_LOCATION", "GCP_PROJECT_ID")
    _REQUIRED_OPTION_KEYS = ("GCP_PROJECT_ID", "GCP_KMS_LOCATION", "GCP_KMS_KEY_RING")

    def __init__(self, options: dict, kek_strategy) -> None:
        super().__init__(options, kek_strategy)
        self._strategy = self._build_strategy(options, self._ssl_context)
        self._primary_versions: dict[str, tuple[str, float]] = {}
        self._version_lock = threading.Lock()

    @staticmethod
    def _build_strategy(options: dict, ssl_context=None):
        strategy_name = options.get("CREDENTIAL_STRATEGY", "adc")
        if strategy_name == "oidc":
            source_name = options.get("OIDC_SOURCE")
            if not source_name:
                log_and_raise_configuration_error(logger, "CREDENTIAL_STRATEGY='oidc' requires OIDC_SOURCE in OPTIONS.")
            source = build_oidc_source(source_name, options.get("OIDC_SOURCE_OPTIONS", {}))
            return GcpWorkloadIdentityStrategy(options, source, ssl_context=ssl_context)
        elif strategy_name == "adc":
            return GcpAdcStrategy()
        elif strategy_name == "service_account_key":
            return GcpServiceAccountKeyStrategy(options)
        else:
            log_and_raise_configuration_error(
                logger, f"Unknown CREDENTIAL_STRATEGY '{strategy_name}'. Valid options: oidc, adc, service_account_key"
            )

    def _kek_resource_name(self, key_name: str) -> str:
        return f"{self._configured_ring()}/cryptoKeys/{key_name}"

    def _configured_ring(self) -> str:
        o = self.options
        return f"projects/{o['GCP_PROJECT_ID']}/locations/{o['GCP_KMS_LOCATION']}/keyRings/{o['GCP_KMS_KEY_RING']}"

    def canonical_kek_name(self, kek_id: str) -> str:
        # Cloud KMS keys are recorded as the full resource path, so a bare
        # template-resolved name is qualified with the configured ring. A
        # KEK_MAP entry that is already a full path is left alone, which also
        # makes this idempotent.
        if kek_id.startswith("projects/"):
            return kek_id
        return self._kek_resource_name(kek_id)

    def kek_resource_mismatch_hint(self, stored_resource_name: str) -> str | None:
        # A rotated/renamed key in the same ring still starts with
        # "<ring>/cryptoKeys/...", so only a different project, location, or
        # key ring trips this. Names that are not in the structured GCP form
        # (e.g. a bare key name on an encrypt-side log) are left alone.
        configured = self._configured_ring()
        if stored_resource_name.startswith("projects/") and not stored_resource_name.startswith(configured + "/"):
            stored_ring = stored_resource_name.rsplit("/cryptoKeys/", 1)[0]
            return f"stored KEK is in '{stored_ring}', but this adapter is configured for '{configured}'"
        return None

    def _request(self, url: str, body: bytes | None = None) -> dict:
        """Call *url* with a bearer token, retry once on 401.

        POSTs *body* when given, GETs when it is ``None`` — urllib chooses the
        method from whether there is data to send.
        """
        import urllib.error
        import urllib.request

        def _do(token: str) -> dict:
            req = urllib.request.Request(
                url,
                data=body,
                headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            )
            with urlopen_with_detail(req, timeout=self._request_timeout, context=self._ssl_context) as resp:
                return json.loads(resp.read())

        try:
            result = _do(self._strategy.get_credentials())
            self._clear_auth_retry_block()
            return result
        except urllib.error.HTTPError as exc:
            if exc.code == 401:
                if self._is_auth_retry_blocked():
                    raise
                logger.warning(
                    "The call was rejected as unauthenticated, so credentials are being refreshed "
                    "and the call retried once. http_status=401",
                )
                if hasattr(self._strategy, "_cache"):
                    self._strategy._cache.invalidate()
                try:
                    result = _do(self._strategy.get_credentials())
                    self._clear_auth_retry_block()
                    return result
                except urllib.error.HTTPError:
                    self._record_auth_retry_failure()
                    raise
            raise

    def encrypt_key(self, plaintext: bytes, silo_ref: str) -> tuple[bytes, KmsMetadata]:
        key_name = self._resolve_kek_id(silo_ref)
        resource = self._kek_resource_name(key_name)
        url = f"https://cloudkms.googleapis.com/v1/{resource}:encrypt"
        aad = self._wrap_aad(silo_ref)
        body = json.dumps(
            {
                "plaintext": base64.b64encode(plaintext).decode(),
                "additionalAuthenticatedData": base64.b64encode(aad).decode(),
            }
        ).encode()
        result = self._request(url, body)
        ciphertext = base64.b64decode(result["ciphertext"])
        return ciphertext, KmsMetadata(
            kek_resource_name=resource,
            kms_provider=_PROVIDER,
            # Cloud KMS names the version it used in the encrypt response.
            # Unlike Azure this is not needed to unwrap — a Cloud KMS ciphertext
            # carries its own version and symmetric decrypt takes the key path,
            # not a version path — so it is recorded for operators: which rows
            # still sit on a version, and so `reencrypt_keys` can skip rows
            # already on the primary.
            kek_key_version=_version_from_resource(result.get("name", "")),
        )

    def current_kek_version(self, silo_ref: str) -> str:
        """The version a new wrap for *silo_ref* would use: the key's primary.

        Cached briefly rather than for the process lifetime: rotation moves the
        primary, and a worker that never looked again would keep reporting the
        old one. Returns ``""`` when the key has no primary version, which is
        every asymmetric key — the caller then treats the row as needing a
        rewrap, which is safe.
        """
        resource = self._kek_resource_name(self._resolve_kek_id(silo_ref))
        ttl = float(self.options.get("KEY_VERSION_TTL_SECONDS", _DEFAULT_KEY_VERSION_TTL_SECONDS))
        cached = self._primary_versions.get(resource)
        if cached is not None and (time.monotonic() - cached[1]) < ttl:
            return cached[0]

        key = self._request(f"https://cloudkms.googleapis.com/v1/{resource}")
        version = _version_from_resource((key.get("primary") or {}).get("name", ""))
        with self._version_lock:
            self._primary_versions[resource] = (version, time.monotonic())
        return version

    def decrypt_key(
        self,
        ciphertext: bytes,
        metadata: KmsMetadata,
        silo_ref: str,
    ) -> bytes:
        # metadata.kek_resource_name is the full resource path stored during encrypt_key.
        resource = metadata.kek_resource_name
        url = f"https://cloudkms.googleapis.com/v1/{resource}:decrypt"
        aad = self._wrap_aad(silo_ref)
        body = json.dumps(
            {
                "ciphertext": base64.b64encode(ciphertext).decode(),
                "additionalAuthenticatedData": base64.b64encode(aad).decode(),
            }
        ).encode()
        result = self._request(url, body)
        return base64.b64decode(result["plaintext"])

    def describe_kek(self) -> str:
        ring = self._configured_ring()
        template = self.options.get("KEK_TEMPLATE", "")
        if template:
            return f"GCP Cloud KMS keys: {ring}/cryptoKeys/{template}"
        return f"GCP Cloud KMS key ring: {ring}"
