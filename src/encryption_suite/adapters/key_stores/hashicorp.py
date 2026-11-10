"""
HashiCorp Vault adapter.

Uses the Vault Transit secrets engine via the Vault HTTP API (no extra Python
library required — only ``urllib`` from the stdlib).

Each silo gets its own Vault Transit key, resolved via ``KEK_TEMPLATE``
or ``KEK_MAP`` in ``OPTIONS``.  The template value is the Transit key name
(e.g. ``"encryption_suite-{silo_uid}"``).

Rows record the bare Transit key name — the identifier the strategy resolved,
the provisioner lists, and the owner prefix is a prefix of. Earlier rows carry a
``{addr}/{mount}/{name}`` URL, which :meth:`HashiCorpVaultAdapter.decrypt_key`
still reduces; nothing writes that form now. Qualifying the name with the
cluster address would also pin every stored row to an address that can change
without the key changing.

Transit versions its keys: a rotation adds a version and keeps the previous ones
available for decryption. The version used is named in the ciphertext itself
(``vault:v3:...``), so ``kek_key_version`` is recorded with no extra call and is
informational — Transit resolves the decrypting version from the ciphertext.

Credential strategy is selected via OPTIONS['CREDENTIAL_STRATEGY']:
  "token"      (default) — HashiCorpVaultTokenStrategy
  "approle"               — HashiCorpVaultAppRoleStrategy (requires VAULT_ROLE_ID +
                            VAULT_SECRET_ID or VAULT_SECRET_ID_FILE)
  "iam_aws"               — HashiCorpVaultIamAwsStrategy
  "oidc"                  — HashiCorpVaultJwtAuthStrategy (OIDC token source via the
                            required OIDC_SOURCE option)

See ``adapters.credentials.hashicorp`` and ``adapters.credentials.oidc_sources``
for strategy details and required options.

Required OPTIONS keys (all strategies):
  VAULT_ENDPOINT         : str  e.g. "https://vault.example.com:8200"
  KEK_TEMPLATE       : str  e.g. "encryption_suite-{silo_uid}"
                              (or KEK_MAP for explicit mapping)
  VAULT_NAMESPACE    : str  (optional, for HCP Vault or Vault Enterprise)
  VAULT_MOUNT_PATH   : str  Transit engine mount path (default: "transit")
"""

from __future__ import annotations

import base64
import json
import threading
import time

from ..._logging import get_logger
from ...exceptions import log_and_raise_configuration_error
from .._http import urlopen_with_detail, warn_if_plaintext_url
from ..credentials.hashicorp import (
    HashiCorpVaultAppRoleStrategy,
    HashiCorpVaultIamAwsStrategy,
    HashiCorpVaultJwtAuthStrategy,
    HashiCorpVaultTokenStrategy,
)
from ..credentials.oidc_sources import build_oidc_source
from .base import AbstractKmsAdapter, KmsMetadata

logger = get_logger(__name__)

_PROVIDER = "hashicorp"

_DEFAULT_KEY_VERSION_TTL_SECONDS = 300.0


def version_from_ciphertext(ciphertext: str) -> str:
    """Return the key version named in a Transit ciphertext, or ``""``.

    Transit prefixes every ciphertext with ``vault:v<N>:``, so the version that
    produced it is readable without asking the provider. Returns the bare number
    (``"3"``), matching how the other adapters record a version.

    Never raises: the version is recorded for reporting, so an unexpected prefix
    must leave the wrap itself alone.
    """
    parts = ciphertext.split(":", 2)
    if len(parts) < 3 or parts[0] != "vault" or not parts[1].startswith("v"):
        return ""
    number = parts[1][1:]
    return number if number.isdigit() else ""


class HashiCorpVaultAdapter(AbstractKmsAdapter):
    """
    HashiCorp Vault Transit secrets engine adapter.

    ``encrypt_key()`` calls Transit ``encrypt`` and ``decrypt_key()`` calls
    ``decrypt``.  On a 403 response, the strategy's ``invalidate()`` method is
    called and the request is retried once with a fresh token.
    """

    kms_provider = _PROVIDER
    _INSTANCE_OPTION_KEYS = ("VAULT_ENDPOINT", "VAULT_MOUNT_PATH")

    def __init__(self, options: dict, kek_strategy) -> None:
        super().__init__(options, kek_strategy)
        # Vault Transit's encrypt/decrypt API has a ``context`` field, but it
        # is only honored for keys created with ``derived: true`` (Vault uses
        # the context for key derivation, not as conventional AEAD AAD).
        # Non-derived keys reject the field. django-encryption-suite does not
        # currently provision derived keys, so this adapter cannot bind the
        # silo UID into the wrapped DEK at the wrap layer. A configuration
        # that resolves two silos to one Transit key leaves no per-tenant
        # cryptographic boundary at the KEK layer, whichever strategy
        # produces it.
        self._require_one_kek_per_silo(
            kek_strategy,
            "Vault Transit's context field requires derived keys, which this package does not provision.",
        )
        if not options.get("VAULT_ENDPOINT"):
            log_and_raise_configuration_error(logger, "HashiCorpVaultAdapter requires VAULT_ENDPOINT in OPTIONS.")
        warn_if_plaintext_url(options["VAULT_ENDPOINT"], "VAULT_ENDPOINT", type(self).__name__)
        self._addr = options["VAULT_ENDPOINT"].rstrip("/")
        self._namespace = options.get("VAULT_NAMESPACE")
        self._mount = options.get("VAULT_MOUNT_PATH", "transit").strip("/")
        self._strategy = self._build_strategy(options, self._ssl_context)
        self._current_versions: dict[str, tuple[str, float]] = {}
        self._version_lock = threading.Lock()

    @staticmethod
    def _build_strategy(options: dict, ssl_context=None):
        strategy_name = options.get("CREDENTIAL_STRATEGY", "token")
        if strategy_name == "token":
            return HashiCorpVaultTokenStrategy(options)
        elif strategy_name == "approle":
            return HashiCorpVaultAppRoleStrategy(options, ssl_context=ssl_context)
        elif strategy_name == "iam_aws":
            return HashiCorpVaultIamAwsStrategy(options, ssl_context=ssl_context)
        elif strategy_name == "oidc":
            source_name = options.get("OIDC_SOURCE")
            if not source_name:
                log_and_raise_configuration_error(logger, "CREDENTIAL_STRATEGY='oidc' requires OIDC_SOURCE in OPTIONS.")
            source = build_oidc_source(source_name, options.get("OIDC_SOURCE_OPTIONS", {}))
            return HashiCorpVaultJwtAuthStrategy(options, source, ssl_context=ssl_context)
        else:
            log_and_raise_configuration_error(
                logger, f"Unknown CREDENTIAL_STRATEGY '{strategy_name}'. Valid options: token, approle, iam_aws, oidc"
            )

    def _request(self, method: str, path: str, body: dict | None = None) -> dict:
        import urllib.error
        import urllib.parse
        import urllib.request

        # Quote the mount segment so a misconfigured value with slashes
        # cannot redirect requests off the intended endpoint.
        mount = urllib.parse.quote(self._mount, safe="")
        url = f"{self._addr}/v1/{mount}/{path}"
        data = json.dumps(body).encode() if body else None

        def _make_request(token: str) -> dict:
            headers = {"X-Vault-Token": token, "Content-Type": "application/json"}
            if self._namespace:
                headers["X-Vault-Namespace"] = self._namespace
            req = urllib.request.Request(url, data=data, headers=headers, method=method)
            with urlopen_with_detail(req, timeout=self._request_timeout, context=self._ssl_context) as resp:
                return json.loads(resp.read())

        try:
            result = _make_request(self._strategy.get_credentials())
            self._clear_auth_retry_block()
            return result
        except urllib.error.HTTPError as exc:
            if exc.code == 403:
                if self._is_auth_retry_blocked():
                    raise
                logger.warning(
                    "The call was rejected as unauthenticated, so credentials are being refreshed "
                    'and the call retried once. http_status=403 method=%s path="%s"',
                    method,
                    path,
                )
                self._strategy.invalidate()
                try:
                    result = _make_request(self._strategy.get_credentials())
                    self._clear_auth_retry_block()
                    return result
                except urllib.error.HTTPError:
                    self._record_auth_retry_failure()
                    raise
            raise

    def encrypt_key(self, plaintext: bytes, silo_ref: str) -> tuple[bytes, KmsMetadata]:
        key = self._resolve_kek_id(silo_ref)
        b64_plaintext = base64.b64encode(plaintext).decode()
        result = self._request("POST", f"encrypt/{key}", {"plaintext": b64_plaintext})
        ciphertext_str: str = result["data"]["ciphertext"]
        return ciphertext_str.encode(), KmsMetadata(
            kek_resource_name=key,
            kms_provider=_PROVIDER,
            kek_key_version=version_from_ciphertext(ciphertext_str),
        )

    def decrypt_key(
        self,
        ciphertext: bytes,
        metadata: KmsMetadata,
        silo_ref: str,
    ) -> bytes:
        # silo_ref is unused: this adapter does not currently bind AAD
        # via Vault Transit's ``context`` field (see __init__ for the
        # rationale). PerSiloKekStrategy provides the per-tenant
        # boundary via distinct KEKs instead.
        del silo_ref
        # Rows record the bare key name. Older rows carry a "{addr}/{mount}/{key}"
        # URL, so reduce that form to the name it ends with; a bare name has no
        # separator to split on and passes through unchanged. Mount-path mismatch
        # between encrypt and decrypt configurations is a deployment error; the
        # decrypt call will fail against Vault with a clear "key not found" rather
        # than silently using the wrong target.
        resource = metadata.kek_resource_name
        key = resource.rsplit(f"/{self._mount}/", 1)[-1]
        ciphertext_str = ciphertext.decode()
        result = self._request("POST", f"decrypt/{key}", {"ciphertext": ciphertext_str})
        return base64.b64decode(result["data"]["plaintext"])

    def current_kek_version(self, silo_ref: str) -> str:
        """Return the version new wraps for *silo_ref* would use, or ``""``.

        Transit encrypts with the key's ``latest_version``, which the key's own
        metadata reports. Cached briefly rather than for the process lifetime: a
        rotation bumps the version while leaving the key's name alone, so a worker
        that never looked again would keep reporting a superseded version and
        ``reencrypt_keys`` would skip the very rows that need re-wrapping.

        Never raises. The version is an optimization, so a lookup failure must not
        fail the caller that asked for it; the empty result is cached for the same
        TTL so a persistent failure cannot issue a request per row.
        """
        key = self._resolve_kek_id(silo_ref)
        ttl = float(self.options.get("KEY_VERSION_TTL_SECONDS", _DEFAULT_KEY_VERSION_TTL_SECONDS))
        cached = self._current_versions.get(key)
        if cached is not None and (time.monotonic() - cached[1]) < ttl:
            return cached[0]
        version = ""
        try:
            result = self._request("GET", f"keys/{key}")
            latest = result.get("data", {}).get("latest_version")
            version = str(latest) if latest else ""
        except Exception as exc:
            from ..._internal import operator_error_text

            logger.debug(
                'Key version lookup failed; this key will report no current version. kek="%s" detail="%s"',
                key,
                operator_error_text(exc),
            )
        with self._version_lock:
            self._current_versions[key] = (version, time.monotonic())
        return version

    def describe_kek(self) -> str:
        template = self.options.get("KEK_TEMPLATE", "")
        kek_map = self.options.get("KEK_MAP")
        if template:
            return f"HashiCorp Vault Transit keys: {self._addr}/{self._mount}/{template}"
        if kek_map:
            return f"HashiCorp Vault Transit keys: {len(kek_map)} mapped keys at {self._addr}"
        return f"HashiCorp Vault at {self._addr} (no KEK_TEMPLATE or KEK_MAP configured)"
