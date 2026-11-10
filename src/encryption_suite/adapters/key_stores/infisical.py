"""
Infisical KMS adapter.

Uses the Infisical KMS REST API for envelope encryption.  Works with both
Infisical Cloud (``https://app.infisical.com``) and self-hosted Infisical
instances.

No extra Python packages are required — API calls use ``urllib`` from the stdlib.

Each silo gets its own Infisical KMS key, resolved via ``KEK_MAP`` or
``KEK_TEMPLATE`` in ``OPTIONS``.  Infisical addresses keys by
server-assigned UUID, but also lets you fetch a key by its (operator-chosen)
name, so both resolution methods work:

* ``KEK_MAP`` — map each silo UID to a key **UUID**.  Used as-is; no
  lookup needed.  Suitable for keys provisioned outside this application.
* ``KEK_TEMPLATE`` — render a key **name** from the silo UID (e.g.
  ``"encryption-suite-{silo_uid}"``).  The adapter resolves the name to its UUID via
  ``GET /api/v1/kms/keys/key-name/{name}`` (cached per process) before the
  encrypt call.  This is the method that pairs with ``InfisicalKekProvisioner``
  for auto-provisioning.  Requires ``INFISICAL_PROJECT_ID``.

Credential strategy is selected via OPTIONS['CREDENTIAL_STRATEGY']:
  "universal_auth" (default) — InfisicalUniversalAuthStrategy
  "token"                     — InfisicalTokenStrategy
  "oidc"                      — InfisicalOidcStrategy (OIDC token source via
                                the required OIDC_SOURCE option)

See ``adapters.credentials.infisical`` and
``adapters.credentials.oidc_sources`` for strategy details and required options.

Required OPTIONS keys (all strategies):
  KEK_MAP            : dict e.g. {"team-1": "uuid-1", "team-2": "uuid-2"}
                              (or KEK_TEMPLATE if keys follow a naming pattern)
Optional OPTIONS keys:
  INFISICAL_PROJECT_ID : str  required when using KEK_TEMPLATE (name → UUID
                              resolution is project-scoped)
  INFISICAL_ENDPOINT : str  base URL for self-hosted instances
                             (default: "https://app.infisical.com")
  KEY_VERSION_TTL_SECONDS : int  (optional, default 300) how long the key's
                             current material version is reused before it is
                             looked up again, so a rotation reaches long-running
                             processes without a restart.

**Rotation is supported and needs nothing re-wrapped to stay readable.** A
rotation keeps the key's name and UUID and adds new material; Infisical retains
every previous version and resolves the one that produced a ciphertext from the
ciphertext itself, so existing wrapped DEKs keep decrypting. The version current
at wrap time is recorded on the row as ``kek_key_version`` — advisory only, since
decrypt never needs it — so ``manage.py reencrypt_keys`` can skip rows already on
the current material, and "is anything still wrapped under the retired version?"
is answerable without unwrapping every row. That matters more here than on other
providers: Infisical exposes no way to list, view, or delete individual key
versions, so the database is the only place that answer exists, and retiring
material means deleting the whole key.
"""

from __future__ import annotations

import base64
import json
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

from django.core.exceptions import ImproperlyConfigured

from ..._logging import get_logger
from ...exceptions import log_and_raise_configuration_error
from .._http import urlopen_with_detail, warn_if_plaintext_url
from ..credentials.infisical import (
    InfisicalOidcStrategy,
    InfisicalTokenStrategy,
    InfisicalUniversalAuthStrategy,
)
from ..credentials.oidc_sources import build_oidc_source
from ..keks.sanitization import LOWER_ALNUM_HYPHEN
from .base import AbstractKmsAdapter, KmsMetadata

logger = get_logger(__name__)

_PROVIDER = "infisical"

# Canonical UUID form (8-4-4-4-12 hex). A KEK identifier matching this is
# treated as an Infisical key UUID and used directly; anything else is treated
# as a key name and resolved to its UUID via the get-key-by-name endpoint.
_UUID_RE = re.compile(r"\A[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\Z")

# How long the key's current material version is reused before it is looked up
# again, so a rotation reaches long-running workers without a restart.
_DEFAULT_KEY_VERSION_TTL_SECONDS = 300.0


def _is_uuid(value: str) -> bool:
    return bool(_UUID_RE.match(value))


def _key_object(result: dict) -> dict:
    """Return the key object from a KMS key response, top-level or under ``key``."""
    key = result.get("key")
    return key if isinstance(key, dict) else result


def _key_id_from_response(result: dict) -> str:
    """Extract a key UUID from a KMS key response, top-level or under ``key``."""
    key = _key_object(result)
    if "id" in key:
        return key["id"]
    raise KeyError("Infisical KMS key response did not contain an 'id' field.")


def _key_version_from_response(result: dict) -> str:
    """Extract the key's current material version, or ``""`` when absent.

    Absence is not an error. The version is an optimization — it lets
    ``reencrypt_keys`` skip rows already wrapped under the current material — so a
    response that omits it degrades to "unknown", which re-wraps everything rather
    than failing an encrypt over a missing hint.
    """
    version = _key_object(result).get("version")
    return str(version) if version is not None else ""


class InfisicalKmsAdapter(AbstractKmsAdapter):
    """
    Infisical KMS adapter.

    ``encrypt_key()`` calls ``POST /api/v1/kms/keys/{key_id}/encrypt`` and
    ``decrypt_key()`` calls ``POST /api/v1/kms/keys/{key_id}/decrypt``.

    On a 401 response, the credential strategy is invalidated and the request
    is retried once with a fresh token.
    """

    kms_provider = _PROVIDER
    _INSTANCE_OPTION_KEYS = ("INFISICAL_PROJECT_ID",)

    # Infisical KMS key names allow lowercase letters, digits and hyphens, and
    # run to at most 32 characters. Infisical describes them as "slug-friendly":
    # lowercase alphanumeric groups joined by single hyphens.
    #
    # The escape is a LETTER here, unlike every other adapter, because Infisical
    # enforces more than the character class its error message quotes: a name may
    # not contain two hyphens in a row, nor start or end with one.
    # ``sanitize_uid`` doubles its own escape character to stay reversible, so a
    # "-" escape would render the ordinary UID "team-1" as "team--1" and be
    # rejected at key creation — and since only the hyphen-free test-console
    # sentinels would still provision, the failure stays hidden until the first
    # real tenant exists.
    #
    # With a letter escape, "-" is an ordinary allowed character that passes
    # through untouched ("team-1" stays "team-1"), and every escape sequence
    # begins with a letter, so an escaped leading character can never produce a
    # name starting with a hyphen. "z" specifically: it is outside the hex range
    # a-f, so an escape is never misread as part of the two hex digits after it,
    # and it is the rarest letter in the model names UIDs are built from — a
    # literal "z" in a UID doubles to "zz", which is legal but worth avoiding.
    _UID_ALLOWED_CHARS = LOWER_ALNUM_HYPHEN
    _UID_ESCAPE_CHAR = "z"
    _UID_MAX_LENGTH = 32

    def __init__(self, options: dict, kek_strategy) -> None:
        super().__init__(options, kek_strategy)
        # Infisical's KMS encrypt/decrypt API takes only ``plaintext`` /
        # ``ciphertext``; there is no AAD-equivalent field. This adapter
        # therefore cannot bind the silo UID into the wrapped DEK at
        # the wrap layer. A configuration that resolves two silos to one key
        # leaves no per-tenant cryptographic boundary at the KEK layer,
        # whichever strategy produces it.
        self._require_one_kek_per_silo(
            kek_strategy,
            "Infisical's KMS API has no field equivalent to associated data.",
        )
        self._strategy = self._build_strategy(options, self._ssl_context)
        self._site_url = options.get("INFISICAL_ENDPOINT", "https://app.infisical.com").rstrip("/")
        warn_if_plaintext_url(self._site_url, "INFISICAL_ENDPOINT", type(self).__name__)
        self._project_id = options.get("INFISICAL_PROJECT_ID")
        # Cache of resolved key name -> UUID. KEK_TEMPLATE renders a name; the
        # encrypt/decrypt endpoints address keys by UUID, so the name is
        # resolved once per process and reused. A UUID is stable for the life of
        # the key, so this never expires.
        self._name_to_id: dict[str, str] = {}
        self._name_lock = threading.Lock()
        # Current material version per key name, with the time it was read.
        # Separate from the UUID cache and deliberately short-lived: a rotation
        # bumps the version while leaving the UUID alone, so a permanent cache
        # would keep stamping rows with a version the provider has moved past.
        self._current_versions: dict[str, tuple[str, float]] = {}
        self._version_lock = threading.Lock()

    @staticmethod
    def _build_strategy(options: dict, ssl_context=None):
        strategy_name = options.get("CREDENTIAL_STRATEGY", "universal_auth")
        if strategy_name == "universal_auth":
            return InfisicalUniversalAuthStrategy(options, ssl_context=ssl_context)
        elif strategy_name == "token":
            return InfisicalTokenStrategy(options)
        elif strategy_name == "oidc":
            source_name = options.get("OIDC_SOURCE")
            if not source_name:
                log_and_raise_configuration_error(logger, "CREDENTIAL_STRATEGY='oidc' requires OIDC_SOURCE in OPTIONS.")
            source = build_oidc_source(source_name, options.get("OIDC_SOURCE_OPTIONS", {}))
            return InfisicalOidcStrategy(options, source, ssl_context=ssl_context)
        else:
            log_and_raise_configuration_error(
                logger, f"Unknown CREDENTIAL_STRATEGY '{strategy_name}'. Valid options: universal_auth, token, oidc"
            )

    def _resolve_kek_id(self, silo_ref: str) -> str:
        """Resolve the KEK identifier, refusing a name Infisical's naming rule rejects.

        Sanitization guarantees the charset, the 32-character cap, and that no
        *escape* introduces a stray hyphen — but a hyphen already in the silo UID
        passes through untouched, so a UID holding ``--`` or ending in ``-`` still
        renders a name Infisical refuses. The shipped silo adapters cannot produce
        either (their UIDs are ``team-1`` in form), so this guards custom adapters
        and unusual ``KEK_TEMPLATE`` prefixes.

        Checked here because it needs the rendered name, which construction-time
        validation cannot see. Without it the failure arrives as a bare 422 whose
        message quotes only the character class the name already satisfies, which
        is a genuinely confusing thing to debug.
        """
        kek_id = super()._resolve_kek_id(silo_ref)
        if _is_uuid(kek_id):
            return kek_id
        problem = ""
        if "--" in kek_id:
            problem = "contains consecutive hyphens"
        elif kek_id.startswith("-") or kek_id.endswith("-"):
            problem = "starts or ends with a hyphen"
        if problem:
            log_and_raise_configuration_error(
                logger,
                f"InfisicalKmsAdapter: the KEK name '{kek_id}' for silo '{silo_ref}' {problem}, which "
                "Infisical refuses. Its key names must satisfy more than the 'lowercase letters, "
                "numbers, and hyphens' its error message reports: a name may not contain two "
                "hyphens in a row, nor begin or end with one. Adjust KEK_TEMPLATE, or the silo UID "
                "the adapter derives, so neither contributes a leading, trailing, or doubled hyphen.",
            )
        return kek_id

    def canonical_kek_name(self, kek_id: str) -> str:
        """Record the identifier verbatim — the key name, not its UUID.

        Stated as an override because Infisical is a provider where the tempting
        alternative fails. A key's UUID is assigned by the server, so it cannot be
        derived from the silo UID and, crucially, an *owner prefix* has no UUID at
        all: recording UUIDs would leave the ownership gate comparing a name
        prefix against UUID-shaped values, matching nothing. That silently refuses
        every deletion and reports KMS-side reconcile as finding no keys.

        So key names are the name space every layer shares, and the UUID is
        resolved from one at the point of the crypto call. A ``KEK_MAP`` entry
        that is already a UUID is still recorded as itself, which those
        deployments can afford: they derive no owner prefix, so neither deletion
        nor reconcile is available to them anyway.
        """
        return kek_id

    def _with_auth_retry(self, action: str, do):
        """Run ``do(token)``, retrying once with a fresh token on a 401."""
        try:
            result = do(self._strategy.get_credentials())
            self._clear_auth_retry_block()
            return result
        except urllib.error.HTTPError as exc:
            if exc.code == 401:
                if self._is_auth_retry_blocked():
                    raise
                logger.warning(
                    "The call was rejected as unauthenticated, so credentials are being refreshed "
                    "and the call retried once. http_status=401 operation=%s",
                    action,
                )
                self._strategy.invalidate()
                try:
                    result = do(self._strategy.get_credentials())
                    self._clear_auth_retry_block()
                    return result
                except urllib.error.HTTPError:
                    self._record_auth_retry_failure()
                    raise
            raise

    def _request(self, action: str, body: dict, key_id: str) -> dict:
        """POST to ``/api/v1/kms/keys/{key_id}/{action}``, retry once on 401."""
        url = f"{self._site_url}/api/v1/kms/keys/{key_id}/{action}"
        encoded = json.dumps(body).encode()

        def _do(token: str) -> dict:
            req = urllib.request.Request(
                url,
                data=encoded,
                headers={
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                },
                method="POST",
            )
            with urlopen_with_detail(req, timeout=self._request_timeout, context=self._ssl_context) as resp:
                return json.loads(resp.read())

        return self._with_auth_retry(action, _do)

    def _get_key_by_name(self, name: str) -> dict:
        """GET ``/api/v1/kms/keys/key-name/{name}?projectId=…``, retry once on 401."""
        if not self._project_id:
            raise ImproperlyConfigured(
                "InfisicalKmsAdapter: INFISICAL_PROJECT_ID is required in "
                "OPTIONS to resolve a KEK_TEMPLATE key name to its UUID. "
                "Set it, or use KEK_MAP with raw key UUIDs."
            )
        query = urllib.parse.urlencode({"projectId": self._project_id})
        url = f"{self._site_url}/api/v1/kms/keys/key-name/{urllib.parse.quote(name, safe='')}?{query}"

        def _do(token: str) -> dict:
            req = urllib.request.Request(
                url,
                headers={
                    "Authorization": f"Bearer {token}",
                    "Accept": "application/json",
                },
                method="GET",
            )
            with urlopen_with_detail(req, timeout=self._request_timeout, context=self._ssl_context) as resp:
                return json.loads(resp.read())

        return self._with_auth_retry("get-key-by-name", _do)

    def _resolve_key_id(self, kek_id: str) -> str:
        """Map a strategy-resolved KEK identifier to an Infisical key UUID.

        A value already in UUID form (typically a ``KEK_MAP`` entry) is used
        as-is. Otherwise it is treated as a key name (from ``KEK_TEMPLATE``)
        and resolved to its UUID via the get-key-by-name endpoint, cached per
        process.
        """
        if _is_uuid(kek_id):
            return kek_id
        cached = self._name_to_id.get(kek_id)
        if cached:
            return cached
        with self._name_lock:
            cached = self._name_to_id.get(kek_id)
            if cached:
                return cached
            key = self._get_key_by_name(kek_id)
            key_uuid = _key_id_from_response(key)
            self._name_to_id[kek_id] = key_uuid
            # The same response carries the current material version, so the
            # common path costs one call rather than two.
            self._remember_version(kek_id, _key_version_from_response(key))
            return key_uuid

    def _forget_key(self, kek_id: str) -> None:
        """Drop the cached UUID and version for *kek_id* so the next call re-resolves."""
        with self._name_lock:
            self._name_to_id.pop(kek_id, None)
        with self._version_lock:
            self._current_versions.pop(kek_id, None)

    def _crypto_request(self, action: str, body: dict, kek_id: str) -> dict:
        """Run a crypto call for *kek_id*, re-resolving once if its UUID is stale.

        Infisical addresses crypto by UUID but assigns a **new** UUID to a key
        recreated under the same name, and it deletes immediately with no waiting
        period — so a name can be freed and re-provisioned within seconds. A
        process that resolved the name earlier still holds the dead UUID and
        encrypts against a key that no longer exists, which the provider answers
        with a 404 reading as "your KEK is missing" rather than "your cache is
        stale". Observed live 2026-08-03: deleting the admin test console's keys
        and re-running its tests without restarting the app failed every time,
        because the console's sentinel names are fixed and so always reused.

        The 404 is the only signal separating the two cases, so it drives one
        re-resolution and one retry — the same shape as the 401 credential retry.
        Nothing is re-resolved on the healthy path: the cached UUID is a dict
        lookup, and a UUID is stable for the life of a key, so this cache is
        invalidated reactively rather than expired on a timer. If the key really
        is gone, the re-resolution raises from the by-name lookup and the caller
        sees the missing-KEK error it would have seen anyway, one request later.
        UUID-form identifiers (``KEK_MAP``) are left alone: they were never
        resolved from a name, so nothing is stale and a 404 means what it says.
        """
        try:
            return self._request(action, body, self._resolve_key_id(kek_id))
        except urllib.error.HTTPError as exc:
            if exc.code != 404 or _is_uuid(kek_id):
                raise
            logger.warning(
                "This key's cached identifier is no longer valid at the provider, most likely because "
                "the key was deleted and recreated under the same name; the name was re-resolved "
                "and the call retried once. Any DEK still wrapped by the previous key may not be "
                'possible to unwrap. kek="%s" http_status=404',
                kek_id,
            )
            self._forget_key(kek_id)
            return self._request(action, body, self._resolve_key_id(kek_id))

    def _remember_version(self, kek_id: str, version: str) -> None:
        with self._version_lock:
            self._current_versions[kek_id] = (version, time.monotonic())

    def _current_version(self, kek_id: str) -> str:
        """Return the key's current material version, or ``""`` when unknown.

        Cached briefly rather than for the process lifetime: a rotation bumps the
        version while leaving the key's UUID and name alone, so a worker that
        never looked again would keep stamping rows with a version the provider
        has moved past — and ``reencrypt_keys`` would then skip the very rows that
        need re-wrapping.

        ``""`` for a ``KEK_MAP`` UUID: those are addressed by id, and the by-name
        endpoint this reads is the only key lookup wired here. Nothing breaks —
        an unknown version means ``reencrypt_keys`` re-wraps every row instead of
        skipping the current ones, which is the safe direction.

        Never raises. The version is an optimization, so a lookup failure must not
        fail the encrypt that asked for it; the empty result is cached for the
        same TTL so a persistent failure cannot issue a request per wrap.
        """
        if _is_uuid(kek_id):
            return ""

        ttl = float(self.options.get("KEY_VERSION_TTL_SECONDS", _DEFAULT_KEY_VERSION_TTL_SECONDS))
        cached = self._current_versions.get(kek_id)
        if cached is not None and (time.monotonic() - cached[1]) < ttl:
            return cached[0]

        try:
            version = _key_version_from_response(self._get_key_by_name(kek_id))
        except Exception as exc:
            from ..._internal import operator_error_text

            logger.debug(
                'Key version lookup failed; this key will report no current version. kek="%s" detail="%s"',
                kek_id,
                operator_error_text(exc),
            )
            version = ""
        self._remember_version(kek_id, version)
        return version

    def current_kek_version(self, silo_ref: str) -> str:
        """The version a new wrap for *silo_ref* would use.

        Read through the same short-lived cache the wrap path uses, so asking does
        not cost a lookup per row when re-encrypting a whole deployment.
        """
        return self._current_version(self._resolve_kek_id(silo_ref))

    def encrypt_key(self, plaintext: bytes, silo_ref: str) -> tuple[bytes, KmsMetadata]:
        kek_id = self._resolve_kek_id(silo_ref)
        b64_plaintext = base64.b64encode(plaintext).decode()
        result = self._crypto_request("encrypt", {"plaintext": b64_plaintext}, kek_id)
        ciphertext: str = result["ciphertext"]
        # The identifier is recorded, not the UUID it resolved to — see
        # canonical_kek_name. Decrypt resolves it back to a UUID through the same
        # per-process cache encrypt just used.
        return ciphertext.encode(), KmsMetadata(
            kek_resource_name=kek_id,
            kms_provider=_PROVIDER,
            # Advisory, unlike Azure's: Infisical resolves the wrapping version
            # from the ciphertext itself, so decrypt never reads this. It records
            # which material was current at wrap time, which is what makes
            # "is anything still on the retired version?" answerable without
            # unwrapping every row. The encrypt response carries no version, so a
            # rotation landing between this lookup and the wrap would leave the
            # row labeled one version behind — harmless for reads, and corrected
            # by the next reencrypt_keys.
            kek_key_version=self._current_version(kek_id),
        )

    def decrypt_key(
        self,
        ciphertext: bytes,
        metadata: KmsMetadata,
        silo_ref: str,
    ) -> bytes:
        # silo_ref is unused: Infisical's KMS API has no AAD-equivalent
        # field. PerSiloKekStrategy (enforced by the guard in
        # __init__) provides per-tenant separation via distinct KEKs.
        del silo_ref
        # The stored resource name is the key identifier: a name under
        # KEK_TEMPLATE, a UUID under KEK_MAP. A full resource URL is tolerated for
        # an operator who configured one. Resolution is cached per process, so a
        # name costs one lookup per key per worker.
        resource = metadata.kek_resource_name
        kek_id = resource.rsplit("/keys/", 1)[-1] if "/keys/" in resource else resource
        ciphertext_str = ciphertext.decode()
        result = self._crypto_request("decrypt", {"ciphertext": ciphertext_str}, kek_id)
        return base64.b64decode(result["plaintext"])

    def describe_kek(self) -> str:
        kek_map = self.options.get("KEK_MAP")
        if kek_map:
            return f"Infisical KMS keys: {len(kek_map)} mapped keys @ {self._site_url}"
        template = self.options.get("KEK_TEMPLATE")
        if template:
            return f"Infisical KMS keys: {template} @ {self._site_url}"
        return f"Infisical KMS @ {self._site_url}"
