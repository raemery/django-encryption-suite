"""
IBM Key Protect / Hyper Protect Crypto Services (HPCS) KMS adapter.

Supports both IBM Key Protect and IBM HPCS — the key encrypt/decrypt REST
API (IBM calls the actions ``wrap``/``unwrap``) is identical between the
two services; only the base endpoint URL differs.

No extra Python packages are required — these calls use the ``urllib``
standard library.

Each silo gets its own root key, resolved via ``KEK_TEMPLATE`` or
``KEK_MAP`` in ``OPTIONS``.  ``KEK_TEMPLATE`` yields a key *name*
(e.g. ``"encryption_suite-{silo_uid}"``); Key Protect addresses keys by
UUID, so the adapter resolves the name to its UUID by listing keys
(``find_key_by_name``).  ``KEK_MAP`` may instead supply explicit
key UUIDs, which pass through unchanged.

Rows record the key **name**, not the UUID it resolved to — see
:meth:`IbmKmsAdapter.canonical_kek_name`.

Key Protect versions its root keys: a rotation adds a version, retires the
previous one for wrapping, and keeps it available for unwrapping. The wrap
response names the version it used, so ``kek_key_version`` is recorded at no
extra cost. It is advisory — Key Protect resolves the unwrapping version from
the ciphertext itself — but it is what makes "is anything still wrapped under
the retired material?" answerable without unwrapping every row.

Credential strategy is selected via OPTIONS['CREDENTIAL_STRATEGY']:
  "api_key"      (default) — IbmApiKeyStrategy
  "iam_assume"             — IbmIamAssumeStrategy (assume a trusted profile)
  "container"              — IbmContainerStrategy (Code Engine / IKS; ``ibm`` extra)
  "vpc_instance"           — IbmVpcInstanceStrategy (VPC VSI; ``ibm`` extra)

See ``adapters.credentials.ibm`` for strategy details and required options.

Required OPTIONS keys (all strategies):
  IBM_INSTANCE_ID : str  service instance GUID (used in ``bluemix-instance`` header)
  KEK_TEMPLATE       : str  e.g. "encryption_suite-{silo_uid}"
                              (or KEK_MAP for explicit key UUID mapping)

Endpoint selection (one of):
  IBM_REGION      : str  region slug, e.g. "us-south", "eu-gb"
                             Constructs a Key Protect endpoint automatically.
  IBM_ENDPOINT    : str  full base URL — overrides IBM_REGION.
                             Use for HPCS:
                             "https://<instance>.api.<region>.hs-crypto.appdomain.cloud"
                             or for private Key Protect endpoints.
"""

from __future__ import annotations

import base64
import json
import re
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Callable

from ..._logging import get_logger
from ...exceptions import log_and_raise_configuration_error
from .._http import urlopen_with_detail, warn_if_plaintext_url
from ..credentials.ibm import (
    IbmApiKeyStrategy,
    IbmContainerStrategy,
    IbmIamAssumeStrategy,
    IbmVpcInstanceStrategy,
)
from .base import AbstractKmsAdapter, KmsMetadata

logger = get_logger(__name__)

_PROVIDER = "ibm"

# IBM Key Protect content-type values for wrap and unwrap actions.
_WRAP_CONTENT_TYPE = "application/vnd.ibm.kms.key_action_wrap+json"
_UNWRAP_CONTENT_TYPE = "application/vnd.ibm.kms.key_action_unwrap+json"

_UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
# Key Protect's list endpoint caps ``limit`` at 200 keys per page; bound the scan.
_KEY_LIST_PAGE = 200
_KEY_LIST_MAX_PAGES = 50

# Key Protect's key states (NIST SP 800-57): 1 Active, 2 Suspended, 3 Deactivated,
# 5 Destroyed. A deleted key sits in Deactivated for 24 hours, then Destroyed.
_STATE_DESTROYED = 5

# How long a lookup-read key version is trusted before being read again.
_DEFAULT_KEY_VERSION_TTL_SECONDS = 300.0

# Statuses that mean "the UUID this name resolved to is no longer usable", and so
# are worth one re-resolution of the name. 410 is the one that actually occurs:
# Key Protect soft-deletes, so a deleted key's UUID still exists and wrapping with
# it answers `410 Gone (KEY_DELETED_ERR)` rather than 404. 404 covers a UUID the
# instance has no record of at all — after a purge, or a key removed outside this
# deployment.
_STALE_KEY_STATUSES = frozenset({404, 410})


def _looks_like_uuid(value: str) -> bool:
    """Return True if *value* is a Key Protect key UUID (so no name lookup is needed)."""
    return bool(_UUID_RE.match(value or ""))


def key_name(kek_id: str) -> str:
    """Reduce an identifier to a bare Key Protect key name.

    ``KEK_TEMPLATE`` renders a bare name, but rows written before this adapter
    recorded names hold a full resource URL, and an operator may have configured
    one; both reduce to the trailing segment.
    """
    if "/keys/" in kek_id:
        return kek_id.rsplit("/keys/", 1)[-1].split("/")[0]
    return kek_id


def is_deleted(resource: dict) -> bool:
    """Return whether a listed key resource is a deleted one.

    Key Protect keeps a deleted key visible — and restorable — for 30 days, so a
    listing shows live and deleted keys together and every caller here wants only
    the live ones. Two signals because they cover different parts of that window:
    ``deleted`` is set from the moment of deletion, while the state only reaches
    *Destroyed* 24 hours later. Reading either alone would resolve a name to a key
    that can no longer wrap anything.
    """
    return bool(resource.get("deleted")) or resource.get("state") == _STATE_DESTROYED


def version_id(container: dict) -> str:
    """Return the ``keyVersion.id`` carried by a wrap response or key metadata.

    Both shapes name the version the same way; only the envelope differs (a wrap
    response carries it at the top level, key metadata inside the resource).
    """
    version = (container or {}).get("keyVersion") or {}
    return version.get("id", "") if isinstance(version, dict) else ""


def find_key_by_name(get_json: Callable[[str], dict], name: str) -> dict | None:
    """Return the live Key Protect key resource named *name*, or ``None`` if absent.

    Key Protect addresses keys by UUID — ``GET /api/v2/keys/{name}`` 404s — so a
    name is resolved by listing keys and matching the ``name`` field. *get_json*
    performs an authenticated GET and returns the decoded body.

    Deleted keys are skipped (see :func:`is_deleted`). Names are not unique in Key
    Protect — the API accepts a duplicate — so the first live match wins.
    """
    offset = 0
    for _ in range(_KEY_LIST_MAX_PAGES):
        data = get_json(f"/api/v2/keys?limit={_KEY_LIST_PAGE}&offset={offset}")
        resources = data.get("resources") or []
        for key in resources:
            if isinstance(key, dict) and key.get("name") == name and not is_deleted(key):
                return key
        total = (data.get("metadata") or {}).get("collectionTotal", 0)
        offset += _KEY_LIST_PAGE
        # Stop on a short page as well as on the reported total: a server that
        # omits or misreports collectionTotal must not spin this walk.
        if len(resources) < _KEY_LIST_PAGE or offset >= total:
            break
    return None


class IbmKmsAdapter(AbstractKmsAdapter):
    """
    IBM Key Protect / HPCS adapter using the Key Protect REST API.

    ``encrypt_key()`` calls ``/api/v2/keys/{key_id}/actions/wrap`` and
    ``decrypt_key()`` calls ``/api/v2/keys/{key_id}/actions/unwrap`` (the
    URL path segments are IBM's own verbs for these operations).

    On a 401 response, the credential strategy is invalidated and the request
    is retried once with a fresh token.
    """

    kms_provider = _PROVIDER
    _INSTANCE_OPTION_KEYS = ("IBM_INSTANCE_ID",)

    # Key Protect refuses a key name outside 2-90 characters. Declared so an
    # over-long name is refused with a config error naming the limit, rather than
    # as a provider rejection on the first encrypt. The charset stays the base
    # ``ALNUM_UNDERSCORE_HYPHEN`` with the ``_`` escape: Key Protect accepts both
    # underscores and hyphens in a name.
    _UID_MAX_LENGTH = 90

    def __init__(self, options: dict, kek_strategy) -> None:
        super().__init__(options, kek_strategy)
        self._strategy = self._build_strategy(options, self._ssl_context)
        self._base_url = self._resolve_endpoint(options)
        warn_if_plaintext_url(self._base_url, "IBM_ENDPOINT", type(self).__name__)
        if not options.get("IBM_INSTANCE_ID"):
            log_and_raise_configuration_error(logger, "IbmKmsAdapter: IBM_INSTANCE_ID is required in OPTIONS.")
        self._instance_id = options["IBM_INSTANCE_ID"]
        # Key Protect addresses keys by UUID; KEK_TEMPLATE yields a name. Cache
        # the name->UUID resolution. Invalidated reactively rather than on a timer
        # — see _crypto_request.
        self._uuid_cache: dict[str, str] = {}
        self._uuid_lock = threading.Lock()
        # name -> (version id, monotonic timestamp). Unlike the UUID, a version
        # changes under a live key on every rotation, so this one does expire.
        self._current_versions: dict[str, tuple[str, float]] = {}
        self._version_lock = threading.Lock()

    @staticmethod
    def _build_strategy(options: dict, ssl_context=None):
        strategy_name = options.get("CREDENTIAL_STRATEGY", "api_key")
        if strategy_name == "api_key":
            return IbmApiKeyStrategy(options, ssl_context=ssl_context)
        elif strategy_name == "iam_assume":
            return IbmIamAssumeStrategy(options, ssl_context=ssl_context)
        elif strategy_name == "container":
            return IbmContainerStrategy(options)
        elif strategy_name == "vpc_instance":
            return IbmVpcInstanceStrategy(options)
        else:
            log_and_raise_configuration_error(
                logger,
                f"Unknown CREDENTIAL_STRATEGY '{strategy_name}'. "
                "Valid options: api_key, iam_assume, container, vpc_instance",
            )

    @staticmethod
    def _resolve_endpoint(options: dict) -> str:
        if "IBM_ENDPOINT" in options:
            return options["IBM_ENDPOINT"].rstrip("/")
        region = options.get("IBM_REGION")
        if not region:
            log_and_raise_configuration_error(
                logger, "IbmKmsAdapter: either IBM_ENDPOINT or IBM_REGION must be set in OPTIONS."
            )
        return f"https://{region}.kms.cloud.ibm.com"

    def _request(self, action: str, body: dict, key_id: str) -> dict:
        """POST to ``/api/v2/keys/{key_id}/actions/{action}``, retry once on 401."""
        content_type = _WRAP_CONTENT_TYPE if action == "wrap" else _UNWRAP_CONTENT_TYPE
        url = f"{self._base_url}/api/v2/keys/{key_id}/actions/{action}"
        encoded = json.dumps(body).encode()

        def _do(token: str) -> dict:
            req = urllib.request.Request(
                url,
                data=encoded,
                headers={
                    "Authorization": f"Bearer {token}",
                    "bluemix-instance": self._instance_id,
                    "Content-Type": content_type,
                    "Accept": content_type,
                },
                method="POST",
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
                    "and the call retried once. http_status=401 operation=%s",
                    action,
                )
                self._strategy.invalidate()
                try:
                    result = _do(self._strategy.get_credentials())
                    self._clear_auth_retry_block()
                    return result
                except urllib.error.HTTPError:
                    self._record_auth_retry_failure()
                    raise
            raise

    def _get_json(self, path: str) -> dict:
        """Authenticated ``GET`` of a Key Protect path, retrying once on 401."""
        url = f"{self._base_url}{path}"

        def _do(token: str) -> dict:
            req = urllib.request.Request(
                url,
                headers={
                    "Authorization": f"Bearer {token}",
                    "bluemix-instance": self._instance_id,
                    "Accept": "application/vnd.ibm.kms.key+json",
                },
                method="GET",
            )
            with urlopen_with_detail(req, timeout=self._request_timeout, context=self._ssl_context) as resp:
                return json.loads(resp.read())

        try:
            return _do(self._strategy.get_credentials())
        except urllib.error.HTTPError as exc:
            if exc.code == 401:
                self._strategy.invalidate()
                return _do(self._strategy.get_credentials())
            raise

    def _get_key_metadata(self, key_uuid: str) -> dict:
        """Return the key resource for *key_uuid* (``GET /api/v2/keys/{id}``)."""
        payload = self._get_json(f"/api/v2/keys/{key_uuid}")
        resources = (payload or {}).get("resources") or []
        return resources[0] if resources and isinstance(resources[0], dict) else {}

    def _resolve_uuid(self, name_or_id: str) -> str:
        """Resolve a key name to its Key Protect UUID (Key Protect addresses keys
        by UUID, not name).

        A value that is already a UUID passes through. If no key matches the
        name, the name is returned unchanged so the subsequent wrap/unwrap call
        surfaces Key Protect's own 404 ("key does not exist"), which the engine
        classifies as a missing KEK — rather than fabricating a transport error
        here.
        """
        if _looks_like_uuid(name_or_id):
            return name_or_id
        with self._uuid_lock:
            cached = self._uuid_cache.get(name_or_id)
        if cached:
            return cached
        key = find_key_by_name(self._get_json, name_or_id)
        if not key or not key.get("id"):
            return name_or_id
        uuid = key["id"]
        with self._uuid_lock:
            self._uuid_cache[name_or_id] = uuid
        # The listing already carried the key's current version, so the common
        # path costs one call rather than two.
        self._remember_version(name_or_id, version_id(key))
        return uuid

    def _forget_key(self, kek_id: str) -> None:
        """Drop the cached UUID and version for *kek_id* so the next call re-resolves."""
        with self._uuid_lock:
            self._uuid_cache.pop(kek_id, None)
        with self._version_lock:
            self._current_versions.pop(kek_id, None)

    def _crypto_request(self, action: str, body: dict, kek_id: str) -> dict:
        """Run a wrap/unwrap for *kek_id*, re-resolving once if its UUID is stale.

        Key Protect assigns a **new** UUID to a key created under a name an older
        key used — names need not be unique and a deleted one is free to reuse — so
        a process that resolved the name earlier still holds the dead UUID and
        wraps against a key that is no longer usable. The provider's answer reads
        as "your KEK is broken" rather than "your cache is stale". The admin test
        console reaches this the fastest, because its sentinel key names are fixed
        and so always reused.

        **The status is 410, not 404.** Key Protect soft-deletes: the old UUID
        still exists, in the deleted state, so wrapping with it returns
        ``410 Gone (KEY_DELETED_ERR)``. 404 is kept for a UUID the instance has no
        record of at all, after a purge or a removal outside this deployment. Both
        mean the same thing here, so both drive one re-resolution and one retry —
        the same shape as the 401 credential retry.

        Nothing is re-resolved on the healthy path: the cached UUID is a dict
        lookup, and a UUID is stable for the life of a key, so this cache is
        invalidated reactively rather than expired on a timer. If the key really is
        gone, the re-resolution finds nothing, the retry sends the name, and the
        caller sees the missing-KEK error it would have seen anyway. UUID-form
        identifiers (``KEK_MAP``) are left alone: they were never resolved from a
        name, so nothing is stale and the status means what it says.
        """
        try:
            return self._request(action, body, self._resolve_uuid(kek_id))
        except urllib.error.HTTPError as exc:
            if exc.code not in _STALE_KEY_STATUSES or _looks_like_uuid(kek_id):
                raise
            logger.warning(
                "This key's cached identifier is no longer valid at the provider, most likely because "
                "the key was deleted and recreated under the same name; the name was re-resolved "
                "and the call retried once. Any DEK still wrapped by the previous key may not be "
                'possible to unwrap. kek="%s" http_status=%s',
                kek_id,
                exc.code,
            )
            self._forget_key(kek_id)
            return self._request(action, body, self._resolve_uuid(kek_id))

    def _remember_version(self, kek_id: str, version: str) -> None:
        with self._version_lock:
            self._current_versions[kek_id] = (version, time.monotonic())

    def _current_version(self, kek_id: str) -> str:
        """Return the key's current material version, or ``""`` when unknown.

        Cached briefly rather than for the process lifetime: a rotation bumps the
        version while leaving the key's UUID and name alone, so a worker that never
        looked again would keep reporting a version the provider has moved past,
        and ``reencrypt_keys`` would then skip the very rows that need re-wrapping.

        Never raises. The version is an optimization, so a lookup failure must not
        fail the caller that asked for it; the empty result is cached for the same
        TTL so a persistent failure cannot issue a request per row.
        """
        ttl = float(self.options.get("KEY_VERSION_TTL_SECONDS", _DEFAULT_KEY_VERSION_TTL_SECONDS))
        cached = self._current_versions.get(kek_id)
        if cached is not None and (time.monotonic() - cached[1]) < ttl:
            return cached[0]

        try:
            key_uuid = self._resolve_uuid(kek_id)
            # _resolve_uuid caches the version off the listing it just read, so
            # for a name this is usually already answered.
            cached = self._current_versions.get(kek_id)
            if cached is not None and (time.monotonic() - cached[1]) < ttl:
                return cached[0]
            version = version_id(self._get_key_metadata(key_uuid))
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

        Read through the same short-lived cache the resolution path fills, so
        asking does not cost a lookup per row when re-encrypting a deployment.
        """
        return self._current_version(key_name(self._resolve_kek_id(silo_ref)))

    def canonical_kek_name(self, kek_id: str) -> str:
        """Record the key **name**, not the UUID it resolves to.

        Stated as an override because Key Protect is a provider where the tempting
        alternative fails. A key's UUID is assigned by the server, so it cannot be
        derived from the silo UID and, crucially, an *owner prefix* has no UUID at
        all: recording UUIDs would leave the ownership gate comparing a name prefix
        against UUID-shaped values, matching nothing. That silently refuses every
        deletion and reports KMS-side reconcile as finding no keys.

        So key names are the name space every layer shares, and the UUID is
        resolved from one at the point of the crypto call. A ``KEK_MAP`` entry that
        is already a UUID is still recorded as itself, which those deployments can
        afford: they derive no owner prefix, so neither deletion nor reconcile is
        available to them anyway.
        """
        return key_name(kek_id)

    def _aad_field(self, silo_ref: str) -> list[str]:
        """Return the IBM Key Protect ``aad`` field value for *silo_ref*.

        IBM's wrap/unwrap API takes ``aad`` as a list of base64-encoded
        strings. We send a single element containing the canonical wrap AAD.
        """
        return [base64.b64encode(self._wrap_aad(silo_ref)).decode()]

    def encrypt_key(self, plaintext: bytes, silo_ref: str) -> tuple[bytes, KmsMetadata]:
        kek_id = key_name(self._resolve_kek_id(silo_ref))
        b64_plaintext = base64.b64encode(plaintext).decode()
        result = self._crypto_request(
            "wrap",
            {"plaintext": b64_plaintext, "aad": self._aad_field(silo_ref)},
            kek_id,
        )
        ciphertext: str = result["ciphertext"]
        # The identifier is recorded, not the UUID it resolved to — see
        # canonical_kek_name. Decrypt resolves it back to a UUID through the same
        # per-process cache the wrap just used.
        wrapped_version = version_id(result)
        if wrapped_version:
            # Authoritative, unlike a version read from a lookup: this is the
            # version Key Protect reports having wrapped *this* ciphertext, so a
            # rotation landing mid-request cannot mislabel the row. Keep the cache
            # in step with it for free.
            self._remember_version(kek_id, wrapped_version)
        return ciphertext.encode(), KmsMetadata(
            kek_resource_name=kek_id,
            kms_provider=_PROVIDER,
            # Advisory, unlike Azure's: Key Protect resolves the unwrapping version
            # from the ciphertext itself, so decrypt never reads this.
            kek_key_version=wrapped_version,
        )

    def decrypt_key(
        self,
        ciphertext: bytes,
        metadata: KmsMetadata,
        silo_ref: str,
    ) -> bytes:
        # The stored resource name is the key identifier: a name under
        # KEK_TEMPLATE, a UUID under KEK_MAP. Rows written before this adapter
        # recorded names hold a full resource URL carrying the UUID, which reduces
        # to that UUID here and still unwraps.
        kek_id = key_name(metadata.kek_resource_name)
        ciphertext_str = ciphertext.decode()
        result = self._crypto_request(
            "unwrap",
            {"ciphertext": ciphertext_str, "aad": self._aad_field(silo_ref)},
            kek_id,
        )
        return base64.b64decode(result["plaintext"])

    def describe_kek(self) -> str:
        template = self.options.get("KEK_TEMPLATE", "")
        if template:
            return f"IBM Key Protect/HPCS keys: {self._base_url} template={template}"
        return f"IBM Key Protect/HPCS at {self._base_url}"
