"""
Fly.io KMS (secretkeys) KEK provisioner.

Creates one Fly secretkey per silo via Fly's public Machines API
at ``https://api.machines.dev``.

Why not the local ``/.fly/api`` socket?
---------------------------------------
The local socket on each machine is restricted to encrypt/decrypt
operations on existing secretkeys. Secretkey *creation*
(``POST /v1/apps/{app}/secretkeys/{name}/generate``) returns
HTTP 403 ``unauthorized`` over that socket regardless of the calling
OS user, because Fly's authorization for management operations
requires an API token rather than mount-based identity. Generation
must therefore go through the public API with a Fly auth token. The
encrypt/decrypt path (used by ``FlyKmsAdapter``) continues to use the
local socket because token-less mount auth is sufficient there.

Auth
----
Reads the bearer token from the ``FLY_API_TOKEN`` environment variable.
On Fly, set it as an app secret. A deploy-scoped token is sufficient
and the safest choice — it only grants management rights to the one
app it was created for:

    fly tokens create deploy -a <app> --expiry 8760h
    fly secrets set FLY_API_TOKEN=<token> -a <app>

If ``FLY_API_TOKEN`` is missing at runtime, ``ensure_kek`` raises a
``RuntimeError`` with a message that names the variable and the fix.
The engine wraps that in ``KekNotProvisionedError`` for the caller.

Idempotency
-----------
``GET /v1/apps/{app}/secretkeys/{name}`` probes for existence.
``/generate`` is called only when the probe returns 404. Fly's
``/generate`` overwrites in place with no version history, so calling
it on an existing key would destroy every ciphertext encrypted under
the previous material. The provisioner is hard-coded to never do that.

KEK_PROVISIONER_OPTIONS keys:
  FLY_APP_NAME       : str  the Fly app that owns the keys. The
                            ``FLY_APP_NAME`` environment variable (which
                            Fly injects into every machine) takes
                            precedence over this option when set.
  FLY_API_ENDPOINT   : str  default ``"https://api.machines.dev"``. Useful
                            in tests or for routing through a regional
                            Fly Machines endpoint.
  KEY_TYPE           : str  default ``"xaes256gcm"`` (the only AEAD type
                            Fly currently exposes for secretkeys; other
                            types are MAC/sign-only and unsuitable for
                            envelope encryption).

Name constraints (from Fly):
  Fly secretkey names must match ``[A-Za-z0-9_]+``. The provisioner
  validates ``kek_resource_name`` and rejects anything outside this
  charset with ``ValueError`` rather than silently transforming the
  name — silent rewrites would let two distinct silos map onto
  the same key (e.g. ``team-1`` and ``team_1`` both becoming
  ``team_1``), defeating tenant isolation. Pair this provisioner with
  a strategy whose ``get_kek_id`` already produces conforming names
  (e.g. a ``KEK_TEMPLATE`` of ``"dck_{uid}"`` over numeric UIDs, or an
  explicit ``KEK_MAP``).
"""

from __future__ import annotations

import json
import os
import re
import threading
import urllib.error
import urllib.request

from django.utils import timezone

from ..._logging import get_logger
from ...exceptions import log_and_raise_configuration_error
from .._http import urlopen_with_detail, warn_if_plaintext_url
from .provisioners import AbstractKekProvisioner, DeleteOutcome

logger = get_logger(__name__)

_NAME_RE = re.compile(r"^[A-Za-z0-9_]+$")
_DEFAULT_KEY_TYPE = "xaes256gcm"
_DEFAULT_API_BASE_URL = "https://api.machines.dev"
_TOKEN_ENV_VAR = "FLY_API_TOKEN"


class FlyKmsKekProvisioner(AbstractKekProvisioner):
    """Create one Fly secretkey per silo, idempotently."""

    # Fly's secretkeys API deletes immediately with no waiting period — there is
    # no scheduled-deletion/recovery window as on AWS/GCP/Azure/OCI (as of June
    # 2026; Fly is considering adding one). So a deletion here is irreversible the
    # instant it returns, and the DeleteOutcome reports ``scheduled=False``.
    supports_delete = True

    # Fly secretkeys carry no tag/label metadata, so ``supports_tagging`` stays
    # at the base default of False and any configured TAGS are reported as
    # undeliverable by the startup check. Ownership is the name-prefix marker.

    # Fly exposes ``GET /v1/apps/{app}/secretkeys`` to list an app's keys, so the
    # KMS half of reconcile is available. Ownership is still proven by the
    # name-prefix marker (no tags), which the base ``list_kek_names`` re-filters.
    supports_enumeration = True

    def __init__(self, options: dict) -> None:
        super().__init__(options)
        app_name = os.environ.get("FLY_APP_NAME") or options.get("FLY_APP_NAME")
        if not app_name:
            log_and_raise_configuration_error(
                logger,
                "FlyKmsKekProvisioner: FLY_APP_NAME is required. Set it "
                "in KEK_PROVISIONER_OPTIONS or rely on the FLY_APP_NAME "
                "environment variable that Fly injects into every "
                "machine.",
            )
        self._app = app_name
        self._key_type = options.get("KEY_TYPE", _DEFAULT_KEY_TYPE)
        self._base_url = options.get("FLY_API_ENDPOINT", _DEFAULT_API_BASE_URL).rstrip("/")
        warn_if_plaintext_url(self._base_url, "FLY_API_ENDPOINT", type(self).__name__)
        self._ensured: set[str] = set()
        self._lock = threading.Lock()

    def ensure_kek(self, kek_resource_name: str, silo_ref: str) -> bool:
        if kek_resource_name in self._ensured:
            return False
        if not _NAME_RE.match(kek_resource_name):
            raise ValueError(
                f"FlyKmsKekProvisioner: '{kek_resource_name}' is not a valid "
                "Fly secretkey name. Allowed: letters, digits, underscore. "
                "Adjust KEK_TEMPLATE / KEK_MAP so the produced name conforms."
            )

        # GET-first probe. Fly's /generate overwrites in place with no
        # version history, so we MUST NOT call it for an existing key.
        path = f"/v1/apps/{self._app}/secretkeys/{kek_resource_name}"
        try:
            self._request("GET", path, None)
            with self._lock:
                self._ensured.add(kek_resource_name)
            return False
        except urllib.error.HTTPError as exc:
            if exc.code != 404:
                raise

        self._request("POST", f"{path}/generate", {"type": self._key_type})
        self._log_kek_created(kek=kek_resource_name, silo_ref=silo_ref)
        with self._lock:
            self._ensured.add(kek_resource_name)
        return True

    def _do_delete_kek(self, kek_resource_name: str, silo_ref: str) -> DeleteOutcome:
        """Delete the Fly secretkey. Immediate and irreversible — no recovery window.

        Idempotent: a 404 (key already absent) is treated as success, since the
        goal state — key gone — is already met. The local ``_ensured`` cache is
        cleared so a future ``ensure_kek`` for the same name re-provisions rather
        than trusting the stale cache.
        """
        path = f"/v1/apps/{self._app}/secretkeys/{kek_resource_name}"
        try:
            self._request("DELETE", path, None)
        except urllib.error.HTTPError as exc:
            if exc.code != 404:
                raise
            self._log_kek_absent_on_delete(kek=kek_resource_name, silo_ref=silo_ref)
        with self._lock:
            self._ensured.discard(kek_resource_name)
        # No waiting period — the key is gone now. The purge emits
        # the audit-level log line; the provisioner only performs the API call.
        return DeleteOutcome(scheduled=False, effective_at=timezone.now())

    def _do_list_kek_names(self, owner_prefix: str) -> list[str]:
        """List the Fly secretkey names in this app via the Machines API.

        Calls ``GET /v1/apps/{app}/secretkeys`` and returns each key's ``name``.
        Fly's list endpoint has no server-side name filter, so *owner_prefix* is
        unused here — the base :meth:`list_kek_names` re-filters the result by the
        prefix, so returning the app's full key list is safe. Raises the raw
        provider error on failure; the enumeration funnel types and logs it.
        """
        payload = self._request("GET", f"/v1/apps/{self._app}/secretkeys", None)
        names = []
        for item in self._secretkey_items(payload):
            name = item.get("name") if isinstance(item, dict) else None
            if name:
                names.append(name)
        return names

    @staticmethod
    def _secretkey_items(payload) -> list:
        """Normalize the secretkeys list response to a list of item dicts.

        Tolerates the response being either a top-level JSON array (the expected
        Machines-API collection shape) or a single object wrapping the array in a
        list-valued field, so a wrapper key does not break enumeration.
        """
        if isinstance(payload, list):
            return payload
        if isinstance(payload, dict):
            for value in payload.values():
                if isinstance(value, list):
                    return value
        return []

    def _request(self, method: str, path: str, body: dict | None) -> dict:
        token = os.environ.get(_TOKEN_ENV_VAR)
        if not token:
            raise RuntimeError(
                "FlyKmsKekProvisioner: FLY_API_TOKEN is not set. The Fly "
                "secretkeys management API (/generate) requires a Fly auth "
                "token; the local /.fly/api socket only authorizes "
                "encrypt/decrypt. Create a deploy-scoped token with "
                "`fly tokens create deploy -a <app>` and store it via "
                "`fly secrets set FLY_API_TOKEN=<token> -a <app>`."
            )

        data = json.dumps(body).encode() if body is not None else None
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
        }
        if data is not None:
            headers["Content-Type"] = "application/json"

        req = urllib.request.Request(
            url=f"{self._base_url}{path}",
            data=data,
            headers=headers,
            method=method,
        )
        with urlopen_with_detail(req, timeout=self._request_timeout, context=self._ssl_context) as resp:
            raw = resp.read()
            return json.loads(raw) if raw else {}

    def describe(self) -> str:
        return f"FlyKmsKekProvisioner(app={self._app})"
