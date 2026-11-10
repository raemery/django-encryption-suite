"""
Fly.io KMS (secretkeys) adapter.

Wraps the per-app Fly secretkeys API. Each silo's DEK is encrypted
under a Fly secretkey of type ``xaes256gcm`` resolved by the injected
KEK strategy.

Transport
---------
``/v1/apps/{app}/secretkeys/{name}/encrypt`` and ``/decrypt`` are
restricted to machines running inside the same app. External callers —
even with a valid Fly API token — receive HTTP 403. This adapter
therefore speaks only to the local ``/.fly/api`` Unix socket. Since the
package is invoked by Django and Django on Fly always runs inside a Fly
machine, this is the only transport that is ever needed.

Wire format
-----------
``plaintext``, ``ciphertext``, and ``associated_data`` are sent as
base64-encoded strings in the JSON body. The OpenAPI spec on Fly's
docs site renders them as integer arrays — that is a Go ``[]byte``
serialization quirk in the spec generator; the actual wire format
accepted by the running endpoint is base64.

Associated data
---------------
The AAD bound to every ciphertext is
``b"django-encryption-suite:dek:" + silo_ref.encode("utf-8")``,
constructed via :meth:`AbstractKmsAdapter._wrap_aad`. Fly's
XAES-256-GCM enforces it cryptographically: a ciphertext minted for
silo A cannot be opened as if it belonged to silo B even
when both share a KEK (for example under
:class:`SharedKekStrategy`), and ciphertexts minted by another Fly
secretkey consumer in the same app are also rejected. This is a
defense-in-depth layer on top of any per-silo KEK separation
the strategy already provides.

Threat model note
-----------------
The ``/.fly/api`` socket is authenticated by mount, not by a token —
any process inside the machine can dial it and call ``/encrypt`` and
``/decrypt`` on every secretkey in the app. RCE inside the Django
machine therefore equates to full KMS access for that app's keys. This
is the same property called out in ``docs/security.md`` under
"compromised application server"; it is not specific to Fly KMS.

Required OPTIONS keys:
  KEK_TEMPLATE    : str  e.g. "dck_{silo_uid}"  (or KEK_MAP)
Optional:
  FLY_APP_NAME    : str  the Fly app that owns the secretkeys. The
                         ``FLY_APP_NAME`` environment variable (which
                         Fly injects into every machine) takes
                         precedence over this option when set.
  FLY_SOCKET_PATH : str  default "/.fly/api"
"""

from __future__ import annotations

import base64
import http.client
import json
import os
import socket
import urllib.error

from ..._logging import get_logger
from ...exceptions import log_and_raise_configuration_error
from ..keks.sanitization import ALNUM_UNDERSCORE
from .base import AbstractKmsAdapter, KmsMetadata

logger = get_logger(__name__)

_PROVIDER = "fly"
_DEFAULT_SOCKET_PATH = "/.fly/api"


class FlyKmsAdapter(AbstractKmsAdapter):
    """
    Fly secretkeys envelope-encryption adapter.

    Calls ``/v1/apps/{app}/secretkeys/{name}/encrypt`` and ``/decrypt`` over
    the local ``/.fly/api`` Unix socket. The KEK (a Fly secretkey of type
    ``xaes256gcm``) must already exist; create it with
    ``FlyKmsKekProvisioner`` or outside this application via ``flyctl``.
    """

    kms_provider = _PROVIDER

    # The Unix-socket transport ignores TLS — there is no TLS over AF_UNIX —
    # but the base class' TLS-option guard remains a meaningful default for
    # any future HTTPS path added to this adapter.
    _HONORS_TLS_OPTIONS: bool = True

    # Fly secretkeys only allow letters, digits, and underscore.
    # Length: Fly does not enforce a documented maximum on secretkey names,
    # but Fly engineering has indicated they may not support names "thousands
    # of characters long". ``_UID_MAX_LENGTH`` is left ``None`` (no hard cap
    # enforced here); operators should keep silo UIDs reasonable.
    _UID_ALLOWED_CHARS = ALNUM_UNDERSCORE

    def __init__(self, options: dict, kek_strategy) -> None:
        super().__init__(options, kek_strategy)
        app_name = os.environ.get("FLY_APP_NAME") or options.get("FLY_APP_NAME")
        if not app_name:
            log_and_raise_configuration_error(
                logger,
                "FlyKmsAdapter: FLY_APP_NAME is required. Set it in "
                "OPTIONS or rely on the FLY_APP_NAME environment "
                "variable that Fly injects into every machine.",
            )
        self._app = app_name
        self._socket_path = options.get("FLY_SOCKET_PATH", _DEFAULT_SOCKET_PATH)

    def describe_instance(self) -> str | None:
        # FLY_APP_NAME is usually injected by Fly into the environment rather
        # than set in OPTIONS, so read the resolved value rather than options.
        return self._app

    def encrypt_key(self, plaintext: bytes, silo_ref: str) -> tuple[bytes, KmsMetadata]:
        key = self._resolve_kek_id(silo_ref)
        aad = self._wrap_aad(silo_ref)
        body = {
            "plaintext": base64.b64encode(plaintext).decode(),
            "associated_data": base64.b64encode(aad).decode(),
        }
        result = self._request("POST", f"/v1/apps/{self._app}/secretkeys/{key}/encrypt", body)
        ciphertext = base64.b64decode(result["ciphertext"])
        return ciphertext, KmsMetadata(
            kek_resource_name=key,
            kms_provider=_PROVIDER,
        )

    def decrypt_key(
        self,
        ciphertext: bytes,
        metadata: KmsMetadata,
        silo_ref: str,
    ) -> bytes:
        key = metadata.kek_resource_name
        aad = self._wrap_aad(silo_ref)
        body = {
            "ciphertext": base64.b64encode(ciphertext).decode(),
            "associated_data": base64.b64encode(aad).decode(),
        }
        result = self._request("POST", f"/v1/apps/{self._app}/secretkeys/{key}/decrypt", body)
        return base64.b64decode(result["plaintext"])

    def is_kek_not_found_error(self, exc: BaseException) -> bool:
        # Fly returns a clean 404 with body {"error": "not_found"} when
        # encrypt/decrypt targets a nonexistent secretkey name.
        if isinstance(exc, urllib.error.HTTPError) and exc.code == 404:
            return True
        return super().is_kek_not_found_error(exc)

    def _request(self, method: str, path: str, body: dict) -> dict:
        socket_path = self._socket_path
        data = json.dumps(body).encode()
        headers = {"Content-Type": "application/json", "Accept": "application/json"}

        class _UnixHTTP(http.client.HTTPConnection):
            def connect(self):
                self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                # HTTPConnection applies its timeout only in its own connect(),
                # which this replaces, so the socket has to be given it here.
                self.sock.settimeout(self.timeout)
                self.sock.connect(socket_path)

        conn = _UnixHTTP("localhost", timeout=self._request_timeout)
        try:
            conn.request(method, path, body=data, headers=headers)
            resp = conn.getresponse()
            raw = resp.read()
            if 200 <= resp.status < 300:
                return json.loads(raw) if raw else {}
            raise urllib.error.HTTPError(
                url=path,
                code=resp.status,
                msg=resp.reason,
                hdrs=resp.headers,
                fp=None,
            )
        finally:
            conn.close()

    def describe_kek(self) -> str:
        template = self.options.get("KEK_TEMPLATE", "")
        kek_map = self.options.get("KEK_MAP")
        if template:
            return f"Fly secretkeys (app={self._app}): {template}"
        if kek_map:
            return f"Fly secretkeys (app={self._app}): {len(kek_map)} mapped keys"
        return f"Fly secretkeys (app={self._app}; no KEK_TEMPLATE or KEK_MAP)"
