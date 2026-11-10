"""
HashiCorp Vault KEK provisioner.

Creates Transit keys via the Vault HTTP API. The Transit secrets engine
itself must already be mounted at the standard ``transit/`` path (or
override via ``VAULT_MOUNT_PATH``) — mounting engines is an admin operation
that should not run from app code.

KEK_PROVISIONER_OPTIONS keys:
  VAULT_ENDPOINT           : str   (required) e.g. "https://vault.example.com:8200"
  CREDENTIAL_STRATEGY  : str   "token" (default), "approle", "iam_aws", "oidc"
  VAULT_ROLE_ID        : str   required when CREDENTIAL_STRATEGY="approle"
  VAULT_SECRET_ID      : str   required when CREDENTIAL_STRATEGY="approle"
                               (or VAULT_SECRET_ID_FILE)
  VAULT_SECRET_ID_FILE : str   path to file containing secret_id
  VAULT_APPROLE_MOUNT  : str   default "approle"
  OIDC_SOURCE          : str   required when CREDENTIAL_STRATEGY="oidc"
  OIDC_SOURCE_OPTIONS  : dict  optional source-specific options
  VAULT_NAMESPACE      : str   optional, for HCP Vault / Vault Enterprise
  VAULT_MOUNT_PATH           : str   default "transit"
  KEY_TYPE             : str   default "aes256-gcm96"
  EXPORTABLE           : bool  default False
  ALLOW_PLAINTEXT_BACKUP : bool default False
  DERIVED              : bool  default False
  KEK_ROTATION_PERIOD_DAYS : int   optional; automatic rotation interval, minimum 1
  ALWAYS_ALLOW_KEY_DELETION : bool default False; see below

Transit guards deletion with a per-key ``deletion_allowed`` flag that is false
on a new key, so deleting from this application overrides a protection the
provider applies by default. ``ALWAYS_ALLOW_KEY_DELETION`` is the deployment
saying to do that. With it off, the provisioner reports itself as unable to
delete and the purge retains keys with a recorded reason instead of attempting
a deletion Vault would refuse. Deletion removes every version of the key at
once and cannot be undone.
"""

from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request

from django.utils import timezone

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
from .provisioners import AbstractKekProvisioner, DeleteOutcome

logger = get_logger(__name__)


class HashiCorpVaultKekProvisioner(AbstractKekProvisioner):
    """Create one Transit key per silo."""

    # ``DELETE /transit/keys/{name}`` removes the key and every one of its
    # versions at once — no scheduled-deletion window and no recovery, so a
    # deletion here is irreversible the instant it returns and the DeleteOutcome
    # reports ``scheduled=False``. ``minimum_deletion_window_days`` stays ``None``
    # for the same reason: there is no window to shorten for a test-console key.
    #
    # This class attribute means *deletion is implemented*, which is what the
    # delete contract table asserts. Whether deletion will actually run is a
    # second question — Transit keeps a per-key ``deletion_allowed`` latch — so
    # ``__init__`` shadows this with an instance attribute carrying the config
    # answer. Every runtime reader holds an instance and sees that one.
    supports_delete = True

    # ``LIST /transit/keys`` returns a project's key names, which is the name
    # space the rows record (see ``HashiCorpVaultAdapter``), so the listing can
    # be diffed against them directly.
    supports_enumeration = True

    # ``supports_state_check`` stays False: with no deletion window a key is
    # either present or gone, which enumeration already answers. Transit's
    # per-key ``min_decryption_version`` trims old versions but says nothing
    # about the key's own lifecycle, and reporting it as one would invent a
    # deletion state Transit does not have.

    # ``supports_tagging`` stays False: the create-key API takes no tag metadata,
    # so any configured TAGS are reported as undeliverable by the startup check.
    # Ownership is the name-prefix marker.

    # Transit takes ``auto_rotate_period`` on a key's config, in seconds, with a
    # floor of one hour — below a day, so the day-denominated floor here is 1.
    # No ceiling is documented, so ``maximum_rotation_days`` stays ``None``
    # (undeclared, not unlimited).
    supports_rotation_policy = True
    minimum_rotation_days = 1
    rotation_policy_remedy = (
        "Setting a rotation policy needs update on the key's config path and Vault 1.10 or later; "
        "set it by hand with `vault write transit/keys/<key>/config auto_rotate_period=<duration>`, "
        "or grant the capability and recreate the key."
    )

    def __init__(self, options: dict) -> None:
        super().__init__(options)
        if not options.get("VAULT_ENDPOINT"):
            log_and_raise_configuration_error(
                logger, "HashiCorpVaultKekProvisioner requires VAULT_ENDPOINT in KEK_PROVISIONER_OPTIONS."
            )
        warn_if_plaintext_url(options["VAULT_ENDPOINT"], "VAULT_ENDPOINT", type(self).__name__)
        self._addr = options["VAULT_ENDPOINT"].rstrip("/")
        self._namespace = options.get("VAULT_NAMESPACE")
        self._mount = options.get("VAULT_MOUNT_PATH", "transit").strip("/")
        self._strategy = self._build_strategy(options, self._ssl_context)
        self._ensured: set[str] = set()
        self._lock = threading.Lock()
        # Shadows the class attribute for every runtime reader. Transit refuses
        # to delete a key whose ``deletion_allowed`` latch is false, and an
        # operator who left it false meant it, so deleting from here is an
        # override of a provider-side protection and has to be asked for. With
        # this off, the purge retains the key at its capability gate and reports
        # a reason, rather than attempting a delete that the provider refuses.
        self.supports_delete = bool(options.get("ALWAYS_ALLOW_KEY_DELETION", False))

    @staticmethod
    def _build_strategy(options: dict, ssl_context):
        name = options.get("CREDENTIAL_STRATEGY", "token")
        if name == "token":
            # Static token — no HTTP call, no TLS context needed.
            return HashiCorpVaultTokenStrategy(options)
        if name == "approle":
            return HashiCorpVaultAppRoleStrategy(options, ssl_context=ssl_context)
        if name == "iam_aws":
            return HashiCorpVaultIamAwsStrategy(options, ssl_context=ssl_context)
        if name == "oidc":
            source_name = options.get("OIDC_SOURCE")
            if not source_name:
                log_and_raise_configuration_error(
                    logger, "CREDENTIAL_STRATEGY='oidc' requires OIDC_SOURCE in KEK_PROVISIONER_OPTIONS."
                )
            source = build_oidc_source(source_name, options.get("OIDC_SOURCE_OPTIONS", {}))
            return HashiCorpVaultJwtAuthStrategy(options, source, ssl_context=ssl_context)
        log_and_raise_configuration_error(
            logger, f"Unknown CREDENTIAL_STRATEGY '{name}'. Valid: token, approle, iam_aws, oidc"
        )

    def _key_name(self, kek_resource_name: str) -> str:
        """Reduce an identifier to a bare Transit key name.

        Rows record the bare name, but older rows and hand-configured ``KEK_MAP``
        values may carry the full ``{addr}/{mount}/{name}`` URL; a bare name has
        no mount marker to split on and passes through unchanged.
        """
        mount_marker = f"/{self._mount}/"
        if mount_marker in kek_resource_name:
            return kek_resource_name.rsplit(mount_marker, 1)[-1]
        return kek_resource_name

    def ensure_kek(self, kek_resource_name: str, silo_ref: str) -> bool:
        key = self._key_name(kek_resource_name)

        if key in self._ensured:
            return False
        # GET-first probe. Vault Transit's create-key endpoint is idempotent —
        # POST to /transit/keys/{name} on an existing key is a no-op and does
        # not rotate or replace key material — so the probe is not needed for
        # correctness. We do it anyway to match the other provisioners: it keeps
        # CreateKey out of the Vault audit log for keys that already exist, and
        # avoids needing the create capability on every encrypt of a known key.
        try:
            self._request("GET", f"{self._mount}/keys/{key}", None)
            with self._lock:
                self._ensured.add(key)
            return False
        except urllib.error.HTTPError as exc:
            if exc.code != 404:
                raise

        body = {
            "type": self.options.get("KEY_TYPE", "aes256-gcm96"),
            "exportable": bool(self.options.get("EXPORTABLE", False)),
            "allow_plaintext_backup": bool(self.options.get("ALLOW_PLAINTEXT_BACKUP", False)),
            "derived": bool(self.options.get("DERIVED", False)),
        }
        self._request("POST", f"{self._mount}/keys/{key}", body)
        self._log_kek_created(kek=key, silo_ref=silo_ref)
        self._apply_rotation_policy(key)
        with self._lock:
            self._ensured.add(key)
        return True

    def _apply_rotation_policy(self, key: str) -> None:
        """Put the configured automatic rotation interval on a newly created key.

        Applied after creation rather than in the create body so the failure is
        separable: the key exists and can wrap either way, and a deployment that
        can create keys but not write their config gets a usable KEK plus one
        clear line saying rotation is not on it.

        Never raises for the same reason. A missing rotation schedule is a
        degradation to manual rotation, not a reason to fail the encrypt that
        triggered provisioning.
        """
        days = self.rotation_period_days()
        if not days:
            return
        try:
            # Transit takes the interval as a Go duration; seconds is the unit
            # every version accepts without ambiguity over how long a day is.
            self._request("POST", f"{self._mount}/keys/{key}/config", {"auto_rotate_period": days * 86400})
        except Exception as exc:
            self._log_rotation_policy_failed(kek=key, days=days, cause=exc)
            return
        self._log_rotation_policy_set(kek=key, days=days)

    def _request(self, method: str, path: str, body: dict | None) -> dict:
        url = f"{self._addr}/v1/{path}"
        data = json.dumps(body).encode() if body is not None else None
        token = self._strategy.get_credentials()
        headers = {"X-Vault-Token": token, "Content-Type": "application/json"}
        if self._namespace:
            headers["X-Vault-Namespace"] = self._namespace
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urlopen_with_detail(req, timeout=self._request_timeout, context=self._ssl_context) as resp:
                raw = resp.read()
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as exc:
            if exc.code == 204:
                return {}
            raise

    def _do_delete_kek(self, kek_resource_name: str, silo_ref: str) -> DeleteOutcome:
        """Delete a Transit key outright — every version, with no recovery.

        Two calls, because Transit guards deletion with a per-key
        ``deletion_allowed`` latch that is false on a new key. Arming it
        immediately before the delete keeps keys protected the rest of the time;
        arming at creation would leave every KEK deletable for its whole life.

        If the delete fails after the latch is armed, the key is left armed and
        the failure is logged by the caller's funnel. Disarming in a handler
        would risk replacing a real error with the error from the disarm, and the
        retry that follows re-arms it anyway.
        """
        key = self._key_name(kek_resource_name)
        self._request("POST", f"{self._mount}/keys/{key}/config", {"deletion_allowed": True})
        try:
            self._request("DELETE", f"{self._mount}/keys/{key}", None)
        except urllib.error.HTTPError as exc:
            # Already gone is the outcome the caller wanted. Anything else is a
            # real failure and belongs to the funnel in ``delete_kek``.
            if exc.code != 404:
                raise
            self._log_kek_absent_on_delete(kek=key, silo_ref=silo_ref)
        with self._lock:
            self._ensured.discard(key)
        # No waiting period — the key is gone now. delete_kek emits the
        # audit-level log line; the provisioner only performs the API calls.
        return DeleteOutcome(scheduled=False, effective_at=timezone.now())

    def _do_list_kek_names(self, owner_prefix: str) -> list[str]:
        """List Transit key names at the configured mount.

        Vault's LIST is an HTTP ``GET`` with ``?list=true``. It returns every key
        at the mount with no server-side name filter, so *owner_prefix* is unused
        here and the base ``list_kek_names`` applies it. An empty mount answers
        404 rather than an empty list, which is not an error.
        """
        del owner_prefix
        try:
            result = self._request("GET", f"{self._mount}/keys?list=true", None)
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return []
            raise
        return [str(name) for name in result.get("data", {}).get("keys", [])]

    def describe(self) -> str:
        return f"HashiCorpVaultKekProvisioner(addr={self._addr}, mount={self._mount})"
