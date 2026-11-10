"""
Infisical KMS KEK provisioner.

Creates one Infisical KMS key per silo.  Infisical addresses keys by
server-assigned UUID, which the KEK strategy cannot predict — but it also lets
a key be fetched by its operator-chosen name.  That name lookup is the hinge
that makes auto-provisioning possible: the strategy commits to a deterministic
name up front, the key is created under it, and the UUID is recovered from the
name afterwards rather than having to be known in advance.

* The KEK strategy renders a deterministic key **name** from the silo UID
  via ``KEK_TEMPLATE`` (e.g. ``"encryption-suite-{silo_uid}"``).
* This provisioner ensures a key with that name exists in the project,
  creating it on first use.
* :class:`~encryption_suite.adapters.key_stores.infisical.InfisicalKmsAdapter`
  resolves the name to its UUID (cached) before each encrypt.

Pair it with ``PerSiloKekStrategy`` and ``KEK_TEMPLATE``.  For keys
provisioned outside this application (Terraform, web console) and referenced by UUID in
``KEK_MAP``, keep the default ``NullKekProvisioner`` instead.

KEK_PROVISIONER_OPTIONS keys:
  INFISICAL_PROJECT_ID : str  (required) project the keys belong to
  CREDENTIAL_STRATEGY  : str  "universal_auth" (default), "token", "oidc"
  OIDC_SOURCE          : str  required when CREDENTIAL_STRATEGY="oidc"
  OIDC_SOURCE_OPTIONS  : dict optional source-specific options
  INFISICAL_ENDPOINT   : str  base URL for self-hosted (default app.infisical.com)
  ENCRYPTION_ALGORITHM : str  default "aes-256-gcm"
  KEY_DESCRIPTION      : str  optional description set on created keys
"""

from __future__ import annotations

import json
import threading
import urllib.error
import urllib.parse
import urllib.request

from django.utils import timezone

from ..._logging import get_logger
from ...exceptions import log_and_raise_configuration_error
from .._http import urlopen_with_detail, warn_if_plaintext_url
from ..credentials.infisical import (
    InfisicalOidcStrategy,
    InfisicalTokenStrategy,
    InfisicalUniversalAuthStrategy,
)
from ..credentials.oidc_sources import build_oidc_source
from .provisioners import AbstractKekProvisioner, DeleteOutcome

logger = get_logger(__name__)

# Infisical's list endpoint caps ``limit`` at 100.
_PAGE_SIZE = 100


class InfisicalKekProvisioner(AbstractKekProvisioner):
    """Create one Infisical KMS key per silo."""

    # ``DELETE /api/v1/kms/keys/{keyId}`` removes the key at once — there is no
    # scheduled-deletion window as on AWS/GCP/Azure/OCI. So a deletion here is
    # irreversible the instant it returns, and the DeleteOutcome reports
    # ``scheduled=False``. ``minimum_deletion_window_days`` stays ``None`` for the
    # same reason: there is no window to shorten for a test-console key.
    supports_delete = True

    # ``GET /api/v1/kms/keys`` lists a project's keys by name, which is the name
    # space the rows record (see ``InfisicalKmsAdapter.canonical_kek_name``), so
    # the listing can be diffed against them directly.
    supports_enumeration = True

    # ``supports_state_check`` stays False: with no deletion window a key is
    # either present or gone, which enumeration already answers. The key's
    # ``isDisabled`` flag is an availability setting, not a lifecycle state, and
    # reporting it as one would invent a deletion state Infisical does not have.

    # ``supports_tagging`` stays False: the create-key API takes no tag metadata,
    # so any configured TAGS are reported as undeliverable by the startup check.
    # Ownership is the name-prefix marker.

    def __init__(self, options: dict) -> None:
        super().__init__(options)
        self._project_id = options.get("INFISICAL_PROJECT_ID")
        if not self._project_id:
            log_and_raise_configuration_error(
                logger, "InfisicalKekProvisioner requires INFISICAL_PROJECT_ID in KEK_PROVISIONER_OPTIONS."
            )
        self._site_url = options.get("INFISICAL_ENDPOINT", "https://app.infisical.com").rstrip("/")
        warn_if_plaintext_url(self._site_url, "INFISICAL_ENDPOINT", type(self).__name__)
        self._algorithm = options.get("ENCRYPTION_ALGORITHM", "aes-256-gcm")
        self._description = options.get("KEY_DESCRIPTION", "")
        self._strategy = self._build_strategy(options, self._ssl_context)
        self._ensured: set[str] = set()
        self._lock = threading.Lock()

    @staticmethod
    def _build_strategy(options: dict, ssl_context=None):
        name = options.get("CREDENTIAL_STRATEGY", "universal_auth")
        if name == "universal_auth":
            return InfisicalUniversalAuthStrategy(options, ssl_context=ssl_context)
        if name == "token":
            return InfisicalTokenStrategy(options)
        if name == "oidc":
            source_name = options.get("OIDC_SOURCE")
            if not source_name:
                log_and_raise_configuration_error(
                    logger, "CREDENTIAL_STRATEGY='oidc' requires OIDC_SOURCE in KEK_PROVISIONER_OPTIONS."
                )
            source = build_oidc_source(source_name, options.get("OIDC_SOURCE_OPTIONS", {}))
            return InfisicalOidcStrategy(options, source, ssl_context=ssl_context)
        log_and_raise_configuration_error(
            logger, f"Unknown CREDENTIAL_STRATEGY '{name}'. Valid: universal_auth, token, oidc"
        )

    @staticmethod
    def _key_name(kek_resource_name: str) -> str:
        """Reduce an identifier to a bare key name.

        The strategy passes the rendered name, but an operator who configured a
        full resource URL (``{site}/api/v1/kms/keys/{name}``) gets the same
        treatment rather than a lookup for a name with slashes in it.
        """
        if "/keys/" in kek_resource_name:
            return kek_resource_name.rsplit("/keys/", 1)[-1].split("/")[0]
        return kek_resource_name

    def ensure_kek(self, kek_resource_name: str, silo_ref: str) -> bool:
        name = self._key_name(kek_resource_name)

        if name in self._ensured:
            return False
        # Already present?
        try:
            self._get_key_by_name(name)
            self._mark_ensured(name)
            return False
        except urllib.error.HTTPError as exc:
            if exc.code != 404:
                raise

        body = {
            "projectId": self._project_id,
            "name": name,
            "encryptionAlgorithm": self._algorithm,
        }
        if self._description:
            body["description"] = self._description

        try:
            self._create_key(body)
        except urllib.error.HTTPError as exc:
            # Race: another worker created it between the GET and the POST.
            # Re-fetch; if that succeeds the key exists, so swallow the create
            # error. Otherwise re-raise the original create failure.
            try:
                self._get_key_by_name(name)
            except urllib.error.HTTPError:
                raise exc from None
        self._log_kek_created(kek=name, silo_ref=silo_ref)
        self._mark_ensured(name)
        return True

    def _mark_ensured(self, name: str) -> None:
        with self._lock:
            self._ensured.add(name)

    def _get_key_by_name(self, name: str) -> dict:
        query = urllib.parse.urlencode({"projectId": self._project_id})
        url = f"{self._site_url}/api/v1/kms/keys/key-name/{urllib.parse.quote(name, safe='')}?{query}"
        return self._api("GET", url, None)

    def _create_key(self, body: dict) -> dict:
        url = f"{self._site_url}/api/v1/kms/keys"
        return self._api("POST", url, body)

    # ------------------------------------------------------------------
    # Deletion
    # ------------------------------------------------------------------

    def _do_delete_kek(self, kek_resource_name: str, silo_ref: str) -> DeleteOutcome:
        """Delete the Infisical KMS key. Immediate and irreversible — no recovery window.

        ``DELETE`` takes a UUID, so the name is resolved through the
        get-key-by-name endpoint first. Idempotent: a 404 at either step means the
        key is already gone, which is the goal state, so it counts as deleted. The
        local ``_ensured`` cache is cleared so a later ``ensure_kek`` for the same
        name re-provisions rather than trusting the stale entry.

        A UUID-form name never reaches here: only ``KEK_MAP`` deployments record
        one, and those derive no owner prefix, so :meth:`delete_kek` refuses them
        at the ownership gate.
        """
        # Imported at call time: the KMS adapter module owns Infisical's response
        # shapes, but importing it at module scope closes a cycle through
        # ``kms.base``, which imports this package's KEK base in turn.
        from ..key_stores.infisical import _key_id_from_response

        name = self._key_name(kek_resource_name)
        with self._lock:
            self._ensured.discard(name)

        try:
            key_id = _key_id_from_response(self._get_key_by_name(name))
            self._api("DELETE", f"{self._site_url}/api/v1/kms/keys/{urllib.parse.quote(key_id, safe='')}", None)
        except urllib.error.HTTPError as exc:
            if exc.code != 404:
                raise
            self._log_kek_absent_on_delete(kek=name, silo_ref=silo_ref)
            return DeleteOutcome(scheduled=False, effective_at=timezone.now())

        # No waiting period — the key is gone now. delete_kek emits the
        # audit-level log line; the provisioner only performs the API call.
        return DeleteOutcome(scheduled=False, effective_at=timezone.now())

    # ------------------------------------------------------------------
    # Enumeration
    # ------------------------------------------------------------------

    def _do_list_kek_names(self, owner_prefix: str) -> list[str]:
        """List the project's KMS key names.

        Key names are what the rows record (see
        ``InfisicalKmsAdapter.canonical_kek_name``), so reconcile compares like
        with like. There is no deletion window, so a name absent here is a key
        that is genuinely gone.

        *owner_prefix* is passed as the API's ``search`` filter to keep the paging
        short. That filter matches anywhere in the name rather than only at the
        front, so the base :meth:`list_kek_names` prefix re-filter is what
        actually enforces ownership — this only narrows the pages.
        """
        names: list[str] = []
        offset = 0
        while True:
            page = self._list_keys_page(owner_prefix, offset, _PAGE_SIZE)
            keys = page.get("keys") or []
            names.extend(key["name"] for key in keys if isinstance(key, dict) and key.get("name"))
            offset += len(keys)
            # Stop on a short page as well as on the reported total: a server that
            # omits or misreports totalCount must not spin this loop forever.
            if len(keys) < _PAGE_SIZE or offset >= int(page.get("totalCount") or 0):
                break
        return sorted(set(names))

    def _list_keys_page(self, search: str, offset: int, limit: int) -> dict:
        query = urllib.parse.urlencode(
            {"projectId": self._project_id, "offset": offset, "limit": limit, "search": search}
        )
        return self._api("GET", f"{self._site_url}/api/v1/kms/keys?{query}", None)

    def _api(self, method: str, url: str, body: dict | None) -> dict:
        """Issue an authenticated request, retrying once with a fresh token on 401."""
        encoded = json.dumps(body).encode() if body is not None else None

        def _do(token: str) -> dict:
            headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
            if encoded is not None:
                headers["Content-Type"] = "application/json"
            req = urllib.request.Request(url, data=encoded, headers=headers, method=method)
            with urlopen_with_detail(req, timeout=self._request_timeout, context=self._ssl_context) as resp:
                raw = resp.read()
                return json.loads(raw) if raw else {}

        try:
            return _do(self._strategy.get_credentials())
        except urllib.error.HTTPError as exc:
            if exc.code == 401:
                self._strategy.invalidate()
                return _do(self._strategy.get_credentials())
            raise

    def describe(self) -> str:
        return f"InfisicalKekProvisioner(project={self._project_id}, site={self._site_url})"
