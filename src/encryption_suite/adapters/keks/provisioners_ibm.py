"""
IBM Key Protect / HPCS KEK provisioner.

Creates root keys via the Key Protect REST API. The strategy returns the
key NAME (from ``KEK_TEMPLATE``). Key Protect addresses keys by UUID, not
by name, so existence is checked by listing keys and matching the ``name``
field; a key is created only when no match is found.

KEK_PROVISIONER_OPTIONS keys:
  IBM_INSTANCE_ID   : str  (required) service instance GUID
  IBM_REGION        : str  region slug, e.g. "us-south"  (or)
  IBM_ENDPOINT      : str  full base URL (overrides region)
  CREDENTIAL_STRATEGY  : str  "api_key" (default), "iam_assume", "container",
                              "vpc_instance" (the latter two need the ``ibm`` extra)
  EXTRACTABLE          : bool default False (root key, never leaves)
  KEY_DESCRIPTION      : str  default "django-encryption-suite KEK"
  KEK_ROTATION_PERIOD_DAYS : int  optional, e.g. 90. Written as the key's rotation
                              policy. Key Protect counts in **whole months of
                              exactly 30 days**, 1 to 12, so this must be a
                              multiple of 30 and no more than 360.

``PROVIDER_DELETION_WINDOW_DAYS`` is **not accepted** here and is refused at
construction. Key Protect's recovery period is a fixed 30 days that no request
can shorten or extend, so an option carried over from an AWS or GCP
configuration would be read and silently ignored.

Deletion is Key Protect's own soft delete: the key stops serving wrap and unwrap
at once — which is what crypto-shreds the DEKs under it — and stays restorable
for 30 days, after which its contents are shredded. That is the same shape as an
Azure key awaiting purge or an AWS key in its pending-deletion window.

Deletion, enumeration and the state probe need IAM beyond wrap/unwrap: the
*Manager* role on the instance covers key creation, listing, reading and
deletion. Restoring a deleted key needs Manager too.
"""

from __future__ import annotations

import datetime
import json
import threading
import urllib.error
import urllib.request

from django.utils import timezone

from ..._logging import get_logger
from ...exceptions import log_and_raise_configuration_error
from .._http import urlopen_with_detail, warn_if_plaintext_url
from ..credentials.ibm import (
    IbmApiKeyStrategy,
    IbmContainerStrategy,
    IbmIamAssumeStrategy,
    IbmVpcInstanceStrategy,
)
from .provisioners import AbstractKekProvisioner, DeleteOutcome, KekState

# Key Protect's list endpoint caps ``limit`` at 200 keys per page; bound the scan.
_KEY_LIST_PAGE = 200
_KEY_LIST_MAX_PAGES = 50

# Key Protect keeps a deleted key restorable for 30 days, then shreds its
# contents. Fixed by the service — no request or account setting changes it — so
# it is a constant here rather than an option, and the only source for the date a
# deletion becomes final: the delete response reports when the key was deleted,
# never when it will be purged.
_RESTORE_WINDOW_DAYS = 30

# Key Protect expresses a rotation policy in whole months, and defines a month as
# exactly 30 days for this purpose ("If a key is set to be rotated every 2 months,
# for example, it will be rotated every 60 days, regardless of the number of days
# in a particular month"). So the package's provider-neutral KEK_ROTATION_PERIOD_DAYS
# converts exactly, but only for multiples of 30.
_ROTATION_MONTH_DAYS = 30
_MAX_ROTATION_MONTHS = 12

_POLICY_CONTENT_TYPE = "application/vnd.ibm.kms.policy+json"

logger = get_logger(__name__)


def _is_deleted(resource: dict) -> bool:
    """Whether a listed key resource is a deleted one."""
    # Imported at call time: the KMS adapter module owns Key Protect's response
    # shapes, but importing it at module scope closes a cycle through ``kms.base``,
    # which imports this package's KEK base in turn.
    from ..key_stores.ibm import is_deleted

    return is_deleted(resource)


def _first_resource(payload: dict) -> dict:
    """Return the single key resource from a Key Protect response body."""
    resources = (payload or {}).get("resources") or []
    return resources[0] if resources and isinstance(resources[0], dict) else {}


def _purge_date(deletion_date: str | None) -> datetime.datetime:
    """Return when a key deleted at *deletion_date* stops being restorable.

    Key Protect reports when the key was deleted but never when it will be
    purged, so the date is derived by adding the service's fixed restore window.
    A missing or unparseable date falls back to now plus the same window: the
    outcome is advisory, and a deletion that succeeded must not be reported as a
    failure because a timestamp did not parse.
    """
    window = datetime.timedelta(days=_RESTORE_WINDOW_DAYS)
    if deletion_date:
        try:
            parsed = datetime.datetime.fromisoformat(str(deletion_date).replace("Z", "+00:00"))
        except ValueError:
            parsed = None
        if parsed is not None:
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=datetime.UTC)
            return parsed + window
    return timezone.now() + window


class IbmKekProvisioner(AbstractKekProvisioner):
    """Create one IBM Key Protect root key per silo, by name."""

    # ``DELETE /api/v2/keys/{id}`` takes the key out of service immediately and
    # starts Key Protect's 30-day restore window, so the outcome reports
    # ``scheduled=True`` with the end of that window as the effective date.
    supports_delete = True

    # ``GET /api/v2/keys`` lists the instance's keys by name, which is the name
    # space the rows record (see ``IbmKmsAdapter.canonical_kek_name``), so the
    # listing can be diffed against them directly.
    supports_enumeration = True

    # A deleted key stays readable through its restore window and reports
    # ``deleted`` plus a ``deletionDate``, so "already on the way out" is a state
    # worth probing before reporting a key as orphaned.
    supports_state_check = True

    # ``None``: Key Protect takes no per-key window argument. The 30 days are
    # fixed by the service, so there is nothing to shorten for a console key —
    # the same position Azure is in with its vault retention.
    minimum_deletion_window_days = None

    # ``supports_tagging`` stays False: a Key Protect key cannot be tagged at all.
    # The create-key body takes no tag metadata, and Global Tagging — where IBM
    # Cloud tags live — refuses a key CRN with TAG_RESOURCE_NOT_SUPPORTED, so
    # there is no second call to add either. The Key Protect *instance* is
    # taggable, but it is provisioned outside this package. Any configured TAGS
    # are reported as undeliverable by the startup check, and ownership is the
    # name-prefix marker.

    # Key Protect takes a per-key rotation policy of 1 to 12 whole 30-day months.
    # The range is the shared floor/ceiling check; only the multiple-of-30 rule
    # needs an override, because no range can express it.
    supports_rotation_policy = True
    minimum_rotation_days = _ROTATION_MONTH_DAYS
    maximum_rotation_days = _MAX_ROTATION_MONTHS * _ROTATION_MONTH_DAYS
    rotation_policy_remedy = (
        "Setting a rotation policy needs the Manager role on the Key Protect instance; apply the "
        "policy by hand, or grant the role and recreate the key."
    )

    def _validate_rotation_period(self, options: dict) -> None:
        """Refuse a ``KEK_ROTATION_PERIOD_DAYS`` Key Protect cannot express exactly.

        The base class covers the range. Key Protect needs one thing more, because
        its policy is counted in months while the package's option is in days: the
        value must be a whole number of 30-day months.

        Rounding is deliberately not offered. Silently rotating every 90 days
        because 100 was asked for gives a deployment a cryptoperiod nobody chose,
        which is exactly the sort of thing an auditor asks about — and the operator
        would have no way to notice. Refusing names the two nearest legal values
        instead.

        Checked at construction, so ``manage.py check`` reports it at deploy
        through ``check_kms_adapter_construction`` rather than the policy call
        failing after a tenant's key has already been created.
        """
        super()._validate_rotation_period(options)
        if "KEK_ROTATION_PERIOD_DAYS" not in options:
            return
        # Safe to convert: the base call above refused anything non-numeric.
        configured = int(options["KEK_ROTATION_PERIOD_DAYS"])
        if configured % _ROTATION_MONTH_DAYS:
            lower = (configured // _ROTATION_MONTH_DAYS) * _ROTATION_MONTH_DAYS
            log_and_raise_configuration_error(
                logger,
                f"IbmKekProvisioner: KEK_ROTATION_PERIOD_DAYS is {configured}, but Key Protect sets a "
                f"rotation policy in whole months of exactly {_ROTATION_MONTH_DAYS} days, so only "
                f"multiples of {_ROTATION_MONTH_DAYS} can be expressed. Use {lower} or "
                f"{lower + _ROTATION_MONTH_DAYS} — the package will not round for you, because a "
                "rotation interval you did not choose is worse than one that is refused.",
            )

    def _validate_deletion_window(self, options: dict) -> None:
        """Refuse ``PROVIDER_DELETION_WINDOW_DAYS``, which cannot reach Key Protect.

        Every other provider with a window takes it from this option, so carrying
        one over from an AWS or GCP configuration is the likely mistake — and
        silently ignoring it would leave an operator believing they had changed a
        window the service fixes at 30 days.
        """
        if "PROVIDER_DELETION_WINDOW_DAYS" not in options:
            return
        log_and_raise_configuration_error(
            logger,
            "IbmKekProvisioner: PROVIDER_DELETION_WINDOW_DAYS is set in KEK_PROVISIONER_OPTIONS, but "
            f"Key Protect's recovery period is a fixed {_RESTORE_WINDOW_DAYS} days that no request can "
            "change — nothing sent from here can alter it. Remove the option.",
        )

    def __init__(self, options: dict) -> None:
        super().__init__(options)
        self._strategy = self._build_strategy(options, self._ssl_context)
        self._base_url = self._resolve_endpoint(options)
        warn_if_plaintext_url(self._base_url, "IBM_ENDPOINT", type(self).__name__)
        if not options.get("IBM_INSTANCE_ID"):
            log_and_raise_configuration_error(
                logger, "IbmKekProvisioner requires IBM_INSTANCE_ID in KEK_PROVISIONER_OPTIONS."
            )
        self._instance_id = options["IBM_INSTANCE_ID"]
        self._ensured: set[str] = set()
        self._lock = threading.Lock()

    @staticmethod
    def _build_strategy(options: dict, ssl_context):
        name = options.get("CREDENTIAL_STRATEGY", "api_key")
        if name == "api_key":
            return IbmApiKeyStrategy(options, ssl_context=ssl_context)
        if name == "iam_assume":
            return IbmIamAssumeStrategy(options, ssl_context=ssl_context)
        if name == "container":
            return IbmContainerStrategy(options)
        if name == "vpc_instance":
            return IbmVpcInstanceStrategy(options)
        log_and_raise_configuration_error(
            logger,
            f"Unknown CREDENTIAL_STRATEGY '{name}'. Valid: api_key, iam_assume, container, vpc_instance",
        )

    @staticmethod
    def _resolve_endpoint(options: dict) -> str:
        if "IBM_ENDPOINT" in options:
            return options["IBM_ENDPOINT"].rstrip("/")
        region = options.get("IBM_REGION")
        if not region:
            log_and_raise_configuration_error(logger, "IbmKekProvisioner: either IBM_ENDPOINT or IBM_REGION required.")
        return f"https://{region}.kms.cloud.ibm.com"

    @staticmethod
    def _key_name(kek_resource_name: str) -> str:
        """Reduce an identifier to a bare key name.

        The strategy passes the rendered name, but a full resource URL
        (``{endpoint}/api/v2/keys/{name}``) gets the same treatment rather than a
        lookup for a name with slashes in it.
        """
        if "/keys/" in kek_resource_name:
            return kek_resource_name.rsplit("/keys/", 1)[-1].split("/")[0]
        return kek_resource_name

    def ensure_kek(self, kek_resource_name: str, silo_ref: str) -> bool:
        key = self._key_name(kek_resource_name)

        if key in self._ensured:
            return False
        # Key Protect has no name lookup and allows duplicate names, so check
        # existence by listing and matching the name; only create when none
        # exists (otherwise a cold start would recreate a duplicate every time).
        if self._find_key(key) is not None:
            with self._lock:
                self._ensured.add(key)
            return False
        body = {
            "metadata": {
                "collectionType": "application/vnd.ibm.kms.key+json",
                "collectionTotal": 1,
            },
            "resources": [
                {
                    "name": key,
                    "description": self.options.get("KEY_DESCRIPTION", "django-encryption-suite KEK"),
                    "extractable": bool(self.options.get("EXTRACTABLE", False)),
                }
            ],
        }
        try:
            created = self._http("POST", "/api/v2/keys", body=body)
        except urllib.error.HTTPError as exc:
            if exc.code != 409:
                raise
            # Another worker won the race and owns the follow-up policy call too.
            self._log_kek_already_present(kek=key)
        else:
            self._log_kek_created(kek=key, silo_ref=silo_ref)
            self._apply_rotation_policy(_first_resource(created).get("id", ""), key)
        with self._lock:
            self._ensured.add(key)
        return True

    def _apply_rotation_policy(self, key_id: str, name: str) -> None:
        """Put the configured automatic rotation schedule on a newly created key.

        Applied after creation because Key Protect's create call takes no rotation
        policy — it is a second call, to a separate policies endpoint.

        Written **at creation only**, like tags: ``ensure_kek`` returns early for a
        key that already exists, so changing ``KEK_ROTATION_PERIOD_DAYS`` later leaves
        existing keys on the schedule they were made with. A key adopted rather
        than created is left alone entirely — its policy is the operator's, and
        overwriting it would be the same overreach as retagging someone else's key.

        A failure here is logged, not raised. The key itself is created and usable,
        so failing the request would break a tenant's first save over metadata; and
        because the retry finds the key already present, the policy would never be
        attempted again anyway. What must not happen is silence: a key left on
        manual rotation while the operator believes a schedule is running is the
        one outcome nobody detects, so it gets a WARNING naming the key and the
        permission.
        """
        rotation_days = self.rotation_period_days()
        if not rotation_days or not key_id:
            return
        months = rotation_days // _ROTATION_MONTH_DAYS
        body = {
            "metadata": {"collectionType": _POLICY_CONTENT_TYPE, "collectionTotal": 1},
            "resources": [{"type": _POLICY_CONTENT_TYPE, "rotation": {"interval_month": months}}],
        }
        try:
            self._http(
                "PUT",
                f"/api/v2/keys/{key_id}/policies?policy=rotation",
                body=body,
                extra_headers={"Content-Type": _POLICY_CONTENT_TYPE, "Accept": _POLICY_CONTENT_TYPE},
            )
        except Exception as exc:
            self._log_rotation_policy_failed(kek=name, days=rotation_days, cause=exc, months=months)
            return
        self._log_rotation_policy_set(kek=name, days=rotation_days, months=months)

    def _iter_live_keys(self):
        """Yield the instance's live key resources, a page at a time.

        Deleted keys are filtered out: Key Protect keeps one listed and restorable
        for 30 days, and every caller here wants the keys that can still wrap. Left
        in, a deleted key would make ``ensure_kek`` skip re-provisioning a name that
        no longer works, and would make reconcile report a shredded key as present.
        """
        offset = 0
        for _ in range(_KEY_LIST_MAX_PAGES):
            data = self._http("GET", f"/api/v2/keys?limit={_KEY_LIST_PAGE}&offset={offset}", body=None)
            resources = data.get("resources") or []
            for key in resources:
                if isinstance(key, dict) and not _is_deleted(key):
                    yield key
            total = (data.get("metadata") or {}).get("collectionTotal", 0)
            offset += _KEY_LIST_PAGE
            # Stop on a short page as well as on the reported total: a server
            # that omits or misreports collectionTotal must not spin this walk.
            if len(resources) < _KEY_LIST_PAGE or offset >= total:
                return

    def _find_key(self, name: str) -> dict | None:
        """Return the live key resource with this ``name``, or ``None``.

        Names need not be unique in Key Protect, so the first live match wins —
        the same rule the KMS adapter's resolution follows, so both address the
        same key.
        """
        for key in self._iter_live_keys():
            if key.get("name") == name:
                return key
        return None

    # ------------------------------------------------------------------
    # Deletion
    # ------------------------------------------------------------------

    def _do_delete_kek(self, kek_resource_name: str, silo_ref: str) -> DeleteOutcome:
        """Delete the Key Protect root key behind *kek_resource_name*.

        The key stops serving wrap and unwrap immediately and stays restorable for
        30 days, which is the date the outcome reports. Deleting takes every
        version of the key with it, which is what crypto-shreds the DEKs wrapped
        under any of them.

        ``DELETE`` takes a UUID, so the name is resolved by listing first.
        Idempotent: a name with no live key behind it, and a 404 from the delete
        itself, both mean the key is already gone — the goal state. The local
        ``_ensured`` cache is cleared so a later ``ensure_kek`` for the same name
        re-provisions rather than trusting the stale entry.

        A UUID-form name never reaches here: only ``KEK_MAP`` deployments record
        one, and those derive no owner prefix, so :meth:`delete_kek` refuses them
        at the ownership gate.
        """
        name = self._key_name(kek_resource_name)
        with self._lock:
            self._ensured.discard(name)

        key = self._find_key(name)
        if key is None:
            self._log_kek_absent_on_delete(kek=name, silo_ref=silo_ref)
            return DeleteOutcome(scheduled=False, effective_at=timezone.now())

        try:
            # ``return=representation`` so the response carries the deletionDate
            # the restore window is measured from, rather than a bare 204.
            deleted = self._http(
                "DELETE",
                f"/api/v2/keys/{key['id']}",
                body=None,
                extra_headers={"prefer": "return=representation"},
            )
        except urllib.error.HTTPError as exc:
            if exc.code != 404:
                raise
            self._log_kek_absent_on_delete(kek=name, silo_ref=silo_ref)
            return DeleteOutcome(scheduled=False, effective_at=timezone.now())

        resource = _first_resource(deleted)
        return DeleteOutcome(scheduled=True, effective_at=_purge_date(resource.get("deletionDate")))

    def _do_describe_kek_state(self, kek_resource_name: str) -> KekState:
        """Read whether the key is live, inside its restore window, or unaccounted for.

        A name with neither a live nor a deleted key behind it reports ``unknown``
        rather than active: it may have been purged, or be unreadable by this
        identity, and neither is evidence the key is healthy.
        """
        name = self._key_name(kek_resource_name)
        if self._find_key(name) is not None:
            return KekState(state=KekState.ACTIVE)
        for key in self._iter_all_keys():
            if key.get("name") == name and _is_deleted(key):
                return KekState(
                    state=KekState.PENDING_DELETION,
                    effective_at=_purge_date(key.get("deletionDate")),
                )
        return KekState.unknown()

    def _iter_all_keys(self):
        """Yield every key resource, deleted ones included (state probe only)."""
        offset = 0
        for _ in range(_KEY_LIST_MAX_PAGES):
            data = self._http("GET", f"/api/v2/keys?limit={_KEY_LIST_PAGE}&offset={offset}", body=None)
            resources = data.get("resources") or []
            for key in resources:
                if isinstance(key, dict):
                    yield key
            total = (data.get("metadata") or {}).get("collectionTotal", 0)
            offset += _KEY_LIST_PAGE
            # Stop on a short page as well as on the reported total: a server
            # that omits or misreports collectionTotal must not spin this walk.
            if len(resources) < _KEY_LIST_PAGE or offset >= total:
                return

    # ------------------------------------------------------------------
    # Enumeration
    # ------------------------------------------------------------------

    def _do_list_kek_names(self, owner_prefix: str) -> list[str]:
        """List the instance's live key names.

        Key names are what the rows record (see
        ``IbmKmsAdapter.canonical_kek_name``), so reconcile compares like with
        like. *owner_prefix* is not sent to the provider — Key Protect's list
        endpoint filters by state and extractability, not by name — so the base
        :meth:`list_kek_names` prefix filter is what enforces ownership.

        Deleted keys are omitted, so a name absent here is one that can no longer
        wrap anything, whatever remains restorable behind it. Duplicate names are
        possible in Key Protect and collapse to one entry, which is the right
        answer for a reconcile diff against rows keyed by name.
        """
        return sorted({key["name"] for key in self._iter_live_keys() if key.get("name")})

    def _http(self, method: str, path: str, body: dict | None, extra_headers: dict | None = None) -> dict:
        url = f"{self._base_url}{path}"
        data = json.dumps(body).encode() if body is not None else None
        token = self._strategy.get_credentials()
        headers = {
            "Authorization": f"Bearer {token}",
            "bluemix-instance": self._instance_id,
            "Content-Type": "application/vnd.ibm.kms.key+json",
            "Accept": "application/vnd.ibm.kms.key+json",
        }
        headers.update(extra_headers or {})
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        with urlopen_with_detail(req, timeout=self._request_timeout, context=self._ssl_context) as resp:
            raw = resp.read()
            return json.loads(raw) if raw else {}

    def describe(self) -> str:
        return f"IbmKekProvisioner(endpoint={self._base_url})"
