"""
OCI Vault KEK provisioner.

OCI Vault keys are addressed by server-assigned **OCID**, which the KEK
strategy cannot predict — but a key also carries an operator-chosen
**display name**, and the OCI management API can list and create keys. That
name is the hinge that makes auto-provisioning possible, the same pattern the
Infisical provisioner uses for its server-assigned UUIDs:

* The KEK strategy renders a deterministic display name from the silo UID
  via ``KEK_TEMPLATE`` (e.g. ``"encryption_suite-{silo_uid}"``).
* This provisioner ensures a key with that display name exists in the
  compartment, creating it on first use.
* :class:`~encryption_suite.adapters.key_stores.oci.OCIVaultAdapter` resolves the
  display name to its OCID (cached) before each encrypt.

Pair it with ``PerSiloKekStrategy`` and ``KEK_TEMPLATE``. For keys
provisioned outside this application (Terraform, OCI Console) and referenced by OCID in
``KEK_MAP`` / ``SHARED_KEK_ID``, keep the default ``NullKekProvisioner`` — this
provisioner treats an OCID-form identifier as already-provisioned and is a
no-op for it.

Provisioning needs the **management** endpoint and an identity with
**manage keys** in the compartment (broader than the encrypt/decrypt the
adapter needs). Deletion, enumeration and the state probe need no permission
beyond that: ``manage keys`` already covers ScheduleKeyDeletion, ListKeys and
GetKey, so an identity that can provision can also delete and reconcile.

KEK_PROVISIONER_OPTIONS keys:
  OCI_VAULT_MANAGEMENT_ENDPOINT : str  (required) vault management endpoint
  OCI_COMPARTMENT_OCID          : str  (required) compartment OCID for new keys
  CREDENTIAL_STRATEGY           : str  "api_key" (default), "instance_principal",
                                       "resource_principal", "oke_workload_identity"
                                       (+ that strategy's own option keys)
  OCI_KEY_PROTECTION_MODE       : str  "HSM" (default) or "SOFTWARE"
  OCI_KEY_ALGORITHM             : str  "AES" (default)
  OCI_KEY_LENGTH                : int  key length in bytes (default 32 = AES-256)
  OCI_KEY_PROVISION_TIMEOUT_SECONDS : int  max seconds to wait for a new key to
                                       reach ENABLED before encrypt (default 60)
  KEK_ROTATION_PERIOD_DAYS          : int  optional, e.g. 90. Written as the key's
                                       auto-rotation schedule on the create call.
                                       OCI accepts 60 to 365 days. Only a
                                       **virtual private vault** can run one; on a
                                       standard vault the key is still created and
                                       one WARNING says it will not rotate.
  TAGS                          : dict optional {key: value} freeform tags,
                                       applied verbatim to the created key
  DEFINED_TAGS                  : dict optional {namespace: {key: value}}
                                       defined tags. OCI's cost-tracking tags
                                       are defined tags, so chargeback uses this
                                       rather than TAGS
  PROVIDER_DELETION_WINDOW_DAYS : int  default 7. Sent as ScheduleKeyDeletion's
                                       ``time_of_deletion`` (now + this many
                                       days); OCI accepts 7-30 and rejects
                                       anything else. This is OCI's own waiting
                                       period, which starts where the package's
                                       KEY_DELETION_WINDOW_DAYS ends: the key is
                                       unusable for its duration and recoverable
                                       only at the provider (`oci kms management
                                       key cancel-deletion`). The admin test
                                       console's keys always use OCI's 7-day
                                       minimum; see
                                       ``AbstractKekProvisioner.deletion_window_days``.

For values a static dict cannot express, subclass this provisioner and override
``build_tags`` (freeform) or ``build_defined_tags`` (defined).

Requires the ``oci`` extra: ``pip install django-encryption-suite[oci]``
"""

from __future__ import annotations

import datetime
import threading

from django.utils import timezone

from ..._logging import get_logger
from ...exceptions import KekPendingDeletionError, log_and_raise_configuration_error
from ..credentials.oci import build_oci_credential_strategy, require_oci
from .provisioners import AbstractKekProvisioner, DeleteOutcome, KekState

logger = get_logger(__name__)

# Lifecycle states that count as "the key already exists" — anything not being
# deleted. Mirrors the adapter's resolution so the two agree on what's usable.
_LIVE_STATES = ("ENABLED", "CREATING", "UPDATING", "DISABLED", "DISABLING")

# OCI's own bounds on an auto-rotation interval, enforced by the shared range
# check at construction so a wrong value is reported by ``manage.py check``.
_MIN_ROTATION_DAYS = 60
_MAX_ROTATION_DAYS = 365

# The key still exists and still holds its display name, but OCI's own deletion
# window is running and no crypto call under it will succeed. Kept distinct from
# both live and gone: a key here can neither be used nor recreated over.
_PENDING_DELETION_STATES = ("SCHEDULING_DELETION", "PENDING_DELETION")


class OciKekProvisioner(AbstractKekProvisioner):
    """Ensure one OCI Vault key per silo, addressed by display name."""

    supports_tagging = True

    # ScheduleKeyDeletion always imposes a waiting period, so a deletion here is
    # reversible at the provider for the whole window and the DeleteOutcome
    # reports ``scheduled=True``.
    supports_delete = True

    # ListKeys returns display names, which is the name space the rows record
    # (see ``OCIVaultAdapter.canonical_kek_name``), so the listing can be diffed
    # against them directly.
    supports_enumeration = True

    # GetKey reports lifecycle_state, so a key inside OCI's deletion window can
    # be recognized without attempting to use it.
    supports_state_check = True

    # OCI refuses a time_of_deletion less than 7 days out, so its floor equals
    # the package default: the test console's shorter window is a no-op here.
    minimum_deletion_window_days = 7
    maximum_deletion_window_days = 30

    # CreateKeyDetails carries an auto-rotation schedule, so the interval goes on
    # the same call that makes the key. OCI takes 60 to 365 days, a far higher
    # floor than any other provider here.
    #
    # Whether the schedule actually runs depends on the *vault*, not the key: only
    # a virtual private vault rotates automatically. That is not something this
    # provisioner can check cheaply — the vault type lives on the Vault resource,
    # which needs a different client, a regional control-plane endpoint, a vault
    # OCID this configuration does not carry, and an inspect permission outside
    # the `manage keys` the rest of this class asks for. So the standard-vault
    # case is handled where it shows up, on the create call. See ``_create_key``.
    supports_rotation_policy = True
    minimum_rotation_days = _MIN_ROTATION_DAYS
    maximum_rotation_days = _MAX_ROTATION_DAYS
    rotation_policy_failure_opening = (
        "OCI refused the auto-rotation schedule; the key works but will not rotate on its own."
    )
    rotation_policy_remedy = (
        "Automatic rotation runs only in a virtual private vault — a standard vault leaves its "
        "keys on manual rotation. Move the vault, or remove KEK_ROTATION_PERIOD_DAYS and rotate "
        "by hand."
    )

    def __init__(self, options: dict) -> None:
        super().__init__(options)
        self._management_endpoint = (options.get("OCI_VAULT_MANAGEMENT_ENDPOINT") or "").rstrip("/")
        self._compartment_id = options.get("OCI_COMPARTMENT_OCID")
        if not self._management_endpoint or not self._compartment_id:
            log_and_raise_configuration_error(
                logger,
                "OciKekProvisioner requires OCI_VAULT_MANAGEMENT_ENDPOINT and "
                "OCI_COMPARTMENT_OCID in KEK_PROVISIONER_OPTIONS.",
            )
        self._protection_mode = options.get("OCI_KEY_PROTECTION_MODE", "HSM")
        self._algorithm = options.get("OCI_KEY_ALGORITHM", "AES")
        self._key_length = int(options.get("OCI_KEY_LENGTH", 32))
        # Seconds to wait for a freshly created key to reach ENABLED before the
        # crypto endpoint can use it. Configurable: HSM keys or a slow region
        # may need longer; a fast path may want it tighter.
        self._provision_timeout = int(options.get("OCI_KEY_PROVISION_TIMEOUT_SECONDS", 60))
        self._strategy = build_oci_credential_strategy(options)
        self._client = None
        self._ensured: set[str] = set()
        # Serializes the list-then-create window so two threads in this process
        # don't both create a key for the same name. Cross-process races are
        # still possible (OCI does not enforce unique display names); the
        # adapter flags duplicate names at resolution time.
        self._lock = threading.Lock()

    def _get_client(self):
        if self._client is not None:
            return self._client
        require_oci()
        from oci.key_management import KmsManagementClient

        config, signer = self._strategy.get_credentials()
        if signer is not None:
            self._client = KmsManagementClient(config, signer=signer, service_endpoint=self._management_endpoint)
        else:
            self._client = KmsManagementClient(config, service_endpoint=self._management_endpoint)
        return self._client

    def ensure_kek(self, kek_resource_name: str, silo_ref: str) -> bool:
        # An OCID-form identifier (KEK_MAP / SHARED_KEK_ID) is already a concrete
        # key; there is nothing to provision.
        if kek_resource_name.startswith("ocid1.key."):
            return False
        name = kek_resource_name
        if name in self._ensured:
            return False
        with self._lock:
            if name in self._ensured:
                return False
            if self._find_key_by_name(name) is not None:
                self._ensured.add(name)
                return False
            self._reject_pending_deletion(name)
            self._create_key(name, silo_ref)
            self._log_kek_created(kek=name, silo_ref=silo_ref)
            self._ensured.add(name)
        return True

    def build_defined_tags(self, silo_ref: str) -> dict:
        """Return OCI *defined* tags for a new key: ``{namespace: {key: value}}``.

        The defined-tag counterpart of :meth:`build_tags`, separate because the
        nested shape does not fit that flat contract. OCI has two tag systems and
        only defined tags can be cost-tracking tags, so an organization doing
        chargeback on OCI configures ``DEFINED_TAGS``, not ``TAGS``.

        Default is the operator's ``DEFINED_TAGS`` verbatim. The override rules
        and hazards documented on :meth:`build_tags` apply here unchanged.
        """
        if not self.supports_tagging:
            return {}
        return {ns: dict(pairs) for ns, pairs in (self.options.get("DEFINED_TAGS", {}) or {}).items()}

    def _reject_pending_deletion(self, name: str) -> None:
        """Raise when the name belongs to a key inside OCI's deletion window.

        OCI does not enforce unique display names, so nothing stops a second key
        being created here — which is exactly why this check exists. The old key
        keeps the name until it is destroyed, so creating over it leaves two keys
        answering to one name, and only one of them holds the material that
        decrypts what was written before. Typed so the engine can tell this apart
        from a key that was never created and record the state on the key's row.
        No logging here — this runs inside the engine's ensure funnel, which
        emits exactly one line.
        """
        pending = self._find_key_by_name(name, _PENDING_DELETION_STATES)
        if pending is None:
            return
        scheduled_for = self._deletion_time(pending)
        raise KekPendingDeletionError(
            f"OciKekProvisioner: KEK '{name}' is scheduled for deletion "
            f"(time_of_deletion {scheduled_for}) and cannot be used or "
            "recreated under the same name. Cancel the deletion at the provider "
            "(`oci kms management key cancel-deletion`) to recover it, or point this silo at a "
            "different KEK.",
            effective_at=self._deletion_date(scheduled_for),
        )

    def _deletion_time(self, key):
        """The key's ``time_of_deletion``, fetching it when the caller has a summary.

        ``ListKeys`` returns *summaries*, which carry no deletion time — only
        ``GetKey`` does. Every pending-deletion path here starts from the listing,
        so without this the date is always absent and callers fall back to a
        computed one: the app would show a date it worked out itself while OCI
        holds the real one, and the two need not agree (an operator can reschedule
        a deletion at the provider). Confirmed live 2026-08-03, where the value
        arrived as ``None``.

        One extra call, only on the pending path, which is rare. A failure
        degrades to ``None`` and the caller's fallback — a date that is close is
        worth more than an exception on an advisory read.
        """
        when = getattr(key, "time_of_deletion", None)
        if when is not None:
            return when
        try:
            return getattr(self._get_client().get_key(key.id).data, "time_of_deletion", None)
        except Exception:
            return None

    def _list_keys(self):
        """Every key in the compartment, in whatever state OCI reports."""
        oci = require_oci()
        client = self._get_client()
        return oci.pagination.list_call_get_all_results(client.list_keys, self._compartment_id).data

    def _find_key_by_name(self, name: str, states: tuple[str, ...] = _LIVE_STATES):
        """Return the one key named *name* in one of *states*, or ``None``.

        Refuses an ambiguous name rather than picking from it: OCI allows
        duplicate display names, the adapter already refuses to resolve one, and
        a provisioner that quietly chose a key here could create under one and
        delete another.
        """
        matches = [k for k in self._list_keys() if k.display_name == name and k.lifecycle_state in states]
        distinct = {k.id for k in matches}
        if not distinct:
            return None
        if len(distinct) > 1:
            raise RuntimeError(
                f"OciKekProvisioner: multiple distinct OCI keys named '{name}' in compartment "
                f"{self._compartment_id}. OCI does not enforce unique display names; remove or "
                "disable the duplicates so the name resolves to a single key."
            )
        return matches[0]

    def _create_key(self, name: str, silo_ref: str) -> None:
        """Create the key, then block until OCI reports it usable.

        When ``KEK_ROTATION_PERIOD_DAYS`` is set the schedule goes on this call. A
        **standard vault cannot run one** — only a virtual private vault can — and
        it refuses the request rather than ignoring the field, which would
        otherwise cost that deployment every key it ever provisions. So a rejected
        interval degrades: the key is created again without the schedule, and one
        WARNING says it will not rotate on its own.

        That is deliberately unlike the package's usual rule, where an unhonorable
        ``KEK_ROTATION_PERIOD_DAYS`` is refused at construction — but there the option
        is unhonorable for the *provider*, which is knowable at deploy. Here it
        depends on the vault, and refusing at construction would mean either
        reading a vault this provisioner is not entitled to read or making every
        OCI deployment declare its vault type by hand.

        Only a 400 is retried, and only when a schedule was asked for. Anything
        else — an authorization failure, a throttle, a bad key shape — is not a
        rotation problem, and swallowing it into a second attempt would report the
        same error one call later.
        """
        rotation_days = self.rotation_period_days()
        try:
            key_id = self._send_create(name, silo_ref, rotation_days)
        except Exception as exc:
            # Duck-typed rather than caught as oci.exceptions.ServiceError: the
            # SDK is an optional extra, and the decision here is only "did the
            # service reject the request".
            if not rotation_days or getattr(exc, "status", None) != 400:
                raise
            key_id = self._create_without_rotation(name, silo_ref, rotation_days, exc)
        self._wait_until_enabled(key_id)

    def _wait_until_enabled(self, key_id: str) -> None:
        """Block until OCI reports *key_id* usable for encrypt.

        OCI key creation is async: the key starts in CREATING and the crypto
        endpoint returns 404/NotAuthorizedOrNotFound until it reaches ENABLED, so
        ``ensure_kek`` must not return before then. A one-time cost per silo, on
        its first encrypt. Software keys settle in seconds; the cap
        (``OCI_KEY_PROVISION_TIMEOUT_SECONDS``) keeps a hung operation from
        wedging the worker — a timeout raises and surfaces as a retryable
        provisioning error rather than a silent wrong-state key.
        """
        oci = require_oci()
        client = self._get_client()
        oci.wait_until(
            client,
            client.get_key(key_id),
            "lifecycle_state",
            "ENABLED",
            max_wait_seconds=self._provision_timeout,
        )

    def _send_create(self, name: str, silo_ref: str, rotation_days: int | None) -> str:
        """Send one CreateKey and return the new key's OCID.

        Split from :meth:`_create_key` so the request can be reissued without the
        rotation schedule, and so the surrounding logic can be exercised without
        the ``oci`` extra installed.
        """
        require_oci()
        from oci.key_management.models import AutoKeyRotationDetails, CreateKeyDetails, KeyShape

        details = CreateKeyDetails(
            compartment_id=self._compartment_id,
            display_name=name,
            key_shape=KeyShape(algorithm=self._algorithm, length=self._key_length),
            protection_mode=self._protection_mode,
            freeform_tags=self.build_tags(silo_ref),
            defined_tags=self.build_defined_tags(silo_ref),
        )
        if rotation_days:
            # No time_of_schedule_start: OCI starts the clock from the key's
            # creation, which is what an operator asking for "every N days" means.
            details.is_auto_rotation_enabled = True
            details.auto_key_rotation_details = AutoKeyRotationDetails(rotation_interval_in_days=rotation_days)
        return self._get_client().create_key(details).data.id

    def _create_without_rotation(self, name: str, silo_ref: str, rotation_days: int, cause) -> str:
        """Recover from a rejected rotation schedule: make the key without one.

        Checks for the key first. A 400 means OCI rejected the request, so nothing
        should exist — but a key created and then reported as failed would be
        invisible to a blind retry, and creating a second one is the outcome this
        class works hardest to avoid: OCI allows duplicate display names, and only
        one of the two would hold the material that decrypts what came after.
        """
        existing = self._find_key_by_name(name)
        self._log_rotation_policy_failed(
            kek=name,
            days=rotation_days,
            cause=cause,
            key_preexisting=existing is not None,
        )
        if existing is not None:
            return existing.id
        return self._send_create(name, silo_ref, None)

    # ------------------------------------------------------------------
    # Deletion
    # ------------------------------------------------------------------

    def _do_delete_kek(self, kek_resource_name: str, silo_ref: str) -> DeleteOutcome:
        """Schedule deletion of the OCI key behind *kek_resource_name*.

        ScheduleKeyDeletion takes an OCID, so the display name is resolved
        through a compartment listing first. The key keeps its display name for
        the whole waiting period, which is what keeps it visible to reconcile —
        the name dropping out of the listing at destruction is the only thing
        that confirms the deletion happened, and a key in the window still
        costs money, so it must not vanish from the report early.

        Idempotent in both directions — a key already gone counts as deleted,
        and one already scheduled reports its existing ``time_of_deletion``
        rather than failing on OCI's invalid-state error.

        An OCID-form name never reaches here: only ``KEK_MAP`` / ``SHARED_KEK_ID``
        deployments record one, and those derive no owner prefix, so
        :meth:`delete_kek` refuses them at the ownership gate.
        """
        with self._lock:
            self._ensured.discard(kek_resource_name)

        key = self._find_key_by_name(kek_resource_name, _LIVE_STATES + _PENDING_DELETION_STATES)
        if key is None:
            self._log_kek_absent_on_delete(kek=kek_resource_name, silo_ref=silo_ref)
            return DeleteOutcome(scheduled=False, effective_at=timezone.now())

        if key.lifecycle_state in _PENDING_DELETION_STATES:
            self._log_kek_deletion_already_underway(
                kek=kek_resource_name, silo_ref=silo_ref, state="scheduled_for_deletion"
            )
            return DeleteOutcome(
                scheduled=True,
                effective_at=self._deletion_date(self._deletion_time(key)),
            )

        window = self.deletion_window_days(silo_ref)
        scheduled_for = self._schedule_deletion(key.id, timezone.now() + datetime.timedelta(days=window))
        return DeleteOutcome(scheduled=True, effective_at=self._deletion_date(scheduled_for, window))

    def _schedule_deletion(self, key_ocid: str, when: datetime.datetime):
        """Ask OCI to destroy *key_ocid* at *when*; return the date it accepted.

        The one call in the deletion path that touches the SDK's model classes,
        kept separate so the surrounding logic can be exercised without the
        ``oci`` extra installed.
        """
        require_oci()
        from oci.key_management.models import ScheduleKeyDeletionDetails

        response = self._get_client().schedule_key_deletion(
            key_ocid,
            ScheduleKeyDeletionDetails(time_of_deletion=when),
        )
        return getattr(response.data, "time_of_deletion", None)

    def _do_describe_kek_state(self, kek_resource_name: str) -> KekState:
        """Read the key's ``lifecycle_state`` from the compartment listing.

        A name OCI has no live or pending key for reports ``unknown`` rather than
        active: it may already be destroyed, or unreadable by this identity, and
        neither is evidence the key is healthy.
        """
        key = self._find_key_by_name(kek_resource_name, _LIVE_STATES + _PENDING_DELETION_STATES)
        if key is None:
            return KekState.unknown()
        if key.lifecycle_state in _PENDING_DELETION_STATES:
            return KekState(
                state=KekState.PENDING_DELETION,
                effective_at=self._deletion_date(self._deletion_time(key)),
            )
        return KekState(state=KekState.ACTIVE)

    def _deletion_date(self, value, window_days: int | None = None) -> datetime.datetime:
        """Normalize OCI's ``time_of_deletion`` to an aware datetime.

        Falls back to now plus the configured window when the field is missing,
        so a sparse response still yields a usable date instead of ``None``.
        """
        if isinstance(value, datetime.datetime):
            return value if timezone.is_aware(value) else timezone.make_aware(value, datetime.UTC)
        days = self.deletion_window_days() if window_days is None else window_days
        return timezone.now() + datetime.timedelta(days=days)

    # ------------------------------------------------------------------
    # Enumeration
    # ------------------------------------------------------------------

    def _do_list_kek_names(self, owner_prefix: str) -> list[str]:
        """List the compartment's key display names, live and pending alike.

        Display names are what the rows record (see
        ``OCIVaultAdapter.canonical_kek_name``), so reconcile compares like with
        like. Keys already destroyed are left out — a name absent from this
        listing is what confirms a deletion completed — but keys inside the
        deletion window are included, because that deletion has not happened yet.

        ListKeys has no server-side name filter, so *owner_prefix* is not passed
        to OCI; the base :meth:`list_kek_names` re-filters the result. Duplicate
        display names are returned once each: reconcile works in names, and the
        ambiguity is refused where it matters, at resolution and deletion.
        """
        states = _LIVE_STATES + _PENDING_DELETION_STATES
        return sorted(
            {key.display_name for key in self._list_keys() if key.display_name and key.lifecycle_state in states}
        )

    def describe(self) -> str:
        return (
            f"OciKekProvisioner(compartment={self._compartment_id}, "
            f"protection={self._protection_mode}, {self._algorithm}-{self._key_length * 8})"
        )
