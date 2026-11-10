"""
GCP Cloud KMS provisioner.

Creates symmetric encrypt/decrypt CryptoKeys in a pre-existing key ring.
The key ring itself must already exist — the provisioner does not create
key rings (this avoids granting ``cloudkms.keyRings.create`` to the app
runtime; rings rarely change).

Requires the ``gcp`` extra: ``pip install django-encryption-suite[gcp]``

KEK_PROVISIONER_OPTIONS keys:
  GCP_PROJECT_ID       : str  (required)
  GCP_KMS_LOCATION     : str  (required) e.g. "global", "us-central1"
  GCP_KMS_KEY_RING     : str  (required) name of existing key ring
  CREDENTIAL_STRATEGY  : str  "adc" (default), "oidc", "service_account_key"
  OIDC_SOURCE          : str  required when CREDENTIAL_STRATEGY="oidc" (e.g. "fly")
  OIDC_SOURCE_OPTIONS  : dict optional source-specific options
  PURPOSE              : str  default "ENCRYPT_DECRYPT"
  ALGORITHM            : str  default "GOOGLE_SYMMETRIC_ENCRYPTION"
  PROTECTION_LEVEL     : str  default "SOFTWARE" (or "HSM")
  KEK_ROTATION_PERIOD_DAYS : int  optional, e.g. 90. Rendered as the CryptoKey's
                              ``rotationPeriod`` in seconds. Cloud KMS's floor is
                              1 day. Rotation adds a new key version and makes it
                              primary; Cloud KMS resolves the version from the
                              ciphertext, so DEKs wrapped under earlier versions
                              keep decrypting without re-wrapping.
  PROVIDER_DELETION_WINDOW_DAYS : int  default 7. Written to the created key's
                              ``destroyScheduledDuration``. This is Cloud KMS's
                              own waiting period, which starts where the
                              package's KEY_DELETION_WINDOW_DAYS ends: destroyed
                              versions are recoverable at the provider
                              (``cryptoKeyVersions.restore``) until it expires.
                              Note this *overrides* the longer default Cloud KMS
                              would otherwise apply — the package's own window is
                              the restorable one, so a long provider tail mostly
                              prolongs billing for a key whose data is already
                              crypto-shredded. GCP fixes this on the key at
                              creation, so unlike AWS it cannot be changed for
                              keys that already exist, and the
                              ``constraints/cloudkms.minimumDestroyScheduledDuration``
                              org policy can raise the floor above what is
                              configured here. The admin test console's keys are
                              created with the 24-hour minimum instead; see
                              ``AbstractKekProvisioner.deletion_window_days``.
  TAGS                 : dict optional {key: value} pairs, applied verbatim to
                              the created key. Written to the CryptoKey's
                              ``labels`` field — the option is named ``TAGS``
                              for consistency across providers, but in GCP terms
                              these are labels, not Resource Manager tags. For
                              values a static dict cannot express, subclass this
                              provisioner and override ``build_tags``.

Note on ownership: GCP has no tag-conditioned control over key destruction.
Resource Manager tags (what IAM conditions match) attach to key *rings*, not
keys, and this provisioner never creates a ring. Labels are for organization
and billing export only. Restrict destruction with ring-scoped IAM plus the
``constraints/cloudkms.disableBeforeDestroy`` and
``constraints/cloudkms.minimumDestroyScheduledDuration`` org policies.

Deleting a key means destroying its versions. Cloud KMS cannot delete a
CryptoKey or a key ring at all — they are permanent, and free. What holds key
material is the *version*, so deletion here destroys every version the key has,
which is what crypto-shreds the DEKs wrapped under it. The empty CryptoKey shell
remains in the ring forever, billing nothing, and enumeration reports such a key
as gone (see ``_do_list_kek_names``) so the reconcile ledger can close it out.

Deletion and enumeration both need IAM beyond encrypt/decrypt:
``cloudkms.cryptoKeys.list``, ``cloudkms.cryptoKeyVersions.list``,
``cloudkms.cryptoKeyVersions.destroy``, and ``cloudkms.cryptoKeyVersions.update``
(versions are disabled before being destroyed, which is what the
``disableBeforeDestroy`` org policy requires). Clearing a rotation schedule at
deletion time also needs ``cloudkms.cryptoKeys.update``.
"""

from __future__ import annotations

import datetime
import json
import re
import threading
import urllib.error
import urllib.parse
import urllib.request

from django.utils import timezone

from ..._logging import get_logger
from ...exceptions import KekPendingDeletionError, log_and_raise_configuration_error
from .._http import urlopen_with_detail
from ..credentials.gcp import GcpAdcStrategy, GcpServiceAccountKeyStrategy, GcpWorkloadIdentityStrategy
from ..credentials.oidc_sources import build_oidc_source
from .provisioners import AbstractKekProvisioner, DeleteOutcome, KekState

logger = get_logger(__name__)

_API_ROOT = "https://cloudkms.googleapis.com/v1"

# CryptoKeyVersion states this provisioner reasons about.
_ENABLED = "ENABLED"
_DESTROY_SCHEDULED = "DESTROY_SCHEDULED"
_DESTROYED = "DESTROYED"


class GcpKekProvisioner(AbstractKekProvisioner):
    """Create one Cloud KMS CryptoKey per silo."""

    supports_tagging = True

    # Destroying a version always imposes ``destroyScheduledDuration`` (24 hours
    # minimum), so a deletion here is reversible at the provider for the whole
    # window and the DeleteOutcome reports ``scheduled=True``.
    supports_delete = True

    # cryptoKeys.list enumerates the configured ring, and the resource name it
    # returns is the same full path the adapter records on the row.
    supports_enumeration = True

    # A version carries a state, so a key inside Cloud KMS's destroy-scheduled
    # window can be recognized without attempting to use it.
    supports_state_check = True

    # Cloud KMS refuses a destroyScheduledDuration under 24 hours.
    minimum_deletion_window_days = 1

    # cryptoKeys.create accepts a rotationPeriod, and its floor is 24 hours.
    supports_rotation_policy = True
    minimum_rotation_days = 1

    def __init__(self, options: dict) -> None:
        super().__init__(options)
        self._strategy = self._build_strategy(options, self._ssl_context)
        missing = [k for k in ("GCP_PROJECT_ID", "GCP_KMS_LOCATION", "GCP_KMS_KEY_RING") if not options.get(k)]
        if missing:
            log_and_raise_configuration_error(
                logger, f"GcpKekProvisioner requires {', '.join(missing)} in KEK_PROVISIONER_OPTIONS."
            )
        self._project = options["GCP_PROJECT_ID"]
        self._location = options["GCP_KMS_LOCATION"]
        self._key_ring = options["GCP_KMS_KEY_RING"]
        self._ensured: set[str] = set()
        self._lock = threading.Lock()

    @staticmethod
    def _build_strategy(options: dict, ssl_context):
        name = options.get("CREDENTIAL_STRATEGY", "adc")
        if name == "adc":
            # google.auth SDK — TLS honored via google-auth's own trust store.
            return GcpAdcStrategy()
        if name == "oidc":
            source_name = options.get("OIDC_SOURCE")
            if not source_name:
                log_and_raise_configuration_error(
                    logger, "CREDENTIAL_STRATEGY='oidc' requires OIDC_SOURCE in KEK_PROVISIONER_OPTIONS."
                )
            source = build_oidc_source(source_name, options.get("OIDC_SOURCE_OPTIONS", {}))
            return GcpWorkloadIdentityStrategy(options, source, ssl_context=ssl_context)
        if name == "service_account_key":
            # google.auth SDK — TLS honored via google-auth's own trust store.
            return GcpServiceAccountKeyStrategy(options)
        log_and_raise_configuration_error(
            logger, f"Unknown CREDENTIAL_STRATEGY '{name}'. Valid: adc, oidc, service_account_key"
        )

    def _key_ring_path(self) -> str:
        return f"projects/{self._project}/locations/{self._location}/keyRings/{self._key_ring}"

    def _crypto_key_path(self, key_name: str) -> str:
        return f"{self._key_ring_path()}/cryptoKeys/{key_name}"

    @staticmethod
    def _key_name(value: str) -> str:
        """Return the bare key name from either form of KEK name.

        Callers hand in whatever they hold: the strategy's bare
        ``KEK_TEMPLATE`` result, or the full resource path recorded on a row.
        """
        if "/cryptoKeys/" in value:
            return value.rsplit("/cryptoKeys/", 1)[-1]
        return value

    def ensure_kek(self, kek_resource_name: str, silo_ref: str) -> bool:
        key_name = self._key_name(kek_resource_name)

        if key_name in self._ensured:
            return False
        token = self._strategy.get_credentials()

        # GET first — cheap and avoids ALREADY_EXISTS noise in audit logs.
        existing = self._get_key(self._crypto_key_path(key_name), token)
        if existing is not None:
            self._reject_unusable_key(existing, key_name)
            self._mark_ensured(key_name)
            return False
        labels = self.build_tags(silo_ref)
        body: dict = {
            "purpose": self.options.get("PURPOSE", "ENCRYPT_DECRYPT"),
            "versionTemplate": {
                "algorithm": self.options.get("ALGORITHM", "GOOGLE_SYMMETRIC_ENCRYPTION"),
                "protectionLevel": self.options.get("PROTECTION_LEVEL", "SOFTWARE"),
            },
            "labels": labels,
            # Read here, not at deletion: Cloud KMS fixes this on the key at
            # creation, so a console key created under the configured window
            # would keep it for good.
            "destroyScheduledDuration": f"{self.deletion_window_days(silo_ref) * 86400}s",
        }
        rotation_days = self.rotation_period_days()
        if rotation_days:
            body["rotationPeriod"] = f"{rotation_days * 86400}s"
            # Cloud KMS treats these two as a pair — the delete path clears both
            # under one field mask for the same reason. Sending the period alone
            # leaves the first rotation date unstated, so state it.
            body["nextRotationTime"] = self._next_rotation_time(rotation_days)

        create_url = f"{_API_ROOT}/{self._key_ring_path()}/cryptoKeys?cryptoKeyId={key_name}"
        try:
            self._http("POST", create_url, token, body=body)
        except urllib.error.HTTPError as exc:
            if exc.code == 409:
                # Race: another process won. Treat as success.
                self._log_kek_already_present(kek=key_name)
            elif exc.code == 400 and "destroy_scheduled_duration" in str(exc):
                # Cloud KMS names the floor it enforces but not the setting that
                # feeds it, and this surfaces on an *encrypt* — so without the
                # pointer an operator is reading a key-creation rejection about
                # deletion timing with no obvious knob. The configured value is
                # already floor-checked at construction, so reaching here means
                # the org policy raised the floor above it.
                raise RuntimeError(
                    f"Cloud KMS refused the destroy window for KEK '{key_name}': "
                    f"{body['destroyScheduledDuration']} is below the minimum this project enforces. "
                    "That minimum is set by the constraints/cloudkms.minimumDestroyScheduledDuration "
                    "org policy; raise PROVIDER_DELETION_WINDOW_DAYS in KEK_PROVISIONER_OPTIONS to "
                    "meet it, or relax the policy. Cloud KMS fixes this value on the key at creation, "
                    "which is why it is rejected here rather than at deletion."
                ) from exc
            else:
                raise
        else:
            self._log_kek_created(kek=key_name, silo_ref=silo_ref)
        self._mark_ensured(key_name)
        return True

    def _http(self, method: str, url: str, token: str, body: dict | None) -> dict:
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(
            url,
            data=data,
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            },
            method=method,
        )
        with urlopen_with_detail(req, timeout=self._request_timeout, context=self._ssl_context) as resp:
            raw = resp.read()
            return json.loads(raw) if raw else {}

    @staticmethod
    def _sanitize_label(value: str) -> str:
        """Coerce *value* into GCP's label charset: lowercase, [a-z0-9_-], max 63.

        Not applied to the operator's ``TAGS`` — those are written verbatim, so a
        value that violates the charset is rejected by GCP with a clear 400
        rather than silently rewritten into something the operator never chose.
        Kept for ``build_tags`` overrides, whose values are usually derived (a
        tenant identifier, an accounting code) rather than typed by hand::

            tags["tenant"] = self._sanitize_label(silo_ref)
        """
        out = "".join(c if c.isalnum() or c in "_-" else "-" for c in value.lower())
        return out[:63] or "unknown"

    @staticmethod
    def _next_rotation_time(rotation_days: int) -> str:
        """When the first automatic rotation of a new key should fall.

        One period from now, in the RFC 3339 UTC form Cloud KMS expects. Cloud KMS
        treats the period and this date as a pair: sending the period alone leaves
        the first rotation unstated and the create call is rejected.
        """
        when = (timezone.now() + datetime.timedelta(days=rotation_days)).astimezone(datetime.UTC)
        return when.strftime("%Y-%m-%dT%H:%M:%SZ")

    def _paged_get(self, url: str, token: str, item_key: str) -> list[dict]:
        """Return every item from a paginated Cloud KMS list endpoint."""
        items: list[dict] = []
        page_token = ""
        while True:
            page_url = url
            if page_token:
                separator = "&" if "?" in url else "?"
                page_url = f"{url}{separator}pageToken={urllib.parse.quote(page_token)}"
            payload = self._http("GET", page_url, token, body=None)
            items.extend(payload.get(item_key) or [])
            page_token = payload.get("nextPageToken") or ""
            if not page_token:
                return items

    def _get_key(self, key_path: str, token: str) -> dict | None:
        """Return the CryptoKey resource, or ``None`` when it does not exist."""
        try:
            return self._http("GET", f"{_API_ROOT}/{key_path}", token, body=None)
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return None
            raise

    def _list_versions(self, key_path: str, token: str) -> list[dict]:
        return self._paged_get(f"{_API_ROOT}/{key_path}/cryptoKeyVersions", token, "cryptoKeyVersions")

    def _has_key_material(self, key: dict, token: str) -> bool:
        """Whether *key* still holds material — the test enumeration reports on.

        A Cloud KMS key is a container: destroying its last version leaves the
        CryptoKey itself in place forever, so "the resource exists" says nothing
        about whether the DEKs under it are recoverable. Presence here means at
        least one version is not yet ``DESTROYED``, which is what makes a
        scheduled key stay listed through its window and a shredded one drop out.

        The primary version answers it without a second round trip in the common
        case. Only when the primary is destroyed (or absent) does this list the
        versions: an operator can destroy the primary at the console and leave an
        older version enabled, and that key can still decrypt, so reporting it
        gone would be a false shred.
        """
        primary_state = (key.get("primary") or {}).get("state")
        if primary_state and primary_state != _DESTROYED:
            return True
        return any(v.get("state") != _DESTROYED for v in self._list_versions(key["name"], token))

    def _reject_unusable_key(self, key: dict, key_name: str) -> None:
        """Raise when the existing key cannot encrypt, instead of caching it ensured.

        Two states reach here, and neither is recoverable by provisioning: the
        name is taken, so nothing can be created over it. Caching it as ensured
        would defer the failure to the first encrypt with a far less legible
        error. Neither raise logs — both run inside the engine's ensure funnel,
        which emits exactly one line.
        """
        primary = key.get("primary") or {}
        state = primary.get("state")
        if state == _DESTROY_SCHEDULED:
            # Typed so the engine can tell this apart from a key that was never
            # created and record the state on the key's row.
            raise KekPendingDeletionError(
                f"GcpKekProvisioner: KEK '{key_name}' has a version scheduled for destruction "
                f"(destroyTime {primary.get('destroyTime')}) and cannot be used. Restore it at the "
                "provider (`gcloud kms keys versions restore`) to recover it, or point this silo "
                "at a different KEK.",
                effective_at=self._destroy_time(primary.get("destroyTime")),
            )
        if state == _DESTROYED:
            raise RuntimeError(
                f"GcpKekProvisioner: KEK '{key_name}' exists but its primary version is destroyed, "
                "so it can no longer encrypt. Its key material is gone for good — nothing can "
                "recover the data it wrapped. Point this silo at a new KEK name, or add a version "
                "to the key at the provider to start encrypting under fresh material."
            )

    # ------------------------------------------------------------------
    # Deletion
    # ------------------------------------------------------------------

    def _do_delete_kek(self, kek_resource_name: str, silo_ref: str) -> DeleteOutcome:
        """Destroy every version of the CryptoKey behind *kek_resource_name*.

        Cloud KMS cannot delete a CryptoKey, so destroying all of its versions is
        the deletion: it removes the key material, which is what makes the DEKs
        wrapped under it unrecoverable. The empty shell stays in the ring, costs
        nothing, and stops being listed by :meth:`_do_list_kek_names` once its
        last version is destroyed — which is what lets reconcile confirm the
        deletion happened.

        Each version is disabled first. A destroy on an enabled version is
        refused outright under the ``constraints/cloudkms.disableBeforeDestroy``
        org policy, and disabling one already on its way out costs nothing.

        Any rotation schedule is cleared first, or Cloud KMS would create a fresh
        enabled version on a key this deployment believes it destroyed —
        resurrecting it as a live, billable key that reconcile then reports as an
        orphan forever.

        Idempotent in both directions — a key already gone counts as deleted, as
        does one whose versions are all destroyed already, and a version already
        scheduled reports its existing destroy time rather than failing.
        """
        token = self._strategy.get_credentials()
        key_name = self._key_name(kek_resource_name)
        key_path = self._crypto_key_path(key_name)
        self._unmark_ensured(key_name)

        key = self._get_key(key_path, token)
        if key is None:
            self._log_kek_absent_on_delete(kek=key_name, silo_ref=silo_ref)
            return DeleteOutcome(scheduled=False, effective_at=timezone.now())

        self._clear_rotation_schedule(key, key_path, token)

        destroy_times: list[datetime.datetime] = []
        for version in self._list_versions(key_path, token):
            state = version.get("state")
            if state == _DESTROYED:
                continue
            if state == _DESTROY_SCHEDULED:
                destroy_times.append(self._destroy_time(version.get("destroyTime")))
                continue
            if state == _ENABLED:
                self._http(
                    "PATCH",
                    f"{_API_ROOT}/{version['name']}?updateMask=state",
                    token,
                    body={"state": "DISABLED"},
                )
            destroyed = self._http("POST", f"{_API_ROOT}/{version['name']}:destroy", token, body={})
            destroy_times.append(self._destroy_time(destroyed.get("destroyTime")))

        if not destroy_times:
            # Nothing left to destroy: the material is already gone, so this is a
            # completed deletion rather than a scheduled one.
            self._log_kek_deletion_already_underway(kek=key_name, silo_ref=silo_ref, state="no_live_versions")
            return DeleteOutcome(scheduled=False, effective_at=timezone.now())

        # The key is unusable once its last live version is destroyed, so the
        # latest destroy time is when it is gone for good.
        return DeleteOutcome(scheduled=True, effective_at=max(destroy_times))

    def _clear_rotation_schedule(self, key: dict, key_path: str, token: str) -> None:
        """Stop Cloud KMS from adding a version to a key being destroyed."""
        if not (key.get("rotationPeriod") or key.get("nextRotationTime")):
            return
        # Both fields in the mask with neither in the body is how Cloud KMS
        # clears a rotation schedule.
        self._http(
            "PATCH",
            f"{_API_ROOT}/{key_path}?updateMask=rotationPeriod,nextRotationTime",
            token,
            body={},
        )
        logger.info(
            'The rotation schedule was cleared before destroying the key. kek="%s"',
            key_path,
        )

    def _do_describe_kek_state(self, kek_resource_name: str) -> KekState:
        """Read the primary version's state.

        A key Cloud KMS has no record of reports ``unknown`` rather than active:
        it may have been deleted at the console, or the caller may lack
        ``cryptoKeys.get`` on it, and neither is evidence the key is healthy. So
        does any state other than enabled or destroy-scheduled — a disabled or
        still-generating version is not being deleted, but it is not usable
        either, and ``active`` is documented to mean usable.
        """
        token = self._strategy.get_credentials()
        key = self._get_key(self._crypto_key_path(self._key_name(kek_resource_name)), token)
        if key is None:
            return KekState.unknown()
        primary = key.get("primary") or {}
        state = primary.get("state")
        if state == _DESTROY_SCHEDULED:
            return KekState(
                state=KekState.PENDING_DELETION,
                effective_at=self._destroy_time(primary.get("destroyTime")),
            )
        if state == _ENABLED:
            return KekState(state=KekState.ACTIVE)
        return KekState.unknown()

    def _destroy_time(self, value) -> datetime.datetime:
        """Normalize Cloud KMS's RFC 3339 ``destroyTime`` to an aware datetime.

        Falls back to now plus the configured window when the field is missing or
        unparseable, so a sparse response still yields a usable date instead of
        ``None``. Cloud KMS reports nanoseconds, which
        :meth:`datetime.datetime.fromisoformat` rejects, so the fraction is
        truncated to microseconds.
        """
        text = (value or "").strip()
        if text.endswith("Z"):
            text = f"{text[:-1]}+00:00"
        fraction = re.match(r"^(.*\.)(\d+)(.*)$", text)
        if fraction:
            text = f"{fraction.group(1)}{fraction.group(2)[:6]}{fraction.group(3)}"
        try:
            parsed = datetime.datetime.fromisoformat(text)
        except ValueError:
            return timezone.now() + datetime.timedelta(days=self.deletion_window_days())
        return parsed if timezone.is_aware(parsed) else timezone.make_aware(parsed, datetime.UTC)

    # ------------------------------------------------------------------
    # Enumeration
    # ------------------------------------------------------------------

    def _do_list_kek_names(self, owner_prefix: str) -> list[str]:
        """List the configured ring's keys that still hold material.

        Returns full resource names, the same form the adapter records on a row,
        so reconcile compares like with like. Keys in other rings are not listed
        at all — the ring is part of the path — and the base
        :meth:`list_kek_names` re-filters what is returned by *owner_prefix*,
        which is why it is not passed to Cloud KMS as a server-side filter.

        A key whose every version is destroyed is deliberately omitted even
        though the CryptoKey resource still exists: Cloud KMS never removes that
        shell, so treating it as present would leave every deletion this
        deployment performs permanently unconfirmed and reported as drift.
        """
        token = self._strategy.get_credentials()
        keys = self._paged_get(f"{_API_ROOT}/{self._key_ring_path()}/cryptoKeys", token, "cryptoKeys")
        return [key["name"] for key in keys if key.get("name") and self._has_key_material(key, token)]

    def _mark_ensured(self, name: str) -> None:
        with self._lock:
            self._ensured.add(name)

    def _unmark_ensured(self, name: str) -> None:
        with self._lock:
            self._ensured.discard(name)

    def describe(self) -> str:
        return f"GcpKekProvisioner(ring={self._key_ring_path()})"
