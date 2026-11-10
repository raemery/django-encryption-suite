"""
Azure Key Vault KEK provisioner.

Creates symmetric AES keys in a pre-existing Key Vault. Vault creation itself is
out of scope (vaults are tenant-level resources rarely created on demand).

Requires the ``azure`` extra: ``pip install django-encryption-suite[azure]``

**Premium vault required.** The keys are ``oct-HSM`` (symmetric AES), which
Standard vaults do not offer, and symmetric key support in vaults is a Microsoft
**preview** feature — no SLA, and not recommended by Microsoft for production
workloads. ``AzureKeyVaultAdapter`` wraps with AES-256-GCM because only a
symmetric algorithm accepts the associated data that binds a wrapped DEK to its
silo.

KEK_PROVISIONER_OPTIONS keys:
  AZURE_VAULT_ENDPOINT  : str   (required) e.g. "https://my-vault.vault.azure.net"
  CREDENTIAL_STRATEGY  : str   "managed_identity" (default), "client_secret", "oidc"
  OIDC_SOURCE          : str   required when CREDENTIAL_STRATEGY="oidc"
  OIDC_SOURCE_OPTIONS  : dict  optional source-specific options
  KEY_SIZE             : int   default 256 (also 128 or 192)
  KEY_OPS              : list  default ["encrypt", "decrypt"]
                                (matches AzureKeyVaultAdapter's AES-GCM usage)
  KEK_ROTATION_PERIOD_DAYS : int   optional, e.g. 180. Written as the key's rotation
                               policy. Key Vault's floor is 7 days. Rotation adds
                               a key version; DEKs wrapped under earlier versions
                               stay readable because each row records the version
                               that wrapped it.
  TAGS                 : dict  optional {key: value} tags, applied verbatim to
                               the created key. For values a static dict cannot
                               express, subclass this provisioner and override
                               ``build_tags``. Key Vault holds tags per key
                               *version*, so a version added by a rotation does
                               not carry them; tags are written at creation only.

``PROVIDER_DELETION_WINDOW_DAYS`` is **not accepted** here and is refused at
construction. Azure's recovery period is the vault's ``softDeleteRetentionInDays``,
chosen when the vault is created and unchangeable afterwards, so nothing this
provisioner sends could alter it. The vault reports the resulting dates itself —
``scheduled_purge_date`` on a deleted key, ``recoverable_days`` on a live one —
and the deletion path reads them.

Deletion is Key Vault's soft delete: the key becomes inaccessible for every
operation but recovery, and Key Vault purges it at the end of the retention
period. That is the same shape as an AWS key in its pending-deletion window and a
Cloud KMS version scheduled for destruction.

Deletion and enumeration need permissions beyond encrypt/decrypt: ``keys/delete``,
``keys/list`` and ``keys/get``. The "Key Vault Crypto Officer" built-in role
covers those and key creation; setting a rotation policy also needs it.
"""

from __future__ import annotations

import datetime
import threading

from django.utils import timezone

from ..._logging import get_logger
from ...exceptions import KekPendingDeletionError, log_and_raise_configuration_error
from ..credentials.azure import (
    AzureClientSecretStrategy,
    AzureManagedIdentityStrategy,
    AzureWorkloadIdentityFederationStrategy,
)
from ..credentials.oidc_sources import build_oidc_source
from .provisioners import AbstractKekProvisioner, DeleteOutcome, KekState

logger = get_logger(__name__)

_KEY_TYPE = "oct-HSM"

# Key Vault's own default soft-delete retention, assumed when no key in the vault
# can be read to learn the real one. Erring long avoids promising a purge earlier
# than it can happen.
_DEFAULT_RETENTION_DAYS = 90


class AzureKekProvisioner(AbstractKekProvisioner):
    """Create one symmetric Key Vault key per silo."""

    supports_tagging = True

    # Soft delete leaves the key recoverable for the vault's retention period, so
    # a deletion here reports ``scheduled=True`` with Key Vault's own purge date.
    # A vault with soft delete off deletes outright and reports ``scheduled=False``.
    supports_delete = True

    # list_properties_of_keys enumerates the vault, and the id it returns matches
    # the vault-qualified name the adapter records on the row.
    supports_enumeration = True

    # A deleted key is readable through get_deleted_key together with its purge
    # date, so a key inside the retention period is recognized without using it.
    supports_state_check = True

    # Key Vault takes a per-key rotation policy, with a 7-day floor.
    supports_rotation_policy = True
    minimum_rotation_days = 7
    rotation_policy_remedy = (
        "Setting a rotation policy needs the Key Vault Crypto Officer role; apply the policy by "
        "hand, or grant the role and recreate the key."
    )

    def __init__(self, options: dict) -> None:
        super().__init__(options)
        self._strategy = self._build_strategy(options)
        self._vault_url = (options.get("AZURE_VAULT_ENDPOINT") or "").rstrip("/")
        if not self._vault_url:
            log_and_raise_configuration_error(
                logger, "AzureKekProvisioner requires AZURE_VAULT_ENDPOINT in KEK_PROVISIONER_OPTIONS."
            )
        self._client = None
        self._client_lock = threading.Lock()
        self._ensured: set[str] = set()
        self._ensured_lock = threading.Lock()

    def _validate_deletion_window(self, options: dict) -> None:
        """Refuse ``PROVIDER_DELETION_WINDOW_DAYS``, which cannot reach Azure.

        Every other provider takes its deletion window from this option, so
        carrying one over from an AWS or GCP configuration is the likely mistake —
        and silently ignoring it would leave an operator believing they had
        shortened a window that is fixed on the vault.
        """
        if "PROVIDER_DELETION_WINDOW_DAYS" not in options:
            return
        log_and_raise_configuration_error(
            logger,
            "AzureKekProvisioner: PROVIDER_DELETION_WINDOW_DAYS is set in KEK_PROVISIONER_OPTIONS, but "
            "Azure's recovery period is the vault's softDeleteRetentionInDays, fixed when the vault is "
            "created and unchangeable afterwards — nothing sent from here can alter it. Remove the "
            "option; the vault reports the real dates and this provisioner reads them.",
        )

    @staticmethod
    def _build_strategy(options: dict):
        name = options.get("CREDENTIAL_STRATEGY", "managed_identity")
        if name == "managed_identity":
            return AzureManagedIdentityStrategy()
        if name == "client_secret":
            return AzureClientSecretStrategy(options)
        if name == "oidc":
            source_name = options.get("OIDC_SOURCE")
            if not source_name:
                log_and_raise_configuration_error(
                    logger, "CREDENTIAL_STRATEGY='oidc' requires OIDC_SOURCE in KEK_PROVISIONER_OPTIONS."
                )
            source = build_oidc_source(source_name, options.get("OIDC_SOURCE_OPTIONS", {}))
            return AzureWorkloadIdentityFederationStrategy(options, source)
        log_and_raise_configuration_error(
            logger, f"Unknown CREDENTIAL_STRATEGY '{name}'. Valid: managed_identity, client_secret, oidc"
        )

    def _get_client(self):
        if self._client is not None:
            return self._client
        with self._client_lock:
            if self._client is None:
                try:
                    from azure.keyvault.keys import KeyClient
                except ImportError as exc:
                    raise RuntimeError(
                        "azure-keyvault-keys is required for AzureKekProvisioner. "
                        "Install django-encryption-suite[azure]."
                    ) from exc
                self._client = KeyClient(
                    vault_url=self._vault_url,
                    credential=self._strategy.get_credentials(),
                )
        return self._client

    @staticmethod
    def _not_found_error():
        """Return azure-core's ``ResourceNotFoundError`` class.

        Imported through here rather than at module scope so the provisioner can
        be constructed — and reported on by ``manage.py check`` — without the
        azure extra installed.
        """
        try:
            from azure.core.exceptions import ResourceNotFoundError
        except ImportError as exc:
            raise RuntimeError(
                "azure-core is required for AzureKekProvisioner. Install django-encryption-suite[azure]."
            ) from exc
        return ResourceNotFoundError

    @staticmethod
    def _key_name(value: str) -> str:
        """Return the bare key name from either form of KEK name.

        Callers hand in whatever they hold: the strategy's bare ``KEK_TEMPLATE``
        result, or the vault-qualified name recorded on a row. A version suffix
        goes with the rest — deletion, listing and state all act on the key.
        """
        tail = value.rstrip("/")
        if "/keys/" in tail:
            tail = tail.rsplit("/keys/", 1)[-1]
        elif tail.startswith("keys/"):
            # The stored, vault-relative form. Every shape a caller might hold —
            # bare name, relative, or a full versioned URI — has to reduce to the
            # same bare name, or a lookup silently addresses a key that does not
            # exist.
            tail = tail[len("keys/") :]
        return tail.split("/")[0]

    def _qualified(self, key_name: str) -> str:
        """Render *key_name* in the form the adapter records on a row.

        Vault-relative, matching ``AzureKeyVaultAdapter.canonical_kek_name``: the
        listing is compared against stored names and filtered by the owner
        prefix, both of which are relative. A vault-qualified name here matches
        neither, which reads as every key having vanished from the provider.
        """
        return f"keys/{key_name}"

    # ------------------------------------------------------------------
    # Provisioning
    # ------------------------------------------------------------------

    def ensure_kek(self, kek_resource_name: str, silo_ref: str) -> bool:
        key_name = self._key_name(kek_resource_name)

        if key_name in self._ensured:
            return False
        client = self._get_client()
        ResourceNotFoundError = self._not_found_error()

        try:
            existing = client.get_key(key_name)
        except ResourceNotFoundError:
            pass
        else:
            # The key is already there, so the only thing left to check is
            # whether its current version still carries the configured tags —
            # a new version may not have inherited them.
            self.sync_tags(existing, silo_ref)
            self._mark_ensured(key_name)
            return False
        self._reject_deleted_key(client, key_name)

        try:
            client.create_oct_key(
                key_name,
                size=int(self.options.get("KEY_SIZE", 256)),
                hardware_protected=True,
                key_operations=self.options.get("KEY_OPS", ["encrypt", "decrypt"]),
                tags=self.build_tags(silo_ref),
            )
        except Exception as exc:
            # Race: another worker created it. get_key now succeeds.
            try:
                client.get_key(key_name)
            except Exception:
                self._explain_creation_failure(exc, key_name)
            else:
                self._mark_ensured(key_name)
                self._log_kek_already_present(kek=key_name)
                return False
        self._apply_rotation_policy(client, key_name)
        self._log_kek_created(kek=key_name, silo_ref=silo_ref)
        self._mark_ensured(key_name)
        return True

    def _explain_creation_failure(self, exc: Exception, key_name: str) -> None:
        """Re-raise a creation failure, naming the SKU when that is the cause.

        A Standard vault rejects ``oct-HSM`` as an unsupported key type, which
        reads as a malformed request rather than as "this vault cannot hold
        symmetric keys at all" — and it surfaces on a tenant's first encrypt,
        nowhere near the vault configuration that caused it.
        """
        text = str(exc)
        if _KEY_TYPE.lower() in text.lower() or "kty" in text.lower():
            raise RuntimeError(
                f"Key Vault refused to create KEK '{key_name}' as a symmetric ({_KEY_TYPE}) key. "
                "Symmetric keys require a Premium vault, and are a preview feature there; a Standard "
                "vault offers RSA and EC only. Upgrade the vault to Premium, or point this deployment "
                "at a vault that already is."
            ) from exc
        raise exc

    def _apply_rotation_policy(self, client, key_name: str) -> None:
        """Put the configured automatic rotation schedule on a newly created key.

        Applied after creation because Key Vault's create call takes no rotation
        policy — it is a second call, needing the rotate-policy permission that
        key creation does not.

        A failure here is logged, not raised. The key itself is created and
        usable, so failing the request would break a tenant's first save over
        metadata; and because the retry finds the key already present, the
        policy would never be attempted again anyway. What must not happen is
        silence: a key left on manual rotation while the operator believes a
        schedule is running is the one outcome nobody detects, so it gets a
        WARNING naming the key and the permission.
        """
        rotation_days = self.rotation_period_days()
        if not rotation_days:
            return
        try:
            from azure.keyvault.keys import KeyRotationLifetimeAction, KeyRotationPolicy, KeyRotationPolicyAction

            client.update_key_rotation_policy(
                key_name,
                KeyRotationPolicy(
                    lifetime_actions=[
                        KeyRotationLifetimeAction(
                            KeyRotationPolicyAction.rotate,
                            time_after_create=f"P{rotation_days}D",
                        )
                    ]
                ),
            )
        except Exception as exc:
            self._log_rotation_policy_failed(kek=key_name, days=rotation_days, cause=exc)
            return
        self._log_rotation_policy_set(kek=key_name, days=rotation_days)

    def _get_deleted_key(self, client, key_name: str):
        """Return the soft-deleted key of that name, or ``None``."""
        try:
            return client.get_deleted_key(key_name)
        except self._not_found_error():
            return None

    def _reject_deleted_key(self, client, key_name: str) -> None:
        """Raise when the name is held by a soft-deleted key, instead of creating.

        Key Vault reserves a deleted key's name for the whole retention period and
        refuses to create over it. Without this the operator reads a raw conflict
        naming a key that does not appear in the vault listing. Typed so the engine
        can tell it apart from a key that was never created and record the state on
        the key's row. No logging here — this runs inside the engine's ensure
        funnel, which emits exactly one line.
        """
        deleted = self._get_deleted_key(client, key_name)
        if deleted is None:
            return
        purge_date = getattr(deleted, "scheduled_purge_date", None)
        raise KekPendingDeletionError(
            f"AzureKekProvisioner: KEK '{key_name}' is deleted and awaiting purge "
            f"(scheduled {purge_date}), so its name cannot be reused. Recover it at the provider "
            "(`az keyvault key recover`) to bring it back, or point this silo at a different KEK.",
            effective_at=self._purge_date(purge_date),
        )

    def sync_tags(self, existing_key, silo_ref: str) -> None:
        """Add configured tags missing from the key's current version.

        Key Vault holds tags per version, and a version added outside this
        application may carry none — the portal copies them when it creates one,
        ``az keyvault key create`` does not. Additive only: whatever else is on
        the key stays, including tags this deployment never configured and
        configured tags an operator has since edited.
        """
        configured = self.build_tags(silo_ref)
        if not configured:
            return
        properties = getattr(existing_key, "properties", None)
        current = dict(getattr(properties, "tags", None) or {})
        missing = {key: value for key, value in configured.items() if key not in current}
        if not missing:
            return
        try:
            self._get_client().update_key_properties(
                existing_key.name,
                version=getattr(properties, "version", None),
                tags={**current, **missing},
            )
        except Exception as exc:
            from ..._internal import operator_error_text

            # Never fails provisioning: the key works, and a missing tag costs
            # inventory accuracy rather than availability. Logged because the
            # drift is otherwise invisible until someone reads the portal.
            logger.warning(
                "The key is usable, but its current version is missing tags this deployment "
                "configures, so anything keyed to them does not see it. Setting them needs "
                'keys/update on the vault. kek="%s" tags=%s detail="%s"',
                existing_key.name,
                ",".join(sorted(missing)),
                operator_error_text(exc),
            )
            return
        logger.info(
            'Missing tags were added to the key. tags=%s kek="%s" version=%s',
            len(missing),
            existing_key.name,
            getattr(properties, "version", None),
        )

    def _mark_ensured(self, name: str) -> None:
        with self._ensured_lock:
            self._ensured.add(name)

    def _unmark_ensured(self, name: str) -> None:
        with self._ensured_lock:
            self._ensured.discard(name)

    # ------------------------------------------------------------------
    # Deletion
    # ------------------------------------------------------------------

    def _do_delete_kek(self, kek_resource_name: str, silo_ref: str) -> DeleteOutcome:
        """Delete the Key Vault key behind *kek_resource_name*.

        Soft delete makes the key unusable at once and keeps it recoverable until
        Key Vault purges it at ``scheduled_purge_date``, which is what the outcome
        reports. Deleting a key takes every version with it, which is what
        crypto-shreds the DEKs wrapped under any of them.

        Idempotent in both directions — a key already gone counts as deleted, and
        one already awaiting purge reports its existing date rather than failing.
        """
        client = self._get_client()
        key_name = self._key_name(kek_resource_name)
        self._unmark_ensured(key_name)

        try:
            deleted = client.begin_delete_key(key_name).result()
        except self._not_found_error():
            # Either never existed or already deleted; only the second has a date.
            existing = self._get_deleted_key(client, key_name)
            if existing is None:
                self._log_kek_absent_on_delete(kek=key_name, silo_ref=silo_ref)
                return DeleteOutcome(scheduled=False, effective_at=timezone.now())
            self._log_kek_deletion_already_underway(kek=key_name, silo_ref=silo_ref, state="deleted_awaiting_purge")
            return DeleteOutcome(scheduled=True, effective_at=self._purge_date(existing.scheduled_purge_date))

        purge_date = getattr(deleted, "scheduled_purge_date", None)
        if purge_date is None:
            # A vault without soft delete reports no purge date because the key is
            # already gone: nothing scheduled, nothing recoverable.
            return DeleteOutcome(scheduled=False, effective_at=timezone.now())
        return DeleteOutcome(scheduled=True, effective_at=self._purge_date(purge_date))

    def _do_describe_kek_state(self, kek_resource_name: str) -> KekState:
        """Read whether the key is live, awaiting purge, or unaccounted for.

        A key the vault has no record of in either state reports ``unknown``
        rather than active: it may have been purged, or be unreadable by this
        identity, and neither is evidence the key is healthy.
        """
        client = self._get_client()
        key_name = self._key_name(kek_resource_name)
        try:
            client.get_key(key_name)
        except self._not_found_error():
            deleted = self._get_deleted_key(client, key_name)
            if deleted is None:
                return KekState.unknown()
            return KekState(
                state=KekState.PENDING_DELETION,
                effective_at=self._purge_date(deleted.scheduled_purge_date),
            )
        return KekState(state=KekState.ACTIVE)

    def _purge_date(self, value) -> datetime.datetime:
        """Normalize Key Vault's ``scheduled_purge_date`` to an aware datetime.

        Falls back to the vault's own retention period when the field is missing
        or unparseable, so a sparse response still yields a usable date instead of
        ``None``.
        """
        if isinstance(value, datetime.datetime):
            return value if timezone.is_aware(value) else timezone.make_aware(value, datetime.UTC)
        return timezone.now() + datetime.timedelta(days=self._retention_days())

    def _retention_days(self) -> int:
        """The vault's ``softDeleteRetentionInDays``, read off any key in it.

        Key attributes carry it, so no control-plane call is needed. Falls back to
        Key Vault's own default of 90 days when no key can be read — a fallback
        date is worth more than none, and erring long avoids promising a purge
        earlier than it can happen.
        """
        try:
            for properties in self._get_client().list_properties_of_keys():
                days = getattr(properties, "recoverable_days", None)
                if days:
                    return int(days)
        except Exception as exc:
            from ..._internal import operator_error_text

            logger.warning(
                "The vault's soft-delete retention could not be read, so a default was assumed; "
                "any deletion date reported for keys in this vault is a guess and may not match "
                'what the vault will do. assumed_retention_days=%d vault="%s" detail="%s"',
                _DEFAULT_RETENTION_DAYS,
                self._vault_url,
                operator_error_text(exc),
            )
        return _DEFAULT_RETENTION_DAYS

    # ------------------------------------------------------------------
    # Enumeration
    # ------------------------------------------------------------------

    def _do_list_kek_names(self, owner_prefix: str) -> list[str]:
        """List the vault's keys, live and awaiting purge alike.

        Returns vault-relative, version-free ids — the form recorded on the row,
        so reconcile compares like with like. Keys in other vaults are not listed
        at all, since the vault is part of the id, and the base
        :meth:`list_kek_names` re-filters by *owner_prefix*, which is why it is not
        passed to Key Vault as a server-side filter.

        Deleted keys are included for the same reason an AWS key stays visible
        through its pending window: the deletion has not completed, and the key
        dropping out of the listing at purge is what confirms that it did.
        """
        client = self._get_client()
        names = [self._qualified(self._key_name(str(p.id))) for p in client.list_properties_of_keys() if p.id]
        names.extend(self._qualified(self._key_name(str(d.id))) for d in client.list_deleted_keys() if d.id)
        return names

    def describe(self) -> str:
        return f"AzureKekProvisioner(vault={self._vault_url})"
