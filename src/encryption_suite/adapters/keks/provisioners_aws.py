"""
AWS KMS provisioner.

Creates symmetric KEKs in AWS KMS on demand and (optionally) attaches an
alias matching the resource name produced by the configured strategy.

Requires the ``aws`` extra: ``pip install django-encryption-suite[aws]``

KEK_PROVISIONER_OPTIONS keys:
  AWS_REGION              : str   (required) e.g. "us-east-1"
  CREDENTIAL_STRATEGY     : str   "iam_role" (default), "oidc"
  OIDC_SOURCE             : str   required when CREDENTIAL_STRATEGY="oidc"
                                  (e.g. "fly")
  OIDC_SOURCE_OPTIONS     : dict  optional source-specific options
  KEY_SPEC                : str   default "SYMMETRIC_DEFAULT"
  KEY_USAGE               : str   default "ENCRYPT_DECRYPT"
  KEY_DESCRIPTION         : str   default "django-encryption-suite KEK"
  TAGS                    : dict  optional {key: value} tags, applied verbatim
                                  to the created key. For values a static dict
                                  cannot express, subclass this provisioner and
                                  override ``build_tags``.
  POLICY                  : str   optional KMS key policy JSON document.
  CUSTOM_KEY_STORE_ID     : str   optional, e.g. "cks-1234567890abcdef0". Creates
                                  keys in this AWS CloudHSM key store
                                  (``Origin=AWS_CLOUDHSM``), a single-tenant HSM
                                  cluster you control, instead of in AWS KMS's
                                  shared HSMs. The key store must be connected
                                  when a key is created. AWS does not rotate keys
                                  in a custom key store, so this cannot be
                                  combined with KEK_ROTATION_PERIOD_DAYS.
  KEK_ROTATION_PERIOD_DAYS    : int   optional, e.g. 365. Turns on AWS KMS automatic
                                  key rotation for the created key, with
                                  ``RotationPeriodInDays`` set to this value.
                                  AWS accepts 90-2560 and rejects anything else.
                                  Rotation adds new backing key material and
                                  keeps the old material for decrypt, so
                                  ciphertext written under an earlier rotation
                                  stays readable and no re-wrap is needed —
                                  AWS resolves the backing key from the
                                  ciphertext itself.
  ALIAS_PROPAGATION_TIMEOUT_SECONDS : float  default 10. How long ensure_kek
                                  waits after CreateAlias for the new alias to
                                  become readable. CreateAlias is eventually
                                  consistent, and the first encrypt under a new
                                  KEK runs in the same request that created it,
                                  so without this wait that encrypt can fail
                                  with NotFoundException on a key that exists.
                                  Paid once per KEK, on the create path only.
  PROVIDER_DELETION_WINDOW_DAYS : int  default 7. Passed to ScheduleKeyDeletion
                                  as ``PendingWindowInDays`` (AWS accepts 7-30
                                  and rejects anything else). This is AWS's own
                                  waiting period, which starts where the
                                  package's KEY_DELETION_WINDOW_DAYS ends: the
                                  key is unusable and still billable for its
                                  duration, recoverable only at the provider
                                  (``aws kms cancel-key-deletion``). The default
                                  is AWS's minimum, not AWS's default of 30 —
                                  the package's own window is the restorable
                                  one, so a long provider tail only prolongs
                                  billing for a key whose data is already
                                  crypto-shredded. The admin test console's keys
                                  always use AWS's 7-day minimum, so raising this
                                  does not slow the console's own cycle; see
                                  ``AbstractKekProvisioner.deletion_window_days``.

Deletion and enumeration both need IAM beyond encrypt/decrypt:
``kms:ScheduleKeyDeletion`` and ``kms:ListAliases``. ``KEK_ROTATION_PERIOD_DAYS``
needs ``kms:EnableKeyRotation``.
"""

from __future__ import annotations

import datetime
import threading
import time

from django.utils import timezone

from ..._logging import get_logger
from ...exceptions import KekPendingDeletionError, log_and_raise_configuration_error
from ..credentials.aws import AwsIamRoleStrategy, AwsOidcStrategy
from ..credentials.oidc_sources import build_oidc_source
from .provisioners import AbstractKekProvisioner, DeleteOutcome, KekState

logger = get_logger(__name__)

_ALIAS_PREFIX = "alias/"
_DEFAULT_ALIAS_PROPAGATION_TIMEOUT = 10.0
_ALIAS_POLL_INTERVAL = 0.25


class AwsKekProvisioner(AbstractKekProvisioner):
    """Create one AWS KMS key per silo, aliased to the strategy's name."""

    supports_tagging = True

    # ScheduleKeyDeletion always imposes a waiting period (7-30 days), so a
    # deletion here is reversible at the provider for the whole window and the
    # DeleteOutcome reports ``scheduled=True``.
    supports_delete = True

    # A KMS key has no name of its own — the alias is the name — so enumeration
    # is ListAliases. That also means it only works for alias-form KEK names;
    # see ``_do_list_kek_names``.
    supports_enumeration = True

    # DescribeKey reports KeyState, so a key inside AWS's pending-deletion window
    # can be recognized without attempting to use it.
    supports_state_check = True

    # AWS rejects a PendingWindowInDays outside 7-30, so its floor equals the
    # package default: the test console's shorter window is a no-op here.
    minimum_deletion_window_days = 7
    maximum_deletion_window_days = 30

    # EnableKeyRotation takes a RotationPeriodInDays, and AWS refuses anything
    # outside 90-2560 days.
    supports_rotation_policy = True
    minimum_rotation_days = 90
    maximum_rotation_days = 2560
    rotation_policy_remedy = (
        "Turning on rotation needs kms:EnableKeyRotation; grant it and enable rotation by hand "
        "(`aws kms enable-key-rotation`), or recreate the key."
    )

    def __init__(self, options: dict) -> None:
        super().__init__(options)
        self._strategy = self._build_strategy(options)
        self._client = None
        self._client_lock = threading.Lock()
        self._ensured: set[str] = set()
        self._ensured_lock = threading.Lock()

    def _validate_rotation_period(self, options: dict) -> None:
        """Also refuse a rotation schedule on keys created in a custom key store.

        AWS rejects ``EnableKeyRotation`` for those keys, and that refusal is only
        logged after the key is created, so without this check the keys would
        quietly never rotate.
        """
        super()._validate_rotation_period(options)
        if options.get("CUSTOM_KEY_STORE_ID") and "KEK_ROTATION_PERIOD_DAYS" in options:
            log_and_raise_configuration_error(
                logger,
                f"{type(self).__name__}: CUSTOM_KEY_STORE_ID and KEK_ROTATION_PERIOD_DAYS are both set in "
                "KEK_PROVISIONER_OPTIONS, but AWS does not rotate keys in a custom key store, so the keys "
                "would never rotate. Remove KEK_ROTATION_PERIOD_DAYS from this store and rotate its keys "
                "manually.",
            )

    @staticmethod
    def _build_strategy(options: dict):
        name = options.get("CREDENTIAL_STRATEGY", "iam_role")
        region = options.get("AWS_REGION", "us-east-1")
        if name == "iam_role":
            return AwsIamRoleStrategy(region)
        if name == "oidc":
            source_name = options.get("OIDC_SOURCE")
            if not source_name:
                log_and_raise_configuration_error(
                    logger, "CREDENTIAL_STRATEGY='oidc' requires OIDC_SOURCE in KEK_PROVISIONER_OPTIONS."
                )
            source = build_oidc_source(source_name, options.get("OIDC_SOURCE_OPTIONS", {}))
            return AwsOidcStrategy(options, source)
        log_and_raise_configuration_error(logger, f"Unknown CREDENTIAL_STRATEGY '{name}'. Valid: iam_role, oidc")

    def _get_client(self):
        if self._client is not None:
            return self._client
        with self._client_lock:
            if self._client is None:
                try:
                    import boto3  # noqa: F401
                except ImportError as exc:
                    raise RuntimeError(
                        "boto3 is required for AwsKekProvisioner. Install: pip install django-encryption-suite[aws]"
                    ) from exc
                session = self._strategy.get_credentials()
                self._client = session.client("kms")
        return self._client

    def ensure_kek(self, kek_resource_name: str, silo_ref: str) -> bool:
        if kek_resource_name in self._ensured:
            return False
        client = self._get_client()

        metadata = self._describe_key(client, kek_resource_name)
        if metadata is not None:
            state = metadata.get("KeyState")
            if state == "PendingDeletion":
                # The key still exists and its alias still resolves, but every
                # encrypt and decrypt under it fails until the deletion is
                # canceled. Recreating is impossible (the alias is taken), and
                # silently caching it as ensured would defer the failure to the
                # first encrypt with a far less legible error.
                #
                # Typed rather than a bare RuntimeError so the engine can tell
                # this apart from a key that was never created and record the
                # state on the key's row. The message text is unchanged — it is
                # what an operator reads in the log. No logging here: the
                # engine's ensure funnel emits exactly one line.
                deletion_date = metadata.get("DeletionDate")
                raise KekPendingDeletionError(
                    f"AwsKekProvisioner: KEK '{kek_resource_name}' is scheduled for deletion "
                    f"(DeletionDate {deletion_date}) and cannot be used. "
                    "Cancel the deletion at the provider (`aws kms cancel-key-deletion`) to "
                    "recover it, or point this silo at a different KEK.",
                    effective_at=self._deletion_date(deletion_date, self.deletion_window_days(silo_ref)),
                )
            self._mark_ensured(kek_resource_name)
            return False
        is_alias = kek_resource_name.startswith(_ALIAS_PREFIX)
        tags = self.build_tags(silo_ref)

        create_kwargs = {
            "Description": self.options.get("KEY_DESCRIPTION", "django-encryption-suite KEK"),
            "KeySpec": self.options.get("KEY_SPEC", "SYMMETRIC_DEFAULT"),
            "KeyUsage": self.options.get("KEY_USAGE", "ENCRYPT_DECRYPT"),
            "Tags": [{"TagKey": k, "TagValue": v} for k, v in tags.items()],
        }
        if "POLICY" in self.options:
            create_kwargs["Policy"] = self.options["POLICY"]
        custom_key_store_id = self.options.get("CUSTOM_KEY_STORE_ID")
        if custom_key_store_id:
            create_kwargs["CustomKeyStoreId"] = custom_key_store_id
            create_kwargs["Origin"] = "AWS_CLOUDHSM"

        response = client.create_key(**create_kwargs)
        key_id = response["KeyMetadata"]["KeyId"]

        if is_alias:
            try:
                client.create_alias(AliasName=kek_resource_name, TargetKeyId=key_id)
            except Exception as exc:
                if not self._is_already_exists(exc):
                    raise

        self._apply_rotation_policy(client, key_id)

        self._log_kek_created(kek=kek_resource_name, silo_ref=silo_ref, key_id=key_id)

        if is_alias and not self._await_alias(client, kek_resource_name):
            # Deliberately not marked ensured and not raised: the key exists and
            # the alias will resolve shortly, so the next request provisions
            # nothing and succeeds. Failing this one encrypt is the honest
            # outcome; caching "ensured" would make it fail on every retry.
            # Still reports created: the key is ours, whatever the alias does.
            return True
        self._mark_ensured(kek_resource_name)
        return True

    def _apply_rotation_policy(self, client, key_id: str) -> None:
        """Turn on automatic rotation for a newly created key.

        Applied after creation because CreateKey takes no rotation setting — it
        is a second call, needing ``kms:EnableKeyRotation``, which key creation
        does not.

        A failure here is logged, not raised, for the same reason as on Azure:
        the key is created and usable, so failing this request would break a
        tenant's first save over something that does not affect it, and the
        retry finds the key already present and never reaches this code again.
        The one outcome nobody would notice is silence, so it gets a WARNING
        naming the key and the permission.

        Addressed by KeyId rather than the alias: CreateAlias is eventually
        consistent, and this runs before the propagation wait.
        """
        rotation_days = self.rotation_period_days()
        if not rotation_days:
            return
        try:
            client.enable_key_rotation(KeyId=key_id, RotationPeriodInDays=rotation_days)
        except Exception as exc:
            self._log_rotation_policy_failed(kek=key_id, days=rotation_days, cause=exc)
            return
        self._log_rotation_policy_set(kek=key_id, days=rotation_days)

    def _await_alias(self, client, kek_resource_name: str) -> bool:
        """Block until *kek_resource_name* resolves, or the timeout expires.

        CreateAlias is eventually consistent: it returns before the alias is
        readable, so an Encrypt issued immediately after provisioning can fail
        with NotFoundException on a key that demonstrably exists. The window is
        sub-second in practice, but the first encrypt under a new KEK runs in the
        same request that created it, which is exactly where it lands.

        Returns whether the alias became resolvable. Waits only on the
        create path — an alias that already existed was proven by DescribeKey.
        """
        timeout = float(self.options.get("ALIAS_PROPAGATION_TIMEOUT_SECONDS", _DEFAULT_ALIAS_PROPAGATION_TIMEOUT))
        deadline = time.monotonic() + timeout
        while True:
            if self._describe_key(client, kek_resource_name) is not None:
                return True
            if time.monotonic() >= deadline:
                logger.warning(
                    "The alias has not propagated yet, so this request could not use it; the key "
                    'exists and the next request should succeed. kek="%s" waited_seconds=%.1f',
                    kek_resource_name,
                    timeout,
                )
                return False
            time.sleep(_ALIAS_POLL_INTERVAL)

    def _mark_ensured(self, name: str) -> None:
        with self._ensured_lock:
            self._ensured.add(name)

    def _unmark_ensured(self, name: str) -> None:
        with self._ensured_lock:
            self._ensured.discard(name)

    def _describe_key(self, client, kek_resource_name: str):
        """Return the key's ``KeyMetadata``, or ``None`` when it does not exist.

        Accepts either form of KEK name: DescribeKey resolves an alias as well
        as a key id or ARN.
        """
        try:
            return client.describe_key(KeyId=kek_resource_name)["KeyMetadata"]
        except Exception as exc:
            if not self._is_not_found(exc):
                raise
            return None

    @staticmethod
    def _error_code(exc: Exception) -> str | None:
        """Return the AWS error code of a botocore ``ClientError``, if it is one.

        Read off the ``response`` payload rather than by isinstance so this works
        whether or not botocore is importable in the calling process.
        """
        response = getattr(exc, "response", None)
        if isinstance(response, dict):
            return (response.get("Error") or {}).get("Code")
        return None

    @classmethod
    def _is_not_found(cls, exc: Exception) -> bool:
        return cls._error_code(exc) in {"NotFoundException", "InvalidAliasNameException"}

    @classmethod
    def _is_already_exists(cls, exc: Exception) -> bool:
        return cls._error_code(exc) == "AlreadyExistsException"

    # ------------------------------------------------------------------
    # Deletion
    # ------------------------------------------------------------------

    def _do_delete_kek(self, kek_resource_name: str, silo_ref: str) -> DeleteOutcome:
        """Schedule deletion of the KMS key behind *kek_resource_name*.

        ScheduleKeyDeletion takes a key id or ARN — not an alias — so the name is
        resolved through DescribeKey first. The alias itself is deliberately left
        in place: AWS removes it with the key when the waiting period expires,
        and until then it is what keeps the pending key visible to reconcile,
        which is the only thing that confirms the deletion actually happened. A
        key in the waiting period still costs money, so it must not vanish from
        the report early.

        Idempotent in both directions — a key already gone counts as deleted, and
        a key already scheduled reports its existing deletion date rather than
        failing on ``KMSInvalidStateException``.
        """
        client = self._get_client()
        metadata = self._describe_key(client, kek_resource_name)
        self._unmark_ensured(kek_resource_name)

        if metadata is None:
            self._log_kek_absent_on_delete(kek=kek_resource_name, silo_ref=silo_ref)
            return DeleteOutcome(scheduled=False, effective_at=timezone.now())

        window = self.deletion_window_days(silo_ref)

        if metadata.get("KeyState") == "PendingDeletion":
            self._log_kek_deletion_already_underway(
                kek=kek_resource_name, silo_ref=silo_ref, state="scheduled_for_deletion"
            )
            return DeleteOutcome(
                scheduled=True,
                effective_at=self._deletion_date(metadata.get("DeletionDate"), window),
            )

        response = client.schedule_key_deletion(KeyId=metadata["KeyId"], PendingWindowInDays=window)
        return DeleteOutcome(
            scheduled=True,
            effective_at=self._deletion_date(response.get("DeletionDate"), window),
        )

    def _do_describe_kek_state(self, kek_resource_name: str) -> KekState:
        """Read the key's ``KeyState`` via DescribeKey.

        A key AWS has no record of reports ``unknown`` rather than active: the
        alias may have been removed, or the caller may lack DescribeKey on it, and
        neither is evidence the key is healthy.
        """
        metadata = self._describe_key(self._get_client(), kek_resource_name)
        if metadata is None:
            return KekState.unknown()
        if metadata.get("KeyState") == "PendingDeletion":
            return KekState(
                state=KekState.PENDING_DELETION,
                effective_at=self._deletion_date(metadata.get("DeletionDate"), self.deletion_window_days()),
            )
        return KekState(state=KekState.ACTIVE)

    @staticmethod
    def _deletion_date(value, window_days: int) -> datetime.datetime:
        """Normalize AWS's ``DeletionDate`` to an aware datetime.

        Falls back to now plus the configured window when the field is missing,
        so a sparse response still yields a usable date instead of ``None``.
        """
        if isinstance(value, datetime.datetime):
            return value if timezone.is_aware(value) else timezone.make_aware(value, datetime.UTC)
        return timezone.now() + datetime.timedelta(days=window_days)

    # ------------------------------------------------------------------
    # Enumeration
    # ------------------------------------------------------------------

    def _do_list_kek_names(self, owner_prefix: str) -> list[str]:
        """List this account/region's KMS aliases via ListAliases.

        A KMS key carries no name — only an alias does — so enumeration is
        alias-based and only works when this deployment's KEKs are named
        ``alias/…``. With a non-alias owner prefix there is nothing to list, and
        returning an empty list would read as "no keys exist", so this raises
        instead: the enumeration funnel turns that into detection-unavailable,
        which reconcile reports rather than treating every silo as orphaned.

        ListAliases has no server-side prefix filter, so *owner_prefix* is not
        passed to AWS; the base :meth:`list_kek_names` re-filters the result.
        Aliases with no target key (AWS allows a dangling alias) are skipped —
        they name nothing this deployment could own.
        """
        if not owner_prefix.startswith(_ALIAS_PREFIX):
            raise RuntimeError(
                "AWS KEK enumeration is alias-based (ListAliases): a KMS key has no name of "
                f"its own. This deployment's owner prefix is '{owner_prefix}', which is not an "
                "alias, so its keys cannot be listed. Use a KEK_TEMPLATE that renders an "
                "'alias/…' name to enable KMS-side reconcile."
            )
        client = self._get_client()
        names: list[str] = []
        for page in client.get_paginator("list_aliases").paginate():
            for alias in page.get("Aliases") or []:
                name = alias.get("AliasName")
                if name and alias.get("TargetKeyId"):
                    names.append(name)
        return names

    def describe(self) -> str:
        return f"AwsKekProvisioner(region={self.options.get('AWS_REGION', 'us-east-1')})"
