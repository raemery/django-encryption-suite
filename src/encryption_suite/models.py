"""
Key lifecycle models — the two key stores and the audit ledger.

* :class:`DataEncryptionKey` — one row per silo per purpose, holding a data
  encryption key (DEK) wrapped by the silo's key encryption key. The crypto
  artifact; the DEK material is never stored in plaintext at rest.
* :class:`KeyEncryptionKey` — one durable row per known key encryption key (KEK)
  on the KMS, the materialized "latest state" of that key on the provider. Rows
  are never deleted; a terminal status keeps the row as the last-known record.
* :class:`KeyLifecycleEvent` — the append-only, immutable audit trail. Every state
  transition on either model writes one ledger event transactionally with the
  act (see :func:`apply_event`), so material is never created or destroyed
  without a trace.
* :class:`DekRotation` and :class:`DekRotationWorkItem` — transient: a data key
  rotation in flight and its worklist, gone once the silo is on one keyset again.

Status is a derived projection of the ledger: it is never assigned directly —
:func:`apply_event` is the single transition funnel that writes the event and
sets ``status`` from :data:`lifecycle.VERB_TO_STATUS` in one transaction. The
vocabulary (verbs, statuses, the projection map, the per-kind allowlists) lives
in :mod:`encryption_suite.lifecycle`.
"""

import ipaddress

from django.conf import settings
from django.core.validators import RegexValidator
from django.db import models, transaction
from django.utils.translation import gettext_lazy as _

from . import conf, lifecycle, user_context
from ._logging import get_logger
from .exceptions import EncryptionError, log_and_raise_key_identity_error
from .fields import EncryptedCharField
from .silo_ref import SiloRef

logger = get_logger(__name__)


def _event_kek_name(row) -> str:
    """The KEK name to snapshot onto a ledger event for *row*.

    A KeyEncryptionKey names itself; a DataEncryptionKey names its KEK through
    the relation. Snapshotted as a string because the event outlives whatever it
    describes — the ledger is the record of what happened, not a live join.
    """
    own = getattr(row, "kek_resource_name", None)
    if own is not None:
        return own
    kek = getattr(row, "kek", None)
    return getattr(kek, "kek_resource_name", "") or ""


def _event_protection(row) -> dict:
    """The protection state to snapshot onto a ledger event for *row*.

    A data key event records what protects the key after the act: the KEK, its
    KMS and version, the backend and the algorithm. Read off the row, so every
    writer must save those columns before it records. The event before it holds
    the state before, so the chain shows each change. A key encryption key's
    event records only its own version as last observed, so its history shows
    each rotation; its row names its KMS.
    """
    if row.key_kind != lifecycle.KIND_DATA_ENCRYPTION_KEY:
        return {"kek_key_version": row.kek_key_version}
    kek = row.kek
    return {
        "wrapping_kek": kek,
        "key_store": kek.key_store,
        "kek_key_version": row.kek_key_version,
        "crypto_backend": row.crypto_backend,
        "algorithm": row.algorithm,
    }


class DataEncryptionKey(models.Model):
    """
    Holds a KMS-wrapped DEK for a single silo and purpose.

    *silo_uid* uniquely identifies the silo across all types.
    The format is defined by the active silo adapter (e.g. ``"team-42"``).

    *purpose* distinguishes the DEK type: ``"field"`` for AEAD (model field
    encryption), ``"file"`` for Streaming AEAD (file/storage encryption), or
    ``"index"`` for the keyed hash behind a blind index — which is not an AEAD
    and encrypts nothing, but is a per-silo key wrapped by the same KEK, so it
    belongs to the same lifecycle: the soft-delete window, the purge that clears
    :attr:`encrypted_keyset`, the ledger, reconcile and the admin. Destroying the
    KEK takes a silo's digests with its data rather than leaving them as rows
    that can still be matched.

    The row carries an app-enforced soft-delete window: *schedule* flips
    ``status`` to ``deletion_scheduled`` (encrypt and decrypt blocked, fully
    restorable); *purge* clears :attr:`encrypted_keyset` — the only durable copy
    of the wrapped DEK, so the field-clear IS the crypto-shred — and leaves the
    row as a ``deleted`` tombstone holding silo_uid / purpose / the KEK reference.
    """

    key_kind = lifecycle.KIND_DATA_ENCRYPTION_KEY

    PURPOSE_FIELD = "field"
    PURPOSE_FILE = "file"
    PURPOSE_INDEX = "index"
    PURPOSE_TEST = "test"
    PURPOSE_CHOICES = [
        (PURPOSE_FIELD, _("Field encryption (AEAD)")),
        (PURPOSE_FILE, _("File encryption (Streaming AEAD)")),
        (PURPOSE_INDEX, _("Blind index (keyed hash)")),
        (PURPOSE_TEST, _("Admin test console (isolated)")),
    ]

    key_set = models.CharField(
        max_length=conf.KEY_SET_MAX_LENGTH,
        default=conf.DEFAULT_KEY_SET,
        db_index=True,
        validators=[RegexValidator(rf"\A{conf.KEY_SET_PATTERN}\Z")],
        verbose_name=_("Key set"),
        help_text=_(
            "A key set is one silo adapter and one key store. Fields that name the same set share "
            "its keys, and the settings choose the adapter and the key store."
        ),
    )
    silo_uid = models.CharField(
        max_length=512,
        db_index=True,
        verbose_name=_("Silo UID"),
        help_text=_("The silo adapter sets this identifier, and no two silos of one key set share one."),
    )
    purpose = models.CharField(
        max_length=20,
        choices=PURPOSE_CHOICES,
        default=PURPOSE_FIELD,
        verbose_name=_("Purpose"),
        help_text=_(
            "This says what the key does: it encrypts model fields, encrypts stored files, or computes a "
            "blind index. The admin test console uses keys of its own."
        ),
    )
    silo_label = models.CharField(
        max_length=100,
        verbose_name=_("Silo label"),
        help_text=_("The silo adapter names its silos with this label."),
    )
    encrypted_keyset = models.BinaryField(
        blank=True,
        default=bytes,
        verbose_name=_("Encrypted DEK"),
        help_text=_(
            "The key encryption key encrypts this data encryption key, and only the encrypted form is "
            "stored. Deleting the key clears it."
        ),
    )
    kek = models.ForeignKey(
        "encryption_suite.KeyEncryptionKey",
        on_delete=models.PROTECT,
        related_name="data_keys",
        verbose_name=_("Key encryption key"),
        help_text=_("This key encryption key encrypts the data encryption key."),
    )
    kek_key_version = models.CharField(
        max_length=255,
        blank=True,
        default="",
        verbose_name=_("KEK key version"),
        help_text=_(
            "The KMS reported this version of the key encryption key when it encrypted the data "
            "encryption key. Some providers need it to decrypt, and the rest keep it for reference. "
            "It is empty where the provider reports no version."
        ),
    )
    crypto_backend = models.CharField(
        max_length=50,
        blank=True,
        default="",
        verbose_name=_("Cryptographic engine"),
        help_text=_(
            "This crypto backend, such as 'tink' or 'cryptography', generated the data encryption key. "
            "The application checks it when it loads the key, so a different backend never loads it. "
            "It is empty for a blind index key."
        ),
    )
    algorithm = models.CharField(
        max_length=64,
        blank=True,
        default="",
        verbose_name=_("Algorithm"),
        help_text=_(
            "The crypto backend generated the data encryption key for this algorithm, such as "
            "'AES256_GCM', and names it in its own terms."
        ),
    )
    reencryption_count = models.PositiveIntegerField(
        default=1,
        verbose_name=_("Encrypted key writes"),
        help_text=_(
            "The application adds one each time it writes new encrypted key material to this row: when "
            "a key encryption key re-encrypts the same key, or when a rotation replaces it."
        ),
    )
    dek_key_version = models.PositiveIntegerField(
        default=1,
        verbose_name=_("DEK key version"),
        help_text=_(
            "The application counts the generations of this key's material: 1 for the first key, then "
            "one more for each rotation. Unlike the key encryption key version, it is not a provider "
            "identifier. Unlike the count of encrypted key writes, it does not change when another key "
            "encryption key re-encrypts the same material."
        ),
    )
    status = models.CharField(
        max_length=30,
        choices=lifecycle.DEK_STATUS_CHOICES,
        default=lifecycle.INITIAL_STATUS,
        db_index=True,
        verbose_name=_("Status"),
        help_text=_("The application derives the key's current status from its key lifecycle events."),
    )
    undeletable_until = models.DateTimeField(
        null=True,
        blank=True,
        verbose_name=_("Undeletable until"),
        help_text=_(
            "The application's deletion window ends at this time. Nothing can destroy the key before "
            "then; after it, deleting the key may destroy it. The key can be restored until it is "
            "actually deleted."
        ),
    )
    is_orphaned = models.BooleanField(
        default=False,
        verbose_name=_("Orphaned"),
        help_text=_(
            "Reconcile sets this when no live silo matches the key's silo UID. It is for display only: "
            "every action that destroys a key checks again before it acts."
        ),
    )
    key_material_last_generated_at = models.DateTimeField(
        null=True,
        blank=True,
        verbose_name=_("Key material last generated at"),
        help_text=_(
            "The key material now in use was generated at this time. A data encryption key's "
            "cryptoperiod counts from here, not from the row's creation date, which a revived key keeps "
            "from its first life. Re-encrypting the key onto another key encryption key does not change "
            "it, because the material stays the same."
        ),
    )
    last_reencrypted_at = models.DateTimeField(
        null=True,
        blank=True,
        verbose_name=_("Last re-encrypted at"),
        help_text=_(
            "Its key encryption key last re-encrypted this data encryption key at this time. Rotating a "
            "key encryption key protects nothing already stored until this re-encryption runs, so a key "
            "encryption key's cryptoperiod counts against this time, not against the rotation."
        ),
    )
    created_at = models.DateTimeField(auto_now_add=True, verbose_name=_("Created at"))
    updated_at = models.DateTimeField(auto_now=True, verbose_name=_("Updated at"))

    class Meta:
        app_label = "encryption_suite"
        verbose_name = _("Data encryption key")
        verbose_name_plural = _("Data encryption keys")
        constraints = [
            models.UniqueConstraint(
                fields=["key_set", "silo_uid", "purpose"],
                name="unique_silo_key_set_purpose",
            ),
        ]

    def __str__(self) -> str:
        # No rewrap count here. It is a maintenance statistic, not part of the
        # key's identity, and rendering it inline read like a KMS key version —
        # which it is not. The column and the detail page still show it.
        key_set = "" if self.key_set == conf.DEFAULT_KEY_SET else f" {self.key_set}"
        return f"{self.silo_label}:{self.silo_uid}{key_set} [{self.purpose}]"

    @property
    def silo_ref(self) -> SiloRef:
        """This key's identity: its key set and the silo adapter's uid."""
        return SiloRef(self.key_set, self.silo_uid)

    def record_event(self, event, *, trigger, **fields):
        """Apply a lifecycle event to this row through the transition funnel.

        ``trigger`` is named explicitly rather than left inside ``**fields``,
        which would swallow it: a miss would then surface as a ``TypeError`` at
        runtime, on a failure path, instead of at the call.
        """
        return apply_event(self, event, trigger=trigger, **fields)


class KeyEncryptionKey(models.Model):
    """One durable row per known key encryption key (KEK) — the materialized latest state.

    A KEK lives on the KMS and never leaves it; this row is the local record of
    one. It replaces the old transient pending-deletion queue: a row exists for
    every KEK the package has provisioned, an operator has recorded, or reconcile
    has discovered, and is **never deleted** — a terminal ``deleted`` status
    keeps the row as the last-known record.

    There is deliberately **no** ``silo_uid`` field: a shared KEK belongs to
    many silos and a discovered orphan to none. Silo association is always via
    the ``data_keys`` reverse relation from :class:`DataEncryptionKey` (whose
    rows survive a purge as tombstones), so the deletion connector joins through
    the deleted silo's DEK rows to find which KeyEncryptionKey rows to schedule —
    and the same relation answers "does live data still depend on this key"
    without matching strings.
    """

    key_kind = lifecycle.KIND_KEY_ENCRYPTION_KEY

    DISPOSITION_SILO_EXCLUSIVE = "silo_exclusive"
    DISPOSITION_SHARED = "shared"
    DISPOSITION_CHOICES = [
        (DISPOSITION_SILO_EXCLUSIVE, _("Silo-exclusive — eligible for deleting")),
        (DISPOSITION_SHARED, _("Shared/opaque — never auto-deleted")),
    ]

    # The ENCRYPTION["KMS_KEY_STORES"] name of the block holding this key, or
    # "system". Every unwrap of a data key under this row routes by it.
    key_store = models.CharField(
        max_length=50,
        verbose_name=_("Key store"),
        help_text=_("This key store holds the key encryption key. The name is a block in the KMS_KEY_STORES setting."),
    )
    kek_resource_name = models.CharField(
        max_length=512,
        verbose_name=_("KEK resource name"),
        help_text=_("The KMS knows this key encryption key by this full resource name."),
    )
    status = models.CharField(
        max_length=30,
        choices=lifecycle.KEK_STATUS_CHOICES,
        default=lifecycle.INITIAL_STATUS,
        db_index=True,
        verbose_name=_("Status"),
        help_text=_("The application derives the key's current status from its key lifecycle events."),
    )
    undeletable_until = models.DateTimeField(
        null=True,
        blank=True,
        verbose_name=_("Undeletable until"),
        help_text=_(
            "The application's deletion window ends at this time. Nothing can destroy the key before "
            "then; after it, deleting the key may destroy it. The key can be restored until it is "
            "actually deleted."
        ),
    )
    kms_deletion_at = models.DateTimeField(
        null=True,
        blank=True,
        verbose_name=_("KMS deletion at"),
        help_text=_(
            "The provider destroys the key at this time. The application sets it when it asks the "
            "provider to delete the key, or when it finds a deletion already under way. Only the "
            "provider can cancel the deletion; this application cannot."
        ),
    )
    disposition = models.CharField(
        max_length=20,
        choices=DISPOSITION_CHOICES,
        blank=True,
        default="",
        verbose_name=_("Disposition"),
        help_text=_(
            "This says whether the key encryption key could be deleted when it was scheduled for "
            "deletion. Wherever a data encryption key still names the key, the deletion works this out "
            "again from the running configuration and uses that answer instead."
        ),
    )
    owner_prefix = models.CharField(
        max_length=512,
        blank=True,
        default="",
        verbose_name=_("Owner prefix"),
        help_text=_(
            "This prefix marked the key as this application's when it was scheduled for deletion. It "
            "stays empty until then, and the application refuses to delete the key if the current "
            "prefix no longer matches."
        ),
    )
    kek_key_version = models.CharField(
        max_length=255,
        blank=True,
        default="",
        verbose_name=_("KEK key version"),
        help_text=_("The KMS last reported this version of the key encryption key as current."),
    )
    is_orphaned = models.BooleanField(
        default=False,
        verbose_name=_("Orphaned"),
        help_text=_(
            "Reconcile sets this when no live silo uses the key. It is for display only: every action "
            "that destroys a key checks again before it acts."
        ),
    )
    created_at = models.DateTimeField(auto_now_add=True, verbose_name=_("Created at"))
    updated_at = models.DateTimeField(auto_now=True, verbose_name=_("Updated at"))

    class Meta:
        app_label = "encryption_suite"
        verbose_name = _("Key encryption key")
        verbose_name_plural = _("Key encryption keys")
        constraints = [
            models.UniqueConstraint(
                fields=["key_store", "kek_resource_name"],
                name="unique_key_store_resource",
            ),
        ]

    #: Columns naming *which* KMS key this row stands for. Set once, at creation.
    IDENTITY_FIELDS = ("key_store", "kek_resource_name")

    def __str__(self) -> str:
        # No status here: wherever the key is named as history, its status now
        # would read as its status then. Pages that want it show it beside.
        return f"{self.key_store}:{self.kek_resource_name}"

    @classmethod
    def from_db(cls, db, field_names, values):
        instance = super().from_db(db, field_names, values)
        # Snapshot the identity as loaded, so save() can tell an in-memory
        # reassignment from a row that always looked this way.
        instance._loaded_identity = {
            name: value for name, value in zip(field_names, values, strict=False) if name in cls.IDENTITY_FIELDS
        }
        return instance

    def save(self, *args, **kwargs):
        """Refuse to reassign the identity of an existing row.

        Deletion reads these columns — the ownership gate prefix-matches
        ``kek_resource_name``, and the purge hands it to the provisioner's delete
        call — so a reassignment aims an irreversible destruction at a key nobody
        chose. Failing the write keeps that loud and local.

        Only rows loaded from the database are checked; a fresh instance has no
        prior identity to contradict. ``QuerySet.update()`` and ``bulk_update()``
        bypass ``save()`` and are deliberately not covered: this is a rail against
        ordinary code and admin paths, not a security boundary.
        """
        loaded = getattr(self, "_loaded_identity", None)
        if loaded:
            changed = {name: was for name, was in loaded.items() if getattr(self, name) != was}
            if changed:
                detail = ", ".join(
                    f"{name}: {was!r} -> {getattr(self, name)!r}" for name, was in sorted(changed.items())
                )
                log_and_raise_key_identity_error(
                    logger,
                    f"KeyEncryptionKey(pk={self.pk}) identity cannot be reassigned once the row "
                    f"exists ({detail}). Create a row for the other key instead.",
                )
        super().save(*args, **kwargs)
        # A save may narrow the row via update_fields; re-snapshot so the next
        # save compares against what is now stored.
        self._loaded_identity = {name: getattr(self, name) for name in self.IDENTITY_FIELDS}

    def record_event(self, event, *, trigger, **fields):
        """Apply a lifecycle event to this row through the transition funnel.

        ``trigger`` is named explicitly rather than left inside ``**fields``,
        which would swallow it: a miss would then surface as a ``TypeError`` at
        runtime, on a failure path, instead of at the call.
        """
        return apply_event(self, event, trigger=trigger, **fields)


class RecordedIPAddress(models.Model):
    """One address an act was recorded from, held once and referenced by key.

    Kept apart from the records that cite it so a value lives in one place, and
    so encrypting it never rewrites an append-only row: a system key rotation
    re-encrypts this table, not the ledger.

    Each row holds the value in exactly one of its two columns, plaintext or
    encrypted, per the configuration in force when it was written. A switch
    between the two applies to later acts only; earlier records keep pointing
    at rows in the old form. Nothing is unique, so the same value may appear
    more than once — across the two forms by design, and from two acts seeing
    a new value at the same instant — and a lookup takes whichever it finds.

    Rows are never deleted: the records referencing them use ``PROTECT``.
    """

    # Null, not "": Postgres `inet` rejects the empty string.
    ip_address = models.GenericIPAddressField(null=True, blank=True, db_index=True)
    # 39 is the longest canonical address text, as GenericIPAddressField sizes it.
    encrypted_ip_address = EncryptedCharField(
        key_set="system", max_length=39, null=True, blank=True, blind_index=True, db_index=True
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        app_label = "encryption_suite"
        verbose_name = _("Recorded IP address")
        verbose_name_plural = _("Recorded IP addresses")
        constraints = [
            models.CheckConstraint(
                condition=~models.Q(ip_address__isnull=False, encrypted_ip_address__isnull=False),
                name="recordedipaddress_one_form",
            ),
        ]

    @property
    def value(self):
        """The address, from whichever column holds it.

        The plaintext column is read first: a row holds one form, so a plaintext
        row costs no decryption. An encrypted value that cannot be read comes back
        as the lenient fallback, detected with ``is_undecryptable``.
        """
        return self.ip_address if self.ip_address is not None else self.encrypted_ip_address

    def __str__(self) -> str:
        return str(self.value or "")


class RecordedOSUser(models.Model):
    """One operating-system account an act was recorded from, held once.

    The same arrangement as :class:`RecordedIPAddress`: one value per row, in
    one of two columns, never deleted. The value is the composed description
    :func:`~encryption_suite.user_context.get_os_user` returns, stored exactly
    as composed.
    """

    os_user = models.CharField(max_length=200, null=True, blank=True, db_index=True)
    encrypted_os_user = EncryptedCharField(
        key_set="system", max_length=200, null=True, blank=True, blind_index=True, db_index=True
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        app_label = "encryption_suite"
        verbose_name = _("Recorded OS user")
        verbose_name_plural = _("Recorded OS users")
        constraints = [
            models.CheckConstraint(
                condition=~models.Q(os_user__isnull=False, encrypted_os_user__isnull=False),
                name="recordedosuser_one_form",
            ),
        ]

    @property
    def value(self):
        """The OS user, from whichever column holds it; see :attr:`RecordedIPAddress.value`."""
        return self.os_user if self.os_user is not None else self.encrypted_os_user

    def __str__(self) -> str:
        return str(self.value or "")


def _recorded_row(model, plain_field: str, encrypted_field: str, value: str, *, encrypted: bool):
    """Return a *model* row holding *value* in the current form, creating one if none matches.

    Matches only within the current form's column — the blind index under
    encryption, the plaintext otherwise — so a value stored the other way gets a
    row of its own. The first match wins; duplicates are harmless.

    Returns ``None`` when the system keys cannot serve the encrypted form: an
    identity is an audit detail, and must never be what fails a key act. Run in a
    savepoint so a failed write cannot abort the caller's transaction.

    The encrypted form needs the system silo's keys. They are never being made
    when this runs: the engine creates them all before it writes their own
    events (``EncryptionEngine.ensure_system_keys``), so even those events carry
    the encrypted value.
    """
    column = encrypted_field if encrypted else plain_field
    try:
        with transaction.atomic():
            row = model.objects.filter(**{column: value}).order_by("pk").first()
            if row is None:
                row = model.objects.create(**{column: value})
    except EncryptionError as exc:
        logger.warning(
            "An act was recorded without one identity value, because the system keys could not "
            "encrypt it. item=%s error_code=%s",
            encrypted_field,
            exc.code,
        )
        return None
    return row


def recorded_identity(*, user=None, os_login_user="", user_ip=None):
    """Apply ``KEY_LIFECYCLE_EVENTS`` to an identity and resolve it to what a record stores.

    Returns ``(user_pk, os_user_row, ip_address_row)``, each ``None`` where the
    list leaves that item out or there is no value. *user* takes an instance or a
    primary key. The address is normalized to its canonical text before lookup;
    an address that does not parse is dropped, since the column cannot hold it.
    The OS user is matched exactly as composed.
    """
    items = conf.user_identity_setting("KEY_LIFECYCLE_EVENTS")
    user = getattr(user, "pk", user) if conf.ITEM_USER_ID in items else None

    os_user_row = None
    encrypted = conf.ITEM_ENCRYPTED_OS_USER in items
    if os_login_user and (encrypted or conf.ITEM_OS_USER in items):
        os_user_row = _recorded_row(RecordedOSUser, "os_user", "encrypted_os_user", os_login_user, encrypted=encrypted)

    ip_row = None
    encrypted = conf.ITEM_ENCRYPTED_IP_ADDRESS in items
    if user_ip and (encrypted or conf.ITEM_IP_ADDRESS in items):
        try:
            address = str(ipaddress.ip_address(str(user_ip).strip()))
        except ValueError:
            logger.warning("An act was recorded without its address, which is not a valid IP address.")
        else:
            ip_row = _recorded_row(
                RecordedIPAddress, "ip_address", "encrypted_ip_address", address, encrypted=encrypted
            )
    return user, os_user_row, ip_row


class KeyLifecycleEvent(models.Model):
    """Append-only, immutable audit trail of every key lifecycle event.

    The permanent record of what happened to a silo's keys — provisioning,
    creation, rewrap, retention, scheduling, deletion — across both
    :class:`KeyEncryptionKey` and :class:`DataEncryptionKey`. The live rows carry the
    *latest* state; this ledger carries the *path*: actor, timestamp and reason
    per transition, repeats/cycles (rewraps, schedule/restore loops), and the
    generation history that a reused tombstone row would otherwise overwrite.

    Rows are **never updated or deleted** (the two key FKs use ``PROTECT``); a
    later state is recorded as a *new* event. Because the permanent-record
    guarantee lives here, an event row MUST be written transactionally with the
    act it records — :func:`apply_event` is the funnel that does so. No plaintext
    or wrapped key material is ever stored here.

    Exactly one of :attr:`kek` / :attr:`dek` is set (a DB
    ``CheckConstraint`` enforces it); which one is set is the key kind, so there
    is no separate ``key_kind`` column. ``kek_resource_name`` and ``silo_uid``
    are snapshotted for search/display without a join.
    """

    # Kept as class attributes for the call sites that already read them, but
    # defined once in ``lifecycle`` beside their labels — the vocabulary module is
    # the single authority for verbs, statuses and now reasons, so a slug and the
    # words shown for it can never drift apart.
    REASON_RECORDED_BY_OPERATOR = lifecycle.REASON_RECORDED_BY_OPERATOR
    REASON_OBSERVED_AT_PROVIDER = lifecycle.REASON_OBSERVED_AT_PROVIDER
    REASON_CONFIRMED_BY_RECONCILE = lifecycle.REASON_CONFIRMED_BY_RECONCILE

    event = models.CharField(
        max_length=30,
        choices=lifecycle.EVENT_CHOICES,
        db_index=True,
        verbose_name=_("Event"),
        help_text=_("This names what happened to the key."),
    )
    kek = models.ForeignKey(
        "encryption_suite.KeyEncryptionKey",
        null=True,
        blank=True,
        on_delete=models.PROTECT,
        related_name="events",
        verbose_name=_("Key encryption key"),
        help_text=_(
            "The event is about this key encryption key. It is empty when the event is about a data encryption key."
        ),
    )
    dek = models.ForeignKey(
        "encryption_suite.DataEncryptionKey",
        null=True,
        blank=True,
        on_delete=models.PROTECT,
        related_name="events",
        verbose_name=_("Data encryption key"),
        help_text=_(
            "The event is about this data encryption key. It is empty when the event is about a key encryption key."
        ),
    )
    key_set = models.CharField(
        max_length=conf.KEY_SET_MAX_LENGTH,
        blank=True,
        default="",
        verbose_name=_("Key set"),
        help_text=_(
            "At the time of this event, the key belonged to this key set. It is empty for a key "
            "encryption key that is shared or belongs to no silo."
        ),
    )
    silo_uid = models.CharField(
        max_length=512,
        blank=True,
        default="",
        db_index=True,
        verbose_name=_("Silo UID"),
        help_text=_(
            "At the time of this event, the key belonged to this silo. It is empty for a key encryption "
            "key that is shared or belongs to no silo."
        ),
    )
    kek_resource_name = models.CharField(
        max_length=512,
        blank=True,
        default="",
        verbose_name=_("KEK resource name"),
        help_text=_("At the time of this event, the key encryption key involved had this resource name."),
    )
    # The protection state of a data key after the act, read off the row by
    # ``record``. A key encryption key's events fill only ``kek_key_version``, its
    # own version as last observed; that row names its KMS. ``wrapping_kek`` is not
    # ``kek``, which says which key the event is about.
    wrapping_kek = models.ForeignKey(
        "encryption_suite.KeyEncryptionKey",
        null=True,
        blank=True,
        on_delete=models.PROTECT,
        related_name="+",
        verbose_name=_("KEK"),
        help_text=_(
            "At the time of this event, this key encryption key encrypted the data encryption key. It is "
            "empty on a key encryption key's own events."
        ),
    )
    key_store = models.CharField(
        max_length=50,
        blank=True,
        default="",
        verbose_name=_("Key store"),
        help_text=_(
            "At the time of this event, this key store held the key encryption key. It is empty on a key "
            "encryption key's own events."
        ),
    )
    kek_key_version = models.CharField(
        max_length=255,
        blank=True,
        default="",
        verbose_name=_("KEK key version"),
        help_text=_(
            "At the time of this event, the KMS reported this version of the key encryption key. It is "
            "empty where the provider reports no version."
        ),
    )
    crypto_backend = models.CharField(
        max_length=50,
        blank=True,
        default="",
        verbose_name=_("Cryptographic engine"),
        help_text=_(
            "At the time of this event, the data encryption key came from this crypto backend. It is "
            "empty for a blind index key and on a key encryption key's own events."
        ),
    )
    algorithm = models.CharField(
        max_length=64,
        blank=True,
        default="",
        verbose_name=_("Algorithm"),
        help_text=_(
            "At the time of this event, the data encryption key was generated for this algorithm. It is "
            "empty on a key encryption key's own events."
        ),
    )
    trigger = models.CharField(
        max_length=20,
        choices=lifecycle.TRIGGER_CHOICES,
        db_index=True,
        verbose_name=_("Trigger"),
        help_text=_(
            "This says how the event came about: someone asked for it, it followed from another act, or "
            "a script or schedule ran it."
        ),
    )
    reason = models.CharField(
        max_length=64,
        blank=True,
        choices=lifecycle.REASON_CHOICES,
        default="",
        verbose_name=_("Reason"),
        help_text=_("This says why the event happened, where the event alone does not."),
    )
    effective_at = models.DateTimeField(
        null=True,
        blank=True,
        verbose_name=_("Effective at"),
        help_text=_(
            "The event set this deletion date, where it set one: the end of the application's window "
            "for a scheduling event, or the provider's date for a requested deletion."
        ),
    )
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        # Never CASCADE: deleting a user would destroy ledger rows for keys other
        # people depend on. PROTECT was rejected too — a library must not block a
        # consuming app's user deletion. DO_NOTHING alone is not enough, since it
        # only means Django emits no SQL and the database constraint would still
        # fire, so the constraint is not created at all.
        on_delete=models.DO_NOTHING,
        db_constraint=False,
        null=True,
        blank=True,
        related_name="+",
        verbose_name=_("User"),
        help_text=_(
            "This user acted, where the configuration records one. The reference stays after the user is deleted."
        ),
    )
    # The two values below live in their own tables, referenced by key; see
    # RecordedIPAddress for why.
    os_user = models.ForeignKey(
        RecordedOSUser,
        null=True,
        blank=True,
        on_delete=models.PROTECT,
        related_name="+",
        verbose_name=_("OS login account"),
        help_text=_(
            "A command-line act ran under this operating-system account, shown with its uid, where the "
            "configuration records one."
        ),
    )
    ip_address = models.ForeignKey(
        RecordedIPAddress,
        null=True,
        blank=True,
        on_delete=models.PROTECT,
        related_name="+",
        verbose_name=_("User IP address"),
        help_text=_("The act came from this address, where the configuration records one."),
    )
    created_at = models.DateTimeField(auto_now_add=True, db_index=True, verbose_name=_("Recorded at"))

    class Meta:
        app_label = "encryption_suite"
        verbose_name = _("Key lifecycle event")
        verbose_name_plural = _("Key lifecycle events")
        ordering = ["-created_at"]
        constraints = [
            models.CheckConstraint(
                condition=(
                    models.Q(kek__isnull=False, dek__isnull=True) | models.Q(kek__isnull=True, dek__isnull=False)
                ),
                name="keylifecycleevent_exactly_one_key",
            ),
        ]

    def __str__(self) -> str:
        return f"{self.event} {self.kek_resource_name or self.silo_uid}"

    @property
    def key_kind(self):
        """Derive the key kind from which FK is set (no stored column)."""
        return lifecycle.KIND_KEY_ENCRYPTION_KEY if self.kek_id is not None else lifecycle.KIND_DATA_ENCRYPTION_KEY

    @classmethod
    def record(
        cls,
        row,
        event,
        *,
        trigger,
        user=None,
        os_user=None,
        ip_address=None,
        reason="",
        effective_at=None,
        silo_ref=None,
    ):
        """Append one immutable event row pointing at *row*. The single write point.

        Sets the correct key FK from *row*'s kind and snapshots
        ``kek_resource_name`` / ``silo_uid``, and for a data key its protection
        state (see :func:`_event_protection`). Call transactionally with the act
        being recorded — :func:`apply_event` is the wrapper that also projects
        status, so prefer it for any status-bearing verb.

        *user* is a primary key, never an instance: ``apply_event`` normalizes it
        above here, and the column is assigned directly so no query is needed —
        fetching the instance would be the same ``SynchronousOnlyOperation`` trap
        under ASGI that the context pair avoids. *os_user* and *ip_address* are
        the rows :func:`recorded_identity` resolved, never strings.
        """
        if silo_ref is None:
            key_set, silo_uid = getattr(row, "key_set", ""), getattr(row, "silo_uid", "")
        else:
            key_set, silo_uid = silo_ref.key_set, silo_ref.uid
        fk = {"kek": row} if row.key_kind == lifecycle.KIND_KEY_ENCRYPTION_KEY else {"dek": row}
        return cls.objects.create(
            event=event,
            key_set=key_set or "",
            silo_uid=silo_uid or "",
            kek_resource_name=_event_kek_name(row),
            trigger=trigger,
            user_id=user,
            os_user=os_user,
            ip_address=ip_address,
            reason=reason,
            effective_at=effective_at,
            **fk,
            **_event_protection(row),
        )

    @classmethod
    def record_by_operator(cls, row, event, *, user=None, os_login_user="", **fields):
        """Append a manually-recorded event for an act performed outside the app.

        Only the kind's manual verbs may be recorded (see
        :func:`lifecycle.manual_events_for_kind`); the reason is pinned to
        :data:`REASON_RECORDED_BY_OPERATOR` and the trigger to ``direct``, so the
        ledger always tells an operator attestation apart from a tooling-verified
        event. A hand-recorded attestation is the definition of a person asking
        for this key event, so neither is ever the caller's to choose. Routed
        through :func:`apply_event` so a recorded ``deleted`` also projects the
        row's status.

        At least one of *user* / *os_login_user* is required — a manual record
        is, by definition, something a person did, and an attestation must not
        land with nobody attached to it. The guard runs on what the caller passed,
        above the funnel's ``KEY_LIFECYCLE_EVENTS`` list: with nothing listed a
        manual record still has to be offered an identity, and still lands
        unattributed once the list is applied. The list is a posture about
        identities, not about the key event, and a settings value must not
        silently disable a management command. An address is not an identity and
        does not count.

        A bare ``ValueError``: both callers supply an identity structurally, at
        every scope, so firing this means a programming error in a new caller,
        not an operational failure.
        """
        if event not in lifecycle.manual_events_for_kind(row.key_kind):
            raise ValueError(f"event {event!r} cannot be recorded by an operator for {row.key_kind}")
        if not user and not os_login_user:
            raise ValueError("user or os_login_user is required when an operator records an act")
        fields.pop("reason", None)  # the reason is owned here, never caller-supplied
        fields.pop("trigger", None)  # so is the trigger
        entry = apply_event(
            row,
            event,
            trigger=lifecycle.TRIGGER_DIRECT,
            user=user,
            os_login_user=os_login_user,
            reason=cls.REASON_RECORDED_BY_OPERATOR,
            **fields,
        )
        # The one act the application did not perform and cannot verify, so the
        # row is the only evidence it happened. A line beside it is what an
        # operator can corroborate, timestamp and alert on from outside the
        # database. INFO, not WARNING: an attestation records a destruction that
        # happened elsewhere rather than causing one.
        logger.info(
            "An operator recorded an act performed outside this application; the ledger stands "
            'behind who claimed it, not behind the act. event=%s kek="%s" silo="%s" %s',
            event,
            _event_kek_name(row),
            getattr(row, "silo_uid", "") or "n/a",
            # Read, not popped: apply_event still needs it. It arrives inside
            # **fields because only the two identities the guard above tests are
            # named in the signature.
            user_context.identity_tail(user=user, os_login_user=os_login_user, user_ip=fields.get("user_ip")),
        )
        return entry


def apply_event(
    row,
    event,
    *,
    trigger,
    user=None,
    os_login_user="",
    user_ip=None,
    reason="",
    undeletable_until=None,
    kms_deletion_at=None,
    silo_ref=None,
    status=None,
):
    """The single lifecycle transition funnel.

    Writes the :class:`KeyLifecycleEvent` event for *row* and projects *row*'s
    ``status`` from :data:`lifecycle.VERB_TO_STATUS` in one transaction, so the
    live row can never drift from the immutable ledger. A verb mapping to
    ``None`` records the act without moving status (e.g. ``reencrypted``).

    *status* supplies the resulting status for the verbs in
    :data:`lifecycle.CALLER_SUPPLIED_STATUS_VERBS`, where one verb legitimately
    ends in more than one status. ``None`` for such a verb means the same as it
    does in the map: record the act, leave the status alone. For a verb in
    :data:`lifecycle.STATUS_ALTERNATIVES` it may name one of that verb's listed
    alternatives, and omitting it keeps the map's answer. Anything else is
    rejected, so the map stays the only authority. The status must also be one
    the row's kind can hold.

    The two dates are separate arguments because they are separate facts, and
    neither ever overwrites the other: *undeletable_until* is the end of the app's
    own window, during which the row can be restored from the admin;
    *kms_deletion_at* is when the provider destroys the key, set once its delete
    API has been called and reversible only at the provider. A key that has been
    requested keeps the record of when its own window ended. The ledger stores
    whichever date the event established in ``effective_at``.

    *trigger* is required, so the interpreter — not a reviewer — is what makes
    every write site say how its act came about. *user* takes an instance or a
    primary key, whichever the caller holds, and is normalized to a key here so
    nothing below sees an instance. *os_login_user* and *user_ip* are strings;
    :func:`recorded_identity` applies ``KEY_LIFECYCLE_EVENTS`` to all three and
    resolves the two strings to their rows, inside the act's transaction.

    Validates *event* against the row kind's allowlist — an invalid verb is
    a programming error, not an operator/runtime condition, so it raises a plain
    ``ValueError`` (it can never reach a user surface).
    """
    if event not in lifecycle.events_for_kind(row.key_kind):
        raise ValueError(f"event {event!r} is not valid for {row.key_kind}")
    if kms_deletion_at is not None and row.key_kind != lifecycle.KIND_KEY_ENCRYPTION_KEY:
        raise ValueError("kms_deletion_at applies to a key encryption key; a DEK has no provider-side deletion")
    if event in lifecycle.CALLER_SUPPLIED_STATUS_VERBS:
        new_status = status
    elif status is None:
        new_status = lifecycle.VERB_TO_STATUS[event]
    elif status in lifecycle.STATUS_ALTERNATIVES.get(event, ()):
        new_status = status
    else:
        raise ValueError(f"event {event!r} takes its status from VERB_TO_STATUS; {status!r} is not an alternative")
    if new_status is not None and new_status not in lifecycle.statuses_for_kind(row.key_kind):
        raise ValueError(f"status {new_status!r} is not valid for {row.key_kind}")
    with transaction.atomic():
        user, os_user_row, ip_row = recorded_identity(user=user, os_login_user=os_login_user, user_ip=user_ip)
        log_entry = KeyLifecycleEvent.record(
            row,
            event,
            trigger=trigger,
            user=user,
            os_user=os_user_row,
            ip_address=ip_row,
            reason=reason,
            effective_at=kms_deletion_at if kms_deletion_at is not None else undeletable_until,
            silo_ref=silo_ref,
        )
        update_fields = []
        if new_status is not None and row.status != new_status:
            row.status = new_status
            update_fields.append("status")
            # A key that is gone is not an orphan. "Orphaned" asks whether a key
            # still standing has anything left depending on it; once the key is
            # destroyed there is nothing to adopt and nothing to clean up, so the
            # annotation would report work that cannot be done. Cleared here, in
            # the one funnel both kinds pass through, because the alternative is
            # every writer of a terminal status remembering to do it — and the
            # reconcile annotations skip terminal rows, so a stale ``True`` would
            # otherwise survive on the row forever.
            if new_status == lifecycle.STATUS_DELETED and row.is_orphaned:
                row.is_orphaned = False
                update_fields.append("is_orphaned")
        for name, value in (("undeletable_until", undeletable_until), ("kms_deletion_at", kms_deletion_at)):
            if value is not None and getattr(row, name) != value:
                setattr(row, name, value)
                update_fields.append(name)
        if update_fields:
            update_fields.append("updated_at")
            row.save(update_fields=update_fields)
    return log_entry


class DekRotation(models.Model):
    """A data key rotation in flight: the incoming keyset and who opened it.

    One per data encryption key at most — the one-to-one is what stops two
    rotations opening at once. Lives from the moment the fence goes up until the
    silo's data is back on one keyset: the swap deletes it, and so does the end
    of a rollback. While it exists it holds the same silo's key material a
    second time, wrapped under a key encryption key of its own, so the purge that
    shreds the data key deletes it too, and the rewrap pass moves it with the
    data key it belongs to.

    Never shown in the admin, so its fields carry no labels; only the model's
    name surfaces, in the permissions Django creates for it. Any debugging view
    of it must render its state and never the keyset.
    """

    dek = models.OneToOneField(DataEncryptionKey, on_delete=models.PROTECT, related_name="rotation")
    # The key material the silo's data is being moved onto, wrapped by `kek`.
    # Becomes the data key's own at the swap.
    encrypted_keyset = models.BinaryField()
    kek = models.ForeignKey("encryption_suite.KeyEncryptionKey", on_delete=models.PROTECT, related_name="dek_rotations")
    kek_key_version = models.CharField(max_length=255, blank=True, default="")
    # The crypto backend that made the incoming keyset, copied onto the data key
    # at the swap. Recorded here rather than read from CRYPTO_BACKEND then, so a
    # run resumed after that setting changed still labels the keyset correctly.
    crypto_backend = models.CharField(max_length=50, blank=True, default="")
    # The algorithm of the incoming keyset, copied onto the data key at the swap
    # for the same reason.
    algorithm = models.CharField(max_length=64, blank=True, default="")
    # When the fence went up. The wait before conversion is measured from here.
    started_at = models.DateTimeField()
    # Written last, so an interrupted build never reads as a finished one.
    worklist_complete = models.BooleanField(default=False)
    # Written before the first reverse conversion. A rollback clears
    # `converted_at` as it goes, so without this an interrupted one reads as an
    # interrupted sweep; a rerun follows the flag.
    rolling_back = models.BooleanField(default=False)
    # Who opened the rotation. Same flags as the ledger's user: a user deletion
    # must neither cascade into an in-flight rotation nor be blocked by one. No
    # address column — a rotation opens from a command, with no request to read
    # one from.
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.DO_NOTHING,
        db_constraint=False,
        null=True,
        blank=True,
        related_name="+",
    )
    os_user = models.ForeignKey(RecordedOSUser, null=True, blank=True, on_delete=models.PROTECT, related_name="+")

    class Meta:
        app_label = "encryption_suite"
        verbose_name = _("Data encryption key rotation")
        verbose_name_plural = _("Data encryption key rotations")

    def __str__(self) -> str:
        return f"rotation of {self.dek_id}"


class DekRotationWorkItem(models.Model):
    """One unit of a rotation's work: a field on a row, or a row's file.

    Keyed on the data key rather than the rotation row. The swap deletes the
    rotation row inside its own small transaction, and the worklist — the
    largest table here — goes afterwards in batches; a foreign key to the
    rotation row would make that order impossible. So a leftover item for a data
    key with no rotation row is provably garbage, and opening a rotation clears
    any it finds.

    Records what to do and what was done, never a value: no ciphertext and no
    plaintext is ever staged here.
    """

    dek = models.ForeignKey(DataEncryptionKey, on_delete=models.PROTECT, related_name="rotation_work_items")
    model_label = models.CharField(max_length=200)
    object_pk = models.CharField(max_length=255)
    # The encrypted field, or the file field, this item converts.
    field_name = models.CharField(max_length=200)
    # When the item moved onto the incoming key material; cleared again by a
    # rollback.
    converted_at = models.DateTimeField(null=True, blank=True)
    # The code of the error the last attempt raised — a copy of an existing slug,
    # never a vocabulary of its own — so the report can be reprinted while the
    # rotation is open and a closed console does not cost the operator the list.
    failure_code = models.CharField(max_length=64, blank=True, default="")
    # File recovery columns, each written before the act it describes.
    old_blob_name = models.CharField(max_length=1024, blank=True, default="")
    new_blob_name = models.CharField(max_length=1024, blank=True, default="")
    old_blob_deleted = models.BooleanField(default=False)

    class Meta:
        app_label = "encryption_suite"
        verbose_name = _("Data encryption key rotation work item")
        verbose_name_plural = _("Data encryption key rotation work items")
        indexes = [
            # The swap's precondition runs inside its transaction on the largest
            # table here, and the batched delete walks the same scope.
            models.Index(fields=["dek", "converted_at"], name="rotation_item_dek_converted"),
        ]

    def __str__(self) -> str:
        return f"{self.model_label}:{self.object_pk}.{self.field_name}"


class BlindIndexEntry(models.Model):
    """One blind index digest, for a field that keeps it here rather than in a column.

    What ``blind_index_storage="table"`` is: a field whose model this project cannot
    change — one belonging to another package — cannot gain a companion column,
    because the column would have to live in that package's app and its
    migrations. A row here instead asks nothing of the target model, which is the
    only way to index such a column at all.

    Keyed on the model, the field and the row, so one field's digest for one row
    is one row here. ``object_pk`` is text because the primary keys it points at
    are not all of one type, and a lookup casts the outer key to match. There is
    no foreign key: the target is a different model for every row, which no
    foreign key can express, and a delete therefore has to be synchronized rather
    than cascaded — see :mod:`encryption_suite.blind_index`, which also pays for
    that by disabling Django's fast-delete path on the models it watches.

    ``unique_enforced`` is how one table carries both kinds of field. A
    uniqueness rule has to cover ``(model_label, field_name, digest)``, but only
    for the fields that declare one; the same tuple must be free to repeat for a
    field that does not. So the constraint takes this column too, set to ``True``
    where the field declares uniqueness and left ``NULL`` where it does not —
    every database Django supports treats a ``NULL`` in a unique index as
    distinct from every other, which keeps those rows out of the constraint
    without a condition on it. A conditional constraint would have been the
    obvious alternative and is the one thing that cannot be used: Django skips an
    unsupported one in silence, leaving no constraint and no error.

    Holds no value, encrypted or otherwise — a digest is a one-way hash, and
    which plaintext produced it is not recoverable from this table.
    """

    model_label = models.CharField(max_length=200)
    field_name = models.CharField(max_length=200)
    object_pk = models.CharField(max_length=255)
    digest = models.CharField(max_length=64)
    # True where the field declares uniqueness, NULL where it does not. See the
    # class docstring: this is what scopes the unique constraint below.
    unique_enforced = models.BooleanField(null=True)

    class Meta:
        app_label = "encryption_suite"
        verbose_name = _("Blind index entry")
        verbose_name_plural = _("Blind index entries")
        constraints = [
            # One digest per row per field, which is what lets a save replace an
            # entry rather than add a second one.
            models.UniqueConstraint(
                fields=["model_label", "field_name", "object_pk"],
                name="blind_index_one_entry_per_row",
            ),
            # The uniqueness a field asks for, scoped by unique_enforced.
            models.UniqueConstraint(
                fields=["model_label", "field_name", "digest", "unique_enforced"],
                name="blind_index_unique_value",
            ),
        ]
        indexes = [
            # What a lookup reads: the digests of one field, to find the rows
            # holding them.
            models.Index(fields=["model_label", "field_name", "digest"], name="blind_index_lookup"),
        ]

    def __str__(self) -> str:
        return f"{self.model_label}:{self.object_pk}.{self.field_name}"


class EncryptionTools(models.Model):
    """No table and no rows — a home for the permissions gating the two custom screens.

    Reconcile Keys and the test console both span *both* key models: reconcile
    reads and annotates data encryption keys and key encryption keys alike, and
    the console creates and deletes rows of both plus a real key at the provider.
    Hanging their permissions off either model would say something untrue about
    which one owns the screen, and would bury two screen permissions in the
    middle of one model's ordinary add/change/delete/view list.

    A permission needs a content type and a content type needs a model, so this
    is the model: unmanaged (the migration creates no table), stripped of the
    default permissions it would otherwise generate, and never registered in the
    admin. Its only effect is the grouping an administrator sees when granting
    access.
    """

    class Meta:
        app_label = "encryption_suite"
        managed = False
        default_permissions = ()
        verbose_name = _("Encryption tools")
        verbose_name_plural = _("Encryption tools")
        # Not translated: ``create_permissions`` writes these labels into the
        # database once, in whatever language happened to be active during
        # ``migrate``, and never revisits them. A lazy string would promise a
        # translation the permission list cannot deliver.
        permissions = [
            ("reconcile_keys", "Can use the Reconcile Keys screen"),
            ("run_test_console", "Can use the Test console screen"),
            ("view_settings", "Can use the Encryption settings screen"),
            ("view_inventory", "Can use the Cryptographic inventory screen"),
        ]
