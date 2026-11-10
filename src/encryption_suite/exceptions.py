"""
Typed exceptions raised by django-encryption-suite.

All exceptions subclass :class:`EncryptionError`, which subclasses
``ValueError`` so that broad ``except ValueError`` handlers around
encrypt/decrypt also catch them. Prefer catching the specific types.
"""

from __future__ import annotations

import logging
from typing import NoReturn

from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _

# The complete set of strings a user may be shown. Every raise site in the
# package passes one of these names — never a literal — so the whole user-facing
# surface can be read in one place, and so a name can be repointed at different
# wording without hunting for which sites meant it.
#
# One name per string. Names that differ only by the reason a message is shown
# are a distinction an operator makes, and an operator reads the code slug and
# the log, not this; a user reading the same sentence twice cannot tell which
# name produced it.
#
# Every one of these names no key, no setting, and no component, and makes no
# claim about whether the condition will clear on its own — a missing dependency
# or a bad setting never does, and inviting a retry that cannot succeed is worse
# than saying nothing. The actionable operator detail goes to the log and to the
# exception's ``detail`` attribute, never here.
#
# Each distinct string is a msgid hand-translated into twelve locale catalogs,
# so reuse beats invention: prefer an existing string over a new one.

# Shown whenever the keys themselves cannot be used, whatever the reason: a
# configuration failure surfaced through :func:`log_and_raise_configuration_error`,
# a KEK that is absent or inside its provider's deletion window, a DEK that is
# scheduled for deletion or gone, or a KMS operation the engine could not
# complete. Which of those it was lives in the code slug and the log.
#
# Names *both* directions because every one of these sites is reachable from a
# read as well as a write: `_decrypt_to_aead` runs the same DEK-status,
# provider, and backend checks the write path does, and the KMS funnel covers
# `key unwrap` as well as `key wrap`. Saying only "encryption" told a reader who
# was opening a record that their save had failed.
#
# Scoped to "this data" because these failures are per-silo, not global — a
# reader seeing an unqualified "unavailable" would reasonably conclude the whole
# application was down. The qualifier stays vague on purpose: the boundary is a
# team, tenant, workspace, or organization depending on the consuming project,
# and the package has no word for it that would be true everywhere.
GENERIC_ENCRYPT_DECRYPT_UNAVAILABLE_MESSAGE = _("Encryption and decryption are unavailable for this data.")

# Shown when the keys were fine and the operation itself failed. Split by
# direction because that is the one distinction a user can act on: they know
# whether they were saving or reading. Field and file share each string — which
# kind of column failed tells a user nothing they can use.
GENERIC_ENCRYPT_FAILED_USER_MESSAGE = _("Encryption failed.")
GENERIC_DECRYPT_FAILED_USER_MESSAGE = _("Decryption failed.")


class EncryptionError(ValueError):
    """Base class for all django-encryption-suite runtime errors.

    Every concrete subclass sets :attr:`code` to a stable, language-neutral
    slug (the decoupling pattern — cf. DRF error ``code``, allauth
    ``error_messages`` slugs). The slug is included in operator logs and exposed
    on the exception so an API/edge layer can serialize it (e.g. a DRF
    ``EXCEPTION_HANDLER`` returning ``{"code": exc.code, "detail": str(exc)}``),
    while user-facing rendered messages stay prose-only. Slugs are append-only:
    never renamed or reused once shipped. The base itself is abstract and
    carries no code.

    The package speaks on two channels, and they are not interchangeable.
    ``str(exc)`` is the *user* channel: a generic, translated sentence that
    names nothing about how the deployment is built. :attr:`detail` is the
    *operator* channel: English prose that may name an option, a resource, a
    field, or a provider error, and that also goes to the log. Declared here as
    ``None`` so ``exc.detail`` reads on every subclass without ``getattr``.

    Pass the operator text with the keyword-only ``detail=``; the first
    positional argument is always the user message.
    """

    code: str = ""

    # Operator-facing detail (English). None when the raising site has nothing
    # to add beyond its code.
    detail: str | None = None

    def __init__(self, *args, detail: str | None = None):
        super().__init__(*args)
        if detail is not None:
            self.detail = detail


class EncryptionConfigurationError(EncryptionError):
    """
    The application is misconfigured or the encryption context is not set up.

    Covers developer-fixable problems in the *consuming project* — not bugs in
    the package, and not transient operational failures:

    * no silo (team/tenant/group) in the current context when an
      encrypted field is accessed — usually missing or mis-ordered middleware;
    * KEK strategy misconfiguration (``KEK_TEMPLATE`` / ``KEK_MAP`` /
      ``SHARED_KEK_ID`` absent), an unknown key template, or a missing optional
      dependency for the configured adapter.

    Subclasses :class:`EncryptionError`, so a single ``except EncryptionError``
    catches it. Because it is a configuration problem rather than ciphertext or
    KMS trouble, the package handles it without a raw traceback (whose frames
    would point into the package and wrongly implicate it): on a lenient read
    it degrades to the fallback after logging a fix-your-config message; on a
    write the consuming view catches it and shows the message.

    When raised via :func:`log_and_raise_configuration_error`, ``str(exc)`` is a
    generic translated user-safe message (so a view showing ``str(exc)`` leaks no
    config detail) and the actionable operator detail is preserved on
    :attr:`detail` (also logged). When raised directly, ``str(exc)`` is the
    message passed in.
    """

    code = "configuration_error"


class MissingDekError(EncryptionError):
    """
    No ``DataEncryptionKey`` row exists for the current silo.

    Raised on decrypt when there is no DEK to decrypt under, and on encrypt
    when ``KEY_AUTO_PROVISION`` is disabled (or no silo object can be
    resolved to create a DEK for).
    """

    code = "missing_dek"


class KekNotProvisionedError(EncryptionError):
    """
    The KMS reported that the configured KEK does not exist.

    This typically means the KEK must be created on the KMS provider before
    encryption can proceed. Configure a KEK provisioner adapter (the
    ``KEK_PROVISIONER_ADAPTER`` of the KMS's ``KMS_KEY_STORES`` block) to have the
    application create KEKs on demand, or provision them outside this
    application. Also raised by the env key store when a row records a
    ``ENV_KEY_STORES`` version that setting no longer holds.
    """

    code = "kek_not_provisioned"


class KekPendingDeletionError(KekNotProvisionedError):
    """
    The KEK exists on the provider but is inside *its* deletion window.

    Distinct from a KEK that was never created, because the remedy is the
    opposite: the key is there and recoverable, so an operator cancels the
    deletion at the provider (``aws kms cancel-key-deletion`` and equivalents)
    rather than creating anything. Both cases look identical to a user, so the
    difference lives in the code slug and the operator log, not the message.

    Subclasses :class:`KekNotProvisionedError` deliberately: every existing
    ``except KekNotProvisionedError`` keeps catching it, and it stays eligible
    for the engine's negative cache, while machine consumers reading
    :attr:`code` can still tell the two apart.

    Raised by a provisioner's ``ensure_kek`` when it observes the state — for
    providers that expose one (AWS ``PendingDeletion``, OCI
    ``PENDING_DELETION``, GCP ``DESTROY_SCHEDULED``); providers whose deletion
    is immediate never raise it. The raise site does not log: it runs inside
    the engine's ``_ensure_kek`` funnel, which logs exactly one line carrying
    :attr:`detail`, so no traceback and no duplicate entry reaches the log.

    *effective_at* carries the provider's own destruction date when it reports
    one, which the engine records onto the key's row so the state outlives the
    failed request.
    """

    code = "kek_pending_deletion"

    def __init__(self, detail, *, effective_at=None):
        # str(exc) stays the generic, translated message a user may see; the
        # operator text lives on `detail`, exactly as the log/raise helpers do.
        super().__init__(GENERIC_ENCRYPT_DECRYPT_UNAVAILABLE_MESSAGE)
        self.detail = detail
        self.effective_at = effective_at


class KekDeleteError(EncryptionError):
    """
    Deleting (scheduling deletion of) a KEK on the KMS provider failed.

    Raised by the KEK deletion path — the admin purge action and
    the provisioner ``delete_kek`` it calls — when a KEK that the package
    provisioned cannot be scheduled for deletion. Causes include a provider error
    from the delete/schedule-deletion API, or the defensive ownership guard
    refusing to delete a key whose name does not carry this deployment's owner
    prefix (a key that is not provably ours).

    Runs *outside* the engine's runtime funnel (deletion is a batch/admin
    operation, not an encrypt/decrypt request), so the provisioner raises this
    typed error directly via :func:`log_and_raise_delete_error`: the operator
    detail (KEK resource name, provider error, refusal reason) is logged once
    under ``error_code=kek_delete_failed`` and attached to :attr:`detail`, while
    ``str(exc)`` is the generic translated message. The command leaves the
    tombstone in place on failure so the deletion is retried rather than lost.
    """

    code = "kek_delete_failed"


class SiloEnumerationError(EncryptionError):
    """
    The configured silo adapter cannot list every live silo.

    Raised by :meth:`~encryption_suite.adapters.silos.base.AbstractSiloAdapter.iter_silos`
    (and the ``queryset_for_model_label`` helper it uses) on the enumeration
    path — keyset setup (``setup_encryption_keys``) and, in Phase 3, KMS
    reconcile. It spans both *operational* failure (``django-tenants`` is not
    installed, or a configured ``model_label`` is malformed or names an
    uninstalled app/model) and the *capability-absent* case (an adapter that
    legitimately cannot enumerate — the abstract base, or a composite adapter
    whose cell model the package cannot know). Note it does *not* wrap a
    transient database error: ``iter_silos`` returns a lazy queryset, so a
    connection failure surfaces (as a DB error) when the caller evaluates it,
    not here. This dual coverage is why the slug is
    ``_unavailable`` (cf. :class:`KekUnavailableError`) rather than ``_failed``:
    on the base/composite path nothing *failed*, the capability simply is not
    there.

    Callers must treat it as **detection-unavailable**, never as "there are no
    silos" — on the destroy path that distinction is critical, since an
    empty/failed enumeration must never be read as "everything is orphaned,
    delete it". Enumeration is operator-facing only (never on the encrypt/decrypt
    request path), so like the deletion path it runs *outside* the engine's
    runtime funnel: raise it via :func:`log_and_raise_enumeration_error`, which
    logs the operator detail once under ``error_code=silo_enumeration_unavailable``
    slug and attaches it to :attr:`detail`, while ``str(exc)`` stays the generic
    translated message so the admin surface never shows a raw traceback.
    """

    code = "silo_enumeration_unavailable"


class KekEnumerationError(EncryptionError):
    """
    Listing this deployment's KEKs on the KMS provider failed.

    Raised by the KEK reconcile path — ``provisioner.list_kek_names`` — when the
    set of KEKs owned by this deployment cannot be retrieved from the KMS.
    Causes include a provider error from the list/describe API, a provisioner
    that does not support enumeration being asked to enumerate, or a request to
    enumerate with no owner prefix (shared / ``KEK_MAP`` configs, where ownership
    is unprovable, so no key can be safely attributed to this deployment).

    The KMS-listing counterpart of :class:`SiloEnumerationError` (which lists
    *silos*); together they gate KEK reconcile, which compares the two sets.
    Callers branch on ``provisioner.supports_enumeration`` (and catch this type)
    to degrade to *detection-unavailable* — the KMS side is reported for manual
    audit rather than inferring orphans, since a wrong/empty enumeration on the
    destroy path could delete a live KEK (unrecoverable).

    Runs *outside* the engine's runtime funnel (reconcile is a batch/admin
    operation), so the provisioner raises this typed error directly via
    :func:`log_and_raise_kek_enumeration_error`: the operator detail is logged
    once under ``error_code=kek_enumeration_unavailable`` and attached to
    :attr:`detail`, while ``str(exc)`` is the generic translated message.
    """

    code = "kek_enumeration_unavailable"


class KekDeletionRecordError(EncryptionError):
    """
    Scheduling key deletion at silo deletion failed.

    Raised by :func:`~encryption_suite.deletion.schedule_deletion` (invoked from
    the ``post_delete`` connector wired by ``ENCRYPTION['SILO_AUTO_KEY_DELETION']``)
    when the DEK and KEK rows for a torn-down silo cannot be flipped to
    ``deletion_scheduled`` — e.g. a database error writing the rows, or a
    configuration error resolving the strategy that supplies the gate inputs.
    Scheduling never destroys a key, so this failure is not itself dangerous; its
    consequence is an *un-scheduled* deletion, which leaves the KEK recoverable
    via the KMS-side reconcile path.

    Runs *outside* the engine's runtime funnel (deletion is a signal/batch
    operation, not an encrypt/decrypt request), so the writer raises this typed
    error directly via :func:`log_and_raise_deletion_record_error`: the operator
    detail is logged once under ``error_code=kek_deletion_record_failed`` and
    attached to :attr:`detail`, while ``str(exc)`` is the generic translated
    message. The ``post_delete`` receiver catches it and swallows it so a failed
    recording can never break the operator's delete transaction.
    """

    code = "kek_deletion_record_failed"


class KeyIdentityImmutableError(EncryptionError):
    """
    A saved :class:`~encryption_suite.models.KeyEncryptionKey`'s identity was reassigned.

    ``key_store`` and ``kek_resource_name`` name *which* KMS key a row stands
    for. They are set when the row is created — by first encrypt,
    reconcile discovery, or an operator recording a key created outside this application — and are
    fixed from then on. A row that changes identity does not describe a different
    key; it silently transfers the history, the ledger events, and the pending
    deletion state of one key onto another.

    That matters because the deletion gates read these columns: the ownership
    gate prefix-matches ``kek_resource_name`` against the deployment's owner
    prefix, and the purge hands it to the provisioner's delete call. Reassigning
    identity therefore aims an irreversible destruction — crypto-shredding a KEK
    is not recoverable from a database backup — at a key nobody chose. Refusing
    the write keeps that failure loud and local, rather than surfacing days later
    as a key deleted at the provider.

    Raised by ``KeyEncryptionKey.save()`` via
    :func:`log_and_raise_key_identity_error`, so ``str(exc)`` is the generic
    translated message and the operator detail — which fields were reassigned,
    and from what — is logged once under ``error_code=key_identity_immutable``
    and attached to :attr:`detail`. This is a programming error, not an
    operational one: normal use never reassigns these fields (rotation repoints
    the *DEK* row instead, which is why ``DataEncryptionKey`` carries no such
    guard). Correct the caller — create a row for the other key, or update the
    fields that are meant to change.

    Enforced at the ORM layer only. ``QuerySet.update()`` and ``bulk_update()``
    do not call ``save()`` and are not covered; neither is direct SQL. The guard
    is a rail against ordinary code and admin paths, not a security boundary —
    anything with database write access can already reach further.
    """

    code = "key_identity_immutable"


class KmsProviderMismatchError(EncryptionError):
    """
    A stored DEK's key encryption key is on a KMS this configuration does not have.

    Every :class:`~encryption_suite.models.KeyEncryptionKey` row records the
    ``key_store`` — a ``KMS_KEY_STORES`` block, or ``"system"`` — whose KMS holds
    it, and every unwrap routes through that name. When no block carries the
    name there is no adapter to unwrap with, so the engine fails fast with this
    typed error before any KMS call, rather than handing the resource name to
    some other KMS, where it would surface as a confusing provider-specific
    "not found"/permission error.

    The usual cause is a ``DATABASE_URL`` pointing at a database from a
    different deployment, or a ``KMS_KEY_STORES`` block renamed or removed while
    rows still use it. Subclasses :class:`EncryptionError`, so a single
    ``except EncryptionError`` catches it. The detail (the stored KMS name and
    KEK resource name) goes to the log; the message is generic and translatable.
    The ``code`` slug predates per-row routing and is kept, as every slug is.
    """

    code = "kms_provider_mismatch"


class CryptoBackendMismatchError(EncryptionError):
    """
    A stored DEK names a crypto backend this installation cannot build.

    Every ``DataEncryptionKey`` row records the ``crypto_backend`` that
    generated its DEK (e.g. ``"tink"`` or ``"cryptography"``), and the engine
    loads the key through that backend, whatever ``CRYPTO_BACKEND`` says. When
    no backend this installation can build has the recorded id, the serialized
    DEK cannot be parsed, so the engine fails fast with this typed error before
    any KMS call — the same failure mode as an unconfigured KMS name, one layer
    up (data plane rather than KMS).

    The usual cause is a ``DATABASE_URL`` pointing at a database written by a
    deployment using a custom backend, or a backend whose optional dependency is
    not installed. The detail (the stored backend id) goes to the log; the
    message is generic and translatable.
    """

    code = "crypto_backend_mismatch"


class FieldAlreadyEncryptedError(EncryptionError):
    """
    ``encrypt()`` was handed a field value that already carries the ciphertext prefix.

    The engine's contract is that it receives plaintext, so a prefixed input is
    a caller mistake: encrypting it again would produce a doubly-wrapped value
    that no read path can unwrap back to the original.

    Field-only, and there is no file counterpart — not by omission. The
    ``~^Dv1:`` prefix is a field-value storage marker, prepended by ``encrypt`` and
    stripped by ``decrypt``; ``encrypt_file`` writes raw streaming-AEAD
    ciphertext carrying no marker at all, so the same mistake is undetectable on
    the file path.

    Raised on two paths. ``get_engine().encrypt()`` called directly with a
    prefixed value is one. A model save is the other: ``pre_save`` writes back
    unchanged only ciphertext the package read from the database (or the
    ciphertext it just produced, so a second ``save()`` of the same instance
    passes), and refuses a ciphertext-shaped value a caller assigned — through
    a form, a serializer or code — unless it equals what the row already holds.
    Writing such a value through would let ciphertext copied from another row
    decrypt under this one. The same refusal covers a user typing a value that
    starts with the marker, which an encrypted field cannot store. The
    migration helper skips already-encrypted rows, which is what makes a
    re-run idempotent.

    A programming error or refused input rather than an operational one, but
    typed like every other failure the package raises, so ``except EncryptionError`` and the DRF
    handler catch it instead of letting a bare ``ValueError`` escape as a 500.
    The user message is the shared write-side one — which operation a developer
    misused is not something a user can act on.
    """

    code = "field_already_encrypted"


class EncryptedFieldEncryptionError(EncryptionError):
    """
    Producing ciphertext for an encrypted field failed at the crypto layer.

    The write-side counterpart to :class:`EncryptedFieldDecryptionError`, and
    the field analogue of :class:`EncryptedFileEncryptionError`. Raised when the
    local AEAD operation that turns a field's plaintext into ciphertext fails
    after the data encryption key has already been acquired — so it is **not** a
    KMS/key problem (those surface as :class:`KekNotProvisionedError` /
    :class:`KekUnavailableError`) but a failure of the encryption operation
    itself. The original error is chained as ``__cause__`` and logged; the
    message is generic and translatable.

    This case is rare (local AES-GCM rarely fails for valid input); the type
    exists so that no raw library error escapes the encrypt path — a single
    ``except EncryptionError`` around a save still catches it.
    """

    code = "field_encryption_failed"


class EncryptedFieldDecryptionError(EncryptionError):
    """
    Authentication or decryption of an encrypted field failed.

    Raised by ``EncryptionEngine.decrypt`` when the crypto backend rejects
    ciphertext — wrong silo context, AAD mismatch (a column the field's
    ``aad=`` binds was changed since the value was written),
    a missing ciphertext prefix, or content tampering. The original backend
    error is chained as ``__cause__``. See
    :class:`EncryptedFileDecryptionError` for the streaming counterpart.

    Also raised by the lazy field-read path when the decrypted value cannot
    be *materialized* — building the row's AAD, or parsing the decrypted
    plaintext back into a typed field value (integer/date/…) — so that a
    lenient read degrades to the fallback instead of raising a raw error.
    """

    code = "field_decryption_failed"


class KekUnavailableError(EncryptionError):
    """
    A key encryption key (KEK) could not be used for operational reasons.

    Raised when wrapping or unwrapping a data encryption key (DEK) through the
    configured KMS adapter fails for a reason other than a clearly-missing KEK
    — for example an authentication/permission failure (an expired token, a
    revoked role), a network/timeout error, or any provider-side error. The
    original provider error (HTTP error, SDK exception, …) is chained as
    ``__cause__``, and the underlying error text is written to the
    ``encryption_suite`` logger for diagnosis.

    Named for the KEK because the KEK is what failed: the DEK is only the
    object of the call. A DEK's own states raise errors of their own
    (:class:`MissingDekError`, :class:`DekDeletionScheduledError`,
    :class:`DekDeletedError`), and none of them reach a KMS.

    This is the residual case, so its causes do not share one shape: a timeout
    or a provider outage clears on its own, while a revoked role or a deleted
    credential never will. The funnel cannot tell them apart — that is what
    makes this the leftover bucket — so nothing downstream may treat it as
    reliably temporary.

    This is provider-agnostic: it covers Vault, AWS, GCP, Azure, and every
    other KMS adapter equally. It is distinct from
    :class:`KekNotProvisionedError` (the KEK does not exist yet and must be
    created) so an access problem is not mistaken for missing setup.
    Like every package runtime error it subclasses :class:`EncryptionError`,
    so a single ``except EncryptionError`` handler catches it alongside the
    rest. The message is generic and translatable; surface it to end users
    without leaking the underlying infrastructure detail (which stays in logs).
    """

    code = "kek_unavailable"


class DekDeletionScheduledError(EncryptionError):
    """
    The silo's DEK is inside its app-enforced soft-delete window.

    Raised by the engine on both read and write when a
    :class:`~encryption_suite.models.DataEncryptionKey` row has status
    ``deletion_scheduled``: a deletion (or an operator) has scheduled the key for
    deletion, but the window has not yet expired, so the wrapped DEK is
    deliberately blocked while still fully recoverable. The block is a pure
    database-state check — no KMS call is made and no ciphertext is touched — so
    it is distinct from the operational :class:`KekUnavailableError` (a KMS
    failure) and from :class:`MissingDekError` (no row at all).

    Restoring the row (within the window) clears this immediately. On a lenient
    field read it degrades to the fallback like any other
    :class:`EncryptionError`; on a write the consuming view surfaces the generic
    translated message. The operator detail (the silo, the scheduled date) is
    logged once under ``error_code=dek_deletion_scheduled``, never shown to the
    user.
    """

    code = "dek_deletion_scheduled"


class DekDeletedError(EncryptionError):
    """
    The silo's DEK has been purged — its wrapped material is gone.

    Raised by the engine on **read** when a
    :class:`~encryption_suite.models.DataEncryptionKey` row has status
    ``deleted``: the soft-delete window expired and the purge cleared
    ``encrypted_keyset`` (the crypto-shred), leaving the row as a tombstone. No
    decryption is possible — the only durable copy of the wrapped DEK no longer
    exists — so the engine fails fast with this typed error rather than handing
    empty bytes to the KMS unwrap.

    On the **write** path a tombstone is not an error but a revival signal: if
    the silo UID is reused and ``KEY_AUTO_PROVISION`` is enabled, the engine
    writes a fresh wrapped DEK into the tombstone row and flips it back to
    ``active`` (a new ``created`` event), so a reused UID transparently gets a new
    key. Like the rest, it subclasses :class:`EncryptionError` (lenient reads
    degrade to the fallback); the operator detail is logged once with the
    ``error_code=dek_deleted``.
    """

    code = "dek_deleted"


class DekReencryptionInProgressError(EncryptionError):
    """
    The silo's data is being moved onto new key material for this purpose.

    Raised by the engine on read and write while a
    :class:`~encryption_suite.models.DataEncryptionKey` row is ``reencrypting``:
    a rotation has fenced it, so the silo's rows are split between two keysets
    and neither alone reads them. A pure database-state check, like the deletion
    branches beside it.

    The first failure the package raises that clears without anyone changing
    configuration — the swap or a finished rollback lowers the fence — so
    retrying is decided from this type and its code, never from the fallback a
    lenient read shows. It is not negative-cached for the same reason: a fence
    that lifts at the swap must not be remembered past it. The message makes no
    promise about when: a run that ends with rows outstanding leaves the fence up
    until an operator acts.
    """

    code = "dek_reencryption_in_progress"


class EncryptedFileEncryptionError(EncryptionError):
    """
    Producing ciphertext for an encrypted file failed at the crypto layer.

    The streaming counterpart of :class:`EncryptedFieldEncryptionError` and the
    write-side counterpart of :class:`EncryptedFileDecryptionError`. Raised when
    the local Streaming AEAD operation that turns a file's plaintext into
    ciphertext fails after the data encryption key has already been acquired —
    so it is **not** a KMS/key problem (those surface as
    :class:`KekNotProvisionedError` / :class:`KekUnavailableError`) and **not** a
    storage/backend problem (that is :class:`EncryptedFileStorageError`), but a
    failure of the encryption operation itself. The original error is chained as
    ``__cause__`` and logged; the message is generic and translatable.

    Like the field variant this is rare for valid input; the type exists so the
    file encrypt path mirrors the field path and no raw library error escapes —
    a single ``except EncryptionError`` around a save still catches it.
    """

    code = "file_encryption_failed"


class EncryptedFileStorageError(EncryptionError):
    """
    The underlying storage backend failed an encrypted-file operation.

    Raised by ``SiloEncryptedStorageMixin`` when the composed storage
    backend (S3, GCS, Azure, local disk, …) errors during an existence check,
    write, or open — for example an S3 ``403`` on ``HeadObject``/``PutObject``
    from a miss-scoped access key, a missing bucket/container, or a network
    failure. The original backend error (e.g. ``botocore`` ``ClientError``) is
    chained as ``__cause__``.

    This is a *storage*, not a *cryptographic*, failure — it is deliberately
    distinct from :class:`EncryptedFileDecryptionError` so callers do not
    mistake an infrastructure/permissions problem for ciphertext corruption.
    The message embeds the storage location (container, backend, key) for
    operators and is intended for logs and developers; surface a friendly,
    translated message to end users rather than this string, which may
    contain infrastructure identifiers.
    """

    code = "file_storage_error"


class EncryptedFileDecryptionError(EncryptionError):
    """
    Authentication or decryption of an encrypted file failed.

    The read-side counterpart of :class:`EncryptedFileEncryptionError` and the
    streaming analogue of :class:`EncryptedFieldDecryptionError`. Raised by the
    streaming-decrypt path (``_DecryptingFile.read``) when the crypto backend
    rejects ciphertext for any reason — wrong silo context, AAD mismatch
    (a column the file field's ``aad=`` binds was changed since the file was
    written, or the storage path was swapped onto a different row), stream-header
    corruption, or content tampering.

    :func:`~encryption_suite.file_view_helpers.serve_encrypted_file` performs an
    eager probe before returning its HTTP response, so consumers can catch
    this exception in the view layer and surface a friendly error
    (redirect with a flash message, inline 4xx response, etc.) rather than
    failing mid-stream with the response already started.
    """

    code = "file_decryption_failed"


class _LookupFailure(ValidationError):
    """What a failed blind-index lookup adds to the error it carries: being a ``ValidationError``.

    A lookup runs wherever a query does, and that is often inside a form's
    ``clean()`` the project did not write — allauth's login and sign-up forms,
    Django's auth backend called from one. Django's form machinery catches a
    ``ValidationError`` from anywhere under ``clean()`` and shows it on the form,
    so the reader sees the generic message on the page rather than a 500.

    The same holds after a query: a lenient read hands back an
    ``UndecryptableValue``, and code calling a string method on it raises this
    too (allauth compares ``user.email.lower()`` once the lookup has matched).

    Mixed into a subclass of the original error's own class, so nothing else
    changes: ``isinstance`` against that class, ``exc.code``, ``exc.detail``, the
    status the DRF handler maps it to. Outside a form it escapes exactly as the
    original would have.
    """

    #: Marks the generated classes, which repeat their parent's ``code`` on purpose.
    _lookup_variant = True

    def __str__(self) -> str:
        # ValidationError prints its message list (``['…']``); the package's
        # contract is that ``str(exc)`` is the user message itself.
        return str(self.message)


_lookup_variants: dict[type, type] = {}


def as_lookup_error(exc: EncryptionError) -> EncryptionError:
    """Return *exc* as the same error that is also a ``ValidationError``. See :class:`_LookupFailure`.

    Copies the instance rather than constructing one, so a subclass with its own
    ``__init__`` signature needs nothing special. Raise it ``from`` the original.
    """
    cls = type(exc)
    variant = _lookup_variants.get(cls)
    if variant is None:
        variant = _lookup_variants.setdefault(cls, type(cls.__name__, (cls, _LookupFailure), {"__module__": __name__}))
    copy = BaseException.__new__(variant)
    copy.__dict__.update(exc.__dict__)
    message = exc.args[0] if exc.args else GENERIC_ENCRYPT_DECRYPT_UNAVAILABLE_MESSAGE
    ValidationError.__init__(copy, message, code=exc.code)
    copy.args = exc.args
    return copy


def log_and_raise_configuration_error(
    logger: logging.Logger,
    message: str,
    *,
    cause: BaseException | None = None,
) -> NoReturn:
    """Log *message* at ERROR on *logger*, then raise EncryptionConfigurationError.

    Construction-time / config-validation counterpart to the engine's
    ``_raise_key_management_error`` funnel. Both enforce the same invariant —
    only a typed :class:`EncryptionError` escapes, the operator detail is logged
    exactly once, and the message that reaches an end user is a generic,
    translated, user-safe one (never internal config detail).

    *message* is the operator detail (English; may name options, credentials, or
    strategies). It is logged and attached to the raised exception's ``detail``
    attribute for operator-facing surfaces (the startup system check, logs). The
    raised exception's ``str()`` is :data:`GENERIC_ENCRYPT_DECRYPT_UNAVAILABLE_MESSAGE`,
    so a consuming view that shows ``str(exc)`` does not leak the detail.

    Use this at any site that runs *outside* the engine's runtime funnel —
    notably adapter / provisioner / strategy ``__init__`` (and anything they call),
    which construct in the registry singletons where no funnel wraps the call.
    Pass *cause* to chain an underlying error (e.g. a missing-dependency
    ``ImportError``) onto the traceback.
    """
    # stacklevel=2 attributes the record's filename/lineno/funcName to the
    # caller's frame (the adapter/provisioner site) rather than this helper, so
    # %(filename)s reads e.g. provisioners_oci.py — matching how the engine
    # funnel's inline logging naturally points at engine.py.
    logger.error(
        'The project\'s encryption configuration is not usable. error_code=%s detail="%s"',
        EncryptionConfigurationError.code,
        message,
        stacklevel=2,
    )
    raise EncryptionConfigurationError(GENERIC_ENCRYPT_DECRYPT_UNAVAILABLE_MESSAGE, detail=message) from cause


def log_and_raise_delete_error(
    logger: logging.Logger,
    message: str,
    *,
    cause: BaseException | None = None,
) -> NoReturn:
    """Log *message* at ERROR on *logger*, then raise :class:`KekDeleteError`.

    KEK-deletion counterpart to :func:`log_and_raise_configuration_error`, for
    the delete path that runs outside the engine's runtime funnel (the
    admin purge action and provisioner ``delete_kek``). Same invariant: a
    typed :class:`EncryptionError` escapes, the operator detail (KEK resource
    name, provider error, or refusal reason) is logged once with the
    ``error_code=kek_delete_failed`` and attached to :attr:`KekDeleteError.detail`, and
    ``str(exc)`` is the generic translated message — so no resource name or
    provider detail reaches a user-facing surface.

    Pass *cause* to chain the underlying provider error onto the traceback.
    """
    logger.error(
        'Scheduling deletion of a provisioned KEK failed. error_code=%s detail="%s"',
        KekDeleteError.code,
        message,
        stacklevel=2,
    )
    raise KekDeleteError(GENERIC_ENCRYPT_DECRYPT_UNAVAILABLE_MESSAGE, detail=message) from cause


def log_and_raise_enumeration_error(
    logger: logging.Logger,
    message: str,
    *,
    cause: BaseException | None = None,
) -> NoReturn:
    """Log *message* at ERROR on *logger*, then raise :class:`SiloEnumerationError`.

    Silo-enumeration counterpart to :func:`log_and_raise_delete_error`, for the
    enumeration path (``iter_silos`` / ``queryset_for_model_label``) that runs
    outside the engine's runtime funnel (keyset setup and KMS reconcile, not an
    encrypt/decrypt request). Same invariant: a typed :class:`EncryptionError`
    escapes, the operator detail (the adapter, the missing dependency, the bad
    model path) is logged once under ``error_code=silo_enumeration_unavailable``
    and attached to :attr:`SiloEnumerationError.detail`, and ``str(exc)`` is the
    generic translated message — so the admin/reconcile surface never renders a
    raw traceback or internal detail.

    Pass *cause* to chain the underlying error (e.g. a missing-dependency
    ``ImportError``) onto the traceback.
    """
    logger.error(
        'The silo adapter cannot list every live silo. error_code=%s detail="%s"',
        SiloEnumerationError.code,
        message,
        stacklevel=2,
    )
    raise SiloEnumerationError(GENERIC_ENCRYPT_DECRYPT_UNAVAILABLE_MESSAGE, detail=message) from cause


def log_and_raise_kek_enumeration_error(
    logger: logging.Logger,
    message: str,
    *,
    cause: BaseException | None = None,
) -> NoReturn:
    """Log *message* at ERROR on *logger*, then raise :class:`KekEnumerationError`.

    KEK-reconcile counterpart to :func:`log_and_raise_delete_error`, for the KMS
    enumeration path (``provisioner.list_kek_names``) that runs outside the
    engine's runtime funnel. Same invariant: a typed :class:`EncryptionError`
    escapes, the operator detail (the provider error, or the refusal reason) is
    logged once under ``error_code=kek_enumeration_unavailable`` and attached to
    :attr:`KekEnumerationError.detail`, and ``str(exc)`` is the generic
    translated message — so the admin/reconcile surface never shows a raw
    traceback or provider detail.

    Pass *cause* to chain the underlying provider error onto the traceback.
    """
    logger.error(
        'The KEK provisioner cannot list this deployment\'s KEKs. error_code=%s detail="%s"',
        KekEnumerationError.code,
        message,
        stacklevel=2,
    )
    raise KekEnumerationError(GENERIC_ENCRYPT_DECRYPT_UNAVAILABLE_MESSAGE, detail=message) from cause


def log_and_raise_key_identity_error(
    logger: logging.Logger,
    message: str,
) -> NoReturn:
    """Log *message* at ERROR on *logger*, then raise :class:`KeyIdentityImmutableError`.

    Raised from ``KeyEncryptionKey.save()``, which runs outside the engine's
    runtime funnel — a row can be saved from a request, a management command, a
    signal receiver, or reconcile. Same invariant as the other helpers: a typed
    :class:`EncryptionError` escapes so an ``except EncryptionError`` catches it,
    the operator detail (which fields were reassigned, and from what) is logged
    once under ``error_code=key_identity_immutable`` and attached to
    :attr:`KeyIdentityImmutableError.detail`, and ``str(exc)`` is the generic
    translated message — so no internal detail or traceback reaches a user.

    No *cause* parameter: nothing underlies this. The guard fires on the
    package's own precondition, not on a wrapped provider or database error.
    """
    logger.error(
        'Refused to point an existing KEK row at a different KMS key. error_code=%s detail="%s"',
        KeyIdentityImmutableError.code,
        message,
        stacklevel=2,
    )
    raise KeyIdentityImmutableError(GENERIC_ENCRYPT_DECRYPT_UNAVAILABLE_MESSAGE, detail=message)


def log_and_raise_deletion_record_error(
    logger: logging.Logger,
    message: str,
    *,
    cause: BaseException | None = None,
) -> NoReturn:
    """Log *message* at ERROR on *logger*, then raise :class:`KekDeletionRecordError`.

    Deletion-recording counterpart to :func:`log_and_raise_delete_error`, for the
    schedule-deletion path (``schedule_deletion``, invoked from the silo
    ``post_delete`` connector) that runs outside the engine's runtime funnel.
    Same invariant: a typed :class:`EncryptionError` escapes, the operator detail
    (the silo UID, the database or strategy error) is logged once with the
    ``error_code=kek_deletion_record_failed`` and attached to
    :attr:`KekDeletionRecordError.detail`, and ``str(exc)`` is the generic
    translated message — so no raw error or traceback reaches a log or surface.

    Pass *cause* to chain the underlying error onto the traceback.
    """
    logger.error(
        "Failed to record key deletion for an already deleted silo; the keys stay unscheduled. "
        'error_code=%s detail="%s"',
        KekDeletionRecordError.code,
        message,
        stacklevel=2,
    )
    raise KekDeletionRecordError(GENERIC_ENCRYPT_DECRYPT_UNAVAILABLE_MESSAGE, detail=message) from cause
