"""
Core encryption engine.

The actual symmetric crypto is delegated to a pluggable crypto backend
(see :mod:`encryption_suite.adapters.crypto_backends`); this module owns DEK
provisioning, KMS wrap/unwrap, caching, and silo resolution.

Handles:
  - DEK lifecycle (generation via the crypto backend, KMS encryption/decryption)
  - In-process primitive cache with TTL and per-silo locking
  - High-level encrypt / decrypt for field use (AEAD)
  - Streaming encrypt / decrypt for file use (Streaming AEAD)
  - Lazy DEK provisioning and translation of KEK-not-found errors into
    :class:`~encryption_suite.exceptions.KekNotProvisionedError`
"""

from __future__ import annotations

import contextlib
import re
import threading
import time
from base64 import b64decode, b64encode

from django.db import transaction
from django.db.models import F
from django.utils import timezone

from . import lifecycle, user_context
from ._internal import (
    DECRYPT_FAILURE_HINT,
    _NonClosingWriter,
    describe_decryption_scope,
    operator_error_text,
    optional_log_field,
)
from ._logging import get_logger
from .adapters.crypto_backends.base import FieldPrimitive, FilePrimitive
from .conf import DEFAULT_KEY_SET, SYSTEM_KEY_SET, SYSTEM_SILO_UID, enc_settings
from .dek_cache import MISS, DekCacheKey, clear_dek_caches, dek_cache
from .exceptions import (
    GENERIC_DECRYPT_FAILED_USER_MESSAGE,
    GENERIC_ENCRYPT_DECRYPT_UNAVAILABLE_MESSAGE,
    GENERIC_ENCRYPT_FAILED_USER_MESSAGE,
    CryptoBackendMismatchError,
    DekDeletedError,
    DekDeletionScheduledError,
    DekReencryptionInProgressError,
    EncryptedFieldDecryptionError,
    EncryptedFieldEncryptionError,
    EncryptedFileEncryptionError,
    EncryptionConfigurationError,
    EncryptionError,
    FieldAlreadyEncryptedError,
    KekNotProvisionedError,
    KekPendingDeletionError,
    KekUnavailableError,
    KmsProviderMismatchError,
    MissingDekError,
)
from .silo_ref import SYSTEM_SILO_REF, AmbientSilo, SiloRef, silo_filter

logger = get_logger(__name__)


#: The system silo: what a ``key_set="system"`` column passes to the engine as its
#: silo. A :class:`SiloRef` like any other, bound to the system adapter, so it is
#: readable with no silo in the context.
SYSTEM_SILO = SYSTEM_SILO_REF

# Maximum number of characters of a provider error body kept in a log line.
# SDK errors can stringify to a full HTTP response (tens of lines of HTML/JSON);
# the status and reason carry the actionable signal, so the body is capped.
_MAX_PROVIDER_ERROR_DETAIL = 200


def _summarize_provider_error(exc: BaseException, max_detail: int = _MAX_PROVIDER_ERROR_DETAIL) -> str:
    """Return a compact, single-line summary of a provider exception for logs.

    Used only on the KEK-not-found path (:meth:`_translate_kek_error`), where a
    missing-key 404 from a ``requests``-backed SDK (Azure, IBM, Infisical),
    botocore, or urllib can stringify to a full HTTP response body —
    tens of lines of HTML or JSON — that adds no diagnostic value beyond the
    status and reason. When the exception exposes an HTTP response, this logs
    the status and reason plus only the first ``max_detail`` characters of the
    body; otherwise it falls back to a length-capped ``str(exc)``. Provider-
    agnostic: it duck-types the response attributes common across SDKs rather
    than importing any provider library.

    Other log sites (the wrap/unwrap operational funnel in
    :meth:`_raise_key_management_error` and the provisioner failure in
    :meth:`_ensure_kek`) intentionally log the full provider error, because a
    detailed message there is usually the actionable signal, not noise.
    """
    status = None
    reason = None
    body = None

    # HTTP-response-bearing errors expose ``status_code`` / ``reason`` / a body.
    # ``.text`` is a plain string on ``requests`` responses but a *method* on
    # Azure's ``HttpResponse``; coerce to a string either way and ignore
    # anything that is neither, so a body attribute never escapes as a non-str.
    response = getattr(exc, "response", None)
    if response is not None:
        status = getattr(response, "status_code", None)
        reason = getattr(response, "reason", None)
        body = getattr(response, "text", None)
        if callable(body):
            try:
                body = body()
            except Exception:
                body = None
        if not isinstance(body, str):
            body = None

    # urllib.error.HTTPError: ``code`` + ``reason``; the body has already been
    # folded into the message by urlopen_with_detail, so ``str(exc)`` carries it.
    if status is None and hasattr(exc, "code") and hasattr(exc, "reason"):
        status = getattr(exc, "code", None)
        reason = getattr(exc, "reason", None)

    raw = body if body else str(exc)
    detail = " ".join(str(raw).split())
    if len(detail) > max_detail:
        detail = detail[:max_detail] + " …(truncated)"

    if status is not None:
        head = f"HTTP {status} {reason}".rstrip() if reason else f"HTTP {status}"
        return f"{head}: {detail}" if detail else head
    return detail


# Prefix prepended to every ciphertext string produced by encrypt().
# This is a storage format marker, not a configurable setting — changing it
# would make all existing encrypted values in the database unreadable.
# The '~^' characters were chosen because they cannot appear in base64 output
# (which uses only A-Za-z0-9+/=), making accidental prefix collisions with
# plaintext values effectively impossible.  The letter after them, ``D``, says
# the value is under a data key; the form and version of the framing follow it,
# in the segment below.
#: Marks a stored value encrypted under a data key — a silo's or the system
#: silo's alike. Which key a value is under is the column's ``key`` option, not
#: the marker: a value read under the other kind's key fails authentication.
PREFIX = "~^D"

#: The form and version after the ``D``. ``v`` is a value and nothing
#: else, which is every form there is: a blind index digest is stored in a column
#: or a table row of its own, never inside the value. The version is of the
#: framing, not of the key.
_VALUE_FORM = "v1:"

#: What every stored value starts with today. One constant, so a prefix test is a
#: comparison rather than an assembly.
_CIPHERTEXT_PREFIX = PREFIX + _VALUE_FORM

#: The shape every stored value starts with, in any version of the framing: the
#: marker, the value form, a version number and a colon. Matching the version
#: as a number rather than as ``1`` keeps every later version recognized as
#: ciphertext, so a newer value is never mistaken for plaintext and encrypted
#: again. A string that starts with the marker but not this shape is plaintext.
_STORED_VALUE_RE = re.compile(re.escape(PREFIX) + r"v[0-9]+:")


def is_silo_value(value) -> bool:
    """Whether *value* has the shape of a stored value this engine writes, in any framing version."""
    return isinstance(value, str) and _STORED_VALUE_RE.match(value) is not None


class StoredCiphertext(str):
    """A stored value the package read from the database, as opposed to one a caller supplied."""

    __slots__ = ()


def stamp(value):
    """Mark a stored value read from the database; return anything else unchanged."""
    if is_silo_value(value) and not isinstance(value, StoredCiphertext):
        return StoredCiphertext(value)
    return value


def is_stamped(value) -> bool:
    """Whether *value* was read from the database by the package."""
    return isinstance(value, StoredCiphertext)


def wrap_ciphertext(raw: bytes) -> str:
    """Return the stored form of raw ciphertext bytes."""
    return _CIPHERTEXT_PREFIX + b64encode(raw).decode("ascii")


def unwrap_ciphertext(stored: str) -> bytes:
    """Return the raw ciphertext bytes of a stored value.

    Raises ``ValueError`` on anything this engine did not write — every caller
    already treats a bad value as a failed read.
    """
    if not stored.startswith(_CIPHERTEXT_PREFIX):
        raise ValueError(f"not a value written by this engine: {stored[:8]!r}")
    return b64decode(stored[len(_CIPHERTEXT_PREFIX) :])


# The in-process cache of loaded primitives is in :mod:`encryption_suite.dek_cache`,
# one instance per key set. Besides the primitives it holds a negative cache: a
# recent *KMS-operation* failure (the KEK could not be reached or used — a
# dead/slow endpoint, expired credentials, a not-yet-provisioned KEK), so that a
# single slow KMS call is not re-paid by every encrypted field on a page. Held for
# DEK_FAILURE_CACHE_TTL, kept far shorter than DEK_CACHE_TTL so a healthy-but-
# briefly-slow backend is retried almost immediately. Only the failure types
# in _NEGATIVE_CACHE_TYPES are cached: a missing DEK row or a configuration
# error is a fast local check whose state can flip as soon as a key is
# provisioned, so re-checking it costs nothing and avoids serving stale errors.
#
# Failure types worth negative-caching: those produced by an attempted (and
# potentially slow) KEK operation. MissingDekError (DB miss) and
# EncryptionConfigurationError (local config check) are deliberately excluded.
_NEGATIVE_CACHE_TYPES = (KekUnavailableError, KekNotProvisionedError)
# Standing operator guidance for the code-carrying error lines. Held apart from
# the log calls because it is prose about what to do next, not a value read off
# the failure — the `hint` field is the same sentence on every occurrence.
_KEK_NOT_FOUND_HINT = (
    "Likely a wrong KMS endpoint, credentials, or auth: the call failed before it reached the key, "
    "and a 404/not-found often means this — check the underlying error in detail first. Otherwise "
    "the key is genuinely absent, so provision it outside this application or set the KMS block's "
    "KEK_PROVISIONER_ADAPTER."
)
_KMS_NOT_CONFIGURED_HINT = (
    "Every unwrap routes through the KMS named on the key encryption key row, and no "
    "ENCRYPTION['KMS_KEY_STORES'] block carries that name. Usually a block was renamed or removed "
    "while rows still use it, or DATABASE_URL points at a database from a different deployment. "
    "Restore the block under its original name, or point at the correct database."
)
_BACKEND_FORMAT_HINT = (
    "The row's crypto_backend column does not match the keyset it holds, which only a direct write to "
    "the column produces. Restore the column to the backend that made the key."
)
_BACKEND_UNAVAILABLE_HINT = (
    "Every data key is loaded through the crypto backend its row records, and no backend this "
    "installation can build has that id. Usually DATABASE_URL points at a database written by a "
    "deployment using a custom backend, or the backend's optional dependency is not installed. "
    "Install the backend, or point at the correct database."
)
_NO_SILO_HINT = (
    "No silo found in the current context. "
    "Set what the key set's silo adapter reads, such as the acting team, tenant or user, "
    "before accessing encrypted fields; outside a request, as in a shell or a task, code must set it itself. "
    "Check your ENCRYPTION['KEY_SETS'] configuration."
)
_MISSING_DEK_HINT = "Has setup_encryption_keys been run?"
_FIELD_ALREADY_ENCRYPTED_HINT = (
    "The engine takes plaintext. Encrypting ciphertext again would produce a value no read "
    "path can unwrap. Reached by calling get_engine().encrypt() directly; the model "
    "field refuses a caller's ciphertext-shaped value before it reaches the engine, and the "
    "migration helper passes an already-encrypted value through untouched."
)
# What the failure *is*, one per purpose. Lifted out of the log format strings
# below so the raise sites can attach the same sentence to the exception's
# `detail` without restating it.
_MISSING_FIELD_DEK_DETAIL = "No field data encryption key found for this silo."
_MISSING_FILE_DEK_DETAIL = "No file data encryption key found for this silo."
_MISSING_INDEX_DEK_DETAIL = "No blind index key found for this silo."
# The same arrangement for the sites whose sentence reaches both channels: the
# log line leads with it, and the raise attaches it to `detail` for the operator
# surfaces that render `detail` alone, with no log line beside it.
_DEK_SCHEDULED_DETAIL = "The DEK is scheduled for deletion; refusing to use it."
_DEK_SCHEDULED_HINT = "Restore the key to resume, or let the window expire."
_DEK_DELETED_DETAIL = "The DEK was deleted; its wrapped material is gone and the value cannot be decrypted."
# What a data key's creation line says, chosen by the reason its ledger row
# records, so the sentence names the act that caused the key.
_DEK_CREATED_SENTENCE = "A data key was created for this silo."
_DEK_CREATED_SENTENCES = {
    lifecycle.REASON_SILO_CREATED: "A data key was created for a newly created silo.",
    lifecycle.REASON_FIRST_ENCRYPTION: "A data key was created on the silo's first encryption.",
}
_DEK_REENCRYPTING_DETAIL = "The DEK is being rotated; its silo's data is fenced until every row is on one keyset."
_DEK_REENCRYPTING_HINT = (
    "Clears when reencrypt_data swaps or finishes a rollback. If no run is in progress, rerun "
    "reencrypt_data for this silo, or pass --abort."
)
# Shared with safe_queries, which repeats this check on the path that never
# reaches the engine.
_MISSING_PREFIX_DETAIL = "The stored value is missing the ciphertext prefix; it may be plaintext or corrupted."
# Operator log lines for a missing DEK, single-sourced so the field/file
# variants can't drift across the terminal sites that emit them. The DB-lookup
# site raises MissingDekError without logging; only the terminal callers (read,
# or encrypt with auto-provision off) log, exactly once.
_MISSING_FIELD_DEK_LOG = (
    f'{_MISSING_FIELD_DEK_DETAIL} error_code={MissingDekError.code} purpose=field silo="%s" hint="{_MISSING_DEK_HINT}"'
)
_MISSING_FILE_DEK_LOG = (
    f'{_MISSING_FILE_DEK_DETAIL} error_code={MissingDekError.code} purpose=file silo="%s" hint="{_MISSING_DEK_HINT}"'
)
_MISSING_INDEX_DEK_LOG = (
    f'{_MISSING_INDEX_DEK_DETAIL} error_code={MissingDekError.code} purpose=index silo="%s" hint="{_MISSING_DEK_HINT}"'
)


def _key_set_log_field(key_set: str) -> str:
    """The `` key_set="..."`` log field for a non-default key set, and nothing for the default."""
    return "" if key_set == DEFAULT_KEY_SET else f' key_set="{key_set}"'


def _field_cache_key(silo_ref: SiloRef) -> DekCacheKey:
    """Cache key for the field AEAD primitive of one key set of a silo."""
    return DekCacheKey(silo_ref.key_set, "field", silo_ref.uid)


def _file_cache_key(silo_ref: SiloRef) -> DekCacheKey:
    """Cache key for the file Streaming AEAD primitive of one key set of a silo."""
    return DekCacheKey(silo_ref.key_set, "file", silo_ref.uid)


def _index_cache_key(silo_ref: SiloRef) -> DekCacheKey:
    """Cache key for the blind index key of one key set of a silo."""
    return DekCacheKey(silo_ref.key_set, "index", silo_ref.uid)


class SiloIndexKey:
    """A silo's blind index key: a keyed hash, not an AEAD.

    Held where the field and file primitives are held, and cached the same way,
    because it is the same kind of thing from the key's point of view — per-silo
    material wrapped by the silo's KEK. What differs is that nothing encrypts
    with it, so there is no primitive for a crypto backend to build: the backends
    expose non-deterministic AEADs, and a digest that changed with
    ``CRYPTO_BACKEND`` would make every indexed row unfindable the moment that
    setting changed. So the material is plain random bytes and the hash runs
    here.

    Wraps the bytes rather than passing them around: a caller gets a thing that
    computes a digest, and the material stays behind one attribute.
    """

    __slots__ = ("_material",)

    def __init__(self, material: bytes) -> None:
        self._material = material

    def digest(self, value: str, *, context: str) -> str:
        from .blind_index import compute_digest

        return compute_digest(self._material, value, context=context)


#: Attribute holding, on a connection, the cache keys whose ``DataEncryptionKey``
#: row was created in that connection's currently open transaction. On the
#: connection rather than in a module-level dict because connections are
#: per-thread and these marks must not be shared between them.
_UNCOMMITTED_ATTR = "_encryption_suite_uncommitted_primitives"


def _mark_uncommitted(cache_key: DekCacheKey) -> None:
    """Record that this key's DEK row is only as durable as the open transaction."""
    connection = transaction.get_connection()
    keys = getattr(connection, _UNCOMMITTED_ATTR, None)
    if keys is None:
        keys = set()
        setattr(connection, _UNCOMMITTED_ATTR, keys)
    keys.add(cache_key)


def _is_uncommitted(cache_key: DekCacheKey) -> bool:
    """Whether *cache_key* names a DEK row this transaction has yet to commit."""
    connection = transaction.get_connection()
    keys = getattr(connection, _UNCOMMITTED_ATTR, None)
    if not keys:
        return False
    if not connection.in_atomic_block:
        # Marks from a transaction that rolled back. Django offers no rollback
        # hook, so they are swept the first time anything looks at them with no
        # transaction open. A mark that survives into a *later* transaction only
        # defers a cache write that would have been safe — never the reverse.
        keys.clear()
        return False
    return cache_key in keys


def _clear_uncommitted(cache_key: DekCacheKey) -> None:
    keys = getattr(transaction.get_connection(), _UNCOMMITTED_ATTR, None)
    if keys:
        keys.discard(cache_key)


def _get_provision_lock(silo_ref: SiloRef) -> threading.Lock:
    """Return the lock serializing the creation of one silo's keys in one key set.

    One of a fixed number per key set, so two silos can share it and wait on each
    other's creation, which is brief and rare.
    """
    return dek_cache(silo_ref.key_set).provision_lock(silo_ref.uid)


@contextlib.contextmanager
def kms_error_guard(operation: str, silo_ref: SiloRef, kms_adapter):
    """Funnel a raw KMS provider error into a typed :class:`EncryptionError`.

    Callers that drive a KMS adapter or KEK provisioner *directly* rather than
    through the engine — the admin test console, the ``reencrypt_keys``
    management command — bypass the engine's own wrap/unwrap funnel, so a
    provider failure (a GCP ``PERMISSION_DENIED``, a urllib ``HTTPError``, a
    boto ``ClientError``, ...) would otherwise escape raw: untranslated, with a
    traceback, and with no error-code slug. Wrapping the call here keeps the
    classification (``KekNotProvisionedError`` vs ``KekUnavailableError``) and
    the concise diagnostic logging identical to the field and file paths.
    *kms_adapter* is the adapter the guarded call drives.
    """
    from .registry import get_engine

    try:
        yield
    except EncryptionError:
        raise
    except Exception as exc:
        kek_id = kms_adapter._resolve_kek_id(silo_ref)
        get_engine()._raise_key_management_error(
            exc, kek_id=kek_id, silo_ref=silo_ref, operation=operation, kms_adapter=kms_adapter
        )


def ensure_kek_provisioned(
    kms_adapter, kek_provisioner, silo_ref: SiloRef, *, user=None, os_login_user: str = "", user_ip=None
) -> tuple[str, bool]:
    """Resolve the KEK id for *silo_ref* and ensure the provisioner created it.

    Returns ``(kek_id, created)``, where *created* says whether **this call**
    made the key. It picks the first-sighting ledger verb, so the record
    distinguishes a key this deployment provisioned from one it found already
    there — a distinction that was previously inferred from whether a
    provisioner happened to be configured, and so was wrong for every key an
    operator created by hand on a deployment that has one.

    The single ensure funnel, shared by :class:`EncryptionEngine` and the admin
    test console. Three behaviors ride on it, and a caller that made the
    provisioner call itself would silently have none of them:

    * a provider-reported pending deletion is **recorded on the key's row**
      before it is lost — the provisioner read that state to raise, and without
      recording it the row keeps claiming ``active`` until someone reproduces
      the failure;
    * the refusal is logged once, with its error-code slug and operator detail;
    * any other provider failure becomes
      :class:`~encryption_suite.exceptions.KekNotProvisionedError` rather than
      escaping raw.

    Returns the resolved KEK identifier so callers can use it in log messages
    without resolving twice. The provisioner is expected to be idempotent — the
    default :class:`~encryption_suite.adapters.keks.NullKekProvisioner` does
    nothing, which preserves provisioning outside this application.
    """
    kek_id = kms_adapter._resolve_kek_id(silo_ref)
    if kek_provisioner is None:
        return kek_id, False
    try:
        created = bool(kek_provisioner.ensure_kek(kek_id, silo_ref=silo_ref))
    except KekPendingDeletionError as exc:
        # The provisioner read the key's state to learn this, so record it
        # before it is lost. Already typed and carrying its own operator text,
        # so it is re-raised as-is rather than wrapped — every
        # ``except KekNotProvisionedError`` still catches it, and its distinct
        # code reaches machine consumers.
        _record_pending_deletion(kms_adapter, kek_id, exc, user=user, os_login_user=os_login_user, user_ip=user_ip)
        logger.error(
            "The KEK is inside the provider's deletion window, so it cannot wrap or unwrap anything. "
            'error_code=%s provisioner="%s" kek="%s" silo="%s" detail="%s"',
            KekPendingDeletionError.code,
            kek_provisioner.describe(),
            kek_id,
            silo_ref,
            exc.detail or operator_error_text(exc),
        )
        raise
    except Exception as exc:
        logger.error(
            "The KEK provisioner could not ensure the KEK exists. "
            'error_code=%s provisioner="%s" kek="%s" silo="%s" detail="%s"',
            KekNotProvisionedError.code,
            kek_provisioner.describe(),
            kek_id,
            silo_ref,
            operator_error_text(exc),
        )
        raise KekNotProvisionedError(
            GENERIC_ENCRYPT_DECRYPT_UNAVAILABLE_MESSAGE,
            detail=(
                f'provisioner="{kek_provisioner.describe()}" kek="{kek_id}" '
                f'silo="{silo_ref}" {operator_error_text(exc)}'
            ),
        ) from exc
    return kek_id, created


def _record_pending_deletion(
    kms_adapter, kek_id: str, exc, *, user=None, os_login_user: str = "", user_ip=None
) -> None:
    """Record that the provider reports *kek_id* inside its deletion window.

    Best-effort: a bookkeeping write must never turn a failed encrypt into a
    different failure. Idempotent — a row already in that state is left alone,
    so repeated attempts do not append an event per request.

    The status is ``deletion_requested`` because that is what it means: the
    provider's own window is running. The reason distinguishes *who* started it —
    this deployment did not, it merely observed the state.

    The identity is the caller's, not this function's: an ordinary request has
    none, while the test console and ``reencrypt_keys`` both reach here from a
    privileged act and pass one. Either way the trigger stays ``indirect`` — the
    caller asked to provision a key, not to record a deletion somebody else
    started.

    *kek_id* arrives in the strategy's identifier space, so it is canonicalized
    first: on an adapter that stores qualified names, recording it verbatim would
    open a second row for the same key that nothing else ever matches.
    """
    from .models import KeyEncryptionKey, KeyLifecycleEvent

    try:
        row, created = KeyEncryptionKey.objects.get_or_create(
            key_store=kms_adapter.kms_name,
            kek_resource_name=kms_adapter.canonical_kek_name(kek_id),
        )
        if created:
            row.record_event(
                lifecycle.EVENT_DISCOVERED,
                trigger=lifecycle.TRIGGER_INDIRECT,
                reason=KeyLifecycleEvent.REASON_OBSERVED_AT_PROVIDER,
                user=user,
                os_login_user=os_login_user,
                user_ip=user_ip,
            )
        if row.status == lifecycle.STATUS_DELETION_REQUESTED:
            return
        row.record_event(
            lifecycle.EVENT_DELETION_REQUESTED,
            trigger=lifecycle.TRIGGER_INDIRECT,
            reason=KeyLifecycleEvent.REASON_OBSERVED_AT_PROVIDER,
            user=user,
            os_login_user=os_login_user,
            user_ip=user_ip,
            kms_deletion_at=getattr(exc, "effective_at", None),
        )
    except Exception as record_exc:
        logger.warning(
            "The provider reported this key as pending deletion, but that status could not be "
            "recorded, so reconcile and the admin will show it as active until a later pass "
            'succeeds. key_store=%s kek="%s" detail="%s" %s',
            kms_adapter.kms_name,
            kek_id,
            operator_error_text(record_exc),
            user_context.identity_tail(user=user, os_login_user=os_login_user, user_ip=user_ip),
        )


class EncryptionEngine:
    """
    Ties together silo resolution, KEK wrapping, and AEAD encryption via
    the configured crypto backend into one cohesive API consumed by the Django fields.

    Async ORM support:
    Currently all methods are synchronous.  As of Django 6.0, the ORM's
    async support is partial — async QuerySet and model methods exist, but
    the field protocol (get_prep_value, from_db_value) has no async
    variants.  Django still uses sync_to_async internally for these calls,
    so blocking KMS calls run in a thread pool and do not block the event
    loop.

    When Django introduces an async field protocol, this class will need
    new async_encrypt and async_decrypt methods (they do not exist yet).
    These should call new async_encrypt_key / async_decrypt_key methods on
    the KMS adapter base class (also do not exist yet — see
    AbstractKmsAdapter).

    The threading.Lock instances used by the cache will also need async
    counterparts (asyncio.Lock).  The two lock types cannot be mixed, so
    the cache layer will need to detect the execution context and use the
    appropriate lock, or maintain separate sync and async code paths.
    """

    def __init__(self, crypto_backend) -> None:
        # Makes every new data key. An existing key is loaded through the backend
        # its row records (see _backend_for_row).
        self.crypto_backend = crypto_backend

    # ------------------------------------------------------------------
    # KMS and backend routing
    # ------------------------------------------------------------------

    @property
    def silo_kms_adapter(self):
        """The adapter new ``scoped`` keys are wrapped through (the kind's default KMS store)."""
        from .registry import get_kms_adapter

        return get_kms_adapter()

    @property
    def silo_kek_provisioner(self):
        """The provisioner of the store new ``scoped`` keys are wrapped through."""
        from .registry import get_kek_provisioner

        return get_kek_provisioner()

    @property
    def silo_adapter(self):
        """The ``default`` key set's silo adapter."""
        return self.silo_adapter_for(DEFAULT_KEY_SET)

    @staticmethod
    def silo_adapter_for(key_set: str):
        """The silo adapter *key_set* is bound to."""
        from .registry import get_silo_adapter

        return get_silo_adapter(key_set)

    def new_key_kms_adapter(self, silo_ref: SiloRef):
        """The adapter a new key for *silo_ref* is wrapped through (see ``new_key_kms``)."""
        from .registry import get_kms_adapter, new_key_kms

        return get_kms_adapter(new_key_kms(silo_ref.key_set))

    def new_key_kek_provisioner(self, silo_ref: SiloRef):
        """The provisioner of the store a new key for *silo_ref* is wrapped through."""
        from .registry import get_kek_provisioner, new_key_kms

        return get_kek_provisioner(new_key_kms(silo_ref.key_set))

    def kms_adapter_for_kek(self, kek, silo_ref: SiloRef):
        """Return the adapter that unwraps under *kek*: the one its row names.

        Raises :class:`KmsProviderMismatchError` when the row names a KMS this
        configuration does not have.
        """
        from .conf import kms_block
        from .registry import get_kms_adapter

        name = kek.key_store
        if kms_block(name) is None:
            logger.error(
                "The key encryption key row names a KMS this configuration does not have. "
                'error_code=%s silo="%s" stored_key_store="%s" stored_kek="%s" hint="%s"',
                KmsProviderMismatchError.code,
                silo_ref,
                name,
                kek.kek_resource_name,
                _KMS_NOT_CONFIGURED_HINT,
            )
            raise KmsProviderMismatchError(
                GENERIC_ENCRYPT_DECRYPT_UNAVAILABLE_MESSAGE,
                detail=(
                    f'silo="{silo_ref}" stored_key_store="{name}" stored_kek="{kek.kek_resource_name}" '
                    f"{_KMS_NOT_CONFIGURED_HINT}"
                ),
            )
        return get_kms_adapter(name)

    def _backend_for_row(self, backend_id: str, silo_ref: SiloRef):
        """Return the crypto backend that loads a key recorded as *backend_id*.

        An empty id — a row with no recorded backend — is loaded by the
        configured one. Raises :class:`CryptoBackendMismatchError` when no
        backend this installation can build has the id.
        """
        from .registry import get_crypto_backend_by_id

        if not backend_id:
            return self.crypto_backend
        backend = get_crypto_backend_by_id(backend_id)
        if backend is not None:
            return backend
        logger.error(
            "The stored DEK names a crypto backend this installation cannot build. "
            'error_code=%s silo="%s" stored_backend="%s" hint="%s"',
            CryptoBackendMismatchError.code,
            silo_ref,
            backend_id,
            _BACKEND_UNAVAILABLE_HINT,
        )
        raise CryptoBackendMismatchError(
            GENERIC_ENCRYPT_DECRYPT_UNAVAILABLE_MESSAGE,
            detail=f'silo="{silo_ref}" stored_backend="{backend_id}" {_BACKEND_UNAVAILABLE_HINT}',
        )

    # ------------------------------------------------------------------
    # Keyset lifecycle
    # ------------------------------------------------------------------

    def _ensure_kek(self, silo_ref: SiloRef, *, user=None, os_login_user: str = "", user_ip=None) -> tuple[str, bool]:
        """Resolve the KEK id for *silo_ref* and make sure the provisioner made it.

        Thin delegate to :func:`ensure_kek_provisioned`, which is shared with the
        admin test console so both paths funnel failures identically. Returns
        ``(kek_id, created)``. Always on the KMS new keys for *silo_ref* are made on.
        """
        return ensure_kek_provisioned(
            self.new_key_kms_adapter(silo_ref),
            self.new_key_kek_provisioner(silo_ref),
            silo_ref,
            user=user,
            os_login_user=os_login_user,
            user_ip=user_ip,
        )

    @staticmethod
    def _resource_mismatch_hint(kek_id: str, kms_adapter) -> str:
        """Return a diagnostic sentence if *kek_id* points at another deployment.

        Asks the adapter whether the stored KEK resource name belongs to a
        different account/project/region/key ring than it is configured for
        (see ``AbstractKmsAdapter.kek_resource_mismatch_hint``). A 403/404 unwrap
        failure is often a wrong-database/region mismatch rather than a genuinely
        missing or inaccessible key, and the bare provider error does not say so.
        Empty when the adapter cannot tell or the coordinates match.
        """
        return kms_adapter.kek_resource_mismatch_hint(kek_id) or ""

    @staticmethod
    def _describe_provisioner(kms_adapter) -> str:
        """Describe *kms_adapter*'s provisioner for an error line, never raising.

        Read on an error path, so a provisioner that cannot be built is reported
        rather than allowed to replace the error being logged.
        """
        from .registry import get_kek_provisioner

        try:
            provisioner = get_kek_provisioner(kms_adapter.kms_name or None)
        except EncryptionError:
            return "unavailable"
        return provisioner.describe() if provisioner is not None else "none"

    def _translate_kek_error(self, exc: BaseException, kek_id: str, silo_ref: SiloRef, kms_adapter) -> None:
        """If *exc* indicates a missing KEK, log and raise KekNotProvisionedError.

        Otherwise returns without raising so the caller can re-raise the
        original exception.
        """
        if not kms_adapter.is_kek_not_found_error(exc):
            return
        provisioner_desc = self._describe_provisioner(kms_adapter)
        logger.error(
            "The KMS reported that the configured KEK does not exist. "
            'error_code=%s key_store=%s kek="%s" silo="%s" strategy="%s" provisioner="%s" detail="%s" hint="%s"%s',
            KekNotProvisionedError.code,
            kms_adapter.kms_name,
            kek_id,
            silo_ref,
            kms_adapter.kek_strategy.describe(),
            provisioner_desc,
            _summarize_provider_error(exc),
            _KEK_NOT_FOUND_HINT,
            optional_log_field("possible_cause", self._resource_mismatch_hint(kek_id, kms_adapter)),
        )
        raise KekNotProvisionedError(
            GENERIC_ENCRYPT_DECRYPT_UNAVAILABLE_MESSAGE,
            detail=(
                f'kek="{kek_id}" silo="{silo_ref}" provisioner="{provisioner_desc}" '
                f"{_summarize_provider_error(exc)} {_KEK_NOT_FOUND_HINT}"
            ),
        ) from exc

    def _raise_key_management_error(
        self, exc: BaseException, *, kek_id: str, silo_ref: SiloRef, operation: str, kms_adapter
    ):
        """Normalize any KEK-operation failure into a typed EncryptionError.

        Provider-agnostic funnel for every wrap/unwrap failure of *kms_adapter*,
        so callers never leak a raw provider error (Vault HTTP error, boto
        ``ClientError``, etc.). A clearly-missing KEK becomes
        :class:`KekNotProvisionedError` (via :meth:`_translate_kek_error`);
        anything else (auth/permission, network, provider error) becomes
        :class:`KekUnavailableError`. The underlying error text is logged for
        diagnosis; the raised exception carries only a generic, translatable
        message. Always raises.
        """
        # Already-typed errors (e.g. a EncryptionConfigurationError raised by a
        # credential strategy) are pass-through: they carry their own classification
        # and have already been logged at the source, so re-raise unchanged rather
        # than re-wrapping them as an operational KekUnavailableError.
        if isinstance(exc, EncryptionError):
            raise exc
        # Missing-KEK case: logs richly and raises KekNotProvisionedError.
        self._translate_kek_error(exc, kek_id, silo_ref, kms_adapter)
        # Any other operational failure: log the cause, raise a neutral error.
        logger.error(
            "The KMS call to use this key failed. error_code=%s operation=%s key_store=%s "
            'kek="%s" silo="%s" detail="%s"%s',
            KekUnavailableError.code,
            operation,
            kms_adapter.kms_name,
            kek_id,
            silo_ref,
            operator_error_text(exc),
            optional_log_field("possible_cause", self._resource_mismatch_hint(kek_id, kms_adapter)),
        )
        raise KekUnavailableError(
            GENERIC_ENCRYPT_DECRYPT_UNAVAILABLE_MESSAGE,
            detail=(
                f'operation={operation} key_store={kms_adapter.kms_name} kek="{kek_id}" silo="{silo_ref}" '
                f"{operator_error_text(exc)}"
            ),
        ) from exc

    def generate_and_store_keyset(
        self,
        silo,
        *,
        key_set: str = DEFAULT_KEY_SET,
        trigger: str = lifecycle.TRIGGER_INDIRECT,
        reason: str = lifecycle.REASON_SILO_CREATED,
        user=user_context._UNSET,
        os_login_user: str = "",
        user_ip=user_context._UNSET,
    ) -> bool:
        """
        Generate a new field DEK for *silo*'s *key_set* via the configured crypto
        backend, wrap it via the key set's key store, and persist it as a
        DataEncryptionKey record.

        Called by the silo-creation signal handler, the management
        command, and the lazy-provisioning path in :meth:`encrypt`.

        The identity is defaulted for the signal, which passes none: a silo
        creation is a person asking for something else, so the keys that follow
        are ``indirect`` and name the act that caused them. The command and the
        lazy-provisioning path pass their own.

        Returns whether a key was stored: ``False`` when another process made
        this silo's key first, and the new one was discarded unused.
        """
        from .models import DataEncryptionKey

        return self._generate_and_store(
            DataEncryptionKey.PURPOSE_FIELD,
            silo,
            key_set=key_set,
            trigger=trigger,
            reason=reason,
            user=user,
            os_login_user=os_login_user,
            user_ip=user_ip,
        )

    def _generate_and_store(
        self,
        purpose: str,
        silo,
        *,
        key_set: str,
        trigger: str,
        reason: str,
        user,
        os_login_user: str,
        user_ip,
    ) -> bool:
        """Make one key of *purpose* for *silo*, wrap it, and persist the row.

        One body for all three purposes: what differs is the material, which
        :meth:`_new_wrapped_keyset` chooses, and which row it lands in, which is
        the purpose itself. Everything around it — resolving the silo, the
        identity the ledger records, ensuring the KEK, reviving a tombstone,
        emitting ``created`` — is the same work whichever key is being made.
        """
        silo_ref = self._ref_of(silo, key_set)
        silo_label = self.silo_adapter_for(silo_ref.key_set).get_silo_label()

        user, user_ip = user_context.resolve_user_and_ip(user, user_ip)
        identity = {
            "trigger": trigger,
            "reason": reason,
            "user": user,
            "os_login_user": os_login_user,
            "user_ip": user_ip,
        }

        kek_id, created_kek = self._ensure_kek(silo_ref, user=user, os_login_user=os_login_user, user_ip=user_ip)

        encrypted_keyset_bytes, metadata = self._new_wrapped_keyset(silo_ref, purpose, kek_id)

        record, created, revived = self._store_keyset(
            silo_ref,
            purpose,
            silo_label,
            encrypted_keyset_bytes,
            metadata,
            created_kek,
            **identity,
        )
        if created or revived:
            self._emit_dek_created(record, silo_ref=silo_ref, **identity)
        return created or revived

    def ensure_system_keys(
        self,
        *,
        key_set: str = SYSTEM_KEY_SET,
        trigger: str = lifecycle.TRIGGER_INDIRECT,
        reason: str = lifecycle.REASON_FIRST_ENCRYPTION,
        user=user_context._UNSET,
        os_login_user: str = "",
        user_ip=user_context._UNSET,
    ) -> None:
        """Create the system silo's KEK row and its field, file and index keys for *key_set*, whichever are missing.

        One routine for every way they come to be made — a first write or lookup
        of a column of a system key set, and ``setup_encryption_keys`` — and all three
        at once, used or not, so there is never a partial set to reason about.

        The order is what makes it safe. The rows are created first, with no
        ledger events; each new key is unwrapped to prove it reads back; only then
        are the events written. An event records who acted, and that identity may
        itself be encrypted under the system silo. Written after the keys exist,
        it finds them; written while they were being made, it would need the very
        keys being made and take this lock again. So every one of these events
        carries the full identity.

        All of it is one transaction under the system silo's provisioning lock:
        a failure rolls back every row and event, releases the lock, and reaches
        the caller as the typed error it was. Another process doing the same at
        the same moment loses on the unique ``(silo_ref, purpose)`` constraint;
        the loser rolls back and uses the winner's keys.
        """
        from django.db import IntegrityError, OperationalError

        from .models import DataEncryptionKey

        uid = SiloRef(key_set, SYSTEM_SILO_UID)
        purposes = (
            DataEncryptionKey.PURPOSE_FIELD,
            DataEncryptionKey.PURPOSE_FILE,
            DataEncryptionKey.PURPOSE_INDEX,
        )

        def _missing():
            present = set(DataEncryptionKey.objects.filter(**silo_filter(uid)).values_list("purpose", flat=True))
            return [purpose for purpose in purposes if purpose not in present]

        if not _missing():
            return
        with _get_provision_lock(uid):
            missing = _missing()
            if not missing:
                return
            user, user_ip = user_context.resolve_user_and_ip(user, user_ip)
            identity = {
                "trigger": trigger,
                "reason": reason,
                "user": user,
                "os_login_user": os_login_user,
                "user_ip": user_ip,
            }
            try:
                with transaction.atomic():
                    self._create_system_keys(uid, missing, identity)
            except (IntegrityError, OperationalError) as exc:
                # Another process made them first (IntegrityError), or SQLite's
                # write lock outlasted its busy timeout (OperationalError). Either
                # way this transaction is gone; the other one's keys are the keys.
                if _missing():
                    # No other process's keys either. A sign-in or sign-up reaches
                    # here from inside code no consumer can wrap, so the database
                    # error leaves as the typed error a missing key is.
                    detail = f"The system silo's keys could not be created. {operator_error_text(exc)}"
                    logger.error(
                        '%s error_code=%s silo="%s"%s',
                        detail,
                        MissingDekError.code,
                        uid,
                        _key_set_log_field(key_set),
                    )
                    raise MissingDekError(GENERIC_ENCRYPT_DECRYPT_UNAVAILABLE_MESSAGE, detail=detail) from exc
                logger.info(
                    'Another process created the system keys first; using those. silo="%s"%s detail="%s"',
                    uid,
                    _key_set_log_field(key_set),
                    operator_error_text(exc),
                )

    def _create_system_keys(self, uid: SiloRef, purposes, identity) -> None:
        """Rows, then the read-back check, then the events. See :meth:`ensure_system_keys`."""
        from .models import DataEncryptionKey

        kms_adapter = self.new_key_kms_adapter(uid)
        kek_id, created_kek = ensure_kek_provisioned(
            kms_adapter,
            self.new_key_kek_provisioner(uid),
            uid,
            user=identity["user"],
            os_login_user=identity["os_login_user"],
            user_ip=identity["user_ip"],
        )

        # 1. Rows, no events.
        kek = new_kek = None
        records = []
        for purpose in purposes:
            keyset, metadata = self._new_wrapped_keyset(uid, purpose, kek_id)
            if kek is None:
                kek, is_new = self._kek_row_quietly(metadata)
                new_kek = kek if is_new else None
            record = DataEncryptionKey.objects.create(
                **silo_filter(uid),
                purpose=purpose,
                silo_label="system",
                encrypted_keyset=keyset,
                kek=kek,
                kek_key_version=metadata.kek_key_version,
                crypto_backend="" if purpose == DataEncryptionKey.PURPOSE_INDEX else self.crypto_backend.backend_id,
                algorithm=self._algorithm_for(purpose),
                key_material_last_generated_at=timezone.now(),
            )
            records.append((record, metadata))

        # 2. Each key reads back before anything says it exists.
        for record, metadata in records:
            with kms_error_guard("key unwrap", uid, kms_adapter):
                kms_adapter.decrypt_key(bytes(record.encrypted_keyset), metadata, uid)

        # 3. The events, now that every key they might need exists.
        if new_kek is not None:
            self._record_kek_first_sighting(new_kek, created_kek, **identity)
        for record, _metadata in records:
            self._emit_dek_created(record, silo_ref=uid, **identity)
            # Published to the shared cache only once the caller's transaction
            # commits, as a lazily created key is (see _publish_primitive).
            _mark_uncommitted(
                {
                    DataEncryptionKey.PURPOSE_FIELD: _field_cache_key,
                    DataEncryptionKey.PURPOSE_FILE: _file_cache_key,
                    DataEncryptionKey.PURPOSE_INDEX: _index_cache_key,
                }[record.purpose](uid)
            )

    def _algorithm_for(self, purpose: str) -> str:
        """The algorithm a keyset generated now for *purpose* holds, as the data key row records it."""
        from .blind_index import INDEX_ALGORITHM
        from .models import DataEncryptionKey

        if purpose == DataEncryptionKey.PURPOSE_INDEX:
            return INDEX_ALGORITHM
        return self.crypto_backend.algorithm_id(purpose)

    def _new_wrapped_keyset(self, silo_ref: SiloRef, purpose: str, kek_id: str):
        """Generate DEK material for *purpose* and return it wrapped by the silo's KEK.

        Returns ``(encrypted_keyset_bytes, metadata)`` and persists nothing, so a
        caller decides where the wrapped keyset lands: the live
        :class:`~encryption_suite.models.DataEncryptionKey` row when a silo is
        first provisioned, somewhere else when the material is not yet the one
        the silo's data is encrypted under.

        The plaintext never leaves this method — it is dropped in a ``finally``
        so its lifetime in process memory is as short as Python allows — and a
        provider failure goes through the engine funnel rather than escaping as a
        raw SDK error.

        The caller ensures the KEK first and passes *kek_id*: provisioning writes
        ledger rows, and keeping that outside means this generates and wraps and
        does nothing else.
        """
        from .models import DataEncryptionKey

        if purpose == DataEncryptionKey.PURPOSE_FIELD:
            plaintext_keyset_bytes = self.crypto_backend.generate_field_dek()
        elif purpose == DataEncryptionKey.PURPOSE_FILE:
            plaintext_keyset_bytes = self.crypto_backend.generate_file_dek()
        elif purpose == DataEncryptionKey.PURPOSE_INDEX:
            # Not the crypto backend's to make: an index key is an HMAC key, and
            # the backends build AEADs. Plain random bytes, so the digests a silo
            # has already stored stay findable across a change of backend.
            import secrets

            from .blind_index import INDEX_KEY_BYTES

            plaintext_keyset_bytes = secrets.token_bytes(INDEX_KEY_BYTES)
        else:
            # Not a config error and not reachable from a request: the purposes
            # are the engine's own vocabulary, so a third value is a programming
            # mistake. Raising beats generating field material for it silently.
            raise ValueError(f"Cannot generate a keyset for purpose {purpose!r}.")

        kms_adapter = self.new_key_kms_adapter(silo_ref)
        try:
            encrypted_keyset_bytes, metadata = kms_adapter.encrypt_key(plaintext_keyset_bytes, silo_ref)
        except Exception as exc:
            self._raise_key_management_error(
                exc, kek_id=kek_id, silo_ref=silo_ref, operation="key wrap", kms_adapter=kms_adapter
            )
        else:
            metadata.kms_name = kms_adapter.kms_name
            return encrypted_keyset_bytes, metadata
        finally:
            # Drop the plaintext keyset reference as soon as possible to shorten its
            # lifetime in process memory.  Python cannot guarantee zeroization, but
            # deleting the reference makes the bytes eligible for GC immediately.
            del plaintext_keyset_bytes

    def _store_keyset(
        self,
        silo_ref,
        purpose,
        silo_label,
        encrypted_keyset_bytes,
        metadata,
        created_kek=False,
        *,
        trigger,
        reason="",
        user=None,
        os_login_user="",
        user_ip=None,
    ):
        """Persist (or revive) the DEK row; return ``(record, created, revived)``.

        A reused tombstone (status not ``active``) is *revived*: status resets to
        ``active`` and the soft-delete window clears, atomically with the keyset
        write. Resetting status here — rather than through the transition funnel —
        is the rebirth analogue of the field default that gives a brand-new row
        its initial ``active`` status; the ledger ``created`` event that records
        the act stays best-effort (see :meth:`_emit_dek_created`).

        Every call here writes freshly generated material, so both branches stamp
        ``key_material_last_generated_at``. It has to be written on the revive
        branch too: a revived row keeps the ``created_at`` of its first life, so
        that column would date brand-new material to whenever the silo first had a
        key — which is the one reading the field exists to prevent. For the same
        reason a revive moves ``dek_key_version`` on by one; a new row starts at 1.

        **An active key is never overwritten.** Another process may have made this
        silo's key since the caller found it missing, and may already have
        encrypted data under it; replacing its keyset would make that data
        unreadable. So when an active row is already there — found under the row
        lock, or committed by another transaction while this insert waited on the
        unique constraint — the new keyset is discarded unused and the existing
        row returned as ``(record, False, False)``. Nothing is written and no event
        recorded; the caller's next load uses the existing key. Only a row that is
        not active, a tombstone, is overwritten, which is a revival.
        """
        from django.db import IntegrityError

        from .models import DataEncryptionKey

        with transaction.atomic():
            existing = (
                DataEncryptionKey.objects.select_for_update().filter(**silo_filter(silo_ref), purpose=purpose).first()
            )
            if existing is not None and existing.status == lifecycle.STATUS_ACTIVE:
                return existing, False, False
            # The KEK row is a prerequisite of the reference, so both writes ride
            # in one transaction: either the data key and its relation land, or
            # neither does.
            kek = self._kek_row(
                metadata,
                created_kek,
                trigger=trigger,
                reason=reason,
                user=user,
                os_login_user=os_login_user,
                user_ip=user_ip,
            )
            fields = {
                "silo_label": silo_label,
                "encrypted_keyset": encrypted_keyset_bytes,
                "kek": kek,
                "kek_key_version": metadata.kek_key_version,
                # Left empty for an index key, which no backend produced: stamping
                # one would make the key unusable after a change of CRYPTO_BACKEND,
                # and its digests unfindable, for a mismatch that cannot happen.
                "crypto_backend": (
                    "" if purpose == DataEncryptionKey.PURPOSE_INDEX else self.crypto_backend.backend_id
                ),
                "algorithm": self._algorithm_for(purpose),
                "status": lifecycle.STATUS_ACTIVE,
                "undeletable_until": None,
                "key_material_last_generated_at": timezone.now(),
            }
            if existing is None:
                try:
                    # Its own savepoint, so a clash leaves the caller's
                    # transaction usable for the re-read below.
                    with transaction.atomic():
                        record = DataEncryptionKey.objects.create(**silo_filter(silo_ref), purpose=purpose, **fields)
                except IntegrityError:
                    # Another transaction committed this silo's key while the
                    # insert waited on the unique constraint.
                    existing = DataEncryptionKey.objects.select_for_update().get(
                        **silo_filter(silo_ref), purpose=purpose
                    )
                    if existing.status == lifecycle.STATUS_ACTIVE:
                        return existing, False, False
                else:
                    self._clear_kek_orphan(
                        kek, silo_ref, trigger=trigger, user=user, os_login_user=os_login_user, user_ip=user_ip
                    )
                    return record, True, False
            # A tombstone: revive it. A reused row counts on from where it left
            # off rather than restarting at 1: the silo UID is the same silo, and
            # a counter that resets says a rotation history was erased along with
            # the material. Written as an expression so two writers cannot both
            # read the old value.
            for name, value in fields.items():
                setattr(existing, name, value)
            existing.dek_key_version = F("dek_key_version") + 1
            existing.save()
            existing.refresh_from_db(fields=["dek_key_version"])
        self._clear_kek_orphan(kek, silo_ref, trigger=trigger, user=user, os_login_user=os_login_user, user_ip=user_ip)
        return existing, False, True

    def _clear_kek_orphan(
        self, kek, silo_ref: SiloRef, *, trigger, reason: str = "", user=None, os_login_user: str = "", user_ip=None
    ) -> None:
        """Note that a live silo now references *kek*, if it was flagged orphaned.

        A key encryption key discovered before its silo existed — or one whose
        silo was deleted and provisioned again — carries a stale orphan flag until
        the next reconcile, which on a scheduled reconcile can be a day. This path
        knows the answer without looking: a data key was just wrapped by this key,
        so a live silo references it.

        Best-effort and never fatal: the annotation is display-only, and failing a
        key provision over a cosmetic flag would trade a working silo for a tidy
        changelist. Silent when the flag was already false, so a routine
        re-provision writes nothing.
        """
        if not getattr(kek, "is_orphaned", False):
            return
        try:
            kek.is_orphaned = False
            kek.save(update_fields=["is_orphaned", "updated_at"])
            kek.record_event(
                lifecycle.EVENT_SILO_FOUND,
                trigger=trigger,
                # A live silo turned up for a key that was annotated as an orphan,
                # whatever the caller's own reason for provisioning.
                reason=lifecycle.REASON_SILO_REACQUIRED,
                user=user,
                os_login_user=os_login_user,
                user_ip=user_ip,
                silo_ref=silo_ref,
            )
        except Exception as exc:
            logger.warning(
                "Provisioning a silo's data key could not clear the stale orphan annotation on the "
                "key encryption key behind it, so reconcile will keep reporting the key as orphaned "
                'until a later pass clears it. kek="%s" silo="%s" detail="%s"',
                getattr(kek, "kek_resource_name", "?"),
                silo_ref,
                operator_error_text(exc),
            )

    def _kek_row(
        self,
        metadata,
        created: bool = False,
        *,
        trigger,
        reason: str = "",
        user=None,
        os_login_user: str = "",
        user_ip=None,
    ):
        """Return (creating if needed) the :class:`KeyEncryptionKey` row for *metadata*.

        A new row gets a first-sighting ledger event, so every key encryption key
        has one however it entered the ledger. Which verb depends on *created*,
        the provisioner's report of whether it made the key on this call:
        ``created`` when it did, ``discovered`` when the key was already there —
        the same verb reconcile records for a key it finds on the provider.
        Claiming ``discovered`` for a key this deployment had just made
        understates the ledger's own knowledge.

        No longer best-effort: the data encryption key row references this one, so
        it must exist first. That is not the fragility it sounds like — writing
        the DEK row already requires a working database, so this adds no failure
        the caller was not already exposed to, and it buys a real relation in
        place of two strings that have to be kept in step by hand.
        """
        # Not named ``created``: that is the caller's fact about the KMS key, and
        # this one is about the row. Reusing the name would silently overwrite the
        # answer the verb below depends on.
        row, is_new = self._kek_row_quietly(metadata)
        if is_new:
            self._record_kek_first_sighting(
                row, created, trigger=trigger, reason=reason, user=user, os_login_user=os_login_user, user_ip=user_ip
            )
        return row

    @staticmethod
    def _kek_row_quietly(metadata):
        """Return ``(row, is_new)`` for *metadata*'s :class:`KeyEncryptionKey`, recording nothing."""
        from .models import KeyEncryptionKey

        return KeyEncryptionKey.objects.get_or_create(
            key_store=metadata.kms_name,
            kek_resource_name=metadata.kek_resource_name,
            defaults={"kek_key_version": metadata.kek_key_version},
        )

    @staticmethod
    def _record_kek_first_sighting(
        row, created: bool, *, trigger, reason: str = "", user=None, os_login_user: str = "", user_ip=None
    ) -> None:
        """Record a new KEK row's first-sighting events (see :meth:`_kek_row`)."""
        from .lifecycle import EVENT_CREATED, EVENT_DISCOVERED, EVENT_SILO_FOUND

        row.record_event(
            EVENT_CREATED if created else EVENT_DISCOVERED,
            trigger=trigger,
            # ``discovered`` keeps the provider's report that the key was
            # already there — a fact about the provider, not about the caller.
            reason=reason if created else lifecycle.REASON_OBSERVED_AT_PROVIDER,
            user=user,
            os_login_user=os_login_user,
            user_ip=user_ip,
        )
        # A row reached here because a silo is provisioning against this key,
        # so it is born backed and the ledger says so — the same rule reconcile
        # follows when it records the state a *discovered* row is born with.
        # Without this, a key created for its silo has no record of ever having
        # had one, while a key that acquired its silo later does.
        row.record_event(
            EVENT_SILO_FOUND,
            trigger=trigger,
            reason=reason,
            user=user,
            os_login_user=os_login_user,
            user_ip=user_ip,
        )

    def _emit_dek_created(
        self, record, *, silo_ref, trigger, reason: str = "", user=None, os_login_user: str = "", user_ip=None
    ) -> None:
        """Record a data key's creation: its ledger events, then its log line.

        The one place every creation path meets — the silo-creation signal, a
        first encryption, ``setup_encryption_keys``, a revived tombstone — so the
        line is logged here rather than by each caller, and none of them can
        forget it.

        The ledger events are best-effort: an additive record, so a failure must
        never break encryption — it is logged and swallowed. (The destructive
        deletion path writes its ledger events transactionally with the act
        instead.) The creation line is logged either way, because the key exists
        either way.
        """
        try:
            identity = {
                "trigger": trigger,
                "reason": reason,
                "user": user,
                "os_login_user": os_login_user,
                "user_ip": user_ip,
            }
            record.record_event(lifecycle.EVENT_CREATED, silo_ref=silo_ref, **identity)
            # The row is born with an orphan annotation (False), so birth records
            # it — the same rule the key encryption key side and reconcile follow.
            # Without this a data key created for a live silo has no ledger entry
            # saying it ever had one, while one that acquired its silo later does.
            record.record_event(lifecycle.EVENT_SILO_FOUND, silo_ref=silo_ref, **identity)
        except Exception as exc:
            logger.warning(
                "The key was created but its birth events could not be appended to the ledger, so "
                'its history begins with a gap. event=%s silo="%s" purpose=%s detail="%s" %s',
                lifecycle.EVENT_CREATED,
                silo_ref,
                record.purpose,
                operator_error_text(exc),
                user_context.identity_tail(user=user, os_login_user=os_login_user, user_ip=user_ip),
            )
        # INFO, like the key encryption key's creation line: nothing is destroyed
        # and nothing counts down. Identified the way every other data key line
        # is — silo and purpose, which the row is unique on, and the key that
        # wraps it.
        logger.info(
            '%s event=%s reason=%s silo="%s" purpose=%s kek="%s" %s',
            _DEK_CREATED_SENTENCES.get(reason, _DEK_CREATED_SENTENCE),
            lifecycle.EVENT_CREATED,
            reason or "none",
            silo_ref,
            record.purpose,
            record.kek.kek_resource_name,
            user_context.identity_tail(user=user, os_login_user=os_login_user, user_ip=user_ip),
        )

    def _check_dek_usable(self, record, silo_ref: SiloRef) -> None:
        """Refuse to load a DEK that must not be used right now, before any KMS call.

        Both callers fetch the primitive that encrypt uses as well as decrypt, so
        this fences writes too, not only reads. A pure database-state check:

        * ``reencrypting`` — a rotation has split the silo's rows between this
          row's keyset and an incoming one, so neither alone reads them, and a
          value written now could land on the wrong one
          (:class:`DekReencryptionInProgressError`). Clears at the swap or at the
          end of a rollback;
        * ``deletion_scheduled`` — still restorable
          (:class:`DekDeletionScheduledError`);
        * ``deleted`` — a tombstone whose wrapped material has been cleared
          (:class:`DekDeletedError`), so there is nothing to unwrap.
        """
        if record.status == lifecycle.STATUS_REENCRYPTING:
            logger.error(
                f'{_DEK_REENCRYPTING_DETAIL} error_code=%s silo="%s" purpose=%s hint="{_DEK_REENCRYPTING_HINT}"',
                DekReencryptionInProgressError.code,
                silo_ref,
                record.purpose,
            )
            raise DekReencryptionInProgressError(
                GENERIC_ENCRYPT_DECRYPT_UNAVAILABLE_MESSAGE,
                detail=(
                    f'silo="{silo_ref}" purpose={record.purpose} {_DEK_REENCRYPTING_DETAIL} {_DEK_REENCRYPTING_HINT}'
                ),
            )
        if record.status == lifecycle.STATUS_DELETION_SCHEDULED:
            logger.error(
                f'{_DEK_SCHEDULED_DETAIL} error_code=%s silo="%s" undeletable_until="%s" hint="{_DEK_SCHEDULED_HINT}"',
                DekDeletionScheduledError.code,
                silo_ref,
                record.undeletable_until,
            )
            raise DekDeletionScheduledError(
                GENERIC_ENCRYPT_DECRYPT_UNAVAILABLE_MESSAGE,
                detail=(
                    f'silo="{silo_ref}" undeletable_until="{record.undeletable_until}" '
                    f"{_DEK_SCHEDULED_DETAIL} {_DEK_SCHEDULED_HINT}"
                ),
            )
        if record.status == lifecycle.STATUS_DELETED:
            logger.error(
                f'{_DEK_DELETED_DETAIL} error_code=%s silo="%s"',
                DekDeletedError.code,
                silo_ref,
            )
            raise DekDeletedError(
                GENERIC_ENCRYPT_DECRYPT_UNAVAILABLE_MESSAGE,
                detail=f'silo="{silo_ref}" {_DEK_DELETED_DETAIL}',
            )

    # ------------------------------------------------------------------
    # Aead cache
    # ------------------------------------------------------------------

    def _decrypt_to_aead(self, silo_ref: SiloRef) -> FieldPrimitive:
        """Fetch DataEncryptionKey, decrypt via KMS, return a field AEAD primitive."""
        from .models import DataEncryptionKey

        try:
            record = DataEncryptionKey.objects.get(
                **silo_filter(silo_ref),
                purpose=DataEncryptionKey.PURPOSE_FIELD,
            )
        except DataEncryptionKey.DoesNotExist:
            # No log here: a missing DEK is an expected first-use event on the
            # auto-provision encrypt path, and the provision lock re-checks this
            # lookup (so logging here double-logs). Terminal callers — read, or
            # encrypt with auto-provision off — log it where it is an error.
            raise MissingDekError(
                GENERIC_ENCRYPT_DECRYPT_UNAVAILABLE_MESSAGE,
                detail=f"{_MISSING_FIELD_DEK_DETAIL} {_MISSING_DEK_HINT}",
            ) from None

        self._check_dek_usable(record, silo_ref)
        return self._unwrap_primitive(
            DataEncryptionKey.PURPOSE_FIELD,
            record.encrypted_keyset,
            record.kek,
            record.kek_key_version,
            silo_ref,
            backend_id=record.crypto_backend,
        )

    def _unwrap_primitive(
        self, purpose: str, encrypted_keyset, kek, kek_key_version: str, silo_ref: SiloRef, *, backend_id: str
    ):
        """Unwrap *encrypted_keyset* under *kek* and load the primitive for *purpose*.

        The half of loading a key that knows nothing about the row it came from:
        no status check and no cache. The read path runs its checks first; a
        rotation calls this directly, because it holds both of a fenced silo's
        keysets at once and the fence is exactly what the checks refuse.

        Routed by what the row recorded: the unwrap goes through the KMS *kek*
        names, and the primitive is built by the backend *backend_id* names. The
        settings that choose those for new keys play no part, which is what lets
        a deployment switch KMS or backend and keep reading what it already has.

        A provider failure goes through the engine funnel, and the plaintext
        keyset is dropped as soon as the primitive is built — Python cannot
        guarantee zeroization, but deleting the reference makes the bytes
        eligible for collection at once.
        """
        from .adapters.key_stores.base import KmsMetadata
        from .models import DataEncryptionKey

        kms_adapter = self.kms_adapter_for_kek(kek, silo_ref)
        # Resolved before the KMS call, so a row no backend here can load costs
        # no unwrap. An index key records no backend and needs none.
        backend = None if purpose == DataEncryptionKey.PURPOSE_INDEX else self._backend_for_row(backend_id, silo_ref)
        metadata = KmsMetadata(
            kek_resource_name=kek.kek_resource_name,
            kms_provider=kms_adapter.kms_provider,
            kms_name=kek.key_store,
            kek_key_version=kek_key_version,
        )
        try:
            plaintext_keyset_bytes = kms_adapter.decrypt_key(bytes(encrypted_keyset), metadata, silo_ref)
        except Exception as exc:
            self._raise_key_management_error(
                exc,
                kek_id=kek.kek_resource_name,
                silo_ref=silo_ref,
                operation="key unwrap",
                kms_adapter=kms_adapter,
            )
        try:
            if purpose == DataEncryptionKey.PURPOSE_FILE:
                return backend.load_file_primitive(plaintext_keyset_bytes)
            if purpose == DataEncryptionKey.PURPOSE_INDEX:
                return SiloIndexKey(plaintext_keyset_bytes)
            return backend.load_field_primitive(plaintext_keyset_bytes)
        except Exception as exc:
            # The unwrap succeeded, so the bytes are the row's own, and the
            # backend the row names cannot parse them: the recorded backend is
            # wrong for this keyset.
            logger.error(
                "The stored DEK is not in the format of the crypto backend its row records. "
                'error_code=%s silo="%s" stored_backend="%s" detail="%s" hint="%s"',
                CryptoBackendMismatchError.code,
                silo_ref,
                backend_id,
                operator_error_text(exc),
                _BACKEND_FORMAT_HINT,
            )
            raise CryptoBackendMismatchError(
                GENERIC_ENCRYPT_DECRYPT_UNAVAILABLE_MESSAGE,
                detail=(
                    f'silo="{silo_ref}" stored_backend="{backend_id}" {operator_error_text(exc)} {_BACKEND_FORMAT_HINT}'
                ),
            ) from exc
        finally:
            del plaintext_keyset_bytes

    def _get_cached_primitive(self, cache_key: DekCacheKey, load_fn):
        """
        Return a cached primitive, refreshing from KMS if the TTL has elapsed.

        *cache_key* names the key set, the kind of key and the silo.

        *load_fn* is called with no arguments when a cache miss occurs and
        must return the primitive to cache.

        A recent failure is cached for ``DEK_FAILURE_CACHE_TTL`` and re-raised
        on subsequent calls within that window, so a slow or dead KMS call is
        not re-paid by every encrypted read in a request.

        A hit takes no lock. A miss takes a per-key lock, which serializes KMS
        calls for the same key without blocking threads that need a different key.
        """
        cache = dek_cache(cache_key.key_set)
        slot = cache_key.slot
        hit = cache.lookup(slot)
        if hit is not MISS:
            return hit

        with cache.load_lock(slot):
            hit = cache.lookup(slot)
            if hit is not MISS:
                return hit

            try:
                primitive = load_fn()
            except Exception as exc:
                failure_ttl = enc_settings.DEK_FAILURE_CACHE_TTL
                if failure_ttl > 0 and isinstance(exc, _NEGATIVE_CACHE_TYPES):
                    cache.put_failure(slot, exc, time.monotonic() + failure_ttl)
                raise

            self._publish_primitive(cache_key, primitive)
            return primitive

    def _get_cached_aead(self, silo_ref: SiloRef) -> FieldPrimitive:
        """Return a cached field AEAD primitive for *silo_ref*."""
        return self._get_cached_primitive(
            _field_cache_key(silo_ref),
            lambda: self._decrypt_to_aead(silo_ref),
        )

    def _get_cached_streaming_aead(self, silo_ref: SiloRef):
        """Return a cached file Streaming AEAD primitive for *silo_ref*."""
        return self._get_cached_primitive(
            _file_cache_key(silo_ref),
            lambda: self._decrypt_to_streaming_aead(silo_ref),
        )

    def _get_cached_index_key(self, silo_ref: SiloRef) -> SiloIndexKey:
        """Return a cached blind index key for *silo_ref*."""
        return self._get_cached_primitive(
            _index_cache_key(silo_ref),
            lambda: self._decrypt_to_index_key(silo_ref),
        )

    def _decrypt_to_index_key(self, silo_ref: SiloRef) -> SiloIndexKey:
        """Fetch the index DataEncryptionKey, unwrap it via KMS, return the key."""
        from .models import DataEncryptionKey

        try:
            record = DataEncryptionKey.objects.get(
                **silo_filter(silo_ref),
                purpose=DataEncryptionKey.PURPOSE_INDEX,
            )
        except DataEncryptionKey.DoesNotExist:
            # Unlogged for the same reason the field lookup is: first use on the
            # provisioning path is expected, and the terminal callers log.
            raise MissingDekError(
                GENERIC_ENCRYPT_DECRYPT_UNAVAILABLE_MESSAGE,
                detail=f"{_MISSING_INDEX_DEK_DETAIL} {_MISSING_DEK_HINT}",
            ) from None

        self._check_dek_usable(record, silo_ref)
        # The material is not a backend's keyset, and the row deliberately
        # records no backend.
        return self._unwrap_primitive(
            DataEncryptionKey.PURPOSE_INDEX,
            record.encrypted_keyset,
            record.kek,
            record.kek_key_version,
            silo_ref,
            backend_id="",
        )

    def _ensure_system_keys_if_system(self, silo_ref: SiloRef) -> bool:
        """Create the system keys when *silo_ref* is the system silo; return whether it was.

        Whatever KEY_AUTO_PROVISION says: nothing else would create them.
        """
        if not silo_ref.is_system:
            return False
        self.ensure_system_keys(key_set=silo_ref.key_set)
        return True

    def _get_or_provision_index_key(self, silo_ref: SiloRef) -> SiloIndexKey:
        """Return the blind index key, lazily creating (or reviving) the DEK if needed."""
        try:
            return self._get_cached_index_key(silo_ref)
        except (MissingDekError, DekDeletedError) as exc:
            if self._ensure_system_keys_if_system(silo_ref):
                return self._get_cached_index_key(silo_ref)
            if not enc_settings.KEY_AUTO_PROVISION:
                if isinstance(exc, MissingDekError):
                    logger.error(_MISSING_INDEX_DEK_LOG + _key_set_log_field(silo_ref.key_set), silo_ref)
                raise
            return self._lazy_provision(
                silo_ref,
                generate=self.generate_and_store_index_keyset,
                get_cached=self._get_cached_index_key,
                cache_key=_index_cache_key(silo_ref),
            )

    def index_digest(self, value: str, *, context: str, silo=None, key_set: str = DEFAULT_KEY_SET) -> str:
        """Return the blind index digest of *value* for the current silo.

        The read and the write both come here: a row's digest is computed on the
        way in, and a lookup computes the digest it is searching for. One key per
        silo, so the same value in two silos indexes differently and neither
        silo's digests can be matched against the other's — the unlinkability is
        in the key rather than in anything hashed with the value.

        Needs the silo's key, so it needs the KMS, once per
        ``DEK_CACHE_TTL``. Nothing in a silo is readable without a data key, so
        that is no new dependency — but a key scheduled for deletion blocks a
        lookup exactly as it blocks an encrypt, and for the same reason.
        """
        silo_ref = self._resolve_current_silo(silo, key_set)
        return self._get_or_provision_index_key(silo_ref).digest(value, context=context)

    @staticmethod
    def _publish_primitive(cache_key: DekCacheKey, primitive) -> None:
        """Share a loaded primitive with the rest of the process.

        The cache is in process memory: nothing rolls it back. A primitive
        published while its ``DataEncryptionKey`` row is still uncommitted
        therefore outlives that row if the transaction does not commit — and a
        later request in the same process then encrypts against a key that exists
        nowhere, without provisioning one, because the cache hit satisfies the
        lookup that would have created a replacement. The rows it writes commit;
        the wrapped keyset that could read them back went out with the rollback.

        So a key marked by :func:`_mark_uncommitted` is published from
        ``on_commit`` instead. The caller still receives the primitive — that
        caller is inside the same transaction, and its writes roll back together
        with the key. Everything else, which is every load of a row that was
        already committed, publishes immediately as before; a rollback cannot
        invalidate those.
        """

        def _store():
            # A success supersedes any cached failure for this key.
            dek_cache(cache_key.key_set).put(cache_key.slot, primitive, time.monotonic() + enc_settings.DEK_CACHE_TTL)
            _clear_uncommitted(cache_key)

        if _is_uncommitted(cache_key):
            transaction.on_commit(_store)
        else:
            _store()

    def _get_or_provision_aead(self, silo_ref: SiloRef) -> FieldPrimitive:
        """Return a field AEAD, lazily creating the DEK if needed.

        This is the encrypt-path variant of :meth:`_get_cached_aead`. If the
        silo has no ``DataEncryptionKey`` row yet (or only a purged tombstone
        from a reused UID) and ``KEY_AUTO_PROVISION`` is enabled, it generates
        and stores one before returning the primitive. A ``deletion_scheduled``
        DEK is *not* revived here — it propagates as a hard block, since the silo
        must be explicitly restored, not silently re-keyed. Decryption never
        triggers lazy provisioning — a missing DEK on read is always a hard error.
        """
        try:
            return self._get_cached_aead(silo_ref)
        except (MissingDekError, DekDeletedError) as exc:
            if self._ensure_system_keys_if_system(silo_ref):
                return self._get_cached_aead(silo_ref)
            if not enc_settings.KEY_AUTO_PROVISION:
                if isinstance(exc, MissingDekError):
                    logger.error(_MISSING_FIELD_DEK_LOG + _key_set_log_field(silo_ref.key_set), silo_ref)
                raise
            return self._lazy_provision(
                silo_ref,
                generate=self.generate_and_store_keyset,
                get_cached=self._get_cached_aead,
                cache_key=_field_cache_key(silo_ref),
            )

    def _get_or_provision_streaming_aead(self, silo_ref: SiloRef):
        """Return a file Streaming AEAD, lazily creating (or reviving) the DEK if needed."""
        try:
            return self._get_cached_streaming_aead(silo_ref)
        except (MissingDekError, DekDeletedError) as exc:
            if self._ensure_system_keys_if_system(silo_ref):
                return self._get_cached_streaming_aead(silo_ref)
            if not enc_settings.KEY_AUTO_PROVISION:
                if isinstance(exc, MissingDekError):
                    logger.error(_MISSING_FILE_DEK_LOG + _key_set_log_field(silo_ref.key_set), silo_ref)
                raise
            return self._lazy_provision(
                silo_ref,
                generate=self.generate_and_store_file_keyset,
                get_cached=self._get_cached_streaming_aead,
                cache_key=_file_cache_key(silo_ref),
            )

    def _lazy_provision(self, silo_ref: SiloRef, generate, get_cached, cache_key):
        """Serialize DEK creation per key set of a silo and return the fresh primitive.

        The per-silo lock ensures two concurrent first-encrypt requests
        don't both try to create a DEK. The inner retry through ``get_cached``
        picks up whatever row the winning thread persisted.

        A row created here is only as durable as the transaction this call sits
        in, so the key is marked before it is read back: every load of it for as
        long as that transaction is open — this one, and the ordinary cached
        loads that follow it when a second field on the same row is encrypted —
        publishes to the shared cache on commit rather than at once. See
        :meth:`_publish_primitive`.
        """
        lock = _get_provision_lock(silo_ref)
        with lock:
            try:
                result = get_cached(silo_ref)
            except (MissingDekError, DekDeletedError):
                # Logged by the creation itself, once the key exists, rather than
                # announced here before anything has happened. Still ``indirect``
                # — a person asked to store a value, not to make a key — but the
                # act that caused it is this encryption, not the silo's creation.
                generate(silo_ref, reason=lifecycle.REASON_FIRST_ENCRYPTION)
                _mark_uncommitted(cache_key)
                result = get_cached(silo_ref)
            return result

    @staticmethod
    def invalidate_cache(silo_ref: SiloRef | None = None, *, key_set: str | None = None) -> None:
        """Remove entries from the in-process primitive cache.

        With a *silo_ref*, every key of that silo in its key set, whatever the
        purpose. With a *key_set*, every entry of that key set. With neither, every
        entry of every key set.
        """
        if silo_ref is not None:
            dek_cache(silo_ref.key_set).invalidate_uid(silo_ref.uid)
        else:
            clear_dek_caches(key_set)

    # ------------------------------------------------------------------
    # Silo resolution
    # ------------------------------------------------------------------

    def _resolve_current_silo(self, silo=None, key_set: str = DEFAULT_KEY_SET) -> SiloRef:
        """Return the :class:`SiloRef` *silo* names in *key_set*.

        A :class:`SiloRef` is used as it is, which is how the system silo (and any
        caller that already holds a reference) skips the context. An
        :class:`AmbientSilo` resolves the current silo of its own key set through
        that key set's silo adapter. ``None`` is the current silo of *key_set*.
        Anything else is a silo instance of *key_set*'s adapter.
        """
        if isinstance(silo, SiloRef):
            return silo
        if isinstance(silo, AmbientSilo):
            key_set = silo.key_set
        if silo is None or isinstance(silo, AmbientSilo):
            current = self.silo_adapter_for(key_set).get_current_silo()
            if current is None:
                # Configuration/wiring problem in the consuming project, not a
                # package bug — log it as such (no raw traceback into the package)
                # so the developer fixes their context/middleware setup.
                logger.error(
                    'No silo in the current context while accessing encrypted data. error_code=%s key_set=%s hint="%s"',
                    EncryptionConfigurationError.code,
                    key_set,
                    _NO_SILO_HINT,
                )
                # `detail` is the hint alone: it already opens by stating the
                # condition, so pairing it with the log line's detail would say the
                # same thing twice.
                raise EncryptionConfigurationError(GENERIC_ENCRYPT_DECRYPT_UNAVAILABLE_MESSAGE, detail=_NO_SILO_HINT)
            return SiloRef(key_set, self.silo_adapter_for(key_set).get_silo_uid(current))
        return SiloRef(key_set, self.silo_adapter_for(key_set).get_silo_uid(silo))

    def _ref_of(self, silo, key_set: str = DEFAULT_KEY_SET) -> SiloRef:
        """Return the :class:`SiloRef` of a silo instance, an existing reference, or the ambient one."""
        return self._resolve_current_silo(silo, key_set)

    def _resolve_silo_uid(self, silo=None, key_set: str = DEFAULT_KEY_SET) -> SiloRef:
        """Return the :class:`SiloRef`, using the adapter if no silo given."""
        return self._resolve_current_silo(silo, key_set)

    # ------------------------------------------------------------------
    # Encrypt / decrypt
    # ------------------------------------------------------------------

    def encrypt(
        self, plaintext: str, aad: bytes = b"", silo=None, field_name: str = "", key_set: str = DEFAULT_KEY_SET
    ) -> str:
        """
        Encrypt *plaintext* and return a versioned base64-encoded ciphertext string.

        The returned value is safe to store in any Django text column.
        Format: ``<prefix><base64>`` (currently ``~^Dv1:<base64>``).

        Raises :class:`FieldAlreadyEncryptedError` if *plaintext* already starts
        with the ciphertext prefix.  This guards against double-encryption bugs
        where ciphertext is accidentally fed back into the encryption path; it
        subclasses ``ValueError``, so an existing broad ``except ValueError``
        still catches it.

        If the silo has no ``DataEncryptionKey`` yet and
        ``KEY_AUTO_PROVISION`` is enabled, a DEK is generated on demand.
        """
        if is_silo_value(plaintext):
            logger.error(
                'Refused to encrypt a field value that is already encrypted. error_code=%s field="%s" hint="%s"',
                FieldAlreadyEncryptedError.code,
                field_name or "<unknown>",
                _FIELD_ALREADY_ENCRYPTED_HINT,
            )
            raise FieldAlreadyEncryptedError(
                GENERIC_ENCRYPT_FAILED_USER_MESSAGE,
                detail=f'field="{field_name or "<unknown>"}" {_FIELD_ALREADY_ENCRYPTED_HINT}',
            )
        silo_ref = self._resolve_current_silo(silo, key_set)
        aead_primitive = self._get_or_provision_aead(silo_ref)
        try:
            ciphertext_bytes = aead_primitive.encrypt(plaintext.encode("utf-8"), aad)
        except Exception as exc:
            logger.error(
                'Failed to encrypt a field value after the key was acquired. error_code=%s field="%s" detail="%s"',
                EncryptedFieldEncryptionError.code,
                field_name or "<unknown>",
                operator_error_text(exc),
            )
            raise EncryptedFieldEncryptionError(
                GENERIC_ENCRYPT_FAILED_USER_MESSAGE,
                detail=f'field="{field_name or "<unknown>"}" {operator_error_text(exc)}',
            ) from exc
        return wrap_ciphertext(ciphertext_bytes)

    def decrypt(
        self,
        ciphertext: str,
        aad: bytes = b"",
        silo=None,
        field_name: str = "",
        row_identity: str = "",
        key_set: str = DEFAULT_KEY_SET,
    ) -> str:
        """
        Decrypt a value produced by :meth:`encrypt`.

        Raises :class:`~encryption_suite.exceptions.EncryptedFieldDecryptionError`
        when the value is malformed (missing the ciphertext prefix) or when
        the crypto backend rejects the ciphertext (wrong silo, AAD
        mismatch, corruption). The exception subclasses ``ValueError`` via
        ``EncryptionError``.

        Emits an INFO-level audit log entry on success when ``LOG_DECRYPTS``
        is True. Route the ``encryption_suite`` logger to your audit log
        sink to capture these events.

        Decryption never lazily creates a DEK — a missing key on read is
        always a hard error, because no ciphertext could have been produced
        under a DEK that does not exist.
        """
        if not is_silo_value(ciphertext):
            logger.error(
                f'{_MISSING_PREFIX_DETAIL} error_code=%s field="%s" prefix="%s"',
                EncryptedFieldDecryptionError.code,
                field_name or "<unknown>",
                _CIPHERTEXT_PREFIX,
            )
            raise EncryptedFieldDecryptionError(
                GENERIC_DECRYPT_FAILED_USER_MESSAGE,
                detail=(f'field="{field_name or "<unknown>"}" prefix="{_CIPHERTEXT_PREFIX}" {_MISSING_PREFIX_DETAIL}'),
            )

        silo_ref = self._resolve_silo_uid(silo, key_set)
        try:
            aead_primitive = self._get_cached_aead(silo_ref)
        except MissingDekError:
            # Terminal on the read path — a missing DEK is never auto-provisioned
            # on decrypt, so this is the genuine error site.
            logger.error(_MISSING_FIELD_DEK_LOG + _key_set_log_field(silo_ref.key_set), silo_ref)
            raise
        try:
            ciphertext_bytes = unwrap_ciphertext(ciphertext)
            plaintext_bytes = aead_primitive.decrypt(ciphertext_bytes, aad)
        except Exception as exc:
            # Most decrypt failures fall into one of three buckets:
            #   1. Wrong silo context (row was reassigned, or query
            #      crossed silo boundaries without filtering).
            #   2. AAD mismatch: a column the field's aad= binds was
            #      changed on the row without re-encrypting the field.
            #   3. Database-level tampering or corruption.
            # The backend's error itself ("Decryption failed.") doesn't
            # distinguish them. Mention the likely causes so operators have
            # a starting point.
            scope = describe_decryption_scope(
                silo_ref=silo_ref,
                field_label=field_name or "<unknown>",
                row_identity=row_identity,
            )
            logger.error(
                'Could not decrypt a field value. error_code=%s %s detail="%s" hint="%s"',
                EncryptedFieldDecryptionError.code,
                scope,
                operator_error_text(exc),
                DECRYPT_FAILURE_HINT,
            )
            raise EncryptedFieldDecryptionError(
                GENERIC_DECRYPT_FAILED_USER_MESSAGE,
                detail=f"{scope} {operator_error_text(exc)} {DECRYPT_FAILURE_HINT}",
            ) from exc

        if enc_settings.LOG_DECRYPTS:
            scope = describe_decryption_scope(
                silo_ref=silo_ref,
                field_label=field_name or "<unknown>",
            )
            logger.info("An encrypted field value was decrypted. %s", scope)

        return plaintext_bytes.decode("utf-8")

    # ------------------------------------------------------------------
    # File keyset lifecycle (Streaming AEAD)
    # ------------------------------------------------------------------

    def generate_and_store_file_keyset(
        self,
        silo,
        *,
        key_set: str = DEFAULT_KEY_SET,
        trigger: str = lifecycle.TRIGGER_INDIRECT,
        reason: str = lifecycle.REASON_SILO_CREATED,
        user=user_context._UNSET,
        os_login_user: str = "",
        user_ip=user_context._UNSET,
    ) -> bool:
        """
        Generate a new file (Streaming AEAD) DEK for *silo*'s *key_set* via the
        configured crypto backend, encrypt it via the KMS adapter, and persist
        it as a DataEncryptionKey with purpose ``"file"``.
        """
        from .models import DataEncryptionKey

        return self._generate_and_store(
            DataEncryptionKey.PURPOSE_FILE,
            silo,
            key_set=key_set,
            trigger=trigger,
            reason=reason,
            user=user,
            os_login_user=os_login_user,
            user_ip=user_ip,
        )

    def generate_and_store_index_keyset(
        self,
        silo,
        *,
        key_set: str = DEFAULT_KEY_SET,
        trigger: str = lifecycle.TRIGGER_INDIRECT,
        reason: str = lifecycle.REASON_SILO_CREATED,
        user=user_context._UNSET,
        os_login_user: str = "",
        user_ip=user_context._UNSET,
    ) -> bool:
        """Generate this silo's blind index key for *key_set*, wrap it, and persist the row.

        Not from the crypto backend and not an AEAD — see :class:`SiloIndexKey` —
        but a key of the silo's own, wrapped by the silo's KEK, so destroying
        that KEK takes the silo's digests with its data.
        """
        from .models import DataEncryptionKey

        return self._generate_and_store(
            DataEncryptionKey.PURPOSE_INDEX,
            silo,
            key_set=key_set,
            trigger=trigger,
            reason=reason,
            user=user,
            os_login_user=os_login_user,
            user_ip=user_ip,
        )

    def _decrypt_to_streaming_aead(self, silo_ref: SiloRef) -> FilePrimitive:
        """Fetch file-purpose DataEncryptionKey, decrypt, return a file primitive."""
        from .models import DataEncryptionKey

        try:
            record = DataEncryptionKey.objects.get(
                **silo_filter(silo_ref),
                purpose=DataEncryptionKey.PURPOSE_FILE,
            )
        except DataEncryptionKey.DoesNotExist:
            # See _decrypt_to_aead: no log here; terminal callers log it.
            raise MissingDekError(
                GENERIC_ENCRYPT_DECRYPT_UNAVAILABLE_MESSAGE,
                detail=f"{_MISSING_FILE_DEK_DETAIL} {_MISSING_DEK_HINT}",
            ) from None

        self._check_dek_usable(record, silo_ref)
        return self._unwrap_primitive(
            DataEncryptionKey.PURPOSE_FILE,
            record.encrypted_keyset,
            record.kek,
            record.kek_key_version,
            silo_ref,
            backend_id=record.crypto_backend,
        )

    # ------------------------------------------------------------------
    # Streaming encrypt / decrypt (for files)
    # ------------------------------------------------------------------

    def encrypt_file(
        self, input_stream, output_stream, aad: bytes = b"", silo=None, key_set: str = DEFAULT_KEY_SET
    ) -> None:
        """
        Encrypt *input_stream* and write ciphertext to *output_stream*.

        Both arguments must be file-like objects (supporting ``read`` / ``write``).
        Uses the crypto backend's streaming AEAD so arbitrarily large files are
        handled without loading the full content into memory.

        If the silo has no file-purpose ``DataEncryptionKey`` yet
        and ``KEY_AUTO_PROVISION`` is enabled, a file DEK is generated on demand.
        """
        silo_ref = self._resolve_current_silo(silo, key_set)
        primitive = self._get_or_provision_streaming_aead(silo_ref)
        try:
            with primitive.new_encrypting_stream(_NonClosingWriter(output_stream), aad) as enc_stream:
                while True:
                    chunk = input_stream.read(64 * 1024)
                    if not chunk:
                        break
                    enc_stream.write(chunk)
        except Exception as exc:
            logger.error(
                'Failed to encrypt a file after the key was acquired. error_code=%s silo="%s" detail="%s"',
                EncryptedFileEncryptionError.code,
                silo_ref,
                operator_error_text(exc),
            )
            raise EncryptedFileEncryptionError(
                GENERIC_ENCRYPT_FAILED_USER_MESSAGE,
                detail=f'silo="{silo_ref}" {operator_error_text(exc)}',
            ) from exc

    def decrypt_file(
        self,
        input_stream,
        output_stream,
        aad: bytes = b"",
        silo=None,
        row_identity: str = "",
        field_name: str = "",
        key_set: str = DEFAULT_KEY_SET,
    ) -> None:
        """
        Decrypt *input_stream* and write plaintext to *output_stream*.

        Both arguments must be file-like objects.
        """
        with self.open_decrypting_stream(
            input_stream,
            aad,
            silo,
            row_identity=row_identity,
            field_name=field_name,
            key_set=key_set,
        ) as dec_stream:
            while True:
                chunk = dec_stream.read(64 * 1024)
                if not chunk:
                    break
                output_stream.write(chunk)

    def open_decrypting_stream(
        self,
        ciphertext_source,
        aad: bytes = b"",
        silo=None,
        row_identity: str = "",
        field_name: str = "",
        key_set: str = DEFAULT_KEY_SET,
    ):
        """
        Return a readable file-like stream that decrypts *ciphertext_source* on demand.

        The caller reads plaintext from the returned stream; the backend pulls
        ciphertext from *ciphertext_source* lazily, so only one segment of plaintext is
        materialized at a time. The caller owns *ciphertext_source* and must keep
        it open for the lifetime of the returned stream.

        ``row_identity`` is used by the storage error log only. It is intentionally
        omitted from the success log to avoid writing AAD-bound column values
        (which may contain PII) to high-volume audit entries.

        ``field_name`` can be provided by higher-level callers (for example,
        ``EncryptedFieldFile``) so file decrypt success entries identify the
        concrete field, matching field decrypt success logs.
        """
        silo_ref = self._resolve_silo_uid(silo, key_set)
        try:
            primitive = self._get_cached_streaming_aead(silo_ref)
        except MissingDekError:
            # Terminal on the read path (see decrypt()).
            logger.error(_MISSING_FILE_DEK_LOG + _key_set_log_field(silo_ref.key_set), silo_ref)
            raise

        if enc_settings.LOG_DECRYPTS:
            scope = describe_decryption_scope(
                silo_ref=silo_ref,
                field_label=field_name or "<unknown>",
            )
            logger.info("An encrypted file was decrypted. %s", scope)

        return primitive.new_decrypting_stream(ciphertext_source, aad)
