"""
Admin test console primitives — isolated encryption round-trip path.

The test console lets an operator validate the full KMS / crypto-backend
pipeline from the admin UI without touching any real tenant's data encryption
key. It uses **the configured crypto backend** (``CRYPTO_BACKEND``), so it
exercises whatever engine the deployment actually uses. It is designed so that a
compromise of the admin UI cannot turn into a decryption oracle for production
ciphertext.

Two layers of isolation enforce that:

1. **Sentinel UIDs.** All test-console keys are stored under reserved silo UIDs
   (``ENCRYPTION["TEST_CONSOLE_FIELD_UID"]`` / ``["TEST_CONSOLE_FILE_UID"]``) and
   reach the KMS under a third (``["TEST_CONSOLE_KEK_UID"]``). The configured silo
   adapter must never resolve any real silo to any of the three.
   :func:`assert_sentinel_not_producible_no_db` runs at app-ready time against
   the current request context (no DB), and
   :func:`assert_sentinel_not_producible` runs lazily on first admin
   test-console view access to cover the DB-enumerating branch.

2. **Purpose partition.** Test-console keys use
   :attr:`~encryption_suite.models.DataEncryptionKey.PURPOSE_TEST`.
   Field decrypts filter on ``PURPOSE_FIELD``, file decrypts on ``PURPOSE_FILE``,
   test-console operations on ``PURPOSE_TEST`` — purposes never cross.
"""

from __future__ import annotations

import io

from . import user_context
from ._logging import get_logger
from .adapters.key_stores.base import KmsMetadata
from .conf import DEFAULT_KEY_SET
from .engine import kms_error_guard
from .exceptions import EncryptionError
from .lifecycle import TRIGGER_DIRECT
from .models import DataEncryptionKey
from .registry import get_engine

logger = get_logger(__name__)


# Reserved silo UIDs used exclusively by the admin test console, read from
# settings (ENCRYPTION["TEST_CONSOLE_FIELD_UID"] / ["TEST_CONSOLE_FILE_UID"] /
# ["TEST_CONSOLE_KEK_UID"]). Real silos must never resolve to any of them.
#
# Two *row* keys rather than one: the field slot and the file slot each hold a
# DEK of a different kind. Colocating them under the same (key set, uid, purpose)
# row would force one to overwrite the other whenever the operator switched
# modes — breaking the "download ciphertext now, upload to decrypt later" flow.
# Separate UIDs keep both persisted independently. Each key set the console
# tests gets its own pair, so testing one key set leaves another's test keys in
# place. The row keys never reach a KMS.
#
# A third UID for the KMS calls, so both tests share one key encryption key
# instead of provisioning one each, and its name says what it is rather than
# naming one of the two tests it serves. See _crypto_uid().
#
# The KEK UID default is lowercase-alphanumeric only so it passes through every
# KMS adapter's name sanitizer unchanged, and short enough that a templated key
# name stays within the tightest provider cap (Infisical: 32); override the
# defaults only if a real UID could collide.


def _field_uid() -> str:
    from .conf import enc_settings

    return enc_settings.TEST_CONSOLE_FIELD_UID


def _file_uid() -> str:
    from .conf import enc_settings

    return enc_settings.TEST_CONSOLE_FILE_UID


def _wrap_for_console(kms_adapter, plaintext_dek: bytes, key_set: str):
    """Wrap *plaintext_dek* under the console's KEK on *kms_adapter*; return ``(ciphertext, metadata)``.

    An env store resolves every UID to its one shared KEK, so its test key is
    recorded under :func:`~encryption_suite.conf.env_test_kek_name` instead —
    the same material, kept off the row real silos use.
    """
    from .conf import env_test_kek_name, is_env_store

    ref = _crypto_ref(key_set)
    with kms_error_guard("key wrap", ref, kms_adapter):
        encrypted_keyset_bytes, metadata = kms_adapter.encrypt_key(plaintext_dek, ref)
    metadata.kms_name = kms_adapter.kms_name
    if is_env_store(kms_adapter.kms_name):
        metadata.kek_resource_name = env_test_kek_name()
    return encrypted_keyset_bytes, metadata


def _crypto_ref(key_set: str):
    """The silo reference the console's KMS calls are made under for *key_set*.

    The console's UID, under the key set being tested, so the console asks the
    strategy the same question a field in that key set would. A store whose
    strategy names no key cannot hold a console key at all, and reaches the caller
    as the configuration error the strategy raises.
    """
    from .silo_ref import SiloRef

    return SiloRef(key_set, _crypto_uid())


def _crypto_uid() -> str:
    """The single silo UID the console's KMS calls are made under.

    Both console tests wrap and unwrap through this one UID, so a deployment
    provisions **one** test key encryption key rather than one per test. It is its
    own setting rather than a reuse of a row key, so the key's name on the KMS
    says what it is instead of naming one of the two tests it serves.

    The two sentinel UIDs remain the *row* keys — a data encryption key row is
    unique on ``(silo_uid, purpose)`` and both console rows share
    ``PURPOSE_TEST``, so they still need distinct UIDs to coexist.

    That makes a console row's ``silo_uid`` its row key, not the UID its crypto is
    bound to. Nothing outside the console reads it as the latter: the engine
    cannot (the purpose partition keeps ``PURPOSE_TEST`` off the field/file
    paths), ``setup_encryption_keys`` iterates real silos which never yield a
    sentinel, reconcile only annotates, and ``reencrypt_keys`` skips test rows
    like every other general command. Keep that true for anything added later.
    """
    from .conf import enc_settings

    return enc_settings.TEST_CONSOLE_KEK_UID


def _reserved_test_uids() -> frozenset[str]:
    """Every sentinel UID the console owns, resolved live from settings.

    Defined in :mod:`encryption_suite.conf` so the KEK provisioners can recognize
    a console key without importing the admin layer; re-exported here because
    this is where it reads naturally.
    """
    from .conf import reserved_test_uids

    return reserved_test_uids()


# Size caps enforced by the admin test console views.
MAX_TEST_PLAINTEXT_BYTES = 1 * 1024 * 1024  # 1 MB
MAX_TEST_FILE_BYTES = 10 * 1024 * 1024  # 10 MB

# Fixed payload used by every console test button. Small, UTF-8, and identical
# across tests so a round-trip mismatch points at the crypto path, not the input.
TEST_CONSOLE_PLAINTEXT = b"encryption_suite console test payload"


class ConsoleSentinelLeakError(RuntimeError):
    """Raised when the configured silo adapter can produce the sentinel UID."""


def assert_sentinel_not_producible_no_db(silo_adapter) -> None:
    """Verify the current-context silo does not resolve to the sentinel UID.

    Safe to call during ``apps.ready`` — touches only the active request
    context (a ContextVar), never the database.
    """
    try:
        current = silo_adapter.get_current_silo()
    except Exception:
        current = None
    if current is None:
        return
    try:
        uid = silo_adapter.get_silo_uid(current)
    except Exception:
        return
    if uid in _reserved_test_uids():
        raise ConsoleSentinelLeakError(
            f"Silo adapter {type(silo_adapter).__name__} produced reserved test-console UID '{uid}'."
        )


def assert_sentinel_not_producible(silo_adapter) -> None:
    """Full defense-in-depth check: current context + DB enumeration.

    Intended to run lazily (e.g. on first admin test-console view access) rather
    than at app init, so the DB-touching enumeration does not trip Django's
    "database access during app initialization" warning.

    Enumeration failures (database not reachable, adapter does not expose
    ``model_label``) are swallowed — this is defense-in-depth, not a replacement
    for the purpose-partition.
    """
    assert_sentinel_not_producible_no_db(silo_adapter)

    # Adapters that cannot enumerate (supports_enumeration is False) simply skip
    # the DB sweep — this is a belt-and-suspenders check, not the boundary.
    if not silo_adapter.supports_enumeration:
        return

    try:
        silos = silo_adapter.iter_silos()
    except Exception as exc:  # pragma: no cover - defensive
        logger.debug('The test-console sentinel check was skipped. detail="%s"', exc)
        return

    try:
        for gk in silos:
            try:
                uid = silo_adapter.get_silo_uid(gk)
            except Exception:
                continue
            if uid in _reserved_test_uids():
                raise ConsoleSentinelLeakError(
                    f"Silo adapter {type(silo_adapter).__name__} "
                    f"produced reserved test-console UID '{uid}' "
                    f"for a configured silo."
                )
    except ConsoleSentinelLeakError:
        raise
    except Exception as exc:  # pragma: no cover - defensive
        logger.debug('The test-console sentinel check was skipped. stage=iteration detail="%s"', exc)


class _NonClosingBytesIO(io.BytesIO):
    """BytesIO whose close() is a no-op.

    Some encrypting-stream implementations (e.g. Tink's) call close() on the
    ciphertext destination when they exit, after writing the final auth tag. A
    plain BytesIO would then reject getvalue(). Swallow the close so we can read
    the full ciphertext after the stream is finalized.
    """

    def close(self):  # noqa: D401 - intentional no-op
        pass


# ---------------------------------------------------------------------------
# Ephemeral path: in-memory round trip (no KMS, no DB)
# ---------------------------------------------------------------------------


def ephemeral_aead_roundtrip(plaintext: bytes, aad: bytes = b"") -> dict:
    """Generate a throwaway field DEK via the backend, encrypt, decrypt."""
    from .registry import get_crypto_backend

    backend = get_crypto_backend()
    dek = backend.generate_field_dek()
    primitive = backend.load_field_primitive(dek)
    ciphertext = primitive.encrypt(plaintext, aad)
    recovered = primitive.decrypt(ciphertext, aad)
    return {
        "keyset_bytes": dek,
        "ciphertext": ciphertext,
        "plaintext": recovered,
        "matches": recovered == plaintext,
    }


def ephemeral_streaming_roundtrip(plaintext: bytes, aad: bytes = b"") -> dict:
    """Generate a throwaway file DEK via the backend, encrypt-then-decrypt in memory."""
    from .registry import get_crypto_backend

    backend = get_crypto_backend()
    dek = backend.generate_file_dek()
    primitive = backend.load_file_primitive(dek)
    ct_buf = _NonClosingBytesIO()
    with primitive.new_encrypting_stream(ct_buf, aad) as enc:
        enc.write(plaintext)
    ciphertext = ct_buf.getvalue()

    ct_read = io.BytesIO(ciphertext)
    with primitive.new_decrypting_stream(ct_read, aad) as dec:
        recovered = dec.read()
    return {
        "keyset_bytes": dek,
        "ciphertext": ciphertext,
        "plaintext": recovered,
        "matches": recovered == plaintext,
    }


# ---------------------------------------------------------------------------
# Full path: full KMS path, isolated by sentinel UID + PURPOSE_TEST
# ---------------------------------------------------------------------------


def _ensure_test_aead(kms_adapter, kek_provisioner, key_set, *, user=None, user_ip=None):
    """Return ``(primitive, created)`` for the PURPOSE_TEST field key of *key_set*.

    Creates the row (and provisions the KEK, if a provisioner is configured) on
    first call. Each key set has its own row, under :func:`_field_uid`. If the
    stored row was produced by a different crypto backend, it is discarded and
    recreated — the test key is disposable.
    """
    from .registry import get_crypto_backend

    backend = get_crypto_backend()
    created = False
    record = (
        DataEncryptionKey.objects.filter(
            key_set=key_set,
            silo_uid=_field_uid(),
            purpose=DataEncryptionKey.PURPOSE_TEST,
        )
        .select_related("kek")
        .first()
    )
    if record is not None and record.crypto_backend != backend.backend_id:
        _discard_test_record(record)
        record = None
    if record is None:
        record = _create_test_aead_record(kms_adapter, kek_provisioner, backend, key_set, user=user, user_ip=user_ip)
        created = True

    metadata = KmsMetadata(
        kek_resource_name=record.kek.kek_resource_name,
        kms_provider=kms_adapter.kms_provider,
        kms_name=record.kek.key_store,
        kek_key_version=record.kek_key_version,
    )
    ref = _crypto_ref(key_set)
    with kms_error_guard("key unwrap", ref, kms_adapter):
        plaintext_dek = kms_adapter.decrypt_key(bytes(record.encrypted_keyset), metadata, ref)
    primitive = backend.load_field_primitive(plaintext_dek)
    del plaintext_dek
    return primitive, created


def _ensure_test_kek(kms_adapter, kek_provisioner, key_set, *, user=None, user_ip=None) -> tuple[str, bool]:
    """Provision the console's KEK through the engine's own ensure funnel.

    Shares the engine's ensure funnel rather than calling the provisioner
    directly. That funnel records a provider-reported pending deletion on the
    key's row, logs the refusal with its error-code slug, and turns a raw
    provider error into :class:`KekNotProvisionedError` — none of which a second
    copy of the call did.
    """
    from .engine import ensure_kek_provisioned

    return ensure_kek_provisioned(kms_adapter, kek_provisioner, _crypto_ref(key_set), user=user, user_ip=user_ip)


def _create_test_aead_record(
    kms_adapter, kek_provisioner, backend, key_set, *, user=None, user_ip=None
) -> DataEncryptionKey:
    _kek_id, created_kek = _ensure_test_kek(kms_adapter, kek_provisioner, key_set, user=user, user_ip=user_ip)

    plaintext_dek = backend.generate_field_dek()
    try:
        encrypted_keyset_bytes, metadata = _wrap_for_console(kms_adapter, plaintext_dek, key_set)
    finally:
        del plaintext_dek

    record, was_created = DataEncryptionKey.objects.update_or_create(
        key_set=key_set,
        silo_uid=_field_uid(),
        purpose=DataEncryptionKey.PURPOSE_TEST,
        defaults={
            "silo_label": "admin_test_console",
            "encrypted_keyset": encrypted_keyset_bytes,
            "kek": _kek_row_for_console(metadata, created_kek, key_set, user=user, user_ip=user_ip),
            "kek_key_version": metadata.kek_key_version,
            "crypto_backend": backend.backend_id,
            "algorithm": backend.algorithm_id(DataEncryptionKey.PURPOSE_FIELD),
        },
    )
    _record_event_for_test_record(record, was_created, user=user, user_ip=user_ip)
    return record


def _kek_row_for_console(metadata, created_kek, key_set, *, user=None, user_ip=None):
    """Resolve the console's key encryption key row, clearing a stale orphan flag.

    The console provisions its own keys rather than going through
    ``EncryptionEngine._store_keyset``, so it needs the same annotation fix that
    path applies: a key discovered by reconcile before any test row existed is
    flagged orphaned, and stays flagged until the next reconcile unless the act
    that gives it a keyset clears it.

    Reconcile counts a test key encryption key as *expected* for as long as a
    ``PURPOSE_TEST`` row names it, so clearing here agrees with what the next
    pass would conclude — it just does not make the operator wait for it.
    """
    engine = get_engine()
    # The trigger and the identity thread all the way into the engine: the
    # console holds a request user, and an internal resolve returns nobody under
    # the default scope.
    row = engine._kek_row(metadata, created_kek, trigger=TRIGGER_DIRECT, user=user, user_ip=user_ip)
    engine._clear_kek_orphan(row, _crypto_ref(key_set), trigger=TRIGGER_DIRECT, user=user, user_ip=user_ip)
    return row


def _record_event_for_test_record(record, was_created: bool, *, user=None, user_ip=None) -> None:
    """Append the ledger event for a test key the console just wrote.

    The console drives the KMS adapter directly rather than through the engine,
    so it must write this itself, or a test key would live and die with no
    history at all.

    ``created`` for a fresh row, ``reencrypted`` for one whose keyset was replaced
    under the same sentinel UID. Best-effort: a bookkeeping failure must not
    break the console test that prompted it.
    """
    from . import lifecycle

    event = lifecycle.EVENT_CREATED if was_created else lifecycle.EVENT_REENCRYPTED
    try:
        record.record_event(event, trigger=TRIGGER_DIRECT, user=user, user_ip=user_ip)
    except Exception as exc:
        from ._internal import operator_error_text

        logger.warning(
            "The test key was written but its event could not be appended to the ledger, so its "
            'history begins with a gap. event=%s key_stores=%s silo="%s" purpose=%s detail="%s" %s',
            event,
            record.kek.key_store,
            record.silo_uid,
            record.purpose,
            operator_error_text(exc),
            user_context.identity_tail(user=user, user_ip=user_ip),
        )


def _discard_test_record(record) -> None:
    """Hard-delete a test row whose keyset a different crypto backend produced.

    The row is disposable — its keyset cannot be read by the running backend, so
    there is nothing to preserve. Its ledger events go first: they are PROTECT
    FKs, so the row cannot be removed while any event still points at it. This
    is the same order the console's cleanup uses, and the same deliberate
    exception to the package's rows-are-never-deleted rule.
    """
    from django.db import transaction

    from .models import KeyLifecycleEvent

    with transaction.atomic():
        KeyLifecycleEvent.objects.filter(dek=record).delete()
        record.delete()


def _ensure_test_streaming(kms_adapter, kek_provisioner, key_set, *, user=None, user_ip=None):
    """Return ``(primitive, created)`` for the PURPOSE_TEST file key of *key_set*.

    Stored under :func:`_file_uid` (distinct from the field sentinel) so both
    persist side-by-side, enabling the download-then-upload flow. Recreated if the
    stored row's backend differs from the current one.
    """
    from .registry import get_crypto_backend

    backend = get_crypto_backend()
    created = False
    record = (
        DataEncryptionKey.objects.filter(
            key_set=key_set,
            silo_uid=_file_uid(),
            purpose=DataEncryptionKey.PURPOSE_TEST,
        )
        .select_related("kek")
        .first()
    )
    if record is not None and record.crypto_backend != backend.backend_id:
        _discard_test_record(record)
        record = None
    if record is None:
        record = _create_test_streaming_record(
            kms_adapter, kek_provisioner, backend, key_set, user=user, user_ip=user_ip
        )
        created = True

    metadata = KmsMetadata(
        kek_resource_name=record.kek.kek_resource_name,
        kms_provider=kms_adapter.kms_provider,
        kms_name=record.kek.key_store,
        kek_key_version=record.kek_key_version,
    )
    ref = _crypto_ref(key_set)
    with kms_error_guard("key unwrap", ref, kms_adapter):
        plaintext_dek = kms_adapter.decrypt_key(bytes(record.encrypted_keyset), metadata, ref)
    primitive = backend.load_file_primitive(plaintext_dek)
    del plaintext_dek
    return primitive, created


def _create_test_streaming_record(
    kms_adapter, kek_provisioner, backend, key_set, *, user=None, user_ip=None
) -> DataEncryptionKey:
    _kek_id, created_kek = _ensure_test_kek(kms_adapter, kek_provisioner, key_set, user=user, user_ip=user_ip)

    plaintext_dek = backend.generate_file_dek()
    try:
        encrypted_keyset_bytes, metadata = _wrap_for_console(kms_adapter, plaintext_dek, key_set)
    finally:
        del plaintext_dek

    record, was_created = DataEncryptionKey.objects.update_or_create(
        key_set=key_set,
        silo_uid=_file_uid(),
        purpose=DataEncryptionKey.PURPOSE_TEST,
        defaults={
            "silo_label": "admin_test_console_stream",
            "encrypted_keyset": encrypted_keyset_bytes,
            "kek": _kek_row_for_console(metadata, created_kek, key_set, user=user, user_ip=user_ip),
            "kek_key_version": metadata.kek_key_version,
            "crypto_backend": backend.backend_id,
            "algorithm": backend.algorithm_id(DataEncryptionKey.PURPOSE_FILE),
        },
    )
    _record_event_for_test_record(record, was_created, user=user, user_ip=user_ip)
    return record


def full_aead_roundtrip(
    kms_adapter,
    kek_provisioner,
    plaintext: bytes,
    aad: bytes = b"",
    *,
    key_set: str = DEFAULT_KEY_SET,
    user=None,
    user_ip=None,
) -> dict:
    """Full-path field round trip (KMS-wrapped DEK) against the isolated PURPOSE_TEST key of *key_set*."""
    primitive, created = _ensure_test_aead(kms_adapter, kek_provisioner, key_set, user=user, user_ip=user_ip)
    ciphertext = primitive.encrypt(plaintext, aad)
    try:
        recovered = primitive.decrypt(ciphertext, aad)
    except Exception as exc:
        raise ValueError("not a test ciphertext") from exc
    return {
        "ciphertext": ciphertext,
        "plaintext": recovered,
        "matches": recovered == plaintext,
        "created_key": created,
    }


def full_streaming_roundtrip(
    kms_adapter,
    kek_provisioner,
    plaintext: bytes,
    aad: bytes = b"",
    *,
    key_set: str = DEFAULT_KEY_SET,
    user=None,
    user_ip=None,
) -> dict:
    """Full-path file round trip (KMS-wrapped DEK) against the isolated PURPOSE_TEST key of *key_set*."""
    primitive, created = _ensure_test_streaming(kms_adapter, kek_provisioner, key_set, user=user, user_ip=user_ip)
    ct_buf = _NonClosingBytesIO()
    with primitive.new_encrypting_stream(ct_buf, aad) as enc:
        enc.write(plaintext)
    ciphertext = ct_buf.getvalue()

    ct_read = io.BytesIO(ciphertext)
    try:
        with primitive.new_decrypting_stream(ct_read, aad) as dec:
            recovered = dec.read()
    except Exception as exc:
        raise ValueError("not a test ciphertext") from exc
    return {
        "ciphertext": ciphertext,
        "plaintext": recovered,
        "matches": recovered == plaintext,
        "created_key": created,
    }


# ---------------------------------------------------------------------------
# File storage reachability (read-only)
# ---------------------------------------------------------------------------

# Probe key for the read-only storage check. Never written or deleted — passed
# to exists() only, so a backend that answers (even "no") proves reachability.
_TEST_STORAGE_PROBE_KEY = "encryption_suite_test/reachability-probe"


def describe_storage_target() -> dict:
    """Return ``{"backend", "location"}`` for the configured encrypted storage.

    Network-free: instantiates the configured backend and reads its identifying
    attributes (bucket / container / filesystem location) for display in the
    console's storage box. Does not contact the backend.
    """
    from ._internal import _STORAGE_CONTAINER_ATTRS
    from .storage import get_encrypted_storage

    storage = get_encrypted_storage()
    location = next(
        (value for attr in _STORAGE_CONTAINER_ATTRS if (value := getattr(storage, attr, None))),
        None,
    )
    return {"backend": type(storage).__name__, "location": str(location) if location else ""}


def storage_reachable() -> None:
    """Read-only reachability probe for the configured encrypted storage.

    Issues a single ``exists()`` check (a HEAD for object stores) against a key
    that will not exist. A backend that answers — even with "no" — is reachable
    and its credentials are valid. Any raised error (auth, missing bucket,
    connectivity) propagates to the caller, which treats it as unreachable.
    Nothing is written, read, or deleted.
    """
    from .storage import get_encrypted_storage

    storage = get_encrypted_storage()
    storage.exists(_TEST_STORAGE_PROBE_KEY)


def test_key_kms_names() -> list[str]:
    """Every KMS that holds one of the console's test keys, sorted."""
    return sorted(
        set(
            DataEncryptionKey.objects.filter(
                silo_uid__in=_reserved_test_uids(),
                purpose=DataEncryptionKey.PURPOSE_TEST,
            ).values_list("kek__key_store", flat=True)
        )
    )


def delete_test_key() -> dict:
    """Delete the admin test-console keys: delete each KEK that is
    provably the console's own, then delete the PURPOSE_TEST DEK rows.

    Operates on the KEKs **named by the provisioned DEK rows** (the stored KMS
    name and ``kek_resource_name``), de-duplicated — multiple test DEK rows can
    name the same KEK (a shared strategy, or the env key store, which wraps every
    DEK with one key), so each distinct KEK is considered once, through the
    adapter and provisioner of the KMS that holds it. A KEK with no test row is
    the reconciliation feature's job, not this delete's.

    For each distinct KEK it is deleted only when **all** of these hold
    (see :func:`encryption_suite.deletion.evaluate_deletion` for the first three —
    the deletion gates):

    1. the strategy classifies it ``silo_exclusive`` (never a shared/opaque KEK),
    2. the provisioner ``supports_delete``,
    3. the key name carries this deployment's owner prefix, and
    4. **no other (non-test) DEK row references the same KEK** — the in-use guard,
       which blocks deleting a key a real silo still depends on.

    Otherwise the KEK is retained at its store.

    Deleting here is a **hard delete** — the ``DataEncryptionKey`` rows, the
    ``KeyEncryptionKey`` rows, and every ``KeyLifecycleEvent`` event pointing at them are removed
    outright, leaving a clean slate for the next run. This is a deliberate
    exception to the package's rows-are-never-deleted rule, and it applies
    **only** to the console's isolated sentinel keys: they hold no tenant data,
    and their events are noise in a ledger whose job is proving what happened to
    real silos' keys. Never generalize it to a real silo's rows, whose tombstone
    and ledger are the audit record.

    A ``KeyEncryptionKey`` row is removed when its KEK was deleted at the
    provider — including when the provider merely *scheduled* the deletion (AWS,
    GCP, Azure all impose a window) — and when a gate refused the deletion for
    any reason but the in-use guard. A console key leaves no tombstone either
    way: a row kept past this point would outlive every real record of the key,
    since the DEK rows and events are gone in the same transaction, and nothing
    would ever revisit it. A key that still exists with no row is still
    reported: reconcile derives the console's KEK names from the sentinel UIDs,
    not from rows, and lists a leftover as a test key. On an env store the row
    is the console's own record of the store's one key, so removing it removes
    nothing else.

    Two outcomes keep the row. An in-use refusal means the row is not the
    console's: the console's UID resolved to a key a real silo uses (a shared
    strategy on a KMS store, or a ``KEK_MAP`` entry naming a real silo's key), and
    that row is the record of a live key real data depends on. A provider error
    leaves the key in an unknown state, and the row is the only record of it. A
    row still referenced by anything else is kept as well, rather than rolling
    back the cleanup. Each outcome carries ``record_deleted``. Returns
    ``{"deks_deleted": int, "deks_retained": int, "keks": [per-KEK outcome, ...],
    "key_stores": [each key store whose test keys were processed]}``.
    """
    from django.db import transaction
    from django.db.models import ProtectedError

    from .models import KeyEncryptionKey, KeyLifecycleEvent

    # De-dupe the console's rows by the KEK they reference — its key store and
    # resource name, which together identify a KeyEncryptionKey row. Keep one
    # representative silo_uid per KEK for the disposition/AAD lookup.
    by_kek: dict[tuple[str, str], tuple[str, str]] = {}
    for key_set, silo_uid, kek_resource_name, key_store in (
        DataEncryptionKey.objects.filter(
            silo_uid__in=_reserved_test_uids(),
            purpose=DataEncryptionKey.PURPOSE_TEST,
        )
        .order_by("key_set", "silo_uid")
        .values_list("key_set", "silo_uid", "kek__kek_resource_name", "kek__key_store")
    ):
        by_kek.setdefault((key_store, kek_resource_name), (key_set, silo_uid))

    keks = [
        _delete_one_test_kek(key_store, key_set, silo_uid, kek_resource_name)
        for (key_store, kek_resource_name), (key_set, silo_uid) in sorted(by_kek.items())
    ]

    with transaction.atomic():
        test_rows = DataEncryptionKey.objects.filter(
            silo_uid__in=_reserved_test_uids(),
            purpose=DataEncryptionKey.PURPOSE_TEST,
        )
        dek_total = test_rows.count()
        # Events first: KeyLifecycleEvent's FKs are PROTECT, so a key row cannot be
        # deleted while any event still points at it.
        KeyLifecycleEvent.objects.filter(dek__in=test_rows).delete()
        _total, per_model = test_rows.delete()
        deks_deleted = per_model.get(DataEncryptionKey._meta.label, 0)

        for kek in keks:
            if not _forgets_kek_row(kek):
                continue
            kms_rows = KeyEncryptionKey.objects.filter(
                key_store=kek["key_store"],
                kek_resource_name=kek["kek_resource_name"],
            )
            # The console's cleanup exception: its rows and their history go,
            # scheduled or immediate. These sentinel keys hold no tenant data,
            # and their events are noise in a ledger whose job is proving what
            # happened to real silos' keys. A savepoint per row, so a row that
            # something else still references stays without undoing the rest.
            try:
                with transaction.atomic():
                    KeyLifecycleEvent.objects.filter(kek__in=kms_rows).delete()
                    kms_rows.delete()
            except ProtectedError:
                logger.warning(
                    "A test key encryption key's record was kept because another record still "
                    'references it. key_store=%s kek="%s"',
                    kek["key_store"],
                    kek["kek_resource_name"],
                )
                continue
            kek["record_deleted"] = True

    return {
        "deks_deleted": deks_deleted,
        "deks_retained": dek_total - deks_deleted,
        "keks": keks,
        "key_stores": sorted({key_store for key_store, _name in by_kek}),
    }


def _forgets_kek_row(kek: dict) -> bool:
    """Whether the console removes the ``KeyEncryptionKey`` row behind one per-KEK outcome.

    Yes once the key is deleted, and yes on any refusal but the in-use guard
    (see :func:`delete_test_key`). No on a provider error.
    """
    from .deletion import RETAIN_IN_USE

    if kek["deleted"]:
        return True
    return bool(kek["retained_reason"]) and kek["retained_reason"] != RETAIN_IN_USE


def _delete_one_test_kek(key_store, key_set, silo_uid, kek_resource_name) -> dict:
    """Decide and perform delete/retain for one distinct test KEK on key store *key_store*.

    *key_set* is the key set of one console row that names the KEK, and decides how the
    strategy classifies it.
    """
    from .conf import kms_block
    from .deletion import RETAIN_IN_USE, RETAIN_NO_PROVISIONER, evaluate_deletion
    from .registry import get_kek_provisioner, get_kms_adapter

    result = {
        "silo_uid": silo_uid,
        "key_store": key_store,
        "kek_resource_name": kek_resource_name,
        "deleted": False,
        "scheduled": False,
        "effective_at": None,
        "retained_reason": None,
        "error": None,
        "record_deleted": False,
    }

    # A KMS no block names has no provisioner to delete through.
    if kms_block(key_store) is None:
        result["retained_reason"] = RETAIN_NO_PROVISIONER
        return result
    kms_adapter = get_kms_adapter(key_store)
    kek_provisioner = get_kek_provisioner(key_store)
    if kek_provisioner is None:
        result["retained_reason"] = RETAIN_NO_PROVISIONER
        return result

    # In-use guard: never delete a KEK any other (non-test) DEK row references.
    if (
        DataEncryptionKey.objects.filter(kek__key_store=key_store, kek__kek_resource_name=kek_resource_name)
        .exclude(purpose=DataEncryptionKey.PURPOSE_TEST)
        .exists()
    ):
        result["retained_reason"] = RETAIN_IN_USE
        return result

    # The prefix is matched against the stored KEK name, so it is canonicalized
    # into the same name space the adapter records (see canonical_kek_name).
    strategy = kms_adapter.kek_strategy
    ref = _crypto_ref(key_set)
    prefix = strategy.owner_prefix()
    owner_prefix = kms_adapter.canonical_kek_name(prefix) if prefix else None
    owned_names = kms_adapter.owned_mapped_kek_names()
    eligible, reason = evaluate_deletion(
        strategy.kek_disposition(ref), owner_prefix, kek_provisioner, kek_resource_name, owned_names=owned_names
    )
    if not eligible:
        result["retained_reason"] = reason
        return result

    try:
        outcome = kek_provisioner.delete_kek(kek_resource_name, ref, owner_prefix=owner_prefix, owned_names=owned_names)
        result["deleted"] = True
        # Most providers only *schedule*: the key lives on for their recovery
        # window and its alias keeps resolving, so it is still listed by
        # enumeration. Carry that through — removing the row here would destroy
        # the only local evidence a deletion is pending, and reconcile would then
        # see a listed key backing no silo and correctly call it an orphan.
        result["scheduled"] = outcome.scheduled
        result["effective_at"] = outcome.effective_at
    except EncryptionError as exc:
        result["error"] = getattr(exc, "detail", None) or str(exc)
    return result
