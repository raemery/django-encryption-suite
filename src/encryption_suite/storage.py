"""
Encrypted storage mixin for Django file fields.

Provides ``SiloEncryptedStorageMixin`` — a mixin that adds transparent
per-silo file encryption to any Django storage backend.  Compose it with
any storage class (``FileSystemStorage``, ``S3Boto3Storage``, etc.) to encrypt
file content on upload and decrypt on download — under the current silo's file
key, or the system silo's for a system key set file field, which names it on
the content it hands over.

It streams the content, so files of any size are handled without loading the
full content into memory.

Usage::

    from encryption_suite.storage import SiloEncryptedStorageMixin
    from storages.backends.s3boto3 import S3Boto3Storage

    class EncryptedS3Storage(SiloEncryptedStorageMixin, S3Boto3Storage):
        pass

    # Then use it on a model field:
    class Document(models.Model):
        file = models.FileField(storage=EncryptedS3Storage(bucket_name="private"))
"""

from __future__ import annotations

import io
import tempfile

from django.conf import settings
from django.core.files.base import File
from django.core.files.storage import FileSystemStorage
from django.utils.module_loading import import_string

from ._internal import (
    DECRYPT_FAILURE_HINT,
    _NonClosingWriter,
    describe_decryption_scope,
    describe_decryption_target,
    describe_storage_location,
    operator_error_text,
)
from ._logging import get_logger
from .conf import DEFAULT_KEY_SET, enc_settings
from .exceptions import (
    GENERIC_DECRYPT_FAILED_USER_MESSAGE,
    GENERIC_ENCRYPT_FAILED_USER_MESSAGE,
    EncryptedFileDecryptionError,
    EncryptedFileEncryptionError,
    EncryptedFileStorageError,
    EncryptionError,
)
from .fields import _resolve_log_silo_uid

logger = get_logger(__name__)


# _NonClosingWriter is imported from ._internal and re-used here; see its
# docstring for why it is needed.


class _DecryptingFile(File):
    """
    Django ``File`` wrapper around the crypto backend's decrypting stream.

    Holds a reference to the underlying ciphertext source so it stays open for
    the lifetime of the plaintext stream, and closes both on ``close()``.

    Streaming AEAD raises decryption errors lazily on ``read()`` rather
    than at stream-creation time. ``read()`` is wrapped here so an AAD mismatch
    or ciphertext corruption surfaces in the log with the row identity supplied
    by the caller (typically pk + AAD columns + storage path), matching the
    cross-reference format used for field decrypts.
    """

    def __init__(
        self,
        decrypting_stream,
        ciphertext_source,
        name,
        silo_uid: str = "",
        row_identity: str = "",
        field_label: str = "",
    ):
        super().__init__(decrypting_stream, name=name)
        self._ciphertext_source = ciphertext_source
        self._silo_uid = silo_uid
        self._row_identity = row_identity
        self._field_label = field_label

    def read(self, *args, **kwargs):
        try:
            return super().read(*args, **kwargs)
        except EncryptionError:
            # Already a typed package error (decryption failure, or a key
            # acquisition error surfaced from the streaming-AEAD load) — let it
            # propagate as-is, without re-logging or re-wrapping into a
            # decryption error it is not.
            raise
        except Exception as exc:
            scope = describe_decryption_scope(
                silo_ref=self._silo_uid,
                field_label=self._field_label,
                row_identity=self._row_identity,
                file_name="" if "file=" in self._row_identity else self.name,
            )
            logger.error(
                'Could not decrypt file. error_code=%s %s detail="%s" hint="%s"',
                EncryptedFileDecryptionError.code,
                scope,
                operator_error_text(exc),
                DECRYPT_FAILURE_HINT,
            )
            # Wrap in a typed exception so view-layer callers can catch a
            # stable type instead of raw backend errors.
            target = describe_decryption_target(
                field_label=self._field_label,
                row_identity=self._row_identity,
                file_name="" if "file=" in self._row_identity else self.name,
            )
            raise EncryptedFileDecryptionError(
                GENERIC_DECRYPT_FAILED_USER_MESSAGE,
                detail=f"{target}: {operator_error_text(exc)}",
            ) from exc

    def close(self):
        try:
            super().close()
        finally:
            if self._ciphertext_source is not None:
                self._ciphertext_source.close()
                self._ciphertext_source = None


class _EncryptedStorageMixin:
    """Encrypts on save and decrypts on open; a subclass says under which key.

    Everything here but :meth:`_encrypt_content` and :meth:`_decrypting_stream`
    moves bytes the backend holds, which is the same whichever key wrote them.
    """

    def _encrypt_content(self, content: File, destination, aad: bytes) -> None:
        """Write the ciphertext of *content* to *destination*."""
        raise NotImplementedError

    def _decrypting_stream(self, ciphertext) -> tuple[object, str]:
        """Return ``(plaintext stream, silo uid for the log)`` for *ciphertext*."""
        raise NotImplementedError

    def _save(self, name: str, content: File) -> str:
        """Encrypt file content, then delegate to the real storage backend.

        Ciphertext is written to a spool that spills from memory to disk
        above ``STORAGE_SPOOL_THRESHOLD`` so peak memory stays flat for
        large uploads.  Set ``STORAGE_SPOOL_ENABLED = False`` on runtimes
        where ``TMPDIR`` is backed by memory (Cloud Run, k8s
        ``emptyDir: {medium: Memory}``) — spooling there costs the same
        memory and only adds overhead.

        ``EncryptedFileField.pre_save`` attaches ``_encryption_suite_aad`` to the
        content object when the field declares ``aad=``, binding file content
        to the row's identity. Reads from the content
        object directly so the storage layer remains agnostic to model state.
        """
        if hasattr(content, "seek"):
            content.seek(0)
        aad = getattr(content, "_encryption_suite_aad", b"")

        with self._open_ciphertext_spool() as ciphertext_buf:
            try:
                self._encrypt_content(content, _NonClosingWriter(ciphertext_buf), aad)
            except Exception as exc:
                logger.error(
                    'A file could not be encrypted for storage, so nothing was written. error_code=%s %s detail="%s"',
                    getattr(exc, "code", "") or EncryptedFileEncryptionError.code,
                    describe_storage_location(self, name),
                    operator_error_text(exc),
                )
                raise
            ciphertext_buf.seek(0)
            return self._save_raw(name, File(ciphertext_buf, name=name))

    @staticmethod
    def _open_ciphertext_spool():
        """Return a writable, seekable file-like for ciphertext staging.

        Returns a :class:`tempfile.SpooledTemporaryFile` when spooling is
        enabled (the default), so large uploads spill from memory to disk.
        Returns an in-memory :class:`io.BytesIO` when spooling is disabled
        — appropriate for memory-backed tmpfs runtimes where spilling to
        disk is a no-op with extra syscalls.
        """
        if not enc_settings.STORAGE_SPOOL_ENABLED:
            return io.BytesIO()
        threshold = enc_settings.STORAGE_SPOOL_THRESHOLD
        if threshold is None:
            threshold = getattr(settings, "FILE_UPLOAD_MAX_MEMORY_SIZE", 2_621_440)
        return tempfile.SpooledTemporaryFile(
            max_size=threshold,
            dir=enc_settings.STORAGE_SPOOL_DIR,
        )

    def exists(self, name: str) -> bool:
        """Delegate to the backend, logging storage location on failure.

        Django's ``Storage.save`` calls ``exists`` (via ``get_available_name``)
        before ``_save`` runs, so a backend permission/connectivity error
        surfaces here — upstream of any encryption. Logging the storage
        location makes that class of failure (e.g. an S3 ``403`` on
        ``HeadObject`` from a misscoped key) self-describing instead of a bare
        backend traceback.
        """
        try:
            return super().exists(name)
        except EncryptedFileStorageError:
            raise
        except Exception as exc:
            logger.error(
                'Encrypted file existence check failed. error_code=%s operation=exists %s detail="%s"',
                EncryptedFileStorageError.code,
                describe_storage_location(self, name),
                operator_error_text(exc),
            )
            raise EncryptedFileStorageError(
                GENERIC_ENCRYPT_FAILED_USER_MESSAGE,
                detail=f"operation=exists {describe_storage_location(self, name)} {operator_error_text(exc)}",
            ) from exc

    def _open(self, name: str, mode: str = "rb") -> File:
        """Open ciphertext from the backend and return a streaming decrypting file.

        Used for direct ``storage.open(name)`` calls without an instance in
        scope. AAD-bound models access encrypted files through
        :class:`~encryption_suite.fields.EncryptedFieldFile`, which calls
        :meth:`_open_raw` and performs its own AAD-aware decryption — so this
        path runs with empty AAD and is correct only for a file field without
        ``aad=``.
        """
        encrypted_file = self._open_backend_ciphertext(name, mode)
        try:
            decrypting_stream, silo_uid = self._decrypting_stream(encrypted_file)
        except Exception:
            encrypted_file.close()
            raise
        return _DecryptingFile(decrypting_stream, encrypted_file, name, silo_uid=silo_uid)

    def _open_raw(self, name: str, mode: str = "rb") -> File:
        """Return raw ciphertext from the underlying backend without decrypting.

        :class:`~encryption_suite.fields.EncryptedFieldFile` calls this so it
        can wrap the ciphertext with a decrypting stream that carries AAD
        derived from the host instance.
        """
        return self._open_backend_ciphertext(name, mode)

    def _save_raw(self, name: str, content: File) -> str:
        """Write *content* — already ciphertext — to the backend, and return the stored name.

        The write counterpart of :meth:`_open_raw`. :meth:`_save` resolves the
        silo from context and encrypts under its current key, which is exactly
        what a data key rotation cannot use: the silo is fenced, and the blob is
        encrypted under the incoming key rather than the current one. A backend
        failure is normalized the same way :meth:`_save` normalizes it.
        """
        try:
            return super()._save(name, content)
        except Exception as exc:
            logger.error(
                'An encrypted file could not be written to storage. error_code=%s operation=write %s detail="%s"',
                EncryptedFileStorageError.code,
                describe_storage_location(self, name),
                operator_error_text(exc),
            )
            raise EncryptedFileStorageError(
                GENERIC_ENCRYPT_FAILED_USER_MESSAGE,
                detail=f"operation=write {describe_storage_location(self, name)} {operator_error_text(exc)}",
            ) from exc

    def _open_backend_ciphertext(self, name: str, mode: str = "rb") -> File:
        """Open raw ciphertext from the backend, normalizing failures.

        The read counterpart of the wrapping in :meth:`exists` / :meth:`_save`:
        a missing object or any backend error (S3 ``404``/``403``, connectivity)
        becomes an :class:`~encryption_suite.exceptions.EncryptedFileStorageError`.
        Callers that already handle ``EncryptionError`` — the
        :meth:`~encryption_suite.fields.EncryptedFieldFile.probe` degrade path
        and :func:`~encryption_suite.file_view_helpers.serve_encrypted_file` — then report
        the file as undisplayable instead of letting a raw backend error 500 the
        view. The storage location is logged for operators.
        """
        try:
            return super()._open(name, mode)
        except EncryptedFileStorageError:
            raise
        except Exception as exc:
            logger.error(
                'An encrypted file could not be read from storage. error_code=%s operation=read %s detail="%s"',
                EncryptedFileStorageError.code,
                describe_storage_location(self, name),
                operator_error_text(exc),
            )
            raise EncryptedFileStorageError(
                GENERIC_DECRYPT_FAILED_USER_MESSAGE,
                detail=f"operation=read {describe_storage_location(self, name)} {operator_error_text(exc)}",
            ) from exc


class SiloEncryptedStorageMixin(_EncryptedStorageMixin):
    """
    Storage mixin that encrypts files on save and decrypts on open.

    Uses the current silo's Streaming AEAD keyset (resolved from the
    context variable, identical to how encrypted model fields resolve their
    silo).

    Place this mixin **before** the storage backend in the MRO::

        class EncryptedS3(SiloEncryptedStorageMixin, S3Boto3Storage):
            pass

    The underlying storage backend sees only opaque ciphertext bytes.
    """

    def _get_engine(self):
        # Lazy import to avoid circular imports and premature settings access.
        from .registry import get_engine

        return get_engine()

    #: The key set a write that names no silo, and a bare ``open``, use. A field names its
    #: own on the content it hands over, so this matters to a file with no
    #: ``aad=`` opened by name.
    key_set = DEFAULT_KEY_SET

    def _encrypt_content(self, content: File, destination, aad: bytes) -> None:
        # The field attaches the silo its file is written under, which carries its key set;
        # content that names none is written under this storage's key set and the context's silo.
        silo = getattr(content, "_encryption_suite_silo", None)
        self._get_engine().encrypt_file(content, destination, aad=aad, silo=silo, key_set=self.key_set)

    def _decrypting_stream(self, ciphertext) -> tuple[object, str]:
        engine = self._get_engine()
        return engine.open_decrypting_stream(ciphertext, key_set=self.key_set), _resolve_log_silo_uid(engine)


class SiloEncryptedFileSystemStorage(SiloEncryptedStorageMixin, FileSystemStorage):
    """Last-resort default: encrypted storage on the local filesystem.

    Used only when neither the configured ``STORAGE_ALIAS`` nor
    the ``"default"`` alias is present in Django's ``STORAGES`` setting.
    Most projects should configure storage via ``STORAGES`` instead; see
    :func:`get_encrypted_storage`.
    """


_composed_storage_cache: dict[tuple[str, type], object] = {}


def get_encrypted_storage():
    """Return a storage instance that encrypts content for ``EncryptedFileField``.

    Resolution order:

    1. ``STORAGES[ENCRYPTION["STORAGE_ALIAS"]]`` — dedicated
       alias (default name ``"encrypted"``). Lets operators point
       sensitive/private files at a different bucket or backend than
       public media.
    2. ``STORAGES["default"]`` — fall back to Django's default backend.
    3. :class:`SiloEncryptedFileSystemStorage` — local disk,
       used only when neither alias is configured.

    The resolved backend class is composed at runtime with
    :class:`SiloEncryptedStorageMixin` via dynamic subclassing, so
    consumers never write ``class EncryptedS3(...)`` boilerplate. All
    ``OPTIONS`` from the ``STORAGES`` entry are passed to the backend's
    ``__init__``.
    """
    return _resolve_encrypted_storage(SiloEncryptedStorageMixin, "Encrypted") or SiloEncryptedFileSystemStorage()


def _resolve_encrypted_storage(mixin: type, name_prefix: str):
    """Return the configured backend with *mixin* composed onto it, or ``None`` if none is configured."""
    storages = getattr(settings, "STORAGES", {}) or {}
    alias = enc_settings.STORAGE_ALIAS

    for candidate in (alias, "default"):
        entry = storages.get(candidate)
        if not entry or not entry.get("BACKEND"):
            continue
        return _build_encrypted_storage(entry, mixin, name_prefix)
    return None


def _build_encrypted_storage(entry: dict, mixin: type, name_prefix: str):
    """Compose *mixin* onto the configured backend class and instantiate it
    with the alias's ``OPTIONS``.

    The composed class is cached per backend and mixin so repeated field access
    does not rebuild the type each time.
    """
    backend_path = entry["BACKEND"]
    options = entry.get("OPTIONS") or {}

    composed = _composed_storage_cache.get((backend_path, mixin))
    if composed is None:
        backend_cls = import_string(backend_path)
        # If the configured backend already includes the mixin (e.g. the
        # user pointed STORAGES at SiloEncryptedFileSystemStorage
        # directly), don't double-wrap — just use it.
        if issubclass(backend_cls, mixin):
            composed = backend_cls
        else:
            composed = type(f"{name_prefix}{backend_cls.__name__}", (mixin, backend_cls), {})
        _composed_storage_cache[(backend_path, mixin)] = composed

    return composed(**options)
