"""
Converting one worklist item during a data key rotation.

An item is a field on a row, or a row's file. Converting it moves that one
value from a source keyset to a target keyset — forward during a sweep,
backward during a rollback — and records that it did so in the same
transaction as the write. The caller decides which way and holds both keysets;
this module never loads a key.

**Fields** are read and written raw: the column is fetched without the model
field's decoding and written with ``.update()``, so no instance ever caches
plaintext or a fallback where a raw read expects ciphertext. The AAD is rebuilt
from the row's bound columns exactly as a read builds it, so a rotation
re-applies identical bytes.

**Files** are never overwritten. Each blob is rewritten under a fresh name,
verified to its end, and only then does the row's pointer move; the old blob is
deleted after. Every name is recorded before the act it describes, so a run
killed at any point can reason from the row's current pointer about what is
stray and what is owed a delete.
"""

from __future__ import annotations

import posixpath
import uuid
from contextlib import contextmanager
from types import SimpleNamespace

from django.apps import apps
from django.core.files.base import File
from django.db import transaction
from django.utils import timezone

from . import user_context
from ._internal import _NonClosingWriter, iter_rows, operator_error_text
from ._logging import get_logger
from .engine import is_silo_value, unwrap_ciphertext, wrap_ciphertext
from .exceptions import (
    EncryptedFieldDecryptionError,
    EncryptedFieldEncryptionError,
    EncryptedFileDecryptionError,
    EncryptedFileEncryptionError,
    EncryptionConfigurationError,
    EncryptionError,
)
from .fields import _build_aad_for_instance, aad_attnames
from .models import DataEncryptionKey, DekRotationWorkItem

logger = get_logger(__name__)

#: What converting one item came to, besides an error code.
DONE = "done"
GONE = "gone"

_CHUNK = 64 * 1024


class ItemConverter:
    """Moves single items between two keysets, on behalf of one operator."""

    def __init__(self, os_login_user: str):
        self.os_login_user = os_login_user

    def convert(self, item, source, target, *, forward: bool, purpose: str, scope=None, reader=None) -> str:
        """Move *item* from *source* to *target*. Returns ``DONE``, ``GONE``, or an error code.

        *scope* maps a model label to that silo's rows — the filter the worklist
        was built with. Reads and writes go through it, so a row that has left
        the silo since the build reads as gone rather than being converted onto
        a key it no longer belongs under.

        *reader* is the silo's field key, supplied only for an index rotation:
        a digest is derived from the plaintext, and the key being rotated cannot
        read it.
        """
        try:
            model = apps.get_model(item.model_label)
            field = model._meta.get_field(item.field_name)
            pk = model._meta.pk.to_python(item.object_pk)
        except Exception:
            return EncryptionConfigurationError.code
        rows = (scope or {}).get(item.model_label)
        if purpose == DataEncryptionKey.PURPOSE_FILE:
            return self._convert_file(item, model, field, pk, source, target, forward=forward, rows=rows)
        if purpose == DataEncryptionKey.PURPOSE_INDEX:
            return self._convert_index(item, model, field, pk, target, forward=forward, reader=reader, rows=rows)
        return self._convert_field(item, model, field, pk, source, target, forward=forward, rows=rows)

    def _convert_index(self, item, model, field, pk, target, *, forward, reader, rows=None) -> str:
        """Rewrite one row's digest under *target*, leaving the value alone.

        Unlike the other two, this reads with a key it is not rotating: a digest
        is a one-way hash of the plaintext, so the only way to produce the new
        one is to decrypt the value under the silo's field key and hash it again.
        Which is also the cost of a re-index — every indexed value is decrypted,
        where a field rotation at least had to decrypt it anyway.

        The value is not rewritten, so a failure here leaves the row readable and
        merely unfindable until the item is retried. A rollback is the same work
        with the two keys the other way round, which is why nothing has to be
        remembered about the digest that was there before.
        """
        found, value = _read_column(model, rows, pk, field)
        if not found:
            return GONE
        if value is None or value == "":
            # Nothing to index. The digest column already holds NULL, and an
            # entry in the shared table was never written.
            self.mark(item, forward=forward)
            return DONE
        if not is_silo_value(value):
            return EncryptedFieldDecryptionError.code
        aad = _row_aad(model, field, pk)
        if aad is None:
            return GONE
        if isinstance(aad, str):
            return aad
        try:
            plaintext = reader.decrypt(unwrap_ciphertext(value), aad)
        except Exception:
            return EncryptedFieldDecryptionError.code
        try:
            digest = target.digest(field._normalized(plaintext.decode("utf-8")), context=field.index_context())
        except Exception:
            return EncryptedFieldEncryptionError.code
        finally:
            del plaintext

        with transaction.atomic():
            scoped = _rows(model, rows).filter(pk=pk)
            column = field.index_update_kwargs(digest)
            if column:
                updated = scoped.update(**column)
            else:
                # The digest is a row of the package's own table, so the write is
                # its own statement; the row still has to be there to write for.
                updated = 1 if scoped.exists() else 0
                if updated:
                    field.record_index_digest(pk, digest)
            if updated:
                self.mark(item, forward=forward)
        return DONE if updated else GONE

    def _convert_field(self, item, model, field, pk, source, target, *, forward, rows=None) -> str:
        found, value = _read_column(model, rows, pk, field)
        if not found:
            return GONE
        if value is None or value == "":
            self.mark(item, forward=forward)
            return DONE
        if not is_silo_value(value):
            return EncryptedFieldDecryptionError.code
        aad = _row_aad(model, field, pk)
        if aad is None:
            return GONE
        if isinstance(aad, str):
            return aad
        try:
            plaintext = source.decrypt(unwrap_ciphertext(value), aad)
        except Exception:
            return EncryptedFieldDecryptionError.code
        try:
            ciphertext = wrap_ciphertext(target.encrypt(plaintext, aad))
        except Exception:
            return EncryptedFieldEncryptionError.code
        finally:
            del plaintext
        with transaction.atomic():
            updated = _rows(model, rows).filter(pk=pk).update(**{field.attname: ciphertext})
            if updated:
                self.mark(item, forward=forward)
        return DONE if updated else GONE

    def _convert_file(self, item, model, field, pk, source, target, *, forward, rows=None) -> str:
        """Rewrite one blob under *target*: fresh name, verify, move the pointer, delete the old one."""
        storage = field.storage
        if not hasattr(storage, "_save_raw"):
            return EncryptionConfigurationError.code
        found, current = _read_column(model, rows, pk, field)
        if not found:
            return GONE
        current = current or ""
        self.settle(item, current, storage)
        if not current:
            self.mark(item, forward=forward)
            return DONE
        aad = _row_aad(model, field, pk)
        if aad is None:
            return GONE
        if isinstance(aad, str):
            return aad

        fresh = posixpath.join(posixpath.dirname(current), f"{uuid.uuid4().hex}.bin")
        item.old_blob_name, item.new_blob_name, item.old_blob_deleted = current, fresh, False
        item.save(update_fields=["old_blob_name", "new_blob_name", "old_blob_deleted"])

        stored, code = _rewrite_blob(storage, current, fresh, source, target, aad)
        if code:
            # A failed write leaves the fresh name recorded; delete what may have
            # landed so a rerun reasoning from the pointer finds nothing stray.
            self._delete_blob(storage, stored or fresh, model_label=item.model_label)
            return code
        if stored != fresh:
            item.new_blob_name = stored
            item.save(update_fields=["new_blob_name"])

        with transaction.atomic():
            updated = _rows(model, rows).filter(pk=pk, **{field.attname: current}).update(**{field.attname: stored})
            if updated:
                self.mark(item, forward=forward)
        if not updated:
            # The row went, or its file was replaced or cleared. The pointer never
            # moved, so nothing else will claim the blob just written.
            self._delete_blob(storage, stored, model_label=item.model_label)
            return GONE
        if self._delete_blob(storage, current, model_label=item.model_label):
            item.old_blob_deleted = True
            item.save(update_fields=["old_blob_deleted"])
        return DONE

    def settle(self, item, current: str, storage) -> None:
        """Finish whatever an earlier attempt at *item* left, judged by the row's pointer."""
        if item.old_blob_deleted or not item.new_blob_name:
            return
        if current == item.new_blob_name:
            # The pointer moved; only the superseded blob's delete is owed.
            if self._delete_blob(storage, item.old_blob_name, model_label=item.model_label):
                item.old_blob_deleted = True
                item.save(update_fields=["old_blob_deleted"])
            return
        # The pointer never moved to the fresh blob, so that blob is stray.
        self._delete_blob(storage, item.new_blob_name, model_label=item.model_label)
        item.old_blob_name, item.new_blob_name = "", ""
        item.save(update_fields=["old_blob_name", "new_blob_name"])

    def settle_pending(self, dek) -> None:
        """Retry the superseded-blob deletes a pass could not finish."""
        pending = DekRotationWorkItem.objects.filter(dek=dek, old_blob_deleted=False).exclude(new_blob_name="")
        for item in iter_rows(pending):
            try:
                model = apps.get_model(item.model_label)
                field = model._meta.get_field(item.field_name)
                # No silo filter here: this only settles blobs a conversion left
                # behind, and a row that has moved silo owes them just the same.
                found, current = _read_column(model, None, model._meta.pk.to_python(item.object_pk), field)
            except Exception:
                continue
            if not found:
                self.close_gone(item, forward=item.converted_at is not None)
                continue
            self.settle(item, current or "", field.storage)

    def close_gone(self, item, *, forward: bool) -> None:
        """Close an item whose target no longer exists, deleting any blob it owes."""
        if item.new_blob_name or (item.old_blob_name and not item.old_blob_deleted):
            try:
                storage = apps.get_model(item.model_label)._meta.get_field(item.field_name).storage
            except Exception:
                storage = None
            if storage is not None:
                for name in (item.new_blob_name, "" if item.old_blob_deleted else item.old_blob_name):
                    if name:
                        self._delete_blob(storage, name, model_label=item.model_label)
            item.old_blob_deleted = True
        self.mark(item, forward=forward, extra=["old_blob_deleted"])

    @staticmethod
    def mark(item, *, forward: bool, extra=()) -> None:
        """Record *item* as on the target keyset: converted going forward, cleared going back."""
        item.converted_at = timezone.now() if forward else None
        item.failure_code = ""
        item.save(update_fields=["converted_at", "failure_code", *extra])

    def _delete_blob(self, storage, name: str, *, model_label: str) -> bool:
        """Delete *name* from *storage*; ``False`` and a warning if the backend refused."""
        if not name:
            return True
        try:
            storage.delete(name)
        except Exception as exc:
            logger.warning(
                "A blob a data key rotation no longer needs could not be deleted from storage; a rerun "
                'tries again. path="%s" model=%s detail="%s" %s',
                name,
                model_label,
                operator_error_text(exc),
                user_context.identity_tail(os_login_user=self.os_login_user),
            )
            return False
        return True


def _rows(model, rows):
    """*rows* where the caller has a silo-scoped queryset, the base manager otherwise.

    The base manager, never ``objects``: a default manager that filters would
    hide live rows from the rotation.
    """
    return model._base_manager.all() if rows is None else rows


def _read_column(model, rows, pk, field):
    """``(found, value)`` for *field* on row *pk*, looked up within *rows*.

    ``found`` is ``False`` for a row that is not in that set at all — deleted,
    or moved to another silo since the worklist was built. Either way it is no
    longer this rotation's to convert, and its item closes.

    ``values_list`` rather than an instance: no descriptor runs, so nothing
    caches plaintext where a later read expects ciphertext. An encrypted field
    passes its stored value straight through ``from_db_value``, so what comes
    back is the ciphertext itself.
    """
    found = list(_rows(model, rows).filter(pk=pk).values_list(field.name, flat=True)[:1])
    return (True, found[0]) if found else (False, None)


def _row_aad(model, field, pk):
    """The AAD for *field* on row *pk*: bytes, ``None`` if the row is gone, or an error code."""
    cols = aad_attnames(field)
    if not cols:
        return b""
    values = model._base_manager.filter(pk=pk).values(*cols).first()
    if values is None:
        return None
    try:
        return _build_aad_for_instance(model, field, SimpleNamespace(**values))
    except Exception:
        return (
            EncryptedFileDecryptionError.code
            if field.get_internal_type() == "FileField"
            else EncryptedFieldDecryptionError.code
        )


@contextmanager
def _decrypting_blob(storage, current: str, source, aad: bytes):
    """Open *current* and yield its plaintext, decrypted under *source*."""
    with storage._open_raw(current, "rb") as ciphertext:
        yield source.new_decrypting_stream(ciphertext, aad)


def write_encrypted_blob(storage, fresh: str, open_plaintext, target, aad: bytes, *, read_code: str) -> tuple[str, str]:
    """Encrypt what *open_plaintext* yields under *target*, store it as *fresh*, and verify it.

    Returns ``(stored name, "")`` on success, or ``(name written so far, error
    code)`` naming whichever step failed — *read_code* for the source side,
    since what a failed read means depends on where the plaintext came from.
    Verification decrypts the new blob to its end and discards the plaintext:
    each segment authenticates on its own and only the last is marked final, so
    a truncated copy reads cleanly until it stops.

    A data key rotation and the adoption helper in ``migration_helpers`` share
    this: both write a blob nothing has claimed yet, under a key the current
    storage context would not choose, and neither may trust it until it has been
    read back.
    """
    stage = read_code
    stored = ""
    try:
        with open_plaintext() as plaintext, storage._open_ciphertext_spool() as spool:
            stage = EncryptedFileEncryptionError.code
            with target.new_encrypting_stream(_NonClosingWriter(spool), aad) as encrypting:
                stage = read_code
                while chunk := plaintext.read(_CHUNK):
                    encrypting.write(chunk)
                stage = EncryptedFileEncryptionError.code
            spool.seek(0)
            stored = storage._save_raw(fresh, File(spool, name=fresh))
        stage = EncryptedFileDecryptionError.code
        with storage._open_raw(stored, "rb") as written:
            check = target.new_decrypting_stream(written, aad)
            while check.read(_CHUNK):
                pass
    except EncryptionError as exc:
        return stored, exc.code
    except Exception as exc:
        logger.debug(
            'A blob could not be written under a new key. stage=%s detail="%s"', stage, operator_error_text(exc)
        )
        return stored, stage
    return stored, ""


def _rewrite_blob(storage, current: str, fresh: str, source, target, aad: bytes) -> tuple[str, str]:
    """Decrypt *current* under *source*, write it under *target* as *fresh*, and verify it."""
    return write_encrypted_blob(
        storage,
        fresh,
        lambda: _decrypting_blob(storage, current, source, aad),
        target,
        aad,
        read_code=EncryptedFileDecryptionError.code,
    )
