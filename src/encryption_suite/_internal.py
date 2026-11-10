"""Private helpers shared between admin_mixins and safe_queries.

Encrypted-field discovery and raw-cursor reads must bypass the ORM's
``from_db_value`` / ``post_init`` hooks so that decryption is never
triggered while loading a "safe shell" of a row. This module factors
those primitives out of the admin mixin so :mod:`safe_queries` can use
them too.
"""

from __future__ import annotations

import io
from collections.abc import Iterable, Sequence

from django.db import connections
from django.utils import translation

from ._logging import log_text
from .fields import EncryptedFileField, _EncryptedFieldMixin


def iter_rows(queryset, chunk_size: int = 500) -> Iterable:
    """Yield every row of *queryset*, a bounded page at a time.

    Stands in for ``QuerySet.iterator()``, which opens a **server-side cursor**.
    A connection pooler in transaction-pooling mode — PgBouncer, and the managed
    Postgres services built on it (Neon, Supabase, RDS Proxy) — does not keep a
    portal alive between statements, so the cursor disappears part way through
    and the loop dies with ``InvalidCursorName``. It fails intermittently, on
    whether consecutive statements land on the same backend connection, which
    makes it exactly the kind of bug that passes a test run and breaks a
    migration.

    Keyset pagination on the primary key rather than ``LIMIT``/``OFFSET``: offset
    re-scans everything it skips, and — where the caller is *writing* to the rows
    it walks — shifts the window under itself. Ordering is imposed here, so any
    ordering on the incoming queryset is replaced.

    The trade against a real cursor is one query per chunk instead of one for the
    whole walk, which is a fair price for working on every deployment.
    """
    last_pk = None
    while True:
        page = queryset.order_by("pk")
        if last_pk is not None:
            page = page.filter(pk__gt=last_pk)
        rows = list(page[:chunk_size])
        if not rows:
            return
        yield from rows
        last_pk = rows[-1].pk


def operator_error_text(exc: BaseException) -> str:
    """Return English, operator-facing text for a caught exception, for logging.

    ``EncryptionError`` instances carry a generic, *translated* ``str(exc)`` so
    the user-facing message respects the request's active language; the English
    operator detail lives on ``exc.detail`` when set by
    ``log_and_raise_configuration_error``. Log lines must stay English no matter
    what locale the request activated, so this prefers ``exc.detail`` and
    otherwise renders ``str(exc)`` under an English override. Plain exceptions
    (already English) pass through unchanged.

    When the exception carries a stable error-code slug (``exc.code`` on
    :class:`~encryption_suite.exceptions.EncryptionError` subclasses), it is
    prepended as ``[slug]`` so operators can grep/alert on a language-neutral
    identifier regardless of the rendered message.

    An exception with no text at all — ``cryptography``'s ``InvalidTag`` on a
    failed authentication, for one — renders as its class name, so the line
    still says what was raised.
    """
    code = getattr(exc, "code", "")
    detail = getattr(exc, "detail", None)
    if detail:
        text = str(detail)
    else:
        with translation.override("en"):
            text = str(exc)
    if not text:
        text = type(exc).__name__
    return f"[{code}] {text}" if code else text


class _NonClosingWriter(io.RawIOBase):
    """Write-through wrapper whose ``close()`` does not close the underlying stream.

    A crypto backend's encrypting-stream context manager may close its output on
    exit (Tink's does). Wrap the caller's buffer in this before passing it to the
    backend so the caller's stream stays open and seekable after ``encrypt_file``
    returns.
    """

    def __init__(self, wrapped):
        self._wrapped = wrapped

    def writable(self):
        return True

    def write(self, b):
        return self._wrapped.write(b)

    def flush(self):
        if not self._wrapped.closed:
            self._wrapped.flush()


DECRYPT_FAILURE_HINT = (
    "Likely causes: row reassigned to a different silo, ciphertext "
    "corruption, or, for AAD-bound rows, an AAD-bound column was changed "
    "without re-encryption. See docs/security.md."
)


def optional_log_field(name: str, value: str) -> str:
    """Return ``' name="value"'`` when *value* is truthy, else an empty string.

    For fields that only sometimes have a value (a diagnostic hint the adapter
    may not be able to produce). Emitting ``name=""`` on every line instead
    would put an empty field in front of the operator on the common path.
    The value is escaped, since some callers pass column values.
    """
    return f' {name}="{log_text(value)}"' if value else ""


def describe_decryption_target(
    *,
    field_label: str = "",
    row_identity: str = "",
    file_name: str = "",
) -> str:
    """Return a consistent, scan-friendly target string for decrypt logs.

    Emitted as ``key="value"`` pairs so a logfmt parser extracts each part as a
    field. Every value is quoted: a field label, a row identity, and a storage
    path can all contain whitespace, and an unquoted value is truncated at the
    first space. The row identity and the file name are escaped as well: one
    can carry column values and the other an uploaded file's name.
    """
    parts: list[str] = []
    if field_label:
        parts.append(f'field="{field_label}"')
    if row_identity:
        parts.append(f'row="{log_text(row_identity)}"')
    if file_name:
        parts.append(f'file="{log_text(file_name)}"')
    if not parts:
        return 'target="<unknown>"'
    return " ".join(parts)


def describe_decryption_scope(
    *,
    silo_ref="",
    field_label: str = "",
    row_identity: str = "",
    file_name: str = "",
) -> str:
    """Return the full shared context fragment for decrypt log lines."""
    target = describe_decryption_target(
        field_label=field_label,
        row_identity=row_identity,
        file_name=file_name,
    )
    if silo_ref:
        return f'silo="{silo_ref}" {target}'
    return target


# Backend-specific attributes that name the container a key lives in. Django's
# abstract Storage API has no portable equivalent, so this is a best-effort
# probe across the backends django-storages ships; absence is fine.
_STORAGE_CONTAINER_ATTRS = ("bucket_name", "azure_container", "container_name", "location")


def describe_storage_location(storage, name: str = "") -> str:
    """Return a scan-friendly storage-location fragment for storage logs.

    Mirrors :func:`describe_decryption_target` in style so encrypt/storage
    failures cross-reference the same way decrypt failures do.

    Backend-agnostic: always reports the storage key and backend class (the
    only universally available identifiers in Django's ``Storage`` API), and
    best-effort enriches with the backend's container/bucket when one of the
    common attributes is present.

    ``name`` is the storage key/path. It can embed the original upload filename
    depending on the field's ``upload_to``; callers that must avoid logging
    user-supplied names should omit it.
    """
    parts: list[str] = []
    container = next(
        (value for attr in _STORAGE_CONTAINER_ATTRS if (value := getattr(storage, attr, None))),
        None,
    )
    if container:
        parts.append(f'container="{log_text(container)}"')
    parts.append(f'backend="{type(storage).__name__}"')
    if name:
        parts.append(f'key="{log_text(name)}"')
    return " ".join(parts)


def encrypted_field_names(model) -> list[str]:
    """Return the names of every encrypted field on ``model``.

    Includes both ``_EncryptedFieldMixin`` subclasses (text/char/etc.)
    and ``EncryptedFileField``.
    """
    return [f.name for f in model._meta.get_fields() if isinstance(f, (_EncryptedFieldMixin, EncryptedFileField))]


def non_encrypted_concrete_field_names(model) -> list[str]:
    """Return concrete field names on ``model`` excluding encrypted columns."""
    encrypted = set(encrypted_field_names(model))
    return [f.name for f in model._meta.concrete_fields if f.name not in encrypted]


def raw_cursor_fetch(model, pk, columns: Sequence[str]) -> tuple | None:
    """Fetch ``columns`` for a single row by pk via a raw cursor.

    Returns ``None`` if the row does not exist. Bypasses ``from_db_value``
    so encrypted columns come back as raw ciphertext strings (or storage
    keys for file fields), never decrypted. Ciphertext comes back stamped
    (see :func:`~encryption_suite.engine.stamp`), as ``from_db_value`` would
    have returned it.
    """
    from .engine import stamp

    if not columns:
        return ()
    meta = model._meta
    table = meta.db_table
    pk_column = meta.pk.column
    connection = connections[model._default_manager.db]
    quote = connection.ops.quote_name
    column_sql = [quote(meta.get_field(c).column) for c in columns]
    with connection.cursor() as cursor:
        cursor.execute(
            f"SELECT {', '.join(column_sql)} FROM {quote(table)} WHERE {quote(pk_column)} = %s",
            [pk],
        )
        row = cursor.fetchone()
    if row is None:
        return None
    return tuple(stamp(value) for value in row)


def raw_cursor_fetch_many(model, pks: Iterable, columns: Sequence[str]) -> dict[object, tuple]:
    """Fetch ``columns`` for many pks in a single query. Returns ``{pk: row}``.

    Used by :func:`~encryption_suite.safe_queries.safe_list_rows` to
    keep query count constant per page rather than per row. Ciphertext comes
    back stamped, as in :func:`raw_cursor_fetch`.
    """
    from .engine import stamp

    pk_list = list(pks)
    if not pk_list or not columns:
        return {}
    meta = model._meta
    table = meta.db_table
    pk_column = meta.pk.column
    connection = connections[model._default_manager.db]
    quote = connection.ops.quote_name
    column_sql = [quote(meta.get_field(c).column) for c in columns]
    placeholders = ", ".join(["%s"] * len(pk_list))
    with connection.cursor() as cursor:
        cursor.execute(
            f"SELECT {quote(pk_column)}, {', '.join(column_sql)} "
            f"FROM {quote(table)} "
            f"WHERE {quote(pk_column)} IN ({placeholders})",
            pk_list,
        )
        return {row[0]: tuple(stamp(value) for value in row[1:]) for row in cursor.fetchall()}
