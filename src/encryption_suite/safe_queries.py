"""Safe query helpers for models with encrypted fields.

Background
----------
Reading a row through the ORM materializes every selected column. For
encrypted fields, materialization triggers ``from_db_value`` (or, for
AAD-bound models, the ``post_init`` decrypt step). A single
undecryptable row therefore raises during queryset iteration, before
application code can isolate the failing row.

The admin sidesteps this by deferring encrypted columns and reading
ciphertext via a raw cursor when needed for previews. This module
exposes the same approach to non-admin code paths:

* :func:`defer_encrypted` — return a queryset with all encrypted
  columns deferred. Iterating it never triggers decryption, so list /
  detail / edit views can render even when some rows are not
  decryptable.
* :func:`probe_decryption` — attempt to decrypt named fields on an
  already-loaded "safe shell" instance, returning structured probes
  rather than mutating the instance with placeholder values.
* :func:`safe_list_rows` / :func:`safe_detail` — materialize the
  deferred queryset and run probes in one batched cursor fetch per
  page (or per single row).

The result objects keep raw state first-class: ``decryptable``,
``has_encrypted_content``, and ``error`` are primary, and ``display``
is a convenience derived from them. Display labels are translatable
and per-field overridable.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any, Literal

from django.db.models import QuerySet
from django.utils.translation import gettext_lazy as _

from ._internal import (
    DECRYPT_FAILURE_HINT,
    describe_decryption_target,
    non_encrypted_concrete_field_names,
    operator_error_text,
    raw_cursor_fetch,
    raw_cursor_fetch_many,
)
from ._logging import get_logger
from .exceptions import (
    GENERIC_DECRYPT_FAILED_USER_MESSAGE,
    EncryptedFieldDecryptionError,
    EncryptedFileDecryptionError,
    EncryptionError,
)
from .fields import (
    EncryptedFileField,
    _build_aad_for_instance,
    _build_row_identity,
    _EncryptedFieldMixin,
)

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Default labels (translatable). Callers override via per-field dicts.
# ---------------------------------------------------------------------------

DEFAULT_EMPTY_FIELD_LABEL = _("No content")
DEFAULT_ERROR_FIELD_LABEL = _("Unable to decrypt field.")
DEFAULT_EMPTY_FILE_LABEL = _("No file uploaded")
DEFAULT_ERROR_FILE_LABEL = _("Unable to decrypt file.")


ProbeState = Literal["empty", "decryptable", "undecryptable"]


@dataclass(frozen=True)
class FieldProbe:
    """Outcome of probing one encrypted field on an instance.

    ``state`` is the primary discriminator:

    * ``"empty"`` — no encrypted content present (the column is NULL or
      a file field has no attached storage key).
    * ``"decryptable"`` — content present and decrypted successfully;
      ``value`` holds the decrypted Python value.
    * ``"undecryptable"`` — content present but decryption failed;
      ``error`` carries the typed exception.

    The boolean shortcuts (``decryptable``, ``has_encrypted_content``)
    are derived from ``state`` and exposed for the requested result
    shape.
    """

    state: ProbeState
    display: str
    value: Any = None
    error: Exception | None = field(default=None, repr=False)

    @property
    def decryptable(self) -> bool:
        return self.state == "decryptable"

    @property
    def has_encrypted_content(self) -> bool:
        return self.state != "empty"


@dataclass(frozen=True)
class SafeRow:
    """Safely-loaded row plus per-field probe results.

    ``instance`` has only non-encrypted columns materialized; touching
    an encrypted attribute on it would still trigger a deferred-field
    refresh, so prefer :attr:`probes` for read access.
    """

    instance: Any
    probes: dict[str, FieldProbe]

    @property
    def display(self) -> dict[str, str]:
        return {name: p.display for name, p in self.probes.items()}

    @property
    def decryptable(self) -> dict[str, bool]:
        return {name: p.decryptable for name, p in self.probes.items()}

    @property
    def errors(self) -> dict[str, Exception | None]:
        return {name: p.error for name, p in self.probes.items()}

    @property
    def has_encrypted_content(self) -> dict[str, bool]:
        return {name: p.has_encrypted_content for name, p in self.probes.items()}


# ---------------------------------------------------------------------------
# Queryset shaping
# ---------------------------------------------------------------------------


def defer_encrypted(queryset: QuerySet, *, extra_defer: Iterable[str] = ()) -> QuerySet:
    """Return ``queryset`` with all encrypted fields deferred.

    Iterating the result is safe: ``from_db_value`` and ``post_init``
    decryption never fire because the encrypted columns are not in the
    instance ``__dict__``. Touching an encrypted attribute later still
    triggers a deferred-field refresh and decrypt, so use
    :func:`probe_decryption` for the read path.
    """
    model = queryset.model
    keep = non_encrypted_concrete_field_names(model)
    deferred = set(extra_defer)
    keep = [name for name in keep if name not in deferred]
    return queryset.only(*keep)


# ---------------------------------------------------------------------------
# Probing
# ---------------------------------------------------------------------------


def _is_text_encrypted_field(f) -> bool:
    return isinstance(f, _EncryptedFieldMixin) and not isinstance(f, EncryptedFileField)


def _label_for(
    field_name: str,
    overrides: Mapping[str, Any] | None,
    default,
) -> str:
    if overrides and field_name in overrides:
        return str(overrides[field_name])
    return str(default)


def _decrypt_text_field(model, field_obj, instance, ciphertext: str):
    """Decrypt a text-encrypted field's raw ciphertext using engine + AAD."""
    from .engine import _CIPHERTEXT_PREFIX, _MISSING_PREFIX_DETAIL, is_silo_value
    from .registry import get_engine

    if not is_silo_value(ciphertext):
        # Duplicates the check ``engine.decrypt`` makes at its own entry, and so
        # pre-empts the log line the engine would have emitted. Log here or the
        # failure is silent — this is the only field_decryption_failed path that
        # never reaches the engine.
        field_label = f"{model._meta.label}.{field_obj.attname}"
        detail = f'field="{field_label}" prefix="{_CIPHERTEXT_PREFIX}" {_MISSING_PREFIX_DETAIL}'
        logger.error(
            f'{_MISSING_PREFIX_DETAIL} error_code=%s field="%s" prefix="%s"',
            EncryptedFieldDecryptionError.code,
            field_label,
            _CIPHERTEXT_PREFIX,
        )
        raise EncryptedFieldDecryptionError(GENERIC_DECRYPT_FAILED_USER_MESSAGE, detail=detail)
    row_identity = _build_row_identity(model, instance, field_obj)
    try:
        aad = _build_aad_for_instance(model, field_obj, instance)
    except ValueError as exc:
        field_label = f"{model._meta.label}.{field_obj.attname}"
        logger.error(
            "Could not build the additional authenticated data for an encrypted field, so its value cannot "
            'be read. error_code=%s field="%s" detail="%s"',
            EncryptedFieldDecryptionError.code,
            field_label,
            operator_error_text(exc),
        )
        raise EncryptedFieldDecryptionError(
            GENERIC_DECRYPT_FAILED_USER_MESSAGE, detail=f'field="{field_label}" {operator_error_text(exc)}'
        ) from exc
    plaintext = get_engine().decrypt(
        ciphertext,
        aad=aad,
        field_name=f"{model._meta.label}.{field_obj.attname}",
        row_identity=row_identity,
    )
    if hasattr(field_obj, "_from_storage_str"):
        plaintext = field_obj._from_storage_str(plaintext)
    return plaintext


def _file_probe_failure(target: str, exc: Exception) -> EncryptedFileDecryptionError:
    """Log a non-package probe failure once and return it as a typed error.

    The probe *returns* its error rather than raising, so nothing downstream
    logs it; without this the failure would never reach an operator.
    """
    error_text = operator_error_text(exc)
    detail = f"{target}: {error_text}"
    logger.error(
        'Could not decrypt file. error_code=%s %s detail="%s" hint="%s"',
        EncryptedFileDecryptionError.code,
        target,
        error_text,
        DECRYPT_FAILURE_HINT,
    )
    return EncryptedFileDecryptionError(GENERIC_DECRYPT_FAILED_USER_MESSAGE, detail=detail)


def _probe_file_field(instance, field_obj: EncryptedFileField) -> tuple[bool, Exception | None]:
    """Eager-probe an encrypted file. Returns ``(decryptable, error_or_None)``.

    Mirrors the eager-probe approach used by
    :func:`~encryption_suite.file_view_helpers.serve_encrypted_file`: the first
    segment is read so authentication runs synchronously. The handle is
    closed regardless.
    """
    from .file_view_helpers import _PROBE_SIZE

    model = type(instance)
    file_attr = getattr(instance, field_obj.attname, None)
    if not file_attr:
        return True, None
    row_identity = _build_row_identity(model, instance, field_obj)
    file_name = getattr(file_attr, "name", "") or ""
    if file_name and "file=" not in row_identity:
        row_identity = f"{row_identity},file={file_name}" if row_identity else f"file={file_name}"
    target = describe_decryption_target(
        field_label=f"{model._meta.label}.{field_obj.attname}",
        row_identity=row_identity,
    )
    try:
        handle = file_attr.open("rb")
    except EncryptionError as exc:
        return False, exc
    except Exception as exc:
        return False, _file_probe_failure(target, exc)
    try:
        try:
            handle.read(_PROBE_SIZE)
        except EncryptionError as exc:
            return False, exc
        except Exception as exc:
            return False, _file_probe_failure(target, exc)
    finally:
        try:
            handle.close()
        except Exception:
            pass
    return True, None


def probe_decryption(
    instance,
    fields: Iterable[str],
    *,
    empty_labels: Mapping[str, Any] | None = None,
    error_labels: Mapping[str, Any] | None = None,
    raw_values: Mapping[str, Any] | None = None,
) -> dict[str, FieldProbe]:
    """Probe ``fields`` on ``instance`` and return per-field results.

    ``raw_values`` is an optional pre-fetched mapping of ``field_name``
    to the raw column value (ciphertext for text fields, storage key
    for file fields). When supplied, the function avoids re-querying
    the database. :func:`safe_list_rows` populates this mapping from a
    single batched cursor fetch so the per-row work stays in Python.

    File fields probe via storage and are opt-in: name them in
    ``fields`` only when ``decryptable`` is actually needed for that
    field.
    """
    fields = list(fields)
    model = type(instance)
    probes: dict[str, FieldProbe] = {}
    fetch_for: list[str] = []
    for name in fields:
        if raw_values is not None and name in raw_values:
            continue
        try:
            f = model._meta.get_field(name)
        except Exception:
            continue
        if isinstance(f, (_EncryptedFieldMixin, EncryptedFileField)):
            fetch_for.append(name)

    fetched: dict[str, Any] = dict(raw_values or {})
    if fetch_for and instance.pk is not None:
        row = raw_cursor_fetch(model, instance.pk, fetch_for)
        if row:
            for col, value in zip(fetch_for, row, strict=True):
                fetched[col] = value

    for name in fields:
        try:
            f = model._meta.get_field(name)
        except Exception:
            probes[name] = FieldProbe(
                state="empty",
                display=_label_for(name, empty_labels, DEFAULT_EMPTY_FIELD_LABEL),
            )
            continue
        is_file = isinstance(f, EncryptedFileField)
        empty_default = DEFAULT_EMPTY_FILE_LABEL if is_file else DEFAULT_EMPTY_FIELD_LABEL
        error_default = DEFAULT_ERROR_FILE_LABEL if is_file else DEFAULT_ERROR_FIELD_LABEL

        raw = fetched.get(name)
        if raw is None or raw == "":
            probes[name] = FieldProbe(
                state="empty",
                display=_label_for(name, empty_labels, empty_default),
            )
            continue

        if is_file:
            decryptable, err = _probe_file_field(instance, f)
            if decryptable:
                probes[name] = FieldProbe(
                    state="decryptable",
                    display=str(raw),
                    value=raw,
                )
            else:
                probes[name] = FieldProbe(
                    state="undecryptable",
                    display=_label_for(name, error_labels, error_default),
                    error=err,
                )
            continue

        if not _is_text_encrypted_field(f):
            probes[name] = FieldProbe(
                state="decryptable",
                display=str(raw),
                value=raw,
            )
            continue

        try:
            plaintext = _decrypt_text_field(model, f, instance, str(raw))
        except EncryptionError as exc:
            probes[name] = FieldProbe(
                state="undecryptable",
                display=_label_for(name, error_labels, error_default),
                error=exc,
            )
        else:
            probes[name] = FieldProbe(
                state="decryptable",
                display=str(plaintext) if plaintext is not None else "",
                value=plaintext,
            )
    return probes


# ---------------------------------------------------------------------------
# List / detail
# ---------------------------------------------------------------------------


def _columns_to_prefetch(model, probe_fields: Iterable[str]) -> list[str]:
    """Return the encrypted-field probe columns that can be fetched up front
    via a single batched cursor query."""
    out: list[str] = []
    for name in probe_fields:
        try:
            f = model._meta.get_field(name)
        except Exception:
            continue
        if isinstance(f, (_EncryptedFieldMixin, EncryptedFileField)):
            out.append(name)
    return out


def safe_list_rows(
    queryset: QuerySet,
    *,
    probe_fields: Iterable[str] = (),
    empty_labels: Mapping[str, Any] | None = None,
    error_labels: Mapping[str, Any] | None = None,
) -> list[SafeRow]:
    """Materialize a safe shell of ``queryset`` and probe ``probe_fields``.

    Issues at most two queries per page: the deferred-only ``SELECT``
    for the queryset itself, plus one batched raw-cursor fetch covering
    all requested probe columns for every pk on the page. Per-row
    decrypt attempts run in Python and isolate cell-level failures.

    File fields probe via storage and are opt-in — name them in
    ``probe_fields`` only when ``decryptable`` is actually needed for
    the list view.
    """
    probe_fields = list(probe_fields)
    deferred = defer_encrypted(queryset)
    instances = list(deferred)
    if not instances:
        return []
    model = queryset.model
    columns = _columns_to_prefetch(model, probe_fields)
    raw_by_pk: dict[Any, dict[str, Any]] = {}
    if columns:
        rows = raw_cursor_fetch_many(
            model,
            [i.pk for i in instances],
            columns,
        )
        for pk, values in rows.items():
            raw_by_pk[pk] = dict(zip(columns, values, strict=True))

    rows_out: list[SafeRow] = []
    for inst in instances:
        raw = raw_by_pk.get(inst.pk, {})
        probes = probe_decryption(
            inst,
            probe_fields,
            empty_labels=empty_labels,
            error_labels=error_labels,
            raw_values=raw,
        )
        rows_out.append(SafeRow(instance=inst, probes=probes))
    return rows_out


def safe_detail(
    queryset: QuerySet,
    pk: Any,
    *,
    probe_fields: Iterable[str] = (),
    empty_labels: Mapping[str, Any] | None = None,
    error_labels: Mapping[str, Any] | None = None,
) -> SafeRow:
    """Single-row variant of :func:`safe_list_rows`.

    Raises ``queryset.model.DoesNotExist`` when the row is missing or
    not in scope of the supplied ``queryset`` (typical for tenant or
    permission filtering).
    """
    deferred = defer_encrypted(queryset)
    instance = deferred.get(pk=pk)
    probes = probe_decryption(
        instance,
        probe_fields,
        empty_labels=empty_labels,
        error_labels=error_labels,
    )
    return SafeRow(instance=instance, probes=probes)


__all__ = [
    "defer_encrypted",
    "probe_decryption",
    "safe_list_rows",
    "safe_detail",
    "FieldProbe",
    "SafeRow",
    "DEFAULT_EMPTY_FIELD_LABEL",
    "DEFAULT_ERROR_FIELD_LABEL",
    "DEFAULT_EMPTY_FILE_LABEL",
    "DEFAULT_ERROR_FILE_LABEL",
]
