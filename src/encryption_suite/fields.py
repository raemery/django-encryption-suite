"""
Encrypted Django model fields.

All fields store ciphertext in the database. Decryption is **lazy**:
ciphertext is loaded into ``instance.__dict__`` like any other column,
and the value is only decrypted when an attribute is read for the first
time. A queryset whose rows contain one undecryptable cell does not
raise during iteration — the failure is isolated to attribute access on
that specific row.

The decryption descriptor is :class:`EncryptedAttributeDescriptor`,
installed automatically on every encrypted field via Django's
``descriptor_class`` hook. On a successful decrypt the plaintext
replaces the ciphertext in ``instance.__dict__`` so later reads are
free. On failure in lenient mode (the default), the descriptor stores
an :class:`UndecryptableValue` sentinel that stringifies to a
translatable fallback message — templates can render
``{{ obj.field }}`` directly without branching, and the rendered string
follows the active Django locale.

Decryption mode resolution, in priority order:

1. Per-field ``decrypt_mode="strict"`` kwarg — the field always raises.
2. The :func:`strict_mode` context manager — every decrypt inside the
   ``with`` block raises. Useful for serializers, exports, and jobs.
3. Default — lenient.

The ``UndecryptableValue`` sentinel is detectable via
:func:`is_undecryptable` for code paths that need to branch without
flipping into strict mode.

AAD (Additional Authenticated Data) binding
-------------------------------------------
An encrypted field can opt into row-identity binding with ``aad=``:

    class MedicalRecord(models.Model):
        person = models.ForeignKey(Person, on_delete=models.CASCADE)
        notes = EncryptedTextField(aad=("pk", "person"))

The field binds its ciphertext to the listed columns via AEAD associated
data. Tampering with any listed column on an existing row makes the field
fail to decrypt on the next read. Each field declares its own binding, and
``aad=`` is recorded in migrations like any other field option. See
``docs/security.md`` for the threat model.

The associated data is the field's ``app.Model.field`` label followed by each
bound attname and its value, attnames sorted. Each element is length-prefixed
(``<byte length>:<bytes>``), so no value can move a boundary, and each value is
first normalized through its field's ``to_python``, so a UUID bound as a hex
string and as a ``UUID`` produce the same bytes.

Names are resolved when the model class is prepared:

* ``"pk"`` resolves to the model's primary key attname.
* A ForeignKey field name (e.g. ``"person"``) resolves to its ``attname``
  (e.g. ``"person_id"``) — the raw column on this row, not the related
  object's pk. This is deliberate: tampering shows up in the column,
  not in the relationship traversal.
* A regular column name (e.g. ``"created_at"``) is used as-is.

Field-level AAD here is distinct from the AAD passed to KMS Encrypt /
Decrypt calls when wrapping the DEK with the KEK. The two layers
serve different purposes; do not conflate them.

Async ORM support
-----------------
The field protocol methods (get_prep_value, from_db_value) are synchronous,
as is attribute access through the descriptor. As of Django 6.0, the ORM's
async support is partial — async QuerySet methods and model methods exist
(e.g. aget, asave), but the ORM still uses sync_to_async internally for
many operations, and the field protocol has no async variants. Blocking
KMS calls in the engine run in a thread pool when accessed from async
views, which is acceptable. The :func:`strict_mode` context manager uses
a ``ContextVar`` so it propagates across ``sync_to_async`` boundaries.

When Django introduces async field protocol methods (e.g.
async_from_db_value), implement them here to call new async counterparts
on EncryptionEngine (async_encrypt / async_decrypt — these do not exist
yet and would need to be created alongside async_encrypt_key /
async_decrypt_key on the KMS adapter base class).  Until then, Django's
own sync_to_async wrapping is sufficient.
"""

from __future__ import annotations

import contextlib
import contextvars
import datetime
import functools
import json
import uuid
from collections.abc import Iterable
from math import ceil
from os.path import splitext
from typing import Literal

from django.core.checks import Error
from django.core.exceptions import NON_FIELD_ERRORS, EmptyResultSet, FieldDoesNotExist, FieldError, ValidationError
from django.core.serializers.json import DjangoJSONEncoder
from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import connection, models, router
from django.db.models.fields.files import FieldFile
from django.db.models.query_utils import DeferredAttribute
from django.db.models.signals import class_prepared
from django.utils.functional import cached_property
from django.utils.translation import gettext_lazy as _

from ._logging import get_logger
from .conf import DEFAULT_KEY_SET, KEY_SET_MAX_LENGTH, is_system_key_set, is_valid_key_set
from .widgets import EncryptedClearableFileInput

logger = get_logger(__name__)

# Operator hint for a ciphertext-shaped value a caller assigned to an encrypted
# field. Logged and put on ``detail``, never shown to a user.
_INJECTED_CIPHERTEXT_HINT = (
    "The value has the shape of stored ciphertext but was not read from this row, so it was not "
    "saved. Writing it through would let ciphertext copied from another row decrypt under this one. "
    "A genuine value rarely has that shape, so treat this as a possible injection attempt "
    "and check which account submitted it."
)

# ---------------------------------------------------------------------------
# Lenient-mode sentinel and strict-mode context
# ---------------------------------------------------------------------------


# Default fallback message rendered when a lenient-mode decrypt fails.
# ``gettext_lazy`` defers translation to the moment ``str()`` is called on
# the proxy — which is exactly when a template renders the sentinel — so
# the rendered text follows the active Django locale at request time.
# The default is intentionally ASCII-only to keep terminals, logs, and
# management commands legible across every platform; consumers that want
# a richer label (icons, color HTML) pass their own ``fallback_label=...``.
DEFAULT_FALLBACK_LABEL = _("Unable to decrypt.")


class UndecryptableValue:
    """Sentinel returned by lenient-mode decrypt failures.

    The instance is always falsy and stringifies to its ``fallback``
    label, so a Django template can render
    ``{{ instance.encrypted_field }}`` directly — a successful decrypt
    yields plaintext, a failure yields the translated fallback message.

    The ``fallback`` argument can be a plain string or a
    :func:`~django.utils.translation.gettext_lazy` proxy. Lazy strings
    resolve to the active Django locale at the moment the template
    evaluates ``str(self)``.

    Code paths that need to branch on decrypt failure can use
    :func:`is_undecryptable`, or read the underlying exception via
    ``UndecryptableValue.error``. Code paths that must hard-fail rather
    than continue with a sentinel should run inside :func:`strict_mode`.

    Code that treats the sentinel as the string it stands in for — calling
    ``value.lower()``, ``value.strip()``, any public ``str`` method — gets the
    underlying error rather than an ``AttributeError``, raised as the
    form-visible copy :func:`~encryption_suite.exceptions.as_lookup_error`
    builds. Such code needs the plaintext and cannot continue without it, and
    it often runs inside a form's ``clean()`` the project did not write:
    allauth compares ``user.email.lower()`` while signing a user in. There the
    form shows the generic message; elsewhere the caller gets a typed
    ``EncryptionError``. Underscore names are left alone, so Django's
    ``hasattr(value, "__html__")`` and copying work as for any object.
    """

    __slots__ = ("_fallback", "_error", "_field_name")

    _STR_METHODS = frozenset(name for name in dir(str) if not name.startswith("_"))

    def __init__(self, fallback, error: Exception, field_name: str = ""):
        self._fallback = fallback
        self._error = error
        self._field_name = field_name

    def __bool__(self) -> bool:
        return False

    def __str__(self) -> str:
        # ``str()`` on a gettext_lazy proxy resolves to the active locale
        # at this exact call. Templates auto-str on render, so the
        # rendered message follows the request's language.
        return str(self._fallback)

    def __repr__(self) -> str:
        name = self._field_name or "<unknown>"
        return f"<UndecryptableValue field={name!r}>"

    def __eq__(self, other) -> bool:
        # Two sentinels for the same field with the same underlying
        # error are equivalent. Comparison to anything else is False —
        # in particular ``sentinel == ""`` is False, so view code that
        # checks for empty strings does not silently treat a failure as
        # an empty value.
        if not isinstance(other, UndecryptableValue):
            return NotImplemented
        return self._field_name == other._field_name and type(self._error) is type(other._error)

    def __hash__(self) -> int:
        return hash((self._field_name, type(self._error).__name__))

    def __getattr__(self, name):
        # Reached only for names the sentinel does not have. See the class
        # docstring for why a str method raises the underlying error.
        if name in UndecryptableValue._STR_METHODS:
            from .exceptions import EncryptionError, as_lookup_error

            error = self._error
            if isinstance(error, EncryptionError):
                raise as_lookup_error(error) from error
        raise AttributeError(f"{type(self).__name__!r} object has no attribute {name!r}")

    @property
    def error(self) -> Exception:
        """The underlying decryption exception."""
        return self._error

    @property
    def field_name(self) -> str:
        """The attname of the field that failed to decrypt."""
        return self._field_name


def is_undecryptable(value) -> bool:
    """Return True if ``value`` is a lenient-mode decrypt-failure sentinel.

    Convenience wrapper around ``isinstance(value, UndecryptableValue)``
    so consuming code does not have to import the class.
    """
    return isinstance(value, UndecryptableValue)


# ContextVar (not threading.local) so the strict flag propagates correctly
# across ``sync_to_async`` and asyncio task boundaries. Each ``strict_mode``
# entry sets the var; the matching exit resets it to the prior token.
_strict_mode_var: contextvars.ContextVar[bool] = contextvars.ContextVar(
    "encryption_suite_strict_mode",
    default=False,
)


@contextlib.contextmanager
def strict_mode():
    """Context manager that escalates every decrypt to strict mode.

    Inside the ``with`` block, encrypted-field reads that fail to
    decrypt raise :class:`~encryption_suite.exceptions.EncryptedFieldDecryptionError`
    instead of returning an :class:`UndecryptableValue` sentinel. Use
    this around code that must not silently degrade — typically DRF
    serializers, exports, and background jobs that re-process plaintext::

        from encryption_suite import strict_mode

        with strict_mode():
            data = MyModelSerializer(instance).data

    Per-field ``decrypt_mode="strict"`` overrides have the same effect
    locally; the context manager is the ergonomic choice when an entire
    code path should be strict regardless of model declarations.

    Implemented with ``ContextVar`` so it propagates across
    ``sync_to_async`` boundaries.
    """
    token = _strict_mode_var.set(True)
    try:
        yield
    finally:
        _strict_mode_var.reset(token)


#: Refuse every encrypted-attribute read.
_REFUSE_ALL = "all"
#: Refuse an encrypted-attribute read whose key set has no silo in the current context.
_REFUSE_WITHOUT_SILO = "without_silo"

#: Set inside :func:`_refusing_encrypted_reads`. A ``ContextVar`` so the refusal
#: covers only the call that opened it, on its own thread or task.
_refuse_reads_var: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "encryption_suite_refuse_reads",
    default=None,
)

#: Instance-dict key marking an instance ``EncryptionAdminMixin``'s queryset loaded.
ADMIN_LOADED = "_encryption_suite_admin_loaded"


class _EncryptedReadRefused(Exception):
    """Raised by an encrypted-attribute read inside :func:`_refusing_encrypted_reads`.

    Control flow, not a failure: the code that opened the block catches it, so it
    never reaches a view or a user. ``key_set`` is set when the read was refused
    because its key set has no silo in the current context, which the catcher
    logs; it is ``None`` for a read refused because every read was.
    """

    def __init__(self, attname: str, key_set: str | None = None):
        super().__init__(attname)
        self.attname = attname
        self.key_set = key_set


@contextlib.contextmanager
def _refusing_encrypted_reads(mode: str):
    """Make encrypted-attribute reads raise :class:`_EncryptedReadRefused`.

    With ``_REFUSE_ALL`` every read raises; with ``_REFUSE_WITHOUT_SILO`` only a
    read whose key set has no silo in the current context does, which is a read
    that could only fail, and not inside :func:`strict_mode`, where that read
    goes on to fail as strict reads do. Either way the read raises before it
    decrypts anything, so the caller learns that the code it ran wanted a
    plaintext value without one being produced. A block opened inside a
    ``_REFUSE_ALL`` block stays ``_REFUSE_ALL``: a nested call cannot loosen the
    refusal around it.
    """
    if _refuse_reads_var.get() == _REFUSE_ALL:
        mode = _REFUSE_ALL
    token = _refuse_reads_var.set(mode)
    try:
        yield
    finally:
        _refuse_reads_var.reset(token)


def _has_current_silo(key_set: str) -> bool:
    """True if *key_set* has a silo in the current context.

    A system key set always does. An adapter that cannot be built answers True,
    so the read goes on and reports that failure the usual way.
    """
    if is_system_key_set(key_set):
        return True
    from .exceptions import EncryptionError
    from .registry import get_silo_adapter

    try:
        return get_silo_adapter(key_set).get_current_silo() is not None
    except EncryptionError:
        return True


def _guard_str(model) -> None:
    """Wrap ``model.__str__`` so it never hands ``str()`` a failed decrypt.

    ``str()`` requires a ``str`` back, and a ``__str__`` that returns an encrypted
    field returns the :class:`UndecryptableValue` sentinel when the decrypt
    fails, so ``str(obj)`` raises ``TypeError``. Django calls ``str(obj)`` in
    places no project code can intercept: the admin's action checkbox, page
    titles, history log, and the delete confirmation's list of cascaded rows.
    The wrapped ``__str__`` gives Django's default ``<Model> object (<pk>)``
    instead when:

    - the original reads an encrypted field whose key set has no silo in the
      current context. The read is refused before it decrypts, and one WARNING
      line names the field, so a task or view missing its context leaves a
      trace. Inside :func:`strict_mode` the read is not refused: it fails as a
      strict read, with the engine's ERROR line and a typed error;
    - the original returns a sentinel, from a decrypt that failed for another
      reason. That decrypt has logged its error;
    - the instance was loaded by ``EncryptionAdminMixin`` and the original reads
      any encrypted field. The admin never decrypts, and the history log, which
      stores ``str(obj)``, never holds plaintext.

    Otherwise the original's result is returned unchanged.
    """
    original = model.__str__
    if getattr(original, "_encryption_suite_guarded", False):
        return

    @functools.wraps(original)
    def __str__(self):
        mode = _REFUSE_ALL if self.__dict__.get(ADMIN_LOADED) else _REFUSE_WITHOUT_SILO
        with _refusing_encrypted_reads(mode):
            try:
                result = original(self)
            except _EncryptedReadRefused as refused:
                if refused.key_set is not None:
                    _log_str_without_silo(type(self), refused)
                return models.Model.__str__(self)
        if isinstance(result, UndecryptableValue):
            return models.Model.__str__(self)
        return result

    __str__._encryption_suite_guarded = True
    model.__str__ = __str__


def _log_str_without_silo(model, refused: _EncryptedReadRefused) -> None:
    """Log the WARNING line for a ``__str__`` read refused for want of a silo."""
    from .engine import _NO_SILO_HINT

    logger.warning(
        "A model's __str__ read an encrypted field with no silo in the current context, so it returned "
        'the default label. field="%s" key_set=%s hint="%s"',
        f"{model._meta.label}.{refused.attname}",
        refused.key_set,
        _NO_SILO_HINT,
    )


#: Set inside :func:`allow_plaintext_writes`. A ``ContextVar`` for the same
#: reason strict mode uses one: it propagates across ``sync_to_async``.
_plaintext_writes_var: contextvars.ContextVar[bool] = contextvars.ContextVar(
    "encryption_suite_plaintext_writes",
    default=False,
)


@contextlib.contextmanager
def allow_plaintext_writes():
    """Context manager that lets plaintext reach an encrypted column.

    Writes that skip the field's ``pre_save`` — ``QuerySet.update()``,
    ``bulk_update()``, a column default a migration applies — are refused,
    because the value would be stored as given and the column would quietly stop
    being encrypted. A column moving *out* of encryption is the one time that is
    the point::

        from encryption_suite import allow_plaintext_writes

        with allow_plaintext_writes():
            decrypt_field(apps, "notes", "Note", "title")

    The package's own reverse-migration helpers hold this open over their writes.
    A project needs it only where it means to leave a column in plaintext, and
    anything inside the block is unencrypted data in an encrypted column's row —
    which is readable, because a value with no storage marker is handed back as
    it stands, and findable by nothing, because the blind index is not written.
    """
    token = _plaintext_writes_var.set(True)
    try:
        yield
    finally:
        _plaintext_writes_var.reset(token)


def _resolve_log_silo_uid(engine) -> str:
    """Best-effort silo uid for log context only."""
    resolver = getattr(engine, "_resolve_silo_uid", None)
    if not callable(resolver):
        return ""
    try:
        silo_uid = resolver()
    except Exception:
        return ""
    return str(silo_uid) if silo_uid else ""


# ---------------------------------------------------------------------------
# AAD column resolution
# ---------------------------------------------------------------------------


def _resolve_aad_columns(model, names, owner: str) -> tuple[str, ...]:
    """Return the attnames an ``aad=`` declaration names, in declaration order.

    *owner* is how the declaration is named in an error, for example
    ``"myapp.Note.body aad="``. Resolution rules:

    * ``"pk"`` -> the model's primary key attname.
    * A field name -> its ``attname`` (FKs become ``<name>_id``).

    Invalid entries (typos, traversal syntax) raise ``TypeError`` or
    ``ValueError``. The ``class_prepared`` listener records the error and the
    field's check reports it, so a mistake surfaces as a system check error
    rather than crashing app loading.
    """
    if not names:
        return ()
    if isinstance(names, str):
        # Catch the common mistake of writing a single string instead of a
        # one-tuple. "pk" iterates as 'p', 'k' otherwise.
        raise TypeError(
            f"{owner} must be a tuple or list of column names, got a single string {names!r}. "
            f"Did you mean ({names!r},)?"
        )
    resolved: list[str] = []
    for name in names:
        if not isinstance(name, str):
            raise TypeError(f"{owner} entries must be strings, got {type(name).__name__}: {name!r}")
        if "." in name or "__" in name:
            raise ValueError(
                f"{owner} entry {name!r} uses traversal syntax. AAD columns must name a column on "
                f"this model directly. For a foreign key, use the field name "
                f"(e.g. 'person') or its attname ('person_id') — not "
                f"'person.id' or 'person__name'."
            )
        if name == "pk":
            resolved.append(model._meta.pk.attname)
            continue
        try:
            field = model._meta.get_field(name)
        except FieldDoesNotExist:
            raise ValueError(f"{owner} references {name!r}, but no such field exists on the model.") from None
        if field.is_relation and not field.concrete:
            raise ValueError(f"{owner} entry {name!r} is a reverse relation, not a column on this model.")
        resolved.append(field.attname)
    return tuple(resolved)


def _aad_owner(field) -> str:
    """How a field's ``aad=`` declaration is named in a check or an error."""
    model = getattr(field, "model", None)
    label = f"{model._meta.label}.{field.name}" if model is not None else field.name
    return f"{label} aad="


def _resolve_field_aad(model, field) -> None:
    """Resolve *field*'s ``aad=`` to attnames on *model*, once, when the class is prepared.

    A declaration that does not resolve leaves the field unbound; the field's
    check resolves it again and reports the error (E020).
    """
    try:
        field._aad_attnames = _resolve_aad_columns(model, field.aad, _aad_owner(field))
    except (TypeError, ValueError):
        field._aad_attnames = ()


def _deconstruct_aad(aad):
    """``aad=`` as a migration records it: a tuple, unless malformed (the check reports that)."""
    return aad if isinstance(aad, str) else tuple(aad)


def aad_attnames(field) -> tuple[str, ...]:
    """The attnames *field* binds into its AAD; empty for a field that binds none."""
    return getattr(field, "_aad_attnames", ())


def encode_aad(label: str, pairs) -> bytes:
    """Encode a field's AAD: its ``app.Model.field`` label, then each ``(attname, value)``.

    Pairs are sorted by attname. Every element is UTF-8 encoded and written as
    ``<byte length>:<bytes>``, so no value can shift a boundary between
    elements. No pairs yields ``b""``: a field that binds nothing has no AAD.
    """
    pairs = sorted(pairs)
    if not pairs:
        return b""
    out = bytearray()
    for element in (label, *(part for pair in pairs for part in pair)):
        data = element.encode("utf-8")
        out += f"{len(data)}:".encode("ascii")
        out += data
    return bytes(out)


def _normalize_aad_value(model, attname: str, value):
    """Normalize one bound value through its field's ``to_python``.

    A foreign key's ``to_python`` defers to its target field, so an ``_id``
    attname normalizes the way the column it points at does. A value the field
    rejects raises ``ValueError``.
    """
    field = next((f for f in model._meta.concrete_fields if f.attname == attname), None)
    if field is None:
        return value
    try:
        return field.to_python(value)
    except ValidationError as exc:
        raise ValueError(
            f"AAD column {attname!r} on {model._meta.label} holds a value its field rejects: {exc.messages}"
        ) from exc


def build_aad(model, field_attname: str, attnames, source) -> bytes:
    """Build the AAD bytes for one field from the bound values on *source*.

    *source* is anything the bound attnames can be read off: an instance, a
    historical-model row, or a namespace of column values. Each value is
    normalized (see :func:`_normalize_aad_value`), then ``str()``-ed and
    encoded by :func:`encode_aad`. A value that is ``None`` after normalizing
    raises ``ValueError``.
    """
    if not attnames:
        return b""
    label = f"{model._meta.label}.{field_attname}"
    pairs = []
    for attname in attnames:
        value = getattr(source, attname, None)
        if value is not None:
            value = _normalize_aad_value(model, attname, value)
        if value is None:
            raise ValueError(
                f"Cannot build the AAD for {label}: AAD column {attname!r} is None on this row. AAD-bound "
                f"columns must have a value before the field is saved."
            )
        pairs.append((attname, str(value)))
    return encode_aad(label, pairs)


def describe_aad_column(value, *, show_value: bool) -> str:
    """Render one AAD-bound column's value for a log line or a report.

    With *show_value* off, only whether it holds anything: ``<populated>`` or
    ``<empty>``. Which bound column moved is usually the whole diagnosis, and
    saying so needs no value — so that is all a line carries unless the
    deployment has said its schema binds nothing personal.
    """
    if show_value:
        return f"{value}"
    return "<empty>" if value is None or value == "" else "<populated>"


def _build_row_identity(model, instance, field, *, show_values: bool | None = None) -> str:
    """Build a short ``pk=...,col=...`` string identifying a row for log output.

    Includes the row's pk plus every column *field* binds into its AAD, so an
    operator reading a decrypt-failure log can locate the offending row in the
    admin or DB without further forensic work. Each column's value is included
    only when ``LOG_AAD_VALUES`` is on (or *show_values* says so); otherwise the
    line says whether the column is populated. Just the pk when the field binds
    no columns.
    """
    if show_values is None:
        from .conf import enc_settings

        show_values = bool(enc_settings.LOG_AAD_VALUES)
    cols = aad_attnames(field)
    parts: list[str] = []
    pk_attname = model._meta.pk.attname
    pk_val = getattr(instance, "pk", None)
    if pk_val is not None:
        parts.append(f"pk={pk_val}")
    for col in cols:
        if col == pk_attname:
            continue
        value = getattr(instance, col, None)
        parts.append(f"{col}={describe_aad_column(value, show_value=show_values)}")
    return ",".join(parts)


def _build_aad_for_instance(model, field, instance) -> bytes:
    """Build the AAD bytes for *field* on *instance*, from the field's own ``aad=``.

    Returns ``b""`` when the field binds no columns. See :func:`build_aad`.
    """
    return build_aad(model, field.attname, aad_attnames(field), instance)


def _build_write_aad(model, field, instance, *, file: bool) -> bytes:
    """Build the AAD for a write, raising a typed error when it cannot be built.

    The read paths translate a failure from :func:`_build_aad_for_instance` into
    a decryption failure themselves. A write has no such caller, so a ``None``
    AAD column would otherwise escape ``save()`` as a bare ``ValueError``.
    """
    try:
        return _build_aad_for_instance(model, field, instance)
    except ValueError as exc:
        from ._internal import operator_error_text
        from .exceptions import (
            GENERIC_ENCRYPT_FAILED_USER_MESSAGE,
            EncryptedFieldEncryptionError,
            EncryptedFileEncryptionError,
        )

        detail = operator_error_text(exc)
        logger.error(
            "The additional authenticated data for an encrypted write could not be built, so the value was "
            'not saved. error_code=%s detail="%s"',
            (EncryptedFileEncryptionError if file else EncryptedFieldEncryptionError).code,
            detail,
        )
        if file:
            raise EncryptedFileEncryptionError(GENERIC_ENCRYPT_FAILED_USER_MESSAGE, detail=detail) from exc
        raise EncryptedFieldEncryptionError(GENERIC_ENCRYPT_FAILED_USER_MESSAGE, detail=detail) from exc


def _check_aad(field):
    """Report what a field's ``aad=`` declaration will cost it.

    Three findings, all about the same property: AAD is part of the key to the
    field's encrypted value, so a bound column's value must be readable,
    present, and stable for as long as the ciphertext is.
    """
    model = getattr(field, "model", None)
    if model is None or not field.aad:
        return []
    owner = _aad_owner(field)
    try:
        resolved = _resolve_aad_columns(model, field.aad, owner)
    except (TypeError, ValueError) as exc:
        return [Error(str(exc), obj=field, id="encryption_suite.E020")]
    errors = []
    # If pk is part of the AAD tuple, the pk must be known at INSERT time.
    # AutoField / BigAutoField pks are assigned by the DB on insert, so
    # the AAD computed in pre_save would not include the eventual pk.
    if model._meta.pk.attname in resolved and isinstance(
        model._meta.pk, (models.AutoField, models.BigAutoField, models.SmallAutoField)
    ):
        errors.append(
            Error(
                f"{owner} includes 'pk', but the model's primary key is "
                f"{type(model._meta.pk).__name__}. Auto-incrementing pks "
                f"are assigned by the database on insert, so the value "
                f"is not available when AAD is computed. Use a "
                f"client-assigned primary key (e.g. UUIDField with "
                f"primary_key=True) or remove 'pk' from aad=.",
                obj=field,
                id="encryption_suite.E021",
            )
        )
    by_attname = {f.attname: f for f in model._meta.concrete_fields}
    for attname in resolved:
        column = by_attname.get(attname)
        if column is None:
            continue
        errors.extend(_check_aad_column(field, owner, model, column))
    return errors


def _check_aad_column(field, owner: str, model, column):
    """Findings about one column bound into *field*'s AAD."""
    from django.core import checks

    label = f"{model._meta.label}.{column.name}"
    if isinstance(column, (_CiphertextFieldMixin, _EncryptedFileFieldBase)):
        # Reading the column to build the AAD goes through the decrypting
        # descriptor, and that decrypt needs an AAD of its own built from
        # the same column. Nothing breaks at deploy and nothing breaks at
        # write; it breaks on every read of the model, which is the worst
        # time to find out.
        return [
            Error(
                f"{owner} names {column.name!r}, which is itself an encrypted field "
                f"({type(column).__name__}). An AAD column is read to "
                f"decrypt the value, so binding an encrypted column to the "
                f"AAD makes decrypting it depend on another decrypt. Bind a column "
                f"stored in plaintext instead.",
                obj=field,
                id="encryption_suite.E022",
            )
        ]
    if not column.null:
        return []
    # Nullable is a warning, not an error: the schema is legal, the rows
    # written so far are fine, and only the ones written after the column
    # goes NULL are lost. It is worth saying at deploy because that is
    # while it is still a schema decision — afterwards it is a migration
    # over live ciphertext.
    if column.is_relation and getattr(column, "remote_field", None) is not None:
        on_delete = getattr(column.remote_field, "on_delete", None)
        if on_delete is models.SET_NULL:
            detail = "It is a foreign key with on_delete=SET_NULL, so deleting the row it points at sets it to NULL."
        else:
            detail = "It is a nullable foreign key."
    else:
        detail = "It is nullable."
    return [
        checks.Warning(
            f"{owner} binds {column.name!r}. {detail} Encryption refuses to write a row "
            f"whose AAD column is None, and a row whose AAD column became "
            f"None after it was written can no longer be decrypted. Make "
            f"{label} non-nullable, or drop it from aad=.",
            obj=field,
            id="encryption_suite.W054",
        )
    ]


# ---------------------------------------------------------------------------
# class_prepared listener: resolve each encrypted field's aad= once per model
# and install the encryption_suite_errors property on models with encrypted fields
# ---------------------------------------------------------------------------


def _model_has_encrypted_field(model) -> bool:
    """True if ``model`` declares at least one encrypted field.

    Walks ``_meta.local_fields`` rather than ``_meta.get_fields()``: the
    latter builds the cross-model relation tree, which requires the app
    registry to be ready, and this helper runs inside the
    ``class_prepared`` signal — fired *before* the registry finishes
    loading. ``local_fields`` is populated as fields contribute to the
    class, so it's safe to read here. The file fields are checked
    explicitly because they don't subclass ``_CiphertextFieldMixin``.
    """
    for f in model._meta.local_fields:
        if isinstance(f, _CiphertextFieldMixin):
            return True
        if isinstance(f, _EncryptedFileFieldBase):
            return True
    return False


def _encryption_suite_errors_getter(self) -> dict:
    """Property body installed on models with encrypted fields.

    Returns the dict populated by the lenient-mode descriptor — empty
    by default. Reading from a freshly-constructed instance returns an
    empty dict; the dict is created lazily on first decrypt failure.
    """
    return self.__dict__.get("_encryption_suite_errors") or {}


def _on_class_prepared(sender, **kwargs):
    # Each encrypted field's aad=, resolved against the model it is declared on.
    # An error is recorded for the field's check() to report, so it appears as
    # a system check error rather than crashing app loading.
    for field in sender._meta.local_fields:
        if isinstance(field, (_CiphertextFieldMixin, _EncryptedFileFieldBase)):
            _resolve_field_aad(sender, field)

    # Expose ``instance.encryption_suite_errors`` as a property on every
    # model that has encrypted fields, so view and template code can
    # check ``if obj.encryption_suite_errors:`` without importing helpers or
    # poking at the underscore attribute. Only install if the model
    # does not already define ``encryption_suite_errors`` (respect explicit
    # user customization).
    if _model_has_encrypted_field(sender) and not hasattr(sender, "encryption_suite_errors"):
        sender.encryption_suite_errors = property(_encryption_suite_errors_getter)

    # A multi-table child or a proxy can define its own ``__str__`` over a
    # parent's encrypted field, so the parents count too.
    if any(_model_has_encrypted_field(m) for m in (sender, *sender._meta.get_parent_list())):
        _guard_str(sender)

    # The companion digest columns, now that it is knowable which of them the
    # model already declares. class_prepared does not fire for an abstract
    # model, which is what keeps this off one.
    for field in list(sender._meta.local_fields):
        if _has_digest_column(field):
            field.contribute_index_column(sender)

    # The uniqueness check Django will not build, because the field reports no
    # field-level unique for it to build one from.
    if not getattr(sender, "_encryption_suite_validates_unique", False) and _unique_indexed_fields(sender._meta):
        _install_validate_unique(sender)

    # Keep a narrowed save from leaving a digest behind, and keep a row and its
    # entry in the shared table from being written apart.
    if not sender._meta.abstract:
        from . import blind_index

        watched = blind_index.save_in_transaction(sender)
        if watched:
            blind_index.install_synchronization(sender)
        if not getattr(sender, "_encryption_suite_wraps_save", False) and (
            watched or any(_has_digest_column(f) for f in sender._meta.local_fields)
        ):
            _install_save_wrapper(sender)


class_prepared.connect(_on_class_prepared, dispatch_uid="encryption_suite.aad_columns_resolve")


def _has_digest_column(field) -> bool:
    """Whether *field* keeps its blind index in a companion column of its own table."""
    return (
        isinstance(field, _CiphertextFieldMixin)
        and field.blind_index
        and field.blind_index_storage == BLIND_INDEX_STORAGE_COLUMN
    )


def _widened_update_fields(meta, update_fields):
    """Return *update_fields* with the digest column of every named field added."""
    named = set(update_fields)
    digests = {
        field.index_field_name
        for field in meta.concrete_fields
        if _has_digest_column(field) and (field.name in named or field.attname in named)
    }
    return named | digests if digests else update_fields


def _unique_indexed_fields(meta):
    """Every field on *meta*'s model whose plaintext is held unique over a digest."""
    return [
        f for f in meta.concrete_fields if isinstance(f, _CiphertextFieldMixin) and f.blind_index and f.index_unique
    ]


def _install_validate_unique(model):
    """Wrap ``model.validate_unique`` so a duplicate is a form error, not an IntegrityError.

    Django builds its uniqueness checks from ``field.unique``, which this field
    answers ``False`` to — it has to, or the database would be asked for an index
    over ciphertext. So the check Django would have run is run here instead,
    against the digest, which is where the uniqueness actually lives.

    The error is raised through ``unique_error_message``, Django's own builder:
    that picks up the translated ``"%(model_name)s with this %(field_label)s
    already exists."`` and a project's ``error_messages={"unique": ...}``
    override, keyed on the field and coded ``"unique"``. So a ModelForm renders
    it beside the input exactly as it renders a plain unique field's, and there
    is no new string to translate.

    Installed once per model, iterating every such field on it, so a model with
    two of them neither wraps twice nor drops one. What remains is the race a
    plain ``unique=True`` has too: a concurrent insert between this query and the
    commit still surfaces as ``IntegrityError`` from the constraint.
    """
    original = model.validate_unique

    @functools.wraps(original)
    def validate_unique(self, exclude=None):
        from .exceptions import EncryptionError

        errors = {}
        try:
            original(self, exclude=exclude)
        except ValidationError as exc:
            errors = exc.update_error_dict(errors)
        for field in _unique_indexed_fields(self._meta):
            if exclude and field.name in exclude:
                continue
            value = getattr(self, field.attname, None)
            # Nothing to collide with: a row holding no value is not a duplicate
            # of another holding none, which is what a nullable unique column
            # means everywhere else.
            if value is None or isinstance(value, UndecryptableValue):
                continue
            # The digest needs the silo's index key, which a first write may have
            # to create through the KMS. A failure there is the same one save()
            # would meet, so it becomes a form-wide error carrying the generic
            # message rather than escaping is_valid() as a 500. The engine has
            # already logged the detail. Every later field needs the same key.
            try:
                digest = field.index_digest(value)
            except EncryptionError as exc:
                errors.setdefault(NON_FIELD_ERRORS, []).append(ValidationError(str(exc), code=exc.code))
                break
            if field.index_conflict(digest, exclude_pk=self.pk):
                errors.setdefault(field.name, []).append(self.unique_error_message(type(self), (field.name,)))
        if errors:
            raise ValidationError(errors)

    model.validate_unique = validate_unique
    model._encryption_suite_validates_unique = True


def _install_save_wrapper(model):
    """Wrap ``model.save`` so a blind index cannot be left behind by one.

    Two jobs, both about a digest kept somewhere other than the column being
    written:

    ``save(update_fields=["email"])`` writes that column and no other, which
    would leave a companion column holding the value before it — and a lookup
    compares the digest, so the row stops answering to its own value. The
    companion is a column the developer did not declare and cannot see, so it is
    added for them rather than demanded of them.

    A digest in the shared table is a second statement, written by a
    ``post_save`` receiver because an insert has no primary key before the row
    exists. ``post_save`` runs outside the block ``save_base`` wraps its own
    writes in — and for a model with no parents that block is not a transaction
    at all — so this opens one, and the row and its entry commit together or
    neither does.

    Wrapping the class rather than ``Model.save`` reaches a model this package
    does not own, and wrapping outside a project's own ``save`` override means
    what that override passes along is already widened. Installed once per
    model; the wrapper reads the instance's own ``_meta``, so a subclass
    inherits a working one. ``asave`` goes through ``self.save``, so it is
    covered too.
    """
    original = model.save

    @functools.wraps(original)
    def save(self, *, update_fields=None, using=None, **kwargs):
        from . import blind_index

        if update_fields:
            update_fields = _widened_update_fields(self._meta, update_fields)
        if blind_index.save_in_transaction(type(self)):
            with blind_index.atomic_for(using or router.db_for_write(type(self), instance=self)):
                return original(self, update_fields=update_fields, using=using, **kwargs)
        return original(self, update_fields=update_fields, using=using, **kwargs)

    model.save = save
    model._encryption_suite_wraps_save = True


# ---------------------------------------------------------------------------
# Lazy-decrypt descriptor
# ---------------------------------------------------------------------------


class EncryptedAttributeDescriptor(DeferredAttribute):
    """Descriptor that lazily decrypts an encrypted column on attribute read.

    Inherits ``DeferredAttribute`` so that columns deferred from the
    queryset (e.g. ``Model.objects.only(...)``) trigger Django's normal
    refresh-from-db machinery on first access. Layered on top of that,
    this descriptor:

    1. Detects ciphertext in ``instance.__dict__``: a value stamped by
       ``from_db_value`` as read from the database. A ciphertext-shaped
       string a caller assigned is not decrypted unless it equals what the
       row already holds.
    2. Computes AAD from the live instance state (no eager ``post_init``
       decrypt needed — the descriptor has the instance in scope and
       can build AAD on demand).
    3. Calls the engine to decrypt and replaces the ciphertext with
       plaintext in ``__dict__`` so subsequent reads skip the engine.
    4. On failure, escalates to strict (raises) or lenient (stores an
       :class:`UndecryptableValue` sentinel and records the exception
       on ``instance._encryption_suite_errors``).

    Mode resolution: per-field ``decrypt_mode="strict"`` wins, then the
    :func:`strict_mode` ContextVar wins, otherwise lenient.

    Plaintext values cached in ``__dict__`` survive subsequent reads
    until the instance is re-loaded from the database. ``pre_save``
    inspects ``__dict__`` directly and re-encrypts only when a plaintext
    value is present, so reads followed by saves don't decrypt-then-
    re-encrypt unchanged ciphertext (see ``_EncryptedFieldMixin.pre_save``).

    This is a **data descriptor**: defining ``__set__`` is required, not
    just for in-memory assignments but to give the descriptor priority
    over ``instance.__dict__`` lookups. A non-data descriptor (just
    ``__get__``, like Django's plain ``DeferredAttribute``) is bypassed
    by attribute access whenever ``__dict__`` already holds a value —
    which is the common case after ``from_db_value`` populates the
    instance with ciphertext. Without ``__set__``, ``obj.notes`` would
    return the raw ciphertext string from ``__dict__`` and our decrypt
    layer would never run.
    """

    def __set__(self, instance, value):
        """Store the value verbatim in the instance dict.

        Called both when the ORM populates a field after ``from_db_value``
        and when application code does ``instance.notes = "..."``. Both
        paths land here; ``__get__`` and ``pre_save`` tell stored
        ciphertext (stamped by ``from_db_value``) from a caller's value and
        act accordingly.

        A failure recorded for this column by an earlier lenient read is
        dropped: ``pre_save`` consults that record to know it must leave the
        stored value alone, and a caller assigning a fresh value has said
        otherwise.
        """
        instance.__dict__[self.field.attname] = value
        errors = instance.__dict__.get("_encryption_suite_errors")
        if errors:
            errors.pop(self.field.attname, None)

    def __get__(self, instance, cls=None):
        if instance is None:
            return self
        refusal = _refuse_reads_var.get()
        if refusal == _REFUSE_ALL:
            raise _EncryptedReadRefused(self.field.attname)
        data = instance.__dict__
        attname = self.field.attname
        # Inherited from DeferredAttribute: if the column was deferred,
        # refresh it from the database before continuing. After refresh
        # the value will be in __dict__ as ciphertext (from_db_value is
        # a passthrough on encrypted fields).
        if attname not in data:
            val = self._check_parent_chain(instance)
            if val is None:
                instance.refresh_from_db(fields=[attname])
            else:
                data[attname] = val
        value = data[attname]
        # None means the column was NULL.
        if value is None:
            return None
        # Already-resolved sentinels stay as-is — no point re-attempting
        # a decrypt that has already failed for this instance.
        if isinstance(value, UndecryptableValue):
            return value
        # Ciphertext awaiting decrypt — but only ciphertext the package read
        # from the database (stamped by ``from_db_value``), or a value equal
        # to what this row holds. A ciphertext-shaped string a caller assigned
        # is returned as it stands: decrypting it would read another row's
        # value under this one. It is not replaced by the fallback sentinel
        # either, because ``pre_save`` keeps the stored value for a sentinel
        # and would drop the caller's input without an error; left as is, the
        # save refuses it.
        if isinstance(value, str) and self.field._is_ciphertext(value):
            from .engine import is_stamped, stamp

            if not is_stamped(value):
                if not self.field._matches_stored(instance, value):
                    return value
                value = stamp(value)
                data[attname] = value
            if (
                refusal == _REFUSE_WITHOUT_SILO
                and not _strict_mode_var.get()
                and not _has_current_silo(self.field.key_set)
            ):
                raise _EncryptedReadRefused(attname, self.field.key_set)
            return self._decrypt_and_cache(instance, value)
        # Plaintext — cached from a prior read on this instance, or
        # assigned in-memory by the caller. Return as-is.
        return value

    def _decrypt_and_cache(self, instance, ciphertext: str):
        """Run the engine, cache the result on the instance, and return it.

        On strict mode the engine exception propagates. On lenient mode
        the exception is captured: a sentinel is cached in place of the
        ciphertext, and the exception is recorded on
        ``instance._encryption_suite_errors[attname]`` for code paths that
        want to surface details.

        Lenient mode captures any :class:`EncryptionError` — not only
        ciphertext-rejection (``EncryptedFieldDecryptionError``) but also a
        missing DEK or an unavailable KEK (``MissingDekError``,
        ``KekUnavailableError``, …). A read should degrade to the fallback
        label rather than 500 whenever the plaintext cannot be produced, for
        whatever reason.
        """
        from .exceptions import (
            GENERIC_DECRYPT_FAILED_USER_MESSAGE,
            EncryptedFieldDecryptionError,
            EncryptionError,
        )

        field = self.field
        attname = field.attname
        model = type(instance)
        field_label = f"{model._meta.label}.{attname}"

        def _degrade_or_raise(error):
            """Strict: re-raise. Lenient: record the error and cache the fallback."""
            if _is_strict(field):
                raise error
            fallback = field._fallback_value(error)
            errors = instance.__dict__.setdefault("_encryption_suite_errors", {})
            errors[attname] = error
            instance.__dict__[attname] = fallback
            return fallback

        def _as_decrypt_failure(exc, what):
            """Log and wrap a non-package error as an EncryptedFieldDecryptionError."""
            from ._internal import operator_error_text

            logger.error(
                "Could not %s for an encrypted field, so its value cannot be read. "
                'error_code=%s field="%s" detail="%s"',
                what,
                EncryptedFieldDecryptionError.code,
                field_label,
                operator_error_text(exc),
            )
            wrapped = EncryptedFieldDecryptionError(
                GENERIC_DECRYPT_FAILED_USER_MESSAGE,
                detail=f'field="{field_label}" Failed to {what}: {exc}',
            )
            wrapped.__cause__ = exc
            return wrapped

        # 1. Build AAD / row-identity. A failure here means the value cannot be
        #    produced, so treat it as a decryption failure (degrades in lenient).
        try:
            aad = _build_aad_for_instance(model, field, instance)
            row_identity = _build_row_identity(model, instance, field)
        except Exception as exc:
            return _degrade_or_raise(_as_decrypt_failure(exc, "build AAD"))

        # 2. Decrypt. Only a EncryptionError is a handled failure (decryption,
        #    missing/unavailable key, or a configuration/context error — all
        #    already logged at their source). Anything else is an unexpected bug
        #    and propagates loud rather than being silently degraded.
        try:
            plaintext = field._decrypt_value(
                ciphertext,
                aad=aad,
                field_label=field_label,
                row_identity=row_identity,
            )
        except EncryptionError as exc:
            return _degrade_or_raise(exc)

        # 3. Parse authenticated plaintext into the field's Python type. A parse
        #    failure is treated as a decryption failure (degrades in lenient).
        if hasattr(field, "_from_storage_str"):
            try:
                plaintext = field._from_storage_str(plaintext)
            except Exception as exc:
                return _degrade_or_raise(_as_decrypt_failure(exc, "parse decrypted value"))

        instance.__dict__[attname] = plaintext
        return plaintext


def _is_strict(field) -> bool:
    """Resolve whether the current decrypt should run in strict mode.

    Per-field ``decrypt_mode="strict"`` wins (a security-sensitive field
    should always raise), then the active :func:`strict_mode` context
    flag, otherwise lenient.
    """
    if getattr(field, "_decrypt_mode", None) == "strict":
        return True
    return _strict_mode_var.get()


def _resolve_fallback(field):
    """Return the fallback label for an encrypted field.

    Per-field ``fallback_label=`` overrides the package default. The
    return value may be a plain string or a ``gettext_lazy`` proxy; the
    sentinel calls ``str()`` on it at render time, which resolves
    proxies to the active locale.
    """
    custom = getattr(field, "_fallback_label", None)
    if custom is not None:
        return custom
    return DEFAULT_FALLBACK_LABEL


def _check_blank_requires_null(field):
    """Report an optional encrypted field that cannot hold its own empty value.

    Django fills a non-nullable ``blank=True`` column with ``""``, both as the
    form's empty value and as the default a migration adds the column with. For a
    silo-encrypted column that value arrives without ever passing through the
    engine, so nothing can tell it from a value awaiting encryption, and the
    conversion that would settle the question needs a silo and a KMS call per row.
    The pair ``blank=True, null=False`` therefore asks the column to hold what it
    cannot. Reported here, against the field, rather than left to surface during a
    migration that names nothing the author just wrote.

    Not applied to a column of a system key set: its key needs no silo context and its
    store is usually the local env key store, so an empty string there converts like any
    other value and is an ordinary one.
    """
    if not field.blank or field.null:
        return []
    if is_system_key_set(getattr(field, "key_set", DEFAULT_KEY_SET)):
        return []
    return [
        Error(
            f"{field.__class__.__name__} sets blank=True without null=True. "
            f"Encrypted fields cannot store the empty string, which Django uses "
            f"for a blank, non-nullable column.",
            hint="Add null=True to this field.",
            obj=field,
            id="encryption_suite.E025",
        )
    ]


# ---------------------------------------------------------------------------
# Blind index
# ---------------------------------------------------------------------------

#: ``normalize=`` values. ``casefold`` indexes and compares the case-folded
#: value, which is what an email address or a username wants; ``None`` indexes
#: the value as given.
NORMALIZE_CASEFOLD = "casefold"
NORMALIZE_CHOICES = (None, NORMALIZE_CASEFOLD)

#: ``blind_index_storage=`` values — which table holds the digest. ``column`` adds a
#: companion column to the field's own table, which is one table and no join;
#: ``table`` puts the digest in a table this package owns, which adds no schema
#: to the model's app and is therefore the only option for a model the project
#: does not own.
BLIND_INDEX_STORAGE_COLUMN = "column"
BLIND_INDEX_STORAGE_TABLE = "table"
BLIND_INDEX_STORAGE_CHOICES = (BLIND_INDEX_STORAGE_COLUMN, BLIND_INDEX_STORAGE_TABLE)

#: Hex digits in a stored digest. A SHA-256 digest, stored whole: a blind index
#: that has to hold a column unique cannot afford the collisions a truncation
#: invites, because a collision there is a refused write for a value nobody else
#: holds. Sixty-four ASCII characters take a plain index on every database
#: Django supports.
INDEX_DIGEST_LEN = 64

#: What ``blind_index_storage="column"`` calls the companion column: the field's name
#: plus this.
INDEX_COLUMN_SUFFIX = "_index"

#: Characters a generated constraint name runs to. Django does not cap one, and
#: 60 sits inside what every backend accepts.
CONSTRAINT_NAME_MAX = 60

#: The fixed allowance of a stored value beyond the base64 of its sealed bytes:
#: the marker (``~^Dv1:``, six characters) and headroom for a crypto backend that
#: adds more per value than :data:`STORED_SEALED_BYTES` counts — Tink prefixes
#: five bytes of key id, about seven base64 characters. Generous rather than
#: exact, because a column sized from it holds values written under any backend,
#: and changing it would change the width of every ``varchar_column`` column.
STORED_FRAMING_CHARS = 23

#: What an AEAD adds to the plaintext before base64: a nonce in front and an
#: authentication tag behind. The ciphertext itself is the plaintext's length.
STORED_SEALED_BYTES = 28

#: The widest ``varchar_column`` this package will accept, in characters. An
#: index key on the strictest backend Django supports runs to 3072 bytes, a
#: character there costs 4, and a companion column in a composite key takes
#: some of it — so a column any wider cannot be indexed everywhere, which is the
#: only reason to ask for one. Reported by ``E028`` rather than discovered at
#: ``migrate`` on the one backend that refuses it.
VARCHAR_COLUMN_MAX = 766


def _bounded_name(name: str, limit: int) -> str:
    """Return *name*, shortened to *limit* characters without colliding.

    Two fields whose names share a long prefix truncate to the same string, and
    the second constraint then collides with the first rather than being
    created. So what is cut is replaced by a digest of the whole name — the
    split Django uses for the names it generates itself.
    """
    if len(name) <= limit:
        return name
    from django.db.backends.utils import names_digest

    digest = names_digest(name, length=8)
    return f"{name[: limit - len(digest) - 1]}_{digest}"


class BlindIndexField(models.CharField):
    """The companion column a blind-indexed field keeps its digest in.

    Hex of a fixed width, so it takes a plain btree on every database Django
    supports and a plain ``UniqueConstraint`` over it needs no expression — which
    is what the ciphertext column could not offer, being text on every backend
    whatever the declared type.

    Nullable because the field it belongs to may be, and a row holding no value
    has no digest; ``editable=False`` keeps it out of forms, the admin and model
    validation, which have nothing to show a reader and nothing to accept from
    one. The field that owns it writes it in ``pre_save`` — nothing assigns it by
    hand.
    """

    def __init__(self, **kwargs):
        kwargs.setdefault("max_length", INDEX_DIGEST_LEN)
        kwargs.setdefault("null", True)
        kwargs.setdefault("editable", False)
        super().__init__(**kwargs)


class _IndexedLookup(models.Lookup):
    """Match a blind-indexed column by comparing digests.

    Builds every digest the lookup value could be stored under and hands them to
    the field's storage strategy, which says what to compare them against — a
    companion column, or a row in this package's index table. More than one
    digest where more than one key may have written the column, so a lookup keeps
    finding rows written under a key that is on its way out.
    """

    lookup_name = "exact"

    def get_prep_lookup(self):
        # The field's own get_prep_value is a passthrough for a stored value, and
        # would have nothing useful to do with a lookup value either: the
        # parameters this lookup sends are digests, built below.
        return self.rhs

    def _values(self):
        return [self.rhs]

    def as_sql(self, compiler, connection):
        from .exceptions import EncryptionError, as_lookup_error

        field = self.lhs.output_field
        digests: list[str] = []
        for value in self._values():
            if value is None:
                raise FieldError(
                    f"Cannot look {field.model._meta.label}.{field.name} up by None. "
                    f"Use __isnull=True to find rows that hold no value."
                )
            try:
                candidates = field.index_candidates(value)
            except EncryptionError as exc:
                # Also a ValidationError, so a form whose clean() ran this query —
                # allauth's sign-in, say — shows the message rather than a 500.
                # The raise site has already logged it.
                raise as_lookup_error(exc) from exc
            for digest in candidates:
                if digest not in digests:
                    digests.append(digest)
        if not digests:
            # An empty __in. Raised rather than compiled to a false constant,
            # which is how Django's own In reports it: the compiler drops the
            # branch instead of running a query that cannot match.
            raise EmptyResultSet
        return field.index_comparison_sql(self.lhs, digests, compiler, connection)


class _IndexedIn(_IndexedLookup):
    lookup_name = "in"

    def _values(self):
        return list(self.rhs)


# ---------------------------------------------------------------------------
# Encrypted field mixin
# ---------------------------------------------------------------------------


class _CiphertextFieldMixin:
    """
    Mixin that adds transparent encrypt-on-save / lazy-decrypt-on-read
    behavior.

    Holds the mechanics and none of the key handling: three hooks
    (:meth:`_is_ciphertext`, :meth:`_encrypt_value`, :meth:`_decrypt_value`)
    say what a stored value looks like and which key it is encrypted under.
    :class:`_EncryptedFieldMixin` fills them in with the silo's data encryption
    key, reached through the KMS; the system fields fill them in with a key held
    in settings. Everything else — the descriptor, ``pre_save``, the database
    passthroughs, the checks — is shared.

    Works with any Django field whose underlying Python type is ``str``
    (CharField, TextField, EmailField, URLField, …). Fields whose Python
    type is not ``str`` (Date, DateTime, Integer) override
    ``_to_storage_str`` and ``_from_storage_str`` to serialize and parse
    around encryption.

    The decrypt path is mediated by :class:`EncryptedAttributeDescriptor`
    rather than ``from_db_value``: ``from_db_value`` stamps the ciphertext
    as read from the database and hands it into ``instance.__dict__``, and
    the descriptor decrypts on the first attribute read.

    Per-field knobs:

    * ``decrypt_mode="strict"`` — this field always raises on decrypt
      failure, regardless of the active :func:`strict_mode` setting.
      Use for fields whose silent fallback would be a security or
      correctness bug.
    * ``fallback_label=...`` — overrides the package default fallback
      string used by lenient-mode failures. Accepts a plain string or
      a ``gettext_lazy`` proxy; lazy proxies resolve to the active
      Django locale at template-render time.
    * ``blind_index=True`` — store a keyed digest of the value beside it,
      and serve ``exact``, ``iexact`` and ``in`` by comparing that.
    * ``normalize="casefold"`` — index and compare the case-folded value.
    * ``blind_index_storage=...`` — which table holds the digest;
      :data:`BLIND_INDEX_STORAGE_COLUMN` or :data:`BLIND_INDEX_STORAGE_TABLE`.

    Blind index
    -----------

    Ciphertext gets a fresh nonce every time, so an encrypted column cannot be
    searched. A field declared ``blind_index=True`` stores a keyed hash of its
    value, and ``exact``, ``iexact`` and ``in`` are rewritten to compare that;
    every other lookup is refused rather than silently matching nothing.

    What that gives away is equality: two rows holding the same value index
    alike, so somebody reading the table can tell which rows share a value and
    how common each value is, and one value known from elsewhere locates every
    row that holds it. For an email address or an account name, where almost
    every value appears once, that costs little. For a birth date or a postal
    code it gives away most of what the encryption was for. So index a column
    only where a lookup genuinely needs it: a column with no index is still
    encrypted, it simply cannot be searched.

    ``db_index=True`` and a uniqueness rule are declarations about the *digest*,
    never about the ciphertext column: an index over ciphertext serves no query,
    and MySQL and Oracle cannot index a text column at all. Both keywords are
    taken here and never passed to Django, and :meth:`deconstruct` puts them
    back so a migration reproduces the declaration.

    Which key computes the digest — the index key of the silo the column's
    ``key`` selects — is answered by :meth:`_compute_index_digest` and
    :meth:`_compute_index_candidates`. Where the digest is stored is answered by
    the storage strategy, through :meth:`index_comparison_sql`.
    """

    descriptor_class = EncryptedAttributeDescriptor

    #: The keyword this column spells uniqueness with, and whether that keyword
    #: is Django's own. A uniqueness rule here is enforced over the digest, and
    #: under a silo's own key the guarantee is per silo rather than per table — a
    #: different promise, so a different word, and Django's own word becomes an
    #: error rather than being honored as if it meant the same thing.
    uniqueness_keyword = "unique"
    honors_django_unique = True

    def __init__(
        self,
        *args,
        decrypt_mode=None,
        fallback_label=None,
        blind_index: bool = False,
        normalize: str | None = None,
        blind_index_storage: str = BLIND_INDEX_STORAGE_COLUMN,
        varchar_column: bool = False,
        aad=(),
        **kwargs,
    ):
        #: Columns on the same model (field names, or ``"pk"``) bound into this
        #: field's AAD. Kept as declared; resolved to attnames when the class is
        #: prepared, and a malformed declaration is reported by the check.
        self.aad = aad
        if decrypt_mode is not None and decrypt_mode not in ("strict", "lenient"):
            raise ValueError(f"decrypt_mode must be 'strict', 'lenient', or None; got {decrypt_mode!r}.")
        if normalize not in NORMALIZE_CHOICES:
            raise ValueError(f"normalize must be None or {NORMALIZE_CASEFOLD!r}; got {normalize!r}.")
        if blind_index_storage not in BLIND_INDEX_STORAGE_CHOICES:
            raise ValueError(
                f"blind_index_storage must be one of {', '.join(repr(c) for c in BLIND_INDEX_STORAGE_CHOICES)}; "
                f"got {blind_index_storage!r}."
            )
        # Stored under leading-underscore names so they don't collide
        # with any future Django field attribute that might use the
        # public name. The descriptor's ``_is_strict`` / ``_resolve_fallback``
        # helpers read these directly.
        self._decrypt_mode = decrypt_mode
        self._fallback_label = fallback_label
        self.blind_index = blind_index
        self.normalize = normalize
        self.blind_index_storage = blind_index_storage
        #: Make the column a bounded ``varchar`` instead of the backend's text
        #: type. Nothing in this package needs it: no lookup compares the
        #: ciphertext column and no index of ours covers it. It exists for a
        #: column some *other* package indexes — a ``Meta`` this project cannot
        #: edit — because MySQL and Oracle refuse an index containing a text
        #: column and fail the migration that adds one. The width is computed,
        #: not declared (:attr:`stored_max_length`), and ``E028`` refuses a
        #: field whose values could not be indexed everywhere anyway.
        self.varchar_column = varchar_column
        # db_index is taken rather than forwarded: Django keeps it in a plain
        # attribute the schema editor reads, and an index over ciphertext serves
        # no query — no lookup on this column is allowed to compare the stored
        # value. ``unique`` is forwarded instead, because Django keeps that one
        # behind a property this class can answer for (see ``unique`` below), so
        # the declaration lives in Django's own ``_unique`` and migrations
        # reproduce it with no help from here.
        self.index_db_index = bool(kwargs.pop("db_index", False))
        super().__init__(*args, **kwargs)

    # ------------------------------------------------------------------
    # Key handling — the three hooks a subclass fills in
    # ------------------------------------------------------------------

    def _is_ciphertext(self, value: str) -> bool:
        """Whether *value* has the shape of a stored value this field wrote.

        Answers on the string alone. Shape is not provenance: the read and save
        paths act on a ciphertext-shaped value only when it was also read from
        the database (see :func:`~encryption_suite.engine.is_stamped`). Each subclass marks its values with
        a prefix of its own, which is what keeps one kind of field from trying to
        read the other's. A value that is not ciphertext is plaintext awaiting
        encryption, and is returned to the caller as it stands.
        """
        raise NotImplementedError

    def _write_silo(self, model_instance):
        """The silo a write of *model_instance* encrypts under, or ``None`` for the field's usual one."""
        return None

    def _encrypt_value(self, text: str, *, aad: bytes, field_label: str, silo=None) -> str:
        """Return the stored form of *text*, under *silo* when given. Raises an ``EncryptionError``."""
        raise NotImplementedError

    def _decrypt_value(self, stored: str, *, aad: bytes, field_label: str, row_identity: str) -> str:
        """Return the plaintext of *stored*. Raises an ``EncryptionError``.

        *row_identity* names the row for the log line and is never stored.
        """
        raise NotImplementedError

    # ------------------------------------------------------------------
    # Lenient degradation
    # ------------------------------------------------------------------

    def _fallback_value(self, error):
        """What a lenient read returns when the plaintext cannot be produced.

        An :class:`UndecryptableValue`, which renders as the fallback label and
        answers :func:`is_undecryptable`. A field whose Python type is not a
        string overrides this: a sentinel that only stringifies would break the
        caller reading it as the declared type, which is the crash lenient mode
        exists to avoid. Such a field is recognized through
        ``instance.encryption_suite_errors`` instead — the record every lenient
        failure writes, whatever the value it hands back.
        """
        return UndecryptableValue(
            fallback=_resolve_fallback(self),
            error=error,
            field_name=self.attname,
        )

    def _field_label(self) -> str:
        """Human-readable label for this field (used in audit logs)."""
        model = getattr(self, "model", None)
        name = getattr(self, "name", "<unknown>")
        if model is not None:
            return f"{model._meta.label}.{name}"
        return name

    def _to_storage_str(self, value) -> str:
        """Convert the in-memory value to the string form stored as ciphertext.

        Subclasses with non-string Python types (Date, DateTime, Integer)
        override this to serialize before encryption.
        """
        return str(value)

    def _from_storage_str(self, plaintext: str):
        """Convert a decrypted plaintext string back to the field's Python type.

        Subclasses with non-string Python types override this to parse.
        """
        return plaintext

    # ------------------------------------------------------------------
    # Blind index — the two hooks a subclass fills in
    # ------------------------------------------------------------------

    def _compute_index_digest(self, normalized: str, *, silo=None) -> str:
        """Return the digest *normalized* is stored under, as hex.

        :data:`INDEX_DIGEST_LEN` hex characters, keyed: an unkeyed hash of an
        email address is recovered by hashing a word list. Which key is the
        subclass's business: the index key of the silo the column's ``key``
        selects, or of *silo* when given.
        """
        raise NotImplementedError

    def _compute_index_candidates(self, normalized: str) -> list[str]:
        """Return every digest *normalized* could be stored under, as hex.

        One per key a read may have to answer for. A subclass that fences lookups
        while it re-indexes returns a single digest; one that cannot fence
        returns the whole set, so a lookup keeps finding rows not yet moved.
        """
        raise NotImplementedError

    # ------------------------------------------------------------------
    # Blind index — shared
    # ------------------------------------------------------------------

    def index_context(self) -> str:
        """What binds this column's digests to this column.

        Part of the hash, so one value held in two columns does not index alike
        and the two cannot be matched against each other. Derived from the model
        and field name, which means renaming either invalidates the stored
        digests — a rename is a migration that has to rewrite them, the same as a
        key rotation does.
        """
        return f"{self.model._meta.label}.{self.name}"

    def _normalized(self, value: str) -> str:
        return value.casefold() if self.normalize == NORMALIZE_CASEFOLD else value

    def index_digest(self, value) -> str:
        """The digest to store for *value*, which is what a write records."""
        return self._compute_index_digest(self._normalized(self._to_storage_str(value)))

    def index_candidates(self, value) -> list[str]:
        """Every digest *value* could be stored under, which is what a lookup compares."""
        return self._compute_index_candidates(self._normalized(self._to_storage_str(value)))

    @property
    def unique(self) -> bool:
        """Never the ciphertext column, whatever the field declares.

        Django's own property answers ``self._unique or self.primary_key``, and
        everything that acts on a uniqueness rule reads it: the schema editor
        emits the index, ``Model._get_unique_checks`` builds the validation
        query, the auth checks ask it of ``USERNAME_FIELD``, a ``ForeignKey``
        asks it of its ``to_field``. None of those can be served over a column
        whose every write differs, and the index itself is rejected outright by
        MySQL and Oracle, which cannot index a text column.

        So the declaration stays in ``_unique``, where ``deconstruct`` reads it
        and a migration reproduces it, while this answers for what the database
        is actually asked to do. :attr:`index_unique` is what carries the
        declaration's intent to the constraint over the digest.
        """
        return self.primary_key

    @property
    def index_unique(self) -> bool:
        """Whether this column's plaintext is held unique, over the digest.

        What the constraint, the index decision and the checks read, and what a
        serializer or a form asks when it needs the validation Django's own
        ``unique`` would have driven. A subclass that spells uniqueness
        differently — per silo rather than per table — overrides this.
        """
        return self._unique

    def index_conflict(self, digest: str, *, exclude_pk) -> bool:
        """Whether another row already holds *digest* for this column.

        The query the uniqueness rule is validated with, asked of whichever
        storage holds the digest. Nothing scopes it to a silo: a digest is
        computed under the silo's own key, so one silo's digests cannot collide
        with another's, and the scoping is in the key rather than in the
        queryset.

        Reads through the base manager, because a default manager that filters
        would hide the very row that is about to make the write fail.
        """
        if self.blind_index_storage == BLIND_INDEX_STORAGE_COLUMN:
            rows = self.model._base_manager.filter(**{self.index_field_name: digest})
            if exclude_pk is not None:
                rows = rows.exclude(pk=exclude_pk)
            return rows.exists()
        from .models import BlindIndexEntry

        entries = BlindIndexEntry.objects.filter(
            model_label=self.model._meta.label,
            field_name=self.name,
            digest=digest,
        )
        if exclude_pk is not None:
            entries = entries.exclude(object_pk=str(exclude_pk))
        return entries.exists()

    @property
    def index_field_name(self) -> str:
        """The companion column's field name, under ``blind_index_storage="column"``."""
        return f"{self.name}{INDEX_COLUMN_SUFFIX}"

    def unique_constraint(self):
        """The constraint that holds this column's plaintext unique.

        Over the digest rather than the ciphertext: a stored value differs on
        every write, so a uniqueness rule on that column could never fire. A
        plain ``fields=`` constraint with no expression and no condition, which
        is what every database Django supports can enforce.

        Named after the table and column, in the shape Django gives the unique
        constraints it names itself: a constraint name is unique across the
        database, and the table name is what already is.
        """
        return models.UniqueConstraint(
            fields=[self.index_field_name],
            name=_bounded_name(
                f"{self.model._meta.db_table}_{self.index_field_name}_uniq",
                CONSTRAINT_NAME_MAX,
            ),
        )

    def index_comparison_sql(self, lhs, digests, compiler, connection):
        """Compare this field's stored digest against *digests*.

        The storage strategy is what knows where the digest lives: a companion
        column compares a column on the same row, the shared table compares
        through a subquery. *lhs* is the resolved reference to the ciphertext
        column, which is where the table alias comes from.

        The digest alone is not enough. A write that cleared the value without
        clearing the digest — ``update(field=None)``, which nothing on a field
        can reach — would leave a row that still answers to the value it used to
        hold, and a false positive on a column used to sign in is worse than a
        missed row. A row holding no value matches no equality lookup, so the
        comparison says that too.

        Composed as expressions and handed to the compiler rather than written
        as SQL, which leaves quoting, placeholders and the backend's parameter
        style where they belong.
        """
        from django.db.models.expressions import Col
        from django.db.models.lookups import In, IsNull
        from django.db.models.sql.where import AND, WhereNode

        if self.blind_index_storage == BLIND_INDEX_STORAGE_COLUMN:
            digest = Col(lhs.alias, self.model._meta.get_field(self.index_field_name))
            held = In(digest, digests)
        else:
            from . import blind_index

            held = blind_index.comparison(self, lhs, digests, compiler, connection)
        return compiler.compile(WhereNode([held, IsNull(lhs, False)], connector=AND))

    def stored_index_digest(self, instance) -> str | None:
        """The digest recorded for *instance*, wherever this field keeps it.

        What tells a current digest from one written under a key on its way out,
        for the programs that convert a column: which index key wrote a digest is
        not recorded, so the only way to judge one is to compute the digest the
        value should have now and compare.
        """
        if self.blind_index_storage == BLIND_INDEX_STORAGE_COLUMN:
            return getattr(instance, self.index_field_name)
        from .models import BlindIndexEntry

        entry = BlindIndexEntry.objects.filter(
            model_label=self.model._meta.label,
            field_name=self.name,
            object_pk=str(instance.pk),
        ).first()
        return entry.digest if entry is not None else None

    def index_update_kwargs(self, digest: str | None) -> dict:
        """What to write alongside a value written directly, not through ``save()``.

        A conversion program writes the column with ``update()``, which runs no
        ``pre_save``, so the digest has to travel with it. Empty for a field
        whose digest is not a column of the same row — :meth:`record_index_digest`
        writes that one.
        """
        if not self.blind_index or self.blind_index_storage != BLIND_INDEX_STORAGE_COLUMN:
            return {}
        return {self.index_field_name: digest}

    def record_index_digest(self, pk, digest: str | None, *, using=None) -> None:
        """Write the digest of a directly-written value, where it is not a column.

        The other half of :meth:`index_update_kwargs`, and a no-op for the
        strategy that one covers.
        """
        if not self.blind_index or self.blind_index_storage == BLIND_INDEX_STORAGE_COLUMN:
            return
        from .models import BlindIndexEntry

        scope = {
            "model_label": self.model._meta.label,
            "field_name": self.name,
            "object_pk": str(pk),
        }
        entries = BlindIndexEntry.objects.using(using)
        if digest is None:
            entries.filter(**scope).delete()
            return
        entries.update_or_create(
            **scope,
            defaults={"digest": digest, "unique_enforced": True if self.index_unique else None},
        )

    def _store_index_digest(self, model_instance, storage_str: str | None, *, silo=None) -> None:
        """Record the digest of the value being written, where the strategy keeps it.

        Called from ``pre_save`` on the paths that know the plaintext — a fresh
        value, or ``None``. The paths that write existing ciphertext back
        unchanged leave the digest alone, because it already belongs to that
        ciphertext. *silo* is the silo the value was encrypted under.
        """
        if not self.blind_index:
            return
        digest = None if storage_str is None else self._compute_index_digest(self._normalized(storage_str), silo=silo)
        if self.blind_index_storage == BLIND_INDEX_STORAGE_COLUMN:
            setattr(model_instance, self.index_field_name, digest)
            return
        # The shared table cannot be written yet: an insert has no primary key
        # until the row is written. Left on the instance for the post_save
        # receiver, which runs inside the transaction the save wrapper opened.
        from . import blind_index

        blind_index.stash_digest(model_instance, self.name, digest)

    # ------------------------------------------------------------------
    # Class-level wiring
    # ------------------------------------------------------------------

    def contribute_to_class(self, cls, name, **kwargs):
        # Field.contribute_to_class consults ``descriptor_class`` and
        # installs an instance of it as a class attribute at the field's
        # attname — that is how our ``EncryptedAttributeDescriptor`` gets
        # wired up on every encrypted field automatically.
        super().contribute_to_class(cls, name, **kwargs)

    def contribute_index_column(self, cls):
        """Add the digest column, its index and its uniqueness to *cls*.

        Declared from here rather than left to the project: the column is an
        implementation detail of the field, and a project that had to remember it
        would have a field whose lookups compare a column that is not there. It
        contributes like any other field, and the constraint goes into
        ``_meta.constraints``, which is what ``makemigrations`` reads — so both
        land in a migration with nothing else asked of the developer.

        Called from ``class_prepared`` rather than from
        ``contribute_to_class``, because only then is it knowable whether the
        column is already there. ``makemigrations`` writes the column into the
        migration like any other, and rendering that migration builds this field
        again — which would add a second copy of a column the state already
        declares, since a field contributed before its companion cannot see it
        coming. Waiting until the class is complete makes the two agree.
        """
        try:
            cls._meta.get_field(self.index_field_name)
        except FieldDoesNotExist:
            # A uniqueness rule is already backed by an index that serves the same
            # lookups, so a plain one beside it would be dead weight — the rule
            # Django applies to its own ``db_index`` plus ``unique``.
            column = BlindIndexField(db_index=self.index_db_index and not self.index_unique)
            column.contribute_to_class(cls, self.index_field_name)
        if not self.index_unique:
            return
        constraint = self.unique_constraint()
        if constraint.name not in {getattr(c, "name", None) for c in cls._meta.constraints}:
            cls._meta.constraints = [*cls._meta.constraints, constraint]
            cls._meta.original_attrs.setdefault("constraints", cls._meta.constraints)

    # ------------------------------------------------------------------
    # Django system checks
    # ------------------------------------------------------------------

    def check(self, **kwargs):
        errors = super().check(**kwargs)
        errors.extend(self._check_aad_columns())
        errors.extend(self._check_blind_index())
        errors.extend(self._check_varchar_column())
        return errors

    def _check_varchar_column(self):
        """Refuse a bounded column that could not be indexed on every backend.

        The point of bounding one is that some other package indexes it, and an
        index key on the strictest backend Django supports runs to 3072 bytes at
        4 bytes a character. A column wider than :data:`VARCHAR_COLUMN_MAX`
        therefore fails the migration that adds that index — on one backend, at
        deploy, long after the declaration. Said here instead.

        Reported as an error rather than a warning because, unlike a rule
        somebody else declared over the column, this one *is* the project's to
        change: lower ``max_length``, or drop the keyword and accept that the
        column cannot be indexed.
        """
        if not self.varchar_column:
            return []
        if not self.max_length:
            return [
                Error(
                    f"{type(self).__name__} sets varchar_column=True with no max_length. The "
                    f"column's width is computed from the longest value it has to hold, and this "
                    f"field declares no such limit.",
                    hint="Declare max_length, or drop varchar_column=True and let the column be text.",
                    obj=self,
                    id="encryption_suite.E028",
                )
            ]
        if self.stored_max_length > VARCHAR_COLUMN_MAX:
            return [
                Error(
                    f"{type(self).__name__} sets varchar_column=True, but a value of max_length="
                    f"{self.max_length} is stored in {self.stored_max_length} characters, and a "
                    f"column that wide cannot be part of an index on every database Django "
                    f"supports — which is the only reason to bound it.",
                    hint=(
                        f"Lower max_length to {self.plain_max_length_for(VARCHAR_COLUMN_MAX)} or less, "
                        f"or drop varchar_column=True and accept that nothing can index this column."
                    ),
                    obj=self,
                    id="encryption_suite.E028",
                )
            ]
        return []

    def _refuse_overlong(self, text: str) -> None:
        """Refuse a value whose stored form would not fit a bounded column.

        On a bounded column ``max_length`` counts bytes, because that is what
        decides the stored width — a character costing four of them turns a
        254-character value into 1016. Django's own ``MaxLengthValidator``
        counts characters, so a value can pass validation and still overflow.

        Raised here rather than left to the database, which would truncate the
        ciphertext on some backends and reject the row on others, and in neither
        case say which column or why.
        """
        if not self.varchar_column or not self.max_length:
            return
        length = len(text.encode("utf-8"))
        if length > self.max_length:
            raise ValueError(
                f"{self._field_label()} holds a value of {length} bytes, and its column is sized "
                f"for {self.max_length}. On a varchar_column field max_length counts bytes rather "
                f"than characters, because the stored width follows the plaintext's encoded "
                f"length: a character outside ASCII costs up to four of them."
            )

    @staticmethod
    def plain_max_length_for(stored_chars: int) -> int:
        """The largest ``max_length`` whose stored value fits *stored_chars*.

        The inverse of :attr:`stored_max_length`, for saying in an error message
        what would have been accepted.
        """
        return max(0, (stored_chars - STORED_FRAMING_CHARS) // 4 * 3 - STORED_SEALED_BYTES)

    def _check_blind_index(self):
        """Report a declaration the blind index cannot honor.

        All three are about the same thing: a stored value is unlike every other
        write of it, so anything that compares the column — a lookup, an index, a
        uniqueness rule — has to go through the digest or not exist.

        Two of them are about uniqueness, and they read different things on
        purpose. The first reads the *intent*, whichever keyword carried it. The
        second reads Django's own keyword, because on a column that spells it
        differently the intent is false and only the raw declaration can report
        the mistake — a field written ``unique=True`` there would otherwise
        deploy with a rule enforced nowhere.
        """
        errors = []
        if self._unique and not self.honors_django_unique:
            errors.append(
                Error(
                    f"{type(self).__name__} sets unique=True, which it cannot honor. Django's "
                    f"unique means unique in the table, and this column's uniqueness is held per "
                    f"silo: two silos may each hold a value, and no rule over this table could say "
                    f"that.",
                    hint=f"Use {self.uniqueness_keyword}=True, which is the guarantee this field enforces.",
                    obj=self,
                    id="encryption_suite.E026",
                )
            )
        elif self.index_unique and not self.blind_index:
            errors.append(
                Error(
                    f"{type(self).__name__} sets {self.uniqueness_keyword}=True without a blind "
                    f"index. Every write stores different ciphertext, so a uniqueness rule over "
                    f"this column can never fire and duplicate values would be accepted silently.",
                    hint=(
                        f"Add blind_index=True, which puts the uniqueness rule over the index, or "
                        f"drop {self.uniqueness_keyword}=True."
                    ),
                    obj=self,
                    id="encryption_suite.E026",
                )
            )
        if self.index_db_index and not self.blind_index:
            errors.append(
                Error(
                    f"{type(self).__name__} sets db_index=True without a blind index. An index "
                    f"over ciphertext can serve no query, because no lookup on this column is "
                    f"allowed to compare the stored value.",
                    hint="Add blind_index=True, which indexes the digest instead, or drop db_index=True.",
                    obj=self,
                    id="encryption_suite.E027",
                )
            )
        return errors

    def _check_aad_columns(self):
        return _check_aad(self)

    # ------------------------------------------------------------------
    # Django field protocol
    # ------------------------------------------------------------------

    def pre_save(self, model_instance, add):
        """Return the value to write to the DB column.

        Reads ``instance.__dict__`` directly so the lazy-decrypt
        descriptor is bypassed. Four cases, in order:

        * **Field absent from __dict__** — column was deferred and
          never accessed. Fetch the raw ciphertext from the DB and
          return it unchanged. The save round-trips the same bytes
          rather than triggering a wasted decrypt-then-re-encrypt
          cycle.
        * **A recorded failure** — a prior lenient-mode read of this column
          failed. Preserve the stored value: re-encrypting the fallback
          would replace the only chance an operator has to recover the data.
          Read from ``_encryption_suite_errors`` rather than by recognizing
          the fallback, because a field whose fallback is an ordinary value of
          its own type (an empty dict, say) is indistinguishable from one the
          caller meant.
        * **Stored ciphertext** — column was loaded but the attribute was
          never read on this instance, so the value sits in ``__dict__`` as
          the stamped string ``from_db_value`` returned. Pass through
          unchanged.
        * **Unstamped ciphertext-shaped string** — the caller assigned it.
          Accepted only when it equals what the row already holds (a raw
          value copied onto an instance of the same row); stamped and passed
          through. Anything else is refused with
          :class:`~encryption_suite.exceptions.FieldAlreadyEncryptedError`:
          writing it through would let a ciphertext copied from another row
          decrypt under this one.
        * **Anything else** — treat as plaintext assigned by caller (or
          decrypted-then-cached on a prior read), encrypt, store the
          fresh ciphertext in ``__dict__``, and return it.

        Note: a save after a successful read re-encrypts the field with
        a fresh nonce. This is intentional and matches AEAD best
        practice (every encryption gets a fresh nonce); it costs one
        engine call per accessed encrypted field per save.
        """
        attname = self.attname
        data = model_instance.__dict__
        if attname not in data:
            # Deferred and never accessed. Preserve the existing
            # ciphertext via a single targeted query.
            return self._fetch_existing_ciphertext(model_instance)

        value = data[attname]
        if value is None:
            self._store_index_digest(model_instance, None)
            return None

        if isinstance(value, UndecryptableValue) or attname in data.get("_encryption_suite_errors", {}):
            return self._fetch_existing_ciphertext(model_instance)

        from .engine import is_stamped, stamp

        if isinstance(value, str) and self._is_ciphertext(value):
            if is_stamped(value):
                return value
            if self._matches_stored(model_instance, value):
                value = stamp(value)
                data[attname] = value
                return value
            self._refuse_injected_ciphertext()

        str_value = self._to_storage_str(value)
        self._refuse_overlong(str_value)
        aad = _build_write_aad(type(model_instance), self, model_instance, file=False)
        # One silo for the value and its digest: a digest under another silo's key
        # would never match a lookup made in the value's silo.
        silo = self._write_silo(model_instance)
        ciphertext = self._encrypt_value(str_value, aad=aad, field_label=self._field_label(), silo=silo)
        # Replace the in-memory plaintext with the saved ciphertext so
        # the next attribute read decrypts the value we just stored,
        # rather than continuing to return stale plaintext. Stamped, so a
        # second save of this instance writes it back unchanged.
        ciphertext = stamp(ciphertext)
        data[attname] = ciphertext
        self._store_index_digest(model_instance, str_value, silo=silo)
        return ciphertext

    def _matches_stored(self, model_instance, value) -> bool:
        """Whether *value* equals the ciphertext this instance's row already holds.

        ``False`` for an unsaved instance or a row that does not exist.
        """
        if model_instance.pk is None:
            return False
        stored = self._fetch_existing_ciphertext(model_instance)
        return stored is not None and stored == value

    def _refuse_injected_ciphertext(self):
        """Log and raise for a ciphertext-shaped value the package did not read from the database."""
        from .exceptions import GENERIC_ENCRYPT_FAILED_USER_MESSAGE, FieldAlreadyEncryptedError

        field_label = self._field_label()
        logger.error(
            "Refused to save a value that looks like ciphertext but was not read from the database. "
            'error_code=%s field="%s" hint="%s"',
            FieldAlreadyEncryptedError.code,
            field_label,
            _INJECTED_CIPHERTEXT_HINT,
        )
        raise FieldAlreadyEncryptedError(
            GENERIC_ENCRYPT_FAILED_USER_MESSAGE,
            detail=f'field="{field_label}" {_INJECTED_CIPHERTEXT_HINT}',
        )

    def _fetch_existing_ciphertext(self, model_instance):
        """Fetch the column's current ciphertext via a raw cursor.

        Used by ``pre_save`` when the field is either deferred or
        holds a sentinel so we can write the existing value back
        unchanged. Returns ``None`` for new (unsaved) instances.
        """
        if model_instance.pk is None:
            return None
        from ._internal import raw_cursor_fetch

        row = raw_cursor_fetch(type(model_instance), model_instance.pk, [self.name])
        if not row:
            return None
        return row[0]

    def get_prep_value(self, value):
        """Pass through. Encryption happens in pre_save (which has the instance).

        Called for both writes (after pre_save returns the ciphertext) and
        for query parameters (e.g. ``filter(field=value)``). Filtering
        encrypted columns by value cannot work — each ciphertext has a
        fresh nonce — so the query case is degenerate; we pass through.
        """
        if value is None:
            return None
        # The descriptor sometimes leaves a sentinel in __dict__ when a
        # lenient-mode decrypt failed; if such a value reaches the
        # database layer (e.g. via QuerySet.update with a sentinel), it
        # would silently overwrite the ciphertext with garbage. Refuse.
        if isinstance(value, UndecryptableValue):
            from .exceptions import GENERIC_ENCRYPT_FAILED_USER_MESSAGE, EncryptedFieldEncryptionError

            detail = (
                f"Refusing to write an UndecryptableValue sentinel to {self._field_label()}: it would overwrite "
                "the ciphertext with a placeholder. Resolve the decrypt failure first or assign a fresh "
                "plaintext value."
            )
            logger.error(
                'An undecryptable placeholder reached the database layer and was refused. error_code=%s detail="%s"',
                EncryptedFieldEncryptionError.code,
                detail,
            )
            raise EncryptedFieldEncryptionError(GENERIC_ENCRYPT_FAILED_USER_MESSAGE, detail=detail)
        return value

    def get_internal_type(self):
        """Present the column to the database layer as text, whatever the declared type.

        The column holds ciphertext, which is longer than the plaintext and is
        not of the declared type. Django chooses the column type and the
        backend's value conversions by internal type, so reporting the
        declared type would give a typed or length-limited column and run date
        or number conversions over ciphertext.

        ``varchar_column=True`` is the one exception, and it is about what
        *another* package does to the column — see :attr:`varchar_column`.
        """
        return "CharField" if self.varchar_column else "TextField"

    @property
    def stored_max_length(self) -> int:
        """Characters the column holds under ``varchar_column=True``.

        Computed, never declared: the stored length follows from the plaintext's
        and a developer typing the number would eventually type a wrong one,
        which costs a refused write on a column they encrypted.

        The marker, the key id and the separator, then base64 of the nonce, the
        ciphertext and the tag. AEAD ciphertext is the plaintext's length, so
        nothing here depends on the value::

            23 + 4 * ceil((max_length + 28) / 3)

        ``max_length`` counts bytes here rather than characters, which is
        tighter than Django means it and is enforced as such — see
        :meth:`_check_varchar_column` for why a byte-for-character reading
        cannot be indexed on every backend.
        """
        return STORED_FRAMING_CHARS + 4 * ceil((self.max_length + STORED_SEALED_BYTES) / 3)

    def db_type_parameters(self, connection):
        """Size the *column* by the stored value, not by the plaintext.

        ``max_length`` is two numbers on one of these fields: what a value may
        be, which validation reads, and how wide the column has to be, which the
        column type reads. Django interpolates this mapping into the column type,
        so this is where the second number belongs; everything else keeps the
        first.
        """
        parameters = super().db_type_parameters(connection)  # type: ignore[misc]
        if self.varchar_column:
            parameters["max_length"] = self.stored_max_length
        return parameters

    def get_db_prep_value(self, value, connection, prepared=False):
        """Hand the ciphertext to the database unchanged.

        The declared types adapt values for their own column type (a datetime
        for a datetime column, for example), which would fail on ciphertext.
        """
        if not prepared:
            value = self.get_prep_value(value)
        return value

    def get_db_prep_save(self, value, connection):
        """Refuse a value that did not come through ``pre_save``.

        Everything the ORM writes through a model arrives here as the ciphertext
        ``pre_save`` just produced, or as ``None``. A plaintext value can only
        have come from a write that skipped ``pre_save`` — ``QuerySet.update()``
        builds the assignment from what the caller passed, and
        ``QuerySet.bulk_update()`` reads the attribute off each instance, which
        is the *decrypted* value the descriptor hands back. Both would write
        plaintext into the column, and because a value with no storage marker is
        read back as plaintext, the column would quietly stop being encrypted
        with nothing to say so.

        A column default reaches this too, and is refused for the same reason: a
        migration adding the column applies the default to every row already
        there, as plaintext. New rows are unaffected — a default assigned to an
        instance is encrypted by ``pre_save`` like any other value — so the
        answer is to add the column without one and backfill it with
        :mod:`~encryption_suite.migration_helpers`, which leaves every row in
        the column ciphertext rather than a mix of the two.

        One write this cannot catch: ``update(field=None)`` is allowed, because a
        nullable model save sends ``None`` through here too and nothing
        distinguishes the callers. That nulls the value and leaves the digest, so
        the row still answers to the value it used to hold.
        """
        if (
            value is not None
            # The sentinel has its own refusal, which says what to do about a
            # failed decrypt rather than about a bypassed write.
            and not isinstance(value, UndecryptableValue)
            and not self._is_ciphertext(value)
            and not _plaintext_writes_var.get()
        ):
            from .exceptions import GENERIC_ENCRYPT_FAILED_USER_MESSAGE, EncryptedFieldEncryptionError

            detail = (
                f"Refusing to write a plaintext value to {self._field_label()}. Nothing "
                f"encrypts at this point, so the value would be stored as given and any "
                f"blind index left behind. Three writes reach it: QuerySet.update() and "
                f"bulk_update(), which bypass the field's pre_save — assign the value to "
                f"the instance and call save() instead; and a column default, which a "
                f"migration applies to the rows already there — add the column without "
                f"one and backfill it with encryption_suite.migration_helpers. To write "
                f"plaintext deliberately, as a column leaving encryption does, hold "
                f"encryption_suite.allow_plaintext_writes() open over the write."
            )
            logger.error(
                "A plaintext value reached an encrypted column without being encrypted and was refused. "
                'error_code=%s detail="%s"',
                EncryptedFieldEncryptionError.code,
                detail,
            )
            raise EncryptedFieldEncryptionError(GENERIC_ENCRYPT_FAILED_USER_MESSAGE, detail=detail)
        if isinstance(value, str):
            # A plain ``str``, so no database driver receives the stamp subclass.
            value = str(value)
        return super().get_db_prep_save(value, connection)  # type: ignore[misc]

    def from_db_value(self, value, expression, connection):
        """Pass through. Decryption is deferred to attribute access.

        The ``EncryptedAttributeDescriptor`` installed via
        ``descriptor_class`` decrypts on the first read of the
        attribute. Returning ciphertext here means iterating a queryset
        never triggers a decrypt — only attribute access does.

        The value is stamped as read from the database (see
        :func:`~encryption_suite.engine.stamp`): only a stamped value is
        decrypted on read or written back unchanged on save, so a
        ciphertext-shaped string a caller assigns is never taken for one.
        """
        from .engine import stamp

        return stamp(value)

    def to_python(self, value):
        """
        Called during form validation with user-supplied input.

        Decryption is intentionally not performed here: values arriving via form
        submission are plaintext, and decrypting them would expose a decryption
        oracle to anyone who can submit form data. Decryption happens
        exclusively through the lazy-decrypt descriptor on attribute access
        of a row loaded from the database.
        """
        if value is None:
            return None
        return super().to_python(value)  # type: ignore[misc]

    def get_lookup(self, lookup_name):
        """Serve what the blind index can answer, and refuse the rest.

        Without this the comparison is built and runs: ``get_prep_value`` passes
        a query parameter straight through, so the database compares plaintext
        against ciphertext and returns no rows. That is a wrong answer rather
        than a failure — a caller reads an empty queryset as "no such row" —
        and nothing in the query marks it as one.

        With a blind index, ``exact``, ``iexact`` and ``in`` are rewritten to
        compare digests. Everything else is still refused: a keyed hash answers
        whether two values are equal and nothing else.
        """
        # isnull is the one lookup that never compares the stored value: it
        # emits IS NULL against the column and sends no parameter.
        if lookup_name == "isnull":
            return super().get_lookup(lookup_name)  # type: ignore[misc]
        label = f"{self.model._meta.label}.{self.name}"
        if not self.blind_index:
            raise FieldError(
                f"{label} is encrypted and has no blind index, so it cannot be looked up by "
                f"value — every write gets a fresh nonce, so a comparison matches nothing "
                f"rather than failing. Only __isnull is supported. Declare blind_index=True "
                f"for exact lookups, or filter on a column stored in plaintext."
            )
        if lookup_name in ("exact", "iexact"):
            if lookup_name == "iexact" and self.normalize != NORMALIZE_CASEFOLD:
                raise FieldError(
                    f"{label} cannot be looked up with __iexact: its blind index is built from "
                    f"the value as given, so nothing case-insensitive can match it. Declare "
                    f"normalize='casefold' — which also makes __exact case-insensitive — or use "
                    f"__exact."
                )
            return _IndexedLookup
        if lookup_name == "in":
            return _IndexedIn
        raise FieldError(
            f"{label} is encrypted and supports only __exact, __iexact, __in and __isnull. "
            f"A blind index answers whether two values are equal and nothing else, so "
            f"__{lookup_name} cannot be served."
        )

    def deconstruct(self):
        """Serialize this field for migrations.

        Defaults are not emitted, so a field declared without
        ``decrypt_mode`` or ``fallback_label`` deconstructs to the same
        kwargs as the underlying Django field type.
        """
        name, path, args, kwargs = super().deconstruct()  # type: ignore[misc]
        if self._decrypt_mode is not None:
            kwargs["decrypt_mode"] = self._decrypt_mode
        if self._fallback_label is not None:
            kwargs["fallback_label"] = self._fallback_label
        if self.blind_index:
            kwargs["blind_index"] = True
        if self.normalize is not None:
            kwargs["normalize"] = self.normalize
        if self.blind_index_storage != BLIND_INDEX_STORAGE_COLUMN:
            kwargs["blind_index_storage"] = self.blind_index_storage
        if self.aad:
            kwargs["aad"] = _deconstruct_aad(self.aad)
        if self.varchar_column:
            kwargs["varchar_column"] = True
        # Put back what __init__ took, so a field rebuilt from a migration is
        # declared the way the model declares it. Django's own deconstruct does
        # not emit this one: it reads an attribute this field never set. It does
        # emit ``unique``, which is why that keyword is forwarded instead of
        # taken.
        if self.index_db_index:
            kwargs["db_index"] = True
        return name, path, args, kwargs


def _engine_silo(key_set: str):
    """The silo to hand the engine for a field of key set *key_set*.

    The current silo of that key set, which its silo adapter names. For a system
    key set the adapter names the system silo.
    """
    from .silo_ref import AmbientSilo

    return AmbientSilo(key_set)


class _EncryptedFieldMixin(_CiphertextFieldMixin):
    """Encrypted under a data encryption key: the current silo's of a key set, or the system silo's.

    ``key_set`` names the key set (``default`` when absent). A key set is one silo
    adapter and one key store, and ``KEY_SETS`` declares both. A key set bound to a
    project's silo adapter resolves the current silo from ambient context on every
    read and write. ``system``, and any key set bound to the system adapter, uses
    the system silo, which needs no context: the column belongs to no silo, is
    read across every silo at once, and is what signing in reads. A field that
    names its own key set gets its own keys. The key is unwrapped through the
    store its row records. Every encrypted field type is built from this class,
    and it is what the rotation, reconcile and data-conversion programs recognize
    an encrypted column by; they tell the key sets apart by ``key_set``.

    Uniqueness is spelled ``unique_in_silo`` for every key set bound to a silo adapter other than the system adapter,
    because that is what it is: the digest is computed under the silo's own key,
    so a constraint over the digest holds a value unique *within* a silo and says
    nothing across them. Two silos may each hold one address and both are valid.
    Django's ``unique`` promises the whole table, which no rule on such a column
    could deliver, so it is reported rather than quietly read as the same thing. A
    ``system`` column has one key for the whole table, so there ``unique`` is the
    guarantee it gives, and ``unique_in_silo`` is the one refused.
    """

    def __init__(
        self,
        *args,
        key_set: str = DEFAULT_KEY_SET,
        unique_in_silo: bool = False,
        **kwargs,
    ):
        self.key_set = key_set
        self.unique_in_silo = unique_in_silo
        super().__init__(*args, **kwargs)

    @property
    def uniqueness_keyword(self) -> str:
        return "unique" if is_system_key_set(self.key_set) else "unique_in_silo"

    @property
    def honors_django_unique(self) -> bool:
        return is_system_key_set(self.key_set)

    @property
    def index_unique(self) -> bool:
        return self._unique if is_system_key_set(self.key_set) else self.unique_in_silo

    def deconstruct(self):
        name, path, args, kwargs = super().deconstruct()
        # Kept in migrations: the conversion helpers read it off the historical
        # model to know which key set a column is encrypted under.
        if self.key_set != DEFAULT_KEY_SET:
            kwargs["key_set"] = self.key_set
        if self.unique_in_silo:
            kwargs["unique_in_silo"] = True
        return name, path, args, kwargs

    def _is_ciphertext(self, value) -> bool:
        from .engine import is_silo_value

        return is_silo_value(value)

    def _write_silo(self, model_instance):
        """The row's own silo when its adapter writes there with nobody acting, else ``None``.

        Only for a key set whose silo adapter sets
        ``writes_to_row_silo_without_context`` and has no current silo. A row that
        names no silo leaves the write to fail as any write with no silo does.
        """
        if is_system_key_set(self.key_set):
            return None
        from .registry import get_silo_adapter
        from .silo_ref import SiloRef

        adapter = get_silo_adapter(self.key_set)
        if not adapter.writes_to_row_silo_without_context or adapter.get_current_silo() is not None:
            return None
        owner = adapter.silo_for_row(model_instance)
        if owner is None:
            return None
        return SiloRef(self.key_set, adapter.get_silo_uid(owner))

    def _encrypt_value(self, text: str, *, aad: bytes, field_label: str, silo=None) -> str:
        from .registry import get_engine

        return get_engine().encrypt(text, aad=aad, silo=silo or _engine_silo(self.key_set), field_name=field_label)

    def _decrypt_value(self, stored: str, *, aad: bytes, field_label: str, row_identity: str) -> str:
        from .registry import get_engine

        return get_engine().decrypt(
            stored,
            aad=aad,
            silo=_engine_silo(self.key_set),
            field_name=field_label,
            row_identity=row_identity,
        )

    def _compute_index_digest(self, normalized: str, *, silo=None) -> str:
        from .registry import get_engine

        return get_engine().index_digest(
            normalized, context=self.index_context(), silo=silo or _engine_silo(self.key_set)
        )

    def _compute_index_candidates(self, normalized: str) -> list[str]:
        """The one digest this silo's key produces.

        Always exactly one: a silo has one index key, and ``reencrypt_data``
        fences the silo while it moves the digests onto new material, so a lookup
        is refused for the length of a re-index rather than matching two
        generations at once. Nothing is ever half converted from a reader's point
        of view.
        """
        return [self._compute_index_digest(normalized)]

    def check(self, **kwargs):
        errors = super().check(**kwargs)
        errors.extend(_check_key(self))
        if is_system_key_set(self.key_set) and self.unique_in_silo:
            errors.append(
                Error(
                    f"{type(self).__name__} sets unique_in_silo=True with the system key set {self.key_set!r}. "
                    f"A system column has one key for the whole table, so there is no silo to be unique "
                    f"within.",
                    hint="Use unique=True, which holds the value unique across the table.",
                    obj=self,
                    id="encryption_suite.E026",
                )
            )
        errors.extend(_check_blank_requires_null(self))
        return errors


def registered_key_sets() -> set[str]:
    """Every key set a field may name: ``system`` and each key set in ``KEY_SETS``."""
    from .conf import key_set_names

    return set(key_set_names())


def _check_key(field):
    """Report a ``key_set`` that is not declared in ``KEY_SETS``, or is not a valid name."""
    errors = []
    if is_valid_key_set(field.key_set) and field.key_set not in registered_key_sets():
        errors.append(
            Error(
                f"{type(field).__name__} sets key_set={field.key_set!r}, which ENCRYPTION['KEY_SETS'] does not "
                f"declare. A value would be encrypted under a key no silo adapter can find.",
                hint=f"Declare {field.key_set!r} in ENCRYPTION['KEY_SETS'], with a silo adapter and a store.",
                obj=field,
                id="encryption_suite.E041",
            )
        )
    if not is_valid_key_set(field.key_set):
        errors.append(
            Error(
                f"{type(field).__name__} sets key_set={field.key_set!r}, which is not a valid key set name.",
                hint=f"Use lowercase letters, digits and underscores, starting with a letter, "
                f"at most {KEY_SET_MAX_LENGTH} characters.",
                obj=field,
                id="encryption_suite.E041",
            )
        )
    return errors


# ---------------------------------------------------------------------------
# Typed storage conversions
# ---------------------------------------------------------------------------
#
# Each pair converts between a field's Python type and the string that gets
# encrypted. Declared apart from the field classes so that a silo field and a
# system field of the same type share one conversion instead of keeping two
# copies of it.
#
# A storage mixin is listed BEFORE the encryption mixin on every field that
# takes one: the methods it overrides have defaults on _CiphertextFieldMixin, so
# the other order silently keeps the passthrough and stores ``str(value)``.


class _IntegerStorage:
    """Integer to decimal string and back, keeping the declared type's range."""

    @cached_property
    def validators(self):
        # IntegerField looks up its range limits by internal type, which is
        # TextField here; keep the limits of the declared integer type.
        min_value, max_value = connection.ops.integer_field_range("IntegerField")
        range_validators = []
        if min_value is not None:
            range_validators.append(MinValueValidator(min_value))
        if max_value is not None:
            range_validators.append(MaxValueValidator(max_value))
        return [*self.default_validators, *self._validators, *range_validators]

    def _to_storage_str(self, value) -> str:
        return str(int(value))

    def _from_storage_str(self, plaintext: str):
        return int(plaintext)


class _DateStorage:
    """Date to an ISO 8601 string (``YYYY-MM-DD``) and back."""

    def _to_storage_str(self, value) -> str:
        if isinstance(value, datetime.date):
            return value.isoformat()
        return str(value)

    def _from_storage_str(self, plaintext: str):
        return datetime.date.fromisoformat(plaintext)


class _DateTimeStorage:
    """Datetime to an ISO 8601 string and back, keeping any timezone."""

    def _to_storage_str(self, value) -> str:
        if isinstance(value, datetime.datetime):
            return value.isoformat()
        return str(value)

    def _from_storage_str(self, plaintext: str):
        return datetime.datetime.fromisoformat(plaintext)


class _JsonStorage:
    """A JSON-serializable value to its JSON text and back.

    Honors the field's own ``encoder`` / ``decoder``, and otherwise encodes with
    ``DjangoJSONEncoder`` so the types Django writes into a JSON column of its
    own — dates, decimals, UUIDs — serialize rather than raise. They come back as
    the strings it wrote, which is what a plain ``JSONField`` returns too.

    A failed lenient read gives back an empty dict, not the string sentinel:
    callers read this field as a mapping, and handing them something that merely
    stringifies turns a degraded read into the crash it was meant to prevent.
    The failure is still recorded on ``instance.encryption_suite_errors``, which
    is the only way to tell an unreadable value from an empty one.
    """

    def _to_storage_str(self, value) -> str:
        return json.dumps(value, cls=getattr(self, "encoder", None) or DjangoJSONEncoder)

    def _from_storage_str(self, plaintext: str):
        return json.loads(plaintext, cls=getattr(self, "decoder", None))

    def _fallback_value(self, error):
        return {}


# ---------------------------------------------------------------------------
# Concrete field types
# ---------------------------------------------------------------------------


class EncryptedTextField(_EncryptedFieldMixin, models.TextField):
    """Encrypted TextField. Stores arbitrary-length text."""


class EncryptedCharField(_EncryptedFieldMixin, models.CharField):
    """
    Encrypted CharField.

    Note: ``max_length`` applies to the *plaintext* value for form validation.
    The ciphertext stored in the database is longer, and the column is the
    backend's text type rather than a length-limited one, so ``max_length``
    does not constrain the column.
    """


class EncryptedEmailField(_EncryptedFieldMixin, models.EmailField):
    """Encrypted EmailField. Validates as email before encrypting."""


class EncryptedURLField(_EncryptedFieldMixin, models.URLField):
    """Encrypted URLField."""


class EncryptedIntegerField(_IntegerStorage, _EncryptedFieldMixin, models.IntegerField):
    """
    Encrypted integer — stores the integer as an encrypted decimal string.

    Because the database column contains text, range constraints and numeric
    indexes are not available.  Use this only for sensitive identifiers where
    query-ability is not required.
    """


class EncryptedDateField(_DateStorage, _EncryptedFieldMixin, models.DateField):
    """
    Encrypted DateField.

    Serializes the date to an ISO 8601 string (``YYYY-MM-DD``) before
    encrypting, and parses it back to a ``datetime.date`` after decrypting.

    Because the database column contains text, date-range filters and
    ordering at the database level are not available.
    """


class EncryptedDateTimeField(_DateTimeStorage, _EncryptedFieldMixin, models.DateTimeField):
    """
    Encrypted DateTimeField.

    Serializes the datetime to an ISO 8601 string before encrypting, and
    parses it back to a ``datetime.datetime`` after decrypting.  Timezone
    information is preserved in the serialized string when present.

    Because the database column contains text, datetime-range filters,
    ordering, and database-level date functions are not available.
    ``auto_now`` / ``auto_now_add`` set the Python value correctly before
    encryption, but the encrypted column cannot be used for ORDER BY or
    date-range queries at the database level.
    """


class EncryptedJSONField(_JsonStorage, _EncryptedFieldMixin, models.JSONField):
    """
    Encrypted JSONField. Stores the value as encrypted JSON text.

    The column is text rather than the database's own JSON type, so nothing can
    query, index or order by what is inside the value — ``filter(data__key=...)``
    included. Where the value is a bag of fields only ever read whole, that costs
    nothing; where parts of it are queried, encrypt those parts as columns of
    their own instead.
    """


# ---------------------------------------------------------------------------
# Encrypted file field
# ---------------------------------------------------------------------------


_UPLOAD_TO_BY_KEY_SET: dict = {}


def _upload_to_for_key_set(key_set: str):
    """Opaque storage path maker for a file of *key_set*: ``encryption_suite_<key_set>/<uuid>.bin``.

    One folder per key set, side by side, so a storage rule written for one folder
    never reaches another: the key sets are read with different keys. One function
    per key set, so a field can tell the default from a project's own ``upload_to``
    by identity.
    """
    if key_set not in _UPLOAD_TO_BY_KEY_SET:

        def upload_to(instance, filename):
            return f"encryption_suite_{key_set}/{uuid.uuid4().hex}.bin"

        _UPLOAD_TO_BY_KEY_SET[key_set] = upload_to
    return _UPLOAD_TO_BY_KEY_SET[key_set]


def _default_encrypted_upload_to(instance, filename):
    """Opaque storage path for a ``default`` key set file: ``encryption_suite_default/<uuid>.bin``.

    The path carries no part of the user's filename (which may be personal data,
    e.g. ``medical_scan.jpg``). The user-facing name is stored encrypted in the
    companion ``display_name_field`` column.
    """
    return f"encryption_suite_{DEFAULT_KEY_SET}/{uuid.uuid4().hex}.bin"


# Preview classification for encrypted files. Lives on the field so the
# descriptor (`obj.file.kind`) and any consumer — HTML template, DRF
# serializer, CLI — can branch on file type without re-implementing the
# extension list. No HTML / widget concerns: the kind is data, not UI.
PreviewKind = Literal["image", "pdf", "unsupported"]

# No "svg": an SVG can carry script, which runs on the site's origin when the
# file is opened directly.
DEFAULT_IMAGE_EXTENSIONS: tuple[str, ...] = (
    "png",
    "jpg",
    "jpeg",
    "gif",
    "webp",
)
DEFAULT_PDF_EXTENSIONS: tuple[str, ...] = ("pdf",)


def _classify_preview_kind(
    display_name: str,
    image_extensions: Iterable[str],
    pdf_extensions: Iterable[str],
) -> PreviewKind:
    ext = splitext(display_name or "")[1].lstrip(".").lower()
    if ext and ext in {e.lower() for e in image_extensions}:
        return "image"
    if ext and ext in {e.lower() for e in pdf_extensions}:
        return "pdf"
    return "unsupported"


class EncryptedFieldFile(FieldFile):
    """Descriptor for encrypted files. Adds AAD-aware streaming decrypt
    plus read-side ergonomics that mirror unencrypted files.

    Decryption
    ----------
    The default ``FieldFile`` calls ``self.storage.open(name)``, which
    goes through the storage mixin's ``_open`` and decrypts with empty
    AAD. That works for a file field without ``aad=`` but
    cannot bind file content to row identity, because the storage
    layer has no instance in scope. This subclass resolves AAD and a
    row-identity string from the host instance, fetches raw ciphertext
    via the storage mixin's ``_open_raw``, then wraps it with the
    engine's decrypting stream itself. Decryption therefore happens
    next to the only code that has ``self.instance``.

    Read-side ergonomics
    --------------------
    Properties expose information that templates and views routinely
    want without forcing them to re-derive it. All are pure data —
    no URLs, no rendering choices — so they apply equally to HTML
    forms, DRF responses, CLI tools, etc.

    * :attr:`display_name` — the decrypted human-readable filename
      from the companion ``display_name_field`` column. Empty string
      when the companion is undecryptable, NULL, or the file is unset.
    * :attr:`display_name_error` — the typed exception captured by the
      lazy-decrypt descriptor when the companion failed to decrypt,
      or ``None``. Detected without calling :meth:`probe`.
    * :attr:`kind` — preview classification (``image`` / ``pdf`` /
      ``unsupported``) based on the decrypted display name's extension
      and the field's ``image_extensions`` / ``pdf_extensions`` config.
    * :meth:`probe` — eager content authentication. Reads a single
      byte through the AAD-aware decrypting stream so a view can
      branch on whether the content will decrypt before committing to
      a streaming response. Result is cached.
    * :attr:`decryption_error` — exception captured by the most recent
      :meth:`probe` call, or ``None``.
    * :attr:`is_undecryptable` — convenience: ``True`` if either the
      probed content failed or the display-name companion failed.
    """

    def __init__(self, instance, field, name):
        super().__init__(instance, field, name)
        # Probe state is per-descriptor-instance. ``FieldFile`` is
        # rebuilt by ``FileDescriptor`` whenever the underlying value
        # changes, so the cache resets when the file does.
        self._probed: bool = False
        self._probe_error: Exception | None = None

    @property
    def display_name(self) -> str:
        """Decrypted human-readable filename from the companion column.

        Returns ``""`` when the file is unset, the companion column is
        NULL, or the companion failed to decrypt. Use
        :attr:`display_name_error` to distinguish the failure case.
        """
        if not self:
            return ""
        value = getattr(self.instance, self.field.display_name_field, None)
        if value is None or is_undecryptable(value):
            return ""
        return str(value)

    @property
    def display_name_error(self) -> Exception | None:
        """Decryption exception for the companion column, or ``None``.

        Reads from ``instance.encryption_suite_errors`` — populated as a
        side effect of the lazy-decrypt descriptor on first access.
        Reading this property triggers a decrypt attempt on the
        companion column if one has not already happened.
        """
        if not self:
            return None
        # Touch the descriptor so the lazy-decrypt path runs and
        # populates encryption_suite_errors on failure. The result is
        # discarded; we only care about the error map.
        getattr(self.instance, self.field.display_name_field, None)
        errors = getattr(self.instance, "encryption_suite_errors", None) or {}
        return errors.get(self.field.display_name_field)

    @property
    def kind(self) -> PreviewKind:
        """Preview classification based on the decrypted display name."""
        return _classify_preview_kind(
            self.display_name,
            self.field.image_extensions,
            self.field.pdf_extensions,
        )

    @property
    def decryption_error(self) -> Exception | None:
        """Exception captured by the most recent :meth:`probe`, or ``None``.

        ``probe()`` must be called explicitly because verifying content
        decryption requires opening the underlying ciphertext stream;
        this property never triggers I/O on its own.
        """
        return self._probe_error

    @property
    def is_undecryptable(self) -> bool:
        """``True`` if probed content failed to decrypt, or the
        companion display-name failed to decrypt."""
        return self._probe_error is not None or self.display_name_error is not None

    def probe(self) -> bool:
        """Eagerly authenticate the encrypted file content.

        Reads a single byte through the AAD-aware decrypting stream.
        Returns ``True`` on success; on failure, stores the typed
        exception on :attr:`decryption_error` and returns ``False``.
        Result is cached on the descriptor — repeat calls do not
        touch storage. A file with no name (``self`` is falsy) is
        considered trivially decryptable.

        Any :class:`EncryptionError` counts as "not decryptable" — not only
        ciphertext rejection (``EncryptedFileDecryptionError``) but also a key
        acquisition failure (``MissingDekError``, ``KekUnavailableError``),
        which surfaces at stream-open time, and a storage-backend failure
        (``EncryptedFileStorageError``) when the ciphertext blob is missing or
        unreadable. A read should report the file as undisplayable rather than
        raising into the view.
        """
        from .exceptions import EncryptionError

        if self._probed:
            return self._probe_error is None
        self._probed = True
        if not self:
            return True
        try:
            with self._open_decrypting() as stream:
                stream.read(1)
        except EncryptionError as exc:
            self._probe_error = exc
            return False
        return True

    def _open_decrypting(self, mode: str = "rb"):
        from .exceptions import (
            GENERIC_DECRYPT_FAILED_USER_MESSAGE,
            EncryptedFileDecryptionError,
        )
        from .storage import _DecryptingFile

        model = type(self.instance)
        field_label = f"{model._meta.label}.{self.field.attname}"

        # Build AAD / row-identity. A failure here (e.g. a None AAD column)
        # means the file cannot be produced, so normalize it to a decryption
        # failure — matching the field read path — rather than letting a raw
        # ValueError escape the graceful read paths (probe(),
        # serve_encrypted_file) and 500 the view.
        try:
            identity_parts: list[str] = []
            base_identity = _build_row_identity(model, self.instance, self.field)
            if base_identity:
                identity_parts.append(base_identity)
            aad = _build_aad_for_instance(model, self.field, self.instance)
            identity_parts.append(f"file={self.name}")
            row_identity = ",".join(identity_parts)
        except Exception as exc:
            from ._internal import operator_error_text

            logger.error(
                "Building the additional authenticated data for an encrypted file failed. "
                'error_code=%s field="%s" detail="%s"',
                EncryptedFileDecryptionError.code,
                field_label,
                operator_error_text(exc),
            )
            raise EncryptedFileDecryptionError(
                GENERIC_DECRYPT_FAILED_USER_MESSAGE,
                detail=(
                    f'field="{field_label}" Failed to build AAD for the encrypted file: {operator_error_text(exc)}'
                ),
            ) from exc

        ciphertext = self.storage._open_raw(self.name, mode)
        try:
            stream, silo_uid = self.field._decrypting_stream(
                ciphertext,
                aad=aad,
                row_identity=row_identity,
                field_label=field_label,
            )
        except Exception:
            ciphertext.close()
            raise
        return _DecryptingFile(
            stream,
            ciphertext,
            self.name,
            silo_uid=silo_uid,
            row_identity=row_identity,
            field_label=field_label,
        )

    def _get_file(self):
        self._require_file()
        if getattr(self, "_file", None) is None:
            self._file = self._open_decrypting()
        return self._file

    def _set_file(self, file):
        self._file = file

    def _del_file(self):
        del self._file

    file = property(_get_file, _set_file, _del_file)

    def open(self, mode: str = "rb"):
        self._require_file()
        if getattr(self, "_file", None) is None:
            self.file = self._open_decrypting(mode)
        else:
            self.file.open(mode)
        return self

    open.alters_data = True


class _EncryptedFileFieldBase(models.FileField):
    """FileField whose content is encrypted on disk and whose user-facing
    filename is encrypted in a companion model column.

    The base of :class:`EncryptedFileField`, which adds the ``key`` option. A
    subclass names how a blob is read through ``_decrypting_stream`` and
    ``_default_storage``, its default ``upload_to``, and the field class its
    companion must be.

    Two things happen automatically:

    1. Content is streamed through the subclass's storage mixin so the
       underlying storage backend only ever sees ciphertext.
    2. The stored path is an opaque UUID (``encryption_suite/<hex>.bin`` by
       default), so storage listings / bucket keys / backup logs do not leak
       filenames.

    The human-readable filename lives in a separate encrypted column on the
    same model, named by ``display_name_field``. Declare that column
    yourself — following the ``ImageField`` / ``width_field`` precedent,
    nothing is auto-attached:

        class Document(models.Model):
            file = EncryptedFileField(display_name_field="file_display_name")
            file_display_name = EncryptedCharField(max_length=255, blank=True)

    On upload, the display name is populated from the original upload name,
    or from the result of the optional ``naming_convention`` callable —
    ``(instance, original_name) -> str``. An explicitly-set value on the
    instance is respected.

    AAD binding
    -----------
    The file field and its display-name companion (a regular encrypted
    field) each bind to the columns their own ``aad=`` names; declare the
    same columns on both to bind them to the same row identity. Tampering
    with a bound column makes the field that binds it fail to decrypt on the
    next read, with a log entry that identifies the row by pk, AAD columns,
    and storage path.

    Decryption for AAD-bound files runs in
    :class:`EncryptedFieldFile` — the descriptor has the host instance in
    scope and computes AAD from it before opening the ciphertext stream.

    Lifecycle cleanup
    -----------------

    Unlike stock ``FileField``, the ciphertext blob is deleted when the
    model row is deleted and when a new file replaces an existing one, so
    that sensitive content does not accumulate as orphans in storage:

    * ``delete_on_row_delete`` (default ``True``) — connects a
      ``post_delete`` receiver that removes the ciphertext after the
      transaction commits. Attaching the receiver also disables Django's
      bulk-delete fast path for the host model, so ``QuerySet.delete()``
      and cascade deletes clean up their files too.
    * ``delete_on_replace`` (default ``True``) — when a fresh upload
      replaces an existing file on the same row, the prior ciphertext is
      deleted after the transaction commits.

    Both deletions are scheduled via ``transaction.on_commit``, so a
    rolled-back save or delete leaves the prior blob intact.

    Set both to ``False`` when pairing with a versioning tool such as
    ``django-reversion`` or ``django-simple-history`` that needs historical
    rows to keep pointing at past ciphertext.
    """

    attr_class = EncryptedFieldFile

    #: The ``upload_to`` used when none is passed, and stripped from migrations.
    default_upload_to = None
    #: The field class ``display_name_field`` must name.
    companion_class: type = models.Field

    @staticmethod
    def _default_storage():
        """Return the storage callable used when none is passed."""
        raise NotImplementedError

    @staticmethod
    def _storage_mixin() -> type:
        """Return the storage mixin this field's storage must include (``E036``)."""
        raise NotImplementedError

    def _decrypting_stream(self, ciphertext, *, aad: bytes, row_identity: str, field_label: str):
        """Return ``(plaintext stream, silo uid for the log)`` for one stored blob."""
        raise NotImplementedError

    def _default_upload_to(self):
        """The ``upload_to`` used when none is passed, and stripped from migrations."""
        return type(self).default_upload_to

    def __init__(
        self,
        *args,
        display_name_field: str,
        naming_convention=None,
        image_extensions: Iterable[str] | None = None,
        pdf_extensions: Iterable[str] | None = None,
        upload_to=None,
        storage=None,
        delete_on_row_delete: bool = True,
        delete_on_replace: bool = True,
        aad=(),
        **kwargs,
    ):
        #: As on the encrypted fields: columns bound into this file's AAD.
        self.aad = aad
        self.display_name_field = display_name_field
        self.naming_convention = naming_convention
        # Extension lists drive the descriptor's ``kind`` classification.
        # Defaults cover common previewable types; consumers that want
        # different rules pass their own. Stored as tuples so deconstruct
        # output is stable across Python invocations.
        self.image_extensions = tuple(image_extensions) if image_extensions is not None else DEFAULT_IMAGE_EXTENSIONS
        self.pdf_extensions = tuple(pdf_extensions) if pdf_extensions is not None else DEFAULT_PDF_EXTENSIONS
        self.delete_on_row_delete = delete_on_row_delete
        self.delete_on_replace = delete_on_replace
        if upload_to is None:
            upload_to = self._default_upload_to()
        if storage is None:
            # Pass the resolver as a callable so Django defers storage
            # instantiation until settings are loaded. The resolver reads
            # Django's STORAGES dict at the configured alias (default
            # "encrypted") and composes the encryption mixin onto it.
            storage = self._default_storage()
        super().__init__(*args, upload_to=upload_to, storage=storage, **kwargs)

    def deconstruct(self):
        name, path, args, kwargs = super().deconstruct()
        kwargs["display_name_field"] = self.display_name_field
        if self.naming_convention is not None:
            kwargs["naming_convention"] = self.naming_convention
        if self.image_extensions != DEFAULT_IMAGE_EXTENSIONS:
            kwargs["image_extensions"] = list(self.image_extensions)
        if self.pdf_extensions != DEFAULT_PDF_EXTENSIONS:
            kwargs["pdf_extensions"] = list(self.pdf_extensions)
        if self.delete_on_row_delete is not True:
            kwargs["delete_on_row_delete"] = self.delete_on_row_delete
        if self.delete_on_replace is not True:
            kwargs["delete_on_replace"] = self.delete_on_replace
        if self.aad:
            kwargs["aad"] = _deconstruct_aad(self.aad)
        # Strip default upload_to / storage so migrations stay stable across
        # Python object identity changes.
        if kwargs.get("upload_to") is self._default_upload_to():
            kwargs.pop("upload_to")
        return name, path, args, kwargs

    def generate_filename(self, instance, filename):
        # A string upload_to is a folder, as on a stock FileField, but the name
        # under it stays opaque. Django would otherwise keep the upload's own
        # filename, which leaks it to storage listings and repeats across
        # uploads. A callable returns the whole name and is left to choose it.
        if not callable(self.upload_to):
            filename = f"{uuid.uuid4().hex}.bin"
        return super().generate_filename(instance, filename)

    def formfield(self, **kwargs):
        # setdefault, so a widget from Meta.widgets or widget= still wins.
        kwargs.setdefault("widget", EncryptedClearableFileInput)
        # The form limits the uploaded filename, which is kept in the
        # display-name column; this column holds the opaque stored path.
        kwargs.setdefault("max_length", self._display_name_max_length())
        return super().formfield(**kwargs)

    def contribute_to_class(self, cls, name, **kwargs):
        super().contribute_to_class(cls, name, **kwargs)
        if self.delete_on_row_delete:
            from django.db.models.signals import pre_delete

            # pre_delete rather than post_delete so the path can still be
            # read from the row. Admin applies .only(non_encrypted) on its
            # querysets, which defers this column; a post_delete receiver
            # that triggers the descriptor's lazy refresh would hit a row
            # that no longer exists and raise DoesNotExist. Attaching
            # either pre_delete or post_delete disables Django's
            # bulk-delete fast path, so cascade and QuerySet.delete()
            # cleanup is preserved.
            pre_delete.connect(
                self._pre_delete_receiver,
                sender=cls,
                weak=False,
                dispatch_uid=(f"encryption_suite_file_delete_{cls._meta.label_lower}_{name}"),
            )

    def _pre_delete_receiver(self, sender, instance, **kwargs):
        # Distinguish "field deferred from the queryset" (column missing
        # from __dict__) from "field loaded with value None" (present in
        # __dict__ as None). Admin applies .only(non_encrypted), which
        # produces the former; going through the descriptor there would
        # trigger a deferred-field refresh that races the in-flight
        # delete.
        if self.attname in instance.__dict__:
            file = getattr(instance, self.attname, None)
            path = getattr(file, "name", None) if file else None
        else:
            path = type(instance)._base_manager.filter(pk=instance.pk).values_list(self.attname, flat=True).first()
        if not path:
            return
        self._schedule_delete(path)

    def _schedule_delete(self, path: str) -> None:
        """Queue a ciphertext delete to run after the current transaction commits.

        Outside an atomic block ``on_commit`` fires immediately. Inside
        one, a rollback discards the callback so ciphertext survives a
        failed save or delete.
        """
        from django.db import transaction

        storage = self.storage
        field_label = self._field_label_for_logging()

        def _run():
            try:
                storage.delete(path)
            except Exception as exc:
                from ._internal import operator_error_text

                # Best-effort cleanup of a file the row no longer points at, so a
                # failure leaves an orphaned ciphertext but breaks nothing. The
                # storage backend's own traceback would say little the marker and
                # the path do not.
                logger.warning(
                    "A superseded encrypted file could not be deleted from storage; the row is "
                    'correct and the old blob is left behind. path="%s" field="%s" detail="%s"',
                    path,
                    field_label,
                    operator_error_text(exc),
                )

        transaction.on_commit(_run)

    def _field_label_for_logging(self) -> str:
        model = getattr(self, "model", None)
        name = getattr(self, "name", "<unknown>")
        if model is not None:
            return f"{model._meta.label}.{name}"
        return name

    def check(self, **kwargs):
        errors = super().check(**kwargs)
        errors.extend(_check_blank_requires_null(self))
        errors.extend(_check_aad(self))
        errors.extend(self._check_display_name_field())
        errors.extend(self._check_storage_mixin())
        return errors

    def _check_storage_mixin(self):
        """``E036`` unless the storage carries the encryption mixin.

        Without it, nothing stands in front of the backend and every upload is
        written as plaintext.
        """
        from django.core import checks

        wanted = self._storage_mixin()
        if isinstance(self.storage, wanted):
            return []
        model = getattr(self, "model", None)
        label = f"{model._meta.label}.{self.name}" if model is not None else type(self).__name__
        return [
            checks.Error(
                f"{label} is a {type(self).__name__}, but its storage {type(self.storage).__name__} does not "
                f"include {wanted.__name__}, so files would be written unencrypted.",
                hint=(
                    f"Leave storage= unset to use the STORAGE_ALIAS backend, or compose {wanted.__name__} "
                    "onto the backend you pass."
                ),
                obj=self,
                id="encryption_suite.E036",
            )
        ]

    def _check_display_name_field(self):
        from django.core import checks

        model = getattr(self, "model", None)
        if model is None:
            return []
        try:
            companion = model._meta.get_field(self.display_name_field)
        except FieldDoesNotExist:
            return [
                checks.Error(
                    f"{type(self).__name__} references display_name_field="
                    f"{self.display_name_field!r}, but no such field exists on "
                    f"{model._meta.label}.",
                    obj=self,
                    id="encryption_suite.E023",
                )
            ]
        if not isinstance(companion, self.companion_class):
            wanted = self.companion_class.__name__
            article = "an" if wanted[0] in "AEIOU" else "a"
            return [
                checks.Error(
                    f"{type(self).__name__}.display_name_field must point to {article} "
                    f"{wanted}. {model._meta.label}."
                    f"{self.display_name_field} is {type(companion).__name__}.",
                    obj=self,
                    id="encryption_suite.E024",
                )
            ]
        mine = getattr(self, "key_set", None)
        theirs = getattr(companion, "key_set", None)
        if mine is not None and theirs != mine:
            return [
                checks.Error(
                    f"{type(self).__name__}.display_name_field must use the same key_set as the "
                    f"file. {model._meta.label}.{self.name} has key_set={mine!r}, "
                    f"and {model._meta.label}.{self.display_name_field} has key_set={theirs!r}.",
                    hint=f"Set key_set={mine!r} on {self.display_name_field}.",
                    obj=self,
                    id="encryption_suite.E024",
                )
            ]
        return []

    def pre_save(self, model_instance, add):
        file = getattr(model_instance, self.attname)
        # _committed=False signals a fresh upload not yet written to storage.
        is_new_upload = bool(file) and not getattr(file, "_committed", True)
        if is_new_upload:
            self._populate_display_name(model_instance, file.name or "")
            # When the field declares aad=, attach AAD
            # to the inner content object so the storage mixin's _save can
            # bind streaming-AEAD ciphertext to the row's identity. Storage
            # has no instance in scope, so the field plumbs the value through
            # the content object that's about to cross the boundary.
            model = type(model_instance)
            inner = getattr(file, "file", None)
            if inner is not None and aad_attnames(self):
                inner._encryption_suite_aad = _build_write_aad(model, self, model_instance, file=True)
            # The silo goes the same way: the storage writes under the one the
            # field names, and resolves the context's when it names none.
            if inner is not None:
                inner._encryption_suite_silo = _engine_silo(getattr(self, "key_set", DEFAULT_KEY_SET))

        # Fetch the prior path on any save of an existing row whose file
        # field value might have changed — covers both replacement (fresh
        # upload) and clearing (empty FieldFile, typically produced by
        # Django's ClearableFileInput "[x] Clear" checkbox or by setting
        # the attribute to None/""). Skipping the empty-value branch
        # would orphan ciphertext whenever a user cleared the field.
        old_name = None
        field_is_empty = not bool(file)
        if self.delete_on_replace and not add and model_instance.pk is not None and (is_new_upload or field_is_empty):
            # One targeted query. Use _base_manager so custom default
            # managers with filters don't hide the row.
            old_name = (
                type(model_instance)
                ._base_manager.filter(pk=model_instance.pk)
                .values_list(self.attname, flat=True)
                .first()
            )

        result = super().pre_save(model_instance, add)

        new_name = result or ""
        if old_name and old_name != new_name:
            self._schedule_delete(old_name)

        return result

    def _populate_display_name(self, model_instance, original_name: str) -> None:
        """Write the display name to the companion column.

        An explicit value already set on the instance is respected. Otherwise,
        the ``naming_convention`` callable decides the name, falling back to
        the original upload filename. A name longer than the companion's
        ``max_length`` keeps its rightmost characters, so the extension
        survives.
        """
        current = getattr(model_instance, self.display_name_field, None)
        if current:
            return
        if self.naming_convention is not None:
            display = self.naming_convention(model_instance, original_name)
        else:
            display = original_name
        max_length = self._display_name_max_length()
        if max_length and len(display) > max_length:
            display = display[-max_length:]
        setattr(model_instance, self.display_name_field, display)

    def _display_name_max_length(self) -> int | None:
        model = getattr(self, "model", None)
        if model is None:
            return None
        return model._meta.get_field(self.display_name_field).max_length


class EncryptedFileField(_EncryptedFileFieldBase):
    """An encrypted file field under a file key: the current silo's, or the system silo's.

    ``key_set`` names the key set (``default`` by default). Files are stored as
    ``encryption_suite_<key_set>/<uuid>.bin``. The display-name companion is an
    encrypted char field with the same ``key_set``.
    ``reencrypt_data`` moves the blobs when the data key rotates.
    """

    default_upload_to = staticmethod(_default_encrypted_upload_to)
    companion_class = EncryptedCharField

    def __init__(self, *args, key_set: str = DEFAULT_KEY_SET, **kwargs):
        self.key_set = key_set
        super().__init__(*args, **kwargs)

    def _default_upload_to(self):
        return _upload_to_for_key_set(self.key_set)

    def deconstruct(self):
        name, path, args, kwargs = super().deconstruct()
        if self.key_set != DEFAULT_KEY_SET:
            kwargs["key_set"] = self.key_set
        return name, path, args, kwargs

    def check(self, **kwargs):
        errors = super().check(**kwargs)
        errors.extend(_check_key(self))
        return errors

    @staticmethod
    def _default_storage():
        from .storage import get_encrypted_storage

        return get_encrypted_storage

    @staticmethod
    def _storage_mixin() -> type:
        from .storage import SiloEncryptedStorageMixin

        return SiloEncryptedStorageMixin

    def _decrypting_stream(self, ciphertext, *, aad: bytes, row_identity: str, field_label: str):
        from .registry import get_engine

        engine = get_engine()
        silo = _engine_silo(self.key_set)
        stream = engine.open_decrypting_stream(
            ciphertext, aad=aad, silo=silo, row_identity=row_identity, field_name=field_label
        )
        return stream, str(engine._resolve_silo_uid(silo))
