"""
Admin mixins for models with encrypted fields.

Django's admin reads every field it renders on the list and change views,
and reading an encrypted attribute decrypts it through the field's
descriptor. Outside of a request with a resolvable silo (e.g. the
``/admin/`` backend of a multi-tenant app viewed without a team context),
each read fails with ``configuration_error``: a lenient read degrades to the
fallback label and logs an error, a strict field raises, and the change form
cannot save.

``EncryptionAdminMixin`` makes admin a forensic view: encrypted fields
are never decrypted. List columns render a ciphertext preview fetched
via a raw cursor query, and change forms exclude encrypted fields
entirely. ``EncryptedFileField`` columns render as a
pair — the opaque storage key plus a ciphertext preview of the
companion ``display_name_field`` — using the same raw-cursor approach.
The instances the admin loads are marked, so a model's ``__str__``, which
the admin calls for the action checkbox, page titles, messages and the
history log, runs with every encrypted read refused and falls back to
Django's default ``<Model> object (<pk>)`` when it reaches for one (see
``fields._guard_str``).
"""

from __future__ import annotations

from django.db import connections
from django.db.models.query import ModelIterable
from django.utils.html import format_html

from ._internal import (
    encrypted_field_names,
    non_encrypted_concrete_field_names,
    raw_cursor_fetch_many,
)
from .fields import ADMIN_LOADED, EncryptedFileField, aad_attnames

CIPHERTEXT_PREVIEW_LENGTH = 48

#: Name prefix of the preview methods the mixin attaches.
_PREVIEW_PREFIX = "encryption_suite_preview_"
#: Instance-dict key holding the raw column values the changelist fetched for a row.
_RAW_COLUMNS = "_encryption_suite_admin_raw"


class _AdminModelIterable(ModelIterable):
    """Model iterable that marks each instance as loaded by the admin."""

    def __iter__(self):
        for obj in super().__iter__():
            obj.__dict__[ADMIN_LOADED] = True
            yield obj


class EncryptionAdminMixin:
    """Render encrypted fields as read-only ciphertext previews.

    Mix into any ``ModelAdmin`` whose model has encrypted fields. The
    mixin:

    - Excludes encrypted fields from the change form, so Django does not
      try to render them (which would decrypt).
    - Replaces any encrypted field names in ``list_display`` with a
      preview method that fetches the raw ciphertext without decrypting.
    - Loads the queryset with ``.only(...)`` restricted to non-encrypted
      columns, so encrypted values are never materialized on the
      instance during iteration.
    - Marks the instances that queryset loads, so a ``__str__`` that reads
      an encrypted field shows ``<Model> object (<pk>)`` rather than
      decrypting.

    The mixin is intentionally strict: encrypted fields cannot be
    edited through the admin when this mixin is in use. Operators who
    need to edit encrypted values should use a per-tenant frontend that
    sets the silo context, not the site-wide admin.
    """

    encryption_suite_ciphertext_preview_length = CIPHERTEXT_PREVIEW_LENGTH

    # ------------------------------------------------------------------
    # Encrypted-field discovery
    # ------------------------------------------------------------------

    def _encryption_suite_encrypted_field_names(self) -> list[str]:
        return encrypted_field_names(self.model)

    # ------------------------------------------------------------------
    # Queryset: avoid SELECTing ciphertext columns so attribute access
    # cannot accidentally trigger decryption during admin iteration.
    # ------------------------------------------------------------------

    def get_queryset(self, request):
        qs = super().get_queryset(request)
        if self._encryption_suite_encrypted_field_names():
            qs = qs.only(*non_encrypted_concrete_field_names(self.model))
            # A custom iterable the project chose is left alone; its instances
            # are not marked.
            if qs._iterable_class is ModelIterable:
                qs._iterable_class = _AdminModelIterable
        return qs

    # ------------------------------------------------------------------
    # Change form: exclude encrypted fields
    # ------------------------------------------------------------------

    def get_exclude(self, request, obj=None):
        base = list(super().get_exclude(request, obj) or [])
        for name in self._encryption_suite_encrypted_field_names():
            if name not in base:
                base.append(name)
        return base

    # ------------------------------------------------------------------
    # Changelist: replace encrypted field names with preview methods
    # ------------------------------------------------------------------

    def get_list_display(self, request):
        base = list(super().get_list_display(request))
        # Add pk and any AAD columns at the end of list_display so an
        # operator reading a decrypt-failure log (which prints
        # `row [pk=...,col=...]`) can locate the offending row in the
        # changelist. Adding them after the ModelAdmin's declared columns
        # keeps the default change-form link on the leading column.
        existing = {e for e in base if isinstance(e, str)}
        pk_attname = self.model._meta.pk.attname
        if pk_attname not in existing and "pk" not in existing:
            base.append(pk_attname)
            existing.add(pk_attname)
        bound = [col for field in self.model._meta.concrete_fields for col in aad_attnames(field)]
        for col in bound:
            if col != pk_attname and col not in existing:
                base.append(col)
                existing.add(col)
        encrypted = set(self._encryption_suite_encrypted_field_names())
        out = []
        for entry in base:
            if isinstance(entry, str) and entry in encrypted:
                try:
                    field = self.model._meta.get_field(entry)
                except Exception:
                    field = None
                if isinstance(field, EncryptedFileField):
                    out.append(self._encryption_suite_file_preview_method_name(entry))
                else:
                    out.append(self._encryption_suite_preview_method_name(entry))
            else:
                out.append(entry)
        return out

    def _encryption_suite_file_preview_method_name(self, field_name: str) -> str:
        """Attach a preview method for an ``EncryptedFileField`` and return its name.

        The list-view cell shows two pieces of raw data, neither decrypted:
        the opaque storage key (the file column's value) and a truncated
        ciphertext preview of the companion ``display_name_field`` column.
        Mirrors the ciphertext-preview approach used for other encrypted
        fields — admins see that rows differ without the admin ever
        materializing plaintext.
        """
        attr = f"{_PREVIEW_PREFIX}{field_name}"
        cls = type(self)
        if not hasattr(cls, attr):
            limit = self.encryption_suite_ciphertext_preview_length

            def method(self, obj, _name=field_name, _limit=limit):
                if obj is None or obj.pk is None:
                    return "—"
                companion = _companion_name(type(obj), _name)
                row = self._encryption_suite_raw_row(obj, [_name] if companion is None else [_name, companion])
                if not row:
                    return "—"
                storage_key = row[0]
                name_ct = row[1] if companion is not None and len(row) > 1 else None
                if storage_key is None and name_ct is None:
                    return "—"

                def _trunc(value):
                    value = str(value)
                    return value[:_limit], "…" if len(value) > _limit else ""

                if storage_key is None:
                    key_html = format_html("<code>{}</code>", "—")
                else:
                    key, key_suffix = _trunc(str(storage_key))
                    key_html = format_html(
                        '<code title="storage key (opaque)">{}{}</code>',
                        key,
                        key_suffix,
                    )
                if name_ct is None:
                    return key_html
                name, name_suffix = _trunc(name_ct)
                name_html = format_html(
                    '<code title="display name (ciphertext, not decrypted)">{}{}</code>',
                    name,
                    name_suffix,
                )
                return format_html("{} ({})", key_html, name_html)

            method.short_description = "file (with file name ciphertext)"
            setattr(cls, attr, method)
        return attr

    def _encryption_suite_preview_method_name(self, field_name: str) -> str:
        """Attach a preview method for *field_name* and return its name.

        The method queries the raw ciphertext via a raw cursor so it
        bypasses the ORM's ``from_db_value`` conversion and never
        decrypts.
        """
        attr = f"{_PREVIEW_PREFIX}{field_name}"
        cls = type(self)
        if not hasattr(cls, attr):
            limit = self.encryption_suite_ciphertext_preview_length

            def method(self, obj, _name=field_name, _limit=limit):
                if obj is None or obj.pk is None:
                    return "—"
                row = self._encryption_suite_raw_row(obj, [_name])
                raw = row[0] if row else None
                if raw is None:
                    return "—"
                raw = str(raw)
                truncated = raw[:_limit]
                suffix = "…" if len(raw) > _limit else ""
                return format_html(
                    '<code title="ciphertext (not decrypted)">{}{}</code>',
                    truncated,
                    suffix,
                )

            method.short_description = f"{field_name} (ciphertext)"
            setattr(cls, attr, method)
        return attr

    # ------------------------------------------------------------------
    # Raw ciphertext for the previews: one query per changelist page
    # ------------------------------------------------------------------

    def get_changelist_instance(self, request):
        """Fetch the page's ciphertext for every preview column in one query.

        The values are stored on the page's instances, which the changelist
        renders from its cached result list, so each preview reads them rather
        than querying its own row.
        """
        cl = super().get_changelist_instance(request)
        names = _preview_field_names(self.model, cl.list_display)
        if not names:
            return cl
        rows = list(cl.result_list)
        fetched = raw_cursor_fetch_many(self.model, [obj.pk for obj in rows], names)
        # A raw cursor returns the pk as the database holds it (a UUID can come
        # back as text), so match on the field's Python value.
        to_python = self.model._meta.pk.to_python
        by_pk = {to_python(pk): values for pk, values in fetched.items()}
        for obj in rows:
            values = by_pk.get(obj.pk)
            if values is not None:
                obj.__dict__[_RAW_COLUMNS] = dict(zip(names, values, strict=True))
        return cl

    def _encryption_suite_raw_row(self, obj, field_names: list[str]) -> tuple | None:
        """The raw values of *field_names* on *obj*'s row, never decrypted.

        Read from the changelist's batch when it holds them; otherwise one raw
        cursor query for this row. ``values_list`` and ``values`` would run the
        field's ``from_db_value`` and decrypt, so neither is used.
        """
        stash = obj.__dict__.get(_RAW_COLUMNS)
        if stash is not None and all(name in stash for name in field_names):
            return tuple(stash[name] for name in field_names)
        model_cls = type(obj)
        meta = model_cls._meta
        connection = connections[model_cls.objects.db]
        quote = connection.ops.quote_name
        columns = ", ".join(quote(meta.get_field(name).column) for name in field_names)
        with connection.cursor() as cursor:
            cursor.execute(
                f"SELECT {columns} FROM {quote(meta.db_table)} WHERE {quote(meta.pk.column)} = %s",
                [obj.pk],
            )
            return cursor.fetchone()


def _companion_name(model, field_name: str) -> str | None:
    """The ``display_name_field`` of file field *field_name*, if the model has it."""
    companion = model._meta.get_field(field_name).display_name_field
    try:
        model._meta.get_field(companion)
    except Exception:
        return None
    return companion


def _preview_field_names(model, list_display) -> list[str]:
    """The fields whose raw values the preview columns in *list_display* show."""
    names: list[str] = []
    for entry in list_display:
        if not (isinstance(entry, str) and entry.startswith(_PREVIEW_PREFIX)):
            continue
        name = entry[len(_PREVIEW_PREFIX) :]
        try:
            field = model._meta.get_field(name)
        except Exception:
            continue
        wanted = [name]
        if isinstance(field, EncryptedFileField):
            companion = _companion_name(model, name)
            if companion is not None:
                wanted.append(companion)
        names.extend(n for n in wanted if n not in names)
    return names
