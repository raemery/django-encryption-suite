"""The table-backed blind index: writing it, deleting it, and reading it back.

:class:`~encryption_suite.models.BlindIndexEntry` holds the digests of fields
declared ``blind_index_storage="table"``. The field computes the digest — which key
does that is the field's business — and everything about *where* it goes is
here.

Three things a companion column gets from the database and this has to do for
itself:

* **The write.** A column is written by the same statement as the value. A row
  here is a second statement, and it cannot run during ``pre_save`` because an
  insert has no primary key yet. So the field stashes the digest on the instance
  and a ``post_save`` receiver writes it. ``post_save`` fires *outside* the block
  ``Model.save_base`` wraps its own writes in, and for a model with no parents
  that block is not even a transaction, so the save wrapper this package installs
  opens one — otherwise a failure between the two leaves a row whose digest was
  never written, which is a row no lookup can find.
* **The delete.** A column goes when its row goes. A row here points at a
  different model for every entry, which no foreign key can express, so a
  ``post_delete`` receiver removes it. That has a cost worth knowing: Django
  skips its fast-delete path for any model with delete signals, so bulk deletes
  on a watched model instantiate objects instead of issuing one statement. A
  delete that bypasses signals — ``_raw_delete``, a ``TRUNCATE``, a migration —
  leaves entries behind. They are harmless until a primary key is reused, and
  nothing in Django reuses one.
* **The read.** A column is compared on the row being filtered. This compares
  through an ``EXISTS`` subquery correlated on the primary key.
"""

from __future__ import annotations

import hashlib
import hmac

from django.db import transaction
from django.db.models.signals import post_delete, post_save

from .conf import DEFAULT_KEY_SET

#: Bytes of key material a blind index key holds — an HMAC-SHA-256 key of the
#: size that hash takes. The width of what it produces is
#: :data:`~encryption_suite.fields.INDEX_DIGEST_LEN`, which is a property of the
#: column it goes in rather than of the key.
INDEX_KEY_BYTES = 32

#: The algorithm recorded for a blind index key, in the spelling the crypto
#: backends use for theirs. No backend makes an index key, so it is named here.
INDEX_ALGORITHM = "HMAC_SHA256"


def compute_digest(material: bytes, value: str, *, context: str) -> str:
    """Return the blind index digest of *value* under *material*, as hex.

    One construction for every column, so a digest means the same thing
    wherever it was computed and whichever key computed it. *context* names the
    column — ``"app.Model.field"`` — and is part of the hash, so one value held
    in two columns does not index alike and the two cannot be matched against
    each other.

    Keyed rather than plain: an unkeyed hash of an email address is recovered by
    hashing a word list. Which key is the index key of the silo the column's
    ``key`` selects: the current silo's, or the system silo's.
    """
    return hmac.new(material, f"{context}\x00{value}".encode(), hashlib.sha256).hexdigest()


#: Where the field leaves a digest for the ``post_save`` receiver to write:
#: ``{field name: digest or None}``, on the instance, cleared once written. On
#: the instance rather than on the field, because a field is shared by every
#: instance of its model and two saves can be in flight at once.
PENDING_ATTR = "_encryption_suite_pending_index"

#: Marks a model whose receivers are installed, so a second ``class_prepared``
#: for the same model — or an inheriting one — does not double them.
INSTALLED_ATTR = "_encryption_suite_blind_index_synchronized"


def silo_indexed_fields(model=None, *, key_set: str = DEFAULT_KEY_SET):
    """Yield ``(model, field)`` for every encrypted field of *key_set* carrying a blind index.

    Answers whether a deployment needs an index key in a key set at all: a project
    declaring no such field needs none, so nothing provisions one for it.

    Only fields on a model's own table, for the reason that helper gives: a
    multi-table child reaches its parent's column through a join, and a proxy
    shares its concrete model's table.
    """
    from django.apps import apps

    from .fields import _EncryptedFieldMixin

    candidates = [model] if model is not None else apps.get_models()
    for candidate in candidates:
        if candidate._meta.proxy:
            continue
        for field in candidate._meta.local_fields:
            if isinstance(field, _EncryptedFieldMixin) and field.blind_index and field.key_set == key_set:
                yield candidate, field


def table_indexed_fields(model):
    """Every field on *model* keeping its blind index in the shared table."""
    from .fields import BLIND_INDEX_STORAGE_TABLE, _CiphertextFieldMixin

    return [
        field
        for field in model._meta.concrete_fields
        if isinstance(field, _CiphertextFieldMixin)
        and field.blind_index
        and field.blind_index_storage == BLIND_INDEX_STORAGE_TABLE
    ]


def stash_digest(instance, field_name: str, digest: str | None) -> None:
    """Record what the ``post_save`` receiver should write for *field_name*.

    ``None`` means the field now holds no value, so its entry is removed rather
    than written: a row holding nothing must not answer a lookup for anything.
    """
    pending = instance.__dict__.setdefault(PENDING_ATTR, {})
    pending[field_name] = digest


def install_synchronization(model) -> None:
    """Connect the write and delete receivers for *model*, once."""
    if getattr(model, INSTALLED_ATTR, False):
        return
    post_save.connect(
        _on_post_save,
        sender=model,
        dispatch_uid=f"encryption_suite.blind_index.save.{model._meta.label_lower}",
    )
    post_delete.connect(
        _on_post_delete,
        sender=model,
        dispatch_uid=f"encryption_suite.blind_index.delete.{model._meta.label_lower}",
    )
    model._encryption_suite_blind_index_synchronized = True


def _on_post_save(sender, instance, using=None, **kwargs):
    """Write the digests ``pre_save`` stashed, and only those.

    A narrowed save — ``update_fields`` naming other columns — runs no
    ``pre_save`` for this field, so nothing is stashed and the entry is left
    alone, which is right: the value it indexes did not change.
    """
    pending = instance.__dict__.pop(PENDING_ATTR, None)
    if not pending:
        return
    from .models import BlindIndexEntry

    label = sender._meta.label
    object_pk = str(instance.pk)
    unique_fields = {field.name: field.index_unique for field in table_indexed_fields(sender)}
    entries = BlindIndexEntry.objects.using(using)
    for field_name, digest in pending.items():
        scope = {"model_label": label, "field_name": field_name, "object_pk": object_pk}
        if digest is None:
            entries.filter(**scope).delete()
            continue
        entries.update_or_create(
            **scope,
            defaults={
                "digest": digest,
                # NULL rather than False where the field declares no uniqueness:
                # see BlindIndexEntry for why that is what scopes the constraint.
                "unique_enforced": True if unique_fields.get(field_name) else None,
            },
        )


def _on_post_delete(sender, instance, using=None, **kwargs):
    """Remove every entry for the row that just went.

    All of the model's fields at once: one statement, and nothing left to find
    for a row that no longer exists.
    """
    from .models import BlindIndexEntry

    BlindIndexEntry.objects.using(using).filter(
        model_label=sender._meta.label,
        object_pk=str(instance.pk),
    ).delete()


#: Answers to :func:`save_in_transaction`, which every save of a watched model
#: asks. Keyed on the model class, which the app registry holds for the life of
#: the process anyway, and settled once its fields are known.
_watched: dict[type, bool] = {}


def save_in_transaction(model) -> bool:
    """Whether *model*'s saves need a transaction opened around them.

    True once any field keeps its digest in the shared table: the row and its
    entry are two statements that have to agree. Asked on the instance's own
    class rather than read off a flag, so a model inheriting from one that
    carries such a field is answered for itself.
    """
    cached = _watched.get(model)
    if cached is None:
        cached = bool(table_indexed_fields(model))
        _watched[model] = cached
    return cached


def atomic_for(using):
    """The transaction a watched model's save runs in."""
    return transaction.atomic(using=using)


def comparison(field, lhs, digests, compiler, connection):
    """``EXISTS`` over the entries of *field* holding any of *digests*.

    Correlated on the primary key, and cast to text because ``object_pk`` holds
    the keys of every kind of model. The caller pairs this with the same
    "the value is present" condition the column strategy uses, so a row whose
    value was cleared answers nothing even if its entry outlived the value.
    """
    from django.db.models import CharField, Exists, OuterRef
    from django.db.models.functions import Cast

    from .models import BlindIndexEntry

    entries = BlindIndexEntry.objects.filter(
        model_label=field.model._meta.label,
        field_name=field.name,
        digest__in=digests,
        object_pk=Cast(OuterRef("pk"), output_field=CharField(max_length=255)),
    )
    return Exists(entries).resolve_expression(compiler.query)
