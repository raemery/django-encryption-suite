"""
Finding what a data key rotation has to convert.

A silo names its keys, not its data: the engine gets the silo from context at
encrypt time, so nothing records which rows were encrypted for which silo. This
module goes the other way, from a silo to its rows, in three steps:

* **Which models hold encrypted data** — every installed model declaring an
  encrypted field on its own table. Nothing to configure, and a model added
  later is covered the day it is added. A file field is file work; every other
  encrypted field is field work, a file's display-name column included.
* **Which of a model's rows belong to a silo** — by introspection where it
  answers: the silo adapter names its silo model in ``model_label``, and a model
  with exactly one foreign key to that model is filtered on it. Where it does
  not, the adapter's :meth:`~encryption_suite.adapters.silos.base.AbstractSiloAdapter.queryset_for_silo`
  answers, if it declares ``supports_silo_data_lookup``.
* **What could not be resolved** — reported by name, never skipped. A model the
  rotation cannot see keeps its rows on the old key, and the swap destroys that
  key.

Every row lookup goes through the model's base manager: a default manager that
filters would hide live rows from the worklist.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field

from django.apps import apps

from .conf import DEFAULT_KEY_SET, SYSTEM_ADAPTER, SYSTEM_KEY_SET
from .fields import EncryptedFileField, _EncryptedFieldMixin
from .models import DataEncryptionKey


def _key_set_of(model, name: str) -> str:
    """The key set the column *name* of *model* belongs to."""
    return model._meta.get_field(name).key_set


@dataclass(frozen=True)
class Target:
    """One model a rotation converts, and how to find a silo's rows of it."""

    model: type
    #: Encrypted field columns declared on this model's own table (field work).
    field_names: tuple[str, ...]
    #: Encrypted file columns declared on this model's own table (file work).
    file_names: tuple[str, ...]
    #: The subset of ``field_names`` carrying a blind index (index work). A
    #: subset rather than a separate set of columns: re-indexing rewrites the
    #: digest of a column the field work also converts, just under a different
    #: key and without touching the value.
    index_names: tuple[str, ...]
    #: The foreign key to the silo model, or ``None`` where the adapter answers.
    fk_name: str | None

    @property
    def label(self) -> str:
        return self.model._meta.label

    def names_for(self, purpose: str, key_set: str = DEFAULT_KEY_SET) -> tuple[str, ...]:
        """The columns encrypted under the *purpose* key of *key_set*: a key converts only its own set's columns."""
        if purpose == DataEncryptionKey.PURPOSE_FILE:
            names = self.file_names
        elif purpose == DataEncryptionKey.PURPOSE_INDEX:
            names = self.index_names
        else:
            names = self.field_names
        return tuple(name for name in names if _key_set_of(self.model, name) == key_set)


@dataclass
class Resolution:
    targets: list[Target] = field(default_factory=list)
    #: ``(model label, why)`` for every model nothing could resolve.
    unresolved: list[tuple[str, str]] = field(default_factory=list)

    def for_purpose(self, purpose: str, key_set: str = DEFAULT_KEY_SET) -> list[Target]:
        return [t for t in self.targets if t.names_for(purpose, key_set)]

    @property
    def needs_silo_object(self) -> bool:
        """Whether any target filters on a foreign key, and so needs the silo row."""
        return any(t.fk_name for t in self.targets)


def encrypted_models(
    key_set: str = DEFAULT_KEY_SET,
) -> Iterator[tuple[type, tuple[str, ...], tuple[str, ...], tuple[str, ...]]]:
    """Yield ``(model, field_names, file_names, index_names)`` for every model holding data in *key_set*.

    *key_set* is a field's ``key_set`` option: its columns are encrypted under the
    keys of that key set, and a rotation of one never converts another. A model
    holding several key sets appears under each.

    Only fields declared on the model's own table count. A multi-table child
    inherits its parent's encrypted fields through a join, and counting them
    on both would convert the same column twice. Proxy models share their
    concrete model's table and are skipped for the same reason.
    """
    for model in apps.get_models():
        if model._meta.proxy:
            continue
        local = model._meta.local_fields
        encrypted = [f for f in local if isinstance(f, _EncryptedFieldMixin) and f.key_set == key_set]
        field_names = tuple(f.name for f in encrypted)
        file_names = tuple(f.name for f in local if isinstance(f, EncryptedFileField) and f.key_set == key_set)
        index_names = tuple(f.name for f in encrypted if f.blind_index)
        if field_names or file_names:
            yield model, field_names, file_names, index_names


def key_sets_in_use() -> set[str]:
    """The key sets the encrypted fields declare: ``{"default"}``, ``{"default", "restricted"}``, or none.

    What tells ``reencrypt_keys`` and ``setup_encryption_keys`` which sets keys
    are made for: the data key row records the store that wraps it, and the
    declaration is the only place the set a column belongs to is written.
    """
    sets = set()
    for model in apps.get_models():
        if model._meta.proxy:
            continue
        for each in model._meta.local_fields:
            if isinstance(each, (_EncryptedFieldMixin, EncryptedFileField)):
                sets.add(each.key_set)
    return sets


def system_key_sets_needed() -> list[str]:
    """The key sets bound to the system adapter that this deployment encrypts anything under, sorted.

    A model declaring a column in a system key set needs that key set's keys. The
    package's own identity tables declare such columns in the ``system`` key set on
    every install, so they count only where ``KEY_LIFECYCLE_EVENTS`` lists an
    ``encrypted_*`` item — when something is written to them encrypted. Otherwise
    every deployment would need system keys, including one that never encrypts a
    system column.
    """
    from .conf import ITEM_ENCRYPTED_IP_ADDRESS, ITEM_ENCRYPTED_OS_USER, key_sets_of_adapter, user_identity_setting
    from .models import RecordedIPAddress, RecordedOSUser

    identity_tables = (RecordedIPAddress, RecordedOSUser)
    items = user_identity_setting("KEY_LIFECYCLE_EVENTS")
    identity_encrypted = ITEM_ENCRYPTED_IP_ADDRESS in items or ITEM_ENCRYPTED_OS_USER in items
    return sorted(
        key_set
        for key_set in key_sets_of_adapter(SYSTEM_ADAPTER)
        if any(model not in identity_tables for model, *_names in encrypted_models(key_set))
        or (key_set == SYSTEM_KEY_SET and identity_encrypted)
    )


def _silo_model(adapter):
    """The model the adapter's ``model_label`` names, or ``None``."""
    label = getattr(adapter, "model_label", None)
    if not label:
        return None
    try:
        return apps.get_model(label)
    except (LookupError, ValueError):
        return None


def _silo_foreign_key(model, silo_model) -> tuple[object | None, str]:
    """The one foreign key from *model* to *silo_model*, or ``None`` and why not."""
    if silo_model is None:
        return None, "the silo adapter declares no model_label"
    keys = [
        f
        for f in model._meta.get_fields()
        if getattr(f, "many_to_one", False) and getattr(f, "concrete", False) and f.related_model is silo_model
    ]
    if len(keys) == 1:
        return keys[0], ""
    if not keys:
        return None, f"no foreign key to {silo_model._meta.label}"
    return None, f"more than one foreign key to {silo_model._meta.label}"


def resolve_targets(adapter, models=None) -> Resolution:
    """Resolve how to find a silo's rows for every model holding encrypted data.

    *models* overrides the discovered
    ``(model, field_names, file_names, index_names)`` list, for callers that
    already hold one.
    """
    resolution = Resolution()
    silo_model = _silo_model(adapter)
    for model, field_names, file_names, index_names in encrypted_models() if models is None else models:
        fk, why = _silo_foreign_key(model, silo_model)
        if fk is not None:
            resolution.targets.append(Target(model, field_names, file_names, index_names, fk.name))
        elif getattr(adapter, "supports_silo_data_lookup", False):
            resolution.targets.append(Target(model, field_names, file_names, index_names, None))
        else:
            resolution.unresolved.append((model._meta.label, why))
    return resolution


def rows_for_silo(adapter, target: Target, silo_uid: str, silo=None):
    """Return the queryset of *target*'s rows that belong to *silo_uid*.

    Raises rather than returning an empty queryset when there is no path, so a
    silo that holds no data and a model nothing could resolve never look alike.
    """
    if target.fk_name:
        if silo is None:
            raise ValueError(f"{target.label} is filtered on {target.fk_name}, which needs the silo row")
        return target.model._base_manager.filter(**{target.fk_name: silo})
    return adapter.queryset_for_silo(target.model, silo_uid)
