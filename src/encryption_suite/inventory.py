"""
The cryptographic inventory: which key stores, keys, cryptographic engines and algorithms are in use.

A point-in-time account of what this deployment knows, for the record an
assessor asks for — the cryptographic architecture with its algorithms and keys,
and an inventory of them reviewed periodically. :func:`build_inventory` reads
settings and key rows only. It makes no KMS call, so it is cheap and safe to run
anywhere; what a KMS itself holds is reconcile's question, not this one's.

It reports counts and identifiers only: never key material, never a wrapped
keyset, never a silo UID. The ``crypto_inventory`` command renders it as text or
JSON, and the admin page renders the same dataclasses.

Rows the inventory leaves out: the admin test console's keys (``PURPOSE_TEST``),
which protect no data, and deleted data keys, whose material is gone. Key
encryption keys are counted in every status, since a deleted one is still a fact
about the KMS.
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass
from datetime import datetime

from django.db.models import Count, Min, Q
from django.utils import timezone

from . import conf, lifecycle
from .exceptions import EncryptionError


@dataclass(frozen=True)
class KeyStoreEntry:
    """One key store: a configured ``KMS_KEY_STORES`` block, ``system``, or a name only rows record."""

    key_store: str
    #: ``False`` for a name key rows record but no block configures.
    configured: bool
    #: The dotted path of the KMS adapter; blank when the key store is not configured.
    kms_adapter: str
    kek_strategy: str
    key_encryption_key_count: int
    data_encryption_key_count: int
    #: When the oldest active key encryption key row on this key store was created.
    oldest_active_kek_at: datetime | None


@dataclass(frozen=True)
class KekGroup:
    key_store: str
    status: str
    count: int


@dataclass(frozen=True)
class DataKeyGroup:
    key_set: str
    #: ``False`` when ``KEY_SETS`` gives this key set no store: a set retired
    #: or renamed in settings while keys exist under it, which no deploy check can see.
    in_settings: bool
    purpose: str
    cryptographic_engine: str
    algorithm: str
    key_store: str
    count: int
    #: The oldest ``key_material_last_generated_at`` in the group.
    oldest_key_material_at: datetime | None
    #: Keys whose material is older than ``DEK_ROTATION_PERIOD_DAYS``; ``None``
    #: when no period is declared.
    older_than_rotation_period: int | None


@dataclass(frozen=True)
class KeyStoreChoice:
    """The store a new key of one key set is wrapped on."""

    key_set: str
    #: Blank when ``KEY_SETS`` gives this key set no store.
    key_store: str
    #: The dotted path of the silo adapter the key set is bound to; blank when it has none.
    silo_adapter: str = ""


@dataclass(frozen=True)
class ConfiguredForNewDataKeys:
    """What a data key generated now gets, so the inventory shows where existing keys lag."""

    cryptographic_engine: str
    #: The engine's own ``describe_config`` rows.
    options: tuple[tuple[str, str], ...]
    #: ``(purpose, algorithm)`` for field, file and index keys.
    algorithms: tuple[tuple[str, str], ...]
    #: The error code when the configured engine cannot be built; blank otherwise.
    error_code: str = ""


@dataclass(frozen=True)
class Inventory:
    """The sections, in the order the admin page and the command show them."""

    generated_at: datetime
    rotation_period_days: int | None
    key_stores: tuple[KeyStoreEntry, ...]
    key_encryption_keys: tuple[KekGroup, ...]
    #: The store and silo adapter each key set gives a new key encryption key.
    configured_for_new_key_encryption_keys: tuple[KeyStoreChoice, ...]
    data_encryption_keys: tuple[DataKeyGroup, ...]
    configured_for_new_data_encryption_keys: ConfiguredForNewDataKeys

    def as_dict(self) -> dict:
        """The inventory as JSON-ready data, dates in ISO 8601."""
        return _jsonable(dataclasses.asdict(self))


def _jsonable(value):
    if isinstance(value, dict):
        return {key: _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    if isinstance(value, datetime):
        return value.isoformat()
    return value


def build_inventory() -> Inventory:
    """Read settings and key rows into an :class:`Inventory`. Read-only; no KMS calls."""
    from .reconcile_service import _overdue_material_cutoff, _period_days

    return Inventory(
        generated_at=timezone.now(),
        rotation_period_days=_period_days(conf.enc_settings.DEK_ROTATION_PERIOD_DAYS),
        key_stores=_key_store_entries(),
        key_encryption_keys=_kek_groups(),
        configured_for_new_key_encryption_keys=_key_stores_for_new_keys(),
        data_encryption_keys=_data_key_groups(_overdue_material_cutoff()),
        configured_for_new_data_encryption_keys=_configured_for_new_data_keys(),
    )


def _live_data_keys():
    from .deletion import LIVE_DEK_STATUSES
    from .models import DataEncryptionKey

    return DataEncryptionKey.objects.exclude(purpose=DataEncryptionKey.PURPOSE_TEST).filter(
        status__in=LIVE_DEK_STATUSES
    )


def _key_store_entries() -> tuple[KeyStoreEntry, ...]:
    from .models import KeyEncryptionKey

    kek_counts = dict(KeyEncryptionKey.objects.values_list("key_store").annotate(n=Count("pk")).order_by())
    oldest_kek = dict(
        KeyEncryptionKey.objects.filter(status=lifecycle.STATUS_ACTIVE)
        .values_list("key_store")
        .annotate(oldest=Min("created_at"))
        .order_by()
    )
    dek_counts = dict(_live_data_keys().values_list("kek__key_store").annotate(n=Count("pk")).order_by())

    configured = conf.kms_names()
    recorded = sorted((set(kek_counts) | set(dek_counts)) - set(configured))
    entries = []
    for name in [*configured, *recorded]:
        block = conf.kms_block(name) or {}
        adapter = block.get("ADAPTER") or ""
        entries.append(
            KeyStoreEntry(
                key_store=name,
                configured=bool(block),
                kms_adapter=adapter,
                kek_strategy=block.get("KEK_STRATEGY_ADAPTER") or "",
                key_encryption_key_count=kek_counts.get(name, 0),
                data_encryption_key_count=dek_counts.get(name, 0),
                oldest_active_kek_at=oldest_kek.get(name),
            )
        )
    return tuple(entries)


def _kek_groups() -> tuple[KekGroup, ...]:
    from .models import KeyEncryptionKey

    rows = (
        KeyEncryptionKey.objects.values("key_store", "status").annotate(n=Count("pk")).order_by("key_store", "status")
    )
    return tuple(KekGroup(key_store=row["key_store"], status=row["status"], count=row["n"]) for row in rows)


def _data_key_groups(cutoff) -> tuple[DataKeyGroup, ...]:
    annotations = {"n": Count("pk"), "oldest": Min("key_material_last_generated_at")}
    if cutoff is not None:
        annotations["overdue"] = Count("pk", filter=Q(key_material_last_generated_at__lt=cutoff))
    fields = ("key_set", "purpose", "crypto_backend", "algorithm", "kek__key_store")
    rows = _live_data_keys().values(*fields).annotate(**annotations).order_by(*fields)
    return tuple(
        DataKeyGroup(
            key_set=row["key_set"],
            in_settings=conf.resolve_store(row["key_set"]) is not None,
            purpose=row["purpose"],
            cryptographic_engine=row["crypto_backend"],
            algorithm=row["algorithm"],
            key_store=row["kek__key_store"],
            count=row["n"],
            oldest_key_material_at=row["oldest"],
            older_than_rotation_period=row.get("overdue"),
        )
        for row in rows
    )


def _configured_for_new_data_keys() -> ConfiguredForNewDataKeys:
    from .blind_index import INDEX_ALGORITHM
    from .models import DataEncryptionKey
    from .registry import get_crypto_backend

    index = (DataEncryptionKey.PURPOSE_INDEX, INDEX_ALGORITHM)
    try:
        backend = get_crypto_backend()
    except EncryptionError as exc:
        # Construction already logged the detail. The inventory still reports
        # everything else, and says which part it could not answer.
        return ConfiguredForNewDataKeys(cryptographic_engine="", options=(), algorithms=(index,), error_code=exc.code)
    return ConfiguredForNewDataKeys(
        cryptographic_engine=backend.backend_id,
        options=tuple(backend.describe_config()),
        algorithms=(
            (DataEncryptionKey.PURPOSE_FIELD, backend.algorithm_id(DataEncryptionKey.PURPOSE_FIELD)),
            (DataEncryptionKey.PURPOSE_FILE, backend.algorithm_id(DataEncryptionKey.PURPOSE_FILE)),
            index,
        ),
    )


#: The purpose each ``describe_config()`` option belongs to; an option not named here applies to every purpose.
_OPTION_PURPOSE = {"segment_size": "file", "field_aead": "field", "file_streaming_aead": "file"}


def engine_table(configured: ConfiguredForNewDataKeys) -> tuple[list[str], list[dict]]:
    """``(option_keys, rows)`` for the engine and algorithm each purpose gets now.

    One row per purpose, with the engine, the algorithm, and a value for each of
    *option_keys*. An option whose value is one of the algorithms is left out,
    since the algorithm already says it; each one left shows on the purpose it
    belongs to and is blank on the others. The page and the command both render
    this, each naming the option keys in its own words.
    """
    from .models import DataEncryptionKey

    algorithm_values = {algorithm for _purpose, algorithm in configured.algorithms}
    extras = [(key, value) for key, value in configured.options if value not in algorithm_values]
    rows = [
        {
            "purpose": purpose,
            # The index key's algorithm is not the engine's.
            "engine": "" if purpose == DataEncryptionKey.PURPOSE_INDEX else configured.cryptographic_engine,
            "algorithm": algorithm,
            "extras": [value if _OPTION_PURPOSE.get(key, purpose) == purpose else "" for key, value in extras],
        }
        for purpose, algorithm in configured.algorithms
    ]
    if configured.error_code:
        # The engine could not be built, so only its error can be said.
        rows.insert(0, {"purpose": "", "engine": f"[{configured.error_code}]", "algorithm": "", "extras": []})
    return [key for key, _value in extras], rows


def _key_stores_for_new_keys() -> tuple[KeyStoreChoice, ...]:
    """The store of every key set, whether ``KEY_SETS`` names it or a field declares it."""
    from .rotation_targets import key_sets_in_use

    return tuple(
        KeyStoreChoice(key_set, conf.resolve_store(key_set) or "", _silo_adapter_path(key_set))
        for key_set in sorted({*conf.key_set_names(), *key_sets_in_use()})
    )


def _silo_adapter_path(key_set: str) -> str:
    """The dotted path of *key_set*'s silo adapter, the system adapter's included, or ``""`` when it has none.

    The system key set is bound to a short sentinel in settings; the inventory
    names the class, like every other adapter in the listing.
    """
    path = conf.adapter_path(key_set) or ""
    if path == conf.SYSTEM_ADAPTER:
        from .adapters.silos.system import SystemSiloAdapter

        return f"{SystemSiloAdapter.__module__}.{SystemSiloAdapter.__qualname__}"
    return path
