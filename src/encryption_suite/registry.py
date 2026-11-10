"""
Singleton registry for adapter instances and the encryption engine.

Adapters are loaded once from settings and cached for the lifetime of the
process. Call ``reset()`` in tests when swapping adapter configurations.

The key store side is keyed by name — a ``KMS_KEY_STORES`` block or an
``ENV_KEY_STORES`` entry — and each name is built on first use and cached on its
own. A store that fails to construct is not cached and stops nothing else from
being built: a broken KMS must leave an env store working. Silo adapters are
keyed by their dotted path, so key sets bound to one adapter share one instance.
"""

from __future__ import annotations

import threading

from django.utils.module_loading import import_string

from ._logging import get_logger
from .conf import (
    DEFAULT_KEY_SET,
    SYSTEM_ADAPTER,
    adapter_path,
    enc_settings,
    key_set_names,
    kms_block,
    resolve_store,
    store_problem,
)
from .exceptions import log_and_raise_configuration_error

logger = get_logger(__name__)


def _import_adapter(setting_label: str, dotted_path):
    """Import the class named by an ENCRYPTION dotted-path setting.

    Wraps :func:`~django.utils.module_loading.import_string` so a bad or missing
    dotted path becomes a typed, logged
    :class:`~encryption_suite.exceptions.EncryptionConfigurationError` naming
    the exact setting — instead of a raw ``ImportError`` escaping as a 500 on the
    first encrypt/decrypt (the registry constructs adapters lazily, outside the
    engine's runtime error funnel). ``setting_label`` names where the path was
    read, e.g. ``ENCRYPTION['KMS_KEY_STORES']['fly']['ADAPTER']``, only to make the
    message actionable.
    """
    if not dotted_path:
        log_and_raise_configuration_error(logger, f"{setting_label} is required.")
    try:
        return import_string(dotted_path)
    except ImportError as exc:
        log_and_raise_configuration_error(
            logger,
            f"{setting_label} = {dotted_path!r} is not an importable dotted path: {exc}",
            cause=exc,
        )


def _block_label(name: str, key: str) -> str:
    return f"ENCRYPTION['KMS_KEY_STORES']['{name}']['{key}']"


def _kms_block(name: str) -> dict:
    """Return the block for named store *name*, raising a configuration error if there is none."""
    block = kms_block(name)
    if block is None:
        log_and_raise_configuration_error(
            logger,
            f"ENCRYPTION['KMS_KEY_STORES'] and ENCRYPTION['ENV_KEY_STORES'] have no store named {name!r}.",
        )
    return block


#: Every crypto backend the package ships, by the id a data key row records. A
#: row is read through the backend it names, so all of them are reachable, not
#: only the configured one. A backend whose optional dependency is missing fails
#: to construct, which reaches the caller as a configuration error.
SHIPPED_CRYPTO_BACKENDS = {
    "cryptography": "encryption_suite.adapters.crypto_backends.cryptography.CryptographyCryptoEngine",
    "tink": "encryption_suite.adapters.crypto_backends.tink.TinkCryptoEngine",
}


_silo_adapters: dict = {}
_kms_adapters: dict = {}
_kek_strategy_adapters: dict = {}
_kek_provisioners: dict = {}
_crypto_backend = None
_crypto_backends_by_id: dict = {}
_engine = None

# Protects lazy initialization of all singletons against concurrent first-use.
#
# Must be reentrant: get_kms_adapter() acquires the lock, then calls
# get_kek_strategy_adapter(), which reacquires it; a backend lookup by id may
# build the configured backend under the same lock. A non-reentrant Lock
# deadlocks the first caller whose entry point is the outer one in a fresh
# process — notably the migration path, where EncryptedField.get_prep_value
# encrypts a default value before any other adapter has been primed.
_registry_lock = threading.RLock()


def get_silo_adapter(key_set: str = DEFAULT_KEY_SET):
    """Return the silo adapter *key_set* is bound to, by default the ``default`` key set's.

    The ``system`` key set, and any entry whose ``silo`` is ``"system"``, gets the built-in
    :class:`~encryption_suite.adapters.silos.system.SystemSiloAdapter`. Key sets
    bound to one adapter share one instance.
    """
    path = adapter_path(key_set)
    if path is None:
        log_and_raise_configuration_error(
            logger, f"ENCRYPTION['KEY_SETS'][{key_set!r}] does not exist or names no 'silo'."
        )
    adapter = _silo_adapters.get(path)
    if adapter is not None:
        return adapter
    with _registry_lock:
        if path not in _silo_adapters:
            if path == SYSTEM_ADAPTER:
                from .adapters.silos.system import SystemSiloAdapter

                _silo_adapters[path] = SystemSiloAdapter()
            else:
                cls = _import_adapter(f"ENCRYPTION['KEY_SETS'][{key_set!r}]['silo']", path)
                _silo_adapters[path] = cls()

        return _silo_adapters[path]


def all_key_sets() -> list[str]:
    """Every key set: the project's own from ``KEY_SETS``, then ``system`` unless it is listed."""
    return key_set_names()


def silo_adapter_groups() -> list[tuple[object, list[str]]]:
    """Each distinct silo adapter with the key sets bound to it, in settings order.

    What a silo-level operation walks: a silo is one adapter's, whatever number of
    key sets it has keys in, so liveness is asked once per adapter.
    """
    groups: dict[str, list[str]] = {}
    for key_set in all_key_sets():
        path = adapter_path(key_set)
        if path is not None:
            groups.setdefault(path, []).append(key_set)
    return [(get_silo_adapter(members[0]), members) for members in groups.values()]


def silo_kms_name() -> str:
    """The named store new keys of the ``default`` key set are wrapped on."""
    return new_key_kms(DEFAULT_KEY_SET)


def new_key_kms(key_set: str = DEFAULT_KEY_SET) -> str:
    """The named store a new key in *key_set* is wrapped on.

    The one place that choice is made, so key creation, rotation and
    ``reencrypt_keys`` cannot disagree about it. Raises a configuration error
    when ``KEY_SETS`` resolves to no store.
    """
    name = resolve_store(key_set)
    if name is None:
        log_and_raise_configuration_error(logger, store_problem(key_set))
    return name


def get_kek_strategy_adapter(name: str | None = None):
    """Return the KEK strategy of named store *name*, by default the ``default`` key set's store."""
    name = name or silo_kms_name()
    strategy = _kek_strategy_adapters.get(name)
    if strategy is not None:
        return strategy
    with _registry_lock:
        if name not in _kek_strategy_adapters:
            block = _kms_block(name)
            kms_cls = _import_adapter(_block_label(name, "ADAPTER"), block["ADAPTER"])
            strategy_cls = _import_adapter(_block_label(name, "KEK_STRATEGY_ADAPTER"), block["KEK_STRATEGY_ADAPTER"])
            _kek_strategy_adapters[name] = kms_cls.build_strategy(strategy_cls, block["OPTIONS"] or {})

        return _kek_strategy_adapters[name]


def get_kek_provisioner(name: str | None = None):
    """Return the KEK provisioner of named store *name*, by default the ``default`` key set's store."""
    name = name or silo_kms_name()
    provisioner = _kek_provisioners.get(name)
    if provisioner is not None:
        return provisioner
    with _registry_lock:
        if name not in _kek_provisioners:
            block = _kms_block(name)
            cls = _import_adapter(_block_label(name, "KEK_PROVISIONER_ADAPTER"), block["KEK_PROVISIONER_ADAPTER"])
            _kek_provisioners[name] = cls(block["KEK_PROVISIONER_OPTIONS"] or {})

        return _kek_provisioners[name]


def get_kms_adapter(name: str | None = None):
    """Return the adapter of named store *name*, by default the ``default`` key set's store.

    The adapter carries the name it was built under as ``kms_name``, which is
    what a key encryption key row it wraps for records.
    """
    name = name or silo_kms_name()
    adapter = _kms_adapters.get(name)
    if adapter is not None:
        return adapter
    with _registry_lock:
        if name not in _kms_adapters:
            block = _kms_block(name)
            cls = _import_adapter(_block_label(name, "ADAPTER"), block["ADAPTER"])
            adapter = cls(block["OPTIONS"] or {}, get_kek_strategy_adapter(name))
            adapter.kms_name = name
            _kms_adapters[name] = adapter

        return _kms_adapters[name]


def get_crypto_backend():
    """Return the configured crypto backend, which makes every new data key."""
    global _crypto_backend
    if _crypto_backend is not None:
        return _crypto_backend
    with _registry_lock:
        if _crypto_backend is None:
            cls = _import_adapter("ENCRYPTION['CRYPTO_BACKEND']", enc_settings.CRYPTO_BACKEND)
            _crypto_backend = cls(enc_settings.CRYPTO_BACKEND_OPTIONS)

        return _crypto_backend


def get_crypto_backend_by_id(backend_id: str):
    """Return the backend that reads a data key recorded as *backend_id*, or ``None``.

    The configured backend answers for its own id, with its options. Any other
    shipped backend is built with no options: loading a key needs none, since
    each key records its own algorithm, and writes under such a key use the
    backend's defaults until ``reencrypt_data`` moves the silo onto the
    configured one. ``None`` means no backend this installation can build has
    that id.
    """
    configured = get_crypto_backend()
    if backend_id == configured.backend_id:
        return configured
    backend = _crypto_backends_by_id.get(backend_id)
    if backend is not None:
        return backend
    dotted_path = SHIPPED_CRYPTO_BACKENDS.get(backend_id)
    if dotted_path is None:
        return None
    with _registry_lock:
        if backend_id not in _crypto_backends_by_id:
            cls = _import_adapter(f"crypto backend {backend_id!r}", dotted_path)
            _crypto_backends_by_id[backend_id] = cls({})

        return _crypto_backends_by_id[backend_id]


def get_engine() -> EncryptionEngine:  # noqa: F821
    global _engine
    if _engine is not None:
        return _engine
    with _registry_lock:
        if _engine is None:
            from .engine import EncryptionEngine

            _engine = EncryptionEngine(crypto_backend=get_crypto_backend())
        return _engine


def reset() -> None:
    """Drop every cached adapter and the engine, so the next call rebuilds them.

    Used by tests that swap adapter configurations, and by the deploy-time system
    check that constructs the adapters to validate them — it resets afterwards so
    the check leaves no singleton built from check-time settings behind.
    """
    global _crypto_backend, _engine
    with _registry_lock:
        _crypto_backend = _engine = None
        _silo_adapters.clear()
        _kms_adapters.clear()
        _kek_strategy_adapters.clear()
        _kek_provisioners.clear()
        _crypto_backends_by_id.clear()
    enc_settings.reset()
