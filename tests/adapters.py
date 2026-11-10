"""Minimal silo adapter for the test suite."""

from __future__ import annotations

from encryption_suite.adapters.key_stores.environment import EnvKeyStoreAdapter
from encryption_suite.adapters.silos.context import ContextSiloAdapter


class TestSiloAdapter(ContextSiloAdapter):
    """Context-driven adapter with a trivial UID scheme.

    Silos are plain objects with an ``id`` attribute; the UID is
    ``test:<id>``. Used only to satisfy the engine's adapter contract during
    tests — no real tenant resolution happens here.
    """

    def get_silo_uid(self, silo) -> str:
        return f"test:{silo.id}"

    def get_silo_label(self) -> str:
        return "test"


class UnversionedTestKmsAdapter(EnvKeyStoreAdapter):
    """A stand-in for an unversioned provider: the suite's silo KMS block.

    Configured as the ``"local"`` KMS block rather than an env store, so the
    suite's scoped keys take the route every real KMS takes, wrapped with the env
    adapter's AES-256-GCM under the suite's ``login`` env store material.

    Reports no current version, as most providers do, so ``reencrypt_keys``
    re-wraps every row rather than skipping the ones already on version 1. The
    versioned behavior is the system adapter's own, tested on it directly.
    """

    kms_provider = "local"

    def __init__(self, options: dict, kek_strategy) -> None:
        from django.conf import settings

        keks = settings.ENCRYPTION["ENV_KEY_STORES"]["login"]["KEKS"]
        super().__init__({**options, "KEKS": keks}, kek_strategy)

    def current_kek_version(self, silo_ref) -> str:
        return ""


class FakeKmsAdapterBase:
    """Name-resolution surface shared by the suite's fake KMS adapters.

    Mirrors :class:`~encryption_suite.adapters.key_stores.base.AbstractKmsAdapter` for
    the parts the lifecycle code calls — identifiers in, canonical names out —
    without the credential and crypto machinery a fake has no use for. Subclasses
    set ``kms_provider`` and override ``canonical_kek_name`` where the test needs
    a name space that differs from the identifier space. The fake's KMS name is
    its provider id, which is how the suite configures its blocks (see the
    ``configured_kms`` fixture).

    The strategy is read from the registry rather than held, because these fakes
    are installed by patching the registry's getters, and the tests vary the
    strategy independently of the adapter.
    """

    kms_provider = "fake"

    @property
    def kms_name(self):
        return self.kms_provider

    def canonical_kek_name(self, kek_id):
        return kek_id

    def resolve_kek_name(self, silo_ref):
        from encryption_suite.registry import get_kek_strategy_adapter

        return self.canonical_kek_name(get_kek_strategy_adapter().get_kek_id(silo_ref))

    def owner_prefix(self):
        from encryption_suite.registry import get_kek_strategy_adapter

        prefix = get_kek_strategy_adapter().owner_prefix()
        return self.canonical_kek_name(prefix) if prefix else None

    def mapped_kek_names(self):
        from encryption_suite.registry import get_kek_strategy_adapter

        strategy = get_kek_strategy_adapter()
        names = strategy.mapped_kek_names() if hasattr(strategy, "mapped_kek_names") else ()
        return frozenset(self.canonical_kek_name(name) for name in names)

    def owned_mapped_kek_names(self):
        from encryption_suite.registry import get_kek_strategy_adapter

        strategy = get_kek_strategy_adapter()
        names = strategy.owned_mapped_kek_names() if hasattr(strategy, "owned_mapped_kek_names") else ()
        return frozenset(self.canonical_kek_name(name) for name in names)

    def dek_pointer_filter(self, kek_resource_name):
        from django.db.models import Q

        return Q(kek_resource_name=kek_resource_name)
