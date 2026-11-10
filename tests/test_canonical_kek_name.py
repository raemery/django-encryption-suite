"""The canonical KEK name space shared by reconcile, ownership and the admin.

The strategy answers in identifier space (``KEK_TEMPLATE``) while some adapters
record a qualified resource name on the row. Everything that compares a resolved
name against a stored or KMS-listed one goes through
``AbstractKmsAdapter.canonical_kek_name``, so the two can never drift apart.
"""

from __future__ import annotations

import pytest

from encryption_suite.adapters.keks.strategies import PerSiloKekStrategy, SharedKekStrategy
from encryption_suite.adapters.key_stores.base import AbstractKmsAdapter, KmsMetadata
from encryption_suite.adapters.key_stores.gcp import GcpKmsAdapter
from encryption_suite.silo_ref import SiloRef

_RING = "projects/p/locations/us-central1/keyRings/r"
_GCP_OPTIONS = {
    "GCP_PROJECT_ID": "p",
    "GCP_KMS_LOCATION": "us-central1",
    "GCP_KMS_KEY_RING": "r",
    "KEK_TEMPLATE": "es-prod-{silo_uid}",
}


class _PlainAdapter(AbstractKmsAdapter):
    """An adapter that records the identifier verbatim, as AWS and Fly do."""

    kms_provider = "plain"

    def encrypt_key(self, plaintext, silo_uid):  # pragma: no cover - unused
        return b"", KmsMetadata(kek_resource_name="", kms_provider=self.kms_provider)

    def decrypt_key(self, ciphertext, metadata, silo_uid):  # pragma: no cover - unused
        return b""


def _adapter(cls, options, strategy_cls=PerSiloKekStrategy):
    return cls(options, cls.build_strategy(strategy_cls, options))


class TestDefault:
    def test_identifier_is_recorded_verbatim(self):
        adapter = _adapter(_PlainAdapter, {"KEK_TEMPLATE": "alias/es-prod-{silo_uid}"})

        assert adapter.canonical_kek_name("alias/es-prod-team-1") == "alias/es-prod-team-1"


class TestGcp:
    def test_bare_name_is_qualified_with_the_configured_ring(self):
        adapter = _adapter(GcpKmsAdapter, _GCP_OPTIONS)

        assert adapter.canonical_kek_name("es-prod-team-1") == f"{_RING}/cryptoKeys/es-prod-team-1"

    def test_a_full_path_passes_through(self):
        # KEK_MAP entries may already be full paths, which also makes this
        # idempotent.
        adapter = _adapter(GcpKmsAdapter, _GCP_OPTIONS)
        name = f"{_RING}/cryptoKeys/es-prod-team-1"

        assert adapter.canonical_kek_name(name) == name

    def test_matches_what_encrypt_records(self):
        # The point of the hook: a resolved name and a stored one are the same
        # string, so reconcile compares like with like.
        adapter = _adapter(GcpKmsAdapter, _GCP_OPTIONS)
        resolved = adapter.canonical_kek_name(adapter.kek_strategy.get_kek_id(SiloRef("default", "team-1")))

        assert resolved == adapter._kek_resource_name("es-prod-team-1")

    def test_the_owner_prefix_stays_a_prefix(self):
        # The same transform is applied to the owner prefix, so it has to remain
        # a prefix of every key name — the ownership gate is a startswith.
        adapter = _adapter(GcpKmsAdapter, _GCP_OPTIONS)
        prefix = adapter.canonical_kek_name(adapter.kek_strategy.owner_prefix())

        assert adapter.canonical_kek_name("es-prod-team-1").startswith(prefix)


def _with_gcp_block(settings, options, strategy):
    """The suite's settings with the default key set on a GCP block on *options* and *strategy*."""
    block = {
        "ADAPTER": "encryption_suite.adapters.key_stores.gcp.GcpKmsAdapter",
        "OPTIONS": options,
        "KEK_STRATEGY_ADAPTER": strategy,
    }
    return {
        **settings.ENCRYPTION,
        "KMS_KEY_STORES": {"gcp": block},
        "KEY_SETS": {
            "default": {**settings.ENCRYPTION["KEY_SETS"]["default"], "key_store": "gcp"},
            "system": {"key_store": "login"},
        },
    }


@pytest.mark.django_db
class TestAdapterResolvers:
    """Resolution lives on the adapter: it owns both halves of the mapping."""

    def test_resolve_kek_name_and_owner_prefix_agree(self, settings):
        from encryption_suite import registry

        settings.ENCRYPTION = _with_gcp_block(
            settings, _GCP_OPTIONS, "encryption_suite.adapters.keks.PerSiloKekStrategy"
        )
        registry.reset()
        try:
            adapter = registry.get_kms_adapter()
            name = adapter.resolve_kek_name(SiloRef("default", "team-1"))
            prefix = adapter.owner_prefix()
        finally:
            registry.reset()

        assert name == f"{_RING}/cryptoKeys/es-prod-team-1"
        assert prefix == f"{_RING}/cryptoKeys/es-prod-"
        assert name.startswith(prefix)

    def test_no_owner_prefix_without_a_template(self, settings):
        # A shared config derives no prefix, so ownership is unprovable and the
        # canonicalization must not invent one.
        from encryption_suite import registry

        settings.ENCRYPTION = _with_gcp_block(
            settings,
            {**_GCP_OPTIONS, "SHARED_KEK_ID": "es-prod-shared"},
            "encryption_suite.adapters.keks.SharedKekStrategy",
        )
        registry.reset()
        try:
            assert registry.get_kms_adapter().owner_prefix() is None
        finally:
            registry.reset()

    def test_shared_strategy_still_resolves_a_canonical_name(self):
        adapter = _adapter(GcpKmsAdapter, {**_GCP_OPTIONS, "SHARED_KEK_ID": "es-prod-shared"}, SharedKekStrategy)

        assert adapter.canonical_kek_name(adapter.kek_strategy.get_kek_id(SiloRef("default", "team-1"))) == (
            f"{_RING}/cryptoKeys/es-prod-shared"
        )
