"""``reencrypt_keys --provision``: the name-rollover half of the command.

Providers that cannot rotate key material behind a stable name rotate by
rollover instead — ``KEK_TEMPLATE`` is pointed at a new generation and every DEK
moves onto the new key. That needs the new key to exist first, which the plain
command never does: it drives the KMS adapter directly, so the provisioner is not
in its path at all.

The guard that matters here is the owner prefix. It is the literal text before
``{silo_uid}``, and it is what proves a key belongs to this deployment — so it
decides what reconcile enumerates and what the deletion gates authorize. A
rollover that moves it strands the generation being rolled off: still on the
provider, still billable, no longer listed and no longer deletable from the
admin. ``--provision`` is the last moment that is free to abort, because nothing
has been created yet.
"""

from __future__ import annotations

from contextlib import contextmanager
from io import StringIO

import pytest
from django.contrib.auth.models import Group
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import override_settings

from encryption_suite import lifecycle, registry
from encryption_suite.adapters.keks import NullKekProvisioner
from encryption_suite.engine import EncryptionEngine
from encryption_suite.models import DataEncryptionKey
from encryption_suite.registry import get_engine


class RecordingProvisioner(NullKekProvisioner):
    """Creates nothing, but records what it was asked to ensure.

    Subclasses the null provisioner so ownership and the deletion capabilities
    keep their shipped defaults — the only added behavior is the call log.
    """

    calls: list[str] = []

    def ensure_kek(self, kek_resource_name: str, silo_ref) -> bool:
        RecordingProvisioner.calls.append(kek_resource_name)
        return True


@pytest.fixture(autouse=True)
def _clean_state():
    RecordingProvisioner.calls = []
    EncryptionEngine.invalidate_cache()
    yield
    EncryptionEngine.invalidate_cache()


@contextmanager
def _template(template: str):
    """Run the silo KMS block with ``PerSiloKekStrategy`` on *template*, rebuilding the registry."""
    from django.conf import settings

    silo_kms = "local"
    block = {
        **settings.ENCRYPTION["KMS_KEY_STORES"][silo_kms],
        "KEK_STRATEGY_ADAPTER": "encryption_suite.adapters.keks.PerSiloKekStrategy",
        "KEK_PROVISIONER_ADAPTER": "tests.test_reencrypt_provision.RecordingProvisioner",
        "OPTIONS": {"KEK_TEMPLATE": template},
    }
    encryption = {**settings.ENCRYPTION, "KMS_KEY_STORES": {silo_kms: block}}
    with override_settings(ENCRYPTION=encryption):
        registry.reset()
        try:
            yield
        finally:
            registry.reset()


def _uid(silo):
    return get_engine().silo_adapter.get_silo_uid(silo)


def _make_dek(name: str = "acme") -> DataEncryptionKey:
    """Create a silo and its field DEK, then forget the setup's ensure calls.

    Creating a keyset provisions through the engine, so the log would otherwise
    open every test with a call none of them are about.
    """
    group = Group.objects.create(name=name)
    get_engine().generate_and_store_keyset(group)
    RecordingProvisioner.calls = []
    return DataEncryptionKey.objects.get(silo_uid=_uid(group))


def _run(*args) -> str:
    out, err = StringIO(), StringIO()
    call_command("reencrypt_keys", *args, stdout=out, stderr=err)
    return out.getvalue() + err.getvalue()


@pytest.mark.django_db
class TestOwnerPrefixGuard:
    def test_a_moved_prefix_refuses_the_run(self):
        with _template("kms_{silo_uid}"):
            dek = _make_dek()

        with _template("kms_v2_{silo_uid}"):
            with pytest.raises(CommandError) as exc:
                _run("--provision")

        assert "kms_v2_" in str(exc.value)
        assert "{silo_uid}" in str(exc.value)
        # Nothing was created, which is what makes reverting the template a
        # complete undo.
        assert RecordingProvisioner.calls == []
        dek.refresh_from_db()
        assert dek.reencryption_count == 1

    def test_a_moved_prefix_refuses_a_dry_run_too(self):
        with _template("kms_{silo_uid}"):
            _make_dek()

        with _template("kms_v2_{silo_uid}"):
            with pytest.raises(CommandError):
                _run("--provision", "--dry-run")

    def test_a_suffix_generation_is_allowed(self):
        with _template("kms_{silo_uid}"):
            dek = _make_dek()

        with _template("kms_{silo_uid}_v2"):
            output = _run("--provision")

        assert "Provisioned: kms_" in output
        assert RecordingProvisioner.calls == [f"kms_{dek.silo_uid}_v2"]
        dek.refresh_from_db()
        assert dek.kek.kek_resource_name == f"kms_{dek.silo_uid}_v2"
        assert dek.reencryption_count == 2

    def test_the_guard_does_not_run_without_provision(self):
        # A plain rewrap cannot strand anything: the new key does not exist, so
        # every wrap fails loudly rather than silently completing a one-way move.
        with _template("kms_{silo_uid}"):
            _make_dek()

        with _template("kms_v2_{silo_uid}"):
            _run("--dry-run")  # no CommandError


@pytest.mark.django_db
class TestProvisioning:
    def test_an_unchanged_name_provisions_nothing(self):
        with _template("kms_{silo_uid}"):
            dek = _make_dek()
            output = _run("--provision")

        assert RecordingProvisioner.calls == []
        assert "Provisioned:" not in output
        dek.refresh_from_db()
        assert dek.reencryption_count == 2

    def test_one_silo_is_ensured_once_across_its_purposes(self):
        with _template("kms_{silo_uid}"):
            group = Group.objects.create(name="acme")
            engine = get_engine()
            engine.generate_and_store_keyset(group)
            engine.generate_and_store_file_keyset(group)
            RecordingProvisioner.calls = []

        assert DataEncryptionKey.objects.filter(silo_uid=_uid(group)).count() == 2

        with _template("kms_{silo_uid}_v2"):
            _run("--provision")

        # Both rows resolve to the one key, so the second must not repeat the call.
        assert RecordingProvisioner.calls == [f"kms_{_uid(group)}_v2"]

    def test_a_provisioned_key_is_recorded_as_provisioned(self):
        # The row and its first ledger event both state provenance, and a key the
        # provisioner just generated must not read as one found already in the
        # KMS — the distinction is what tells an operator whether the deployment
        # made a key or inherited it.
        from encryption_suite.models import KeyEncryptionKey

        with _template("kms_{silo_uid}"):
            dek = _make_dek()

        with _template("kms_{silo_uid}_v2"):
            _run("--provision")

        kek = KeyEncryptionKey.objects.get(kek_resource_name=f"kms_{dek.silo_uid}_v2")
        # A set, not a list: both events land in the same instant and the ledger
        # orders by timestamp, so their relative order is not deterministic.
        assert {e.event for e in kek.events.all()} == {lifecycle.EVENT_CREATED, lifecycle.EVENT_SILO_FOUND}

    def test_dry_run_names_the_keys_and_creates_none(self):
        with _template("kms_{silo_uid}"):
            dek = _make_dek()

        with _template("kms_{silo_uid}_v2"):
            output = _run("--provision", "--dry-run")

        assert f"[dry-run] Would provision: kms_{dek.silo_uid}_v2" in output
        assert RecordingProvisioner.calls == []
        dek.refresh_from_db()
        assert dek.reencryption_count == 1
