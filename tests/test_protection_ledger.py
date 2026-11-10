"""What protects a data key, on the row and on each of its ledger events.

The row records the algorithm its keyset was generated for, taken from the
backend that generated it. Each data key event snapshots the protection state
after the act — KEK, KMS, KEK version, backend, algorithm — so the chain of
events shows every move between them. A KEK's events record only its version.
"""

from __future__ import annotations

from io import StringIO

import pytest
from django.core.management import call_command

from encryption_suite import lifecycle, registry, rotation
from encryption_suite.conf import SYSTEM_SILO_UID
from encryption_suite.contrib.simpleteams.models import SimpleTeam
from encryption_suite.engine import EncryptionEngine
from encryption_suite.models import DataEncryptionKey, KeyLifecycleEvent
from tests.key_set_settings import key_sets
from tests.rotation_helpers import dek, make_document, make_note, make_team, run

pytestmark = pytest.mark.django_db

_PYCA = "encryption_suite.adapters.crypto_backends.cryptography.CryptographyCryptoEngine"
_PROTECTION = ("wrapping_kek_id", "key_store", "kek_key_version", "crypto_backend", "algorithm")


@pytest.fixture(autouse=True)
def _no_wait(monkeypatch):
    monkeypatch.setattr(rotation, "_sleep", lambda seconds: None)
    EncryptionEngine.invalidate_cache()
    yield
    EncryptionEngine.invalidate_cache()


def _configure(settings, **changes):
    settings.ENCRYPTION = {**settings.ENCRYPTION, **changes}
    registry.reset()
    EncryptionEngine.invalidate_cache()


def _events(row, event):
    return list(KeyLifecycleEvent.objects.filter(dek=row, event=event).order_by("created_at", "pk"))


def _reencrypt_keys(*args) -> str:
    out = StringIO()
    call_command("reencrypt_keys", *args, stdout=out, stderr=StringIO())
    return out.getvalue()


# ---------------------------------------------------------------------------
# Part 2: the algorithm on the row
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("backend", "options", "field", "file"),
    [
        ("tink", {}, "AES256_GCM", "AES256_GCM_HKDF_4KB"),
        (
            "tink",
            {"AEAD_KEY_TEMPLATE": "AES256_EAX", "STREAMING_AEAD_KEY_TEMPLATE": "AES256_GCM_HKDF_1MB"},
            "AES256_EAX",
            "AES256_GCM_HKDF_1MB",
        ),
        ("cryptography", {}, "AES256_GCM", "AES256_GCM_STREAM"),
        ("cryptography", {"AEAD": "CHACHA20_POLY1305"}, "CHACHA20_POLY1305", "CHACHA20_POLY1305_STREAM"),
    ],
)
def test_each_backend_and_purpose_records_its_algorithm(settings, backend, options, field, file):
    path = _PYCA if backend == "cryptography" else settings.ENCRYPTION["CRYPTO_BACKEND"]
    _configure(settings, CRYPTO_BACKEND=path, CRYPTO_BACKEND_OPTIONS=options)
    team = make_team()
    make_note(team)
    make_document(team)

    assert (dek(team).crypto_backend, dek(team).algorithm) == (backend, field)
    assert dek(team, DataEncryptionKey.PURPOSE_FILE).algorithm == file


def test_a_blind_index_key_records_hmac_without_a_backend():
    SimpleTeam.objects.create(name="Acme")

    index = DataEncryptionKey.objects.get(silo_uid=SYSTEM_SILO_UID, purpose=DataEncryptionKey.PURPOSE_INDEX)
    assert (index.crypto_backend, index.algorithm) == ("", "HMAC_SHA256")


def test_an_unknown_purpose_has_no_algorithm():
    with pytest.raises(ValueError):
        registry.get_crypto_backend().algorithm_id("index")


def test_a_rotation_that_switches_backend_leaves_the_new_algorithm(settings):
    team = make_team()
    make_note(team)
    _configure(settings, CRYPTO_BACKEND=_PYCA, CRYPTO_BACKEND_OPTIONS={"AEAD": "AES256_GCM_SIV"})

    run("--silo-uid", f"group-{team.pk}", "--purpose", "field")

    assert (dek(team).crypto_backend, dek(team).algorithm) == ("cryptography", "AES256_GCM_SIV")


# ---------------------------------------------------------------------------
# Part 1: the protection state on each event
# ---------------------------------------------------------------------------


def test_the_created_event_records_the_protection_state():
    team = make_team()
    make_note(team)
    row = dek(team)

    (created,) = _events(row, lifecycle.EVENT_CREATED)
    assert created.wrapping_kek_id == row.kek_id
    assert (created.key_store, created.crypto_backend, created.algorithm) == ("local", "tink", "AES256_GCM")


def test_a_cross_kms_reencryption_records_the_new_kms_and_keeps_the_old_one_on_created(settings):
    team = make_team()
    make_note(team)
    old_kek = dek(team).kek
    blocks = dict(settings.ENCRYPTION["KMS_KEY_STORES"])
    blocks["other"] = {**blocks["local"], "OPTIONS": {"SHARED_KEK_ID": "other-test-kek"}}
    _configure(settings, KMS_KEY_STORES=blocks, KEY_SETS=key_sets(default="other"))

    _reencrypt_keys()

    row = dek(team)
    (created,) = _events(row, lifecycle.EVENT_CREATED)
    (reencrypted,) = _events(row, lifecycle.EVENT_REENCRYPTED)
    assert (created.wrapping_kek_id, created.key_store) == (old_kek.pk, "local")
    assert (reencrypted.wrapping_kek_id, reencrypted.key_store) == (row.kek_id, "other")
    assert reencrypted.wrapping_kek.kek_resource_name == "other-test-kek"


def test_a_backend_switch_records_the_new_backend_and_algorithm_on_rotated(settings):
    team = make_team()
    make_note(team)
    _configure(settings, CRYPTO_BACKEND=_PYCA, CRYPTO_BACKEND_OPTIONS={})

    run("--silo-uid", f"group-{team.pk}", "--purpose", "field")

    row = dek(team)
    (created,) = _events(row, lifecycle.EVENT_CREATED)
    (rotated,) = _events(row, lifecycle.EVENT_ROTATED)
    assert (created.crypto_backend, created.algorithm) == ("tink", "AES256_GCM")
    assert (rotated.crypto_backend, rotated.algorithm) == ("cryptography", "AES256_GCM")


def test_a_system_kek_rotation_records_the_new_version(settings):
    import base64

    SimpleTeam.objects.create(name="Acme")
    versions = {**settings.ENCRYPTION["ENV_KEY_STORES"]["login"]["KEKS"], 2: base64.b64encode(b"\x01" * 32).decode()}
    _configure(settings, ENV_KEY_STORES={"login": {"KEKS": versions}})

    _reencrypt_keys("--key-set", "system")

    row = DataEncryptionKey.objects.get(silo_uid=SYSTEM_SILO_UID, purpose=DataEncryptionKey.PURPOSE_FIELD)
    (created,) = _events(row, lifecycle.EVENT_CREATED)
    (reencrypted,) = _events(row, lifecycle.EVENT_REENCRYPTED)
    assert (created.key_store, created.kek_key_version) == ("login", "1")
    assert (reencrypted.key_store, reencrypted.kek_key_version) == ("login", "2")


def test_kek_events_record_only_the_kek_version():
    team = make_team()
    make_note(team)
    kek = dek(team).kek
    kek.kek_key_version = "7"
    kek.save(update_fields=["kek_key_version"])
    kek.record_event(lifecycle.EVENT_SILO_NOT_FOUND, trigger=lifecycle.TRIGGER_AUTOMATED)

    kek_events = KeyLifecycleEvent.objects.filter(kek=kek)
    assert kek_events.exists()
    for event in kek_events:
        assert event.wrapping_kek_id is None
        assert all(getattr(event, name) == "" for name in ("key_store", "crypto_backend", "algorithm"))
    assert kek_events.latest("created_at", "pk").kek_key_version == "7"


def test_an_observed_kek_rotation_records_the_new_version_and_keeps_the_old_one():
    from encryption_suite.reconcile_service import _sync_kek_versions

    team = make_team()
    make_note(team)
    kek = dek(team).kek
    kek.kek_key_version = "1"
    kek.save(update_fields=["kek_key_version"])
    kek.record_event(lifecycle.EVENT_SILO_NOT_FOUND, trigger=lifecycle.TRIGGER_AUTOMATED)

    rotated, _ = _sync_kek_versions(
        None,
        key_store=kek.key_store,
        uid_by_kek_name={},
        current_versions={kek.kek_resource_name: "2"},
        probe_failures=set(),
        orphan_names=set(),
    )

    assert rotated == [kek.kek_resource_name]
    before = KeyLifecycleEvent.objects.get(kek=kek, event=lifecycle.EVENT_SILO_NOT_FOUND)
    (after,) = KeyLifecycleEvent.objects.filter(kek=kek, event=lifecycle.EVENT_ROTATED)
    assert (before.kek_key_version, after.kek_key_version) == ("1", "2")
