"""reencrypt_data --only-outdated: rotate only the keys another backend or algorithm made.

A data key is outdated when the backend or algorithm its row recorded differs
from what CRYPTO_BACKEND and its options generate now for its purpose, or when
the row recorded no algorithm. The dry run, the ``Converting:`` line and the
opening log line name each such move the same way.
"""

from __future__ import annotations

import pytest
from django.core.management.base import CommandError

from encryption_suite import registry, rotation
from encryption_suite.engine import EncryptionEngine
from encryption_suite.models import DataEncryptionKey
from tests.rotation_helpers import dek, make_note, make_team, read_note, run, uid

pytestmark = pytest.mark.django_db

_PYCA = "encryption_suite.adapters.crypto_backends.cryptography.CryptographyCryptoEngine"


@pytest.fixture(autouse=True)
def _no_wait(monkeypatch):
    monkeypatch.setattr(rotation, "_sleep", lambda seconds: None)
    EncryptionEngine.invalidate_cache()
    yield
    EncryptionEngine.invalidate_cache()


def _configure(settings, **values):
    settings.ENCRYPTION = {**settings.ENCRYPTION, **values}
    registry.reset()
    EncryptionEngine.invalidate_cache()


def test_a_current_key_is_skipped_and_an_outdated_one_rotated(settings):
    old = make_team("old")
    note = make_note(old, title="t", body="b")
    _configure(settings, CRYPTO_BACKEND_OPTIONS={"AEAD_KEY_TEMPLATE": "AES128_GCM"})
    new = make_team("new")
    make_note(new)
    assert dek(new).algorithm == "AES128_GCM"
    writes = dek(new).reencryption_count

    current = run("--silo-uid", uid(new), "--purpose", "field", "--only-outdated")
    rotated = run("--silo-uid", uid(old), "--purpose", "field", "--only-outdated")

    assert f"Current: default:{uid(new)} [field] — backend tink, algorithm AES128_GCM" in current
    assert "Rotated:" not in current
    assert dek(new).reencryption_count == writes
    assert f"Rotated: default:{uid(old)} [field]" in rotated
    assert dek(old).algorithm == "AES128_GCM"
    assert read_note(note.pk, old) == ("t", "b")


def test_a_key_with_no_recorded_algorithm_is_outdated():
    team = make_team()
    make_note(team)
    DataEncryptionKey.objects.filter(pk=dek(team).pk).update(algorithm="")

    preview = run("--silo-uid", uid(team), "--purpose", "field", "--only-outdated", "--dry-run")
    run("--silo-uid", uid(team), "--purpose", "field", "--only-outdated")

    assert "(algorithm unrecorded -> AES256_GCM)" in preview
    assert dek(team).algorithm == "AES256_GCM"


def test_index_keys_are_skipped_once_with_the_reason():
    team = make_team()
    make_note(team)

    output = run("--silo-uid", uid(team), "--purpose", "index", "--only-outdated")

    assert output.count("Skipped: every [index] key") == 1
    assert "HMAC-SHA-256" in output
    assert "Rotated:" not in output


def test_an_algorithm_only_move_is_named(settings, caplog):
    team = make_team()
    make_note(team)
    _configure(settings, CRYPTO_BACKEND_OPTIONS={"AEAD_KEY_TEMPLATE": "AES128_GCM"})

    with caplog.at_level("WARNING", logger="encryption_suite.management.commands.reencrypt_data"):
        output = run("--silo-uid", uid(team), "--purpose", "field", "--dry-run")

    assert "[dry-run] Converting: algorithm AES256_GCM -> AES128_GCM" in output
    assert "(algorithm AES256_GCM -> AES128_GCM)" in output
    opening = next(r.getMessage() for r in caplog.records if "command started" in r.getMessage())
    assert 'converts="algorithm AES256_GCM -> AES128_GCM"' in opening


def test_a_backend_and_algorithm_move_is_named_as_one(settings):
    team = make_team()
    make_note(team)
    _configure(settings, CRYPTO_BACKEND=_PYCA, CRYPTO_BACKEND_OPTIONS={"AEAD": "CHACHA20_POLY1305"})

    output = run("--silo-uid", uid(team), "--purpose", "field", "--dry-run")

    assert "Converting: backend tink -> cryptography, algorithm AES256_GCM -> CHACHA20_POLY1305" in output


@pytest.mark.parametrize("flags", [["--abort"], ["--check", "--purpose", "index"]])
def test_only_outdated_is_refused_with_abort_and_check(flags):
    with pytest.raises(CommandError, match="--only-outdated"):
        run("--only-outdated", *flags)
