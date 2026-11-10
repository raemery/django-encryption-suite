"""reencrypt_data across crypto backends: how a silo moves onto a new CRYPTO_BACKEND.

Each data key is read through the backend its row records, and a rotation's
incoming key is made by ``CRYPTO_BACKEND``. So after that setting changes,
existing data keeps reading, and a rotation is what moves each silo onto the new
backend. The dry run and the opening log line name the move.
"""

from __future__ import annotations

import pytest

from encryption_suite import registry, rotation
from encryption_suite.engine import EncryptionEngine
from encryption_suite.models import DataEncryptionKey
from tests.rotation_helpers import dek, make_document, make_note, make_team, read_document, read_note, run, uid

pytestmark = pytest.mark.django_db

_PYCA = "encryption_suite.adapters.crypto_backends.cryptography.CryptographyCryptoEngine"


@pytest.fixture(autouse=True)
def _no_wait(monkeypatch):
    monkeypatch.setattr(rotation, "_sleep", lambda seconds: None)
    EncryptionEngine.invalidate_cache()
    yield
    EncryptionEngine.invalidate_cache()


def _switch_to_pyca(settings):
    settings.ENCRYPTION = {**settings.ENCRYPTION, "CRYPTO_BACKEND": _PYCA}
    registry.reset()
    EncryptionEngine.invalidate_cache()


def test_a_field_rotation_moves_the_silo_onto_the_configured_backend(settings):
    team = make_team()
    note = make_note(team, title="t", body="b")
    assert dek(team).crypto_backend == "tink"
    _switch_to_pyca(settings)

    output = run("--silo-uid", uid(team), "--purpose", "field")

    assert "converting backend tink -> cryptography" in output
    # No arrow: a cp1252 console cannot encode one, and the write would raise.
    assert "→" not in output
    assert dek(team).crypto_backend == "cryptography"
    EncryptionEngine.invalidate_cache()
    assert read_note(note.pk, team) == ("t", "b")


def test_a_file_rotation_moves_the_silo_onto_the_configured_backend(settings):
    team = make_team()
    document = make_document(team, content=b"payload")
    _switch_to_pyca(settings)

    run("--silo-uid", uid(team), "--purpose", "file")

    assert dek(team, DataEncryptionKey.PURPOSE_FILE).crypto_backend == "cryptography"
    EncryptionEngine.invalidate_cache()
    assert read_document(document.pk, team) == b"payload"


def test_the_dry_run_and_the_opening_line_name_the_move(settings, caplog):
    team = make_team()
    make_note(team)
    _switch_to_pyca(settings)

    with caplog.at_level("WARNING", logger="encryption_suite.management.commands.reencrypt_data"):
        output = run("--silo-uid", uid(team), "--purpose", "field", "--dry-run")

    assert "[dry-run] Converting: backend tink -> cryptography" in output
    assert "(backend tink -> cryptography)" in output
    opening = next(r.getMessage() for r in caplog.records if "command started" in r.getMessage())
    assert 'converts="backend tink -> cryptography"' in opening
    assert dek(team).crypto_backend == "tink"


def test_no_move_is_reported_when_the_backend_is_unchanged(caplog):
    team = make_team()
    make_note(team)

    output = run("--silo-uid", uid(team), "--purpose", "field", "--dry-run")

    assert "Converting:" not in output
    assert "→" not in output.split("Would rotate:")[1].splitlines()[0]
