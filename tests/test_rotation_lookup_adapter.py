"""Rotating through ``queryset_for_silo``, the path a cell deployment takes.

The other rotation tests find a silo's rows by foreign key, which is what an
adapter with a ``model_label`` gets for free. An adapter that has no such key —
the composite one, where a tenant's schema holds every cell's rows — answers the
lookup itself, and ``rows_for_silo`` asks it. What matters is that the answer
*scopes* the rotation: everything the adapter returns moves onto the new key,
and nothing else moves at all.

So the adapter here declares no ``model_label``, which is what makes foreign-key
resolution unavailable (``rotation_targets._silo_foreign_key`` reports it), and
implements the hook instead.
"""

from __future__ import annotations

import pytest
from django.test import override_settings

from encryption_suite import registry
from encryption_suite.models import DataEncryptionKey
from tests.rotation_helpers import (
    dek,
    make_document,
    make_note,
    make_team,
    read_document,
    read_note,
    run,
    uid,
)
from tests.settings import ENCRYPTION as _SUITE_ENCRYPTION
from tests.silo import GroupSiloAdapter
from tests.testapp.models import Document, Note

pytestmark = pytest.mark.django_db


class CellLookupAdapter(GroupSiloAdapter):
    """Finds a silo's rows the way a cell-encrypted deployment has to.

    ``model_label`` is cleared so the foreign key on the test models cannot be
    found by introspection, even though it is right there — this stands in for
    the composite adapter, whose silo is a cell that no column names.
    """

    model_label = None
    supports_silo_data_lookup = True

    def queryset_for_silo(self, model, silo_uid: str):
        return model._base_manager.filter(team_id=int(silo_uid.removeprefix("group-")))


_SETTINGS = {
    "KEY_SETS": {
        "default": {"silo": "tests.test_rotation_lookup_adapter.CellLookupAdapter", "key_store": "local"},
        "system": {"key_store": "login"},
    },
    # The suite's own silo KMS, so keys wrap exactly as everywhere else.
    "KMS_KEY_STORES": _SUITE_ENCRYPTION["KMS_KEY_STORES"],
    "ENV_KEY_STORES": _SUITE_ENCRYPTION["ENV_KEY_STORES"],
    "CRYPTO_BACKEND": "encryption_suite.adapters.crypto_backends.tink.TinkCryptoEngine",
    "KEY_AUTO_PROVISION": True,
}


@pytest.fixture(autouse=True)
def _lookup_adapter():
    """Run every test in this module against the lookup adapter."""
    with override_settings(ENCRYPTION=_SETTINGS):
        registry.reset()
        yield
    registry.reset()


@pytest.fixture(autouse=True)
def _no_wait(monkeypatch):
    from encryption_suite import rotation

    monkeypatch.setattr(rotation, "_sleep", lambda seconds: None)


def _ciphertext(model, pk, column):
    """The stored value, read past the field descriptor so nothing decrypts."""
    from encryption_suite._internal import raw_cursor_fetch

    return raw_cursor_fetch(model, pk, [column])[0]


def test_the_lookup_is_what_resolves_the_models():
    from encryption_suite.rotation_targets import resolve_targets

    resolution = resolve_targets(registry.get_silo_adapter())

    assert resolution.unresolved == []
    assert all(target.fk_name is None for target in resolution.targets)


def test_a_rotation_converts_the_rows_the_lookup_returns_and_no_others():
    mine, theirs = make_team("cell-one"), make_team("cell-two")
    my_note, their_note = make_note(mine, body="mine"), make_note(theirs, body="theirs")
    my_file, their_file = make_document(mine, content=b"mine"), make_document(theirs, content=b"theirs")
    before = {
        "my_note": _ciphertext(Note, my_note.pk, "body"),
        "their_note": _ciphertext(Note, their_note.pk, "body"),
        "my_file": my_file.upload.name,
        "their_file": their_file.upload.name,
    }

    output = run("--silo-uid", uid(mine))

    assert "Rotated" in output
    assert dek(mine).dek_key_version == 2
    assert dek(mine, DataEncryptionKey.PURPOSE_FILE).dek_key_version == 2
    # The other silo is untouched: same key, same bytes on disk.
    assert dek(theirs).dek_key_version == 1
    assert dek(theirs, DataEncryptionKey.PURPOSE_FILE).dek_key_version == 1
    assert _ciphertext(Note, their_note.pk, "body") == before["their_note"]
    assert Document.objects.get(pk=their_file.pk).upload.name == before["their_file"]
    # The rotated silo really did move, and still reads.
    assert _ciphertext(Note, my_note.pk, "body") != before["my_note"]
    assert read_note(my_note.pk, mine)[1] == "mine"
    assert read_document(my_file.pk, mine) == b"mine"
    # And the silo that stayed behind still reads on its old key.
    assert read_note(their_note.pk, theirs)[1] == "theirs"
    assert read_document(their_file.pk, theirs) == b"theirs"


def test_a_rotation_leaves_nothing_fenced_when_the_lookup_answers():
    from encryption_suite.models import DekRotation, DekRotationWorkItem

    team = make_team("cell-one")
    make_note(team)
    make_document(team)

    run("--silo-uid", uid(team))

    assert DekRotation.objects.count() == 0
    assert DekRotationWorkItem.objects.count() == 0
