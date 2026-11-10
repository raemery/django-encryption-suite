"""Rotating a silo's blind index key, and what that does and does not touch.

An index rotation is unlike the other two: a digest is a one-way hash of the
plaintext, so the new digest can only be produced by decrypting the value — with
the silo's *field* key, which is not the key being rotated. The model lives in
``testapp`` rather than being declared here, because a rotation resolves targets
from the app registry and names each item's model by label, neither of which can
see a transient model.
"""

from __future__ import annotations

import pytest

from encryption_suite.models import DataEncryptionKey
from encryption_suite.registry import get_silo_adapter
from tests.rotation_helpers import run, run_fenced
from tests.testapp.models import Indexed


@pytest.fixture
def waits(monkeypatch):
    """The wait exists so every process drops the old key from its cache."""
    from encryption_suite import rotation

    monkeypatch.setattr(rotation, "_sleep", lambda seconds: None)


@pytest.fixture
def team(transactional_db):
    from django.contrib.auth.models import Group

    from encryption_suite.adapters.silos.context import override_current_silo

    group = Group.objects.create(name="acme")
    with override_current_silo(group):
        yield group


def _uid(team):
    return get_silo_adapter().get_silo_uid(team)


def _digest(row):
    return Indexed._base_manager.values_list("handle_index", flat=True).get(pk=row.pk)


def _key(team, purpose):
    return DataEncryptionKey.objects.get(silo_uid=_uid(team), purpose=purpose)


def test_an_index_rotation_moves_the_digest_and_keeps_the_lookup_working(team, waits):
    row = Indexed.objects.create(team=team, handle="Ann")
    before = _digest(row)

    output = run("--silo-uid", _uid(team), "--purpose", "index")

    assert _digest(row) != before, output
    # Found again under the new key, and the value itself was never rewritten.
    assert Indexed.objects.get(handle="ann").pk == row.pk
    assert Indexed.objects.get(pk=row.pk).handle == "Ann"


def test_the_opening_line_names_no_backend_template(team, waits):
    Indexed.objects.create(team=team, handle="ann")

    output = run("--silo-uid", _uid(team), "--purpose", "index")

    opened = next(line for line in output.splitlines() if line.startswith("Opened:"))
    # An index key is HMAC key material, which no crypto backend produces.
    assert "index key material" in opened
    assert "template" not in opened


def test_the_field_key_is_left_where_it_was(team, waits):
    Indexed.objects.create(team=team, handle="ann")

    run("--silo-uid", _uid(team), "--purpose", "index")

    assert _key(team, DataEncryptionKey.PURPOSE_FIELD).dek_key_version == 1
    assert _key(team, DataEncryptionKey.PURPOSE_INDEX).dek_key_version == 2


def test_a_field_rotation_leaves_the_digest_alone(team, waits):
    row = Indexed.objects.create(team=team, handle="ann")
    before = _digest(row)

    run("--silo-uid", _uid(team), "--purpose", "field")

    # The index key is not the data key: moving one leaves the other's work.
    assert _digest(row) == before
    assert Indexed.objects.get(handle="ann").pk == row.pk
    assert _key(team, DataEncryptionKey.PURPOSE_INDEX).dek_key_version == 1


def test_a_row_holding_no_value_needs_no_digest(team, waits):
    empty = Indexed.objects.create(team=team, handle=None)
    Indexed.objects.create(team=team, handle="ann")

    run("--silo-uid", _uid(team), "--purpose", "index")

    assert _digest(empty) is None


def test_an_abort_puts_the_old_digests_back(team, waits, monkeypatch):
    """A rollback is the same work with the keys the other way round."""
    from encryption_suite import rotation

    row = Indexed.objects.create(team=team, handle="ann")
    before = _digest(row)
    # Stop after the fence goes up, leaving the rotation open.
    monkeypatch.setattr(rotation.Rotator, "_sweep", lambda *a, **k: (0, "stopped for the test"))
    run_fenced("--silo-uid", _uid(team), "--purpose", "index")
    monkeypatch.undo()

    run("--silo-uid", _uid(team), "--purpose", "index", "--abort")

    assert _digest(row) == before
    assert Indexed.objects.get(handle="ann").pk == row.pk


# ---------------------------------------------------------------------------
# Which purposes `--purpose all` expands to
# ---------------------------------------------------------------------------


def test_all_rotates_the_index_too(team, waits):
    row = Indexed.objects.create(team=team, handle="ann")
    before = _digest(row)

    run("--silo-uid", _uid(team), "--purpose", "all")

    assert _digest(row) != before
    assert _key(team, DataEncryptionKey.PURPOSE_FIELD).dek_key_version == 2
    assert _key(team, DataEncryptionKey.PURPOSE_INDEX).dek_key_version == 2


def test_all_leaves_the_index_out_where_nothing_declares_one(monkeypatch):
    """The gate is a registry walk, so it is asked of a chosen set of models."""
    from django.apps import apps

    from encryption_suite import blind_index

    monkeypatch.setattr(apps, "get_models", lambda: [Indexed])
    assert [m.__name__ for m, _f in blind_index.silo_indexed_fields()] == ["Indexed"]

    monkeypatch.setattr(apps, "get_models", lambda: [])
    assert list(blind_index.silo_indexed_fields()) == []
