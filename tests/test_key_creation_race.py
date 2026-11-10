"""A key creation that loses a race to another process yields to the winner's key.

The in-process provisioning lock serializes threads; nothing serializes two
processes. A second writer used to overwrite the first one's keyset, making
whatever the first had already encrypted unreadable. Now an active key is never
overwritten: the loser discards its keyset unused and loads the winner's.
"""

import pytest

from encryption_suite.models import DataEncryptionKey
from encryption_suite.registry import get_engine


@pytest.mark.django_db
def test_an_active_key_made_meanwhile_is_kept_and_used(silo_context):
    engine = get_engine()
    engine.generate_and_store_keyset(silo_context)
    winner = DataEncryptionKey.objects.get(purpose=DataEncryptionKey.PURPOSE_FIELD)
    stored_by_winner = engine.encrypt("written under the first key")

    # The loser found no key before the winner committed, and now stores its own.
    stored = engine.generate_and_store_keyset(silo_context)

    assert stored is False
    after = DataEncryptionKey.objects.get(purpose=DataEncryptionKey.PURPOSE_FIELD)
    assert bytes(after.encrypted_keyset) == bytes(winner.encrypted_keyset)
    assert after.dek_key_version == winner.dek_key_version
    engine.invalidate_cache()
    assert engine.decrypt(stored_by_winner) == "written under the first key"


@pytest.mark.django_db
def test_a_tombstone_is_still_revived(silo_context):
    from encryption_suite import lifecycle

    engine = get_engine()
    engine.generate_and_store_keyset(silo_context)
    DataEncryptionKey.objects.filter(purpose=DataEncryptionKey.PURPOSE_FIELD).update(
        status=lifecycle.STATUS_DELETED, encrypted_keyset=b""
    )

    assert engine.generate_and_store_keyset(silo_context) is True
    revived = DataEncryptionKey.objects.get(purpose=DataEncryptionKey.PURPOSE_FIELD)
    assert revived.status == lifecycle.STATUS_ACTIVE
    assert revived.dek_key_version == 2
    assert bytes(revived.encrypted_keyset)


@pytest.mark.django_db
def test_an_insert_clashing_with_a_committed_key_yields(silo_context, monkeypatch):
    """The other process committed while this insert waited on the constraint: the
    row lock saw nothing, the insert hit the unique constraint, and the re-read
    finds the winner's active key."""
    engine = get_engine()
    engine.generate_and_store_keyset(silo_context)
    winner = DataEncryptionKey.objects.get(purpose=DataEncryptionKey.PURPOSE_FIELD)

    # Make the row lock miss the winner's row, as it would before the commit.
    calls = {"n": 0}

    class _FirstLookupMisses:
        def __init__(self, qs):
            self._qs = qs

        def filter(self, *args, **kwargs):
            calls["n"] += 1
            qs = self._qs.filter(*args, **kwargs)
            return qs.none() if calls["n"] == 1 else qs

        def get(self, *args, **kwargs):
            return self._qs.get(*args, **kwargs)

    original = DataEncryptionKey.objects.select_for_update
    monkeypatch.setattr(DataEncryptionKey.objects, "select_for_update", lambda: _FirstLookupMisses(original()))

    assert engine.generate_and_store_keyset(silo_context) is False
    after = DataEncryptionKey.objects.get(purpose=DataEncryptionKey.PURPOSE_FIELD)
    assert bytes(after.encrypted_keyset) == bytes(winner.encrypted_keyset)
