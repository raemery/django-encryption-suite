"""A primitive may not outlive the transaction that created its key row.

The in-process primitive cache is a plain module-level dict, so nothing rolls it
back. Caching a freshly provisioned DEK's primitive the moment the row is
written therefore leaves the primitive behind when the surrounding transaction
does not commit — and the next request in that process encrypts against a key
that exists nowhere, *without* provisioning one, because the cache hit satisfies
it. Those writes commit. The wrapped keyset that could read them back went out
with the rollback, so the rows are undecryptable as soon as the entry expires or
another process serves the read.

``transaction=True`` throughout: the fault is about what survives a real
rollback, which the usual test transaction cannot express.
"""

from __future__ import annotations

import pytest
from django.contrib.auth.models import Group
from django.db import transaction

from encryption_suite.adapters.silos.context import override_current_silo
from encryption_suite.dek_cache import dek_cache
from encryption_suite.engine import (
    EncryptionEngine,
    _field_cache_key,
    _file_cache_key,
)
from encryption_suite.models import DataEncryptionKey
from encryption_suite.registry import get_engine
from encryption_suite.silo_ref import SiloRef

pytestmark = pytest.mark.django_db(transaction=True)


@pytest.fixture(autouse=True)
def _fresh_primitive_cache():
    EncryptionEngine.invalidate_cache()
    yield
    EncryptionEngine.invalidate_cache()


@pytest.fixture
def team():
    return Group.objects.create(name="acme")


def _write(team, title="secret"):
    from tests.testapp.models import Note

    with override_current_silo(team):
        return Note.objects.create(team=team, author="a", title=title, body=None)


def _read(team, pk):
    from tests.testapp.models import Note

    with override_current_silo(team):
        return Note.objects.get(pk=pk).title


def _cached(team):
    return dek_cache("default").contains(_field_cache_key(SiloRef("default", f"group-{team.pk}")).slot)


def test_a_rollback_leaves_no_primitive_behind(team):
    """The whole fault, end to end.

    Before the fix the second write succeeded against the orphaned primitive,
    provisioned nothing, and produced a row that read back as undecryptable.
    """
    with pytest.raises(RuntimeError):
        with transaction.atomic():
            _write(team, "lost with the rollback")
            raise RuntimeError("the request failed after the first encrypt")

    assert DataEncryptionKey.objects.count() == 0
    assert not _cached(team)

    # A later, independent request must provision a key of its own.
    note = _write(team, "kept")

    assert DataEncryptionKey.objects.count() == 1
    EncryptionEngine.invalidate_cache()
    assert _read(team, note.pk) == "kept"


def test_a_first_encrypt_outside_a_transaction_is_cached_at_once(team):
    """``on_commit`` runs inline with no atomic block, so nothing is deferred."""
    _write(team)

    assert _cached(team)


def test_a_second_write_reuses_the_cached_primitive(team):
    """The point of the cache, unchanged: one provision per silo, not one per write."""
    _write(team)
    _write(team, "again")

    assert DataEncryptionKey.objects.count() == 1


def test_the_primitive_is_not_shared_until_the_transaction_commits(team):
    """Inside the block the caller holds it; the rest of the process does not."""
    with transaction.atomic():
        _write(team)
        assert not _cached(team)

    assert _cached(team)


def test_a_savepoint_rollback_discards_it(team):
    """The provisioning rolls back on its own, inside a transaction that commits."""
    with transaction.atomic():
        with pytest.raises(RuntimeError):
            with transaction.atomic():
                _write(team)
                raise RuntimeError("inner block failed")
        Group.objects.create(name="work the outer block still commits")

    assert DataEncryptionKey.objects.count() == 0
    assert not _cached(team)


def test_the_file_dek_takes_the_same_path(team):
    """Field and file DEKs are provisioned through the same call."""
    silo_uid = SiloRef("default", f"group-{team.pk}")

    with pytest.raises(RuntimeError):
        with transaction.atomic():
            get_engine()._get_or_provision_streaming_aead(silo_uid)
            raise RuntimeError("the request failed after the first file write")

    assert DataEncryptionKey.objects.count() == 0
    assert not dek_cache("default").contains(_file_cache_key(silo_uid).slot)


def test_a_second_encrypt_in_the_same_transaction_does_not_publish_it(team):
    """The read that follows a provision must not publish the primitive either.

    Once the DEK row exists it is visible to the rest of its own transaction, so
    an ordinary cached load finds it and caches it at once — putting the
    primitive back into the shared cache by the other door. Two encrypted fields
    on one model is all it takes.
    """
    from tests.testapp.models import Note

    with pytest.raises(RuntimeError):
        with transaction.atomic():
            with override_current_silo(team):
                Note.objects.create(team=team, author="a", title="one", body="two")
            raise RuntimeError("the request failed after writing both fields")

    assert DataEncryptionKey.objects.count() == 0
    assert not _cached(team)
