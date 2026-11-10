"""What an encrypted JSON column does when its value cannot be read.

Every other encrypted field degrades to a sentinel that renders as a fallback
label. A JSON field cannot: callers read it as a mapping, so handing them
something that only stringifies turns a degraded read into the crash that
lenient mode exists to prevent. It gives back an empty dict instead, and the
failure is recorded on the instance — the only thing that tells an unreadable
value from an empty one.

That makes the fallback indistinguishable from a value the caller meant, so the
tests below also pin the two consequences: a save after a failed read must leave
the stored value alone, and assigning a fresh value must still save it.
"""

from __future__ import annotations

import pytest
from django.contrib.auth.models import Group
from django.db import connection, models

from encryption_suite._internal import raw_cursor_fetch
from encryption_suite.adapters.silos.context import override_current_silo
from encryption_suite.engine import _CIPHERTEXT_PREFIX
from encryption_suite.exceptions import EncryptedFieldDecryptionError
from encryption_suite.fields import EncryptedJSONField, is_undecryptable, strict_mode
from tests.rotation_helpers import make_team

# Ciphertext-shaped, so it is read as a value to decrypt rather than as plaintext
# awaiting encryption, and rejected once the engine tries to decode it.
UNREADABLE = _CIPHERTEXT_PREFIX + "not base64 at all"


# Transient, like the other models declared in the suite: never registered with
# an installed app, so nothing that enumerates installed models sees it.


class Payload(models.Model):
    team = models.ForeignKey(Group, on_delete=models.CASCADE, related_name="+")
    data = EncryptedJSONField(null=True)

    class Meta:
        app_label = "tests"


@pytest.fixture
def payload_model(db):
    with connection.schema_editor() as editor:
        editor.create_model(Payload)
    try:
        yield Payload
    finally:
        with connection.schema_editor() as editor:
            editor.delete_model(Payload)


@pytest.fixture
def unreadable_row(payload_model):
    """A saved row whose JSON column has been replaced with a value nothing can read."""
    team = make_team()
    with override_current_silo(team):
        row = payload_model.objects.create(team=team, data={"email": "ann@example.com"})
        payload_model.objects.filter(pk=row.pk).update(data=UNREADABLE)
        yield payload_model, row.pk


@pytest.mark.django_db(transaction=True)
def test_a_failed_read_gives_back_an_empty_dict(unreadable_row):
    model, pk = unreadable_row
    loaded = model.objects.get(pk=pk)

    assert loaded.data == {}
    # The sentinel would have answered True, and nothing would have been able to
    # call .get() on it.
    assert not is_undecryptable(loaded.data)
    assert isinstance(loaded.encryption_suite_errors["data"], EncryptedFieldDecryptionError)


@pytest.mark.django_db(transaction=True)
def test_strict_mode_raises_instead_of_degrading(unreadable_row):
    model, pk = unreadable_row
    loaded = model.objects.get(pk=pk)

    with strict_mode(), pytest.raises(EncryptedFieldDecryptionError):
        loaded.data  # noqa: B018


@pytest.mark.django_db(transaction=True)
def test_saving_after_a_failed_read_leaves_the_stored_value_alone(unreadable_row):
    model, pk = unreadable_row
    loaded = model.objects.get(pk=pk)
    assert loaded.data == {}

    loaded.save()

    # Writing the fallback would have replaced the only copy of the data an
    # operator could still recover by fixing the key.
    assert raw_cursor_fetch(model, pk, ["data"])[0] == UNREADABLE


@pytest.mark.django_db(transaction=True)
def test_assigning_a_value_after_a_failed_read_still_saves_it(unreadable_row):
    model, pk = unreadable_row
    team = model.objects.get(pk=pk).team
    loaded = model.objects.get(pk=pk)
    assert loaded.data == {}

    loaded.data = {"email": "replaced@example.com"}
    with override_current_silo(team):
        loaded.save()
        assert model.objects.get(pk=pk).data == {"email": "replaced@example.com"}
