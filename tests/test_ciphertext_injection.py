"""A ciphertext-shaped value a caller assigns is never decrypted or written through.

The field tells stored ciphertext from a caller's value by provenance, not by
shape: ``from_db_value`` and the raw-cursor helpers stamp what they read, and only
a stamped value is decrypted on read or passed through on save. Without that, a
ciphertext copied out of a database dump and submitted through a form would be
stored as is, and the next read would decrypt it under the attacker's row —
handing back another row's plaintext to anyone with an account in the same silo.

A value equal to what the row already holds is still accepted, so code that
copies a loaded row's raw value onto a fresh instance of the same row keeps
working.
"""

from __future__ import annotations

import logging

import pytest
from django import forms
from django.contrib.auth.models import Group
from django.db import connection, models, transaction

from encryption_suite._internal import raw_cursor_fetch
from encryption_suite.adapters.silos.context import override_current_silo
from encryption_suite.engine import is_silo_value, is_stamped
from encryption_suite.exceptions import GENERIC_ENCRYPT_FAILED_USER_MESSAGE, FieldAlreadyEncryptedError
from encryption_suite.fields import EncryptedJSONField
from tests.rotation_helpers import make_team
from tests.testapp.models import HiddenNote, Member

VICTIM_SECRET = "the victim's secret"


def _raw(model, pk, field) -> str:
    """The stored ciphertext of one column, as a plain ``str`` an attacker would paste."""
    value = raw_cursor_fetch(model, pk, [field])[0]
    assert is_stamped(value)
    return str(value)


def _refused(save) -> FieldAlreadyEncryptedError:
    """Run *save*, expecting the refusal; inside a savepoint, so the test's transaction survives it."""
    with pytest.raises(FieldAlreadyEncryptedError) as raised, transaction.atomic():
        save()
    return raised.value


@pytest.fixture
def team(db) -> Group:
    return make_team()


@pytest.fixture
def victim_ciphertext(team) -> str:
    with override_current_silo(team):
        victim = HiddenNote.objects.create(team=team, secret=VICTIM_SECRET)
    return _raw(HiddenNote, victim.pk, "secret")


def test_copied_ciphertext_is_refused_on_save(team, victim_ciphertext, caplog):
    with override_current_silo(team):
        attacker = HiddenNote(team=team, secret=victim_ciphertext)
        with caplog.at_level(logging.ERROR, logger="encryption_suite"):
            error = _refused(attacker.save)

    assert str(error) == str(GENERIC_ENCRYPT_FAILED_USER_MESSAGE)
    assert "testapp.HiddenNote.secret" in error.detail
    errors = [r for r in caplog.records if r.levelno == logging.ERROR]
    assert len(errors) == 1
    message = errors[0].getMessage()
    assert "error_code=field_already_encrypted" in message
    assert 'field="testapp.HiddenNote.secret"' in message
    assert errors[0].exc_info is None
    assert HiddenNote.objects.count() == 1


def test_copied_ciphertext_reads_back_as_raw_text(team, victim_ciphertext):
    with override_current_silo(team):
        unsaved = HiddenNote(team=team, secret=victim_ciphertext)
        assert unsaved.secret == victim_ciphertext

        existing = HiddenNote.objects.create(team=team, secret="mine")
        existing = HiddenNote.objects.get(pk=existing.pk)
        existing.secret = victim_ciphertext
        assert existing.secret == victim_ciphertext
        assert existing.secret != VICTIM_SECRET
        _refused(existing.save)

        assert HiddenNote.objects.get(pk=existing.pk).secret == "mine"


def test_copied_ciphertext_between_system_columns_is_refused(db):
    victim = Member.objects.create(email="victim@example.com", handle="victim")
    stolen = _raw(Member, victim.pk, "email")

    attacker = Member.objects.create(email="attacker@example.com", handle="attacker")
    attacker = Member.objects.get(pk=attacker.pk)
    attacker.handle = stolen
    assert attacker.handle == stolen
    _refused(attacker.save)

    assert Member.objects.get(pk=attacker.pk).handle == "attacker"


class HiddenNoteForm(forms.ModelForm):
    class Meta:
        model = HiddenNote
        fields = ["secret"]


def test_model_form_does_not_decrypt_copied_ciphertext(team, victim_ciphertext):
    with override_current_silo(team):
        form = HiddenNoteForm(data={"secret": victim_ciphertext}, instance=HiddenNote(team=team))
        assert form.is_valid(), form.errors
        assert form.instance.__dict__["secret"] == victim_ciphertext
        assert form.instance.secret != VICTIM_SECRET
        _refused(form.save)


class InjectedPayload(models.Model):
    team = models.ForeignKey(Group, on_delete=models.CASCADE, related_name="+")
    data = EncryptedJSONField(null=True)

    class Meta:
        app_label = "tests"


@pytest.fixture
def payload_model(db):
    with connection.schema_editor() as editor:
        editor.create_model(InjectedPayload)
    try:
        yield InjectedPayload
    finally:
        with connection.schema_editor() as editor:
            editor.delete_model(InjectedPayload)


@pytest.mark.django_db(transaction=True)
def test_json_string_value_is_refused(payload_model, team, victim_ciphertext):
    with override_current_silo(team):
        row = payload_model(team=team, data=victim_ciphertext)
        assert row.data == victim_ciphertext
        _refused(row.save)


def test_unchanged_raw_value_round_trips(team):
    with override_current_silo(team):
        note = HiddenNote.objects.create(team=team, secret=VICTIM_SECRET)
        loaded = HiddenNote.objects.get(pk=note.pk)
        copied = HiddenNote(pk=loaded.pk, team=team, secret=str(loaded.__dict__["secret"]))
        assert not is_stamped(copied.__dict__["secret"])
        copied.save()
        assert copied.secret == VICTIM_SECRET
        assert HiddenNote.objects.get(pk=note.pk).secret == VICTIM_SECRET

        other = HiddenNote(pk=loaded.pk, team=team, secret=str(loaded.__dict__["secret"]))
        assert other.secret == VICTIM_SECRET


def test_saving_the_same_instance_twice(team):
    with override_current_silo(team):
        note = HiddenNote(team=team, secret=VICTIM_SECRET)
        note.save()
        assert is_stamped(note.__dict__["secret"])
        note.save()
        assert HiddenNote.objects.get(pk=note.pk).secret == VICTIM_SECRET


def test_saving_with_a_deferred_encrypted_field(team):
    with override_current_silo(team):
        note = HiddenNote.objects.create(team=team, secret=VICTIM_SECRET)
        deferred = HiddenNote.objects.defer("secret").get(pk=note.pk)
        deferred.hidden = False
        deferred.save()
        assert HiddenNote.objects.get(pk=note.pk).secret == VICTIM_SECRET


def test_loaded_value_saves_unchanged(team):
    with override_current_silo(team):
        note = HiddenNote.objects.create(team=team, secret=VICTIM_SECRET)
        before = _raw(HiddenNote, note.pk, "secret")
        HiddenNote.objects.get(pk=note.pk).save()
        assert _raw(HiddenNote, note.pk, "secret") == before


def test_typed_value_with_the_stored_shape_is_refused(team):
    with override_current_silo(team):
        _refused(lambda: HiddenNote.objects.create(team=team, secret="~^Dv1:is how my password starts"))
        _refused(lambda: HiddenNote.objects.create(team=team, secret="~^Dv27:a later framing"))


def test_typed_value_starting_with_the_marker_alone_is_stored(team):
    with override_current_silo(team):
        note = HiddenNote.objects.create(team=team, secret="~^D is how my password starts")
        assert _raw(HiddenNote, note.pk, "secret") != "~^D is how my password starts"
        assert HiddenNote.objects.get(pk=note.pk).secret == "~^D is how my password starts"


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("~^Dv1:abc", True),
        ("~^Dv2:abc", True),
        ("~^Dv10:", True),
        ("~^D", False),
        ("~^Dv:abc", False),
        ("~^Dvx:abc", False),
        ("~^D hello", False),
        ("x~^Dv1:abc", False),
        (None, False),
    ],
)
def test_is_silo_value_matches_every_framing_version_and_nothing_else(value, expected):
    assert is_silo_value(value) is expected
