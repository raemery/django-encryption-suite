"""A silo field's blind index: the digest, the key it comes from, and the lookups.

The digest is keyed per silo, which is the whole design: two silos holding one
value index differently, neither finds the other's row, and destroying a silo's
KEK takes its digests with its data. These exercise that through the ORM, the way
an application meets it.

Both storage strategies run here. ``column`` keeps the digest in a companion
column of the model's own table; ``table`` keeps it in the package's own table,
which is the only option for a model the project cannot change.
"""

from __future__ import annotations

import pytest
from django.contrib.auth.models import Group
from django.core.exceptions import ValidationError
from django.db import IntegrityError, connection, models, transaction

from encryption_suite.adapters.silos.context import override_current_silo
from encryption_suite.fields import EncryptedCharField
from encryption_suite.models import BlindIndexEntry, DataEncryptionKey


class Indexed(models.Model):
    """Digests in a companion column, and one of them held unique per silo."""

    team = models.ForeignKey("auth.Group", on_delete=models.CASCADE, related_name="+")
    handle = EncryptedCharField(max_length=100, null=True, blank=True, blind_index=True, normalize="casefold")
    label = EncryptedCharField(max_length=100, null=True, blank=True, blind_index=True, unique_in_silo=True)

    class Meta:
        app_label = "tests"


class Shared(models.Model):
    """Digests in the package's table, the strategy a third-party model needs."""

    team = models.ForeignKey("auth.Group", on_delete=models.CASCADE, related_name="+")
    handle = EncryptedCharField(
        max_length=100,
        null=True,
        blank=True,
        blind_index=True,
        normalize="casefold",
        blind_index_storage="table",
        unique_in_silo=True,
    )

    class Meta:
        app_label = "tests"


@pytest.fixture(params=[Indexed, Shared], ids=["column", "table"])
def model(request, transactional_db):
    """Each test runs against both storage strategies."""
    with connection.schema_editor() as editor:
        editor.create_model(request.param)
    yield request.param
    with connection.schema_editor() as editor:
        editor.delete_model(request.param)


@pytest.fixture
def column_model(transactional_db):
    with connection.schema_editor() as editor:
        editor.create_model(Indexed)
    yield Indexed
    with connection.schema_editor() as editor:
        editor.delete_model(Indexed)


# ---------------------------------------------------------------------------
# Lookups
# ---------------------------------------------------------------------------


def test_an_exact_lookup_finds_the_row(model, silo_context):
    row = model.objects.create(team=silo_context, handle="Ann")

    assert model.objects.get(handle="ann").pk == row.pk
    assert model.objects.filter(handle="bob").count() == 0


def test_an_in_lookup_finds_every_match(model, silo_context):
    first = model.objects.create(team=silo_context, handle="ann")
    second = model.objects.create(team=silo_context, handle="bob")

    found = set(model.objects.filter(handle__in=["ann", "bob", "nobody"]).values_list("pk", flat=True))

    assert found == {first.pk, second.pk}


def test_a_row_whose_value_was_cleared_answers_nothing(model, silo_context):
    row = model.objects.create(team=silo_context, handle="ann")

    # update() cannot clear the digest — nothing on a field can reach an UPDATE
    # the ORM built from the caller's kwargs — so the comparison also requires
    # the value to be present.
    model.objects.filter(pk=row.pk).update(handle=None)

    assert model.objects.filter(handle="ann").count() == 0


def test_a_lookup_the_index_cannot_serve_is_refused(model, silo_context):
    model.objects.create(team=silo_context, handle="ann")

    with pytest.raises(Exception) as caught:
        model.objects.filter(handle__contains="nn").count()

    assert "__contains" in str(caught.value)


# ---------------------------------------------------------------------------
# One key per silo
# ---------------------------------------------------------------------------


def test_the_index_key_is_provisioned_on_first_use_and_names_no_backend(model, silo_context):
    model.objects.create(team=silo_context, handle="ann")

    key = DataEncryptionKey.objects.get(purpose=DataEncryptionKey.PURPOSE_INDEX)

    assert bytes(key.encrypted_keyset)
    # No crypto backend produced it, and stamping one would make the key
    # unusable — and its digests unfindable — after a change of CRYPTO_BACKEND.
    assert key.crypto_backend == ""


def test_two_silos_index_the_same_value_differently(model, transactional_db):
    one = Group.objects.create(name="one")
    two = Group.objects.create(name="two")

    with override_current_silo(one):
        first = model.objects.create(team=one, handle="ann")
    with override_current_silo(two):
        second = model.objects.create(team=two, handle="ann")
        # The other silo's row is not found, though it holds the same value.
        assert model.objects.filter(handle="ann").count() == 1
        assert model.objects.get(handle="ann").pk == second.pk

    assert _digest(model, first) != _digest(model, second)


def test_a_lookup_with_no_silo_in_context_raises(model, transactional_db):
    from encryption_suite.exceptions import EncryptionError

    with pytest.raises(EncryptionError) as caught:
        model.objects.filter(handle="ann").count()

    # A typed error carrying the generic message, not a FieldError and not a
    # leak: the lookup is supported, the silo is what is missing, and the reader
    # of the message is not told which.
    assert str(caught.value) == "Encryption and decryption are unavailable for this data."
    assert "silo" not in str(caught.value).lower()


def test_a_failed_lookup_inside_a_form_is_a_form_error(model, silo_context, monkeypatch):
    """A lookup run from a form's clean() — allauth's sign-in, say — shows on the form.

    The error is the original one as well as a ValidationError: same class, code
    and message, so code catching it by type and the DRF status are unchanged.
    """
    from django import forms

    from encryption_suite.engine import EncryptionEngine
    from encryption_suite.exceptions import GENERIC_ENCRYPT_DECRYPT_UNAVAILABLE_MESSAGE, KekUnavailableError

    def unreachable(*args, **kwargs):
        raise KekUnavailableError(GENERIC_ENCRYPT_DECRYPT_UNAVAILABLE_MESSAGE, detail="the KMS refused the connection")

    monkeypatch.setattr(EncryptionEngine, "_new_wrapped_keyset", unreachable)

    with pytest.raises(KekUnavailableError) as caught:
        model.objects.filter(handle="ann").exists()
    error = caught.value
    assert isinstance(error, ValidationError)
    assert error.code == "kek_unavailable"
    assert error.detail == "the KMS refused the connection"
    assert str(error) == "Encryption and decryption are unavailable for this data."

    class SignIn(forms.Form):
        handle = forms.CharField()

        def clean(self):
            model.objects.filter(handle=self.cleaned_data["handle"]).exists()
            return self.cleaned_data

    form = SignIn(data={"handle": "ann"})

    assert not form.is_valid()
    assert form.non_field_errors() == ["Encryption and decryption are unavailable for this data."]
    assert form.errors.as_data()["__all__"][0].code == "kek_unavailable"


# ---------------------------------------------------------------------------
# Uniqueness, per silo
# ---------------------------------------------------------------------------


def test_a_duplicate_inside_one_silo_is_a_validation_error(model, silo_context):
    field = "label" if model is Indexed else "handle"
    model.objects.create(team=silo_context, **{field: "ann"})

    with pytest.raises(ValidationError) as caught:
        model(team=silo_context, **{field: "ann"}).full_clean()

    assert caught.value.error_dict[field][0].code == "unique"


def test_the_database_refuses_the_duplicate_too(model, silo_context):
    field = "label" if model is Indexed else "handle"
    model.objects.create(team=silo_context, **{field: "ann"})

    with pytest.raises(IntegrityError), transaction.atomic():
        model.objects.create(team=silo_context, **{field: "ann"})


def test_the_same_value_in_another_silo_is_not_a_duplicate(model, transactional_db):
    field = "label" if model is Indexed else "handle"
    one = Group.objects.create(name="one")
    two = Group.objects.create(name="two")

    with override_current_silo(one):
        model.objects.create(team=one, **{field: "ann"})
    with override_current_silo(two):
        model(team=two, **{field: "ann"}).full_clean()
        model.objects.create(team=two, **{field: "ann"})

    assert model.objects.count() == 2


def test_an_index_key_that_cannot_be_created_is_a_validation_error(model, silo_context, monkeypatch):
    from encryption_suite.engine import EncryptionEngine
    from encryption_suite.exceptions import GENERIC_ENCRYPT_DECRYPT_UNAVAILABLE_MESSAGE, KekUnavailableError

    def unreachable(*args, **kwargs):
        raise KekUnavailableError(GENERIC_ENCRYPT_DECRYPT_UNAVAILABLE_MESSAGE, detail="the KMS refused the connection")

    monkeypatch.setattr(EncryptionEngine, "_new_wrapped_keyset", unreachable)
    field = "label" if model is Indexed else "handle"

    # A first write in a silo whose KMS is down: the check needs a digest, the
    # digest needs a key, and the key cannot be made. A ModelForm's is_valid()
    # runs this, so it must arrive as a form error, not escape as a 500.
    with pytest.raises(ValidationError) as caught:
        model(team=silo_context, **{field: "ann"}).full_clean()

    [error] = caught.value.error_dict["__all__"]
    assert error.code == "kek_unavailable"
    assert error.messages == ["Encryption and decryption are unavailable for this data."]


def test_the_row_holding_the_value_is_not_a_duplicate_of_itself(model, silo_context):
    field = "label" if model is Indexed else "handle"
    row = model.objects.create(team=silo_context, **{field: "ann"})

    setattr(row, field, "ann")
    row.full_clean()


# ---------------------------------------------------------------------------
# What each storage strategy puts where
# ---------------------------------------------------------------------------


def test_the_column_strategy_adds_a_companion_column(column_model):
    names = [f.name for f in column_model._meta.local_fields]

    assert "handle_index" in names
    assert "label_index" in names


def test_the_table_strategy_adds_nothing_to_the_model(transactional_db):
    assert [f.name for f in Shared._meta.local_fields] == ["id", "team", "handle"]


def test_a_narrowed_save_carries_the_digest_with_the_value(model, silo_context):
    row = model.objects.create(team=silo_context, handle="ann")

    row.handle = "bob"
    row.save(update_fields=["handle"])

    assert model.objects.filter(handle="ann").count() == 0
    assert model.objects.get(handle="bob").pk == row.pk


def test_deleting_the_row_takes_its_digest_with_it(model, silo_context):
    row = model.objects.create(team=silo_context, handle="ann")
    pk = row.pk

    row.delete()

    if model is Shared:
        assert not BlindIndexEntry.objects.filter(object_pk=str(pk)).exists()
    assert model.objects.filter(pk=pk).count() == 0


def _digest(model, row):
    """The digest recorded for *row*, read from wherever the field keeps it."""
    field = model._meta.get_field("handle")
    return field.stored_index_digest(model._base_manager.get(pk=row.pk))


# ---------------------------------------------------------------------------
# A digest edited in the database
# ---------------------------------------------------------------------------


def _set_digest(model, row, digest):
    """Write a digest past the field, the way someone with database access would."""
    if model is Indexed:
        model._base_manager.filter(pk=row.pk).update(handle_index=digest)
    else:
        BlindIndexEntry.objects.filter(
            model_label=model._meta.label, field_name="handle", object_pk=str(row.pk)
        ).update(digest=digest)


def test_a_tampered_digest_does_not_stop_the_row_being_read(model, silo_context):
    row = model.objects.create(team=silo_context, handle="ann")
    other = model._meta.get_field("handle").index_digest("bob")

    _set_digest(model, row, other)

    # The digest is no AAD input, by decision: feeding it back at every decrypt
    # would cost a read of it per row, and a mismatch anywhere presents as
    # undecryptable data.
    assert model.objects.get(pk=row.pk).handle == "ann"


def test_a_tampered_digest_makes_the_row_answer_to_a_value_it_does_not_hold(model, silo_context):
    row = model.objects.create(team=silo_context, handle="ann")
    field = model._meta.get_field("handle")

    _set_digest(model, row, field.index_digest("bob"))

    # What tampering buys, and why it is worth being able to detect: the row is
    # found by a value nobody stored in it, and no longer by the one they did.
    assert model.objects.get(handle="bob").pk == row.pk
    assert model.objects.filter(handle="ann").count() == 0


def test_the_misdirection_is_found_by_recomputing_the_digest(model, silo_context):
    row = model.objects.create(team=silo_context, handle="ann")
    field = model._meta.get_field("handle")
    _set_digest(model, row, field.index_digest("bob"))

    loaded = model._base_manager.get(pk=row.pk)
    # The check an operator or a verify pass would run: what the row holds,
    # hashed again, against what the storage says.
    assert field.stored_index_digest(loaded) != field.index_digest(loaded.handle)

    # And it agrees for a row nobody touched.
    untouched = model._base_manager.get(pk=model.objects.create(team=silo_context, handle="cat").pk)
    assert field.stored_index_digest(untouched) == field.index_digest(untouched.handle)
