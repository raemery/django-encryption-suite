"""A bounded ciphertext column: why it exists, how wide it gets, and what it refuses.

Nothing in this package needs it — no lookup compares a ciphertext column and no
index of ours covers one. It is for a column some *other* package indexes, in a
``Meta`` the project cannot edit, because MySQL and Oracle refuse an index
containing a text column and fail the migration that adds it.
"""

from __future__ import annotations

import pytest
from django.db import connection, models

from encryption_suite.fields import (
    STORED_FRAMING_CHARS,
    STORED_SEALED_BYTES,
    VARCHAR_COLUMN_MAX,
    EncryptedCharField,
    EncryptedEmailField,
    EncryptedTextField,
)


class Bounded(models.Model):
    email = EncryptedEmailField(key_set="system", max_length=254, null=True, blank=True, varchar_column=True)
    unbounded = EncryptedCharField(key_set="system", max_length=254, null=True, blank=True)

    class Meta:
        app_label = "tests"


@pytest.fixture
def table(transactional_db):
    with connection.schema_editor() as editor:
        editor.create_model(Bounded)
    yield
    with connection.schema_editor() as editor:
        editor.delete_model(Bounded)


def _field(**kwargs):
    field = EncryptedCharField(key_set="system", **kwargs)
    field.set_attributes_from_name("probe")
    field.model = Bounded
    return field


# ---------------------------------------------------------------------------
# The column
# ---------------------------------------------------------------------------


def test_the_column_is_a_varchar_sized_for_the_stored_value():
    field = Bounded._meta.get_field("email")

    assert field.get_internal_type() == "CharField"
    # Framing, then base64 of the nonce, the ciphertext and the tag.
    assert field.stored_max_length == STORED_FRAMING_CHARS + 4 * ((254 + STORED_SEALED_BYTES + 2) // 3)
    assert field.db_type(connection) == f"varchar({field.stored_max_length})"


def test_max_length_still_describes_the_value_not_the_column():
    field = Bounded._meta.get_field("email")

    # Two numbers on one field: what a value may be, and how wide the column is.
    assert field.max_length == 254
    assert field.stored_max_length > field.max_length


def test_without_the_keyword_the_column_stays_text():
    field = Bounded._meta.get_field("unbounded")

    assert field.get_internal_type() == "TextField"
    assert field.db_type(connection) == "text"


def test_the_keyword_survives_a_migration():
    field = Bounded._meta.get_field("email")

    assert field.deconstruct()[3]["varchar_column"] is True


# ---------------------------------------------------------------------------
# Round trip
# ---------------------------------------------------------------------------


def test_a_value_round_trips_through_the_bounded_column(table):
    row = Bounded.objects.create(email="ann@example.com")

    assert Bounded.objects.get(pk=row.pk).email == "ann@example.com"


def test_a_value_longer_than_the_column_is_refused_by_the_field(table):
    # Passes Django's character-counting validation and would overflow the
    # column: 100 characters, three bytes each, is 300 bytes of the 254 the
    # column is sized for.
    row = Bounded(email="あ" * 100 + "@example.com")

    with pytest.raises(ValueError, match="counts bytes"):
        row.save()


def test_the_refusal_names_the_field_and_both_numbers(table):
    row = Bounded(email="あ" * 100 + "@example.com")

    with pytest.raises(ValueError) as caught:
        row.save()

    assert "tests.Bounded.email" in str(caught.value)
    assert "254" in str(caught.value)


# ---------------------------------------------------------------------------
# E028
# ---------------------------------------------------------------------------


def test_a_column_too_wide_to_index_anywhere_is_refused():
    field = _field(max_length=600, varchar_column=True)

    errors = field._check_varchar_column()

    assert [e.id for e in errors] == ["encryption_suite.E028"]
    assert field.stored_max_length > VARCHAR_COLUMN_MAX
    # The hint names a max_length that would have fitted.
    assert str(field.plain_max_length_for(VARCHAR_COLUMN_MAX)) in errors[0].hint


def test_the_named_max_length_actually_fits():
    fits = _field(max_length=EncryptedCharField.plain_max_length_for(VARCHAR_COLUMN_MAX), varchar_column=True)

    assert fits.stored_max_length <= VARCHAR_COLUMN_MAX
    assert fits._check_varchar_column() == []


def test_a_bounded_column_with_no_max_length_is_refused():
    field = _field(varchar_column=True)

    assert [e.id for e in field._check_varchar_column()] == ["encryption_suite.E028"]


def test_a_field_type_with_no_max_length_cannot_be_bounded():
    """Text and JSON have no length to compute a width from."""
    field = EncryptedTextField(varchar_column=True)
    field.set_attributes_from_name("notes")
    field.model = Bounded

    assert [e.id for e in field._check_varchar_column()] == ["encryption_suite.E028"]


def test_an_unbounded_field_is_not_checked():
    assert _field(max_length=100000)._check_varchar_column() == []
    assert EncryptedCharField(max_length=100000)._check_varchar_column() == []
