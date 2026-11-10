"""What ``manage.py check`` says about an optional encrypted field.

An encrypted column holds ciphertext, and "no value" has none: the empty string
is not something the engine can encrypt and read back. Django reaches for ``""``
whenever a ``blank=True`` column is not nullable — as the form's empty value, and
as the default a migration adds the column with — so that pair asks the column
for the one thing it cannot hold. The check says so against the field, while the
declaration is still the line the author just wrote.
"""

from __future__ import annotations

from django.db import models

from encryption_suite.fields import (
    EncryptedCharField,
    EncryptedDateField,
    EncryptedFileField,
    EncryptedTextField,
)

_counter = 0


def _make_model(**fields):
    """A throwaway model carrying *fields*, never migrated."""
    global _counter
    _counter += 1
    attrs = {
        "__module__": "tests.test_blank_null_check",
        "Meta": type("Meta", (), {"app_label": "tests"}),
        **fields,
    }
    return type(f"BlankNullModel{_counter}", (models.Model,), attrs)


def _check(model, field_name):
    return model._meta.get_field(field_name).check()


def test_blank_without_null_is_an_error():
    model = _make_model(secret=EncryptedTextField(blank=True))

    (error,) = _check(model, "secret")

    assert error.id == "encryption_suite.E025"
    assert "null=True" in error.hint


def test_blank_with_null_reports_nothing():
    model = _make_model(secret=EncryptedTextField(blank=True, null=True))

    assert _check(model, "secret") == []


def test_a_required_field_reports_nothing():
    """blank=False never reaches the empty value, nullable or not."""
    model = _make_model(secret=EncryptedDateField())

    assert _check(model, "secret") == []


def test_the_file_field_is_checked_too():
    """EncryptedFileField does not use the mixin, so it carries its own call."""
    model = _make_model(
        upload=EncryptedFileField(display_name_field="upload_name", blank=True),
        upload_name=EncryptedCharField(max_length=255, null=True, blank=True),
    )

    ids = [e.id for e in _check(model, "upload")]

    assert "encryption_suite.E025" in ids


def test_the_companion_display_name_column_is_checked_too():
    """The column people most often leave non-nullable."""
    model = _make_model(
        upload=EncryptedFileField(display_name_field="upload_name", null=True, blank=True),
        upload_name=EncryptedCharField(max_length=255, blank=True),
    )

    (error,) = _check(model, "upload_name")

    assert error.id == "encryption_suite.E025"
