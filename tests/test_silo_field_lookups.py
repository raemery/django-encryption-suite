"""A silo encrypted column refuses the lookups it cannot answer.

The refusal is the whole point: without it the comparison is built and runs,
the database compares a plaintext parameter against ciphertext, and the caller
gets an empty queryset it reads as "no such row".
"""

from __future__ import annotations

import pytest
from django.core.exceptions import FieldError
from django.db import models
from django.test.utils import isolate_apps

from encryption_suite.fields import EncryptedCharField, EncryptedIntegerField

REFUSED_LOOKUPS = [
    ("exact", "Report"),
    ("iexact", "report"),
    ("in", ["Report"]),
    ("contains", "Rep"),
    ("startswith", "Rep"),
    ("gt", "Report"),
    ("regex", "^Rep"),
]


@isolate_apps("tests")
def _document_model():
    class Document(models.Model):
        title = EncryptedCharField(max_length=100, null=True)
        pages = EncryptedIntegerField(null=True)

        class Meta:
            app_label = "tests"

    return Document


@pytest.mark.parametrize("lookup,value", REFUSED_LOOKUPS, ids=[name for name, _ in REFUSED_LOOKUPS])
def test_value_lookup_is_refused(lookup, value):
    model = _document_model()
    with pytest.raises(FieldError, match="cannot be looked up by value"):
        model.objects.filter(**{f"title__{lookup}": value})


def test_implicit_exact_is_refused():
    model = _document_model()
    with pytest.raises(FieldError, match="cannot be looked up by value"):
        model.objects.filter(title="Report")


def test_refusal_names_the_field_and_the_supported_lookups():
    model = _document_model()
    with pytest.raises(FieldError) as caught:
        model.objects.filter(title="Report")
    message = str(caught.value)
    assert "tests.Document.title" in message
    assert "__isnull" in message


def test_typed_field_is_refused_too():
    """A declared type is no help: the column holds ciphertext either way."""
    model = _document_model()
    with pytest.raises(FieldError, match="cannot be looked up by value"):
        model.objects.filter(pages__gt=10)


def test_isnull_is_served():
    """A NULL column is a NULL column — and the rotation walk filters on it."""
    model = _document_model()
    sql = str(model.objects.filter(title__isnull=False).query)
    assert "title" in sql
