"""Every encrypted field stores its ciphertext as text, whatever its declared type."""

from __future__ import annotations

import datetime
from types import SimpleNamespace

import pytest
from django.contrib.auth.models import Group
from django.core.exceptions import ValidationError
from django.db import connection, models
from django.test.utils import isolate_apps

from encryption_suite.adapters.silos.context import override_current_silo
from encryption_suite.fields import (
    EncryptedCharField,
    EncryptedDateField,
    EncryptedDateTimeField,
    EncryptedEmailField,
    EncryptedIntegerField,
    EncryptedJSONField,
    EncryptedTextField,
    EncryptedURLField,
)
from tests.rotation_helpers import make_team

ENCRYPTED_FIELDS = [
    EncryptedCharField(max_length=10),
    EncryptedTextField(),
    EncryptedEmailField(),
    EncryptedURLField(),
    EncryptedIntegerField(),
    EncryptedDateField(),
    EncryptedDateTimeField(),
    EncryptedJSONField(),
]


@pytest.mark.parametrize("field", ENCRYPTED_FIELDS, ids=lambda field: type(field).__name__)
@pytest.mark.parametrize("text_type", ["text", "longtext", "NCLOB"])
def test_column_type_is_the_backends_text_type(field, text_type):
    fake_connection = SimpleNamespace(data_types={"TextField": text_type}, ops=SimpleNamespace(quote_name=str))
    assert field.db_type(fake_connection) == text_type


@pytest.mark.django_db(transaction=True)
@isolate_apps("tests.testapp")
def test_every_type_reads_back_what_was_saved():
    class EveryType(models.Model):
        team = models.ForeignKey(Group, on_delete=models.CASCADE, related_name="+")
        char = EncryptedCharField(max_length=20, null=True, aad=("team",))
        text = EncryptedTextField(null=True, aad=("team",))
        email = EncryptedEmailField(null=True, aad=("team",))
        url = EncryptedURLField(null=True, aad=("team",))
        number = EncryptedIntegerField(null=True, aad=("team",))
        day = EncryptedDateField(null=True, aad=("team",))
        moment = EncryptedDateTimeField(null=True, aad=("team",))
        payload = EncryptedJSONField(null=True, aad=("team",))

        class Meta:
            app_label = "testapp"

    values = {
        "char": "name",
        "text": "a longer body",
        "email": "ann@example.com",
        "url": "https://example.com/",
        "number": 42,
        "day": datetime.date(2026, 9, 18),
        "moment": datetime.datetime(2026, 9, 18, 12, 30, tzinfo=datetime.UTC),
        "payload": {"email": "ann@example.com", "roles": ["admin", "member"], "seats": 3},
    }
    with connection.schema_editor() as editor:
        editor.create_model(EveryType)
    try:
        team = make_team()
        with override_current_silo(team):
            row = EveryType.objects.create(team=team, **values)
            loaded = EveryType.objects.get(pk=row.pk)
            assert {name: getattr(loaded, name) for name in values} == values
    finally:
        with connection.schema_editor() as editor:
            editor.delete_model(EveryType)


def test_encrypted_integer_keeps_the_integer_range():
    field = EncryptedIntegerField()
    min_value, max_value = connection.ops.integer_field_range("IntegerField")
    field.run_validators(max_value)
    with pytest.raises(ValidationError):
        field.run_validators(max_value + 1)
    with pytest.raises(ValidationError):
        field.run_validators(min_value - 1)
