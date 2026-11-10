"""``key_set="system"`` columns: what they store, what can be looked up, what cannot.

They share every mechanism with the silo columns except the silo, so what is worth
pinning here is the part that differs. Three things:

* they work with no silo in context, which is why they exist;
* a blind index makes exact lookups work, and the field refuses every lookup it
  cannot serve rather than quietly matching nothing;
* ``unique=True`` is enforced by the database over the index, because a
  uniqueness rule over ciphertext could never fire.
"""

from __future__ import annotations

import datetime

import pytest
from django.core.exceptions import FieldError, ValidationError
from django.db import IntegrityError, connection, models, transaction

from encryption_suite import allow_plaintext_writes
from encryption_suite._internal import raw_cursor_fetch
from encryption_suite.engine import is_silo_value
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

# Transient, like the other models declared across the suite: never registered
# with an installed app, so nothing enumerating installed models sees them.


class Account(models.Model):
    """Everything a system column can hold, plus the two indexed columns."""

    email = EncryptedEmailField(key_set="system", blind_index=True, normalize="casefold", null=True)
    handle = EncryptedCharField(key_set="system", max_length=150, unique=True, blind_index=True, null=True)
    note = EncryptedTextField(key_set="system", null=True)
    site = EncryptedURLField(key_set="system", null=True)
    number = EncryptedIntegerField(key_set="system", null=True)
    day = EncryptedDateField(key_set="system", null=True)
    moment = EncryptedDateTimeField(key_set="system", null=True)
    payload = EncryptedJSONField(key_set="system", null=True)

    class Meta:
        app_label = "tests"


@pytest.fixture
def accounts(db):
    with connection.schema_editor() as editor:
        editor.create_model(Account)
    try:
        yield Account
    finally:
        with connection.schema_editor() as editor:
            editor.delete_model(Account)


VALUES = {
    "email": "Ann@Example.com",
    "handle": "ann",
    "note": "a longer body",
    "site": "https://example.com/",
    "number": 42,
    "day": datetime.date(2026, 10, 4),
    "moment": datetime.datetime(2026, 10, 4, 12, 30, tzinfo=datetime.UTC),
    "payload": {"roles": ["admin"], "seats": 3},
}


# ---------------------------------------------------------------------------
# Storage
# ---------------------------------------------------------------------------


@pytest.mark.django_db(transaction=True)
def test_every_type_reads_back_what_was_saved(accounts):
    row = accounts.objects.create(**VALUES)

    loaded = accounts.objects.get(pk=row.pk)
    assert {name: getattr(loaded, name) for name in VALUES} == VALUES


@pytest.mark.django_db(transaction=True)
def test_nothing_readable_reaches_the_column(accounts):
    accounts.objects.create(**VALUES)

    stored = raw_cursor_fetch(accounts, accounts.objects.get().pk, ["email", "note"])
    assert all(is_silo_value(value) for value in stored)
    assert "example.com" not in stored[0]


@pytest.mark.django_db(transaction=True)
def test_no_silo_is_needed(accounts):
    """The reason these columns exist: a user belongs to no silo, and signing in reads them.

    Nothing in this test enters a silo context, and a silo column would refuse.
    """
    row = accounts.objects.create(email="ann@example.com")

    assert accounts.objects.get(pk=row.pk).email == "ann@example.com"


@pytest.mark.django_db(transaction=True)
def test_a_plaintext_value_is_handed_back_as_it_stands(accounts):
    """What lets an existing column be converted in place rather than all at once."""
    row = accounts.objects.create(email="ann@example.com")
    with allow_plaintext_writes():
        accounts.objects.filter(pk=row.pk).update(note="never encrypted")

    assert accounts.objects.get(pk=row.pk).note == "never encrypted"


# ---------------------------------------------------------------------------
# Looking a value up
# ---------------------------------------------------------------------------


@pytest.mark.django_db(transaction=True)
def test_an_exact_lookup_finds_the_row(accounts):
    row = accounts.objects.create(email="ann@example.com", handle="ann")

    assert accounts.objects.get(email="ann@example.com").pk == row.pk
    assert accounts.objects.get(handle="ann").pk == row.pk


@pytest.mark.django_db(transaction=True)
def test_casefolding_makes_the_lookup_case_insensitive(accounts):
    row = accounts.objects.create(email="Ann@Example.com")

    assert accounts.objects.get(email="ann@example.com").pk == row.pk
    assert accounts.objects.get(email__iexact="ANN@EXAMPLE.COM").pk == row.pk


@pytest.mark.django_db(transaction=True)
def test_without_casefolding_the_lookup_is_case_sensitive(accounts):
    accounts.objects.create(handle="Ann")

    assert not accounts.objects.filter(handle="ann").exists()
    assert accounts.objects.filter(handle="Ann").exists()


@pytest.mark.django_db(transaction=True)
def test_an_in_lookup_finds_every_match(accounts):
    accounts.objects.create(email="ann@example.com")
    accounts.objects.create(email="bob@example.com")
    accounts.objects.create(email="cal@example.com")

    found = accounts.objects.filter(email__in=["ann@example.com", "CAL@example.com"])
    assert found.count() == 2


@pytest.mark.django_db(transaction=True)
def test_an_empty_in_lookup_matches_nothing(accounts):
    accounts.objects.create(email="ann@example.com")

    assert not accounts.objects.filter(email__in=[]).exists()


@pytest.mark.django_db(transaction=True)
def test_isnull_needs_no_index(accounts):
    accounts.objects.create(email="ann@example.com", note=None)

    assert accounts.objects.filter(note__isnull=True).count() == 1
    assert accounts.objects.filter(email__isnull=False).count() == 1


@pytest.mark.django_db(transaction=True)
def test_a_lookup_the_index_cannot_serve_is_refused(accounts):
    # Matching nothing would read as "no such user", which is the answer that
    # quietly breaks a sign-in.
    with pytest.raises(FieldError, match="__exact, __iexact, __in and __isnull"):
        accounts.objects.filter(email__contains="example").exists()


@pytest.mark.django_db(transaction=True)
def test_a_column_without_an_index_cannot_be_looked_up(accounts):
    with pytest.raises(FieldError, match="no blind index"):
        accounts.objects.filter(note="a longer body").exists()


def test_iexact_without_casefolding_is_refused():
    field = EncryptedCharField(key_set="system", blind_index=True)
    field.contribute_to_class(Account, "unfolded", private_only=True)

    with pytest.raises(FieldError, match="normalize='casefold'"):
        field.get_lookup("iexact")


@pytest.mark.django_db(transaction=True)
def test_a_lookup_by_none_asks_about_the_column(accounts):
    """Django rewrites ``=None`` to ``__isnull=True`` before a lookup sees it."""
    accounts.objects.create(email=None, note="no address")

    assert accounts.objects.filter(email=None).count() == 1


@pytest.mark.django_db(transaction=True)
def test_none_among_the_values_of_an_in_lookup_says_to_use_isnull(accounts):
    # This one does reach the lookup, and there is no index for "no value".
    with pytest.raises(FieldError, match="__isnull=True"):
        accounts.objects.filter(email__in=["ann@example.com", None]).exists()


# ---------------------------------------------------------------------------
# Uniqueness, which the database holds over the index
# ---------------------------------------------------------------------------


@pytest.mark.django_db(transaction=True)
def test_the_database_refuses_a_duplicate_value(accounts):
    accounts.objects.create(handle="ann")

    # The column's own ciphertext differs every time, so this can only be the
    # constraint over the blind index.
    with pytest.raises(IntegrityError), transaction.atomic():
        accounts.objects.create(handle="ann")


@pytest.mark.django_db(transaction=True)
def test_model_validation_reports_a_duplicate_before_the_database_does(accounts):
    accounts.objects.create(handle="ann")

    with pytest.raises(ValidationError):
        accounts(handle="ann").validate_unique()


def test_the_constraint_covers_the_digest_column_and_nothing_else():
    field = Account._meta.get_field("handle")
    constraint = field.unique_constraint()

    assert constraint in Account._meta.constraints
    # Plain fields, no expression and no condition: an expression constraint is
    # what MariaDB cannot take and Django skips in silence.
    assert constraint.fields == (field.index_field_name,)
    assert not constraint.expressions
    assert constraint.condition is None


# ---------------------------------------------------------------------------
# Deploy-time checks
# ---------------------------------------------------------------------------


def test_unique_without_a_blind_index_is_refused():
    field = EncryptedCharField(key_set="system", max_length=10, unique=True)

    assert [error.id for error in field._check_blind_index()] == ["encryption_suite.E026"]


def test_db_index_without_a_blind_index_is_refused():
    field = EncryptedCharField(key_set="system", max_length=10, db_index=True)

    assert [error.id for error in field._check_blind_index()] == ["encryption_suite.E027"]


def test_an_unknown_normalize_is_refused_at_declaration():
    with pytest.raises(ValueError, match="normalize must be"):
        EncryptedCharField(key_set="system", max_length=10, normalize="upper")


def _store_check_ids(monkeypatch, settings, *, env_stores, models_seen):
    """Run the key store check against a chosen set of models, with the env stores as the only stores."""
    from django.apps import apps

    from encryption_suite.checks import check_kms_settings

    settings.ENCRYPTION = {
        **settings.ENCRYPTION,
        "KMS_KEY_STORES": {},
        "ENV_KEY_STORES": env_stores,
        "KEY_SETS": {},
    }
    monkeypatch.setattr(apps, "get_models", lambda: models_seen)
    return [error.id for error in check_kms_settings(None)]


def test_a_configured_store_passes_the_deploy_check(monkeypatch, settings):
    configured = settings.ENCRYPTION["ENV_KEY_STORES"]
    assert _store_check_ids(monkeypatch, settings, env_stores=configured, models_seen=[Account]) == []


def test_a_project_declaring_no_system_column_needs_no_store(monkeypatch, settings):
    assert _store_check_ids(monkeypatch, settings, env_stores={}, models_seen=[]) == []


def test_no_store_fails_the_deploy_where_system_columns_are_declared(monkeypatch, settings):
    # Reported now rather than at the first sign-in.
    assert _store_check_ids(monkeypatch, settings, env_stores={}, models_seen=[Account]) == ["encryption_suite.E038"]


def test_a_blank_system_field_need_not_be_nullable():
    """E025 is about a silo column, and says so by not firing here.

    Django fills a blank, non-nullable column with "" — which for a silo column
    arrives without passing through the engine and cannot be told from a value
    awaiting encryption. Settling that needs a silo per row; here it needs none,
    so an empty string is an ordinary value. CustomUser.email depends on it:
    allauth writes "" there when a user has no address left.
    """
    field = EncryptedCharField(key_set="system", max_length=10, blank=True)
    field.contribute_to_class(Account, "optional", private_only=True)

    assert [error.id for error in field.check()] == []
