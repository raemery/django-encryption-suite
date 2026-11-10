"""What the digest's storage looks like to the database, and to two families at once.

The point of moving a digest out of the ciphertext column was that a database can
index it. These assert that it does — on the query plan, not by reading the DDL
and inferring — and that the names the field generates cannot collide.
"""

from __future__ import annotations

import pytest
from django.db import connection, models

from encryption_suite.fields import CONSTRAINT_NAME_MAX, EncryptedCharField


class Searched(models.Model):
    """A column asking for an index, and one asking for uniqueness."""

    team = models.ForeignKey("auth.Group", on_delete=models.CASCADE, related_name="+")
    handle = EncryptedCharField(max_length=100, null=True, blank=True, blind_index=True, db_index=True)
    label = EncryptedCharField(max_length=100, null=True, blank=True, blind_index=True, unique_in_silo=True)

    class Meta:
        app_label = "tests"


class BothFamilies(models.Model):
    """One model, one column under the system silo's key and one under the silo's."""

    team = models.ForeignKey("auth.Group", on_delete=models.CASCADE, related_name="+")
    account = EncryptedCharField(key_set="system", max_length=100, null=True, blank=True, blind_index=True, unique=True)
    note = EncryptedCharField(max_length=100, null=True, blank=True, blind_index=True, unique_in_silo=True)

    class Meta:
        app_label = "tests"


class LongPrefixes(models.Model):
    """Two names that share everything a blind truncation would have kept."""

    team = models.ForeignKey("auth.Group", on_delete=models.CASCADE, related_name="+")
    correspondence_address_line_one_of_the_recipient = EncryptedCharField(
        max_length=50, null=True, blank=True, blind_index=True, unique_in_silo=True
    )
    correspondence_address_line_two_of_the_recipient = EncryptedCharField(
        max_length=50, null=True, blank=True, blind_index=True, unique_in_silo=True
    )

    class Meta:
        app_label = "tests"


def _table(model):
    with connection.schema_editor() as editor:
        editor.create_model(model)
    return model


@pytest.fixture
def searched(transactional_db):
    _table(Searched)
    yield Searched
    with connection.schema_editor() as editor:
        editor.delete_model(Searched)


@pytest.fixture
def both(transactional_db):
    _table(BothFamilies)
    yield BothFamilies
    with connection.schema_editor() as editor:
        editor.delete_model(BothFamilies)


# ---------------------------------------------------------------------------
# The index is used, not merely created
# ---------------------------------------------------------------------------


def _plan(queryset):
    with connection.cursor() as cursor:
        sql, params = queryset.query.sql_with_params()
        cursor.execute(f"EXPLAIN QUERY PLAN {sql}", params)
        return " ".join(str(column) for row in cursor.fetchall() for column in row)


def test_a_lookup_uses_the_digest_index(searched, silo_context):
    searched.objects.create(team=silo_context, handle="ann")

    plan = _plan(searched.objects.filter(handle="ann"))

    # The whole reason the digest left the ciphertext column.
    assert "USING INDEX" in plan.upper(), plan
    assert "handle_index" in plan


def test_a_uniqueness_lookup_uses_the_constraint_index(searched, silo_context):
    searched.objects.create(team=silo_context, label="ann")

    plan = _plan(searched.objects.filter(label="ann"))

    assert "USING INDEX" in plan.upper(), plan


def test_a_scan_is_what_an_unindexed_digest_gets(searched, silo_context):
    """The control: a digest column nobody asked to index is still searched, slowly."""
    from tests.test_silo_blind_index import Indexed

    _table(Indexed)
    try:
        Indexed.objects.create(team=silo_context, handle="ann")
        plan = _plan(Indexed.objects.filter(handle="ann"))
    finally:
        with connection.schema_editor() as editor:
            editor.delete_model(Indexed)

    assert "SCAN" in plan.upper(), plan


# ---------------------------------------------------------------------------
# Names that cannot collide
# ---------------------------------------------------------------------------


def test_two_long_shared_prefixes_get_distinct_constraint_names():
    first, second = (
        LongPrefixes._meta.get_field("correspondence_address_line_one_of_the_recipient"),
        LongPrefixes._meta.get_field("correspondence_address_line_two_of_the_recipient"),
    )

    one, two = first.unique_constraint().name, second.unique_constraint().name

    # Both truncated, both inside the limit, and not the same string — a blind
    # cut would have produced one name twice, and the second constraint would
    # have collided with the first rather than being created.
    assert one != two
    assert len(one) == len(two) == CONSTRAINT_NAME_MAX
    assert one[:40] == two[:40]


def test_both_constraints_reach_the_schema(transactional_db):
    """A collision would mean the second constraint silently never existing."""
    with connection.schema_editor() as editor:
        editor.create_model(LongPrefixes)
    try:
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT sql FROM sqlite_master WHERE type='table' AND name=%s",
                [LongPrefixes._meta.db_table],
            )
            created = cursor.fetchone()[0]
    finally:
        with connection.schema_editor() as editor:
            editor.delete_model(LongPrefixes)

    for field_name in (
        "correspondence_address_line_one_of_the_recipient",
        "correspondence_address_line_two_of_the_recipient",
    ):
        assert LongPrefixes._meta.get_field(field_name).unique_constraint().name in created


# ---------------------------------------------------------------------------
# Both families on one model
# ---------------------------------------------------------------------------


def test_one_model_carries_both_families_and_both_work(both, silo_context):
    row = both.objects.create(team=silo_context, account="ann", note="secret")

    # One from a key in the settings, one from the silo's own key.
    assert both.objects.get(account="ann").pk == row.pk
    assert both.objects.get(note="secret").pk == row.pk
    assert both._meta.get_field("account").index_digest("ann") != both._meta.get_field("note").index_digest("ann")


def test_the_validate_unique_wrapper_is_installed_once_and_covers_both(both, silo_context):
    from django.core.exceptions import ValidationError

    both.objects.create(team=silo_context, account="ann", note="secret")

    with pytest.raises(ValidationError) as caught:
        both(team=silo_context, account="ann", note="other").full_clean()
    assert "account" in caught.value.error_dict

    with pytest.raises(ValidationError) as caught:
        both(team=silo_context, account="other", note="secret").full_clean()
    assert "note" in caught.value.error_dict


def test_each_family_contributes_its_own_digest_column(both):
    names = [f.name for f in both._meta.local_fields]

    assert "account_index" in names
    assert "note_index" in names
    assert len([c for c in both._meta.constraints]) == 2
