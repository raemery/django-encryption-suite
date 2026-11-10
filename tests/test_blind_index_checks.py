"""What the deploy-time checks say about a blind index, and what they stay quiet about.

The registry-walking checks are asked of a chosen set of models: the suite's
transient models are declared under an app that is deliberately not installed, so
``apps.get_models`` cannot see them by itself.
"""

from __future__ import annotations

import pytest
from django.contrib import admin
from django.db import models

from encryption_suite.checks import (
    check_ordering_by_an_encrypted_field,
    check_table_level_rules_over_encrypted_columns,
)
from encryption_suite.fields import EncryptedCharField, EncryptedDateField


class SiloIndexed(models.Model):
    team = models.ForeignKey("auth.Group", on_delete=models.CASCADE, related_name="+")
    handle = EncryptedCharField(max_length=100, null=True, blank=True, blind_index=True, unique_in_silo=True)
    born = EncryptedDateField(null=True, blank=True, blind_index=True)

    class Meta:
        app_label = "tests"


class Composite(models.Model):
    team = models.ForeignKey("auth.Group", on_delete=models.CASCADE, related_name="+")
    title = EncryptedCharField(max_length=100, null=True, blank=True)

    class Meta:
        app_label = "tests"
        unique_together = [("team", "title")]
        constraints = [models.UniqueConstraint(fields=["title"], name="tests_composite_unique_title")]


class BoundedComposite(models.Model):
    team = models.ForeignKey("auth.Group", on_delete=models.CASCADE, related_name="+")
    email = EncryptedCharField(max_length=100, null=True, blank=True, varchar_column=True)

    class Meta:
        app_label = "tests"
        unique_together = [("team", "email")]
        constraints = [models.UniqueConstraint(fields=["email"], name="tests_boundedcomposite_unique_email")]


class Plain(models.Model):
    team = models.ForeignKey("auth.Group", on_delete=models.CASCADE, related_name="+")
    label = models.CharField(max_length=100)
    secret = EncryptedCharField(max_length=100, null=True, blank=True)

    class Meta:
        app_label = "tests"
        unique_together = [("team", "label")]


@pytest.fixture
def seen(monkeypatch):
    """Point the registry walk at a chosen set of models."""
    from django.apps import apps

    def _use(*chosen):
        # Keyword-tolerant: Django's own internals call get_models with
        # include_auto_created while resolving related objects.
        monkeypatch.setattr(apps, "get_models", lambda **kwargs: list(chosen))

    return _use


# ---------------------------------------------------------------------------
# No check refuses an index by field type
# ---------------------------------------------------------------------------


def test_a_date_may_carry_an_index(seen):
    """Which columns repeat too often to index is the declaring developer's call."""
    field = SiloIndexed._meta.get_field("born")

    assert field.blind_index
    assert field._check_blind_index() == []


# ---------------------------------------------------------------------------
# Uniqueness spelled the wrong way, and spelled with nothing to enforce it
# ---------------------------------------------------------------------------


def test_the_django_spelling_is_refused_on_a_silo_field():
    field = EncryptedCharField(max_length=10, blind_index=True, unique=True)
    field.contribute_to_class(SiloIndexed, "spelled_wrong")

    errors = field._check_blind_index()

    assert [e.id for e in errors] == ["encryption_suite.E026"]
    assert "unique_in_silo=True" in errors[0].hint


def test_uniqueness_without_an_index_is_refused_in_either_spelling():
    silo = EncryptedCharField(max_length=10, unique_in_silo=True)
    silo.contribute_to_class(SiloIndexed, "unindexed_silo")
    system = EncryptedCharField(key_set="system", max_length=10, unique=True)
    system.contribute_to_class(SiloIndexed, "unindexed_system")

    assert "unique_in_silo=True without a blind index" in silo._check_blind_index()[0].msg
    assert "unique=True without a blind index" in system._check_blind_index()[0].msg


# ---------------------------------------------------------------------------
# Ordering (W055)
# ---------------------------------------------------------------------------


def test_ordering_by_an_encrypted_column_is_warned_about(seen):
    seen(SiloIndexed)
    SiloIndexed._meta.ordering = ["handle"]
    try:
        warnings = check_ordering_by_an_encrypted_field(None)
    finally:
        SiloIndexed._meta.ordering = []

    assert [w.id for w in warnings] == ["encryption_suite.W055"]


def test_an_admin_ordering_by_an_encrypted_column_is_warned_about(seen):
    class SiloIndexedAdmin(admin.ModelAdmin):
        ordering = ["-handle"]

    seen()
    admin.site.register(SiloIndexed, SiloIndexedAdmin)
    try:
        ids = [w.id for w in check_ordering_by_an_encrypted_field(None)]
    finally:
        admin.site.unregister(SiloIndexed)

    assert ids == ["encryption_suite.W055"]


def test_ordering_by_a_plaintext_column_is_not_warned_about(seen):
    seen(Plain)
    Plain._meta.ordering = ["label"]
    try:
        assert check_ordering_by_an_encrypted_field(None) == []
    finally:
        Plain._meta.ordering = []


# ---------------------------------------------------------------------------
# Table-level rules (W056)
# ---------------------------------------------------------------------------


def test_unique_together_over_an_encrypted_column_is_warned_about(seen):
    seen(Composite)

    warnings = check_table_level_rules_over_encrypted_columns(None)

    assert [w.id for w in warnings] == ["encryption_suite.W056"]
    assert "'title'" in warnings[0].msg
    assert "unique_together" in warnings[0].msg


def test_every_rule_on_a_model_is_reported_in_one_warning(seen):
    seen(Composite)

    warnings = check_table_level_rules_over_encrypted_columns(None)

    assert len(warnings) == 1
    assert "Meta.unique_together ('title')" in warnings[0].msg
    assert "Meta.constraints['tests_composite_unique_title'] ('title')" in warnings[0].msg


def test_a_rule_over_a_varchar_column_is_not_warned_about(seen):
    """The column was bounded for a rule in a Meta the project cannot edit; nothing is left to do."""
    seen(BoundedComposite)

    assert check_table_level_rules_over_encrypted_columns(None) == []


def test_the_digest_columns_own_constraint_is_not_warned_about(seen):
    """The field contributes a UniqueConstraint over handle_index, which works."""
    seen(SiloIndexed)

    assert [c.name for c in SiloIndexed._meta.constraints]
    assert check_table_level_rules_over_encrypted_columns(None) == []


def test_a_rule_over_plaintext_columns_is_not_warned_about(seen):
    seen(Plain)

    assert check_table_level_rules_over_encrypted_columns(None) == []
