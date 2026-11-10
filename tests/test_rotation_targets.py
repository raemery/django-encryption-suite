"""Finding a silo's rows, and what happens when that cannot be done.

Also the pieces a rotation leans on outside the command: the silo adapter's
lookup hooks, the two system checks, and the funnel's status alternatives.
"""

from __future__ import annotations

import pytest
from django.core.management.base import CommandError
from django.db import models

from encryption_suite import lifecycle, rotation_targets
from encryption_suite.adapters.silos.base import AbstractSiloAdapter
from encryption_suite.checks import check_log_aad_values, check_silo_data_lookup
from encryption_suite.exceptions import EncryptionConfigurationError
from encryption_suite.fields import EncryptedTextField
from encryption_suite.models import DekRotation
from encryption_suite.registry import get_silo_adapter
from tests.factories import make_kek_row
from tests.rotation_helpers import dek, make_note, make_team, run, uid
from tests.testapp.models import Document, HiddenNote, Note

# Transient models, never registered with an installed app, so nothing that
# enumerates installed models ever sees them outside the tests that pass them in.


class Unanchored(models.Model):
    secret = EncryptedTextField(null=True)

    class Meta:
        app_label = "tests"


class TwoAnchors(models.Model):
    first = models.ForeignKey("auth.Group", on_delete=models.CASCADE, related_name="+")
    second = models.ForeignKey("auth.Group", on_delete=models.CASCADE, related_name="+")
    secret = EncryptedTextField(null=True)

    class Meta:
        app_label = "tests"


@pytest.fixture(autouse=True)
def _clear_cache():
    from encryption_suite.engine import EncryptionEngine

    # Silo UIDs repeat across tests as primary keys are reused, and a primitive
    # cached by an earlier test would skip provisioning this one's key.
    EncryptionEngine.invalidate_cache()
    yield
    EncryptionEngine.invalidate_cache()


def _discovered(model):
    return [entry for entry in rotation_targets.encrypted_models() if entry[0] is model]


# ---------------------------------------------------------------------------
# Resolution
# ---------------------------------------------------------------------------


def test_installed_models_resolve_through_their_one_foreign_key():
    resolution = rotation_targets.resolve_targets(get_silo_adapter())

    by_label = {t.label: t for t in resolution.targets}
    assert not resolution.unresolved
    assert by_label["testapp.Note"].fk_name == "team"
    assert by_label["testapp.Note"].field_names == ("title", "body")
    assert by_label["testapp.Document"].file_names == ("upload",)
    # A file's display name is an ordinary encrypted field and rotates with them.
    assert by_label["testapp.Document"].field_names == ("upload_name",)
    assert "testapp.HiddenNote" in by_label


def test_a_model_with_no_foreign_key_to_the_silo_is_unresolved():
    resolution = rotation_targets.resolve_targets(get_silo_adapter(), models=[(Unanchored, ("secret",), (), ())])

    assert resolution.unresolved == [("tests.Unanchored", "no foreign key to auth.Group")]


def test_a_model_with_two_foreign_keys_to_the_silo_is_unresolved():
    resolution = rotation_targets.resolve_targets(get_silo_adapter(), models=[(TwoAnchors, ("secret",), (), ())])

    assert resolution.unresolved == [("tests.TwoAnchors", "more than one foreign key to auth.Group")]


class _NoLabelAdapter(AbstractSiloAdapter):
    def get_current_silo(self):
        return None

    def get_silo_uid(self, silo):
        return f"x-{silo.pk}"

    def get_silo_label(self):
        return "x"


class _LookupAdapter(_NoLabelAdapter):
    supports_silo_data_lookup = True

    def queryset_for_silo(self, model, silo_uid):
        return model._base_manager.none()


def test_an_adapter_without_a_model_label_resolves_nothing_by_itself():
    resolution = rotation_targets.resolve_targets(_NoLabelAdapter(), models=[(Unanchored, ("secret",), (), ())])

    assert resolution.unresolved == [("tests.Unanchored", "the silo adapter declares no model_label")]


def test_an_adapter_that_declares_a_lookup_answers_where_introspection_cannot():
    resolution = rotation_targets.resolve_targets(_LookupAdapter(), models=[(Unanchored, ("secret",), (), ())])

    (target,) = resolution.targets
    assert target.fk_name is None and not resolution.unresolved
    assert not resolution.needs_silo_object


def test_rows_are_looked_up_through_the_base_manager(db):
    team = make_team()
    hidden = HiddenNote._base_manager.create(team=team, hidden=True)
    target = next(t for t in rotation_targets.resolve_targets(get_silo_adapter()).targets if t.model is HiddenNote)

    rows = rotation_targets.rows_for_silo(get_silo_adapter(), target, uid(team), team)

    assert list(rows.values_list("pk", flat=True)) == [hidden.pk]


# ---------------------------------------------------------------------------
# The command refuses before any fence
# ---------------------------------------------------------------------------


def test_an_unresolvable_model_stops_the_run_before_the_fence(db, monkeypatch):
    team = make_team()
    make_note(team)
    real = list(rotation_targets.encrypted_models())
    monkeypatch.setattr(
        rotation_targets, "encrypted_models", lambda key_set="default": [*real, (Unanchored, ("secret",), (), ())]
    )

    with pytest.raises(CommandError, match="tests.Unanchored"):
        run("--silo-uid", uid(team))

    assert dek(team).status == lifecycle.STATUS_ACTIVE
    assert not DekRotation.objects.exists()


def test_a_dry_run_names_the_unresolvable_model_and_writes_nothing(db, monkeypatch):
    team = make_team()
    make_note(team)
    real = list(rotation_targets.encrypted_models())
    monkeypatch.setattr(
        rotation_targets, "encrypted_models", lambda key_set="default": [*real, (Unanchored, ("secret",), (), ())]
    )

    output = run("--silo-uid", uid(team), "--dry-run")

    assert "Unresolved: tests.Unanchored (no foreign key to auth.Group)" in output
    assert not DekRotation.objects.exists()


def test_a_run_over_every_silo_needs_an_adapter_that_can_list_them(db, monkeypatch):
    monkeypatch.setattr(type(get_silo_adapter()), "supports_enumeration", False)

    with pytest.raises(CommandError, match="--silo-uid"):
        run()


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------


def test_the_deploy_check_warns_and_names_what_it_cannot_resolve(monkeypatch):
    real = list(rotation_targets.encrypted_models())
    monkeypatch.setattr(
        rotation_targets, "encrypted_models", lambda key_set="default": [*real, (Unanchored, ("secret",), (), ())]
    )

    (warning,) = check_silo_data_lookup(None)

    assert warning.id == "encryption_suite.W053"
    assert "tests.Unanchored" in warning.msg


def test_the_deploy_check_is_silent_when_every_model_resolves():
    assert check_silo_data_lookup(None) == []


@pytest.mark.parametrize("value", ["False", 1, None])
def test_log_aad_values_must_be_a_real_boolean(settings, value):
    settings.ENCRYPTION = {**settings.ENCRYPTION, "LOG_AAD_VALUES": value}

    (error,) = check_log_aad_values(None)

    assert error.id == "encryption_suite.E032"


def test_log_aad_values_accepts_a_boolean(settings):
    settings.ENCRYPTION = {**settings.ENCRYPTION, "LOG_AAD_VALUES": True}
    assert check_log_aad_values(None) == []


# ---------------------------------------------------------------------------
# Silo adapter hooks
# ---------------------------------------------------------------------------


def test_declaring_the_lookup_without_implementing_it_is_a_configuration_fault():
    class Declared(_NoLabelAdapter):
        supports_silo_data_lookup = True

    with pytest.raises(EncryptionConfigurationError) as info:
        Declared().queryset_for_silo(Note, "x-1")
    assert "queryset_for_silo" in info.value.detail


def test_the_default_silo_context_does_nothing():
    with _NoLabelAdapter().use_silo("x-1"):
        pass


def test_the_default_reverse_lookup_cannot_say_without_enumeration():
    assert _NoLabelAdapter().silo_for_uid("x-1") is None


def test_the_generic_adapter_reverses_its_own_uid(db):
    team = make_team()
    adapter = get_silo_adapter()

    assert adapter.silo_for_uid(uid(team)) == team
    assert adapter.silo_for_uid("group-not-a-number") is None
    assert adapter.silo_for_uid("other-1") is None
    assert adapter.silo_exists(uid(team)) is True
    assert adapter.silo_exists("group-999999") is False


# ---------------------------------------------------------------------------
# The funnel's status alternatives
# ---------------------------------------------------------------------------


def test_an_alternative_status_must_be_one_the_verb_lists(db):
    team = make_team()
    make_note(team)

    with pytest.raises(ValueError, match="not an alternative"):
        dek(team).record_event(
            lifecycle.EVENT_ROTATED, trigger=lifecycle.TRIGGER_AUTOMATED, status=lifecycle.STATUS_DELETED
        )


def test_an_alternative_status_must_suit_the_key_kind(db):
    kek = make_kek_row(key_store="local", kek_resource_name="kek-alt")

    with pytest.raises(ValueError, match="not valid for kek"):
        kek.record_event(
            lifecycle.EVENT_RESTORED, trigger=lifecycle.TRIGGER_DIRECT, status=lifecycle.STATUS_REENCRYPTING
        )


def test_the_rotation_verbs_belong_to_data_keys_only(db):
    kek = make_kek_row(key_store="local", kek_resource_name="kek-verbs")

    for verb in (lifecycle.EVENT_ROTATION_STARTED, lifecycle.EVENT_ROTATION_ABANDONED):
        with pytest.raises(ValueError):
            kek.record_event(verb, trigger=lifecycle.TRIGGER_AUTOMATED)
    assert lifecycle.EVENT_ROTATED in lifecycle.KEK_EVENTS and lifecycle.EVENT_ROTATED in lifecycle.DEK_EVENTS
    assert not {lifecycle.EVENT_ROTATION_STARTED, lifecycle.EVENT_ROTATION_ABANDONED} & lifecycle.MANUAL_DEK_EVENTS


def test_documents_and_notes_are_what_the_suite_rotates():
    """Guards the assumption the rotation tests rest on."""
    assert _discovered(Note) and _discovered(Document)
    assert not _discovered(Unanchored)
