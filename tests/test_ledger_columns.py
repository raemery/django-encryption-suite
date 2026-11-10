"""The ledger's Event and Reason columns: the translated words, then the code.

Log lines name an act by its code (``event=``, ``reason=``) and are always in
English, so the code beside the label is how a reader of the admin, in any
language, finds the matching line. The trigger has no log counterpart, but the
docs describe triggers by their codes, so it carries its code too.
"""

from __future__ import annotations

from types import SimpleNamespace

from django.utils import translation

from encryption_suite import lifecycle
from encryption_suite.admin_lifecycle import (
    DekEventInline,
    EventColumnMixin,
    KeyLifecycleEventAdmin,
    ReasonColumnMixin,
)


def _event(event="", reason="", trigger=""):
    label = dict(lifecycle.EVENT_CHOICES).get(event, event)
    trigger_label = dict(lifecycle.TRIGGER_CHOICES).get(trigger, trigger)
    return SimpleNamespace(
        event=event,
        reason=reason,
        trigger=trigger,
        get_event_display=lambda: label,
        get_trigger_display=lambda: trigger_label,
    )


def test_the_trigger_column_shows_the_label_then_the_code():
    row = _event(trigger=lifecycle.TRIGGER_AUTOMATED)
    assert EventColumnMixin().trigger_label(row) == "Script or schedule (automated)"


def test_the_event_column_shows_the_label_then_the_verb():
    row = _event(event=lifecycle.EVENT_ROTATION_ABANDONED)
    assert EventColumnMixin().event_label(row) == "Rotation abandoned (rotation_abandoned)"


def test_the_code_stays_english_when_the_label_is_translated():
    row = _event(event=lifecycle.EVENT_DELETED)
    with translation.override("de"):
        assert EventColumnMixin().event_label(row) == "Gelöscht (deleted)"


def test_the_reason_column_shows_the_label_then_the_slug():
    row = _event(reason=lifecycle.REASON_DEK_DELETED)
    assert ReasonColumnMixin().reason_label(row) == "The data encryption key was deleted (dek_deleted)"


def test_an_empty_reason_stays_empty():
    assert ReasonColumnMixin().reason_label(_event()) == ""


def test_a_reason_with_no_label_renders_once():
    row = _event(reason="provider said no")
    assert ReasonColumnMixin().reason_label(row) == "provider said no"


def test_a_keys_history_reads_oldest_first_and_the_changelist_newest_first():
    """Two questions, two orders: how this key got here, against what happened lately."""
    # ``pk`` breaks the tie between events one transaction wrote at the same instant.
    assert DekEventInline.ordering == ("created_at", "pk")
    assert KeyLifecycleEventAdmin.ordering == ("-created_at",)


def test_the_ledger_detail_page_reads_like_its_row():
    """Same columns, same order, same display methods — so the codes are there too."""
    detail = KeyLifecycleEventAdmin.fields
    assert {"event_label", "trigger_label", "reason_label"} <= set(detail)
    assert not {"event", "trigger", "reason"} & set(detail)
    # Everything shown is read-only: the ledger is append-only.
    assert KeyLifecycleEventAdmin.readonly_fields == detail
    # The row's own timestamp, which an editable-fields form would leave out.
    assert "created_at" in detail


def test_both_views_show_the_coded_columns():
    for columns in (KeyLifecycleEventAdmin.list_display, DekEventInline.fields):
        assert {"event_label", "trigger_label", "reason_label"} <= set(columns)
        assert not {"event", "trigger"} & set(columns)
    # Filtering still works on the stored codes.
    assert {"event", "trigger"} <= set(KeyLifecycleEventAdmin.list_filter)
