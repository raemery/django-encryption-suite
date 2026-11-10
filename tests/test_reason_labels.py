"""The ledger's ``reason`` column renders its slug as words.

The stored value stays a stable, language-neutral slug — an audit record read
years from now must not be frozen into the language whoever wrote it happened to
be using. These cover the display layer that turns it back into a sentence, and
the values that are deliberately *not* translated because they never were a
slug.
"""

from __future__ import annotations

from encryption_suite import lifecycle
from encryption_suite.deletion import RETAIN_IN_USE, RETAIN_REASON_TEXT
from encryption_suite.models import KeyLifecycleEvent


def test_a_ledger_reason_renders_its_label():
    assert lifecycle.reason_label(KeyLifecycleEvent.REASON_CONFIRMED_BY_RECONCILE) == "Confirmed by reconcile"


def test_a_retain_slug_reuses_the_text_it_already_had():
    """These were written to the ledger and shown only in purge messages.

    The mapping existed the whole time; nothing but the ledger column was reading
    it, so a retained key reported its reason on one screen and a bare slug on
    another.

    The phrase is lowercase where a message places it inside a sentence. The
    column shows it alone, so it leads with a capital like every other reason.
    """
    assert str(RETAIN_REASON_TEXT[RETAIN_IN_USE]) == "still referenced by another key record"
    assert lifecycle.reason_label(RETAIN_IN_USE) == "Still referenced by another key record"


def test_an_operator_record_renders_its_label():
    assert lifecycle.reason_label(KeyLifecycleEvent.REASON_RECORDED_BY_OPERATOR) == "Recorded by an operator"


def test_an_unmapped_value_is_shown_unchanged():
    """A failed deletion stores the provider's message, not a slug.

    Falling back to the raw value keeps the operator detail visible; swallowing
    it would hide the only account of why the provider refused.
    """
    detail = "AccessDeniedException: user is not authorized to perform kms:ScheduleKeyDeletion"

    assert lifecycle.reason_label(detail) == detail


def test_no_reason_renders_as_empty():
    assert lifecycle.reason_label("") == ""


def test_every_ledger_reason_slug_has_a_label():
    """A slug reaching the ledger with no label renders raw to an operator.

    The failure is silent — the column still shows something — so it needs a
    test rather than a review to catch.
    """
    slugs = {
        value
        for name, value in vars(KeyLifecycleEvent).items()
        if name.startswith("REASON_") and isinstance(value, str)
    }

    assert slugs
    assert slugs <= set(lifecycle.REASON_LABELS)
