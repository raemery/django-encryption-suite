"""Drift guards for the key lifecycle ledger's closed vocabularies.

The ``event``, ``trigger`` and ``reason`` columns each hold a closed slug set.
Nothing in the models enforces that a slug has a label or reaches the field's
``choices`` — membership is a frozenset and the labels are a separate map — so a
slug added to one and not the other renders in the admin as its raw value and
raises nothing. These tests are what catch that.

The combination rules are exercised rather than parsed: the write sites are run
and the rows they produce are checked, so a rule holds however many sites there
are and adding one obliges no edit here.
"""

from __future__ import annotations

import datetime

import pytest
from django.utils import timezone

from encryption_suite import deletion, lifecycle
from encryption_suite.models import DataEncryptionKey, KeyLifecycleEvent
from encryption_suite.silo_ref import SiloRef
from tests.factories import make_dek, make_kek, make_kek_row, make_user

# Frozen source of truth for the reason column. Append-only: never rename or
# reuse a shipped slug, since the ledger is read years after it was written.
EXPECTED_REASONS = {
    "recorded_by_operator",
    "observed_at_provider",
    "confirmed_by_reconcile",
    "determined_by_reconcile",
    "silo_created",
    "silo_deleted",
    "first_encryption",
    "silo_reacquired",
    "failed_at_provider",
    "shared_or_opaque_disposition",
    "provisioner_cannot_delete",
    "not_owned_by_deployment",
    "in_use_by_other_silo",
    "no_provisioner",
    "silo_still_exists",
    "silo_liveness_unknown",
    "silo_check_failed",
    "dek_deleted",
    "unconvertible_rows",
}


def test_the_reason_vocabulary_is_what_this_test_says_it_is():
    added = lifecycle.REASONS - EXPECTED_REASONS
    removed = EXPECTED_REASONS - lifecycle.REASONS
    assert not removed, f"reason slugs are append-only; these went missing: {sorted(removed)}"
    assert not added, f"new reason slugs must be added to this test deliberately: {sorted(added)}"


def test_every_trigger_resolves_to_a_label():
    missing = [t for t in lifecycle.TRIGGERS if t not in lifecycle.TRIGGER_LABELS]
    assert not missing, f"triggers with no label: {missing}"


def test_every_reason_resolves_to_a_label():
    # Through ``reason_label`` so both maps count; it falls back to the raw
    # value, so a miss is a slug that renders as itself.
    missing = [r for r in lifecycle.REASONS if lifecycle.reason_label(r) == r]
    assert not missing, f"reasons with no label: {missing}"


def test_every_event_resolves_to_a_label():
    missing = [e for e in lifecycle.KEK_EVENTS | lifecycle.DEK_EVENTS if e not in lifecycle.EVENT_LABELS]
    assert not missing, f"events with no label: {missing}"


def test_every_trigger_and_reason_reaches_the_field_choices():
    """A constant no site can write, or that the admin cannot show, is invisible."""
    trigger_choices = {value for value, _label in KeyLifecycleEvent._meta.get_field("trigger").choices}
    reason_choices = {value for value, _label in KeyLifecycleEvent._meta.get_field("reason").choices}
    assert lifecycle.TRIGGERS <= trigger_choices
    assert lifecycle.REASONS <= reason_choices


# --- The rules, over the combinations the write sites actually produce -------


@pytest.fixture
def written_rows(db, configured_owner_prefix, monkeypatch):
    """Run a spread of write sites and return every ledger row they wrote."""
    configured_owner_prefix("kek_")
    alice = make_user("alice")
    past = timezone.now() - datetime.timedelta(days=1)

    # An operator attestation, from the admin and the command alike.
    kek = make_kek_row(key_store="fly", kek_resource_name="kek_team1")
    KeyLifecycleEvent.record_by_operator(kek, lifecycle.EVENT_CREATED, user=alice)

    # The silo cascade: a person asked for something else and the keys followed.
    dek = make_dek("team1", kek=kek)
    deletion.schedule_deletion(SiloRef("default", "team1"))

    # An admin action on one row.
    other = make_dek("team2", kek=kek)
    deletion.schedule_dek_deletion(other, trigger=lifecycle.TRIGGER_DIRECT, user=alice)
    deletion.restore_dek(other, trigger=lifecycle.TRIGGER_DIRECT, user=alice)

    # A purge, once its window has run.
    DataEncryptionKey.objects.filter(pk=dek.pk).update(undeletable_until=past)
    deletion.purge_expired_deks(trigger=lifecycle.TRIGGER_DIRECT, user=alice)

    # A refused scheduling.
    deletion.record_refused_scheduling(
        [(other, lifecycle.RETAIN_SILO_LIVE)],
        trigger=lifecycle.TRIGGER_DIRECT,
        user=alice,
    )

    # A maintenance command's identity: automated, named by the OS account.
    kek.record_event(
        lifecycle.EVENT_REENCRYPTED,
        trigger=lifecycle.TRIGGER_AUTOMATED,
        os_login_user="deploy (uid 1000)",
    )
    make_kek("kek_team3", "fly").record_event(
        lifecycle.EVENT_DELETED,
        trigger=lifecycle.TRIGGER_AUTOMATED,
        reason=lifecycle.REASON_CONFIRMED_BY_RECONCILE,
    )

    rows = list(KeyLifecycleEvent.objects.all())
    assert rows, "the write sites produced no rows, so these rules would pass vacuously"
    return rows


def test_an_indirect_event_always_names_the_act_that_caused_it(written_rows):
    """The invariant on its own, so it names itself when it breaks."""
    bare = [
        (row.event, row.trigger) for row in written_rows if row.trigger == lifecycle.TRIGGER_INDIRECT and not row.reason
    ]
    assert not bare, f"indirect events with no reason: {bare}"


def test_an_operator_attestation_is_always_direct(written_rows):
    wrong = [
        (row.event, row.trigger)
        for row in written_rows
        if row.reason == lifecycle.REASON_RECORDED_BY_OPERATOR and row.trigger != lifecycle.TRIGGER_DIRECT
    ]
    assert not wrong, f"operator attestations that are not direct: {wrong}"


def test_a_reconcile_finding_is_never_direct(written_rows):
    """Nobody asks for a finding by name — the pass goes looking and reports what it sees.

    Which of the other two it takes says how the pass was started: ``automated``
    for the command or a schedule, ``indirect`` for the admin page, where an
    operator asked for a pass and the findings followed from it.
    """
    reconcile_reasons = {lifecycle.REASON_CONFIRMED_BY_RECONCILE, lifecycle.REASON_DETERMINED_BY_RECONCILE}
    wrong = [
        (row.event, row.trigger, row.reason)
        for row in written_rows
        if row.reason in reconcile_reasons and row.trigger == lifecycle.TRIGGER_DIRECT
    ]
    assert not wrong, f"reconcile findings recorded as asked for by name: {wrong}"


def test_every_written_slug_is_in_the_closed_vocabulary(written_rows):
    stray = {row.reason for row in written_rows if row.reason and row.reason not in lifecycle.REASONS}
    assert not stray, f"reasons written that are not in the vocabulary: {sorted(stray)}"
    stray_triggers = {row.trigger for row in written_rows if row.trigger not in lifecycle.TRIGGERS}
    assert not stray_triggers, f"triggers written that are not in the vocabulary: {sorted(stray_triggers)}"
