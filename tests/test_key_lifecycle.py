"""
Lifecycle vocabulary + transition-funnel invariants.

These lock the contract that the rest of the refactor relies on: every verb has
a status projection, status is only ever set through the funnel, and a row's
live status always equals the projection of its latest status-bearing ledger
event (the rebuild integrity check).
"""

import pytest
from django.db import IntegrityError

from encryption_suite import lifecycle
from tests.factories import make_kek, make_kek_row

# --- Pure-vocabulary checks (no DB) ----------------------------------------


def test_every_verb_has_a_status_projection():
    """VERB_TO_STATUS must cover every event verb exactly, bar the ones whose
    status the caller supplies — no gaps, no extras."""
    all_verbs = set(dict(lifecycle.EVENT_CHOICES))
    assert set(lifecycle.VERB_TO_STATUS) == all_verbs - lifecycle.CALLER_SUPPLIED_STATUS_VERBS


def test_caller_supplied_verbs_are_real_verbs_and_absent_from_the_map():
    all_verbs = set(dict(lifecycle.EVENT_CHOICES))
    assert lifecycle.CALLER_SUPPLIED_STATUS_VERBS <= all_verbs
    assert not (lifecycle.CALLER_SUPPLIED_STATUS_VERBS & set(lifecycle.VERB_TO_STATUS))


def test_a_caller_supplied_status_never_leaves_a_data_key_in_a_kek_only_status():
    """``deletion_failed`` applies to both kinds, and on a refusal its status comes
    from the retain reason — so no data-key refusal may resolve to a KEK-only status."""
    from encryption_suite.deletion import RETAIN_REASON_TEXT, retain_status

    dek_statuses = lifecycle.statuses_for_kind(lifecycle.KIND_DATA_ENCRYPTION_KEY)
    for slug in ("silo_still_exists", "silo_liveness_unknown", "silo_check_failed"):
        assert slug in RETAIN_REASON_TEXT
        status = retain_status(slug)
        assert status is None or status in dek_statuses, slug


def test_projection_targets_are_valid_statuses():
    """Every non-None projected status is a real status string."""
    every_status = lifecycle.KEK_STATUSES | lifecycle.DEK_STATUSES
    for verb, status in lifecycle.VERB_TO_STATUS.items():
        if status is not None:
            assert status in every_status, verb


def test_per_kind_verbs_only_project_into_that_kinds_statuses():
    """A verb allowed for a kind must project into a status that kind allows."""
    for kind in (lifecycle.KIND_KEY_ENCRYPTION_KEY, lifecycle.KIND_DATA_ENCRYPTION_KEY):
        allowed_statuses = lifecycle.statuses_for_kind(kind)
        for verb in lifecycle.events_for_kind(kind):
            if verb in lifecycle.CALLER_SUPPLIED_STATUS_VERBS:
                continue
            status = lifecycle.VERB_TO_STATUS[verb]
            if status is not None:
                assert status in allowed_statuses, (kind, verb, status)


def test_initial_status_valid_for_both_kinds():
    assert lifecycle.INITIAL_STATUS in lifecycle.KEK_STATUSES
    assert lifecycle.INITIAL_STATUS in lifecycle.DEK_STATUSES


def test_manual_events_are_a_subset_of_the_kinds_verbs():
    for kind in (lifecycle.KIND_KEY_ENCRYPTION_KEY, lifecycle.KIND_DATA_ENCRYPTION_KEY):
        assert lifecycle.manual_events_for_kind(kind) <= lifecycle.events_for_kind(kind)


# --- Transition funnel (DB) ------------------------------------------------


@pytest.fixture
def kek(db):

    return make_kek_row(key_store="local", kek_resource_name="kek-1")


def test_row_is_born_active_without_an_event(kek):
    """Initial status is a field default, not a funnel transition — no event."""
    assert kek.status == lifecycle.STATUS_ACTIVE
    assert kek.events.count() == 0


def test_apply_event_writes_ledger_and_projects_status(kek):
    from django.utils import timezone

    when = timezone.now()
    kek.record_event(lifecycle.EVENT_DELETION_SCHEDULED, trigger=lifecycle.TRIGGER_DIRECT, undeletable_until=when)
    kek.refresh_from_db()
    assert kek.status == lifecycle.STATUS_DELETION_SCHEDULED
    assert kek.undeletable_until == when
    event = kek.events.get()
    assert event.event == lifecycle.EVENT_DELETION_SCHEDULED
    assert event.trigger == lifecycle.TRIGGER_DIRECT
    assert event.kek_resource_name == "kek-1"


def test_none_projecting_verb_records_act_without_moving_status(kek):
    kek.record_event(lifecycle.EVENT_REENCRYPTED, trigger=lifecycle.TRIGGER_DIRECT)
    kek.refresh_from_db()
    assert kek.status == lifecycle.STATUS_ACTIVE
    assert kek.events.get().event == lifecycle.EVENT_REENCRYPTED


def test_invalid_verb_for_kind_raises(db):
    from encryption_suite.models import DataEncryptionKey

    sek = DataEncryptionKey.objects.create(
        key_set="default", silo_uid="team-1", silo_label="group", kek=make_kek("kek-1", "local")
    )
    # deletion_requested is a KMS-key-only verb.
    with pytest.raises(ValueError):
        sek.record_event(lifecycle.EVENT_DELETION_REQUESTED, trigger=lifecycle.TRIGGER_DIRECT)
    assert sek.events.count() == 0


def test_status_rebuild_integrity(kek):
    """Live status must equal the projection of the latest status-bearing event."""
    from django.utils import timezone

    kek.record_event(
        lifecycle.EVENT_DELETION_SCHEDULED, trigger=lifecycle.TRIGGER_DIRECT, undeletable_until=timezone.now()
    )
    kek.record_event(
        lifecycle.EVENT_REENCRYPTED, trigger=lifecycle.TRIGGER_DIRECT
    )  # None-projecting; must not move status
    kek.record_event(lifecycle.EVENT_RESTORED, trigger=lifecycle.TRIGGER_DIRECT)
    kek.refresh_from_db()

    status_bearing = [
        e for e in kek.events.order_by("created_at", "id") if lifecycle.VERB_TO_STATUS[e.event] is not None
    ]
    expected = lifecycle.VERB_TO_STATUS[status_bearing[-1].event] if status_bearing else lifecycle.INITIAL_STATUS
    assert kek.status == expected == lifecycle.STATUS_ACTIVE


def test_exactly_one_key_fk_enforced(db):
    """The ledger CheckConstraint rejects an event with neither key FK set."""
    from encryption_suite.models import KeyLifecycleEvent

    with pytest.raises(IntegrityError):
        KeyLifecycleEvent.objects.create(event=lifecycle.EVENT_CREATED)


def test_record_by_operator_pins_recorded_reason(kek):
    from encryption_suite.models import KeyLifecycleEvent

    KeyLifecycleEvent.record_by_operator(kek, lifecycle.EVENT_DELETED, os_login_user="bob (uid 1000)")
    event = kek.events.get()
    assert event.reason == KeyLifecycleEvent.REASON_RECORDED_BY_OPERATOR
    kek.refresh_from_db()
    assert kek.status == lifecycle.STATUS_DELETED


def test_record_by_operator_rejects_non_manual_verb(kek):
    from encryption_suite.models import KeyLifecycleEvent

    with pytest.raises(ValueError):
        KeyLifecycleEvent.record_by_operator(kek, lifecycle.EVENT_REENCRYPTED, os_login_user="bob (uid 1000)")


def test_kms_deletion_at_is_rejected_for_a_dek(db):
    """A DEK has no provider-side deletion — only its wrapping KEK does.

    Passing the provider's date to a DEK event would be a category error, and
    silently ignoring it would lose the fact somewhere a caller believed it was
    recorded.
    """
    from django.utils import timezone

    from encryption_suite.models import DataEncryptionKey, apply_event

    dek = DataEncryptionKey.objects.create(
        key_set="default",
        silo_uid="team-1",
        purpose=DataEncryptionKey.PURPOSE_FIELD,
        silo_label="team",
        encrypted_keyset=b"wrapped",
        kek=make_kek("kek-1", "local"),
    )

    with pytest.raises(ValueError, match="kms_deletion_at"):
        apply_event(
            dek,
            lifecycle.EVENT_DELETION_SCHEDULED,
            trigger=lifecycle.TRIGGER_DIRECT,
            kms_deletion_at=timezone.now(),
        )
