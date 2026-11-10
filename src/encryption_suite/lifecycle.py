"""
Key lifecycle vocabulary — the single source of truth for the package's key
state machine.

Both key models (:class:`~encryption_suite.models.KeyEncryptionKey` and
:class:`~encryption_suite.models.DataEncryptionKey`) and the append-only
:class:`~encryption_suite.models.KeyLifecycleEvent` draw their event verbs, statuses,
and the verb→status projection from here, so the vocabulary is defined exactly
once. Status is never assigned directly anywhere in the package — the transition
funnel (``models.apply_event``) reads :data:`VERB_TO_STATUS` and writes the
ledger event and the row's ``status`` together, keeping the live row a faithful
materialized projection of the immutable ledger.

This module is pure vocabulary: constants, label maps, and membership sets, with
no Django model import (only :func:`gettext_lazy` for human labels). That keeps
it importable from migrations, checks, and tests without pulling in the ORM.

Design notes (decided 2026-06-11):

* **Two kinds, one vocabulary.** A status string means the same thing on both
  models — ``active`` is "usable / live as far as we know", ``deletion_scheduled``
  is always *our* app-enforced window (restorable, provider untouched). The
  KEK-only ``deletion_requested`` means the provider's delete API was called
  and *its* recovery window is running. Rule of thumb: scheduled = our clock,
  requested = provider's clock.
* **Initial status is a field default, not a transition.** A row is born
  ``active`` (the ``status`` field default); the funnel governs transitions only.
  Discovery of a never-tracked key therefore creates an ``active`` row and
  appends a non-status-bearing ``discovered`` event: our bookkeeping is not a key
  lifecycle act, but *when we first saw a key we did not create* is a fact worth
  keeping, and the ledger is where facts about a key live.
* **A verb mapping to ``None`` records an act without moving status** (a rewrap,
  an orphan annotation, a refused scheduling — none of which changes the key's
  state). ``deletion_failed`` is absent from the map entirely: it ends in three
  different statuses depending on what stopped the deletion, so the caller
  supplies one (see ``CALLER_SUPPLIED_STATUS_VERBS``).
"""

from django.utils.text import capfirst
from django.utils.translation import gettext_lazy as _

# --- Kinds -----------------------------------------------------------------

KIND_KEY_ENCRYPTION_KEY = "kek"
KIND_DATA_ENCRYPTION_KEY = "data_encryption_key"

KIND_CHOICES = [
    (KIND_KEY_ENCRYPTION_KEY, _("Key encryption key")),
    (KIND_DATA_ENCRYPTION_KEY, _("Data encryption key")),
]

# Column-width labels for the ledger's kind column. The stored values are
# internal identifiers and are not symmetrical (``kek`` against
# ``data_encryption_key``), which reads as an oversight when shown side by side
# in a table. The acronym is right for a column and wrong for a sentence, so the
# full names above stay the label everywhere prose is involved.
KIND_SHORT_LABELS = {
    KIND_KEY_ENCRYPTION_KEY: _("KEK"),
    KIND_DATA_ENCRYPTION_KEY: _("DEK"),
}

# --- Statuses --------------------------------------------------------------

STATUS_ACTIVE = "active"
STATUS_DELETION_SCHEDULED = "deletion_scheduled"  # our app window (restorable)
STATUS_DELETION_REQUESTED = "deletion_requested"  # provider window (KEK only)
# A deletion gate refused the key, and the refusal is one only a configuration
# change can lift, so retrying would give the same answer forever: the key still
# exists on the provider and this deployment will not delete it. Distinct from
# deletion_failed, which means we tried and the provider call errored. A refusal
# that current data state will clear on its own leaves the row where it was, to
# be retried — see TERMINAL_RETAIN_REASONS in deletion.py. Scheduling only
# pre-checks the disposition gate, so a perfectly healthy deployment whose
# provisioner cannot delete lands every scheduled key here — a policy outcome,
# not a fault.
STATUS_RETAINED = "retained"  # KEK only
STATUS_DELETION_FAILED = "deletion_failed"  # purge attempt errored (KEK only)
STATUS_DELETED = "deleted"  # terminal / tombstone
# The silo's data is split across two keysets — the row's own and a rotation's
# incoming one — so encrypt and decrypt are fenced for this purpose until every
# row is back on one. DEK only. Tracks homogeneity, not the sweep: it clears on
# a swap or a finished rollback, never on abandonment alone.
STATUS_REENCRYPTING = "reencrypting"

STATUS_LABELS = {
    STATUS_ACTIVE: _("Active"),
    STATUS_REENCRYPTING: _("Re-encrypting"),
    STATUS_DELETION_SCHEDULED: _("Deletion scheduled (app window)"),
    STATUS_DELETION_REQUESTED: _("Deletion requested (provider window)"),
    STATUS_RETAINED: _("Retained (deletion not allowed)"),
    STATUS_DELETION_FAILED: _("Deletion failed"),
    STATUS_DELETED: _("Deleted"),
}

# Initial status at row birth — a field default, NOT a funnel transition.
INITIAL_STATUS = STATUS_ACTIVE

# Per-kind status allowlists. KEKs carry the provider-window and failure
# statuses; a data encryption key (DEK) purge is a local DB transaction that
# fails atomically and is retried next run, so it never persists those.
_KEK_STATUS_ORDER = (
    STATUS_ACTIVE,
    STATUS_DELETION_SCHEDULED,
    STATUS_DELETION_REQUESTED,
    STATUS_RETAINED,
    STATUS_DELETION_FAILED,
    STATUS_DELETED,
)
_DEK_STATUS_ORDER = (
    STATUS_ACTIVE,
    STATUS_REENCRYPTING,
    STATUS_DELETION_SCHEDULED,
    STATUS_DELETED,
)

KEK_STATUS_CHOICES = [(s, STATUS_LABELS[s]) for s in _KEK_STATUS_ORDER]
DEK_STATUS_CHOICES = [(s, STATUS_LABELS[s]) for s in _DEK_STATUS_ORDER]

KEK_STATUSES = frozenset(_KEK_STATUS_ORDER)
DEK_STATUSES = frozenset(_DEK_STATUS_ORDER)

# --- Event verbs -----------------------------------------------------------

EVENT_CREATED = "created"
# Not a claim that anything happened to the key — only that this deployment first
# observed one it did not create. Deliberately distinct from ``created``, which
# would assert a provenance reconcile cannot prove.
EVENT_DISCOVERED = "discovered"
EVENT_REENCRYPTED = "reencrypted"
# A completed rotation of the key's material. On a key encryption key this is
# always an observation of the provider's act, never one of ours: the version the
# provider reports for new wraps differs from the one last recorded. Status does
# not move — a rotated key is still active. What the rotation *obliges* is
# tracked per data key (rows still wrapped under the old material), not here.
# On a data key it is ours: the swap that puts the silo back on one keyset, and
# the only place that clears the re-encryption fence going forward.
EVENT_ROTATED = "rotated"
# A data key rotation opened, and one abandoned before the swap. Both are ours,
# never a provider observation. Started raises the fence; abandoned does not drop
# it — the fence tracks homogeneity, so only a swap or a finished rollback lowers
# it. Neither verb exists on a key encryption key.
EVENT_ROTATION_STARTED = "rotation_started"
EVENT_ROTATION_ABANDONED = "rotation_abandoned"
# A scheduling a gate turned away, so no deletion window ever started. Which gate
# and why is in the event's ``reason`` (a stable RETAIN_* slug). Unlike
# ``deletion_failed`` this never moves the row, on any slug: nothing about the key
# changed and it stays schedulable once the reason is dealt with.
EVENT_DELETION_SCHEDULE_FAILED = "deletion_schedule_failed"
EVENT_DELETION_SCHEDULED = "deletion_scheduled"
EVENT_DELETION_REQUESTED = "deletion_requested"
# One verb for every deletion that did not happen, whichever side stopped it: a
# gate of ours refused (``reason`` is a RETAIN_* slug, nothing errored) or the
# provider call raised (``reason`` is ``failed_at_provider``). Splitting
# those into two verbs said twice what the reason and the resulting status
# already say, when the operation and its success verb are the same either way.
EVENT_DELETION_FAILED = "deletion_failed"
EVENT_DELETED = "deleted"
EVENT_RESTORED = "restored"
# The orphan-annotation pair, written by reconcile only when the answer *changes*.
# "Silo", not "orphan", because that is the observation: whether a live silo still
# resolves to this key. Orphanhood is the conclusion drawn from it, and naming the
# conclusion would make the event editorial rather than factual.
EVENT_SILO_FOUND = "silo_found"
EVENT_SILO_NOT_FOUND = "silo_not_found"

EVENT_LABELS = {
    EVENT_CREATED: _("Created"),
    EVENT_DISCOVERED: _("Discovered"),
    EVENT_REENCRYPTED: _("Reencrypted"),
    EVENT_ROTATED: _("Rotated"),
    EVENT_ROTATION_STARTED: _("Rotation started"),
    EVENT_ROTATION_ABANDONED: _("Rotation abandoned"),
    EVENT_DELETION_SCHEDULE_FAILED: _("Deletion scheduling failed"),
    EVENT_DELETION_SCHEDULED: _("Deletion scheduled"),
    EVENT_DELETION_REQUESTED: _("Deletion requested"),
    EVENT_DELETION_FAILED: _("Deletion failed"),
    EVENT_DELETED: _("Deleted"),
    EVENT_RESTORED: _("Restored"),
    EVENT_SILO_FOUND: _("Silo found"),
    EVENT_SILO_NOT_FOUND: _("Silo not found"),
}

EVENT_CHOICES = list(EVENT_LABELS.items())

# --- Triggers --------------------------------------------------------------
#
# How an event came about. Mandatory on every row, and the first thing to read
# when something looks wrong, because it says whether to look at a person, at
# configuration, or at a scheduled job.

# A person asked for *this key event* — an admin action, a hand-recorded
# attestation.
TRIGGER_DIRECT = "direct"
# A person asked for something else and this followed — the silo cascade,
# provisioning during a user's request. The ``reason`` then names the act that
# caused it, and is never empty.
TRIGGER_INDIRECT = "indirect"
# A script or schedule did it — reconcile, maintenance commands. Names the
# mechanism, not the absence of a person: a command run by hand still records
# the operator in ``os_login_user``.
TRIGGER_AUTOMATED = "automated"

TRIGGER_LABELS = {
    TRIGGER_DIRECT: _("Asked for directly"),
    TRIGGER_INDIRECT: _("Followed from another act"),
    TRIGGER_AUTOMATED: _("Script or schedule"),
}

TRIGGER_CHOICES = list(TRIGGER_LABELS.items())

TRIGGERS = frozenset(TRIGGER_LABELS)

# --- Reason slugs ----------------------------------------------------------
#
# Why an event happened, where the verb alone does not say. Stored as a stable,
# language-neutral slug and rendered through :data:`REASON_LABELS`: the ledger is
# an audit record that may be read years later, in a language nobody has chosen
# yet, so the database keeps the identifier and the display layer supplies the
# words. Storing the sentence instead would freeze the record into one language
# and rewrite history whenever the wording were revised.

# An operator recorded this event by hand for an act performed outside the
# application (Terraform, a KMS console, flyctl).
REASON_RECORDED_BY_OPERATOR = "recorded_by_operator"
# The provider reported this state; this deployment did not cause it and did not
# verify it through its own act.
REASON_OBSERVED_AT_PROVIDER = "observed_at_provider"
# The reconcile enumeration witnessed a provider-window key drop out of the
# listing — the only authority that may confirm a deletion.
REASON_CONFIRMED_BY_RECONCILE = "confirmed_by_reconcile"
# Reconcile compared the key against the live silos and set the orphan
# annotation from the answer.
REASON_DETERMINED_BY_RECONCILE = "determined_by_reconcile"
# The silo was created, and its keys followed.
REASON_SILO_CREATED = "silo_created"
# The silo was deleted, and the deletion cascaded to its keys.
REASON_SILO_DELETED = "silo_deleted"
# The first value encrypted for a silo that had no key yet.
REASON_FIRST_ENCRYPTION = "first_encryption"
# A live silo turned up for a key that had been annotated as an orphan.
REASON_SILO_REACQUIRED = "silo_reacquired"
# A provider call was made and raised. The provider's own words are not recorded
# here — the log carries them untruncated, under the raise site's error code.
REASON_FAILED_AT_PROVIDER = "failed_at_provider"
# What ended a data key rotation before its swap. A plain ``--abort`` records
# neither: the operator decided, and there is nothing further to name.
# The key's material was destroyed under the rotation, taking its data with it.
REASON_DEK_DELETED = "dek_deleted"
# An unattended run unwound rather than leave the fence standing over rows it
# could not convert.
REASON_UNCONVERTIBLE_ROWS = "unconvertible_rows"

REASON_LABELS = {
    REASON_RECORDED_BY_OPERATOR: _("Recorded by an operator"),
    REASON_OBSERVED_AT_PROVIDER: _("Observed at the provider"),
    REASON_CONFIRMED_BY_RECONCILE: _("Confirmed by reconcile"),
    REASON_DETERMINED_BY_RECONCILE: _("Determined by reconcile"),
    REASON_SILO_CREATED: _("The silo was created"),
    REASON_SILO_DELETED: _("The silo was deleted"),
    REASON_FIRST_ENCRYPTION: _("First encryption for the silo"),
    REASON_SILO_REACQUIRED: _("A live silo turned up again"),
    REASON_FAILED_AT_PROVIDER: _("The provider call failed"),
    REASON_DEK_DELETED: _("The data encryption key was deleted"),
    REASON_UNCONVERTIBLE_ROWS: _("Rows could not be converted"),
}

# --- Refusal reasons -------------------------------------------------------
#
# One of the package's own deletion gates declining to act — nothing errored. A
# refusal and a provider error share the ``deletion_failed`` verb, so the slug is
# what tells them apart. Declared here rather than in ``deletion`` because
# ``deletion`` imports this module, and :data:`REASONS` unions both halves.

RETAIN_SHARED_DISPOSITION = "shared_or_opaque_disposition"
RETAIN_PROVISIONER_CANNOT_DELETE = "provisioner_cannot_delete"
RETAIN_NOT_OWNED = "not_owned_by_deployment"
RETAIN_IN_USE = "in_use_by_other_silo"
RETAIN_NO_PROVISIONER = "no_provisioner"
# Data-encryption-key side. All three mean "this key still backs something live,
# or we cannot prove it does not" — see KEY_DELETION_CAN_RENDER_DATA_INACCESSIBLE.
RETAIN_SILO_LIVE = "silo_still_exists"
RETAIN_SILO_UNKNOWN = "silo_liveness_unknown"
RETAIN_SILO_CHECK_FAILED = "silo_check_failed"

# Short, localized phrases for each retain slug, for display in operator UIs.
RETAIN_REASON_TEXT = {
    RETAIN_SHARED_DISPOSITION: _("shared or operator-supplied key"),
    # Covers both reasons a provisioner will not delete: the provider leg does not
    # implement deletion, and a provider whose deletion is opt-in where the
    # deployment has not opted in. The slug does not distinguish them and the
    # operator's next step is the same either way — look at the provisioner.
    RETAIN_PROVISIONER_CANNOT_DELETE: _("key deletion is not enabled for this provisioner"),
    RETAIN_NOT_OWNED: _("not provisioned by this deployment"),
    RETAIN_IN_USE: _("still referenced by another key record"),
    RETAIN_NO_PROVISIONER: _("no KEK provisioner configured"),
    RETAIN_SILO_LIVE: _("the silo still exists"),
    RETAIN_SILO_UNKNOWN: _("the silo adapter cannot report whether the silo still exists"),
    RETAIN_SILO_CHECK_FAILED: _("checking whether the silo still exists failed"),
}

#: The closed ``reason`` vocabulary: the slugs above plus every refusal slug.
REASONS = frozenset(REASON_LABELS) | frozenset(RETAIN_REASON_TEXT)

REASON_CHOICES = [(slug, REASON_LABELS.get(slug) or RETAIN_REASON_TEXT[slug]) for slug in sorted(REASONS)]


def reason_label(reason):
    """Render a stored ``reason`` for display, falling back to the raw value.

    Covers both slug vocabularies that reach the column: the reasons above, and
    the ``RETAIN_*`` slugs a refused deletion records.

    Every slug is stored whole, so the whole value is what gets looked up.
    Anything that matches nothing is returned unchanged: a value with no label is
    still shown rather than swallowed.

    A label is returned with its first letter capitalized, because here it stands
    alone. The ``RETAIN_*`` phrases are written lowercase for the messages that
    place them inside a sentence.
    """
    if not reason:
        return ""
    label = REASON_LABELS.get(reason) or RETAIN_REASON_TEXT.get(reason)
    return capfirst(str(label)) if label is not None else reason


# Verbs whose resulting status the caller supplies, because one verb legitimately
# ends in more than one status. ``deletion_failed`` is the only one, and it ends
# in three: a provider error lands the row in ``deletion_failed``; a refusal a
# configuration change alone could lift is terminal and lands it in ``retained``;
# one that current data state will clear leaves the row where it was so the next
# run retries it. The funnel still never branches on the verb — it asks this set
# whether to expect a status argument.
CALLER_SUPPLIED_STATUS_VERBS = frozenset({EVENT_DELETION_FAILED})

# The projection: which status a verb leaves the row in. ``None`` = the verb
# records an act but does not move status. Every verb MUST appear here, except
# those in CALLER_SUPPLIED_STATUS_VERBS (enforced by
# tests/test_key_lifecycle.py map-coverage); the transition funnel reads this map
# and never branches on the verb itself.
VERB_TO_STATUS = {
    EVENT_CREATED: STATUS_ACTIVE,
    EVENT_DISCOVERED: None,
    EVENT_REENCRYPTED: None,
    # A key encryption key's rotation leaves it active. A data key's swap lowers
    # the fence, and says so through STATUS_ALTERNATIVES below.
    EVENT_ROTATED: None,
    EVENT_ROTATION_STARTED: STATUS_REENCRYPTING,
    # Never moves status on its own: a finished rollback returns the key to
    # active, and the purge that abandons a rotation writes ``deleted`` itself.
    EVENT_ROTATION_ABANDONED: None,
    EVENT_DELETION_SCHEDULE_FAILED: None,
    EVENT_DELETION_SCHEDULED: STATUS_DELETION_SCHEDULED,
    EVENT_DELETION_REQUESTED: STATUS_DELETION_REQUESTED,
    EVENT_DELETED: STATUS_DELETED,
    EVENT_RESTORED: STATUS_ACTIVE,
    # Observations, not transitions: whether a silo still resolves says nothing
    # about whether the key is usable, scheduled, or gone.
    EVENT_SILO_FOUND: None,
    EVENT_SILO_NOT_FOUND: None,
}

# Verbs whose projection above is right in general and wrong in one named case,
# and the statuses a caller may choose instead. Unlike a caller-supplied verb,
# passing nothing keeps the map's answer, so every existing caller stays correct
# without knowing the alternative exists; and the alternative is a closed set, so
# the map is still the only authority for anything not listed.
#
# * ``restored`` returns a data key whose rotation survived its deletion window
#   to ``reencrypting``: the silo is still split across two keysets.
# * ``rotated`` on a data key is the swap, which lowers the fence.
# * ``rotation_abandoned`` lowers it too, once a rollback has left nothing
#   converted.
STATUS_ALTERNATIVES = {
    EVENT_RESTORED: frozenset({STATUS_REENCRYPTING}),
    EVENT_ROTATED: frozenset({STATUS_ACTIVE}),
    EVENT_ROTATION_ABANDONED: frozenset({STATUS_ACTIVE}),
}

# Per-kind verb allowlists. ``discovered`` and ``deletion_requested`` are
# KEK-only (a DEK is never enumerated at a provider and has no provider window);
# ``rotation_started`` and ``rotation_abandoned`` are DEK-only (a sweep of a
# silo's data has no key encryption key counterpart).
# ``deletion_failed`` and ``deletion_schedule_failed`` apply to either kind: an
# operator can be refused on either changelist, and that attempt is recorded
# wherever it happened. Only its provider-error branch is KEK-only, since a data
# key deletion is a local transaction with no provider call to fail.
_KEK_EVENTS = (
    EVENT_CREATED,
    EVENT_DISCOVERED,
    EVENT_REENCRYPTED,
    EVENT_ROTATED,
    EVENT_DELETION_SCHEDULE_FAILED,
    EVENT_DELETION_SCHEDULED,
    EVENT_DELETION_REQUESTED,
    EVENT_DELETION_FAILED,
    EVENT_DELETED,
    EVENT_RESTORED,
    EVENT_SILO_FOUND,
    EVENT_SILO_NOT_FOUND,
)
_DEK_EVENTS = (
    EVENT_CREATED,
    EVENT_REENCRYPTED,
    EVENT_ROTATED,
    EVENT_ROTATION_STARTED,
    EVENT_ROTATION_ABANDONED,
    EVENT_DELETION_SCHEDULE_FAILED,
    EVENT_DELETION_SCHEDULED,
    EVENT_DELETION_FAILED,
    EVENT_DELETED,
    EVENT_RESTORED,
    EVENT_SILO_FOUND,
    EVENT_SILO_NOT_FOUND,
)

KEK_EVENTS = frozenset(_KEK_EVENTS)
DEK_EVENTS = frozenset(_DEK_EVENTS)

# Verbs an operator may record by hand for an act performed outside the app
# (Terraform, KMS console, flyctl). On most cloud providers a manual "delete" is
# actually a *scheduled* deletion (a recovery window), so for KEKs both
# ``deletion_scheduled`` (our intent) and ``deletion_requested`` (provider window
# running) are recordable. ``restored`` is recordable for the counterpart act —
# canceling a deletion in the KMS (``aws kms cancel-key-deletion`` and
# equivalents) — without which a row that reached ``deletion_requested`` had no
# supported way back: the restore action only reverses *our* window, and reconcile
# flags drift rather than auto-correcting it. Rewrap / deletion failure / discover
# are tooling-internal, never manual — ``discovered`` in particular is an observation
# this deployment made, so a hand-recorded one would be a claim about our own eyes.
MANUAL_KEK_EVENTS = frozenset(
    {EVENT_CREATED, EVENT_DELETION_SCHEDULED, EVENT_DELETION_REQUESTED, EVENT_DELETED, EVENT_RESTORED}
)
MANUAL_DEK_EVENTS = frozenset({EVENT_CREATED, EVENT_DELETED})


def statuses_for_kind(kind):
    """Return the frozenset of statuses valid for *kind*."""
    return KEK_STATUSES if kind == KIND_KEY_ENCRYPTION_KEY else DEK_STATUSES


def events_for_kind(kind):
    """Return the frozenset of event verbs valid for *kind*."""
    return KEK_EVENTS if kind == KIND_KEY_ENCRYPTION_KEY else DEK_EVENTS


def manual_events_for_kind(kind):
    """Return the frozenset of verbs an operator can record for *kind*."""
    return MANUAL_KEK_EVENTS if kind == KIND_KEY_ENCRYPTION_KEY else MANUAL_DEK_EVENTS
