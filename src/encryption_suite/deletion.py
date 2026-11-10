"""
Key deletion — schedule, restore, and purge over the soft-delete window.

A silo deletion is a two-sided, reversible act, and both sides are gated by the
same window (``KEY_DELETION_WINDOW_DAYS``):

* :func:`schedule_deletion` flips the silo's :class:`DataEncryptionKey` (DEK)
  rows to ``deletion_scheduled`` and — only when the KEK is *silo-exclusive* —
  schedules the matching :class:`KeyEncryptionKey` rows too, snapshotting the gate inputs
  (disposition, owner prefix). Scheduling destroys nothing and is fully
  restorable for the duration of the window.
* :func:`restore_deletion` reverses both sides while the window is still open
  (a pure DB state flip, provider-agnostic).
* :func:`purge_expired_deks` clears each expired DEK row's ``encrypted_keyset``
  field — the crypto-shred; the row survives as a ``deleted`` tombstone.
* :func:`purge_expired_keks` re-checks every deletion gate on each expired KEK
  before asking the provisioner to delete the key encryption key.

The two purges are separate functions because they are separate acts with
different consequences, and neither should ever run as a side effect of the
other. Each is driven from its own admin changelist. **No management command
calls either one**: destroying keys is a deliberate, reviewed act here, not a
scheduled sweep. A project that cannot expose the admin can call these directly
from its own tooling — both take ``dry_run`` for previewing the same decisions.

The configuration gates live in :func:`evaluate_deletion` so there is exactly one
enforcement point shared by every caller. Keeping the decision in one place means
no caller can drift or re-implement a gate incorrectly — important because the
cost of a wrong "eligible" is destroying a key real data depends on.

The purge authorizes against the *running* configuration, never against the
values snapshotted on the row: the owner prefix and — wherever a DEK row still
names the key — the disposition are re-derived per run, and it tests directly
whether any un-shredded DEK still depends on the key. A snapshot may withhold
permission to destroy a key; it can never grant it.

Every state transition is written through the lifecycle funnel
(``models.apply_event``), so each act appends its immutable ``KeyLifecycleEvent`` event
transactionally with the change — material is never created or destroyed without
a trace.
"""

from __future__ import annotations

import datetime
from dataclasses import dataclass, field

from django.db import transaction
from django.utils import timezone

from . import lifecycle, user_context
from ._logging import get_logger
from .models import DataEncryptionKey, KeyEncryptionKey
from .silo_ref import SiloRef, whole_silo_filter

logger = get_logger(__name__)

# The refusal slugs and their phrases are part of the closed ``reason``
# vocabulary and live in :mod:`encryption_suite.lifecycle` beside the rest of it.
# Re-exported here under the names every caller already uses.
RETAIN_SHARED_DISPOSITION = lifecycle.RETAIN_SHARED_DISPOSITION
RETAIN_PROVISIONER_CANNOT_DELETE = lifecycle.RETAIN_PROVISIONER_CANNOT_DELETE
RETAIN_NOT_OWNED = lifecycle.RETAIN_NOT_OWNED
RETAIN_IN_USE = lifecycle.RETAIN_IN_USE
RETAIN_NO_PROVISIONER = lifecycle.RETAIN_NO_PROVISIONER
RETAIN_SILO_LIVE = lifecycle.RETAIN_SILO_LIVE
RETAIN_SILO_UNKNOWN = lifecycle.RETAIN_SILO_UNKNOWN
RETAIN_SILO_CHECK_FAILED = lifecycle.RETAIN_SILO_CHECK_FAILED
RETAIN_REASON_TEXT = lifecycle.RETAIN_REASON_TEXT

# Data key statuses that still hold usable material. A key under rotation is
# fenced, not retired: scheduling it is intent, and the rotation row and worklist
# stay so a restore can finish what was converted.
LIVE_DEK_STATUSES = (lifecycle.STATUS_ACTIVE, lifecycle.STATUS_REENCRYPTING)

# Which refusals only a configuration change can lift. These three come from how
# the deployment is configured — the KEK strategy, the provisioner, the naming
# convention — so retrying gives the same answer forever; the row moves to
# ``retained`` and leaves the queue. Every other refusal comes from current data
# state (live keysets, a silo that still exists, a probe that could not answer)
# and clears as that state changes, so the row stays where it is and the next run
# retries it.
TERMINAL_RETAIN_REASONS = frozenset(
    {
        RETAIN_SHARED_DISPOSITION,
        RETAIN_PROVISIONER_CANNOT_DELETE,
        RETAIN_NOT_OWNED,
    }
)


def retain_status(retain_reason: str):
    """Return the status a refusal for *retain_reason* leaves the row in.

    ``None`` where the refusal is transient, meaning the funnel records the
    attempt and does not move the row.
    """
    from . import lifecycle

    return lifecycle.STATUS_RETAINED if retain_reason in TERMINAL_RETAIN_REASONS else None


def record_refused_scheduling(
    blocked, *, trigger, user=None, os_login_user: str = "", user_ip=None, kind: str = ""
) -> None:
    """Record that an operator tried to schedule keys a gate would not allow.

    *blocked* is the ``[(row, retain_reason)]`` the schedule action turned away.
    Each row gets a ``deletion_schedule_failed`` event carrying the slug; no status
    moves, because nothing about the key changed and it stays schedulable once
    the reason is dealt with.

    Recorded rather than only shown on screen: a message vanishes on the next
    page load, so an attempt to make a live silo's data permanently unreadable
    would leave no trace of who tried or when — while the *allowed* case has been
    recorded all along. One audit line accompanies the events, at WARNING so it
    survives a production log-level cut.
    """
    if not blocked:
        return
    for row, retain_reason in blocked:
        row.record_event(
            lifecycle.EVENT_DELETION_SCHEDULE_FAILED,
            trigger=trigger,
            user=user,
            os_login_user=os_login_user,
            user_ip=user_ip,
            reason=retain_reason,
        )
    logger.warning(
        "An operator tried to schedule keys that a gate would not allow; nothing changed and the "
        "keys stay schedulable once the reasons are dealt with. event=%s reasons=%s keys=%d "
        "silos=%s kind=%s %s",
        lifecycle.EVENT_DELETION_SCHEDULE_FAILED,
        ",".join(sorted({reason for _row, reason in blocked})),
        len(blocked),
        ",".join(sorted({str(row.silo_ref) for row, _reason in blocked if getattr(row, "silo_uid", "")})) or "n/a",
        kind or "?",
        user_context.identity_tail(user=user, os_login_user=os_login_user, user_ip=user_ip),
    )


def format_retain_reasons(slugs) -> str:
    """Return a comma-joined, de-duplicated human description of retain reasons.

    ``str()`` resolves the lazy gettext proxies in :data:`RETAIN_REASON_TEXT` so
    ``join`` receives real strings (a lazy proxy is not a ``str``). An unknown
    slug falls back to itself.
    """
    return ", ".join(sorted({str(RETAIN_REASON_TEXT.get(s, s)) for s in slugs}))


def allow_deleting_keys_in_use() -> bool:
    """Whether destroying a key that live data depends on is permitted.

    Reads ``KEY_DELETION_CAN_RENDER_DATA_INACCESSIBLE``. Off by default, and
    consulted by both halves of a deletion: a key encryption key that still wraps
    live keysets, and a data encryption key whose silo still exists.
    """
    from .conf import enc_settings

    return bool(enc_settings.KEY_DELETION_CAN_RENDER_DATA_INACCESSIBLE)


def _silo_liveness(silo_ref: str):
    """Return whether *silo_ref* still belongs to a live silo.

    ``True`` / ``False`` / ``None`` for *cannot say*, straight from
    :meth:`AbstractSiloAdapter.silo_exists`. A raised error is **not** folded into
    ``None``: a transient failure (the database is down) and a permanent inability
    (this adapter has no way to check) call for different responses — retry versus
    write code — so the caller distinguishes them.

    Private, and stays private, because it propagates whatever the adapter raised.
    Its one caller turns that into a retain reason; nothing outside this module
    should have to catch a raw adapter error.
    """
    from .registry import get_silo_adapter

    return get_silo_adapter(silo_ref.key_set).silo_exists(silo_ref.uid)


def dek_retain_reason(silo_ref: str) -> str | None:
    """Why this key may not be destroyed, or ``None`` to proceed.

    Asked twice: by the purge before shredding, and by the admin schedule action
    before starting a window the purge would refuse to finish.

    The gate exists because shredding is irreversible and a silo that still exists
    is a silo whose data someone can still reach. It is skipped entirely when
    ``KEY_DELETION_CAN_RENDER_DATA_INACCESSIBLE`` is on — that setting is the
    operator saying they mean to make live data unreadable.

    Refuses on *cannot say* as well as on *yes*. The alternative is to shred on a
    question we could not answer, which is the one direction that cannot be undone.
    The refusal names which of the three it was, because the remedies differ: delete
    the silo, implement ``silo_exists()``, or retry.

    The keys of a key set whose adapter sets ``prevents_key_delete`` are refused
    whatever that setting says. The system silo is one: it always exists and its
    columns are read across every silo — sign-in among them — so shredding its
    key is never the targeted act the setting is for.
    """
    from .exceptions import EncryptionError
    from .registry import get_silo_adapter

    if get_silo_adapter(silo_ref.key_set).prevents_key_delete:
        return RETAIN_SILO_LIVE
    if allow_deleting_keys_in_use():
        return None
    try:
        exists = _silo_liveness(silo_ref)
    except EncryptionError:
        # Already logged with its slug by the helper that raised it — a silo
        # adapter that cannot enumerate raises SiloEnumerationError this way. A
        # second line for one failure is the noise the funnels exist to prevent.
        return RETAIN_SILO_CHECK_FAILED
    except Exception as exc:
        from ._internal import operator_error_text

        logger.warning(
            "The silo adapter could not say whether this silo still exists, so the key was kept "
            'rather than destroyed on an unanswered question. reason=%s silo="%s" detail="%s"',
            RETAIN_SILO_CHECK_FAILED,
            silo_ref,
            operator_error_text(exc),
        )
        return RETAIN_SILO_CHECK_FAILED
    if exists is None:
        return RETAIN_SILO_UNKNOWN
    return RETAIN_SILO_LIVE if exists else None


def _window_expiry() -> datetime.datetime:
    """Return the moment the soft-delete window expires from now."""
    from .conf import enc_settings

    days = int(enc_settings.KEY_DELETION_WINDOW_DAYS)
    return timezone.now() + datetime.timedelta(days=days)


# ---------------------------------------------------------------------------
# Schedule
# ---------------------------------------------------------------------------


def schedule_deletion(
    silo_ref: str,
    *,
    trigger: str = lifecycle.TRIGGER_INDIRECT,
    reason: str = lifecycle.REASON_SILO_DELETED,
    user=user_context._UNSET,
    os_login_user: str = "",
    user_ip=user_context._UNSET,
) -> list:
    """Schedule deletion of every key a torn-down silo owns. Destroys nothing.

    Called when a silo is deleted (the ``post_delete`` connector wired by
    ``ENCRYPTION['SILO_AUTO_KEY_DELETION']``, or any caller that observes a real
    deletion). In one transaction it flips the silo's active DEK rows to
    ``deletion_scheduled`` and — only for a ``silo_exclusive`` KEK disposition —
    schedules the matching :class:`KeyEncryptionKey` rows, snapshotting the gate inputs
    (disposition, owner prefix) so a later strategy/config change cannot rewrite
    what the purge gates will see. A ``shared`` KEK is referenced by many silos'
    DEKs and is never scheduled by one silo's deletion — clearing this silo's DEK
    rows alone is its shred.

    The test console's isolated ``PURPOSE_TEST`` keys are skipped (they have
    their own deletion path and never belong to a real silo).

    Idempotent: a re-run skips rows already scheduled or deleted. Returns the
    rows scheduled this call (DEK + KEK rows; empty when nothing was active).
    """
    from .exceptions import EncryptionError, log_and_raise_deletion_record_error

    # Resolved here rather than defaulted to ``None``: the ``post_delete`` caller
    # in ``apps.py`` passes no identity, so the cascade would otherwise go
    # unattributed under ``all_acts``.
    user, user_ip = user_context.resolve_user_and_ip(user, user_ip)

    # Everything that touches the DB or the strategy runs inside the deletion
    # funnel: a typed EncryptionError (e.g. a config error resolving the
    # strategy) passes through already-logged; any raw error (a DB failure) is
    # converted to a typed KekDeletionRecordError with one clean
    # error_code=kek_deletion_record_failed line and no traceback.
    try:
        # A key under rotation still holds its material, so it is as live as an
        # active one. Missing it here would leave a deleted silo's key standing,
        # and the key encryption key scheduling below derives from this list.
        dek_rows = list(
            DataEncryptionKey.objects.filter(**whole_silo_filter(silo_ref), status__in=LIVE_DEK_STATUSES)
            .exclude(purpose=DataEncryptionKey.PURPOSE_TEST)
            .select_related("kek")
        )
        if not dek_rows:
            return []

        # Each key encryption key answers through the KMS its row names: the
        # silo's keys can sit on more than one while a move between KMSs is
        # under way. Resolved before the transaction, so a strategy that cannot
        # be built fails the call before anything is written.
        kek_gates = _silo_kek_gates(dek_rows, silo_ref)
        expiry = _window_expiry()

        scheduled: list = []
        with transaction.atomic():
            for row in dek_rows:
                row.record_event(
                    lifecycle.EVENT_DELETION_SCHEDULED,
                    trigger=trigger,
                    reason=reason,
                    user=user,
                    os_login_user=os_login_user,
                    user_ip=user_ip,
                    undeletable_until=expiry,
                    silo_ref=silo_ref,
                )
                # The silo is gone — this function is only ever called on an
                # observed deletion — so the row is orphaned as a fact, not an
                # inference. Recorded here rather than left for the next reconcile,
                # which would otherwise leave the row reading `deletion_scheduled`
                # beside `is_orphaned = False` for as long as the reconcile interval.
                newly_orphaned = not row.is_orphaned
                row.is_orphaned = True
                row.save(update_fields=["is_orphaned", "updated_at"])
                if newly_orphaned:
                    row.record_event(
                        lifecycle.EVENT_SILO_NOT_FOUND,
                        trigger=trigger,
                        reason=reason,
                        user=user,
                        os_login_user=os_login_user,
                        user_ip=user_ip,
                        silo_ref=silo_ref,
                    )
                scheduled.append(row)

            # Schedule the KEKs only for a silo-exclusive disposition; a
            # shared KEK is never deleted by a single silo's deletion.
            scheduled.extend(
                _schedule_silo_keks(
                    dek_rows,
                    silo_ref,
                    kek_gates,
                    expiry,
                    trigger=trigger,
                    reason=reason,
                    user=user,
                    os_login_user=os_login_user,
                    user_ip=user_ip,
                )
            )
    except EncryptionError:
        raise
    except Exception as exc:
        log_and_raise_deletion_record_error(
            logger,
            f"Failed to schedule key deletion for silo '{silo_ref}': {exc}",
            cause=exc,
        )

    # WARNING, not INFO: production log levels commonly cut INFO, and an event
    # nobody sees cannot be intervened on — by the time the destruction itself
    # logs, the moment to act has passed.
    logger.warning(
        "Key deletion was scheduled; this starts the countdown that ends in destroyed key "
        'material, and it can be canceled until the window elapses. event=%s keys=%d silo="%s" %s',
        lifecycle.EVENT_DELETION_SCHEDULED,
        len(scheduled),
        silo_ref,
        user_context.identity_tail(user=user, os_login_user=os_login_user, user_ip=user_ip),
    )
    return scheduled


def _silo_kek_gates(dek_rows, silo_ref) -> dict:
    """Return ``{key_store: (disposition, owner_prefix)}`` for the key stores behind *dek_rows*.

    Asked of each KMS's own strategy, for this silo. A KMS no block names has
    no strategy to ask, so it answers shared — the value that never schedules a
    key — rather than failing the whole deletion over a key this configuration
    could not delete anyway.
    """
    from .conf import kms_block
    from .registry import get_kek_strategy_adapter

    gates = {}
    for key_store in {dek.kek.key_store for dek in dek_rows}:
        if kms_block(key_store) is None:
            gates[key_store] = (KeyEncryptionKey.DISPOSITION_SHARED, "")
            continue
        disposition = get_kek_strategy_adapter(key_store).kek_disposition(silo_ref)
        gates[key_store] = (disposition, live_owner_prefix(key_store))
    return gates


def _schedule_silo_keks(
    dek_rows,
    silo_ref,
    kek_gates,
    expiry,
    *,
    trigger,
    reason="",
    user=None,
    os_login_user="",
    user_ip=None,
) -> list:
    """Schedule the distinct silo-exclusive KEKs behind *dek_rows*.

    The KeyEncryptionKey rows are reached through each DEK row's ``kek``
    relation, which survives a purge along with the tombstone. Every DEK has one:
    the engine writes it in the same transaction as the row, so there is nothing
    to backfill. *kek_gates* gives each KMS's disposition and owner prefix, which
    are snapshotted onto the row for the purge gates.
    """
    seen: set[int] = set()
    scheduled: list = []
    for dek in dek_rows:
        kek = dek.kek
        if kek.pk in seen:
            continue
        seen.add(kek.pk)
        disposition, owner_prefix = kek_gates[kek.key_store]
        if disposition != KeyEncryptionKey.DISPOSITION_SILO_EXCLUSIVE:
            continue
        # The silo is gone and this key was exclusive to it, so nothing live
        # references it any more — a fact this path establishes rather than
        # infers. Recording it closes the window in which the row read
        # `deletion_scheduled` beside `is_orphaned = False`, two columns
        # contradicting each other until the next reconcile happened to run.
        #
        # Safe only inside the silo-exclusive gate above: a shared key still
        # backs other silos, and this branch never runs for one.
        newly_orphaned = not kek.is_orphaned
        if kek.status != lifecycle.STATUS_ACTIVE:
            # Already scheduled/requested/deleted by another path, so do not
            # schedule it again — but the silo still just vanished, and that is
            # a separate fact from scheduling. Annotating it here is what keeps
            # the two independent: the status guard governs the scheduling
            # event, never the orphan observation.
            if newly_orphaned:
                kek.is_orphaned = True
                kek.save(update_fields=["is_orphaned", "updated_at"])
                kek.record_event(
                    lifecycle.EVENT_SILO_NOT_FOUND,
                    trigger=trigger,
                    reason=reason,
                    user=user,
                    os_login_user=os_login_user,
                    user_ip=user_ip,
                    silo_ref=silo_ref,
                )
            continue
        kek.disposition = disposition
        kek.owner_prefix = owner_prefix
        kek.is_orphaned = True
        kek.save(update_fields=["disposition", "owner_prefix", "is_orphaned", "updated_at"])
        kek.record_event(
            lifecycle.EVENT_DELETION_SCHEDULED,
            trigger=trigger,
            reason=reason,
            user=user,
            os_login_user=os_login_user,
            user_ip=user_ip,
            undeletable_until=expiry,
            silo_ref=silo_ref,
        )
        if newly_orphaned:
            kek.record_event(
                lifecycle.EVENT_SILO_NOT_FOUND,
                trigger=trigger,
                reason=reason,
                user=user,
                os_login_user=os_login_user,
                user_ip=user_ip,
                silo_ref=silo_ref,
            )
        scheduled.append(kek)
    return scheduled


# ---------------------------------------------------------------------------
# Restore
# ---------------------------------------------------------------------------


def _restored_status(dek_row):
    """The status a restored data key returns to, or ``None`` for the usual ``active``.

    A rotation row that survived the window means the silo is still split
    between two keysets, so the key goes back to ``reencrypting``: the next move
    is to rerun the sweep or abort it, and reading either keyset alone would be
    wrong.
    """
    from .models import DekRotation

    if DekRotation.objects.filter(dek=dek_row).exists():
        return lifecycle.STATUS_REENCRYPTING
    return None


def restore_deletion(
    silo_ref: str, *, trigger, reason: str = "", user=None, os_login_user: str = "", user_ip=None
) -> list:
    """Reverse a scheduled deletion while the window is still open.

    A pure DB state flip (provider-agnostic): the silo's ``deletion_scheduled``
    DEK rows and the KEKs behind them return to ``active`` via a ``restored``
    event. Only valid before purge — once material has been cleared or the
    provider's delete API called, the key counts as gone and a restore is a
    manual, separately-recorded by an operator act. Returns the rows restored.
    """
    restored: list = []
    with transaction.atomic():
        dek_rows = list(
            DataEncryptionKey.objects.filter(**whole_silo_filter(silo_ref), status=lifecycle.STATUS_DELETION_SCHEDULED)
        )
        for row in dek_rows:
            row.record_event(
                lifecycle.EVENT_RESTORED,
                trigger=trigger,
                reason=reason,
                user=user,
                os_login_user=os_login_user,
                user_ip=user_ip,
                silo_ref=silo_ref,
                status=_restored_status(row),
            )
            if row.undeletable_until:
                row.undeletable_until = None
                row.save(update_fields=["undeletable_until", "updated_at"])
            restored.append(row)

        for kek in KeyEncryptionKey.objects.filter(
            pk__in={d.kek_id for d in dek_rows},
            status=lifecycle.STATUS_DELETION_SCHEDULED,
        ):
            kek.record_event(
                lifecycle.EVENT_RESTORED,
                trigger=trigger,
                reason=reason,
                user=user,
                os_login_user=os_login_user,
                user_ip=user_ip,
                silo_ref=silo_ref,
            )
            if kek.undeletable_until:
                kek.undeletable_until = None
                kek.save(update_fields=["undeletable_until", "updated_at"])
            restored.append(kek)

    logger.info(
        "Scheduled key deletion was canceled; the keys are usable again, or back under their rotation, "
        'and no material was destroyed. event=%s keys=%d silo="%s" %s',
        lifecycle.EVENT_RESTORED,
        len(restored),
        silo_ref,
        user_context.identity_tail(user=user, os_login_user=os_login_user, user_ip=user_ip),
    )
    return restored


# ---------------------------------------------------------------------------
# Single-key schedule / restore (admin actions on the KMS Keys changelist)
# ---------------------------------------------------------------------------


def schedule_kek_deletion(
    row, *, owner_prefix: str, trigger, reason: str = "", user=None, os_login_user: str = "", user_ip=None
) -> None:
    """Schedule one :class:`KeyEncryptionKey` row for deletion. Destroys nothing.

    The changelist counterpart of :func:`schedule_deletion`: snapshots the gate
    inputs (disposition and owner prefix) and records ``deletion_scheduled`` with
    the standard window expiry. Fully restorable until the window runs; the purge
    re-checks every gate.

    The disposition is **derived from the strategy**, by name, rather than assumed
    silo-exclusive. This path once handled only confirmed reconcile orphans, where
    an owned orphan was silo-exclusive by construction; the changelist now
    schedules any active key, so assuming it wrote a snapshot that contradicted
    the strategy. That mattered because the purge falls back to this snapshot for
    a key no data encryption key names — exactly the orphan case — so a shared or
    ``KEK_MAP`` key could pass the disposition gate on an assumption.

    Asked of the strategy of the KMS the row names, which is also where
    *owner_prefix* must come from (see :func:`live_owner_prefix`). A row on a
    KMS no block names snapshots shared, which the purge retains.
    """
    from .conf import kms_block
    from .registry import get_kek_strategy_adapter

    expiry = _window_expiry()
    prefix = owner_prefix or None
    if kms_block(row.key_store) is None:
        row.disposition = KeyEncryptionKey.DISPOSITION_SHARED
    else:
        row.disposition = get_kek_strategy_adapter(row.key_store).kek_disposition_for_name(
            row.kek_resource_name, prefix
        )
    row.owner_prefix = owner_prefix or ""
    row.save(update_fields=["disposition", "owner_prefix", "updated_at"])
    row.record_event(
        lifecycle.EVENT_DELETION_SCHEDULED,
        trigger=trigger,
        reason=reason,
        user=user,
        os_login_user=os_login_user,
        user_ip=user_ip,
        undeletable_until=expiry,
    )
    # WARNING for the same reason the silo-wide scheduling uses it: this starts
    # the countdown that ends in destroyed key material, and a level the pipeline
    # cuts would hide the one moment when intervening is still possible.
    logger.warning(
        "Key deletion was scheduled; this starts the countdown that ends in destroyed key "
        'material, and it can be canceled until the window elapses. event=%s kek="%s" %s',
        lifecycle.EVENT_DELETION_SCHEDULED,
        row.kek_resource_name,
        user_context.identity_tail(user=user, os_login_user=os_login_user, user_ip=user_ip),
    )


def restore_kek(row, *, trigger, reason: str = "", user=None, os_login_user: str = "", user_ip=None) -> None:
    """Return a scheduled or retained :class:`KeyEncryptionKey` to ``active``.

    A pure DB state flip back to ``active`` (provider untouched). Valid before
    purge — the window is still open — and after a gate refusal, which made no
    provider call either. Once the provider's delete API has been called the key
    counts as gone and a restore is a manual act outside this application.
    """
    row.record_event(
        lifecycle.EVENT_RESTORED,
        trigger=trigger,
        reason=reason,
        user=user,
        os_login_user=os_login_user,
        user_ip=user_ip,
    )
    if row.undeletable_until:
        row.undeletable_until = None
        row.save(update_fields=["undeletable_until", "updated_at"])
    logger.info(
        "Scheduled key deletion was canceled; the key is usable again and no material was "
        'destroyed. event=%s kek="%s" %s',
        lifecycle.EVENT_RESTORED,
        row.kek_resource_name,
        user_context.identity_tail(user=user, os_login_user=os_login_user, user_ip=user_ip),
    )


def schedule_dek_deletion(row, *, trigger, reason: str = "", user=None, os_login_user: str = "", user_ip=None) -> None:
    """Schedule one :class:`DataEncryptionKey` row for deletion. Destroys nothing.

    The changelist counterpart of :func:`schedule_deletion`, and deliberately
    **row-scoped**: it schedules the selected key and nothing else. Unlike the
    silo-keyed path — which a real silo deletion drives, and which also schedules
    a ``silo_exclusive`` KEK so the provider is not left holding a stranded
    key — an operator acting on one key row must never cascade into the KMS. The
    Key Encryption Keys changelist is where a KEK is scheduled.

    Records ``deletion_scheduled`` with the standard window expiry
    (``KEY_DELETION_WINDOW_DAYS``) and stamps who did it. Blocks encrypt
    and decrypt for this key, and is fully restorable until the window expires.
    """
    expiry = _window_expiry()
    row.record_event(
        lifecycle.EVENT_DELETION_SCHEDULED,
        trigger=trigger,
        reason=reason,
        user=user,
        os_login_user=os_login_user,
        user_ip=user_ip,
        undeletable_until=expiry,
        silo_ref=row.silo_ref,
    )
    logger.warning(
        "Key deletion was scheduled; this starts the countdown that ends in destroyed key "
        'material, and it can be canceled until the window elapses. event=%s silo="%s" purpose=%s %s',
        lifecycle.EVENT_DELETION_SCHEDULED,
        row.silo_ref,
        row.purpose,
        user_context.identity_tail(user=user, os_login_user=os_login_user, user_ip=user_ip),
    )


def restore_dek(row, *, trigger, reason: str = "", user=None, os_login_user: str = "", user_ip=None) -> None:
    """Reverse a scheduled :class:`DataEncryptionKey` deletion, row-scoped.

    The undo for :func:`schedule_dek_deletion`, and scoped to match it: it
    restores the selected row and leaves every KEK alone. Only valid before
    purge — once the window has expired and ``encrypted_keyset`` has been
    cleared, the key is gone and nothing can bring it back.
    """
    row.record_event(
        lifecycle.EVENT_RESTORED,
        trigger=trigger,
        reason=reason,
        user=user,
        os_login_user=os_login_user,
        user_ip=user_ip,
        silo_ref=row.silo_ref,
        status=_restored_status(row),
    )
    logger.info(
        "Scheduled key deletion was canceled; the key is usable again, or back under its rotation, and "
        'no material was destroyed. event=%s silo="%s" purpose=%s %s',
        lifecycle.EVENT_RESTORED,
        row.silo_ref,
        row.purpose,
        user_context.identity_tail(user=user, os_login_user=os_login_user, user_ip=user_ip),
    )
    if row.undeletable_until:
        row.undeletable_until = None
        row.save(update_fields=["undeletable_until", "updated_at"])


# ---------------------------------------------------------------------------
# Gates
# ---------------------------------------------------------------------------


def evaluate_deletion(
    disposition, owner_prefix, provisioner, kek_resource_name, *, owned_names=frozenset()
) -> tuple[bool, str]:
    """Return ``(eligible, reason)`` for deleting *kek_resource_name*.

    The three configuration gates, in order:

    1. ``disposition == silo_exclusive`` — the KEK belongs to exactly one silo.
       Shared/opaque (e.g. ``SharedKekStrategy`` or an unopted ``KEK_MAP`` key)
       is never deleted.
    2. ``provisioner.supports_delete`` — the configured provisioner can delete at
       all (``NullKekProvisioner`` and not-yet-implemented providers cannot).
    3. ``provisioner.owns_kek(name, owner_prefix, owned_names=...)`` — the key name
       carries this deployment's owner prefix, or is a ``KEK_MAP`` key the
       operator marked ``KEK_MAP_DESTROYABLE``, so the key is provably ours.

    When *eligible* is ``True`` the reason is the empty string; otherwise it is
    one of the ``RETAIN_*`` slugs describing the first gate that failed.
    """
    if disposition != KeyEncryptionKey.DISPOSITION_SILO_EXCLUSIVE:
        return False, RETAIN_SHARED_DISPOSITION
    if not provisioner.supports_delete:
        return False, RETAIN_PROVISIONER_CANNOT_DELETE
    if not provisioner.owns_kek(kek_resource_name, owner_prefix, owned_names=owned_names):
        return False, RETAIN_NOT_OWNED
    return True, ""


def _live_disposition(row, default):
    """Return the disposition the *current* configuration derives for *row*'s KEK.

    The row carries a snapshot taken when it was scheduled. Where the DEK rows
    naming this KEK are still around, the silos they name can be put back to the
    strategy, which is the authoritative answer now — a strategy swapped from
    per-silo to shared mid-window must not have a stale ``silo_exclusive``
    snapshot spend its permission.

    Tombstones count here. A shredded DEK row no longer needs the KEK, but it
    still records that its silo *used* it, which is what makes the KEK shared.

    Falls back to *default* (the snapshot) when no DEK row names the key — a
    discovered orphan has no silo to ask about — and when any silo answers
    "shared", that answer wins. The strategy asked is that of the KMS the row
    names.
    """
    from .exceptions import EncryptionError
    from .registry import get_kek_strategy_adapter

    silo_refs = [
        SiloRef(key_set, uid) for key_set, uid in row.data_keys.values_list("key_set", "silo_uid").distinct() if uid
    ]
    if not silo_refs:
        return default

    try:
        strategy = get_kek_strategy_adapter(row.key_store)
        dispositions = {strategy.kek_disposition(ref) for ref in silo_refs}
    except EncryptionError:
        # Already logged with its slug. An unresolvable strategy must not grant
        # permission, so answer with the gate-failing value.
        return KeyEncryptionKey.DISPOSITION_SHARED
    except Exception as exc:
        from ._internal import operator_error_text

        logger.warning(
            "This key's disposition could not be read, so it is treated as shared and will be "
            "retained rather than deleted on an unanswered question. assumed_disposition=%s "
            'kek="%s" detail="%s"',
            KeyEncryptionKey.DISPOSITION_SHARED,
            row.kek_resource_name,
            operator_error_text(exc),
        )
        return KeyEncryptionKey.DISPOSITION_SHARED

    if KeyEncryptionKey.DISPOSITION_SILO_EXCLUSIVE in dispositions and len(dispositions) == 1:
        return KeyEncryptionKey.DISPOSITION_SILO_EXCLUSIVE
    return KeyEncryptionKey.DISPOSITION_SHARED


def _kek_still_in_use(row, now) -> bool:
    """Whether any un-shredded DEK still depends on this KEK.

    The hazard the disposition gate is a proxy for, tested directly: a DEK row
    whose ``encrypted_keyset`` is still present can only ever be unwrapped by
    this KEK, so destroying it destroys that silo's data.

    Status is not the test — the keyset is. A ``deletion_scheduled`` row whose
    window has not expired is restorable and its keyset is intact, so it still
    depends on the key; a ``deleted`` tombstone has been shredded and depends on
    nothing.

    Rows this same run shreds are excluded. A live run shreds the DEKs before it
    considers the KEKs, so they are already empty by now; a ``--dry-run`` shreds
    nothing, and without the exclusion the preview would report a retain where
    the real run deletes. Excluding them makes the two agree, which is the whole
    point of the preview.

    A data key rotation's incoming keyset counts the same way: it is a silo's
    material wrapped by this key, and after the swap it is the only copy. It goes
    with its data key when that key is shredded, so the same exclusion applies.
    """
    return (
        row.data_keys.exclude(encrypted_keyset=b"")
        .exclude(status=lifecycle.STATUS_DELETION_SCHEDULED, undeletable_until__lte=now)
        .exists()
    ) or (
        row.dek_rotations.exclude(
            dek__status=lifecycle.STATUS_DELETION_SCHEDULED, dek__undeletable_until__lte=now
        ).exists()
    )


# ---------------------------------------------------------------------------
# Purge
# ---------------------------------------------------------------------------

# Per-KEK purge outcomes.
PURGE_SKIPPED = "skipped"
PURGE_FAILED = "failed"
PURGE_RETAINED = "retained"
PURGE_REQUESTED = "requested"
PURGE_DELETED = "deleted"


@dataclass
class DekPurgeSummary:
    """Tallied outcome of a :func:`purge_expired_deks` run.

    ``details`` is populated on a dry run only: one ``(verb, label)`` pair per row
    the real run would act on, so a caller can show what is about to happen rather
    than only how much.
    """

    purged: int = 0
    #: Rows a gate refused. They stay scheduled and can be retried — unlike a
    #: retained key encryption key, nothing about them changes.
    retained: int = 0
    #: ``RETAIN_*`` slugs seen this run, for explaining the retained count.
    retain_reasons: set = field(default_factory=set)
    details: list = field(default_factory=list)


@dataclass
class KekPurgeSummary:
    """Tallied outcome of a :func:`purge_expired_keks` run.

    ``retained`` and ``failed`` are counted apart on purpose: retained means a
    gate refused the key (expected wherever the provisioner cannot delete),
    failed means the provider call errored.
    """

    deleted: int = 0
    requested: int = 0
    retained: int = 0
    failed: int = 0
    skipped: int = 0
    details: list = field(default_factory=list)
    #: KMS names seen on the rows this run skipped. A skip only ever means no
    #: ``KMS_KEY_STORES`` block carries the row's name, so callers use this to
    #: explain the count — most usefully, that the run may be under the wrong
    #: settings.
    skipped_key_stores: set = field(default_factory=set)


def purge_expired_deks(
    *, trigger, reason: str = "", user=None, os_login_user: str = "", user_ip=None, dry_run: bool = False, pks=None
) -> DekPurgeSummary:
    """Shred data encryption keys whose restore window has closed.

    The window closing destroys nothing by itself — it only lifts the bar on
    destroying. This function is that act. The package ships no command that
    calls it: a destroyed keyset has no provider window behind it and no gate in
    front of it, so the shipped path is a person on the Data Encryption Keys
    changelist, confirming what they are about to lose. Projects that do not
    expose the admin can call this from their own tooling — see
    :doc:`management-commands` for what that costs.

    Clears ``encrypted_keyset`` on each row whose window has expired (``status ==
    deletion_scheduled`` and ``undeletable_until <= now``), leaving a ``deleted``
    tombstone. No gate: a silo's own data encryption key is always its to destroy
    once the window has run, and the disposition branch was applied at schedule
    time. ``PURPOSE_TEST`` rows shred the same way.

    *pks* restricts to rows an operator selected; the window still decides, so it
    can only ever shrink the candidate set. *dry_run* previews the same decisions
    without clearing anything, filling ``details``.
    """
    now = timezone.now()
    summary = DekPurgeSummary()

    expired = (
        DataEncryptionKey.objects.filter(
            status=lifecycle.STATUS_DELETION_SCHEDULED,
            undeletable_until__lte=now,
        )
        .select_related("kek")
        .order_by("undeletable_until")
    )
    if pks is not None:
        expired = expired.filter(pk__in=pks)
    for dek in expired:
        label = f"{dek.kek.key_store}:{dek.kek.kek_resource_name} silo={dek.silo_ref}"
        retain_reason = dek_retain_reason(dek.silo_ref)
        if retain_reason is not None:
            summary.retained += 1
            summary.retain_reasons.add(retain_reason)
            if dry_run:
                summary.details.append(("RETAIN", label, retain_reason))
            else:
                # The attempt is recorded; the status is not moved. Every refusal
                # on this side is transient — a live silo, or an adapter that
                # could not answer — so the row stays scheduled and the operator
                # can delete the silo (or fix the adapter) and retry.
                dek.record_event(
                    lifecycle.EVENT_DELETION_FAILED,
                    trigger=trigger,
                    user=user,
                    os_login_user=os_login_user,
                    user_ip=user_ip,
                    reason=retain_reason,
                    status=retain_status(retain_reason),
                )
                logger.info(
                    "Key deletion was refused; the key is unchanged and the row stays scheduled, "
                    'so a retry once the reason is dealt with will proceed. event=%s reason=%s silo="%s" %s',
                    lifecycle.EVENT_DELETION_FAILED,
                    retain_reason,
                    dek.silo_ref,
                    user_context.identity_tail(user=user, os_login_user=os_login_user, user_ip=user_ip),
                )
            continue
        if dry_run:
            summary.details.append(("SHRED", label, ""))
            summary.purged += 1
            continue
        _purge_dek(dek, trigger=trigger, reason=reason, user=user, os_login_user=os_login_user, user_ip=user_ip)
        summary.purged += 1
    return summary


def purge_expired_keks(
    *,
    trigger,
    reason: str = "",
    user=None,
    os_login_user: str = "",
    user_ip=None,
    dry_run: bool = False,
    pks=None,
) -> KekPurgeSummary:
    """Delete key encryption keys whose restore window has closed.

    Kept separate from :func:`purge_expired_deks` deliberately. The two destroy
    different things with different consequences, and neither should ever happen
    as a side effect of the other — one clears a row this deployment owns
    outright, the other makes an irreversible call to a KMS. As with the data
    side, no shipped command calls this; the Key Encryption Keys changelist is the
    path, and custom tooling is the project's own decision.

    Every gate is re-checked here, at the moment of destruction, rather than
    trusted from schedule time — see :func:`evaluate_deletion`. A refusal records
    its reason and retains the key.

    Order against the data-side purge does not matter. The in-use gate reads
    keysets rather than statuses and treats a row whose own window has expired as
    already gone, so a key is retained only for silos that could still lose live
    data.

    *pks* restricts to rows an operator selected. *dry_run* previews through the
    same gates without calling the provider, filling ``details``.

    Each key is deleted through the provisioner of the KMS its row names, and
    its ownership is judged against that KMS's owner prefix. A key on a KMS no
    block names is skipped untouched.
    """
    from .conf import kms_block

    now = timezone.now()
    summary = KekPurgeSummary()
    # Read once per KMS per run rather than per row.

    expired = KeyEncryptionKey.objects.filter(
        status=lifecycle.STATUS_DELETION_SCHEDULED,
        undeletable_until__lte=now,
    ).order_by("undeletable_until")
    if pks is not None:
        expired = expired.filter(pk__in=pks)
    for kek in expired:
        outcome, retain_reason = _purge_kek(
            kek,
            live_owner_prefix=(
                live_owner_prefix(kek.key_store, kek_name=kek.kek_resource_name)
                if kms_block(kek.key_store) is not None
                else ""
            ),
            now=now,
            trigger=trigger,
            reason=reason,
            user=user,
            os_login_user=os_login_user,
            user_ip=user_ip,
            dry_run=dry_run,
        )
        if dry_run:
            verb = {
                PURGE_DELETED: "DELETE",
                PURGE_RETAINED: "RETAIN",
                PURGE_FAILED: "FAIL",
                PURGE_SKIPPED: "SKIP",
            }[outcome]
            summary.details.append((verb, f"{kek.key_store}:{kek.kek_resource_name}", retain_reason))
        if outcome == PURGE_SKIPPED:
            summary.skipped += 1
            summary.skipped_key_stores.add(kek.key_store)
        elif outcome == PURGE_RETAINED:
            summary.retained += 1
        elif outcome == PURGE_FAILED:
            summary.failed += 1
        elif outcome == PURGE_REQUESTED:
            summary.requested += 1
        elif outcome == PURGE_DELETED:
            summary.deleted += 1
    return summary


def _purge_dek(row, *, trigger, reason: str = "", user=None, os_login_user: str = "", user_ip=None) -> None:
    """Clear a DEK row's wrapped keyset (the crypto-shred) and tombstone it.

    The field-clear and the ``deleted`` ledger event are written in one
    transaction so material is never destroyed unrecorded. The row survives as a
    ``deleted`` tombstone holding silo_ref / purpose / the KEK reference.

    A rotation still open on the key is abandoned here, in the same transaction
    and before the keyset is cleared — the moment it actually becomes
    unrecoverable, which is what keeps every rotation in the ledger opening and
    closing exactly once. Its row goes too: it holds the same silo's material
    wrapped under a second key encryption key, so leaving it would make the
    crypto-shred partial.
    """
    from .models import DekRotation, DekRotationWorkItem

    abandoned = False
    with transaction.atomic():
        rotation = DekRotation.objects.filter(dek=row).first()
        if rotation is not None:
            DekRotationWorkItem.objects.filter(dek=row).delete()
            rotation.delete()
            row.record_event(
                lifecycle.EVENT_ROTATION_ABANDONED,
                trigger=trigger,
                user=user,
                os_login_user=os_login_user,
                user_ip=user_ip,
                reason=lifecycle.REASON_DEK_DELETED,
            )
            abandoned = True
        if row.encrypted_keyset:
            row.encrypted_keyset = b""
            row.save(update_fields=["encrypted_keyset", "updated_at"])
        row.record_event(
            lifecycle.EVENT_DELETED,
            trigger=trigger,
            reason=reason,
            user=user,
            os_login_user=os_login_user,
            user_ip=user_ip,
        )
    if abandoned:
        logger.warning(
            "A data key rotation was abandoned because the key it was rotating was destroyed; its incoming "
            'key material went with it. event=%s reason=%s silo="%s" purpose=%s %s',
            lifecycle.EVENT_ROTATION_ABANDONED,
            lifecycle.REASON_DEK_DELETED,
            row.silo_ref,
            row.purpose,
            user_context.identity_tail(user=user, os_login_user=os_login_user, user_ip=user_ip),
        )
    logger.warning(
        "Key material was destroyed; the row survives as a tombstone recording the silo, "
        'purpose, and key it belonged to. event=%s silo="%s" purpose=%s kek="%s" %s',
        lifecycle.EVENT_DELETED,
        row.silo_ref,
        row.purpose,
        row.kek.kek_resource_name,
        user_context.identity_tail(user=user, os_login_user=os_login_user, user_ip=user_ip),
    )


def live_owner_prefix(key_store: str, *, kek_name: str = "") -> str:
    """Return the owner prefix the *current* configuration derives for named store *key_store*, or ``""``.

    A key known only by its name (*kek_name*) is classified by the store's
    prefix: the prefixes are prefix-free across stores, so a name matches at most
    one store's. A ``KEK_MAP`` key the operator marked ``KEK_MAP_DESTROYABLE`` is
    owned without the prefix and snapshots the store's prefix too, so every path
    that schedules a key records the same value for it. Without a name, it is the
    store's prefix itself.

    Never raised from: a configuration error resolving the strategy yields
    ``""``, which fails the ownership gate and retains every key on that KMS.
    Refusing to delete on a broken config is the only safe reading, since the
    gate exists to prove a key is ours.
    """
    from ._internal import operator_error_text
    from .exceptions import EncryptionError
    from .registry import get_kms_adapter

    try:
        adapter = get_kms_adapter(key_store)
        prefix = adapter.owner_prefix() or ""
        if kek_name and not kek_name.startswith(prefix) and kek_name not in adapter.owned_mapped_kek_names():
            return ""
        return prefix
    except EncryptionError:
        # Already logged with its slug by the raising helper. Retaining is the
        # safe outcome, so it is swallowed rather than failing the whole run.
        return ""
    except Exception as exc:
        # One clean English line, no traceback: an operator reading this should
        # see what to fix, not frames pointing into the package.
        logger.warning(
            "The configured owner prefix could not be resolved, so no key on this KMS can be "
            "confirmed as this deployment's and every one will be retained; scheduled deletions "
            'there have stopped happening until this is fixed. key_store=%s detail="%s"',
            key_store,
            operator_error_text(exc),
        )
        return ""


def live_owned_names(key_store: str) -> frozenset[str]:
    """Return the ``KEK_MAP`` keys the *current* configuration marks owned for store *key_store*.

    The counterpart of :func:`live_owner_prefix` for mapped keys, and never raised
    from for the same reason: a store that cannot be resolved owns nothing, which
    retains its keys.
    """
    from .registry import get_kms_adapter

    try:
        return get_kms_adapter(key_store).owned_mapped_kek_names()
    except Exception:
        # live_owner_prefix has already logged why this store cannot be resolved.
        return frozenset()


def _purge_kek(
    row,
    *,
    live_owner_prefix: str = "",
    now=None,
    trigger,
    reason: str = "",
    user=None,
    os_login_user: str = "",
    user_ip=None,
    dry_run: bool = False,
) -> str:
    """Process one expired scheduled :class:`KeyEncryptionKey` row.

    Returns ``(PURGE_* outcome, retain_reason)``. The reason is a ``RETAIN_*``
    slug when the outcome is ``PURGE_RETAINED`` and ``""`` otherwise — carried out
    rather than only logged so a dry run can report *which* gate refused.

    Re-checks the deletion gates, then asks the provisioner to delete the
    key. The provider response branches the terminal state: a provider recovery
    window → ``deletion_requested`` (only reconcile enumeration may later confirm
    it ``deleted``); an immediate delete → ``deleted`` directly.

    Both non-success outcomes record the same ``deletion_failed`` verb — the
    deletion did not happen either way — but they land in different statuses,
    because they call for different operator responses:

    * a **gate refusal** carries the ``RETAIN_*`` slug as its reason and moves the
      row to ``retained`` — the key still exists on the provider and this
      deployment will not delete it. Routine, not a fault: scheduling only
      pre-checks the disposition gate, so any deployment whose provisioner cannot
      delete lands every scheduled key here. The operator deletes it outside this
      application (the Reconcile Keys page names it).
    * a **provider error** carries ``failed_at_provider`` as its reason and moves
      the row to ``deletion_failed`` — we tried and the call failed, so it is
      worth investigating. The provider's own message is in the log, not the row.

    Both move the row off the scheduled queue so the purge does not retry it
    forever. A key on a KMS no block names is skipped untouched.
    """
    from .conf import kms_block
    from .exceptions import EncryptionError
    from .registry import get_kek_provisioner

    label = f"{row.key_store}:{row.kek_resource_name}"

    # Never act on a key whose KMS this configuration lacks — there is nothing
    # to delete it through. Leave it for a run that has the block.
    if kms_block(row.key_store) is None:
        if dry_run:
            return PURGE_SKIPPED, ""
        # WARNING: the command's own output says so, but a log read afterwards
        # would not.
        logger.warning(
            "This key is on a KMS no KMS_KEY_STORES block names, so the purge left it untouched; a "
            "run pointed at the wrong settings module skips every row and looks like a run with "
            'nothing to do. reason=kms_not_configured kek="%s" key_store=%s',
            label,
            row.key_store,
        )
        return PURGE_SKIPPED, ""
    try:
        provisioner = get_kek_provisioner(row.key_store)
    except EncryptionError:
        # A block that cannot be built is a configuration to fix, not a verdict
        # on this key: left queued and untouched, like a block that is missing,
        # so the keys on every other KMS still purge. The raise site logged the
        # detail; this line names the key it held up.
        if not dry_run:
            logger.warning(
                "This key's KMS block could not be built, so the purge left the key untouched and "
                'queued for a later run. reason=kms_not_buildable kek="%s" key_store=%s',
                label,
                row.key_store,
            )
        return PURGE_SKIPPED, ""

    # Authorize against the *live* configuration, not the snapshot taken when the
    # row was scheduled. The snapshot is a stored value, so anything that can
    # write it could otherwise steer an irreversible deletion; and a KEK_TEMPLATE
    # changed during the window means the key was scheduled under naming
    # assumptions that no longer hold. Either way the snapshot only gets to
    # *withhold* permission, never to grant it.
    owner_prefix = live_owner_prefix or None
    owned_names = live_owned_names(row.key_store)
    drift = (row.owner_prefix or "") != (live_owner_prefix or "")

    if drift:
        eligible, retain_reason = False, RETAIN_NOT_OWNED
    elif not allow_deleting_keys_in_use() and _kek_still_in_use(row, now or timezone.now()):
        # Tested directly rather than inferred from the disposition snapshot: an
        # un-shredded DEK can only be unwrapped by this key. Skipped when
        # KEY_DELETION_CAN_RENDER_DATA_INACCESSIBLE is on — the operator has
        # said they mean to make those silos' data unreadable. The other three
        # gates still apply: this one guards the data, they guard whether the key
        # is ours to destroy at all.
        eligible, retain_reason = False, RETAIN_IN_USE
    else:
        eligible, retain_reason = evaluate_deletion(
            _live_disposition(row, row.disposition),
            owner_prefix,
            provisioner,
            row.kek_resource_name,
            owned_names=owned_names,
        )

    if dry_run:
        # Carry the reason out: a preview that says only "retained" sends the
        # operator to the source to learn which gate refused, which is the one
        # thing they needed the preview for.
        return (PURGE_DELETED, "") if eligible else (PURGE_RETAINED, retain_reason)

    if not eligible:
        _record_kek_refusal(
            row, retain_reason, trigger=trigger, user=user, os_login_user=os_login_user, user_ip=user_ip
        )
        if drift:
            # WARNING against the routine refusal's INFO: drift means the running
            # configuration stopped matching what these keys were scheduled
            # under, so deletions have quietly stopped happening and nothing else
            # will say so.
            logger.warning(
                "Key deletion was refused, and these keys were scheduled under a different owner "
                "prefix than the one now configured, so deletions have quietly stopped happening. "
                'event=%s reason=%s scheduled_under="%s" configured="%s" kek="%s" %s',
                lifecycle.EVENT_DELETION_FAILED,
                retain_reason,
                row.owner_prefix,
                live_owner_prefix,
                label,
                user_context.identity_tail(user=user, os_login_user=os_login_user, user_ip=user_ip),
            )
        elif retain_reason in TERMINAL_RETAIN_REASONS:
            logger.info(
                "Key deletion was refused; the key is unchanged and leaves the deletion queue. "
                'event=%s reason=%s kek="%s" %s',
                lifecycle.EVENT_DELETION_FAILED,
                retain_reason,
                label,
                user_context.identity_tail(user=user, os_login_user=os_login_user, user_ip=user_ip),
            )
        else:
            logger.info(
                "Key deletion was refused; the key is unchanged and stays queued, so a retry once "
                'the reason is dealt with will proceed. event=%s reason=%s kek="%s" %s',
                lifecycle.EVENT_DELETION_FAILED,
                retain_reason,
                label,
                user_context.identity_tail(user=user, os_login_user=os_login_user, user_ip=user_ip),
            )
        return PURGE_RETAINED, retain_reason

    try:
        outcome = provisioner.delete_kek(row.kek_resource_name, "", owner_prefix=owner_prefix, owned_names=owned_names)
    except EncryptionError:
        # The deletion funnel already logged the error_code=kek_delete_failed detail.
        _record_kek_failure(row, trigger=trigger, user=user, os_login_user=os_login_user, user_ip=user_ip)
        return PURGE_FAILED, ""

    # The provider was asked and answered, on either outcome.
    row.record_event(
        outcome.event,
        trigger=trigger,
        reason=lifecycle.REASON_OBSERVED_AT_PROVIDER,
        user=user,
        os_login_user=os_login_user,
        user_ip=user_ip,
        kms_deletion_at=outcome.effective_at,
    )
    return (PURGE_REQUESTED if outcome.scheduled else PURGE_DELETED), ""


def _record_kek_failure(row, *, trigger, user=None, os_login_user="", user_ip=None) -> None:
    """Record a provider error: a ``deletion_failed`` event reasoned at the provider.

    The ledger counts the attempts — one ``deletion_failed`` event each. The
    provider's own message is not copied onto the row: the log carries it
    untruncated, under the raise site's error code, with the key encryption key
    resource name and silo uid beside it, which is what joins a log line to a
    ledger row.

    The status is passed explicitly because the same verb also records a gate
    refusal, which ends somewhere else entirely; only this branch means the
    provider was asked and the call raised.
    """
    row.record_event(
        lifecycle.EVENT_DELETION_FAILED,
        trigger=trigger,
        reason=lifecycle.REASON_FAILED_AT_PROVIDER,
        user=user,
        os_login_user=os_login_user,
        user_ip=user_ip,
        status=lifecycle.STATUS_DELETION_FAILED,
    )


def _record_kek_refusal(row, retain_reason, *, trigger, user=None, os_login_user="", user_ip=None) -> None:
    """Record a gate refusal: a ``deletion_failed`` event with the ``RETAIN_*`` slug.

    Same verb as a provider error — the deletion did not happen either way — and
    the two are told apart by what fills the ``reason``. The stable slug says *why* the
    key was kept in a language-neutral, greppable form, and decides the resulting
    status: terminal refusals land in ``retained`` and leave the queue, transient
    ones leave the row scheduled to be retried.
    """
    row.record_event(
        lifecycle.EVENT_DELETION_FAILED,
        trigger=trigger,
        reason=retain_reason,
        user=user,
        os_login_user=os_login_user,
        user_ip=user_ip,
        status=retain_status(retain_reason),
    )
