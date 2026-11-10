"""Registry-backed orchestration for the reconcile engine — discovery and sync.

:mod:`encryption_suite.reconcile` is deliberately pure (set logic only). This
module performs the registry/DB I/O it cannot — enumerating silos, resolving the
expected KEK name for each, listing the key encryption keys this deployment owns — feeds the
resolved sets into the pure engine, and then **syncs the findings onto the
durable :class:`~encryption_suite.models.KeyEncryptionKey` rows**: discovering never-tracked
keys, stamping the orphan annotation when it changes, confirming
provider-window deletions the enumeration witnessed, and flagging drift.

Discovery writes *records and annotations, never deletes* — the cardinal safety
rule. A *missing* detection degrades to **detection-unavailable**, never to
"nothing exists": an adapter that cannot enumerate (or whose enumeration raises)
contributes ``None``, and the sync is skipped entirely for that pass, because a
false orphan here ends in an unrecoverable key deletion. Only the enumeration
listing — never the ledger — may confirm a ``deletion_requested`` key gone.

Kept separate from the pure engine so the latter stays testable without a
database or a KMS, and so every caller shares exactly one reconcile path — the
report an operator sees and the rows a later action re-verifies against can never
drift.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timedelta

from django.db import transaction
from django.utils import timezone

from . import user_context
from ._logging import get_logger
from .lifecycle import REASON_DETERMINED_BY_RECONCILE, REASON_OBSERVED_AT_PROVIDER, TRIGGER_AUTOMATED
from .reconcile import ReconcileReport, build_reconcile_report

logger = get_logger(__name__)


@dataclass(frozen=True)
class ReconcileResult:
    """A reconcile pass plus the registry facts and sync findings beside it.

    ``owner_prefix`` is ``""`` (not ``None``) when ownership cannot be derived
    (shared / ``KEK_MAP`` configs), so it drops straight into a ``KeyEncryptionKey``
    ``owner_prefix`` CharField. ``kms_kek_names`` is the live KMS listing
    (owner-filtered) when enumeration ran, or ``None`` when it was unavailable —
    the same detection-unavailable signal the engine uses.

    The five sync lists are the persisted-this-pass findings (empty when
    enumeration was unavailable): ``discovered`` keys got a new ``KeyEncryptionKey`` row;
    ``observed_pending`` were ``active`` keys the provider reports as already
    scheduled for deletion (now ``deletion_requested``);
    ``confirmed_deleted`` were ``deletion_requested`` keys the enumeration found
    gone (now ``deleted``); ``drift_overdue`` are ``deletion_requested`` keys
    still listed past their effective date (canceled in the KMS, or failed);
    ``drift_missing`` are ``active`` / ``deletion_scheduled`` keys absent from the
    listing (deleted in the KMS). Drift is flagged for the operator, never
    auto-actioned.
    """

    report: ReconcileReport
    owner_prefix: str
    #: The key store this pass covered.
    key_store: str
    kms_kek_names: frozenset[str] | None
    expected_kek_names: frozenset[str]
    discovered: tuple = ()
    observed_pending: tuple = ()
    confirmed_deleted: tuple = ()
    drift_overdue: tuple = ()
    drift_missing: tuple = ()
    #: Keys whose material the provider reports at a version this deployment had
    #: not recorded — the ledger's record of what obliges a re-encryption.
    rotated: tuple = ()
    #: True when the rotation check stopped at its probe budget, so the answer
    #: covers only part of the keys.
    probes_capped: bool = False


@dataclass
class _SyncFindings:
    discovered: list = field(default_factory=list)
    observed_pending: list = field(default_factory=list)
    confirmed_deleted: list = field(default_factory=list)
    drift_overdue: list = field(default_factory=list)
    drift_missing: list = field(default_factory=list)


def _overdue_material_cutoff():
    """The moment before which data key material counts as overdue, or ``None``.

    ``None`` when no cryptoperiod is declared — the same thing as "the question
    has no answer", which the report turns into a degraded slug rather than an
    empty finding.
    """
    from .conf import enc_settings

    period = _period_days(enc_settings.DEK_ROTATION_PERIOD_DAYS)
    return None if period is None else timezone.now() - timedelta(days=period)


def _period_days(value):
    """Coerce a configured cryptoperiod to a whole number of days, or ``None``.

    ``None`` means "not declared", and so does any value that is not a
    non-negative whole number — a typo cannot be honored, and guessing at one
    would put a wrong date in front of an auditor. ``0`` is kept and is **not**
    the same as unset: it declares a period that has already elapsed, so every
    key reads as overdue. That matches ``KEY_DELETION_WINDOW_DAYS``, where ``0``
    is likewise a real setting rather than an absent one.
    """
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        logger.error(
            "ENCRYPTION['DEK_ROTATION_PERIOD_DAYS'] must be a non-negative whole number of days "
            "or None; got %r. Ignoring it — no rotation-due finding will be reported.",
            value,
        )
        return None
    return value


def _resolve_key_material(kms_adapter, key_store: str):
    """Read the active key rows and ask the provider for its current versions.

    The I/O half of the key-material dimension; the comparison itself is pure and
    lives in :func:`reconcile.build_reconcile_report`.

    The provider is asked **once per distinct key encryption key**, not once per
    row — a silo's field and file keys share one — and adapters cache the answer
    for their own version TTL, so a pass costs one lookup per key rather than one
    per row. Under a per-silo key strategy that is still one call per silo, which
    is why this runs on an operator-triggered reconcile and never on a changelist.

    Every probe failure degrades that key to "version unknown", leaving its rows
    out of the findings. Reporting a key as current because the lookup failed
    would be the one wrong answer available here. The failed names are returned
    alongside, so the report can tell "this provider has no versions" (permanent,
    uninteresting) from "the lookups failed" (an incident).
    """
    from ._internal import operator_error_text
    from .deletion import LIVE_DEK_STATUSES
    from .models import DataEncryptionKey

    # A key under rotation still holds the material its data is on, so its age
    # and wrapping are as live a question as an active key's.
    rows = [
        {
            "silo_ref": row.silo_ref,
            "key_set": row.key_set,
            "purpose": row.purpose,
            "key_material_last_generated_at": row.key_material_last_generated_at,
            "last_reencrypted_at": row.last_reencrypted_at,
            "kek_resource_name": row.kek.kek_resource_name,
            "kek_key_version": row.kek_key_version,
        }
        for row in (
            DataEncryptionKey.objects.exclude(purpose=DataEncryptionKey.PURPOSE_TEST)
            .filter(status__in=LIVE_DEK_STATUSES, kek__key_store=key_store)
            .select_related("kek")
        )
    ]

    current_versions: dict[str, str] = {}
    probe_failures: set[str] = set()
    for row in rows:
        name = row["kek_resource_name"]
        if name in current_versions:
            continue
        try:
            current_versions[name] = kms_adapter.current_kek_version(row["silo_ref"]) or ""
        except Exception as exc:
            current_versions[name] = ""
            probe_failures.add(name)
            logger.warning(
                "The provider would not report this key's current version, so the re-encryption "
                'check cannot tell a superseded key from an up-to-date one. kek="%s" detail="%s"',
                name,
                operator_error_text(exc),
            )
    return rows, current_versions, probe_failures


def stores_in_play(*, include_env: bool = False) -> list[str]:
    """The configured stores that matter: the ones key sets use, then the ones still holding keys.

    A store no key set uses is included while it still holds a key encryption key
    row that is not ``deleted``, because a store being moved off has no key set
    pointing at it and ``reencrypt_keys`` still has to drain it. A configured
    store that nothing uses and nothing holds is left out. An env store is left
    out unless *include_env*: it has no provider to list.
    """
    from .conf import is_env_store, key_set_names, kms_names, resolve_store
    from .lifecycle import STATUS_DELETED
    from .models import KeyEncryptionKey

    in_use = {store for key_set in key_set_names() if (store := resolve_store(key_set))}
    holding = set(
        KeyEncryptionKey.objects.exclude(status=STATUS_DELETED).values_list("key_store", flat=True).distinct()
    )
    return [name for name in kms_names() if name in in_use | holding and (include_env or not is_env_store(name))]


def stores_to_reconcile() -> list[str]:
    """Every store a full reconcile run covers. See :func:`stores_in_play`; env stores are left out."""
    return stores_in_play()


def run_reconcile(
    *,
    key_store: str | None = None,
    trigger: str = TRIGGER_AUTOMATED,
    user=None,
    os_login_user: str = "",
    user_ip=None,
) -> ReconcileResult:
    """Resolve every enumeration input, build the report, and sync the KeyEncryptionKey rows.

    One pass covers one key store, *key_store* (by default the ``default`` key set's store): the keys it
    lists, the key encryption key rows that name it, and the data keys wrapped
    under them. The data-key orphan annotation does not depend on the KMS, so
    every pass repeats it, idempotently.

    Every row this pass writes carries *trigger*, because how the pass was
    started is the one thing the sweep itself cannot know. A command or a
    schedule leaves it at ``automated``, the default; the admin page passes
    ``indirect``, since the operator asked for a pass and these events followed
    from it — not one of them is a thing anyone asked for by name.

    The identity comes from the caller too: the admin page passes the operator
    who pressed the button, the ``reconcile_keys`` command a resolved OS login,
    and an unattended run neither.
    """
    from .conf import resolve_store
    from .deletion import LIVE_DEK_STATUSES
    from .exceptions import EncryptionError
    from .models import DataEncryptionKey
    from .registry import all_key_sets, get_kek_provisioner, get_kms_adapter, silo_adapter_groups, silo_kms_name
    from .silo_ref import SiloRef

    key_store = key_store or silo_kms_name()
    provisioner = get_kek_provisioner(key_store)
    kms_adapter = get_kms_adapter(key_store)
    # The store's one owner prefix, or None when it has no template; the template
    # prefixes are prefix-free across stores, so a listed key belongs to at most
    # one store.
    owner_prefix = kms_adapter.owner_prefix() or None
    # A key set whose new keys go to this store can say what a live silo's key
    # *should* be called. On any other store a live silo's key is the one its data
    # keys still reference there — a store being moved off, whose keys are
    # expected until reencrypt_keys has re-wrapped every row onto the new one.
    derive_key_sets = {key_set for key_set in all_key_sets() if resolve_store(key_set) == key_store}

    # Live silo set: None signals detection-unavailable (an adapter cannot
    # enumerate, or iter_silos raised), never an empty set. Resolve each live
    # silo's expected KEK name so the engine can tell an orphan from a
    # still-backed key.
    live_silo_uids: set[SiloRef] | None = None
    expected_kek_names: set[str] = set()
    # The same derivation, kept rather than discarded: it is the best probe
    # address for every key a live silo maps to, verified by construction, and it
    # covers keys being discovered for the first time this pass. First silo wins.
    uid_by_kek_name: dict[str, SiloRef] = {}
    # Tracked apart from the ``None`` for the same reason as the KMS listing
    # below: an adapter that cannot enumerate and one whose enumeration raised
    # produce the same value and mean opposite things.
    silo_listing_failed = False
    live: set[SiloRef] | None = set()
    # Liveness is asked once per adapter; a live silo is live in every key set bound to its adapter.
    for silo_adapter, key_sets in silo_adapter_groups():
        if not silo_adapter.supports_enumeration:
            live = None
            break
        try:
            for silo in silo_adapter.iter_silos():
                uid = silo_adapter.get_silo_uid(silo)
                live.update(SiloRef(key_set, uid) for key_set in key_sets)
        except Exception as exc:
            # A typed error was logged where it was raised. Anything else —
            # a project adapter's own error, a database error mid-listing —
            # would otherwise leave "listing failed" on the page and nothing
            # in the log to say why.
            if not isinstance(exc, EncryptionError):
                from ._internal import operator_error_text

                logger.error(
                    "The silo adapter's listing failed, so this reconcile pass reports no orphans. "
                    'error_code=silo_enumeration_unavailable adapter=%s detail="%s"',
                    type(silo_adapter).__name__,
                    operator_error_text(exc),
                )
            live = None
            silo_listing_failed = True
            break
    # Live silos whose expected key name raised; reported below, once the pass
    # knows whether the KMS listing ran.
    unresolved: list[tuple[SiloRef, Exception]] = []
    if live is not None:
        live_silo_uids = live
        for ref in live:
            # Only silos whose keys this store makes.
            if ref.key_set not in derive_key_sets:
                continue
            try:
                name = kms_adapter.resolve_kek_name(ref)
            except Exception as exc:
                # Skipped, not fatal: the silo's data keys below still add the
                # name they reference. Logged, because a live silo whose key has
                # no data key yet can now read as an orphan.
                unresolved.append((ref, exc))
                continue
            if name:
                expected_kek_names.add(name)
                uid_by_kek_name.setdefault(name, ref)
        for key_set, uid, name in (
            DataEncryptionKey.objects.filter(status__in=LIVE_DEK_STATUSES, kek__key_store=key_store)
            .values_list("key_set", "silo_uid", "kek__kek_resource_name")
            .distinct()
        ):
            if SiloRef(key_set, uid) in live:
                expected_kek_names.add(name)
                uid_by_kek_name.setdefault(name, SiloRef(key_set, uid))
        # A test-console KEK is expected only while a test key actually
        # exists. The sentinel UIDs are reserved so that no real silo can
        # resolve to them, so a live test KEK would otherwise read as a
        # permanent false orphan. But a test KEK whose rows are gone is a
        # genuine leftover — it still costs money — so it must keep falling
        # through to the orphan report. Keyed off the stored name, not a
        # freshly resolved one, so a strategy change cannot hide it either.
        expected_kek_names.update(
            DataEncryptionKey.objects.filter(purpose=DataEncryptionKey.PURPOSE_TEST, kek__key_store=key_store)
            .values_list("kek__kek_resource_name", flat=True)
            .distinct()
        )

    kms_kek_names: set[str] | None = None
    # Tracked apart from the ``None`` because ``None`` has three causes — the
    # silo set is untrustworthy, the provisioner cannot list, or the listing
    # raised — and only the last is something going wrong. The report cannot tell
    # them apart from the value alone.
    kms_listing_failed = False
    if live_silo_uids is not None and provisioner.supports_enumeration and owner_prefix:
        try:
            kms_kek_names = set(provisioner.list_kek_names(owner_prefix))
        except EncryptionError:
            kms_kek_names = None  # the enumeration funnel already logged the detail
            kms_listing_failed = True

    # Only where the listing ran: that is the only pass in which a skipped name
    # can turn into a reported orphan. A store with no owner prefix — a KEK_MAP
    # with no template, where an unmapped silo raises on every pass — never lists
    # its keys, so the line would repeat forever and claim a consequence that
    # cannot happen.
    if unresolved and kms_kek_names is not None:
        from ._internal import operator_error_text

        first_ref, first_exc = unresolved[0]
        logger.warning(
            "The expected key encryption key name could not be resolved for some live silos, so a key "
            "of theirs that no data key uses yet may be reported as an orphan this pass. "
            'key_store=%s silos=%d first_silo="%s" detail="%s"',
            key_store,
            len(unresolved),
            first_ref,
            operator_error_text(first_exc),
        )

    # Test-console rows are excluded on the DEK side for the same reason their
    # KEK is treated as expected above: their sentinel UID is never a live silo,
    # so they would read as orphans for as long as a test key exists.
    stored_uids = {
        SiloRef(key_set, uid)
        for key_set, uid in DataEncryptionKey.objects.exclude(purpose=DataEncryptionKey.PURPOSE_TEST)
        .values_list("key_set", "silo_uid")
        .distinct()
    }
    key_rows, current_versions, probe_failures = _resolve_key_material(kms_adapter, key_store)
    report = build_reconcile_report(
        stored_uids=stored_uids,
        live_silo_uids=live_silo_uids,
        expected_kek_names=expected_kek_names,
        kms_kek_names=kms_kek_names,
        delete_available=provisioner.supports_delete,
        owner_prefix=owner_prefix,
        silo_listing_failed=silo_listing_failed,
        kms_listing_failed=kms_listing_failed,
        check_key_material=True,
        key_rows=key_rows,
        overdue_cutoff=_overdue_material_cutoff(),
        current_versions=current_versions,
        probe_failures=probe_failures,
    )

    # Sync only when the live listing is trustworthy — never touch the durable
    # rows from a degraded pass (we cannot see the provider, so any inference
    # would be a guess, and a wrong one destroys data later).
    findings = _SyncFindings()
    if kms_kek_names is not None:
        findings = _sync_keks(
            key_store=key_store,
            owner_prefix=owner_prefix,
            owned_mapped_names=kms_adapter.owned_mapped_kek_names(),
            live_names=kms_kek_names,
            orphan_names=set(report.kms_orphan_keks),
            provisioner=provisioner,
            trigger=trigger,
            user=user,
            os_login_user=os_login_user,
            user_ip=user_ip,
        )

    # The DEK-side annotation is gated on its OWN detection, which needs only
    # silo enumeration. Folding it into _sync_keks would tie it to the
    # stricter KMS gate (provisioner enumeration plus an owner prefix), so on a
    # local / shared-KEK / KEK_MAP deployment every row would read "not
    # orphaned" forever — a false negative, the one direction reconcile must
    # never take.
    if report.db_reconcile_available:
        _sync_deks(
            orphan_uids=report.db_orphan_uids,
            trigger=trigger,
            user=user,
            os_login_user=os_login_user,
            user_ip=user_ip,
        )

    # Gated on its own signal, not on the KMS-enumeration gate _sync_keks uses: a
    # probe needs no listing, so a local / shared-KEK / KEK_MAP deployment still
    # gets rotation detection. Runs after _sync_keks so rows discovered this pass
    # are included.
    rotated, probes_capped = _sync_kek_versions(
        kms_adapter,
        key_store=key_store,
        uid_by_kek_name=uid_by_kek_name,
        current_versions=current_versions,
        probe_failures=probe_failures,
        orphan_names=set(report.kms_orphan_keks),
        trigger=trigger,
        user=user,
        os_login_user=os_login_user,
        user_ip=user_ip,
    )

    return ReconcileResult(
        report=report,
        owner_prefix=owner_prefix or "",
        key_store=key_store,
        kms_kek_names=frozenset(kms_kek_names) if kms_kek_names is not None else None,
        expected_kek_names=frozenset(expected_kek_names),
        discovered=tuple(findings.discovered),
        observed_pending=tuple(findings.observed_pending),
        confirmed_deleted=tuple(findings.confirmed_deleted),
        drift_overdue=tuple(findings.drift_overdue),
        drift_missing=tuple(findings.drift_missing),
        rotated=tuple(rotated),
        probes_capped=probes_capped,
    )


def _sync_deks(*, orphan_uids, trigger=TRIGGER_AUTOMATED, user=None, os_login_user="", user_ip=None) -> None:
    """Stamp the cached orphan annotation onto the ``DataEncryptionKey`` rows.

    The DEK-side counterpart of :func:`_sync_keks`'s annotation step, and the
    only writer of ``is_orphaned`` on those rows: a row is orphaned when no live
    silo resolves to its ``silo_uid``. Display only — every destructive action
    re-verifies against a live enumeration, so a stale annotation can never
    itself cause a deletion.

    **Writes only when the answer changes**, and records a ``silo_found`` /
    ``silo_not_found`` ledger event when it does. A pass that finds nothing new
    touches no row, which is what keeps ``updated_at`` meaningful and makes a
    scheduled reconcile free on a quiet deployment. The ledger, not a column,
    carries when the answer last moved.

    Covers ``active``, ``reencrypting`` and ``deletion_scheduled`` rows. A scheduled row is on its
    way out, but it is still listed on the Reconcile Keys page, so leaving it
    unannotated made the two surfaces disagree.

    Purged tombstones are excluded: their keyset is already cleared, so whether a
    live silo resolves to them decides nothing. So are the test console's
    ``PURPOSE_TEST`` rows, whose sentinel UID is reserved so that no real silo
    resolves to it — they would otherwise read as permanent false orphans.
    """
    from .deletion import LIVE_DEK_STATUSES
    from .lifecycle import EVENT_SILO_FOUND, EVENT_SILO_NOT_FOUND, STATUS_DELETION_SCHEDULED
    from .models import DataEncryptionKey

    rows = DataEncryptionKey.objects.filter(status__in=(*LIVE_DEK_STATUSES, STATUS_DELETION_SCHEDULED)).exclude(
        purpose=DataEncryptionKey.PURPOSE_TEST
    )
    for row in rows:
        is_orphaned = row.silo_ref in orphan_uids
        if row.is_orphaned == is_orphaned:
            continue
        row.is_orphaned = is_orphaned
        row.save(update_fields=["is_orphaned", "updated_at"])
        row.record_event(
            EVENT_SILO_NOT_FOUND if is_orphaned else EVENT_SILO_FOUND,
            trigger=trigger,
            reason=REASON_DETERMINED_BY_RECONCILE,
            user=user,
            os_login_user=os_login_user,
            user_ip=user_ip,
        )


# Most a reconcile pass will probe for provider-side state. A healthy deployment
# has no orphans at all; this only bounds the pathological case so an admin page
# load cannot turn into hundreds of serial provider calls.
_MAX_STATE_PROBES = 25


def _probe_address_for(kms_adapter, row, uid_by_kek_name):
    """Return a silo reference that addresses *row*'s key at the provider, or ``None``.

    ``current_kek_version`` does not require a live silo: name derivation through
    the KEK strategy is local, and the adapter then reads that key by name. So any
    uid that derives this key's name works as a probe address for it, including
    one whose silo is long gone.

    Tried in order: the pairing built from the live silos, then a uid from any
    data key row pointing at the key — an active one first, though a scheduled or
    tombstoned row's uid derives the same name — then the uids snapshotted onto
    its ledger events.

    Every candidate is verified before use. A strategy or ``KEK_MAP`` change can
    leave a uid naming a different key, and stamping one key's version onto
    another's row is the one real hazard here. No verified candidate means no
    probe.
    """
    from .models import DataEncryptionKey, KeyLifecycleEvent
    from .silo_ref import SiloRef

    name = row.kek_resource_name
    candidates = []
    if name in uid_by_kek_name:
        candidates.append(uid_by_kek_name[name])
    candidates.extend(
        SiloRef(key_set, uid)
        for key_set, uid in DataEncryptionKey.objects.filter(kek_id=row.pk)
        .order_by("status", "-updated_at")
        .values_list("key_set", "silo_uid")
    )
    candidates.extend(
        SiloRef(key_set, uid)
        for key_set, uid in KeyLifecycleEvent.objects.filter(kek_id=row.pk)
        .exclude(silo_uid="")
        .values_list("key_set", "silo_uid")
    )

    seen = set()
    for ref in candidates:
        if not ref.uid or ref in seen:
            continue
        seen.add(ref)
        try:
            if kms_adapter.resolve_kek_name(ref) == name:
                return ref
        except Exception:
            continue
    return None


def _sync_kek_versions(
    kms_adapter,
    *,
    key_store,
    uid_by_kek_name,
    current_versions,
    probe_failures,
    orphan_names,
    trigger=TRIGGER_AUTOMATED,
    user=None,
    os_login_user="",
    user_ip=None,
):
    """Record a ``rotated`` event for every key whose material the provider moved.

    Returns ``(rotated_names, probes_capped)``. A row with no version stored is a
    first sighting rather than a rotation: it is stamped and records nothing.

    Reuses the versions this pass already read as a warm cache and probes only
    for the names it does not cover. Names whose version lookup already failed
    are skipped outright — a probe that could not answer must never read as an
    up-to-date key.

    Bounded by the same probe budget as the state check, since this runs on an
    operator-triggered page. Orphans go first: they are the smaller set, the one
    the report is built around, and the one an operator is about to make a
    deletion decision on. The order is stable, so a deployment carrying more
    orphans than the budget probes the same tail never — which is what
    ``probes_capped`` says out loud.
    """
    from ._internal import operator_error_text
    from .lifecycle import EVENT_ROTATED, STATUS_DELETED
    from .models import KeyEncryptionKey

    rows = list(KeyEncryptionKey.objects.filter(key_store=key_store).exclude(status=STATUS_DELETED))
    rows.sort(key=lambda row: (row.kek_resource_name not in orphan_names, row.kek_resource_name))

    rotated: list[str] = []
    probed = 0
    capped = False
    for row in rows:
        name = row.kek_resource_name
        if name in probe_failures:
            continue
        version = current_versions.get(name)
        if version is None:
            if probed >= _MAX_STATE_PROBES:
                capped = True
                break
            uid = _probe_address_for(kms_adapter, row, uid_by_kek_name)
            if uid is None:
                continue
            probed += 1
            try:
                version = kms_adapter.current_kek_version(uid) or ""
            except Exception as exc:
                logger.warning(
                    "The provider would not report this key's current version, so a rotation of it "
                    'would go unrecorded. kek="%s" detail="%s"',
                    name,
                    operator_error_text(exc),
                )
                continue
        if not version or version == row.kek_key_version:
            continue
        with transaction.atomic():
            first_sighting = not row.kek_key_version
            # Saved before recording: the event snapshots the version after the act.
            row.kek_key_version = version
            row.save(update_fields=["kek_key_version", "updated_at"])
            if not first_sighting:
                row.record_event(
                    EVENT_ROTATED,
                    trigger=trigger,
                    # Without a reason a rotated row does not say what saw it.
                    reason=REASON_OBSERVED_AT_PROVIDER,
                    user=user,
                    os_login_user=os_login_user,
                    user_ip=user_ip,
                )
                rotated.append(name)
    return rotated, capped


def _probe_kek_states(
    provisioner, rows, findings, *, trigger=TRIGGER_AUTOMATED, user=None, os_login_user="", user_ip=None
) -> None:
    """Ask the provider what state each key is really in.

    A discovered row is born ``active`` because that is the field default, not
    because anyone checked, and a key scheduled at the provider console leaves no
    trace here at all. Until something tries to encrypt under it, nothing learns
    that the provider already has a deletion running.

    Both orphans and in-use keys are probed. An orphan mid-deletion is not
    awaiting a decision, and reporting it as one asks the operator to redo work
    already done. An *in-use* key mid-deletion is the more urgent of the two: the
    silo it backs reads healthy while its key is being destroyed, and because the
    data encryption key is cached per process for ``DEK_CACHE_TTL``, reads keep
    succeeding until the cache turns over rather than failing at the next
    encrypt. This page is what an operator consults before making a deletion
    decision, so it must not report a scheduled key as ready.

    *rows* is probed in the order given, and only ``active`` rows cost a probe —
    a row already recorded as scheduled, requested or retained needs no provider
    round trip. Callers put orphan candidates first so a deployment large enough
    to reach :data:`_MAX_STATE_PROBES` spends the budget on them.

    A probe that returns ``unknown`` changes nothing, which is the point — a
    failed check must never be mistaken for a healthy answer.
    """
    from .lifecycle import EVENT_DELETION_REQUESTED, STATUS_ACTIVE
    from .models import KeyLifecycleEvent

    if provisioner is None or not getattr(provisioner, "supports_state_check", False):
        return

    probed = 0
    for row in rows:
        if row.status != STATUS_ACTIVE:
            continue  # already recorded as scheduled/requested/retained
        if probed >= _MAX_STATE_PROBES:
            return
        probed += 1
        state = provisioner.describe_kek_state(row.kek_resource_name)
        if not state.is_pending_deletion:
            continue
        row.record_event(
            EVENT_DELETION_REQUESTED,
            trigger=trigger,
            reason=KeyLifecycleEvent.REASON_OBSERVED_AT_PROVIDER,
            user=user,
            os_login_user=os_login_user,
            user_ip=user_ip,
            kms_deletion_at=state.effective_at,
        )
        findings.observed_pending.append(row.kek_resource_name)


def _sync_keks(
    *,
    key_store,
    owner_prefix,
    live_names,
    orphan_names,
    owned_mapped_names=frozenset(),
    provisioner=None,
    trigger=TRIGGER_AUTOMATED,
    user=None,
    os_login_user="",
    user_ip=None,
) -> _SyncFindings:
    """Persist a trustworthy enumeration onto the durable :class:`KeyEncryptionKey` rows.

    Called only when the KMS listing actually ran. Four jobs, none of them
    destructive:

    1. **Discovery** — a listed key with no row gets one (``active`` by field
       default), plus a ``discovered`` event and the silo annotation it is born
       with. The verb is never ``created``: reconcile saw the key, it did not
       make it.
    2. **Annotation** — ``is_orphaned`` (listed but backing no live silo) is
       updated where it changed, and the change is recorded as a ``silo_found``
       / ``silo_not_found`` event. A pass that learns nothing writes nothing.
    3. **Confirmation** — an owned ``deletion_requested`` key now *absent* from
       the listing is recorded ``deleted`` (reason ``confirmed_by_reconcile``);
       the enumeration witnessing its disappearance is the only authority that
       may make this transition.
    4. **Drift** — an owned ``deletion_requested`` key still listed past its
       effective date, or an owned ``active`` / ``deletion_scheduled`` key absent
       from the listing, is collected for the operator. Drift is flagged, never
       auto-actioned.

    A ``KEK_MAP`` key that is owned (*owned_mapped_names*, the ``KEK_MAP_DESTROYABLE``
    opt-in) is state-probed for a provider deletion window, like an owned listed key.
    It is never in the prefix listing unless its name carries the prefix, so the
    listing-based checks above do not apply to it.
    """
    from .lifecycle import (
        EVENT_DELETED,
        EVENT_DISCOVERED,
        EVENT_SILO_FOUND,
        EVENT_SILO_NOT_FOUND,
        STATUS_ACTIVE,
        STATUS_DELETED,
        STATUS_DELETION_REQUESTED,
        STATUS_DELETION_SCHEDULED,
    )
    from .models import KeyEncryptionKey, KeyLifecycleEvent

    now = timezone.now()
    findings = _SyncFindings()

    existing = {k.kek_resource_name: k for k in KeyEncryptionKey.objects.filter(key_store=key_store)}

    for name in live_names:
        if name not in existing:
            # Row and its first-sighting event in one transaction, so a key this
            # deployment did not create still has a ledger entry recording when it
            # first became observable. The verb is `discovered`, never `created`:
            # reconcile saw the key, it did not make it, and the ledger must not
            # launder an observation into a provenance claim.
            with transaction.atomic():
                orphaned_at_birth = name in orphan_names
                row = KeyEncryptionKey.objects.create(
                    key_store=key_store,
                    kek_resource_name=name,
                    is_orphaned=orphaned_at_birth,
                )
                row.record_event(
                    EVENT_DISCOVERED,
                    trigger=trigger,
                    reason=KeyLifecycleEvent.REASON_OBSERVED_AT_PROVIDER,
                    user=user,
                    os_login_user=os_login_user,
                    user_ip=user_ip,
                )
                # The annotation has a value from birth, so birth records it.
                # Only the change loop below fires for rows that already exist,
                # which left a discovered key's flag unexplained by the ledger —
                # the one thing the ledger is supposed to be able to reconstruct.
                row.record_event(
                    EVENT_SILO_NOT_FOUND if orphaned_at_birth else EVENT_SILO_FOUND,
                    trigger=trigger,
                    reason=REASON_DETERMINED_BY_RECONCILE,
                    user=user,
                    os_login_user=os_login_user,
                    user_ip=user_ip,
                )
            findings.discovered.append(name)

    for name, row in existing.items():
        owned = bool(owner_prefix) and name.startswith(owner_prefix)
        present = name in live_names
        if present:
            # A row recorded ``deleted`` is never annotated as an orphan, even
            # while the provider still lists the key. The disagreement is real
            # drift and is reported as such below; calling it an orphan would ask
            # for a cleanup this deployment believes it already completed.
            is_orphaned = name in orphan_names and row.status != STATUS_DELETED
            if row.is_orphaned != is_orphaned:
                row.is_orphaned = is_orphaned
                row.save(update_fields=["is_orphaned", "updated_at"])
                row.record_event(
                    EVENT_SILO_NOT_FOUND if is_orphaned else EVENT_SILO_FOUND,
                    trigger=trigger,
                    reason=REASON_DETERMINED_BY_RECONCILE,
                    user=user,
                    os_login_user=os_login_user,
                    user_ip=user_ip,
                )
            if (
                row.status == STATUS_DELETION_REQUESTED
                and row.kms_deletion_at is not None
                and row.kms_deletion_at <= now
            ):
                findings.drift_overdue.append(name)
        elif owned:
            if row.status == STATUS_DELETION_REQUESTED:
                row.record_event(
                    EVENT_DELETED,
                    trigger=trigger,
                    reason=KeyLifecycleEvent.REASON_CONFIRMED_BY_RECONCILE,
                    user=user,
                    os_login_user=os_login_user,
                    user_ip=user_ip,
                )
                findings.confirmed_deleted.append(name)
            elif row.status in (STATUS_ACTIVE, STATUS_DELETION_SCHEDULED):
                findings.drift_missing.append(name)

    # Probe last, once every row exists and its annotations are settled, so the
    # set probed is the set the report will show. Orphan candidates first: they
    # are the smaller set and the one the report is built around, so a deployment
    # that reaches the probe cap spends it there rather than on healthy keys.
    #
    # In-use keys are limited to the ones this deployment provably owns — a probe
    # is a provider call naming a key, and an unowned key is not ours to
    # interrogate or to record a lifecycle event against.
    owned_in_use = sorted(
        name for name in live_names if name not in orphan_names and owner_prefix and name.startswith(owner_prefix)
    )
    probe_order = sorted(orphan_names) + owned_in_use + sorted(owned_mapped_names - set(live_names))
    rows_by_name = {
        row.kek_resource_name: row
        for row in KeyEncryptionKey.objects.filter(
            key_store=key_store,
            kek_resource_name__in=probe_order,
        )
    }
    _probe_kek_states(
        provisioner,
        [rows_by_name[name] for name in probe_order if name in rows_by_name],
        findings,
        trigger=trigger,
        user=user,
        os_login_user=os_login_user,
        user_ip=user_ip,
    )

    return findings


def reconcile_summary_fields(result: ReconcileResult) -> tuple[str, tuple]:
    """The fields of a reconcile summary line, as a log format and its arguments.

    Every summary line — the admin page's and the command's closing line — is
    built here, so the two carry the same fields and cannot drift apart. ``n/a``
    marks a dimension that could not be inspected, which is not the same as ``0``.
    """
    report = result.report
    return (
        "key_store=%s discovered=%d observed_pending=%d confirmed=%d kek_delete_on_kms_overdue=%d "
        "kek_missing_on_kms=%d rotated=%d probes_capped=%s dek_orphans=%s kek_orphans=%s "
        "data_reencrypt_due=%s key_reencrypt_due=%s unavailable_detection=%s",
        (
            result.key_store,
            len(result.discovered),
            len(result.observed_pending),
            len(result.confirmed_deleted),
            len(result.drift_overdue),
            len(result.drift_missing),
            len(result.rotated),
            result.probes_capped,
            len(report.db_orphan_uids) if report.db_reconcile_available else "n/a",
            len(report.kms_orphan_keks) if report.kms_reconcile_available else "n/a",
            len(report.overdue) if report.cryptoperiod_declared else "n/a",
            len(report.superseded) if report.key_versions_available else "n/a",
            ",".join(sorted(report.degraded)) or "-",
        ),
    )


def log_reconcile_changes(result: ReconcileResult, *, user=None, user_ip=None) -> None:
    """The admin page's summary: one line per pass that changed something.

    Silent on a pass that changed nothing, because the page reconciles on every
    load and a line per visit is noise. The command does not call this — its
    closing line carries the same fields on every run.
    """
    if not (
        result.discovered
        or result.observed_pending
        or result.confirmed_deleted
        or result.drift_overdue
        or result.drift_missing
        or result.rotated
        or result.probes_capped
    ):
        return
    fields, args = reconcile_summary_fields(result)
    logger.info(
        "Reconciled keys. " + fields + " %s",
        *args,
        user_context.identity_tail(user=user, user_ip=user_ip),
    )
