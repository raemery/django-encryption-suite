"""
Reconcile capability matrix — the provider-agnostic engine that combines the two
enumeration halves (silo-side and KMS-side) into a single, degrade-safe picture
of drift between what the deployment *thinks* exists (DEK rows) and what actually
exists (live silos, KEKs on the KMS).

There are two independent drift dimensions, each gated by its own enumeration
capability:

* **DB-side orphans** — ``DataEncryptionKey`` rows whose ``silo_uid`` no live
  silo resolves to (the silo was deleted). Detectable only when the *silo
  adapter* can enumerate (:meth:`AbstractSiloAdapter.iter_silos` /
  ``supports_enumeration``). Without it we have no trustworthy "live" set and
  must not infer any row orphaned.
* **KMS-side orphans** — KEKs on the KMS, owned by this deployment (carrying the
  strategy's ``owner_prefix``), that back no live silo. Detectable only when the
  *provisioner* can enumerate (:meth:`AbstractKekProvisioner.list_kek_names` /
  ``supports_enumeration``) **and** the silo adapter can enumerate (to know which
  keys are still expected) **and** an owner prefix exists (shared / ``KEK_MAP``
  configs derive none, so ownership is unprovable).

The cardinal safety rule is the same on both sides: a *missing* detection
degrades to **detection-unavailable**, never to "nothing exists". Reporting a
false orphan here ends in a deletion — unrecoverable data loss — so every
absent capability widens what we *don't* claim, it never narrows what we keep.

This module is pure and presentation-neutral: it takes already-resolved Python
sets (the Django/registry I/O — ``iter_silos``, ``list_kek_names``,
``get_kek_id`` — is done by the caller and funneled there) and returns a
:class:`ReconcileReport`. Whether and how a KMS-side orphan is then destroyed is
decided by the deletion gates in :mod:`encryption_suite.deletion`, not here.
"""

from __future__ import annotations

from dataclasses import dataclass

from django.utils.translation import gettext_lazy as _

# Stable reason slugs for why a reconcile dimension is degraded (detection
# unavailable). Distinct from deletion's ``RETAIN_*`` vocab: those say why a
# *known* KEK was kept; these say why a whole *detection* could not run. Surfaced
# in the operator UI and audit log alongside the report.
# The silo adapter cannot enumerate at all — a capability it does not have.
DETECTION_SILO_ENUMERATION_UNAVAILABLE = "silo_enumeration_unavailable"
# It can enumerate, and the attempt raised. Same distinction as the two KMS-side
# reasons below: a missing capability is how the deployment is built, a failing
# call is an incident, and one slug for both hides the second behind the first.
DETECTION_SILO_LISTING_FAILED = "silo_listing_failed"
# The provisioner cannot list at all — a capability it does not have, true on
# every pass until the configuration changes.
DETECTION_KMS_ENUMERATION_UNAVAILABLE = "kms_enumeration_unavailable"
# The provisioner can list, and the attempt failed. Kept apart from the line
# above for the same reason the key-version reasons are: a missing capability
# needs no attention, a failing call is an incident, and one slug for both makes
# an outage indistinguishable from a property of the deployment.
DETECTION_KEK_LISTING_FAILED = "kek_listing_failed"
DETECTION_NO_OWNER_PREFIX = "no_owner_prefix"

# Short, localized phrases for each degraded-detection slug, for operator UIs.
DETECTION_REASON_TEXT = {
    DETECTION_SILO_ENUMERATION_UNAVAILABLE: _(
        "the silo adapter cannot enumerate silos, so deleted-silo (DB-side) orphans cannot be detected"
    ),
    DETECTION_SILO_LISTING_FAILED: _(
        "enumerating the silos failed, so deleted-silo (DB-side) orphans could not be detected on this pass"
    ),
    DETECTION_KMS_ENUMERATION_UNAVAILABLE: _(
        "the provisioner cannot list key encryption keys, so orphaned keys cannot be detected"
    ),
    DETECTION_KEK_LISTING_FAILED: _(
        "listing the key encryption keys failed, so orphaned keys could not be detected on this pass"
    ),
    DETECTION_NO_OWNER_PREFIX: _(
        "no owner prefix (shared or KEK_MAP key naming), so key encryption keys cannot be attributed to this deployment"
    ),
}


def format_detection_reasons(slugs) -> str:
    """Return a comma-joined, de-duplicated human description of degraded reasons.

    ``str()`` resolves the lazy gettext proxies in :data:`DETECTION_REASON_TEXT`
    so ``join`` receives real strings. An unknown slug falls back to itself.
    """
    return ", ".join(sorted({str(DETECTION_REASON_TEXT.get(s, s)) for s in slugs}))


@dataclass(frozen=True)
class ReconcileReport:
    """Structured outcome of a reconcile pass. Presentation-neutral.

    ``db_orphan_uids`` and ``kms_orphan_keks`` are only ever non-empty for a
    dimension whose detection actually ran; a degraded dimension yields an empty
    finding plus a slug in ``degraded`` explaining why — so an empty finding is
    never ambiguous between "clean" and "couldn't look".
    """

    # DB-side: ``silo_uid`` values in DEK rows that no live silo resolves to.
    db_orphan_uids: frozenset
    # KMS-side: owned KEK resource names on the KMS backing no live silo.
    kms_orphan_keks: tuple
    # What each dimension could actually inspect this pass.
    silo_enumeration_available: bool
    kms_enumeration_available: bool
    delete_available: bool
    # Reason slugs for every degraded dimension (display + audit).
    degraded: tuple
    # Key-material currency, the second dimension (see below). Defaulted because
    # a caller that does not ask for it gets no findings *and* no degraded slug:
    # "not asked" is distinct from "asked and could not look".
    overdue: tuple = ()
    superseded: tuple = ()
    cryptoperiod_declared: bool = False
    key_versions_available: bool = False

    @property
    def key_material_checked(self) -> bool:
        """The key-material dimension was inspected on this pass."""
        return self.cryptoperiod_declared or self.key_versions_available

    @property
    def db_reconcile_available(self) -> bool:
        """DB-side orphan detection ran (silo enumeration was available)."""
        return self.silo_enumeration_available

    @property
    def kms_reconcile_available(self) -> bool:
        """KMS-side orphan detection ran (needs KMS *and* silo enumeration).

        Without the live silo set we cannot say which listed KEKs are still
        expected, so KMS-side reconcile requires both halves.
        """
        return self.kms_enumeration_available and self.silo_enumeration_available

    @property
    def can_auto_delete_kms_orphans(self) -> bool:
        """A KMS-side orphan may be offered for (human-confirmed) destruction.

        Requires that the KMS-side reconcile actually ran *and* the provisioner
        can delete. When this is ``False`` but ``kms_orphan_keks`` is non-empty,
        the orphans are report-only: surface them with manual-cleanup
        instructions rather than a destroy action.
        """
        return self.kms_reconcile_available and self.delete_available


def build_reconcile_report(
    *,
    stored_uids,
    live_silo_uids,
    expected_kek_names,
    kms_kek_names,
    delete_available: bool,
    owner_prefix,
    silo_listing_failed: bool = False,
    kms_listing_failed: bool = False,
    check_key_material: bool = False,
    key_rows=(),
    overdue_cutoff=None,
    current_versions=None,
    probe_failures=(),
) -> ReconcileReport:
    """Combine the resolved enumeration inputs into a :class:`ReconcileReport`.

    All I/O is the caller's job; this is pure set logic. Parameters:

    * ``stored_uids`` — every ``silo_uid`` present in ``DataEncryptionKey`` rows.
    * ``live_silo_uids`` — the set of UIDs the silo adapter enumerates, or
      ``None`` when silo enumeration is unavailable (capability off, or
      ``iter_silos`` raised). ``None`` (not an empty set) is the degraded signal.
    * ``expected_kek_names`` — the resolved KEK resource name for every live silo
      (what *should* exist on the KMS). Only meaningful when silo enumeration
      ran; ignored otherwise.
    * ``kms_kek_names`` — owned KEK names listed from the KMS, or ``None`` when
      KMS enumeration is unavailable. ``None`` is the degraded signal.
    * ``silo_listing_failed`` / ``kms_listing_failed`` — the matching input is
      ``None`` because the enumeration *raised*, rather than because the adapter
      or provisioner cannot enumerate at all. Only the caller can tell those
      apart, and they degrade to different reasons.
    * ``delete_available`` — whether the configured provisioner can delete.
    * ``owner_prefix`` — the deployment's KEK-name prefix, or ``None`` when
      ownership cannot be derived (shared / ``KEK_MAP`` config).
    * ``check_key_material`` — opt in to the key-material dimension. Off by
      default so a caller asking only about orphans gets no key-material slugs in
      ``degraded``; "did not ask" must not read as "asked and could not look".
    * ``key_rows`` / ``overdue_cutoff`` / ``current_versions`` /
      ``probe_failures`` — the resolved inputs for that dimension (see
      :func:`_key_material_findings`).

    The safety contract: a dimension whose inputs are degraded contributes an
    *empty* finding and a ``degraded`` slug — never an inferred orphan.
    """
    degraded: list[str] = []

    silo_available = live_silo_uids is not None
    if silo_available:
        db_orphan_uids = frozenset(set(stored_uids) - set(live_silo_uids))
    else:
        degraded.append(
            DETECTION_SILO_LISTING_FAILED if silo_listing_failed else DETECTION_SILO_ENUMERATION_UNAVAILABLE
        )
        db_orphan_uids = frozenset()

    # KMS-side ownership prerequisite: without a prefix we cannot attribute any
    # listed key to this deployment, so KMS reconcile is off regardless of the
    # provisioner's listing capability.
    if owner_prefix is None:
        degraded.append(DETECTION_NO_OWNER_PREFIX)

    kms_listing_available = kms_kek_names is not None and owner_prefix is not None
    if kms_kek_names is None:
        # A failed listing is an incident; an absent capability is not. The
        # caller distinguishes them because only it knows whether the call was
        # attempted. Note this branch is also reached when silo enumeration is
        # unavailable — the KMS side needs the live set — and in that case the
        # silo-side reason is reported beside this one, so the cause is not lost.
        degraded.append(DETECTION_KEK_LISTING_FAILED if kms_listing_failed else DETECTION_KMS_ENUMERATION_UNAVAILABLE)

    # A listed KEK is orphaned only if it backs no *live* silo — which we can
    # only assert when the silo set is trustworthy too. Require both halves.
    if kms_listing_available and silo_available:
        kms_orphan_keks = tuple(sorted(set(kms_kek_names) - set(expected_kek_names)))
    else:
        kms_orphan_keks = ()

    overdue = superseded = ()
    if check_key_material:
        overdue, superseded, key_material_degraded = _key_material_findings(
            key_rows=key_rows,
            overdue_cutoff=overdue_cutoff,
            current_versions=current_versions or {},
            probe_failures=probe_failures,
        )
        degraded.extend(key_material_degraded)

    return ReconcileReport(
        db_orphan_uids=db_orphan_uids,
        kms_orphan_keks=kms_orphan_keks,
        silo_enumeration_available=silo_available,
        kms_enumeration_available=kms_listing_available,
        delete_available=delete_available,
        degraded=tuple(degraded),
        overdue=overdue,
        superseded=superseded,
        cryptoperiod_declared=check_key_material and overdue_cutoff is not None,
        key_versions_available=check_key_material and any((current_versions or {}).values()),
    )


# Action slugs for the manual-cleanup guidance derived from a report. Stable,
# greppable handles for what the operator must do by hand when the tooling cannot
# finish the job itself. Parallel to deletion's ``RETAIN_*`` vocab.
CLEANUP_DELETE_KEK_IN_KMS = "delete_kek_in_kms"
CLEANUP_AUDIT_KMS_MANUALLY = "audit_kms_manually"


@dataclass(frozen=True)
class CleanupInstruction:
    """One operator-actionable manual-cleanup step. Presentation-neutral.

    ``action`` is a stable slug; ``text`` is the resolved, translated guidance.
    ``kek_resource_name`` names the precise key when one is known (the
    delete-in-the-KMS case); it is ``None`` for the audit case where the keys
    could not even be listed.
    """

    action: str
    text: str
    kek_resource_name: str | None = None
    key_store: str | None = None


def build_cleanup_instructions(report, *, key_store=None, owner_prefix=None) -> list:
    """Translate a degraded/incomplete :class:`ReconcileReport` into the manual
    steps an operator must take so no orphan is silently left behind.

    Two situations produce guidance — they are not mutually exclusive:

    * **Orphans found, but the provisioner cannot delete them**
      (``kms_orphan_keks`` non-empty and ``can_auto_delete_kms_orphans`` False):
      one *delete-in-the-KMS* instruction per key, naming the exact KEK and
      KMS. This is the enumerate-yes / delete-no tier — we know precisely
      what is dead, the tooling just cannot destroy it.
    * **KMS-side reconcile could not run** (``kms_reconcile_available`` False):
      a single *audit-manually* instruction citing the specific degraded
      reason(s), because we cannot even list the keys to point at one. Includes
      the ``owner_prefix`` to scope the audit when one exists.

    A fully-capable, clean reconcile returns an empty list. KMS name and prefix
    are the caller's to supply (registry I/O stays out of this module).
    """
    instructions: list = []

    if report.kms_orphan_keks and not report.can_auto_delete_kms_orphans:
        provider_label = key_store or _("the KMS provider")
        for name in report.kms_orphan_keks:
            instructions.append(
                CleanupInstruction(
                    action=CLEANUP_DELETE_KEK_IN_KMS,
                    kek_resource_name=name,
                    key_store=key_store,
                    text=_(
                        "Delete key encryption key '%(name)s' on %(provider)s in the KMS — the "
                        "configured provisioner cannot delete it. The silo it "
                        "backed no longer exists."
                    )
                    % {"name": name, "provider": provider_label},
                )
            )

    if not report.kms_reconcile_available:
        provider_label = key_store or _("the KMS provider")
        reasons = format_detection_reasons(report.degraded)
        if owner_prefix:
            text = _(
                "KMS-side reconcile is unavailable (%(reasons)s). List key encryption keys whose "
                "name starts with '%(prefix)s' on %(provider)s and audit them "
                "against your live silos by hand; delete any that back no silo."
            ) % {"reasons": reasons, "prefix": owner_prefix, "provider": provider_label}
        else:
            text = _(
                "KMS-side reconcile is unavailable (%(reasons)s). List the key encryption keys this "
                "deployment uses on %(provider)s and audit them against your live "
                "silos by hand; delete any that back no silo."
            ) % {"reasons": reasons, "provider": provider_label}
        instructions.append(
            CleanupInstruction(
                action=CLEANUP_AUDIT_KMS_MANUALLY,
                text=text,
                key_store=key_store,
            )
        )

    return instructions


# ---------------------------------------------------------------------------
# Key material currency — the second reconcile dimension, one layer down
# ---------------------------------------------------------------------------
#
# Orphan detection above asks "does this key still belong to anything". This
# asks the other maintenance question: "is the material behind this key still
# current". Two independent answers, one per layer, and neither is the other:
#
#   * The **data key's own material** ages against a declared cryptoperiod
#     (DEK_ROTATION_PERIOD_DAYS). Resolving it means re-encrypting the silo's
#     data under a new data key.
#   * The **key encryption key's material** moves when the provider rotates.
#     Resolving it means re-wrapping the stored keys onto the new version, which
#     `reencrypt_keys` does without touching any data.
#
# Same degrade-safe rule as above: a dimension that could not be inspected
# reports nothing rather than reporting "clean". The KEK side needs the provider
# to identify a version at all, and several (AWS KMS, Fly KMS) identify none.

DETECTION_NO_CRYPTOPERIOD = "no_cryptoperiod_declared"
# Two reasons the key-version comparison can come up empty, deliberately kept
# apart. A provider that identifies no version is a permanent property of the
# configuration and needs no attention; probes that *failed* are an incident —
# expired credentials, a dead endpoint — and would read identically in the
# findings if they shared a slug. The first is structural, the second never is.
DETECTION_NO_KEY_VERSIONS = "provider_reports_no_key_versions"
DETECTION_KEY_VERSION_PROBE_FAILED = "key_version_probe_failed"

DETECTION_REASON_TEXT.update(
    {
        DETECTION_NO_CRYPTOPERIOD: _(
            "no data key rotation period is declared (DEK_ROTATION_PERIOD_DAYS), so nothing can be called overdue"
        ),
        DETECTION_NO_KEY_VERSIONS: _(
            "this provider identifies no key version, so keys needing re-encryption after a rotation cannot be detected"
        ),
        DETECTION_KEY_VERSION_PROBE_FAILED: _(
            "the key version lookup failed for one or more keys, so those keys were left out of the "
            "key re-encryption check"
        ),
    }
)

# Reasons that describe the shape of the deployment rather than something going
# wrong. They hold on every pass until the configuration changes, so a scheduled
# run can report them as information while everything else stays a warning.
# Every reason here names something the configuration *is*; each has a paired
# ``*_listing_failed`` slug for the case where the same capability existed and the
# call failed, and those pairs are what keep an incident from being demoted.
STRUCTURAL_DETECTION_REASONS = frozenset(
    {
        DETECTION_NO_CRYPTOPERIOD,
        DETECTION_NO_OWNER_PREFIX,
        DETECTION_NO_KEY_VERSIONS,
        DETECTION_KMS_ENUMERATION_UNAVAILABLE,
        DETECTION_SILO_ENUMERATION_UNAVAILABLE,
    }
)


def partition_detection_reasons(slugs):
    """Split *slugs* into ``(structural, incidental)``, each sorted.

    Presentation-neutral: callers decide what to do with each half. The admin
    page shows them together; a scheduled command separates them so a permanent
    property of the configuration does not arrive as a daily warning.
    """
    unique = set(slugs)
    structural = sorted(s for s in unique if s in STRUCTURAL_DETECTION_REASONS)
    incidental = sorted(s for s in unique if s not in STRUCTURAL_DETECTION_REASONS)
    return structural, incidental


def _key_material_findings(*, key_rows, overdue_cutoff, current_versions, probe_failures=()):
    """Compare stored key rows against the cryptoperiod and the provider's versions.

    *key_rows* are mappings carrying at least ``key_material_last_generated_at``,
    ``kek_resource_name`` and ``kek_key_version``. *overdue_cutoff* is the moment
    before which material counts as overdue, or ``None`` when no cryptoperiod is
    declared. *current_versions* maps a key encryption key's resource name to the
    version the provider would use for a new wrap; a missing or empty entry means
    that key's version is unknown and its rows are left out of ``superseded``
    rather than guessed at. *probe_failures* names the keys whose lookup raised,
    which is *why* they are unknown — reported apart from a provider that simply
    has no version to give.

    A row with no recorded generation date is not reported overdue. That is the
    lenient reading on purpose: the alternative flags every key written before
    the column existed as though its material were ancient.

    Returns ``(overdue, superseded, degraded)``, all tuples.
    """
    degraded = []
    overdue = ()
    superseded = ()

    if overdue_cutoff is None:
        degraded.append(DETECTION_NO_CRYPTOPERIOD)
    else:
        overdue = tuple(
            row
            for row in key_rows
            if row.get("key_material_last_generated_at") is not None
            and row["key_material_last_generated_at"] < overdue_cutoff
        )

    if probe_failures:
        degraded.append(DETECTION_KEY_VERSION_PROBE_FAILED)
    if not any(current_versions.values()):
        # Only when nothing failed. A run where every probe raised has already
        # said so; adding "this provider has no versions" on top would assert
        # something the run never established.
        if not probe_failures:
            degraded.append(DETECTION_NO_KEY_VERSIONS)
    else:
        superseded = tuple(
            row
            for row in key_rows
            if (current := current_versions.get(row.get("kek_resource_name") or ""))
            and row.get("kek_key_version")
            and row["kek_key_version"] != current
        )

    return overdue, superseded, tuple(degraded)
