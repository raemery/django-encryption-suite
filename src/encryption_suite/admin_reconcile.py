"""
The Reconcile Keys admin page for django-encryption-suite.

Lists every silo with the resource name of the key encryption key that should be
provisioned on the KMS, shows adapter wiring and key counts, and flags drift
(orphaned data encryption keys, silos still waiting for their first successful
encryption). The page only reports — every action that changes a key lives on a
changelist. Routed from ``DataEncryptionKeyAdmin.get_urls``, which is why the
view takes that ModelAdmin as its first argument.
"""

from __future__ import annotations

from django.contrib import messages
from django.db.models import F
from django.template.response import TemplateResponse
from django.urls import reverse
from django.utils.translation import gettext_lazy as _

from . import blind_index, lifecycle
from .admin_access import PERM_RECONCILE_KEYS, require_screen_access
from .models import DataEncryptionKey
from .silos import SiloEnumerationError
from .user_context import get_user_ip


def _key_marker(present: bool, status: str | None) -> dict:
    """Describe a key for the silos table as existence *and* usability.

    Presence alone reports a silo healthy while its crypto is blocked. A key
    scheduled for deletion still has a row here and, on providers with a deletion
    window, still exists and still lists at the provider — but it will not
    encrypt or decrypt. Nothing in the application notices until a data
    encryption key falls out of the per-process cache, at which point reads start
    failing somewhere unrelated to this page.

    Three states, because collapsing them loses the distinction that matters:

    * ``present`` — exists and is usable.
    * ``blocked`` — exists, but its lifecycle status stops encrypt and decrypt.
      ``status`` names which one, for the row's single Status verdict; the marker
      itself renders as an icon only.
    * ``absent`` — no key.
    """
    if not present:
        return {"state": "absent", "status": None}
    if status is not None and status != lifecycle.STATUS_ACTIVE:
        return {"state": "blocked", "status": status}
    return {"state": "present", "status": status}


def _store_label(key_store: str, key_sets: list[str]) -> str:
    """The selector label for a key store and the key sets that use it: ``fly (default, restricted)``."""
    return f"{key_store} ({', '.join(key_sets)})" if key_sets else key_store


def _kek_verdict(row, *, is_orphan: bool) -> str:
    """Classify what an operator should do about a listed key encryption key.

    Orphan-set membership alone is too coarse. A key already scheduled,
    requested, or refused has been acted on — reporting it as "orphaned" asks for
    work that is already done and contradicts the status shown beside it. Only a
    key still ``active`` is genuinely awaiting a decision.

    Drives the *count* of outstanding work, not the Orphaned marker beside each
    row. The marker reports the plain fact — no live silo references this key —
    which is what the changelist's ``is_orphaned`` shows and what the column
    header claims; binding it to this classification instead made every scheduled
    orphan read "not orphaned" and contradicted both. The count is narrower on
    purpose: an orphan already being deleted is not work awaiting a decision, and
    the Status column beside the marker says which case a row is in.
    """
    status = getattr(row, "status", None)
    if status in {
        lifecycle.STATUS_DELETION_SCHEDULED,
        lifecycle.STATUS_DELETION_REQUESTED,
    }:
        return "in_progress"
    if status == lifecycle.STATUS_DELETION_FAILED:
        return "failed"
    if status == lifecycle.STATUS_RETAINED:
        return "retained"
    if is_orphan:
        return "orphaned"
    return "not_applicable"


def reconcile_keys_view(model_admin, request):
    """Render the Reconcile Keys page: every silo and the state of its keys.

    For each silo the page shows the resolved key encryption key resource
    name (the string an admin would create on the KMS) and whether a
    ``DataEncryptionKey`` row exists for each purpose. Rows without a data
    encryption key are highlighted — these are the silos whose first
    encryption will try to use the listed key encryption key, and will fail
    with ``KekNotProvisionedError`` if that key has not been created.

    The page reports, but it is not read-only: discovery records a row for a key
    the provider lists that this deployment has none for, and both key models
    carry the orphan annotation each pass determines. So it takes a permission of
    its own rather than riding on whoever may view a changelist.
    """
    require_screen_access(request, PERM_RECONCILE_KEYS)

    from .conf import DEFAULT_KEY_SET, is_system_key_set, key_set_names, kms_names, resolve_store, store_problem
    from .reconcile_service import stores_in_play
    from .registry import (
        get_kek_provisioner,
        get_kms_adapter,
        silo_adapter_groups,
    )
    from .rotation_targets import key_sets_in_use
    from .silo_ref import SiloRef

    # The page describes one key store, as the reconcile_keys command does: the
    # live key listing, the sync and the probes cover the store, and so does every
    # table, for all the key sets that use it. Env stores are offered too, since
    # their silos and keys are still worth showing.
    stores = stores_in_play(include_env=True)
    default_store = resolve_store(DEFAULT_KEY_SET)
    stores.sort(key=lambda name: name != default_store)
    picked = request.GET.get("key_store")
    if picked in stores:
        key_store = picked
    else:
        key_store = default_store if default_store in stores or not stores else stores[0]
    # The key sets that use each store, ``default`` first.
    key_sets_by_store: dict[str | None, list[str]] = {}
    for name in sorted(key_set_names(), key=lambda each: each != DEFAULT_KEY_SET):
        key_sets_by_store.setdefault(resolve_store(name), []).append(name)
    store_key_sets = key_sets_by_store.get(key_store, [])
    provisioner = get_kek_provisioner(key_store)

    error: str | None = None
    rows: list[dict] = []
    # Every silo of every adapter, each with the label its adapter names it by. The
    # adapter is listed once it says something encrypts under it.
    #
    # Branch on the capability first: an adapter that cannot enumerate gives
    # no trustworthy live set, so per-silo status and orphan detection are
    # unavailable (never inferred). Only call iter_silos() when supported,
    # and still catch a runtime failure (DB down, etc.) of a capable adapter. The
    # first such failure is the one reported.
    silos: list[tuple[SiloRef, str]] = []
    live_refs: set[SiloRef] = set()
    declared = key_sets_in_use()
    for silo_adapter, group_key_sets in silo_adapter_groups():
        if not silo_adapter.is_in_use():
            continue
        if not silo_adapter.supports_enumeration:
            error = error or _(
                "The configured silo adapter cannot enumerate silos, so per-silo "
                "status and orphan detection are unavailable. Override iter_silos() "
                "on the adapter to enable them."
            )
            continue
        try:
            listed = list(silo_adapter.iter_silos())
        except SiloEnumerationError as exc:
            error = error or exc.detail or str(exc)
            continue
        label = silo_adapter.get_silo_label()
        for silo in listed:
            uid = silo_adapter.get_silo_uid(silo)
            # A silo is live in every key set bound to its adapter; it is listed
            # for the key sets that fields declare, or the default when none does.
            live_refs.update(SiloRef(key_set, uid) for key_set in group_key_sets)
            silos.extend(
                (SiloRef(key_set, uid), label)
                for key_set in group_key_sets
                if key_set in store_key_sets and key_set in declared
            )

    # Lifecycle status, not just existence: a scheduled or purged key still has
    # a row, so presence alone would report a silo healthy while its crypto is
    # blocked. See _key_marker. A key is one row of a silo's key set, so the
    # lookups carry the key set: two sets of one silo are two rows here.
    existing_keys: dict[tuple, str] = {}
    existing_resources: dict[tuple, str] = {}
    for key_set, uid, purpose, status, kek_name in DataEncryptionKey.objects.exclude(
        purpose=DataEncryptionKey.PURPOSE_TEST
    ).values_list("key_set", "silo_uid", "purpose", "status", "kek__kek_resource_name"):
        existing_keys[(key_set, uid, purpose)] = status
        existing_resources[(key_set, uid)] = kek_name

    for ref, label in silos:
        key_set = ref.key_set
        store = resolve_store(key_set)
        # Whether this key set's fields index anything, which decides whether a
        # missing index key is a gap or simply a key nobody asked for. The
        # system silo makes all three keys at once, used or not.
        wants_index = is_system_key_set(key_set) or any(
            True for _model, _field in blind_index.silo_indexed_fields(key_set=key_set)
        )
        if store is None:
            resolved_kek = f"<unresolvable: {store_problem(key_set)}>"
        else:
            try:
                resolved_kek = get_kms_adapter(store).resolve_kek_name(ref)
            except Exception as exc:
                resolved_kek = f"<unresolvable: {exc}>"

        # Compared canonically: a stored pointer is not always the key's name
        # (Azure records the wrapping version), and a raw comparison reports
        # every healthy silo on such an adapter as drifted.
        stored_kek = existing_resources.get((key_set, ref.uid))
        try:
            stored_differs = bool(stored_kek) and get_kms_adapter(store).canonical_kek_name(stored_kek) != resolved_kek
        except Exception:
            stored_differs = bool(stored_kek) and stored_kek != resolved_kek

        field_status = existing_keys.get((key_set, ref.uid, DataEncryptionKey.PURPOSE_FIELD))
        file_status = existing_keys.get((key_set, ref.uid, DataEncryptionKey.PURPOSE_FILE))
        index_status = existing_keys.get((key_set, ref.uid, DataEncryptionKey.PURPOSE_INDEX))
        field_ready = field_status is not None
        file_ready = file_status is not None
        index_ready = index_status is not None or not wants_index
        needs_setup = not (field_ready and file_ready and index_ready)
        missing_deks = [
            key_label
            for key_label, ready in (
                (_("field"), field_ready),
                (_("file"), file_ready),
                (_("index"), index_ready),
            )
            if not ready
        ]

        rows.append(
            {
                "silo_uid": ref.uid,
                "key_set": key_set,
                "key_store": store,
                "wants_index": wants_index,
                "silo_label": label,
                "resolved_kek": resolved_kek,
                "stored_kek": stored_kek,
                "stored_differs": stored_differs,
                "field_ready": field_ready,
                "file_ready": file_ready,
                "index_ready": index_ready,
                "missing_deks": missing_deks,
                "field_marker": _key_marker(field_ready, field_status),
                "file_marker": _key_marker(file_ready, file_status),
                # Absent where nothing indexes, so the column reads the same as
                # a silo whose key is there: there is nothing to do either way.
                "index_marker": _key_marker(index_ready, index_status),
                "needs_setup": needs_setup,
            }
        )

    # Whether any row's key set indexes anything, which decides whether to show the
    # index column at all: a deployment that indexes nothing would get a column of
    # checkmarks for a key it never needs.
    wants_index = any(row["wants_index"] for row in rows)
    rows.sort(key=lambda r: (not r["needs_setup"], r["key_set"], r["silo_uid"]))

    # Rows whose silo is not yielded by its key set's live adapter. Only computed
    # when enumeration succeeded — if iter_silos raised, everything would
    # look orphaned.
    #
    # Test-console rows are listed here too, marked, with their verdict set
    # to "not applicable" rather than "orphan". Their sentinel UID is
    # reserved so no real silo can ever resolve to it, which makes the
    # orphan question structurally unanswerable for them, not answered "yes".
    # Reporting that plainly beats hiding them in a separate panel: the
    # panel was keyed off DEK rows, so a leftover test KEK whose rows were
    # already deleted could not appear in it at all.
    orphan_rows: list[dict] = []
    if error is None:
        # Purged tombstones are left out entirely. The row survives as the
        # record that a key existed, but its keyset is cleared, so there is no
        # key to adopt, delete, or restore — nothing this table exists to
        # prompt. They remain visible on the changelist, which lists every row
        # rather than only the ones needing a decision.
        orphan_qs = (
            DataEncryptionKey.objects.filter(kek__key_store=key_store)
            .exclude(status=lifecycle.STATUS_DELETED)
            .annotate(kek_resource_name=F("kek__kek_resource_name"))
            .values(
                "pk",
                "key_set",
                "silo_uid",
                "silo_label",
                "purpose",
                "kek_resource_name",
                "status",
                "undeletable_until",
            )
            .order_by("key_set", "silo_uid", "purpose")
        )
        status_labels = dict(lifecycle.DEK_STATUS_CHOICES)
        orphan_rows = [
            {
                **row,
                "status_label": status_labels.get(row["status"], row["status"]),
                "is_test": row["purpose"] == DataEncryptionKey.PURPOSE_TEST,
                # A key set the settings no longer define: the key is wrapped on
                # this store, but no entry says which store its key set uses.
                "no_settings_entry": resolve_store(row["key_set"]) is None,
                # Computed live rather than read from the row's cached
                # ``is_orphaned``, which reconcile has not refreshed yet at
                # this point in the request — reading it would report every
                # orphan one page load late. Every row reaching here already
                # failed to resolve to a live silo and is not a tombstone; only
                # a test row is exempt, its sentinel UID being reserved so the
                # question cannot be asked.
                "is_orphaned": row["purpose"] != DataEncryptionKey.PURPOSE_TEST,
                # Same three-state marker as the key-encryption-key table.
                # ``absent`` cannot occur while tombstones are filtered out, so
                # in practice this reads present or blocked.
                "dek_marker": _key_marker(row["status"] != lifecycle.STATUS_DELETED, row["status"]),
            }
            for row in orphan_qs
            if row["purpose"] == DataEncryptionKey.PURPOSE_TEST
            or SiloRef(row["key_set"], row["silo_uid"]) not in live_refs
        ]

    # KMS-side reconcile (the matrix): enumerate silos + KEKs, diff them,
    # and sync the findings onto the durable KeyEncryptionKey rows (discovery, orphan and
    # last-reconciled annotations, requested→deleted confirmation, drift).
    # Read-only here — every destructive action lives on the two changelists,
    # re-verified at execution. Degrades to detection-unavailable when the
    # provisioner cannot enumerate, ownership is unprovable, or silo
    # enumeration failed.
    from .models import KeyEncryptionKey
    from .reconcile import build_cleanup_instructions, format_detection_reasons
    from .reconcile_service import log_reconcile_changes, run_reconcile

    # ``indirect``, not ``automated``: an operator asked for a pass, and every
    # event it writes followed from that — none of them is a thing anyone asked
    # for by name. The command keeps ``automated``, which is what tells the two
    # apart in the ledger.
    user_ip = get_user_ip(request)
    reconcile = run_reconcile(
        key_store=key_store, trigger=lifecycle.TRIGGER_INDIRECT, user=request.user, user_ip=user_ip
    )
    log_reconcile_changes(reconcile, user=request.user, user_ip=user_ip)
    report = reconcile.report
    owner_prefix = reconcile.owner_prefix
    cleanup_instructions = build_cleanup_instructions(report, key_store=reconcile.key_store, owner_prefix=owner_prefix)
    degraded_reasons = format_detection_reasons(report.degraded) if report.degraded else ""

    # Per-silo KEK existence column. Prefer the live listing; fall back to
    # the durable KeyEncryptionKey row's status when enumeration was unavailable.
    live_names = reconcile.kms_kek_names  # frozenset | None
    kek_rows = {k.kek_resource_name: k for k in KeyEncryptionKey.objects.filter(key_store=reconcile.key_store)}
    present_statuses = (
        lifecycle.STATUS_ACTIVE,
        lifecycle.STATUS_DELETION_SCHEDULED,
        lifecycle.STATUS_DELETION_REQUESTED,
    )
    # Every row is on the store the pass reconciled, so the live listing answers for all of them.
    for row in rows:
        name = row["resolved_kek"]
        recorded = kek_rows.get(name)
        if live_names is not None:
            row["kek_existence"] = {"known": True, "present": name in live_names}
        elif recorded is not None:
            row["kek_existence"] = {"known": True, "present": recorded.status in present_statuses}
        else:
            row["kek_existence"] = {"known": False, "present": False}
        # A listed key whose recorded status is no longer active exists but
        # will not encrypt or decrypt, so it reads blocked rather than present.
        # No row at all leaves the live answer alone: an unrecorded key is
        # unremarkable (reconcile discovers one on this same pass), whereas
        # inventing a blocked state for it would report trouble that is not
        # there.
        row["kek_marker"] = _key_marker(
            row["kek_existence"]["present"],
            recorded.status if recorded is not None else None,
        )
        row["kek_known"] = row["kek_existence"]["known"]
        # Only when the answer is known: an unknown key is not a key to create.
        row["kek_absent"] = row["kek_known"] and row["kek_marker"]["state"] == "absent"
        # One verdict for the Status column: any blocked key blocks the silo.
        # Named separately from needs_setup because the remedy differs — a
        # missing key is created, a blocked one is restored or replaced.
        row["blocked_status"] = next(
            (
                marker["status"]
                for marker in (row["kek_marker"], row["field_marker"], row["file_marker"])
                if marker["state"] == "blocked"
            ),
            None,
        )
    # Re-sorted now that the blocked verdict exists, so rows needing attention
    # stay at the top for either reason.
    rows.sort(key=lambda r: (not r["needs_setup"], r["blocked_status"] is None, r["key_set"], r["silo_uid"]))
    # Silos with a key still to create, on either side. ``needs_setup`` is the
    # data-key half (a silo needs both a field and a file key); ``kek_absent``
    # is the key-encryption-key half. Either gap puts the silo in the table.
    missing_key_rows = [row for row in rows if row["needs_setup"] or row["kek_absent"]]
    kek_existence_source = "live" if live_names is not None else "recorded"

    # Which KEK names belong to the test console. Resolved from the two
    # sentinel UIDs — the same derivation the console itself uses — and
    # unioned with the names its DEK rows carry, so a key stays identifiable
    # after those rows are gone (a leftover the old panel could not show at
    # all) and also when the strategy cannot resolve a name right now.
    from .test_console import _reserved_test_uids

    kms_adapter = get_kms_adapter(key_store)
    test_kek_names = set(
        DataEncryptionKey.objects.filter(purpose=DataEncryptionKey.PURPOSE_TEST, kek__key_store=key_store)
        .values_list("kek__kek_resource_name", flat=True)
        .distinct()
    )
    # A store no key set uses has no strategy to ask; its names come from its rows.
    sentinel_key_set = store_key_sets[0] if store_key_sets else None
    for uid in _reserved_test_uids() if sentinel_key_set is not None else []:
        try:
            resolved = kms_adapter.resolve_kek_name(SiloRef(sentinel_key_set, uid))
        except Exception:
            continue
        if resolved:
            test_kek_names.add(resolved)
    # An env store resolves every UID to its shared KEK, which real silos use;
    # the console records its own key under a name of its own instead.
    from .conf import env_test_kek_name, is_env_store

    if is_env_store(key_store):
        if sentinel_key_set:
            test_kek_names.discard(kms_adapter.resolve_kek_name(SiloRef(sentinel_key_set, "")))
        test_kek_names.add(env_test_kek_name())

    # Key encryption keys backing no live silo, carrying the same verdict
    # column as the data-encryption-key table above so both read alike.
    #
    # The orphan set (from the fresh report) is the actionable half. Test
    # console keys are unioned in so the key itself stays visible while it is
    # still in use — reconcile deliberately keeps a live test key out of the
    # orphan set, which would otherwise leave its status and existence
    # unreported anywhere on this page. Their verdict depends on whether they
    # are still backing a test keyset: a leftover is a real cleanup item,
    # because unlike a test key row it exists on the provider and is billing.
    orphan_kek_names = list(report.kms_orphan_keks)

    def _kek_exists(name):
        """Whether the key is known to exist — listed live, or recorded as present."""
        if live_names is not None:
            return name in live_names
        row = kek_rows.get(name)
        return row is not None and row.status in present_statuses

    # A sentinel name resolves whether or not the key was ever created, so
    # only surface a test key that actually exists; otherwise the table would
    # carry a phantom row for every test key never provisioned.
    extra_test_names = sorted(n for n in test_kek_names - set(orphan_kek_names) if _kek_exists(n))
    listed_kek_names = orphan_kek_names + extra_test_names
    orphan_kek_rows = []
    for name in listed_kek_names:
        kk = kek_rows.get(name)
        is_test = name in test_kek_names
        # A key recorded as deleted is not an orphan, even if the provider
        # still lists it: there is nothing left to adopt or clean up. The
        # disagreement is drift, which reconcile reports separately.
        is_orphan = name in orphan_kek_names and not (kk is not None and kk.status == lifecycle.STATUS_DELETED)
        if live_names is not None:
            existence = {"known": True, "present": name in live_names}
        elif kk is not None:
            existence = {"known": True, "present": kk.status in present_statuses}
        else:
            existence = {"known": False, "present": False}
        orphan_kek_rows.append(
            {
                "name": name,
                "last_status": kk.get_status_display() if kk else "",
                "kms_deletion_at": kk.kms_deletion_at if kk else None,
                "is_test": is_test,
                "is_orphan": is_orphan,
                "kek_existence": existence,
                # Same three-state marker the silos table uses: a key listed
                # at the provider but no longer active exists without being
                # usable, and on this table that is the common case rather
                # than the exception.
                "kek_marker": _key_marker(existence["present"], kk.status if kk is not None else None),
                "kek_known": existence["known"],
                "verdict": _kek_verdict(kk, is_orphan=is_orphan),
            }
        )

    # Config-aware setup guidance for the Silos section, so the "what to do"
    # text matches this deployment instead of listing options. The two answers
    # come from different places and are named for what decides each: whether a
    # KEK gets created is the provisioner class, whether the keys are made on
    # first encrypt is the KEY_AUTO_PROVISION setting.
    from .adapters.keks import NullKekProvisioner
    from .conf import enc_settings

    provisioner_creates_keks = not isinstance(provisioner, NullKekProvisioner)
    key_auto_provision = bool(enc_settings.KEY_AUTO_PROVISION)

    context = {
        **model_admin.admin_site.each_context(request),
        "title": _("Reconcile Keys"),
        "rows": rows,
        "missing_key_rows": missing_key_rows,
        "kek_existence_source": kek_existence_source,
        "key_store": key_store,
        # Each store with the key sets that use it, so a reader can see which
        # key sets the tables below cover.
        "key_store_choices": [
            {"key_store": name, "label": _store_label(name, key_sets_by_store.get(name, []))} for name in stores
        ],
        # Stores that key encryption key rows record but no block configures. The
        # page cannot reconcile one; it says so, so the keys are not forgotten.
        "unconfigured_stores": sorted(
            set(
                KeyEncryptionKey.objects.exclude(status=lifecycle.STATUS_DELETED)
                .values_list("key_store", flat=True)
                .distinct()
            )
            - set(kms_names())
        ),
        "orphan_rows": orphan_rows,
        # Counts what the table's Orphaned column marks, so a reader can tally
        # the checkmarks and reach the same number. It deliberately does *not*
        # narrow to rows still awaiting a decision: a heading that says
        # "orphaned" has to count the orphans, and the Status column beside
        # each marker already distinguishes one mid-deletion from one untouched.
        #
        # One row per (silo, purpose), matching the table below and the KMS
        # orphan count — a silo with both a field and a file key counts twice.
        "orphan_count": sum(1 for row in orphan_rows if row["is_orphaned"]),
        "error": error,
        "provisioner_creates_keks": provisioner_creates_keks,
        "key_auto_provision": key_auto_provision,
        "wants_index": wants_index,
        "total_count": len(rows),
        "opts": model_admin.model._meta,
        "changelist_url": reverse("admin:encryption_suite_dataencryptionkey_changelist"),
        "kms_changelist_url": reverse("admin:encryption_suite_keyencryptionkey_changelist"),
        "kms_orphan_keks": report.kms_orphan_keks,
        "orphan_kek_rows": orphan_kek_rows,
        # Same rule on the KMS side: the count matches the column's markers.
        "kms_orphan_count": sum(1 for row in orphan_kek_rows if row["is_orphan"]),
        "can_auto_delete_kms_orphans": report.can_auto_delete_kms_orphans,
        "degraded_reasons": degraded_reasons,
        "cleanup_instructions": cleanup_instructions,
        "discovered": reconcile.discovered,
        "confirmed_deleted": reconcile.confirmed_deleted,
        "drift_overdue": reconcile.drift_overdue,
        "drift_missing": reconcile.drift_missing,
        # Key-material currency: the same report's second dimension. Its
        # degraded slugs are already in ``degraded_reasons`` above, which is
        # the point of carrying one report rather than two.
        "overdue_keys": report.overdue,
        "superseded_keys": report.superseded,
    }
    if error:
        messages.warning(request, error)
    # TemplateResponse, not render: same output, but the resolved context stays
    # inspectable, which is what lets the page's table contents be asserted.
    return TemplateResponse(request, "admin/encryption_suite/reconcile_keys.html", context)
