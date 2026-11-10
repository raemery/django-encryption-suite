"""
Django admin for django-encryption-suite.

Registers ``DataEncryptionKey`` read-only and owns the key actions an operator
takes from its changelist: scheduling deletion, restoring, and purging expired
work. The two custom screens this ModelAdmin routes live in their own modules —
:mod:`encryption_suite.admin_reconcile` and
:mod:`encryption_suite.admin_test_console` — and are reached through
:meth:`DataEncryptionKeyAdmin.get_urls`, which is the hook Django calls.
"""

from __future__ import annotations

from django.contrib import admin, messages
from django.db import models
from django.template.response import TemplateResponse
from django.urls import NoReverseMatch, path, reverse
from django.utils import timezone
from django.utils.html import format_html
from django.utils.timesince import timesince
from django.utils.translation import gettext_lazy as _

from . import (
    admin_inventory,
    admin_lifecycle,  # noqa: F401  (registers the lifecycle ModelAdmins)
    admin_reconcile,
    admin_settings,
    admin_test_console,
    lifecycle,
)
from .admin_lifecycle import DekEventInline
from .models import DataEncryptionKey
from .user_context import get_user_ip, user_label_for


@admin.register(DataEncryptionKey)
class DataEncryptionKeyAdmin(admin_lifecycle.OrphanColumnMixin, admin.ModelAdmin):
    # The rotation joins here so its age column costs no query per row.
    list_select_related = ("kek", "rotation")
    list_display = (
        "silo_uid",
        "silo_name",
        "purpose_code",
        "key_set",
        "status",
        "rotation_age",
        "kek_name",
        "orphan_marker",
        "undeletable_until",
    )

    @admin.display(description=_("Rotation age"), ordering="rotation__started_at")
    def rotation_age(self, obj):
        """How long a data key rotation has held this key's data fenced.

        Read from the rotation row rather than the status, so it survives a
        status the rotation does not control — a key scheduled for deletion in
        the middle of one still shows it. Read with a default: most keys have no
        rotation, and the reverse accessor raises rather than returning ``None``.
        """
        rotation = getattr(obj, "rotation", None)
        if rotation is None:
            return None
        return timesince(rotation.started_at)

    @admin.display(description=_("KEK resource name"), ordering="kek__kek_resource_name")
    def kek_name(self, obj):
        """The KEK's name, read through the relation the row carries."""
        return obj.kek.kek_resource_name

    @admin.display(description=_("Key encryption key"))
    def kek_link(self, obj):
        """The KEK as a link to its own page, with provider and status inline.

        The detail page would otherwise render the relation as plain text, which
        loses the one thing a reader wants next: whether that key is active,
        scheduled, or already deleted. Reading a data key's page without being
        able to reach its key encryption key was the awkward half of splitting
        these into two tables.
        """
        url = reverse("admin:encryption_suite_keyencryptionkey_change", args=[obj.kek_id])
        return format_html('<a href="{}">{}</a> [{}]', url, str(obj.kek), obj.kek.get_status_display())

    @admin.display(description=_("Silo name"))
    def silo_name(self, obj):
        """What the silo UID refers to, in the words the deployment uses for it.

        A UID is derived from something that cannot be reissued — usually a
        surrogate key — so ``team-42`` identifies a silo precisely and describes
        it not at all. Every destructive action on this page is confirmed by UID,
        which is the moment an operator most needs to know which tenant that is.

        Shown on the changelist as well as the detail page, at the cost of one
        adapter lookup per row.

        A test console key names a sentinel UID that no silo will ever have, so
        it is labeled as the console's own instead of being asked about.
        """
        from .registry import get_silo_adapter

        if obj.purpose == DataEncryptionKey.PURPOSE_TEST:
            return _("Test Console")
        try:
            adapter = get_silo_adapter(obj.key_set)
            name = adapter.describe_silo(obj.silo_uid)
            exists = adapter.silo_exists(obj.silo_uid)
        except Exception:
            # Informational only: an adapter that cannot answer must not take
            # the page down with it.
            return _("— (unavailable)")
        if name:
            return name
        # No name, so say which kind of nothing it is: a silo that is genuinely
        # gone (its key rows outlive it by design) reads very differently from an
        # adapter that cannot look one up.
        if exists is False:
            return _("— (silo no longer exists)")
        return _("— (unavailable)")

    @admin.display(description=_("Silo name"))
    def silo_link(self, obj):
        """The silo name, linked to the silo's own admin page when it has one.

        The text is always :meth:`silo_name`'s, fallbacks included; a silo with
        no admin page to link to shows that text unlinked. The link is offered
        whatever the viewer's permissions: the target page enforces its own.
        """
        name = self.silo_name(obj)
        url = self._silo_admin_url(obj)
        return format_html('<a href="{}">{}</a>', url, name) if url else name

    def _silo_admin_url(self, obj):
        """The change URL of the model instance *obj*'s silo is, or ``None``."""
        from .registry import get_silo_adapter

        try:
            silo = get_silo_adapter(obj.key_set).silo_for_uid(obj.silo_uid)
        except Exception:
            return None
        if not isinstance(silo, models.Model) or not self.admin_site.is_registered(type(silo)):
            return None
        opts = silo._meta
        try:
            return reverse(f"{self.admin_site.name}:{opts.app_label}_{opts.model_name}_change", args=[silo.pk])
        except NoReverseMatch:
            return None

    @admin.display(description=_("Purpose"), ordering="purpose")
    def purpose_code(self, obj):
        return obj.purpose

    @admin.display(description=_("Scheduled deletion by"))
    def scheduled_deletion_by(self, obj):
        """Who scheduled this key's deletion, from the ledger's own record of it.

        The ledger has recorded the act since it existed, as a reference to the
        user rather than a copied name — which is what the recording settings
        govern, what survives a rename, and what cannot hold a customer's
        plaintext. This reads the latest such event rather than a column of its
        own, so there is one answer to the question instead of two that can part.
        """
        event = (
            obj.events.filter(event=lifecycle.EVENT_DELETION_SCHEDULED)
            .select_related("user", "os_user")
            .order_by("-created_at")
            .first()
        )
        if event is None:
            return ""
        return user_label_for(event) or (str(event.os_user) if event.os_user_id else "")

    @admin.display(description=_("Encrypted DEK"))
    def key_material_state(self, obj):
        """Whether this row still holds key material, and what protects it.

        Names the key encryption key as the thing that encrypted this row — not
        the KMS, which holds that key rather than performing the encryption, and
        not "encrypted by <provider>" bare, which invites the reading that the
        provider encrypts the tenant's data. It encrypts only this key, which in
        turn encrypts the data.
        """
        if not bytes(obj.encrypted_keyset or b""):
            # Field cleared: this row is a purged tombstone, its key destroyed.
            return _("— (cleared)")
        return _("DEK encrypted by %(provider)s KEK") % {"provider": obj.kek.key_store}

    list_filter = (
        "purpose",
        "status",
        "key_set",
        "kek__key_store",
        "crypto_backend",
        "is_orphaned",
    )
    search_fields = ("silo_uid",)
    readonly_fields = (
        "key_set",
        "silo_uid",
        "silo_link",
        "silo_label",
        "kek_link",
        "kek_key_version",
        "crypto_backend",
        "algorithm",
        "reencryption_count",
        "dek_key_version",
        "purpose",
        "status",
        "rotation_age",
        "undeletable_until",
        "scheduled_deletion_by",
        "key_material_state",
        "orphan_marker",
        "key_material_last_generated_at",
        "last_reencrypted_at",
        "created_at",
        "updated_at",
    )
    # Three fields are rendered through a display method instead of directly, so
    # the underlying field is excluded to keep it off the form — otherwise the
    # page shows the same fact twice, once raw and once formatted.
    #
    # ``kek`` in particular is excluded rather than merely made read-only: which
    # key wrapped a data encryption key is a fact the engine records at wrap time,
    # and editable here it would point a row at a key that never encrypted it,
    # failing the next read against a key that cannot unwrap it. ``is_orphaned``
    # renders through ``orphan_marker`` because Django's own boolean icon shows a
    # green check for ``True`` — a tick against the answer that needs acting on.
    exclude = ("encrypted_keyset", "kek", "is_orphaned")
    change_list_template = "admin/encryption_suite/dataencryptionkey/change_list.html"
    inlines = (DekEventInline,)
    actions = ("schedule_dek_deletion", "restore_scheduled", "purge_expired_work")

    def has_add_permission(self, request):
        return False

    def has_delete_permission(self, request, obj=None):
        return False

    def has_destroy_permission(self, request):
        """Answer for the actions that move a key toward being unreadable.

        Reads the model's own delete permission. The action machinery resolves
        ``permissions=("destroy",)`` to this method, which exists because the
        obvious name resolves to :meth:`has_delete_permission` — hard-coded
        ``False`` here to strip the admin's own delete button, which would hide
        these actions from everyone including a superuser.
        """
        return request.user.has_perm("encryption_suite.delete_dataencryptionkey")

    def has_change_permission(self, request, obj=None):
        """A specific row is view-only: every state change goes through an action.

        Scoped to ``obj`` so the changelist and its actions are untouched — only
        the detail page loses its Save buttons, which offered to write a row whose
        every field is already read-only. That write was not harmless: it bumped
        ``updated_at``, the one column that is supposed to mean something actually
        changed. Matches the ledger admin, which has been view-only all along.

        Chains to ``super()`` rather than answering ``True`` outright, so the
        model permission still decides. The action machinery resolves
        ``permissions=("change",)`` to this method with no ``obj``, and a bare
        ``True`` would have offered the restore actions to view-only staff.
        """
        return obj is None and super().has_change_permission(request, obj)

    # ------------------------------------------------------------------
    # Lifecycle actions — re-verified server-side; share the deletion path
    # ------------------------------------------------------------------

    @admin.action(description=_("Schedule deletion of selected data encryption key(s)"), permissions=("destroy",))
    def schedule_dek_deletion(self, request, queryset):
        """Schedule the selected key rows for deletion, after a confirmation step.

        Row-scoped: it schedules exactly the rows selected and never a key
        encryption key —
        only a real silo deletion cascades that far (see
        :func:`~encryption_suite.deletion.schedule_deletion`).

        A row whose silo still exists is refused, matching the key-encryption-key
        side: the purge would refuse it too, and an operator should not wait out a
        window to find that out. ``KEY_DELETION_CAN_RENDER_DATA_INACCESSIBLE``
        permits it. The refusal is reported on the confirmation screen rather than
        as a banner, so every refusal in this admin reads the same way.

        The connector that schedules on a real silo deletion
        (:func:`~encryption_suite.deletion.schedule_deletion`) is deliberately not
        gated: it fires after the silo is gone, so the check would pass anyway, and
        gating it would let an adapter that cannot answer silently stop teardown.
        """
        from .deletion import LIVE_DEK_STATUSES, dek_retain_reason, record_refused_scheduling, schedule_dek_deletion

        selected = list(queryset)
        # A key under rotation is schedulable like an active one: scheduling
        # moves only its own status, and the rotation survives for a restore.
        rows = [
            row for row in selected if row.status in LIVE_DEK_STATUSES and row.purpose != DataEncryptionKey.PURPOSE_TEST
        ]
        # Counted rather than dropped in silence, so a selection of five that
        # schedules three says where the other two went. Test-console rows are
        # counted apart: they have their own deletion path, so "not active" would
        # be the wrong explanation for them.
        test_rows = sum(1 for row in selected if row.purpose == DataEncryptionKey.PURPOSE_TEST)
        inactive = len(selected) - len(rows) - test_rows

        blocked = [(row, dek_retain_reason(row.silo_ref)) for row in rows]
        blocked = [(row, reason) for row, reason in blocked if reason is not None]
        if blocked:
            blocked_pks = {row.pk for row, _reason in blocked}
            rows = [row for row in rows if row.pk not in blocked_pks]
        # Recorded here rather than on either branch below, so a selection that is
        # only partly blocked is captured too. Runs once per attempt: the
        # confirmation screen posts back the schedulable rows only, so the
        # confirmed request re-derives an empty ``blocked``.
        record_refused_scheduling(
            blocked,
            trigger=lifecycle.TRIGGER_DIRECT,
            user=request.user,
            user_ip=get_user_ip(request),
            kind=lifecycle.KIND_DATA_ENCRYPTION_KEY,
        )

        if not rows:
            # Nothing to confirm, so no confirmation screen — see the
            # key-encryption-key action for the reasoning.
            self._report_nothing_schedulable(request, blocked, inactive, test_rows)
            return None

        if blocked or inactive or test_rows or request.POST.get("confirmed") != "1":
            return self._render_schedule_confirm(request, rows, blocked, inactive, test_rows)

        user_ip = get_user_ip(request)
        for row in rows:
            schedule_dek_deletion(row, trigger=lifecycle.TRIGGER_DIRECT, user=request.user, user_ip=user_ip)
        self.message_user(
            request,
            _("Scheduled %(n)d data encryption key(s) for deletion. Restore within the window.") % {"n": len(rows)},
            level=messages.SUCCESS,
        )
        return None

    def _report_nothing_schedulable(self, request, blocked, inactive, test_rows):
        """Explain a selection that yields nothing to schedule, on the changelist."""
        from .deletion import format_retain_reasons

        if blocked:
            uids = ", ".join(row.silo_uid for row, _reason in blocked[:5])
            if len(blocked) > 5:
                uids = _("%(uids)s and %(n)d more") % {"uids": uids, "n": len(blocked) - 5}
            self.message_user(
                request,
                _(
                    "Cannot schedule %(n)d key(s) (%(reasons)s). Destroying one makes its silo's "
                    "data permanently unreadable, and deleting would refuse it for the same "
                    "reason. Delete the silo first, or set "
                    "KEY_DELETION_CAN_RENDER_DATA_INACCESSIBLE to True in ENCRYPTION. %(uids)s"
                )
                % {
                    "n": len(blocked),
                    "reasons": format_retain_reasons({reason for _row, reason in blocked}),
                    "uids": uids,
                },
                level=messages.ERROR,
            )
        if inactive:
            self.message_user(
                request,
                _("Skipped %(n)d key(s) that are not active — already scheduled or deleted.") % {"n": inactive},
                level=messages.INFO,
            )
        if test_rows:
            self.message_user(
                request,
                _("Skipped %(n)d test console key(s), which have their own deletion path.") % {"n": test_rows},
                level=messages.INFO,
            )

    def _render_schedule_confirm(self, request, rows, blocked=(), inactive=0, test_rows=0):
        """Render the confirmation screen for the schedule action.

        Lists the rows that will be scheduled, and separately any the gate
        refused, with the reason. The live-silo count on the schedulable rows is
        informational — it survives because with
        ``KEY_DELETION_CAN_RENDER_DATA_INACCESSIBLE`` on there is no gate and
        an operator should still see the outage they are about to cause. The live
        set comes from the local helper rather than ``run_reconcile()``: a
        confirmation screen should not write rows or call the KMS.
        """
        from .conf import enc_settings
        from .deletion import format_retain_reasons

        orphan_uids = self._compute_orphan_uids()
        live_count = sum(1 for row in rows if (row.key_set, row.silo_uid) not in orphan_uids)
        context = {
            **self.admin_site.each_context(request),
            "title": _("Schedule deletion"),
            "opts": self.model._meta,
            "rows": rows,
            "blocked": [(row, format_retain_reasons([reason])) for row, reason in blocked],
            "inactive_count": inactive,
            "test_count": test_rows,
            "live_count": live_count,
            "total_count": len(rows),
            "cache_ttl": enc_settings.DEK_CACHE_TTL,
            "window_days": enc_settings.KEY_DELETION_WINDOW_DAYS,
            "action_name": "schedule_dek_deletion",
            "selected": [str(row.pk) for row in rows],
        }
        # TemplateResponse (not render) mirrors Django's own admin confirmation
        # views and keeps the context inspectable by callers and tests.
        return TemplateResponse(request, "admin/encryption_suite/dataencryptionkey/schedule_confirm.html", context)

    @admin.action(description=_("Restore selected scheduled data encryption key(s)"), permissions=("change",))
    def restore_scheduled(self, request, queryset):
        """Reverse a scheduled deletion, scoped to the selected rows.

        Matches the schedule action's scope — restoring a key row never touches a
        key encryption key.
        """
        from .deletion import restore_dek

        user_ip = get_user_ip(request)
        restored = 0
        for row in queryset.filter(status=lifecycle.STATUS_DELETION_SCHEDULED):
            restore_dek(row, trigger=lifecycle.TRIGGER_DIRECT, user=request.user, user_ip=user_ip)
            restored += 1
        self.message_user(
            request,
            _("Restored %(n)d data encryption key(s).") % {"n": restored},
            level=messages.SUCCESS,
        )

    @admin.action(description=_("Delete selected expired data encryption key(s)"), permissions=("destroy",))
    def purge_expired_work(self, request, queryset):
        """Shred the selected rows whose window has expired. This page's keys only.

        Scoped to data encryption keys: a key encryption key is destroyed from its
        own changelist, so neither irreversible act is a side effect of the other.
        Unexpired rows in the selection are left alone — the window decides, the
        selection only narrows.

        Confirmed first, because this is the irreversible half. A shredded keyset
        has no provider window behind it: the data is unreadable the moment this
        runs, and only a database backup taken while the wrapping key still exists
        could bring it back. The preview runs the real selection through a dry run
        so the screen lists exactly what the confirm will destroy.
        """
        from .deletion import purge_expired_deks

        pks = list(queryset.values_list("pk", flat=True))
        if request.POST.get("confirmed") != "1":
            confirm = self._render_purge_confirm(request, queryset, pks)
            if confirm.context_data["total_count"]:
                return confirm
            self._report_nothing_purgeable(request, confirm.context_data)
            return None

        summary = purge_expired_deks(
            trigger=lifecycle.TRIGGER_DIRECT,
            user=request.user,
            user_ip=get_user_ip(request),
            pks=pks,
        )
        self.message_user(
            request,
            _("Deletion complete: %(destroyed)d of %(picked)d selected data encryption key(s) destroyed.")
            % {"destroyed": summary.purged, "picked": len(pks)},
            # SUCCESS, not WARNING: the act completed as asked. WARNING is kept
            # for outcomes that want an operator's attention — a retained key, a
            # skipped selection — so the color still carries information.
            level=messages.SUCCESS if summary.purged else messages.INFO,
        )
        if summary.retained:
            from .deletion import format_retain_reasons

            self.message_user(
                request,
                _(
                    "Retained %(n)d key(s): %(reasons)s. Nothing changed — they stay scheduled, so "
                    "resolving the cause and deleting again works. Set "
                    "KEY_DELETION_CAN_RENDER_DATA_INACCESSIBLE to True in ENCRYPTION to delete "
                    "them regardless, making that data permanently unreadable."
                )
                % {"n": summary.retained, "reasons": format_retain_reasons(summary.retain_reasons)},
                level=messages.WARNING,
            )
        return None

    def _report_nothing_purgeable(self, request, ctx):
        """Explain a purge selection with nothing to shred, on the changelist."""
        if ctx["retained_count"]:
            self.message_user(
                request,
                _(
                    "Retained %(n)d key(s): %(reasons)s. Nothing changed — they stay scheduled, so "
                    "resolving the cause and deleting again works."
                )
                % {"n": ctx["retained_count"], "reasons": ctx["retained_reasons"]},
                level=messages.WARNING,
            )
        if ctx["unscheduled_count"]:
            self.message_user(
                request,
                _(
                    "Skipped %(n)d key(s) that are not scheduled for deletion. Schedule them first — "
                    "deleting only acts on scheduled work whose restore window has closed."
                )
                % {"n": ctx["unscheduled_count"]},
                level=messages.INFO,
            )
        if ctx["unexpired_count"]:
            self.message_user(
                request,
                _("Skipped %(n)d key(s) still inside their restore window.") % {"n": ctx["unexpired_count"]},
                level=messages.INFO,
            )

    def _render_purge_confirm(self, request, queryset, pks):
        """Render the confirmation screen, listing what the shred will destroy.

        Built from a dry run of the same call the confirm will make, so the list
        is the decision the real run makes rather than a second implementation of
        the window check. Rows whose window has not closed are absent from it, as
        are rows a gate refuses — the honest preview of a selection that includes
        either. Both are counted separately so the screen can say why the list is
        shorter than the selection.
        """
        from .deletion import format_retain_reasons, purge_expired_deks

        preview = purge_expired_deks(trigger=lifecycle.TRIGGER_DIRECT, dry_run=True, pks=pks)
        shredding = {label for verb, label, _reason in preview.details if verb == "SHRED"}
        eligible_pks = {
            row.pk
            for row in DataEncryptionKey.objects.filter(
                pk__in=pks,
                status=lifecycle.STATUS_DELETION_SCHEDULED,
                undeletable_until__lte=timezone.now(),
            )
        }
        rows = []
        unscheduled = 0
        unexpired = 0
        for row in queryset:
            if row.pk in eligible_pks:
                if f"{row.kek.key_store}:{row.kek.kek_resource_name} silo={row.silo_ref}" in shredding:
                    rows.append(row)
                continue
            # Counted apart: a row nobody scheduled is not waiting out a window,
            # and saying it is sends the operator to wait for nothing.
            if row.status != lifecycle.STATUS_DELETION_SCHEDULED:
                unscheduled += 1
            else:
                unexpired += 1
        context = {
            **self.admin_site.each_context(request),
            "title": _("Delete data encryption keys"),
            "opts": self.model._meta,
            "rows": rows,
            "unscheduled_count": unscheduled,
            "unexpired_count": unexpired,
            "retained_count": preview.retained,
            "retained_reasons": format_retain_reasons(preview.retain_reasons) if preview.retain_reasons else "",
            "total_count": preview.purged,
            "action_name": "purge_expired_work",
            "selected": [str(pk) for pk in pks],
        }
        return TemplateResponse(request, "admin/encryption_suite/dataencryptionkey/purge_confirm.html", context)

    @staticmethod
    def _compute_orphan_uids() -> set[tuple[str, str]]:
        """Return ``(key_set, uid)`` pairs stored in DEK rows that no live silo of that key set's adapter resolves to.

        Rows are orphan when the silo adapter no longer enumerates a
        source object with that UID (e.g. the tenant/team was deleted).
        Returns an empty set if enumeration fails — in that case, surface
        no drift rather than misreport every row as orphaned. Test-console
        rows are excluded: their sentinel UID is reserved so no real silo
        resolves to it, which would make them permanent false orphans.
        """
        from .conf import adapter_path, is_system_key_set
        from .registry import get_silo_adapter

        stored = set(
            DataEncryptionKey.objects.exclude(purpose=DataEncryptionKey.PURPOSE_TEST)
            .values_list("key_set", "silo_uid")
            .distinct()
        )
        orphans: set[tuple[str, str]] = set()
        # Liveness is asked once per adapter, however many key sets are bound to it.
        live_by_adapter: dict = {}
        for key_set in {key_set for key_set, _uid in stored if not is_system_key_set(key_set)}:
            # The system silo is live by definition, and not an adapter's to list.
            path = adapter_path(key_set)
            if path not in live_by_adapter:
                try:
                    adapter = get_silo_adapter(key_set)
                    # Detection-unavailable: an adapter that cannot enumerate every live
                    # silo gives us no trustworthy "live" set, so we cannot prove any row
                    # orphaned. Report none rather than misreport every row as an orphan.
                    live_by_adapter[path] = (
                        {adapter.get_silo_uid(g) for g in adapter.iter_silos()}
                        if adapter.supports_enumeration
                        else None
                    )
                except Exception:
                    live_by_adapter[path] = None
            live = live_by_adapter[path]
            if live is None:
                continue
            orphans.update((k, uid) for k, uid in stored if k == key_set and uid not in live)
        return orphans

    # ------------------------------------------------------------------
    # Custom screens
    #
    # get_urls is Django's hook, so the routes are registered here even though
    # the views themselves live in their own modules. The four URL names are
    # referenced from three changelist templates and from the views, and a
    # reverse() only fails at render time — so they stay exactly as they are.
    # ------------------------------------------------------------------

    def get_urls(self):
        urls = super().get_urls()
        custom = [
            path(
                "reconcile-keys/",
                self.admin_site.admin_view(self.reconcile_keys_view),
                name="encryption_suite_reconcile_keys",
            ),
            path(
                "settings/",
                self.admin_site.admin_view(self.settings_view),
                name="encryption_suite_settings",
            ),
            path(
                "inventory/",
                self.admin_site.admin_view(self.inventory_view),
                name="encryption_suite_inventory",
            ),
            path(
                "test-console/",
                self.admin_site.admin_view(self.test_console_view),
                name="encryption_suite_test_console",
            ),
            path(
                "test-console/run/",
                self.admin_site.admin_view(self.test_console_run_view),
                name="encryption_suite_test_console_run",
            ),
            path(
                "test-console/delete/",
                self.admin_site.admin_view(self.test_console_delete_view),
                name="encryption_suite_test_console_delete",
            ),
        ]
        return custom + urls

    def reconcile_keys_view(self, request):
        return admin_reconcile.reconcile_keys_view(self, request)

    def settings_view(self, request):
        return admin_settings.settings_view(self, request)

    def inventory_view(self, request):
        return admin_inventory.inventory_view(self, request)

    def test_console_view(self, request):
        return admin_test_console.test_console_view(self, request)

    def test_console_run_view(self, request):
        return admin_test_console.test_console_run_view(self, request)

    def test_console_delete_view(self, request):
        return admin_test_console.test_console_delete_view(self, request)
