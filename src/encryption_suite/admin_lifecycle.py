"""
Admin for the KEK/DEK lifecycle models:

* :class:`~encryption_suite.models.KeyEncryptionKey` — the durable "latest state" of every
  known key encryption key (KEK) on the KMS. Its add form records a key created outside this application
  key; selection actions
  schedule, restore, record, and purge — each re-verified server-side against the
  same gates the command-line path uses.
* :class:`~encryption_suite.models.KeyLifecycleEvent` — the permanent, append-only key
  lifecycle ledger, registered strictly read-only and surfaced as a read-only
  event inline on each key's detail page.

Registered via an import from ``admin.py`` (Django autodiscovers only that
module), keeping the lifecycle admin out of the already-large main admin file.
"""

from __future__ import annotations

import ipaddress

from django.contrib import admin, messages
from django.template.loader import render_to_string
from django.template.response import TemplateResponse
from django.utils.safestring import mark_safe
from django.utils.translation import gettext_lazy as _

from . import lifecycle, user_context
from .exceptions import EncryptionError
from .fields import is_undecryptable
from .models import DataEncryptionKey, KeyEncryptionKey, KeyLifecycleEvent, RecordedIPAddress, RecordedOSUser
from .user_context import get_user_ip

ORPHAN_MARKER_TEMPLATE = "admin/encryption_suite/components/orphan_marker.html"


class OrphanColumnMixin:
    """Render the ``is_orphaned`` changelist column through the shared marker.

    Mixed into both key changelists so the reconcile page and the two changelists
    give one answer one way. The field stays in ``list_filter`` — only its
    *display* is replaced — and ``ordering`` keeps the column sortable on the real
    column rather than on rendered markup.
    """

    @admin.display(description=_("Orphaned"), ordering="is_orphaned")
    def orphan_marker(self, obj):
        return mark_safe(render_to_string(ORPHAN_MARKER_TEMPLATE, {"is_orphaned": obj.is_orphaned}).strip())


class KeyKindListFilter(admin.SimpleListFilter):
    """Filter the ledger by key kind, derived from which FK is set.

    ``key_kind`` is a model property (no stored column), so the standard field
    list_filter cannot drive it — this maps the two kinds onto the FK presence.
    """

    title = _("key kind")
    parameter_name = "key_kind"

    def lookups(self, request, model_admin):
        return lifecycle.KIND_CHOICES

    def queryset(self, request, queryset):
        if self.value() == lifecycle.KIND_KEY_ENCRYPTION_KEY:
            return queryset.filter(kek__isnull=False)
        if self.value() == lifecycle.KIND_DATA_ENCRYPTION_KEY:
            return queryset.filter(dek__isnull=False)
        return queryset


def _label_with_code(label, code: str) -> str:
    """``Label (code)``: the translated words, then the code the log line carries.

    Log lines are English-pinned and name an act by its code (``event=``,
    ``reason=``), so the code beside the label is how a reader of this page, in
    any language, finds the matching line.
    """
    return f"{label} ({code})"


class ReasonColumnMixin:
    """Render a stored ``reason`` slug as its translated label, then the slug.

    The column is display-only, so the slug stays in the database exactly as
    written — this adds the words an operator reads. A value with no label (a
    provider message on a failed deletion) renders as itself, once.
    """

    @admin.display(description=_("Reason"), ordering="reason")
    def reason_label(self, obj):
        label = lifecycle.reason_label(obj.reason)
        if not obj.reason or label == obj.reason:
            return label
        return _label_with_code(label, obj.reason)


class EventColumnMixin:
    """Render the event verb and the trigger as their translated labels, then the code.

    The trigger has no log counterpart, but the docs describe every trigger by
    its code (``direct``, ``indirect``, ``automated``) and the combinations
    table is written in codes, so the code is what joins this column to them.
    """

    @admin.display(description=_("Event"), ordering="event")
    def event_label(self, obj):
        return _label_with_code(obj.get_event_display(), obj.event)

    @admin.display(description=_("Trigger"), ordering="trigger")
    def trigger_label(self, obj):
        return _label_with_code(obj.get_trigger_display(), obj.trigger)


class UserColumnMixin:
    """Render the recorded user, and join it in so rendering costs no query.

    The label goes through :func:`user_context.user_label_for`, which reads
    ``user_id`` and the joined instance and never ``event.user``: the forward
    descriptor raises ``RelatedObjectDoesNotExist`` on a row whose user has been
    deleted, which the admin swallows into an empty cell — saying nothing on
    exactly the rows a deactivate-over-delete policy makes expected. The method's
    name, not the field's, is what belongs in ``fields`` / ``readonly_fields`` /
    ``list_display``, since a field name there is attribute access.
    """

    @admin.display(description=_("User"))
    def user_label(self, obj):
        return user_context.user_label_for(obj)

    def get_queryset(self, request):
        # Defined on both ModelAdmin and InlineModelAdmin, so this one override
        # covers the changelist and both inlines. Never memoized on the admin
        # instance, which lives for the process. The OS user and the address are
        # joined too: each renders from its own row.
        return super().get_queryset(request).select_related("user", "os_user", "ip_address")

    def get_search_results(self, request, queryset, search_term):
        """Let the text fields answer, then OR in the user id, OS user and address.

        ``user_id`` cannot go in ``search_fields``: Django ORs one term across
        every field, and an integer primary key cannot prepare a non-numeric one —
        ``Field 'id' expected a number but got 'alice'`` 500s the changelist on
        the first thing an operator types into a box labeled with a person's name.
        ``user_id`` rather than ``user__username``, because the user model is
        swappable and may have no username field.

        The OS user and the address live in their own tables, possibly encrypted,
        so neither can be a ``search_fields`` entry either; see
        :func:`_matching_os_user_ids` and :func:`_matching_ip_address_ids`.
        """
        results, may_have_duplicates = super().get_search_results(request, queryset, search_term)
        term = (search_term or "").strip()
        if not term:
            return results, may_have_duplicates
        if term.isdigit():
            results = results | self.model.objects.filter(user_id=int(term))
            may_have_duplicates = True
        os_user_ids = _matching_os_user_ids(term)
        if os_user_ids:
            results = results | self.model.objects.filter(os_user_id__in=os_user_ids)
            may_have_duplicates = True
        ip_address_ids = _matching_ip_address_ids(term)
        if ip_address_ids:
            results = results | self.model.objects.filter(ip_address_id__in=ip_address_ids)
            may_have_duplicates = True
        return results, may_have_duplicates

    @admin.display(description=KeyLifecycleEvent._meta.get_field("os_user").verbose_name)
    def os_user_label(self, obj):
        """The OS user, for ``list_display``; unsortable, since its rows are ordered by first sight."""
        return str(obj.os_user) if obj.os_user_id else ""

    @admin.display(description=KeyLifecycleEvent._meta.get_field("ip_address").verbose_name)
    def ip_address_label(self, obj):
        """The address, for ``list_display``; unsortable, for the same reason."""
        return str(obj.ip_address) if obj.ip_address_id else ""


def _matching_os_user_ids(term: str) -> list[int]:
    """Ids of the recorded OS users whose value contains *term*, case-insensitively.

    Searched in memory: the table holds a handful of rows — one per operator
    account and sudo combination — and an encrypted value can only be compared
    once decrypted. The whole composed string is matched; it is not split into
    parts. A value that cannot be decrypted matches nothing, rather than letting
    its fallback label answer for it.
    """
    needle = term.casefold()
    ids = []
    for row in RecordedOSUser.objects.order_by("pk"):
        try:
            value = row.value
        except EncryptionError:
            continue
        if value is None or is_undecryptable(value):
            continue
        if needle in str(value).casefold():
            ids.append(row.pk)
    return ids


def _matching_ip_address_ids(term: str) -> list[int]:
    """Ids of the recorded addresses equal to *term*: plaintext, then the blind index.

    An exact match only, since that is all a blind index answers — and this table
    can grow large under ``all_acts``, so it is never read whole. A term that is
    not an address matches nothing. Where the system keys cannot serve the
    encrypted lookup, the plaintext answer stands alone: a search must not 500.
    """
    try:
        address = str(ipaddress.ip_address(term))
    except ValueError:
        return []
    ids = list(RecordedIPAddress.objects.filter(ip_address=address).values_list("pk", flat=True))
    try:
        ids += RecordedIPAddress.objects.filter(encrypted_ip_address=address).values_list("pk", flat=True)
    except EncryptionError:
        pass
    return ids


class KeyKindColumnMixin:
    """Render the ledger's kind column as an acronym rather than its raw value.

    ``key_kind`` is a model property with no stored column, so it has no
    ``choices`` for the admin to resolve — it rendered the internal identifiers,
    which are not symmetrical (``kek`` against ``data_encryption_key``).
    """

    @admin.display(description=_("Key kind"))
    def key_kind_label(self, obj):
        return lifecycle.KIND_SHORT_LABELS.get(obj.key_kind, obj.key_kind)


class _KeyEventInline(UserColumnMixin, ReasonColumnMixin, EventColumnMixin, admin.TabularInline):
    """Read-only event history for a key detail page (one row per ledger event)."""

    model = KeyLifecycleEvent
    extra = 0
    can_delete = False
    # Django's tabular inline without the row name it prints above each row —
    # an event's name is its verb and key, which on a key's own page repeat the
    # Event column and the page itself.
    template = "admin/encryption_suite/edit_inline/tabular_history.html"
    fields = (
        "created_at",
        "event_label",
        "trigger_label",
        # Beside the trigger: together they say how and why the event came
        # about, before the columns saying who.
        "reason_label",
        "user_label",
        # The foreign keys themselves, so the headings keep the fields' help
        # text; each renders its row's value, which is unregistered and so is
        # shown as text rather than a link.
        "os_user",
        "ip_address",
        "effective_at",
    )
    readonly_fields = fields
    # Oldest first, so a key's history reads as the story it is: created, then
    # what happened to it, ending at where the row stands now. ``pk`` breaks the
    # tie between events a single transaction wrote at the same instant, which
    # timestamps alone order arbitrarily. The changelist keeps newest first —
    # there the question is what happened lately, across every key.
    ordering = ("created_at", "pk")

    def has_add_permission(self, request, obj=None):
        return False

    def has_change_permission(self, request, obj=None):
        return False


class KekEventInline(_KeyEventInline):
    fk_name = "kek"
    # The version each event saw, so the history shows each rotation. The KMS
    # and the other protection columns are blank on a KEK's events.
    fields = (*_KeyEventInline.fields, "kek_key_version")
    readonly_fields = fields


class DekEventInline(_KeyEventInline):
    fk_name = "dek"
    # What protected the data key after each event, so the history shows each
    # move between KEKs, KMSs, KEK versions and backends. ``wrapping_kek`` links
    # to the KEK that wrapped the key then, which may not be the one it has now.
    fields = (
        *_KeyEventInline.fields,
        "wrapping_kek",
        "key_store",
        "kek_key_version",
        "crypto_backend",
        "algorithm",
    )
    readonly_fields = fields


@admin.register(KeyLifecycleEvent)
class KeyLifecycleEventAdmin(
    UserColumnMixin, ReasonColumnMixin, EventColumnMixin, KeyKindColumnMixin, admin.ModelAdmin
):
    """Read-only view of the append-only key lifecycle ledger.

    The ledger is the immutable audit trail, so the admin offers no add, change,
    or delete — only viewing, filtering, and search.
    """

    list_display = (
        "created_at",
        "event_label",
        "key_kind_label",
        "key_set",
        "silo_uid",
        "kek_resource_name",
        "key_store",
        "kek_key_version",
        "crypto_backend",
        "algorithm",
        "trigger_label",
        # Beside the trigger, as on a key's own history.
        "reason_label",
        "user_label",
        "os_user_label",
        "ip_address_label",
    )
    # The detail page reads as its own row does: the same columns, in the same
    # order, through the same display methods — so the codes beside the labels
    # are there too. Declared explicitly because the default form is built from
    # *editable* fields, which on an append-only ledger means the raw verb and
    # slug, and no ``created_at`` at all.
    fields = (
        "created_at",
        "event_label",
        "key_kind_label",
        "kek",
        "dek",
        "key_set",
        "silo_uid",
        "kek_resource_name",
        "wrapping_kek",
        "key_store",
        "kek_key_version",
        "crypto_backend",
        "algorithm",
        "trigger_label",
        "reason_label",
        "user_label",
        "os_user",
        "ip_address",
        "effective_at",
    )
    readonly_fields = fields
    list_filter = ("event", "trigger", ("user", admin.RelatedOnlyFieldListFilter), KeyKindListFilter)
    # The user id, OS user and address are searched in get_search_results.
    search_fields = ("silo_uid", "kek_resource_name")
    date_hierarchy = "created_at"
    ordering = ("-created_at",)
    change_list_template = "admin/encryption_suite/keylifecycleevent/change_list.html"

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False


@admin.register(KeyEncryptionKey)
class KeyEncryptionKeyAdmin(OrphanColumnMixin, admin.ModelAdmin):
    """The durable key-encryption-key store, with the lifecycle selection actions.

    The add form records a key an operator created outside this application (row + ``created``
    event). Existing rows are not hand-editable — every state change goes through
    a re-verified action: schedule, restore, record a deletion performed outside this application, or
    purge expired scheduled work. The actions share the same gates as the
    test console's deletion, so neither path can drift.

    Scheduling states intent and the purge enforces, so a key that reconcile has
    not confirmed as an orphan may still be scheduled — the refusal, when one
    comes, names its reason instead of the changelist silently offering nothing.

    The exception is a key live data still depends on. That is refused at
    scheduling rather than at purge, because the purge would refuse it too and an
    operator should not wait out a window to find that out. See
    ``KEY_DELETION_CAN_RENDER_DATA_INACCESSIBLE``.
    """

    # Every column is a live property an operator acts on. `disposition` is not:
    # it records what was concluded when a key was scheduled, so it is blank on
    # exactly the rows where scheduling is still the decision to make, and the
    # delete re-derives it anyway. It stays on the detail page, beside the owner
    # prefix it was recorded with.
    list_display = (
        "kek_resource_name",
        "key_store",
        "status",
        "kek_key_version",
        "orphan_marker",
        "undeletable_until",
        "kms_deletion_at",
    )
    list_filter = ("status", "key_store", "is_orphaned")
    search_fields = ("kek_resource_name",)
    ordering = ("kek_resource_name",)
    change_list_template = "admin/encryption_suite/keyencryptionkey/change_list.html"
    inlines = (KekEventInline,)
    actions = (
        "schedule_deletion",
        "restore_scheduled",
        "record_deleted_in_kms",
        "record_requested_in_kms",
        "record_restored_in_kms",
        "purge_expired_work",
    )

    # The add form captures only what an operator attests about an outside this application
    # key; everything else is derived (status from the ledger, dates from later
    # actions). On an existing row every field is read-only.
    _ADD_FIELDS = ("key_store", "kek_resource_name", "disposition")
    _READONLY = (
        "status",
        "undeletable_until",
        "kms_deletion_at",
        "owner_prefix",
        "kek_key_version",
        "orphan_marker",
        "created_at",
        "updated_at",
    )

    def get_fields(self, request, obj=None):
        if obj is None:
            return self._ADD_FIELDS
        return ("key_store", "kek_resource_name", "disposition", *self._READONLY)

    def get_readonly_fields(self, request, obj=None):
        if obj is None:
            return ()
        return ("key_store", "kek_resource_name", "disposition", *self._READONLY)

    def has_delete_permission(self, request, obj=None):
        return False

    def has_destroy_permission(self, request):
        """Answer for the actions that move a key toward being destroyed.

        Reads the model's own delete permission. The action machinery resolves
        ``permissions=("destroy",)`` to this method, which exists because the
        obvious name resolves to :meth:`has_delete_permission` — hard-coded
        ``False`` here to strip the admin's own delete button, which would hide
        these actions from everyone including a superuser.
        """
        return request.user.has_perm("encryption_suite.delete_keyencryptionkey")

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

    def formfield_for_dbfield(self, db_field, request, **kwargs):
        """Offer the configured KMS names, and only those, for ``key_store``.

        Every unwrap, deletion and reconcile pass routes by the name a row
        records, so a name no block carries produces a row that looks tracked,
        does nothing, and can be duplicated later by discovery. A choice list
        makes that row impossible to enter. The field is only editable on the
        add form; on an existing row it is read-only and never reaches here.
        """
        if db_field.name == "key_store":
            from django import forms

            from .conf import is_env_store, kms_names

            # Not an env store: no KMS outside this application holds its key,
            # so there is no act there to record.
            names = [name for name in kms_names() if not is_env_store(name)]
            silo_kms = self._silo_kms_name()
            return forms.ChoiceField(
                choices=[(name, name) for name in names],
                label=db_field.verbose_name,
                help_text=db_field.help_text,
                initial=silo_kms if silo_kms in names else (names[0] if names else None),
            )
        return super().formfield_for_dbfield(db_field, request, **kwargs)

    @staticmethod
    def _silo_kms_name() -> str:
        """The ``default`` key set's store, or ``""`` if the settings cannot be read.

        Never raises: a misconfiguration must not stop the add form from
        rendering, since recording a key by hand is exactly what an operator does
        while sorting a configuration out.
        """
        from .conf import DEFAULT_KEY_SET, resolve_store

        return resolve_store(DEFAULT_KEY_SET) or ""

    def save_model(self, request, obj, form, change):
        """Persist an add for a key created outside this application as a row plus its ``created`` ledger event."""
        super().save_model(request, obj, form, change)
        if change:
            return
        KeyLifecycleEvent.record_by_operator(
            obj, lifecycle.EVENT_CREATED, user=request.user, user_ip=get_user_ip(request)
        )

    # ------------------------------------------------------------------
    # Actions — each re-verifies live before touching anything
    # ------------------------------------------------------------------

    @admin.action(description=_("Schedule deletion of selected key encryption key(s)"), permissions=("destroy",))
    def schedule_deletion(self, request, queryset):
        """Schedule the selected active keys, after a confirmation step.

        Scheduling is an expression of intent, not the enforcement point. Any
        active key may be scheduled — including one that is not a reconcile
        orphan — because the purge re-checks every gate at the moment of
        destruction and refuses with a named reason: a key still wrapping live
        keysets is retained as ``in_use_by_other_silo``, a shared one as
        ``shared_or_opaque_disposition``, an unowned one as
        ``not_owned_by_deployment``.

        Gating *scheduling* on orphan status instead made the capability vanish
        whenever enumeration was unavailable — no owner prefix, a provisioner that
        cannot list, a KMS hiccup — which is a detection outcome, not a statement
        about whether deleting would be safe. The operator saw an unexplained
        refusal either way. The confirmation screen now reports how many silos'
        keysets each key still wraps, so the blast radius is visible before the
        window starts rather than discovered at purge.
        """
        from .deletion import (
            RETAIN_IN_USE,
            allow_deleting_keys_in_use,
            live_owner_prefix,
            record_refused_scheduling,
            schedule_kek_deletion,
        )

        selected = list(queryset)
        # The test console's keys are deleted from the console, whatever their
        # status and whatever the settings, the same as on the data key side.
        test_pks = self._test_console_kek_pks(selected)
        rows = [row for row in selected if row.status == lifecycle.STATUS_ACTIVE and row.pk not in test_pks]
        # Only an active key can be scheduled. Counted rather than dropped in
        # silence: a selection of five that schedules three should say where the
        # other two went, the same way the purge screen does. Test-console keys
        # are counted apart, since "not active" would be the wrong explanation.
        test_rows = len(test_pks)
        inactive = len(selected) - len(rows) - test_rows

        # Refuse here rather than at purge. Scheduling a key the purge can never
        # destroy leaves it sitting out a window under a promise nothing will
        # keep, and the operator learns only after it expires. Reported on the
        # confirmation screen rather than as a banner, so every refusal in this
        # admin reads the same way: a page naming the keys and what to do, with
        # no button that would go through.
        blocked = []
        if not allow_deleting_keys_in_use():
            blocked = [row for row in rows if self._live_keyset_count(row)]
            rows = [row for row in rows if row not in blocked]
        # Recorded here rather than on either branch below, so a selection that is
        # only partly blocked is captured too. Runs once per attempt: the
        # confirmation screen posts back the schedulable rows only, so the
        # confirmed request re-derives an empty ``blocked``.
        record_refused_scheduling(
            [(row, RETAIN_IN_USE) for row in blocked],
            trigger=lifecycle.TRIGGER_DIRECT,
            user=request.user,
            user_ip=get_user_ip(request),
            kind=lifecycle.KIND_KEY_ENCRYPTION_KEY,
        )

        if not rows:
            # Nothing to confirm, so no confirmation screen: a page whose only
            # control is "take me back" asks no question and costs a click to
            # leave. Report on the changelist instead, the way every other
            # outcome in this admin is reported.
            self._report_nothing_schedulable(request, blocked, inactive, test_rows)
            return None

        if blocked or inactive or test_rows or request.POST.get("confirmed") != "1":
            return self._render_schedule_confirm(request, rows, blocked, inactive, test_rows)

        # Each key's prefix comes from the store its row names, matched against its
        # name; one that cannot be read is "" (already logged), and the purge gate
        # refuses without one.

        user_ip = get_user_ip(request)
        for row in rows:
            schedule_kek_deletion(
                row,
                owner_prefix=live_owner_prefix(row.key_store, kek_name=row.kek_resource_name),
                trigger=lifecycle.TRIGGER_DIRECT,
                user=request.user,
                user_ip=user_ip,
            )

        self.message_user(
            request,
            _("Scheduled %(n)d key encryption key(s) for deletion. Restore within the window, or run the deletion.")
            % {"n": len(rows)},
            level=messages.SUCCESS,
        )
        return None

    @staticmethod
    def _test_console_kek_pks(rows) -> set:
        """The pks among *rows* of keys only the test console's data keys use.

        A key that any other data key names is not the console's, even when the
        console uses it too: that is a real silo's key, and the in-use gate
        decides it like any other.
        """
        pks = [row.pk for row in rows]
        keys = DataEncryptionKey.objects.filter(kek__in=pks)
        test = set(keys.filter(purpose=DataEncryptionKey.PURPOSE_TEST).values_list("kek_id", flat=True))
        real = set(keys.exclude(purpose=DataEncryptionKey.PURPOSE_TEST).values_list("kek_id", flat=True))
        return test - real

    @staticmethod
    def _live_keyset_count(row) -> int:
        """How many silos still hold an un-shredded keyset wrapped by *row*.

        The blast radius of destroying this key: every one of them loses its data
        permanently. Counts keysets rather than statuses — a shredded tombstone
        records that a silo used the key but no longer depends on it.

        Shared by the schedule refusal, the schedule confirmation, and the purge
        confirmation so all three report the same number.

        A data key rotation's incoming keyset counts too: a key whose last
        dependent is a rotation row still holds a silo's material, and after the
        swap it is the only copy.
        """
        silos = set(row.data_keys.exclude(encrypted_keyset=b"").values_list("key_set", "silo_uid"))
        silos.update(row.dek_rotations.values_list("dek__key_set", "dek__silo_uid"))
        return len(silos)

    def _report_nothing_schedulable(self, request, blocked, inactive, test_rows=0):
        """Explain a selection that yields nothing to schedule, on the changelist."""
        if blocked:
            names = ", ".join(row.kek_resource_name for row in blocked[:5])
            if len(blocked) > 5:
                names = _("%(names)s and %(n)d more") % {"names": names, "n": len(blocked) - 5}
            self.message_user(
                request,
                _(
                    "Cannot schedule %(n)d key(s): live data still depends on them, and destroying "
                    "them would make it permanently unreadable. Delete the silos using them first, "
                    "or set KEY_DELETION_CAN_RENDER_DATA_INACCESSIBLE to True in ENCRYPTION. "
                    "%(names)s"
                )
                % {"n": len(blocked), "names": names},
                level=messages.ERROR,
            )
        if inactive:
            self.message_user(
                request,
                _("Skipped %(n)d key(s) that are not active — already scheduled, retained, or deleted.")
                % {"n": inactive},
                level=messages.INFO,
            )
        if test_rows:
            self.message_user(
                request,
                _("Skipped %(n)d test console key(s), which have their own deletion path.") % {"n": test_rows},
                level=messages.INFO,
            )

    def _render_schedule_confirm(self, request, rows, blocked=(), inactive=0, test_rows=0):
        """Render the confirmation screen, reporting each key's blast radius.

        The count that matters is how many silos' keysets a key still wraps —
        every one of them loses its data if the key is destroyed. Informational,
        never a gate: the purge is what refuses, and it re-checks live.

        Counts un-shredded keysets only, matching the purge's in-use gate: a
        shredded tombstone records that a silo used the key but no longer depends
        on it.
        """
        from .conf import enc_settings

        in_use = {}
        for row in rows:
            in_use[row.pk] = self._live_keyset_count(row)

        context = {
            **self.admin_site.each_context(request),
            "title": _("Schedule deletion"),
            "opts": self.model._meta,
            "rows": [(row, in_use[row.pk]) for row in rows],
            "blocked": [(row, self._live_keyset_count(row)) for row in blocked],
            "inactive_count": inactive,
            "test_count": test_rows,
            "total_count": len(rows),
            "in_use_count": sum(1 for row in rows if in_use[row.pk]),
            "window_days": enc_settings.KEY_DELETION_WINDOW_DAYS,
            "action_name": "schedule_deletion",
            "selected": [str(row.pk) for row in rows],
        }
        return TemplateResponse(request, "admin/encryption_suite/keyencryptionkey/schedule_confirm.html", context)

    @admin.action(
        description=_("Restore selected scheduled or retained key encryption key(s)"), permissions=("change",)
    )
    def restore_scheduled(self, request, queryset):
        """Return a scheduled or retained key to active. Touches no provider.

        ``retained`` is included because it is otherwise a dead end: the schedule
        action takes only active keys and this one took only scheduled ones, so a
        key a gate refused could be neither re-scheduled nor restored. The only
        way out was the operator-attested "deletion canceled in the KMS", which
        asserts something about the *provider* — a false statement for a key no
        provider call was ever made against.
        """
        from .deletion import restore_kek

        user_ip = get_user_ip(request)
        restored = 0
        for row in queryset.filter(status__in=(lifecycle.STATUS_DELETION_SCHEDULED, lifecycle.STATUS_RETAINED)):
            restore_kek(row, trigger=lifecycle.TRIGGER_DIRECT, user=request.user, user_ip=user_ip)
            restored += 1
        self.message_user(
            request,
            _("Restored %(n)d key encryption key(s) to active.") % {"n": restored},
            level=messages.SUCCESS,
        )

    @admin.action(description=_("Record selected as deleted in the key store"), permissions=("destroy",))
    def record_deleted_in_kms(self, request, queryset):
        self._record_in_kms(request, queryset, lifecycle.EVENT_DELETED)

    @admin.action(description=_("Record selected as deletion requested in the key store"), permissions=("destroy",))
    def record_requested_in_kms(self, request, queryset):
        self._record_in_kms(request, queryset, lifecycle.EVENT_DELETION_REQUESTED)

    @admin.action(description=_("Record selected as deletion canceled in the key store"), permissions=("change",))
    def record_restored_in_kms(self, request, queryset):
        """Record that a provider-side deletion was canceled, returning the row to active.

        The counterpart to recording a deletion. A key whose deletion was
        canceled in the KMS is usable again, but the row still reads
        ``deletion_requested``: the restore action only reverses this
        application's own window, and reconcile flags the disagreement rather
        than auto-correcting it, because inferring a restore from what the
        provider happens to list is exactly the guess that must never be made
        automatically. The operator who ran the cancellation records it.
        """
        self._record_in_kms(request, queryset, lifecycle.EVENT_RESTORED)

    def _record_in_kms(self, request, queryset, event):
        """Append an operator-attested event to the selected keys. No KMS call.

        A row already standing where the verb would put it is skipped, the way
        the restore action skips a key that is not scheduled. Recording a key as
        deleted twice appends a second attestation at a later date, which reads
        as a second deletion — and the funnel would not move the row, so the
        ledger and the row would disagree about whether anything happened.

        The guard is here rather than in ``record_by_operator``: that funnel is a
        ledger, and a project driving it from its own tooling may have reason to
        re-assert. What this action offers is a state change, and there is none
        to make.
        """
        user_ip = get_user_ip(request)
        settled = lifecycle.VERB_TO_STATUS[event]
        verb = dict(lifecycle.EVENT_CHOICES).get(event, event)

        recorded = 0
        skipped = 0
        for row in queryset:
            if row.status == settled:
                skipped += 1
                continue
            KeyLifecycleEvent.record_by_operator(row, event, user=request.user, user_ip=user_ip)
            recorded += 1
        if recorded:
            self.message_user(
                request,
                _("Recorded %(n)d key encryption key(s) as '%(verb)s' in the key store.")
                % {"n": recorded, "verb": verb},
                level=messages.SUCCESS,
            )
        if skipped:
            self.message_user(
                request,
                _("Skipped %(n)d key encryption key(s) already recorded as '%(verb)s'.") % {"n": skipped, "verb": verb},
                level=messages.INFO,
            )

    @admin.action(description=_("Delete selected expired key encryption key(s)"), permissions=("destroy",))
    def purge_expired_work(self, request, queryset):
        """Delete the selected expired keys at the provider. This page's keys only.

        Scoped to key encryption keys, and refuses "select all N records": this is
        the irreversible half of a deletion — a destroyed KEK cannot be recovered
        from a database backup, because what is lost is the key that backup's
        ciphertext depends on. Destroying an unbounded set of them should be a
        deliberate, reviewable act, which is why nothing in this package sweeps
        them and why the selection is confirmed against a preview first.

        Unexpired rows in the selection are left alone, and every gate is still
        re-checked per key — the selection only narrows the candidates.
        """
        from .deletion import purge_expired_keks

        if request.POST.get("select_across") == "1":
            self.message_user(
                request,
                _(
                    "Select the key encryption keys to delete individually. Deleting a key at the "
                    "provider cannot be undone from here, so this action does not act on every "
                    "matching record at once."
                ),
                level=messages.WARNING,
            )
            return None

        pks = list(queryset.values_list("pk", flat=True))

        if request.POST.get("confirmed") != "1":
            confirm = self._render_purge_confirm(request, queryset, pks)
            if confirm.context_data["delete_count"]:
                return confirm
            # Nothing would be destroyed, so there is nothing to confirm — but the
            # operator did attempt a destruction and the gates refused it, and that
            # is the terminal outcome of this request, not a preview they can still
            # back out of. Run the purge so the refusal is recorded against each key
            # and the rows leave the scheduled queue. Provably destroys nothing: a
            # zero delete_count means every outcome was RETAIN or SKIP, and the
            # preview reaches those verdicts without calling the provider.
            #
            # Not a corner case. Any deployment whose provisioner cannot delete —
            # NullKekProvisioner, or a provider with no delete support — refuses
            # every key at gate 2, so delete_count is always zero and this is the
            # only path its purges ever take.
            purge_expired_keks(
                trigger=lifecycle.TRIGGER_DIRECT,
                user=request.user,
                user_ip=get_user_ip(request),
                pks=pks,
            )
            self._report_nothing_purgeable(request, confirm.context_data)
            return None

        summary = purge_expired_keks(
            trigger=lifecycle.TRIGGER_DIRECT,
            user=request.user,
            user_ip=get_user_ip(request),
            pks=pks,
        )
        self.message_user(
            request,
            _(
                "Deletion complete on %(picked)d selected key encryption key(s): %(del)d deleted, "
                "%(req)d requested at the provider, %(retain)d retained, %(fail)d failed, %(skip)d skipped."
            )
            % {
                "picked": len(pks),
                "del": summary.deleted,
                "req": summary.requested,
                "retain": summary.retained,
                "fail": summary.failed,
                "skip": summary.skipped,
            },
            # SUCCESS, not WARNING: the act completed as asked. WARNING is kept
            # for outcomes that want an operator's attention.
            level=messages.SUCCESS if (summary.deleted or summary.requested) else messages.INFO,
        )
        if summary.skipped_key_stores:
            # Every skip means no block carries the row's KMS name, which is most
            # often a deployment pointed at the wrong settings — the same diagnosis
            # the management commands print.
            from .management._hints import kms_not_configured_hint

            self.message_user(
                request,
                kms_not_configured_hint(summary.skipped_key_stores),
                level=messages.WARNING,
            )
        return None

    def _report_nothing_purgeable(self, request, ctx):
        """Explain a purge selection with nothing to destroy, on the changelist."""
        retained = [(row, reason) for row, verb, reason, _in_use in ctx["rows"] if verb == "RETAIN"]
        if retained:
            self.message_user(
                request,
                _("Retained %(n)d key(s): %(reasons)s.")
                % {"n": len(retained), "reasons": ", ".join(sorted({reason for _row, reason in retained}))},
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
        """Render the confirmation screen, reporting each key's decided outcome.

        Built from a dry run of the same call the confirm will make, so the screen
        reports what the gates actually decide — retained, skipped, deleted — rather
        than promising a destruction that a gate will refuse a moment later. A key
        still wrapping live keysets shows the silo count it would take with it.
        """
        from .deletion import format_retain_reasons, purge_expired_keks

        preview = purge_expired_keks(
            trigger=lifecycle.TRIGGER_DIRECT,
            dry_run=True,
            pks=pks,
        )
        outcomes = {label: (verb, reason) for verb, label, reason in preview.details}
        rows = []
        unscheduled = 0
        unexpired = 0
        for row in queryset:
            label = f"{row.key_store}:{row.kek_resource_name}"
            if label not in outcomes:
                # Never reached the purge, and the two ways that happens call for
                # different words: a key nobody scheduled is not "waiting out a
                # window", and telling an operator it is sends them to wait for
                # something that will never arrive.
                if row.status != lifecycle.STATUS_DELETION_SCHEDULED:
                    unscheduled += 1
                else:
                    unexpired += 1
                continue
            verb, reason = outcomes[label]
            in_use = self._live_keyset_count(row)
            rows.append((row, verb, format_retain_reasons([reason]) if reason else "", in_use))

        context = {
            **self.admin_site.each_context(request),
            "title": _("Delete key encryption keys"),
            "opts": self.model._meta,
            "rows": rows,
            "delete_count": preview.deleted + preview.requested,
            "unscheduled_count": unscheduled,
            "unexpired_count": unexpired,
            "in_use_count": sum(1 for _row, verb, _reason, in_use in rows if verb == "DELETE" and in_use),
            "action_name": "purge_expired_work",
            "selected": [str(pk) for pk in pks],
        }
        return TemplateResponse(request, "admin/encryption_suite/keyencryptionkey/purge_confirm.html", context)
