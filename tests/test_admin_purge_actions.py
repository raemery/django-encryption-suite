"""The two admin purge actions are scoped per changelist and honor the selection.

Destroying a data encryption key and destroying the key encryption key that wraps
it have different reversibility — a shredded DEK can come back from a database
restore, a deleted KEK cannot — so neither is a side effect of the other, and
neither acts on rows the operator did not pick.
"""

from __future__ import annotations

import datetime

import pytest
from django.conf import settings
from django.contrib import admin as django_admin
from django.test import RequestFactory, override_settings
from django.utils import timezone

from encryption_suite import lifecycle
from encryption_suite.adapters.keks.provisioners import AbstractKekProvisioner, DeleteOutcome
from encryption_suite.admin import DataEncryptionKeyAdmin
from encryption_suite.admin_lifecycle import KeyEncryptionKeyAdmin
from encryption_suite.models import DataEncryptionKey, KeyEncryptionKey
from encryption_suite.silo_ref import SiloRef
from tests.adapters import FakeKmsAdapterBase
from tests.factories import make_kek, make_kek_row, make_user

_PROVIDER = "fly"
_PREFIX = "kek_"
_PAST = timezone.now() - datetime.timedelta(days=1)


class _FakeProvisioner(AbstractKekProvisioner):
    supports_delete = True

    def __init__(self):
        super().__init__({})
        self.deleted: list[str] = []

    def ensure_kek(self, kek_resource_name, silo_ref):  # pragma: no cover
        pass

    def _do_delete_kek(self, kek_resource_name, silo_ref):
        self.deleted.append(kek_resource_name)
        return DeleteOutcome(scheduled=False, effective_at=timezone.now())


class _FakeAdapter(FakeKmsAdapterBase):
    kms_provider = _PROVIDER


@pytest.fixture(autouse=True)
def _fake_kms_is_configured(configured_kms):
    configured_kms(_PROVIDER, silo_kms=False)


@pytest.fixture
def wired(monkeypatch, configured_owner_prefix):
    prov = _FakeProvisioner()
    monkeypatch.setattr("encryption_suite.registry.get_kek_provisioner", lambda name=None: prov)
    monkeypatch.setattr("encryption_suite.registry.get_kms_adapter", lambda name=None: _FakeAdapter())
    configured_owner_prefix(_PREFIX)
    return prov


def _request(**post):
    request = RequestFactory().post("/", post)
    # A real row, because the ledger records who acted as a reference to one.
    request.user = make_user("alice")
    request._messages = _Messages()
    return request


class _Messages:
    def __init__(self):
        self.sent = []

    def add(self, level, message, extra_tags=""):
        self.sent.append((level, str(message)))

    def __iter__(self):
        # The confirmation screens extend admin/base_site.html, which iterates
        # the message store while rendering.
        return iter([])


def _scheduled_dek(uid):
    row = DataEncryptionKey.objects.create(
        key_set="default",
        silo_uid=uid,
        purpose=DataEncryptionKey.PURPOSE_FIELD,
        silo_label="team",
        encrypted_keyset=b"wrapped-dek",
        kek=make_kek(_PREFIX + uid, _PROVIDER),
    )
    row.record_event(lifecycle.EVENT_DELETION_SCHEDULED, trigger=lifecycle.TRIGGER_DIRECT, undeletable_until=_PAST)
    return row


def _scheduled_kek(uid):
    row = make_kek_row(
        key_store=_PROVIDER,
        kek_resource_name=_PREFIX + uid,
        disposition=KeyEncryptionKey.DISPOSITION_SILO_EXCLUSIVE,
        owner_prefix=_PREFIX,
    )
    row.record_event(
        lifecycle.EVENT_DELETION_SCHEDULED,
        trigger=lifecycle.TRIGGER_DIRECT,
        undeletable_until=_PAST,
        silo_ref=SiloRef("default", uid),
    )
    return row


@pytest.mark.django_db
def test_dek_action_shreds_only_the_selected_rows(wired):
    picked = _scheduled_dek("team1")
    other = _scheduled_dek("team2")
    ma = DataEncryptionKeyAdmin(DataEncryptionKey, django_admin.site)

    ma.purge_expired_work(_request(confirmed="1"), DataEncryptionKey.objects.filter(pk=picked.pk))

    picked.refresh_from_db()
    other.refresh_from_db()
    assert bytes(picked.encrypted_keyset) == b""
    assert bytes(other.encrypted_keyset) == b"wrapped-dek"  # not selected, untouched


@pytest.mark.django_db
def test_dek_action_leaves_key_encryption_keys_alone(wired):
    dek = _scheduled_dek("team1")
    kek = _scheduled_kek("team1")
    ma = DataEncryptionKeyAdmin(DataEncryptionKey, django_admin.site)

    ma.purge_expired_work(_request(confirmed="1"), DataEncryptionKey.objects.filter(pk=dek.pk))

    kek.refresh_from_db()
    assert wired.deleted == []
    assert kek.status == lifecycle.STATUS_DELETION_SCHEDULED


@pytest.mark.django_db
def test_kek_action_deletes_only_the_selected_rows(wired):
    picked = _scheduled_kek("team1")
    other = _scheduled_kek("team2")
    ma = KeyEncryptionKeyAdmin(KeyEncryptionKey, django_admin.site)

    ma.purge_expired_work(_request(confirmed="1"), KeyEncryptionKey.objects.filter(pk=picked.pk))

    picked.refresh_from_db()
    other.refresh_from_db()
    assert wired.deleted == [_PREFIX + "team1"]
    assert picked.status == lifecycle.STATUS_DELETED
    assert other.status == lifecycle.STATUS_DELETION_SCHEDULED


@pytest.mark.django_db
def test_kek_action_leaves_data_encryption_keys_alone(wired):
    dek = _scheduled_dek("team1")
    kek = _scheduled_kek("team1")
    ma = KeyEncryptionKeyAdmin(KeyEncryptionKey, django_admin.site)

    ma.purge_expired_work(_request(confirmed="1"), KeyEncryptionKey.objects.filter(pk=kek.pk))

    dek.refresh_from_db()
    assert bytes(dek.encrypted_keyset) == b"wrapped-dek"


@pytest.mark.django_db
def test_kek_action_refuses_select_all_across_pages(wired):
    """A destroyed KEK cannot be restored from a backup, so an unbounded sweep is
    not two clicks away — it belongs to the scheduled command."""
    kek = _scheduled_kek("team1")
    ma = KeyEncryptionKeyAdmin(KeyEncryptionKey, django_admin.site)
    request = _request(select_across="1", confirmed="1")

    ma.purge_expired_work(request, KeyEncryptionKey.objects.all())

    kek.refresh_from_db()
    assert wired.deleted == []
    assert kek.status == lifecycle.STATUS_DELETION_SCHEDULED
    assert "individually" in request._messages.sent[0][1]


@pytest.mark.django_db
def test_dek_action_allows_select_all_across_pages(wired):
    """The recoverable half stays a sweep: a shred can be undone from a database
    restore, so it does not need the same friction."""
    dek = _scheduled_dek("team1")
    ma = DataEncryptionKeyAdmin(DataEncryptionKey, django_admin.site)

    ma.purge_expired_work(_request(select_across="1", confirmed="1"), DataEncryptionKey.objects.all())

    dek.refresh_from_db()
    assert bytes(dek.encrypted_keyset) == b""


@pytest.mark.django_db
def test_unexpired_selection_is_left_alone(wired):
    """The window decides; the selection only narrows."""
    row = DataEncryptionKey.objects.create(
        key_set="default",
        silo_uid="team1",
        purpose=DataEncryptionKey.PURPOSE_FIELD,
        silo_label="team",
        encrypted_keyset=b"wrapped-dek",
        kek=make_kek(_PREFIX + "team1", _PROVIDER),
    )
    row.record_event(
        lifecycle.EVENT_DELETION_SCHEDULED,
        trigger=lifecycle.TRIGGER_DIRECT,
        undeletable_until=timezone.now() + datetime.timedelta(days=7),
    )
    ma = DataEncryptionKeyAdmin(DataEncryptionKey, django_admin.site)

    ma.purge_expired_work(_request(confirmed="1"), DataEncryptionKey.objects.all())

    row.refresh_from_db()
    assert bytes(row.encrypted_keyset) == b"wrapped-dek"


def _active_kek(name):
    return make_kek_row(
        key_store=_PROVIDER,
        kek_resource_name=_PREFIX + name,
    )


@pytest.mark.django_db
def test_tombstones_do_not_count_toward_blast_radius(wired):
    kek = _active_kek("team1")
    DataEncryptionKey.objects.create(
        key_set="default",
        silo_uid="team1",
        purpose=DataEncryptionKey.PURPOSE_FIELD,
        silo_label="team",
        encrypted_keyset=b"",  # already shredded
        status=lifecycle.STATUS_DELETED,
        kek=make_kek(kek.kek_resource_name, _PROVIDER),
    )
    ma = KeyEncryptionKeyAdmin(KeyEncryptionKey, django_admin.site)

    response = ma.schedule_deletion(_request(), KeyEncryptionKey.objects.filter(pk=kek.pk))

    assert response.context_data["in_use_count"] == 0


@pytest.mark.django_db
def test_non_active_rows_are_reported_not_dropped(wired):
    """A selection that schedules nothing says why, on the same screen shape as
    every other refusal — rather than dropping the rows in silence."""
    kek = _scheduled_kek("team1")  # already deletion_scheduled
    ma = KeyEncryptionKeyAdmin(KeyEncryptionKey, django_admin.site)

    request = _request(confirmed="1")

    result = ma.schedule_deletion(request, KeyEncryptionKey.objects.filter(pk=kek.pk))

    # Nothing to confirm, so no screen — reported on the changelist instead.
    assert result is None
    assert "not active" in request._messages.sent[0][1]


# ---------------------------------------------------------------------------
# Confirmation screens
#
# Both purges are irreversible, so neither runs on the first click. The screen is
# built from a dry run of the same call the confirm will make, so what it lists
# is the decision the real run makes rather than a second implementation of it.
# ---------------------------------------------------------------------------


@pytest.mark.django_db
def test_dek_action_confirms_before_shredding(wired):
    dek = _scheduled_dek("team1")
    ma = DataEncryptionKeyAdmin(DataEncryptionKey, django_admin.site)

    response = ma.purge_expired_work(_request(), DataEncryptionKey.objects.filter(pk=dek.pk))

    dek.refresh_from_db()
    assert bytes(dek.encrypted_keyset) == b"wrapped-dek"  # nothing destroyed yet
    assert response.context_data["total_count"] == 1
    assert list(response.context_data["rows"]) == [dek]
    assert b"Yes, destroy these keys" in response.render().content


@pytest.mark.django_db
def test_dek_confirm_omits_rows_still_inside_the_window(wired):
    expired = _scheduled_dek("team1")
    unexpired = DataEncryptionKey.objects.create(
        key_set="default",
        silo_uid="team2",
        purpose=DataEncryptionKey.PURPOSE_FIELD,
        silo_label="team",
        encrypted_keyset=b"wrapped-dek",
        kek=make_kek(_PREFIX + "team2", _PROVIDER),
    )
    unexpired.record_event(
        lifecycle.EVENT_DELETION_SCHEDULED,
        trigger=lifecycle.TRIGGER_DIRECT,
        undeletable_until=timezone.now() + datetime.timedelta(days=7),
    )
    ma = DataEncryptionKeyAdmin(DataEncryptionKey, django_admin.site)

    response = ma.purge_expired_work(_request(), DataEncryptionKey.objects.all())

    assert list(response.context_data["rows"]) == [expired]
    assert response.context_data["unexpired_count"] == 1


@pytest.mark.django_db
def test_kek_action_confirms_before_deleting(wired):
    kek = _scheduled_kek("team1")
    ma = KeyEncryptionKeyAdmin(KeyEncryptionKey, django_admin.site)

    response = ma.purge_expired_work(_request(), KeyEncryptionKey.objects.filter(pk=kek.pk))

    kek.refresh_from_db()
    assert wired.deleted == []  # provider never called on the preview
    assert kek.status == lifecycle.STATUS_DELETION_SCHEDULED
    assert response.context_data["delete_count"] == 1
    assert b"Yes, destroy these keys" in response.render().content


@pytest.mark.django_db
def test_kek_confirm_reports_the_gate_decision(wired):
    """A key a gate will refuse says so, instead of promising a destruction."""
    kek = _scheduled_kek("team1")
    kek.disposition = KeyEncryptionKey.DISPOSITION_SHARED  # gate 1 refuses
    kek.save(update_fields=["disposition"])
    ma = KeyEncryptionKeyAdmin(KeyEncryptionKey, django_admin.site)

    request = _request()

    result = ma.purge_expired_work(request, KeyEncryptionKey.objects.filter(pk=kek.pk))

    # Nothing would be destroyed, so the reason is reported without a screen —
    # and it names the gate rather than saying only "retained".
    assert result is None
    assert "shared or operator-supplied key" in request._messages.sent[0][1]


@pytest.mark.django_db
def test_kek_confirm_counts_silos_that_would_lose_data(wired):
    """The blast radius: keysets this key still wraps, each one a silo's data."""
    _scheduled_dek("team1")
    kek = _scheduled_kek("team1")
    ma = KeyEncryptionKeyAdmin(KeyEncryptionKey, django_admin.site)

    response = ma.purge_expired_work(_request(), KeyEncryptionKey.objects.filter(pk=kek.pk))

    assert [in_use for _row, _verb, _reason, in_use in response.context_data["rows"]] == [1]


@pytest.mark.django_db
def test_kek_confirm_names_the_in_use_gate(wired):
    """The case that sent an operator to the source: a key still wrapping a live
    keyset reads as in-use, not as an unexplained refusal."""
    _scheduled_dek("team1").record_event(lifecycle.EVENT_RESTORED, trigger=lifecycle.TRIGGER_DIRECT)  # active again
    kek = _scheduled_kek("team1")
    ma = KeyEncryptionKeyAdmin(KeyEncryptionKey, django_admin.site)

    request = _request()

    result = ma.purge_expired_work(request, KeyEncryptionKey.objects.filter(pk=kek.pk))

    assert result is None
    assert "still referenced by another key record" in request._messages.sent[0][1]


# ---------------------------------------------------------------------------
# KEY_DELETION_CAN_RENDER_DATA_INACCESSIBLE
#
# Destroying a key that live data still depends on is refused by default, on
# both halves of a deletion, and refused at *scheduling* rather than after a
# window has been waited out. The setting is the operator saying they mean it.
# ---------------------------------------------------------------------------


def _allow_data_loss(value=True):
    cfg = {**settings.ENCRYPTION, "KEY_DELETION_CAN_RENDER_DATA_INACCESSIBLE": value}
    return override_settings(ENCRYPTION=cfg)


def _live_dek(uid, kek):
    return DataEncryptionKey.objects.create(
        key_set="default",
        silo_uid=uid,
        purpose=DataEncryptionKey.PURPOSE_FIELD,
        silo_label="team",
        encrypted_keyset=b"wrapped-dek",
        kek=make_kek(kek.kek_resource_name, _PROVIDER),
    )


@pytest.mark.django_db
def test_scheduling_an_in_use_key_is_refused_up_front(wired):
    """Refused now, not after the window — nothing is left waiting on a promise
    the purge would never keep.

    Refused the same way every gate in this admin refuses: a screen naming the
    keys and what to do, with no button that would go through.
    """
    kek = _active_kek("team1")
    _live_dek("team1", kek)
    ma = KeyEncryptionKeyAdmin(KeyEncryptionKey, django_admin.site)

    request = _request(confirmed="1")

    result = ma.schedule_deletion(request, KeyEncryptionKey.objects.filter(pk=kek.pk))

    kek.refresh_from_db()
    assert kek.status == lifecycle.STATUS_ACTIVE  # untouched, even on a confirmed POST
    assert result is None  # nothing schedulable, so nothing to confirm
    message = request._messages.sent[0][1]
    assert "KEY_DELETION_CAN_RENDER_DATA_INACCESSIBLE" in message
    assert kek.kek_resource_name in message


@pytest.mark.django_db
def test_scheduling_a_key_nothing_depends_on_still_works(wired):
    """The gate is about live data, not about being an orphan."""
    kek = _active_kek("team1")
    ma = KeyEncryptionKeyAdmin(KeyEncryptionKey, django_admin.site)

    ma.schedule_deletion(_request(confirmed="1"), KeyEncryptionKey.objects.filter(pk=kek.pk))

    kek.refresh_from_db()
    assert kek.status == lifecycle.STATUS_DELETION_SCHEDULED
    assert kek.undeletable_until is not None


@pytest.mark.django_db
def test_the_setting_permits_scheduling_and_destroying_an_in_use_key(wired):
    """The erasure case: render live data unreadable while its rows remain."""
    kek = _active_kek("team1")
    dek = _live_dek("team1", kek)
    ma = KeyEncryptionKeyAdmin(KeyEncryptionKey, django_admin.site)

    with _allow_data_loss():
        ma.schedule_deletion(_request(confirmed="1"), KeyEncryptionKey.objects.filter(pk=kek.pk))
        kek.refresh_from_db()
        assert kek.status == lifecycle.STATUS_DELETION_SCHEDULED
        kek.undeletable_until = _PAST
        kek.save(update_fields=["undeletable_until"])

        ma.purge_expired_work(_request(confirmed="1"), KeyEncryptionKey.objects.filter(pk=kek.pk))

    kek.refresh_from_db()
    assert wired.deleted == [kek.kek_resource_name]
    assert kek.status == lifecycle.STATUS_DELETED
    # Deliberately untouched: the DEK row keeps its keyset, now unusable.
    dek.refresh_from_db()
    assert bytes(dek.encrypted_keyset) == b"wrapped-dek"


@pytest.mark.django_db
def test_schedule_confirmation_still_reports_the_blast_radius(wired):
    """With the setting on, the operator still sees what they are about to lose."""
    kek = _active_kek("team1")
    _live_dek("team1", kek)
    _live_dek("team2", kek)
    ma = KeyEncryptionKeyAdmin(KeyEncryptionKey, django_admin.site)

    with _allow_data_loss():
        response = ma.schedule_deletion(_request(), KeyEncryptionKey.objects.filter(pk=kek.pk))

    kek.refresh_from_db()
    assert kek.status == lifecycle.STATUS_ACTIVE  # unconfirmed: numbers first
    assert response.context_data["in_use_count"] == 1
    assert response.context_data["rows"][0][1] == 2  # two silos still hold keysets


def _test_dek(kek):
    return DataEncryptionKey.objects.create(
        key_set="default",
        silo_uid="enctestfieldkey",
        purpose=DataEncryptionKey.PURPOSE_TEST,
        silo_label="admin_test_console",
        encrypted_keyset=b"wrapped-dek",
        kek=make_kek(kek.kek_resource_name, _PROVIDER),
    )


@pytest.mark.django_db
@pytest.mark.parametrize("allow", [False, True])
def test_a_test_console_kek_is_skipped_with_its_own_message(wired, allow):
    """The console deletes its own keys, so the schedule action points there
    rather than at the in-use gate, whatever the settings say."""
    kek = _active_kek("enctestkey")
    _test_dek(kek)
    ma = KeyEncryptionKeyAdmin(KeyEncryptionKey, django_admin.site)
    request = _request(confirmed="1")

    with _allow_data_loss(allow):
        result = ma.schedule_deletion(request, KeyEncryptionKey.objects.filter(pk=kek.pk))

    kek.refresh_from_db()
    assert result is None
    assert kek.status == lifecycle.STATUS_ACTIVE
    assert [text for _level, text in request._messages.sent] == [
        "Skipped 1 test console key(s), which have their own deletion path."
    ]


@pytest.mark.django_db
def test_a_kek_a_real_silo_also_uses_is_not_a_test_console_kek(wired):
    """The console borrowing a real silo's key does not make it the console's."""
    kek = _active_kek("shared")
    _test_dek(kek)
    _live_dek("team1", kek)
    ma = KeyEncryptionKeyAdmin(KeyEncryptionKey, django_admin.site)
    request = _request(confirmed="1")

    ma.schedule_deletion(request, KeyEncryptionKey.objects.filter(pk=kek.pk))

    assert "KEY_DELETION_CAN_RENDER_DATA_INACCESSIBLE" in request._messages.sent[0][1]


@pytest.mark.django_db
def test_the_recording_actions_take_an_env_store_key(wired):
    """An env store's key is settings material an operator can remove and restore."""
    kek = make_kek_row(key_store="login", kek_resource_name="shared")
    ma = KeyEncryptionKeyAdmin(KeyEncryptionKey, django_admin.site)
    selected = KeyEncryptionKey.objects.filter(pk=kek.pk)

    for action, status in (
        (ma.record_deleted_in_kms, lifecycle.STATUS_DELETED),
        (ma.record_restored_in_kms, lifecycle.STATUS_ACTIVE),
        (ma.record_requested_in_kms, lifecycle.STATUS_DELETION_REQUESTED),
    ):
        action(_request(), selected)
        kek.refresh_from_db()
        assert kek.status == status


@pytest.mark.django_db
def test_the_confirmation_screen_counts_test_console_keks_apart(wired):
    test_kek = _active_kek("enctestkey")
    _test_dek(test_kek)
    other = _active_kek("team1")
    ma = KeyEncryptionKeyAdmin(KeyEncryptionKey, django_admin.site)

    response = ma.schedule_deletion(_request(), KeyEncryptionKey.objects.filter(pk__in=[test_kek.pk, other.pk]))

    assert response.context_data["test_count"] == 1
    assert response.context_data["inactive_count"] == 0
    assert [row.pk for row, _in_use in response.context_data["rows"]] == [other.pk]


@pytest.mark.django_db
def test_purge_confirm_separates_unscheduled_from_unexpired(wired):
    """Two different states, two different remedies — and neither is 'in use'.

    Selecting an active key for the purge must not report it as waiting out a
    restore window it was never put into.
    """
    active = _active_kek("team1")
    _live_dek("team1", active)  # gives it a non-zero blast radius too
    scheduled_open = _active_kek("team2")
    scheduled_open.record_event(
        lifecycle.EVENT_DELETION_SCHEDULED,
        trigger=lifecycle.TRIGGER_DIRECT,
        undeletable_until=timezone.now() + datetime.timedelta(days=7),
    )
    ma = KeyEncryptionKeyAdmin(KeyEncryptionKey, django_admin.site)

    request = _request()

    result = ma.purge_expired_work(request, KeyEncryptionKey.objects.all())

    # Two states, two messages — neither collapsed into the other, and no screen
    # because nothing would be destroyed.
    assert result is None
    sent = " | ".join(message for _level, message in request._messages.sent)
    assert "not scheduled for deletion" in sent
    assert "still inside their restore window" in sent


@pytest.mark.django_db
def test_purge_acts_on_the_eligible_subset_of_a_mixed_selection(wired):
    """One selection, four states: destroy the eligible, report the rest, touch nothing else."""
    eligible = _scheduled_kek("team1")
    unscheduled = _active_kek("team2")
    open_window = _active_kek("team3")
    open_window.record_event(
        lifecycle.EVENT_DELETION_SCHEDULED,
        trigger=lifecycle.TRIGGER_DIRECT,
        undeletable_until=timezone.now() + datetime.timedelta(days=7),
    )
    ma = KeyEncryptionKeyAdmin(KeyEncryptionKey, django_admin.site)

    preview = ma.purge_expired_work(_request(), KeyEncryptionKey.objects.all())
    assert preview.context_data["delete_count"] == 1
    assert preview.context_data["unscheduled_count"] == 1
    assert preview.context_data["unexpired_count"] == 1
    # The whole selection is carried forward: the window and the gates decide,
    # so nothing has to be dropped from the form to keep the confirm honest.
    assert len(preview.context_data["selected"]) == 3

    ma.purge_expired_work(_request(confirmed="1"), KeyEncryptionKey.objects.all())

    for row in (eligible, unscheduled, open_window):
        row.refresh_from_db()
    assert wired.deleted == [eligible.kek_resource_name]
    assert eligible.status == lifecycle.STATUS_DELETED
    assert unscheduled.status == lifecycle.STATUS_ACTIVE
    assert open_window.status == lifecycle.STATUS_DELETION_SCHEDULED


@pytest.mark.django_db
def test_the_dek_purge_screen_names_the_provider_and_key(wired):
    """The confirmation has to say which KMS key the rows depend on.

    Both values live on the related key encryption key now, so a template still
    reading them off the data key renders blank — and a blank column on a
    destruction screen reads as "no key", which is the opposite of the truth.
    """
    kek = _active_kek("team1")
    dek = _live_dek("team1", kek)
    dek.record_event(lifecycle.EVENT_DELETION_SCHEDULED, trigger=lifecycle.TRIGGER_DIRECT, undeletable_until=_PAST)
    ma = DataEncryptionKeyAdmin(DataEncryptionKey, django_admin.site)

    response = ma.purge_expired_work(_request(), DataEncryptionKey.objects.filter(pk=dek.pk))
    response.render()
    html = response.content.decode()

    assert kek.key_store in html
    assert kek.kek_resource_name in html


# ---------------------------------------------------------------------------
# Recording a gate refusal.
#
# A refusal is a policy outcome the operator asked for and the deployment
# declined, so it belongs in the ledger with an actor and a reason. Both paths
# to it are covered here: the selection where something is also destroyed, and
# the selection where nothing is — the latter being the only path a deployment
# whose provisioner cannot delete ever takes.
# ---------------------------------------------------------------------------


class _CannotDeleteProvisioner(AbstractKekProvisioner):
    """The default posture: NullKekProvisioner and any not-yet-fanned-out provider."""

    def __init__(self):
        super().__init__({})

    def ensure_kek(self, kek_resource_name, silo_ref):  # pragma: no cover
        pass


@pytest.fixture
def cannot_delete(monkeypatch, configured_owner_prefix):
    monkeypatch.setattr("encryption_suite.registry.get_kek_provisioner", lambda name=None: _CannotDeleteProvisioner())
    monkeypatch.setattr("encryption_suite.registry.get_kms_adapter", lambda name=None: _FakeAdapter())
    configured_owner_prefix(_PREFIX)


def _shared_kek(uid):
    row = make_kek_row(
        key_store=_PROVIDER,
        kek_resource_name=_PREFIX + uid,
        disposition=KeyEncryptionKey.DISPOSITION_SHARED,
        owner_prefix=_PREFIX,
    )
    row.record_event(
        lifecycle.EVENT_DELETION_SCHEDULED,
        trigger=lifecycle.TRIGGER_DIRECT,
        undeletable_until=_PAST,
        silo_ref=SiloRef("default", uid),
    )
    return row


@pytest.mark.django_db
def test_a_selection_that_destroys_nothing_still_records_the_refusal(cannot_delete):
    """No key is deletable, so no confirmation screen appears — and this request is
    therefore the terminal outcome, not a preview the operator can back out of."""
    kek = _scheduled_kek("team1")  # gate 2: the provisioner cannot delete
    ma = KeyEncryptionKeyAdmin(KeyEncryptionKey, django_admin.site)

    result = ma.purge_expired_work(_request(), KeyEncryptionKey.objects.filter(pk=kek.pk))

    kek.refresh_from_db()
    assert result is None  # still no screen
    assert kek.status == lifecycle.STATUS_RETAINED
    event = kek.events.get(event=lifecycle.EVENT_DELETION_FAILED)
    assert event.reason == "provisioner_cannot_delete"
    assert event.user_id == make_user("alice").pk  # who attempted it


@pytest.mark.django_db
def test_the_refusal_takes_the_key_off_the_scheduled_queue(cannot_delete):
    """Otherwise every later purge re-previews a key that can never be destroyed."""
    kek = _scheduled_kek("team1")
    ma = KeyEncryptionKeyAdmin(KeyEncryptionKey, django_admin.site)

    ma.purge_expired_work(_request(), KeyEncryptionKey.objects.filter(pk=kek.pk))
    ma.purge_expired_work(_request(), KeyEncryptionKey.objects.filter(pk=kek.pk))

    kek.refresh_from_db()
    # One refusal recorded, not one per purge run.
    assert kek.events.filter(event=lifecycle.EVENT_DELETION_FAILED).count() == 1


@pytest.mark.django_db
def test_a_mixed_selection_records_the_refusal_alongside_the_deletion(wired):
    """The other path: one deletable key renders the screen, and the refused key
    riding along in the same selection is decided too."""
    good = _scheduled_kek("team1")
    shared = _shared_kek("shared")
    ma = KeyEncryptionKeyAdmin(KeyEncryptionKey, django_admin.site)

    ma.purge_expired_work(_request(confirmed="1"), KeyEncryptionKey.objects.filter(pk__in=[good.pk, shared.pk]))

    good.refresh_from_db()
    shared.refresh_from_db()
    assert good.status == lifecycle.STATUS_DELETED
    assert shared.status == lifecycle.STATUS_RETAINED
    assert shared.events.get(event=lifecycle.EVENT_DELETION_FAILED).reason == "shared_or_opaque_disposition"


@pytest.mark.django_db
def test_a_retained_key_can_be_restored_to_active(cannot_delete):
    """Without this, a refused key is a dead end: the schedule action takes only
    active keys, so it could be neither re-scheduled nor restored."""
    kek = _scheduled_kek("team1")
    ma = KeyEncryptionKeyAdmin(KeyEncryptionKey, django_admin.site)
    ma.purge_expired_work(_request(), KeyEncryptionKey.objects.filter(pk=kek.pk))

    ma.restore_scheduled(_request(), KeyEncryptionKey.objects.filter(pk=kek.pk))

    kek.refresh_from_db()
    assert kek.status == lifecycle.STATUS_ACTIVE
    assert kek.undeletable_until is None


@pytest.mark.django_db
def test_a_restored_key_can_be_scheduled_again(cannot_delete):
    """The exit has to lead somewhere: back to active means back to schedulable."""
    kek = _scheduled_kek("team1")
    ma = KeyEncryptionKeyAdmin(KeyEncryptionKey, django_admin.site)
    ma.purge_expired_work(_request(), KeyEncryptionKey.objects.filter(pk=kek.pk))
    ma.restore_scheduled(_request(), KeyEncryptionKey.objects.filter(pk=kek.pk))

    ma.schedule_deletion(_request(confirmed="1"), KeyEncryptionKey.objects.filter(pk=kek.pk))

    kek.refresh_from_db()
    assert kek.status == lifecycle.STATUS_DELETION_SCHEDULED


# ---------------------------------------------------------------------------
# Refused *scheduling*.
#
# The allowed case has always been recorded — schedule_dek_deletion writes a
# deletion_scheduled event with the actor. These cover the refused case, which
# left no trace of who tried to make a live silo's data unreadable.
# ---------------------------------------------------------------------------


@pytest.fixture
def silo_is_live(monkeypatch):
    """The silo still exists, so scheduling its key is refused."""
    from encryption_suite import deletion as deletion_module

    monkeypatch.setattr(deletion_module, "dek_retain_reason", lambda uid: "silo_still_exists")


@pytest.mark.django_db
def test_a_refused_dek_scheduling_is_recorded(wired, silo_is_live):
    kek = _active_kek("team1")
    dek = _live_dek("team1", kek)
    ma = DataEncryptionKeyAdmin(DataEncryptionKey, django_admin.site)

    ma.schedule_dek_deletion(_request(), DataEncryptionKey.objects.filter(pk=dek.pk))

    dek.refresh_from_db()
    event = dek.events.get(event=lifecycle.EVENT_DELETION_SCHEDULE_FAILED)
    assert event.reason == "silo_still_exists"
    assert event.user_id == make_user("alice").pk
    # Nothing about the key changed, so it stays schedulable.
    assert dek.status == lifecycle.STATUS_ACTIVE


@pytest.mark.django_db
def test_a_refused_dek_scheduling_logs_one_audit_line(wired, silo_is_live, caplog):
    import logging

    kek = _active_kek("team1")
    dek = _live_dek("team1", kek)
    ma = DataEncryptionKeyAdmin(DataEncryptionKey, django_admin.site)

    with caplog.at_level(logging.WARNING, logger="encryption_suite.deletion"):
        ma.schedule_dek_deletion(_request(), DataEncryptionKey.objects.filter(pk=dek.pk))

    lines = [r.getMessage() for r in caplog.records if "event=deletion_schedule_failed" in r.getMessage()]
    assert len(lines) == 1
    assert f"user_id={make_user('alice').pk}" in lines[0]
    assert 'user_name="alice"' in lines[0]
    assert "reasons=silo_still_exists" in lines[0]


@pytest.mark.django_db
def test_a_partly_blocked_selection_records_only_the_blocked_rows(wired, monkeypatch):
    """A selection that is only partly refused still records the refused half."""
    from encryption_suite import deletion as deletion_module

    kek = _active_kek("team1")
    blocked_dek = _live_dek("team1", kek)
    free_dek = _live_dek("team2", kek)
    monkeypatch.setattr(
        deletion_module,
        "dek_retain_reason",
        lambda ref: "silo_still_exists" if ref.uid == "team1" else None,
    )
    ma = DataEncryptionKeyAdmin(DataEncryptionKey, django_admin.site)

    ma.schedule_dek_deletion(_request(), DataEncryptionKey.objects.filter(pk__in=[blocked_dek.pk, free_dek.pk]))

    assert blocked_dek.events.filter(event=lifecycle.EVENT_DELETION_SCHEDULE_FAILED).count() == 1
    assert not free_dek.events.filter(event=lifecycle.EVENT_DELETION_SCHEDULE_FAILED).exists()


@pytest.mark.django_db
def test_an_in_use_refusal_leaves_the_key_scheduled_for_retry(wired):
    """Transient gate: live keysets still reference the key, so the next run
    retries rather than parking it in a terminal state."""
    kek = _scheduled_kek("team1")
    _live_dek("team1", kek)  # un-shredded, so the key is still in use
    ma = KeyEncryptionKeyAdmin(KeyEncryptionKey, django_admin.site)

    ma.purge_expired_work(_request(confirmed="1"), KeyEncryptionKey.objects.filter(pk=kek.pk))

    kek.refresh_from_db()
    assert kek.status == lifecycle.STATUS_DELETION_SCHEDULED
    assert kek.events.get(event=lifecycle.EVENT_DELETION_FAILED).reason == "in_use_by_other_silo"
    assert wired.deleted == []


# ---------------------------------------------------------------------------
# The snapshot must not contradict the strategy.
#
# schedule_kek_deletion once asserted silo-exclusive, from when it only ever ran
# on confirmed reconcile orphans. The changelist now schedules any active key, so
# a shared key was recorded silo-exclusive and the detail page disagreed with the
# refusal it produced.
# ---------------------------------------------------------------------------


@pytest.mark.django_db
def test_scheduling_under_a_shared_strategy_snapshots_shared(wired, configured_owner_prefix):
    configured_owner_prefix(None, disposition=KeyEncryptionKey.DISPOSITION_SHARED)
    kek = _active_kek("shared")
    ma = KeyEncryptionKeyAdmin(KeyEncryptionKey, django_admin.site)

    ma.schedule_deletion(_request(confirmed="1"), KeyEncryptionKey.objects.filter(pk=kek.pk))

    kek.refresh_from_db()
    assert kek.status == lifecycle.STATUS_DELETION_SCHEDULED
    assert kek.disposition == KeyEncryptionKey.DISPOSITION_SHARED
    assert kek.owner_prefix == ""


@pytest.mark.django_db
def test_an_orphan_snapshot_cannot_grant_what_the_strategy_refuses(wired, configured_owner_prefix):
    """The case the snapshot is load-bearing for: no data key names this row, so
    the deletion falls back to it rather than re-deriving from a silo."""
    configured_owner_prefix(None, disposition=KeyEncryptionKey.DISPOSITION_SHARED)
    kek = _active_kek("shared")
    ma = KeyEncryptionKeyAdmin(KeyEncryptionKey, django_admin.site)
    ma.schedule_deletion(_request(confirmed="1"), KeyEncryptionKey.objects.filter(pk=kek.pk))
    kek.refresh_from_db()
    kek.undeletable_until = _PAST
    kek.save(update_fields=["undeletable_until"])
    assert not kek.data_keys.exists()

    ma.purge_expired_work(_request(confirmed="1"), KeyEncryptionKey.objects.filter(pk=kek.pk))

    kek.refresh_from_db()
    assert kek.status == lifecycle.STATUS_RETAINED
    # Refused by the gate that owns the question, not by the ownership gate
    # happening to catch it.
    assert kek.events.get(event=lifecycle.EVENT_DELETION_FAILED).reason == "shared_or_opaque_disposition"


@pytest.mark.django_db
def test_scheduling_under_a_per_silo_strategy_still_snapshots_exclusive(wired):
    kek = _active_kek("team1")
    ma = KeyEncryptionKeyAdmin(KeyEncryptionKey, django_admin.site)

    ma.schedule_deletion(_request(confirmed="1"), KeyEncryptionKey.objects.filter(pk=kek.pk))

    kek.refresh_from_db()
    assert kek.disposition == KeyEncryptionKey.DISPOSITION_SILO_EXCLUSIVE
    assert kek.owner_prefix == _PREFIX
