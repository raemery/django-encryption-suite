"""The schedule action's confirmation screen.

The action is deliberately two-step: the first POST renders a confirmation, and
only a POST carrying ``confirmed=1`` schedules anything.

A row whose silo still exists is refused outright unless
``KEY_DELETION_CAN_RENDER_DATA_INACCESSIBLE`` is on — the purge would refuse
it too, so refusing at scheduling saves waiting out a window to learn that. With
the setting on there is no gate, and the live-silo count on the screen is what
tells the operator about the outage they are about to cause.
"""

from __future__ import annotations

import pytest
from django.contrib.admin.sites import AdminSite
from django.contrib.auth.models import Group, User
from django.contrib.messages.storage.fallback import FallbackStorage
from django.test import RequestFactory

from encryption_suite import lifecycle
from encryption_suite.admin import DataEncryptionKeyAdmin
from encryption_suite.models import DataEncryptionKey, KeyLifecycleEvent
from tests.factories import make_kek, make_kek_row


@pytest.fixture
def model_admin():
    return DataEncryptionKeyAdmin(DataEncryptionKey, AdminSite())


@pytest.fixture
def post_request():
    def _build(**post):
        request = RequestFactory().post("/admin/", post)
        request.user = User(username="alice", is_staff=True, is_superuser=True)
        request.session = {}
        request._messages = FallbackStorage(request)
        return request

    return _build


def _make_row(silo_uid, purpose=DataEncryptionKey.PURPOSE_FIELD):
    return DataEncryptionKey.objects.create(
        key_set="default",
        silo_uid=silo_uid,
        purpose=purpose,
        silo_label="group",
        encrypted_keyset=b"x",
        kek=make_kek("local-test-kek", "local"),
    )


@pytest.mark.django_db
def test_first_post_confirms_and_schedules_nothing(model_admin, post_request):
    row = _make_row("group-1")

    response = model_admin.schedule_dek_deletion(post_request(), DataEncryptionKey.objects.all())

    assert response.status_code == 200
    row.refresh_from_db()
    assert row.status == lifecycle.STATUS_ACTIVE


@pytest.mark.django_db
def test_confirmed_post_schedules_the_rows(model_admin, post_request):
    row = _make_row("group-1")

    result = model_admin.schedule_dek_deletion(post_request(confirmed="1"), DataEncryptionKey.objects.all())

    assert result is None  # falls through to the changelist redirect
    row.refresh_from_db()
    assert row.status == lifecycle.STATUS_DELETION_SCHEDULED
    # Who asked is the ledger's to record, and test_dek_row_scheduling checks it
    # against a saved user. This screen's job is that the act happened at all.
    assert KeyLifecycleEvent.objects.filter(dek=row, event=lifecycle.EVENT_DELETION_SCHEDULED).exists()


@pytest.mark.django_db
def test_confirm_screen_counts_only_the_live_silos(model_admin, post_request, settings):
    # The GroupSiloAdapter enumerates auth Groups, so a row whose silo_uid has a
    # matching Group is live and one without is an orphan. The count only applies
    # where live rows are schedulable at all, which is what the setting permits.
    settings.ENCRYPTION = {**settings.ENCRYPTION, "KEY_DELETION_CAN_RENDER_DATA_INACCESSIBLE": True}
    live = Group.objects.create(name="live-team")
    _make_row(f"group-{live.pk}")
    _make_row("group-999999")  # no such group -> orphaned

    response = model_admin.schedule_dek_deletion(post_request(), DataEncryptionKey.objects.all())

    assert response.context_data["total_count"] == 2
    assert response.context_data["live_count"] == 1


@pytest.mark.django_db
def test_confirm_screen_carries_the_settings_values(model_admin, post_request, settings):
    settings.ENCRYPTION = {
        **settings.ENCRYPTION,
        "DEK_CACHE_TTL": 42,
        "KEY_DELETION_WINDOW_DAYS": 7,
        # The DEK_CACHE_TTL warning is about the outage scheduling causes for a
        # live silo, so it only appears where a live silo can be scheduled.
        "KEY_DELETION_CAN_RENDER_DATA_INACCESSIBLE": True,
    }
    live = Group.objects.create(name="live-team")
    _make_row(f"group-{live.pk}")

    response = model_admin.schedule_dek_deletion(post_request(), DataEncryptionKey.objects.all())

    # The screen names each setting and shows its live value, so an operator does
    # not have to go looking it up.
    assert response.context_data["cache_ttl"] == 42
    assert response.context_data["window_days"] == 7
    rendered = response.render().content.decode()
    assert "DEK_CACHE_TTL" in rendered
    assert "42" in rendered
    assert "KEY_DELETION_WINDOW_DAYS" in rendered


@pytest.mark.django_db
def test_test_keys_and_inactive_rows_are_excluded(model_admin, post_request):
    _make_row("group-1", purpose=DataEncryptionKey.PURPOSE_TEST)
    scheduled = _make_row("group-2")
    scheduled.status = lifecycle.STATUS_DELETION_SCHEDULED
    scheduled.save(update_fields=["status"])

    request = post_request(confirmed="1")

    result = model_admin.schedule_dek_deletion(request, DataEncryptionKey.objects.all())

    # Nothing eligible, so no confirmation screen — but each kind still gets its
    # own explanation, because one "skipped" count would not tell them apart.
    assert result is None
    assert (
        not DataEncryptionKey.objects.filter(purpose=DataEncryptionKey.PURPOSE_TEST)
        .exclude(status=lifecycle.STATUS_ACTIVE)
        .exists()
    )
    sent = " | ".join(m.message for m in request._messages)
    assert "test console" in sent
    assert "not active" in sent


@pytest.mark.django_db
def test_confirmed_schedule_leaves_keks_untouched(model_admin, post_request):
    kek = make_kek_row(key_store="local", kek_resource_name="local-test-kek")
    _make_row("group-1")

    model_admin.schedule_dek_deletion(post_request(confirmed="1"), DataEncryptionKey.objects.all())

    kek.refresh_from_db()
    assert kek.status == lifecycle.STATUS_ACTIVE


@pytest.mark.django_db
def test_a_live_silo_is_refused_with_the_reason(model_admin, post_request):
    """Nothing schedulable means no screen — the refusal lands on the changelist,
    naming the silo, the reason, and the setting that would permit it."""
    live = Group.objects.create(name="live-team")
    _make_row(f"group-{live.pk}")
    request = post_request()

    result = model_admin.schedule_dek_deletion(request, DataEncryptionKey.objects.all())

    assert result is None
    assert DataEncryptionKey.objects.get().status == lifecycle.STATUS_ACTIVE
    message = next(m.message for m in request._messages)
    assert f"group-{live.pk}" in message
    assert "the silo still exists" in message
    assert "KEY_DELETION_CAN_RENDER_DATA_INACCESSIBLE" in message


@pytest.mark.django_db
def test_a_confirmed_post_still_refuses_a_live_silo(model_admin, post_request):
    """The gate is re-checked on the confirming POST, not only on the preview."""
    live = Group.objects.create(name="live-team")
    _make_row(f"group-{live.pk}")

    model_admin.schedule_dek_deletion(post_request(confirmed="1"), DataEncryptionKey.objects.all())

    assert DataEncryptionKey.objects.get().status == lifecycle.STATUS_ACTIVE


@pytest.mark.django_db
def test_a_mixed_selection_schedules_only_what_passes(model_admin, post_request):
    live = Group.objects.create(name="live-team")
    _make_row(f"group-{live.pk}")
    _make_row("group-999999")

    response = model_admin.schedule_dek_deletion(post_request(), DataEncryptionKey.objects.all())

    assert response.context_data["total_count"] == 1
    assert len(response.context_data["blocked"]) == 1
    body = response.render().content
    assert b"Yes, schedule deletion" in body  # something is still actionable


@pytest.mark.django_db
def test_a_mixed_selection_completes_on_the_second_post(model_admin, post_request):
    """The blocked row must not deadlock the confirmation.

    The screen carries only the schedulable rows in its hidden inputs, so the
    confirming POST arrives with the blocked row already dropped — otherwise the
    gate would re-trigger and the operator could never schedule the good ones.
    """
    live = Group.objects.create(name="live-team")
    blocked_row = _make_row(f"group-{live.pk}")
    good_row = _make_row("group-999999")

    preview = model_admin.schedule_dek_deletion(post_request(), DataEncryptionKey.objects.all())
    carried = preview.context_data["selected"]
    assert carried == [str(good_row.pk)]  # the blocked row is not resubmitted

    model_admin.schedule_dek_deletion(
        post_request(confirmed="1"),
        DataEncryptionKey.objects.filter(pk__in=carried),
    )

    good_row.refresh_from_db()
    blocked_row.refresh_from_db()
    assert good_row.status == lifecycle.STATUS_DELETION_SCHEDULED
    assert blocked_row.status == lifecycle.STATUS_ACTIVE


@pytest.mark.django_db
def test_a_selection_of_every_kind_accounts_for_all_of_it(model_admin, post_request):
    """Five selected, three explanations, and the numbers add up.

    The screen is the only place these rows are mentioned, so anything it omits
    is a row the operator silently loses track of.
    """
    live = Group.objects.create(name="live-team")
    _make_row(f"group-{live.pk}")  # blocked: silo still exists
    _make_row("group-999999")  # schedulable: orphaned
    _make_row("group-888888", purpose=DataEncryptionKey.PURPOSE_FILE)  # schedulable
    _make_row("group-777777", purpose=DataEncryptionKey.PURPOSE_TEST)  # test console
    already = _make_row("group-666666")
    already.status = lifecycle.STATUS_DELETION_SCHEDULED
    already.save(update_fields=["status"])

    response = model_admin.schedule_dek_deletion(post_request(), DataEncryptionKey.objects.all())

    ctx = response.context_data
    assert ctx["total_count"] == 2
    assert len(ctx["blocked"]) == 1
    assert ctx["test_count"] == 1
    assert ctx["inactive_count"] == 1
    assert ctx["total_count"] + len(ctx["blocked"]) + ctx["test_count"] + ctx["inactive_count"] == 5


@pytest.mark.django_db
def test_a_screen_appears_only_when_something_passes(model_admin, post_request):
    """The rule the four actions share: a confirmation asks a question, so it is
    rendered when there is one — and skipped when the answer could only be no."""
    live = Group.objects.create(name="live-team")
    _make_row(f"group-{live.pk}")  # blocked
    _make_row("group-999999")  # schedulable

    response = model_admin.schedule_dek_deletion(post_request(), DataEncryptionKey.objects.all())

    # One passes, so the screen is worth showing — and it still reports the one
    # that does not, rather than dropping it silently.
    assert response.context_data["total_count"] == 1
    assert len(response.context_data["blocked"]) == 1
    assert b"Yes, schedule deletion" in response.render().content
