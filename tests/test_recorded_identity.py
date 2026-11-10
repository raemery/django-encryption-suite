"""The OS user and address a record points at: one row per value, in one form.

``KEY_LIFECYCLE_EVENTS`` lists each value plaintext or encrypted. A record finds
the row holding its value in the listed form, or adds one, and never converts a
row between the two.
"""

from __future__ import annotations

import logging

import pytest
from django.db import IntegrityError, transaction
from django.test import RequestFactory

from encryption_suite import lifecycle
from encryption_suite._internal import raw_cursor_fetch
from encryption_suite.admin_lifecycle import KeyLifecycleEventAdmin
from encryption_suite.engine import EncryptionEngine, is_silo_value
from encryption_suite.models import (
    KeyLifecycleEvent,
    RecordedIPAddress,
    RecordedOSUser,
    apply_event,
    recorded_identity,
)
from tests.factories import make_dek, make_user

ADDRESS = "127.0.0.1"
OS_USER = "deploy (uid 1000)"
PLAIN = ["ip_address", "os_user"]
ENCRYPTED = ["encrypted_ip_address", "encrypted_os_user"]


def _record(settings, items):
    settings.ENCRYPTION = {**settings.ENCRYPTION, "USER_IDENTITY": {"KEY_LIFECYCLE_EVENTS": list(items)}}


def _act(dek, **identity):
    return apply_event(dek, lifecycle.EVENT_REENCRYPTED, trigger=lifecycle.TRIGGER_AUTOMATED, **identity)


def _replace_system_kek(settings):
    """Swap ENV_KEY_STORES for a version that never wrapped anything, so the system silo's keys cannot unwrap."""
    import base64

    from encryption_suite import registry

    settings.ENCRYPTION = {
        **settings.ENCRYPTION,
        "ENV_KEY_STORES": {"login": {"KEKS": {9: base64.b64encode(b"	" * 32).decode()}}},
    }
    registry.reset()
    EncryptionEngine.invalidate_cache()


# --- Finding or creating a row ---------------------------------------------


@pytest.mark.django_db
def test_a_plaintext_value_is_stored_in_the_plaintext_column(settings):
    _record(settings, PLAIN)

    _user, os_user, ip = recorded_identity(os_login_user=OS_USER, user_ip=ADDRESS)

    assert (os_user.os_user, os_user.encrypted_os_user) == (OS_USER, None)
    assert (ip.ip_address, ip.encrypted_ip_address) == (ADDRESS, None)


@pytest.mark.django_db(transaction=True)
def test_an_encrypted_value_reaches_its_column_encrypted(settings):
    _record(settings, ENCRYPTED)

    _user, os_user, ip = recorded_identity(os_login_user=OS_USER, user_ip=ADDRESS)

    assert (os_user.os_user, os_user.value) == (None, OS_USER)
    assert (ip.ip_address, ip.value) == (None, ADDRESS)
    (stored,) = raw_cursor_fetch(RecordedOSUser, os_user.pk, ["encrypted_os_user"])
    assert is_silo_value(stored) and "deploy" not in stored


@pytest.mark.django_db
@pytest.mark.parametrize("items", [PLAIN, ENCRYPTED])
def test_a_value_seen_again_in_the_same_form_reuses_its_row(settings, items):
    _record(settings, items)
    dek = make_dek()

    first = _act(dek, os_login_user=OS_USER, user_ip=ADDRESS)
    second = _act(dek, os_login_user=OS_USER, user_ip=ADDRESS)

    assert (first.os_user_id, first.ip_address_id) == (second.os_user_id, second.ip_address_id)
    assert (RecordedOSUser.objects.count(), RecordedIPAddress.objects.count()) == (1, 1)


@pytest.mark.django_db
def test_a_value_in_the_other_form_gets_a_row_of_its_own(settings):
    """A switch applies to later acts only: the earlier record keeps its row."""
    dek = make_dek()
    _record(settings, PLAIN)
    before = _act(dek, os_login_user=OS_USER, user_ip=ADDRESS)
    _record(settings, ENCRYPTED)
    after = _act(dek, os_login_user=OS_USER, user_ip=ADDRESS)

    assert before.os_user_id != after.os_user_id
    assert before.ip_address_id != after.ip_address_id
    before.os_user.refresh_from_db()
    assert (before.os_user.os_user, before.os_user.encrypted_os_user) == (OS_USER, None)


@pytest.mark.django_db
@pytest.mark.parametrize("items", [PLAIN, ENCRYPTED])
def test_a_duplicate_value_is_accepted_and_the_first_row_is_used(settings, items):
    """Nothing is unique: two acts seeing a new value at once may both insert it."""
    _record(settings, items)
    column = "os_user" if items is PLAIN else "encrypted_os_user"
    first = RecordedOSUser.objects.create(**{column: OS_USER})
    RecordedOSUser.objects.create(**{column: OS_USER})

    _user, os_user, _ip = recorded_identity(os_login_user=OS_USER)

    assert os_user.pk == first.pk


@pytest.mark.django_db
def test_an_address_is_matched_on_its_canonical_text(settings):
    _record(settings, ["encrypted_ip_address"])

    _u, _o, first = recorded_identity(user_ip="2001:0db8:0000::0001")
    _u, _o, second = recorded_identity(user_ip="2001:db8::1")

    assert first.pk == second.pk
    assert first.value == "2001:db8::1"


@pytest.mark.django_db
def test_an_address_that_does_not_parse_is_dropped(settings, caplog):
    _record(settings, PLAIN)

    with caplog.at_level(logging.WARNING, logger="encryption_suite.models"):
        _u, _o, ip = recorded_identity(user_ip="not-an-address")

    assert ip is None
    assert not RecordedIPAddress.objects.exists()
    assert "not a valid IP address" in caplog.text


@pytest.mark.django_db
def test_both_columns_cannot_be_set_on_one_row():
    with pytest.raises(IntegrityError), transaction.atomic():
        RecordedOSUser.objects.create(os_user=OS_USER, encrypted_os_user=OS_USER)


@pytest.mark.django_db
def test_unusable_system_keys_drop_the_value_not_the_act(settings, caplog):
    """An audit detail must never be what fails a key operation."""
    _record(settings, ["user_id", "encrypted_os_user", "ip_address"])
    # The system silo's keys exist, wrapped under a ENV_KEY_STORES version that is
    # then dropped: they are there and cannot be used.
    recorded_identity(os_login_user="someone else (uid 7)")
    _replace_system_kek(settings)
    alice = make_user("alice")

    with caplog.at_level(logging.WARNING, logger="encryption_suite.models"):
        event = _act(make_dek(), user=alice, os_login_user=OS_USER, user_ip=ADDRESS)

    event.refresh_from_db()
    assert event.user_id == alice.pk
    assert event.os_user_id is None
    assert event.ip_address.value == ADDRESS
    assert "item=encrypted_os_user" in caplog.text


# --- The admin -------------------------------------------------------------


def _admin():
    from django.contrib.admin.sites import AdminSite

    return KeyLifecycleEventAdmin(KeyLifecycleEvent, AdminSite())


def _search(term):
    request = RequestFactory().get("/", {"q": term})
    request.user = make_user("alice")
    admin = _admin()
    results, _dupes = admin.get_search_results(request, admin.get_queryset(request), term)
    return set(results.values_list("pk", flat=True))


@pytest.fixture
def one_event_per_form(settings):
    dek = make_dek()
    _record(settings, PLAIN)
    plain = _act(dek, os_login_user="deploy (uid 1000)", user_ip="127.0.0.1")
    _record(settings, ENCRYPTED)
    encrypted = _act(dek, os_login_user="ops → root (uid 0)", user_ip="192.0.2.1")
    return plain, encrypted


@pytest.mark.django_db
def test_the_columns_render_each_form_as_its_value(one_event_per_form):
    plain, encrypted = one_event_per_form
    admin = _admin()

    assert (admin.os_user_label(plain), admin.ip_address_label(plain)) == ("deploy (uid 1000)", "127.0.0.1")
    assert (admin.os_user_label(encrypted), admin.ip_address_label(encrypted)) == ("ops → root (uid 0)", "192.0.2.1")


@pytest.mark.django_db
def test_a_plaintext_row_renders_without_decrypting(one_event_per_form, monkeypatch):
    plain, _encrypted = one_event_per_form

    def _refuse(*args, **kwargs):
        raise AssertionError("a plaintext row was decrypted")

    monkeypatch.setattr(EncryptionEngine, "decrypt", _refuse)
    row = RecordedOSUser.objects.get(pk=plain.os_user_id)
    assert str(row) == "deploy (uid 1000)"


@pytest.mark.django_db
@pytest.mark.parametrize(
    ("term", "which"),
    [
        ("deploy", "plain"),
        ("ROOT", "encrypted"),
        ("uid", "both"),
        ("127.0.0.1", "plain"),
        ("192.0.2.1", "encrypted"),
        ("192.0.2", "neither"),
    ],
)
def test_search_finds_the_os_user_and_the_address_in_either_form(one_event_per_form, term, which):
    plain, encrypted = one_event_per_form
    expected = {
        "plain": {plain.pk},
        "encrypted": {encrypted.pk},
        "both": {plain.pk, encrypted.pk},
        "neither": set(),
    }[which]

    assert _search(term) == expected


@pytest.mark.django_db
def test_an_undecryptable_os_user_matches_nothing(one_event_per_form, settings):
    """Its fallback label must not answer for it."""
    _plain, _encrypted = one_event_per_form
    _replace_system_kek(settings)

    assert _search("root") == set()
