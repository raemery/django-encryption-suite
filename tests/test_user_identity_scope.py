"""Which acts record who did them, per ``USER_IDENTITY``.

``SCOPE`` decides whether an *ambient* identity — one resolved from the request
context rather than passed by the caller — reaches a row, and
``KEY_LIFECYCLE_EVENTS`` which items of it do. Getting either wrong is a real
fault: under-recording loses the audit trail, and over-recording names a
customer on a key the application provisioned while serving their request.
"""

from __future__ import annotations

import pytest
from django.contrib.auth.models import Group

from encryption_suite import lifecycle
from encryption_suite.models import KeyLifecycleEvent
from encryption_suite.registry import get_engine
from encryption_suite.user_context import override_current_user
from tests.factories import make_user


def _identity(settings, scope="privileged_acts", record=("user_id", "os_user")):
    settings.ENCRYPTION = {
        **settings.ENCRYPTION,
        "USER_IDENTITY": {"SCOPE": scope, "KEY_LIFECYCLE_EVENTS": list(record)},
    }


def _uid(silo):
    return get_engine().silo_adapter.get_silo_uid(silo)


def _created_event(silo):
    return KeyLifecycleEvent.objects.select_related("os_user", "ip_address").get(
        silo_uid=_uid(silo), event=lifecycle.EVENT_CREATED, dek__isnull=False
    )


def _address(event):
    return event.ip_address.value if event.ip_address_id else None


@pytest.mark.django_db
def test_ambient_provisioning_records_the_user_under_all_acts(settings):
    _identity(settings, "all_acts")
    bob = make_user("bob")
    group = Group.objects.create(name="acme")

    with override_current_user(bob.pk, "203.0.113.9"):
        get_engine().generate_and_store_keyset(group)

    event = _created_event(group)
    assert event.user_id == bob.pk
    assert event.trigger == lifecycle.TRIGGER_INDIRECT
    # The address is an item of its own, and this list leaves it out.
    assert event.ip_address_id is None


@pytest.mark.django_db
def test_ambient_provisioning_records_the_address_when_it_is_listed(settings):
    _identity(settings, "all_acts", record=("user_id", "ip_address"))
    bob = make_user("bob")
    group = Group.objects.create(name="acme")

    with override_current_user(bob.pk, "203.0.113.9"):
        get_engine().generate_and_store_keyset(group)

    assert _address(_created_event(group)) == "203.0.113.9"


@pytest.mark.django_db
def test_ambient_provisioning_records_nobody_under_privileged_acts(settings):
    """A populated context is not evidence the scope permits recording it."""
    _identity(settings, "privileged_acts", record=("user_id", "ip_address"))
    bob = make_user("bob")
    group = Group.objects.create(name="acme")

    with override_current_user(bob.pk, "203.0.113.9"):
        get_engine().generate_and_store_keyset(group)

    event = _created_event(group)
    assert (event.user_id, event.ip_address_id) == (None, None)


@pytest.mark.django_db
@pytest.mark.parametrize("scope", ["all_acts", "privileged_acts"])
def test_an_explicit_identity_is_recorded_under_either_scope(settings, scope):
    _identity(settings, scope, record=("user_id", "ip_address"))
    alice = make_user("alice")
    group = Group.objects.create(name="acme")

    get_engine().generate_and_store_keyset(
        group,
        trigger=lifecycle.TRIGGER_DIRECT,
        reason="",
        user=alice,
        user_ip="198.51.100.7",
    )

    event = _created_event(group)
    assert (event.user_id, _address(event)) == (alice.pk, "198.51.100.7")


@pytest.mark.django_db
def test_the_shipped_default_records_nothing_even_when_passed_explicitly(settings):
    settings.ENCRYPTION = {k: v for k, v in settings.ENCRYPTION.items() if k != "USER_IDENTITY"}
    alice = make_user("alice")
    group = Group.objects.create(name="acme")

    get_engine().generate_and_store_keyset(
        group,
        trigger=lifecycle.TRIGGER_DIRECT,
        reason="",
        user=alice,
        os_login_user="deploy (uid 1000)",
        user_ip="198.51.100.7",
    )

    event = _created_event(group)
    assert (event.user_id, event.os_user_id, event.ip_address_id) == (None, None, None)


@pytest.mark.django_db
def test_an_unlisted_address_is_dropped(settings):
    _identity(settings, record=("user_id",))
    alice = make_user("alice")
    group = Group.objects.create(name="acme")

    get_engine().generate_and_store_keyset(
        group,
        trigger=lifecycle.TRIGGER_DIRECT,
        reason="",
        user=alice,
        user_ip="198.51.100.7",
    )

    event = _created_event(group)
    assert event.user_id == alice.pk
    assert event.ip_address_id is None


@pytest.mark.django_db
def test_the_test_console_records_its_operator_under_the_default_scope(settings):
    """The case that proves the identity and trigger thread through `_ensure_kek`.

    The console holds a request user, and an internal resolve returns nobody
    under `privileged_acts` — so if either stopped short of the engine, this row
    would be unattributed.
    """
    from encryption_suite import test_console as tc
    from encryption_suite.registry import get_kek_provisioner, get_kms_adapter

    _identity(settings, record=("user_id", "ip_address"))
    alice = make_user("alice")

    tc.full_aead_roundtrip(
        get_kms_adapter(),
        get_kek_provisioner(),
        b"probe",
        user=alice,
        user_ip="198.51.100.7",
    )

    kek_rows = KeyLifecycleEvent.objects.filter(kek__isnull=False).select_related("ip_address")
    assert kek_rows.exists()
    assert all(row.user_id == alice.pk for row in kek_rows)
    assert all(row.trigger == lifecycle.TRIGGER_DIRECT for row in kek_rows)
    assert all(_address(row) == "198.51.100.7" for row in kek_rows)
