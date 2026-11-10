"""The identity a log line carries, and where it comes from.

Two mechanisms, deliberately: a site that holds an identity passes it, and
everything else — the engine, the adapters, the error funnel, all several frames
below any caller that knows who acted — has it appended by the filter
`_logging.get_logger` attaches. ``USER_IDENTITY['LOGS']`` decides what either
one renders.
"""

from __future__ import annotations

import logging

import pytest

from encryption_suite._logging import IdentityTail, _IdentityFilter, get_logger, log_text
from encryption_suite.user_context import identity_tail, override_current_user
from tests.factories import make_user


def _identity(settings, scope="privileged_acts", logs=("user_id", "user_name"), record=()):
    settings.ENCRYPTION = {
        **settings.ENCRYPTION,
        "USER_IDENTITY": {"SCOPE": scope, "LOGS": list(logs), "KEY_LIFECYCLE_EVENTS": list(record)},
    }


@pytest.fixture
def all_acts(settings):
    _identity(settings, "all_acts")


def test_the_factory_attaches_the_filter_once():
    """`get_logger` runs at import in every module; duplicates would stack."""
    logger = get_logger("encryption_suite.tests.duplicate")
    for _ in range(3):
        get_logger("encryption_suite.tests.duplicate")
    assert sum(isinstance(f, _IdentityFilter) for f in logger.filters) == 1


@pytest.mark.django_db
def test_an_ambient_identity_reaches_a_line_that_never_asked_for_one(all_acts, caplog):
    logger = get_logger("encryption_suite.tests.ambient")
    alice = make_user("alice")

    with caplog.at_level(logging.INFO, logger="encryption_suite.tests.ambient"):
        with override_current_user(alice.pk):
            logger.info("A key was wrapped. silo=%s", "team-1")

    message = caplog.records[0].getMessage()
    assert "silo=team-1" in message
    assert f"user_id={alice.pk}" in message
    assert 'user_name="alice"' in message


@pytest.mark.django_db
def test_nothing_is_appended_under_the_default_scope(settings, caplog):
    """A populated context is not read outside ``all_acts``."""
    _identity(settings, "privileged_acts")
    logger = get_logger("encryption_suite.tests.privileged")
    alice = make_user("alice")

    with caplog.at_level(logging.INFO, logger="encryption_suite.tests.privileged"):
        with override_current_user(alice.pk):
            logger.info("A key was wrapped. silo=%s", "team-1")

    assert caplog.records[0].getMessage() == "A key was wrapped. silo=team-1"


@pytest.mark.django_db
def test_a_line_that_passed_its_own_identity_is_left_alone(all_acts, caplog):
    """A site holding an identity renders it; the filter must not add a second."""
    logger = get_logger("encryption_suite.tests.explicit")
    alice = make_user("alice")
    bob = make_user("bob")

    with caplog.at_level(logging.INFO, logger="encryption_suite.tests.explicit"):
        with override_current_user(alice.pk):
            logger.info("Key material was destroyed. %s", identity_tail(user=bob))

    message = caplog.records[0].getMessage()
    assert message.count("user_id=") == 1
    assert f"user_id={bob.pk}" in message


@pytest.mark.django_db
def test_an_empty_explicit_tail_still_keeps_the_context_out(all_acts, caplog):
    """The marker is the type, not the text: an empty tail is still a decision."""
    logger = get_logger("encryption_suite.tests.empty_tail")
    alice = make_user("alice")

    with caplog.at_level(logging.INFO, logger="encryption_suite.tests.empty_tail"):
        with override_current_user(alice.pk):
            logger.info("Key material was destroyed.%s", IdentityTail(""))

    assert caplog.records[0].getMessage() == "Key material was destroyed."


@pytest.mark.django_db
def test_text_that_looks_like_a_tail_is_not_one(all_acts, caplog):
    """Only the type marks a tail, so a plain ``user_id=`` gets the context appended."""
    logger = get_logger("encryption_suite.tests.lookalike")
    alice = make_user("alice")

    with caplog.at_level(logging.INFO, logger="encryption_suite.tests.lookalike"):
        with override_current_user(alice.pk):
            logger.info("A row was read. user_id=%s", 999)

    assert caplog.records[0].getMessage() == f'A row was read. user_id=999 user_id={alice.pk} user_name="alice"'


@pytest.mark.django_db
def test_rendering_a_line_costs_no_query(settings, caplog, django_assert_num_queries):
    """The middleware resolves the names once; a line must not look them up again.

    Without this every log line naming a user is a user lookup, and the decrypt
    path logs one line per field.
    """
    from encryption_suite.user_context import UserContext, _current_user

    _identity(settings, "all_acts", logs=("user_id", "user_name", "user_str"))
    alice = make_user("alice")
    token = _current_user.set(UserContext(alice.pk, None, alice.get_username(), str(alice)))
    try:
        with caplog.at_level(logging.INFO, logger="encryption_suite.tests.cost"):
            logger = get_logger("encryption_suite.tests.cost")
            with django_assert_num_queries(0):
                for _ in range(5):
                    logger.info("A field was decrypted. silo=%s", "team-1")
    finally:
        _current_user.reset(token)

    message = caplog.records[0].getMessage()
    assert 'user_name="alice"' in message
    assert f'user_str="{alice}"' in message


@pytest.mark.django_db
def test_a_context_without_a_resolved_name_still_renders_one(all_acts, caplog):
    """A setter that supplied only a key falls back to a lookup rather than `?`."""
    alice = make_user("alice")
    with caplog.at_level(logging.INFO, logger="encryption_suite.tests.fallback"):
        with override_current_user(alice.pk):
            get_logger("encryption_suite.tests.fallback").info("A key was wrapped.")

    assert 'user_name="alice"' in caplog.records[0].getMessage()


@pytest.mark.django_db
def test_a_percent_in_the_identity_cannot_break_formatting(all_acts, caplog):
    """The filter appends after interpolation, so a stray % is only text."""
    logger = get_logger("encryption_suite.tests.percent")
    awkward = make_user("100%_admin")

    with caplog.at_level(logging.INFO, logger="encryption_suite.tests.percent"):
        with override_current_user(awkward.pk):
            logger.info("A key was wrapped. silo=%s", "team-1")

    assert 'user_name="100%_admin"' in caplog.records[0].getMessage()


def test_a_failure_in_the_filter_never_loses_the_line(caplog, monkeypatch):
    """A logging call must not take a real operation down with it."""

    def _boom():
        raise RuntimeError("context is unreadable")

    monkeypatch.setattr(_IdentityFilter, "_tail", staticmethod(_boom))
    logger = get_logger("encryption_suite.tests.boom")

    with caplog.at_level(logging.WARNING, logger="encryption_suite.tests.boom"):
        logger.warning("Key material was destroyed.")

    assert caplog.records[0].getMessage() == "Key material was destroyed."


# --- Text the package does not choose ---------------------------------------


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("alice", "alice"),
        ("Zoë O'Brien (ops)", "Zoë O'Brien (ops)"),
        ('x" user_id="1', 'x\\" user_id=\\"1'),
        ("a\nERROR forged line", "a\\nERROR forged line"),
        ("a\r\n\tb", "a\\r\\n\\tb"),
        ("a\u2028b\x00c", "a\\u2028b\\x00c"),
        ("C:\\keys", "C:\\\\keys"),
        (42, "42"),
    ],
)
def test_log_text_escapes_what_would_break_a_quoted_field(value, expected):
    assert log_text(value) == expected


def test_a_quote_or_line_break_in_a_name_cannot_forge_fields(settings):
    _identity(settings, logs=("user_id", "user_name", "user_str", "os_user"))

    tail = identity_tail(user=7, username='eve" user_id="1', label="Eve\nERROR forged", os_login_user='op"s')

    assert tail == 'user_id=7 user_name="eve\\" user_id=\\"1" user_str="Eve\\nERROR forged" os_user="op\\"s"'
    assert "\n" not in tail


def test_row_identity_file_name_and_storage_key_are_escaped():
    from encryption_suite._internal import describe_decryption_target, describe_storage_location

    target = describe_decryption_target(field_label="app.Doc.body", row_identity='pk=1,name=a"b', file_name="x\ny.bin")
    assert target == 'field="app.Doc.body" row="pk=1,name=a\\"b" file="x\\ny.bin"'

    class _Storage:
        bucket_name = "private"

    assert describe_storage_location(_Storage(), 'up"load\n.bin') == (
        'container="private" backend="_Storage" key="up\\"load\\n.bin"'
    )


# --- What the tail renders -------------------------------------------------


@pytest.mark.django_db
def test_the_tail_renders_the_listed_items_in_one_order(settings):
    _identity(settings, logs=("os_user", "ip_address", "user_str", "user_name", "user_id"))
    alice = make_user("alice")

    tail = identity_tail(user=alice, os_login_user="deploy (uid 1000)", user_ip="127.0.0.1")

    assert isinstance(tail, IdentityTail)
    assert tail == (
        f'user_id={alice.pk} user_name="alice" user_str="{alice}" ip_address=127.0.0.1 os_user="deploy (uid 1000)"'
    )


@pytest.mark.django_db
def test_a_listed_item_with_no_value_renders_a_question_mark(settings):
    _identity(settings, logs=("user_id", "user_name", "user_str", "ip_address", "os_user"))

    assert identity_tail() == 'user_id=? user_name="?" user_str="?" ip_address=? os_user="?"'


@pytest.mark.django_db
def test_an_unlisted_item_is_absent(settings):
    _identity(settings, logs=("ip_address",))
    alice = make_user("alice")

    assert identity_tail(user=alice, os_login_user="deploy (uid 1000)", user_ip="127.0.0.1") == "ip_address=127.0.0.1"


def test_with_nothing_listed_the_tail_is_empty_but_still_a_tail(settings):
    _identity(settings, logs=())

    tail = identity_tail(user=1, os_login_user="deploy (uid 1000)", user_ip="127.0.0.1")
    assert (tail, type(tail)) == ("", IdentityTail)


# --- The record and the log decide separately ------------------------------


@pytest.mark.django_db
def test_an_address_can_be_logged_without_being_recorded(settings, caplog):
    """Nothing in the record, the address in the log: the two lists are independent."""
    from django.contrib.auth.models import Group

    from encryption_suite import lifecycle
    from encryption_suite.models import KeyLifecycleEvent
    from encryption_suite.registry import get_engine

    _identity(settings, logs=("ip_address",), record=())
    group = Group.objects.create(name="acme")

    with caplog.at_level(logging.INFO, logger="encryption_suite"):
        get_engine().generate_and_store_keyset(
            group, trigger=lifecycle.TRIGGER_DIRECT, reason="", user=make_user("alice"), user_ip="127.0.0.1"
        )

    event = KeyLifecycleEvent.objects.get(event=lifecycle.EVENT_CREATED, dek__isnull=False)
    assert (event.user_id, event.ip_address_id) == (None, None)
    assert any("ip_address=127.0.0.1" in record.getMessage() for record in caplog.records)


@pytest.mark.django_db
def test_an_address_can_be_recorded_without_being_logged(settings, caplog):
    from django.contrib.auth.models import Group

    from encryption_suite import lifecycle
    from encryption_suite.models import KeyLifecycleEvent
    from encryption_suite.registry import get_engine

    _identity(settings, logs=(), record=("ip_address",))
    group = Group.objects.create(name="acme")

    with caplog.at_level(logging.INFO, logger="encryption_suite"):
        get_engine().generate_and_store_keyset(
            group, trigger=lifecycle.TRIGGER_DIRECT, reason="", user=make_user("alice"), user_ip="127.0.0.1"
        )

    event = KeyLifecycleEvent.objects.select_related("ip_address").get(event=lifecycle.EVENT_CREATED, dek__isnull=False)
    assert event.ip_address.value == "127.0.0.1"
    assert not any("127.0.0.1" in record.getMessage() for record in caplog.records)
