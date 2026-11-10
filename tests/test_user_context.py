"""The identity a lifecycle row records: the OS account, the address, the scope.

The OS-account shapes are exercised with ``SUDO_USER``, ``os.getuid``,
``pwd.getpwuid`` and ``getpass.getuser`` all patched, so both branches run
whatever the host is. The POSIX branch is reached by putting a stand-in ``pwd``
module in ``sys.modules``; the non-POSIX branch by making that import fail.
"""

from __future__ import annotations

import sys
import types

import pytest
from django.test import RequestFactory

from encryption_suite.user_context import get_os_user, get_user_ip

# --- The OS login account ---------------------------------------------------


@pytest.fixture
def posix(monkeypatch):
    """Make the POSIX branch run, with a uid and a passwd database we control."""

    def _apply(uid=1000, name="deploy"):
        module = types.ModuleType("pwd")

        def getpwuid(asked):
            assert asked == uid
            if name is None:
                raise KeyError(uid)
            return types.SimpleNamespace(pw_name=name)

        module.getpwuid = getpwuid
        monkeypatch.setitem(sys.modules, "pwd", module)
        monkeypatch.setattr("os.getuid", lambda: uid, raising=False)

    return _apply


@pytest.fixture
def non_posix(monkeypatch):
    """Make ``import pwd`` fail, as it does off POSIX."""
    monkeypatch.setitem(sys.modules, "pwd", None)


@pytest.fixture(autouse=True)
def _no_sudo(monkeypatch):
    monkeypatch.delenv("SUDO_USER", raising=False)


def test_names_the_account_and_the_uid(posix):
    posix(uid=1000, name="deploy")
    assert get_os_user() == "deploy (uid 1000)"


def test_sudo_names_the_person_who_escalated(posix, monkeypatch):
    posix(uid=0, name="root")
    monkeypatch.setenv("SUDO_USER", "user1")
    assert get_os_user() == "user1 → root (uid 0)"


def test_a_uid_with_no_passwd_entry_keeps_the_uid(posix):
    posix(uid=1000, name=None)
    # The parentheses stay: an allowed name can contain digits and a space, so a
    # bare "uid 1000" would read as a name.
    assert get_os_user() == "(uid 1000)"


def test_a_uid_with_no_passwd_entry_still_shows_the_escalation(posix, monkeypatch):
    posix(uid=1000, name=None)
    monkeypatch.setenv("SUDO_USER", "user1")
    assert get_os_user() == "user1 → (uid 1000)"


def test_off_posix_the_name_is_marked_unverified(non_posix, monkeypatch):
    monkeypatch.setattr("getpass.getuser", lambda: "deploy")
    assert get_os_user() == "deploy (unverified)"


def test_off_posix_an_escalation_still_shows(non_posix, monkeypatch):
    monkeypatch.setattr("getpass.getuser", lambda: "deploy")
    monkeypatch.setenv("SUDO_USER", "user1")
    assert get_os_user() == "user1 → deploy (unverified)"


def test_off_posix_with_nothing_in_the_environment_records_nothing(non_posix, monkeypatch):
    def _raise():
        raise OSError("no login name")

    monkeypatch.setattr("getpass.getuser", _raise)
    assert get_os_user() == ""


@pytest.mark.parametrize(
    "forged",
    [
        "admin → root (uid 0)",  # a whole forged rendering
        "ad→min",  # would become "admin" if the character were filtered out
        "admin\nkek deleted",  # injects a line into any log echoing the field
        "администратор",  # non-ASCII: bidi overrides and homoglyphs live here
        "a" * 65,  # over the per-component cap
    ],
)
def test_a_forged_originating_name_is_refused_whole(posix, monkeypatch, forged):
    posix(uid=0, name="root")
    monkeypatch.setenv("SUDO_USER", forged)
    # The arrow is kept, so the escalation stays visible without echoing the
    # forged text, and the uid still identifies the account acted as.
    assert get_os_user() == "? → root (uid 0)"


def test_a_nul_is_refused():
    """Postgres rejects NUL outright, which would abort the enclosing transaction.

    Checked against the validator rather than through the environment:
    ``os.environ`` refuses to hold a NUL, so no environment variable can carry
    one this far.
    """
    from encryption_suite.user_context import _accepted_name

    assert _accepted_name("admin\x00") == ""


def test_a_forged_account_name_off_posix_leaves_only_the_marker(non_posix, monkeypatch):
    monkeypatch.setattr("getpass.getuser", lambda: "ad→min")
    assert get_os_user() == "(unverified)"


def test_a_windows_domain_name_is_accepted(non_posix, monkeypatch):
    monkeypatch.setattr("getpass.getuser", lambda: "CORP\\Ann Lee")
    assert get_os_user() == "CORP\\Ann Lee (unverified)"


# --- The client address -----------------------------------------------------


def _request(remote="198.51.100.7", forwarded=None):
    request = RequestFactory().get("/", REMOTE_ADDR=remote)
    if forwarded is not None:
        request.META["HTTP_X_FORWARDED_FOR"] = forwarded
    return request


def test_no_trusted_proxies_reads_remote_addr(settings):
    settings.ENCRYPTION = {**settings.ENCRYPTION, "USER_IDENTITY": {"IP_PROXY_COUNT": 0}}
    assert get_user_ip(_request(forwarded="203.0.113.1, 192.0.2.1")) == "198.51.100.7"


def test_one_trusted_proxy_takes_the_entry_from_the_right(settings):
    settings.ENCRYPTION = {**settings.ENCRYPTION, "USER_IDENTITY": {"IP_PROXY_COUNT": 1}}
    assert get_user_ip(_request(forwarded="203.0.113.1, 192.0.2.1")) == "192.0.2.1"


def test_a_forged_prefix_ahead_of_that_entry_is_not_recorded(settings):
    settings.ENCRYPTION = {**settings.ENCRYPTION, "USER_IDENTITY": {"IP_PROXY_COUNT": 1}}
    assert get_user_ip(_request(forwarded="9.9.9.9, 203.0.113.1, 192.0.2.1")) == "192.0.2.1"


def test_a_header_shorter_than_the_count_falls_back(settings):
    settings.ENCRYPTION = {**settings.ENCRYPTION, "USER_IDENTITY": {"IP_PROXY_COUNT": 2}}
    assert get_user_ip(_request(forwarded="192.0.2.1")) == "198.51.100.7"


def test_a_junk_address_records_nothing_rather_than_raising(settings):
    settings.ENCRYPTION = {**settings.ENCRYPTION, "USER_IDENTITY": {"IP_PROXY_COUNT": 0}}
    assert get_user_ip(_request(remote="not-an-address")) is None


def test_a_port_and_ipv6_brackets_are_stripped(settings):
    settings.ENCRYPTION = {**settings.ENCRYPTION, "USER_IDENTITY": {"IP_PROXY_COUNT": 1}}
    assert get_user_ip(_request(forwarded="[2001:db8::1]:443")) == "2001:db8::1"
    assert get_user_ip(_request(forwarded="192.0.2.1:1234")) == "192.0.2.1"
