"""Tests for IBM Key Protect KEK deletion, enumeration and the state probe.

Key Protect's delete is a soft delete: the key stops wrapping at once and stays
listed and restorable for 30 days. Nearly everything here follows from that —
the deleted key has to be filtered out of resolution and enumeration, and it is
what the state probe reports as pending deletion.
"""

from __future__ import annotations

import datetime
import json
import urllib.error
from unittest.mock import patch

import pytest
from django.utils import timezone

from encryption_suite.adapters.keks.provisioners import KekState
from encryption_suite.adapters.keks.provisioners_ibm import (
    _RESTORE_WINDOW_DAYS,
    IbmKekProvisioner,
)
from encryption_suite.exceptions import EncryptionConfigurationError, KekDeleteError
from encryption_suite.silo_ref import SiloRef

_UUID = "53008d3e-8fa4-4de3-be83-836c3376773f"
_OTHER_UUID = "11111111-2222-3333-4444-555555555555"
_PREFIX = "encryption_suite-"


def _resp(payload: dict):
    class _CM:
        def __enter__(self_inner):
            return self_inner

        def __exit__(self_inner, *exc):
            return False

        def read(self_inner):
            return json.dumps(payload).encode()

    return _CM()


def _http_error(code: int) -> urllib.error.HTTPError:
    return urllib.error.HTTPError("https://x", code, "boom", {}, None)


def _key(name: str, key_id: str = _UUID, **extra):
    return {"name": name, "id": key_id, **extra}


class _Provider:
    """A stand-in Key Protect holding a fixed set of key resources."""

    def __init__(self, keys=None, *, pages=None, policy_fails=False):
        self.keys = list(keys or [])
        self.pages = pages
        self.policy_fails = policy_fails
        self.deleted: list[str] = []
        self.delete_headers: list[dict] = []
        self.created: list[dict] = []
        self.policies: list[tuple[str, dict]] = []
        self.list_calls = 0

    def __call__(self, req, timeout, context=None):
        url = req.full_url
        method = req.get_method()
        if "identity/token" in url:
            return _resp({"access_token": "t", "expires_in": 3600})
        if method == "PUT" and "policy=rotation" in url:
            if self.policy_fails:
                raise _http_error(403)
            key_id = url.split("/policies")[0].rsplit("/", 1)[-1]
            self.policies.append((key_id, json.loads(req.data.decode())))
            return _resp({})
        if method == "POST" and url.endswith("/api/v2/keys"):
            body = json.loads(req.data.decode())
            self.created.append(body)
            return _resp({"resources": [{"name": body["resources"][0]["name"], "id": _UUID}]})
        if method == "DELETE":
            key_id = url.rsplit("/", 1)[-1]
            self.delete_headers.append(dict(req.headers))
            if key_id not in [k["id"] for k in self.keys]:
                raise _http_error(404)
            self.deleted.append(key_id)
            return _resp({"resources": [{"id": key_id, "deleted": True, "deletionDate": "2026-08-03T12:00:00Z"}]})
        if method == "GET":
            self.list_calls += 1
            if self.pages is not None:
                offset = int(url.split("offset=")[-1])
                return _resp(self.pages[offset // 200])
            return _resp({"metadata": {"collectionTotal": len(self.keys)}, "resources": self.keys})
        raise AssertionError(f"unexpected {method} {url}")


def _provisioner(**overrides):
    return IbmKekProvisioner({"IBM_INSTANCE_ID": "inst-1", "IBM_REGION": "us-east", "IBM_API_KEY": "k", **overrides})


# ---------------------------------------------------------------------------
# Declared capabilities
# ---------------------------------------------------------------------------


def test_declared_capabilities():
    assert IbmKekProvisioner.supports_delete is True
    assert IbmKekProvisioner.supports_enumeration is True
    assert IbmKekProvisioner.supports_state_check is True
    # No per-key lever: the 30 days are fixed by the service.
    assert IbmKekProvisioner.minimum_deletion_window_days is None
    # The create-key body takes no tag metadata.
    assert IbmKekProvisioner.supports_tagging is False
    # Key Protect's policy is in whole 30-day months, so one month is the floor.
    assert IbmKekProvisioner.supports_rotation_policy is True
    assert IbmKekProvisioner.minimum_rotation_days == 30


def test_a_provider_deletion_window_is_refused_at_construction():
    """Nothing sent from here can change Key Protect's fixed window, so an
    operator carrying the option over from AWS or GCP must be told, not ignored."""
    with pytest.raises(EncryptionConfigurationError) as ei:
        _provisioner(PROVIDER_DELETION_WINDOW_DAYS=7)

    assert "PROVIDER_DELETION_WINDOW_DAYS" in ei.value.detail
    assert str(_RESTORE_WINDOW_DAYS) in ei.value.detail


# ---------------------------------------------------------------------------
# Rotation policy
# ---------------------------------------------------------------------------


class TestRotationPeriodValidation:
    """Key Protect counts rotation in whole 30-day months, 1 to 12.

    Refused at construction, which ``check_kms_adapter_construction`` turns into
    an ``E004`` at ``manage.py check`` — so a value Key Protect cannot express is
    caught at deploy, not after a tenant's key has already been created.
    """

    @pytest.mark.parametrize("days", [30, 60, 90, 180, 360])
    def test_multiples_of_thirty_are_accepted(self, days):
        assert _provisioner(KEK_ROTATION_PERIOD_DAYS=days).rotation_period_days() == days

    @pytest.mark.parametrize("days", [45, 100, 91, 359])
    def test_a_value_that_is_not_whole_months_is_refused(self, days):
        with pytest.raises(EncryptionConfigurationError) as ei:
            _provisioner(KEK_ROTATION_PERIOD_DAYS=days)

        assert "multiples of 30" in ei.value.detail

    def test_the_refusal_names_the_two_nearest_legal_values(self):
        """Naming them is the whole point: the package will not round for you."""
        with pytest.raises(EncryptionConfigurationError) as ei:
            _provisioner(KEK_ROTATION_PERIOD_DAYS=100)

        assert "90" in ei.value.detail
        assert "120" in ei.value.detail

    def test_over_twelve_months_is_refused(self):
        with pytest.raises(EncryptionConfigurationError) as ei:
            _provisioner(KEK_ROTATION_PERIOD_DAYS=390)

        assert "360" in ei.value.detail

    def test_under_one_month_is_refused_by_the_shared_floor(self):
        with pytest.raises(EncryptionConfigurationError) as ei:
            _provisioner(KEK_ROTATION_PERIOD_DAYS=7)

        assert "30" in ei.value.detail

    def test_a_non_numeric_value_is_refused(self):
        with pytest.raises(EncryptionConfigurationError):
            _provisioner(KEK_ROTATION_PERIOD_DAYS="quarterly")


class TestRotationPolicyIsWritten:
    def test_a_created_key_gets_the_policy_in_months(self):
        provider = _Provider([])
        with patch("urllib.request.urlopen", side_effect=provider):
            _provisioner(KEK_ROTATION_PERIOD_DAYS=90).ensure_kek(f"{_PREFIX}team-1", SiloRef("default", "team-1"))

        assert len(provider.policies) == 1
        key_id, body = provider.policies[0]
        assert key_id == _UUID
        assert body["resources"][0]["rotation"]["interval_month"] == 3

    def test_no_policy_call_without_the_option(self):
        provider = _Provider([])
        with patch("urllib.request.urlopen", side_effect=provider):
            _provisioner().ensure_kek(f"{_PREFIX}team-1", SiloRef("default", "team-1"))

        assert provider.policies == []

    def test_an_adopted_key_is_left_alone(self):
        """Its policy is the operator's; overwriting it would be overreach."""
        provider = _Provider([_key(f"{_PREFIX}team-1")])
        with patch("urllib.request.urlopen", side_effect=provider):
            _provisioner(KEK_ROTATION_PERIOD_DAYS=90).ensure_kek(f"{_PREFIX}team-1", SiloRef("default", "team-1"))

        assert provider.policies == []
        assert provider.created == []

    def test_a_failed_policy_call_warns_but_keeps_the_key(self, caplog):
        """A key without a schedule beats no key — but silence is the one
        outcome nobody detects, so it must be logged."""
        provider = _Provider([], policy_fails=True)
        with patch("urllib.request.urlopen", side_effect=provider):
            created = _provisioner(KEK_ROTATION_PERIOD_DAYS=90).ensure_kek(
                f"{_PREFIX}team-1", SiloRef("default", "team-1")
            )

        assert created is True
        assert len(provider.created) == 1
        messages = [r.getMessage() for r in caplog.records if r.levelname == "WARNING"]
        assert any("will not rotate on its own" in m for m in messages)
        # No traceback reaches the log — this is a dependency the operator does
        # not maintain.
        assert all(r.exc_info is None for r in caplog.records)


# ---------------------------------------------------------------------------
# Deletion
# ---------------------------------------------------------------------------


class TestDelete:
    def test_deleting_resolves_the_name_and_reports_the_restore_window(self):
        provider = _Provider([_key(f"{_PREFIX}team-1")])
        with patch("urllib.request.urlopen", side_effect=provider):
            outcome = _provisioner().delete_kek(f"{_PREFIX}team-1", SiloRef("default", "team-1"), owner_prefix=_PREFIX)

        assert provider.deleted == [_UUID]
        # Restorable, so the tombstone stays SCHEDULED until reconcile confirms.
        assert outcome.scheduled is True
        expected = datetime.datetime(2026, 8, 3, 12, 0, tzinfo=datetime.UTC) + datetime.timedelta(
            days=_RESTORE_WINDOW_DAYS
        )
        assert outcome.effective_at == expected

    def test_the_delete_asks_for_the_representation(self):
        """A bare 204 carries no deletionDate to measure the window from."""
        provider = _Provider([_key(f"{_PREFIX}team-1")])
        with patch("urllib.request.urlopen", side_effect=provider):
            _provisioner().delete_kek(f"{_PREFIX}team-1", SiloRef("default", "team-1"), owner_prefix=_PREFIX)

        headers = {k.lower(): v for k, v in provider.delete_headers[0].items()}
        assert headers["prefer"] == "return=representation"

    def test_a_missing_deletion_date_falls_back_to_now(self):
        provider = _Provider([_key(f"{_PREFIX}team-1")])

        def _no_date(req, timeout, context=None):
            if req.get_method() == "DELETE":
                provider.deleted.append(_UUID)
                return _resp({"resources": [{"id": _UUID, "deleted": True}]})
            return provider(req, timeout, context)

        before = timezone.now()
        with patch("urllib.request.urlopen", side_effect=_no_date):
            outcome = _provisioner().delete_kek(f"{_PREFIX}team-1", SiloRef("default", "team-1"), owner_prefix=_PREFIX)

        assert outcome.effective_at >= before + datetime.timedelta(days=_RESTORE_WINDOW_DAYS)

    def test_a_name_with_no_live_key_counts_as_deleted(self):
        """Idempotent: already gone is the goal state, not a failure."""
        provider = _Provider([])
        with patch("urllib.request.urlopen", side_effect=provider):
            outcome = _provisioner().delete_kek(f"{_PREFIX}team-1", SiloRef("default", "team-1"), owner_prefix=_PREFIX)

        assert outcome.scheduled is False
        assert provider.deleted == []

    def test_an_already_deleted_key_is_not_deleted_again(self):
        provider = _Provider([_key(f"{_PREFIX}team-1", deleted=True)])
        with patch("urllib.request.urlopen", side_effect=provider):
            outcome = _provisioner().delete_kek(f"{_PREFIX}team-1", SiloRef("default", "team-1"), owner_prefix=_PREFIX)

        assert outcome.scheduled is False
        assert provider.deleted == []

    def test_deleting_clears_the_ensured_cache(self):
        """Otherwise a later ensure_kek trusts a stale entry and never re-provisions."""
        provider = _Provider([_key(f"{_PREFIX}team-1")])
        prov = _provisioner()
        with patch("urllib.request.urlopen", side_effect=provider):
            prov.ensure_kek(f"{_PREFIX}team-1", SiloRef("default", "team-1"))
            assert f"{_PREFIX}team-1" in prov._ensured
            prov.delete_kek(f"{_PREFIX}team-1", SiloRef("default", "team-1"), owner_prefix=_PREFIX)

        assert f"{_PREFIX}team-1" not in prov._ensured

    def test_a_key_without_the_owner_prefix_is_refused(self):
        provider = _Provider([_key("someone-elses-key")])
        with patch("urllib.request.urlopen", side_effect=provider):
            with pytest.raises(KekDeleteError):
                _provisioner().delete_kek("someone-elses-key", SiloRef("default", "team-1"), owner_prefix=_PREFIX)

        assert provider.deleted == []

    def test_a_provider_error_becomes_a_typed_delete_error(self):
        def _fails(req, timeout, context=None):
            if "identity/token" in req.full_url:
                return _resp({"access_token": "t", "expires_in": 3600})
            raise _http_error(500)

        with patch("urllib.request.urlopen", side_effect=_fails):
            with pytest.raises(KekDeleteError):
                _provisioner().delete_kek(f"{_PREFIX}team-1", SiloRef("default", "team-1"), owner_prefix=_PREFIX)


# ---------------------------------------------------------------------------
# Enumeration
# ---------------------------------------------------------------------------


class TestEnumeration:
    def test_lists_owned_names(self):
        provider = _Provider([_key(f"{_PREFIX}team-1"), _key(f"{_PREFIX}team-2", _OTHER_UUID)])
        with patch("urllib.request.urlopen", side_effect=provider):
            names = _provisioner().list_kek_names(_PREFIX)

        assert names == [f"{_PREFIX}team-1", f"{_PREFIX}team-2"]

    def test_foreign_keys_are_filtered_out(self):
        provider = _Provider([_key(f"{_PREFIX}team-1"), _key("other-app-key", _OTHER_UUID)])
        with patch("urllib.request.urlopen", side_effect=provider):
            names = _provisioner().list_kek_names(_PREFIX)

        assert names == [f"{_PREFIX}team-1"]

    def test_deleted_keys_are_omitted(self):
        """A deleted key can no longer wrap, so reporting it as present would make
        reconcile call a shredded key healthy."""
        provider = _Provider([_key(f"{_PREFIX}team-1"), _key(f"{_PREFIX}team-2", _OTHER_UUID, deleted=True)])
        with patch("urllib.request.urlopen", side_effect=provider):
            names = _provisioner().list_kek_names(_PREFIX)

        assert names == [f"{_PREFIX}team-1"]

    def test_duplicate_names_collapse(self):
        # Key Protect does not require names to be unique.
        provider = _Provider([_key(f"{_PREFIX}team-1"), _key(f"{_PREFIX}team-1", _OTHER_UUID)])
        with patch("urllib.request.urlopen", side_effect=provider):
            names = _provisioner().list_kek_names(_PREFIX)

        assert names == [f"{_PREFIX}team-1"]

    def test_pages_through_a_long_listing(self):
        first = [_key(f"{_PREFIX}team-{i}", f"id-{i}") for i in range(200)]
        second = [_key(f"{_PREFIX}team-200", "id-200")]
        provider = _Provider(
            pages=[
                {"metadata": {"collectionTotal": 201}, "resources": first},
                {"metadata": {"collectionTotal": 201}, "resources": second},
            ]
        )
        with patch("urllib.request.urlopen", side_effect=provider):
            names = _provisioner().list_kek_names(_PREFIX)

        assert len(names) == 201
        assert provider.list_calls == 2

    def test_a_short_page_stops_the_walk(self):
        """A server that misreports collectionTotal must not spin the loop."""
        provider = _Provider(pages=[{"metadata": {"collectionTotal": 9999}, "resources": [_key(f"{_PREFIX}team-1")]}])
        with patch("urllib.request.urlopen", side_effect=provider):
            names = _provisioner().list_kek_names(_PREFIX)

        assert names == [f"{_PREFIX}team-1"]
        assert provider.list_calls == 1


# ---------------------------------------------------------------------------
# State probe
# ---------------------------------------------------------------------------


class TestStateCheck:
    def test_a_live_key_reports_active(self):
        provider = _Provider([_key(f"{_PREFIX}team-1")])
        with patch("urllib.request.urlopen", side_effect=provider):
            state = _provisioner().describe_kek_state(f"{_PREFIX}team-1")

        assert state.state == KekState.ACTIVE

    def test_a_deleted_key_reports_pending_deletion_with_its_purge_date(self):
        provider = _Provider([_key(f"{_PREFIX}team-1", deleted=True, deletionDate="2026-08-03T12:00:00Z")])
        with patch("urllib.request.urlopen", side_effect=provider):
            state = _provisioner().describe_kek_state(f"{_PREFIX}team-1")

        assert state.is_pending_deletion
        assert state.effective_at == datetime.datetime(2026, 8, 3, 12, 0, tzinfo=datetime.UTC) + datetime.timedelta(
            days=_RESTORE_WINDOW_DAYS
        )

    def test_an_absent_key_reports_unknown(self):
        """Purged, or unreadable by this identity — neither is evidence of health."""
        provider = _Provider([])
        with patch("urllib.request.urlopen", side_effect=provider):
            state = _provisioner().describe_kek_state(f"{_PREFIX}team-1")

        assert state.state == KekState.UNKNOWN

    def test_a_failing_probe_degrades_to_unknown(self):
        def _fails(req, timeout, context=None):
            if "identity/token" in req.full_url:
                return _resp({"access_token": "t", "expires_in": 3600})
            raise _http_error(500)

        with patch("urllib.request.urlopen", side_effect=_fails):
            state = _provisioner().describe_kek_state(f"{_PREFIX}team-1")

        assert state.state == KekState.UNKNOWN
