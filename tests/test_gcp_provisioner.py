"""GcpKekProvisioner deletion, enumeration and state checks against a fake API.

The provisioner talks to Cloud KMS over plain HTTP, so the fake replaces
``_http`` and records every call. Cloud KMS cannot delete a CryptoKey, so most of
what is asserted here is about *versions*: destroying all of them is the
deletion, and a key whose versions are all destroyed has to stop being listed or
no deletion could ever be confirmed.
"""

from __future__ import annotations

import datetime
import urllib.error

import pytest

from encryption_suite.adapters.keks.provisioners import KekState
from encryption_suite.adapters.keks.provisioners_gcp import GcpKekProvisioner
from encryption_suite.exceptions import (
    EncryptionConfigurationError,
    KekEnumerationError,
    KekPendingDeletionError,
)
from encryption_suite.silo_ref import SiloRef

_API = "https://cloudkms.googleapis.com/v1"
_RING = "projects/p/locations/us-central1/keyRings/r"
_PREFIX = f"{_RING}/cryptoKeys/es-prod-"
_NAME = _PREFIX + "team-1"


def _aware(*args):
    return datetime.datetime(*args, tzinfo=datetime.UTC)


def _key(name, *, primary_state="ENABLED", destroy_time=None, rotation=None):
    key: dict = {"name": name}
    if primary_state is not None:
        key["primary"] = {"name": f"{name}/cryptoKeyVersions/1", "state": primary_state}
        if destroy_time:
            key["primary"]["destroyTime"] = destroy_time
    if rotation:
        key["rotationPeriod"] = rotation
    return key


def _version(key_name, number, state, destroy_time=None):
    version = {"name": f"{key_name}/cryptoKeyVersions/{number}", "state": state}
    if destroy_time:
        version["destroyTime"] = destroy_time
    return version


class _FakeApi:
    """Stands in for ``GcpKekProvisioner._http``.

    *keys* maps a full resource name to its CryptoKey resource; *versions* maps
    the same name to its version list. *pages* optionally overrides the paged
    ``cryptoKeys`` listing so pagination can be exercised.
    """

    def __init__(self, *, keys=None, versions=None, pages=None, destroy_time="2026-08-01T12:00:00Z"):
        self.keys = dict(keys or {})
        self.versions = {k: list(v) for k, v in (versions or {}).items()}
        self.pages = pages
        self.destroy_time = destroy_time
        self.calls: list[tuple] = []

    def __call__(self, method, url, token, body):
        self.calls.append((method, url.replace(_API + "/", ""), body))
        path = url[len(_API) + 1 :]

        if method == "GET" and path.endswith("/cryptoKeys") or path.startswith(f"{_RING}/cryptoKeys?"):
            return self._list_keys(path)
        if method == "GET" and path.endswith("/cryptoKeyVersions"):
            return {"cryptoKeyVersions": self.versions.get(path.rsplit("/cryptoKeyVersions", 1)[0], [])}
        if method == "POST" and path.endswith(":destroy"):
            return self._destroy(path[: -len(":destroy")])
        if method == "PATCH":
            return {}
        if method == "POST":
            return {}
        if method == "GET":
            if path not in self.keys:
                raise urllib.error.HTTPError(url, 404, "Not Found", None, None)
            return self.keys[path]
        raise AssertionError(f"unexpected call: {method} {path}")

    def _list_keys(self, path):
        if self.pages is None:
            return {"cryptoKeys": list(self.keys.values())}
        token = path.partition("pageToken=")[2]
        index = int(token) if token else 0
        page = {"cryptoKeys": self.pages[index]}
        if index + 1 < len(self.pages):
            page["nextPageToken"] = str(index + 1)
        return page

    def _destroy(self, version_name):
        return {"name": version_name, "state": "DESTROY_SCHEDULED", "destroyTime": self.destroy_time}

    def urls(self, method=None):
        return [path for verb, path, _body in self.calls if method is None or verb == method]


def _provisioner(api, **options):
    prov = GcpKekProvisioner(
        {
            "GCP_PROJECT_ID": "p",
            "GCP_KMS_LOCATION": "us-central1",
            "GCP_KMS_KEY_RING": "r",
            **options,
        }
    )
    prov._http = api
    prov._strategy = _FakeStrategy()
    return prov


class _FakeStrategy:
    def get_credentials(self):
        return "token"


class TestCapabilityFlags:
    def test_all_three_are_declared(self):
        assert GcpKekProvisioner.supports_delete is True
        assert GcpKekProvisioner.supports_enumeration is True
        assert GcpKekProvisioner.supports_state_check is True


class TestEnsure:
    def test_creates_key_with_the_configured_destroy_window(self):
        api = _FakeApi()
        prov = _provisioner(api, PROVIDER_DELETION_WINDOW_DAYS=3)

        prov.ensure_kek(_NAME, SiloRef("default", "team-1"))

        create = next(c for c in api.calls if c[0] == "POST")
        assert create[1] == f"{_RING}/cryptoKeys?cryptoKeyId=es-prod-team-1"
        assert create[2]["destroyScheduledDuration"] == "259200s"

    def test_defaults_to_seven_days(self):
        api = _FakeApi()
        prov = _provisioner(api)

        prov.ensure_kek(_NAME, SiloRef("default", "team-1"))

        create = next(c for c in api.calls if c[0] == "POST")
        assert create[2]["destroyScheduledDuration"] == "604800s"

    def test_a_test_console_key_is_created_with_the_provider_minimum(self):
        # Read at creation, not deletion: Cloud KMS welds the duration onto the
        # key, so the console could not shorten it later.
        api = _FakeApi()
        prov = _provisioner(api, PROVIDER_DELETION_WINDOW_DAYS=30)

        prov.ensure_kek(_PREFIX + "enctestkey", SiloRef("default", "enctestkey"))

        create = next(c for c in api.calls if c[0] == "POST")
        assert create[2]["destroyScheduledDuration"] == "86400s"

    def test_a_window_under_the_cloud_kms_floor_is_refused_at_construction(self):
        # The wiring mistake this guards: PROVIDER_DELETION_WINDOW_DAYS pointed at
        # the same value as the package's KEY_DELETION_WINDOW_DAYS, which accepts 0.
        with pytest.raises(EncryptionConfigurationError):
            _provisioner(_FakeApi(), PROVIDER_DELETION_WINDOW_DAYS=0)

    def test_an_org_policy_floor_rejection_names_the_setting(self):
        # Not catchable at construction: the floor is raised by
        # constraints/cloudkms.minimumDestroyScheduledDuration, not by config.
        def _reject(method, url, token, body):
            if method == "POST":
                raise urllib.error.HTTPError(
                    url,
                    400,
                    "Bad Request: the minimum allowed value for destroy_scheduled_duration is 7d",
                    None,
                    None,
                )
            raise urllib.error.HTTPError(url, 404, "Not Found", None, None)

        prov = _provisioner(_FakeApi())
        prov._http = _reject

        with pytest.raises(RuntimeError, match="PROVIDER_DELETION_WINDOW_DAYS"):
            prov.ensure_kek(_NAME, SiloRef("default", "team-1"))

    def test_existing_key_is_not_recreated(self):
        api = _FakeApi(keys={_NAME: _key(_NAME)})
        prov = _provisioner(api)

        prov.ensure_kek(_NAME, SiloRef("default", "team-1"))

        assert api.urls("POST") == []

    def test_scheduled_key_is_refused_with_its_destroy_date(self):
        # The name is taken, so nothing can be created over it; caching it as
        # ensured would defer the failure to the first encrypt.
        api = _FakeApi(
            keys={_NAME: _key(_NAME, primary_state="DESTROY_SCHEDULED", destroy_time="2026-08-01T12:00:00Z")}
        )
        prov = _provisioner(api)

        with pytest.raises(KekPendingDeletionError) as ei:
            prov.ensure_kek(_NAME, SiloRef("default", "team-1"))

        assert ei.value.effective_at == _aware(2026, 8, 1, 12, 0)

    def test_destroyed_key_is_refused(self):
        api = _FakeApi(keys={_NAME: _key(_NAME, primary_state="DESTROYED")})
        prov = _provisioner(api)

        with pytest.raises(RuntimeError, match="destroyed"):
            prov.ensure_kek(_NAME, SiloRef("default", "team-1"))

    def test_accepts_the_bare_template_name(self):
        api = _FakeApi(keys={_NAME: _key(_NAME)})
        prov = _provisioner(api)

        prov.ensure_kek("es-prod-team-1", SiloRef("default", "team-1"))

        assert api.urls("GET") == [_NAME]


class TestDelete:
    def test_disables_then_destroys_every_live_version(self):
        api = _FakeApi(
            keys={_NAME: _key(_NAME)},
            versions={
                _NAME: [
                    _version(_NAME, 1, "ENABLED"),
                    _version(_NAME, 2, "DISABLED"),
                    _version(_NAME, 3, "DESTROYED"),
                ]
            },
        )
        prov = _provisioner(api)

        outcome = prov.delete_kek(_NAME, SiloRef("default", "team-1"), owner_prefix=_PREFIX)

        # Version 1 is disabled first (the disableBeforeDestroy org policy
        # refuses a destroy on an enabled version); 2 is already disabled; 3 is
        # already destroyed and is skipped entirely.
        assert api.urls("PATCH") == [f"{_NAME}/cryptoKeyVersions/1?updateMask=state"]
        assert api.urls("POST") == [
            f"{_NAME}/cryptoKeyVersions/1:destroy",
            f"{_NAME}/cryptoKeyVersions/2:destroy",
        ]
        assert outcome.scheduled is True
        assert outcome.effective_at == _aware(2026, 8, 1, 12, 0)

    def test_reports_the_latest_destroy_time(self):
        api = _FakeApi(
            keys={_NAME: _key(_NAME)},
            versions={
                _NAME: [
                    _version(_NAME, 1, "DESTROY_SCHEDULED", "2026-08-05T09:00:00Z"),
                    _version(_NAME, 2, "DESTROY_SCHEDULED", "2026-08-02T09:00:00Z"),
                ]
            },
        )
        prov = _provisioner(api)

        outcome = prov.delete_kek(_NAME, SiloRef("default", "team-1"), owner_prefix=_PREFIX)

        # Already scheduled: no destroy calls, and the key is gone for good only
        # once its last version goes.
        assert api.urls("POST") == []
        assert outcome.effective_at == _aware(2026, 8, 5, 9, 0)

    def test_clears_a_rotation_schedule_first(self):
        # Rotation would add a fresh enabled version to a key this deployment
        # believes it destroyed.
        api = _FakeApi(
            keys={_NAME: _key(_NAME, rotation="7776000s")},
            versions={_NAME: [_version(_NAME, 1, "ENABLED")]},
        )
        prov = _provisioner(api)

        prov.delete_kek(_NAME, SiloRef("default", "team-1"), owner_prefix=_PREFIX)

        assert api.urls("PATCH")[0] == f"{_NAME}?updateMask=rotationPeriod,nextRotationTime"

    def test_leaves_an_unrotated_key_alone(self):
        api = _FakeApi(keys={_NAME: _key(_NAME)}, versions={_NAME: [_version(_NAME, 1, "ENABLED")]})
        prov = _provisioner(api)

        prov.delete_kek(_NAME, SiloRef("default", "team-1"), owner_prefix=_PREFIX)

        assert f"{_NAME}?updateMask=rotationPeriod,nextRotationTime" not in api.urls("PATCH")

    def test_absent_key_counts_as_deleted(self):
        api = _FakeApi()
        prov = _provisioner(api)

        outcome = prov.delete_kek(_NAME, SiloRef("default", "team-1"), owner_prefix=_PREFIX)

        assert outcome.scheduled is False
        assert api.urls("POST") == []

    def test_fully_destroyed_key_counts_as_deleted(self):
        # Nothing left to destroy, so this is a completed deletion rather than a
        # scheduled one — the row goes straight to deleted.
        api = _FakeApi(
            keys={_NAME: _key(_NAME, primary_state="DESTROYED")},
            versions={_NAME: [_version(_NAME, 1, "DESTROYED")]},
        )
        prov = _provisioner(api)

        outcome = prov.delete_kek(_NAME, SiloRef("default", "team-1"), owner_prefix=_PREFIX)

        assert outcome.scheduled is False

    def test_forgets_the_ensured_cache_entry(self):
        api = _FakeApi(keys={_NAME: _key(_NAME)}, versions={_NAME: [_version(_NAME, 1, "ENABLED")]})
        prov = _provisioner(api)
        prov.ensure_kek(_NAME, SiloRef("default", "team-1"))

        prov.delete_kek(_NAME, SiloRef("default", "team-1"), owner_prefix=_PREFIX)

        assert "es-prod-team-1" not in prov._ensured


class TestEnumeration:
    def test_lists_full_resource_names(self):
        other = _PREFIX + "team-2"
        api = _FakeApi(keys={_NAME: _key(_NAME), other: _key(other)})
        prov = _provisioner(api)

        assert prov.list_kek_names(_PREFIX) == [_NAME, other]

    def test_a_live_primary_costs_no_version_listing(self):
        api = _FakeApi(keys={_NAME: _key(_NAME)})
        prov = _provisioner(api)

        prov.list_kek_names(_PREFIX)

        assert not [u for u in api.urls("GET") if u.endswith("/cryptoKeyVersions")]

    def test_omits_a_key_whose_versions_are_all_destroyed(self):
        # Cloud KMS never removes the CryptoKey shell, so treating it as present
        # would leave every deletion permanently unconfirmed.
        api = _FakeApi(
            keys={_NAME: _key(_NAME, primary_state="DESTROYED")},
            versions={_NAME: [_version(_NAME, 1, "DESTROYED")]},
        )
        prov = _provisioner(api)

        assert prov.list_kek_names(_PREFIX) == []

    def test_keeps_a_key_with_a_surviving_older_version(self):
        # Destroying the primary at the console leaves an enabled version that
        # can still decrypt, so reporting the key gone would be a false shred.
        api = _FakeApi(
            keys={_NAME: _key(_NAME, primary_state="DESTROYED")},
            versions={_NAME: [_version(_NAME, 1, "ENABLED"), _version(_NAME, 2, "DESTROYED")]},
        )
        prov = _provisioner(api)

        assert prov.list_kek_names(_PREFIX) == [_NAME]

    def test_keeps_a_key_inside_its_destroy_window(self):
        api = _FakeApi(keys={_NAME: _key(_NAME, primary_state="DESTROY_SCHEDULED")})
        prov = _provisioner(api)

        assert prov.list_kek_names(_PREFIX) == [_NAME]

    def test_follows_pagination(self):
        second = _PREFIX + "team-2"
        api = _FakeApi(pages=[[_key(_NAME)], [_key(second)]])
        prov = _provisioner(api)

        assert prov.list_kek_names(_PREFIX) == [_NAME, second]

    def test_filters_out_another_deployments_keys(self):
        foreign = f"{_RING}/cryptoKeys/other-team-1"
        api = _FakeApi(keys={_NAME: _key(_NAME), foreign: _key(foreign)})
        prov = _provisioner(api)

        assert prov.list_kek_names(_PREFIX) == [_NAME]

    def test_provider_error_is_funneled(self):
        def _boom(method, url, token, body):
            raise urllib.error.HTTPError(url, 403, "Forbidden", None, None)

        prov = _provisioner(_FakeApi())
        prov._http = _boom

        with pytest.raises(KekEnumerationError):
            prov.list_kek_names(_PREFIX)


class TestStateCheck:
    def test_enabled_reads_active(self):
        api = _FakeApi(keys={_NAME: _key(_NAME)})
        prov = _provisioner(api)

        assert prov.describe_kek_state(_NAME).state == KekState.ACTIVE

    def test_scheduled_reads_pending_with_its_date(self):
        api = _FakeApi(
            keys={_NAME: _key(_NAME, primary_state="DESTROY_SCHEDULED", destroy_time="2026-08-01T12:00:00Z")}
        )
        prov = _provisioner(api)

        state = prov.describe_kek_state(_NAME)

        assert state.is_pending_deletion is True
        assert state.effective_at == _aware(2026, 8, 1, 12, 0)

    def test_absent_key_reads_unknown(self):
        # Never active: the key may have been deleted at the console, or the
        # caller may lack cryptoKeys.get on it.
        prov = _provisioner(_FakeApi())

        assert prov.describe_kek_state(_NAME).state == KekState.UNKNOWN

    def test_disabled_reads_unknown(self):
        # It exists and is not being deleted, but it cannot encrypt either, and
        # active is documented to mean usable.
        api = _FakeApi(keys={_NAME: _key(_NAME, primary_state="DISABLED")})
        prov = _provisioner(api)

        assert prov.describe_kek_state(_NAME).state == KekState.UNKNOWN

    def test_a_failed_probe_degrades_to_unknown(self):
        def _boom(method, url, token, body):
            raise urllib.error.HTTPError(url, 500, "Server Error", None, None)

        prov = _provisioner(_FakeApi())
        prov._http = _boom

        assert prov.describe_kek_state(_NAME).state == KekState.UNKNOWN


class TestDestroyTimeParsing:
    def test_truncates_nanoseconds(self):
        # Cloud KMS reports nanoseconds, which fromisoformat rejects.
        prov = _provisioner(_FakeApi())

        assert prov._destroy_time("2026-08-01T12:00:00.123456789Z") == _aware(2026, 8, 1, 12, 0, 0, 123456)

    def test_missing_value_falls_back_to_the_configured_window(self):
        prov = _provisioner(_FakeApi(), PROVIDER_DELETION_WINDOW_DAYS=2)

        parsed = prov._destroy_time(None)

        assert parsed.tzinfo is not None
        assert 1 < (parsed - datetime.datetime.now(datetime.UTC)).total_seconds() / 86400 <= 2


class TestRotation:
    """Cloud KMS pairs rotationPeriod with nextRotationTime, and the delete path
    clears both under one field mask. Creation has to set both for the same reason."""

    def test_creation_sets_both_rotation_fields(self):
        api = _FakeApi()
        prov = _provisioner(api, KEK_ROTATION_PERIOD_DAYS=1)

        prov.ensure_kek(_NAME, SiloRef("default", "team-1"))

        body = next(c for c in api.calls if c[0] == "POST")[2]
        assert body["rotationPeriod"] == "86400s"
        assert body["nextRotationTime"].endswith("Z")

    def test_days_are_rendered_as_cloud_kms_seconds(self):
        # KEK_ROTATION_PERIOD_DAYS is provider-neutral; each provisioner renders it
        # in its own provider's units.
        api = _FakeApi()
        prov = _provisioner(api, KEK_ROTATION_PERIOD_DAYS=90)

        prov.ensure_kek(_NAME, SiloRef("default", "team-1"))

        body = next(c for c in api.calls if c[0] == "POST")[2]
        assert body["rotationPeriod"] == "7776000s"

    def test_the_first_rotation_is_one_period_out(self):
        api = _FakeApi()
        prov = _provisioner(api, KEK_ROTATION_PERIOD_DAYS=1)

        prov.ensure_kek(_NAME, SiloRef("default", "team-1"))

        body = next(c for c in api.calls if c[0] == "POST")[2]
        when = datetime.datetime.strptime(body["nextRotationTime"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.UTC)
        assert 0.9 < (when - datetime.datetime.now(datetime.UTC)).total_seconds() / 86400 <= 1

    def test_no_rotation_configured_sets_neither(self):
        api = _FakeApi()
        prov = _provisioner(api)

        prov.ensure_kek(_NAME, SiloRef("default", "team-1"))

        body = next(c for c in api.calls if c[0] == "POST")[2]
        assert "rotationPeriod" not in body
        assert "nextRotationTime" not in body

    def test_an_unreadable_period_is_refused_at_construction(self):
        # Caught at deploy rather than at the first encrypt, where Cloud KMS
        # rejects the key *creation* over a malformed duration.
        api = _FakeApi()
        with pytest.raises(EncryptionConfigurationError):
            _provisioner(api, KEK_ROTATION_PERIOD_DAYS="90 days")

    def test_a_period_under_the_floor_is_refused_at_construction(self):
        api = _FakeApi()
        with pytest.raises(EncryptionConfigurationError):
            _provisioner(api, KEK_ROTATION_PERIOD_DAYS=0)

    def test_deleting_a_rotating_key_clears_the_schedule_first(self):
        api = _FakeApi(
            keys={_NAME: _key(_NAME, rotation="86400s")},
            versions={_NAME: [_version(_NAME, 1, "ENABLED")]},
        )
        prov = _provisioner(api)

        prov.delete_kek(_NAME, SiloRef("default", "team-1"), owner_prefix=_PREFIX)

        patches = api.urls("PATCH")
        assert patches[0] == f"{_NAME}?updateMask=rotationPeriod,nextRotationTime"
        # Cleared before anything is destroyed, or Cloud KMS adds a fresh enabled
        # version to a key this deployment believes it destroyed.
        assert api.urls("POST").index(f"{_NAME}/cryptoKeyVersions/1:destroy") >= 0
