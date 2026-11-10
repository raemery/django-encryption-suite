"""Provider-agnostic tests for the KEK delete contract on AbstractKekProvisioner.

Covers the two deletion guards (capability + ownership) and the DeleteOutcome
shape. Per-provider scheduled-deletion behavior is tested in each provider's
own suite against its KMS API.
"""

from __future__ import annotations

import datetime

import pytest

from encryption_suite.adapters.keks.provisioners import (
    AbstractKekProvisioner,
    DeleteOutcome,
    NullKekProvisioner,
)
from encryption_suite.exceptions import EncryptionConfigurationError, KekDeleteError
from encryption_suite.silo_ref import SiloRef

_PREFIX = "alias/es-prod-"


class _RecordingProvisioner(AbstractKekProvisioner):
    """Delete-capable provisioner that records the call instead of hitting a KMS."""

    supports_delete = True

    def __init__(self, options=None, *, scheduled=True):
        super().__init__(options or {})
        self._scheduled = scheduled
        self.deleted: list[str] = []

    def ensure_kek(self, kek_resource_name, silo_ref):  # pragma: no cover - unused here
        pass

    def _do_delete_kek(self, kek_resource_name, silo_ref):
        self.deleted.append(kek_resource_name)
        return DeleteOutcome(
            scheduled=self._scheduled,
            effective_at=datetime.datetime(2026, 6, 15, tzinfo=datetime.UTC),
        )


class TestOwnsKek:
    def test_true_when_name_has_owner_prefix(self):
        prov = _RecordingProvisioner()
        assert prov.owns_kek(_PREFIX + "team-1", _PREFIX) is True

    def test_false_when_prefix_absent_from_name(self):
        prov = _RecordingProvisioner()
        assert prov.owns_kek("alias/other-team-1", _PREFIX) is False

    def test_false_when_owner_prefix_is_none(self):
        # KEK_MAP / shared configs derive no prefix → ownership unprovable.
        prov = _RecordingProvisioner()
        assert prov.owns_kek("alias/es-prod-team-1", None) is False


class TestDeleteGuards:
    def test_deletes_owned_key_and_returns_outcome(self):
        prov = _RecordingProvisioner(scheduled=True)
        outcome = prov.delete_kek(_PREFIX + "team-1", SiloRef("default", "team-1"), owner_prefix=_PREFIX)
        assert prov.deleted == [_PREFIX + "team-1"]
        assert outcome.scheduled is True
        assert outcome.effective_at.year == 2026

    def test_immediate_delete_reports_unscheduled(self):
        prov = _RecordingProvisioner(scheduled=False)
        outcome = prov.delete_kek(_PREFIX + "team-1", SiloRef("default", "team-1"), owner_prefix=_PREFIX)
        assert outcome.scheduled is False

    def test_refuses_unowned_key(self):
        prov = _RecordingProvisioner()
        with pytest.raises(KekDeleteError):
            prov.delete_kek("alias/foreign-team-1", SiloRef("default", "team-1"), owner_prefix=_PREFIX)
        assert prov.deleted == []  # never reached the provider call

    def test_refuses_when_owner_prefix_none(self):
        prov = _RecordingProvisioner()
        with pytest.raises(KekDeleteError):
            prov.delete_kek(_PREFIX + "team-1", SiloRef("default", "team-1"), owner_prefix=None)
        assert prov.deleted == []

    def test_refuses_when_provisioner_cannot_delete(self):
        # NullKekProvisioner (supports_delete=False) must refuse outright.
        prov = NullKekProvisioner({})
        with pytest.raises(KekDeleteError):
            prov.delete_kek(_PREFIX + "team-1", SiloRef("default", "team-1"), owner_prefix=_PREFIX)


class _ExplodingProvisioner(AbstractKekProvisioner):
    """Delete-capable provisioner whose provider call raises a raw error."""

    supports_delete = True

    def ensure_kek(self, kek_resource_name, silo_ref):  # pragma: no cover
        pass

    def _do_delete_kek(self, kek_resource_name, silo_ref):
        raise RuntimeError("provider 500: kms unavailable")


def test_raw_provider_error_is_funneled_to_typed_error():
    # A raw provider error from _do_delete_kek must not escape — it is funneled
    # into KekDeleteError (with the original chained as __cause__).
    prov = _ExplodingProvisioner({})
    with pytest.raises(KekDeleteError) as ei:
        prov.delete_kek(_PREFIX + "team-1", SiloRef("default", "team-1"), owner_prefix=_PREFIX)
    assert isinstance(ei.value.__cause__, RuntimeError)


def test_successful_delete_logs_kek_delete_at_warning(caplog):
    import logging

    prov = _RecordingProvisioner()
    with caplog.at_level(logging.WARNING, logger="encryption_suite.adapters.keks.provisioners"):
        prov.delete_kek(_PREFIX + "team-1", SiloRef("default", "team-1"), owner_prefix=_PREFIX)
    # Irreversible action → WARNING (survives production INFO filtering), emitted
    # at the destruction point so every caller (command + admin) gets it.
    matching = [r for r in caplog.records if "event=" in r.getMessage()]
    assert matching, "expected a deletion log line"
    assert all(r.levelno == logging.WARNING for r in matching)
    assert "silo=default:team-1" in matching[0].getMessage()


def test_a_purge_without_a_silo_logs_n_a(caplog):
    """The purge passes no silo — a key encryption key is not tied to one there.

    Reads as a stated absence rather than a field that failed to populate.
    """
    import logging

    prov = _RecordingProvisioner()
    with caplog.at_level(logging.WARNING, logger="encryption_suite.adapters.keks.provisioners"):
        prov.delete_kek(_PREFIX + "team-1", SiloRef("default", ""), owner_prefix=_PREFIX)

    line = next(r.getMessage() for r in caplog.records if "event=" in r.getMessage())
    assert "silo=n/a" in line


def test_refusal_logs_slug(caplog):
    import logging

    prov = _RecordingProvisioner()
    with caplog.at_level(logging.ERROR, logger="encryption_suite.adapters.keks.provisioners"):
        with pytest.raises(KekDeleteError):
            prov.delete_kek("alias/foreign", SiloRef("default", "team-1"), owner_prefix=_PREFIX)
    assert "error_code=kek_delete_failed" in caplog.text


class TestDeletionWindowDays:
    """The provider window, and the test console's standing exception to it."""

    def test_defaults_when_unconfigured(self):
        prov = _RecordingProvisioner()

        assert (
            prov.deletion_window_days(SiloRef("default", "team-1"))
            == AbstractKekProvisioner.default_deletion_window_days
        )

    def test_reads_the_configured_window(self):
        prov = _RecordingProvisioner({"PROVIDER_DELETION_WINDOW_DAYS": 30})

        assert prov.deletion_window_days(SiloRef("default", "team-1")) == 30

    def test_a_test_console_silo_gets_the_provider_minimum(self):
        # The console already bypasses the package's own window, so leaving its
        # keys to sit out a production-length provider window would contradict
        # that — and stall the one workflow that proves deletion end to end.
        prov = _RecordingProvisioner({"PROVIDER_DELETION_WINDOW_DAYS": 30})
        prov.minimum_deletion_window_days = 1

        assert prov.deletion_window_days(SiloRef("default", "enctestkey")) == 1
        assert prov.deletion_window_days(SiloRef("default", "team-1")) == 30

    def test_no_minimum_declared_leaves_the_window_alone(self):
        # A provider whose deletion is immediate has no window to shorten.
        prov = _RecordingProvisioner({"PROVIDER_DELETION_WINDOW_DAYS": 30})

        assert prov.minimum_deletion_window_days is None
        assert prov.deletion_window_days(SiloRef("default", "enctestkey")) == 30

    def test_no_silo_uid_reads_the_configured_window(self):
        # State probes and fallback dates have no silo in hand.
        prov = _RecordingProvisioner({"PROVIDER_DELETION_WINDOW_DAYS": 30})
        prov.minimum_deletion_window_days = 1

        assert prov.deletion_window_days() == 30

    def test_a_window_under_the_floor_is_refused_at_construction(self):
        # Caught here rather than at the first encrypt, where the provider rejects
        # the key *creation* call with an opaque error about deletion timing.
        class _FloorProvisioner(_RecordingProvisioner):
            minimum_deletion_window_days = 1

        with pytest.raises(EncryptionConfigurationError):
            _FloorProvisioner({"PROVIDER_DELETION_WINDOW_DAYS": 0})

    def test_the_refusal_names_the_other_window(self):
        # The likely mistake: wiring this to KEY_DELETION_WINDOW_DAYS, which
        # legitimately accepts 0.
        class _FloorProvisioner(_RecordingProvisioner):
            minimum_deletion_window_days = 1

        with pytest.raises(EncryptionConfigurationError) as ei:
            _FloorProvisioner({"PROVIDER_DELETION_WINDOW_DAYS": 0})
        assert "KEY_DELETION_WINDOW_DAYS" in ei.value.detail

    def test_a_non_numeric_window_is_refused_at_construction(self):
        class _FloorProvisioner(_RecordingProvisioner):
            minimum_deletion_window_days = 1

        with pytest.raises(EncryptionConfigurationError):
            _FloorProvisioner({"PROVIDER_DELETION_WINDOW_DAYS": "soon"})

    def test_a_window_over_the_ceiling_is_refused_at_construction(self):
        class _CappedProvisioner(_RecordingProvisioner):
            maximum_deletion_window_days = 30

        with pytest.raises(EncryptionConfigurationError) as ei:
            _CappedProvisioner({"PROVIDER_DELETION_WINDOW_DAYS": 45})
        assert "30" in ei.value.detail

    def test_a_ceiling_alone_is_enough_to_validate(self):
        # The floor used to be the only gate on whether anything was checked, so a
        # provider declaring only a ceiling would have been validated against
        # nothing at all.
        class _CeilingOnly(_RecordingProvisioner):
            minimum_deletion_window_days = None
            maximum_deletion_window_days = 30

        with pytest.raises(EncryptionConfigurationError):
            _CeilingOnly({"PROVIDER_DELETION_WINDOW_DAYS": 45})

    def test_the_bounds_themselves_are_accepted(self):
        class _BoundedProvisioner(_RecordingProvisioner):
            minimum_deletion_window_days = 7
            maximum_deletion_window_days = 30

        assert (
            _BoundedProvisioner({"PROVIDER_DELETION_WINDOW_DAYS": 7}).deletion_window_days(SiloRef("default", "team-1"))
            == 7
        )
        assert (
            _BoundedProvisioner({"PROVIDER_DELETION_WINDOW_DAYS": 30}).deletion_window_days(
                SiloRef("default", "team-1")
            )
            == 30
        )

    def test_a_provider_without_a_floor_accepts_anything(self):
        # Nothing to validate against where deletion is immediate.
        prov = _RecordingProvisioner({"PROVIDER_DELETION_WINDOW_DAYS": 0})

        assert prov.deletion_window_days(SiloRef("default", "team-1")) == 0

    @pytest.mark.parametrize(
        ("module", "cls_name", "minimum", "maximum"),
        [
            ("provisioners_fly", "FlyKmsKekProvisioner", None, None),
            ("provisioners_infisical", "InfisicalKekProvisioner", None, None),
            ("provisioners_aws", "AwsKekProvisioner", 7, 30),
            ("provisioners_gcp", "GcpKekProvisioner", 1, None),
            ("provisioners_oci", "OciKekProvisioner", 7, 30),
            ("provisioners_ibm", "IbmKekProvisioner", None, None),
        ],
    )
    def test_declared_bounds(self, module, cls_name, minimum, maximum):
        # The ranges the providers actually enforce. Fly and Infisical delete
        # immediately, with no window at all. IBM has a window but no lever — its
        # length is fixed by the service — so neither bound applies and the option
        # is refused outright. A ``None`` ceiling elsewhere means undeclared, not
        # unbounded.
        mod = pytest.importorskip(f"encryption_suite.adapters.keks.{module}")
        cls = getattr(mod, cls_name)

        assert cls.minimum_deletion_window_days == minimum
        assert cls.maximum_deletion_window_days == maximum


class TestSupportsDeleteMatchesReality:
    """The flag must match whether each shipped provisioner implements deletion.

    Deletion is fanned out one provider at a time, so this table is the record of
    which are done. A provisioner that implements ``_do_delete_kek`` without
    setting the flag can never delete; one that sets the flag without the method
    fails at the provider call instead of retaining cleanly at gate 2.
    """

    @pytest.mark.parametrize(
        ("module", "cls_name", "expected"),
        [
            ("provisioners_fly", "FlyKmsKekProvisioner", True),
            ("provisioners_aws", "AwsKekProvisioner", True),
            ("provisioners_gcp", "GcpKekProvisioner", True),
            ("provisioners_azure", "AzureKekProvisioner", True),
            ("provisioners_oci", "OciKekProvisioner", True),
            ("provisioners_infisical", "InfisicalKekProvisioner", True),
            ("provisioners_hashicorp", "HashiCorpVaultKekProvisioner", True),
            ("provisioners_ibm", "IbmKekProvisioner", True),
        ],
    )
    def test_flag_matches_implementation(self, module, cls_name, expected):
        mod = pytest.importorskip(f"encryption_suite.adapters.keks.{module}")
        cls = getattr(mod, cls_name)

        assert cls.supports_delete is expected
        implements = cls._do_delete_kek is not AbstractKekProvisioner._do_delete_kek
        assert implements is expected, (
            f"{cls_name} {'implements' if implements else 'does not implement'} _do_delete_kek "
            f"but supports_delete is {cls.supports_delete!r}."
        )
