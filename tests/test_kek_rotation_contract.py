"""Provider-agnostic tests for the ``KEK_ROTATION_PERIOD_DAYS`` contract on
AbstractKekProvisioner.

Covers the capability guard and the declared floor/ceiling, all checked at
construction so ``manage.py check`` reports them at deploy rather than the
provider rejecting the value at key creation. Per-provider rules a range cannot
express, and the writing of the policy itself, are tested in each provider's own
suite.
"""

from __future__ import annotations

import pytest

from encryption_suite.adapters.keks.provisioners import AbstractKekProvisioner
from encryption_suite.exceptions import EncryptionConfigurationError


class _RotatingProvisioner(AbstractKekProvisioner):
    supports_rotation_policy = True

    def ensure_kek(self, kek_resource_name, silo_ref):  # pragma: no cover - unused here
        pass


class TestCapabilityGuard:
    def test_a_provisioner_that_cannot_schedule_refuses_the_option(self):
        """Silently ignoring it would leave keys unrotated while the operator
        believes a schedule is running — the failure nothing else detects."""

        class _NoPolicy(_RotatingProvisioner):
            supports_rotation_policy = False

        with pytest.raises(EncryptionConfigurationError) as ei:
            _NoPolicy({"KEK_ROTATION_PERIOD_DAYS": 90})

        assert "KEK_ROTATION_PERIOD_DAYS" in ei.value.detail

    def test_no_option_is_always_fine(self):
        class _NoPolicy(_RotatingProvisioner):
            supports_rotation_policy = False

        assert _NoPolicy({}).rotation_period_days() is None

    def test_a_non_numeric_value_is_refused(self):
        with pytest.raises(EncryptionConfigurationError):
            _RotatingProvisioner({"KEK_ROTATION_PERIOD_DAYS": "quarterly"})


class TestDeclaredRange:
    def test_a_value_under_the_floor_is_refused(self):
        class _Floored(_RotatingProvisioner):
            minimum_rotation_days = 90

        with pytest.raises(EncryptionConfigurationError) as ei:
            _Floored({"KEK_ROTATION_PERIOD_DAYS": 30})

        assert "90" in ei.value.detail

    def test_a_value_over_the_ceiling_is_refused(self):
        class _Capped(_RotatingProvisioner):
            maximum_rotation_days = 360

        with pytest.raises(EncryptionConfigurationError) as ei:
            _Capped({"KEK_ROTATION_PERIOD_DAYS": 400})

        assert "360" in ei.value.detail

    def test_the_bounds_themselves_are_accepted(self):
        class _Bounded(_RotatingProvisioner):
            minimum_rotation_days = 90
            maximum_rotation_days = 360

        assert _Bounded({"KEK_ROTATION_PERIOD_DAYS": 90}).rotation_period_days() == 90
        assert _Bounded({"KEK_ROTATION_PERIOD_DAYS": 360}).rotation_period_days() == 360

    def test_an_undeclared_bound_checks_nothing(self):
        """``None`` means the ceiling was never established, not that the provider
        has none — an over-large value then surfaces as the provider's own
        rejection instead of at deploy."""
        assert _RotatingProvisioner.minimum_rotation_days is None
        assert _RotatingProvisioner.maximum_rotation_days is None

        assert _RotatingProvisioner({"KEK_ROTATION_PERIOD_DAYS": 99999}).rotation_period_days() == 99999


class TestDeclaredBounds:
    """The ledger of what each shipped provisioner says its provider accepts.

    A bound that drifts from the provider's real limit turns a deploy-time
    refusal into a key-creation failure, or the reverse — refusing a value the
    provider would have taken.
    """

    @pytest.mark.parametrize(
        ("module", "cls_name", "supported", "minimum", "maximum"),
        [
            ("provisioners_aws", "AwsKekProvisioner", True, 90, 2560),
            ("provisioners_gcp", "GcpKekProvisioner", True, 1, None),
            ("provisioners_azure", "AzureKekProvisioner", True, 7, None),
            ("provisioners_ibm", "IbmKekProvisioner", True, 30, 360),
            ("provisioners_oci", "OciKekProvisioner", True, 60, 365),
            ("provisioners_fly", "FlyKmsKekProvisioner", False, None, None),
            ("provisioners_infisical", "InfisicalKekProvisioner", False, None, None),
            ("provisioners_hashicorp", "HashiCorpVaultKekProvisioner", True, 1, None),
        ],
    )
    def test_declared_bounds(self, module, cls_name, supported, minimum, maximum):
        mod = pytest.importorskip(f"encryption_suite.adapters.keks.{module}")
        cls = getattr(mod, cls_name)

        assert cls.supports_rotation_policy is supported
        assert cls.minimum_rotation_days == minimum
        assert cls.maximum_rotation_days == maximum
