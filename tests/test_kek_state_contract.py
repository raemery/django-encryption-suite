"""Provider-agnostic tests for the KEK state-check contract on AbstractKekProvisioner.

Covers the capability guard and the degrade-to-unknown rule. Per-provider state
reads are tested in each provider's own suite against its KMS API.
"""

from __future__ import annotations

import logging

import pytest

from encryption_suite.adapters.keks.provisioners import (
    AbstractKekProvisioner,
    KekState,
    NullKekProvisioner,
)

_NAME = "alias/es-prod-team-1"


class _ProbingProvisioner(AbstractKekProvisioner):
    """State-check-capable provisioner that answers from memory instead of a KMS."""

    supports_state_check = True

    def __init__(self, options=None, *, state=None, error=None):
        super().__init__(options or {})
        self._state = state
        self._error = error
        self.called_with = "<unset>"

    def ensure_kek(self, kek_resource_name, silo_ref):  # pragma: no cover - unused here
        pass

    def _do_describe_kek_state(self, kek_resource_name):
        self.called_with = kek_resource_name
        if self._error is not None:
            raise self._error
        return self._state


class TestStateGuards:
    def test_unsupported_provisioner_reports_unknown_without_probing(self):
        assert NullKekProvisioner({}).describe_kek_state(_NAME).state == KekState.UNKNOWN

    def test_supported_provisioner_returns_the_provider_answer(self):
        prov = _ProbingProvisioner(state=KekState(state=KekState.ACTIVE))

        assert prov.describe_kek_state(_NAME).state == KekState.ACTIVE
        assert prov.called_with == _NAME

    def test_a_provider_error_degrades_to_unknown(self, caplog):
        """Advisory only: a broken probe must annotate nothing, not break the page."""
        prov = _ProbingProvisioner(error=RuntimeError("connection reset"))

        with caplog.at_level(logging.WARNING, logger="encryption_suite"):
            assert prov.describe_kek_state(_NAME).state == KekState.UNKNOWN

        assert "would not report this key's state" in caplog.text


class TestSupportsStateCheckMatchesReality:
    """The flag must match whether each shipped provisioner implements a state read.

    Only a provider with a deletion window has a state worth reporting, so the
    three that delete immediately deliberately leave it off. A provisioner that
    implements ``_do_describe_kek_state`` without setting the flag is never
    called; one that sets the flag without the method raises
    ``NotImplementedError`` into the funnel and degrades to unknown on every
    probe, which reads as a provider that never answers.
    """

    @pytest.mark.parametrize(
        ("module", "cls_name", "expected"),
        [
            ("provisioners_aws", "AwsKekProvisioner", True),
            ("provisioners_gcp", "GcpKekProvisioner", True),
            ("provisioners_azure", "AzureKekProvisioner", True),
            ("provisioners_ibm", "IbmKekProvisioner", True),
            ("provisioners_oci", "OciKekProvisioner", True),
            ("provisioners_fly", "FlyKmsKekProvisioner", False),
            ("provisioners_infisical", "InfisicalKekProvisioner", False),
            ("provisioners_hashicorp", "HashiCorpVaultKekProvisioner", False),
        ],
    )
    def test_flag_matches_implementation(self, module, cls_name, expected):
        mod = pytest.importorskip(f"encryption_suite.adapters.keks.{module}")
        cls = getattr(mod, cls_name)

        assert cls.supports_state_check is expected
        implements = cls._do_describe_kek_state is not AbstractKekProvisioner._do_describe_kek_state
        assert implements is expected, (
            f"{cls_name} {'implements' if implements else 'does not implement'} _do_describe_kek_state "
            f"but supports_state_check is {cls.supports_state_check!r}."
        )
