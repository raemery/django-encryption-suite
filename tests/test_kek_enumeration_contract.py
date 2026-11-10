"""Provider-agnostic tests for the KEK enumeration (reconcile) contract on
AbstractKekProvisioner.

Covers the two list guards (capability + owner-prefix), the defensive
owner-prefix filter, and funnel conversion of a raw provider error. Per-provider
listing behavior is tested in each provider's own suite against its KMS API.
"""

from __future__ import annotations

import logging

import pytest

from encryption_suite.adapters.keks.provisioners import (
    AbstractKekProvisioner,
    NullKekProvisioner,
)
from encryption_suite.exceptions import KekEnumerationError

_PREFIX = "alias/es-prod-"


class _ListingProvisioner(AbstractKekProvisioner):
    """Enumeration-capable provisioner that returns a canned list instead of a KMS."""

    supports_enumeration = True

    def __init__(self, options=None, *, names=None):
        super().__init__(options or {})
        self._names = list(names) if names is not None else []
        self.called_with = "<unset>"

    def ensure_kek(self, kek_resource_name, silo_ref):  # pragma: no cover - unused here
        pass

    def _do_list_kek_names(self, owner_prefix):
        self.called_with = owner_prefix
        return list(self._names)


class TestListGuards:
    def test_lists_owned_names(self):
        prov = _ListingProvisioner(names=[_PREFIX + "team-1", _PREFIX + "team-2"])
        assert prov.list_kek_names(_PREFIX) == [_PREFIX + "team-1", _PREFIX + "team-2"]
        assert prov.called_with == _PREFIX

    def test_filters_out_foreign_names(self):
        # Even if the provider over-lists (shared ring, foreign project), names
        # without the owner prefix are dropped — reconcile only ever sees ours.
        prov = _ListingProvisioner(names=[_PREFIX + "team-1", "alias/other-team-9", "key/foreign"])
        assert prov.list_kek_names(_PREFIX) == [_PREFIX + "team-1"]

    def test_refuses_when_owner_prefix_none(self):
        # Shared / KEK_MAP configs derive no prefix → ownership unprovable.
        prov = _ListingProvisioner(names=[_PREFIX + "team-1"])
        with pytest.raises(KekEnumerationError):
            prov.list_kek_names(None)
        assert prov.called_with == "<unset>"  # never reached the provider call

    def test_refuses_when_provisioner_cannot_enumerate(self):
        # NullKekProvisioner (supports_enumeration=False) must refuse outright.
        prov = NullKekProvisioner({})
        with pytest.raises(KekEnumerationError):
            prov.list_kek_names(_PREFIX)


class _ExplodingListingProvisioner(AbstractKekProvisioner):
    """Enumeration-capable provisioner whose provider call raises a raw error."""

    supports_enumeration = True

    def ensure_kek(self, kek_resource_name, silo_ref):  # pragma: no cover
        pass

    def _do_list_kek_names(self, owner_prefix):
        raise RuntimeError("provider 500: kms list unavailable")


def test_raw_provider_error_is_funneled_to_typed_error():
    # A raw provider error from _do_list_kek_names must not escape — it is
    # funneled into KekEnumerationError (original chained as __cause__).
    prov = _ExplodingListingProvisioner({})
    with pytest.raises(KekEnumerationError) as ei:
        prov.list_kek_names(_PREFIX)
    assert isinstance(ei.value.__cause__, RuntimeError)


def test_refusal_logs_slug(caplog):
    prov = NullKekProvisioner({})
    with caplog.at_level(logging.ERROR, logger="encryption_suite.adapters.keks.provisioners"):
        with pytest.raises(KekEnumerationError):
            prov.list_kek_names(_PREFIX)
    assert "error_code=kek_enumeration_unavailable" in caplog.text


class TestSupportsEnumerationMatchesReality:
    """The flag must match whether each shipped provisioner implements listing.

    Enumeration is fanned out one provider at a time, so this table is the record
    of which are done. The mismatch that matters: a flag set without the method
    turns a reconcile pass into a provider error instead of the intended
    detection-unavailable degradation.
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

        assert cls.supports_enumeration is expected
        implements = cls._do_list_kek_names is not AbstractKekProvisioner._do_list_kek_names
        assert implements is expected, (
            f"{cls_name} {'implements' if implements else 'does not implement'} _do_list_kek_names "
            f"but supports_enumeration is {cls.supports_enumeration!r}."
        )
