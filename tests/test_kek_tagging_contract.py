"""Provider-agnostic tests for the KEK tagging contract.

Covers ``build_tags`` (operator pass-through, the ``supports_tagging``
short-circuit, override behavior), the ``describe_tagging`` status the startup
check and test console share, and a per-provisioner assertion that the
``supports_tagging`` flag matches what each provisioner actually does. That last
one is the point of the file: the flag and the behavior drifting apart is what
made ``supports_tagging`` dead weight before.
"""

from __future__ import annotations

import pytest

from encryption_suite.adapters.keks.provisioners import (
    AbstractKekProvisioner,
    NullKekProvisioner,
    describe_tagging,
)


class _TaggingProvisioner(AbstractKekProvisioner):
    """Minimal provisioner that can carry tags."""

    supports_tagging = True

    def ensure_kek(self, kek_resource_name, silo_ref):  # pragma: no cover - unused here
        pass


class _NonTaggingProvisioner(AbstractKekProvisioner):
    """Minimal provisioner whose provider takes no metadata at create time."""

    def ensure_kek(self, kek_resource_name, silo_ref):  # pragma: no cover - unused here
        pass


class TestBuildTags:
    def test_returns_operator_tags_unmodified(self):
        tags = {"ManagedBy": "encryption-suite", "Environment": "prod", "CostCenter": "cc-42"}
        provisioner = _TaggingProvisioner({"TAGS": tags})

        built = provisioner.build_tags("silo-1")

        # More than one pair, byte-for-byte: a single-pair assertion would still
        # pass if something collapsed the dict.
        assert built == tags

    def test_does_not_stamp_silo_uid(self):
        provisioner = _TaggingProvisioner({"TAGS": {"Environment": "prod"}})

        built = provisioner.build_tags("silo-1")

        assert "silo_uid" not in built
        assert "silo-1" not in built.values()

    def test_result_is_a_copy(self):
        options = {"TAGS": {"Environment": "prod"}}
        provisioner = _TaggingProvisioner(options)

        provisioner.build_tags("silo-1")["Environment"] = "mutated"

        assert options["TAGS"] == {"Environment": "prod"}

    def test_empty_without_tags(self):
        assert _TaggingProvisioner({}).build_tags("silo-1") == {}

    def test_short_circuits_when_unsupported(self):
        provisioner = _NonTaggingProvisioner({"TAGS": {"Environment": "prod"}})

        assert provisioner.build_tags("silo-1") == {}

    def test_override_may_add_several_pairs(self):
        class _Override(_TaggingProvisioner):
            def build_tags(self, silo_uid):
                tags = super().build_tags(silo_uid)
                tags["tenant"] = silo_uid
                tags["cost-center"] = f"cc-{silo_uid}"
                return tags

        built = _Override({"TAGS": {"Environment": "prod"}}).build_tags("silo-1")

        assert built == {"Environment": "prod", "tenant": "silo-1", "cost-center": "cc-silo-1"}

    def test_override_short_circuits_when_unsupported(self):
        """A subclass calling super() pays nothing when tags cannot be written."""

        class _Override(_NonTaggingProvisioner):
            def build_tags(self, silo_uid):
                return super().build_tags(silo_uid)

        assert _Override({"TAGS": {"Environment": "prod"}}).build_tags("silo-1") == {}


class TestDescribeTagging:
    def test_reports_dropped_when_configured_but_unsupported(self):
        status = describe_tagging(_NonTaggingProvisioner({"TAGS": {"a": "1", "b": "2"}}))

        assert status.tag_count == 2
        assert status.configured is True
        assert status.supported is False
        assert status.dropped is True

    def test_not_dropped_when_supported(self):
        status = describe_tagging(_TaggingProvisioner({"TAGS": {"a": "1"}}))

        assert status.dropped is False

    def test_not_dropped_when_nothing_configured(self):
        status = describe_tagging(_NonTaggingProvisioner({}))

        assert status.configured is False
        assert status.dropped is False

    def test_counts_defined_tag_namespaces(self):
        status = describe_tagging(
            _TaggingProvisioner({"DEFINED_TAGS": {"Operations": {"CostCenter": "42"}, "Finance": {"Project": "x"}}})
        )

        assert status.defined_tag_namespace_count == 2
        assert status.configured is True

    def test_null_provisioner_cannot_tag(self):
        assert describe_tagging(NullKekProvisioner({})).supported is False


class TestSupportsTaggingMatchesReality:
    """The flag must match what each shipped provisioner actually does.

    Imports are per-provider and optional: most provisioner modules import their
    provider SDK lazily, but any that does not would fail collection here rather
    than report a mismatch.
    """

    @pytest.mark.parametrize(
        ("module", "cls_name", "expected"),
        [
            ("provisioners_aws", "AwsKekProvisioner", True),
            ("provisioners_gcp", "GcpKekProvisioner", True),
            ("provisioners_azure", "AzureKekProvisioner", True),
            ("provisioners_oci", "OciKekProvisioner", True),
            ("provisioners_fly", "FlyKmsKekProvisioner", False),
            ("provisioners_hashicorp", "HashiCorpVaultKekProvisioner", False),
            ("provisioners_ibm", "IbmKekProvisioner", False),
            ("provisioners_infisical", "InfisicalKekProvisioner", False),
        ],
    )
    def test_flag_matches_provider_capability(self, module, cls_name, expected):
        mod = pytest.importorskip(f"encryption_suite.adapters.keks.{module}")
        cls = getattr(mod, cls_name)

        assert cls.supports_tagging is expected, (
            f"{cls_name}.supports_tagging is {cls.supports_tagging!r}; expected {expected!r}. "
            "Set it to match whether the provider's create-key call carries operator tags."
        )
