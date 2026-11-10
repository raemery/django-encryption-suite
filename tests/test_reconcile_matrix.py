"""Provider-agnostic tests for the reconcile capability matrix.

The engine in :mod:`encryption_suite.reconcile` is pure set logic, so these
tests cover every cell of the degrade matrix without a database or a KMS:
silo-enum {on, off} x kms-enum {on, off} x owner-prefix {present, none} x delete
{on, off}. The cardinal rule under test is that any degraded dimension yields an
*empty* finding plus a ``degraded`` slug — never an inferred orphan.
"""

from __future__ import annotations

from encryption_suite.reconcile import (
    CLEANUP_AUDIT_KMS_MANUALLY,
    CLEANUP_DELETE_KEK_IN_KMS,
    DETECTION_KMS_ENUMERATION_UNAVAILABLE,
    DETECTION_NO_OWNER_PREFIX,
    DETECTION_SILO_ENUMERATION_UNAVAILABLE,
    build_cleanup_instructions,
    build_reconcile_report,
    format_detection_reasons,
)

_PREFIX = "alias/es-prod-"
# Two live silos and the KEK names they resolve to.
_LIVE = {"team-1", "team-2"}
_EXPECTED_KEKS = {_PREFIX + "team-1", _PREFIX + "team-2"}


class TestFullyCapable:
    def test_clean_when_everything_lines_up(self):
        report = build_reconcile_report(
            stored_uids=_LIVE,
            live_silo_uids=_LIVE,
            expected_kek_names=_EXPECTED_KEKS,
            kms_kek_names=_EXPECTED_KEKS,
            delete_available=True,
            owner_prefix=_PREFIX,
        )
        assert report.db_orphan_uids == frozenset()
        assert report.kms_orphan_keks == ()
        assert report.degraded == ()
        assert report.db_reconcile_available
        assert report.kms_reconcile_available
        assert report.can_auto_delete_kms_orphans

    def test_detects_db_orphan(self):
        # A DEK row for a deleted silo: stored has team-3, no longer live.
        report = build_reconcile_report(
            stored_uids=_LIVE | {"team-3"},
            live_silo_uids=_LIVE,
            expected_kek_names=_EXPECTED_KEKS,
            kms_kek_names=_EXPECTED_KEKS,
            delete_available=True,
            owner_prefix=_PREFIX,
        )
        assert report.db_orphan_uids == frozenset({"team-3"})
        assert report.kms_orphan_keks == ()

    def test_detects_kms_orphan(self):
        # A KEK on the KMS for a silo that no longer exists.
        report = build_reconcile_report(
            stored_uids=_LIVE,
            live_silo_uids=_LIVE,
            expected_kek_names=_EXPECTED_KEKS,
            kms_kek_names=_EXPECTED_KEKS | {_PREFIX + "team-9"},
            delete_available=True,
            owner_prefix=_PREFIX,
        )
        assert report.kms_orphan_keks == (_PREFIX + "team-9",)
        assert report.can_auto_delete_kms_orphans


class TestSiloEnumerationOff:
    def test_no_db_orphans_inferred_and_kms_reconcile_disabled(self):
        # live_silo_uids=None is the degraded signal. Even with a full KMS
        # listing, we cannot say which KEKs are expected, so KMS reconcile is off.
        report = build_reconcile_report(
            stored_uids=_LIVE | {"team-3"},
            live_silo_uids=None,
            expected_kek_names=set(),
            kms_kek_names=_EXPECTED_KEKS | {_PREFIX + "team-9"},
            delete_available=True,
            owner_prefix=_PREFIX,
        )
        assert report.db_orphan_uids == frozenset()
        assert report.kms_orphan_keks == ()
        assert not report.db_reconcile_available
        assert not report.kms_reconcile_available
        assert not report.can_auto_delete_kms_orphans
        assert DETECTION_SILO_ENUMERATION_UNAVAILABLE in report.degraded


class TestKmsEnumerationOff:
    def test_db_side_still_works_kms_degraded(self):
        report = build_reconcile_report(
            stored_uids=_LIVE | {"team-3"},
            live_silo_uids=_LIVE,
            expected_kek_names=_EXPECTED_KEKS,
            kms_kek_names=None,
            delete_available=True,
            owner_prefix=_PREFIX,
        )
        assert report.db_orphan_uids == frozenset({"team-3"})
        assert report.db_reconcile_available
        assert report.kms_orphan_keks == ()
        assert not report.kms_reconcile_available
        assert not report.can_auto_delete_kms_orphans
        assert DETECTION_KMS_ENUMERATION_UNAVAILABLE in report.degraded


class TestNoOwnerPrefix:
    def test_kms_reconcile_off_when_ownership_unprovable(self):
        # Shared / KEK_MAP config: owner_prefix None. Even a KMS listing cannot
        # be attributed to this deployment, so KMS reconcile is off.
        report = build_reconcile_report(
            stored_uids=_LIVE,
            live_silo_uids=_LIVE,
            expected_kek_names=_EXPECTED_KEKS,
            kms_kek_names=_EXPECTED_KEKS,
            delete_available=True,
            owner_prefix=None,
        )
        assert report.kms_orphan_keks == ()
        assert not report.kms_reconcile_available
        assert DETECTION_NO_OWNER_PREFIX in report.degraded
        # DB side is unaffected by ownership.
        assert report.db_reconcile_available


class TestDeleteOff:
    def test_kms_orphans_reported_but_not_auto_deletable(self):
        # enumerate-yes / delete-no tier: orphans are surfaced for manual cleanup.
        report = build_reconcile_report(
            stored_uids=_LIVE,
            live_silo_uids=_LIVE,
            expected_kek_names=_EXPECTED_KEKS,
            kms_kek_names=_EXPECTED_KEKS | {_PREFIX + "team-9"},
            delete_available=False,
            owner_prefix=_PREFIX,
        )
        assert report.kms_orphan_keks == (_PREFIX + "team-9",)
        assert report.kms_reconcile_available
        assert not report.can_auto_delete_kms_orphans


def test_format_detection_reasons_is_readable_and_deduped():
    text = format_detection_reasons(
        [
            DETECTION_SILO_ENUMERATION_UNAVAILABLE,
            DETECTION_KMS_ENUMERATION_UNAVAILABLE,
            DETECTION_SILO_ENUMERATION_UNAVAILABLE,  # dupe
        ]
    )
    assert "silo adapter cannot enumerate" in text
    assert "provisioner cannot list" in text
    # de-duplicated: the silo phrase appears once
    assert text.count("silo adapter cannot enumerate") == 1


def test_format_detection_reasons_unknown_slug_falls_back():
    assert format_detection_reasons(["mystery_slug"]) == "mystery_slug"


class TestCleanupInstructions:
    def test_clean_report_yields_no_instructions(self):
        report = build_reconcile_report(
            stored_uids=_LIVE,
            live_silo_uids=_LIVE,
            expected_kek_names=_EXPECTED_KEKS,
            kms_kek_names=_EXPECTED_KEKS,
            delete_available=True,
            owner_prefix=_PREFIX,
        )
        assert build_cleanup_instructions(report, key_store="aws", owner_prefix=_PREFIX) == []

    def test_delete_in_kms_per_orphan_when_delete_unavailable(self):
        # enumerate-yes / delete-no: precise per-key delete guidance.
        report = build_reconcile_report(
            stored_uids=_LIVE,
            live_silo_uids=_LIVE,
            expected_kek_names=_EXPECTED_KEKS,
            kms_kek_names=_EXPECTED_KEKS | {_PREFIX + "team-9"},
            delete_available=False,
            owner_prefix=_PREFIX,
        )
        instructions = build_cleanup_instructions(report, key_store="aws", owner_prefix=_PREFIX)
        assert len(instructions) == 1
        step = instructions[0]
        assert step.action == CLEANUP_DELETE_KEK_IN_KMS
        assert step.kek_resource_name == _PREFIX + "team-9"
        assert step.key_store == "aws"
        assert _PREFIX + "team-9" in step.text
        assert "aws" in step.text

    def test_audit_manually_when_kms_enumeration_unavailable(self):
        report = build_reconcile_report(
            stored_uids=_LIVE,
            live_silo_uids=_LIVE,
            expected_kek_names=_EXPECTED_KEKS,
            kms_kek_names=None,
            delete_available=True,
            owner_prefix=_PREFIX,
        )
        instructions = build_cleanup_instructions(report, key_store="gcp", owner_prefix=_PREFIX)
        assert len(instructions) == 1
        step = instructions[0]
        assert step.action == CLEANUP_AUDIT_KMS_MANUALLY
        assert step.kek_resource_name is None
        # Audit guidance scopes by prefix and names the specific degraded reason.
        assert _PREFIX in step.text
        assert "provisioner cannot list" in step.text

    def test_audit_manually_without_prefix_omits_prefix_scope(self):
        # Shared / KEK_MAP: no owner prefix, so audit text cannot scope by name.
        report = build_reconcile_report(
            stored_uids=_LIVE,
            live_silo_uids=_LIVE,
            expected_kek_names=_EXPECTED_KEKS,
            kms_kek_names=_EXPECTED_KEKS,
            delete_available=True,
            owner_prefix=None,
        )
        instructions = build_cleanup_instructions(report, key_store="azure", owner_prefix=None)
        assert len(instructions) == 1
        assert instructions[0].action == CLEANUP_AUDIT_KMS_MANUALLY
        assert "no owner prefix" in instructions[0].text

    def test_silo_enumeration_off_yields_audit_instruction(self):
        # Detection-unavailable: cannot list orphans, so only the audit step.
        report = build_reconcile_report(
            stored_uids=_LIVE | {"team-3"},
            live_silo_uids=None,
            expected_kek_names=set(),
            kms_kek_names=_EXPECTED_KEKS,
            delete_available=True,
            owner_prefix=_PREFIX,
        )
        instructions = build_cleanup_instructions(report, key_store="oci", owner_prefix=_PREFIX)
        actions = {i.action for i in instructions}
        assert actions == {CLEANUP_AUDIT_KMS_MANUALLY}

    def test_provider_label_falls_back_when_unnamed(self):
        report = build_reconcile_report(
            stored_uids=_LIVE,
            live_silo_uids=_LIVE,
            expected_kek_names=_EXPECTED_KEKS,
            kms_kek_names=_EXPECTED_KEKS | {_PREFIX + "team-9"},
            delete_available=False,
            owner_prefix=_PREFIX,
        )
        step = build_cleanup_instructions(report, key_store=None, owner_prefix=_PREFIX)[0]
        assert "the KMS provider" in step.text
