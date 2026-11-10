"""How old the key material is, and when it was last re-encrypted.

Two dates on ``DataEncryptionKey``, each answering the same question one layer
apart: ``key_material_last_generated_at`` for the data key's own bytes, and
``last_reencrypted_at`` for the key encryption key that wraps them. Neither may
answer for the other — generating a new data key is not a rewrap, and a rewrap
leaves the data key's bytes exactly as they were.

The revive case is the reason the generated-at column exists at all: reusing a
tombstone gives a row brand-new material while keeping the ``created_at`` of its
first life, so ``created_at`` cannot stand in.

Also covers the key-material findings the reconcile report derives from those
two dates, which say nothing at all on a dimension they could not inspect.
"""

from __future__ import annotations

import logging
from datetime import timedelta
from io import StringIO

import pytest
from django.contrib.auth.models import Group
from django.core.management import call_command
from django.utils import timezone

from encryption_suite import lifecycle
from encryption_suite.engine import EncryptionEngine
from encryption_suite.models import DataEncryptionKey
from encryption_suite.reconcile import (
    DETECTION_KEK_LISTING_FAILED,
    DETECTION_KEY_VERSION_PROBE_FAILED,
    DETECTION_KMS_ENUMERATION_UNAVAILABLE,
    DETECTION_NO_CRYPTOPERIOD,
    DETECTION_NO_KEY_VERSIONS,
    DETECTION_SILO_ENUMERATION_UNAVAILABLE,
    DETECTION_SILO_LISTING_FAILED,
    build_reconcile_report,
    partition_detection_reasons,
)
from encryption_suite.reconcile_service import _period_days
from encryption_suite.registry import get_engine

pytestmark = pytest.mark.django_db


@pytest.fixture(autouse=True)
def _clear_cache():
    EncryptionEngine.invalidate_cache()
    yield
    EncryptionEngine.invalidate_cache()


def _make_dek(name="acme") -> tuple[DataEncryptionKey, Group]:
    """The freshly provisioned field key for a new silo, and the silo itself."""
    group = Group.objects.create(name=name)
    engine = get_engine()
    engine.generate_and_store_keyset(group)
    return DataEncryptionKey.objects.get(silo_uid=engine.silo_adapter.get_silo_uid(group)), group


# ---------------------------------------------------------------------------
# Stamping the two dates
# ---------------------------------------------------------------------------


def test_generating_a_key_stamps_the_material_date():
    before = timezone.now()
    dek, _group = _make_dek()

    assert dek.key_material_last_generated_at is not None
    assert dek.key_material_last_generated_at >= before
    # Nothing has been rewrapped yet, so the KEK-layer date has nothing to say.
    assert dek.last_reencrypted_at is None
    assert dek.dek_key_version == 1


def test_reviving_a_tombstone_restamps_the_material_date():
    """A reused row gets new material, so the date must move — created_at will not."""
    dek, group = _make_dek()
    first_stamp = dek.key_material_last_generated_at

    # Purge: the field-clear is the crypto-shred, leaving the row as a tombstone.
    dek.encrypted_keyset = b""
    dek.status = lifecycle.STATUS_DELETED
    dek.save(update_fields=["encrypted_keyset", "status", "updated_at"])

    get_engine().generate_and_store_keyset(group)
    dek.refresh_from_db()

    assert dek.status == lifecycle.STATUS_ACTIVE
    assert dek.key_material_last_generated_at > first_stamp
    # The row is the same row, so its creation date still describes the first
    # life — which is exactly why it cannot answer how old the material is.
    assert dek.created_at < dek.key_material_last_generated_at


def test_rewrap_stamps_the_reencryption_date_and_leaves_the_material_date():
    dek, _group = _make_dek()
    generated_at = dek.key_material_last_generated_at

    out, err = StringIO(), StringIO()
    call_command("reencrypt_keys", stdout=out, stderr=err)
    assert "Re-encrypted:" in out.getvalue()

    dek.refresh_from_db()
    assert dek.last_reencrypted_at is not None
    # The bytes are unchanged; only their wrapping moved.
    assert dek.key_material_last_generated_at == generated_at
    assert dek.dek_key_version == 1


def test_dry_run_stamps_nothing():
    dek, _group = _make_dek()

    call_command("reencrypt_keys", "--dry-run", stdout=StringIO(), stderr=StringIO())

    dek.refresh_from_db()
    assert dek.last_reencrypted_at is None


# ---------------------------------------------------------------------------
# The key-material findings on the reconcile report
# ---------------------------------------------------------------------------


def _report(*, key_rows=(), overdue_cutoff=None, current_versions=None, probe_failures=(), check=True):
    """A report built with only the key-material dimension supplied."""
    return build_reconcile_report(
        stored_uids=set(),
        live_silo_uids=set(),
        expected_kek_names=set(),
        kms_kek_names=set(),
        delete_available=False,
        owner_prefix="kms_",
        check_key_material=check,
        key_rows=key_rows,
        overdue_cutoff=overdue_cutoff,
        current_versions=current_versions,
        probe_failures=probe_failures,
    )


def _row(**overrides):
    row = {
        "silo_uid": "team-1",
        "purpose": "field",
        "key_material_last_generated_at": timezone.now(),
        "last_reencrypted_at": None,
        "kek_resource_name": "kms_team-1",
        "kek_key_version": "2",
    }
    row.update(overrides)
    return row


def test_material_older_than_the_cutoff_is_overdue():
    now = timezone.now()
    old = _row(silo_uid="old", key_material_last_generated_at=now - timedelta(days=100))
    fresh = _row(silo_uid="fresh", key_material_last_generated_at=now - timedelta(days=1))

    report = _report(key_rows=[old, fresh], overdue_cutoff=now - timedelta(days=90))

    assert [r["silo_uid"] for r in report.overdue] == ["old"]
    assert DETECTION_NO_CRYPTOPERIOD not in report.degraded


def test_a_row_with_no_generation_date_is_not_called_overdue():
    """Lenient on purpose: the alternative flags every pre-existing key as ancient."""
    report = _report(
        key_rows=[_row(key_material_last_generated_at=None)],
        overdue_cutoff=timezone.now(),
    )
    assert report.overdue == ()


def test_no_cryptoperiod_degrades_rather_than_reporting_clean():
    report = _report(key_rows=[_row()], overdue_cutoff=None)

    assert report.overdue == ()
    assert DETECTION_NO_CRYPTOPERIOD in report.degraded
    assert report.cryptoperiod_declared is False


def test_a_row_wrapped_by_an_older_version_is_superseded():
    rows = [
        _row(silo_uid="behind", kek_key_version="2"),
        _row(silo_uid="current", kek_key_version="3"),
    ]
    report = _report(key_rows=rows, current_versions={"kms_team-1": "3"})

    assert [r["silo_uid"] for r in report.superseded] == ["behind"]


def test_a_key_whose_version_is_unknown_is_left_out():
    """A failed or unsupported probe must never read as 'current'."""
    rows = [
        _row(silo_uid="known", kek_resource_name="kms_a", kek_key_version="1"),
        _row(silo_uid="unknown", kek_resource_name="kms_b", kek_key_version="1"),
    ]
    report = _report(key_rows=rows, current_versions={"kms_a": "2", "kms_b": ""})

    assert [r["silo_uid"] for r in report.superseded] == ["known"]


def test_a_provider_reporting_no_versions_degrades():
    report = _report(key_rows=[_row()], current_versions={"kms_team-1": ""})

    assert report.superseded == ()
    assert DETECTION_NO_KEY_VERSIONS in report.degraded
    assert report.key_versions_available is False


def test_not_asking_is_not_the_same_as_asking_and_failing():
    """A caller that skips the dimension gets no findings *and* no degraded slug."""
    report = _report(check=False)

    assert report.degraded == ()
    assert report.key_material_checked is False


# ---------------------------------------------------------------------------
# Reading the declared period
# ---------------------------------------------------------------------------


def test_zero_days_is_a_real_period_not_an_absent_one():
    """0 declares a period that has already elapsed — everything reads overdue."""
    assert _period_days(0) == 0


@pytest.mark.parametrize("bad", ["90", -1, 1.5, True])
def test_a_bad_period_is_ignored_rather_than_honored(bad, caplog):
    """A typo must not put a wrong date in front of an auditor."""
    with caplog.at_level(logging.ERROR, logger="encryption_suite.reconcile_service"):
        assert _period_days(bad) is None
    assert "DEK_ROTATION_PERIOD_DAYS" in caplog.text


def test_a_failed_probe_is_not_reported_as_a_provider_without_versions():
    """The two reasons a version comparison comes up empty are different facts.

    A provider that identifies no version (AWS KMS, Fly KMS) is permanent and
    uninteresting; probes that failed are an incident. Sharing one slug made an
    outage indistinguishable from a configuration property.
    """
    report = _report(key_rows=[_row()], current_versions={"kms_team-1": ""}, probe_failures={"kms_team-1"})

    assert DETECTION_KEY_VERSION_PROBE_FAILED in report.degraded
    assert DETECTION_NO_KEY_VERSIONS not in report.degraded
    assert report.superseded == ()


def test_a_partial_probe_failure_is_reported_even_though_the_check_ran():
    """One unreachable key must not be silently dropped from a working check."""
    rows = [
        _row(silo_uid="known", kek_resource_name="kms_a", kek_key_version="1"),
        _row(silo_uid="unreachable", kek_resource_name="kms_b", kek_key_version="1"),
    ]
    report = _report(
        key_rows=rows,
        current_versions={"kms_a": "2", "kms_b": ""},
        probe_failures={"kms_b"},
    )

    assert [r["silo_uid"] for r in report.superseded] == ["known"]
    assert DETECTION_KEY_VERSION_PROBE_FAILED in report.degraded


def test_a_probe_failure_is_never_classified_structural():
    """Structural reasons get demoted to information; an incident must not be."""
    structural, incidental = partition_detection_reasons(
        [DETECTION_NO_CRYPTOPERIOD, DETECTION_NO_KEY_VERSIONS, DETECTION_KEY_VERSION_PROBE_FAILED]
    )

    assert DETECTION_KEY_VERSION_PROBE_FAILED in incidental
    assert DETECTION_NO_CRYPTOPERIOD in structural
    assert DETECTION_NO_KEY_VERSIONS in structural


def test_a_failed_kek_listing_is_told_apart_from_a_provisioner_that_cannot_list():
    """Same empty listing, opposite meanings — one is an incident, one is not."""
    common = dict(
        stored_uids=set(),
        live_silo_uids=set(),
        expected_kek_names=set(),
        kms_kek_names=None,
        delete_available=False,
        owner_prefix="kms_",
    )
    failed = build_reconcile_report(**common, kms_listing_failed=True)
    absent = build_reconcile_report(**common, kms_listing_failed=False)

    assert DETECTION_KEK_LISTING_FAILED in failed.degraded
    assert DETECTION_KMS_ENUMERATION_UNAVAILABLE not in failed.degraded
    assert DETECTION_KMS_ENUMERATION_UNAVAILABLE in absent.degraded
    assert DETECTION_KEK_LISTING_FAILED not in absent.degraded


def test_only_the_absent_capability_is_structural():
    """A listing that raised must never be demoted to information."""
    structural, incidental = partition_detection_reasons(
        [DETECTION_KMS_ENUMERATION_UNAVAILABLE, DETECTION_KEK_LISTING_FAILED]
    )

    assert structural == [DETECTION_KMS_ENUMERATION_UNAVAILABLE]
    assert incidental == [DETECTION_KEK_LISTING_FAILED]


def test_a_failed_silo_enumeration_is_told_apart_from_an_adapter_that_cannot():
    """The third and last pair — same shape as the two above."""
    common = dict(
        stored_uids={"team-1"},
        live_silo_uids=None,
        expected_kek_names=set(),
        kms_kek_names=set(),
        delete_available=False,
        owner_prefix="kms_",
    )
    failed = build_reconcile_report(**common, silo_listing_failed=True)
    absent = build_reconcile_report(**common, silo_listing_failed=False)

    assert DETECTION_SILO_LISTING_FAILED in failed.degraded
    assert DETECTION_SILO_ENUMERATION_UNAVAILABLE not in failed.degraded
    assert DETECTION_SILO_ENUMERATION_UNAVAILABLE in absent.degraded
    # Either way the safety rule holds: no orphan is inferred without a live set.
    assert failed.db_orphan_uids == frozenset()
    assert absent.db_orphan_uids == frozenset()


def test_every_capability_reason_is_structural_and_every_failure_is_not():
    """The full partition, so a new reason cannot be added on the wrong side."""
    capability = [
        DETECTION_NO_CRYPTOPERIOD,
        DETECTION_NO_KEY_VERSIONS,
        DETECTION_KMS_ENUMERATION_UNAVAILABLE,
        DETECTION_SILO_ENUMERATION_UNAVAILABLE,
    ]
    failures = [
        DETECTION_KEY_VERSION_PROBE_FAILED,
        DETECTION_KEK_LISTING_FAILED,
        DETECTION_SILO_LISTING_FAILED,
    ]
    structural, incidental = partition_detection_reasons(capability + failures)

    assert structural == sorted(capability)
    assert incidental == sorted(failures)
