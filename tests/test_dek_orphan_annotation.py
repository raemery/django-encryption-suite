"""Reconcile stamps the cached orphan annotation onto DataEncryptionKey rows.

The DEK-side annotation (``is_orphaned``) is gated on *silo* enumeration alone —
unlike the KMS-side annotation, which additionally needs a provisioner that can
list keys and an owner prefix. These tests pin that separation: the column must
still be stamped on a deployment where KMS-side reconcile is unavailable, because
a permanent "not orphaned" reading would be a false negative, the one direction
reconcile must never take.

They also pin the write discipline: the annotation moves only when the answer
changes, and each change appends a ``silo_found`` / ``silo_not_found`` event. A
pass that learns nothing must leave every row — and every ``updated_at`` — alone.
"""

from __future__ import annotations

import pytest

from encryption_suite import lifecycle
from encryption_suite.adapters.silos.system import SystemSiloAdapter
from encryption_suite.models import DataEncryptionKey
from encryption_suite.reconcile_service import run_reconcile
from encryption_suite.silo_ref import SiloRef
from tests.adapters import FakeKmsAdapterBase
from tests.factories import make_kek


def _events(row):
    """The silo observation verbs recorded against *row*, oldest first."""
    return list(
        row.events.filter(event__in=(lifecycle.EVENT_SILO_FOUND, lifecycle.EVENT_SILO_NOT_FOUND))
        .order_by("created_at")
        .values_list("event", flat=True)
    )


_PREFIX = "alias/es-prod-"
_LIVE = ["team-1"]


class _FakeSilo:
    def __init__(self, *, supports_enumeration=True, uids=_LIVE):
        self.supports_enumeration = supports_enumeration
        self._uids = uids

    def iter_silos(self):
        return list(self._uids)

    def get_silo_uid(self, s):
        return s


class _FakeStrategy:
    def __init__(self, *, owner_prefix=_PREFIX):
        self._owner_prefix = owner_prefix

    def owner_prefix(self):
        return self._owner_prefix

    def get_kek_id(self, ref):
        return _PREFIX + ref.uid


class _FakeProvisioner:
    def __init__(self, *, supports_enumeration=True):
        self.supports_enumeration = supports_enumeration
        self.supports_delete = True

    def list_kek_names(self, owner_prefix):
        return [_PREFIX + u for u in _LIVE]


class _FakeKms(FakeKmsAdapterBase):
    kms_provider = "fly"


@pytest.fixture(autouse=True)
def _fake_kms_is_silo_kms(configured_kms):
    configured_kms("fly")


@pytest.fixture
def patch_registry(monkeypatch):
    def _apply(*, silo=None, provisioner=None):
        monkeypatch.setattr(
            "encryption_suite.registry.get_silo_adapter",
            lambda key_set="default": SystemSiloAdapter() if key_set == "system" else silo or _FakeSilo(),
        )
        monkeypatch.setattr("encryption_suite.registry.get_kek_strategy_adapter", lambda name=None: _FakeStrategy())
        monkeypatch.setattr(
            "encryption_suite.registry.get_kek_provisioner", lambda name=None: provisioner or _FakeProvisioner()
        )
        monkeypatch.setattr("encryption_suite.registry.get_kms_adapter", lambda name=None: _FakeKms())

    return _apply


def _make_row(silo_uid, purpose=DataEncryptionKey.PURPOSE_FIELD):
    return DataEncryptionKey.objects.create(
        key_set="default",
        silo_uid=silo_uid,
        purpose=purpose,
        silo_label="team",
        encrypted_keyset=b"x",
        kek=make_kek(_PREFIX + silo_uid, "fly"),
    )


@pytest.mark.django_db
def test_dead_silo_is_flagged_and_live_silo_is_not(patch_registry):
    live = _make_row("team-1")
    dead = _make_row("team-9")
    patch_registry()

    run_reconcile()

    live.refresh_from_db()
    dead.refresh_from_db()
    assert dead.is_orphaned is True
    assert live.is_orphaned is False
    assert _events(dead) == [lifecycle.EVENT_SILO_NOT_FOUND]
    # The live row was never orphaned, so nothing changed and nothing is recorded.
    assert _events(live) == []


@pytest.mark.django_db
def test_annotation_runs_without_kms_enumeration(patch_registry):
    # The KMS half is unavailable, so kms_orphan_keks cannot be computed — but
    # the DEK half only needs the live silo set, so the column is still stamped.
    dead = _make_row("team-9")
    patch_registry(provisioner=_FakeProvisioner(supports_enumeration=False))

    result = run_reconcile()

    assert result.report.kms_reconcile_available is False
    dead.refresh_from_db()
    assert dead.is_orphaned is True


@pytest.mark.django_db
def test_degraded_silo_enumeration_stamps_nothing(patch_registry):
    # No trustworthy live set: flagging anything here would be a false orphan.
    dead = _make_row("team-9")
    patch_registry(silo=_FakeSilo(supports_enumeration=False))

    run_reconcile()

    dead.refresh_from_db()
    assert dead.is_orphaned is False
    assert _events(dead) == []


@pytest.mark.django_db
def test_test_console_rows_are_never_flagged(patch_registry):
    from encryption_suite.test_console import _field_uid

    test_row = _make_row(_field_uid(), purpose=DataEncryptionKey.PURPOSE_TEST)
    patch_registry()

    run_reconcile()

    test_row.refresh_from_db()
    assert test_row.is_orphaned is False
    assert _events(test_row) == []


@pytest.mark.django_db
def test_a_second_pass_that_learns_nothing_writes_nothing(patch_registry):
    """The whole point of change-only writes: a quiet reconcile is free.

    Without this, a scheduled daily run rewrites every key row every day and
    ``updated_at`` degrades into "when did reconcile last run" — which is what
    ``last_reconciled_at`` used to mean, and why it was removed.
    """
    dead = _make_row("team-9")
    patch_registry()

    run_reconcile()
    dead.refresh_from_db()
    first_touch = dead.updated_at

    run_reconcile()
    dead.refresh_from_db()

    assert dead.updated_at == first_touch
    # And the ledger records the transition once, not once per pass.
    assert _events(dead) == [lifecycle.EVENT_SILO_NOT_FOUND]


@pytest.mark.django_db
def test_a_silo_coming_back_records_the_other_verb(patch_registry):
    """Both directions are observations worth recording, not just the bad one."""
    row = _make_row("team-9")
    patch_registry()
    run_reconcile()

    # The silo exists again: a restore, or a UID that resolves once more.
    patch_registry(silo=_FakeSilo(uids={"team-1", "team-9"}))
    run_reconcile()

    row.refresh_from_db()
    assert row.is_orphaned is False
    assert _events(row) == [lifecycle.EVENT_SILO_NOT_FOUND, lifecycle.EVENT_SILO_FOUND]


@pytest.mark.django_db
def test_a_discovered_key_records_the_flag_it_is_born_with(patch_registry):
    """A key born orphaned must say so in the ledger, not only in the column.

    Only the change loop fired before, so a discovered key's annotation had no
    explanation at all — which defeats the point of the ledger carrying the
    answer instead of a timestamp column.
    """
    from encryption_suite.models import KeyEncryptionKey

    patch_registry(provisioner=_FakeProvisioner())
    run_reconcile()

    row = KeyEncryptionKey.objects.get(kek_resource_name=_PREFIX + "team-1")
    verbs = [e.event for e in row.events.order_by("created_at")]
    assert verbs[0] == lifecycle.EVENT_DISCOVERED
    # team-1 is live, so this key is born backed.
    assert lifecycle.EVENT_SILO_FOUND in verbs
    assert row.is_orphaned is False


@pytest.mark.django_db
def test_the_silo_lifecycle_annotates_without_waiting_for_reconcile(patch_registry):
    """The live sequence, with no reconcile click between the steps.

    Previously the flag only moved when reconcile happened to run, so between a
    silo's deletion and the next pass a row read `deletion_scheduled` beside
    `is_orphaned = False` — two columns contradicting each other for as long as
    the reconcile interval, up to a day on a schedule.
    """
    from encryption_suite.deletion import schedule_dek_deletion  # noqa: F401
    from encryption_suite.models import KeyEncryptionKey

    # A key discovered before its silo exists: born orphaned.
    patch_registry(silo=_FakeSilo(uids=set()))
    run_reconcile()
    kek = KeyEncryptionKey.objects.get(kek_resource_name=_PREFIX + "team-1")
    assert kek.is_orphaned is True

    # The silo appears and provisions a data key against that same key.
    row = _make_row("team-1")
    row.kek = kek
    row.save(update_fields=["kek"])
    from encryption_suite.registry import get_engine

    get_engine()._clear_kek_orphan(kek, SiloRef("default", "team-1"), trigger=lifecycle.TRIGGER_INDIRECT)

    kek.refresh_from_db()
    assert kek.is_orphaned is False
    assert kek.events.filter(event=lifecycle.EVENT_SILO_FOUND).exists()


@pytest.mark.django_db
def test_the_test_console_clears_a_stale_orphan_flag_too(patch_registry):
    """The console provisions its own keys, so it needs the same fix separately.

    Its key is discovered as an orphan on a fresh database — no PURPOSE_TEST row
    names it yet — and reconcile counts it as expected the moment one does. The
    flag has to move at that moment, not at the next pass.
    """
    from encryption_suite.registry import get_engine

    patch_registry()
    kek = make_kek(_PREFIX + "console", "fly")
    kek.is_orphaned = True
    kek.save(update_fields=["is_orphaned", "updated_at"])

    get_engine()._clear_kek_orphan(kek, SiloRef("default", "enctestkey"), trigger=lifecycle.TRIGGER_DIRECT)

    kek.refresh_from_db()
    assert kek.is_orphaned is False
    assert kek.events.filter(event=lifecycle.EVENT_SILO_FOUND).exists()


@pytest.mark.django_db
def test_the_system_silo_is_exempt_but_a_team_key_on_the_system_kek_is_not(patch_registry):
    """The exemption is keyed on the row's silo UID, never on the KEK wrapping it.

    With the scoped kind's KMS slot on an env store a team's keys are wrapped by shared too. When
    that team is deleted they are orphans like any other; only the system silo's
    own three keys are always backed.
    """
    from encryption_suite.conf import SYSTEM_SILO_UID

    system_kek = make_kek("shared", "system")

    def _on_system_kek(silo_uid, purpose=DataEncryptionKey.PURPOSE_FIELD, key_set="default"):
        return DataEncryptionKey.objects.create(
            key_set=key_set,
            silo_uid=silo_uid,
            purpose=purpose,
            silo_label="team",
            encrypted_keyset=b"x",
            kek=system_kek,
        )

    system_rows = [
        _on_system_kek(SYSTEM_SILO_UID, purpose, key_set="system")
        for purpose in (
            DataEncryptionKey.PURPOSE_FIELD,
            DataEncryptionKey.PURPOSE_FILE,
            DataEncryptionKey.PURPOSE_INDEX,
        )
    ]
    live_team = _on_system_kek("team-1")
    deleted_team = _on_system_kek("team-9")
    patch_registry()

    run_reconcile()

    for row in (*system_rows, live_team):
        row.refresh_from_db()
        assert row.is_orphaned is False
    deleted_team.refresh_from_db()
    assert deleted_team.is_orphaned is True
