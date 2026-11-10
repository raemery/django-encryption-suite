"""Tests for the reconcile discovery-sync onto the durable KeyEncryptionKey rows.

``run_reconcile`` now persists a trustworthy enumeration: it discovers
never-tracked keys, stamps the orphan / last-reconciled annotations, confirms a
``deletion_requested`` key the listing shows gone, and flags drift — all
non-destructive, and skipped entirely when enumeration is unavailable.
"""

from __future__ import annotations

import datetime

import pytest
from django.utils import timezone

from encryption_suite import lifecycle
from encryption_suite.models import KeyEncryptionKey, KeyLifecycleEvent
from encryption_suite.reconcile_service import run_reconcile
from tests.adapters import FakeKmsAdapterBase
from tests.factories import make_kek_row

_PREFIX = "alias/es-prod-"
_PROVIDER = "fly"
_LIVE = ["team-1", "team-2"]
_PAST = timezone.now() - datetime.timedelta(days=1)


class _FakeSilo:
    supports_enumeration = True

    def __init__(self, uids=_LIVE):
        self._uids = uids

    def iter_silos(self):
        return list(self._uids)

    def get_silo_uid(self, s):
        return s


class _FakeStrategy:
    def __init__(self, owner_prefix=_PREFIX):
        self._owner_prefix = owner_prefix

    def owner_prefix(self):
        return self._owner_prefix

    def get_kek_id(self, ref):
        return _PREFIX + ref.uid


class _FakeProvisioner:
    supports_delete = True
    supports_enumeration = True

    def __init__(self, names):
        self._names = names

    def list_kek_names(self, owner_prefix):
        return list(self._names)


class _FakeKms(FakeKmsAdapterBase):
    kms_provider = _PROVIDER


@pytest.fixture(autouse=True)
def _fake_kms_is_silo_kms(configured_kms):
    configured_kms(_PROVIDER)


@pytest.fixture
def patch_registry(monkeypatch):
    def _apply(*, names, silo=None, strategy=None):
        monkeypatch.setattr("encryption_suite.registry.get_silo_adapter", lambda key_set="default": silo or _FakeSilo())
        monkeypatch.setattr(
            "encryption_suite.registry.get_kek_strategy_adapter", lambda name=None: strategy or _FakeStrategy()
        )
        monkeypatch.setattr("encryption_suite.registry.get_kek_provisioner", lambda name=None: _FakeProvisioner(names))
        monkeypatch.setattr("encryption_suite.registry.get_kms_adapter", lambda name=None: _FakeKms())

    return _apply


def _scheduled_requested_kek(name, *, when=_PAST):
    row = make_kek_row(
        key_store=_PROVIDER,
        kek_resource_name=name,
        owner_prefix=_PREFIX,
    )
    row.record_event(lifecycle.EVENT_DELETION_REQUESTED, trigger=lifecycle.TRIGGER_DIRECT, kms_deletion_at=when)
    return row


@pytest.mark.django_db
def test_discovers_untracked_keys(patch_registry):
    patch_registry(names=[_PREFIX + u for u in _LIVE])

    result = run_reconcile()

    rows = KeyEncryptionKey.objects.filter(key_store=_PROVIDER)
    assert rows.count() == 2
    assert all(r.events.filter(event=lifecycle.EVENT_DISCOVERED).exists() for r in rows)
    assert all(r.status == lifecycle.STATUS_ACTIVE for r in rows)
    assert all(r.is_orphaned is not None for r in rows)
    assert set(result.discovered) == {_PREFIX + u for u in _LIVE}
    # Each discovery appends two events: `discovered` — when a key this deployment
    # did not create first became observable, a fact worth keeping, and never
    # `created`, since reconcile saw the key rather than making it — plus the
    # silo verb recording the orphan annotation the row is born with. Without the
    # second, a discovered key's flag has no explanation in the ledger at all.
    # Neither moves status, so the rows stay `active`.
    events = KeyLifecycleEvent.objects.all()
    assert events.count() == 4
    assert {e.event for e in events} == {
        lifecycle.EVENT_DISCOVERED,
        # These keys back live silos, so they are born not-orphaned.
        lifecycle.EVENT_SILO_FOUND,
    }
    assert {e.kek_resource_name for e in events} == {_PREFIX + u for u in _LIVE}
    assert all(e.created_at is not None for e in events)


@pytest.mark.django_db
def test_annotates_orphan(patch_registry):
    orphan = _PREFIX + "team-9"  # listed but backs no live silo
    patch_registry(names=[_PREFIX + u for u in _LIVE] + [orphan])

    run_reconcile()

    row = KeyEncryptionKey.objects.get(kek_resource_name=orphan)
    assert row.is_orphaned is True
    live = KeyEncryptionKey.objects.get(kek_resource_name=_PREFIX + "team-1")
    assert live.is_orphaned is False


@pytest.mark.django_db
def test_confirms_requested_deletion_when_gone(patch_registry):
    gone = _PREFIX + "team-9"
    _scheduled_requested_kek(gone)
    # Listing does NOT include the gone key → enumeration confirms it deleted.
    patch_registry(names=[_PREFIX + u for u in _LIVE])

    result = run_reconcile()

    row = KeyEncryptionKey.objects.get(kek_resource_name=gone)
    assert row.status == lifecycle.STATUS_DELETED
    assert gone in result.confirmed_deleted
    event = row.events.get(event=lifecycle.EVENT_DELETED)
    assert event.reason == KeyLifecycleEvent.REASON_CONFIRMED_BY_RECONCILE


@pytest.mark.django_db
def test_flags_overdue_drift_when_still_listed(patch_registry):
    still_here = _PREFIX + "team-1"
    _scheduled_requested_kek(still_here)  # requested, effective date passed
    patch_registry(names=[_PREFIX + u for u in _LIVE])  # but still listed

    result = run_reconcile()

    assert still_here in result.drift_overdue
    # Not auto-confirmed: it is still on the provider.
    assert KeyEncryptionKey.objects.get(kek_resource_name=still_here).status == lifecycle.STATUS_DELETION_REQUESTED


@pytest.mark.django_db
def test_flags_missing_active_key_as_drift(patch_registry):
    missing = _PREFIX + "team-2"
    make_kek_row(
        key_store=_PROVIDER,
        kek_resource_name=missing,
        owner_prefix=_PREFIX,
    )
    # Listing omits team-2 → an active owned key vanished outside this application.
    patch_registry(names=[_PREFIX + "team-1"])

    result = run_reconcile()

    assert missing in result.drift_missing
    # Never auto-deleted — drift is flagged, not actioned.
    assert KeyEncryptionKey.objects.get(kek_resource_name=missing).status == lifecycle.STATUS_ACTIVE


@pytest.mark.django_db
def test_degraded_enumeration_skips_sync(patch_registry):
    # No owner prefix → KMS enumeration cannot run → no rows touched at all.
    patch_registry(names=[_PREFIX + u for u in _LIVE], strategy=_FakeStrategy(owner_prefix=None))

    result = run_reconcile()

    assert result.kms_kek_names is None
    assert result.discovered == ()
    assert not KeyEncryptionKey.objects.exists()


@pytest.mark.django_db
def test_rediscovery_does_not_append_a_second_event(patch_registry):
    """The event marks first sighting, not every pass.

    Reconcile runs on a schedule; an event per pass would bury the one entry that
    says when the key appeared under thousands that say it is still there.
    """
    patch_registry(names=[_PREFIX + u for u in _LIVE])

    run_reconcile()
    run_reconcile()

    assert KeyLifecycleEvent.objects.filter(event=lifecycle.EVENT_DISCOVERED).count() == 2


class _StateProvisioner(_FakeProvisioner):
    """Enumerates like the base fake, and reports provider-side state."""

    supports_state_check = True

    def __init__(self, names, *, pending=(), effective_at=None, explode=False):
        super().__init__(names)
        self._pending = set(pending)
        self._effective_at = effective_at
        self._explode = explode
        self.probed: list[str] = []

    def describe_kek_state(self, name):
        from encryption_suite.adapters.keks.provisioners import AbstractKekProvisioner

        self.probed.append(name)
        return AbstractKekProvisioner.describe_kek_state(self, name)

    def _do_describe_kek_state(self, name):
        from encryption_suite.adapters.keks.provisioners import KekState

        if self._explode:
            raise RuntimeError("provider 500")
        if name in self._pending:
            return KekState(state=KekState.PENDING_DELETION, effective_at=self._effective_at)
        return KekState(state=KekState.ACTIVE)


@pytest.mark.django_db
def test_an_orphan_already_being_deleted_is_recorded_as_requested(monkeypatch):
    """The case a discovered row cannot otherwise learn.

    A row is born `active` because that is the field default, not because anyone
    checked. Until something encrypts under the key, nothing discovers that the
    provider already has a deletion running — so it reads as an orphan awaiting a
    decision when the work is already done.
    """
    orphan = _PREFIX + "team-9"
    when = timezone.now() + datetime.timedelta(days=7)
    prov = _StateProvisioner([_PREFIX + u for u in _LIVE] + [orphan], pending=[orphan], effective_at=when)
    monkeypatch.setattr("encryption_suite.registry.get_silo_adapter", lambda key_set="default": _FakeSilo())
    monkeypatch.setattr("encryption_suite.registry.get_kek_strategy_adapter", lambda name=None: _FakeStrategy())
    monkeypatch.setattr("encryption_suite.registry.get_kek_provisioner", lambda name=None: prov)
    monkeypatch.setattr("encryption_suite.registry.get_kms_adapter", lambda name=None: _FakeKms())

    run_reconcile()

    row = KeyEncryptionKey.objects.get(kek_resource_name=orphan)
    assert row.status == lifecycle.STATUS_DELETION_REQUESTED
    assert row.kms_deletion_at == when
    assert row.events.get(event=lifecycle.EVENT_DELETION_REQUESTED).reason == (
        KeyLifecycleEvent.REASON_OBSERVED_AT_PROVIDER
    )
    # Orphan candidates are probed first, so a deployment large enough to reach
    # the probe cap spends the budget on the set the report is built around.
    assert prov.probed[0] == orphan


@pytest.mark.django_db
def test_an_in_use_key_already_being_deleted_is_recorded_as_requested(monkeypatch):
    """The silo reads healthy while its key is being destroyed.

    An in-use key mid-deletion is more urgent than an orphan mid-deletion, not
    less: nothing in the app has any reason to notice, and because the data
    encryption key is cached per process, reads keep succeeding until the cache
    turns over. Reconcile is the page an operator consults before making a
    deletion decision, so it must not report a scheduled key as ready.
    """
    in_use = _PREFIX + "team-2"
    when = timezone.now() + datetime.timedelta(days=7)
    prov = _StateProvisioner([_PREFIX + u for u in _LIVE], pending=[in_use], effective_at=when)
    monkeypatch.setattr("encryption_suite.registry.get_silo_adapter", lambda key_set="default": _FakeSilo())
    monkeypatch.setattr("encryption_suite.registry.get_kek_strategy_adapter", lambda name=None: _FakeStrategy())
    monkeypatch.setattr("encryption_suite.registry.get_kek_provisioner", lambda name=None: prov)
    monkeypatch.setattr("encryption_suite.registry.get_kms_adapter", lambda name=None: _FakeKms())

    run_reconcile()

    row = KeyEncryptionKey.objects.get(kek_resource_name=in_use)
    assert row.status == lifecycle.STATUS_DELETION_REQUESTED
    assert row.kms_deletion_at == when
    assert row.events.get(event=lifecycle.EVENT_DELETION_REQUESTED).reason == (
        KeyLifecycleEvent.REASON_OBSERVED_AT_PROVIDER
    )


@pytest.mark.django_db
def test_a_row_already_recorded_scheduled_costs_no_probe(monkeypatch):
    """The cap counts provider round trips, not rows considered."""
    requested = _PREFIX + "team-1"
    _scheduled_requested_kek(requested)
    prov = _StateProvisioner([_PREFIX + u for u in _LIVE])
    monkeypatch.setattr("encryption_suite.registry.get_silo_adapter", lambda key_set="default": _FakeSilo())
    monkeypatch.setattr("encryption_suite.registry.get_kek_strategy_adapter", lambda name=None: _FakeStrategy())
    monkeypatch.setattr("encryption_suite.registry.get_kek_provisioner", lambda name=None: prov)
    monkeypatch.setattr("encryption_suite.registry.get_kms_adapter", lambda name=None: _FakeKms())

    run_reconcile()

    assert requested not in prov.probed


@pytest.mark.django_db
def test_a_failed_probe_leaves_the_row_untouched(monkeypatch):
    """`unknown` must never be read as healthy, or as anything at all."""
    orphan = _PREFIX + "team-9"
    prov = _StateProvisioner([_PREFIX + u for u in _LIVE] + [orphan], explode=True)
    monkeypatch.setattr("encryption_suite.registry.get_silo_adapter", lambda key_set="default": _FakeSilo())
    monkeypatch.setattr("encryption_suite.registry.get_kek_strategy_adapter", lambda name=None: _FakeStrategy())
    monkeypatch.setattr("encryption_suite.registry.get_kek_provisioner", lambda name=None: prov)
    monkeypatch.setattr("encryption_suite.registry.get_kms_adapter", lambda name=None: _FakeKms())

    run_reconcile()  # must not raise

    row = KeyEncryptionKey.objects.get(kek_resource_name=orphan)
    assert row.status == lifecycle.STATUS_ACTIVE


@pytest.mark.django_db
def test_a_provisioner_without_the_capability_is_not_probed(monkeypatch):
    orphan = _PREFIX + "team-9"
    prov = _FakeProvisioner([_PREFIX + u for u in _LIVE] + [orphan])  # supports_state_check absent
    monkeypatch.setattr("encryption_suite.registry.get_silo_adapter", lambda key_set="default": _FakeSilo())
    monkeypatch.setattr("encryption_suite.registry.get_kek_strategy_adapter", lambda name=None: _FakeStrategy())
    monkeypatch.setattr("encryption_suite.registry.get_kek_provisioner", lambda name=None: prov)
    monkeypatch.setattr("encryption_suite.registry.get_kms_adapter", lambda name=None: _FakeKms())

    run_reconcile()

    assert KeyEncryptionKey.objects.get(kek_resource_name=orphan).status == lifecycle.STATUS_ACTIVE


@pytest.mark.django_db
def test_a_failed_probe_logs_one_clean_english_line(monkeypatch, caplog):
    """Advisory probe: a note, not a stack trace, and no raw provider string."""
    orphan = _PREFIX + "team-9"
    prov = _StateProvisioner([_PREFIX + u for u in _LIVE] + [orphan], explode=True)
    monkeypatch.setattr("encryption_suite.registry.get_silo_adapter", lambda key_set="default": _FakeSilo())
    monkeypatch.setattr("encryption_suite.registry.get_kek_strategy_adapter", lambda name=None: _FakeStrategy())
    monkeypatch.setattr("encryption_suite.registry.get_kek_provisioner", lambda name=None: prov)
    monkeypatch.setattr("encryption_suite.registry.get_kms_adapter", lambda name=None: _FakeKms())

    with caplog.at_level("WARNING", logger="encryption_suite.adapters.keks.provisioners"):
        run_reconcile()

    records = [r for r in caplog.records if "would not report this key's state" in r.getMessage()]
    # One line per probed key, each naming its own key: a probe that fails for
    # every key is still one note per key, never a traceback.
    assert len(records) == len(prov.probed)
    assert all(r.exc_info is None for r in records)  # no traceback into package internals
    assert orphan in records[0].getMessage()


@pytest.mark.django_db
def test_a_deleted_row_is_never_annotated_as_an_orphan(patch_registry):
    """Deleted here, still listed there: drift, not a cleanup awaiting an operator.

    The annotation would otherwise re-mark a terminal row every pass, contradicting
    the changelist's own rule that a destroyed key has nothing depending on it.
    """
    gone = _PREFIX + "team-9"
    row = make_kek_row(
        key_store=_PROVIDER,
        kek_resource_name=gone,
    )
    row.record_event(lifecycle.EVENT_DELETED, trigger=lifecycle.TRIGGER_DIRECT)
    patch_registry(names=[_PREFIX + u for u in _LIVE] + [gone])

    run_reconcile()

    row.refresh_from_db()
    assert row.status == lifecycle.STATUS_DELETED
    assert row.is_orphaned is False


@pytest.mark.django_db
def test_a_pass_records_the_trigger_the_caller_names(patch_registry):
    """How the pass was started is the one thing the sweep cannot know itself.

    A command or a schedule leaves the default, ``automated``. The admin page
    passes ``indirect``: an operator asked for a pass, and every event it writes
    followed from that — none of them was asked for by name. Without this a
    page-run pass wrote rows reading "Script or schedule" beside the user and IP
    of the person who pressed the button.
    """
    patch_registry(names=[_PREFIX + u for u in _LIVE])

    run_reconcile(trigger=lifecycle.TRIGGER_INDIRECT)

    assert {e.trigger for e in KeyLifecycleEvent.objects.all()} == {lifecycle.TRIGGER_INDIRECT}


@pytest.mark.django_db
def test_a_pass_that_names_no_trigger_is_automated(patch_registry):
    patch_registry(names=[_PREFIX + u for u in _LIVE])

    run_reconcile()

    assert {e.trigger for e in KeyLifecycleEvent.objects.all()} == {lifecycle.TRIGGER_AUTOMATED}


class _FailingSilo(_FakeSilo):
    def iter_silos(self):
        raise RuntimeError("database went away mid-listing")


@pytest.mark.django_db
def test_an_unresolved_kek_name_is_not_logged_when_the_keys_are_never_listed(patch_registry, caplog):
    """A KEK_MAP with no template has no owner prefix: unmapped silos raise every pass, and nothing can be orphaned."""
    patch_registry(names=[], strategy=_PartlyUnresolvableStrategy(owner_prefix=None))

    with caplog.at_level("WARNING", logger="encryption_suite"):
        result = run_reconcile()

    assert result.kms_kek_names is None
    assert not [r for r in caplog.records if "could not be resolved" in r.getMessage()]


class _PartlyUnresolvableStrategy(_FakeStrategy):
    def get_kek_id(self, ref):
        if ref.uid == "team-2":
            raise RuntimeError("template could not be rendered")
        return super().get_kek_id(ref)


@pytest.mark.django_db
def test_an_untyped_silo_listing_error_is_logged_once(patch_registry, caplog):
    """A project adapter's own error would otherwise leave "listing failed" with nothing in the log."""
    patch_registry(names=[_PREFIX + u for u in _LIVE], silo=_FailingSilo())

    with caplog.at_level("ERROR", logger="encryption_suite"):
        result = run_reconcile()

    assert result.kms_kek_names is None
    (line,) = [r for r in caplog.records if r.levelname == "ERROR"]
    message = line.getMessage()
    assert "error_code=silo_enumeration_unavailable" in message
    assert "adapter=_FailingSilo" in message
    assert "database went away mid-listing" in message
    assert line.exc_info is None


@pytest.mark.django_db
def test_an_unresolved_kek_name_is_logged_once_per_pass(patch_registry, caplog):
    """The skipped silo's key can read as an orphan, so the pass says why."""
    patch_registry(names=[_PREFIX + u for u in _LIVE], strategy=_PartlyUnresolvableStrategy())

    with caplog.at_level("WARNING", logger="encryption_suite"):
        result = run_reconcile()

    assert _PREFIX + "team-2" in result.report.kms_orphan_keks
    (line,) = [r for r in caplog.records if "could not be resolved" in r.getMessage()]
    message = line.getMessage()
    assert line.levelname == "WARNING"
    assert "silos=1" in message
    assert 'first_silo="default:team-2"' in message
    assert "template could not be rendered" in message
