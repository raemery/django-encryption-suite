"""Reconcile Keys view: what the two "without a live silo" tables list.

Test-console keys are listed inline with a verdict rather than split into a
section of their own. The invariant that matters is that a test key is *visible*
in both tables — the key row and the key itself — whether or not it is currently
in use. A section built from the key rows could not show a key whose rows were
already deleted, which is precisely the leftover an operator needs to find.
"""

from __future__ import annotations

import pytest
from django.contrib import admin as django_admin
from django.contrib.auth.models import AnonymousUser
from django.test import RequestFactory
from django.utils import timezone

from encryption_suite.admin import DataEncryptionKeyAdmin
from encryption_suite.models import DataEncryptionKey, KeyEncryptionKey
from tests.adapters import FakeKmsAdapterBase
from tests.factories import make_kek, make_kek_row

_PROVIDER = "fly"
_PREFIX = "alias/es-prod-"
_TEST_KEK = _PREFIX + "enctestkey"


class _FakeSilo:
    supports_enumeration = True
    is_in_use = lambda self: True  # noqa: E731

    def iter_silos(self):
        return ["team-1"]

    def get_silo_uid(self, s):
        return s

    def get_silo_label(self):
        return "team"


class _FakeStrategy:
    def owner_prefix(self):
        return _PREFIX

    def get_kek_id(self, ref):
        return _PREFIX + ref.uid

    def kek_disposition(self, uid):
        return KeyEncryptionKey.DISPOSITION_SILO_EXCLUSIVE


class _FakeProvisioner:
    supports_delete = True
    supports_enumeration = True
    is_in_use = lambda self: True  # noqa: E731

    def __init__(self, names):
        self._names = names

    def list_kek_names(self, owner_prefix):
        return list(self._names)


class _FakeKms(FakeKmsAdapterBase):
    kms_provider = _PROVIDER


@pytest.fixture(autouse=True)
def _fake_kms_is_silo_kms(configured_kms):
    configured_kms(_PROVIDER)

    def describe_kek(self):
        return "fake"


class _User(AnonymousUser):
    is_active = True
    is_staff = True
    is_superuser = True
    username = "alice"

    # AnonymousUser answers False to every permission whatever its flags say,
    # and the page is gated on one.
    def has_perm(self, perm, obj=None):
        return True


@pytest.fixture
def wired(monkeypatch):
    def _apply(kms_names):
        monkeypatch.setattr("encryption_suite.registry.get_silo_adapter", lambda key_set="default": _FakeSilo())
        monkeypatch.setattr("encryption_suite.registry.get_kek_strategy_adapter", lambda name=None: _FakeStrategy())
        monkeypatch.setattr(
            "encryption_suite.registry.get_kek_provisioner", lambda name=None: _FakeProvisioner(kms_names)
        )
        monkeypatch.setattr("encryption_suite.registry.get_kms_adapter", lambda name=None: _FakeKms())

    return _apply


def _test_dek():
    return DataEncryptionKey.objects.create(
        key_set="default",
        silo_uid="enctestkey",
        purpose=DataEncryptionKey.PURPOSE_TEST,
        silo_label="test",
        encrypted_keyset=b"wrapped",
        kek=make_kek(_TEST_KEK, _PROVIDER),
    )


def _context(wired, kms_names):
    wired(kms_names)
    request = RequestFactory().get("/reconcile-keys/")
    request.user = _User()
    ma = DataEncryptionKeyAdmin(DataEncryptionKey, django_admin.site)
    return ma.reconcile_keys_view(request).context_data


@pytest.mark.django_db
def test_in_use_test_key_appears_in_both_tables_as_not_applicable(wired):
    """The regression this guards: a live test key's own KEK must stay visible.

    Reconcile deliberately keeps a live test key out of the orphan set, so listing
    only orphans left its status and existence reported nowhere on the page.
    """
    _test_dek()

    context = _context(wired, [_PREFIX + "team-1", _TEST_KEK])

    dek_row = next(r for r in context["orphan_rows"] if r["kek_resource_name"] == _TEST_KEK)
    assert dek_row["is_test"] is True

    kek_row = next(r for r in context["orphan_kek_rows"] if r["name"] == _TEST_KEK)
    assert kek_row["is_test"] is True
    assert kek_row["is_orphan"] is False  # in use, just not by a real silo
    assert kek_row["kek_existence"] == {"known": True, "present": True}

    # Listed but not counted: the summary reports work to do, and a row marked
    # "not applicable" is not work. Counting it would contradict its own verdict.
    assert context["orphan_count"] == 0


@pytest.mark.django_db
def test_orphan_count_counts_only_actionable_rows(wired):
    """A real orphan alongside a test row: the count reflects one, the table two."""
    _test_dek()
    DataEncryptionKey.objects.create(
        key_set="default",
        silo_uid="team-9",  # no live silo resolves to this
        purpose=DataEncryptionKey.PURPOSE_FIELD,
        silo_label="team",
        encrypted_keyset=b"wrapped",
        kek=make_kek(_PREFIX + "team-9", _PROVIDER),
    )

    context = _context(wired, [_PREFIX + "team-1", _TEST_KEK])

    assert len(context["orphan_rows"]) == 2
    assert context["orphan_count"] == 1


@pytest.mark.django_db
def test_leftover_test_key_is_a_real_orphan(wired):
    """No key rows left, but the key is still on the provider and still billing."""
    context = _context(wired, [_PREFIX + "team-1", _TEST_KEK])

    kek_row = next(r for r in context["orphan_kek_rows"] if r["name"] == _TEST_KEK)
    assert kek_row["is_test"] is True
    assert kek_row["is_orphan"] is True


@pytest.mark.django_db
def test_a_real_orphan_is_not_marked_as_a_test_key(wired):
    abandoned = _PREFIX + "team-9"

    context = _context(wired, [_PREFIX + "team-1", abandoned])

    kek_row = next(r for r in context["orphan_kek_rows"] if r["name"] == abandoned)
    assert kek_row["is_test"] is False
    assert kek_row["is_orphan"] is True


@pytest.mark.django_db
def test_a_scheduled_orphan_still_reports_as_orphaned(wired):
    """The Orphaned column states a fact; only the count is about work to do.

    Binding the marker to the actionable classification instead made every
    scheduled orphan read "not orphaned" — contradicting both the column header
    and the `is_orphaned` field the changelists show for the same key.
    """
    abandoned = _PREFIX + "team-9"
    make_kek_row(
        key_store=_PROVIDER,
        kek_resource_name=abandoned,
        status="deletion_requested",
    )

    context = _context(wired, [_PREFIX + "team-1", abandoned])

    kek_row = next(r for r in context["orphan_kek_rows"] if r["name"] == abandoned)
    assert kek_row["is_orphan"] is True
    assert kek_row["verdict"] == "in_progress"
    assert context["kms_orphan_count"] == 1
    # Same marker rule as the silos table: listed at the provider, but a status
    # out of active means it exists without being usable.
    assert kek_row["kek_existence"]["present"] is True
    assert kek_row["kek_marker"]["state"] == "blocked"


@pytest.mark.django_db
def test_a_scheduled_dek_row_still_reports_as_orphaned(wired):
    """Orphan-ness is computed live, so it does not lag reconcile by a page load.

    The rows are built before reconcile refreshes each row's cached
    ``is_orphaned``, so reading that field here would report a fresh orphan as
    not orphaned until the next visit.
    """
    dek = DataEncryptionKey.objects.create(
        key_set="default",
        silo_uid="team-9",
        purpose=DataEncryptionKey.PURPOSE_FIELD,
        silo_label="team",
        encrypted_keyset=b"wrapped",
        kek=make_kek(_PREFIX + "team-9", _PROVIDER),
        status="deletion_scheduled",
    )
    assert dek.is_orphaned is False  # never reconciled yet

    context = _context(wired, [_PREFIX + "team-1", _PREFIX + "team-9"])

    row = next(r for r in context["orphan_rows"] if r["silo_uid"] == "team-9")
    assert row["is_orphaned"] is True
    # And it agrees with what the changelist will show once reconcile has run.
    dek.refresh_from_db()
    assert dek.is_orphaned is True


@pytest.mark.django_db
def test_a_deleted_kek_still_listed_by_the_provider_is_not_an_orphan(wired):
    """Deleted here but still listed there is drift, not a cleanup to do."""
    from encryption_suite import lifecycle

    gone = _PREFIX + "team-9"
    row = make_kek_row(key_store=_PROVIDER, kek_resource_name=gone, owner_prefix=_PREFIX)
    row.record_event(lifecycle.EVENT_DELETED, trigger=lifecycle.TRIGGER_DIRECT)

    context = _context(wired, [_PREFIX + "team-1", gone])

    kek_row = next(r for r in context["orphan_kek_rows"] if r["name"] == gone)
    assert kek_row["is_orphan"] is False
    assert context["kms_orphan_count"] == 0


@pytest.mark.django_db
def test_a_test_console_dek_row_is_not_reported_as_orphaned(wired):
    """Its sentinel UID is reserved, so the orphan question cannot be asked."""
    _test_dek()

    context = _context(wired, [_PREFIX + "team-1", _TEST_KEK])

    row = next(r for r in context["orphan_rows"] if r["kek_resource_name"] == _TEST_KEK)
    assert row["is_orphaned"] is False


@pytest.mark.django_db
def test_a_live_silos_key_is_listed_in_neither_table(wired):
    DataEncryptionKey.objects.create(
        key_set="default",
        silo_uid="team-1",
        purpose=DataEncryptionKey.PURPOSE_FIELD,
        silo_label="team",
        encrypted_keyset=b"wrapped",
        kek=make_kek(_PREFIX + "team-1", _PROVIDER),
    )

    context = _context(wired, [_PREFIX + "team-1"])

    assert context["orphan_rows"] == []
    assert [r["name"] for r in context["orphan_kek_rows"]] == []


@pytest.mark.django_db
def test_a_never_provisioned_test_key_is_not_listed(wired):
    """A sentinel name resolves whether or not the key exists.

    Listing it unconditionally would put a phantom row in the table for every
    test key that was never created.
    """
    context = _context(wired, [_PREFIX + "team-1"])  # KMS lists no test key

    assert [r["name"] for r in context["orphan_kek_rows"]] == []


def _kek_row(name, status=None, **kw):
    from encryption_suite import lifecycle

    row = make_kek_row(key_store=_PROVIDER, kek_resource_name=name, owner_prefix=_PREFIX, **kw)
    if status:
        row.record_event(status, trigger=lifecycle.TRIGGER_DIRECT)
    return row


@pytest.mark.django_db
def test_a_key_already_being_deleted_is_not_reported_as_orphaned(wired):
    """Orphan-set membership alone is too coarse for the verdict.

    A key already scheduled or requested has been acted on; calling it orphaned
    asks for work that is done and contradicts the status shown beside it.
    """
    from encryption_suite import lifecycle

    requested = _PREFIX + "team-8"
    scheduled = _PREFIX + "team-9"
    _kek_row(requested).record_event(lifecycle.EVENT_DELETION_REQUESTED, trigger=lifecycle.TRIGGER_DIRECT)
    _kek_row(scheduled).record_event(lifecycle.EVENT_DELETION_SCHEDULED, trigger=lifecycle.TRIGGER_DIRECT)

    context = _context(wired, [_PREFIX + "team-1", requested, scheduled])

    verdicts = {r["name"]: r["verdict"] for r in context["orphan_kek_rows"]}
    assert verdicts[requested] == "in_progress"
    assert verdicts[scheduled] == "in_progress"


@pytest.mark.django_db
def test_an_untouched_orphan_is_still_reported_as_orphaned(wired):
    """The actionable case must keep reading as actionable."""
    abandoned = _PREFIX + "team-9"
    _kek_row(abandoned)

    context = _context(wired, [_PREFIX + "team-1", abandoned])

    verdict = next(r["verdict"] for r in context["orphan_kek_rows"] if r["name"] == abandoned)
    assert verdict == "orphaned"


@pytest.mark.django_db
def test_a_leftover_test_key_is_still_orphaned(wired):
    """A test key nothing uses any more is a genuine cleanup item, not exempt."""
    context = _context(wired, [_PREFIX + "team-1", _TEST_KEK])

    verdict = next(r["verdict"] for r in context["orphan_kek_rows"] if r["name"] == _TEST_KEK)
    assert verdict == "orphaned"


@pytest.mark.django_db
def test_a_retained_key_reports_the_gate_refusal(wired):
    from encryption_suite import lifecycle

    retained = _PREFIX + "team-9"
    _kek_row(retained).record_event(
        lifecycle.EVENT_DELETION_FAILED,
        trigger=lifecycle.TRIGGER_DIRECT,
        reason="provisioner_cannot_delete",
        status=lifecycle.STATUS_RETAINED,
    )

    context = _context(wired, [_PREFIX + "team-1", retained])

    verdict = next(r["verdict"] for r in context["orphan_kek_rows"] if r["name"] == retained)
    assert verdict == "retained"


@pytest.mark.django_db
def test_a_scheduled_dek_is_still_counted_as_orphaned(wired):
    """The count matches the Orphaned column, so the two cannot disagree.

    A scheduled row is an orphan that has been acted on, not a row that stopped
    being an orphan. Its verdict still records that distinction, and the Status
    column beside the marker is what tells the two apart on the page.
    """
    from encryption_suite import lifecycle

    row = DataEncryptionKey.objects.create(
        key_set="default",
        silo_uid="team-9",
        purpose=DataEncryptionKey.PURPOSE_FIELD,
        silo_label="team",
        encrypted_keyset=b"wrapped",
        kek=make_kek(_PREFIX + "team-9", _PROVIDER),
    )
    row.record_event(
        lifecycle.EVENT_DELETION_SCHEDULED, trigger=lifecycle.TRIGGER_DIRECT, undeletable_until=timezone.now()
    )

    context = _context(wired, [_PREFIX + "team-1"])

    dek_row = next(r for r in context["orphan_rows"] if r["silo_uid"] == "team-9")
    assert dek_row["is_orphaned"] is True
    assert context["orphan_count"] == 1
    # Scheduled, so the key exists but will not encrypt or decrypt.
    assert dek_row["dek_marker"]["state"] == "blocked"


@pytest.mark.django_db
def test_a_scheduled_dek_gets_its_orphan_annotation(wired):
    """The changelist and the reconcile page must not disagree.

    Skipping scheduled rows left `is_orphaned = False` and a null
    an unannotated row — which reads as "checked, fine" when it means "never
    checked" — while the page listed the same row as an orphan.
    """
    from encryption_suite import lifecycle

    row = DataEncryptionKey.objects.create(
        key_set="default",
        silo_uid="team-9",
        purpose=DataEncryptionKey.PURPOSE_FIELD,
        silo_label="team",
        encrypted_keyset=b"wrapped",
        kek=make_kek(_PREFIX + "team-9", _PROVIDER),
    )
    row.record_event(
        lifecycle.EVENT_DELETION_SCHEDULED, trigger=lifecycle.TRIGGER_DIRECT, undeletable_until=timezone.now()
    )

    _context(wired, [_PREFIX + "team-1"])

    row.refresh_from_db()
    assert row.is_orphaned is True
    assert row.is_orphaned is True


@pytest.mark.django_db
def test_a_purged_tombstone_is_neither_annotated_nor_listed(wired):
    """Its keyset is already cleared, so orphan-ness decides nothing.

    Not listed either: the table exists to prompt a decision, and a key that is
    gone offers none — nothing to adopt, delete, or restore. The row stays on the
    changelist, which lists every row rather than only the actionable ones.
    """
    from encryption_suite import lifecycle

    row = DataEncryptionKey.objects.create(
        key_set="default",
        silo_uid="team-9",
        purpose=DataEncryptionKey.PURPOSE_FIELD,
        silo_label="team",
        encrypted_keyset=b"",
        status=lifecycle.STATUS_DELETED,
        kek=make_kek(_PREFIX + "team-9", _PROVIDER),
    )

    context = _context(wired, [_PREFIX + "team-1"])

    row.refresh_from_db()
    assert row.is_orphaned is False
    assert "team-9" not in {r["silo_uid"] for r in context["orphan_rows"]}
    assert context["orphan_count"] == 0


@pytest.mark.django_db
def test_a_key_being_deleted_is_listed_and_counted(wired):
    """The KMS-side summary counts the orphans, matching its Orphaned column."""
    from encryption_suite import lifecycle

    requested = _PREFIX + "team-9"
    row = make_kek_row(key_store=_PROVIDER, kek_resource_name=requested, owner_prefix=_PREFIX)
    row.record_event(lifecycle.EVENT_DELETION_REQUESTED, trigger=lifecycle.TRIGGER_DIRECT)

    context = _context(wired, [_PREFIX + "team-1", requested])

    assert [r["name"] for r in context["orphan_kek_rows"]] == [requested]
    assert context["kms_orphan_count"] == 1
    # The verdict still separates "already being deleted" from "awaiting a
    # decision"; the Status column is where that reaches the operator.
    assert context["orphan_kek_rows"][0]["verdict"] == "in_progress"


@pytest.mark.django_db
def test_both_changelist_links_filter_to_orphans(wired):
    """The link under each table must land on that table's rows.

    The data-encryption-key link filtered on `status__exact=active`, which is
    orthogonal to orphan-ness — it showed the healthy rows, the opposite of what
    the table above it lists.
    """
    # Each link renders only when its table has rows, so give both one.
    abandoned = _PREFIX + "team-9"
    DataEncryptionKey.objects.create(
        key_set="default",
        silo_uid="team-9",
        purpose=DataEncryptionKey.PURPOSE_FIELD,
        silo_label="team",
        encrypted_keyset=b"wrapped",
        kek=make_kek(abandoned, _PROVIDER),
    )
    context = _context(wired, [_PREFIX + "team-1", abandoned])
    response = _render(context)

    assert f"{context['changelist_url']}?is_orphaned__exact=1" in response
    assert f"{context['kms_changelist_url']}?is_orphaned__exact=1" in response


def _render(context):
    """Render the reconcile template with a context the view produced."""
    from django.template.loader import render_to_string

    return render_to_string("admin/encryption_suite/reconcile_keys.html", context)


@pytest.mark.django_db
def test_the_page_records_its_events_as_followed_from_the_pass(wired):
    """A person pressed a button; nobody asked for the events the pass then wrote.

    The command keeps ``automated``, which is what tells a sweep apart from an
    operator in the ledger — so the page must not read the same way beside the
    user and IP it records.
    """
    from encryption_suite import lifecycle
    from encryption_suite.models import KeyLifecycleEvent

    _context(wired, [_PREFIX + "team-1"])

    events = KeyLifecycleEvent.objects.all()
    assert events.exists()
    assert {e.trigger for e in events} == {lifecycle.TRIGGER_INDIRECT}
