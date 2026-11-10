"""Enumeration reads the rows, not the default manager's view of them.

A default manager that filters is a statement about what an application shows —
soft-deleted, suspended, archived. The silo questions are about what the database
holds: a workspace in the trash still owns every row it ever had, and someone can
still restore it and read them. Ask those questions through ``objects`` and a
hidden silo comes back as an orphan whose key can be destroyed.

The data half of this already holds — ``HiddenNote`` proves a hidden row is still
rotated. These are the silo half.
"""

from __future__ import annotations

import pytest

from encryption_suite import deletion
from encryption_suite.silo_ref import SiloRef
from encryption_suite.silos import queryset_for_model_label
from tests.testapp.models import Workspace
from tests.testapp.silo import WorkspaceSiloAdapter

pytestmark = pytest.mark.django_db


@pytest.fixture
def deleted_workspace():
    """A workspace in the trash: hidden from ``objects``, every row still present."""
    from django.utils import timezone

    return Workspace.objects.create(name="Acme", deleted_at=timezone.now())


def test_the_helper_reads_past_a_filtering_default_manager(deleted_workspace):
    assert not Workspace.objects.filter(pk=deleted_workspace.pk).exists()

    assert list(queryset_for_model_label("testapp.Workspace")) == [deleted_workspace]


def test_a_hidden_silo_is_enumerated(deleted_workspace):
    """Left out of this list, its keys read as orphans on the next reconcile."""
    assert list(WorkspaceSiloAdapter().iter_silos()) == [deleted_workspace]


def test_a_hidden_silo_still_exists(deleted_workspace):
    """The point lookup, which answers the deletion gate."""
    adapter = WorkspaceSiloAdapter()
    uid = adapter.get_silo_uid(deleted_workspace)

    assert adapter.silo_exists(uid) is True
    assert adapter.silo_for_uid(uid) == deleted_workspace


def test_a_hidden_silo_is_still_named_for_an_operator(deleted_workspace):
    adapter = WorkspaceSiloAdapter()

    assert adapter.describe_silo(adapter.get_silo_uid(deleted_workspace)) == "Acme"


def test_the_deletion_gate_keeps_a_hidden_silos_key(monkeypatch, deleted_workspace):
    """The payoff, and the reason this is not a cosmetic preference.

    The gate refuses on *cannot say* as carefully as on *yes* — but a filtered
    manager produces neither. It produces a confident ``False``, which is the one
    answer the gate acts on, and the act is irreversible.
    """
    adapter = WorkspaceSiloAdapter()
    monkeypatch.setattr("encryption_suite.registry.get_silo_adapter", lambda key_set="default": adapter)

    reason = deletion.dek_retain_reason(SiloRef("default", adapter.get_silo_uid(deleted_workspace)))

    assert reason == deletion.RETAIN_SILO_LIVE


def test_a_silo_that_is_really_gone_is_not_kept(monkeypatch):
    """The other direction: the change must not make every key unshreddable."""
    adapter = WorkspaceSiloAdapter()
    monkeypatch.setattr("encryption_suite.registry.get_silo_adapter", lambda key_set="default": adapter)

    assert deletion.dek_retain_reason(SiloRef("default", "workspace-999999")) is None
