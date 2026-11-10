"""Resolving a silo UID back to something an operator recognizes.

A UID is derived from something that will never be reissued — usually a
surrogate key — which makes it stable and unrecognizable. ``describe_silo`` is
the one-way trip back, and it is purely informational: nothing gates on it, and
every failure degrades to ``""`` rather than breaking the page that shows it.
"""

from __future__ import annotations

import pytest
from django.contrib.auth.models import Group

from encryption_suite.adapters.silos.base import AbstractSiloAdapter
from tests.factories import make_dek
from tests.silo import GroupSiloAdapter


class _Unenumerable(AbstractSiloAdapter):
    """An adapter that cannot list its silos, like the composite one."""

    def get_current_silo(self):  # pragma: no cover - unused
        return None

    def get_silo_uid(self, silo) -> str:
        return f"thing-{silo.pk}"

    def get_silo_label(self) -> str:
        return "thing"


class _Enumerable(_Unenumerable):
    """Exercises the base class's walk, which every adapter inherits."""

    supports_enumeration = True

    def iter_silos(self):
        return Group.objects.all()


@pytest.mark.django_db
class TestTheBaseWalk:
    def test_matches_on_the_uid_the_adapter_derives(self):
        group = Group.objects.create(name="Acme Corporation")

        assert _Enumerable().describe_silo(f"thing-{group.pk}") == "Acme Corporation"

    def test_an_unknown_uid_yields_empty(self):
        assert _Enumerable().describe_silo("thing-999999") == ""

    def test_an_adapter_that_cannot_enumerate_yields_empty(self):
        # Not a failure — the composite adapter is deliberately in this position,
        # and "" means "cannot say", which the admin renders as a fallback.
        group = Group.objects.create(name="Acme Corporation")

        assert _Unenumerable().describe_silo(f"thing-{group.pk}") == ""

    def test_an_enumeration_failure_yields_empty(self, monkeypatch):
        # An adapter whose enumeration is broken must not take down the page
        # that merely wanted to label a row.
        adapter = _Enumerable()
        monkeypatch.setattr(type(adapter), "iter_silos", lambda self: (_ for _ in ()).throw(RuntimeError("down")))

        assert adapter.describe_silo("thing-1") == ""


@pytest.mark.django_db
class TestThePointQuery:
    """``GenericModelSiloAdapter`` reads the field value back out of the UID."""

    def test_resolves_the_name(self):
        group = Group.objects.create(name="Acme Corporation")

        assert GroupSiloAdapter().describe_silo(f"group-{group.pk}") == "Acme Corporation"

    def test_a_uid_from_another_silo_label_yields_empty(self):
        # Rows outlive a settings change, so a row written by a different adapter
        # can be sitting in the table. Matching its UID against this model would
        # name the wrong silo.
        group = Group.objects.create(name="Acme Corporation")

        assert GroupSiloAdapter().describe_silo(f"team-{group.pk}") == ""

    def test_a_uid_the_field_cannot_hold_yields_empty(self):
        # "group-abc" against an integer pk raises in the ORM rather than missing.
        assert GroupSiloAdapter().describe_silo("group-abc") == ""

    def test_a_deleted_silo_yields_empty(self):
        # The common case for a tombstone row: key rows outlive their silo by
        # design, so this is expected rather than exceptional.
        group = Group.objects.create(name="Acme Corporation")
        uid = f"group-{group.pk}"
        group.delete()

        assert GroupSiloAdapter().describe_silo(uid) == ""


@pytest.mark.django_db
class TestTheAdminField:
    """The data key's detail page names the silo beside its UID."""

    def _display(self, dek):
        from django.contrib.admin.sites import AdminSite

        from encryption_suite.admin import DataEncryptionKeyAdmin
        from encryption_suite.models import DataEncryptionKey

        return str(DataEncryptionKeyAdmin(DataEncryptionKey, AdminSite()).silo_name(dek))

    def test_shows_the_name(self):
        group = Group.objects.create(name="Acme Corporation")

        assert self._display(make_dek(silo_uid=f"group-{group.pk}")) == "Acme Corporation"

    def test_a_silo_that_is_gone_says_so(self):
        # Distinct from "unavailable": the row is a tombstone whose silo was
        # deleted, which is the expected end state, not a lookup problem.
        assert self._display(make_dek(silo_uid="group-999999")) == "— (silo no longer exists)"

    def test_a_test_console_key_is_labeled_as_the_console(self):
        from encryption_suite.models import DataEncryptionKey

        dek = make_dek(silo_uid="enctestfieldkey", purpose=DataEncryptionKey.PURPOSE_TEST)

        assert self._display(dek) == "Test Console"

    def test_an_adapter_that_cannot_say_falls_back(self, monkeypatch):
        monkeypatch.setattr(GroupSiloAdapter, "describe_silo", lambda self, uid: "")
        monkeypatch.setattr(GroupSiloAdapter, "silo_exists", lambda self, uid: None)

        assert self._display(make_dek(silo_uid="group-1")) == "— (unavailable)"

    def test_an_adapter_that_raises_falls_back(self, monkeypatch):
        def _boom(self, uid):
            raise RuntimeError("adapter down")

        monkeypatch.setattr(GroupSiloAdapter, "describe_silo", _boom)

        assert self._display(make_dek(silo_uid="group-1")) == "— (unavailable)"
