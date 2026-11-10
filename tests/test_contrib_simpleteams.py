"""The simpleteams app: a team model, its silo adapter, middleware and admin.

What is worth pinning is where the app relies on the schema or on the core rather
than on code of its own: one team per user is the database's rule, the team name
is a system field read with no silo in context, and everything the adapter does
is inherited from ``GenericModelSiloAdapter``.
"""

from __future__ import annotations

import pytest
from asgiref.sync import async_to_sync
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.db import IntegrityError, models, transaction
from django.test import AsyncClient, RequestFactory, override_settings
from django.test.utils import isolate_apps

from encryption_suite._internal import raw_cursor_fetch
from encryption_suite.adapters.silos.context import get_current_silo
from encryption_suite.conf import SYSTEM_SILO_UID
from encryption_suite.contrib.simpleteams.adapter import SimpleTeamSiloAdapter
from encryption_suite.contrib.simpleteams.admin import SimpleTeamAdmin
from encryption_suite.contrib.simpleteams.middleware import SimpleTeamSiloMiddleware
from encryption_suite.contrib.simpleteams.models import SimpleTeam, SimpleTeamMembership
from encryption_suite.engine import is_silo_value
from encryption_suite.fields import EncryptedCharField
from encryption_suite.models import DataEncryptionKey
from encryption_suite.rotation_targets import resolve_targets

pytestmark = pytest.mark.django_db

ADD_URL = "/admin/encryption_suite_simpleteams/simpleteam/add/"


def _user(username="ann"):
    return get_user_model().objects.create_user(username=username, password="pw")


def _member(team, username="ann"):
    user = _user(username)
    SimpleTeamMembership.objects.create(user=user, team=team)
    return user


# --- Models ------------------------------------------------------------------


def test_a_user_cannot_join_a_second_team():
    user = _member(SimpleTeam.objects.create(name="Acme"))
    with pytest.raises(IntegrityError), transaction.atomic():
        SimpleTeamMembership.objects.create(user=user, team=SimpleTeam.objects.create(name="Globex"))


def test_the_name_is_stored_encrypted_and_reads_back():
    team = SimpleTeam.objects.create(name="Acme")
    [stored] = raw_cursor_fetch(SimpleTeam, team.pk, ["name"])
    assert is_silo_value(stored)
    assert DataEncryptionKey.objects.filter(silo_uid=SYSTEM_SILO_UID).exists()
    assert "Acme" not in stored
    assert SimpleTeam.objects.get(pk=team.pk).name == "Acme"


def test_names_differing_only_in_case_are_one_name():
    SimpleTeam.objects.create(name="Acme")
    assert SimpleTeam.objects.get(name="ACME").name == "Acme"
    with pytest.raises(ValidationError):
        SimpleTeam(name="acme").full_clean()
    with pytest.raises(IntegrityError), transaction.atomic():
        SimpleTeam.objects.create(name="acme")


# --- Adapter -----------------------------------------------------------------


def test_the_silo_uid_is_simpleteam_and_the_pk():
    team = SimpleTeam.objects.create(name="Acme")
    assert SimpleTeamSiloAdapter().get_silo_uid(team) == f"simpleteam-{team.pk}"
    assert SimpleTeamSiloAdapter().get_silo_label() == "simpleteam"


def test_every_team_is_enumerated():
    teams = {SimpleTeam.objects.create(name=name).pk for name in ("Acme", "Globex", "Initech")}
    assert {team.pk for team in SimpleTeamSiloAdapter().iter_silos()} == teams


def test_a_uid_resolves_to_its_team_and_nothing_else_does():
    team = SimpleTeam.objects.create(name="Acme")
    adapter = SimpleTeamSiloAdapter()
    assert adapter.silo_for_uid(f"simpleteam-{team.pk}") == team
    assert adapter.silo_for_uid("simpleteam-abc") is None
    assert adapter.silo_for_uid(f"team-{team.pk}") is None
    assert adapter.silo_for_uid(f"simpleteam-{team.pk + 1}") is None


def test_a_team_is_described_by_its_decrypted_name():
    team = SimpleTeam.objects.create(name="Acme")
    assert SimpleTeamSiloAdapter().describe_silo(f"simpleteam-{team.pk}") == "Acme"


@isolate_apps("tests")
def test_reencrypt_data_finds_a_model_through_its_one_foreign_key_to_the_team():
    class Ledger(models.Model):
        team = models.ForeignKey(SimpleTeam, on_delete=models.PROTECT, related_name="+")
        entry = EncryptedCharField(max_length=100, null=True)

        class Meta:
            app_label = "tests"

    resolution = resolve_targets(SimpleTeamSiloAdapter(), models=[(Ledger, ("entry",), (), ())])
    assert resolution.unresolved == []
    assert [target.fk_name for target in resolution.targets] == ["team"]


# --- Middleware --------------------------------------------------------------


def _silo_seen_by_view(user):
    seen = []

    def view(request):
        seen.append(get_current_silo())
        return None

    request = RequestFactory().get("/")
    request.user = user
    SimpleTeamSiloMiddleware(view)(request)
    return seen[0]


def test_a_member_gets_their_team_and_it_is_cleared_after_the_response():
    team = SimpleTeam.objects.create(name="Acme")
    assert _silo_seen_by_view(_member(team)) == team
    assert get_current_silo() is None


def test_a_user_with_no_team_gets_no_silo():
    assert _silo_seen_by_view(_user()) is None


def test_an_anonymous_user_gets_no_silo():
    from django.contrib.auth.models import AnonymousUser

    assert _silo_seen_by_view(AnonymousUser()) is None


def test_the_silo_is_cleared_when_the_view_raises():
    def view(request):
        raise RuntimeError("boom")

    request = RequestFactory().get("/")
    request.user = _member(SimpleTeam.objects.create(name="Acme"))
    with pytest.raises(RuntimeError):
        SimpleTeamSiloMiddleware(view)(request)
    assert get_current_silo() is None


def test_the_team_reaches_the_view_under_the_async_client(settings):
    team = SimpleTeam.objects.create(name="Acme")
    user = _member(team)

    async def fetch():
        client = AsyncClient()
        await client.aforce_login(user)
        return await client.get("/silo/")

    middleware = [*settings.MIDDLEWARE, "encryption_suite.contrib.simpleteams.middleware.SimpleTeamSiloMiddleware"]
    with override_settings(MIDDLEWARE=middleware, ROOT_URLCONF="tests.simpleteams_urls"):
        response = async_to_sync(fetch)()
    assert response.content.decode() == str(team.pk)


# --- Admin -------------------------------------------------------------------


@pytest.fixture
def admin_client(client):
    client.force_login(get_user_model().objects.create_superuser(username="root", password="pw"))
    return client


def _add_form(name, *user_pks):
    data = {
        "name": name,
        "memberships-TOTAL_FORMS": str(len(user_pks)),
        "memberships-INITIAL_FORMS": "0",
        "memberships-MIN_NUM_FORMS": "0",
        "memberships-MAX_NUM_FORMS": "1000",
    }
    for index, pk in enumerate(user_pks):
        data[f"memberships-{index}-user"] = str(pk)
    return data


def test_the_admin_adds_a_team_with_a_member(admin_client):
    user = _user()
    response = admin_client.post(ADD_URL, _add_form("Acme", user.pk))
    assert response.status_code == 302
    assert SimpleTeamMembership.objects.get(user=user).team.name == "Acme"


def test_adding_a_user_already_on_a_team_is_a_form_error(admin_client):
    user = _member(SimpleTeam.objects.create(name="Acme"))
    response = admin_client.post(ADD_URL, _add_form("Globex", user.pk))
    assert response.status_code == 200
    assert response.context["inline_admin_formsets"][0].formset.errors[0]["user"]
    assert not SimpleTeam.objects.filter(name="Globex").exists()


def test_a_duplicate_name_is_a_form_error(admin_client):
    SimpleTeam.objects.create(name="Acme")
    response = admin_client.post(ADD_URL, _add_form("acme"))
    assert response.status_code == 200
    assert response.context["adminform"].form.errors["name"]


def test_the_admin_renames_a_team(admin_client):
    team = SimpleTeam.objects.create(name="Acme")
    url = f"/admin/encryption_suite_simpleteams/simpleteam/{team.pk}/change/"
    assert "Acme" in admin_client.get(url).content.decode()
    response = admin_client.post(url, _add_form("Acme Corp"))
    assert response.status_code == 302
    assert SimpleTeam.objects.get(pk=team.pk).name == "Acme Corp"


def test_search_matches_part_of_a_name_ignoring_case():
    from django.contrib import admin

    acme = SimpleTeam.objects.create(name="Acme Corp")
    SimpleTeam.objects.create(name="Globex")
    model_admin = SimpleTeamAdmin(SimpleTeam, admin.site)
    queryset, duplicates = model_admin.get_search_results(None, SimpleTeam.objects.all(), "  CME c ")
    assert list(queryset) == [acme]
    assert duplicates is False
    assert model_admin.get_search_results(None, SimpleTeam.objects.all(), "")[0].count() == 2
