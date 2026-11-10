"""The admin test console and the Reconcile Keys page choose a key set, shown as ``default (local)``."""

from __future__ import annotations

import pytest
from django.test import RequestFactory

from encryption_suite import admin_test_console as console
from encryption_suite import conf, registry
from encryption_suite import test_console as tc
from encryption_suite.models import DataEncryptionKey
from encryption_suite.reconcile_service import stores_to_reconcile
from tests.factories import make_kek
from tests.key_set_settings import key_sets


def _request(session=None):
    request = RequestFactory().get("/")
    request.session = dict(session or {})
    return request


# --- The choices ----------------------------------------------------------


def test_the_choices_list_default_first_with_the_store_of_each(settings):
    settings.ENCRYPTION = {**settings.ENCRYPTION, "KEY_SETS": {**key_sets(), "alpha": key_sets()["default"]}}
    # ``system`` is listed before ``alpha`` by settings order; ``default`` is moved to the front.
    assert conf.key_set_choices()[0] == ("default", "local")
    assert dict(conf.key_set_choices()) == {"default": "local", "system": "login", "alpha": "local"}


def test_a_key_set_with_no_store_is_left_out(settings):
    settings.ENCRYPTION = {**settings.ENCRYPTION, "KEY_SETS": key_sets(broken="nonesuch")}

    assert "broken" not in dict(conf.key_set_choices())


def test_the_label_is_the_key_set_then_the_store_in_parentheses():
    assert conf.key_set_label("default", "fly") == "default (fly)"


# --- The test console -----------------------------------------------------


def test_a_pick_is_restored_and_a_stale_pick_falls_back(settings):
    assert console._console_key_set(_request({"_tc_key_set": "system"})) == "system"
    assert console._console_key_set(_request({"_tc_key_set": "gone"})) == "default"
    assert console._console_key_set(_request()) == "default"


def test_results_are_kept_per_key_set():
    request = _request()
    outcome = {"status": "pass", "detail": ""}

    console._store_results(request, "default", {"field_full": outcome, "field_memory": outcome})
    console._store_results(request, "system", {"field_full": {"status": "fail", "detail": "x"}})

    assert console._results_for(request, "default")["field_full"]["status"] == "pass"
    assert console._results_for(request, "system")["field_full"]["status"] == "fail"
    # The shared (non-KMS) results show under every key set.
    assert console._results_for(request, "system")["field_memory"]["status"] == "pass"


@pytest.mark.django_db
def test_the_console_rows_carry_the_picked_key_set_and_the_bare_uid():
    adapter = registry.get_kms_adapter("local")

    tc.full_aead_roundtrip(adapter, None, b"payload", key_set="default")
    tc.full_streaming_roundtrip(adapter, None, b"payload", key_set="default")

    rows = set(
        DataEncryptionKey.objects.filter(purpose=DataEncryptionKey.PURPOSE_TEST).values_list("key_set", "silo_uid")
    )
    assert rows == {("default", "enctestfieldkey"), ("default", "enctestfilekey")}


@pytest.mark.django_db
def test_delete_removes_every_key_set_pair_and_the_shared_key_once(settings):
    settings.ENCRYPTION = {**settings.ENCRYPTION, "KEY_SETS": key_sets(other="local")}
    adapter = registry.get_kms_adapter("local")
    for key_set in ("default", "other"):
        tc.full_aead_roundtrip(adapter, None, b"payload", key_set=key_set)

    result = tc.delete_test_key()

    assert result["deks_deleted"] == 2
    assert len(result["keks"]) == 1
    assert not DataEncryptionKey.objects.filter(purpose=DataEncryptionKey.PURPOSE_TEST).exists()


def test_the_env_test_key_name_is_the_bare_console_uid():
    assert conf.env_test_kek_name() == conf.enc_settings.TEST_CONSOLE_KEK_UID == "enctestkey"


# --- The reserved uids ----------------------------------------------------


def test_the_reserved_uids_are_the_three_settings(settings):
    assert conf.reserved_test_uids() == {"enctestfieldkey", "enctestfilekey", "enctestkey"}


def test_the_sentinel_check_covers_every_silo_adapter(settings):
    class _Leaky:
        supports_enumeration = False

        def get_current_silo(self):
            return object()

        def get_silo_uid(self, silo):
            return "enctestfieldkey"

    with pytest.raises(tc.ConsoleSentinelLeakError):
        tc.assert_sentinel_not_producible_no_db(_Leaky())


# --- The reconcile command ------------------------------------------------


@pytest.mark.django_db
def test_only_stores_in_use_run_and_env_stores_do_not():
    assert stores_to_reconcile() == ["local"]


@pytest.mark.django_db
def test_a_retired_store_that_still_holds_a_key_runs(configured_kms):
    configured_kms("retired", silo_kms=False)
    make_kek("old-key", "retired")

    assert stores_to_reconcile() == ["local", "retired"]


@pytest.mark.django_db
def test_a_retired_store_holding_only_deleted_keys_does_not_run(configured_kms):
    configured_kms("retired", silo_kms=False)
    make_kek("old-key", "retired", status="deleted")

    assert stores_to_reconcile() == ["local"]
