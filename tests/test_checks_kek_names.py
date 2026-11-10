"""Tests for the deploy-time checks that keep two silos from sharing one KEK (E042-E046, W059)."""

from __future__ import annotations

import copy

from django.conf import settings
from django.test import override_settings

from encryption_suite.adapters.keks.strategies import PerSiloKekStrategy
from encryption_suite.checks_kek_names import (
    CHECK_IDS,
    check_kek_names_do_not_collide,
    is_per_silo_strategy,
    per_silo_blocks,
)

_PER_SILO = "encryption_suite.adapters.keks.PerSiloKekStrategy"
_USER_ADAPTER = "tests.test_key_set_binding.ActingUserSiloAdapter"
_GROUP_ADAPTER = "tests.silo.GroupSiloAdapter"


class SubclassedStrategy(PerSiloKekStrategy):
    """A per-silo strategy under a name that does not contain ``PerSiloKekStrategy``."""


class NotAStrategy:
    pass


def _store(template=None, kek_map=None, destroyable=False, strategy=_PER_SILO):
    options = {}
    if template is not None:
        options["KEK_TEMPLATE"] = template
    if kek_map is not None:
        options["KEK_MAP"] = kek_map
    if destroyable:
        options["KEK_MAP_DESTROYABLE"] = True
    return {"ADAPTER": "tests.adapters.UnversionedTestKmsAdapter", "KEK_STRATEGY_ADAPTER": strategy, "OPTIONS": options}


def _check(stores, key_sets=None):
    """Run the check over *stores*, with *key_sets* defaulting to one group key set on the first store."""
    cfg = copy.deepcopy(settings.ENCRYPTION)
    cfg["KMS_KEY_STORES"] = stores
    cfg["KEY_SETS"] = key_sets or {
        "default": {"silo": _GROUP_ADAPTER, "key_store": next(iter(stores))},
        "system": {"key_store": "login"},
    }
    with override_settings(ENCRYPTION=cfg):
        return check_kek_names_do_not_collide(app_configs=None)


def _ids(messages):
    return {m.id for m in messages}


def _two_stores(**second):
    return {"a": _store("team-a-{silo_uid}"), "b": _store(**{"template": "team-b-{silo_uid}", **second})}


def test_a_clean_configuration_reports_nothing():
    assert _check(_two_stores()) == []


def test_the_suite_settings_report_nothing():
    assert check_kek_names_do_not_collide(app_configs=None) == []


# --- recognizing a per-silo store ---------------------------------------------


def test_a_subclass_under_another_name_counts_as_per_silo():
    assert is_per_silo_strategy(f"{__name__}.SubclassedStrategy")


def test_an_unrelated_class_with_the_name_in_its_path_does_not_count():
    assert not is_per_silo_strategy(f"{__name__}.NotAStrategy")
    assert not is_per_silo_strategy("tests.PerSiloKekStrategy")


def test_a_path_that_does_not_import_is_skipped():
    assert not is_per_silo_strategy("no.such.PerSiloKekStrategy")
    cfg = copy.deepcopy(settings.ENCRYPTION)
    cfg["KMS_KEY_STORES"] = {"x": _store("t-{silo_uid}", strategy="no.such.PerSiloKekStrategy")}
    with override_settings(ENCRYPTION=cfg):
        assert per_silo_blocks() == {}


# --- E042: one silo adapter per store -----------------------------------------


def _two_adapters_on(store):
    return {
        "default": {"silo": _GROUP_ADAPTER, "key_store": store},
        "user": {"silo": _USER_ADAPTER, "key_store": store},
        "system": {"key_store": "login"},
    }


def test_two_adapters_on_one_per_silo_store_is_an_error():
    found = _check(_two_stores(), _two_adapters_on("a"))
    assert _ids(found) == {"encryption_suite.E042"}
    message = found[0].msg
    assert "['a']" in message and "default" in message and "user" in message
    assert found[0].hint is None


def test_the_system_key_set_counts_as_a_different_adapter():
    sets = {"default": {"silo": _GROUP_ADAPTER, "key_store": "a"}, "system": {"key_store": "a"}}
    assert _ids(_check(_two_stores(), sets)) == {"encryption_suite.E042"}


def test_one_adapter_with_two_key_sets_is_clean():
    sets = {
        "default": {"silo": _GROUP_ADAPTER, "key_store": "a"},
        "archive": {"silo": _GROUP_ADAPTER, "key_store": "a"},
        "system": {"key_store": "login"},
    }
    assert _check(_two_stores(), sets) == []


def test_two_adapters_on_a_shared_strategy_store_is_clean():
    stores = {**_two_stores(), "shared": _store(strategy="encryption_suite.adapters.keks.SharedKekStrategy")}
    assert _check(stores, _two_adapters_on("shared")) == []


def test_two_adapters_on_an_env_store_is_clean():
    assert _check(_two_stores(), _two_adapters_on("login")) == []


# --- E043: a template needs a literal prefix ----------------------------------


def test_a_prefixless_template_with_several_per_silo_stores_is_an_error():
    stores = {"a": _store("{silo_uid}"), "b": _store("team-b-{silo_uid}")}
    found = _check(stores)
    assert _ids(found) == {"encryption_suite.E043"}
    assert "['a']" in found[0].msg and found[0].hint is None


def test_a_prefixless_template_alone_is_clean():
    assert _check({"a": _store("{silo_uid}")}) == []


def test_a_map_only_store_is_exempt_from_the_prefix_rule():
    stores = {"a": _store(kek_map={"1": "key-1"}), "b": _store("team-b-{silo_uid}")}
    assert _check(stores) == []


# --- E044 / W059: duplicate map values ----------------------------------------


def test_duplicate_values_in_a_destroyable_map_are_an_error():
    stores = _two_stores(kek_map={"1": "shared-key", "2": "shared-key"}, destroyable=True)
    found = _check(stores)
    assert _ids(found) == {"encryption_suite.E044"}
    assert "['b']" in found[0].msg and "'shared-key'" in found[0].msg and found[0].hint is None


def test_duplicate_values_in_an_unflagged_map_are_a_warning():
    from django.core.checks import WARNING

    found = _check(_two_stores(kek_map={"1": "shared-key", "2": "shared-key"}))
    assert _ids(found) == {"encryption_suite.W059"}
    assert found[0].level == WARNING and found[0].hint is None


def test_distinct_values_are_clean():
    assert _check(_two_stores(kek_map={"1": "key-1", "2": "key-2"}, destroyable=True)) == []


# --- E045: a map value another store can name ---------------------------------


def test_a_value_in_another_stores_map_is_an_error():
    stores = {"a": _store(kek_map={"1": "key-1"}), "b": _store("team-b-{silo_uid}", {"2": "key-1"})}
    found = _check(stores)
    assert _ids(found) == {"encryption_suite.E045"}
    assert {m.msg.split("['")[2][0] for m in found} == {"a", "b"}


def test_a_value_under_another_stores_prefix_is_an_error():
    found = _check(_two_stores(kek_map={"1": "team-a-1"}))
    assert _ids(found) == {"encryption_suite.E045"}
    assert "['b']" in found[0].msg and "'a'" in found[0].msg and found[0].hint is None


def test_a_value_no_other_store_can_name_is_clean():
    assert _check(_two_stores(kek_map={"1": "arn:aws:kms:key/1"})) == []


# --- E046: a map value its own template can name ------------------------------


def test_a_value_under_the_stores_own_prefix_is_an_error():
    found = _check({"a": _store("team-a-{silo_uid}", {"1": "team-a-7"})})
    assert _ids(found) == {"encryption_suite.E046"}
    assert "['a']" in found[0].msg and "'team-a-7'" in found[0].msg and found[0].hint is None


def test_a_value_outside_the_stores_own_prefix_is_clean():
    assert _check({"a": _store("team-a-{silo_uid}", {"1": "key-1"})}) == []


# --- messages ------------------------------------------------------------------


def test_every_new_check_id_is_documented_and_carries_no_hint():
    from pathlib import Path

    docs = (Path(__file__).parent.parent / "docs" / "configuration.md").read_text(encoding="utf-8")
    for check_id in CHECK_IDS:
        assert f"`{check_id}`" in docs, check_id

    offenders = [
        *_check(_two_stores(), _two_adapters_on("a")),
        *_check({"a": _store("{silo_uid}"), "b": _store("team-b-{silo_uid}")}),
        *_check(_two_stores(kek_map={"1": "k", "2": "k"}, destroyable=True)),
        *_check(_two_stores(kek_map={"1": "k", "2": "k"})),
        *_check(_two_stores(kek_map={"1": "team-a-1"})),
        *_check({"a": _store("team-a-{silo_uid}", {"1": "team-a-7"})}),
    ]
    assert {m.id for m in offenders} == set(CHECK_IDS)
    assert all(m.hint is None for m in offenders)
