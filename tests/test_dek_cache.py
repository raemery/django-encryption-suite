"""The in-process data key cache: one instance per key set, lock-free hits, bounded locks."""

from __future__ import annotations

import threading

import pytest

from encryption_suite import dek_cache as dek_cache_module
from encryption_suite.dek_cache import MISS, DekCache, DekCacheKey, clear_dek_caches, dek_cache
from encryption_suite.engine import EncryptionEngine
from encryption_suite.exceptions import KekUnavailableError
from encryption_suite.silo_ref import SiloRef


class _Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


@pytest.fixture(autouse=True)
def _fresh():
    clear_dek_caches()
    yield
    clear_dek_caches()


# --- Routing --------------------------------------------------------------


def test_one_instance_per_key_set_created_on_first_use():
    assert dek_cache("default") is dek_cache("default")
    assert dek_cache("default") is not dek_cache("other")


def test_two_key_sets_with_one_raw_uid_do_not_share_an_entry():
    dek_cache("default").put(("field", "1"), "primitive-default", 2000.0)

    assert dek_cache("other").contains(("field", "1")) is False


def test_system_key_set_gets_one_stripe_and_a_capped_one_gets_many(settings):
    settings.ENCRYPTION = {**settings.ENCRYPTION, "DEK_CACHE_MAX": {"default": 10}}
    from encryption_suite.conf import enc_settings

    enc_settings.reset()
    clear_dek_caches()

    assert len(dek_cache("system")._load_locks) == dek_cache_module.SYSTEM_STRIPES
    assert len(dek_cache("default")._load_locks) == dek_cache_module.CAPPED_STRIPES
    assert len(dek_cache("uncapped")._load_locks) == dek_cache_module.DEFAULT_STRIPES
    enc_settings.reset()


def test_the_setting_overrides_the_packages_table(settings, monkeypatch):
    from encryption_suite import conf

    monkeypatch.setitem(conf.DEFAULT_DEK_CACHE_MAX, "default", 5)
    settings.ENCRYPTION = {**settings.ENCRYPTION, "DEK_CACHE_MAX": {"default": 7}}
    conf.enc_settings.reset()
    try:
        assert conf.dek_cache_cap("default") == 7
        assert conf.dek_cache_cap("missing") is None
    finally:
        conf.enc_settings.reset()


@pytest.mark.parametrize("bad", [0, -1, True, "5", 1.5, None])
def test_a_value_that_is_not_a_positive_whole_number_means_no_cap(settings, bad):
    from encryption_suite import conf

    settings.ENCRYPTION = {**settings.ENCRYPTION, "DEK_CACHE_MAX": {"default": bad}}
    conf.enc_settings.reset()
    try:
        assert conf.dek_cache_cap("default") is None
    finally:
        conf.enc_settings.reset()


# --- Expiry and sweeping ---------------------------------------------------


def test_an_entry_is_a_miss_once_it_has_expired_even_without_a_sweep():
    clock = _Clock()
    cache = DekCache(clock=clock)
    cache.put(("field", "a"), "p", clock.now + 10)

    assert cache.lookup(("field", "a")) == "p"
    clock.now += 11
    assert cache.lookup(("field", "a")) is MISS


def test_expired_entries_are_swept_at_most_once_per_interval():
    clock = _Clock()
    cache = DekCache(clock=clock)
    cache.put(("field", "a"), "p", clock.now + 10)

    clock.now += 11  # expired, but the first sweep is not due
    cache.put(("field", "b"), "p", clock.now + 1000)
    assert ("field", "a") in cache._entries

    clock.now += dek_cache_module.SWEEP_INTERVAL_SECONDS
    cache.put(("field", "c"), "p", clock.now + 1000)
    assert ("field", "a") not in cache._entries


def test_an_expired_failure_is_a_miss_and_is_swept():
    clock = _Clock()
    cache = DekCache(clock=clock)
    cache.put_failure(("field", "a"), KekUnavailableError("down"), clock.now + 5)

    with pytest.raises(KekUnavailableError):
        cache.lookup(("field", "a"))
    clock.now += 6
    assert cache.lookup(("field", "a")) is MISS
    cache.sweep()
    assert not cache._failures
    assert not cache._by_uid


def test_a_put_clears_a_cached_failure():
    cache = DekCache()
    cache.put_failure(("field", "a"), KekUnavailableError("down"), 1e12)
    cache.put(("field", "a"), "p", 1e12)

    assert cache.lookup(("field", "a")) == "p"


# --- Invalidation ---------------------------------------------------------


def test_invalidating_a_silo_drops_every_purpose_of_it():
    cache = dek_cache("default")
    for purpose in ("field", "file", "index"):
        cache.put((purpose, "5"), "p", 1e12)
    cache.put(("field", "6"), "p", 1e12)

    EncryptionEngine.invalidate_cache(SiloRef("default", "5"))

    assert [purpose for purpose in ("field", "file", "index") if cache.contains((purpose, "5"))] == []
    assert cache.contains(("field", "6"))


def test_a_uid_containing_a_colon_does_not_drop_another_silos_entry():
    cache = dek_cache("default")
    cache.put(("field", "acme:billing"), "p", 1e12)
    cache.put(("field", "billing"), "p", 1e12)

    EncryptionEngine.invalidate_cache(SiloRef("default", "billing"))

    assert cache.contains(("field", "acme:billing"))
    assert not cache.contains(("field", "billing"))


def test_invalidating_a_key_set_clears_only_that_instance():
    dek_cache("default").put(("field", "1"), "p", 1e12)
    dek_cache("other").put(("field", "1"), "p", 1e12)

    EncryptionEngine.invalidate_cache(key_set="default")

    assert not dek_cache("default").contains(("field", "1"))
    assert dek_cache("other").contains(("field", "1"))


def test_invalidating_everything_clears_every_instance():
    dek_cache("default").put(("field", "1"), "p", 1e12)
    dek_cache("other").put(("field", "1"), "p", 1e12)

    EncryptionEngine.invalidate_cache()

    assert not dek_cache("default").contains(("field", "1"))
    assert not dek_cache("other").contains(("field", "1"))


# --- The cap --------------------------------------------------------------


def test_over_the_cap_the_oldest_loaded_entry_goes_first():
    cache = DekCache(max_entries=2)
    cache.put(("field", "a"), "p", 1e12)
    cache.put(("field", "b"), "p", 1e12)
    cache.put(("field", "c"), "p", 1e12)

    assert not cache.contains(("field", "a"))
    assert cache.contains(("field", "b")) and cache.contains(("field", "c"))


def test_a_refreshed_entry_counts_as_newly_loaded():
    cache = DekCache(max_entries=2)
    cache.put(("field", "a"), "p", 1e12)
    cache.put(("field", "b"), "p", 1e12)
    cache.put(("field", "a"), "p", 1e12)  # reloaded after its TTL
    cache.put(("field", "c"), "p", 1e12)

    assert not cache.contains(("field", "b"))
    assert cache.contains(("field", "a"))


def test_an_evicted_entry_leaves_no_index_behind():
    cache = DekCache(max_entries=1)
    cache.put(("field", "a"), "p", 1e12)
    cache.put(("field", "b"), "p", 1e12)

    assert set(cache._by_uid) == {"b"}


# --- Locks ----------------------------------------------------------------


def test_a_hit_takes_no_lock():
    cache = DekCache()
    cache.put(("field", "a"), "p", 1e12)

    with cache._lock:  # a writer holds the cache's lock for the whole read
        assert cache.lookup(("field", "a")) == "p"
        assert cache.contains(("field", "a"))


def test_locks_stay_bounded_however_many_silos_are_seen():
    cache = DekCache(stripes=8)
    for n in range(2000):
        cache.put(("field", str(n)), "p", 1e12)
        cache.load_lock(("field", str(n)))
        cache.provision_lock(str(n))

    assert len(cache._load_locks) == len(cache._provision_locks) == 8


def test_the_load_lock_and_the_provision_lock_are_not_the_same_lock():
    cache = DekCache(stripes=1)

    assert cache.load_lock(("field", "a")) is not cache.provision_lock("a")


# --- Threads --------------------------------------------------------------


def test_concurrent_readers_and_writers_never_see_a_torn_entry():
    cache = DekCache(max_entries=50)
    errors: list[BaseException] = []
    stop = threading.Event()

    def writer(offset):
        n = 0
        while not stop.is_set():
            slot = ("field", str((n + offset) % 200))
            cache.put(slot, slot, 1e12)
            if n % 7 == 0:
                cache.invalidate_uid(slot[1])
            n += 1

    def reader():
        while not stop.is_set():
            for n in range(200):
                slot = ("field", str(n))
                try:
                    value = cache.lookup(slot)
                except BaseException as exc:  # noqa: BLE001
                    errors.append(exc)
                    return
                if value is not MISS and value != slot:
                    errors.append(AssertionError(f"{slot} read back {value}"))
                    return

    threads = [threading.Thread(target=writer, args=(i * 40,)) for i in range(3)]
    threads += [threading.Thread(target=reader) for _ in range(3)]
    for thread in threads:
        thread.start()
    threading.Event().wait(0.5)
    stop.set()
    for thread in threads:
        thread.join(timeout=5)

    assert errors == []
    assert len(cache) <= 50
    assert all(slots for slots in cache._by_uid.values())


def test_a_dek_cache_key_names_its_slot():
    assert DekCacheKey("default", "field", "a:b").slot == ("field", "a:b")
