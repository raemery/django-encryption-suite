"""
The in-process cache of loaded data key primitives.

One :class:`DekCache` exists per key set, created on first use by :func:`dek_cache`.
Inside an instance an entry is keyed by ``(purpose, uid)``; the key set is the
instance, so two key sets with one raw uid never share an entry and a uid that
contains a colon cannot be mistaken for another silo's.

A hit reads an immutable ``(primitive, expiry)`` tuple and takes no lock. A lock is
taken on a miss, a put, a sweep and an eviction. Expired entries are swept at most
once per :data:`SWEEP_INTERVAL_SECONDS`; every lookup still checks its own entry's
expiry, so correctness never depends on the sweep.

The locks that serialize loading one key and provisioning one silo are striped: a
fixed array per instance, chosen by hashing, so memory is bounded by the stripe
count and not by the number of silos ever seen. Loading and provisioning use
separate arrays because provisioning holds its lock while it loads.
"""

from __future__ import annotations

import threading
import time
from typing import NamedTuple

#: Seconds between sweeps of expired entries, per instance.
SWEEP_INTERVAL_SECONDS = 60

#: Stripes for a key set bound to the system adapter: it has one silo and at most three keys.
SYSTEM_STRIPES = 1
#: Stripes for a key set with a cap on its entries.
CAPPED_STRIPES = 256
#: Stripes for a key set with no cap.
DEFAULT_STRIPES = 16

#: Returned by :meth:`DekCache.lookup` when nothing usable is cached.
MISS = object()


class DekCacheKey(NamedTuple):
    """One cached primitive: the key set, the kind of key and the silo uid."""

    key_set: str
    purpose: str
    uid: str

    @property
    def slot(self) -> tuple[str, str]:
        """The key inside its key set's instance."""
        return (self.purpose, self.uid)


class DekCache:
    """The primitives and recent failures of one key set."""

    def __init__(self, *, stripes: int = DEFAULT_STRIPES, max_entries: int | None = None, clock=time.monotonic):
        self._clock = clock
        self._max_entries = max_entries
        # Guards every mutation. Reads do not take it.
        self._lock = threading.Lock()
        # Insertion order is load order, which is what eviction removes first.
        self._entries: dict[tuple[str, str], tuple[object, float]] = {}
        self._failures: dict[tuple[str, str], tuple[BaseException, float]] = {}
        # uid -> the slots of that uid that hold an entry or a failure.
        self._by_uid: dict[str, set[tuple[str, str]]] = {}
        self._load_locks = tuple(threading.Lock() for _ in range(stripes))
        self._provision_locks = tuple(threading.Lock() for _ in range(stripes))
        self._next_sweep = clock() + SWEEP_INTERVAL_SECONDS

    # -- Reads: no lock -----------------------------------------------------

    def lookup(self, slot: tuple[str, str]):
        """The cached primitive, :data:`MISS`, or the recent failure raised again."""
        now = self._clock()
        entry = self._entries.get(slot)
        if entry is not None and now < entry[1]:
            return entry[0]
        failure = self._failures.get(slot)
        if failure is not None and now < failure[1]:
            raise failure[0]
        return MISS

    def contains(self, slot: tuple[str, str]) -> bool:
        """Whether an unexpired primitive is cached for *slot*."""
        entry = self._entries.get(slot)
        return entry is not None and self._clock() < entry[1]

    def __len__(self) -> int:
        return len(self._entries)

    def load_lock(self, slot: tuple[str, str]) -> threading.Lock:
        """The lock that serializes loading *slot*. Held across the KMS call."""
        return self._load_locks[hash(slot) % len(self._load_locks)]

    def provision_lock(self, uid: str) -> threading.Lock:
        """The lock that serializes creating the keys of the silo *uid*."""
        return self._provision_locks[hash(uid) % len(self._provision_locks)]

    # -- Writes: under the lock ----------------------------------------------

    def put(self, slot: tuple[str, str], primitive: object, expiry: float) -> None:
        """Cache *primitive* until *expiry*, replacing any entry and clearing any failure."""
        with self._lock:
            self._sweep_if_due()
            self._entries.pop(slot, None)  # a refresh moves to the end of the load order
            self._entries[slot] = (primitive, expiry)
            self._failures.pop(slot, None)
            self._by_uid.setdefault(slot[1], set()).add(slot)
            while self._max_entries is not None and len(self._entries) > self._max_entries:
                self._drop(next(iter(self._entries)), failures=False)

    def put_failure(self, slot: tuple[str, str], exc: BaseException, expiry: float) -> None:
        """Remember that loading *slot* failed, until *expiry*."""
        with self._lock:
            self._sweep_if_due()
            self._failures[slot] = (exc, expiry)
            self._by_uid.setdefault(slot[1], set()).add(slot)

    def invalidate_uid(self, uid: str) -> None:
        """Drop every entry and failure of the silo *uid*, whatever the purpose."""
        with self._lock:
            for slot in list(self._by_uid.get(uid, ())):
                self._drop(slot)

    def clear(self) -> None:
        """Drop everything."""
        with self._lock:
            self._entries.clear()
            self._failures.clear()
            self._by_uid.clear()

    def sweep(self) -> None:
        """Drop every expired entry and failure now."""
        with self._lock:
            self._sweep()

    # -- Internals: the lock is held -----------------------------------------

    def _sweep_if_due(self) -> None:
        if self._clock() >= self._next_sweep:
            self._sweep()

    def _sweep(self) -> None:
        now = self._clock()
        self._next_sweep = now + SWEEP_INTERVAL_SECONDS
        for slot in [s for s, (_, expiry) in self._entries.items() if now >= expiry]:
            self._drop(slot, failures=False)
        for slot in [s for s, (_, expiry) in self._failures.items() if now >= expiry]:
            self._failures.pop(slot, None)
            self._unindex(slot)

    def _drop(self, slot: tuple[str, str], *, failures: bool = True) -> None:
        self._entries.pop(slot, None)
        if failures:
            self._failures.pop(slot, None)
        self._unindex(slot)

    def _unindex(self, slot: tuple[str, str]) -> None:
        """Forget *slot* in the uid index once neither an entry nor a failure holds it."""
        if slot in self._entries or slot in self._failures:
            return
        slots = self._by_uid.get(slot[1])
        if slots is not None:
            slots.discard(slot)
            if not slots:
                del self._by_uid[slot[1]]


_caches: dict[str, DekCache] = {}
_caches_lock = threading.Lock()


def dek_cache(key_set: str) -> DekCache:
    """The cache instance of *key_set*, created on first use."""
    cache = _caches.get(key_set)
    if cache is None:
        with _caches_lock:
            cache = _caches.get(key_set)
            if cache is None:
                cache = _caches[key_set] = _new_cache(key_set)
    return cache


def _new_cache(key_set: str) -> DekCache:
    from .conf import dek_cache_cap, is_system_key_set

    cap = dek_cache_cap(key_set)
    if is_system_key_set(key_set):
        stripes = SYSTEM_STRIPES
    else:
        stripes = CAPPED_STRIPES if cap else DEFAULT_STRIPES
    return DekCache(stripes=stripes, max_entries=cap)


def clear_dek_caches(key_set: str | None = None) -> None:
    """Empty the cache of *key_set*, or every key set's when none is named.

    Clearing everything also forgets the instances, so the next use reads the
    settings again.
    """
    with _caches_lock:
        if key_set is None:
            caches = list(_caches.values())
            _caches.clear()
        else:
            caches = [cache] if (cache := _caches.get(key_set)) is not None else []
    for cache in caches:
        cache.clear()
