"""Tests for the in-process negative cache of failed DEK unwraps.

A failed DEK unwrap (KMS unreachable, key unavailable, missing DEK) is cached
per silo for ``DEK_FAILURE_CACHE_TTL`` and re-raised on subsequent reads
within that window, so a single slow/dead KMS call is not re-paid by every
encrypted field on a page. The window is kept short so a healthy-but-briefly
slow backend is retried almost immediately.
"""

from __future__ import annotations

import time
from unittest.mock import patch

import pytest

from encryption_suite import registry
from encryption_suite.dek_cache import DekCacheKey
from encryption_suite.engine import EncryptionEngine
from encryption_suite.exceptions import KekUnavailableError


@pytest.fixture
def engine():
    eng = registry.get_engine()
    EncryptionEngine.invalidate_cache()
    yield eng
    EncryptionEngine.invalidate_cache()


def _key(uid: str) -> DekCacheKey:
    return DekCacheKey("default", "field", uid)


def _counting_failure(counter: dict):
    def _load():
        counter["calls"] += 1
        raise KekUnavailableError("KMS unreachable")

    return _load


def test_failure_is_cached_and_not_re_paid(engine):
    counter = {"calls": 0}
    load = _counting_failure(counter)

    with patch("encryption_suite.engine.enc_settings.DEK_FAILURE_CACHE_TTL", 5):
        with pytest.raises(KekUnavailableError):
            engine._get_cached_primitive(_key("neg-uid"), load)
        # Second read within the window short-circuits: load_fn is not invoked
        # again, so the dead-KMS timeout is paid once, not per field.
        with pytest.raises(KekUnavailableError):
            engine._get_cached_primitive(_key("neg-uid"), load)

    assert counter["calls"] == 1


def test_failure_ttl_zero_disables_negative_cache(engine):
    counter = {"calls": 0}
    load = _counting_failure(counter)

    with patch("encryption_suite.engine.enc_settings.DEK_FAILURE_CACHE_TTL", 0):
        for _ in range(3):
            with pytest.raises(KekUnavailableError):
                engine._get_cached_primitive(_key("neg-uid"), load)

    assert counter["calls"] == 3


def test_failure_entry_expires_and_retries(engine):
    counter = {"calls": 0}
    load = _counting_failure(counter)

    with patch("encryption_suite.engine.enc_settings.DEK_FAILURE_CACHE_TTL", 0.05):
        with pytest.raises(KekUnavailableError):
            engine._get_cached_primitive(_key("neg-uid"), load)
        time.sleep(0.1)
        # Past the window the backend is retried rather than treated as down.
        with pytest.raises(KekUnavailableError):
            engine._get_cached_primitive(_key("neg-uid"), load)

    assert counter["calls"] == 2


def test_success_supersedes_cached_failure(engine):
    counter = {"calls": 0}
    sentinel = object()

    def _load_then_succeed():
        counter["calls"] += 1
        if counter["calls"] == 1:
            raise KekUnavailableError("KMS unreachable")
        return sentinel

    with patch("encryption_suite.engine.enc_settings.DEK_FAILURE_CACHE_TTL", 0.05):
        with pytest.raises(KekUnavailableError):
            engine._get_cached_primitive(_key("neg-uid"), _load_then_succeed)
        time.sleep(0.1)
        # Once the failure entry expires, a successful load is cached and a
        # subsequent read returns it without re-invoking the loader.
        assert engine._get_cached_primitive(_key("neg-uid"), _load_then_succeed) is sentinel
        assert engine._get_cached_primitive(_key("neg-uid"), _load_then_succeed) is sentinel

    assert counter["calls"] == 2


def test_failure_cache_is_per_silo(engine):
    counter_a = {"calls": 0}
    counter_b = {"calls": 0}

    with patch("encryption_suite.engine.enc_settings.DEK_FAILURE_CACHE_TTL", 5):
        with pytest.raises(KekUnavailableError):
            engine._get_cached_primitive(_key("uid-a"), _counting_failure(counter_a))
        # A different silo is not short-circuited by the first one's failure.
        with pytest.raises(KekUnavailableError):
            engine._get_cached_primitive(_key("uid-b"), _counting_failure(counter_b))

    assert counter_a["calls"] == 1
    assert counter_b["calls"] == 1
