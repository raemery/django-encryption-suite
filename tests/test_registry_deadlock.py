"""Regression test for the registry lazy-init deadlock.

Before the fix, ``threading.Lock`` in ``registry`` deadlocked any caller whose
first registry touch was ``get_engine()`` — because ``get_engine`` reacquires
the same lock while holding it to resolve its adapter dependencies. The fix
was to use ``threading.RLock``. This test fails (hangs) with ``Lock``.
"""

from __future__ import annotations

import threading

import pytest

from encryption_suite import registry


@pytest.fixture(autouse=True)
def _reset_registry():
    """Ensure each test starts from a cold registry."""
    registry.reset()
    yield
    registry.reset()


def test_get_engine_on_cold_registry_does_not_deadlock():
    """Calling get_engine() first on a fresh process must not deadlock.

    Runs the call on a worker thread with a hard join timeout so the test
    fails fast instead of hanging the suite if the lock regresses.
    """
    result: dict = {}
    error: dict = {}

    def _call():
        try:
            result["engine"] = registry.get_engine()
        except Exception as exc:
            error["exc"] = exc

    worker = threading.Thread(target=_call, daemon=True)
    worker.start()
    worker.join(timeout=5.0)

    assert not worker.is_alive(), (
        "get_engine() did not return within 5s on a cold registry — "
        "the lazy-init lock has likely regressed to a non-reentrant Lock."
    )
    assert "exc" not in error, f"get_engine() raised: {error.get('exc')!r}"
    assert result.get("engine") is not None


def test_get_kms_adapter_on_cold_registry_does_not_deadlock():
    """get_kms_adapter() nests into get_kek_strategy_adapter() under the lock."""
    result: dict = {}
    error: dict = {}

    def _call():
        try:
            result["kms"] = registry.get_kms_adapter()
        except Exception as exc:
            error["exc"] = exc

    worker = threading.Thread(target=_call, daemon=True)
    worker.start()
    worker.join(timeout=5.0)

    assert not worker.is_alive()
    assert "exc" not in error, f"get_kms_adapter() raised: {error.get('exc')!r}"
    assert result.get("kms") is not None
