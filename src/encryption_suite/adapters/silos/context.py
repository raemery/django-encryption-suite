"""
Context-aware silo adapter base and helpers.

Provides ``set_current_silo()`` / ``clear_current_silo()`` helpers so
management commands, Celery tasks, tests, and middleware can set the active
silo without relying on a specific framework integration.

Uses ``contextvars.ContextVar`` so that state is correctly isolated under both
synchronous servers (gunicorn with sync workers — one thread per request) and
asynchronous servers (uvicorn / Daphne — multiple requests share one thread via
``asyncio`` tasks).  Each task or thread automatically gets its own value.

``ContextSiloAdapter`` implements ``get_current_silo()`` via the
context variable. Subclass it and implement ``get_silo_uid()`` and
``get_silo_label()`` for your model.

Usage in middleware::

    from encryption_suite.adapters.silo.context import (
        set_current_silo,
        clear_current_silo,
    )

    class EncryptionSiloMiddleware:
        def __init__(self, get_response):
            self.get_response = get_response

        def __call__(self, request):
            if request.team:
                set_current_silo(request.team)
            try:
                return self.get_response(request)
            finally:
                clear_current_silo()

Usage in tests::

    with override_current_silo(team):
        assert MyModel.objects.get(pk=pk).sensitive_field == "secret"
"""

from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar

from .base import AbstractSiloAdapter

_current_silo: ContextVar = ContextVar("current_silo", default=None)


def set_current_silo(silo) -> None:
    """Set the active silo for the current context (thread or async task)."""
    _current_silo.set(silo)


def get_current_silo():
    """Return the active silo for the current context, or None."""
    return _current_silo.get()


def clear_current_silo() -> None:
    """Clear the active silo for the current context."""
    _current_silo.set(None)


@contextmanager
def override_current_silo(silo):
    """Context manager: set silo for the duration of the block."""
    token = _current_silo.set(silo)
    try:
        yield
    finally:
        _current_silo.reset(token)


class ContextSiloAdapter(AbstractSiloAdapter):
    """
    Base adapter that resolves the current silo from a context variable.

    Works correctly under both sync (WSGI) and async (ASGI) servers.

    Implements ``get_current_silo()``. Subclass and implement
    ``get_silo_uid()`` and ``get_silo_label()`` for your model.
    """

    def get_current_silo(self):
        return get_current_silo()
