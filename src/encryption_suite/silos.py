"""
Shared helpers for silo enumeration.

Enumeration — listing every live silo for the configured deployment — is owned
by the **silo adapter** (:meth:`AbstractSiloAdapter.iter_silos`). It is the
single, programmed, testable source of truth for "which silos exist", because
that answer feeds both keyset setup *and* (Phase 3) KMS reconcile, where a wrong
or partial list can cause a live silo's KEK to be treated as an orphan and
destroyed. There is deliberately **no** runtime override (no settings key, no
free-text model path) that can substitute a different model: flexibility comes
from subclassing an adapter and overriding ``iter_silos``.

This module holds the small piece shared across adapters — turning a configured
``model_label`` into a queryset. The typed :class:`SiloEnumerationError` and its
funnel helper live in :mod:`encryption_suite.exceptions` with the rest of the
``EncryptionError`` family; ``SiloEnumerationError`` is re-exported here for the
adapters and call sites that import it alongside this helper.
"""

from __future__ import annotations

from ._logging import get_logger
from .exceptions import SiloEnumerationError, log_and_raise_enumeration_error

__all__ = ["SiloEnumerationError", "queryset_for_model_label"]

logger = get_logger(__name__)


def queryset_for_model_label(model_label: str):
    """Return ``Model._base_manager.all()`` for a ``"app_label.ModelName"`` string.

    Used by :meth:`AbstractSiloAdapter.iter_silos` for adapters that identify
    their silo by a single model — e.g. ``GenericModelSiloAdapter`` and
    ``PegasusTeamSiloAdapter`` (``"teams.Team"``). Both failure modes are routed
    through the enumeration funnel — logged once with the
    ``error_code=silo_enumeration_unavailable`` and raised as a typed
    :class:`SiloEnumerationError` — so the caller surfaces a clean
    detection-unavailable state, not a raw error:

    * a malformed label (not ``app_label.ModelName``), and
    * a label naming an app/model that is not installed — ``apps.get_model``
      raises ``LookupError``. This is the enumeration-side equivalent of the
      ``ImportError`` guard on a resolve path (e.g. ``PegasusTeamSiloAdapter``
      checking that ``apps.teams`` is installed): if the silo app is absent,
      enumeration is *unavailable*, not a crash.

    Reads through ``_base_manager``, never ``objects``, for the same reason the
    rotation path does: a default manager that filters is a statement about what
    an application shows, and this is a question about what a database holds. A
    soft-deleted, suspended, or otherwise hidden silo still owns rows somebody
    can read, and a silo missing from this list is read as an orphan — reconcile
    flags its keys, ``silo_exists`` answers ``False``, and the deletion gate
    destroys a key whose data is still there. That gate refuses on *cannot say*;
    a filtered manager does not produce *cannot say*, it produces a confident
    wrong answer.

    Excluding something from encryption is done by overriding ``iter_silos``,
    which says so about silos, rather than by a manager that says it about
    admin list views.
    """
    from django.apps import apps

    parts = model_label.rsplit(".", 1)
    if len(parts) != 2:
        log_and_raise_enumeration_error(
            logger,
            f"Invalid silo model path '{model_label}'. Use 'app_label.ModelName'.",
        )
    try:
        model = apps.get_model(*parts)
    except LookupError as exc:
        log_and_raise_enumeration_error(
            logger,
            f"Silo model '{model_label}' is not installed; cannot enumerate silos. "
            "Ensure the app providing it is in INSTALLED_APPS.",
            cause=exc,
        )
    return model._base_manager.all()
