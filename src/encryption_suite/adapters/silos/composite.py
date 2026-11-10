"""
Composite silo adapter for mixed-encryption scenarios.

Some silos (tenants/organizations) encrypt at the top level — all their
data shares one KEK.  Others encrypt at the cell level — different cells
(sub-divisions within the same tenant) each have their own KEK.

The composite adapter checks a configurable flag on the top-level tenant to
decide which mode to use, then returns the appropriate object to the engine.

Cell resolution is via a context variable (``contextvars.ContextVar``) set
by middleware, so ``set_current_cell()`` / ``clear_current_cell()`` must be
called around every request (or task) for tenants that use cell-level
encryption.  This works correctly under both sync (WSGI) and async (ASGI)
servers.

-------------------------------------------------------------------------------
Quick start
-------------------------------------------------------------------------------

1. Add a boolean flag to your tenant model::

       class Client(TenantMixin):       # django-tenants example
           uses_cell_encryption = models.BooleanField(default=False)

2. Add middleware that sets the current cell for cell-encrypted tenants::

       from encryption_suite.adapters.silo.composite import (
           set_current_cell, clear_current_cell,
       )

       class CellEncryptionMiddleware:
           def __init__(self, get_response):
               self.get_response = get_response

           def __call__(self, request):
               tenant = connection.tenant
               if getattr(tenant, "uses_cell_encryption", False):
                   set_current_cell(self._resolve_cell(request))
               try:
                   return self.get_response(request)
               finally:
                   clear_current_cell()

           def _resolve_cell(self, request):
               # your logic here — resolve the cell for this request,
               # e.g. request.user.groups.filter(...).first()
               ...

3. Subclass the abstract adapter for your framework::

       # yourapp/encryption.py
       from encryption_suite.adapters.silo.composite import (
           AbstractCompositeSiloAdapter,
       )

       class MyCompositeSiloAdapter(AbstractCompositeSiloAdapter):

           def get_current_tenant(self):
               from django.db import connection
               tenant = getattr(connection, "tenant", None)
               return None if (not tenant or tenant.schema_name == "public") else tenant

           def is_tenant(self, obj) -> bool:
               return hasattr(obj, "schema_name")   # or isinstance(obj, Client)

           def get_tenant_uid(self, tenant) -> str:
               return f"tenant-{tenant.schema_name}"

           def get_cell_uid(self, cell) -> str:
               # namespace the cell under its tenant to avoid uid collisions
               return f"tenant-{cell.tenant.schema_name}-cell-{cell.pk}"

4. Point settings at your adapter::

       ENCRYPTION = {
           "KEY_SETS": {"default": {"silo": "yourapp.encryption.MyCompositeSiloAdapter", "key_store": "..."}},
           ...
       }

-------------------------------------------------------------------------------
Notes
-------------------------------------------------------------------------------

* ``cell_encryption_flag`` (class attribute, default ``"uses_cell_encryption"``)
  is the name of the boolean field on your tenant model that controls which mode
  is used.  Override it if your field is named differently.

* If a tenant has cell encryption enabled but no cell is active in the current
  context, the adapter raises ``EncryptionConfigurationError`` (slug
  ``configuration_error``) immediately rather than silently falling back to
  tenant-level encryption.  This prevents data from being encrypted under the
  wrong key if middleware is misconfigured.

* A ready-to-use subclass for django-tenants is provided:
  ``DjangoTenantsCompositeSiloAdapter``.
"""

from __future__ import annotations

from abc import abstractmethod
from contextlib import contextmanager
from contextvars import ContextVar

from ..._logging import get_logger
from ...exceptions import log_and_raise_configuration_error
from .base import AbstractSiloAdapter

logger = get_logger(__name__)

# Context variable for the current cell.
# Separate from the top-level silo context var so that frameworks which
# set their own tenant (e.g. django-tenants via connection.tenant) are not
# conflated with the cell set by application middleware.
_current_cell: ContextVar = ContextVar("current_cell", default=None)


def set_current_cell(cell) -> None:
    """Set the active cell for the current context (thread or async task)."""
    _current_cell.set(cell)


def get_current_cell():
    """Return the active cell for the current context, or None."""
    return _current_cell.get()


def clear_current_cell() -> None:
    """Clear the active cell for the current context."""
    _current_cell.set(None)


@contextmanager
def override_current_cell(cell):
    """Context manager: set the cell for the duration of the block."""
    token = _current_cell.set(cell)
    try:
        yield
    finally:
        _current_cell.reset(token)


class AbstractCompositeSiloAdapter(AbstractSiloAdapter):
    """
    Base class for composite silo adapters.

    Handles the branching logic between tenant-level and cell-level encryption.
    Subclass and implement the four abstract methods for your specific framework.
    """

    #: Name of the boolean field on the tenant model that enables cell encryption.
    cell_encryption_flag: str = "uses_cell_encryption"

    # ------------------------------------------------------------------
    # Abstract methods — implement these for your framework
    # ------------------------------------------------------------------

    @abstractmethod
    def get_current_tenant(self):
        """
        Return the current top-level tenant object from ambient context, or None.

        Read from wherever your framework stores it: ``connection.tenant``,
        a thread-local, ``request.team``, etc.
        """

    @abstractmethod
    def is_tenant(self, obj) -> bool:
        """
        Return True if *obj* is a top-level tenant, False if it is a cell.

        Used by ``get_silo_uid()`` to decide which UID method to call.
        Typically an ``isinstance`` check or an attribute check.
        """

    @abstractmethod
    def get_tenant_uid(self, tenant) -> str:
        """Return the unique UID string for a top-level tenant."""

    @abstractmethod
    def get_cell_uid(self, cell) -> str:
        """
        Return the unique UID string for a cell.

        The UID must be globally unique — namespace it under the tenant to avoid
        collisions across tenants, e.g. ``"tenant-{schema}-cell-{pk}"``.
        """

    # ------------------------------------------------------------------
    # AbstractSiloAdapter implementation
    # ------------------------------------------------------------------

    def get_current_silo(self):
        tenant = self.get_current_tenant()
        if tenant is None:
            return None

        if getattr(tenant, self.cell_encryption_flag, False):
            cell = get_current_cell()
            if cell is not None:
                return cell
            # Wiring problem in the consuming project: route through the shared
            # funnel so the actionable operator detail (which tenant, what to
            # call) is logged once under error_code=configuration_error and a
            # typed error escapes whose str() is the generic user-safe message —
            # degrades on read / surfaces cleanly on write, never a raw traceback.
            log_and_raise_configuration_error(
                logger,
                f"Tenant '{self.get_tenant_uid(tenant)}' uses cell encryption but no cell "
                "is active in the current context. Ensure your middleware calls "
                "set_current_cell() before the view runs.",
            )

        return tenant

    def get_silo_uid(self, silo) -> str:
        if self.is_tenant(silo):
            return self.get_tenant_uid(silo)
        return self.get_cell_uid(silo)

    def get_silo_label(self) -> str:
        return "composite"

    # ``supports_enumeration`` stays False (inherited). A composite deployment's
    # silos span TWO model types — tenants AND cells — and the package cannot
    # know the cell model (it is app-specific, resolved from the cell context
    # var). Enumerating tenants ONLY would be worse than not enumerating: every
    # live cell KEK would look orphaned on the reconcile path and could be
    # deleted. So the default refuses; override BOTH this method (to yield every
    # tenant AND every cell) and ``supports_enumeration = True`` to opt in.

    def iter_silos(self):
        from ...exceptions import log_and_raise_enumeration_error

        log_and_raise_enumeration_error(
            logger,
            f"Composite adapter '{type(self).__name__}' cannot enumerate silos "
            "automatically: its silos span both tenants and cells, and the cell "
            "model is app-specific. Override iter_silos() to yield every tenant "
            "AND every cell, and set supports_enumeration = True. A partial list "
            "would make live cells look orphaned on the KEK reconcile path.",
        )


class DjangoTenantsCompositeSiloAdapter(AbstractCompositeSiloAdapter):
    """
    Composite silo adapter for django-tenants.

    Reads the current tenant from ``connection.tenant`` (set automatically by
    the django-tenants middleware).  The current cell is read from the
    context variable set by your ``CellEncryptionMiddleware``.

    Requires your ``Tenant`` model to have a boolean field named
    ``uses_cell_encryption`` (or override ``cell_encryption_flag``).

    Requires your cell model to have a ``tenant`` FK back to the Tenant.
    Override ``get_cell_uid()`` if your relationship is structured differently.
    """

    def get_current_tenant(self):
        from django.db import connection

        tenant = getattr(connection, "tenant", None)
        if tenant is None or getattr(tenant, "schema_name", None) == "public":
            return None
        return tenant

    def is_tenant(self, obj) -> bool:
        """True if obj has a schema_name attribute (i.e. is a django-tenants Tenant)."""
        return hasattr(obj, "schema_name")

    def get_tenant_uid(self, tenant) -> str:
        return f"tenant-{tenant.schema_name}"

    def get_cell_uid(self, cell) -> str:
        return f"tenant-{cell.tenant.schema_name}-cell-{cell.pk}"

    def get_silo_label(self) -> str:
        return "django_tenant_composite"

    def use_silo(self, silo_uid: str):
        # A tenant UID and a cell UID both carry the schema the rows live in. The
        # lookup is deliberately not implemented here: with cell encryption on,
        # the silo is a cell and its schema holds every cell's rows, so "all of
        # the schema" would be the wrong answer. A deployment rotating cells
        # implements queryset_for_silo in the subclass where the cell is defined.
        from .tenants import _schema_context_for_uid

        return _schema_context_for_uid(silo_uid)
