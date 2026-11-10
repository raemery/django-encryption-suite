"""
Silo adapter for django-tenants.

Resolves the current silo from ``connection.tenant``, which is set
automatically by the django-tenants middleware on every request.
"""

from ..._logging import get_logger
from .base import AbstractSiloAdapter

logger = get_logger(__name__)


def _schema_context_for_uid(silo_uid: str):
    """``schema_context`` on the schema name a ``tenant-…`` UID carries.

    A cell UID (``tenant-<schema>-cell-<pk>``) lives in its tenant's schema, so
    the cell suffix is dropped. The search path it sets is tenant-then-public,
    so tables that exist only in public — this package's key tables — still
    resolve there.
    """
    from django_tenants.utils import schema_context

    schema = silo_uid[len("tenant-") :] if silo_uid.startswith("tenant-") else silo_uid
    schema = schema.split("-cell-", 1)[0]
    return schema_context(schema)


class DjangoTenantsSiloAdapter(AbstractSiloAdapter):
    """Silo adapter for django-tenants Tenant objects."""

    # Every non-public tenant schema is one silo, so enumeration is supported
    # (see iter_silos below). KEK reconcile and setup_encryption_keys rely on it.
    supports_enumeration = True
    # A tenant's rows carry no column naming the tenant — the tenant is the
    # schema the connection points at — so the package cannot filter for one and
    # this adapter answers instead (see queryset_for_silo).
    supports_silo_data_lookup = True

    def get_current_silo(self):
        # connection.tenant is set by the django-tenants middleware. When
        # django-tenants is absent there is simply no `tenant` attribute, so this
        # returns None and the engine raises configuration_error downstream — no
        # explicit import guard needed (django.db is core Django, always present).
        from django.db import connection

        tenant = getattr(connection, "tenant", None)
        if tenant is None or getattr(tenant, "schema_name", None) == "public":
            return None
        return tenant

    def get_silo_uid(self, silo) -> str:
        return f"tenant-{silo.schema_name}"

    def get_silo_label(self) -> str:
        return "django_tenant"

    def silo_for_uid(self, silo_uid: str):
        # A point query on the schema name the UID carries, rather than the base
        # class's walk over every tenant. Through _base_manager, so a tenant
        # model whose default manager hides suspended or soft-deleted tenants
        # cannot make this answer "no such tenant" — the schema and every row in
        # it are still there, and silo_exists is read as a deletion gate.
        if not silo_uid.startswith("tenant-"):
            return None
        from django_tenants.utils import get_tenant_model

        return get_tenant_model()._base_manager.filter(schema_name=silo_uid[len("tenant-") :]).first()

    def silo_exists(self, silo_uid: str):
        return self.silo_for_uid(silo_uid) is not None

    def describe_silo(self, silo_uid: str) -> str:
        try:
            tenant = self.silo_for_uid(silo_uid)
        except Exception:
            return ""
        return str(tenant) if tenant is not None else ""

    def queryset_for_silo(self, model, silo_uid: str):
        # Everything in the schema: inside use_silo the connection's search path
        # is the tenant's, so every row it can see is the tenant's. Lazy, so
        # building it touches no schema at all.
        return model._base_manager.all()

    def use_silo(self, silo_uid: str):
        return _schema_context_for_uid(silo_uid)

    def iter_silos(self):
        from ...exceptions import log_and_raise_enumeration_error

        try:
            from django_tenants.utils import get_tenant_model
        except ImportError as exc:
            log_and_raise_enumeration_error(
                logger,
                "django-tenants is not installed; cannot enumerate tenants.",
                cause=exc,
            )
        # The public schema is shared infrastructure, never a silo. Everything
        # else is one, whatever the tenant model's default manager shows: a
        # tenant left out of this list is read as an orphan by reconcile.
        return get_tenant_model()._base_manager.exclude(schema_name="public")
