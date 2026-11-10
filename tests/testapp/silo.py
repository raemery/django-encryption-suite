from encryption_suite.adapters.silos.generic import GenericModelSiloAdapter


class TenantSiloAdapter(GenericModelSiloAdapter):
    model_label = "testapp.Tenant"
    uid_field = "pk"
    label = "tenant"


class WorkspaceSiloAdapter(GenericModelSiloAdapter):
    """A silo whose model hides soft-deleted rows from its default manager."""

    model_label = "testapp.Workspace"
    uid_field = "pk"
    label = "workspace"
