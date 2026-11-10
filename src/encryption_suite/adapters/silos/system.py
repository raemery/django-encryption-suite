"""The built-in silo adapter of the system key sets."""

from __future__ import annotations

from ...conf import SYSTEM_ADAPTER, SYSTEM_SILO_UID, key_sets_of_adapter
from ...silo_ref import SYSTEM_SILO_REF
from .base import AbstractSiloAdapter


class SystemSiloAdapter(AbstractSiloAdapter):
    """The one silo that holds system-wide data, which always exists.

    The registry returns this adapter for the ``system`` key set, which ``KEY_SETS``
    need not list, and for any entry whose ``silo`` is ``"system"``. No ambient state
    selects the silo: there is exactly one, and every row of a model with a system column
    belongs to it.
    """

    supports_enumeration = True
    supports_silo_data_lookup = True
    prevents_key_delete = True

    def is_in_use(self) -> bool:
        from ...models import DataEncryptionKey
        from ...rotation_targets import system_key_sets_needed

        return (
            bool(system_key_sets_needed())
            or DataEncryptionKey.objects.filter(key_set__in=key_sets_of_adapter(SYSTEM_ADAPTER)).exists()
        )

    def queryset_for_silo(self, model, silo_uid: str):
        return model._base_manager.all()

    def get_current_silo(self):
        return SYSTEM_SILO_REF

    def get_silo_uid(self, silo) -> str:
        return SYSTEM_SILO_UID

    def get_silo_label(self) -> str:
        return "system"

    def iter_silos(self):
        yield SYSTEM_SILO_REF

    def silo_exists(self, silo_uid: str) -> bool:
        return silo_uid == SYSTEM_SILO_UID

    def silo_for_uid(self, silo_uid: str):
        return SYSTEM_SILO_REF if silo_uid == SYSTEM_SILO_UID else None

    def describe_silo(self, silo_uid: str) -> str:
        return "System" if silo_uid == SYSTEM_SILO_UID else ""
