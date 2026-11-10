"""The identity of one silo's keys: a key set and the silo adapter's raw uid."""

from __future__ import annotations

from typing import NamedTuple

from . import conf
from .conf import SYSTEM_KEY_SET, SYSTEM_SILO_UID


class SiloRef(NamedTuple):
    """A key set plus the adapter's raw uid, which identifies one silo's keys anywhere in the code.

    The uid is the adapter's own, unmodified. A key set is bound to one silo
    adapter, so the pair names one silo of one adapter and the keys of one key set.
    """

    key_set: str
    uid: str

    @property
    def is_system(self) -> bool:
        """Whether the key set is bound to the package's system adapter."""
        return conf.adapter_path(self.key_set) == conf.SYSTEM_ADAPTER

    def __str__(self) -> str:
        return f"{self.key_set}:{self.uid}"


#: The one silo of the built-in ``system`` key set.
SYSTEM_SILO_REF = SiloRef(SYSTEM_KEY_SET, SYSTEM_SILO_UID)


class AmbientSilo(NamedTuple):
    """The current silo of one key set, resolved through that key set's silo adapter.

    What a field passes the engine: the silo is
    whatever the adapter's context holds when the value is read or written.
    """

    key_set: str


def silo_filter(ref: SiloRef) -> dict:
    """The ``DataEncryptionKey`` / ``KeyLifecycleEvent`` column filter that selects *ref*'s keys."""
    return {"key_set": ref.key_set, "silo_uid": ref.uid}


def whole_silo_filter(ref: SiloRef) -> dict:
    """The column filter that selects the keys of *ref*'s silo in every key set bound to its silo adapter."""
    path = conf.adapter_path(ref.key_set)
    return {"key_set__in": conf.key_sets_of_adapter(path) if path else [ref.key_set], "silo_uid": ref.uid}


def silo_text(silo_ref) -> str:
    """The text *silo_ref* is named by in a log line or an AAD, or ``""`` when it names no silo.

    A reference with an empty uid names no silo, and so does an empty string: a
    key encryption key that no one silo owns is recorded that way.
    """
    return str(silo_ref) if getattr(silo_ref, "uid", silo_ref) else ""
