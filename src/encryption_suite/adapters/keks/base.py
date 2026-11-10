"""
KEK strategy adapter interface.

A KEK strategy decides which key encryption key (KEK) on the KMS encrypts the data encryption key
(DEK) for a given silo.  It sits between the silo layer (which
identifies the silo) and the KMS adapter (which talks to the cloud KMS).

The strategy is the extension point for provisioning policies such as:

* One KEK per silo (maximum isolation, per-tenant deletion).
* A single shared KEK (cheapest, no isolation).
* Cohort-based KEKs (e.g. one KEK per region or compliance class).
* Composite-aware KEKs (top-level tenants use one KEK each; group-encrypted
  tenants use one KEK per group).
* BYOK pass-through (each tenant supplies their own KEK ARN in a model field).

Subclass this to implement a policy that is not covered by the built-in
strategies in :mod:`encryption_suite.adapters.kek.strategies`.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from ..._logging import get_logger
from ...exceptions import log_and_raise_configuration_error
from .sanitization import ALNUM_UNDERSCORE_HYPHEN, sanitize_uid

logger = get_logger(__name__)

# KEK disposition: whether a silo's KEK may be destroyed when the silo is torn
# down. This is the first of the three deletion gates (disposition → provisioner
# ownership → name-prefix ownership); only ``silo_exclusive`` KEKs are eligible
# for destruction, and only then if the other gates also pass.
DISPOSITION_SILO_EXCLUSIVE = "silo_exclusive"  # one KEK per silo — destroyable
DISPOSITION_SHARED = "shared"  # KEK shared / opaque / operator-owned — never auto-destroy


class AbstractKekStrategyAdapter(ABC):
    """
    Interface for resolving a silo reference to a provider-specific KEK identifier.

    Instances are constructed once per process and reused across requests, so
    the strategy should be side-effect free and thread-safe.  Any mutable state
    (caches, KMS clients) must be guarded by appropriate locking.

    The *options* dict passed to the constructor is the same ``OPTIONS`` dict
    of the KMS block used by the KMS adapter, so strategies can read their configuration
    from the same place as the KMS adapter they sit in front of.
    """

    def __init__(
        self,
        options: dict,
        allowed: frozenset[str] = ALNUM_UNDERSCORE_HYPHEN,
        escape: str = "_",
        max_length: int | None = None,
    ) -> None:
        self.options = options
        self._allowed = allowed
        self._escape = escape
        self._max_length = max_length

    @abstractmethod
    def get_kek_id(self, silo_ref) -> str:
        """
        Return the provider-specific KEK identifier for *silo_ref*, a
        :class:`~encryption_suite.silo_ref.SiloRef` (the silo's kind and uid).

        The returned string is passed directly to the KMS adapter, which uses it
        as whatever its provider addresses keys by — a key id, a resource name, or
        a name it resolves to an opaque id.

        Raise ``ValueError`` if the strategy cannot resolve a KEK for the given
        silo — this is treated as a configuration error and surfaces to
        the caller unchanged.
        """

    def describe(self) -> str:
        """Human-readable description of the strategy configuration (for logging)."""
        return type(self).__name__

    def shared_kek_problem(self) -> str | None:
        """Say how this configuration lets two silos resolve to one KEK, or ``None`` when it does not.

        Asked at construction by a KMS adapter whose provider cannot bind
        associated data into a wrapped DEK. For such an adapter a distinct KEK
        per silo is the only boundary at the wrap layer, so it refuses any
        configuration this method reports.

        The default is ``None``: a strategy the package cannot inspect is taken
        at its word. A custom strategy that can resolve two silos to one key
        should override this and say so.
        """
        return None

    def kek_disposition(self, silo_ref) -> str:
        """Return whether the KEK for *silo_ref* may be destroyed on deletion.

        One of :data:`DISPOSITION_SILO_EXCLUSIVE` (the KEK belongs to exactly
        one silo and is eligible for destruction when that silo is torn down) or
        :data:`DISPOSITION_SHARED` (the KEK is shared across silos, or is an
        opaque/operator-owned identifier, and must never be auto-destroyed).

        The default is :data:`DISPOSITION_SHARED` — the conservative answer that
        leaves the KEK in place. Strategies that provision one distinct KEK per
        silo override this. Disposition is the first deletion gate; even
        ``silo_exclusive`` only leads to destruction if the provisioner
        provisioned the KEK and its name carries this deployment's owner prefix.
        """
        return DISPOSITION_SHARED

    def kek_disposition_for_name(self, kek_resource_name: str, owner_prefix: str | None) -> str:
        """Return the disposition of a KEK known only by its name.

        The counterpart to :meth:`kek_disposition` for a key encryption key row,
        which carries no silo UID: a discovered orphan never had one, and a
        shared key has many. Asked when a KEK is scheduled for deletion, so the
        snapshot recorded on the row is derived rather than assumed.

        The default is :data:`DISPOSITION_SHARED` — the same conservative answer
        :meth:`kek_disposition` defaults to, so a strategy that cannot tell never
        implies a destroyable key. Strategies that name keys from a template
        override this; one that resolves every silo to the same key does not need
        to, since none of its keys is ever exclusive to one silo.

        *owner_prefix* is this deployment's prefix already canonicalized into the
        name space the row records (see
        :meth:`AbstractKmsAdapter.owner_prefix`), so an override can compare it
        against *kek_resource_name* directly. ``None`` when ownership cannot be
        derived at all.
        """
        return DISPOSITION_SHARED

    def owner_prefix(self) -> str | None:
        """Return a literal key-name prefix marking the keys of this store owned by this deployment.

        Used to scope KMS-side reconciliation and to guard destruction to keys
        this deployment provisioned. The default returns ``None`` — meaning
        ownership cannot be derived from a naming convention (e.g. shared or
        BYOK/opaque key identifiers), so KMS-side ownership detection is
        unavailable and callers must fall back to DB-only reconciliation.

        Strategies that name keys from a template (see
        :class:`~encryption_suite.adapters.kek.strategies.PerSiloKekStrategy`)
        override this to return the template's literal prefix.
        """
        return None

    def kek_template(self) -> str | None:
        """The store's ``KEK_TEMPLATE``, or ``None`` when it has none."""
        template = self.options.get("KEK_TEMPLATE")
        return template if isinstance(template, str) and template else None

    def kek_map(self) -> dict:
        """The store's ``KEK_MAP``: silo uid to KEK identifier. Empty when it has none."""
        kek_map = self.options.get("KEK_MAP")
        return kek_map if isinstance(kek_map, dict) else {}

    def mapped_kek_names(self) -> frozenset[str]:
        """Every KEK identifier the store's ``KEK_MAP`` names."""
        return frozenset(value for value in self.kek_map().values() if isinstance(value, str))

    def owned_mapped_kek_names(self) -> frozenset[str]:
        """The ``KEK_MAP`` identifiers this deployment owns, and so may delete.

        A mapped identifier is a name the operator supplied, so the default is that
        none is owned. Strategies with an opt-in for deleting mapped keys override
        this. A key is owned when its name carries :meth:`owner_prefix` or it is in
        this set.
        """
        return frozenset()

    def _sanitize_uid(self, uid: str) -> str:
        """Encode UID for use in KMS key names using the configured charset.

        Charset and escape char are set via the constructor and typically
        supplied by :meth:`AbstractKmsAdapter.build_strategy` so they match the
        paired KMS provider's key-naming rules.

        For example, with an underscore-only charset (``[A-Za-z0-9_]``):
        - ``"team-1"`` becomes ``"team_2d1"`` (dash encoded as hex)
        - ``"team_1"`` becomes ``"team__1"`` (underscore escaped)

        The provider's length cap is *not* applied here — it governs the whole
        rendered key name (``KEK_TEMPLATE`` prefix + sanitized UID), so it is
        enforced after templating by :meth:`_enforce_name_length`. Non-ASCII
        chars expand to 3 chars per UTF-8 byte (e.g. one emoji can produce 12
        chars), so a permissive raw UID can blow past the provider limit
        unexpectedly.
        """
        return sanitize_uid(uid, self._allowed, self._escape)

    def _enforce_name_length(self, name: str) -> str:
        """Return *name* unchanged, or raise if it exceeds the provider's cap.

        ``max_length`` (from the paired KMS adapter) is the limit the provider
        imposes on the **whole** key name, so this is applied to the rendered
        ``KEK_TEMPLATE`` result rather than to the sanitized UID alone — a short
        template prefix plus a long UID can overflow even when the UID by itself
        would fit.
        """
        if self._max_length is not None and len(name) > self._max_length:
            log_and_raise_configuration_error(
                logger,
                f"KMS key name {name!r} ({len(name)} chars) exceeds the "
                f"{self._max_length}-character limit imposed by the KMS provider's key naming "
                f"rules. Use a shorter KEK_TEMPLATE prefix or a shorter silo UID (each "
                f"non-ASCII char in the UID expands to 3 chars per UTF-8 byte).",
            )
        return name
