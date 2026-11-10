"""
Built-in KEK strategy adapters.

Two strategies ship with django-encryption-suite:

* :class:`PerSiloKekStrategy` — one KEK per silo.  Resolves the
  KEK identifier from ``KEK_MAP`` or ``KEK_TEMPLATE`` in the key store block's
  ``OPTIONS``.

* :class:`SharedKekStrategy` — every silo shares the same KEK.
  Reads the KEK identifier from ``SHARED_KEK_ID`` in the KMS block's
  ``OPTIONS``.

For any other policy (cohort-based, composite-aware, BYOK, etc.), subclass
:class:`~encryption_suite.adapters.kek.base.AbstractKekStrategyAdapter` and
point the block's ``KEK_STRATEGY_ADAPTER`` at your class.
"""

from __future__ import annotations

from ..._logging import get_logger
from ...exceptions import log_and_raise_configuration_error
from .base import (
    DISPOSITION_SHARED,
    DISPOSITION_SILO_EXCLUSIVE,
    AbstractKekStrategyAdapter,
)

logger = get_logger(__name__)


class PerSiloKekStrategy(AbstractKekStrategyAdapter):
    """
    Resolve one KEK per silo.

    ``KEK_TEMPLATE`` is one naming convention and ``KEK_MAP`` one set of explicit
    entries, both for the store. Every key set on the store shares them.

    Resolution order for a silo with uid *uid*:

    1. ``KEK_MAP[uid]`` â€” **exact match** against the raw, *unsanitized*
       silo UID. Use this when your KMS provider identifies keys by UUID or
       OCID, where a naming convention is not practical. Map keys must match the
       silo UID byte-for-byte (e.g. ``"team-42"`` exactly); this lets KEK
       identifiers be opaque values that have no relationship to the UID.
    2. ``KEK_TEMPLATE.format(silo_uid=â€¦)`` â€” naming-convention fallback.
       The silo UID is sanitized to the paired KMS provider's allowed
       charset before substitution (default ``[a-zA-Z0-9_-]``; Fly is
       ``[a-zA-Z0-9_]``; Azure is ``[a-zA-Z0-9-]``). A normal UID like
       ``"team-42"`` fits the default charset and passes through unchanged;
       any character outside the charset is hex-encoded via UTF-8 bytes â€”
       e.g. ``"@"`` becomes ``"_40"`` under the default charset.

       This means ``KEK_MAP`` and ``KEK_TEMPLATE`` are *not* symmetric: a
       map miss does not fall through to a sanitized lookup.
    3. A configuration error â€” neither matched.

    The templates' literal prefixes must be prefix-free across stores: no store's
    prefix may be a prefix of another's. Ownership tests and the destruction
    guard match names with ``startswith``, so an overlap would let one store's
    reconcile read another store's keys as orphans.

    Example configuration::

        ENCRYPTION = {
            "KMS_KEY_STORES": {
                "aws": {
                    "ADAPTER": "encryption_suite.adapters.key_stores.aws.AwsKmsAdapter",
                    "OPTIONS": {
                        "AWS_REGION": "us-east-1",
                        "KEK_TEMPLATE": "alias/encryption_suite-team-{silo_uid}",
                    },
                    "KEK_STRATEGY_ADAPTER": "encryption_suite.adapters.kek.PerSiloKekStrategy",
                },
            },
        }
    """

    def get_kek_id(self, silo_ref) -> str:
        kek_map = self.kek_map()
        if silo_ref.uid in kek_map:
            return kek_map[silo_ref.uid]

        kek_template = self.kek_template()
        if kek_template:
            name = kek_template.format(silo_uid=self._sanitize_uid(silo_ref.uid))
            return self._enforce_name_length(name)

        log_and_raise_configuration_error(
            logger,
            f"PerSiloKekStrategy requires a KEK_TEMPLATE or KEK_MAP in OPTIONS for the key set {silo_ref.key_set!r}.  "
            "See the django-encryption-suite documentation.",
        )

    def shared_kek_problem(self) -> str | None:
        """Report a ``KEK_TEMPLATE`` or ``KEK_MAP`` that resolves two silos to one key.

        A template with no ``{silo_uid}`` placeholder renders the same name for
        every silo, and a map value listed twice names one key for two silos.
        """
        template = self.kek_template()
        if template and "{silo_uid}" not in template:
            return f"KEK_TEMPLATE {template!r} has no {{silo_uid}} placeholder, so every silo resolves to one key."
        values = [value for value in self.kek_map().values() if isinstance(value, str)]
        duplicated = sorted({value for value in values if values.count(value) > 1})
        if duplicated:
            listed = ", ".join(repr(value) for value in duplicated[:5])
            return f"KEK_MAP maps more than one silo to the key {listed}."
        return None

    def kek_disposition(self, silo_ref) -> str:
        """Mirror :meth:`get_kek_id` resolution to classify the KEK.

        - Resolved via ``KEK_MAP`` (an exact-match entry for the silo): the
          KEK identifier is opaque/operator-supplied (UUID, OCID, BYOK ARN), so
          it is :data:`DISPOSITION_SHARED` â€” never auto-destroyed â€” *unless* the
          operator sets ``KEK_MAP_DESTROYABLE`` to opt these keys into
          destruction, in which case it is :data:`DISPOSITION_SILO_EXCLUSIVE`.
        - Resolved via ``KEK_TEMPLATE``: one distinct KEK per silo, named from
          the UID, so :data:`DISPOSITION_SILO_EXCLUSIVE`.
        - Otherwise unresolvable (``get_kek_id`` would raise): fall back to the
          safe :data:`DISPOSITION_SHARED` rather than imply a destroyable key.
        """
        if silo_ref.uid in self.kek_map():
            if self.options.get("KEK_MAP_DESTROYABLE"):
                return DISPOSITION_SILO_EXCLUSIVE
            return DISPOSITION_SHARED
        if self.kek_template():
            return DISPOSITION_SILO_EXCLUSIVE
        return DISPOSITION_SHARED

    def kek_disposition_for_name(self, kek_resource_name: str, owner_prefix: str | None) -> str:
        """Classify a KEK by name, mirroring :meth:`kek_disposition`'s rules.

        - Listed in the ``KEK_MAP``: an opaque, operator-supplied
          identifier, so :data:`DISPOSITION_SHARED` unless ``KEK_MAP_DESTROYABLE``
          opts it into destruction.
        - Carries this deployment's owner prefix: named from a ``KEK_TEMPLATE``,
          so :data:`DISPOSITION_SILO_EXCLUSIVE`.
        - Neither: not a name this strategy produces, so the safe
          :data:`DISPOSITION_SHARED`.

        Kept in step with :meth:`kek_disposition` on purpose â€” the two answer the
        same question from different starting points (a silo, or a stored name),
        and a deployment whose ``KEK_MAP`` keys are destroyable must get the same
        answer either way.
        """
        mapped = set(self.kek_map().values())
        if kek_resource_name in mapped:
            if self.options.get("KEK_MAP_DESTROYABLE"):
                return DISPOSITION_SILO_EXCLUSIVE
            return DISPOSITION_SHARED
        if owner_prefix and kek_resource_name.startswith(owner_prefix):
            return DISPOSITION_SILO_EXCLUSIVE
        return DISPOSITION_SHARED

    def owned_mapped_kek_names(self) -> frozenset[str]:
        """The ``KEK_MAP`` identifiers, when ``KEK_MAP_DESTROYABLE`` is set; otherwise none.

        Setting ``KEK_MAP_DESTROYABLE`` is the operator's statement that this
        deployment owns the mapped keys, so it makes them both deletable (the
        disposition gates) and owned (the ownership gate).
        """
        if self.options.get("KEK_MAP_DESTROYABLE"):
            return self.mapped_kek_names()
        return frozenset()

    def owner_prefix(self) -> str | None:
        """Return the literal ``KEK_TEMPLATE`` prefix that marks the keys of this store owned by this deployment.

        The prefix is everything in the template before the ``{silo_uid}``
        placeholder. It lands in every provisioned key name verbatim (only the
        UID is sanitized), so ``name.startswith(prefix)`` identifies the keys
        this deployment owns â€” used to scope KMS-side reconciliation and to
        guard destruction.

        Returns ``None`` when the store has no ``KEK_TEMPLATE`` (e.g. a
        ``KEK_MAP``-only store): key names are then opaque/operator-supplied and
        cannot be filtered by a naming convention, so KMS-side ownership
        detection is unavailable for it and callers must fall back to DB-only
        reconciliation.

        Two deployments sharing one KMS MUST use distinct template prefixes
        (already required to avoid key-name collisions).
        """
        template = self.kek_template()
        if not template or "{silo_uid}" not in template:
            return None
        prefix = template.split("{silo_uid}", 1)[0]
        return prefix or None

    def describe(self) -> str:
        template = self.kek_template()
        kek_map = self.kek_map()
        if template and kek_map:
            return f"PerSiloKekStrategy(template={template!r}, map={len(kek_map)} entries)"
        if template:
            return f"PerSiloKekStrategy(template={template!r})"
        if kek_map:
            return f"PerSiloKekStrategy(map={len(kek_map)} entries)"
        return "PerSiloKekStrategy(unconfigured)"


class SharedKekStrategy(AbstractKekStrategyAdapter):
    """
    Resolve every silo to the same KEK.

    All silos share a single KEK, read from ``SHARED_KEK_ID`` in
    ``OPTIONS``.  DEKs still differ per silo (each silo has
    its own DEK), so tenant data remains cryptographically separated
    at the DEK layer — but the KEK itself cannot be rotated or revoked for a
    single tenant without rotating it for everyone.

    Use this when the operational cost of managing many KEKs outweighs the
    per-tenant isolation benefit, or when your KMS has low quotas for
    distinct keys.

    Example configuration::

        ENCRYPTION = {
            "KMS_KEY_STORES": {
                "aws": {
                    "ADAPTER": "encryption_suite.adapters.key_stores.aws.AwsKmsAdapter",
                    "OPTIONS": {
                        "AWS_REGION": "us-east-1",
                        "SHARED_KEK_ID": "alias/encryption_suite-shared",
                    },
                    "KEK_STRATEGY_ADAPTER": "encryption_suite.adapters.kek.SharedKekStrategy",
                },
            },
        }
    """

    def get_kek_id(self, silo_ref) -> str:
        kek_id = self.options.get("SHARED_KEK_ID")
        if not kek_id:
            log_and_raise_configuration_error(logger, "SharedKekStrategy requires SHARED_KEK_ID in OPTIONS.")
        return kek_id

    def shared_kek_problem(self) -> str | None:
        return "SharedKekStrategy resolves every silo to the one key SHARED_KEK_ID names."

    def describe(self) -> str:
        kek_id = self.options.get("SHARED_KEK_ID") or "<unset>"
        return f"SharedKekStrategy(kek_id={kek_id!r})"
