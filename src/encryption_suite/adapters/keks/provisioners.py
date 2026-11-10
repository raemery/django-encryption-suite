"""
KEK provisioner adapters.

A *provisioner* creates the KEK on the KMS provider when it does not already
exist. It is a separate concern from the *strategy*, which only decides the
KEK's name/identifier for a given silo. Splitting the two lets you mix
any naming policy with any provisioning policy.

Provisioners are optional. The default :class:`NullKekProvisioner` does
nothing, preserving the library's original behavior: KEKs must be created
outside this application (Terraform, a bootstrap script, a manual console action) before
encryption can succeed.

Writing a real provisioner requires IAM permissions beyond ``Encrypt`` and
``Decrypt`` — typically ``CreateKey``, ``CreateAlias``, or the provider's
equivalent. Some organizations forbid application-created KEKs for
compliance reasons; in that case, keep the default and rely on outside this application
provisioning plus the clear error surfaced by
:class:`~encryption_suite.exceptions.KekNotProvisionedError`.
"""

from __future__ import annotations

import datetime
from abc import ABC, abstractmethod
from dataclasses import dataclass

from ..._logging import get_logger
from ...exceptions import (
    EncryptionError,
    log_and_raise_configuration_error,
    log_and_raise_delete_error,
    log_and_raise_kek_enumeration_error,
)
from ...silo_ref import silo_text
from .._http import resolve_request_timeout
from .._tls import build_ssl_context

logger = get_logger(__name__)


@dataclass(frozen=True)
class TaggingStatus:
    """What the configured provisioner will actually do with ``TAGS``.

    Structured facts only — no display strings — so the startup check and the
    test console can read the same source and phrase it for their own audience
    (operator English in a ``manage.py check`` line, translated text in the
    admin). Keeping one derivation is the point: the two drifting apart is how
    ``supports_tagging`` became vestigial the first time.
    """

    #: Number of ``{key: value}`` pairs in the operator's ``TAGS``.
    tag_count: int
    #: The pairs themselves, in configured order. Structured, not rendered: the
    #: console shows them so an operator can check the values rather than only
    #: the count, and it does its own truncation for the panel it draws.
    tags: tuple[tuple[str, str], ...]
    #: Number of ``{namespace: {key: value}}`` namespaces in ``DEFINED_TAGS``,
    #: for providers whose tags are namespaced; zero elsewhere.
    defined_tag_namespace_count: int
    #: Those namespaces by name. The tree beneath them is not carried: naming
    #: which namespaces are in play is what an operator checks, and rendering
    #: the nesting inline would need a format nothing else needs.
    defined_tag_namespaces: tuple[str, ...]
    #: Whether the provisioner's create-key call can carry them at all.
    supported: bool

    @property
    def configured(self) -> bool:
        return bool(self.tag_count or self.defined_tag_namespace_count)

    @property
    def dropped(self) -> bool:
        """Tags are configured but this provisioner cannot write them.

        The deploy-time defect worth reporting: a cost tag silently dropped
        yields a wrong chargeback report, and an ownership tag silently dropped
        means every key this deployment creates lacks the tag a deny-untagged
        policy keys on — so the policy either protects nothing or renders those
        keys undeletable.
        """
        return self.configured and not self.supported


def describe_tagging(provisioner) -> TaggingStatus:
    """Report how *provisioner* will treat the configured ``TAGS``."""
    options = getattr(provisioner, "options", None) or {}
    defined = options.get("DEFINED_TAGS") or {}
    tags = options.get("TAGS") or {}
    return TaggingStatus(
        tag_count=len(tags),
        tags=tuple((str(key), str(value)) for key, value in tags.items()),
        defined_tag_namespace_count=len(defined),
        defined_tag_namespaces=tuple(str(namespace) for namespace in defined),
        supported=bool(getattr(provisioner, "supports_tagging", False)),
    )


@dataclass(frozen=True)
class DeleteOutcome:
    """Result of a successful KEK deletion request.

    *scheduled* is ``True`` when the provider scheduled deletion for a future
    date — the common case, since most providers enforce a waiting period during
    which the key can still be recovered; *effective_at* is then that date. It is
    ``False`` where the provider deletes immediately and irreversibly, in which
    case *effective_at* is the moment of deletion.

    The deletion command uses this to set the tombstone state: ``scheduled`` →
    ``SCHEDULED`` (Phase 3 reconcile later confirms the key is gone and flips it
    to ``DELETED``); not ``scheduled`` → ``DELETED`` directly.
    """

    scheduled: bool
    effective_at: datetime.datetime

    @property
    def event(self) -> str:
        """The lifecycle event this outcome records.

        Held here so the log line and the ledger row cannot spell the same act
        two ways: the provisioner logs from this, and the caller that records
        the event reads it rather than deriving its own.
        """
        from ... import lifecycle

        return lifecycle.EVENT_DELETION_REQUESTED if self.scheduled else lifecycle.EVENT_DELETED


@dataclass(frozen=True)
class KekState:
    """What the provider currently reports about a key's own lifecycle.

    Three answers, and the third is not a failure mode to be smoothed over:

    * ``active`` — the key exists and is usable.
    * ``pending_deletion`` — the provider's own deletion window is running, with
      *effective_at* set to the date it destroys the key when it reports one.
    * ``unknown`` — nobody asked, or asking failed. Callers must treat this as
      "no information", never as "active": inferring health from a failed probe
      is how a reconcile report starts lying.

    Read-only and advisory. Nothing gates a destructive act on this — the purge
    re-checks its own conditions — so a probe that errors degrades to ``unknown``
    rather than raising.
    """

    UNKNOWN = "unknown"
    ACTIVE = "active"
    PENDING_DELETION = "pending_deletion"

    state: str = UNKNOWN
    effective_at: datetime.datetime | None = None

    @property
    def is_pending_deletion(self) -> bool:
        return self.state == self.PENDING_DELETION

    @classmethod
    def unknown(cls) -> KekState:
        return cls()


class AbstractKekProvisioner(ABC):
    """
    Interface for ensuring a KEK exists on the configured KMS provider.

    Instances are constructed once per process and reused across requests,
    so implementations must be thread-safe. Any mutable state (KMS clients,
    per-KEK caches) must be guarded by appropriate locking.

    The *options* dict passed to the constructor is the KMS block's
    ``KEK_PROVISIONER_OPTIONS``. This is intentionally separate from the
    block's ``OPTIONS`` because provisioning often needs different
    credentials, tags, key specs, or key policies than routine encrypt/decrypt
    use.
    """

    def __init__(self, options: dict) -> None:
        self.options = options
        # Honors TLS_CA_BUNDLE / TLS_EXTRA_CA for urllib-based provisioners.
        # SDK-backed provisioners ignore this and rely on the SDK's own TLS
        # configuration, usually its own environment variables.
        self._ssl_context = build_ssl_context(options)
        # HTTP request timeout (seconds) for urllib-based provisioners; read
        # from KMS_REQUEST_TIMEOUT_SECONDS in KEK_PROVISIONER_OPTIONS (default 10).
        self._request_timeout = resolve_request_timeout(options)
        self._validate_deletion_window(options)
        self._validate_rotation_period(options)

    def _validate_deletion_window(self, options: dict) -> None:
        """Reject a ``PROVIDER_DELETION_WINDOW_DAYS`` the provider will not accept.

        Checked at construction so ``manage.py check`` reports it at deploy. The
        provider would otherwise reject it at the first *encrypt*, on the key
        creation call, as an opaque provider error on a request that has nothing
        to do with deletion — and only for the first tenant unlucky enough to
        trigger provisioning.

        A value under the floor is worth its own wording, because it is usually a
        wiring mistake rather than a wrong number: this window is easily confused
        with the package's own ``KEY_DELETION_WINDOW_DAYS``, which legitimately
        accepts 0. A value over the ceiling is a plain out-of-range mistake.

        A bound left ``None`` is not checked — *undeclared*, not *unbounded*. A
        provider that rejects out-of-range values then does so at key creation, on
        a request that has nothing to do with deletion, and only for the first
        tenant unlucky enough to trigger provisioning.
        """
        minimum = self.minimum_deletion_window_days
        maximum = self.maximum_deletion_window_days
        if (minimum is None and maximum is None) or "PROVIDER_DELETION_WINDOW_DAYS" not in options:
            return
        raw = options["PROVIDER_DELETION_WINDOW_DAYS"]
        try:
            configured = int(raw)
        except (TypeError, ValueError):
            log_and_raise_configuration_error(
                logger,
                f"{type(self).__name__}: PROVIDER_DELETION_WINDOW_DAYS in KEK_PROVISIONER_OPTIONS "
                f"must be a whole number of days, got {raw!r}.",
            )
        if minimum is not None and configured < minimum:
            log_and_raise_configuration_error(
                logger,
                f"{type(self).__name__}: PROVIDER_DELETION_WINDOW_DAYS is {configured}, but this "
                f"provider refuses anything under {minimum} day(s) and will reject key creation. "
                "This is the KMS provider's own deletion window, not the package's — "
                "KEY_DELETION_WINDOW_DAYS in ENCRYPTION is the one that accepts 0, and the two are "
                "easy to wire to the same value by accident. Set PROVIDER_DELETION_WINDOW_DAYS to "
                f"{minimum} or more, or remove it to take the default of "
                f"{self.default_deletion_window_days}.",
            )
        if maximum is not None and configured > maximum:
            log_and_raise_configuration_error(
                logger,
                f"{type(self).__name__}: PROVIDER_DELETION_WINDOW_DAYS is {configured}, but this "
                f"provider refuses anything over {maximum} day(s) and will reject key creation. "
                f"Set it to {maximum} or less, or remove it to take the default of "
                f"{self.default_deletion_window_days}.",
            )

    @abstractmethod
    def ensure_kek(self, kek_resource_name: str, silo_ref: str) -> bool:
        """
        Ensure *kek_resource_name* exists on the KMS provider.

        Returns whether **this call created the key**. The engine records that as
        the row's first-sighting ledger verb, so the difference between a key
        this deployment made and one it found already there is a fact rather than
        an inference from whether a provisioner happens to be configured. Return
        ``False`` when the key was already present, when a race meant another
        process created it, and from any provisioner that never creates.

        Called by the engine before the first encryption under a new KEK.
        Implementations must be idempotent — this method will be called every
        time a new silo's DEK is created, and may be called repeatedly
        for the same KEK if caches are flushed.

        *silo_ref* is provided for logging and for any provisioner that
        wants to tag the created key with the tenant identifier. It must not
        be used to derive the KEK name — that is the strategy's responsibility.

        Raise ``Exception`` (or any subclass) on unrecoverable failure. The
        engine translates provider-specific errors into
        :class:`~encryption_suite.exceptions.KekNotProvisionedError` for
        the caller.
        """

    def describe(self) -> str:
        """Human-readable description of the provisioner (for logging)."""
        return type(self).__name__

    # ------------------------------------------------------------------
    # Tagging
    # ------------------------------------------------------------------

    def build_tags(self, silo_ref: str) -> dict:
        """Return the tags to attach to a KEK at creation time.

        The default is the operator's ``TAGS`` option verbatim — the package
        adds, removes, and reorders nothing, so what lands on a key is exactly
        what was configured. ``TAGS`` is provider-neutral in name; each
        provisioner maps it onto whatever its provider calls that field, and
        applies its own charset rules to the result.

        *silo_ref* is passed for overrides only. The package does **not** tag
        keys with it: under ``KEK_TEMPLATE`` the UID is already in the key name
        (which is what :meth:`owns_kek` reads), and a per-tenant value suits
        neither ABAC (a policy cannot name an unbounded value) nor cost
        allocation (N tenants become N billing dimensions).

        Override to add tags a static dict cannot express — a per-tenant cost
        center, say — calling ``super()`` and adding to the result::

            def build_tags(self, silo_ref):
                tags = super().build_tags(silo_ref)
                tags["cost-center"] = lookup_cost_center(silo_ref)
                return tags

        Three hazards for an override:

        * Under :class:`SharedKekStrategy` every silo resolves to the same KEK
          and only the first one to encrypt triggers creation, so a per-tenant
          value permanently labels that key with one arbitrary tenant. The same
          applies to any ``KEK_MAP`` entries an operator has pointed at a shared
          key id.
        * ``ensure_kek`` runs on the first-encrypt path *inside a user request*,
          so a synchronous call to an accounting API puts its latency and its
          outages in front of a tenant's first write. Cache it, or read a value
          already denormalized onto the tenant row.
        * If this raises, the engine funnel turns it into
          :class:`~encryption_suite.exceptions.KekNotProvisionedError` — a
          broken tag lookup becomes a failed encryption. No tag beats no key.
        """
        if not self.supports_tagging:
            return {}
        return dict(self.options.get("TAGS", {}) or {})

    def sync_tags(self, existing_key, silo_ref: str) -> None:
        """Add any configured tag missing from an existing key.

        A no-op almost everywhere: where a provider holds tags on the key itself,
        they survive a rotation, so what was written at creation is still there.
        A provider that holds them per key *version* is the exception — whether a
        new version inherits them can depend on how it was made, so the current
        version's tags cannot be predicted from the configuration, only compared
        against it.

        **Additive only.** Tags this deployment did not configure are left
        exactly as they are — an operator's cost center, a compliance marker, a
        label some other tool maintains. This never removes a tag and never
        changes the value of one it did not configure; it only adds what is
        missing. A configured tag whose value differs on the key is left alone
        too: that is an operator's deliberate edit, and overwriting it would be
        the same overreach as deleting one.

        Called from ``ensure_kek`` on the path that has already fetched the key,
        so it costs nothing when the tags are in order. Implementations must not
        let a failure here break provisioning — a tag is not worth a failed save.
        """
        return None

    # ------------------------------------------------------------------
    # KEK destruction (deletion)
    # ------------------------------------------------------------------

    #: Whether this provisioner can delete (schedule deletion of) a KEK it
    #: provisioned. ``False`` by default — deleting requires IAM beyond
    #: encrypt/decrypt, and not every provider/path supports it. The purge checks
    #: this before attempting a
    #: deletion and retains the key with a recorded reason when ``False``.
    supports_delete: bool = False

    #: Whether this provisioner can carry the operator's ``TAGS`` onto the keys
    #: it creates. ``False`` by default — a provider whose create-key API takes
    #: no metadata can never write them.
    #: Nothing refuses an operation on this flag: you would not decline to
    #: create a key because it cannot be tagged. It is read at *deploy* time, by
    #: the ``TAGS``-set-but-unsupported system check and the test console, so a
    #: silently dropped tag is visible instead of discovered in the provider
    #: console — and by :meth:`build_tags`, which short-circuits on ``False``.
    supports_tagging: bool = False

    #: Whether this provisioner can LIST the KEKs it provisioned on the KMS — the
    #: KMS half of reconcile (the silo half is ``AbstractSiloAdapter.iter_silos``).
    #: ``False`` by default: listing requires IAM beyond encrypt/decrypt, and not
    #: every provider/path supports it. Reconcile checks this before calling
    #: :meth:`list_kek_names`;
    #: when ``False`` the KMS side degrades to *detection-unavailable* (reported
    #: for manual audit, never auto-orphaned). Implemented per provider in the
    #: same retest cycle as ``delete``/``tagging``.
    supports_enumeration: bool = False

    #: Whether this provisioner can report a key's own lifecycle state on the
    #: provider — distinct from *whether it exists*, which enumeration answers.
    #: ``False`` by default: only providers with a deletion window have a state
    #: worth reporting, and each needs its own describe/get call. Reconcile reads
    #: this to decide whether probing is worth a round trip.
    supports_state_check: bool = False

    #: Provider deletion window, in days, when ``PROVIDER_DELETION_WINDOW_DAYS``
    #: is not configured. Every provider with a window defaults to the same 7
    #: days: the data is already crypto-shredded when this window starts, so the
    #: tail guards against operator error on the key rather than data loss, and a
    #: long one mostly prolongs billing. Ignored by providers whose deletion is
    #: immediate.
    default_deletion_window_days: int = 7

    #: Shortest window the provider will accept, in days, or ``None`` when it has
    #: no window at all (deletion is immediate) or none has been established.
    #: Declared per provider because the floors differ. Also read by
    #: :meth:`deletion_window_days`, which hands this to the test console's keys.
    minimum_deletion_window_days: int | None = None

    #: Longest window the provider will accept, in days, or ``None`` where no
    #: ceiling has been established. Declared per provider like the floor;
    #: ``None`` means *undeclared*, not *unbounded*.
    maximum_deletion_window_days: int | None = None

    #: Whether this provisioner can put an automatic rotation schedule on the keys
    #: it creates. ``False`` by default: most providers either have no such
    #: concept or need a permission beyond key creation, and a rotation setting
    #: that is silently ignored is worse than one that is refused.
    supports_rotation_policy: bool = False

    #: Shortest rotation interval the provider accepts, in days, or ``None`` where
    #: no rotation policy exists. Declared per provider because the floors differ.
    minimum_rotation_days: int | None = None

    #: Longest rotation interval the provider accepts, in days, or ``None`` where
    #: no ceiling has been established. Declared per provider like the floor.
    #: ``None`` means *undeclared*, not *unlimited*: an over-large value then
    #: surfaces as the provider's own rejection at key creation rather than at
    #: deploy.
    maximum_rotation_days: int | None = None

    #: What an operator can do when this provider refuses a rotation policy.
    #: Declared per provider because the permission, the console command, and
    #: sometimes the cause differ; every provisioner that sets a rotation policy
    #: supplies one, so the failure line always ends in something actionable.
    rotation_policy_remedy: str = ""

    #: Opening clause of that failure line. Overridden only where the cause is not
    #: a permission — a provider that refuses the schedule outright leads with the
    #: refusal instead.
    rotation_policy_failure_opening: str = "The key was created and works, but it will not rotate on its own."

    def _log_rotation_policy_failed(self, *, kek: str, days, cause, **extra) -> None:
        """Report a key that was created without the rotation policy it asked for.

        One emission point so the level, the field names, and the quoting cannot
        drift apart across providers; only the wording varies, and it varies
        through the two class attributes above.
        """
        from ..._internal import operator_error_text

        fields = "".join(f" {name}={value}" for name, value in extra.items())
        logger.warning(
            '%s %s kek="%s" days=%s detail="%s"%s',
            self.rotation_policy_failure_opening,
            self.rotation_policy_remedy,
            kek,
            days,
            operator_error_text(cause),
            fields,
        )

    def _log_rotation_policy_set(self, *, kek: str, days, **extra) -> None:
        """Report a rotation policy the provider accepted."""
        fields = "".join(f" {name}={value}" for name, value in extra.items())
        logger.info(
            'Automatic rotation was set on the key. kek="%s" days=%s%s',
            kek,
            days,
            fields,
        )

    def _log_kek_created(self, *, kek: str, silo_ref: str, **extra) -> None:
        """Report a key encryption key this deployment just created."""
        from ... import lifecycle

        fields = "".join(f" {name}={value}" for name, value in extra.items())
        logger.info(
            'A key encryption key was created for this silo. event=%s silo="%s" kek="%s"%s',
            lifecycle.EVENT_CREATED,
            silo_ref,
            kek,
            fields,
        )

    def _log_kek_already_present(self, *, kek: str) -> None:
        """Report a create that lost a race and adopted the existing key."""
        logger.info(
            "Another process created this key first, so the failed create was recovered and the "
            'existing key is in use. kek="%s"',
            kek,
        )

    def _log_kek_absent_on_delete(self, *, kek: str, silo_ref: str) -> None:
        """Report a deletion that found nothing to delete."""
        logger.info(
            'There was no such key at the provider, so the deletion had nothing to do. silo="%s" kek="%s"',
            silo_text(silo_ref) or "n/a",
            kek,
        )

    def _log_kek_deletion_already_underway(self, *, kek: str, silo_ref: str, state: str) -> None:
        """Report a deletion the provider had already begun.

        *state* names which of the provider-shaped conditions this is; they are
        genuinely different states rather than one spelled several ways, so the
        distinction is carried as a value rather than flattened into the prose.
        """
        logger.info(
            "The provider reports this key's deletion is already under way, so nothing further "
            'was requested. state=%s silo="%s" kek="%s"',
            state,
            silo_text(silo_ref) or "n/a",
            kek,
        )

    def rotation_period_days(self) -> int | None:
        """Return the configured rotation interval in days, or ``None`` for manual.

        ``KEK_ROTATION_PERIOD_DAYS`` is provider-neutral, and each provisioner renders
        it in its own provider's units — seconds, an ISO 8601 duration, a count of
        months. Days is the shared unit because it converts exactly to each of
        those, where ISO months or years would need an assumed month length to
        become seconds.
        """
        configured = self.options.get("KEK_ROTATION_PERIOD_DAYS")
        return int(configured) if configured else None

    def _validate_rotation_period(self, options: dict) -> None:
        """Reject a ``KEK_ROTATION_PERIOD_DAYS`` this provider cannot honor.

        Checked at construction, like the deletion window, so ``manage.py check``
        reports it at deploy. Three failures are worth separating: a provider that
        takes no rotation policy at all (where the setting would otherwise be
        read, ignored, and quietly leave keys unrotated), and a value outside the
        provider's floor or ceiling (which the provider rejects at key creation,
        on a request that has nothing to do with rotation).

        A provider whose rule a range cannot express — one whose interval is
        counted in a coarser unit, say — overrides this, calls ``super()``, and
        adds its own check.
        """
        if "KEK_ROTATION_PERIOD_DAYS" not in options:
            return
        if not self.supports_rotation_policy:
            log_and_raise_configuration_error(
                logger,
                f"{type(self).__name__}: KEK_ROTATION_PERIOD_DAYS is set in KEK_PROVISIONER_OPTIONS, but this "
                "provisioner cannot set a rotation schedule on the keys it creates, so the setting would "
                "have no effect and the keys would never rotate. Remove it, and rotate at the provider "
                "instead — `manage.py reencrypt_keys` re-wraps the data encryption keys afterwards.",
            )
        raw = options["KEK_ROTATION_PERIOD_DAYS"]
        try:
            configured = int(raw)
        except (TypeError, ValueError):
            log_and_raise_configuration_error(
                logger,
                f"{type(self).__name__}: KEK_ROTATION_PERIOD_DAYS in KEK_PROVISIONER_OPTIONS must be a whole "
                f"number of days, got {raw!r}.",
            )
        minimum = self.minimum_rotation_days
        if minimum is not None and configured < minimum:
            log_and_raise_configuration_error(
                logger,
                f"{type(self).__name__}: KEK_ROTATION_PERIOD_DAYS is {configured}, but this provider refuses "
                f"anything under {minimum} day(s) and will reject the rotation schedule. Set it to "
                f"{minimum} or more, or remove it to leave the keys on manual rotation.",
            )
        maximum = self.maximum_rotation_days
        if maximum is not None and configured > maximum:
            log_and_raise_configuration_error(
                logger,
                f"{type(self).__name__}: KEK_ROTATION_PERIOD_DAYS is {configured}, but this provider refuses "
                f"anything over {maximum} day(s) and will reject the rotation schedule. Set it to "
                f"{maximum} or less, or remove it to leave the keys on manual rotation.",
            )

    def deletion_window_days(self, silo_ref: str = "") -> int:
        """Return the provider deletion window, in days, for *silo_ref*'s key.

        The configured ``PROVIDER_DELETION_WINDOW_DAYS``, except for the admin
        test console's sentinel silos, which always get
        :attr:`minimum_deletion_window_days`. The console already bypasses the
        package's own window — it deletes at the provider directly and hard-deletes
        its rows, rather than scheduling and waiting for a purge — because its keys
        hold no tenant data and exist to be created and destroyed repeatedly.
        Leaving them to sit out a production-length provider window would
        contradict that: it costs money for a key nobody can use, and it stalls the
        one workflow that proves deletion works end to end.

        Pass *silo_ref* wherever the provider will accept a window; omit it where
        the caller has no silo in hand (a state probe, a fallback date), which
        yields the configured value.

        **Where to call it is provider-specific.** A provider that takes the window
        as an argument to its delete call reads it at deletion; one that fixes the
        window on the key at creation must read it in ``ensure_kek``, because by
        deletion time it is welded on and a console key created under the
        configured window keeps it for good.
        """
        configured = int(self.options.get("PROVIDER_DELETION_WINDOW_DAYS", self.default_deletion_window_days))
        if self.minimum_deletion_window_days is None or not silo_text(silo_ref):
            return configured
        from ...conf import reserved_test_uids

        if silo_ref.uid in reserved_test_uids():
            return self.minimum_deletion_window_days
        return configured

    def describe_kek_state(self, kek_resource_name: str) -> KekState:
        """Report what the provider currently says about *kek_resource_name*.

        Advisory only, and deliberately incapable of failing loudly: an
        unsupported provisioner, a provider error, and a malformed response all
        yield :meth:`KekState.unknown`. Callers use this to annotate a report, so
        a probe that breaks must degrade to "no information" rather than break
        the page it annotates.

        Reconcile calls this for keys it would otherwise report as orphaned. A key
        the provider says is already being deleted is not awaiting a decision, and
        without this the only way to learn that is to attempt an encrypt under it.
        """
        if not self.supports_state_check:
            return KekState.unknown()
        try:
            return self._do_describe_kek_state(kek_resource_name)
        except Exception as exc:
            from ..._internal import operator_error_text

            # One clean English line, no traceback: this is an advisory probe, so
            # a provider hiccup is worth a note, not a stack trace implicating the
            # package. The raw provider string never reaches the log.
            logger.warning(
                "The provider would not report this key's state, so reconcile shows it as "
                'state-unknown rather than active or scheduled. kek="%s" detail="%s"',
                kek_resource_name,
                operator_error_text(exc),
            )
            return KekState.unknown()

    def _do_describe_kek_state(self, kek_resource_name: str) -> KekState:
        """Provider-specific state read. Override alongside ``supports_state_check``."""
        raise NotImplementedError

    def owns_kek(
        self, kek_resource_name: str, owner_prefix: str | None, *, owned_names: frozenset[str] = frozenset()
    ) -> bool:
        """Return whether *kek_resource_name* is provably owned by this deployment.

        Ownership is established by the KEK name carrying this deployment's
        ``owner_prefix`` (derived from ``KEK_TEMPLATE`` — see
        :meth:`AbstractKekStrategyAdapter.owner_prefix`), or by the name being in
        *owned_names*: the ``KEK_MAP`` identifiers the operator opted in with
        ``KEK_MAP_DESTROYABLE`` (see
        :meth:`AbstractKekStrategyAdapter.owned_mapped_kek_names`). With neither
        (no prefix, and the name not opted in) ownership cannot be proven, so this
        returns ``False`` and destruction is refused.

        Name-based by design: a name prefix is the one ownership signal every
        provider can carry, so the package never gates deletion on a tag — a tag
        check would refuse every key on a provisioner that cannot tag. A
        deployment whose provider does tag its keys may override this to also
        require the tag, a stronger boundary the KMS itself can enforce.
        """
        if kek_resource_name in owned_names:
            return True
        return bool(owner_prefix) and kek_resource_name.startswith(owner_prefix)

    def delete_kek(
        self,
        kek_resource_name: str,
        silo_ref: str,
        *,
        owner_prefix: str | None,
        owned_names: frozenset[str] = frozenset(),
    ) -> DeleteOutcome:
        """Schedule deletion of *kek_resource_name* on the KMS provider.

        Template method enforcing the two deletion guards uniformly so no provider
        implementation can forget them:

        1. ``supports_delete`` — refuse if this provisioner cannot delete.
        2. :meth:`owns_kek` — refuse any key not provably owned by this
           deployment (defensive: the command already gates on ownership, so
           reaching here with a foreign key is an anomaly worth failing loudly).

        Both refusals raise :class:`~encryption_suite.exceptions.KekDeleteError`
        via the deletion funnel (operator detail logged with the
        ``error_code=kek_delete_failed``, generic translated ``str``). On success it
        logs one line at **WARNING** — this is an irreversible
        action, and WARNING (not INFO) is the level that survives the common
        production log-level cut. The line is emitted here, the actual
        destruction point, so it fires for every caller (the admin purge action and
        the test-console deletion alike). Returns a
        :class:`DeleteOutcome`. Provider subclasses implement :meth:`_do_delete_kek`
        and set ``supports_delete = True``.
        """
        if not self.supports_delete:
            log_and_raise_delete_error(
                logger,
                f"{type(self).__name__} does not support KEK deletion; "
                f"refusing to delete '{kek_resource_name}'. Delete the KEK outside this application.",
            )
        if not self.owns_kek(kek_resource_name, owner_prefix, owned_names=owned_names):
            log_and_raise_delete_error(
                logger,
                f"Refusing to delete KEK '{kek_resource_name}': it does not carry this "
                f"deployment's owner prefix ({owner_prefix!r}) and is not a KEK_MAP key marked "
                "KEK_MAP_DESTROYABLE, so it is not provably ours. "
                "Deleting is limited to keys this deployment provisioned.",
            )
        # Funnel any raw provider error (HTTP, SDK, auth) from the provider call
        # into a typed KekDeleteError with operator detail logged under the
        # error_code=kek_delete_failed — so no raw provider error or traceback escapes
        # to the caller (the purge catches EncryptionError and leaves the
        # tombstone for retry).
        try:
            outcome = self._do_delete_kek(kek_resource_name, silo_ref)
        except EncryptionError:
            raise
        except Exception as exc:
            log_and_raise_delete_error(
                logger,
                f"Failed to delete KEK '{kek_resource_name}' (silo '{silo_ref}'): {exc}",
                cause=exc,
            )
        if outcome.scheduled:
            message = (
                "Deletion was requested at the provider; the key encryption key enters the "
                "provider's own deletion window and can be canceled there until it elapses."
            )
        else:
            message = (
                "Key material was destroyed at the provider; any DEK still wrapped by this "
                "key encryption key may not be possible to unwrap."
            )
        logger.warning(
            # "n/a" rather than an empty value: the purge passes no silo, because a
            # key encryption key at that point is not tied to one (it may have
            # backed several, and the row records none). A blank reads like a field
            # that failed to populate.
            '%s event=%s effective="%s" silo=%s kek="%s"',
            message,
            outcome.event,
            outcome.effective_at.isoformat(),
            silo_text(silo_ref) or "n/a",
            kek_resource_name,
        )
        return outcome

    def _do_delete_kek(self, kek_resource_name: str, silo_ref: str) -> DeleteOutcome:
        """Provider-specific deletion. Override and set ``supports_delete = True``.

        Schedule deletion (or, for providers without a waiting period, delete)
        the KEK, and return a :class:`DeleteOutcome`. Raise a provider error on
        failure — callers route it through the deletion funnel.
        """
        raise NotImplementedError

    # ------------------------------------------------------------------
    # KEK enumeration (reconcile)
    # ------------------------------------------------------------------

    def list_kek_names(self, owner_prefix: str | None) -> list[str]:
        """List the KEK resource names this deployment owns on the KMS provider.

        The KMS half of reconcile: the returned names are diffed against the live
        silos (:meth:`AbstractSiloAdapter.iter_silos`) to find KEKs that no silo
        claims. Template method enforcing two guards uniformly so no provider
        implementation can forget them:

        1. ``supports_enumeration`` — refuse if this provisioner cannot list.
        2. *owner prefix present* — refuse when ``owner_prefix`` is ``None``
           (shared / ``KEK_MAP`` configs derive no prefix, so ownership cannot be
           proven and no key may be safely attributed to this deployment — the
           same boundary :meth:`owns_kek` enforces).

        Both refusals, and any raw provider error from the listing call, raise
        :class:`~encryption_suite.exceptions.KekEnumerationError` via the
        enumeration funnel (operator detail logged with the
        ``error_code=kek_enumeration_unavailable``, generic translated ``str``). On
        success the provider listing is filtered to names carrying
        *owner_prefix*, so no foreign-project / shared key is ever returned even
        if a provider's ``_do_list_kek_names`` over-lists. Provider subclasses
        implement :meth:`_do_list_kek_names` and set ``supports_enumeration =
        True``.
        """
        if not self.supports_enumeration:
            log_and_raise_kek_enumeration_error(
                logger,
                f"{type(self).__name__} does not support KEK enumeration; "
                "cannot reconcile KMS-side. List and audit KEKs outside this application.",
            )
        if not owner_prefix:
            log_and_raise_kek_enumeration_error(
                logger,
                "Cannot enumerate KEKs without an owner prefix (shared / KEK_MAP "
                "config): ownership is unprovable, so no key can be attributed to "
                "this deployment for reconcile.",
            )
        try:
            names = self._do_list_kek_names(owner_prefix)
        except EncryptionError:
            raise
        except Exception as exc:
            log_and_raise_kek_enumeration_error(
                logger,
                f"Failed to list KEKs (owner prefix '{owner_prefix}'): {exc}",
                cause=exc,
            )
        # Defensive owner-prefix filter: never surface a key we cannot prove is
        # ours, even if a provider's listing over-returns (shared rings, foreign
        # projects). Mirrors owns_kek so reconcile only ever sees owned keys.
        return [name for name in names if name.startswith(owner_prefix)]

    def _do_list_kek_names(self, owner_prefix: str) -> list[str]:
        """Provider-specific KEK listing. Override and set ``supports_enumeration = True``.

        Return the KEK resource names visible to this deployment on the KMS.
        *owner_prefix* is provided for providers whose list API can filter
        server-side; the base :meth:`list_kek_names` re-filters by prefix
        regardless, so an over-broad listing is still safe. Raise a provider
        error on failure — callers route it through the enumeration funnel.
        """
        raise NotImplementedError


class NullKekProvisioner(AbstractKekProvisioner):
    """
    Default provisioner. Does nothing.

    With this provisioner in place, KEKs must exist on the KMS provider before
    the application tries to encrypt a DEK under them. If the KEK is missing,
    the first encryption attempt raises
    :class:`~encryption_suite.exceptions.KekNotProvisionedError` with a
    translated user-facing message and an English admin log entry that names
    the missing KEK and points to the strategy in use.

    This is the safe default for production deployments that provision keys
    outside this application (Terraform, CI bootstrap scripts, manual IAM reviews).
    """

    def ensure_kek(self, kek_resource_name: str, silo_ref: str) -> bool:
        logger.debug(
            "No provisioner is configured, so nothing was created; the key must already exist at "
            'the provider. silo="%s" kek="%s"',
            silo_ref,
            kek_resource_name,
        )
        return False
