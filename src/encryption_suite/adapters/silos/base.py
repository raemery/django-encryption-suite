"""Abstract base for silo adapters."""

from __future__ import annotations

import contextlib
from abc import ABC, abstractmethod

from ..._logging import get_logger
from ...exceptions import log_and_raise_configuration_error, log_and_raise_enumeration_error
from ...silos import queryset_for_model_label

logger = get_logger(__name__)


class AbstractSiloAdapter(ABC):
    """
    A silo adapter does two related jobs in one class:

    1. **Resolve** the current silo from ambient runtime state
       (thread-local variable, ``connection.tenant``, framework middleware, …).
       The engine calls ``get_current_silo()`` on every field read/write.

    2. **Identify** a silo object by producing the two stable strings the
       engine needs to look up and store its DEK:
       - ``silo_uid``        — globally unique key, e.g. ``"team-42"``
       - ``silo_label``      — human-readable label, e.g. ``"pegasus_team"``

    Implement all three methods. Return ``None`` from ``get_current_silo()``
    when no silo is active — the engine raises ``EncryptionConfigurationError``
    (slug ``configuration_error``) in that case.

    Optionally, an adapter may also **enumerate** every live silo (see
    ``supports_enumeration`` / ``iter_silos`` below). Enumeration is a strictly
    stronger capability than resolving the *current* silo and is opt-in.
    """

    #: Whether this adapter can list **every** live silo via :meth:`iter_silos`.
    #:
    #: ``False`` by default. Enumeration feeds keyset setup and (Phase 3) KMS
    #: reconcile, where a wrong or partial list can cause a live silo's KEK to be
    #: treated as an orphan and destroyed. An adapter that cannot list *all*
    #: silos must leave this ``False`` — the reconcile/destroy path then treats
    #: it as *detection-unavailable* (DB-row reconcile only, KMS side flagged for
    #: manual audit) and never infers an orphan it might destroy.
    #:
    #: Callers check this flag to pick the safe tier; they do not call
    #: :meth:`iter_silos` and catch to find out. Subclasses that can enumerate
    #: set this ``True`` and override (or inherit) a working :meth:`iter_silos`.
    supports_enumeration: bool = False

    #: Whether this adapter resolves its current silo from the user context, which
    #: ``UserContextMiddleware`` fills. The middleware populates the context for a
    #: request when any key set is bound to such an adapter.
    reads_user_context: bool = False

    @property
    def silo_model_labels(self) -> tuple[str, ...]:
        """The ``"app_label.ModelName"`` labels of the models whose instances are this adapter's silos.

        What ``SILO_AUTO_KEY_CREATION`` and ``SILO_AUTO_KEY_DELETION`` connect their
        signals to. The ``model_label`` an adapter declares is its one model;
        an adapter whose silos span several models (a composite adapter's tenant
        and cell) overrides this. An adapter that declares none cannot use either
        setting.
        """
        label = getattr(self, "model_label", None)
        return (label,) if label else ()

    def is_in_use(self) -> bool:
        """Return whether anything encrypts under this adapter's key sets.

        ``True`` by default. Where an operator reviews keys, the page lists the
        silos of an adapter only when this is ``True``. An adapter answers ``False``
        when its silos always exist but a deployment may never use them.
        This is not a statement about whether the silos exist: :meth:`iter_silos`
        still lists every live silo.
        """
        return True

    #: Whether :meth:`queryset_for_silo` can hand back one silo's rows of a model.
    #:
    #: ``False`` by default, because the package can usually work the answer out
    #: for itself: a model with exactly one foreign key to :attr:`model_label`'s
    #: model is filtered on it. Set this ``True`` and override the method where
    #: that does not hold — no ``model_label``, a model that reaches its silo
    #: through a related model, one with more than one such key, or silos that are
    #: database schemas rather than rows. The same rule as enumeration applies: a
    #: partial answer is worse than none, because a data key rotation swaps the
    #: silo's key after converting only the rows it was told about.
    supports_silo_data_lookup: bool = False

    #: Whether the silos of this adapter always exist, so that no key of theirs may be deleted.
    #:
    #: ``False`` by default. Narrow on purpose: it says this adapter's silos cannot go away,
    #: and the operator override ``KEY_DELETION_CAN_RENDER_DATA_INACCESSIBLE`` cannot
    #: change that. It is not a general retention flag.
    prevents_key_delete: bool = False

    #: Whether a write with no current silo goes to the silo of the row being written.
    #:
    #: ``False`` by default: with no current silo, a write fails. Set this ``True``
    #: and override :meth:`silo_for_row` where each row has one owning silo that
    #: server code sets, and a write can happen while nothing is acting. Reads never
    #: take the row's silo, whatever this says. Only an encrypted field's write on a
    #: model save follows it: a file and ``QuerySet.update()`` have no row in hand.
    writes_to_row_silo_without_context: bool = False

    @abstractmethod
    def get_current_silo(self):
        """Return the active silo object, or ``None`` if none is active."""

    @abstractmethod
    def get_silo_uid(self, silo) -> str:
        """Return the unique UID string for *silo*.

        **A UID must never be reissued.** Uniqueness among *live* silos is not
        enough: key rows outlive the silos they belonged to (a scheduled key
        keeps its UID through the restore window, and a purged tombstone keeps it
        forever), and :meth:`silo_exists` answers a destructive gate by that UID.
        Hand the same UID to a second silo and that gate reads the newcomer as
        proof the original is still in use, refusing to purge a key whose silo is
        long gone.

        Derive it from something the database will not hand out twice — a
        surrogate primary key is the usual answer.
        :class:`~encryption_suite.adapters.silo.pegasus.PegasusTeamSiloAdapter`
        uses ``team-{pk}`` for this reason. Anything an operator can free and
        re-take — a slug, a schema name, an email — is not safe on its own.
        """

    @abstractmethod
    def get_silo_label(self) -> str:
        """Return a stable label for this adapter's silos (not per-instance)."""

    def iter_silos(self):
        """Yield (or return a queryset of) **every** live silo for this deployment.

        Default implementation: if the adapter declares a ``model_label``
        (``"app_label.ModelName"``), return that model's full queryset;
        otherwise raise :class:`SiloEnumerationError`. Override for adapters
        whose silos span more than one model (e.g. composite tenant + cell) or
        come from elsewhere.

        Must be kept in lock-step with ``supports_enumeration``: leave the flag
        ``False`` unless this lists *every* live silo. A partial list makes the
        omitted silos look like orphans on the reconcile path — and a wrongly
        "orphaned" KEK can be destroyed, which is unrecoverable. This guard
        raises rather than returning an empty/partial result so a misconfigured
        adapter degrades to detection-unavailable instead of false-orphaning.
        """
        model_label = getattr(self, "model_label", None)
        if model_label:
            return queryset_for_model_label(model_label)
        log_and_raise_enumeration_error(
            logger,
            f"Adapter '{type(self).__name__}' cannot enumerate silos. Set "
            "supports_enumeration = True and override iter_silos() to yield every live silo.",
        )

    def describe_silo(self, silo_uid: str) -> str:
        """Return a human-readable name for *silo_uid*, or ``""`` if unavailable.

        A UID is derived from something that will never be reissued — usually a
        surrogate key — which makes it stable and unrecognizable. An operator
        looking at ``team-42`` cannot tell whether that is the tenant they meant
        to act on, and destructive actions are confirmed by UID.

        Purely informational: nothing gates on this. Every failure degrades to
        ``""`` (the caller shows a fallback), because a name that cannot be
        looked up must never break the page that displays it, and must never
        block a lifecycle action.

        The default matches on :meth:`get_silo_uid`, since UID derivation is
        one-way and only the adapter knows how to reverse it. That walks
        :meth:`iter_silos`, so **adapters with a cheap point lookup should
        override** — same reasoning as :meth:`silo_exists`, and more pressing
        here, because this is called while rendering a page.
        """
        if not self.supports_enumeration:
            return ""
        try:
            for silo in self.iter_silos():
                if self.get_silo_uid(silo) == silo_uid:
                    return str(silo)
        except Exception:  # informational only — never break the caller
            return ""
        return ""

    def silo_exists(self, silo_uid: str):
        """Return whether a live silo currently has *silo_uid*.

        Three answers, and the third is not a failure to smooth over:
        ``True``, ``False``, or ``None`` for *cannot say*. Callers must treat
        ``None`` as no information — never as either answer.

        A **strictly weaker** capability than :meth:`iter_silos`, and the reason
        it exists separately. Enumeration must list *every* silo, which is why a
        composite adapter refuses it: its silos span two model types and a partial
        list would make live cells look orphaned. Answering about **one** UID
        carries no such risk, so an adapter that cannot enumerate can usually
        still answer this — and should, because the deletion gate that consumes it
        is otherwise stuck refusing work it cannot verify.

        The default derives the answer from :meth:`iter_silos` when the adapter
        enumerates, and returns ``None`` when it does not. Adapters with a cheaper
        lookup should override — this is a point query, and walking every silo to
        answer it is wasteful once a deployment is large.

        An enumeration that *raises* propagates rather than degrading to ``None``:
        a transient failure and a permanent inability are different facts, and the
        gate treats them differently.
        """
        if not self.supports_enumeration:
            return None
        return any(self.get_silo_uid(silo) == silo_uid for silo in self.iter_silos())

    def silo_for_uid(self, silo_uid: str):
        """Return the live silo whose UID is *silo_uid*, or ``None``.

        The reverse of :meth:`get_silo_uid`, which only the adapter can perform.
        ``reencrypt_data`` holds a UID — from its flag, or from the key row it is
        rotating — and needs the silo object to filter a model's rows by the
        foreign key pointing at it.

        The default walks :meth:`iter_silos` where the adapter enumerates and
        returns ``None`` where it does not, so ``None`` from the default can mean
        *cannot say* rather than *no such silo*. Adapters with a point lookup
        should override, and answer :meth:`silo_exists` from the same query.

        Errors propagate: a lookup that failed is not a silo that is absent.
        """
        if not self.supports_enumeration:
            return None
        for silo in self.iter_silos():
            if self.get_silo_uid(silo) == silo_uid:
                return silo
        return None

    def queryset_for_silo(self, model, silo_uid: str):
        """Return every row of *model* that belongs to the silo *silo_uid*.

        Called only when :attr:`supports_silo_data_lookup` is ``True``, and only
        for a model the package could not resolve by introspection. Takes a model
        rather than a queryset to narrow, because a silo is not always a column:
        where each silo is its own database schema, the answer is everything in
        that schema. It is only right inside :meth:`use_silo`, which the caller
        holds for as long as it uses the rows — an override may assume it.

        Look rows up through ``model._base_manager``, never ``objects``. A default
        manager that filters hides live rows from the rotation, and the swap then
        replaces the key they are encrypted under without them.

        The base raises: an adapter that declares the capability without
        implementing it is a configuration fault.
        """
        log_and_raise_configuration_error(
            logger,
            f"Adapter '{type(self).__name__}' sets supports_silo_data_lookup = True but does not "
            "override queryset_for_silo(). Implement queryset_for_silo(model, silo_uid) to return that "
            "silo's rows of the model, or leave supports_silo_data_lookup False.",
        )

    def silo_for_row(self, instance):
        """Return the silo *instance* belongs to, or ``None`` when it names none.

        Called only when :attr:`writes_to_row_silo_without_context` is ``True``
        and :meth:`get_current_silo` returns ``None``, while an encrypted field of
        *instance* is written. The answer is passed to :meth:`get_silo_uid`, so it
        is anything that method accepts. ``None`` fails the write as a missing
        current silo does.

        The base raises: an adapter that declares the capability without
        implementing it is a configuration fault.
        """
        log_and_raise_configuration_error(
            logger,
            f"Adapter '{type(self).__name__}' sets writes_to_row_silo_without_context = True but does not "
            "override silo_for_row(). Implement silo_for_row(instance) to return the silo the row belongs to, "
            "or leave writes_to_row_silo_without_context False.",
        )

    def use_silo(self, silo_uid: str):
        """Return a context manager that makes *silo_uid* the silo rows are read from.

        Entered once around each silo's work in ``reencrypt_data``. The default
        does nothing, which is right wherever a silo is a column. Where a silo is
        a database schema its rows are not visible outside it, so an adapter of
        that kind of adapter must override this — without it a rotation reads the wrong
        schema in silence.
        """
        return contextlib.nullcontext()
