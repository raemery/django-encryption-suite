"""The silo adapters that make each user a silo."""

from __future__ import annotations

from django.core.exceptions import ValidationError

from ...silos import queryset_for_model_label
from ...user_context import get_current_user
from .base import AbstractSiloAdapter


class ActingUserSiloAdapter(AbstractSiloAdapter):
    """One silo per user, chosen by who is acting.

    The current silo is the acting user's primary key, read from the user context
    that ``UserContextMiddleware`` fills for a request and ``override_current_user``
    fills elsewhere. It reads a context variable of its own, so it can sit beside a
    team adapter that reads the silo context variable.
    """

    supports_enumeration = True

    #: Tells the middleware that something reads the user context.
    reads_user_context = True

    #: The silo label, and the prefix of every silo uid.
    label = "user"

    @property
    def model_label(self) -> str:
        from django.conf import settings

        return settings.AUTH_USER_MODEL

    def get_current_silo(self):
        return get_current_user().user_pk

    def get_silo_uid(self, silo) -> str:
        """Return ``<label>-<pk>`` for a user instance or a primary key."""
        return f"{self.label}-{getattr(silo, 'pk', silo)}"

    def get_silo_label(self) -> str:
        return self.label

    def silo_for_uid(self, silo_uid: str):
        # A value the pk field cannot hold names no user, which is an answer.
        prefix = f"{self.label}-"
        if not silo_uid.startswith(prefix):
            return None
        try:
            return queryset_for_model_label(self.model_label).filter(pk=silo_uid[len(prefix) :]).first()
        except (ValueError, TypeError, ValidationError):
            return None

    def silo_exists(self, silo_uid: str):
        return self.silo_for_uid(silo_uid) is not None

    def describe_silo(self, silo_uid: str) -> str:
        """The user's ``str()``, so an operator can match the silo to the user it belongs to.

        The pk is already in the uid. A ``__str__`` that reads an encrypted field
        it cannot decrypt here gives Django's default ``<Model> object (<pk>)``.
        """
        try:
            user = self.silo_for_uid(silo_uid)
        except Exception:
            return ""
        return str(user) if user is not None else ""


class ActingUserOrOwnerSiloAdapter(ActingUserSiloAdapter):
    """One silo per user: the acting user's, or for a write with nobody acting, the row's owner's.

    Reads follow the acting user alone, as :class:`ActingUserSiloAdapter`'s do,
    and with nobody acting a read is refused. A write with someone acting goes to
    that user's silo. A write with nobody acting goes to the silo of the user the
    row belongs to: the row itself on the user model, otherwise the user its one
    foreign key to the user model names. Server code must set that foreign key,
    because whoever sets it chooses whose silo the value is written to.
    """

    label = "user_owner"

    writes_to_row_silo_without_context = True

    def silo_for_row(self, instance):
        """The pk of the user *instance* belongs to, or ``None`` when it names none.

        The pk rather than the user, so no query is made for the row's owner.
        """
        from ...rotation_targets import _silo_foreign_key, _silo_model

        model = type(instance)
        silo_model = _silo_model(self)
        if model._meta.concrete_model is silo_model:
            return instance.pk
        fk, _why = _silo_foreign_key(model, silo_model)
        if fk is None:
            return None
        return getattr(instance, fk.attname)
