"""
Generic silo adapter for any Django model.

Resolves the current silo from a context variable (set by middleware)
and identifies silo objects by a configurable model field.

Configure via subclass::

    class TeamSiloAdapter(GenericModelSiloAdapter):
        model_label = "myapp.Team"
        uid_field = "pk"        # optional; defaults to "pk"
        label = "team"     # optional

Or use the factory function::

    TeamSiloAdapter = make_silo_adapter(
        model_label="myapp.Team",
        uid_field="pk",
        label="team",
    )
"""

from __future__ import annotations

from .context import ContextSiloAdapter


class GenericModelSiloAdapter(ContextSiloAdapter):
    """
    Identifies silos by an arbitrary field on an arbitrary Django model.
    Resolves the current silo from a context variable.

    Subclass and set ``model_label``, ``uid_field``, and ``label``::

        class TeamSiloAdapter(GenericModelSiloAdapter):
            model_label = "myapp.Team"
            uid_field = "pk"
            label = "team"
    """

    #: Django app_label.ModelName  (e.g. "myapp.Team")
    model_label: str = ""
    #: Field whose value is included in the uid  (default "pk")
    uid_field: str = "pk"
    #: Stable label stored in DataEncryptionKey.silo_label
    label: str = ""

    #: A single model fully defines the silo set, so enumeration is supported via
    #: the base ``iter_silos`` (returns ``model_label``'s queryset).
    supports_enumeration: bool = True

    def get_silo_uid(self, silo) -> str:
        label = self.label or self.model_label.split(".")[-1].lower()
        value = getattr(silo, self.uid_field)
        return f"{label}-{value}"

    def get_silo_label(self) -> str:
        return self.label or self.model_label.split(".")[-1].lower()

    def silo_for_uid(self, silo_uid: str):
        # A point query rather than the base class's walk: the UID is
        # "<label>-<uid_field>", so the field value can be read straight back out
        # of it. A value the field cannot hold (a slug where an integer pk is
        # expected) names no silo, which is an answer rather than a failure.
        from django.core.exceptions import ValidationError

        from ...silos import queryset_for_model_label

        prefix = f"{self.get_silo_label()}-"
        if not silo_uid.startswith(prefix):
            return None
        try:
            return (
                queryset_for_model_label(self.model_label).filter(**{self.uid_field: silo_uid[len(prefix) :]}).first()
            )
        except (ValueError, TypeError, ValidationError):
            return None

    def silo_exists(self, silo_uid: str):
        return self.silo_for_uid(silo_uid) is not None

    def describe_silo(self, silo_uid: str) -> str:
        try:
            silo = self.silo_for_uid(silo_uid)
        except Exception:
            return ""
        return str(silo) if silo is not None else ""


def make_silo_adapter(
    model_label: str,
    uid_field: str = "pk",
    label: str = "",
) -> type[GenericModelSiloAdapter]:
    """Factory that returns a configured subclass of GenericModelSiloAdapter."""
    return type(
        f"_{label or model_label.split('.')[-1]}SiloAdapter",
        (GenericModelSiloAdapter,),
        {"model_label": model_label, "uid_field": uid_field, "label": label},
    )
