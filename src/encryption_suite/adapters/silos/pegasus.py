"""
Silo adapter for SaaS Pegasus teams.

Resolves the current silo from ``apps.teams.context.get_current_team()``,
which is set by the Pegasus team middleware on every request.
"""

from ..._logging import get_logger
from ...exceptions import log_and_raise_configuration_error
from .base import AbstractSiloAdapter

logger = get_logger(__name__)


class PegasusTeamSiloAdapter(AbstractSiloAdapter):
    """Silo adapter for Pegasus ``Team`` objects."""

    # Silos are exactly the rows of one model, so enumeration is supported: the
    # base iter_silos() returns this model's queryset. Used by
    # setup_encryption_keys and (Phase 3) KMS reconcile to discover every silo.
    model_label = "teams.Team"
    supports_enumeration = True

    def get_current_silo(self):
        try:
            from apps.teams.context import get_current_team
        except ImportError as exc:
            log_and_raise_configuration_error(
                logger,
                "PegasusTeamSiloAdapter requires apps.teams to be installed. Ensure 'apps.teams' is in INSTALLED_APPS.",
                cause=exc,
            )
        return get_current_team()

    def get_silo_uid(self, silo) -> str:
        return f"team-{silo.pk}"

    def get_silo_label(self) -> str:
        return "pegasus_team"

    def silo_for_uid(self, silo_uid: str):
        # A point query on the pk the UID carries, rather than the base class's
        # walk over every team. A suffix that is not a pk names no team.
        from django.core.exceptions import ValidationError

        from ...silos import queryset_for_model_label

        if not silo_uid.startswith("team-"):
            return None
        try:
            return queryset_for_model_label(self.model_label).filter(pk=silo_uid[len("team-") :]).first()
        except (ValueError, TypeError, ValidationError):
            return None

    def silo_exists(self, silo_uid: str):
        return self.silo_for_uid(silo_uid) is not None

    def describe_silo(self, silo_uid: str) -> str:
        try:
            team = self.silo_for_uid(silo_uid)
        except Exception:
            return ""
        return str(team) if team is not None else ""
