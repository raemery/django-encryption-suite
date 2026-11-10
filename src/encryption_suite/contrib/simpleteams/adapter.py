from ...adapters.silos.generic import GenericModelSiloAdapter


class SimpleTeamSiloAdapter(GenericModelSiloAdapter):
    """Silo adapter for :class:`~encryption_suite.contrib.simpleteams.models.SimpleTeam`.

    Silo UIDs are ``simpleteam-<pk>``. A surrogate pk is never reissued, so a
    deleted team's UID never names a new one. The current team comes from
    :class:`~encryption_suite.contrib.simpleteams.middleware.SimpleTeamSiloMiddleware`.
    """

    model_label = "encryption_suite_simpleteams.SimpleTeam"
    uid_field = "pk"
    label = "simpleteam"
