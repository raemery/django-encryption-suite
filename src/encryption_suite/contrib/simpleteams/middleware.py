from ...adapters.silos.context import clear_current_silo, set_current_silo
from .models import SimpleTeamMembership


class SimpleTeamSiloMiddleware:
    """Make the signed-in user's team the current silo for the request.

    Belongs below ``AuthenticationMiddleware``, which sets ``request.user``. A
    user with no team, and an anonymous one, get no silo, so encrypted access
    fails as it does under any adapter with nothing current.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        team = None
        if request.user.is_authenticated:
            # A query rather than request.user.simple_team_membership, which raises
            # for a user with no team instead of answering None.
            membership = SimpleTeamMembership.objects.filter(user=request.user).select_related("team").first()
            team = membership.team if membership else None
        if team is not None:
            set_current_silo(team)
        try:
            return self.get_response(request)
        finally:
            clear_current_silo()
