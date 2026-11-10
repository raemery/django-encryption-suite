from django.conf import settings
from django.db import models
from django.utils.translation import gettext_lazy as _

from ...fields import EncryptedCharField


class SimpleTeam(models.Model):
    """A team, and the silo its members' data is encrypted under.

    The name is encrypted under the system silo's key, so it reads in the site-wide
    admin with no team in context. Its blind index casefolds, so "Acme" and
    "acme" cannot both exist.

    A model holding a team's data should point here with ``on_delete=PROTECT``:
    a team deleted from under its rows leaves data nobody is meant to read.
    """

    name = EncryptedCharField(
        _("Name"),
        key_set="system",
        max_length=150,
        unique=True,
        blind_index=True,
        normalize="casefold",
    )

    class Meta:
        verbose_name = _("Simple team")
        verbose_name_plural = _("Simple teams")

    def __str__(self):
        return self.name


class SimpleTeamMembership(models.Model):
    """One user's team. A one-to-one, so the database refuses a second team."""

    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="simple_team_membership",
        verbose_name=_("User"),
    )
    team = models.ForeignKey(SimpleTeam, on_delete=models.CASCADE, related_name="memberships", verbose_name=_("Team"))

    class Meta:
        verbose_name = _("Simple team membership")
        verbose_name_plural = _("Simple team memberships")

    def __str__(self):
        return f"{self.user} ({self.team})"
