from django.apps import AppConfig
from django.utils.translation import gettext_lazy as _


class SimpleTeamsConfig(AppConfig):
    name = "encryption_suite.contrib.simpleteams"
    # Explicit, so the tables cannot collide with a project app called simpleteams.
    label = "encryption_suite_simpleteams"
    verbose_name = _("Simple teams")
    # Explicit, so the migration does not depend on the project's DEFAULT_AUTO_FIELD.
    default_auto_field = "django.db.models.BigAutoField"
