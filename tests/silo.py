from encryption_suite.adapters.silos.generic import GenericModelSiloAdapter


class GroupSiloAdapter(GenericModelSiloAdapter):
    """Uses django.contrib.auth.Group as the test silo — no custom model or migration needed."""

    model_label = "auth.Group"
    uid_field = "pk"
    label = "group"
