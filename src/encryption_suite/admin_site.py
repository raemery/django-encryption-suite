"""Order and label this app's models in the admin index — with no setup.

Django's admin index sorts each app's models alphabetically by their plural
display name, so the reading order an operator wants (the key a silo uses, then
the key that protects it, then the history) is left to an accident of the
alphabet. The index also shows the bare plural name, where a word on *which*
keys are listed — the ones on the KMS, the ones held per silo — is what tells
the two apart at a glance.

There is no per-model ordering or index-label hook, so the only lever is
``get_app_list``. :func:`install_app_ordering` wraps it on the default admin
site at app-ready, so both are correct with no settings change. The wrap is
*surgical*: it touches **only** this app's models and passes every other app
through exactly as Django returned it, so a consuming project's own admin index
is untouched. The models' ``verbose_name_plural`` stays the plain term, which is
what every other surface (breadcrumbs, page titles, messages) reads.
"""

from __future__ import annotations

from django.utils.translation import gettext_lazy as _

APP_LABEL = "encryption_suite"

# The two state-bearing models first, then the history, matching how an operator
# reads them. Any model not listed (e.g. one added later) keeps Django's default
# alphabetical position after these.
MODEL_ORDER = (
    "DataEncryptionKey",
    "KeyEncryptionKey",
    "KeyLifecycleEvent",
)

# Index-only labels: the plural name plus where those keys live. Models not
# listed here keep the plural name Django derived from the model's Meta.
INDEX_LABELS = {
    "DataEncryptionKey": _("Data encryption keys (per silo)"),
    "KeyEncryptionKey": _("Key encryption keys (on key store)"),
}

_WRAPPED_FLAG = "_encryption_suite_ordered"


def _reorder(app_list):
    rank = {name: index for index, name in enumerate(MODEL_ORDER)}
    for app in app_list:
        if app["app_label"] != APP_LABEL:
            continue
        # Stable: unlisted models keep their alphabetical order behind the
        # listed ones (rank defaults past the end of MODEL_ORDER).
        app["models"].sort(key=lambda model: rank.get(model["object_name"], len(rank)))
        for model in app["models"]:
            label = INDEX_LABELS.get(model["object_name"])
            if label:
                model["name"] = label
    return app_list


def install_app_ordering(site=None) -> None:
    """Wrap ``get_app_list`` on the default admin site to order this app's models.

    Idempotent: a second call (e.g. after an autoreload) is a no-op. Other apps'
    ordering is left exactly as Django produced it.
    """
    if site is None:
        from django.apps import apps

        # The default admin site is lazy and resolves through the "admin" app
        # config; touching it without django.contrib.admin installed raises.
        # No admin installed => nothing to order.
        if not apps.is_installed("django.contrib.admin"):
            return
        from django.contrib import admin

        site = admin.site

    original = site.get_app_list
    if getattr(original, _WRAPPED_FLAG, False):
        return

    def get_app_list(request, *args, **kwargs):
        return _reorder(original(request, *args, **kwargs))

    setattr(get_app_list, _WRAPPED_FLAG, True)
    site.get_app_list = get_app_list
