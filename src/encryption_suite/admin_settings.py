"""
The Encryption settings admin screen.

What this package is configured to do, read-only, in one place. The question it
answers is the one the other screens raise and cannot settle: a ledger row with
no user or no address is ``USER_IDENTITY``, and a deployment that keeps its
configuration in secrets has nowhere else to look.

Two properties keep it safe to show. The package's settings are its own
namespace — ``conf`` reads ``settings.ENCRYPTION`` and merges it over
``DEFAULTS`` — and the only thing outside it this page reaches is one entry of
Django's ``STORAGES``, the one an encrypted file is written through, which
``STORAGE_ALIAS`` names but does not describe (see :func:`resolved_storage`).
Within both, what may be shown is declared beside the settings themselves in
:mod:`encryption_suite.conf`, down to the individual keys of the options dicts,
and the value of anything it cannot place is hidden.

The screen reports values, never where they came from: Django hands the package
a resolved value and no history, so it can say a value differs from the default
and never that it arrived in an environment variable or a secret.
"""

from __future__ import annotations

from django.conf import settings as django_settings
from django.template.response import TemplateResponse
from django.urls import reverse
from django.utils.translation import gettext_lazy as _

from . import conf
from .admin_access import PERM_VIEW_SETTINGS, require_screen_access

GROUP_LABELS = {
    conf.GROUP_GENERAL: _("General"),
    conf.GROUP_RECORDING: _("Recording and identity"),
    conf.GROUP_ENGINE: _("Cryptographic engine"),
    conf.GROUP_SILO: _("Silo"),
    conf.GROUP_KMS: _("KMS"),
    conf.GROUP_KEYS: _("Keys and rotation"),
    conf.GROUP_STORAGE: _("Storage"),
    conf.GROUP_OTHER: _("Other"),
}

HIDDEN = _("(hidden)")


def _render_options(options: dict, *, show_all: bool = False) -> str:
    """Render an options dict key by key, hiding only the values that carry a secret.

    Hiding a whole dict because one key in it is a credential costs the rest,
    and the rest is what an operator came for: ``KEK_TEMPLATE`` is a naming
    convention the test console already prints, and a region or an endpoint
    names no secret at all. So each key answers for itself, and a nested options
    dict is walked the same way.
    """
    rendered = []
    for key in sorted(options, key=str):
        value = options[key]
        if not show_all and not conf.option_value_is_shown(str(key)):
            rendered.append(f"{key}={HIDDEN}")
        elif isinstance(value, dict):
            rendered.append(f"{key}={{{_render_options(value, show_all=show_all)}}}")
        else:
            rendered.append(f"{key}={_render_value(value, hide_value=False)}")
    return ", ".join(rendered)


def _render_value(value, *, hide_value: bool, show_all: bool = False) -> str:
    """Render *value* for the screen. A hidden value loses the value, never the row."""
    if isinstance(value, dict):
        if hide_value:
            return ", ".join(f"{key}={HIDDEN}" for key in sorted(map(str, value))) or str(_("(empty)"))
        return _render_options(value, show_all=show_all) or str(_("(empty)"))
    if hide_value:
        return str(HIDDEN)
    if isinstance(value, (list, tuple, set, frozenset)):
        return ", ".join(str(item) for item in value) or str(_("(empty)"))
    if value is None:
        return str(_("(not set)"))
    return str(value)


def resolved_storage() -> list[dict]:
    """Rows describing the ``STORAGES`` entry an encrypted file is written through.

    Not ``ENCRYPTION`` settings, and the only things on this page that are not, so
    they carry their own ``source`` rather than reading as configured or default.
    They sit in the storage group beside ``STORAGE_ALIAS``, which names an entry
    without describing it.

    The resolution falls back — an alias naming an entry that does not exist
    quietly uses ``default``, and a deployment with neither gets the package's own
    file backend — and nothing reported which of the three happened until these
    rows.

    ``OPTIONS`` are the backend's constructor arguments, so which names appear
    depends on the backend: Django's file storage takes ``location``,
    django-storages' S3 backend ``bucket_name`` and ``endpoint_url``, and the
    same dict is where an access key and secret usually sit. Hence a value is
    hidden unless :data:`conf.SHOWN_STORAGE_OPTION_KEYS` lists its name.
    """
    storages = getattr(django_settings, "STORAGES", {}) or {}
    alias = conf.enc_settings.STORAGE_ALIAS
    for candidate in (alias, "default"):
        entry = storages.get(candidate) or {}
        if not entry.get("BACKEND"):
            continue
        source = (
            _("named by STORAGE_ALIAS")
            if candidate == alias
            else _("fallback — no STORAGES entry is named by STORAGE_ALIAS")
        )
        options = entry.get("OPTIONS") or {}
        rendered = ", ".join(
            f"{key}={value if conf.storage_option_value_is_shown(str(key)) else HIDDEN}"
            for key, value in sorted(options.items(), key=lambda item: str(item[0]))
        )
        return [
            {"name": "STORAGES alias in use", "value": candidate, "source": source},
            {"name": "STORAGES BACKEND", "value": entry["BACKEND"], "source": _("resolved")},
            {"name": "STORAGES OPTIONS", "value": rendered or str(_("(empty)")), "source": _("resolved")},
        ]
    return [
        {
            "name": "STORAGES alias in use",
            "value": str(_("none — the package's own file storage")),
            "source": _("fallback — no STORAGES entry resolved"),
        }
    ]


def build_setting_groups() -> list[dict]:
    """Group every known setting with its effective value and where that came from.

    ``configured`` means the name appears in the project's ``ENCRYPTION`` dict,
    not that the value differs from the default — a project that spells out a
    default is stating an intention, and the screen reports what it finds rather
    than guessing which of the two happened.
    """
    declared = getattr(django_settings, "ENCRYPTION", {}) or {}
    effective = {**conf.DEFAULTS, **declared}
    # Filled key by key, as the runtime reads it, so a project that set one key
    # sees the other three it is actually running with. A value that is not a
    # dict is shown as it is: that is the misconfiguration to read here.
    if isinstance(effective["USER_IDENTITY"], dict):
        effective["USER_IDENTITY"] = conf.resolve_user_identity(effective["USER_IDENTITY"])
    rows_by_group: dict[str, list[dict]] = {group: [] for group in conf.SETTING_GROUPS}
    for name in sorted(effective):
        group, hide_value = conf.describe_setting(name)
        if name == "KMS_KEY_STORES" and isinstance(effective[name], dict) and effective[name]:
            # One row per block, so each KMS reads on its own line and the block's
            # keys are walked like any other options dict.
            for block_name in sorted(effective[name], key=str):
                block = effective[name][block_name]
                rows_by_group[group].append(
                    {
                        "name": f'{name}["{block_name}"]',
                        "value": _render_value(block, hide_value=hide_value),
                        "redacted": hide_value,
                        "is_configured": True,
                    }
                )
            continue
        rows_by_group[group].append(
            {
                "name": name,
                "value": _render_value(effective[name], hide_value=hide_value, show_all=name in conf.SHOWN_SETTINGS),
                "redacted": hide_value,
                "is_configured": name in declared,
            }
        )
    # The storage group ends with what STORAGE_ALIAS resolved to, since the alias
    # alone does not say where a file lands.
    rows_by_group[conf.GROUP_STORAGE].extend(resolved_storage())
    return [
        {"label": GROUP_LABELS[group], "rows": rows_by_group[group]}
        for group in conf.SETTING_GROUPS
        if rows_by_group[group]
    ]


def settings_view(model_admin, request):
    """Render the Encryption settings page."""
    require_screen_access(request, PERM_VIEW_SETTINGS)
    context = {
        **model_admin.admin_site.each_context(request),
        "title": _("Encryption settings"),
        "opts": model_admin.model._meta,
        "groups": build_setting_groups(),
        "changelist_url": reverse("admin:encryption_suite_dataencryptionkey_changelist"),
    }
    return TemplateResponse(request, "admin/encryption_suite/settings.html", context)
