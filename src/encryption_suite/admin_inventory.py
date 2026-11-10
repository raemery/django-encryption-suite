"""
The Cryptographic inventory admin screen.

Renders :func:`encryption_suite.inventory.build_inventory` — the same data the
``crypto_inventory`` command prints — and links each count to the changelist
filtered to the rows behind it. Read-only, no KMS calls.
"""

from __future__ import annotations

from urllib.parse import urlencode

from django.template.response import TemplateResponse
from django.urls import reverse
from django.utils.translation import gettext_lazy as _

from .admin_access import PERM_VIEW_INVENTORY, require_screen_access

#: Where a shipped adapter's dotted path may wrap on screen.
_PACKAGE_ADAPTERS = "encryption_suite.adapters."


def _changelist(name: str, **filters) -> str:
    return f"{reverse(f'admin:encryption_suite_{name}_changelist')}?{urlencode(filters)}"


def _count_link(allowed: bool, name: str, **filters) -> str:
    """The changelist URL behind a count, or ``""`` — shown as the bare count — when not *allowed*."""
    return _changelist(name, **filters) if allowed else ""


def _may_view(user, model_name: str) -> bool:
    """Whether *user* may open *model_name*'s changelist, as the admin decides it.

    The admin lets the change permission view as well, so either one counts.
    The inventory permission does not grant this: a count whose changelist the
    user cannot open is shown without a link rather than as a link to a 403.
    """
    return user.has_perm(f"encryption_suite.view_{model_name}") or user.has_perm(
        f"encryption_suite.change_{model_name}"
    )


def _wrap_parts(path: str) -> tuple[str, str]:
    """``(head, tail)`` of a dotted path, split after the package's adapter prefix.

    The template joins them with ``<wbr>``, a line-break opportunity, so a long
    path wraps without a character added: copied off the screen, it is still the
    path ``crypto_inventory`` prints. A path outside the package is not split.
    """
    if path.startswith(_PACKAGE_ADAPTERS):
        return _PACKAGE_ADAPTERS, path[len(_PACKAGE_ADAPTERS) :]
    return "", path


def inventory_view(model_admin, request):
    """Render the Cryptographic inventory page."""
    from .admin_test_console import _CRYPTO_CONFIG_LABELS
    from .deletion import LIVE_DEK_STATUSES
    from .inventory import build_inventory, engine_table

    require_screen_access(request, PERM_VIEW_INVENTORY)
    inventory = build_inventory()
    option_keys, engine_rows = engine_table(inventory.configured_for_new_data_encryption_keys)
    # Headed by the label the test console gives each option.
    engine_headers = [_CRYPTO_CONFIG_LABELS.get(key, key) for key in option_keys]
    live = ",".join(LIVE_DEK_STATUSES)
    may_view_keks = _may_view(request.user, "keyencryptionkey")
    may_view_deks = _may_view(request.user, "dataencryptionkey")
    context = {
        **model_admin.admin_site.each_context(request),
        "title": _("Cryptographic inventory"),
        "opts": model_admin.model._meta,
        "inventory": inventory,
        "engine_headers": engine_headers,
        "engine_rows": engine_rows,
        "kms_rows": [
            {
                "entry": entry,
                "adapter_parts": _wrap_parts(entry.kms_adapter),
                "kek_strategy_parts": _wrap_parts(entry.kek_strategy),
                "kek_url": _count_link(may_view_keks, "keyencryptionkey", key_store=entry.key_store),
                "dek_url": _count_link(
                    may_view_deks, "dataencryptionkey", kek__key_store=entry.key_store, status__in=live
                ),
            }
            for entry in inventory.key_stores
        ],
        "key_store_rows": [
            {"choice": choice, "adapter_parts": _wrap_parts(choice.silo_adapter)}
            for choice in inventory.configured_for_new_key_encryption_keys
        ],
        "kek_rows": [
            {
                "group": group,
                "url": _count_link(may_view_keks, "keyencryptionkey", key_store=group.key_store, status=group.status),
            }
            for group in inventory.key_encryption_keys
        ],
        "data_key_rows": [
            {
                "group": group,
                "url": _count_link(
                    may_view_deks,
                    "dataencryptionkey",
                    key_set=group.key_set,
                    purpose=group.purpose,
                    crypto_backend=group.cryptographic_engine,
                    algorithm=group.algorithm,
                    kek__key_store=group.key_store,
                    status__in=live,
                ),
            }
            for group in inventory.data_encryption_keys
        ],
        "changelist_url": reverse("admin:encryption_suite_dataencryptionkey_changelist"),
    }
    return TemplateResponse(request, "admin/encryption_suite/inventory.html", context)
