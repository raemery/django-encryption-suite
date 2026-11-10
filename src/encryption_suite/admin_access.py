"""
Who may reach the four custom admin screens.

Reconcile Keys, the test console, Encryption settings and the Cryptographic
inventory are plain views, not ``ModelAdmin`` screens, so nothing checks a model
permission on their behalf. Each is gated by a permission of its own, carried by
:class:`~encryption_suite.models.EncryptionTools` because each screen spans both
key models and belongs to neither.

``admin_site.admin_view`` already enforces active + staff on the routes. The
staff half is repeated here because these views are ordinary functions a project
can call from a URLconf of its own.
"""

from __future__ import annotations

from django.core.exceptions import PermissionDenied

#: Gates the Reconcile Keys page.
PERM_RECONCILE_KEYS = "encryption_suite.reconcile_keys"

#: Gates all three test console views.
PERM_RUN_TEST_CONSOLE = "encryption_suite.run_test_console"

#: Gates the read-only Encryption settings page.
PERM_VIEW_SETTINGS = "encryption_suite.view_settings"

#: Gates the read-only Cryptographic inventory page.
PERM_VIEW_INVENTORY = "encryption_suite.view_inventory"


def require_screen_access(request, permission: str) -> None:
    """Reject anyone who is not active staff holding *permission*.

    Raises ``PermissionDenied``, which the admin renders as its own 403 — the
    same response a missing model permission produces, so a screen an operator
    may not use fails the way every other one does.
    """
    user = request.user
    if not (user.is_active and user.is_staff and user.has_perm(permission)):
        raise PermissionDenied("Staff access and the screen permission are required.")
