"""Operator hints shared by the management commands.

Separate from the commands so the wording of a diagnosis lives in one place: the
same misconfiguration reaches every KMS-facing surface alike, and two of them
explaining it differently is how an operator learns to distrust both.
"""

from __future__ import annotations


def kms_not_configured_hint(skipped_names) -> str:
    """Explain a run that skipped rows because their KMS is not configured.

    Every key is handed only to the KMS its row names, so a row naming a KMS
    with no ``KMS_KEY_STORES`` block cannot be acted on, which is the correct and
    safe outcome. It is also indistinguishable, from the summary line alone,
    between two very different situations: a deployment carrying keys on a KMS
    it has since dropped, and a command pointed at the wrong settings module —
    which in a repository with one settings file per KMS is a single missing
    ``--settings``.

    Names the live settings module rather than only the KMS, because that is the
    thing the operator would have to change, and prints the exact flag. The
    wording stays even-handed: a dropped KMS is a real configuration and must not
    be reported as an error.
    """
    from django.conf import settings

    module = getattr(settings, "SETTINGS_MODULE", None) or "<unknown>"
    names = ", ".join(f"'{name}'" for name in sorted(skipped_names))
    return (
        f"Note: rows on key store {names} were skipped because no ENCRYPTION['KMS_KEY_STORES'] block "
        f"carries that name. Keys are only ever handed to the KMS that wrapped them.\n"
        f"This run used settings module '{module}'. If that is not the deployment that owns "
        f"those keys, the command is pointed at the wrong configuration — name the right module "
        f"explicitly:\n"
        f"    manage.py <command> --settings=<your.settings.module>\n"
        f"If those keys are on a KMS this deployment no longer configures, the skip is expected; "
        f"restore its block under the same name to act on them."
    )
