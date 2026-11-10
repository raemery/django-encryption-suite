"""
Management command: crypto_inventory

Prints the cryptographic inventory in the order the admin page shows it: each
key store, the key encryption keys on it, the data encryption keys grouped by key
set, purpose, cryptographic engine, algorithm and key store, and what a new key
encryption key and a new data encryption key would get. See
:mod:`encryption_suite.inventory`.

Read-only and makes no KMS call, so it is safe to run anywhere and to schedule.
``--format json`` writes a document to keep with a review, or to diff against
last year's (see :mod:`encryption_suite.management._report`). Counts and
identifiers only — no key material, no wrapped keysets, no silo UIDs.

Usage::

    python manage.py crypto_inventory
    python manage.py crypto_inventory --format json --output inventory.json
"""

from __future__ import annotations

from django.core.management.base import BaseCommand

from ..._logging import get_logger
from .._report import Report, add_report_arguments

logger = get_logger(__name__)


def _date(value) -> str:
    return value.isoformat() if value else "-"


class Command(BaseCommand):
    help = (
        "Print the cryptographic inventory: key stores, keys, cryptographic engines and algorithms in use (read-only)."
    )

    def add_arguments(self, parser):
        add_report_arguments(parser)

    def handle(self, *args, **options):
        from encryption_suite.inventory import build_inventory
        from encryption_suite.user_context import get_os_user, identity_tail

        report = Report(self, "crypto_inventory", options, schema_version=2)
        # One line, not a started/finished pair: the command changes nothing, so
        # the line only has to say who read the inventory and when.
        logger.warning(
            "A privileged management command ran; this line records that it ran. command=crypto_inventory %s",
            identity_tail(os_login_user=get_os_user()),
        )
        inventory = build_inventory()
        if report.enabled:
            report.write(inventory.as_dict())
        else:
            self._write_text(inventory)

    def _write_text(self, inventory) -> None:
        """Print the sections in the order, and with the headings, the admin page uses."""
        from encryption_suite.admin_test_console import _CRYPTO_CONFIG_LABELS
        from encryption_suite.inventory import engine_table

        write = self.stdout.write
        configured = inventory.configured_for_new_data_encryption_keys
        write(f"Cryptographic inventory, {inventory.generated_at.isoformat()}")

        write("")
        write("Key management system (KMS)")
        for entry in inventory.key_stores:
            write(f"  {entry.key_store}")
            if entry.configured:
                write(f"    KMS adapter: {entry.kms_adapter}")
                write(f"    KEK strategy: {entry.kek_strategy or '-'}")
            else:
                write("    Not configured")
            write(f"    Key encryption keys: {entry.key_encryption_key_count}")
            write(f"    Data encryption keys: {entry.data_encryption_key_count}")
            write(f"    Oldest active KEK: {_date(entry.oldest_active_kek_at)}")

        write("")
        write("Key encryption keys (key store / status: count)")
        for group in inventory.key_encryption_keys:
            write(f"  {group.key_store} / {group.status}: {group.count}")
        if not inventory.key_encryption_keys:
            write("  none")

        write("")
        write("Configured for new key encryption keys (key set / key store / silo adapter)")
        for choice in inventory.configured_for_new_key_encryption_keys:
            line = f"  {choice.key_set} / {choice.key_store or '-'} / {choice.silo_adapter or '-'}"
            write(line if choice.key_store else self.style.WARNING(f"{line} [no store resolves]"))

        write("")
        period = inventory.rotation_period_days
        write(
            "Data encryption keys (key set / purpose / cryptographic engine / algorithm / key store: "
            + "count, oldest key material"
            + (f", older than {period} days)" if period is not None else "; no rotation period declared)")
        )
        for group in inventory.data_encryption_keys:
            overdue = group.older_than_rotation_period
            older = f", older than {period} days {overdue}" if overdue is not None else ""
            line = (
                f"  {group.key_set} / {group.purpose} / {group.cryptographic_engine or '-'} / "
                f"{group.algorithm or '-'} / {group.key_store}: "
                f"{group.count}, oldest key material {_date(group.oldest_key_material_at)}{older}"
            )
            if group.in_settings:
                write(line)
            else:
                write(self.style.WARNING(f"{line} [no settings entry]"))
        if not inventory.data_encryption_keys:
            write("  none")

        write("")
        option_keys, rows = engine_table(configured)
        labels = [str(_CRYPTO_CONFIG_LABELS.get(key, key)) for key in option_keys]
        columns = " / ".join(["purpose", "cryptographic engine", "algorithm", *labels])
        write(f"Configured for new data encryption keys ({columns})")
        for row in rows:
            cells = [row["purpose"], row["engine"], row["algorithm"], *row["extras"]]
            line = "  " + " / ".join(cell or "-" for cell in cells)
            write(self.style.WARNING(line) if configured.error_code and not row["purpose"] else line)
