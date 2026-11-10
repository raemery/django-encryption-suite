"""
Management command: reconcile_keys

Runs the same reconcile pass the admin's Reconcile Keys page runs, from the
command line, so it can be scheduled.

Reconcile compares what this deployment *thinks* exists (key rows) against what
actually exists (live silos, key encryption keys on the KMS) and records what it
learns: newly discovered keys, keys whose silo has gone, keys whose silo has come
back, and provider-window deletions the enumeration witnessed. It also reports
which keys are behind on material — data keys past their declared rotation
period, and keys still wrapped by a key version the provider has moved past.

One pass runs per key store that a key set uses, each covering the keys on that
store, plus any other store that still holds a key encryption key row that is
not deleted, so keys left on a store a deployment is moving off stay accounted
for until ``reencrypt_keys`` has moved every row. An env store has no provider
to list and gets no pass. The admin page runs the pass for the store of the key
set it shows.

Scheduling it (daily is a sensible starting point) keeps the annotations from
going stale between admin visits. A pass that learns nothing writes nothing, so a
quiet deployment costs a listing call and no database writes.

**There is deliberately no --dry-run.** Reconcile only ever records what it
observed; it never deletes, never schedules, and never touches key material. A
preview would be the same enumeration at the same cost, differing only in whether
the findings are written down — and the findings are the point.

Usage::

    python manage.py reconcile_keys
    python manage.py reconcile_keys --format json --output reconcile.json
"""

from __future__ import annotations

from django.core.management.base import BaseCommand

from encryption_suite.reconcile import format_detection_reasons, partition_detection_reasons

from ..._logging import get_logger
from .._report import Report, add_report_arguments

logger = get_logger(__name__)


class Command(BaseCommand):
    help = "Reconcile stored key records against live silos and the KMS (safe to schedule)."

    def add_arguments(self, parser):
        add_report_arguments(parser)

    def handle(self, *args, **options):
        from encryption_suite.reconcile_service import run_reconcile, stores_to_reconcile
        from encryption_suite.user_context import get_os_user, identity_tail

        report = Report(self, "reconcile_keys", options, schema_version=2)
        os_login_user = get_os_user()
        logger.warning(
            "A privileged management command started; this line records that it ran, including a run "
            "that changes nothing. command=reconcile_keys %s",
            identity_tail(os_login_user=os_login_user),
        )
        names = stores_to_reconcile()
        passes = []
        for key_store in names:
            self.stdout.write(f"Key store: {key_store}")
            result = run_reconcile(key_store=key_store, os_login_user=os_login_user)
            self._log_pass(result, os_login_user)
            self._report(result)
            passes.append(self._pass_document(result))
        logger.warning(
            "A privileged management command finished. command=reconcile_keys passes=%d %s",
            len(names),
            identity_tail(os_login_user=os_login_user),
        )
        report.write({"passes": passes})

    @staticmethod
    def _pass_document(result) -> dict:
        """One pass as JSON-ready data: the same findings the text prints, in the same terms.

        A count is ``None`` where the text says "not checked". The two reason
        lists carry the language-neutral slugs, not their translated words.
        Silo UIDs are left out, as the text leaves them out: the orphaned keys
        are counted, and the admin's Reconcile Keys page lists them.
        """
        report = result.report
        structural, incidental = partition_detection_reasons(report.degraded)

        def count(items, checked):
            return len(items) if checked else None

        return {
            "key_store": result.key_store,
            "discovered": list(result.discovered),
            "observed_pending": list(result.observed_pending),
            "confirmed_deleted": list(result.confirmed_deleted),
            "kek_live_past_deletion_date": list(result.drift_overdue),
            "kek_missing_from_kms": list(result.drift_missing),
            "kek_rotated_at_provider": list(result.rotated),
            "orphaned_data_keys": count(report.db_orphan_uids, report.db_reconcile_available),
            "orphaned_keks": count(report.kms_orphan_keks, report.kms_reconcile_available),
            "data_reencryption_due": count(
                report.overdue, report.key_material_checked and report.cryptoperiod_declared
            ),
            "key_reencryption_due": count(
                report.superseded, report.key_material_checked and report.key_versions_available
            ),
            "rotation_check_capped": result.probes_capped,
            "not_applicable": structural,
            "could_not_run": incidental,
        }

    def _report(self, result) -> None:
        """Print one pass's findings and counts."""
        report = result.report

        # Colored like the other commands: green for what this pass recorded,
        # yellow for drift an operator has to look into.
        for label, names, style in (
            ("Discovered", result.discovered, self.style.SUCCESS),
            ("Confirmed deleted", result.confirmed_deleted, self.style.SUCCESS),
            ("KEK still live on KMS past its deletion date", result.drift_overdue, self.style.WARNING),
            ("KEK missing from KMS", result.drift_missing, self.style.WARNING),
            ("KEK material rotated at the provider", result.rotated, self.style.SUCCESS),
        ):
            for name in names:
                self.stdout.write(style(f"{label}: {name}"))

        # Degraded dimensions split by whether they describe the shape of the
        # deployment or something going wrong. A scheduled run repeats its output
        # every day: a permanent property of the configuration arriving as a daily
        # warning is how warnings stop being read, so those go to stdout in green
        # and only the rest reaches stderr in yellow. Neither is a failure — the
        # pass did everything it could — so the exit status stays 0.
        structural, incidental = partition_detection_reasons(report.degraded)

        # Counts rather than a row per key: these are standing conditions, not
        # things that happened on this pass, and a scheduled run would otherwise
        # reprint the same list every day until someone acts on it.
        failed = bool(incidental)
        self._write_count("Orphaned data encryption keys", report.db_orphan_uids, report.db_reconcile_available, failed)
        self._write_count(
            "Orphaned key encryption keys", report.kms_orphan_keks, report.kms_reconcile_available, failed
        )
        if report.key_material_checked:
            self._write_count("Data re-encryption due", report.overdue, report.cryptoperiod_declared, failed)
            self._write_count("Key re-encryption due", report.superseded, report.key_versions_available, failed)

        if structural:
            self.stdout.write(
                self.style.SUCCESS(f"Not applicable to this configuration: {format_detection_reasons(structural)}")
            )
        if incidental:
            self.stderr.write(self.style.WARNING(f"Some checks could not run: {format_detection_reasons(incidental)}"))

    def _write_count(self, label, items, checked, failed) -> None:
        """One count line: yellow when there is something to act on, green otherwise.

        ``not checked`` is green when the configuration explains it, and yellow
        when a check failed on this pass: the report does not say which check a
        failure blocked, so a failure on any of them withholds the green.
        """
        if not checked:
            style = self.style.WARNING if failed else self.style.SUCCESS
            self.stdout.write(style(f"{label}: not checked"))
        elif items:
            self.stdout.write(self.style.WARNING(f"{label}: {len(items)}"))
        else:
            self.stdout.write(self.style.SUCCESS(f"{label}: 0"))

    def _log_pass(self, result, os_login_user) -> None:
        """Close one pass on one line, changed or not.

        This is the run log, and the reason no reconcile-run *table* exists. The
        service logs no summary of its own for a command run, so these lines are
        the only ones, each carrying every field the admin page's summary
        carries, ``key_store=`` naming its pass; the command's closing line follows the
        last. At WARNING, the level the opening line was written at: a deployment
        that cuts INFO would otherwise keep the opening line and lose these,
        which reads as a run that never reached an ending.
        """
        from encryption_suite.reconcile_service import reconcile_summary_fields
        from encryption_suite.user_context import identity_tail

        fields, args = reconcile_summary_fields(result)
        logger.warning(
            "A reconcile pass finished. command=reconcile_keys " + fields + " %s",
            *args,
            identity_tail(os_login_user=os_login_user),
        )
