"""
Management command: record_key_event

Append a manually-recorded entry to the ``KeyLifecycleEvent`` ledger for a key encryption key
(KEK) lifecycle act performed *outside* the application — a key created,
scheduled for deletion, or deleted via Terraform, the provider console, or
``flyctl``. The application's automatic paths (provisioning, deletion) record
their own events; this command exists for the acts performed outside this application they never
observe, so the ledger stays a complete history. The Add form on the admin "Key
encryption keys" page is the GUI counterpart.

The act is recorded row-first: the durable :class:`KeyEncryptionKey` row is created (or
fetched) before its event, so every event points at a row. The event is pinned
with the stable ``recorded_by_operator`` reason and the operating-system login
account of whoever runs the command, so a manual attestation is always
distinguishable from a tooling-verified event. Only KEK manual verbs may be
recorded (see :func:`lifecycle.manual_events_for_kind`).

The recorded identity is always the person running the command — it is never
supplied as an argument. A record here is that person's *claim* that something
happened in the provider console; the ledger stands behind who made the claim,
not behind the act itself.

Usage::

    python manage.py record_key_event --event created \\
        --kek-resource-name alias/es-prod-team-7
"""

from __future__ import annotations

from django.core.management.base import BaseCommand, CommandError

from encryption_suite._logging import get_logger

logger = get_logger(__name__)


class Command(BaseCommand):
    help = (
        "Record a key created outside this application encryption key lifecycle event "
        "(created/deletion_scheduled/deletion_requested/deleted)."
    )

    def add_arguments(self, parser):
        from encryption_suite import lifecycle

        parser.add_argument(
            "--event",
            required=True,
            choices=sorted(lifecycle.MANUAL_KEK_EVENTS),
            help="The lifecycle verb to record (created / deletion_scheduled / deletion_requested / deleted).",
        )
        parser.add_argument(
            "--kek-resource-name",
            required=True,
            help="Key encryption key resource identifier the event concerns.",
        )
        parser.add_argument(
            "--key-store",
            default="",
            help="Name of the key store that holds the key, from KMS_KEY_STORES or ENV_KEY_STORES (defaults to "
            "the default key set's store).",
        )
        parser.add_argument("--silo-uid", default="", help="Silo UID the event concerns, if known (event snapshot).")
        parser.add_argument(
            "--key-set", default="default", help="Key set of --silo-uid (default: default; event snapshot)."
        )

    def handle(self, *args, **options):
        from encryption_suite.conf import default_kms_name, kms_names
        from encryption_suite.models import KeyEncryptionKey, KeyLifecycleEvent
        from encryption_suite.silo_ref import SiloRef
        from encryption_suite.user_context import get_os_user, identity_tail

        os_login_user = get_os_user()
        logger.warning(
            "A privileged management command started; this line records that it ran, including a run "
            'that changes nothing. command=record_key_event kek="%s" %s',
            options["kek_resource_name"],
            identity_tail(os_login_user=os_login_user),
        )

        def log_finished(recorded: int) -> None:
            """Close the run, at the level its opening line was written at.

            Called from every ending the command reaches on purpose, a refusal
            included: the ledger row this command writes is its own record, so
            without this line a run that refused to write one leaves an opening
            line and nothing to pair it with.
            """
            logger.warning(
                'A privileged management command finished. command=record_key_event event=%s kek="%s" recorded=%d %s',
                options["event"],
                options["kek_resource_name"],
                recorded,
                identity_tail(os_login_user=os_login_user),
            )

        if not os_login_user:
            log_finished(0)
            raise CommandError(
                "Could not determine the operating-system login account for this record. "
                "Set the USER (or USERNAME on Windows) environment variable and run again."
            )

        # Every path that later acts on the row routes by this name, so a name no
        # block carries would record a key nothing can ever process.
        kms_name = options["key_store"] or default_kms_name()
        recordable = kms_names()
        if kms_name not in recordable:
            log_finished(0)
            raise CommandError(
                f"{kms_name!r} is not a configured key store. Pass --key-store with one of: {', '.join(recordable)}."
            )

        # Row-first: the durable KeyEncryptionKey row exists before its event. A key
        # this application has never seen gets its row here; an already-known key
        # keeps the one it has.
        row, _created = KeyEncryptionKey.objects.get_or_create(
            key_store=kms_name,
            kek_resource_name=options["kek_resource_name"],
        )

        log_entry = KeyLifecycleEvent.record_by_operator(
            row,
            options["event"],
            os_login_user=os_login_user,
            silo_ref=SiloRef(options["key_set"], options["silo_uid"]) if options["silo_uid"] else None,
        )
        self.stdout.write(
            self.style.SUCCESS(
                f"Recorded {log_entry.event} key encryption key event "
                f"(os_user={os_login_user}, kek={options['kek_resource_name']}, key_store={kms_name})."
            )
        )
        log_finished(1)
