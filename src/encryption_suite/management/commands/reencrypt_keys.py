"""
Management command: reencrypt_keys

Re-encrypts each DataEncryptionKey under its key set's store (``KEY_SETS``)
and that store's current KEK.

Each row is unwrapped through the KMS its key encryption key row names and
wrapped through its key set's store, so the same run serves two jobs: after rotating the
Key Encryption Key (KEK) in your KMS, it moves every stored DEK onto the new key
version; after pointing the key set's store at a different store, it
moves every stored DEK of that set onto it. One pass runs per key set
fields declare. The old key encryption key rows remain.
The plaintext DEK is never persisted — it lives in memory only during the
re-encrypt operation.

Each record is updated inside its own database transaction so that a partial
failure leaves already-reencrypted records committed and does not roll back
previously successful work. A run that fails any record still finishes the
others, then exits non-zero, so a scheduler sees the failure.

Only DEKs that can actually be re-wrapped are attempted, so the failure count
means a real failure. Test-console keys and non-active DEKs (scheduled or purged)
are excluded from the queryset outright and appear in no count. Of the rows that
remain, those whose key encryption key has been retired, those on a KMS no
``KMS_KEY_STORES`` block names, and — where the row is already on the set's store and
the provider records a key version — those already wrapped under the current one
are reported as skipped. A dry run reports the same decisions the real run will
make, and the dry run and the opening log line both name each KMS the run moves
rows off (``adapter fly → aws``).

``--provision`` additionally creates each silo's KEK on the key set's store before
re-wrapping onto it. It is for the *name rollover* rotation used by providers that
cannot rotate key material behind a stable name — ``KEK_TEMPLATE`` is pointed at a
new generation and every DEK moves to the new key — and for a move to a KMS whose
keys do not exist yet. Without it the command only re-wraps, which is all an
in-place provider rotation needs.

Usage::

    python manage.py reencrypt_keys
    python manage.py reencrypt_keys --silo-uid "team-42"
    python manage.py reencrypt_keys --dry-run
    python manage.py reencrypt_keys --provision --dry-run
    python manage.py reencrypt_keys --provision
    python manage.py reencrypt_keys --format json --output reencrypt_keys.json
"""

from __future__ import annotations

from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from django.utils import timezone

from encryption_suite import lifecycle
from encryption_suite._internal import iter_rows, optional_log_field
from encryption_suite._logging import get_logger
from encryption_suite.deletion import LIVE_DEK_STATUSES
from encryption_suite.models import DataEncryptionKey, DekRotation, KeyEncryptionKey

from .._report import Report, add_report_arguments

logger = get_logger(__name__)


class Command(BaseCommand):
    help = (
        "Re-encrypt DataEncryptionKey records under their key set's key store and its current KEK "
        "(use after KEK rotation, or after pointing KEY_SETS at another store)."
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "--silo-uid",
            dest="silo_uid",
            default=None,
            help="Only re-encrypt the specified silo_uid. Re-encrypts all if omitted.",
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Show which records would be re-encrypted without contacting KMS.",
        )
        parser.add_argument(
            "--key-set",
            dest="key_set",
            default="default",
            help="Which key set's keys to re-wrap onto that key set's store: default (the default), system, "
            "another key set declared in KEY_SETS, or all, one pass per key set.",
        )
        parser.add_argument(
            "--provision",
            action="store_true",
            help="Create each silo's key encryption key on its key set's store before re-wrapping onto it. For "
            "the name-rollover rotation used by providers that cannot rotate a key in place (point "
            "KEK_TEMPLATE at a new generation, then run this), and for a move to a KMS whose keys do "
            "not exist yet. Refuses if the template's owner prefix changed.",
        )
        add_report_arguments(parser)

    def handle(self, *args, **options):
        report = Report(self, "reencrypt_keys", options, schema_version=2)
        from encryption_suite.conf import key_set_names
        from encryption_suite.exceptions import EncryptionError
        from encryption_suite.registry import new_key_kms
        from encryption_suite.rotation_targets import key_sets_in_use

        known = key_set_names()
        if options["key_set"] != "all" and options["key_set"] not in known:
            raise CommandError(
                f"--key-set {options['key_set']!r} is not a declared key set: use all or one of {known}."
            )
        # One pass per key set its fields declare.
        declared = key_sets_in_use()
        key_sets = [each for each in known if each in declared] if options["key_set"] == "all" else [options["key_set"]]
        # Every store resolved before the first row moves, so a key set with no
        # usable store refuses the run instead of stopping it after earlier passes.
        for key_set in key_sets:
            try:
                new_key_kms(key_set)
            except EncryptionError as exc:
                raise CommandError(f"Nothing was re-encrypted. {getattr(exc, 'detail', None) or exc}") from exc
        passes = [self._run(key_set, options) for key_set in key_sets]
        report.write({"passes": passes})
        # After the report, so a scheduler that reads the document also sees the
        # exit status. Every row was still attempted: a failure stops nothing.
        failed = sum(each["failed"] for each in passes)
        if failed:
            raise CommandError(
                f"{failed} data encryption key(s) could not be re-encrypted. Each is named in a "
                "'Failed to' line above; the rest were re-encrypted."
            )

    def _run(self, key_set: str, options) -> dict:
        """Run one pass, for key set *key_set*, and return its summary."""
        from encryption_suite.adapters.key_stores.base import KmsMetadata
        from encryption_suite.conf import kms_block
        from encryption_suite.engine import EncryptionEngine, ensure_kek_provisioned, kms_error_guard
        from encryption_suite.registry import get_engine, get_kek_provisioner, get_kms_adapter, new_key_kms
        from encryption_suite.user_context import get_os_user, identity_tail

        # Resolved once for the whole run: every row this pass rewraps is the
        # same act by the same person, and re-reading it per row would only
        # invite the values to disagree.
        os_login_user = get_os_user()
        dry_run: bool = options["dry_run"]
        provision: bool = options["provision"]
        silo_uid: str | None = options["silo_uid"]
        engine = get_engine()
        # The store every row of this pass is wrapped onto: the one the settings
        # give this key set. Each row is unwrapped through the one its key
        # encryption key row names.
        kms = get_kms_adapter(new_key_kms(key_set))

        # Test-console keys have their own lifecycle and are skipped here, as they
        # are by schedule_deletion, orphan detection, and SILO_AUTO_KEY_DELETION. Their
        # DEK protects a fixed throwaway payload and the console recreates it on
        # demand, so re-wrapping one preserves a key nobody needs preserved.
        #
        # Only live DEKs are re-wrapped: active ones, and ones under a data key
        # rotation, which still hold material — along with a second keyset on
        # the rotation row that nothing else rewraps. A scheduled one is blocked
        # from encrypt and decrypt for the length of its restore window, and a
        # purged one is a tombstone whose encrypted_keyset has been cleared to
        # empty — handing either to the KMS trades a rewrap that cannot succeed
        # for a provider error (a purged row's empty ciphertext fails validation).
        qs = (
            DataEncryptionKey.objects.exclude(purpose=DataEncryptionKey.PURPOSE_TEST)
            .filter(status__in=LIVE_DEK_STATUSES)
            .select_related("kek", "rotation__kek")
        )
        qs = qs.filter(key_set=key_set)
        if silo_uid:
            qs = qs.filter(silo_uid=silo_uid)

        # Every configured KMS this run moves rows off, named up front so an
        # operator sees a conversion before it happens and the log records it.
        # One the configuration lacks is left out: its rows are skipped below.
        conversions = sorted(
            f"key store {name} -> {kms.kms_name}"
            for name in set(qs.values_list("kek__key_store", flat=True))
            if name != kms.kms_name and kms_block(name) is not None
        )
        logger.warning(
            "A privileged management command started; this line records that it ran, including a run "
            "that changes nothing. command=reencrypt_keys key_set=%s dry_run=%s provision=%s "
            'silo="%s"%s %s',
            key_set,
            dry_run,
            provision,
            silo_uid or "all",
            optional_log_field("converts", ", ".join(conversions)),
            identity_tail(os_login_user=os_login_user),
        )
        prefix = "[dry-run] " if dry_run else ""
        for conversion in conversions:
            self.stdout.write(f"{prefix}Converting: {conversion}")

        provisioner = get_kek_provisioner(kms.kms_name) if provision else None
        if provision:
            self._check_owner_prefix(qs, kms, provisioner)

        # Silos whose key has already been ensured this run. The template keys on
        # the silo UID alone, so a silo's field and file rows resolve to one key —
        # without this the second row repeats the lookup for no gain.
        provisioned_silos: set[str] = set()

        # Whether the provisioner *created* each silo's key on this run, carried
        # to the key encryption key row so its first ledger event says the key
        # was provisioned rather than merely observed. Empty without
        # --provision, where nothing is ever created and False is always right.
        created_keks: dict[str, bool] = {}

        # A KEK that is scheduled, requested, or already gone cannot unwrap
        # anything, so its DEKs are reported as skipped rather than failed —
        # they are retired on purpose, and counting them as failures buries the
        # one result that means something.
        retired_keks = {
            (kms_name, name): status
            for kms_name, name, status in KeyEncryptionKey.objects.exclude(status=lifecycle.STATUS_ACTIVE).values_list(
                "key_store", "kek_resource_name", "status"
            )
        }

        # Unconfigured KMS names seen on rows this run could not touch. Collected
        # rather than counted so the closing hint can name them.
        unconfigured_names: set[str] = set()

        def probe_version(uid: str) -> str:
            """The key version a new wrap would use, or "" if the provider cannot say.

            Every failure degrades to "": a broken probe must never skip real
            work, and must never turn a successful rewrap into a reported one.
            Adapters cache this for the length of KEY_VERSION_TTL_SECONDS, so
            asking once per row costs one lookup per run, not one per row.
            """
            try:
                return kms.current_kek_version(uid)
            except Exception:
                return ""

        def provision_target(record) -> str | None:
            """The key name to ensure for *record*, or ``None`` when there is none.

            ``None`` covers the two cases that need no provisioning: a silo already
            ensured on this run, and a row already on the kind's store whose resolved
            name still matches the key it is wrapped by — an unchanged
            ``KEK_TEMPLATE``, or a ``KEK_MAP`` entry, where the rewrap is an
            in-place rotation and no key is new. Resolution is local (the strategy
            renders the template), so this costs no provider call.
            """
            if record.silo_ref in provisioned_silos:
                return None
            resolved = kms.resolve_kek_name(record.silo_ref)
            provisioned_silos.add(record.silo_ref)
            if record.kek.key_store == kms.kms_name and resolved == record.kek.kek_resource_name:
                return None
            return resolved

        def skip_reason(record) -> str | None:
            """Why this DEK cannot be re-wrapped, or None to attempt it.

            Raw status values rather than their translated labels: this is
            operator output, and a language-neutral slug stays greppable.
            """
            # A DEK is only ever unwrapped by the KMS its row names. With no
            # block under that name there is nothing to unwrap it with — a KMS
            # this deployment dropped, or a run pointed at the wrong settings
            # module, which the closing hint tells apart.
            if kms_block(record.kek.key_store) is None:
                unconfigured_names.add(record.kek.key_store)
                return f"on key store '{record.kek.key_store}', which no KMS_KEY_STORES block names"
            retired_status = retired_keks.get((record.kek.key_store, record.kek.kek_resource_name))
            if retired_status is not None:
                return f"key encryption key is {retired_status}"
            # Already on the current key material: re-wrapping would produce the
            # same result at the cost of a KMS round trip per row, and would bump
            # the re-encryption count for nothing. Only providers that record a
            # version can answer this; the rest report "" and are always re-wrapped.
            # A row on another KMS always moves, whatever its version.
            if record.kek.key_store == kms.kms_name and record.kek_key_version:
                current = probe_version(record.silo_ref)
                if current and current == record.kek_key_version:
                    return "already wrapped by the current key version"
            return None

        reencrypted = failed = skipped = 0

        # iter_rows, not QuerySet.iterator(): the latter needs a server-side
        # cursor, which a pooled Postgres connection drops part way through the
        # walk. See encryption_suite._internal.iter_rows.
        for record in iter_rows(qs):
            # Evaluated for a dry run too, so the preview reports the same
            # decisions the real run will make.
            reason = skip_reason(record)
            if reason is not None:
                self.stdout.write(f"{prefix}Skipped: {record.silo_ref} [{record.purpose}] — {reason}")
                skipped += 1
                continue
            if dry_run:
                if provision:
                    # Evaluated here too, so the preview names the keys the real
                    # run would create — and so a template that renders an
                    # unusable name fails now rather than mid-rollover.
                    try:
                        target = provision_target(record)
                    except Exception as exc:
                        self._report_failure(record, exc, "resolve the key name for")
                        failed += 1
                        continue
                    if target:
                        self.stdout.write(f"[dry-run] Would provision: {target}")
                also = " and its rotation's incoming key" if getattr(record, "rotation", None) else ""
                self.stdout.write(f"[dry-run] Would re-encrypt: {record.silo_ref} [{record.purpose}]{also}")
                reencrypted += 1
                continue
            try:
                if provision:
                    # Before the unwrap: the rewrap below targets this key, and on
                    # a name rollover it does not exist yet.
                    target = provision_target(record)
                    if target:
                        _, created_kek = ensure_kek_provisioned(
                            kms, provisioner, record.silo_ref, os_login_user=os_login_user
                        )
                        created_keks[record.silo_ref] = created_kek
                        self.stdout.write(f"{'Provisioned' if created_kek else 'Found existing'}: {target}")
                source = engine.kms_adapter_for_kek(record.kek, record.silo_ref)
                old_metadata = KmsMetadata(
                    kek_resource_name=record.kek.kek_resource_name,
                    kms_provider=source.kms_provider,
                    kms_name=record.kek.key_store,
                    kek_key_version=record.kek_key_version,
                )
                # Decrypt outside the transaction: KMS calls are not transactional,
                # and we do not want to hold a DB transaction open during a network call.
                #
                # This command drives the adapters directly rather than through the
                # engine, so the guard supplies the funnel the engine would have:
                # without it a raw provider error (a boto ClientError, a urllib
                # HTTPError) reaches the operator untranslated, with no error-code
                # slug to grep for.
                with kms_error_guard("key unwrap", record.silo_ref, source):
                    plaintext_keyset = source.decrypt_key(bytes(record.encrypted_keyset), old_metadata, record.silo_ref)
                with kms_error_guard("key wrap", record.silo_ref, kms):
                    new_ciphertext, new_metadata = kms.encrypt_key(plaintext_keyset, record.silo_ref)
                new_metadata.kms_name = kms.kms_name
                # The save below overwrites the only wrapped copy, so the new one
                # is unwrapped first, through exactly what will be stored.
                self._check_wrap(kms, new_ciphertext, new_metadata, record.silo_ref, plaintext_keyset)
                # Drop the plaintext keyset reference as soon as possible to
                # shorten its lifetime in process memory.  Python cannot
                # guarantee zeroization, but deleting the reference makes the
                # bytes eligible for GC immediately.
                del plaintext_keyset

                # A data key rotation in flight holds the silo's incoming
                # material on its own row, wrapped by its own key. It moves with
                # the data key or not at all: nothing else rewraps it, so a key
                # retired mid-rotation would strand the material the silo is
                # being moved onto.
                rotation = getattr(record, "rotation", None)
                rotation_rewrap = None
                if rotation is not None:
                    rotation_source = engine.kms_adapter_for_kek(rotation.kek, record.silo_ref)
                    rotation_metadata = KmsMetadata(
                        kek_resource_name=rotation.kek.kek_resource_name,
                        kms_provider=rotation_source.kms_provider,
                        kms_name=rotation.kek.key_store,
                        kek_key_version=rotation.kek_key_version,
                    )
                    with kms_error_guard("key unwrap", record.silo_ref, rotation_source):
                        incoming = rotation_source.decrypt_key(
                            bytes(rotation.encrypted_keyset), rotation_metadata, record.silo_ref
                        )
                    with kms_error_guard("key wrap", record.silo_ref, kms):
                        rotation_rewrap = kms.encrypt_key(incoming, record.silo_ref)
                    rotation_rewrap[1].kms_name = kms.kms_name
                    self._check_wrap(kms, rotation_rewrap[0], rotation_rewrap[1], record.silo_ref, incoming)
                    del incoming

                # Each record is updated in its own transaction so that a failure on
                # one silo does not roll back records that were already re-encrypted.
                with transaction.atomic():
                    # Re-fetch inside the transaction to guard against concurrent updates.
                    locked = DataEncryptionKey.objects.select_for_update().get(pk=record.pk)
                    # If another process re-encrypted this record between our decrypt and
                    # this lock, the keyset we decrypted is stale — skip it. A data
                    # key rotation's swap moves the count too, which is what makes a
                    # swap landing in that gap skip here rather than be overwritten
                    # with the material it just replaced.
                    if locked.reencryption_count != record.reencryption_count:
                        self.stderr.write(
                            self.style.WARNING(
                                f"Skipped: {record.silo_ref} was concurrently "
                                f"re-encrypted (v{record.reencryption_count} -> v{locked.reencryption_count})"
                            )
                        )
                        skipped += 1
                        continue
                    locked.encrypted_keyset = new_ciphertext
                    # The created flag matters only when this call brings the row
                    # into being: without it a key the provisioner had just
                    # generated was recorded as one found already in the KMS, and
                    # its first ledger event said `discovered` rather than
                    # `created`. Harmless before --provision, which never created
                    # anything.
                    locked.kek = engine._kek_row(
                        new_metadata,
                        created_keks.get(record.silo_ref, False),
                        trigger=lifecycle.TRIGGER_AUTOMATED,
                        os_login_user=os_login_user,
                    )
                    locked.kek_key_version = new_metadata.kek_key_version
                    locked.reencryption_count += 1
                    # The date a key-encryption-key cryptoperiod is measured
                    # against. Rotating the key at the provider protects nothing
                    # already stored; this rewrap is the act that moves the row off
                    # the old material, so it is the act that carries the date.
                    # key_material_last_generated_at is deliberately untouched —
                    # the data key itself is the same bytes, only rewrapped.
                    locked.last_reencrypted_at = timezone.now()
                    locked.save(
                        update_fields=[
                            "encrypted_keyset",
                            "kek",
                            "kek_key_version",
                            "reencryption_count",
                            "last_reencrypted_at",
                            "updated_at",
                        ]
                    )
                    # Record the rewrap in the lifecycle ledger, in the same
                    # transaction as the act. There is no logged-in user on a
                    # command run, but there is always the operating-system
                    # login account that started it — which is the accountable
                    # identity for an act only shell access can perform.
                    locked.record_event(
                        lifecycle.EVENT_REENCRYPTED,
                        trigger=lifecycle.TRIGGER_AUTOMATED,
                        os_login_user=os_login_user,
                    )
                    if rotation_rewrap is not None:
                        # Taken after the data key row, the order the swap takes
                        # them in, so the two cannot deadlock.
                        self._rewrap_rotation(
                            engine, rotation, rotation_rewrap, created_keks.get(record.silo_ref, False), os_login_user
                        )

                # Invalidate the Aead cache for this silo so the next field
                # access fetches the freshly encrypted keyset.
                EncryptionEngine.invalidate_cache(record.silo_ref)

                # "write N" rather than "vN": the count says how many times new
                # encrypted key material has been written to this row — by a
                # rewrap like this one, or by a data key rotation's swap — which
                # is not a KMS key version and reads like one. Where the provider
                # reports a version, name it separately — and say so when the wrap
                # did not land on the version the provider had just reported as
                # current. That happens when a provider chooses the version
                # server-side and its metadata moves ahead of its crypto (Cloud
                # KMS is eventually consistent after a rotation), and without this
                # the run looks like it accomplished nothing.
                #
                # ASCII "->", not an arrow: a Windows console piped to a file
                # encodes as cp1252, which has no arrow, and the failed write would
                # land in the except below and count a committed rewrap as failed.
                detail = f"write {locked.reencryption_count}"
                if record.kek.key_store != kms.kms_name:
                    detail += f", key store {record.kek.key_store} -> {kms.kms_name}"
                if locked.kek_key_version:
                    detail += f", key version {locked.kek_key_version}"
                    expected = probe_version(record.silo_ref)
                    if expected and expected != locked.kek_key_version:
                        detail += f" (provider has not moved to {expected} yet — rerun later)"
                self.stdout.write(self.style.SUCCESS(f"Re-encrypted: {record.silo_ref} [{record.purpose}] -> {detail}"))
                reencrypted += 1
            except Exception as exc:
                self._report_failure(record, exc, "re-encrypt")
                failed += 1

        summary = f"Done. Re-encrypted: {reencrypted}, Skipped: {skipped}, Failed: {failed}."
        if dry_run:
            summary = f"[dry-run] {summary}"
        self.stdout.write(summary)

        # The closing half of the opening line above, at the same level so one
        # filter catches both: an opening line with no closing line after it is
        # a run that died part way through. Everything else this command reports
        # goes to a console that a scheduled run has nobody watching, so these
        # counts are the only durable record that a rewrap pass ran and what it
        # touched. A dry run logs it too — it decided the same rows, and a
        # preview nobody can prove ran is worth as little as a real one.
        logger.warning(
            "A privileged management command finished. command=reencrypt_keys key_set=%s "
            'dry_run=%s silo="%s" reencrypted=%d skipped=%d failed=%d %s',
            key_set,
            dry_run,
            silo_uid or "all",
            reencrypted,
            skipped,
            failed,
            identity_tail(os_login_user=os_login_user),
        )

        if unconfigured_names:
            from encryption_suite.management._hints import kms_not_configured_hint

            self.stdout.write(self.style.WARNING(kms_not_configured_hint(unconfigured_names)))

        return {
            "key_set": key_set,
            "dry_run": dry_run,
            "provision": provision,
            "silo_uid": silo_uid,
            "target_key_store": kms.kms_name,
            "converts": conversions,
            "reencrypted": reencrypted,
            "skipped": skipped,
            "failed": failed,
            "unconfigured_key_stores": sorted(unconfigured_names),
        }

    @staticmethod
    def _check_wrap(kms, ciphertext, metadata, silo_ref, expected) -> None:
        """Unwrap *ciphertext* through *metadata* and require *expected* back.

        The rewrap replaces the only wrapped copy of a data key, so a new wrap
        that cannot be unwrapped later — a provider quirk, a wrong recorded key
        name or version, a binding mismatch — would take every value under that
        key with it. Checked before anything is saved: on failure this raises a
        typed error, already logged, and the caller keeps the old copy.
        """
        from encryption_suite.engine import kms_error_guard
        from encryption_suite.exceptions import GENERIC_ENCRYPT_DECRYPT_UNAVAILABLE_MESSAGE, KekUnavailableError

        with kms_error_guard("key wrap check", silo_ref, kms):
            recovered = kms.decrypt_key(ciphertext, metadata, silo_ref)
        matches = bytes(recovered) == bytes(expected)
        del recovered
        if matches:
            return
        detail = (
            f'silo="{silo_ref}" kek="{metadata.kek_resource_name}" The new wrap unwrapped to different key '
            "material, so it was not saved and the old wrap was kept."
        )
        logger.error(
            "A rewrapped data key did not unwrap to the key it was made from, so the old wrap was kept. "
            'error_code=%s silo="%s" kek="%s"',
            KekUnavailableError.code,
            silo_ref,
            metadata.kek_resource_name,
        )
        raise KekUnavailableError(GENERIC_ENCRYPT_DECRYPT_UNAVAILABLE_MESSAGE, detail=detail)

    def _rewrap_rotation(self, engine, rotation, rewrap, created_kek, os_login_user) -> None:
        """Write a rotation's rewrapped incoming keyset, unless it changed underneath us.

        Runs inside the data key's transaction. The rotation row can be gone —
        abandoned since it was read — or hold different material than was
        unwrapped; either way the rewrap is stale and is dropped, which leaves
        the row exactly as whoever changed it meant it.
        """
        new_ciphertext, new_metadata = rewrap
        locked = DekRotation.objects.select_for_update().filter(pk=rotation.pk).first()
        if locked is None or bytes(locked.encrypted_keyset) != bytes(rotation.encrypted_keyset):
            self.stderr.write(
                self.style.WARNING(
                    f"Skipped the rotation's incoming key for {rotation.dek.silo_ref} [{rotation.dek.purpose}]: "
                    "it changed while this run was re-encrypting it."
                )
            )
            return
        locked.encrypted_keyset = new_ciphertext
        locked.kek = engine._kek_row(
            new_metadata, created_kek, trigger=lifecycle.TRIGGER_AUTOMATED, os_login_user=os_login_user
        )
        locked.kek_key_version = new_metadata.kek_key_version
        locked.save(update_fields=["encrypted_keyset", "kek", "kek_key_version"])

    def _report_failure(self, record, exc, action: str) -> None:
        """Report *exc* against *record* as one clean operator line.

        Reports the operator detail the funnel attached — which the generic
        ``str(exc)`` deliberately withholds from end users — plus the error-code
        slug, and never a traceback.
        """
        detail = getattr(exc, "detail", "") or str(exc)
        code = getattr(exc, "code", "")
        slug = f" [{code}]" if code else ""
        self.stderr.write(self.style.ERROR(f"Failed to {action} {record.silo_ref} [{record.purpose}]{slug}: {detail}"))

    def _check_owner_prefix(self, qs, kms, provisioner) -> None:
        """Refuse the run when ``KEK_TEMPLATE``'s owner prefix has moved.

        A name rollover must keep the literal text before ``{silo_uid}`` fixed:
        that prefix is how the package proves which keys are its own, so it
        decides what reconcile enumerates and what the deletion gates authorize.
        Move it and the generation being rolled off stops being owned — still
        present on the provider, still billable, no longer listed, and no longer
        deletable through the admin.

        Checked here because ``--provision`` is the last moment the change is free
        to abort: nothing has been created yet, so backing the template change out
        restores the previous state exactly. Once the new keys exist and the DEKs
        have moved, the old ones are stranded for good.

        The whole run is refused rather than the offending rows, which would
        provision some silos and strand the rest — a half-rolled deployment is
        worse than one that did not start. Uses the provisioner's own
        :meth:`owns_kek` so there is one ownership rule, shared with the gate that
        guards deletion.
        """
        prefix = kms.owner_prefix()
        if not prefix:
            # KEK_MAP-only and shared configurations derive no prefix, so
            # ownership cannot be established from a name and the hazard this
            # guard addresses cannot arise. Say so rather than refusing every run.
            self.stdout.write(
                self.style.WARNING(
                    "No KEK_TEMPLATE owner prefix is derivable from this configuration, so key "
                    "ownership could not be verified before provisioning."
                )
            )
            return

        # Only keys already on the target KMS: a key on the KMS being moved off
        # was never this prefix's to own, and leaving it unowned is the point.
        # A KEK_MAP key is left out: the template never produced it, so its name
        # says nothing about whether the prefix moved.
        mapped = kms.mapped_kek_names()
        unowned = sorted(
            name
            for name in qs.filter(kek__key_store=kms.kms_name)
            .values_list("kek__kek_resource_name", flat=True)
            .distinct()
            if name not in mapped and not provisioner.owns_kek(name, prefix)
        )
        if not unowned:
            return

        shown = ", ".join(unowned[:5])
        if len(unowned) > 5:
            shown += f", and {len(unowned) - 5} more"
        # "key encryption key(s)", not "key(s)": the success path counts data
        # encryption keys, and one KEK backs several of them, so a bare "3 keys"
        # here reads against a "Re-encrypted: 6" there.
        raise CommandError(
            f"Refusing to provision: {len(unowned)} key encryption key(s) currently in use do not "
            f"carry the configured owner prefix '{prefix}' ({shown}). KEK_TEMPLATE's owner prefix appears to "
            "have changed, which would leave those keys unowned — not listed by reconcile and not "
            "deletable from the admin. Put the generation marker after {silo_uid} instead "
            "(kms_{silo_uid}_v2, not kms_v2_{silo_uid}). Nothing has been created; reverting "
            "KEK_TEMPLATE restores the previous state."
        )
