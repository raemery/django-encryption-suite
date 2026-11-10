"""
Management command: setup_encryption_keys

Creates a DataEncryptionKey (and generates + wraps the DEK via KMS)
for each silo that does not yet have one.

Usage::

    python manage.py setup_encryption_keys
    python manage.py setup_encryption_keys --silo-model yourapp.Department

The command discovers silos via the configured silo adapter's ``iter_silos()``.
For adapters that cannot enumerate automatically (``supports_enumeration`` is
``False`` — composite *cell* models, or custom adapters that have not overridden
``iter_silos``), pass ``--silo-model app_label.ModelName`` to provision a
specific model's keysets.

This is the **provisioning** path — it only ever *creates* keysets, never
destroys, so an explicit ``--silo-model`` override is safe here. It is
deliberately distinct from the KEK reconcile/deletion path, which must use the
adapter's own ``iter_silos()`` with no override (a wrong model there could make
a live silo's KEK look orphaned and be deleted — unrecoverable).
"""

from __future__ import annotations

from django.core.management.base import BaseCommand, CommandError

from encryption_suite import blind_index
from encryption_suite._logging import get_logger
from encryption_suite.conf import DEFAULT_KEY_SET
from encryption_suite.silos import SiloEnumerationError

logger = get_logger(__name__)


def _key_set_suffix(key_set: str) -> str:
    """`` (key set restricted)`` for a non-default key set, and no text for the default."""
    return "" if key_set == DEFAULT_KEY_SET else f" (key set {key_set})"


class Command(BaseCommand):
    help = "Create encryption keysets for any silos that do not yet have one."

    def add_arguments(self, parser):
        parser.add_argument(
            "--silo-model",
            dest="silo_model",
            default=None,
            help="Dotted app_label.ModelName of the silo model to provision keysets "
            "for. Use it for adapters that cannot enumerate automatically (composite "
            "cell models, custom adapters); inferred from the adapter otherwise.",
        )
        parser.add_argument(
            "--key-set",
            dest="key_set",
            default=None,
            help="Provision only this key set's keys. Without it every key set a field declares is provisioned, "
            "the system key sets first.",
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Show what would be created without calling KMS.",
        )

    def handle(self, *args, **options):
        from encryption_suite import lifecycle
        from encryption_suite.models import DataEncryptionKey
        from encryption_suite.registry import get_engine, get_silo_adapter
        from encryption_suite.user_context import get_os_user, identity_tail

        dry_run: bool = options["dry_run"]
        os_login_user = get_os_user()
        logger.warning(
            "A privileged management command started; this line records that it ran, including a run "
            'that changes nothing. command=setup_encryption_keys dry_run=%s silo_model="%s" %s',
            dry_run,
            options["silo_model"] or "auto",
            identity_tail(os_login_user=os_login_user),
        )
        engine = get_engine()
        from encryption_suite.conf import SYSTEM_SILO_UID, adapter_path, is_system_key_set, key_set_names
        from encryption_suite.rotation_targets import key_sets_in_use, system_key_sets_needed
        from encryption_suite.silo_ref import SiloRef, silo_filter

        known = key_set_names()
        if options["key_set"] is not None and options["key_set"] not in known:
            raise CommandError(f"--key-set {options['key_set']!r} is not a declared key set: use one of {known}.")
        chosen = [options["key_set"]] if options["key_set"] else None

        # A maintenance command: the trigger names the mechanism, and the
        # operator who ran it is named in the OS login account.
        identity = {
            "trigger": lifecycle.TRIGGER_AUTOMATED,
            "reason": "",
            "os_login_user": os_login_user,
            "user": None,
            "user_ip": None,
        }

        # The system key sets' keys first, so every team key event after them can
        # encrypt its identity under them. All three at once, in one transaction
        # (see EncryptionEngine.ensure_system_keys).
        for key_set in system_key_sets_needed():
            if chosen is not None and key_set not in chosen:
                continue
            missing_system = not DataEncryptionKey.objects.filter(
                **silo_filter(SiloRef(key_set, SYSTEM_SILO_UID))
            ).exists()
            named = f"{SYSTEM_SILO_UID}{_key_set_suffix(key_set)}"
            if dry_run:
                if missing_system:
                    self.stdout.write(f"[dry-run] Would create the system keys: {named}")
            elif missing_system:
                engine.ensure_system_keys(key_set=key_set, **identity)
                self.stdout.write(self.style.SUCCESS(f"Created the system keys: {named}"))

        existing = set(DataEncryptionKey.objects.values_list("key_set", "silo_uid", "purpose"))
        field_created = file_created = index_created = skipped = 0
        declared = sorted(key_sets_in_use())
        silos_by_adapter: dict = {}

        for key_set in chosen if chosen is not None else declared:
            if is_system_key_set(key_set) or key_set not in declared:
                continue
            silo_adapter = get_silo_adapter(key_set)
            path = adapter_path(key_set)
            # Enumerated once per adapter, however many key sets are bound to it.
            if path not in silos_by_adapter:
                silos_by_adapter[path] = self._get_silos(silo_adapter, options["silo_model"])
            # Only where a field asks for one: a project declaring no blind-indexed
            # silo column has nothing to hash, and a key nothing uses is a KMS call
            # and a row to look after for no reason.
            wants_index = any(True for _model, _field in blind_index.silo_indexed_fields(key_set=key_set))

            for silo in silos_by_adapter[path]:
                uid = silo_adapter.get_silo_uid(silo)
                named = f"{uid}{_key_set_suffix(key_set)}"

                # Field keyset (AEAD)
                if (key_set, uid, DataEncryptionKey.PURPOSE_FIELD) in existing:
                    skipped += 1
                elif dry_run:
                    self.stdout.write(f"[dry-run] Would create field key for silo: {named}")
                    field_created += 1
                elif engine.generate_and_store_keyset(silo, key_set=key_set, **identity):
                    self.stdout.write(self.style.SUCCESS(f"Created field key for silo: {named}"))
                    field_created += 1
                else:
                    # Made by another process since this run listed what existed.
                    skipped += 1

                # File keyset (Streaming AEAD)
                if (key_set, uid, DataEncryptionKey.PURPOSE_FILE) in existing:
                    skipped += 1
                elif dry_run:
                    self.stdout.write(f"[dry-run] Would create file key for silo: {named}")
                    file_created += 1
                elif engine.generate_and_store_file_keyset(silo, key_set=key_set, **identity):
                    self.stdout.write(self.style.SUCCESS(f"Created file key for silo: {named}"))
                    file_created += 1
                else:
                    # Made by another process since this run listed what existed.
                    skipped += 1

                # Blind index key (keyed hash)
                if not wants_index:
                    pass
                elif (key_set, uid, DataEncryptionKey.PURPOSE_INDEX) in existing:
                    skipped += 1
                elif dry_run:
                    self.stdout.write(f"[dry-run] Would create blind index key for silo: {named}")
                    index_created += 1
                elif engine.generate_and_store_index_keyset(silo, key_set=key_set, **identity):
                    self.stdout.write(self.style.SUCCESS(f"Created blind index key for silo: {named}"))
                    index_created += 1
                else:
                    # Made by another process since this run listed what existed.
                    skipped += 1

        summary = (
            f"Done. Field keys created: {field_created}, "
            f"File keys created: {file_created}, "
            f"Blind index keys created: {index_created}, "
            f"Skipped (already exist): {skipped}."
        )
        if dry_run:
            summary = f"[dry-run] {summary}"
        self.stdout.write(summary)

        # The closing half of the opening line above, at the same level so one
        # filter catches both: an opening line with no closing line after it is a
        # run that never reached an ending. The ledger records each key that was
        # created, and nothing else about the run — not the silos already keyed,
        # not a dry run, and not a run that ended part way through a list of
        # silos with the rest still unkeyed.
        logger.warning(
            "A privileged management command finished. command=setup_encryption_keys dry_run=%s "
            'silo_model="%s" field_keys_created=%d file_keys_created=%d index_keys_created=%d '
            "skipped=%d %s",
            dry_run,
            options["silo_model"] or "auto",
            field_created,
            file_created,
            index_created,
            skipped,
            identity_tail(os_login_user=os_login_user),
        )

    def _get_silos(self, silo_adapter, model_dotted: str | None):
        """Return a list of silo objects to provision keysets for.

        Resolution order, provisioning-only (this path never destroys, so an
        explicit model override is safe — see the module docstring):

        1. An explicit ``--silo-model`` wins — provision that model's rows
           directly. This is the escape hatch for adapters that cannot
           enumerate (composite cell models, custom adapters).
        2. Otherwise the adapter enumerates itself via ``iter_silos()`` when it
           can (``supports_enumeration``).
        3. Otherwise fail with an actionable message pointing at ``--silo-model``.

        Any enumeration failure is surfaced as a clean ``CommandError`` carrying
        the operator detail, never a traceback.
        """
        from encryption_suite.silos import queryset_for_model_label

        if model_dotted:
            try:
                return list(queryset_for_model_label(model_dotted))
            except SiloEnumerationError as exc:
                raise CommandError(exc.detail or str(exc)) from exc

        if not silo_adapter.supports_enumeration:
            raise CommandError(
                f"The configured silo adapter '{type(silo_adapter).__name__}' cannot "
                "enumerate silos automatically. Pass --silo-model app_label.ModelName to "
                "provision a specific model's keysets (e.g. a composite cell model), or "
                "override iter_silos() on the adapter."
            )
        try:
            return list(silo_adapter.iter_silos())
        except SiloEnumerationError as exc:
            raise CommandError(exc.detail or str(exc)) from exc
