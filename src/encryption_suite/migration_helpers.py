"""
Migration helpers for adopting, removing, or changing encryption.

These functions are designed to be called from Django data migrations
(``RunPython`` operations).  They read and write raw column values on the
historical model from ``apps.get_model()``, bypassing the encrypted field
protocol entirely.

Bypassing it takes work on the read side, because a historical model is not
the plain shell it looks like.  ``migrate`` rebuilds it from the migration
files, and a migration file records a field by its import path — so an
encrypted column is rendered as a genuine encrypted field, with its
decrypting descriptor wired up exactly as at runtime, and ``getattr`` returns
plaintext rather than the column.  The rebuild carries each field's ``aad=``
as it stands in the migration state, which during a conversion is not the
binding the stored values were written under, and a decrypt needs a silo in
context besides.  So these helpers read every value they are about to act on
through :func:`~encryption_suite._internal.raw_cursor_fetch_many` instead,
take the binding from their ``aad_columns`` arguments, and only ever write
with ``.update()``.

Four helpers are provided:

* ``encrypt_field`` — encrypt a previously-plaintext column. A column in a system key set
  needs no silo arguments, and its blind index digest is written with it.
* ``decrypt_field`` — decrypt back to plaintext (when removing encryption).
* ``reencrypt_for_aad_change`` — decrypt under one AAD policy and
  re-encrypt under another.  Use this when adding, removing, or changing a
  field's ``aad=`` on a model that already has encrypted data.
* ``encrypt_file_field`` — encrypt the blobs a plain file column already
  points at, move the column onto opaque names, and fill the companion
  display-name column from the filenames the old names carried.

Usage in a data migration::

    from django.db import migrations

    def forwards(apps, schema_editor):
        from encryption_suite.migration_helpers import encrypt_field
        encrypt_field(
            apps, "myapp", "Patient", "national_id",
            silo_fk="team",       # FK field on Patient pointing to the silo
            silo_uid_field="pk",   # field on the silo model used in the UID
            silo_label="team",
            aad_columns=("pk",),         # match the field's aad=
        )

    def backwards(apps, schema_editor):
        from encryption_suite.migration_helpers import decrypt_field
        decrypt_field(
            apps, "myapp", "Patient", "national_id",
            silo_fk="team",
            silo_uid_field="pk",
            silo_label="team",
            aad_columns=("pk",),
        )

    class Migration(migrations.Migration):
        dependencies = [("myapp", "0043_encrypt_patient_fields")]
        operations = [migrations.RunPython(forwards, backwards)]
"""

from __future__ import annotations

import posixpath
import uuid

from ._internal import (
    encrypted_field_names,
    iter_rows,
    operator_error_text,
    raw_cursor_fetch_many,
)
from ._logging import get_logger
from .conf import DEFAULT_KEY_SET, SYSTEM_SILO_UID, is_system_key_set
from .exceptions import (
    GENERIC_DECRYPT_FAILED_USER_MESSAGE,
    GENERIC_ENCRYPT_FAILED_USER_MESSAGE,
    EncryptedFieldDecryptionError,
    EncryptedFieldEncryptionError,
    EncryptedFileEncryptionError,
    EncryptedFileStorageError,
    log_and_raise_configuration_error,
)
from .fields import _resolve_aad_columns, allow_plaintext_writes, build_aad
from .silo_ref import SiloRef

logger = get_logger(__name__)

#: How many failed row pks the closing error names before it summarizes. The
#: full list is in the log, one line per row; ``detail`` has to stay readable.
_FAILED_PKS_IN_DETAIL = 20


def _iter_rows_with_columns(Model, queryset, columns, chunk_size):
    """Yield ``(row, {name: column value})`` for every row of *queryset*.

    The row comes from the ORM, for its silo FK and its AAD columns — ordinary
    columns, which the field protocol does not touch. The values in the mapping
    come from the table itself, because these are the encrypted ones, and
    reading those off a historical model decrypts them (see the module
    docstring). The encrypted columns are deferred on the way in so their
    ciphertext is not fetched twice.
    """
    deferred = queryset.defer(*encrypted_field_names(Model))
    page: list = []
    for row in iter_rows(deferred, chunk_size=chunk_size):
        page.append(row)
        if len(page) >= chunk_size:
            yield from _attach_columns(Model, page, columns)
            page = []
    yield from _attach_columns(Model, page, columns)


def _attach_columns(Model, rows, columns):
    if not rows:
        return
    raw = raw_cursor_fetch_many(Model, [row.pk for row in rows], columns)
    for row in rows:
        values = raw.get(row.pk)
        if values is None:
            # Deleted between the page query and this one. Nothing to convert.
            continue
        yield row, dict(zip(columns, values, strict=True))


def _record_row_failure(failures, *, operation, label, pk, exc=None, detail=""):
    """Log one row's failure and keep walking.

    A row that will not convert used to end the run where it stood, which left
    the table half converted and named exactly one bad row per attempt — so
    finding the extent of the problem meant re-running the migration once per
    row. Collecting them costs nothing and tells the operator the whole story
    in one pass.

    Pass *detail* instead of *exc* where the step that failed reported a code
    rather than raising — the blob rewrite does, because it has already put the
    underlying error in the log itself.
    """
    logger.error(
        'Row could not be converted. operation=%s field="%s" row="pk=%s" detail="%s"',
        operation,
        label,
        pk,
        detail or operator_error_text(exc),
    )
    failures.append(pk)


def _fail_if_rows_were_left(failures, *, error_cls, message, operation, label, total):
    """Raise once at the end if any row was left unconverted.

    The walk finishes first, deliberately. Inside an atomic migration this
    rolls back exactly as an abort would have, but the operator gets every bad
    row out of the one run; outside one, the convertible rows stay converted
    and the migration still reports the failure rather than a success it did
    not have.
    """
    if not failures:
        return
    shown = ", ".join(str(pk) for pk in failures[:_FAILED_PKS_IN_DETAIL])
    if len(failures) > _FAILED_PKS_IN_DETAIL:
        shown += f", and {len(failures) - _FAILED_PKS_IN_DETAIL} more"
    logger.error(
        'Finished with rows left unconverted. operation=%s field="%s" failed=%d rows=%d',
        operation,
        label,
        len(failures),
        total,
    )
    raise error_cls(
        message,
        detail=(
            f"{operation} left {len(failures)} of {total} rows unconverted for {label}. "
            f"Rows: {shown}. Each one is logged with its own reason."
        ),
    )


def _resolve_aad_columns_historical(Model, aad_columns):
    """Resolve ``aad_columns`` against a historical model, by the runtime's rules.

    ``"pk"`` becomes the historical pk attname; field names become attnames.
    """
    return _resolve_aad_columns(Model, aad_columns, "aad_columns")


def _build_aad(Model, field_name: str, aad_column_attnames: tuple[str, ...], row) -> bytes:
    """Build the associated data the runtime field protocol produces for *field_name* on *row*.

    The same encoder and normalization as the runtime (:func:`~encryption_suite.fields.build_aad`),
    so a value written here reads back through the field. Empty
    ``aad_column_attnames`` produces ``b""`` (no AAD binding).
    """
    attname = Model._meta.get_field(field_name).attname
    return build_aad(Model, attname, aad_column_attnames, row)


def _resolve_silo_uid(
    row,
    silo_fk: str,
    silo_uid_field: str,
    silo_label: str,
    key_set: str = DEFAULT_KEY_SET,
) -> SiloRef:
    """Derive the silo reference for a model row, matching the adapter convention.

    ``<label>-<value>``, which is what every adapter the package ships writes —
    :class:`~encryption_suite.adapters.silos.generic.GenericModelSiloAdapter` and
    the Pegasus and django-tenants adapters alike. A UID built any other way
    names a silo that has no key, so the run fails on its first row.
    """
    silo = getattr(row, silo_fk)
    if silo is None:
        raise ValueError(
            f"Row pk={row.pk} has no silo ('{silo_fk}' is None). Cannot encrypt or decrypt without a silo."
        )
    uid_value = getattr(silo, silo_uid_field)
    return SiloRef(key_set, f"{silo_label}-{uid_value}")


def _silo_of_column(Model, field_name: str, silo_fk, silo_label, operation: str) -> bool:
    """Return whether the historical column is a system column; check a silo column has its silo arguments.

    A system column is encrypted under the system silo on every row, so it needs
    no foreign key to find one; a silo column needs both.
    """

    system = is_system_key_set(getattr(Model._meta.get_field(field_name), "key_set", DEFAULT_KEY_SET))
    if not system and (not silo_fk or not silo_label):
        raise TypeError(
            f"{operation} needs silo_fk and silo_label for {Model._meta.label}.{field_name}, a silo encrypted "
            f"column: each row is encrypted under its own silo's key. A column in a system key set needs neither."
        )
    return system


def encrypt_field(
    apps,
    app_label: str,
    model_name: str,
    field_name: str,
    *,
    silo_fk: str | None = None,
    silo_uid_field: str = "pk",
    silo_label: str | None = None,
    aad_columns: tuple[str, ...] = (),
    batch_size: int = 500,
) -> int:
    """
    Encrypt all plaintext values in an existing database column.

    Reads the raw column value via the historical model (no field protocol),
    encrypts it using the AEAD primitive for the row's silo, and writes
    the ciphertext back.  Rows that are already encrypted (start with the
    ciphertext prefix) are skipped.

    No silo context (middleware, thread-local) is needed — the
    silo is resolved from each row's FK.

    :param apps: The ``apps`` registry passed to a ``RunPython`` callback.
    :param app_label: Django app label (e.g. ``"myapp"``).
    :param model_name: Model class name (e.g. ``"Patient"``).
    :param field_name: Name of the field to encrypt (e.g. ``"national_id"``).
    :param silo_fk: Name of the FK field on the model that points to the
        silo (e.g. ``"team"``). Not needed for a column in a system key set, which
        is encrypted under the system silo on every row.
    :param silo_uid_field: Field on the silo model used in the UID
        (default ``"pk"``).
    :param silo_label: The label the silo adapter puts before the id in a silo uid
        (e.g. ``"team"``).  Must match what your adapter's
        ``get_silo_uid()`` produces.
    :param aad_columns: Tuple matching the field's ``aad=``. Pass the same
        value here that the field declares so that
        ciphertexts written by this migration decrypt correctly at runtime.
        Empty tuple = no AAD binding.
    :param batch_size: Number of rows to process before logging progress.
    :returns: Number of rows encrypted.
    :raises EncryptionError: If any row could not be converted. Every such
        row is logged with its own reason first and the walk finishes, so
        one run reports all of them rather than stopping at the first.
    """
    from .engine import is_silo_value, wrap_ciphertext
    from .registry import get_engine

    Model = apps.get_model(app_label, model_name)
    engine = get_engine()
    system = _silo_of_column(Model, field_name, silo_fk, silo_label, "encrypt_field")
    field = Model._meta.get_field(field_name)
    key_set = getattr(field, "key_set", DEFAULT_KEY_SET)
    aad_attnames = _resolve_aad_columns_historical(Model, aad_columns)
    field_label = f"{app_label}.{model_name}.{field_name}"
    if system:
        # Every row is the system silo's, and its keys may not exist yet.
        engine.ensure_system_keys(key_set=key_set)

    # Local per-migration primitive cache. Bypasses engine._aead_cache so
    # long-lived migrate workers don't retain primitives for every silo
    # touched by the migration. Dies with this function's scope.
    primitive_cache: dict[SiloRef, object] = {}

    encrypted_count = 0
    failures: list = []
    total = Model.objects.count()
    logger.info(
        'Encrypting existing rows. operation=encrypt_field rows=%d field="%s"',
        total,
        field_label,
    )

    for row, columns in _iter_rows_with_columns(
        Model,
        Model.objects.all() if system else Model.objects.select_related(silo_fk),
        [field_name],
        batch_size,
    ):
        value = columns[field_name]
        if value is None:
            continue
        # Convert to string — matches what get_prep_value does.
        str_value = str(value)
        if is_silo_value(str_value):
            # Already encrypted — skip. This is what makes a re-run idempotent,
            # and it can only be judged on the column: through the field it
            # would read as plaintext and be encrypted a second time.
            continue

        try:
            silo_uid = (
                SiloRef(field.key_set, SYSTEM_SILO_UID)
                if system
                else _resolve_silo_uid(row, silo_fk, silo_uid_field, silo_label, field.key_set)
            )
        except Exception as exc:
            _record_row_failure(failures, operation="encrypt_field", label=field_label, pk=row.pk, exc=exc)
            continue

        # Acquiring the key is not a property of this row: if it fails, it fails
        # for every row in the silo, and carrying on would just log the same
        # outage once per row. Let it end the run.
        aead_primitive = primitive_cache.get(silo_uid)
        if aead_primitive is None:
            aead_primitive = engine._decrypt_to_aead(silo_uid)
            primitive_cache[silo_uid] = aead_primitive

        try:
            aad = _build_aad(Model, field_name, aad_attnames, row)
            ciphertext_bytes = aead_primitive.encrypt(str_value.encode("utf-8"), aad)
            # A system column's digest is written with its value. It is what
            # sign-in looks a user up by, and the migration that converts it runs
            # after the column is declared with its blind index, so the field
            # can compute it. A silo column's adoption runs before that, and its
            # digests are built afterwards (reencrypt_data --check reports them).
            digest = None
            if system and getattr(field, "blind_index", False):
                digest = field._compute_index_digest(field._normalized(str_value))
        except Exception as exc:
            _record_row_failure(failures, operation="encrypt_field", label=field_label, pk=row.pk, exc=exc)
            continue
        ciphertext = wrap_ciphertext(ciphertext_bytes)

        # Write the ciphertext directly, bypassing the field protocol.
        # Use .update() on a filtered queryset to avoid triggering save signals
        # or re-encrypting via get_prep_value.
        if digest is not None:
            Model.objects.filter(pk=row.pk).update(**{field_name: ciphertext}, **field.index_update_kwargs(digest))
            field.record_index_digest(row.pk, digest)
        else:
            Model.objects.filter(pk=row.pk).update(**{field_name: ciphertext})
        encrypted_count += 1

        if encrypted_count % batch_size == 0:
            logger.info(
                'Encrypting existing rows. operation=encrypt_field encrypted=%d rows=%d field="%s"',
                encrypted_count,
                total,
                field_label,
            )

    logger.info(
        'Finished encrypting existing rows. operation=encrypt_field encrypted=%d not_encrypted=%d rows=%d field="%s"',
        encrypted_count,
        total - encrypted_count,
        total,
        field_label,
    )
    _fail_if_rows_were_left(
        failures,
        error_cls=EncryptedFieldEncryptionError,
        message=GENERIC_ENCRYPT_FAILED_USER_MESSAGE,
        operation="encrypt_field",
        label=field_label,
        total=total,
    )
    return encrypted_count


def decrypt_field(
    apps,
    app_label: str,
    model_name: str,
    field_name: str,
    *,
    silo_fk: str | None = None,
    silo_uid_field: str = "pk",
    silo_label: str | None = None,
    aad_columns: tuple[str, ...] = (),
    batch_size: int = 500,
) -> int:
    """
    Decrypt all encrypted values in a database column back to plaintext.

    Reads the raw column value via the historical model (no field protocol),
    decrypts it using the AEAD primitive for the row's silo, and writes
    the plaintext back.  Rows that are not encrypted (do not start with the
    ciphertext prefix) are skipped.

    Use this when removing encryption from a field.  The key encryption keys and
    ``DataEncryptionKey`` records must still exist when this runs —
    do not delete them until after this migration has completed successfully.

    No silo context (middleware, thread-local) is needed — the
    silo is resolved from each row's FK.

    :param apps: The ``apps`` registry passed to a ``RunPython`` callback.
    :param app_label: Django app label (e.g. ``"myapp"``).
    :param model_name: Model class name (e.g. ``"Patient"``).
    :param field_name: Name of the field to decrypt (e.g. ``"national_id"``).
    :param silo_fk: Name of the FK field on the model that points to the
        silo (e.g. ``"team"``). Not needed for a column in a system key set, which
        is encrypted under the system silo on every row.
    :param silo_uid_field: Field on the silo model used in the UID
        (default ``"pk"``).
    :param silo_label: The label the silo adapter puts before the id in a silo uid
        (e.g. ``"team"``).  Must match what your adapter's
        ``get_silo_uid()`` produces.
    :param aad_columns: Tuple matching the field's ``aad=`` at the time the
        data was encrypted. Empty tuple if no AAD
        binding was configured.
    :param batch_size: Number of rows to process before logging progress.
    :returns: Number of rows decrypted.
    :raises EncryptionError: If any row could not be converted. Every such
        row is logged with its own reason first and the walk finishes, so
        one run reports all of them rather than stopping at the first.
    """
    from .engine import is_silo_value, unwrap_ciphertext
    from .registry import get_engine

    Model = apps.get_model(app_label, model_name)
    engine = get_engine()
    system = _silo_of_column(Model, field_name, silo_fk, silo_label, "decrypt_field")
    field = Model._meta.get_field(field_name)
    aad_attnames = _resolve_aad_columns_historical(Model, aad_columns)
    field_label = f"{app_label}.{model_name}.{field_name}"

    # See encrypt_field for rationale — keep primitives off the shared cache.
    primitive_cache: dict[SiloRef, object] = {}

    decrypted_count = 0
    failures: list = []
    total = Model.objects.count()
    logger.info(
        'Decrypting existing rows. operation=decrypt_field rows=%d field="%s"',
        total,
        field_label,
    )

    for row, columns in _iter_rows_with_columns(
        Model,
        Model.objects.all() if system else Model.objects.select_related(silo_fk),
        [field_name],
        batch_size,
    ):
        value = columns[field_name]
        if value is None:
            continue
        str_value = str(value)
        if not is_silo_value(str_value):
            # Not encrypted — skip.
            continue

        try:
            silo_uid = (
                SiloRef(field.key_set, SYSTEM_SILO_UID)
                if system
                else _resolve_silo_uid(row, silo_fk, silo_uid_field, silo_label, field.key_set)
            )
        except Exception as exc:
            _record_row_failure(failures, operation="decrypt_field", label=field_label, pk=row.pk, exc=exc)
            continue

        # Run-scoped, like encrypt_field: a key that cannot be acquired is not
        # this row's problem and will not be the next row's either.
        aead_primitive = primitive_cache.get(silo_uid)
        if aead_primitive is None:
            aead_primitive = engine._decrypt_to_aead(silo_uid)
            primitive_cache[silo_uid] = aead_primitive

        try:
            aad = _build_aad(Model, field_name, aad_attnames, row)
            ciphertext_bytes = unwrap_ciphertext(str_value)
            plaintext_bytes = aead_primitive.decrypt(ciphertext_bytes, aad)
            plaintext = plaintext_bytes.decode("utf-8")
        except Exception as exc:
            _record_row_failure(failures, operation="decrypt_field", label=field_label, pk=row.pk, exc=exc)
            continue

        # The one write that means to store plaintext: the column is leaving
        # encryption, which is what this helper is for.
        with allow_plaintext_writes():
            Model.objects.filter(pk=row.pk).update(**{field_name: plaintext})
        decrypted_count += 1

        if decrypted_count % batch_size == 0:
            logger.info(
                'Decrypting existing rows. operation=decrypt_field decrypted=%d rows=%d field="%s"',
                decrypted_count,
                total,
                field_label,
            )

    logger.info(
        'Finished decrypting existing rows. operation=decrypt_field decrypted=%d not_decrypted=%d rows=%d field="%s"',
        decrypted_count,
        total - decrypted_count,
        total,
        field_label,
    )
    _fail_if_rows_were_left(
        failures,
        error_cls=EncryptedFieldDecryptionError,
        message=GENERIC_DECRYPT_FAILED_USER_MESSAGE,
        operation="decrypt_field",
        label=field_label,
        total=total,
    )
    return decrypted_count


def reencrypt_for_aad_change(
    apps,
    app_label: str,
    model_name: str,
    field_names: tuple[str, ...],
    *,
    silo_fk: str | None = None,
    silo_uid_field: str = "pk",
    silo_label: str | None = None,
    old_aad_columns: tuple[str, ...] = (),
    new_aad_columns: tuple[str, ...] = (),
    batch_size: int = 500,
) -> int:
    """
    Re-encrypt encrypted columns from one AAD policy to another.

    Use this helper when adding, removing, or changing a field's ``aad=`` on a
    model that already has encrypted data. Each row is read, every listed
    encrypted field is decrypted under the old AAD policy, then re-encrypted
    under the new AAD policy, then the row is written back. One call covers
    fields that share one binding; call it once per binding when fields on the
    model change differently.

    Operationally, this is a data migration: plan downtime (or read-only
    mode for the affected models) while it runs. A partially-completed
    run leaves the table in a half-migrated state where some rows decrypt
    under the old policy and some under the new — neither side will work
    until the migration completes.

    Changing ``aad=`` generates an ``AlterField`` migration; run this helper
    in a data migration right after it. The deployed field's ``aad=`` must
    match the **new** policy by the time application traffic resumes; if
    the code change is live before this helper has run, every read fails.

    :param field_names: Tuple of encrypted field names on the model that
        share the AAD policy. Pass every encrypted field whose policy is
        changing — they re-encrypt together within a single row read so
        the row sees a consistent policy state.
    :param silo_fk: FK field on the model pointing to the silo. Required
        only when a listed field is a silo field; a field in a system key set
        is encrypted under the system silo on every row and needs neither
        this nor *silo_label*.
    :param silo_label: The silo label the adapter uses in its UIDs. Required
        with *silo_fk*.
    :param old_aad_columns: The AAD policy that was in effect when the data
        was originally encrypted. Empty tuple means "no AAD".
    :param new_aad_columns: The AAD policy to write under. Empty tuple means
        "no AAD".
    :returns: Number of rows visited (whether or not any field on the row
        actually changed).
    :raises EncryptionError: If any row could not be converted. Every such
        row is logged with its own reason first and the walk finishes, so
        one run reports all of them rather than stopping at the first.
    """
    from .engine import is_silo_value, unwrap_ciphertext, wrap_ciphertext
    from .registry import get_engine

    Model = apps.get_model(app_label, model_name)
    engine = get_engine()
    old_attnames = _resolve_aad_columns_historical(Model, old_aad_columns)
    new_attnames = _resolve_aad_columns_historical(Model, new_aad_columns)
    label = f"{app_label}.{model_name}"
    # Whether each field is a system column: those are under the system silo on
    # every row; the rest need the row's silo, and so silo_fk and silo_label.
    system_field = {
        name: _silo_of_column(Model, name, silo_fk, silo_label, "reencrypt_for_aad_change") for name in field_names
    }
    needs_row_silo = not all(system_field.values())

    primitive_cache: dict[tuple[SiloRef, str], object] = {}

    visited = 0
    failures: list = []
    total = Model.objects.count()
    logger.info(
        "Re-encrypting existing rows for a change of AAD columns. "
        'operation=reencrypt_for_aad_change rows=%d model="%s" fields=%s old_aad_columns=%s '
        "new_aad_columns=%s",
        total,
        label,
        ",".join(field_names) or "-",
        ",".join(old_aad_columns) or "-",
        ",".join(new_aad_columns) or "-",
    )

    queryset = Model.objects.select_related(silo_fk) if silo_fk else Model.objects.all()
    for row, columns in _iter_rows_with_columns(
        Model,
        queryset,
        list(field_names),
        batch_size,
    ):
        row_silo_uid = None
        if needs_row_silo:
            try:
                row_silo_uid = _resolve_silo_uid(row, silo_fk, silo_uid_field, silo_label).uid
            except Exception as exc:
                _record_row_failure(failures, operation="reencrypt_for_aad_change", label=label, pk=row.pk, exc=exc)
                continue

        updates: dict[str, str] = {}
        failed = False
        for field_name in field_names:
            value = columns[field_name]
            if value is None:
                continue
            str_value = str(value)
            if not is_silo_value(str_value):
                # Already plaintext (e.g. partial prior run, or never
                # encrypted) — skip rather than encrypt under new AAD,
                # because we can't tell whether the value is "still
                # plaintext" or "ciphertext under a third unknown AAD".
                continue
            # The key of the field's own set: fields of one model may sit in different sets.
            key_set = getattr(Model._meta.get_field(field_name), "key_set", DEFAULT_KEY_SET)
            field_ref = SiloRef(key_set, SYSTEM_SILO_UID if system_field[field_name] else row_silo_uid)
            aead_primitive = primitive_cache.get(field_ref)
            if aead_primitive is None:
                aead_primitive = engine._decrypt_to_aead(field_ref)
                primitive_cache[field_ref] = aead_primitive
            try:
                old_aad = _build_aad(Model, field_name, old_attnames, row)
                new_aad = _build_aad(Model, field_name, new_attnames, row)
                ciphertext_bytes = unwrap_ciphertext(str_value)
                plaintext_bytes = aead_primitive.decrypt(ciphertext_bytes, old_aad)
                new_ciphertext_bytes = aead_primitive.encrypt(plaintext_bytes, new_aad)
            except Exception as exc:
                # One field's failure discards the whole row: the fields listed
                # here change policy together, and a row left holding some of
                # each is the half-migrated state this helper exists to avoid.
                _record_row_failure(
                    failures,
                    operation="reencrypt_for_aad_change",
                    label=f"{label}.{field_name}",
                    pk=row.pk,
                    exc=exc,
                )
                failed = True
                break
            updates[field_name] = wrap_ciphertext(new_ciphertext_bytes)

        if failed:
            continue
        if updates:
            Model.objects.filter(pk=row.pk).update(**updates)
        visited += 1

        if visited % batch_size == 0:
            logger.info(
                "Re-encrypting existing rows for a change of AAD columns. "
                'operation=reencrypt_for_aad_change processed=%d rows=%d model="%s"',
                visited,
                total,
                label,
            )

    logger.info(
        "Finished re-encrypting existing rows for a change of AAD columns. "
        'operation=reencrypt_for_aad_change processed=%d not_processed=%d rows=%d model="%s"',
        visited,
        total - visited,
        total,
        label,
    )
    _fail_if_rows_were_left(
        failures,
        error_cls=EncryptedFieldDecryptionError,
        message=GENERIC_DECRYPT_FAILED_USER_MESSAGE,
        operation="reencrypt_for_aad_change",
        label=label,
        total=total,
    )
    return visited


def _delete_converted_blob(storage, name: str, *, label: str, pk, plaintext: bool) -> bool:
    """Delete a blob the conversion no longer needs. ``False`` if the backend refused.

    Two kinds of leftover reach this, and they are not equally serious. A
    ciphertext blob a failed row wrote is stray — it costs storage and nothing
    else, so a warning and a rerun settle it. The *plaintext* original of a row
    that did convert is the file the operator just chose to encrypt, still
    readable where it always was: the conversion succeeded and must not be
    rolled back for it, but nothing else will remove it either, so it is logged
    at ERROR and named.
    """
    if not name:
        return True
    try:
        storage.delete(name)
    except Exception as exc:
        if plaintext:
            logger.error(
                "A file was encrypted but its plaintext original could not be deleted, so the plaintext is "
                'still readable in storage; delete it by hand. operation=encrypt_file_field field="%s" '
                'row="pk=%s" path="%s" detail="%s"',
                label,
                pk,
                name,
                operator_error_text(exc),
            )
        else:
            logger.warning(
                "A blob written for a row that then failed to convert could not be deleted; a rerun writes "
                'another, so delete this one by hand. operation=encrypt_file_field field="%s" row="pk=%s" '
                'path="%s" detail="%s"',
                label,
                pk,
                name,
                operator_error_text(exc),
            )
        return False
    return True


def encrypt_file_field(
    apps,
    app_label: str,
    model_name: str,
    field_name: str,
    *,
    silo_fk: str,
    silo_uid_field: str = "pk",
    silo_label: str,
    aad_columns: tuple[str, ...] = (),
    batch_size: int = 500,
) -> int:
    """
    Encrypt the files an existing plaintext file column already points at.

    The field counterpart rewrites a column in place; a file column cannot be
    rewritten in place, because the blob and the name that reaches it are two
    different things. So for each row this reads the blob the column names,
    encrypts it under the silo's file key, writes it under a fresh opaque name,
    moves the column onto that name, and deletes the original object. The
    filename the original name carried is what the column stops saying out
    loud, so it is encrypted into the companion display-name column in the same
    write — that column is where an encrypted file field keeps the name a
    person sees, and a row converted without it has lost the filename for good.

    Run this **after** the migration operation that makes the column an
    :class:`~encryption_suite.fields.EncryptedFileField`, and before the
    application deploys against it. The helper reads the field's storage and
    its ``display_name_field`` off the historical model, so both must be there;
    a plain ``FileField`` has neither and the run refuses.

    A blob is written, read back, and verified before the column moves, and the
    original is deleted only after. A run killed anywhere leaves either a row
    that still points at its plaintext original, or a converted row — never a
    row pointing at a blob nothing has checked.

    :param apps: The ``apps`` registry passed to a ``RunPython`` callback.
    :param app_label: Django app label (e.g. ``"myapp"``).
    :param model_name: Model class name (e.g. ``"Document"``).
    :param field_name: Name of the file field to encrypt (e.g. ``"upload"``).
    :param silo_fk: Name of the FK field on the model that points to the
        silo (e.g. ``"team"``).
    :param silo_uid_field: Field on the silo model used in the UID
        (default ``"pk"``).
    :param silo_label: The label the silo adapter puts before the id in a silo uid
        (e.g. ``"team"``).
    :param aad_columns: Tuple matching the ``aad=`` the file field and its
        display-name field both declare. The blob and the display name both
        bind to it, exactly as an upload through the field protocol would.
    :param batch_size: Number of rows to process before logging progress.
    :returns: Number of rows converted.
    :raises EncryptionError: If any row could not be converted. Every such
        row is logged with its own reason first and the walk finishes, so
        one run reports all of them rather than stopping at the first.
    """
    from .engine import is_silo_value, wrap_ciphertext
    from .registry import get_engine
    from .rotation_items import write_encrypted_blob

    Model = apps.get_model(app_label, model_name)
    field = Model._meta.get_field(field_name)
    storage = getattr(field, "storage", None)
    display_name_field = getattr(field, "display_name_field", "")
    field_label = f"{app_label}.{model_name}.{field_name}"
    if not display_name_field or not hasattr(storage, "_save_raw"):
        log_and_raise_configuration_error(
            logger,
            f"encrypt_file_field was called for {field_label}, which is not an encrypted file field on the "
            f"historical model: it has no display_name_field, or its storage does not encrypt. Run this "
            f"helper after the operation that changes the column to EncryptedFileField.",
        )
    if is_system_key_set(getattr(field, "key_set", DEFAULT_KEY_SET)):
        log_and_raise_configuration_error(
            logger,
            f"encrypt_file_field was called for {field_label}, a system file field. This helper "
            f"encrypts each blob under its row's silo file key, which that field does not read with.",
        )

    engine = get_engine()
    key_set = getattr(field, "key_set", DEFAULT_KEY_SET)
    aad_attnames = _resolve_aad_columns_historical(Model, aad_columns)

    # Run-scoped, like the field helpers: one keyset per silo, off the shared cache.
    file_primitives: dict[str, object] = {}
    field_primitives: dict[str, object] = {}

    converted_count = 0
    failures: list = []
    total = Model.objects.count()
    logger.info(
        'Encrypting existing files. operation=encrypt_file_field rows=%d field="%s"',
        total,
        field_label,
    )

    for row, columns in _iter_rows_with_columns(
        Model,
        Model.objects.select_related(silo_fk),
        [field_name, display_name_field],
        batch_size,
    ):
        current = columns[field_name] or ""
        if not current:
            continue
        display = str(columns[display_name_field] or "")
        if is_silo_value(display):
            # Already converted, and the display name is the only thing that can
            # say so: an opaque path is not proof — the original name was the
            # project's to choose and may look like anything. The name and the
            # pointer move in one write, so a row holding one holds both.
            continue

        try:
            silo_uid = _resolve_silo_uid(row, silo_fk, silo_uid_field, silo_label, key_set)
        except Exception as exc:
            _record_row_failure(failures, operation="encrypt_file_field", label=field_label, pk=row.pk, exc=exc)
            continue

        # Both keysets, for the same reason encrypt_field takes one: a key that
        # cannot be acquired is not this row's problem and will not be the next
        # row's either, so let it end the run.
        file_primitive = file_primitives.get(silo_uid)
        if file_primitive is None:
            file_primitive = engine._decrypt_to_streaming_aead(silo_uid)
            file_primitives[silo_uid] = file_primitive
        field_primitive = field_primitives.get(silo_uid)
        if field_primitive is None:
            field_primitive = engine._decrypt_to_aead(silo_uid)
            field_primitives[silo_uid] = field_primitive

        try:
            file_aad = _build_aad(Model, field_name, aad_attnames, row)
            name_aad = _build_aad(Model, display_name_field, aad_attnames, row)
            # A display name already on the row is respected, exactly as
            # EncryptedFileField.pre_save respects one on an upload; otherwise
            # the old path's own filename is the name the file was known by.
            display = display or posixpath.basename(current)
            name_bytes = field_primitive.encrypt(display.encode("utf-8"), name_aad)
            display_ciphertext = wrap_ciphertext(name_bytes)
            # Whatever a fresh upload would be named — the field's own upload_to
            # decides, so a project that lays its storage out per tenant keeps
            # that layout instead of having this helper invent one.
            fresh = field.generate_filename(row, f"{uuid.uuid4().hex}.bin")
        except Exception as exc:
            _record_row_failure(failures, operation="encrypt_file_field", label=field_label, pk=row.pk, exc=exc)
            continue

        stored, code = write_encrypted_blob(
            storage,
            fresh,
            lambda: storage._open_raw(current, "rb"),  # noqa: B023 — consumed before the next iteration
            file_primitive,
            file_aad,
            # The source here is a plaintext object in storage, so a failed read
            # is a storage failure rather than a decryption one.
            read_code=EncryptedFileStorageError.code,
        )
        if code:
            _delete_converted_blob(storage, stored or fresh, label=field_label, pk=row.pk, plaintext=False)
            _record_row_failure(
                failures,
                operation="encrypt_file_field",
                label=field_label,
                pk=row.pk,
                detail=f"The file could not be encrypted and stored. error_code={code}",
            )
            continue

        # The pointer is part of the filter: a row whose file changed under the
        # run is not this run's to convert, and the blob just written is not the
        # one it should carry.
        updated = Model.objects.filter(pk=row.pk, **{field.attname: current}).update(
            **{field.attname: stored, display_name_field: display_ciphertext}
        )
        if not updated:
            _delete_converted_blob(storage, stored, label=field_label, pk=row.pk, plaintext=False)
            _record_row_failure(
                failures,
                operation="encrypt_file_field",
                label=field_label,
                pk=row.pk,
                detail="The row's file changed while it was being converted, so the column was left alone.",
            )
            continue

        _delete_converted_blob(storage, current, label=field_label, pk=row.pk, plaintext=True)
        converted_count += 1

        if converted_count % batch_size == 0:
            logger.info(
                'Encrypting existing files. operation=encrypt_file_field encrypted=%d rows=%d field="%s"',
                converted_count,
                total,
                field_label,
            )

    logger.info(
        "Finished encrypting existing files. operation=encrypt_file_field encrypted=%d not_encrypted=%d "
        'rows=%d field="%s"',
        converted_count,
        total - converted_count,
        total,
        field_label,
    )
    _fail_if_rows_were_left(
        failures,
        error_cls=EncryptedFileEncryptionError,
        message=GENERIC_ENCRYPT_FAILED_USER_MESSAGE,
        operation="encrypt_file_field",
        label=field_label,
        total=total,
    )
    return converted_count
