# Error codes

Every runtime error django-encryption-suite raises is a `EncryptionError` subclass
that carries a stable, language-neutral **code slug** on `exc.code`. The slug is
the durable, greppable identifier for an error condition; the human-readable
message may be reworded or translated, but the slug never changes.

This page is the **reference catalog**. To actually handle these errors in your
app, see the guide: [Handling encryption_suite errors](handling-errors.md).

This is the *decoupling pattern* — the same idea behind Django REST Framework's
error `code`, Django's `ValidationError(code=...)`, and django-allauth's
`error_messages` slugs: machines and operators key off the code; humans read the
prose.

## Code locations

| Surface | Code? | What you see |
| --- | --- | --- |
| **Operator logs** | yes | The line states what happened, then carries the slug as its first field, `error_code=<slug>`, e.g. `The KMS call to use this key failed. error_code=kek_unavailable operation=unwrap kek="…" silo="…" detail="…"`. Logs are English-pinned regardless of the request's active language, so the sentence, the slug, and the fields around it are stable to grep and alert on. |
| **`exc.code`** | yes | The slug, for any layer that wants to serialize it (e.g. a DRF API — see the [guide](handling-errors.md)). |
| **End-user message** (`str(exc)`) | no | A generic, translated, user-safe message only. Codes are **not** appended to the rendered string. |

The package stays presentation-neutral: it emits these structured signals and
leaves it to your app to decide how to surface them (see
[Handling encryption_suite errors](handling-errors.md)).

## The shape of a logged error

Every error line opens with a short English sentence saying what happened, then
runs `key=value` pairs beginning with `error_code`. Every value that can contain
whitespace is quoted, so a logfmt parser extracts each part as a field and the
operator prose in `detail` survives whole:

```
ERROR encryption_suite.engine Could not decrypt a field value. error_code=field_decryption_failed silo="acme" field="myapp.Patient.national_id" row="pk=12,user_id=<populated>" detail="decryption failed" hint="Likely causes: …"
```

The sentence is the package's own, written per site: it says what a reader would
otherwise have to come to this page to look up. It never repeats what the fields
already carry — no identifiers, counts, or provider text — so
`An encrypted file could not be read from storage.`, never
`Read failed for container acme-uploads`. It is English on every line, whatever
language the request activated, exactly like the fields beside it.

The recurring fields:

| Field | Carries |
| --- | --- |
| `error_code` | The slug, identical to `exc.code` on the exception raised from the same site. |
| `detail` | The particulars — a provider error, or the specific values the package observed. Quoted, so text with spaces stays one field. What *kind* of failure it was is the leading sentence's job, not this field's. |
| `hint` | What to check next. The same sentence on every occurrence of a given code. |
| `possible_cause` | Present only when the adapter can name a likely cause (e.g. a stored KEK whose region does not match the configured one). |
| `silo`, `field`, `row`, `kek`, `key`, `operation` | The scope the failure happened in, where the site knows it. |

## The codes

| Slug | Exception | Meaning |
| --- | --- | --- |
| `configuration_error` | `EncryptionConfigurationError` | The consuming project is misconfigured (missing option, bad dotted path, no silo in context). Operator detail is on `exc.detail`. |
| `missing_dek` | `MissingDekError` | No `DataEncryptionKey` row for this silo/purpose. |
| `kek_not_provisioned` | `KekNotProvisionedError` | The KMS reports the configured KEK does not exist. |
| `kek_pending_deletion` | `KekPendingDeletionError` | The KEK exists on the provider but sits inside the provider's own deletion window, so it cannot wrap or unwrap anything. A subclass of `KekNotProvisionedError` — every `except` for that type still catches it, and the user-facing message is identical — because the difference matters to an operator, not a user: the key is there and recoverable, so the remedy is to cancel the deletion at the provider (`aws kms cancel-key-deletion` and equivalents) rather than to create anything. Raised by a provisioner's `ensure_kek` on providers that expose the state; the engine records `deletion_requested` on the key's row so the state outlives the failed request. Operator detail is on `exc.detail`. |
| `kek_delete_failed` | `KekDeleteError` | Scheduling deletion of a provisioned KEK failed — a provider error, or the ownership guard refusing a key that does not carry this deployment's owner prefix. Raised by the deletion / provisioner `delete_kek`, outside the engine funnel. Operator detail is on `exc.detail`. |
| `silo_enumeration_unavailable` | `SiloEnumerationError` | The configured silo adapter cannot list every live silo — either a real failure (`django-tenants` not installed, or a `model_label` that is malformed or names an uninstalled app/model) or the capability-absent case (an adapter whose `supports_enumeration` is `False`). Raised by the adapter's `iter_silos()` on the keyset-setup / KMS-reconcile path, outside the engine funnel. Callers branch on `supports_enumeration` (and catch this type) to degrade to *detection-unavailable* — never "no silos exist". Operator detail is on `exc.detail`. |
| `kek_enumeration_unavailable` | `KekEnumerationError` | The KEK provisioner cannot list this deployment's KEKs on the KMS — a provider list/describe error, a provisioner whose `supports_enumeration` is `False`, or a request with no owner prefix (shared/`KEK_MAP` config, where ownership is unprovable). The KMS-side counterpart of `silo_enumeration_unavailable`; together they gate KEK reconcile. Raised by `provisioner.list_kek_names()`, outside the engine funnel. Callers branch on `supports_enumeration` (and catch this type) to degrade to *detection-unavailable* — the KMS side is reported for manual audit, never auto-orphaned. Operator detail is on `exc.detail`. |
| `kek_deletion_record_failed` | `KekDeletionRecordError` | Scheduling key deletion for a deleted silo failed (a database error, or a configuration error resolving the strategy) in `schedule_deletion`, invoked from the `post_delete` connector wired by `ENCRYPTION['SILO_AUTO_KEY_DELETION']`. Scheduling never destroys a key, so this is not itself dangerous — the consequence is an *un-scheduled* deletion, leaving the KEK recoverable via the KMS-side reconcile path. Raised outside the engine funnel; the `post_delete` receiver catches and swallows it so a failed recording never breaks the operator's delete. Operator detail is on `exc.detail`. |
| `kek_unavailable` | `KekUnavailableError` | A KMS wrap/unwrap failed operationally (auth, network, provider error). |
| `dek_deletion_scheduled` | `DekDeletionScheduledError` | The silo's DEK is inside its app-enforced soft-delete window (status `deletion_scheduled`): a deletion or operator scheduled it for deletion but the window has not expired, so the engine blocks both read and write while the key stays fully restorable. A pure DB-state check — no KMS call. Restoring the row clears it. |
| `dek_deleted` | `DekDeletedError` | The silo's DEK was deleted (status `deleted`, `encrypted_keyset` cleared — the crypto-shred): on **read** the value cannot be decrypted (raised before any unwrap). On **write** a tombstone is instead a revival signal — a reused silo UID transparently gets a fresh DEK when `KEY_AUTO_PROVISION` is on. |
| `dek_reencryption_in_progress` | `DekReencryptionInProgressError` | The silo's DEK is being rotated (status `reencrypting`): its data is split between the current key and the incoming one, so the engine blocks both read and write for that silo and purpose until `reencrypt_data` swaps or finishes a rollback. A pure DB-state check — no KMS call, and never negative-cached. It clears without anyone changing configuration, but only when the sweep finishes, which is an operator's pace rather than a duration the package can estimate — so DRF maps it to `409` and no client is told to wait it out. One that persists is a rotation that ended with rows outstanding; see [Rotating a data encryption key](key-rotation.md#rotating-a-data-encryption-key). |
| `key_identity_immutable` | `KeyIdentityImmutableError` | Code reassigned `key_store` or `kek_resource_name` on an existing `KeyEncryptionKey` row and called `save()`. Those columns name *which* KMS key the row stands for and are fixed at creation: changing them transfers one key's history, ledger events, and pending deletion state onto another, and the deletion would then aim an irreversible destruction at a key nobody chose. A programming error — create a row for the other key instead. Enforced at the ORM layer only; `QuerySet.update()`, `bulk_update()`, and raw SQL bypass it by design. |
| `kms_provider_mismatch` | `KmsProviderMismatchError` | The DEK's key encryption key records a KMS name that no `KMS_KEY_STORES` block configures, so nothing here can unwrap it. |
| `crypto_backend_mismatch` | `CryptoBackendMismatchError` | The DEK's recorded crypto backend cannot be built here (its dependency is missing), or its keyset does not parse under that backend. |
| `field_already_encrypted` | `FieldAlreadyEncryptedError` | A value that already carries the ciphertext prefix reached a write. Two paths raise it. The engine's `encrypt()` refuses a prefixed value, because its contract is that it receives plaintext and encrypting ciphertext again yields a value no read path can unwrap; only a direct `get_engine().encrypt()` call reaches it. A model field's `pre_save` refuses a value with the shape of stored ciphertext (`~^Dv`, a version number, a colon) that it did not read from the database — usually ciphertext copied from another row and submitted through a form or an API — unless it equals what the row already holds; writing it through would let ciphertext from another row decrypt under this one. A re-save of an instance the field has already encrypted passes its ciphertext through untouched, and the migration helper skips already-encrypted rows so a re-run is idempotent. **No file counterpart exists, and none can:** the `~^Dv1:` prefix is a field-value storage marker, while `encrypt_file` writes a raw streaming-AEAD encrypted stream carrying no marker, so the same mistake is undetectable there. Operator detail is on `exc.detail`. |
| `field_encryption_failed` | `EncryptedFieldEncryptionError` | Local AEAD encryption of a field value failed after the key was acquired. |
| `field_decryption_failed` | `EncryptedFieldDecryptionError` | A field value could not be authenticated/decrypted. |
| `file_encryption_failed` | `EncryptedFileEncryptionError` | Local Streaming AEAD encryption of a file failed after the key was acquired. |
| `file_decryption_failed` | `EncryptedFileDecryptionError` | A file could not be authenticated/decrypted. |
| `file_storage_error` | `EncryptedFileStorageError` | The underlying storage backend (S3/GCS/disk/…) failed an existence-check, write, or open. This is an infrastructure failure, **not** a cryptographic one. |

Slugs are **append-only from the first release**: once shipped, a slug is never
renamed or reused, because a consumer may have branched on it. Until then a slug
may still be corrected — `key_unavailable` became `kek_unavailable` so that
every slug names the key it is about, the way `kek_not_provisioned` and
`dek_deleted` do. A test (`tests/test_error_codes.py`) freezes the full set so
any addition, rename, or removal fails CI until both the code and this table are
updated.

## Emitting loggers

Every logger is named for the module that defines it, so a code is grepped by
`error_code=` and narrowed by namespace. An error raised through one of the
package's `log_and_raise_*` helpers is logged by **the module that raised it**,
not by the helper: the helper logs through the logger it is handed, so a code
raised from a provisioner carries that provisioner's namespace. (`stacklevel` in
those helpers is a separate matter — it governs `filename` / `lineno` /
`funcName`, not the name.)

| Slug | Emitting logger |
| --- | --- |
| `configuration_error` | `encryption_suite.engine` for the no-silo-in-context case; otherwise the module that raised it (an adapter, provisioner, credential strategy, or KEK strategy) |
| `crypto_backend_mismatch` | `encryption_suite.engine` |
| `dek_deleted` | `encryption_suite.engine` |
| `dek_deletion_scheduled` | `encryption_suite.engine` |
| `dek_reencryption_in_progress` | `encryption_suite.engine` |
| `field_already_encrypted` | `encryption_suite.engine` (`encrypt()`), `encryption_suite.fields` (a model save) |
| `field_decryption_failed` | `encryption_suite.engine`, `encryption_suite.fields` (AAD build, and a non-package error wrapped on read), `encryption_suite.safe_queries` (a stored value carrying no ciphertext prefix) |
| `field_encryption_failed` | `encryption_suite.engine` |
| `file_decryption_failed` | `encryption_suite.storage` (stream read), `encryption_suite.fields` (AAD build), `encryption_suite.safe_queries`, `encryption_suite.file_view_helpers` |
| `file_encryption_failed` | `encryption_suite.engine`, `encryption_suite.storage` (write) |
| `file_storage_error` | `encryption_suite.storage` |
| `kek_delete_failed` | the module that raised it (a KEK provisioner) |
| `kek_deletion_record_failed` | the module that raised it (`encryption_suite.deletion` or `encryption_suite.apps`) |
| `kek_enumeration_unavailable` | the module that raised it (a KEK provisioner) |
| `kek_not_provisioned` | `encryption_suite.engine` |
| `kek_pending_deletion` | `encryption_suite.engine` |
| `kek_unavailable` | `encryption_suite.engine` |
| `key_identity_immutable` | the module that raised it (`encryption_suite.models`) |
| `kms_provider_mismatch` | `encryption_suite.engine` |
| `missing_dek` | `encryption_suite.engine` |
| `silo_enumeration_unavailable` | the module that raised it (`encryption_suite.silos`, or a silo adapter) |

The namespace is the log record's, not a field in the message — the package
never writes a `logger=` field, because a second copy would go out of sync the
first time a module moves. A stock Django console handler carries **no**
formatter and prints the message alone, so ask for the name explicitly:

```python
LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "encryption_suite": {
            "format": '[{asctime}] {levelname} "{name}" {message}',
            "style": "{",
        },
    },
    "handlers": {
        "console": {"class": "logging.StreamHandler", "formatter": "encryption_suite"},
    },
    "loggers": {
        "encryption_suite": {"handlers": ["console"], "level": "INFO"},
    },
}
```

That gives an operator both filters at once — by namespace (`"name"`) and by
code (`error_code=`) — over the same line. See
[logging](logging.md) for routing the package's other lines.

## Deploy-time check IDs

The Django system-check IDs emitted at deploy by `manage.py check`
(`encryption_suite.E001`–`E046`, `W001`–`W006`, `W050`–`W061`) are a **different**
namespace from these runtime slugs — they belong to Django's checks framework
and surface at a different time (deploy, not request). See
[configuration](configuration.md) for those.

## Surfacing codes in your app

This page is the catalog. For *how* to handle these errors in code, see
[Handling encryption_suite errors](handling-errors.md). For returning them from
a Django REST Framework API and what a client of it can rely on, see
[Working with Django REST Framework](working-with-django-rest-framework.md). The slug is stable across
releases and languages, so clients can branch on `code` while showing the
translated `detail` to users.
