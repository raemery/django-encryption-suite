# Managing encrypted files

This page covers operating and tuning `EncryptedFileField` once it is in place: which
path prefix holds the files, how they are named, lifecycle cleanup, forms, the admin,
configuration settings, and upload memory and disk use. For the initial setup see
[Getting started](getting-started-storage.md) and
[Storage backends](storage-backends.md).

## Customizing the storage path prefix

By default, every `EncryptedFileField` writes to `encryption_suite/<uuid>.bin`,
and every `EncryptedFileField(key_set="system")` to `encryption_suite_system/<uuid>.bin`,
under whatever backend the `encrypted` alias points at. Each folder is that
`key`'s default `upload_to` — not the bucket name, not hardcoded. The two
are siblings rather than one inside the other, so a storage rule can select
either kind of file on its own. Override either like a stock `FileField`, by
passing `upload_to`:

```python
class Document(models.Model):
    # Static prefix — stored as "patient-scans/<uuid>.bin".
    scan = EncryptedFileField(
        display_name_field="scan_display_name",
        upload_to="patient-scans/",
    )
    scan_display_name = EncryptedCharField(max_length=255, null=True, blank=True)
```

A string names the folder only: the name under it is always a fresh
`<uuid>.bin`, never the upload's own filename. As on a stock `FileField`, the
string can carry `strftime` codes (`"scans/%Y/%m/"`).

The folder is relative to the root of the storage, the bucket or the
`location`, and replaces the default rather than nesting under it:
`"patient-scans/"` stores `patient-scans/<uuid>.bin`, not
`encryption_suite/patient-scans/<uuid>.bin`. `""` stores at the root itself. To
keep a file in a default folder while passing `upload_to` for another reason,
name that folder: `"encryption_suite/"` or `"encryption_suite_system/"`.

The whole stored path, folder included, must fit the field's `max_length`,
which defaults to 100 as on a stock `FileField`. The opaque name takes 36
characters and its separator one more, which leaves 63 for the folder; pass a
larger `max_length` for a deeper layout.

### Per-team / per-silo prefixes

`upload_to` also accepts a callable `(instance, filename) -> str`, so each
team or silo can use its own prefix. A callable returns the whole stored
name, so it chooses the name under the prefix too. Derive that prefix from the
**current silo**, not from a field on the instance — the silo is
resolved from request-scoped context, and using the same source the
encryption engine uses guarantees the prefix and the DEK never disagree:

```python
import uuid

from encryption_suite.registry import get_silo_adapter


def scan_upload_to(instance, filename):
    # Same source the engine uses to choose the DEK. With
    # PegasusTeamSiloAdapter this is the request's current team.
    adapter = get_silo_adapter()
    silo = adapter.get_current_silo()
    uid = adapter.get_silo_uid(silo)  # e.g. "team-42"
    # uid may contain ":"; make it path-safe. Keep the leaf opaque (UUID),
    # never the original filename, so listings/keys don't leak it.
    return f"{uid.replace(':', '-')}/{uuid.uuid4().hex}.bin"


class Document(models.Model):
    team = models.ForeignKey("teams.Team", on_delete=models.CASCADE)
    scan = EncryptedFileField(
        display_name_field="scan_display_name",
        upload_to=scan_upload_to,
    )
    scan_display_name = EncryptedCharField(max_length=255, null=True, blank=True)
```

This changes only the storage layout — it does **not** change which DEK
encrypts the file. Key separation per team is the silo/KEK strategy's
job (see [KEK provisioning](kek-provisioning.md)); the prefix is purely
organizational. `get_current_silo()` returns `None` outside a request
(shell, data migrations), so saves outside silo context need their own
context set first — the encryption itself already requires it.

Only the default `upload_to` is stripped from migrations; a custom `upload_to`
is preserved, so changing it later generates a migration. To direct encrypted
files at a different bucket or backend entirely, change the `encrypted`
storage alias instead — see
[Mixing public and encrypted storage](storage-backends.md#mixing-public-and-encrypted-storage).

## Naming conventions

By default, `EncryptedFileField` populates the display name from the original
upload filename. Pass a `naming_convention` callable to enforce a
project-specific scheme:

```python
def patient_document_name(instance, original_name):
    ext = original_name.rsplit(".", 1)[-1].lower()
    return f"{instance.last_name}-{instance.first_name}-{instance.document_type}.{ext}"

class PatientDocument(models.Model):
    file = EncryptedFileField(
        display_name_field="file_display_name",
        naming_convention=patient_document_name,
    )
    file_display_name = EncryptedCharField(max_length=255, null=True, blank=True)
```

The callable receives `(instance, original_name)` where `original_name` is the
uploaded filename and `instance` is the model instance at save time. Returning
a string sets `file_display_name`, keeping its rightmost characters if it is
longer than the column's `max_length`; an explicit value already on the
instance is always respected. The callable must be importable at the module level (not
a lambda) so Django migrations can serialize it.

The upload form refuses a file whose name is longer than the display-name
column's `max_length`, since that column is where the name is kept and the name
a download is saved under. Django itself trims any uploaded name to 255
characters, keeping the extension, before the form sees it, so a `max_length`
of 255 accepts every name a user's device can produce.

## File lifecycle: delete and replace

Unlike stock `FileField`, `EncryptedFileField` cleans up its encrypted file when a
row is deleted or a file is replaced. Django removed auto-delete from
`FileField` in 1.3 over transaction/rollback and shared-file concerns —
sensible for a general-purpose field, wrong for a field whose whole purpose is
holding sensitive content. Leaving orphaned ciphertext after a delete violates
the retention expectation most users bring to this package.

Two per-field kwargs control the behavior, both default to `True`:

| Kwarg | Default | Behavior |
|---|---|---|
| `delete_on_row_delete` | `True` | Connects a `pre_delete` receiver that reads the prior path and schedules deleting the encrypted file for after the surrounding transaction commits. |
| `delete_on_replace` | `True` | When a fresh upload replaces an existing file on the same row, the prior encrypted file is deleted after the transaction commits. |

```python
class Document(models.Model):
    file = EncryptedFileField(
        display_name_field="file_display_name",
        delete_on_row_delete=True,
        delete_on_replace=True,
    )
    file_display_name = EncryptedCharField(max_length=255, null=True, blank=True)
```

### Guarantees and caveats

- **Rollback-safe.** Both deletions schedule via `transaction.on_commit`. A
  rolled-back save or delete discards the callback, so the prior ciphertext is
  never lost to a transaction that didn't actually succeed.
- **Pre-delete, not post-delete.** The receiver runs on `pre_delete` so it can
  still read the path from the row about to be deleted. This matters because
  `EncryptionAdminMixin` applies `.only(non_encrypted)` to its querysets,
  which defers the file column; a `post_delete` hook accessing the descriptor
  on a row already removed would trip the deferred refresh and raise
  `DoesNotExist`. The receiver reads the value from `instance.__dict__` when
  present and falls back to a targeted
  `values_list(attname, flat=True).first()` query when the column was
  deferred. The `transaction.on_commit` gate ensures the actual
  `storage.delete()` still honors rollback.
- **Bulk deletes covered.** Attaching the `pre_delete` receiver opts the host
  model out of Django's bulk-delete fast path. `QuerySet.delete()` and cascade
  deletes iterate per-instance, fire the receiver, and clean up each file. The
  cost is one extra row load per deleted instance plus one storage delete —
  almost always the right trade for sensitive content, but worth knowing on
  very large deletions.
- **Replace and clear both covered.** The replacement path fires when
  `instance.file = upload; instance.save()` — the upload's `_committed=False`
  flag is the signal. The clear path fires when the file attribute is falsy on
  an existing row: the field's default widget, `EncryptedClearableFileInput`
  (a `ClearableFileInput` subclass — see [Forms](#forms)),
  renders a `[x] Clear` checkbox that empties the attribute on form save, and
  programmatic clears (`instance.file = None` or `""` then `save()`) take the
  same path. In both cases a single
  `_base_manager.filter(pk=...).values_list(attname, flat=True).first()` query
  fetches the prior path and schedules its delete for after commit. Saves of
  existing rows where the file field is empty pay one extra PK-indexed query —
  negligible except on high-frequency saves of empty-file rows.
- **Storage errors are logged, not raised.** A failing `storage.delete()`
  emits an ERROR-level log entry with the field label and path, then returns.
  Cleanup failures never crash the calling save/delete path.
- **Raw SQL bypasses everything.** `cursor.execute("DELETE FROM ...")` does not
  go through the ORM collector, so neither the receiver nor any orphan cleanup
  runs. Don't delete rows with `EncryptedFileField` via raw SQL unless you
  clean up files separately.

### Versioning: opt out

When pairing `EncryptedFileField` with a versioning tool —
[`django-reversion`](https://django-reversion.readthedocs.io/),
[`django-simple-history`](https://django-simple-history.readthedocs.io/), or a
hand-rolled history table — set both kwargs to `False`:

```python
file = EncryptedFileField(
    display_name_field="file_display_name",
    delete_on_row_delete=False,
    delete_on_replace=False,
)
```

Historical revisions hold the prior file path. Auto-deleting the encrypted file
would break the history row; the versioning library expects to manage cleanup
on its own schedule (typically a retention-based cleanup). The opaque UUID
`upload_to` already ensures each save writes to a distinct key, so historical
and current paths never collide.

For the deletion half — "delete encrypted files that no live or historical row
references, older than N days" — iterate your storage under the `encryption_suite/`
prefix, diff against the union of current and historical paths, and call
`field.storage.delete(path)` on the orphans. This is application-specific
because only your history schema knows which paths are still referenced.

### Relationship to object-versioned storage

Bucket-level versioning (S3, GCS object versioning) is orthogonal. The opaque
`upload_to` means each save writes a new key, so bucket versioning doesn't
preserve prior uploads per row — it only guards against accidental
`storage.delete()` calls on the same key. Enable it as a recovery net if your
compliance posture wants belt-and-suspenders protection; pair it with a
lifecycle rule that expires non-current versions after the retention window.

## Moving to another storage backend

An encrypted file moves to another storage backend as it is, with no
re-encryption. Nothing in the encrypted file refers to the storage or the object: its
AAD, where the file field declares `aad=`, binds it to the row and
nothing else. So a byte-for-byte copy decrypts on the new backend.

1. **Copy the objects with the provider's own tools**, such as `aws s3 sync`,
   `gsutil rsync` or `rclone`.
2. **Keep every object name exactly.** Each row stores its file's name
   (`encryption_suite/<uuid>.bin`, `encryption_suite_system/<uuid>.bin`, or what
   a custom `upload_to` produced), and the new backend must answer to that same
   name. Give the new backend the same `location` or key prefix as the old one.
3. **Point the storage alias at the new backend** — `STORAGES["encrypted"]`, or
   the alias [`STORAGE_ALIAS`](#configuration) names — and deploy. A field
   constructed with its own `storage=` moves with that storage instead. The
   display-name column is in the database and does not move.
4. **Verify.** Run **File storage reachable (read-only)** in the
   [test console](admin-panel.md#test-console), then download a few files through
   the application, including some written before the copy.

The old backend receives any upload made during the copy. Copy, switch, then copy
again to pick them up, or stop uploads for the switch.

`reencrypt_data` does not move files between backends. It re-encrypts each file
through the one storage its field is configured with, and a row does not record
which storage holds its file.

## Forms

A model form renders `EncryptedFileField` with
`encryption_suite.widgets.EncryptedClearableFileInput`, a `ClearableFileInput`
subclass. Django's stock widget shows the current file as a link: the link text
is the storage name and the target is `storage.url()`. For an encrypted file
that name is the opaque `encryption_suite_default/<hex>.bin` path, and the URL serves
the encrypted file. The default widget shows the label `Encrypted file` instead, with
no link. It also renders on storage whose `url()` raises, because it never
calls it.

Clear works as it does on the stock widget. The label is display-only: on
save, the field reads the old storage name from the database row and deletes
the old encrypted file after commit (see
[File lifecycle](#file-lifecycle-delete-and-replace)).

To change the label:

- **Per form:** `widgets = {"scan": EncryptedClearableFileInput(encrypted_text=_("Scan on file"))}` in `Meta`.
- **Subclass:** set `encrypted_text` on a subclass and use that as the widget.
- **Template:** override
  `encryption_suite/widgets/encrypted_clearable_file_input.html`. Form widgets
  load templates through `FORM_RENDERER`, so a project-level override needs
  `FORM_RENDERER = "django.forms.renderers.TemplatesSetting"`.

A widget set in `Meta.widgets` or passed as `widget=` replaces the default.
To give users a working link to the file, render one to a view that decrypts
it — see [Serving encrypted files](serving-encrypted-files.md).

A Django REST Framework serializer renders the same `storage.url()` unless the
file field sets `use_url=False`; see
[Uploads](working-with-django-rest-framework.md#uploads).

## Admin

`EncryptionAdminMixin` handles `EncryptedFileField` the same way it handles
text encrypted fields:

- The field is **excluded from the change form** — no broken upload widget, no
  save-time silo error.
- The changelist shows the **full stored storage key** (e.g.
  `encryption_suite/3f9a...bin`, or whatever a custom `upload_to` produced) for any
  `EncryptedFileField` in `list_display` — the key is safe to display and
  confirms a file is attached.
- The companion `file_display_name` column is separately excluded and shows a
  truncated ciphertext preview.

Files cannot be downloaded from the admin. Downloads require a tenant-scoped
view where the silo context is set.

## Configuration

File encryption adds these optional settings to `ENCRYPTION`:

| Setting | Default | Description |
|---|---|---|
| `STORAGE_ALIAS` | `"encrypted"` | `STORAGES` alias whose backend is wrapped for `EncryptedFileField`. Falls back to `"default"` if not defined. |
| file segment size | backend default | Set in `CRYPTO_BACKEND_OPTIONS`, not top-level: `STREAMING_AEAD_KEY_TEMPLATE` (Tink) or `SEGMENT_SIZE` (pyca-cryptography). See [Crypto backends](crypto-backends.md). |
| `STORAGE_SPOOL_ENABLED` | `True` | Spool the encrypted upload to `SpooledTemporaryFile`. Set `False` on runtimes where `TMPDIR` is backed by memory (see below). |
| `STORAGE_SPOOL_THRESHOLD` | `None` | Bytes above which the spool spills from memory to disk. `None` uses Django's `FILE_UPLOAD_MAX_MEMORY_SIZE`. |
| `STORAGE_SPOOL_DIR` | `None` | Directory for the spool file. `None` honors `TMPDIR` / `TMP` / `TEMP`. Point at a mounted volume when rootfs is too small for concurrent uploads. |

Available streaming templates: `AES256_GCM_HKDF_4KB` (4 KB segments,
recommended), `AES256_GCM_HKDF_1MB` (1 MB segments, better throughput for very
large files), `AES128_GCM_HKDF_4KB`.

## Upload memory and disk

On upload, the mixin holds the encrypted file between "encrypt" and "hand to backend"
in a `SpooledTemporaryFile` that stays in memory for small uploads and spills
to `TMPDIR` once it crosses `STORAGE_SPOOL_THRESHOLD`. This keeps peak memory
flat for large files.

**Runtimes where `/tmp` is backed by memory** (Cloud Run, Kubernetes
`emptyDir: {medium: Memory}`, explicit tmpfs mounts): bytes written to `/tmp`
count against the container memory limit. Spooling gives no memory relief — set
`STORAGE_SPOOL_ENABLED = False` and size the memory limit for
`concurrency × max_upload_size`.

**Runtimes with real but bounded disk** (Fly machines, Fargate ephemeral
storage, disk-backed Kubernetes nodes, plain VMs): spooling works as intended.
Size the backing disk for `concurrency × max_upload_size`, or attach a
dedicated volume and point `STORAGE_SPOOL_DIR` at it so uploads don't compete
with rootfs.

## Opening a file by name

Reading a file through its field always works. The field passes the silo and the key
set to the engine, so `row.document.open()` decrypts a file of any key set.

A direct `storage.open(name)` has no field instance. The engine takes the key set from
the storage class's `key_set` attribute, which is `"default"` unless a subclass sets
another, and takes the silo from the current context. A file of any other key set,
including a `system` file, therefore fails to decrypt through the default storage. A
storage class that sets `key_set` reads those files, as long as their file field
declares no `aad=`:

```python
from encryption_suite.storage import SiloEncryptedStorageMixin
from django.core.files.storage import FileSystemStorage


class SystemFileStorage(SiloEncryptedStorageMixin, FileSystemStorage):
    key_set = "system"
```

`SystemFileStorage().open(name)` then decrypts a `key_set="system"` file with no silo
context. A storage class that sets `key_set = "user"` decrypts a file of a
[user-specific key set](user-specific-silos.md#files) for the acting user. Files of that
key set are stored under `encryption_suite_user/`. Compose the class on the backend you configured for
[`STORAGE_ALIAS`](configuration.md#storage_alias).

## Advanced: storage class composition

In rare cases — one model using a different bucket than the default encrypted
pool, a custom backend not configurable through `OPTIONS` — you can compose the
mixin manually and pass `storage=` directly on the field:

```python
from encryption_suite.storage import SiloEncryptedStorageMixin
from storages.backends.s3boto3 import S3Boto3Storage

class EncryptedArchiveStorage(SiloEncryptedStorageMixin, S3Boto3Storage):
    pass

class ArchiveDocument(models.Model):
    file = EncryptedFileField(
        display_name_field="file_display_name",
        storage=EncryptedArchiveStorage(bucket_name="long-term-archive"),
    )
    file_display_name = EncryptedCharField(max_length=255, null=True, blank=True)
```

`EncryptedArchiveStorage` is your storage backend (here S3) with
`SiloEncryptedStorageMixin` in front of it. List the mixin first so it encrypts the
content before the backend receives it.

The same storage serves a `key_set="system"` file field: the field names the system
silo on the content it hands over, and the mixin encrypts under it:

```python
class ArchivedAvatar(models.Model):
    image = EncryptedFileField(
        key_set="system",
        display_name_field="image_name",
        storage=EncryptedArchiveStorage(bucket_name="long-term-archive"),
    )
    image_name = EncryptedCharField(key_set="system", max_length=255, null=True, blank=True)
```

**The storage must carry the mixin.** Without it, nothing stands in front of the
backend and every upload is stored unencrypted. `manage.py check` refuses such a
storage as [`encryption_suite.E036`](configuration.md#system-checks).

This is the escape hatch. The `STORAGES` alias approach
([Storage backends](storage-backends.md)) covers the common case and should be
preferred.
