# Encrypted file storage

`EncryptedFileField` encrypts files uploaded through a Django model field. It
is the file-storage counterpart to the encrypted *value* fields
([encrypted data](encrypted-data.md)) — same silo, same KMS, different
primitive. With [`key_set="system"`](system-wide-silos.md#files), for files no
silo owns, it works the same way in every respect this page describes except the
key.

This page is the design of the field. The practical pages:

- [Getting started with encrypted file uploads](getting-started-storage.md) — install, configure, first upload/download
- [Storage backends](storage-backends.md) — S3, Tigris, GCS, Azure, MinIO, local disk recipes
- [Serving encrypted files](serving-encrypted-files.md) — download/inline views and error handling
- [Managing encrypted files](managing-encrypted-files.md) — lifecycle, forms, admin, config, tuning

## Content, storage path, and filename

`EncryptedFileField` protects three things:

1. **Encrypted content.** File bytes stream through
   `SiloEncryptedStorageMixin` before reaching the storage backend.
   The backend only ever receives encrypted files.
2. **Opaque storage path.** The name in the bucket or on disk is a UUID
   (`encryption_suite_default/<hex>.bin`), not the original filename. Storage listings,
   bucket keys, and backup logs never expose filenames.
3. **Encrypted display name.** The user-facing filename is held in a companion
   encrypted column on the model, encrypted at rest like any other
   `EncryptedCharField`.

```
EncryptedFileField
        ↓ encrypts bytes via Streaming AEAD
Configured storage backend    (S3, Azure, GCS, disk — receives encrypted files only)
        ↓ stores as encryption_suite_default/<hex>.bin

Companion column (EncryptedCharField)
        ↓ stores encrypted display name ("invoice.pdf")
Database
```

`EncryptedFileField` reads the `"encrypted"` alias from Django's `STORAGES`
setting and wraps the configured backend at runtime. You configure once in
settings; no consumer-side storage class is needed. Switching backends later
is a settings change only.

File encryption uses **Streaming AEAD**, which processes data in chunks,
so arbitrarily large files are encrypted without loading the entire content
into memory.

## Using the field

```python
class Patient(models.Model):
    scan = EncryptedFileField(display_name_field="scan_name", null=True, blank=True)
    scan_name = EncryptedCharField(max_length=255, null=True, blank=True)
```

Read and write the field as normal: `patient.scan.save(...)` and
`patient.scan.open().read()`. Both need silo context, except under
`key_set="system"`.

```python
patient.scan        # FieldFile — streams decrypted bytes on .read()
patient.scan.name   # opaque storage path: "encryption_suite_default/3f9a....bin"
patient.scan_name   # decrypted display name: "scan.pdf"
```

For writes not attached to a model, `get_encrypted_storage()` in
`encryption_suite.storage` returns the storage the field uses. Such a write
encrypts under the current silo's file key.

## Fields and files

A model can hold both encrypted value fields and encrypted files; the
[two-paths table](encrypted-data.md#one-package-two-paths) compares them. The two
never apply to the same data, and they use separate keys. The file content uses
the silo's `"file"` key, and the companion display-name column, being an
ordinary encrypted field, uses its `"field"` key.

[Row-identity binding](security.md#row-identity-binding-optional) covers the file
too: when a bound column changes, the encrypted fields and the file fail to
decrypt instead of reading as the new owner's.

Optional files follow the rule for every encrypted field: pair `blank=True`
with `null=True`, on the file field and on the companion display-name column
alike. See [Optional encrypted fields](encrypted-data.md#optional-encrypted-fields).
