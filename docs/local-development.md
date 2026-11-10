# Local Development

This page collects practical notes for running django-encryption-suite on a developer
work station or in a local CI runner. This page focuses on the **runtime behavior** you'll
see on macOS and Windows — temp-file handling, memory/disk for file
uploads, and test-run cleanup. It does **not** cover KMS setup for local
dev; see the cross-references below for that.

## Starting points

- **[Getting started](getting-started.md)** — install the package, add it
  to `INSTALLED_APPS`, generate `ENV_KEY_STORES`, and run silo keys on the env
  key store so encryption round-trips without network calls. Do this first.
- **[Configuration reference](configuration.md)** — every
  `ENCRYPTION` setting in one place. Use this as the source of
  truth when a setting below seems under-specified.
- **[Managing encrypted files](managing-encrypted-files.md)** — the storage
  mixin's full feature set. The storage-specific notes below are a
  developer-work station narrowing of that reference.

## Encrypted field values

For field encryption (`EncryptedCharField` and friends), local
development is identical to production in shape: configure the env key store
(with one store configured, every key set uses it), run migrations, and assign values in your shell or
tests. No files or temp directories are involved. If reads and writes
round-trip through your shell, the engine is wired correctly.

The one local-dev pitfall is forgetting to set a silo context
before touching encrypted fields in a management command or script.
That raises a clear error — see
[Core concepts](concepts.md) and [Silo adapters](silo-adapters.md)
for the context-variable pattern.

## Encrypted file storage on a developer work station

When you upload a file through `SiloEncryptedStorageMixin`, the mixin has to hold the encrypted upload between "encrypt" and "hand
to storage backend". By default it writes to a
`tempfile.SpooledTemporaryFile` that stays in memory below Django's
`FILE_UPLOAD_MAX_MEMORY_SIZE` (2.5 MB by default) and spills to the
OS temp directory above that threshold. This is controlled by three
settings — `STORAGE_SPOOL_ENABLED`, `STORAGE_SPOOL_THRESHOLD`, and
`STORAGE_SPOOL_DIR` — all documented in the
[Managing encrypted files](managing-encrypted-files.md#upload-memory-and-disk) page.

On a developer machine, **you don't need to configure any of them.**
Defaults are correct. The notes below explain what's happening under
the hood so you can recognize it when it matters.

### macOS

- `tempfile.gettempdir()` resolves to a per-user directory under
  `/var/folders/...` (APFS, mode 0700). Real disk, not tmpfs.
- Small uploads (under 2.5 MB) never touch disk — the spool stays in
  memory. This matches the behavior of the old in-memory-only code
  path, so nothing feels different for typical test fixtures.
- Larger uploads spill to that per-user temp directory. The file is
  unlinked immediately after creation, so the inode disappears on
  close even if your dev server crashes. No manual cleanup required.
- Filenames are unpredictable (`mkstemp` + `os.urandom`), mode 0600,
  owned by your user. Other accounts on the machine can't read spooled
  ciphertext.

### Windows 11

- `tempfile.gettempdir()` resolves to `%TEMP%`, typically
  `C:\Users\You\AppData\Local\Temp`. NTFS, real disk, per-user ACL.
- Small uploads stay in memory as on macOS. Larger uploads spill into
  `%TEMP%`, using `FILE_ATTRIBUTE_TEMPORARY` and delete-on-close
  semantics. Auto-cleanup is automatic.
- If `%TEMP%` has a third-party antivirus watching every write, expect
  per-write latency on large uploads. Defender normally excludes
  `%TEMP%`; third-party AV sometimes doesn't. If test I/O feels slow,
  check exclusions.
- If your system drive is small and you're testing multi-GB uploads,
  point `STORAGE_SPOOL_DIR` at a larger drive in your dev settings:

  ```python
  ENCRYPTION = {
      # ...
      "STORAGE_SPOOL_DIR": r"D:\scratch\encryption_suite-spool",
  }
  ```

### Running tests

- `pytest` and unittest need no extra setup. The spool is in the OS
  temp directory regardless of any `tmp_path` or `tmpdir` fixture you
  might use in your own test bodies — those fixtures don't collide.
- `pytest-xdist` parallel workers don't collide either, because the
  spool filenames are randomized and each worker has its own process.
- Forced process exit (`kill -9`, closing the terminal, taskkill) still
  cleans up the spool: macOS reclaims the unlinked inode, Windows
  honors `DELETE_ON_CLOSE`.

### Disabling spooling locally

You almost never need to. The only reason to set `STORAGE_SPOOL_ENABLED = False`
on a work station is to exactly mirror the memory-only behavior you'd use on
Cloud Run (where `/tmp` is tmpfs-backed). If you're not specifically
reproducing that runtime, leave it on.

## MinIO local S3 smoke test

If you want to validate encrypted file storage against an S3-compatible
backend in local development, MinIO is a practical choice.

Prerequisites:

- Docker Desktop installed and running.
- A Django app already configured with django-encryption-suite and working
  round-trips on the env key store.

### 1. Add MinIO to `docker-compose.yml`

```yaml
services:
  minio:
    image: minio/minio
    command: server /data --console-address ':9001'
    environment:
      MINIO_ROOT_USER: minioadmin
      MINIO_ROOT_PASSWORD: minioadmin
    ports:
      - '127.0.0.1:9000:9000'
      - '127.0.0.1:9001:9001'
    volumes:
      - minio_data:/data
    healthcheck:
      test: ['CMD', 'mc', 'ready', 'local']
      interval: 2s
      retries: 10
```

Start MinIO:

```bash
docker compose up -d minio
```

Then open `http://localhost:9001`, sign in with `minioadmin` /
`minioadmin`, and create a bucket (for example,
`encrypted-file-bucket`).

### 2. Configure encrypted storage to switch between disk and S3

Keep your default local filesystem setup, but allow an env-driven
override for encrypted files:

```python
# settings.py
STORAGES = {
    'default': {
        'BACKEND': 'django.core.files.storage.FileSystemStorage',
    },
    'encrypted': {
        'BACKEND': 'django.core.files.storage.FileSystemStorage',
        'OPTIONS': {'location': '/encrypted_file_location'},
    },
}

USE_S3_ENCRYPTED = env.bool('USE_S3_ENCRYPTED', default=False)
if USE_S3_ENCRYPTED:
    STORAGES['encrypted'] = {
        'BACKEND': 'storages.backends.s3boto3.S3Boto3Storage',
        'OPTIONS': {
            'bucket_name': env('AWS_S3_ENCRYPTED_BUCKET_NAME', default='secure-share-encrypted'),
            'endpoint_url': env('AWS_S3_ENCRYPTED_ENDPOINT_URL', default=None),
            'access_key': env('AWS_S3_ENCRYPTED_ACCESS_KEY', default=''),
            'secret_key': env('AWS_S3_ENCRYPTED_SECRET_KEY', default=''),
            'region_name': env('AWS_S3_ENCRYPTED_REGION', default='us-east-1'),
            'addressing_style': env('AWS_S3_ENCRYPTED_ADDRESSING_STYLE', default='path'),
            'signature_version': 's3v4',
            'file_overwrite': False,
            'default_acl': 'private',
            'querystring_auth': False,
        },
    }
```

### 3. Add local environment variables

```dotenv
# Docker service ports
MINIO_PORT=9000
MINIO_CONSOLE_PORT=9001

# Optional: route public media to MinIO too
# AWS_S3_ENDPOINT_URL=http://localhost:9000

# encryption_suite encrypted file storage
# Set True to store encrypted files in S3/MinIO instead of local disk.
USE_S3_ENCRYPTED=False
AWS_S3_ENCRYPTED_BUCKET_NAME=encrypted-file-bucket
AWS_S3_ENCRYPTED_ENDPOINT_URL=http://localhost:9000
AWS_S3_ENCRYPTED_ACCESS_KEY=minioadmin
AWS_S3_ENCRYPTED_SECRET_KEY=minioadmin
# AWS_S3_ENCRYPTED_REGION=us-east-1
# AWS_S3_ENCRYPTED_ADDRESSING_STYLE=path
```

Set `USE_S3_ENCRYPTED=True` when you want encrypted uploads to go to
MinIO.

### 4. Verify end-to-end encrypted upload behavior

1. Start your Django app.
2. Upload a file through a model using `EncryptedFileField`.
3. In MinIO, confirm an opaque object key appears under a
   `encryption_suite/` prefix, for example
   `encryption_suite/3581bdca64f044b18b6f3daea2e8d417.bin`.
4. In Django admin for that model row, confirm the encrypted path and
   ciphertext preview are present, for example:

   ```text
   encryption_suite/3581bdca64f044b18b6f3daea2e8d417.bin
   (~^Dv1:AV3ReV7DmFX6j+u9nHszAQNFRX8dKUoMZdXned/NCTvpw...)
   ```

A matching encrypted object key in MinIO and encrypted reference in
admin confirms the storage path is correctly using encrypted file
storage.

## See also

- [Getting started](getting-started.md) — package installation, the minimal
  `ENCRYPTION` wiring, the env key store, and tests.
- [Configuration reference](configuration.md) — every setting,
  including the three `STORAGE_SPOOL_*` options and their defaults.
- [Managing encrypted files](managing-encrypted-files.md) — the full mixin
  reference and the runtime-specific upload memory/disk guidance.
