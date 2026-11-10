# Storage backends for encrypted files

`EncryptedFileField` wraps, under either `key`, whatever backend the
`"encrypted"` alias in Django's `STORAGES` defines. This page is the recipe
catalog — one section per backend, each self-contained: the settings block,
where to get credentials, and a local-development option where one exists.

Switching backends later (local → S3 → Tigris → GCS) is a settings change
only. No Python code in the consumer app changes. For the first-time walk
through, start at [Getting started with encrypted file uploads](getting-started-storage.md).

`OPTIONS` is passed straight to the backend's `__init__`, so any
django-storages setting that would normally be a class kwarg goes there.

The field and the storage mixin need nothing beyond Django and the configured
crypto backend (pyca-cryptography by default). For cloud backends, install
[django-storages](https://django-storages.readthedocs.io/) yourself; it is your
project's dependency, not django-encryption-suite's.

## No-overwrite requirement

A row finds its encrypted file by the stored name alone, so every name must
belong to one file. Django keeps names unique by asking the backend whether a
name is taken before saving and choosing another if it is. A backend configured
to overwrite skips that question and writes over whatever already holds the
name.

If two saves land on one name on such a backend, the second replaces the
first's file:

- The first row now points at the second row's ciphertext. Under another
  silo's key, or with
  [row identity binding](configuration.md#row-identity-binding-aad),
  it fails to decrypt, and the original file is gone. Within one silo and
  without that binding it decrypts, to the other row's file, shown under the
  first row's display name.
- Both rows point at one blob, so deleting or replacing either row deletes the
  file the other still uses.

The default names are random (`encryption_suite/<32 hex characters>.bin`, and
`encryption_suite_system/…` for system files), so a clash is not expected. An `upload_to` callable that can repeat a name makes one
likely. Either way, whether a clash is survived or loses a file is decided by
this setting:

| Backend | Option in `OPTIONS` | Set it to | Backend default |
|---------|---------------------|-----------|-----------------|
| Django `FileSystemStorage` | `allow_overwrite` | `False` | `False` |
| django-storages S3 (`S3Storage`, `S3Boto3Storage`) | `file_overwrite` | `False` | **`True`** |
| django-storages Google Cloud Storage | `file_overwrite` | `False` | **`True`** |
| django-storages Azure | `overwrite_files` | `False` | `False` |
| django-storages Dropbox | `write_mode` | `"add"` | `"add"` |
| django-storages FTP | `allow_overwrite` | `False` | `False` |

The S3 and Google Cloud Storage backends overwrite unless told not to, which is
why every `"encrypted"` alias on this page that uses them sets
`file_overwrite: False`. The FTP backend
with `allow_overwrite: True` also stops deleting: its `delete()` asks whether
the file exists, and in that mode the answer is always no, so replaced and
deleted files stay in storage with nothing logged.

With overwriting off, every upload asks the backend whether the name is taken.
On S3 that is a `HeadObject` request, and without `s3:ListBucket` on the bucket
a missing object answers `403` rather than `404`, which fails the upload.
Grant both `s3:GetObject` and `s3:ListBucket`.

### System check scope

`manage.py check` reports
[`encryption_suite.W057`](configuration.md#system-checks) when the storage an
`EncryptedFileField` writes through has
overwriting on. It reads the option
from that storage itself, so a per-alias `OPTIONS` value and a field's own
`storage=` both count. It recognizes only the six backends in the table above,
and subclasses of them. Nothing else is inspected:

- **Any other backend**, from another package or written in your project, is
  not checked. Make sure that its name selection asks `exists()` (Django's
  default, unless `get_available_name` is overridden), or that the backend
  refuses to write over an existing name, and that `exists()` raises when it
  cannot answer rather than reporting the name free.
- **An `exists()` that reports a name free when the question failed** cannot be
  seen from the configuration. The django-storages Dropbox and FTP backends do
  this for some errors.
- **Data key rotation** writes each replacement blob
  under a fresh random name without asking whether it is taken, on every
  backend; `FileSystemStorage` still refuses to write over an existing file at
  the moment of writing.

## Environment variables in settings

Give every environment read in `STORAGES` a default, such as
`os.environ.get("BUCKET", "")`. Build steps like image builds and
`collectstatic` import the settings module before the platform injects
runtime secrets, so a bare `os.environ["BUCKET"]` raises at import and fails
the build. The backend needs the real values only at runtime, on its first
read or write.

## Local disk (development / small deployments)

Either omit the `"encrypted"` alias entirely (it falls back to `"default"`,
then to `FileSystemStorage`) or configure it explicitly:

```python
STORAGES = {
    "encrypted": {
        "BACKEND": "django.core.files.storage.FileSystemStorage",
        "OPTIONS": {"location": "/var/data/encrypted-files"},
    },
}
```

## Amazon S3 (via django-storages)

Install the SDK: `uv add 'django-storages[s3]'`.

For production, prefer IAM roles (EC2/ECS/EKS/Lambda) over static keys —
boto3's default credential chain picks up the role, so no `access_key` /
`secret_key` entries are needed.

```python
STORAGES = {
    "default": {
        "BACKEND": "django.core.files.storage.FileSystemStorage",
    },
    "staticfiles": {
        "BACKEND": "django.contrib.staticfiles.storage.StaticFilesStorage",
    },
    "encrypted": {
        "BACKEND": "storages.backends.s3boto3.S3Boto3Storage",
        "OPTIONS": {
            "bucket_name": "acme-private-documents",
            "region_name": "us-east-1",
            "file_overwrite": False,
            "default_acl": "private",
            "querystring_auth": False,  # downloads go through Django, not presigned URLs
        },
    },
}
```

Off-AWS (no role available), set credentials via the standard
`AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` environment variables or add
`access_key` / `secret_key` to `OPTIONS`. Create the access key in the AWS
IAM console under **Users → Security credentials → Access keys**.

### Local development against MinIO

[MinIO](https://min.io) speaks the S3 API and runs in one container, so the
same `S3Boto3Storage` backend works for local iteration:

```bash
docker run -d --name minio \
  -p 9000:9000 -p 9001:9001 \
  -e MINIO_ROOT_USER=minioadmin \
  -e MINIO_ROOT_PASSWORD=minioadmin \
  minio/minio server /data --console-address ":9001"
```

```python
# settings_dev.py
STORAGES = {
    "encrypted": {
        "BACKEND": "storages.backends.s3boto3.S3Boto3Storage",
        "OPTIONS": {
            "bucket_name": "dev-documents",
            "endpoint_url": "http://localhost:9000",
            "access_key": "minioadmin",
            "secret_key": "minioadmin",
            "addressing_style": "path",    # MinIO does not do vhost-style
            "signature_version": "s3v4",
            "file_overwrite": False,
            "default_acl": "private",
            "querystring_auth": False,
        },
    },
}
```

Create the bucket via the MinIO console at `http://localhost:9001` or the `mc`
CLI. Model code is identical to production — only settings differ. For a full
local runbook (Compose service, env toggles, end-to-end verification), see
[Local development: MinIO local S3 smoke test](local-development.md#minio-local-s3-smoke-test).

## Tigris (S3-compatible object storage)

[Tigris](https://www.tigrisdata.com/docs/) is an S3-compatible global object
store. It uses the same `S3Boto3Storage` backend as Amazon S3, with its own
endpoint, region and credentials. Tigris has no IAM-role credential chain, so
you always supply an access key pair.

### Bucket and access key

In the [Tigris web console](https://console.tigris.dev):

1. Create a bucket for the `"encrypted"` alias and leave it private, which is
   the default. Tigris ignores S3 ACL headers, so the bucket setting is what
   keeps the files private.
2. Under **Access Keys**, create an access key. The console shows the Access
   Key ID and Secret Access Key only once, so copy both now. One key pair
   reaches every bucket in the account; create a key per bucket for tighter
   isolation.

### Settings

```python
import os

STORAGES = {
    "encrypted": {
        "BACKEND": "storages.backends.s3boto3.S3Boto3Storage",
        "OPTIONS": {
            "bucket_name": os.environ.get("TIGRIS_PRIVATE_BUCKET", ""),
            # Inside Fly.io's network, https://fly.storage.tigris.dev is faster.
            "endpoint_url": "https://t3.storage.dev",
            "access_key": os.environ.get("TIGRIS_ACCESS_KEY", ""),
            "secret_key": os.environ.get("TIGRIS_SECRET_KEY", ""),
            "region_name": "auto",          # Tigris uses a single "auto" region
            "signature_version": "s3v4",
            "addressing_style": "virtual",
            "file_overwrite": False,
            "default_acl": None,            # Tigris ignores ACL headers
            "querystring_auth": False,      # downloads go through Django, not presigned URLs
        },
    },
}
```

Keep `querystring_auth` at `False`. The bucket holds only encrypted files, and only the
package can decrypt them, so every download has to go through Django's serving
views. With `True`, `storage.url()` hands out a working presigned link that
fetches the encrypted file straight from Tigris. See
[Serving encrypted files](serving-encrypted-files.md).

To serve ordinary public media from Tigris as well, put it in a separate
public bucket on the `"default"` alias, as in
[Mixing public and encrypted storage](#mixing-public-and-encrypted-storage).
Tigris serves public buckets from `https://<bucket>.t3.tigrisfiles.io`, not
from the S3 API host, so set that host as `custom_domain` on the public
bucket.

## Google Cloud Storage (via django-storages)

Install the SDK: `uv add 'django-storages[google]'`.

On GCP (GKE, Cloud Run, GCE), attach a service account with
`roles/storage.objectAdmin` on the target bucket — the Google client library
picks it up automatically. Off-GCP, set `GOOGLE_APPLICATION_CREDENTIALS` to a
service-account JSON path.

```python
STORAGES = {
    "encrypted": {
        "BACKEND": "storages.backends.gcloud.GoogleCloudStorage",
        "OPTIONS": {
            "bucket_name": "acme-private-documents",
            "default_acl": None,          # uniform bucket-level access
            "querystring_auth": False,
            "file_overwrite": False,
        },
    },
}
```

Minimum django-storages version for streaming reads is **1.14** — earlier
versions call `blob.download_as_bytes()` in `_open`, buffering the whole file
and defeating the streaming decrypt. Check with `pip show django-storages`.

### Local development against fake-gcs-server

[fake-gcs-server](https://github.com/fsouza/fake-gcs-server) emulates the GCS
JSON API locally:

```bash
docker run -d --name fake-gcs \
  -p 4443:4443 \
  fsouza/fake-gcs-server -scheme http -public-host localhost:4443
```

```python
# settings_dev.py
import os
os.environ["STORAGE_EMULATOR_HOST"] = "http://localhost:4443"

STORAGES = {
    "encrypted": {
        "BACKEND": "storages.backends.gcloud.GoogleCloudStorage",
        "OPTIONS": {
            "bucket_name": "dev-documents",
            "custom_endpoint": "http://localhost:4443",
            "file_overwrite": False,
        },
    },
}
```

Create the bucket:

```bash
curl -X POST "http://localhost:4443/storage/v1/b" \
  -H "Content-Type: application/json" \
  -d '{"name": "dev-documents"}'
```

## Azure Blob Storage (via django-storages)

```python
STORAGES = {
    "encrypted": {
        "BACKEND": "storages.backends.azure_storage.AzureStorage",
        "OPTIONS": {
            "azure_container": "private-docs",
            "overwrite_files": False,
        },
    },
}
```

Supply the account and credentials through django-storages' Azure options.

> **Very important: keep `overwrite_files` at `False`.** With `True`, a save
> under a name that already exists writes over that blob. Two rows then share
> one file: the first row decrypts to the second row's file, or fails to
> decrypt and loses its own file for good, and deleting either row deletes
> the file the other still uses. `False` is the backend default, and setting
> it explicitly keeps a later settings change from turning it on by accident.
> See [No-overwrite requirement](#no-overwrite-requirement).

## Custom storage backends

Any class implementing Django's storage API (`_save` / `_open`) works — point
`BACKEND` at it and supply `OPTIONS` as needed. For the rare case of composing
the encryption mixin manually onto a backend, see
[Advanced: storage class composition](managing-encrypted-files.md#advanced-storage-class-composition).

## Mixing public and encrypted storage

Public assets (product images, marketing) and private encrypted files
(contracts, medical records) are kept in separate pools, controlled entirely by
settings:

```python
STORAGES = {
    "default": {
        # Public media — not encrypted, CDN-friendly.
        "BACKEND": "storages.backends.s3boto3.S3Boto3Storage",
        "OPTIONS": {
            "bucket_name": "myapp-public-assets",
            "default_acl": "public-read",
        },
    },
    "encrypted": {
        # Private encrypted uploads — separate bucket, no CDN.
        "BACKEND": "storages.backends.s3boto3.S3Boto3Storage",
        "OPTIONS": {
            "bucket_name": "myapp-private-documents",
            "default_acl": "private",
            "querystring_auth": False,
            "file_overwrite": False,
        },
    },
}
```

Public `FileField` / `ImageField` models use `default_storage` implicitly.
Only models with `EncryptedFileField` use the
`"encrypted"` alias. The two
pools do not interact. To direct encrypted files at a different bucket per
model, see [custom upload paths](managing-encrypted-files.md#customizing-the-storage-path-prefix).
