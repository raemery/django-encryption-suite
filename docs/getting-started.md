# Getting started

This page gets django-encryption-suite running on a local development machine.
You will install the package, wire the minimum `settings.py`, apply
migrations, add an encrypted field and an encrypted file upload, expose
the admin, and verify the round-trip two different ways.

This guide runs silo keys on the env key store, which needs no external
service and suits local development and tests. When you are ready to deploy, see
[Moving to production](production.md).

The env key store gives silo keys **no protection beyond your settings**. Its key
encryption key sits in `settings.py` (or the environment variables it reads), so
anyone who can read those can unwrap every data key, and therefore every
encrypted field and file. Every silo shares that one key, so the key encryption
key isolates no silo from another. A local KMS such as a HashiCorp Vault dev
server gives each silo its own key encryption key, the way production does; see
[Getting started with HashiCorp Vault](getting-started-hashicorp.md).

## Requirements

- Python 3.12+
- Django 5.2+
- Django supported database  — see [Supported databases](encrypted-data.md#supported-databases)

## 1. Install

```bash
uv add django-encryption-suite
```

The default crypto backend is pyca-cryptography (its `cryptography` dependency
is core), so a bare install is ready to encrypt, and is all this guide needs.
Other backends, KMS providers and framework integrations come as extras, combined
with commas. An example follows:

```bash
uv add 'django-encryption-suite[tink,drf]'
```

The `tink` extra adds the [Tink crypto backend](crypto-backends.md), and `drf`
adds the [Django REST Framework integration](working-with-django-rest-framework.md).
Each KMS provider has an extra of its own; the
[adapter quick reference](kms-adapters.md#quick-reference) lists them all.


## 2. Minimum `settings.py`

You need a **silo**: the object that scopes encryption keys, typically a tenant
or team model. This walkthrough uses the optional [`simpleteams` app](simple-teams.md), which ships
a team model, its silo adapter, the middleware and an admin, with one team per
user. If you already have a team or tenant model, use its adapter instead; see
[Silo adapters](silo-adapters.md).

Add django-encryption-suite and the SimpleTeams app and its middleware, below 
`AuthenticationMiddleware`:

```python
INSTALLED_APPS = [
    # ...
    "django.contrib.auth",
    "django.contrib.admin",    
    "encryption_suite",
    "encryption_suite.contrib.simpleteams",
]

MIDDLEWARE = [
    # ...
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "encryption_suite.contrib.simpleteams.middleware.SimpleTeamSiloMiddleware",
]
```

Note: `django.contrib.auth` is required: key lifecycle events in the admin panel
record user who act on keys, based on `AUTH_USER_MODEL`. 

The env key store needs one key per environment: 32 random bytes, base64
encoded, as version 1. Generate it once:

```bash
openssl rand -base64 32
```

Keep the output in a `.env` file, an exported variable, or your shell profile:

```bash
export ENC_LOGIN_KEK="q1WZ...="     # output from the command above
```

Treat it as a development secret. If you commit a `.env.example`, document the
variable but never commit a real value. The format does not depend on
`CRYPTO_BACKEND`: the env key store wraps keys with AES-256-GCM through the
`cryptography` library directly, so a backend switch needs no new value.

Configure `ENCRYPTION` in `settings.py`. `ENV_KEY_STORES` defines a key store
named `login` that holds the key. [`KEY_SETS`](configuration.md#key_sets) then
pairs each key set with a silo and the key store that wraps its keys. The
`default` key set uses the `SimpleTeam` silo. A team's name is encrypted under the
`system` key set, which takes only a `key_store` because it always uses the
[system silo](system-wide-silos.md#keys):

```python
import os

ENCRYPTION = {
    "ENV_KEY_STORES": {"login": {"KEKS": {1: os.environ["ENC_LOGIN_KEK"]}}},
    "KEY_SETS": {
        "default": {
            "silo": "encryption_suite.contrib.simpleteams.adapter.SimpleTeamSiloAdapter",
            "key_store": "login",
        },
        "system": {"key_store": "login"},  # no silo: the system key set always uses the system silo
    },
}
```

That is the whole KMS configuration. An env store needs no
[`KMS_KEY_STORES`](configuration.md#kms_key_stores) block. With one store
configured, a `KEY_SETS` entry may leave out `key_store`, but naming it keeps the
mapping visible. Read the key from the environment, a `.env` file, or a developer
secret store, not from a string literal in a committed settings file.

An empty `KEKS` fails `manage.py check` (`E039`) and raises at first use. The
package never generates key material, so a missing variable cannot silently
produce a new key that orphans what a previous run wrote. Every process that
shares a database must read the same value, or each writes data keys the other
cannot unwrap. To rotate the key, see
[`ENV_KEY_STORES`](configuration.md#env_key_stores).

To develop against the Tink crypto backend, install the `tink` extra and add one
line to `ENCRYPTION`. The `ENV_KEY_STORES` value stays the same:

```python
    "CRYPTO_BACKEND": "encryption_suite.adapters.crypto_backends.tink.TinkCryptoEngine",
```

For a real KMS, your own tenant structure, or alternatives like django-tenants,
see [Moving to production](production.md).

## 3. Migrate

```bash
python manage.py migrate
```

This creates the `DataEncryptionKey` table that stores the
KMS-wrapped DEK for each silo, and the `simpleteams` tables.

Data keys are created on first use. With `KEY_AUTO_PROVISION = True` (the
default), the engine creates each silo's data key the first time that silo
encrypts, so nothing needs creating yet: no team exists until section 6.

There is no key encryption key to provision, because the key encryption key is
`ENV_KEY_STORES` itself. That also makes the key lifecycle inert here: nothing at
a provider holds the key, so there is nothing to create, list, or destroy. One
key encryption key row, `shared`, serves every silo, so deleting it always
retains it at the first gate and records why. The
[Reconcile Keys](admin-panel.md#reconcile-keys-page) page reports its KMS side as
detection-unavailable. Exercise deletion and reconcile against a real provider.

## 4. Encrypted fields

django-encryption-suite handles two kinds of data in parallel: **model field
values** and **uploaded files**. This section adds the field values; the next adds
a file.

```python
# yourapp/models.py
from django.db import models
from encryption_suite.contrib.simpleteams.models import SimpleTeam
from encryption_suite.fields import EncryptedCharField, EncryptedDateField

class Patient(models.Model):
    team = models.ForeignKey(SimpleTeam, on_delete=models.PROTECT)
    pseudonym = models.CharField(max_length=100)      # plaintext, queryable
    first_name = EncryptedCharField(max_length=100)   # encrypted at rest
    date_of_birth = EncryptedDateField(null=True, blank=True)
```

Optional encrypted fields must pair `blank=True` with `null=True`; see
[Optional encrypted fields](encrypted-data.md#optional-encrypted-fields).

> **Binding data within a silo:** each silo has its own DEK, so a row moved to
> another silo already fails to decrypt. To tie encrypted data to something
> *inside* a silo — the user who owns it, or the parent record it belongs to —
> pass those columns to each encrypted field's `aad=`, e.g.
> `aad=("owner",)`. If one of them is changed, for example to hand a record to
> another user on the same team, its encrypted fields fail to decrypt instead
> of reading as the new owner's. See
> [Row-identity binding](security.md#row-identity-binding-optional).

## 5. Encrypted file uploads

File content goes through Django's storage layer, not a column. Use
`EncryptedFileField`, which handles encrypted content, an opaque storage path, and
an encrypted display-name column. Configure the storage backend with Django's
`STORAGES` setting. No consumer-side storage class is needed:

```python
# settings.py
STORAGES = {
    "default": {
        "BACKEND": "django.core.files.storage.FileSystemStorage",
    },
    "staticfiles": {
        "BACKEND": "django.contrib.staticfiles.storage.StaticFilesStorage",
    },
    "encrypted": {
        "BACKEND": "django.core.files.storage.FileSystemStorage",
        "OPTIONS": {"location": "var/encrypted-files"},
    },
}
```

`EncryptedFileField` reads the `"encrypted"` alias and wraps the backend with
encryption. If the alias is missing, the field falls back to the `"default"` alias,
so configuring the alias explicitly is cleaner.

Then add the field and its companion display-name column to the model:

```python
# yourapp/models.py (continued)
from encryption_suite.fields import EncryptedFileField

class Patient(models.Model):
    # ... fields from section 4 ...
    scan = EncryptedFileField(
        display_name_field="scan_display_name",
        null=True,
        blank=True,
    )
    scan_display_name = EncryptedCharField(max_length=255, null=True, blank=True)
```

On upload, the file content is encrypted before it reaches `FileSystemStorage`,
and the original filename is encrypted into `scan_display_name`. The stored path
is an opaque UUID (`encryption_suite_default/<hex>.bin`), so the
`var/encrypted-files/` directory exposes no filenames. A `naming_convention`
callable on the field enforces a specific naming scheme instead.

Field writes use AEAD and a `PURPOSE_FIELD` DEK; file writes use
Streaming AEAD and a `PURPOSE_FILE` DEK. Both paths go through
the same KMS and the same silo; they never cross. The algorithm depends on the
configured crypto backend; see [Crypto backends](crypto-backends.md).

Apply the migration:

```bash
python manage.py makemigrations
python manage.py migrate
```

### Serving downloads

Serve files through Django so decryption happens server-side. Presigned URLs do
not work, because the browser would receive the encrypted file. The bundled helper
streams the decrypted content with the decrypted display name:

```python
from django.contrib.auth.decorators import login_required
from django.shortcuts import get_object_or_404
from encryption_suite.contrib.simpleteams.models import SimpleTeamMembership
from encryption_suite.file_view_helpers import serve_encrypted_file

@login_required
def download_scan(request, pk):
    membership = get_object_or_404(SimpleTeamMembership, user=request.user)
    patient = get_object_or_404(Patient, pk=pk, team=membership.team)
    return serve_encrypted_file(request, patient, "scan")
```

See [Serving encrypted files](serving-encrypted-files.md) for inline display and
error handling.

### Other storage backends

For cloud storage (S3, GCS, Azure), change the `"encrypted"` alias `BACKEND` and
`OPTIONS`; the model code stays identical. To develop against an S3-compatible
service locally, see
[Local development against MinIO](storage-backends.md#local-development-against-minio).
The [Encrypted file storage](encrypted-files.md) page links to every file guide,
including spool settings and the full storage setup.

For the full field catalog and the `NOT NULL` backfill pattern, see
[Encrypted data](encrypted-data.md).

## 6. Wire `urls.py` for the admin

The Reconcile Keys page and test console live under the Django
admin. If you don't already expose the admin, wire it now — this step is
easy to miss.

```python
# yourproject/urls.py
from django.contrib import admin
from django.urls import path

urlpatterns = [
    path("admin/", admin.site.urls),
]
```

No separate include is needed — django-encryption-suite registers its views
through its `ModelAdmin`, so they appear automatically once the admin is
mounted.

Create a superuser and start the server:

```bash
python manage.py createsuperuser
python manage.py runserver
```

In the admin, add a team named `Acme` under **Simple teams** and add yourself as a
member. Your requests then run with that team as the current silo. See
[Managing teams in the admin](simple-teams.md#managing-teams-in-the-admin).

## 7. Check a round trip in a shell

Open `python manage.py shell`. Encrypted access needs a current silo, so run inside
the team from the previous step:

```python
>>> from django.core.files.base import ContentFile
>>> from encryption_suite.adapters.silos.context import override_current_silo
>>> from encryption_suite.contrib.simpleteams.models import SimpleTeam
>>> from yourapp.models import Patient
>>> team = SimpleTeam.objects.get(name="Acme")
>>> with override_current_silo(team):
...     patient = Patient.objects.create(team=team, pseudonym="p1", first_name="Alice")
...     patient.scan.save("scan.txt", ContentFile(b"hello"))
...     Patient.objects.get(pk=patient.pk).first_name
'Alice'
```

Then check that the stored values are encrypted. Read the column directly:

```sql
SELECT first_name FROM yourapp_patient;
-- an encoded encrypted value, not "Alice"
```

For the file, print the opaque path and read the bytes at that path:

```bash
python manage.py shell -c "from yourapp.models import Patient; print(Patient.objects.last().scan.name)"
# encryption_suite_default/3f9a1c....bin

xxd "var/encrypted-files/encryption_suite_default/3f9a1c....bin" | head
# no trace of "hello"
```

The round trip created `Acme`'s data keys on first use. To create the data keys
for every existing team ahead of time instead, run:

```bash
python manage.py setup_encryption_keys
```

## 8. Verify via the Reconcile Keys page

Visit `http://localhost:8000/admin/encryption_suite/dataencryptionkey/`.
Use the "Reconcile Keys" link at the top of the change list.

The Reconcile Keys page reports drift; it never changes a key. It shows every
silo the adapter can enumerate with the key encryption key name it expects and whether
that key and its data encryption keys exist, plus any orphaned keys left
behind by deleted tenants. Acting on what it finds happens on the Data
Encryption Keys and Key Encryption Keys changelists. See
[Reconcile Keys page](admin-panel.md#reconcile-keys-page).

The test console shows which adapters loaded, the curated `OPTIONS`, and per-purpose
key counts (next section).

For an end-to-end encrypt/decrypt round-trip against the sentinel test
key, use the **Test console** (next section). The full-KMS-path check
confirms the KMS is reachable, credentials are valid, and
`encrypt_key` / `decrypt_key` round-trip correctly.

## 9. Verify via the test console

From the Reconcile Keys page, follow the link to the **test console** (or
visit `/admin/encryption_suite/dataencryptionkey/test-console/`).

The console runs encryption round-trips against an isolated test key —
it never touches real silo DEKs.

**In-memory field check (no KMS).** Run the field round-trip in the
in-memory mode. The result shows `matches: True`, confirming the
configured crypto backend and its AEAD primitive work — no KMS involved.

**Full-KMS field check.** Run the field round-trip in the full mode. This
exercises `kms_adapter.encrypt_key` / `decrypt_key` against the KMS and a
real `DataEncryptionKey` row (under the reserved sentinel UID).
A `matches: True` here means the full production path — KMS, DEK
wrapping, crypto backend — is working end to end for the field path.

**Full-KMS file check.** Run the file round-trip in the full mode. This
exercises the Streaming AEAD path your encrypted storage will use — same
KMS, the file primitive, a different DEK purpose. `matches: True`
confirms the file path works end to end too.

When you are done, click **Delete** to remove the test rows. The test key
encryption key is retained rather than destroyed, because nothing ever deletes the
env key store's key. See [Using the admin panel](admin-panel.md) for a deeper tour
of the admin views.

**If a check fails here, the console is the tool for it.** A round-trip that
reports a failure names the layer and writes a log line carrying the operator
detail and a stable [error code](error-codes.md). Most connection problems — an
unreachable KMS, a key name that does not exist, credentials the provider
rejects — do not block a deploy at all, because building an adapter performs no
I/O; they surface here, which is the point. If a misconfiguration is bad enough
to fail `manage.py check` (or `migrate`, which runs the same checks) and you
want the deployment up anyway so you can use this page, see
[Deploying to debug a broken connection](configuration.md#deploying-to-debug-a-broken-connection).

## 10. Check the deployment's configuration

The **Encryption settings** page — linked from the same three changelists —
lists every setting this package reads, with its effective value and whether
your project set it or left it at the default, plus the `STORAGES` entry your
encrypted files are actually written through.

Reach for it when a screen disagrees with what you think you configured. It
answers the questions the other pages raise and cannot: why a key event names
no user (`USER_IDENTITY`), why your uploads are stored somewhere unexpected (an
alias that did not resolve, falling back to `default`), which adapters and
engine a deployment is really running. On a deployment whose configuration
is held in environment variables or secrets, it is the only place the running
values are visible at all.

Values that carry a credential read as `(hidden)`; the row still shows the
option is set. See
[Encryption settings page](admin-panel.md#encryption-settings-page).

## Tests

Give the test settings a fixed env store. The adapter refuses an empty `KEKS`
whatever `DEBUG` says:

```python
# settings_test.py
ENCRYPTION = {
    **ENCRYPTION,
    # Test material, under a database thrown away per run.
    "ENV_KEY_STORES": {"login": {"KEKS": {1: "q1WZ5r3Ue9cS0GmZ8h2Ft1o4xJbLkV7nC0aY6dR2pXE="}}},
}
```

To change the encryption settings inside one test class, override them and reset
the registry:

```python
from django.test import TestCase, override_settings

@override_settings(ENCRYPTION={
    "KEY_SETS": {"default": {"silo": "encryption_suite.contrib.simpleteams.adapter.SimpleTeamSiloAdapter"}},
    "ENV_KEY_STORES": {"login": {"KEKS": {1: "q1WZ5r3Ue9cS0GmZ8h2Ft1o4xJbLkV7nC0aY6dR2pXE="}}},
})
class PatientEncryptionTests(TestCase):
    def setUp(self):
        from encryption_suite.registry import reset
        reset()    # drop cached adapters from any earlier test
        # ...
```

Calling `encryption_suite.registry.reset()` is important: the package caches
adapters as process singletons, so a settings override in one test does not take
effect in the next unless you reset the registry.

For tests that load fixtures containing pre-encrypted values, keep the
`ENV_KEY_STORES` version the fixtures were written under, and re-encrypt the
fixtures whenever you rotate it.

## Moving to a real KMS

Point silo keys at a real KMS when any of these becomes true:

- The data is real: production, staging with production-like data, or a
  pre-launch beta with real users.
- You need each silo under its own key encryption key.
- You need audit logs on every key encryption key use.
- You need per-tenant key custody for compliance.

Pick a provider from the [adapter quick reference](kms-adapters.md#quick-reference)
and follow its guide. The data path is the same. An existing development database
moves with it: configure the provider as a `KMS_KEY_STORES` block, point the key
set's `key_store` at it, and run `reencrypt_keys`. See
[Moving to another KMS](key-rotation.md#moving-to-another-kms).

## Next steps

- [Using the admin panel](admin-panel.md) — day-to-day operational views,
  including the [Encryption settings page](admin-panel.md#encryption-settings-page)
  for what a deployment is configured to do
- [Encrypted data](encrypted-data.md) — field catalog, encrypted
  file storage, the `NOT NULL` two-phase backfill, silo context, and the
  blind index that keeps an encrypted column searchable by exact value
- [System-wide silos](system-wide-silos.md) — the columns no group of
  users scopes, such as the ones a sign-in reads, under the system silo's keys,
  which the env key store wraps under `ENV_KEY_STORES` from your settings
- [Core concepts](concepts.md) — envelope encryption, silos, DEKs,
  KEKs
- [Moving to production](production.md) — real KMS adapters, KEK
  strategies, deployment checklist
- [Security model](security.md) — threat model and what this package
  does not protect against
- [Adopting and removing encryption](adopting-and-removing-encryption.md) —
  encrypting an existing table, and unwinding it again
