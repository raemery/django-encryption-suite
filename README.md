# django-encryption-suite

> Copyright 2026 J. Randall Emery. Licensed under the
> [Apache License, Version 2.0](https://github.com/raemery/django-encryption-suite/blob/main/LICENSE).

django-encryption-suite aims to be a general tool to help you:
1. isolate groups of users who share data
2. define subsets of data that require extra protection
3. use key management systems (KMS)
4. manage keys through their lifecycle
5. encrypt and decrypt data and files
6. search encrypted data

It encrypts data in **silos**, groups of data that share key isolation.
A silo is usually one of the groups of users your project defines, such as
teams or tenants, each with its own keys; it is the operation that motivated
the development of this project. A silo can also be a single user, or the one
system silo for system-wide encryption of data that no group of users scopes.
A **key set** binds the adapter that resolves silos to the **key store** that
holds their key encryption keys, and each encrypted field names its key set.

It gives you the flexibility to choose which fields should be encrypted
with new model fields and mixins, whether to have one or more key
encryption keys (KEKs) on a key management system, whether those keys
can be created (provisioned) automatically, and how narrowly to define
the groups that share encrypted information.

It works with any database or storage backend, and performs the actual
encryption and decryption through a pluggable crypto backend. The
default backend is built on [pyca/cryptography](https://cryptography.io);
[Google Tink](https://developers.google.com/tink) is available as an
alternative via the `[tink]` extra.

Using django-encryption-suite involves:
1. configuring pluggable adapters and options for isolating users,
   working with KMSs, and using encryption backends
2. configuring system-wide keys
3. connecting and testing connections to your KMS
4. creating key encryption keys on your KMS (manually or automatically)
5. updating your model fields
6. migrating your data (for existing projects)
7. rotating keys on your KMS periodically

## Motivation

This package aims to support the scenario where you have a small group of
people sharing sensitive data and files, reviewing them, and working with
them online. Think about sharing the documents you would need to apply
for a passport or a bank loan, or to make an insurance claim.

End-to-end encryption is one solution. This approach requires encrypting
and decrypting data on a device, which on the positive side can support
zero-knowledge solutions with a provider. The downside is that your data
then becomes tied to a user's device. Imagine you have a small business
helping people work with sensitive data, and a staff member who works
with you and then leaves. Yes, you can rent or buy them a laptop and
have it wiped automatically when they leave, but a lot of small
businesses don't have the technical infrastructure to support that.

Server-side encryption with a single key, at the database or field
level, is another possible solution. Several existing packages support
this approach, and this package offers field-level encryption with a
single system-wide key as well, but with a narrow use in mind: for
encrypting information that must be available across groups of people
(think login IDs).

The main focus is an easy-to-use solution that lets you both encrypt
data *and* isolate encrypted data for groups of users using
group-specific keys.

Beyond partitioning data by groups of users, this package provides
adapters for industry-grade key management systems on popular cloud
providers to support envelope encryption, where a key or set of keys is
stored on a KMS, and those keys encrypt (or wrap) the keys you use to
encrypt and decrypt data (also known as data encryption keys, or DEKs).
Using a KMS means that the key encryption keys (KEKs) reside only in
the KMS, and the DEKs are generated on the fly and kept only in memory.

## Features

- Envelope encryption for model fields using authenticated encryption
  (AEAD)
- `EncryptedFileField` for encrypted file uploads with opaque on-disk
  names and an encrypted display-name column; works with any Django
  storage backend (S3, Azure, GCS, local disk), encrypting file contents
  with streaming AEAD
- Crypto backend adapters: the local data-plane engine that generates
  the DEK and performs field (AEAD) and file (streaming AEAD)
  encryption/decryption — pyca/cryptography by default (a core
  dependency), or Google Tink via the `[tink]` extra; selected with the
  `CRYPTO_BACKEND` setting
- KMS adapters: GCP Cloud KMS, AWS KMS, Azure Key Vault, HashiCorp Vault,
  IBM Key Protect / HPCS, Oracle OCI Vault, Infisical, Fly.io KMS, and a
  system key alternative
- Keyless cross-cloud auth: any KMS provider that supports OIDC (AWS,
  GCP, Azure, Vault, Infisical) can be reached via a pluggable OIDC
  token source (Fly.io, file-based for Kubernetes / IRSA / Azure Workload
  Identity / Nomad, GCP metadata, Vercel, SPIFFE) — pair any source with
  any provider that exposes an OIDC-based auth method (AWS STS
  `AssumeRoleWithWebIdentity`, GCP Workload Identity Federation, Azure AD
  federated credentials, Vault JWT auth, Infisical OIDC auth)
- Key sets, chosen per field with `key_set`: each one binds a silo adapter to a
  key store in the `KEY_SETS` setting. A field without `key_set=` will use
  the `default` key set.
- Silo adapters, which cover:
  - groups of users: SaaS Pegasus teams, django-tenants, a generic
    model-based adapter for your own team or organization model, composite
    (mixed tenant/cell KEKs), and an optional ready-made team app for
    projects with no team model of their own
  - individual users: `ActingUserSiloAdapter` encrypts under the acting
    user's keys, and `ActingUserOrOwnerSiloAdapter` also lets a write with
    nobody acting use the keys of the user who owns the row
  - the whole system: the built-in `system` key set, one silo for columns
    that no group of users scopes, such as a user's email address or
    username, with `key_set="system"` on any encrypted field
- Key stores: a KMS store (`KMS_KEY_STORES`) wraps keys on a key management
  service, and an env store (`ENV_KEY_STORES`) wraps them locally under key
  material from your settings. Each key set names its store, so a project can
  put team data on a KMS and the `system` key set on an env store, where
  signing in does not depend on an external KMS
- An optional blind index on any encrypted column, `blind_index=True`,
  which keeps it searchable by exact value and holds its plaintext unique;
  the digest comes from the index key of the column's silo in its key set,
  such as the system silo for a `key_set="system"` column

## Quickstart

A local setup: a key held in settings in place of a KMS, files on local disk,
and teams managed in the Django admin by the optional `simpleteams` app, with
one team per user. It is for development only; see
[Moving to production](https://github.com/raemery/django-encryption-suite/blob/main/docs/production.md) for a real KMS.

Install the package:

```bash
uv add django-encryption-suite
```

Generate one key and set it in your environment as `ENC_LOGIN_KEK`. It wraps every
key in this setup: each team's data keys, and the system silo's, which encrypt each
team's name:

```bash
openssl rand -base64 32
```

Configure `settings.py`, reading the key from the environment:

```python
import os

INSTALLED_APPS = [
    # ...
    "django.contrib.admin",
    "django.contrib.auth",
    "encryption_suite",
    "encryption_suite.contrib.simpleteams",
    "yourapp",
]

MIDDLEWARE = [
    # ...
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "encryption_suite.contrib.simpleteams.middleware.SimpleTeamSiloMiddleware",
]

ENCRYPTION = {
    # The env key store: no external service, one key for every team.
    "ENV_KEY_STORES": {"login": {"KEKS": {1: os.environ["ENC_LOGIN_KEK"]}}},
    # The default key set: one silo per team, its keys wrapped by the "login" store.
    # The built-in system key set uses the only configured store.
    "KEY_SETS": {
        "default": {
            "silo": "encryption_suite.contrib.simpleteams.adapter.SimpleTeamSiloAdapter",
            "key_store": "login",
        },
    },
}

STORAGES = {
    "default": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
    "staticfiles": {"BACKEND": "django.contrib.staticfiles.storage.StaticFilesStorage"},
    "encrypted": {
        "BACKEND": "django.core.files.storage.FileSystemStorage",
        "OPTIONS": {"location": "var/encrypted-files"},
    },
}
```

Every team's key wraps under the one `ENV_KEY_STORES` entry. That suits a first run
on a work station; for a real KMS, see
[KMS adapters](https://github.com/raemery/django-encryption-suite/blob/main/docs/kms-adapters.md).

Add a model that points at its team:

```python
# yourapp/models.py
from django.db import models
from encryption_suite.contrib.simpleteams.models import SimpleTeam
from encryption_suite.fields import EncryptedCharField, EncryptedFileField

class Patient(models.Model):
    team = models.ForeignKey(SimpleTeam, on_delete=models.PROTECT)
    pseudonym = models.CharField(max_length=100)     # plaintext, queryable
    first_name = EncryptedCharField(max_length=100)  # encrypted at rest
    scan = EncryptedFileField(display_name_field="scan_name", null=True, blank=True)
    scan_name = EncryptedCharField(max_length=255, null=True, blank=True)
```

Optional encrypted fields take `null=True` alongside `blank=True`; an
encrypted column cannot hold the empty string.

Migrate, create a superuser, and start the server:

```bash
python manage.py makemigrations
python manage.py migrate
python manage.py createsuperuser
python manage.py runserver
```

In the admin, add a team under **Simple teams** and add yourself as a member.
Requests you make while signed in then run with that team as the current
silo. Check a round trip from `python manage.py shell`, where no request sets
the team, so you set it yourself:

```python
from encryption_suite.adapters.silos.context import override_current_silo
from encryption_suite.contrib.simpleteams.models import SimpleTeam
from yourapp.models import Patient

team = SimpleTeam.objects.get(name="Acme")
with override_current_silo(team):
    patient = Patient.objects.create(team=team, pseudonym="p-1", first_name="Jane")
    Patient.objects.get(pk=patient.pk).first_name  # 'Jane'
```

The `first_name` column in the database holds ciphertext. From here,
[Getting started](https://github.com/raemery/django-encryption-suite/blob/main/docs/getting-started.md) adds the admin's key pages and test
console, [Encrypted data](https://github.com/raemery/django-encryption-suite/blob/main/docs/encrypted-data.md) covers the field types and
working with encrypted values, and
[Serving encrypted files](https://github.com/raemery/django-encryption-suite/blob/main/docs/serving-encrypted-files.md) covers downloads.

## Documentation

Full documentation starts at [docs/index.md](https://github.com/raemery/django-encryption-suite/blob/main/docs/index.md): a
[getting started](https://github.com/raemery/django-encryption-suite/blob/main/docs/getting-started.md) guide, provider-specific setup
guides, encrypted fields and files, the admin panel, KEK strategies, silo
adapters, key rotation, system-wide encryption, blind indexes,
management commands, and a configuration reference. To find your way
around the source, see [Understanding the code base](https://github.com/raemery/django-encryption-suite/blob/main/docs/architecture.md).
