# Changelog

## 1.0.0

First public release.

### Encryption

- Encrypted model fields for text, email, URL, integer, date, date-time and JSON
  values, and `EncryptedFileField` for files. Uploads are encrypted in streamed
  segments before they reach the storage backend, so file size is not bounded by
  memory.
- Envelope encryption: each silo has its own data encryption keys, wrapped by a key
  encryption key held by a key store.
- Blind indexes: `blind_index=True` keeps an encrypted column searchable by exact
  value, and `unique=True` or `unique_in_silo=True` enforces uniqueness over the
  digest.
- Row-identity binding through a field's `aad=`, which ties its ciphertext to
  columns in the same row.
- Tamper protection to prevent ciphertext injection.
- View helpers that serve decrypted files, since a presigned URL would hand the
  browser an encrypted file.
- Pluggable crypto backends: `pyca-cryptography` (the default) and Google Tink via
  the `[tink]` extra.

### Silos

- Key sets, chosen per field with `key_set`: each one binds a silo adapter to a key
  store in `KEY_SETS`. The built-in `system` key set is a single silo for system-wide
  data.
- Silo adapters for SaaS Pegasus teams, django-tenants schemas, any model you name,
  composites of these, and individual users. Custom adapters are supported.
- `encryption_suite.contrib.simpleteams`, a ready-made team app for projects with no
  team model.
- Silo enumeration as an adapter capability, used to provision keys and to reconcile
  the database against the key stores.

### Key management

- Key stores: KMS adapters for GCP Cloud KMS, AWS KMS, Azure Key Vault, HashiCorp
  Vault, IBM Key Protect / HPCS, OCI Vault, Infisical and Fly.io, and env key stores
  that take their key material from your settings. Each key set names its store.
- Keyless authentication through OIDC federation, beside each provider's native
  credential strategies.
- KEK strategies for one key per silo, one shared key, or a map you control, with
  automatic provisioning where the provider allows it.
- Rotation of both key layers: `reencrypt_keys` rewraps data keys under a new key
  encryption key, and `reencrypt_data` moves the data onto new data key material.
- Scheduled deletion of a silo's keys, gated on data still in use, with a local
  waiting period ahead of the provider's own.
- An append-only key lifecycle event log that records each key action, including
  attempts a provider refused, and optionally who acted.

### Operations

- Swapping what protects your data with one setting and one command: the key store
  (any KMS provider, or an environment-variable key), the crypto backend, or the
  algorithm. Existing data stays readable until it moves.
- Admin screens to reconcile the database against the key stores, act on individual
  keys, review key events, browse the cryptographic inventory, and run an isolated
  encrypt/decrypt round trip against any configured store.
- Management commands for key setup, reconciliation, the cryptographic inventory,
  recording a key event, and the rotations, with JSON reports for scheduling.
- Data migration helpers that encrypt an existing column or file field in place, and
  back that out again.
- Typed errors: each failure carries a generic, translated message for users and a
  stable error code with one clean log line for operators.
- Deploy-time system checks for configuration mistakes.
- Integrations for Django REST Framework (`encryption_suite.contrib.drf`) and for
  django-allauth's MFA secrets (`encryption_suite.contrib.allauth`).
- Translations for 12 locales.
