# Core Concepts

This page introduces the ideas and terminology behind django-encryption-suite.
Read this first if you are new to envelope encryption or want to understand
how the pieces fit together before diving into configuration.

For definitions of the acronyms and terms used throughout the docs, see the
[Glossary](glossary.md).

---

## Envelope encryption

### Origins

Public-key cryptography arrived in the late 1970s — Diffie and Hellman's key
exchange in 1976, then RSA in 1977 — and solved a real problem: you could
encrypt a message to someone using only their public key, with no shared secret
arranged in advance. But RSA had a hard limit. It was slow, and the math let it
encrypt only a few hundred bytes at a time. The fast symmetric ciphers (DES
then, AES now) could encrypt data of any size, but they reintroduced the
original headache: how do you deliver the secret key to the other side without
it being intercepted? One tool could share keys but not move data; the other
could move data but not share keys.

The fix was to use both at once. Encrypt the data with a freshly generated
**random symmetric key** — fast, any size — then encrypt that one small key with
the slow public-key cipher. You store and ship the two together: the bulk
ciphertext, plus the wrapped key that opens it. The expensive operation runs
once, on a few bytes, instead of over the whole message.

This is the scheme Phil Zimmermann built into **PGP** ("Pretty Good Privacy")
and released free to the internet in 1991. His motivation was political, not
commercial: he wanted activists, journalists, and dissidents to have the same
strong cryptography that until then only governments and large institutions
could afford — a direct response to a 1991 US Senate bill (Senate Bill 266) that
would have forced "trap door" backdoors into secure communications products.
Because PGP used RSA key sizes the US government then classified as *munitions*
under arms-export law, its rapid spread overseas triggered a three-year federal
criminal investigation of Zimmermann, finally dropped without charges in 1996.
The episode helped cement encryption as a civil-liberties tool in the hands of
ordinary people, not just a military one — the same democratizing instinct that
puts strong, per-tenant encryption within reach of an ordinary Django app today.

When RSA's company standardized the same hybrid format in **PKCS #7** (later
[RFC 2315](https://datatracker.ietf.org/doc/html/rfc2315)) they gave the bundle
a name — the **digital envelope** — picturing a sealed message with its key
tucked in alongside, addressed to whoever holds the matching private key.

Decades later the cloud reused the exact structure, but for data *at rest*
rather than data *in transit*. The outer key moved into a hardened, audited
vault — a **key management service (KMS)** — and the two layers were renamed for
the new job: the inner random key became the **data-encryption key (DEK)**, the
outer wrapping key the **key-encryption key (KEK)**. The pattern got a matching
name, **envelope encryption**, and today it underpins TLS, S/MIME, and
essentially all cloud encryption at rest. It is also exactly what this package
does.

In django-encryption-suite a key store holds the KEK. With a KMS the KEK never
leaves the service, and each silo gets its own DEK to encrypt its fields and files;
your database stores only the wrapped DEK. Because the two keys sit in separate
systems, an attacker has to breach both to read anything — which is what the next
table breaks down. It describes a KMS key store; the
[env key store](#with-an-env-key-store) keeps the KEK in your settings instead.

### Protection per layer

| Compromised system | What the attacker gets | Can they read your data? |
|---|---|---|
| Database only | Wrapped DEKs, encrypted field values, encrypted file names, opaque storage paths | No — DEKs are wrapped, field values are encrypted, and file *content* is in file storage, not the database |
| File storage only | Encrypted file content under opaque object keys | No — the DEK needed to decrypt it is wrapped in the database, not in storage |
| KMS only | The KEK (ability to unwrap DEKs) | No — no wrapped DEKs and no encrypted data to apply it to |
| Database + KMS | Wrapped DEKs + KEK + encrypted field values | Yes for fields — the KEK unwraps the DEKs, which decrypt the field data; file content still requires file storage too |
| Database + KMS + file storage | Everything above plus encrypted file content | Yes — both fields and files |
| Application memory | Decrypted DEK for cached silos | Yes, for those silos — the tradeoff of in-process caching |

For a [`key_set="system"` column](system-wide-silos.md), read "settings" for
"KMS" in this table: the system silo's key encryption key is `ENV_KEY_STORES`, in your
settings. A stolen database alone is still unreadable, but there is no second
system to breach: reaching the running application is enough. See [Security model — System
keys](security.md#system-keys).

### Further reading

- [RFC 2315 — PKCS #7: Cryptographic Message Syntax](https://datatracker.ietf.org/doc/html/rfc2315) — the standard that named the **digital envelope**.
- [Why I Wrote PGP — Philip Zimmermann](https://www.philzimmermann.com/EN/essays/WhyIWrotePGP.html) — the author's own account of the motivation behind PGP.
- [Google Cloud KMS — Envelope encryption](https://cloud.google.com/kms/docs/envelope-encryption) — the DEK/KEK model in a cloud KMS.
- [AWS Encryption SDK — Concepts](https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/concepts.html) — envelope encryption and key wrapping.
- [Envelope Encryption in the Symmetric-Key Setting (IACR ePrint 2023/1727)](https://eprint.iacr.org/2023/1727) — a formal treatment.

---

## Envelope encryption in django-encryption-suite

### Writing an encrypted field

1. Your Django code assigns a value to an encrypted field (e.g.,
   `patient.national_id = "123-45-6789"`).
2. On save, the field's `pre_save` calls `engine.encrypt()`.
3. The engine resolves the current silo from the adapter (e.g., which
   team or tenant is active in this request).
4. The engine looks up the silo's AEAD primitive in the in-process cache.
   If the cache entry is missing or expired, it fetches the encrypted DEK
   from `DataEncryptionKey`, sends it to the KMS to be decrypted, builds
   an AEAD primitive from the decrypted DEK with the configured crypto
   backend, and caches it.
5. The AEAD primitive encrypts the plaintext value. When the field declares
   `aad=`, it binds the value to the model, the field name and those columns
   via AAD.
6. The ciphertext (prefixed with `~^Dv1:` and base64-encoded — see
   [Stored formats](#stored-formats)) is written to the database column.

### Reading an encrypted field

1. Django loads a row from the database. The ciphertext stays on the instance
   undecrypted, so iterating a queryset decrypts nothing.
2. The first read of the attribute calls `engine.decrypt()`, through the
   field's descriptor.
3. The engine resolves the current silo and obtains the AEAD primitive
   (from cache or via KMS decrypt, same as above).
4. The AEAD primitive decrypts the ciphertext, verifying the key and, where
   the field declares `aad=`, the AAD. A different
   silo's key fails authentication; with AAD columns declared, so does
   ciphertext moved to another field or row, or a bound column that changed.
5. The plaintext string is converted back to the field's native Python type.
6. The native value is returned to your Django code.

### Stored formats

A stored value says what it is in its own first characters, so nothing has to
guess:

```
~^Dv1:<base64 ciphertext>
```

Reading the parts:

| Part | Means |
|---|---|
| `~^D` | Encrypted under a data key: a silo's, or the [system silo's](system-wide-silos.md) for a `key_set="system"` column. The column's `key` says which; the marker does not. |
| `v` | The form, and the only one there is: a value. A [blind index](encrypted-data.md#finding-a-row-by-its-value) digest is stored in a column or a table of its own, never inside the value. |
| `1` | The version of the framing, not of the key. |

Two properties the rest of the package leans on:

- **A value without this shape is plaintext that has not been encrypted yet.**
  The shape is the marker, `v`, a version number and a colon; a value that
  starts with `~^D` alone is plaintext. Any version number counts, so a value
  in a later framing is never taken for plaintext.
  That is what lets an existing column be converted in place, and it is why
  `encrypt_field` can be re-run without encrypting anything twice.
- **A value read under the wrong silo's key fails authentication**, so a value
  copied between a `key_set="default"` and a `key_set="system"` column, or between two
  silos, never decrypts to something wrong. The same holds for a value copied
  between two key sets of one silo. Changing a column's `key_set`
  therefore means converting it, not just altering the field.

Nothing outside the package should read or write this prefix. `engine.py` exposes
the pair of functions that wrap and unwrap a value, and every path in the package
goes through them.

### Native type conversion

Each encrypted field type converts values to strings before encrypting, and
converts them back to native Python types after decrypting:

| Field | Write (Python → string → ciphertext) | Read (ciphertext → string → Python) |
|---|---|---|
| `EncryptedTextField` | `"Hello"` → encrypt → `~^Dv1:aBc...` | `~^Dv1:aBc...` → decrypt → `"Hello"` (`str`) |
| `EncryptedCharField` | `"Jane"` → encrypt → `~^Dv1:xYz...` | `~^Dv1:xYz...` → decrypt → `"Jane"` (`str`) |
| `EncryptedIntegerField` | `42` → `"42"` → encrypt → `~^Dv1:dEf...` | `~^Dv1:dEf...` → decrypt → `"42"` → `42` (`int`) |
| `EncryptedDateField` | `date(1990, 3, 15)` → `"1990-03-15"` → encrypt → `~^Dv1:gHi...` | `~^Dv1:gHi...` → decrypt → `"1990-03-15"` → `date(1990, 3, 15)` (`datetime.date`) |
| `EncryptedDateTimeField` | `datetime(...)` → `"2024-03-15T10:30:00+00:00"` → encrypt → `~^Dv1:jKl...` | `~^Dv1:jKl...` → decrypt → ISO string → `datetime(...)` (`datetime.datetime`) |
| `EncryptedEmailField` | `"j@example.com"` → encrypt → `~^Dv1:mNo...` | `~^Dv1:mNo...` → decrypt → `"j@example.com"` (`str`) |

By the time a value reaches your application code — templates, forms, date
pickers, DRF serializers, type annotations — it is a native Python object,
indistinguishable from a value read from an unencrypted field.  Encryption
and decryption happen entirely at the database boundary and are invisible
to the rest of your application.

### The role of the cache

The in-process cache (`DEK_CACHE_TTL`, default 300 seconds) stores the
decrypted AEAD primitive so that the KMS decrypt call does not happen on
every field access. For a system with 100 silos and a 5-minute TTL,
the engine makes at most 100 KMS calls every 5 minutes, regardless of how
many field accesses occur in that window.

The TTL is not a cryptographic expiration — the AEAD primitive works
indefinitely once decrypted. The TTL controls how often the engine checks
back with the KMS, which is the point where revoked or rotated keys are
detected. See [Key rotation](key-rotation.md) for details.

A primitive created by auto-provisioning is shared with the rest of the
process only once the transaction that wrote its `DataEncryptionKey` row
commits. The cache is an ordinary in-memory dictionary and is not rolled
back, so an entry published any earlier would outlive its key row — and the
next write in that process would encrypt against a key that exists nowhere,
because the cached entry satisfies the lookup that would otherwise have
provisioned a new one. The request that provisioned the key does use it
straight away: its own writes roll back alongside the key if it fails.

---

## Per-silo isolation

Each silo has its own DEK. Data encrypted under one silo's key
cannot be decrypted by another silo's key — the AEAD authentication
check will fail. This means:

- A missing query filter that returns rows from multiple silos produces
  ciphertext that can only be decrypted one silo at a time, with the
  correct silo context active.
- An IDOR vulnerability that leaks a row from another silo returns
  ciphertext that cannot be decrypted in the current context.
- A database dump contains encrypted values from all silos, each
  requiring its own KEK to decrypt its own DEK to decrypt.

The strength of this isolation depends on your tenancy model. See
[Security model](security.md) for a detailed comparison between schema-based
and row-based tenancy.

A silo's keys are further divided by [key set](#key-sets), which lets a few
columns sit on a different key store from the rest of the silo's data.

## Full picture

The same layers handle every encrypted column: a field, a silo adapter, the
crypto engine, a crypto backend, and a place that holds the wrapped data
encryption keys. Deployments differ in one respect: which system holds the **key encryption
key** (KEK). The two sections below draw that line:

- A **KMS key store** keeps the KEK in a remote key management service. The
  process asks the service to wrap and unwrap each data key, and the KEK never
  reaches the process.
- An **env key store** keeps the KEK in your settings. The process wraps and
  unwraps data keys itself, and nothing leaves the machine.

`KEY_SETS` chooses a store for each [key set](#key-sets), so
one deployment can use both: team data on a KMS and the columns a sign-in reads on
an env store. A field never names a store.

### With a KMS key store

The diagram below shows how django-encryption-suite's parts work together to use
a key management system, data silos, encryption backends, and custom field
types:

```
                       ┌──────────────────────────────────────────────┐
                       │  KMS Provider (GCP, AWS, Azure, Vault, …)    │
                       │   ┌───────┐  KEK never leaves the KMS;       │
                       │   │  KEK  │  wraps / unwraps the DEK         │
                       │   └───────┘  server-side only.               │
                       └──────────────────────────────────────────────┘
                                  ▲                  │
              provision KEK /     │                  │  unwrap DEK
              wrap DEK            │                  ▼
 ┌───────────────────────────────────────────────────────────────────────────────────┐
 │  Application Process  (in memory only)                                            │
 │                                                                                   │
 │   ┌──────────────────────────┐                                                    │
 │   │  Encrypted model fields  │   EncryptedField / EncryptedFileField              │
 │   │  & files                 │   (Django save / load)                             │
 │   └──────────────────────────┘                                                    │
 │                      ▲                                                            │
 │                      │                                                            │
 │   fields: encrypt() / decrypt()                                                   │
 │   files:  encrypt_file() / decrypt_file()                                         │
 │                      │                                                            │
 │                      ▼                                                            │
 │  ┌───────────┐  ┌────────────────────────────┐  build    ┌──────────────────────┐ │
 │  │  Silo     │  │  Crypto Engine             │ ───────►  │  Crypto Backend      │ │
 │  │  adapter  │─►│  · current silo → uid      │ primitive │  tink / cryptography │ │
 │  │           │  │  · DEK cache (TTL)         │           │  ┌───────────────┐   │ │
 │  │ resolves  │  │  · call KMS adapter        │ ◄───────  │  │ Decrypted DEK │   │ │
 │  │ active    │  │  · read/write wrapped DEK  │ run AEAD  │  │ · AEAD fields │   │ │
 │  │ silo      │  │    + encrypted values/files│           │  │ · Stream files│   │ │
 │  └───────────┘  └────────────────────────────┘           │  └───────────────┘   │ │
 │                          ▲         ▲                     └──────────────────────┘ │
 └──────────────────────────┼─────────┼──────────────────────────────────────────────┘
                            │         │
   wrapped DEKs +           │         └─── encrypted file content ──────────┐
   ciphertext + digests     ▼                                               ▼
   ┌──────────────────────────────────────────┐   ┌─────────────────────────────────┐
   │  Your Database                           │   │  Your File Storage              │
   │  DataEncryptionKey, per silo and key set:│   │  (S3, disk, …)                  │
   │   • wrapped DEK — fields                 │   │   • encrypted file content      │
   │   • wrapped DEK — files                  │   │     (written in segments)       │
   │   • wrapped DEK — blind index            │   │                                 │
   │  Application rows:                       │   │                                 │
   │   • encrypted field values               │   │                                 │
   │   • blind index digests (keyed hashes)   │   │                                 │
   │   • encrypted file display name          │   │   Opaque object keys — no       │
   │   • opaque file storage path  ───────────┼──►│   real filename in listings.    │
   └──────────────────────────────────────────┘   └─────────────────────────────────┘
```

A silo's blind index key is a third `DataEncryptionKey` purpose beside field and
file, wrapped by the same KEK — so destroying the KEK destroys the digests along
with the data, and a reader of the database cannot test a guess against them.
See [Finding a row by its value](encrypted-data.md#finding-a-row-by-its-value).

**Files.** An `EncryptedFileField` streams the file through the file data key and
writes only the encrypted file to your storage, under opaque names in
`encryption_suite_<key_set>/`. The display name is an encrypted column beside it, so
a bucket listing shows neither the content nor the original filename.

**Application processes.** Every process that touches an encrypted column — web
workers, Celery workers, management commands, a shell — runs the same engine and
holds its own cache of unwrapped data keys. A process reads the wrapped key from
your database, asks the KMS to unwrap it, and keeps the result in memory for
[`DEK_CACHE_TTL`](configuration.md#dek_cache_ttl) seconds. Nothing is shared
between processes, and no unwrapped key is written anywhere. So:

- A KMS outage stops a process only when it needs a key it has not cached. A recent
  failure is remembered for a short time, so one dead endpoint is not retried by
  every field on a page.
- The application's credentials to the KMS decide what a compromised process can
  do, and the KMS's own audit log records every unwrap.
- With one KEK per silo, deleting that KEK at the provider destroys the silo's
  data for good, backups included.

An attacker needs both the database and the right to ask the KMS to unwrap keys. A
stolen database, dump or bucket alone is unreadable.

### With an env key store

An env key store keeps the KEK in your settings and does the wrapping inside the
process. Use it where a KMS would be in the way or out of reach: the columns a
sign-in reads, which must not depend on any team's KMS, development, tests, and a
deployment that wants no external service. The `system` key set (declared with
[`key_set="system"`](system-wide-silos.md)) uses one by default: a user's
email address and avatar belong to the user, not to a team, so they sit in a silo
of their own with the same three data keys (field, file and blind index) on
rows of `DataEncryptionKey` whose silo uid is `system`. The `system` key set is a key set
like `default`, with one silo.

Everything in the KMS picture applies, with these differences. The KEK comes from
`ENV_KEY_STORES` in your settings, by version. The process wraps and unwraps data
keys itself with AES-256-GCM, so no call leaves the machine. The `system` key set
uses the built-in system silo adapter. And a team silo placed on an env store still has its own
data keys, but every silo under it shares the one KEK.

```
                       ┌──────────────────────────────────────────────┐
                       │  Your Settings  (ENCRYPTION)                 │
                       │   ┌───────┐  ENV_KEY_STORES holds the KEK,   │
                       │   │  KEK  │  by version. It never reaches    │
                       │   └───────┘  the database or the storage.    │
                       └──────────────────────────────────────────────┘
                                                     │
                                                     │  read in process memory,
                                                     ▼  no call off the machine
 ┌───────────────────────────────────────────────────────────────────────────────────┐
 │  Application Process  (KEK and DEKs in memory only)                               │
 │                                                                                   │
 │   ┌──────────────────────────┐                                                    │
 │   │  Encrypted model fields  │   EncryptedField / EncryptedFileField              │
 │   │  & files                 │   (Django save / load)                             │
 │   └──────────────────────────┘                                                    │
 │                      ▲                                                            │
 │                      │                                                            │
 │   fields: encrypt() / decrypt()                                                   │
 │   files:  encrypt_file() / decrypt_file()                                         │
 │                      │                                                            │
 │                      ▼                                                            │
 │  ┌───────────┐  ┌────────────────────────────┐  build    ┌──────────────────────┐ │
 │  │  Silo     │  │  Crypto Engine             │ ───────►  │  Crypto Backend      │ │
 │  │  adapter  │─►│  · current silo → uid      │ primitive │  tink / cryptography │ │
 │  │           │  │  · DEK cache (TTL)         │           │  ┌───────────────┐   │ │
 │  │ resolves  │  │  · wrap/unwrap (env KEK)   │ ◄───────  │  │ Decrypted DEK │   │ │
 │  │ active    │  │  · read/write wrapped DEK  │ run AEAD  │  │ · AEAD fields │   │ │
 │  │ silo      │  │    + encrypted values/files│           │  │ · Stream files│   │ │
 │  └───────────┘  └────────────────────────────┘           │  └───────────────┘   │ │
 │                          ▲         ▲                     └──────────────────────┘ │
 └──────────────────────────┼─────────┼──────────────────────────────────────────────┘
                            │         │
   wrapped DEKs +           │         └─── encrypted file content ──────────┐
   ciphertext + digests     ▼                                               ▼
   ┌──────────────────────────────────────────┐   ┌─────────────────────────────────┐
   │  Your Database                           │   │  Your File Storage              │
   │  DataEncryptionKey, per silo and key set:│   │  (S3, disk, …)                  │
   │   • wrapped DEK — fields                 │   │   • encrypted file content      │
   │   • wrapped DEK — files                  │   │     (written in segments)       │
   │   • wrapped DEK — blind index            │   │                                 │
   │  Application rows:                       │   │                                 │
   │   • encrypted field values               │   │                                 │
   │   • blind index digests (keyed hashes)   │   │                                 │
   │   • encrypted file display name          │   │   Opaque object keys — no       │
   │   • opaque file storage path  ───────────┼──►│   real filename in listings.    │
   └──────────────────────────────────────────┘   └─────────────────────────────────┘
```

**Files.** They follow the same path as under a KMS: streamed through the file data
key, written encrypted to the same storage, with the display name encrypted
beside the opaque path. The `system` key set's files go under
`encryption_suite_system/`, a sibling of the default key set's `encryption_suite_default/`, so
a lifecycle rule or permission scope can select either on its own.

**Application processes.** Every process that decrypts must carry the same
`ENV_KEY_STORES` in its settings: web workers, Celery workers, scheduled commands
and a shell alike. A process with a missing or older version cannot unwrap the keys
it needs. Each still caches its own unwrapped data keys for
[`DEK_CACHE_TTL`](configuration.md#dek_cache_ttl) seconds. So:

- Nothing is unavailable because a remote service is, which is why sign-in survives
  a KMS outage or a missing KMS setting.
- A new KEK version is a rollout: add the version beside the current one, deploy it
  to every process, run `reencrypt_keys`, then drop the old version. Drop it earlier
  and a row that still records it cannot be unwrapped.
- There is no provider access policy, audit log or HSM, and nothing outside this
  application can restore the key. Back it up wherever you back up your other
  secrets.

An attacker needs both the database and your settings. An attacker who reaches the
running application, or reads its settings, has `ENV_KEY_STORES`, because the
application must. A stolen database, backup, dump or bucket alone is still
unreadable.

### Key sets

A **key set** is one silo adapter and one key store, and it holds one set of keys
per silo: a field key, a file key and, where a field declares a blind index, an
index key. A field names its key set with `key_set`; fields in the same key set share
its keys, and a field that names none is in `default`. A silo then holds one data key
per purpose **per key set**, and each key set's keys have their own rows in
`DataEncryptionKey`. Key sets bound to one adapter share its silos.

The field says only which key set its data belongs to. `KEY_SETS` says which adapter
resolves the silo and where the keys live, so any key set can sit on a KMS store or
an env store. A key set can also be bound to the user adapter, which gives each user their own keys:
see [User-specific silos](user-specific-silos.md). Key sets say nothing about file storage: the field's `storage=` (or the
`STORAGE_ALIAS` default) decides which bucket holds a file, and the two choices are
independent.

```python
# models.py
class Patient(models.Model):
    # The default key set, on its store. The file uses the STORAGE_ALIAS storage.
    notes = EncryptedTextField()
    photo = EncryptedFileField(display_name_field="photo_name", null=True, blank=True)
    photo_name = EncryptedCharField(max_length=255, null=True, blank=True)

    # The "restricted" key set: keys on a stricter KMS, and the file in its own bucket.
    scan = EncryptedFileField(
        key_set="restricted",
        display_name_field="scan_name",
        storage=EncryptedRestrictedStorage(bucket_name="restricted-scans"),
        null=True,
        blank=True,
    )
    scan_name = EncryptedCharField(key_set="restricted", max_length=255, null=True, blank=True)


class Profile(models.Model):
    # The system key set: no team in context, and keys on an env store.
    email = EncryptedEmailField(key_set="system", blind_index=True, normalize="casefold")


# settings.py
ENCRYPTION = {
    "KMS_KEY_STORES": {"aws": {...}, "hsm": {...}},
    "ENV_KEY_STORES": {"login": {"KEKS": {1: env("ENC_LOGIN_KEK")}}},
    "KEY_SETS": {
        "default": {"silo": "yourapp.encryption.TeamSiloAdapter", "key_store": "aws"},
        "restricted": {"silo": "yourapp.encryption.TeamSiloAdapter", "key_store": "hsm"},
        "system": {"key_store": "login"},  # no silo: the system key set always uses the system silo
    },
}
```

In the example above, `EncryptedRestrictedStorage` is a storage class you write: your
storage backend (S3, say) with `SiloEncryptedStorageMixin` in front of it, as in
[Advanced: storage class composition](managing-encrypted-files.md#advanced-storage-class-composition).
A field needs one to use a bucket of its own, because a field's `storage=` must encrypt
what it writes and the default `STORAGES` alias gives you only one pool. A plain
backend there would store the file unencrypted, which `manage.py check` refuses
([`E036`](configuration.md#system-checks)). The class changes which bucket holds the
file; the key set still chooses the keys.

```
   Fields                 Key set                KEY_SETS gives
   ┌──────────────────┐   ┌────────────────┐
   │ notes, photo     │──►│ default        │──► aws    (KMS store)
   │ scan             │──►│ restricted     │──► hsm    (KMS store)
   │ email            │──►│ system         │──► login  (env store)
   └──────────────────┘   └────────────────┘
```

Two rules keep a set coherent. A file field and its display-name companion must name
the same set, so one key reads both ([`E024`](configuration.md#system-checks)). And
every key set a field uses needs an entry in `KEY_SETS`, which `manage.py check`
enforces ([`E041`](configuration.md#system-checks) for the name,
[`E038`](configuration.md#system-checks) for its store).

**Swapping a set's store.** Moving a set from one store to another is a settings
change and one command:

1. Point the key set at the new store in `KEY_SETS` (`"key_store": "aws"`) and
   deploy. New keys go to the new store. Existing rows keep reading through the
   store they recorded.
2. Run `python manage.py reencrypt_keys`. It makes one pass per key set, unwraps each
   row through the store the row records, and wraps it under the store the settings
   now give its set. Only that set's rows move, and no application data is touched.
3. Read a value written before the move, then retire the old store as
   [Moving to another KMS](key-rotation.md#moving-to-another-kms) describes.

The swap moves where a set's keys are wrapped. It does not change which set a
field belongs to: pointing a field at another `key_set` points it at different keys,
so its existing values fail to authenticate until the column is converted with
`decrypt_field` and `encrypt_field`. See
[Adopting and removing encryption](adopting-and-removing-encryption.md).

---

## Further reading

- [Getting started](getting-started.md) — install the package and configure
  your first encrypted field
- [KMS adapters](kms-adapters.md) — choose and configure your KMS provider
- [Silo adapters](silo-adapters.md) — configure how silos
  are resolved
- [Adopting and removing encryption](adopting-and-removing-encryption.md) — migrating existing data
- [Key rotation](key-rotation.md) — rotate KEKs and re-encrypt DEKs
- [Security model](security.md) — threat model and isolation guarantees
- [Auditing](auditing.md) — the two records the package keeps, and which one to read
- [Glossary](glossary.md) — definitions of the acronyms and terms used across the docs
