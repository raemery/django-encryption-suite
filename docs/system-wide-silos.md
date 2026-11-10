# System-wide silos

The `system` key set holds data that belongs to the whole system rather than to a
group of users. It has exactly one silo, the **system-wide silo**, and a column joins
it with `key_set="system"`.

A silo is a group of data that shares key isolation, and a key set binds a silo
adapter to a key store. A field's `key_set` names its key set. The default key set,
`default`, is bound to the adapter for the groups of users your project defines,
such as teams or tenants. Each of those silos has its own data keys, and the engine
resolves the current silo, unwraps its data encryption key, and refuses when none is
active. The `system` key set is built in and bound to the system adapter. Its single
silo needs no resolving, so a read or write works with no team or user in context.

Three kinds of data belong in the system-wide silo:

- **Data no group of users owns.** A user's email address and username belong to the
  user, not to a team.
- **Data read across every team at once.** A team's own name appears in
  lists that span teams, which under each team's key would cost one key per team
  per page.
- **Data created before any team exists.** A public form is filled in before any
  team exists, and may be copied into one later.

One requirement shapes the rest: **signing in must not depend on a team's KMS.** The
admin test console is how an operator gets a KMS working, and reaching it needs a
login. If the columns a login reads were encrypted under a team's silo, a
misconfigured KMS would lock everybody out of the screen that diagnoses it.

The system-wide silo therefore takes its keys from a store of its own choosing. The
package wraps them under the key store that
[`KEY_SETS`](configuration.md#key_sets) gives the `system` key set, and an
[env key store](configuration.md#env_key_stores) is the usual choice. That store makes
no call off the machine: its one key encryption key is in
[`ENV_KEY_STORES`](configuration.md#env_key_stores), in your settings. This page calls
a column declared with `key_set="system"` a system column.

## Protection scope

A lost or stolen database, backup or dump is unreadable, and so is anything read
out through SQL injection. An attacker who reaches the running application, or
reads its settings, has `ENV_KEY_STORES`, because the application must. That is the
same bargain as any at-rest encryption whose key the process holds — see
[Security model](security.md#system-keys).

## Declaring a system column

Every encrypted field type takes `key_set`, the key set whose keys encrypt the
column: `"default"`, the default, `"system"`, or a key set your project declares in
[`KEY_SETS`](configuration.md#key_sets). The store that wraps a system column's keys
comes from `KEY_SETS`, not from the field. Point the `system` key set at an env
store, `"system": {"key_store": "login"}`, so its keys do not wait on a KMS.

A project can declare further system key sets with `"silo": "system"`, for
example `"directory": {"silo": "system", "key_store": "kms"}`. They share the one
system silo but keep their own keys, so data meant to be readable outside any team
can sit on a KMS store while the sign-in columns stay on the env store.

```python
from encryption_suite.fields import EncryptedCharField, EncryptedEmailField


class CustomUser(AbstractUser):
    email = EncryptedEmailField(key_set="system", blank=True, blind_index=True, normalize="casefold")
    username = EncryptedCharField(
        key_set="system", max_length=150, unique=True, blind_index=True, normalize="casefold"
    )
```

A `key_set="system"` column has the same lazy decryption, the same lenient fallback,
the same [row-identity binding](security.md#row-identity-binding-optional) and the
same database passthroughs as a column in a team key set. What differs:

- **No silo to resolve.** A read or write needs no team in the context, because
  the system silo is the only silo, so a model
  whose encrypted columns are all `key_set="system"` needs no `EncryptionAdminMixin`
  in the admin.
- **Uniqueness is `unique=True`.** The column has one key for the whole table,
  so `unique=True` holds the value unique across it, and `unique_in_silo` is
  refused ([`E026`](configuration.md#system-checks)).
- **`""` is an ordinary value** (see [Empty values](#empty-values-and-short-values)).

A `key_set` that `KEY_SETS` does not declare, or that is not a valid name, fails
`manage.py check` with [`E041`](configuration.md#system-checks).

**Changing `key_set` moves no data.** The `AlterField` that Django generates for
it changes nothing in the column, and a value written under one key set's key fails
authentication under another's. Convert the column instead: decrypt it with
`decrypt_field` under the old `key_set`, change the field, encrypt it with
`encrypt_field` under the new one (see
[Adopting and removing encryption](adopting-and-removing-encryption.md)).

### Files

`EncryptedFileField(key_set="system")` is [`EncryptedFileField`](managing-encrypted-files.md)
under the system silo's file key: the same opaque stored names, the same
display-name companion, the same cleanup on replace and delete, the same download
helper. The companion must be a `key_set="system"` column too, since a silo-encrypted
name would need a silo to read ([`E024`](configuration.md#system-checks)):

```python
from encryption_suite.fields import EncryptedCharField, EncryptedFileField


class Profile(models.Model):
    avatar = EncryptedFileField(key_set="system", display_name_field="avatar_name", null=True, blank=True)
    avatar_name = EncryptedCharField(key_set="system", max_length=255, null=True, blank=True)
```

It writes through the same storage as the silo files, the
[`STORAGE_ALIAS`](configuration.md#storage_alias) entry in `STORAGES`, and stores
under `encryption_suite_system/` by default rather than the silo files'
`encryption_suite/`. The two folders are siblings, not nested, so a lifecycle
rule, permission scope or backup filter can select either one on its own: each
reads with a different key. `upload_to` moves it, as for any file field — see
[Customizing the storage path prefix](managing-encrypted-files.md#customizing-the-storage-path-prefix).

A system file sits under the system silo, not a team's, so deleting a team's
silo does not touch it; the file goes with its row.

Reading a system file through its field works anywhere. Opening it by name with a
direct `storage.open(name)` needs a storage class that sets `key_set = "system"`; see
[Opening a file by name](managing-encrypted-files.md#opening-a-file-by-name).

## Keys

The system silo has the same three data keys as any silo — field, file and blind
index — on rows of `DataEncryptionKey` whose silo uid is `system`, each wrapped by
the system store's key encryption key. On an env store that key is named `shared`
unless the entry's `SHARED_KEK_ID` says otherwise. The package makes all three at once,
used or not: on the first write or lookup of a `key_set="system"` column, or when
`setup_encryption_keys` runs, whatever
[`KEY_AUTO_PROVISION`](configuration.md#key_auto_provision) says. Nothing else
would create them, since no model's creation signals the system silo.

Two settings choose where they live. `ENV_KEY_STORES` holds 32 random bytes per
version, base64 encoded, and `KEY_SETS` gives the `system` key set that store:

```python
ENCRYPTION = {
    "ENV_KEY_STORES": {"login": {"KEKS": {1: env("ENC_SYSTEM_KEK")}}},  # openssl rand -base64 32
    # No silo: the system key set always uses the system silo.
    "KEY_SETS": {"system": {"key_store": "login"}},
}
```

With one store configured, the `system` key set needs no entry. With a KMS store
beside it, the entry is required.

The system silo's keys follow [`CRYPTO_BACKEND`](configuration.md#crypto_backend-and-crypto_backend_options)
and its options, like every silo's; the blind index key is an HMAC-SHA-256 key
whatever the backend. A later backend switch moves them with
`reencrypt_data --key-set system` — see
[Switching backends](crypto-backends.md#switching-backends). Keep the backend's
dependency installed: with login columns under `key_set="system"`, a backend that
fails to load blocks sign-in, not only team data.

The keys stay in place for good. The deletion gates refuse every system key, and
manual key records refuse them too: no KMS outside this application holds them.

Rotation is in [Key rotation](key-rotation.md#rotating-a-system-key).

## Looking a value up

`blind_index=True` on a `key_set="system"` column works as on any encrypted column.
[Finding a row by its value](encrypted-data.md#finding-a-row-by-its-value) covers
the lookups it answers and refuses, `normalize="casefold"`, what it discloses,
where the digest goes, and the code that reads `field.unique`. The system silo's
index key changes two things:

- **Uniqueness is table-wide.** One key covers the whole table, so `unique=True`
  holds the plaintext unique across it. It needs `blind_index=True`, as any
  uniqueness rule over ciphertext does ([`E026`](configuration.md#system-checks)).
- **Anyone holding the settings can compute a digest.** A reader of the database
  who also has `ENV_KEY_STORES` can test a guess, and the package never deletes the
  system silo's keys, so the digests last as long as their rows. See
  [Blind index leakage](security.md#blind-index-leakage).

## Empty values and short values

`""` is an ordinary value: saved through the model it is encrypted like any other,
so `blank=True` needs no `null=True` here and check
[`E025`](configuration.md#system-checks) does not apply. That is what lets a column
keep holding `""` where some other library writes one.

A very short value is safe to encrypt — every write uses a fresh nonce, so two
rows holding `"a"` have unrelated ciphertext. What a stored value does reveal is
its **length**, since ciphertext length tracks plaintext length. That holds for
silo columns too.

## Failed reads

A failed read behaves as it does on a silo column: lenient mode returns a fallback label,
recorded on `instance.encryption_suite_errors`, and [strict mode](handling-errors.md)
raises an exception. An `EncryptedJSONField` hands back an **empty dict**, under either
`key`. See [Handling errors](handling-errors.md).

## Deploy-time checks

A model declaring a `key_set="system"` column while no store resolves for the
`system` key set fails `manage.py check` with [`E038`](configuration.md#system-checks).
Without a store nothing could wrap the system silo's keys, and every user's
sign-in is under them. `E038` is not downgradeable by
[`STARTUP_CHECK_WARN_ONLY`](configuration.md#startup_check_warn_only): that
setting exists so a deploy can proceed and someone can watch the failure at
request time, and without the key nobody can sign in to watch it.

When `KEY_SETS` gives the `system` key set a KMS store, `manage.py check`
warns with [`W058`](configuration.md#system-checks): sign-in would stop working
when that KMS is unreachable.

A project that declares no `key_set="system"` column gets no check.

## The package's own: recorded addresses and OS accounts

The [key lifecycle record](key-lifecycle-events.md) keeps the address an act came
from and the operating-system account behind a command in two tables of its own,
each with a plaintext column and a `key_set="system"` one, blind-indexed. Which column
a value goes to is [`USER_IDENTITY`](configuration.md#user_identity)'s
`KEY_LIFECYCLE_EVENTS` list: `encrypted_ip_address` and `encrypted_os_user` select
the encrypted one.

Every install has those tables, so the checks count them only while an `encrypted_*`
item is listed ([`E040`](configuration.md#system-checks) when the `system` key set has
no store): a deployment that never encrypts them needs no store for them.

The system silo's first key events carry the encrypted identity too: the package
creates all three keys before it writes any of their events. A value that cannot
be encrypted — `ENV_KEY_STORES` changed under existing keys, say — leaves that one
item out of the record with a warning, and the act still records.

`reencrypt_data --key-set system` moves their encrypted values onto a new data key
like any other system column. It never converts a value between the plaintext
and the encrypted column: a change of form applies to later events only.

## Adopting a column that already holds plaintext

`encrypt_field` converts it from a `RunPython` migration, and `decrypt_field`
backs it out. For a `key_set="system"` column neither takes silo arguments, and
`encrypt_field` writes each row's blind index digest with its value. See
[Adopting and removing encryption](adopting-and-removing-encryption.md#adopting-a-system-encrypted-column).

Ship the conversion in the same migration as the column change, not in a command
afterwards. An unconverted row still *reads*, because a value with no marker
comes back as it stands — but nobody can *find* it, since a lookup matches the
blind index and a plaintext row has none. The gap between the two would be a gap
in which nobody can sign in.

## Related

- [Configuration reference](configuration.md#env_key_stores) — the env key store and `ENV_KEY_STORES`
- [Key rotation](key-rotation.md#rotating-a-system-key) — rotating the system silo's keys, and why its risk profile differs
- [`reencrypt_data`](management-commands.md#reencrypt_data) and [`reencrypt_keys`](management-commands.md#reencrypt_keys) — `--key-set system`
- [Core concepts](concepts.md#stored-formats) — what a stored value looks like
- [Security model](security.md#system-keys) — the threat model, and the equality disclosure
- [Working with django-allauth](working-with-django-allauth.md) — its MFA secrets, and the columns that stay in plaintext
