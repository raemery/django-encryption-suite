# Management Commands

| Command | Purpose |
|---|---|
| [`setup_encryption_keys`](#setup_encryption_keys) | Provision a DEK for every silo that lacks one. |
| [`reencrypt_keys`](#reencrypt_keys) | Re-wrap stored keysets under the current KEK after a KMS rotation. |
| [`reencrypt_data`](#reencrypt_data) | Rotate data encryption keys: re-encrypt each silo's fields and files under new key material, recompute its blind index digests, then swap it in. `--check` instead reports indexed values holding no digest. |
| [`reconcile_keys`](#reconcile_keys) | Compare stored key records against live silos and the KMS. Safe to schedule. |
| [`record_key_event`](#record_key_event) | Record a key encryption key act performed outside the application. |
| [`crypto_inventory`](#crypto_inventory) | Report the key stores, keys, backends and algorithms in use. Read-only. |
| [`encryption_suite_rotate_hashicorp_approle`](#encryption_suite_rotate_hashicorp_approle) | Issue a fresh HashiCorp Vault AppRole `secret_id`. HashiCorp only. |

Every command the package ships logs one WARNING line as it starts: the command,
the options that say what it was pointed at, and who ran it. A run leaves that
trace even when it changes nothing, and the line never carries a secret. It goes
wherever the process's output goes — in an interactive shell that is the
terminal, not the platform's log stream; see
[Auditing someone with a shell](security.md#auditing-someone-with-a-shell).

## Scheduling and collecting output

`crypto_inventory`, `reconcile_keys`, `reencrypt_keys` and `reencrypt_data` take
`--format json` and `--output FILENAME` to hand a JSON report to another tool.
[Command output](scheduled-tasks.md#command-output) describes the report, each
command's exit status, and where the log lines go.

---

## `setup_encryption_keys`

This command generates and stores a `DataEncryptionKey` for every silo that
does not yet have one. For each silo, this command:

1. Generates a new data encryption key (DEK) via the configured crypto backend
   (see [Crypto backends](crypto-backends.md))
2. Encrypts (wraps) it via the store [`KEY_SETS`](configuration.md#key_sets) gives the key set
3. Stores the wrapped key in `DataEncryptionKey`

A silo gets keys for every [key set](configuration.md#key_sets) that fields
declare on its adapter, which is `default` alone for a project that sets no `key_set`.

Run this once after initial deployment, and again whenever new silos are
bulk-imported outside of the normal creation flow (which would trigger
`SILO_AUTO_KEY_CREATION`).

Where the deployment needs the [system silo's keys](system-wide-silos.md#keys)
— a model declares a `key_set="system"` column, or `USER_IDENTITY` lists an
`encrypted_*` item — it creates those first, all three at once, so every silo key
event after them can encrypt the operator's identity under them.

### Basic usage

```bash
# Auto-detect silos from the configured adapter
python manage.py setup_encryption_keys

# Preview what would be created without contacting KMS
python manage.py setup_encryption_keys --dry-run
```

### Specifying the silo model

For `DjangoTenantsSiloAdapter` and `PegasusTeamSiloAdapter`, the
model is detected automatically. For `GenericModelSiloAdapter` with a
`model_label` set, it is also detected automatically. In other cases, pass it
explicitly:

```bash
python manage.py setup_encryption_keys --silo-model myapp.Organization
```

### Options

| Option | Description |
|---|---|
| `--silo-model app.Model` | Dotted model path to iterate over. Auto-detected for built-in adapters. |
| `--key-set name` | Provision only this key set's keys. Without it every key set that a field declares is provisioned, the system key sets first. |
| `--dry-run` | Print what would be created without contacting KMS or writing to the database. |

### Notes

- `--key-set user` provisions the keys of a [user-specific key set](user-specific-silos.md), once a field declares it,
  for every user. A run with no `--key-set` includes it like any declared key set, and
  it makes up to three keys for each user, so use `--dry-run` first on a large user table.
- Silos that already have a `DataEncryptionKey` are skipped.
- The command is idempotent — safe to run multiple times.
- For django-tenants, this depends on [where the package
  sits](django-tenants.md#schema-placement). With `encryption_suite` in
  `TENANT_APPS`, each tenant has its own key tables, so run it once per tenant
  through django-tenants' wrapper — `python manage.py tenant_command
  setup_encryption_keys --schema=acme` — and each run creates only that tenant's
  keys. With the package in `SHARED_APPS`, run it plainly: it lists every tenant
  and writes their keys to the package's tables in `public`.

---

## `reencrypt_keys`

`reencrypt_keys` re-encrypts stored keysets under
the store [`KEY_SETS`](configuration.md#key_sets) gives their key set, and its current KEK. Use it after rotating the Key Encryption Key (KEK) in your KMS
provider, after adding a [`ENV_KEY_STORES`](configuration.md#env_key_stores) version, or
after pointing `KEY_SETS` at another KMS.

Each row is unwrapped through the [`KMS_KEY_STORES`](configuration.md#kms_key_stores)
block it records and re-wrapped under the store of its key set. When the two differ, the run
moves the row to the new key store, and its output says so on a `Converting: key store …
-> …` line. A pass runs per key set that fields declare, and moves only
that key set's keys, so key sets on different stores move the one you
repointed. See [Moving to another KMS](key-rotation.md#moving-to-another-kms).

During re-encryption, the plaintext keyset exists in memory only briefly — it
is never written to disk. The new wrap replaces the only wrapped copy of the
data key, so before anything is saved the command unwraps it with the key name
and version that will be recorded, and requires the same key back. A wrap that
fails this check is not saved: the row keeps its old wrap, is reported as
failed, and its data stays readable. Each record is updated in its own database
transaction, so a failure on one silo does not roll back
already-completed work. A run that fails any record still tries the rest, then
exits non-zero.

### Basic usage

```bash
# Re-encrypt all silos
python manage.py reencrypt_keys

# Re-encrypt a single silo
python manage.py reencrypt_keys --silo-uid "tenant-acme"

# Preview which records would be re-encrypted without contacting KMS
python manage.py reencrypt_keys --dry-run

# Create each silo's new key first, for a name-rollover rotation 
# WARNING: this is work-round, not for use with most KMS providers
python manage.py reencrypt_keys --provision
```

### Options

| Option | Description |
|---|---|
| `--key-set default\|system\|all` | Which key set's keys to re-wrap: `default` (the default), `system` (onto the highest `ENV_KEY_STORES` version), another key set declared in `KEY_SETS`, or `all`, one pass per key set. Each is re-wrapped onto the store `KEY_SETS` gives it. |
| `--silo-uid uid` | Only re-encrypt the record with this UID. Re-encrypts all if omitted. |
| `--dry-run` | Print which records would be re-encrypted without contacting KMS. |
| `--provision` | Create each silo's key encryption key on its key set's store before re-wrapping onto it — for a name-rollover rotation, or a move to a KMS that does not hold the keys yet. Refuses the run if `KEK_TEMPLATE`'s owner prefix (text *before* {silo_uid}, not text *after*) changed. |
| `--format text\|json`, `--output FILENAME` | Write a JSON report of each pass's counts. See [Command output](scheduled-tasks.md#command-output). |

### Timing

- After rotating a KEK in your KMS provider (GCP key version, AWS key rotation,
  Azure key version, HashiCorp Vault key rotation)
- After adding a new `ENV_KEY_STORES` version, before dropping the old one
- After pointing `KEY_SETS` at another KMS
- As part of a regular key hygiene schedule

### `--provision`

Without this flag the command only re-wraps. That is all an in-place rotation
needs — the key keeps its name, so it already exists.

`--provision` is for the [name
rollover](key-rotation.md#name-rollover)
used by providers that cannot rotate key material behind a stable name: you point
`KEK_TEMPLATE` at a new generation, and the keys under the new names do not exist
yet. The command drives the KMS adapter directly, so the provisioner is otherwise
not in its path at all and every wrap would fail.

It creates one key per silo — a silo's field and file records resolve to the same
name, and rows whose resolved name still matches the key they are wrapped by are
left alone.

Before creating anything it checks that every key it is about to roll off still
carries the configured owner prefix, and refuses the whole run if not. Moving that
prefix would leave the previous generation unowned: still on the provider, still
billable, no longer listed by reconcile and no longer deletable from the admin.
Put the generation marker after `{silo_uid}` — `kms_{silo_uid}_v2`, not
`kms_v2_{silo_uid}`. The check is skipped, with a warning, on configurations that
derive no prefix at all (`KEK_MAP`-only and shared setups), where key names are
opaque and the hazard cannot arise.

`--dry-run` evaluates the same check and lists the key names that would be
created, contacting no KMS. Since nothing has been created at that point,
reverting `KEK_TEMPLATE` after a refusal restores the previous state exactly.

`--provision` also serves a move to another KMS whose block has a provisioner:
it creates each silo's key encryption key on the key set's store first, then each row is
unwrapped through the block it records and re-wrapped there. A row whose
recorded KMS no block configures is skipped and named. See
[Moving to another KMS](key-rotation.md#moving-to-another-kms) and
[re-encrypted keys](key-rotation.md#re-encrypted-keys).

### Notes

- A row whose recorded KMS no block configures is skipped and named, with a hint
  explaining the usual cause: a run under the wrong settings module.
- Re-encryption does not change the underlying data encryption key (DEK) or
  re-encrypt any field data. Only the envelope around the DEK changes. Replacing
  the DEK itself is [`reencrypt_data`](#reencrypt_data).
- Test-console keys are passed over, as they are by the deletion connector and by
  orphan detection. Their DEK protects a fixed throwaway payload and the console
  recreates it on demand, so re-wrapping one preserves a key nobody needs. They
  are excluded from the query rather than skipped inside it, so they appear in no
  count — a run on a deployment whose only other keys are console keys reports
  `Skipped: 0`, not `Skipped: 2`.
- The in-process Aead cache is invalidated for each silo after its
  keyset is successfully re-encrypted, so the next field access fetches the
  updated keyset.
- Failed records are logged to stderr and counted in the summary. Previously
  re-encrypted records in the same run are not rolled back on a later failure.
- `reencryption_count` is incremented on each successful re-encryption for audit
  purposes. A data key rotation's swap increments it too, and a re-wrap that
  unwrapped the key just before a swap replaced it sees the count move and skips
  the row rather than overwriting the new key with the old one.
- A data key under rotation (`reencrypting`) is re-wrapped like an active one,
  together with the incoming key its rotation holds — the dry run says so on that
  row.

---

## `reencrypt_data`

`reencrypt_data` rotates data encryption keys. For each silo, and each purpose in
turn — fields, then files — it generates new key material, re-encrypts every encrypted field or
file the silo holds under it, and then swaps the new material in as the silo's
key. See [Rotating a data encryption key](key-rotation.md#rotating-a-data-encryption-key)
for the overview; this section is the reference.

The new material comes from the current `CRYPTO_BACKEND` and its options, so a
rotation also moves a silo whose key was made under another backend or algorithm.
The opening log line (`converts=`) and a `Converting:` line name each move, and
the dry run marks each affected key the same way:

```
Converting: backend tink -> cryptography, algorithm AES256_GCM_HKDF_4KB -> AES256_GCM_STREAM
Converting: algorithm AES256_GCM -> CHACHA20_POLY1305
```

Distinct moves are separated by `; `. A key that recorded no algorithm shows
`algorithm unrecorded -> …`. See
[Switching backends](crypto-backends.md#switching-backends).

```bash
# Preview: silos, models, row counts, the idle wait. Fences nothing, writes nothing, calls no KMS.
python manage.py reencrypt_data --dry-run

# Rotate one silo: fields, then files, then blind indexes
python manage.py reencrypt_data --silo-uid "team-42"

# Rotate only the silo's blind index key, leaving its data where it is
python manage.py reencrypt_data --silo-uid "team-42" --purpose index

# Rotate every silo (needs a silo adapter that can enumerate)
python manage.py reencrypt_data

# Rotate only the keys another backend or algorithm made, after a settings change
python manage.py reencrypt_data --only-outdated

# Undo an open rotation
python manage.py reencrypt_data --silo-uid "team-42" --purpose field --abort

# Report values whose blind index digest was never built. Reads no key, calls no KMS.
python manage.py reencrypt_data --purpose index --check
```

### Options

| Option | Description |
|---|---|
| `--key-set default\|system\|all` | Which key set's data keys to rotate: `default` (the default), `system`, another key set declared in `KEY_SETS`, or `all`, one pass per key set. The system silo's rotation fences every `key_set="system"` column — sign-in included — until each swap; see [Rotating a system key](key-rotation.md#rotating-a-system-key). Not with `--silo-uid`. |
| `--silo-uid uid` | Rotate only this silo. Without it every silo is rotated, which needs a silo adapter with `supports_enumeration`; one without it can rotate one silo per run. |
| `--purpose field\|file\|index\|all` | Which key to rotate. `all`, the default, runs fields, then files, then blind indexes wherever a field declares one. |
| `--only-outdated` | Rotate only the data keys that are outdated, and report the rest as `Current:`. See [below](#rotating-only-outdated-keys). Not with `--abort` or `--check`. |
| `--dry-run` | Report what a run would do. Never fences, never writes, never contacts the KMS. With a rotation open it reprints the outstanding report; with `--abort`, what a rollback would reverse. |
| `--abort` | Undo an open rotation: move converted rows back onto the old key, then lower the fence. |
| `--abort-on-unconvertible` | Undo the rotation instead of leaving the fence up when a row cannot be converted. Ends the run. |
| `--show-aad-values` | Print the values of AAD-bound columns beside rows that could not be converted. Standard output only. |
| `--check` | Report indexed values holding no digest and change nothing. Applies to blind indexes only: leave `--purpose` out or pass `--purpose index`, since any other purpose is refused. Takes no `--silo-uid`, and exits non-zero while any row is left. See [below](#reporting-digests-that-were-never-built). |
| `--format text\|json`, `--output FILENAME` | Write a JSON report of each pass: its counts, any key left fenced, and, under `--check`, the values with no digest per column. See [Command output](scheduled-tasks.md#command-output). |

### The order a run takes

For each silo and purpose, in this order — none of the steps is interchangeable:

1. **Checks, before anything changes.** Every model holding encrypted data must
   resolve to a way of finding a silo's rows, or the whole run is refused (see
   [Finding a silo's rows](silo-adapters.md#finding-a-silos-rows)). A data key
   made by another crypto backend, or wrapped by another KMS provider, than the
   one configured is skipped with the reason named. Only an `active` key opens a
   rotation; one already `reencrypting` is resumed, and anything else is skipped.
2. **Open.** The new key material is generated and wrapped by the silo's current
   key encryption key. Then, in one transaction, the data key is fenced
   (`reencrypting`) and the rotation is recorded (`rotation_started`).
3. **Wait** a full `DEK_CACHE_TTL` plus a margin, so that no process still holds
   the old key in its cache. The command prints how long, once, when it starts.
4. **List the rows.** Only after the wait: the fence stops every encrypted write
   for the purpose, so the list stays complete for as long as it holds.
5. **Convert** each row, each in its own transaction. Fields are read and written
   raw; files are rewritten under a fresh name, verified to their end, and only
   then does the row point at them and the old blob get deleted. Blind index
   digests are the odd one out: the value is not rewritten at all, but it *is*
   decrypted — under the silo's field key, because a digest is a one-way hash and
   the key being rotated cannot read it — and the digest recomputed from the
   plaintext. So an index rotation decrypts every indexed value and needs the
   field key usable, and a failed row stays readable and merely unfindable.
6. **Swap** — only if every row converted. The new material replaces the old,
   `dek_key_version` and `reencryption_count` move, the fence lowers, and
   `rotated` is recorded.

A purpose that ends with rows outstanding stops the run before the next purpose
or silo starts: a second fence over an unresolved first doubles the outage.

### End states

A run that cannot swap **leaves the fence up and says so** — in its report and in
a non-zero exit — rather than end quietly, because a silo fenced without anyone
knowing is the failure this command is designed around. The report is the only
view of that state: counts converted and outstanding, then each outstanding row
with its model, primary key, field or file, the error code, and each AAD-bound
column named and marked `<populated>` or `<empty>`. Which bound column moved is
usually the whole diagnosis, and saying so needs no values. The report is kept
while the rotation is open, so `--dry-run` reprints it after the console is gone.

It ends with the two ways out and the command line for each:

- **Fix and rerun**, keeping every row already converted. A failure that is not
  the row's own — a storage timeout, an unreachable provider — clears on a rerun
  alone. A changed or emptied AAD-bound column, ciphertext that no longer
  authenticates, or a row sitting in the wrong silo predates the rotation and is
  repaired in the application first: restore the value, correct the assignment,
  or delete a row whose plaintext is gone.
- **Abort** with `--abort`, which puts the silo back in service on its old key
  while the rows are repaired at leisure. It can discard hours of conversion over
  a failure a rerun would have stepped past, which is why the command picks
  neither.

**An unreachable provider holds both exits shut.** Finishing unwraps both keys,
and aborting re-encrypts under the old one. A storage outage is narrower: it
stops only file work.

**Two runs against one silo at once are unsupported**, and not blocked. Neither
can lose data — only one of them can swap — but the second can report a row the
first has just converted as unconvertible. A clean rerun clears it.

### Rotating only outdated keys

A data key is **outdated** when its row's recorded backend or algorithm differs
from what `CRYPTO_BACKEND` and its options generate now for its purpose, or when
the row recorded no algorithm, since nothing then proves it current.
`--only-outdated` rotates those keys and reports each other active key as
current:

```
Current: team-42 [field] — backend cryptography, algorithm CHACHA20_POLY1305
```

It works with `--silo-uid`, `--key`, every `--purpose` and `--dry-run`, which
lists what would rotate and what is current. A blind index key is HMAC-SHA-256
whatever the backend and its options, so it is never outdated: the run skips the
`index` purpose and says why, once. An open rotation is resumed, as on any run.
The JSON report and the closing log line count the skipped keys as `current`.

Without the flag, `reencrypt_data` rotates every key it is pointed at, current or
not, because a rotation also replaces the key material, which is reason enough on
its own.

### `--abort-on-unconvertible`

For runs nobody reads, such as a scheduled job: a run that would otherwise end
with the fence up for hours undoes the rotation instead, records
`rotation_abandoned` with reason `unconvertible_rows`, and ends the run. It cannot
tell a row that will never convert from a storage error that would have passed,
so it buys an unfenced silo by repeating the conversion later — the right trade
only where an unnoticed fence costs more than the repeat.

### `--show-aad-values`

This flag adds the values of AAD-bound columns to the report, for an operator comparing
the row against an audit trail. They are printed to standard output and **never
logged** — the log line for the same row follows
[`LOG_AAD_VALUES`](configuration.md#log_aad_values) — and the command warns once
when standard output is not a terminal. This is where binding personal data with
a field's `aad=` becomes something to know about: the values you
bound are the values this prints.

### Reporting digests that were never built

`--check` answers one question: does any indexed value hold no digest at all. It
reads the stored column as it stands, so it decrypts nothing, needs no silo
context, and contacts no KMS — which is also what makes it runnable on a
deployment where the KMS is the thing that is broken.

It covers every model holding an indexed silo column, and takes no `--silo-uid`:
an absent digest is a property of the row, and the scan reads nothing a silo
would scope.

```bash
python manage.py reencrypt_data --purpose index --check
```

```
myapp.Patient.national_id: 0 value(s) with no digest
myapp.Member.handle: 128 value(s) with no digest

CommandError: 128 value(s) hold no digest, so no lookup can find them. …
```

The state it is for is an adoption that stopped at the column change.
[`encrypt_field`](adopting-and-removing-encryption.md#adding-encryption-to-an-existing-field)
converts the value and leaves the digest alone — it cannot do otherwise, because
the migration that calls it runs while the column is still declared as a plain
`TextField`, with no `blind_index` to read and, under the default storage, no
digest column to write to yet. The rows come out encrypted and unfindable, and a
lookup against them matches nothing rather than failing, which reads as "no such
row". Gate the release that starts relying on such a lookup on a clean run of
this.

Build the digests with `setup_encryption_keys`, which provisions the index key
for a silo that has none, then `reencrypt_data --purpose index`, which recomputes
every digest from the plaintext.

Whether a digest is *current* is not asked here and cannot be: nothing records
which index key wrote one, so telling a live digest from one written under a key
on its way out means decrypting every value — which is a rotation, is fenced, and
is what `--purpose index` does without `--check`.

### Notes

- Ledger rows are written once per outcome: `rotation_started` with the fence,
  `rotated` in the swap, `rotation_abandoned` when a rollback finishes. A resumed
  run records no second `rotation_started`. Each is echoed to the log at WARNING
  with `silo=`, `purpose=` and who ran it, and never with row values.
- The trigger is `automated`; the operator is recorded in `os_user`, where
  [`USER_IDENTITY`](configuration.md#user_identity) lists it.
- A rotation is where a silo's algorithm changes: the new key comes from the
  configured backend's current template, and the command names it when the
  rotation opens. `--only-outdated` limits a run to the keys that change.

---

## Destroying keys

There is deliberately **no command that destroys keys**. Deleting a silo (via the
[`SILO_AUTO_KEY_DELETION`](configuration.md#silo_auto_key_deletion) connector or an admin
action) only *schedules* its keys, leaving them fully restorable for
[`KEY_DELETION_WINDOW_DAYS`](configuration.md#key_deletion_window_days). When that
window closes, nothing happens: the window does not run a timer that destroys
anything, it lifts the bar on a person destroying it.

That person works from the admin, on one of two changelists:

| Page | Action | Destroys |
|---|---|---|
| Data Encryption Keys | Delete selected expired data encryption key(s) | `encrypted_keyset` cleared — the crypto-shred. The row survives as a `deleted` tombstone. |
| Key Encryption Keys | Delete selected expired key encryption key(s) | The key at the KMS provider, after re-checking every deletion gate. |

Both confirm first, listing what is about to be destroyed and what depends on it.
Neither is a side effect of the other: they are separate acts with different
reversibility, so each belongs to its own page. See the
[admin panel](admin-panel.md#deleting-expired-keys).

The package ships no command because a `manage.py` entry point is one tab-completion
away from running, and both acts are irreversible in ways a database restore does not fix.
A shredded keyset has no provider window behind it — the data is unreadable the
moment it runs. A destroyed key encryption key cannot be recovered from a backup
at all, because what is lost is the key that backup's ciphertext depends on. The
package will not put either one behind a name you can type by accident.

### If you cannot expose the admin

Some deployments do not run the Django admin, or lock it off in production. The
deletion functions are importable and are the supported way to build your own path:

```python
from encryption_suite.deletion import purge_expired_deks, purge_expired_keks
from encryption_suite.user_context import get_os_user

# Preview first. Same window, same gates, no destruction, no provider calls.
# Each key goes to the provisioner of the KMS its row records.
preview = purge_expired_keks(trigger="automated", dry_run=True)
for verb, label, reason in preview.details:
    # DELETE / RETAIN / SKIP / FAIL, one per key. `reason` is the RETAIN_* slug
    # naming the gate that refused, and "" for every other verb.
    print(verb, label, reason)

# Then, once a human has read that:
summary = purge_expired_keks(
    trigger="automated",        # how the act came about; required
    os_login_user=get_os_user(),   # who ran it, for an unattended run
)
```

`trigger` is required on every call that writes a lifecycle row, so the ledger
can always say how an act came about: `"direct"` when a person asked for this
key event, `"indirect"` when it followed another act (pass a `reason` naming
that act), `"automated"` for a script or a schedule. Identity is separate and
optional — `user=` takes a user object or primary key, `os_login_user=` a
resolved operating-system account (`encryption_suite.user_context.get_os_user()`
composes one), and `user_ip=` an address. Which of them is actually recorded or
logged, and in which form, is
[`USER_IDENTITY`](configuration.md#user_identity)'s decision, not the call
site's.

The data side takes no provisioner, because nothing outside this deployment is
called:

```python
from encryption_suite.deletion import purge_expired_deks
from encryption_suite.user_context import get_os_user

preview = purge_expired_deks(trigger="automated", dry_run=True)
summary = purge_expired_deks(trigger="automated", os_login_user=get_os_user())
print(summary.purged, summary.retained, summary.retain_reasons)
```

`retained` counts rows a gate refused — the silo still exists, or the silo
adapter cannot say whether it does. Those rows are left entirely unchanged and
can be retried; see
[`KEY_DELETION_CAN_RENDER_DATA_INACCESSIBLE`](configuration.md#key_deletion_can_render_data_inaccessible)
for what the reasons mean and how to resolve each. Custom tooling should report
them rather than treating `purged == 0` as success.

Both accept `pks=[...]` to restrict to specific rows. The window still decides —
`pks` can only ever shrink the candidate set, never widen it past unexpired work.

Check `summary.skipped_key_stores` on the key-encryption-key side. A skip means the
row records a KMS name that no `KMS_KEY_STORES` block configures, which usually means
the process is running under the wrong settings module — the same trap that makes
a scheduled job silently do nothing.
`encryption_suite.management._hints.kms_not_configured_hint()` renders the same
explanation the built-in commands print.

**Understand what you are building.** A cron entry wrapped around the code above
is exactly the unattended destruction this package declines to ship. That may be
the right call for your deployment — but it is your call, and it should be a
considered one rather than a copied snippet.

### Scheduling from your own code

The scheduling half is importable too, though most projects should not need it:
[`SILO_AUTO_KEY_DELETION`](configuration.md#silo_auto_key_deletion) already schedules a
silo's keys on `post_delete`, which covers the ordinary case.

```python
from encryption_suite.deletion import restore_deletion, schedule_deletion
from encryption_suite.user_context import get_os_user

# Schedule every key the silo owns. Destroys nothing; fully reversible.
scheduled = schedule_deletion("team-42", trigger="automated", os_login_user=get_os_user())

# Change of mind, any time before the window closes:
restore_deletion("team-42", trigger="automated", os_login_user=get_os_user())
```

`schedule_deletion` only schedules the *key encryption key* when the strategy
calls it `silo_exclusive`. A shared key is referenced by many silos, so one
silo's deletion never schedules it — clearing that silo's own data encryption
keys is its shred.

A user is shredded the same way, with `schedule_deletion(SiloRef("user", pk))`. What that
removes depends on the key store of the [user-specific key set](user-specific-silos.md#declaring-the-key-set):
a per-user key encryption key is scheduled, while a shared key encryption key or an env
store loses only the user's data key rows, which a restored backup brings back.

To schedule a single key encryption key that no silo claims — a reconcile orphan,
say — use `schedule_kek_deletion(row, owner_prefix=..., trigger=...)` from
`encryption_suite.deletion`, passing the prefix from
`live_owner_prefix(row.key_store)` in the same module.

### The deletion gates

| Gate | Passes when |
|---|---|
| In use | No `DataEncryptionKey` row still holds an `encrypted_keyset` wrapped by this KEK, and no open data key rotation holds its incoming key under it. Tested directly against the rows, not inferred: a keyset that has not been destroyed can only ever be unwrapped by this key. Rows whose own window has already closed are excluded, so a silo torn down alongside its own key does not block it, and the two deletion runs can be made in either order. |
| Disposition | `disposition == silo_exclusive` — the KEK belongs to exactly one silo, so deleting it cannot orphan another silo's data. Re-derived from the running strategy for every silo whose DEK rows name the key (tombstones included — a shredded row still records that its silo used the KEK); any "shared" answer wins. The row's snapshot is used only for a key no DEK row names at all, such as a discovered orphan — and that snapshot is itself derived at schedule time by asking the strategy about the stored key *name*, so it cannot claim a key is destroyable when the strategy says otherwise. A `KEK_MAP` key is shared/opaque unless [`KEK_MAP_DESTROYABLE`](configuration.md#kek_map_destroyable) is set. |
| Capability | The configured provisioner reports `supports_delete`. Usually a fact about the provider leg — either it implements deletion or it does not — but a provider whose deletion is opt-in also answers no until the deployment opts in (HashiCorp Vault's `ALWAYS_ALLOW_KEY_DELETION`). |
| Ownership | `provisioner.owns_kek(name, owner_prefix, owned_names=...)` — the key name carries this deployment's owner prefix, or the key is a `KEK_MAP` value and [`KEK_MAP_DESTROYABLE`](configuration.md#kek_map_destroyable) is set. Either proves the key is ours to delete. |

The gates are re-evaluated when the deletion runs, not at scheduling time. The owner
prefix is re-derived from the running configuration on every run, and the value
recorded on the row when it was scheduled only has to agree: if the two differ —
a changed `KEK_TEMPLATE`, or a row edited by hand — the key is retained as
`not_owned_by_deployment` rather than deleted, and logged at WARNING naming both
the prefix it was scheduled under and the one now configured. Worth alerting on: it means scheduled deletions have
stopped happening and nothing else will tell you. A stored value can withhold
permission to destroy a key; it can never grant it. If the strategy cannot be
resolved at all, no prefix is derived and every key retains.


---

## `reconcile_keys`

`reconcile_keys` runs the same reconcile pass the admin's [Reconcile Keys
page](admin-panel.md#reconcile-keys-page) runs, so you can schedule it.

```bash
python manage.py reconcile_keys

# For a scheduler: one JSON document, one entry per store
python manage.py reconcile_keys --format json --output reconcile.json
```

The JSON entry for each store, named by `key_store`, lists the key names behind each
finding (discovered, confirmed deleted, live past its deletion date, missing from
the KMS, rotated at the provider) and counts the standing conditions. A count is
`null` where the text says "not checked". `not_applicable` and `could_not_run` carry
the reason slugs from the table below. The entry counts orphaned data encryption keys
without naming their silos; the admin page lists them.

The command runs one pass per key store that a key set uses, plus one for any other
store that still holds a key encryption key that is not deleted, so `reencrypt_keys`
can drain a store you are moving off. An env key store has no provider to list and gets
no pass. Each pass ends with an `A reconcile pass finished.` line naming
its store, and the run ends with one `command finished` line. The admin page runs the
pass for the key store it shows.

Reconcile compares what this deployment *thinks* exists (key rows) against what
actually exists (live silos, keys on the KMS) and records what it learns:
newly discovered keys, keys whose silo has gone or come back, and
provider-window deletions the enumeration witnessed. It then reports the standing
conditions as counts — orphaned keys, data re-encryption due, and key
re-encryption due.

**Safe to schedule.** Reconcile only ever records what it observed: it never
deletes, never schedules a deletion, and never touches key material. Daily is a
sensible starting point. A pass that learns nothing writes nothing, so a quiet
deployment costs one listing call and no database writes — which is why the
orphan annotation moves only on a change, and why `updated_at` on a key row means
"something changed" rather than "reconcile ran".

**There is deliberately no `--dry-run`.** A preview would perform the same
enumeration at the same cost and differ only in whether the findings were written
down — and writing them down is the point. Contrast `reencrypt_keys`, where a dry
run is genuinely useful because the real run performs KMS operations.

Dimensions that could not be inspected are always named — never silently treated
as clean, since "the provisioner cannot list keys" must not read as "no orphans"
— but they are split by whether they can change:

- **Permanent properties of the configuration** go to **stdout** as
  `Not applicable to this configuration:` — no cryptoperiod declared, no owner
  prefix derivable, a provider that identifies no key version, an adapter or
  provisioner that cannot enumerate. These read identically on every run, and a
  daily warning about them is how warnings stop being read.
- **Everything that might be going wrong** goes to **stderr** as
  `Some checks could not run:` — an enumeration or lookup that *raised*.

The distinction matters because the same empty result has two causes. A
provisioner that *cannot* list and one that *tried and failed* both yield no
keys; the first is how the deployment is built, the second is an incident. Each
capability therefore has a paired failure slug:

| Capability absent (information) | The call failed (warning) |
|---|---|
| `silo_enumeration_unavailable` | `silo_listing_failed` |
| `kms_enumeration_unavailable` | `kek_listing_failed` |
| `provider_reports_no_key_versions` | `key_version_probe_failed` |

`no_cryptoperiod_declared` has no failure counterpart — it is purely a setting.

The exit status is 0 either way — a degraded dimension is a limit of what could
be inspected, not a failure of the run. Alert on the stderr line, or on a
non-empty `could_not_run` in the JSON, not on the exit code.

---

## `record_key_event`

This command appends a manually-recorded entry to the `KeyLifecycleEvent` ledger for a key encryption key
lifecycle act performed **outside** the application — a key created, scheduled,
or deleted through Terraform, the provider console, or `flyctl`. The
application's automatic paths record their own events; this command covers the
acts performed outside this application they never observe, so the ledger stays a complete history.

The admin "Key Encryption Keys" add form is the GUI counterpart — same effect, same
pinning. Use whichever fits your workflow.

### Basic usage

```bash
python manage.py record_key_event --event created --kek-resource-name alias/es-prod-team-7

python manage.py record_key_event --event deleted --kek-resource-name alias/es-prod-team-9
```

### Options

| Option | Description |
|---|---|
| `--event` | **Required.** The verb to record: `created`, `deletion_scheduled`, `deletion_requested`, `deleted`, or `restored`. |
| `--kek-resource-name` | **Required.** The key encryption key identifier the event concerns. |
| `--key-store` | The name of the key store that holds the key, from `KMS_KEY_STORES` or `ENV_KEY_STORES`. Defaults to the `default` key set's store. A name that matches no configured key store is refused. |
| `--silo-uid` | Silo the event concerns, if known. Stored as a snapshot on the event. |
| `--key-set` | Key set of `--silo-uid`. Defaults to `default`. Stored as a snapshot on the event. |

### Recorded actor

The command records the operating-system login account of whoever runs it, in the
event's `os_user`, where [`USER_IDENTITY`](configuration.md#user_identity) lists
it. It cannot be passed as an argument. The trigger is
always `direct`: a hand-recorded attestation is the definition of a person asking
for this key event.

The value is composed rather than a bare name, because the unforgeable half is
the uid and the name is only as good as the password database a root user can
edit:

| Shape | Means |
|---|---|
| `deploy (uid 1000)` | The uid the process runs as, and the name the password database gives it. |
| `user1 → root (uid 0)` | `SUDO_USER` named the person who escalated into the account on the right. |
| `(uid 1000)` | That uid has no password-database entry, so there is no name to show. |
| `deploy (unverified)` | No password database (Windows): the name comes from the environment and carries no kernel guarantee. |
| `? → root (uid 0)` | The originating name was not a plain ASCII account name and was refused whole, so the escalation stays visible without echoing forged text. |

`SUDO_USER` takes precedence when set, because it names the person while the
process uid names the account they escalated into — but it is an environment
variable, so it is a claim, not evidence. The uid is read from the kernel, and
the name from the password database rather than from the environment, so neither
can be spoofed by setting `USER` or `LOGNAME`.

With neither `os_user` nor `encrypted_os_user` listed — the default — the
command still runs and still records the event; the account name is dropped
before the row is written. The command refuses only when it cannot compose an
account name at all.

A record here is that person's **claim** that something happened in the provider
console. The ledger stands behind who made the claim, not behind the act itself,
which is why the reason is pinned to `recorded_by_operator` and never reads as
machine evidence.

### Notes

- **Row-first.** The durable `KeyEncryptionKey` row is created (or fetched) before its
  event, so every event points at a real row. A key the application has never
  seen gets its row here; a key it already knows keeps the one it has.
- Every event written here is pinned with the stable `recorded_by_operator`
  reason, so a manual attestation is always distinguishable from a
  tooling-verified event — the ledger never launders a human claim into
  machine evidence.
- The verbs above are always recordable. They are not gated behind
  `supports_delete`, because the act being recorded already happened elsewhere
  and the ledger's job is to reflect reality, not to authorize it.
- The ledger is append-only. To correct a mistaken entry, record the correcting
  act rather than editing history.

---

## `crypto_inventory`

`crypto_inventory` reports what this deployment knows about its cryptography at
the moment it runs. The report has five sections:

- **Key management system (KMS).** The report lists every `KMS_KEY_STORES` block (a
  key store) and `system`, with its KMS adapter, KEK strategy and key counts. It
  lists a key store name that key rows record but no block configures as
  **Not configured**.
- **Key encryption keys.** The report counts them per key store and status, in
  every status.
- **Configured for new key encryption keys.** The report lists the key store and the
  silo adapter that `KEY_SETS` gives each key set, including any key set a field
  declares that no entry covers. A new key encryption key is created on that store.
- **Data encryption keys.** The report counts them per key set, purpose,
  cryptographic engine, algorithm and key store, and gives the oldest key material
  in each group. Where `DEK_ROTATION_PERIOD_DAYS` is declared, it also counts the
  keys older than that period. It leaves out deleted keys and the test console's
  keys.
- **Configured for new data encryption keys.** The report gives the cryptographic
  engine (`CRYPTO_BACKEND`) and the algorithm each purpose would get now, with any
  engine option that the algorithm does not already say, such as the file segment
  size. Comparing this section with the data encryption keys section shows which
  existing keys lag behind the configuration.

The command prints the sections in the order the admin page shows them, under the
same headings.

The command reads settings and key rows only, and makes no KMS call;
[`reconcile_keys`](#reconcile_keys) is the command that asks the KMS what it
holds. The report holds counts and identifiers only. It never holds key material,
a wrapped keyset or a silo UID.

### Basic usage

```bash
# For a person
python manage.py crypto_inventory

# For a record to keep with a review, or to diff against last year's
python manage.py crypto_inventory --format json --output inventory.json
```

### Options

| Option | Description |
|---|---|
| `--format text\|json`, `--output FILENAME` | `text` (the default) is for reading. `json` writes the inventory as a document to keep; see [Command output](scheduled-tasks.md#command-output). |

### Notes

- The admin's [Cryptographic inventory page](admin-panel.md#cryptographic-inventory-page)
  shows the same data, and links each count to its keys.
- The JSON document has one key per section, named for its heading:
  `key_stores`, `key_encryption_keys`, `configured_for_new_key_encryption_keys`,
  `data_encryption_keys` and `configured_for_new_data_encryption_keys`. The fields
  inside each section are named for the page's column headings, such as `key_store`,
  `kms_adapter`, `cryptographic_engine` and `older_than_rotation_period`.
- The command writes nothing, so it is safe to schedule.

---

## `encryption_suite_rotate_hashicorp_approle`

This command generates a fresh AppRole `secret_id` for a HashiCorp Vault role and prints the result as
JSON on stdout. **HashiCorp Vault deployments only** — irrelevant to every other
KMS adapter.

Run it from a *privileged* context: CI/CD, an ops work station, or a scheduled
job holding elevated credentials. Never from the application workloads that
consume the `secret_id`. The app uses the rotated value; it does not rotate it
for itself, since a workload able to mint its own credential defeats the point
of AppRole.

This is HashiCorp's [trusted orchestrator
pattern](https://developer.hashicorp.com/vault/tutorials/app-integration/secure-introduction).

### Basic usage

```bash
VAULT_ADDR=https://vault.example.com:8200 VAULT_TOKEN=<admin token> python manage.py encryption_suite_rotate_hashicorp_approle --role encryption_suite | jq -r .secret_id
```

With `--wrap`, the command emits a single-use [response-wrapping
token](https://developer.hashicorp.com/vault/docs/concepts/response-wrapping)
instead. The workload unwraps it once at startup, so the raw `secret_id` never
traverses the delivery channel — the preferred form wherever the consumer can
unwrap:

```bash
python manage.py encryption_suite_rotate_hashicorp_approle --role encryption_suite --wrap --wrap-ttl 5m
```

### Options

| Option | Description |
|---|---|
| `--role` | **Required.** AppRole role name (e.g. `encryption_suite`). |
| `--vault-addr` | Vault server URL. Defaults to the `VAULT_ADDR` env var. |
| `--admin-token` | Admin token permitted to call the AppRole secret-id endpoint. Defaults to the `VAULT_TOKEN` env var. |
| `--vault-namespace` | Vault namespace (HCP Vault / Enterprise). Defaults to the `VAULT_NAMESPACE` env var. |
| `--approle-mount` | AppRole auth mount path. Default `approle`. |
| `--wrap` | Emit a response-wrapping token instead of the raw `secret_id`. |
| `--wrap-ttl` | Wrapping token TTL as a Vault duration string. Default `5m`. Only used with `--wrap`. |

### Output

The command writes JSON to stdout. Without `--wrap`:

```json
{"secret_id": "...", "secret_id_accessor": "...", "secret_id_ttl": 0,
 "secret_id_num_uses": 0, "expiration_time": "..."}
```

With `--wrap`:

```json
{"wrapping_token": "...", "wrapping_token_ttl": 300,
 "wrapping_token_accessor": "...", "creation_path": "auth/approle/role/.../secret-id"}
```

### Notes

- Prefer passing the admin token by environment variable over `--admin-token`,
  which is visible in the process list and shell history.
- The unwrapped output contains a live credential. Pipe it straight into your
  secrets manager rather than writing it to a file or a log.
- See [Getting started with HashiCorp Vault](getting-started-hashicorp.md) for
  the AppRole setup this command assumes.
