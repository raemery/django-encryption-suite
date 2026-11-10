# Using the admin panel

django-encryption-suite adds seven things to the standard Django admin: two
changelists that hold state (**Data Encryption Keys**, **Key Encryption Keys**), the
append-only **Key Lifecycle Events** changelist, the **Reconcile Keys** page for
finding drift, the **Test console** for isolated round-trips, and the read-only
**Encryption settings** and **Cryptographic inventory** pages.

The division of labor is worth learning once, because it is the safety model:
**Reconcile Keys only reports** — it discovers, annotates, and flags, and never
destroys anything. **Every action that changes a key is on a changelist**,
where the selection is re-verified server-side at execution time.

Everything requires `is_staff`, and each screen and action requires a permission
of its own — see [Permissions](#permissions).

Before any of this works, `admin.site.urls` must be mounted — see
[Getting started, step 6](getting-started.md#6-wire-urlspy-for-the-admin).
Nothing else is required: the package registers these views through its own
`ModelAdmin`, so they appear as soon as the admin is mounted and
`encryption_suite` is in `INSTALLED_APPS`.

Three ways to reach the Reconcile Keys page:

- **Object tool** on the Data Encryption Keys changelist (top right,
  "Reconcile Keys").
- **Direct URL**:
  `/admin/encryption_suite/dataencryptionkey/reconcile-keys/`.
- **Reverse**: `reverse("admin:encryption_suite_reconcile_keys")` /
  `{% url "admin:encryption_suite_reconcile_keys" %}`.

## Permissions

Every screen here requires `is_staff`. Beyond that, each screen and each action
is gated on a specific permission, so an operator can be given the ability to
read the key state without the ability to destroy a key.

### Screens

| Screen | Permission |
| --- | --- |
| Data Encryption Keys changelist | `encryption_suite.view_dataencryptionkey` |
| Key Encryption Keys changelist | `encryption_suite.view_keyencryptionkey` |
| Key Encryption Keys add form | `encryption_suite.add_keyencryptionkey` |
| Key Lifecycle Events changelist | `encryption_suite.view_keylifecycleevent` |
| Reconcile Keys | `encryption_suite.reconcile_keys` |
| Test console | `encryption_suite.run_test_console` |
| Encryption settings | `encryption_suite.view_settings` |
| Cryptographic inventory | `encryption_suite.view_inventory` |

### Actions

| Changelist | Action | Permission |
| --- | --- | --- |
| Data Encryption Keys | Schedule deletion | `encryption_suite.delete_dataencryptionkey` |
| Data Encryption Keys | Delete expired | `encryption_suite.delete_dataencryptionkey` |
| Data Encryption Keys | Restore scheduled | `encryption_suite.change_dataencryptionkey` |
| Key Encryption Keys | Schedule deletion | `encryption_suite.delete_keyencryptionkey` |
| Key Encryption Keys | Delete expired | `encryption_suite.delete_keyencryptionkey` |
| Key Encryption Keys | Record as deleted in the key store | `encryption_suite.delete_keyencryptionkey` |
| Key Encryption Keys | Record as deletion requested in the key store | `encryption_suite.delete_keyencryptionkey` |
| Key Encryption Keys | Restore scheduled | `encryption_suite.change_keyencryptionkey` |
| Key Encryption Keys | Record as deletion canceled in the key store | `encryption_suite.change_keyencryptionkey` |

Anything that moves a key toward being unreadable takes the **delete**
permission — including the two attestations that a deletion happened at the
provider, which make a row terminal. Anything that returns a key to service
takes **change**. An action a user may not run is absent from the drop-down and
is rejected if its name is POSTed anyway.

The change permission runs the restore actions but still does not make a key row
editable: every detail page is view-only, and every state change goes through an
action that re-verifies the selection.

### The four screen permissions

`reconcile_keys`, `run_test_console`, `view_settings` and `view_inventory` are
not model permissions. None of the screens belongs to a key model — reconcile reads and annotates rows of each, the
console creates and deletes rows of each plus a real key at the provider, the
inventory counts rows of each, and the settings page is about neither. They are
carried instead by `EncryptionTools`, a model with no table whose only purpose is
to be their home. In the permission list they appear under their own heading:

```
Encryption | Encryption tools | Can use the Cryptographic inventory screen
Encryption | Encryption tools | Can use the Encryption settings screen
Encryption | Encryption tools | Can use the Reconcile Keys screen
Encryption | Encryption tools | Can use the Test console screen
```

They arrive with the package's migrations and are granted to nobody. Until an
administrator grants them, a non-superuser staff member sees none of the four
screens' links, and their URLs answer 403. Superusers are unaffected, holding every
permission by definition.

## Reconcile Keys page

**URL:**
`/admin/encryption_suite/dataencryptionkey/reconcile-keys/`

Read-only. Each visit enumerates your silos and, where the provisioner supports
it, the key encryption keys this deployment owns; records what it finds on the durable
rows; and reports the differences.

A **Key store** selector at the top of the page chooses what the page describes. It lists
each store with the key sets that use it, as in `fly (default, restricted)`, starts on the
`default` key set's store, and reloads the page when you pick another. The store decides
which keys the page lists, records and probes, and every table covers every key set that
uses that store, so the summary counts the rows those tables show, exactly as one pass of
[`reconcile_keys`](management-commands.md#reconcile_keys) does.

The selector lists a store while it matters: a key set uses it, or it still holds key
encryption keys that are not deleted. A store you have moved off therefore stays listed
until `reencrypt_keys` has drained it and its keys are deleted, then drops off. The page
also lists env stores, but reports that detection is unavailable for them, because an env
store has no provisioner that can list its keys. A notice names any store that key rows
record but the settings no longer configure, with an alert icon and the words "Not configured";
the page cannot reconcile them. The page shows:

- **Silos.** One row for each silo of each key set on the chosen store: the silos its
  adapter can enumerate, and the system silo once anything encrypts under it.
  Each row shows the **key set**, the silo UID, and the
  **expected KEK name** (the exact string the key set's store would be asked for on
  first encrypt — copy this into your KMS console when creating keys out of
  band). It also shows whether that key exists, and whether a field, a file and (where
  a field of the set declares a blind index) an index data encryption key exist.
  The existence check is live when enumeration is available, and the last
  recorded state otherwise. Rows missing a data encryption key are flagged **Needs setup** and
  listed first, and are counted in the summary at the top of the page; their first
  encryption creates the missing row, and fails with `KekNotProvisionedError` if the
  key encryption key itself has not been created.
- **Data Encryption Keys Without a Live Silo.** Rows wrapped on the chosen store whose
  `silo_uid` no longer resolves to a live silo, with each row's key set (with an
  alert icon before it when `KEY_SETS` no longer defines it), status, a **DEK (live)**
  marker, the end of its restore window, and a **Test console** marker. Every row here
  except a test-console one is orphaned — usually the tenant was deleted — so the
  table carries no separate orphan column; act on them from the Data Encryption Keys
  changelist. The summary count at the top of the page counts exactly those rows.

  Tombstones are left out. The row survives as the record that a key
  existed, but its keyset is cleared, so there is nothing to adopt, delete, or
  restore — no decision for this table to prompt. Find them on the changelist,
  which lists every row.

  Test-console rows appear here too, marked, and report as not orphaned. Their
  silo UID is reserved so no real silo can ever use it, which makes the orphan
  question structurally unanswerable for them rather than answered yes. Stating
  that is more honest than either counting them as orphans (permanent false
  positives, which teach operators to distrust the table) or hiding them.
- **Key Encryption Keys Without a Live Silo.** Keys on the chosen store,
  owned by this deployment, that back no live silo of any key set — with status, a **KEK (live)** marker, the
  provider's deletion date once requested, a **Test console** marker, and the same
  **Orphaned** marker. Orphaned keys cost money until removed. Act on them from the
  Key Encryption Keys changelist.

  Test-console keys are listed here too. One left over after its key rows are gone
  is a genuine orphan, because unlike a test key *row* it exists on the provider
  and is still billing; one still backing a test keyset is in use, just not by a
  real silo, and reports as not orphaned. A test key that was never provisioned is
  not listed at all: its name always resolves, but there is nothing there to
  report.

  Both states answer in words: an orphan reads "Yes" behind the alert icon, and
  everything else reads "No". Only the answer that needs acting on carries ink, so
  the page points at the rows awaiting a decision.

  Read the two marker columns together. **Orphaned** states a fact — no live silo
  references this key — and the **Status** column says what has been done about it:
  a key `deletion_scheduled` or `deletion_requested` is an orphan you have already
  acted on, `deletion_failed` needs a different action, and a gate refusal reads
  retained. An orphan still `active` is the one awaiting a decision. The
  **KEK (live)** marker adds whether the key is usable: a key inside a provider's
  deletion window still lists at the KMS, so it shows an alert icon rather than a
  check — it exists, but it will not encrypt or decrypt.
- **Overdue Re-encryption.** Two findings about whether the material behind your
  keys is still current, each resolved by its own command and neither actionable
  from the admin. *Data re-encryption due* lists keys whose own material predates
  [`DEK_ROTATION_PERIOD_DAYS`](configuration.md#dek_rotation_period_days);
  resolving one means re-encrypting that silo's data under a new data key with
  [`reencrypt_data`](key-rotation.md#rotating-a-data-encryption-key). *Key
  re-encryption due* lists keys whose key encryption key has rotated at the
  provider since they were wrapped; `reencrypt_keys` moves them onto the current
  version without touching any data.

  The second finding compares each row's recorded key version against the version
  the provider reports as current — an observed fact rather than an inference from
  elapsed time. Providers that identify no version (AWS KMS, Fly KMS) cannot
  answer it, so on those the finding is permanently empty.
- **Manual cleanup instructions.** When a key is orphaned but this deployment
  cannot delete it, the page names the exact key and provider so you can remove
  it by hand.

Every section renders on every load, and every summary row is a count, so a
section with nothing in it says so rather than disappearing. A detection that
*cannot* run — the silo adapter cannot enumerate, the provisioner cannot list
keys, ownership cannot be derived, the provider identifies no key version —
reports **nothing** for its dimension rather than guessing, and so reads as a
zero on this page.

`reconcile_keys` makes the distinction explicit: it prints `not checked` in
place of a count and names the reason. Run it when you need to know whether a
zero means "clean" or "could not look".

Adapters that cannot enumerate their silos (composite cell models, or custom
adapters that have not overridden `iter_silos()`) therefore show no per-silo
rows. Override `iter_silos()` on the adapter and set
`supports_enumeration = True` to populate them.

## Encryption settings page

**URL:**
`/admin/encryption_suite/dataencryptionkey/settings/`

Read-only. Every setting this package knows about, grouped by the part of the
system it governs: **General**, **Recording and identity**, **Cryptographic
engine**, **Silo**, **KMS**, **Keys and rotation**, **Storage**, and **Other**.
Each row carries the effective value and whether the project named it
(`configured`) or left it alone (`default`).

Only what a deployment actually sets appears. The options dicts are rendered key
by key from their contents, so an adapter you do not use contributes nothing.

It is the answer to the questions the other screens raise. A ledger row with no
user, no OS login account or no address is `USER_IDENTITY`: its
`KEY_LIFECYCLE_EVENTS` list names what the record keeps, and is empty unless the
deployment filled it. Keys the project left out of `USER_IDENTITY` are shown at
their defaults, so the row reads as the configuration actually running.

**Values only.** Django hands the package a resolved value and no history, so
the page can say a value differs from the default and never that it arrived in
an environment variable, a secret, or the settings file. `configured` means the
name appears in the project's `ENCRYPTION` dict, nothing more.

**What it hides.** The page reads this package's own namespace — `ENCRYPTION`,
merged over the package defaults — plus the one `STORAGES` entry described
below. Nothing else in a project's settings is reachable from it. Within the
`ENCRYPTION` namespace, hiding is per key, not per dict: a
`KEK_TEMPLATE` or an `AWS_REGION` prints, while the dozen option keys that carry
a credential — a token, a client secret, an API key, a passphrase, raw key
material — render as `(hidden)`. The row always stays: you can see that an
option is configured without seeing its value. Nested options, such as
`OIDC_SOURCE_OPTIONS`, are walked the same way.

Both answers come from a catalog declared beside the settings in
`encryption_suite/conf.py`, not from the page. It fails safe in both directions:
a setting name the package does not recognize is hidden and grouped under
**Other**, and an option key not listed as showable is hidden too — so an
adapter option added later reads as `(hidden)` until someone classifies it,
rather than being exposed by default.

### Resolved file storage

`STORAGE_ALIAS` names a `STORAGES` entry but does not describe it, so the
**Storage** group ends with three rows for the entry an encrypted file is
actually written through:

- **STORAGES alias in use** — the alias that answered, and how. The resolution
  falls back: an alias naming an entry that does not exist uses `default`
  instead, and a project with neither gets the package's own file backend. That
  fallback is silent everywhere else, so a typo in the alias name puts encrypted
  files in a bucket nobody chose with nothing reporting it.
- **STORAGES BACKEND** — the dotted path that was imported and composed with the
  encrypting storage.
- **STORAGES OPTIONS** — key by key.

These are the only rows on the page that are not `ENCRYPTION` settings, so their
Source column says where each came from rather than `configured` or `default`.

`STORAGES`, `BACKEND` and `OPTIONS` are Django's own; what is *inside* `OPTIONS`
is whatever the configured backend takes as constructor arguments, so the names
depend on the backend — Django's file storage reads `location` and `base_url`,
django-storages' S3 backend `bucket_name` and `endpoint_url`. That same dict is
where an access key and secret usually sit, so the values are hidden except the
handful that say where files go. A backend this package has never seen
contributes only hidden values, which is the safe way to be wrong about an
option nobody has classified.

## Cryptographic inventory page

**URL:**
`/admin/encryption_suite/dataencryptionkey/inventory/`

Read-only. The same inventory the
[`crypto_inventory`](management-commands.md#crypto_inventory) command prints: each
key store and its KMS adapter, the key encryption keys per key store and status,
the data encryption keys per key set, purpose, cryptographic engine, algorithm and key
store, and what a data key or a key encryption key generated now would get. Each count links to the changelist filtered to the keys behind it, for a
user who may view that changelist; for anyone else the count shows without a
link. It makes no KMS call. Dates are shown in the active time zone, which the page names beside
the date it was generated; the command prints them in ISO 8601 with their UTC
offset.

Use the command for a record to keep: the page is for browsing, and a screenshot
is poor evidence next to a JSON file.

## Data Encryption Keys changelist

The changelist holds one row per silo per purpose. Each row holds the encryption key for that
silo's data, itself encrypted by a key encryption key. The **Orphaned** column is a cached reconcile
annotation and is filterable; it is display-only — every action re-verifies
against a live enumeration before touching anything. It moves only when the
answer changes, and each change appends a `silo_found` / `silo_not_found` event,
so `updated_at` on these rows means "something actually changed" rather than
"reconcile ran".

**Key rotation is not surfaced here.** Which keys are overdue for re-encryption
appears on [Reconcile Keys](#reconcile-keys-page), because neither re-encryption
command can be run from a changelist — a column flagging work you cannot start
from that page would be a dead end. The detail page still carries the underlying
facts: **Key material last generated at**, **DEK key version** and **Last
re-encrypted at**. See [the two rotation
dates](key-rotation.md#the-two-rotation-dates).

**A data key rotation in flight is surfaced here**, because it is a live outage
rather than work you might start. While
[`reencrypt_data`](key-rotation.md#rotating-a-data-encryption-key) holds a key's
data fenced its **Status** reads **Re-encrypting**, and a **Rotation age**
column says how long the fence has been up. The column is read from the rotation
itself rather than from the status, so a key scheduled for deletion in the middle
of a rotation still shows it — scheduling does not end a rotation, and restoring
the key returns it to **Re-encrypting**. A fence that has been up far longer than
a sweep takes is a run that ended with rows outstanding: rerun the command, or
abort it.

Three actions:

- **Schedule deletion of selected data encryption key(s).** Opens a
  confirmation screen that reports how many of the selected keys still belong
  to a live silo, then flips those rows to `deletion_scheduled` — a key under
  rotation included, whose rotation waits out the window with it. This blocks
  encryption and decryption for those keys — immediately in the database, and
  within `DEK_CACHE_TTL` (default 300 seconds) in each running process, since a
  worker holding a cached key keeps using it until its cache entry expires.
  Nothing is destroyed: the rows stay restorable for
  `KEY_DELETION_WINDOW_DAYS` (default 14).

  **This action never schedules or deletes a key encryption key.** Only deleting a real
  silo does that, via the `SILO_AUTO_KEY_DELETION` connector, so that a departed
  tenant's exclusive key encryption key is not left stranded on the provider.

- **Restore selected scheduled data encryption key(s).** Reverses the above
  while the window is open, and is scoped the same way — restoring a key row
  never touches a key encryption key.

- **Delete selected expired data encryption key(s).** Destroys the key material on the rows you
  selected whose window has expired: it clears the `encrypted_keyset` field —
  the only durable copy of the wrapped key, so the field-clear *is* the
  crypto-shred. The row survives as a `deleted` tombstone; the data it protected
  can no longer be decrypted, including in backups taken afterwards.

  Scoped to this page. Key encryption keys are destroyed from their own
  changelist, so neither irreversible act happens as a side effect of the other.
  The selection only narrows the work — an unexpired row you select is left
  alone, because the window decides. Django's "select all N records" banner is
  accepted here: a shredded key can be recovered from a database restore
  (provided its key encryption key still exists), so the sweep does not need
  extra friction.

  Confirmed before anything is cleared — see
  [deleting expired keys](#deleting-expired-keys).

The changelist and a key's detail page show a **Silo name**: what the UID refers to, in
the words your deployment uses for it. A silo UID is derived from something that
cannot be reissued — usually a surrogate key — so `team-42` identifies a silo
precisely and describes it not at all, and every destructive action here is
confirmed by UID. The name comes from the silo adapter's
[`describe_silo()`](silo-adapters.md#naming-a-silo-describe_silo), one lookup per
row. Two fallbacks:

| Shown | Meaning |
|---|---|
| `— (silo no longer exists)` | The row outlived its silo, which is the expected end state for a tombstone |
| `— (unavailable)` | The adapter cannot look names up, or the lookup failed. Purely cosmetic — nothing else on the page depends on it |

On the detail page, the silo name links to the silo's own admin page when the
silo is a model instance registered in the admin, such as a team or a user. The
target page applies its own permissions. A silo with no admin page shows the same
text without a link.

The detail page also carries the key-age facts in full: **Key material last
generated at**, **DEK key version** and **Last re-encrypted at**. Those are
stored values, not derived readings — what is *due* is answered once, on
Reconcile Keys.

## Key Encryption Keys changelist

The changelist holds one durable row per known key encryption key, and never deletes it — a
terminal `deleted` status keeps the row as the last-known record. Rows arrive by being provisioned by the
package, recorded by an operator through the add form, or discovered by
reconcile. The **Key store** column names the `KMS_KEY_STORES` block that holds each key,
or `system`, and the add form offers every configured key store, with the `default`
key set's store selected. Actions cover scheduling a confirmed orphan for deletion, restoring
within the window, recording a deletion performed outside this application, and running the
deletion.

- **Restore selected scheduled or retained key encryption key(s).** Returns a key
  to `active` and clears its window. No provider call is made, so this covers both
  a key still inside its window and one a deletion gate refused (`retained`) —
  neither reached the provider. Restoring a retained key is how it becomes
  schedulable again once the reason it was refused has been dealt with.

- **Record selected as deletion canceled in the key store.** The counterpart to
  recording a deletion. A key whose deletion you canceled in the KMS
  (`aws kms cancel-key-deletion` and equivalents) is usable again, but its row
  still reads `deletion_requested` — the restore action only reverses this
  application's own window, and reconcile flags the disagreement rather than
  auto-correcting it. Recording it returns the row to `active`, pinned as an
  operator attestation.

The three recording actions also take env store keys. An env store's key is the
material in its `KEKS` setting, so removing that material and putting it back
from a backup are the acts to record. The package does not check the setting
against what you record.

An attestation is a state change, so a key already standing where the verb would
put it is skipped and counted in the message — recording a key as deleted a
second time would append an attestation at a later date, reading as a second
deletion, while the row itself would not move. This matches the restore action,
which takes only the keys it can actually return to service.

- **Delete selected expired key encryption key(s).** Asks the provider to delete
  the selected keys whose window has expired. Scoped to this page — data
  encryption keys are shredded from their own changelist.

  Unlike the data-encryption-key action, this one **refuses Django's "select all
  N records"**. A destroyed key encryption key cannot be recovered from a
  database backup, because what is lost is the key that backup's ciphertext
  depends on. Destroying an unbounded set of them should be deliberate and
  reviewable, so select the rows individually. Nothing in this package sweeps
  them — see
  [destroying keys](management-commands.md#destroying-keys).

  Confirmed before any provider call — see
  [deleting expired keys](#deleting-expired-keys).

Deleting a key encryption key is gated, re-checked when the deletion runs: no live
data encryption key may still depend on it, the key must be silo-exclusive (a
shared key is never deleted), the provisioner must support deleting, and the key
must be owned: its name carries this deployment's owner prefix, or it is a
`KEK_MAP` value and `KEK_MAP_DESTROYABLE` is set. A key failing any gate is
retained with the reason recorded.

## Deleting expired keys

Both delete actions confirm before destroying anything. The window closing does
not start a timer — it lifts the bar on a person destroying the key — so the
confirmation is where that person sees what they are about to lose.

Each screen is built by running the *same* deletion the confirm will run, with
`dry_run=True`. What it lists is therefore the decision the real run makes, not a
second implementation of the window check that could disagree with it.

The data-encryption-key screen lists each row to be shredded — silo, purpose, the
key encryption key that wraps it — and states plainly that no provider window
stands behind the act: the data is unreadable the moment it runs, recoverable
only from a database backup taken while the wrapping key still exists.

The key-encryption-key screen adds an **outcome** column, because not every
selected key will be destroyed. A key a gate refuses shows *retained*, one
on a KMS that no `KMS_KEY_STORES` block configures shows *skipped*, and only *will be destroyed* means
what it says — so the screen never promises a destruction a gate is about to
refuse. Beside it is the blast radius: how many silos still hold keysets wrapped
by that key, every one of which loses its data permanently.

Rows still inside their window are excluded from both lists and reported
separately, so a selection that mixes expired and unexpired work shows exactly
which half is in play.

### Keys with live data

By default the package refuses to destroy a key that data still in use depends
on, and the two halves refuse at different moments.

The question — "does live data still depend on this key" — is answered by the
database, not by matching strings: every data encryption key row references its
key encryption key by foreign key, so the count of silos that would lose data is
a join. It is exact for every adapter, including a custom one, and it is the same
number the schedule refusal, the schedule confirmation, and the delete
confirmation all report.

A **key encryption key** is refused at **scheduling**, not at deletion.
Scheduling one the deletion could never destroy would leave it waiting out a
restore window under a promise nothing would keep. The message names the keys and
the setting that would permit it.

A **data encryption key** is refused at deletion, when the silo it belongs to
still exists — or when the silo adapter cannot say whether it does. The row is
left where it is: still scheduled, still restorable. Resolve the cause and run the
deletion again. The confirmation screen lists refused rows apart from the ones it
will destroy, with the reason.

Every refusal is recorded. A refused *scheduling* appends a
`deletion_schedule_failed` event to the key's ledger; a refused *deletion* appends
`deletion_failed`. Both carry the acting user and a stable reason slug, so an
attempt to destroy a key that live data depends on leaves a trace even though
nothing was destroyed — see
[Refused attempts](key-lifecycle-events.md#refused-attempts--terminal-and-transient) for
which refusals move a key to `retained` and which leave it to be retried.

Both are governed by
[`KEY_DELETION_CAN_RENDER_DATA_INACCESSIBLE`](configuration.md#key_deletion_can_render_data_inaccessible),
which exists for the case where making live data unreadable *is* the intent — an
erasure obligation that requires the records to survive. With it on, both gates
are skipped and the blast-radius counts on the confirmation screens are the only
thing standing between the operator and the loss.

## Key Lifecycle Events

This changelist is the append-only audit trail. Every state transition on either model writes
one event in the same transaction as the act, so key material is never created or
destroyed without a trace. The admin registers it strictly read-only — no add, change, or
delete — and also shows it as an inline on each key's detail page.

**Event**, **Trigger** and **Reason** show the translated words followed by the
code in parentheses — `Rotation abandoned (rotation_abandoned)`, `Script or
schedule (automated)`, `The data encryption key was deleted (dek_deleted)`. Log
lines are always in English and name an act by its event and reason codes
(`event=`, `reason=`), and [Key lifecycle events](key-lifecycle-events.md)
describes every trigger and combination by code, so the code is how a reader of
this page, in any language, finds the matching line or rule.

The changelist carries **Trigger** — whether a person asked for this key event,
it followed another act, or a script did it — and three attribution columns:
**User**, **OS login account**, and **User IP address**. Trigger is the first
thing to read when something looks wrong, because it says whether to look at a
person, at configuration, or at a scheduled job. Filter by event, trigger, key
kind, or user; search by silo UID or key resource name, by a user's numeric id —
the handle an erasure request would use — by OS login account, and by address.

The OS login account and the address may each be stored in plaintext or
encrypted, and both columns show the value either way; a plaintext row costs no
decryption. Search treats them differently because their tables grow
differently. The OS login account matches on any part of the value, ignoring
case: its table holds one row per operator account and sudo combination, so
search reads it whole and decrypts what it must. The address matches only in
full, in either form, since that table can grow with every request under
`all_acts` and an encrypted address is findable only by its exact value. An
encrypted value that can no longer be decrypted shows the fallback label and
matches no search.

Which of the three attribution columns hold anything is
[`USER_IDENTITY`](configuration.md#user_identity)'s decision. A row
whose user has since been deleted shows `Deleted user #<id>` rather than an empty
cell, so the column can still say that somebody acted.

**KMS**, **KEK key version**, **Cryptographic engine** and **Algorithm** say what
protected a data encryption key after each event; the detail page adds the key
encryption key itself. A data encryption key's own history shows them too. They
are blank on a key encryption key's events. See
[Data key protection](key-lifecycle-events.md#data-key-protection).

## Test console

**URL:**
`/admin/encryption_suite/dataencryptionkey/test-console/`

The test console runs encryption operations against an **isolated test
keyset**. Two layers of isolation protect real tenant data:

1. **Sentinel UIDs.** All test-console keysets are stored under reserved silo UIDs
   (`TEST_CONSOLE_FIELD_UID`, `TEST_CONSOLE_FILE_UID` and `TEST_CONSOLE_KEK_UID`).
   `apps.ready` defensively verifies that the silo adapter of every key set cannot
   produce these UIDs for any real silo — mis-wiring raises
   `ConsoleSentinelLeakError` at startup.
2. **Purpose partition.** Test-console rows use `PURPOSE_TEST`. Field
   and file encrypt/decrypt paths filter on `PURPOSE_FIELD` /
   `PURPOSE_FILE` respectively — data encrypted here cannot be decrypted
   as real data, and the reverse.

### In-memory and KMS tests

**In-memory path — no KMS, no database.** This path generates a throwaway encryption key
with the configured crypto backend in process memory, encrypts the test payload,
decrypts it back, and reports whether they match. Use this to confirm the
crypto backend is healthy without involving the KMS at all.

**Full KMS path.** Uses the persisted `PURPOSE_TEST` keyset (or creates it on
first run), goes through `encrypt_key` / `decrypt_key` on a real KMS adapter, and exercises the same field (AEAD) and file (Streaming AEAD)
crypto as production writes do.

A **Key set** selector chooses which key set the full-KMS path tests. It lists each key
set with its store, as in `default (fly)`, and starts on `default`. Picking one reloads
the page with the configuration box of that key set's store, colored by the key set's
own last result: each key set keeps its own results for the full-KMS tests, while the
in-memory and storage results are shared. The first line of the key management box
is the **Key store**. **Delete** removes the test keys of every key set.

Each runs in both **field** and **file** mode, so the console offers
field/file × in-memory/full round-trip checks plus a read-only storage
reachability probe. Every call is rate-limited per user and emits an audit
entry with user, action, and input size — never content.

### Create and delete

The console owns the whole life of its keys: they are created here — running
either full-KMS test provisions them — and deleted here. They are not subject
to the soft-delete window, are never offered as changelist actions, and are
never reported as orphans on the Reconcile Keys page — they appear there marked as
test-console keys instead. They are ordinary rows on both changelists.

Test keys accrue ledger history like any other key while they exist: the console
drives the KMS adapter directly rather than through the engine, so it writes the
events itself — `created` for a fresh key, `reencrypted` when the keyset is
replaced under the same sentinel UID, and a first-sighting event for the key
encryption key behind it (`created` when the provisioner made it, `discovered`
when it was already there).

Both console tests share **one** key encryption key per store. The two row UIDs
identify rows only — a data encryption key row is unique on
`(key_set, silo_uid, purpose)` and both console rows are `PURPOSE_TEST`, so they need
distinct UIDs to coexist — but every KMS call is made under a single UID, so a
deployment provisions and pays for one test key, not one per test. Each key set gets
its own pair of rows, named `enctestfieldkey` and `enctestfilekey` and recorded under
that key set. Two key sets on one store therefore have two pairs of rows and share one
key encryption key. To list the test keys on the Data Encryption Keys changelist, filter
its **Purpose** column on "Admin test console (isolated)". The test KEK keeps the name the store's
strategy gives it, except on an env key store, whose strategy gives every UID the
shared key `shared`: there the console records its key as `enctestkey`, wrapped under
the same `ENV_KEY_STORES` material at its highest version.

**Delete** is the cleanup: it removes the `PURPOSE_TEST` rows, their ledger
events, and — only when the provider deleted the key **outright** — the matching
key encryption key rows and their events. When the provider merely *scheduled*
the deletion (AWS, GCP, Azure, OCI, IBM), the key encryption key row is kept as
`deletion_requested` with the provider's date: the key still exists, still costs
money, and its alias still resolves to enumeration, so removing the row would
leave reconcile seeing a listed key backing no silo and correctly calling it an
orphan. A later reconcile confirms it `deleted` once the provider finishes. This is a deliberate exception to the
rule that rows are never deleted, and it applies only to these isolated sentinel
keys, so the next run starts from a clean slate. The history is destroyed with
them; the console's own audit log still records that a cleanup ran, who ran it,
and what it removed.

One consequence of keeping history: a row is `PROTECT`-guarded once it has
events, so any path that discards a test row clears its events first. That
applies to the cleanup above and to the discard of a row whose keyset a
different crypto backend produced.

The test key encryption key itself is deleted **only when it is provably the console's
own**: silo-exclusive, the provisioner supports deleting, the name carries this
deployment's owner prefix (or the key is a `KEK_MAP` value marked
`KEK_MAP_DESTROYABLE`), and no other non-test row references it. Otherwise
it is **retained** — a shared key, an opaque `KEK_MAP` key, a key provisioned
outside this application, or one still in use is never destroyed. A retained key still
exists on the provider and **keeps incurring charges until you delete it by
hand**; because its rows are gone, reconcile will report it as an orphaned KMS
key so it does not stay invisible.

### Logging

All test-console calls log to the `encryption_suite.admin_test_console`
logger. Route this logger to an append-only sink (syslog, a WORM
bucket, SIEM pipeline) to preserve the "every call logged" property
against an admin-UI compromise.

## Rendering models with encrypted fields in the admin

Django's admin reads every field it renders on the list and change views. In
a request where the silo adapter resolves no silo (common for multi-tenant
apps: the site-wide `/admin/` has no team context), each read of a silo
encrypted field fails with `configuration_error`. In the default lenient mode
the page renders the fallback label in place of each value and logs one ERROR
line per value read; a field declared `decrypt_mode="strict"` raises instead,
and saving the change form fails, since a write needs a silo.

### The mixin

Apply `EncryptionAdminMixin` to any `ModelAdmin` for a model that
declares encrypted fields or `EncryptedFileField`:

```python
from django.contrib import admin
from encryption_suite.admin_mixins import EncryptionAdminMixin

from .models import SharedData

@admin.register(SharedData)
class SharedDataAdmin(EncryptionAdminMixin, admin.ModelAdmin):
    list_display = ("id", "team", "title", "body")
    # title and body are encrypted — shown as ciphertext previews.
```

The mixin does the following:

- **Excludes** encrypted fields and `EncryptedFileField` from the change
  form. They cannot be edited through this admin. Operators who need to
  edit encrypted values must use an in-tenant frontend that sets the
  silo context. Files cannot be downloaded from the admin — use a
  tenant-scoped view with `serve_encrypted_file` instead.
- **Rewrites** `list_display` entries for encrypted fields to a preview
  method that fetches the raw ciphertext via a raw SQL cursor (bypassing
  the field's decrypting descriptor entirely) and renders a truncated
  preview. The changelist fetches every preview column for the whole page
  in one query; a preview used elsewhere, such as in `readonly_fields`,
  queries its own row. For `EncryptedFileField`, the preview shows the full stored
  storage key exactly as the row holds it (e.g.
  `encryption_suite_default/<uuid>.bin` under the default `upload_to`, or whatever
  prefix a custom `upload_to` produced). The key is safe to display and
  confirms a file is attached.
- **Restricts** the queryset with `.only(...)` to non-encrypted columns,
  so loading the rows reads no ciphertext. Django loads an encrypted
  attribute from the database, and the package decrypts it, only when code
  reads it.
- **Marks the instances its queryset loads**, so their `__str__` never
  decrypts. The admin calls `str(obj)` for the action checkbox, page
  titles, messages, the delete confirmation and the history log, which
  stores the result. A `__str__` that reads only plain columns shows as it
  always does. One that reads an encrypted field shows Django's default
  `<Model> object (<pk>)` instead. The package attempts no decrypt and logs
  nothing, even when a silo is in context. Rows that another admin loads, such
  as the cascade list when you delete a team, get the same label whenever no
  silo is in context, and each logs a WARNING line. See
  [A model's `__str__`](encrypted-data.md#a-models-__str__).
- **Adds the primary key and every column an encrypted field binds with `aad=`
  to `list_display`** when they aren't already declared. Decrypt-failure
  log entries identify the offending row as
  `row [pk=<value>,<aad_col>=<value>,...]`; surfacing those columns in
  the changelist lets an operator locate and remediate the row directly
  from the admin. The columns are added after the ModelAdmin's declared
  entries, so the default change-form link stays on the leading column.

The mixin is strict by design: admin is treated as a forensic view,
not a data-entry surface.

The mixin covers the admin's own model only. A related object, such as the row behind a foreign key in
`list_display` or the raw-ID widget, or a row in an inline, loads through its own query, and
its `__str__` follows the ordinary rule: it decrypts when the field's silo is in context
and shows `<Model> object (<pk>)` when none is. A system key set's silo is always in
context, so a related object whose `__str__` reads a system field shows the plaintext.
Any code running in the application can read that field, and the admin is no exception.

### System check

`manage.py check` emits `encryption_suite.W050` for every registered
`ModelAdmin` that renders a model with encrypted fields but does not
use the mixin:

```
System check identified some issues:

WARNINGS:
share.SharedDataAdmin: (encryption_suite.W050) share.admin.SharedDataAdmin
renders share.SharedData which has encrypted fields (title, body) without
encryption_suite.admin_mixins.EncryptionAdminMixin, so outside a silo context
every encrypted value renders as the fallback label, logs an error, and the
change form cannot save.
```

Only fields of a key set that needs a resolved silo count: a model whose encrypted columns are all
in system key sets needs no silo from the context and draws no warning.

Silence the warning by either adding the mixin or unregistering the
admin (`admin.site.unregister(SharedData)`).

### Every key set

The mixin applies to every key set, the `system` key set included. For a model with
columns of a key set that needs a silo, such as a [user-specific key
set](user-specific-silos.md), the mixin keeps another user's values from showing in the
admin. Without it, a user-specific column decrypts on the logged-in staff member's own row
and shows the fallback label on every other user's row. A `system` column decrypts
without the mixin, since it needs no request context.

### Cases against the mixin

If you have a dedicated per-tenant admin surface (e.g. django-tenants
schema-routed `/admin/` where every request has a tenant in context),
the silo always resolves. In that setup the mixin is unnecessary — decryption
works correctly and you can edit encrypted fields through the admin form.

## Log lines from outside the package

Under an ASGI server you may see this while using the Reconcile Keys page or the
test console:

```
StreamingHttpResponse must consume synchronous iterators in order to serve them
asynchronously. Use an asynchronous iterator instead.
```

It is not an encryption failure and nothing in this package streams a response
here. Both pages show status icons from Django's own admin static files
(`icon-yes.svg`, `icon-no.svg`, `icon-unknown.svg`), and Django serves static
files as `FileResponse` — a subclass of `StreamingHttpResponse`. The warning is
Django noting that a synchronous file iterator is consumed in a threadpool rather
than natively async. It appears for the icons, not for the page.

Worth writing down only because these pages are where you are most likely to meet
it, and the natural assumption is that the encryption suite caused it. If you
want it gone, it is a static-files question for your deployment — serving admin
assets through an ASGI-aware path or a reverse proxy — and unrelated to
encryption.

## Related

- [Getting started](getting-started.md) — initial wiring
- [Logging](logging.md) — routing and retention
- [Key lifecycle events](key-lifecycle-events.md) — the verbs the changelists write
- [Management commands](management-commands.md) —
  `setup_encryption_keys`, `reencrypt_keys`
