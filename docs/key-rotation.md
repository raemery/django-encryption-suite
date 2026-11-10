# Key Rotation

This page covers the rotations of a silo's keys. The system silo — the
`key_set="system"` columns no group of users scopes — has the same keys and rotates the same way,
with one difference worth reading first: see
[Rotating the system silo's keys](#rotating-a-system-key).

| Rotation | What moves | Command | KMS |
|---|---|---|---|
| [Key encryption key](#kek-rotation-effects) | The envelope around each silo's data keys. No application data is touched. | [`reencrypt_keys`](management-commands.md#reencrypt_keys) | yes |
| [Data encryption key](#rotating-a-data-encryption-key) | Every encrypted field and file in a silo, onto new key material. | [`reencrypt_data`](management-commands.md#reencrypt_data) | yes |
| [Blind index key](#rotating-a-blind-index-key) | Every digest in a silo, recomputed under new key material. No value is rewritten. | [`reencrypt_data --purpose index`](management-commands.md#reencrypt_data) | yes |
| [The system silo's keys](#rotating-a-system-key) | The same three, for the `key_set="system"` columns, under the env store `KEY_SETS` gives the `system` key set. | the same commands with `--key-set system` | no |

The first two are what most of this page is about, including how to run them where
you may not have direct CLI access. A change of KMS, crypto backend, algorithm or
storage is summarized, setting and command, in
[Switching what protects your data](switching.md).

---

## Background: two layers of keys

The envelope has two layers. The system silo has both as well: its data keys are
rows here, and its key encryption key is `ENV_KEY_STORES`, on the env key store.

| Key | What it does | Where it is held |
|---|---|---|
| **KEK** (Key Encryption Key) | Encrypts/decrypts the DEK | Your KMS provider (GCP, AWS, Azure, HashiCorp Vault, etc.) |
| **DEK** (Data Encryption Key) | Encrypts/decrypts field values | Stored encrypted in `DataEncryptionKey`; decrypted only in process memory |

When you rotate a key encryption key, the DEK itself does not change — only the
envelope around it is replaced. Rotating the DEK is a separate, heavier operation
with its own command; it is described [below](#rotating-a-data-encryption-key).

---

## KEK rotation effects

When your KMS provider rotates a key (or you create a new key version), the
provider marks the new version as the **primary** for future encrypt
operations. Critically, **old versions remain available for decrypt**. This
is standard behavior across all major providers:

- **AWS KMS** — old key versions decrypt automatically (the version is
  embedded in the ciphertext metadata)
- **GCP Cloud KMS** — old versions remain enabled for decrypt unless
  explicitly disabled or destroyed
- **Azure Key Vault** — same pattern; old versions decrypt, new version
  encrypts
- **HashiCorp Vault (transit)** — old key versions decrypt; new version is used for new
  encrypts
- **IBM Key Protect, OCI Vault, Infisical** — same pattern; each resolves the
  version that produced a ciphertext from the ciphertext itself

Fly.io KMS is the exception: it versions nothing, so a "rotation" there is a new
key under a new name and the old wrapped DEKs must be re-wrapped before the old
key goes away. See [Provider note: Fly.io KMS](#provider-note-flyio-kms) below.

This means that after a KEK rotation, **everything continues to work
without any immediate action**. The encrypted keysets in your database were
encrypted by the old KEK version, and the KMS provider still knows how to
decrypt them using that old version.

---

## Re-encryption after rotation

Even though the system keeps working, the encrypted keysets are still
protected by the old KEK version. Re-encryption updates them to use the new
version:

1. **Retire old key versions.** Until all encrypted keysets are re-encrypted,
   you cannot safely disable or destroy the old KEK version in your KMS
   provider. Re-encryption lets you decommission old versions.

2. **Compliance.** Many security policies require that key material be
   re-encrypted under current keys within a defined window after rotation.

3. **Limit exposure.** If the old KEK version were ever compromised, any
   encrypted keysets still using it would be at risk. Re-encryption limits
   the window of exposure.

Re-encryption does **not** re-encrypt any field data in the database. The DEK
inside the envelope is unchanged — only the envelope itself is replaced. This
makes re-encryption fast and safe; it touches only the
`DataEncryptionKey` table, not your application data.

### Existing rows

A stored field or file is encrypted by the DEK; the DEK is wrapped by the KEK.
Rotation moves the outer layer only:

```
field ciphertext  ──encrypted by──>  DEK  ──wrapped by──>  KEK (in your KMS)
```

`reencrypt_keys` unwraps the DEK with the old key material and rewraps it with
the new. The DEK bytes that come out are byte-identical to the bytes that went
in, so every ciphertext ever written under it stays valid. There is nothing to
re-encrypt at the data layer, and no row needs to be touched or saved. A field's
ciphertext changes only when the application writes to it, exactly as it would
have without a rotation.

Rotating the **DEK** is a different operation: it decrypts and re-encrypts every
field and file in the silo before the new keyset replaces the old one, because
replacing a keyset while anything is still encrypted under it strands that data.
KEK rotation is cheap precisely because the data layer never moves.

### Re-encrypted keys

`reencrypt_keys` attempts only the DEKs a rewrap can succeed on. Everything else
is reported as skipped so the failure count means a real failure:

- **Test-console keys** protect a fixed throwaway payload the console recreates
  on demand, so there is nothing worth preserving.
- **DEKs that are neither active nor under a data key rotation** — a
  `deletion_scheduled` DEK is blocked from encrypt and decrypt for its restore
  window, and a deleted one is a tombstone whose `encrypted_keyset` has been
  cleared to empty. A `reencrypting` DEK is re-wrapped like an active one, and so
  is the incoming key its rotation holds, in the same transaction: nothing else
  re-wraps that key, so skipping it would strand the material the silo is being
  moved onto.
- **DEKs whose key encryption key has been retired** (scheduled, requested, or
  deleted) have nothing left to unwrap them. These were retired deliberately.
- **DEKs on a KMS no `KMS_KEY_STORES` block names.** Nothing here can unwrap
  them. This is what a run pointed at the wrong settings module looks like: every
  row is skipped and named, rather than every unwrap being aimed at an unrelated
  KMS.
- **DEKs already wrapped by the current key version of their key set's store**, where the
  provider reports one (see [Key versions on the row](kms-adapters.md#key-versions-on-the-row)).
  Re-wrapping these would cost a KMS round trip to produce the same result.
  Providers that report no version have all their rows re-wrapped.

A dry run reports the same decisions the real run will make, so a preview showing
nothing but skips tells you the run would do no work.

### Reading the output

```
Re-encrypted: team-7 [field] -> write 4, key version 3
```

`write 4` counts how many times new encrypted key material has been written to
this row — by a re-wrap like this one, or by a data key rotation's swap. It is
**not** a KMS key version — the key may never have been rotated. `key version 3`
is the provider's own version identifier, and appears only for providers that
report one; on AWS or Fly.io the line ends after the write count.

Occasionally a run reports a version other than the one it was aiming for:

```
Re-encrypted: team-7 [field] -> write 4, key version 2 (provider has not moved to 3 yet — rerun later)
```

Nothing is wrong, and nothing needs undoing: the row was re-wrapped under a live
key version and records the version that actually wrapped it. Some providers pick
the version server-side, and their metadata can move ahead of their crypto —
Cloud KMS is explicitly eventually consistent after a rotation, taking anywhere
from under a minute to a few hours to route encrypts to the new primary. Wait,
then run again. **The dry run is the reliable "am I finished?" signal**: when it
reports every row skipped, every row is on the current version.

Skipping relies on the local lifecycle state being current. If a KEK was retired
at the provider but this deployment has not learned that yet, its DEKs are still
attempted and fail at the KMS. Run **Reconcile Keys** first if the two may have
drifted.

---

## Re-encryption methods

### Via the management command (direct CLI access)

If you can run Django management commands directly:

```bash
# Re-encrypt all silos
python manage.py reencrypt_keys

# Re-encrypt a single silo
python manage.py reencrypt_keys --silo-uid "team-42"

# Preview what would be re-encrypted without contacting KMS
python manage.py reencrypt_keys --dry-run
```

See [Management commands](management-commands.md) for full option reference.

### Via platform-specific one-off commands

Most cloud platforms let you run a one-off command using your app's container
image and environment:

**Fly.io:**
```bash
fly ssh console -C "python manage.py reencrypt_keys"
```

**Heroku:**
```bash
heroku run python manage.py reencrypt_keys
```

**AWS ECS:**
Create a one-off task using your existing task definition with a command
override:
```bash
aws ecs run-task \
  --cluster your-cluster \
  --task-definition your-app \
  --overrides '{"containerOverrides": [{"name": "web", "command": ["python", "manage.py", "reencrypt_keys"]}]}'
```

**Google Cloud Run Jobs:**
```bash
gcloud run jobs execute reencrypt-keys \
  --region your-region
```
(Requires a Cloud Run Job configured with your app image and the management
command as the entrypoint.)

**Kubernetes:**
```bash
kubectl exec -it deploy/your-app -- python manage.py reencrypt_keys
```
Or create a one-off Job:
```yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: reencrypt-keys
spec:
  template:
    spec:
      containers:
        - name: reencrypt
          image: your-app-image
          command: ["python", "manage.py", "reencrypt_keys"]
          envFrom:
            - secretRef:
                name: your-app-secrets
      restartPolicy: Never
```

### Via a staff-only endpoint or admin action

If your deployment has no shell access at all, you can expose re-encryption
through your application. The management command is a thin wrapper around
library code that can be called from anywhere — a Django view, an admin
action, or a Celery task.

Call the command itself through `call_command`, so your path gets everything
the command does: per-row routing to the KMS each row records, the rotation
fence, the lifecycle record, and cache invalidation.

Example admin action:

```python
from django.core.management import call_command


def reencrypt_selected_keys(modeladmin, request, queryset):
    silo_uids = queryset.values_list("silo_uid", flat=True).distinct()
    for silo_uid in silo_uids:
        call_command("reencrypt_keys", silo_uid=silo_uid)
    modeladmin.message_user(request, f"Re-encrypted the keys of {len(silo_uids)} silo(s).")

reencrypt_selected_keys.short_description = "Re-encrypt selected keys with current KEK"
```

Example Celery task:

```python
from celery import shared_task
from django.core.management import call_command


@shared_task
def reencrypt_all_keys():
    call_command("reencrypt_keys")
```

---

## The full rotation workflow

1. **Rotate the KEK in your KMS provider.** Create a new key version and mark
   it as primary. The exact steps vary by provider — consult your provider's
   documentation.

2. **Verify the system still works.** No immediate action is required after
   rotation. Your application continues to decrypt using the old KEK version.
   Confirm that reads and writes to encrypted fields are functioning normally.

3. **Re-encrypt all keysets.** Run `reencrypt_keys` using any of the methods
   described above. The command decrypts each keyset with the old KEK version
   and re-encrypts it with the new primary version.

4. **Verify re-encryption completed.** Check that the run's summary reports
   `Failed: 0`. On a provider that reports key versions, `reencrypt_keys
   --dry-run` then reports every row skipped. Each row the run re-wrapped has
   its `DataEncryptionKey.reencryption_count` incremented; a row already on the
   current version is skipped and keeps its count.

   Then read a record written *before* the rotation. This is the check that
   matters: it proves the DEK unwrapped from the new envelope still decrypts
   ciphertext produced under the old one, which is exactly what a corrupted
   rewrap would break. Writing and reading back a new value only exercises the
   current envelope and would pass either way.

   Restart your application processes first. The DEK is cached per process, and
   the command's cache invalidation reaches only the process it ran in — a
   one-off shell or job, not your web workers. Without a restart a worker may
   serve a DEK it cached before the rotation and the read proves nothing.

5. **Disable or destroy the old KEK version (optional).** Once all encrypted
   keysets use the new version, the old version is no longer needed. Disable
   it first and monitor for errors before destroying it permanently.
   Destruction is irreversible — any encrypted keyset still using the old
   version will become permanently undecryptable.

   Not every provider offers this. See the AWS note below.

---

## Moving to another KMS

Every key encryption key row records the name of the
[`KMS_KEY_STORES`](configuration.md#kms_key_stores) block that holds it, and every
unwrap goes through that block. So two KMSs can serve one deployment at once,
and `reencrypt_keys` moves silo keys between them:

1. **Configure the new KMS as a second block**, beside the one in use. Keep the
   old block unchanged — its name is what the existing rows record.
2. **Point [`KEY_SETS`](configuration.md#key_sets) at the new block**
   for each key set that moves, and deploy. New silo keys go to the new KMS;
   existing ones keep reading through the old block. Several
   [key sets](configuration.md#key_sets) move independently: repoint
   only the key sets you are moving.
3. **Run `reencrypt_keys`.** It makes one pass per key set that fields
   declare, filtering the data keys by the key set, so key sets that sit on
   different stores move the right rows. It unwraps each row through the block
   the row records and re-wraps it under the store `KEY_SETS` gives its
   set, and its output names the move (`Converting: key store … -> …`). Add
   `--provision` when the new KMS does not hold the silos' key encryption keys yet
   and its block has a provisioner.
4. **Verify reads.** Restart the application processes, then read a record
   written before the move, as in step 4 of
   [the full rotation workflow](#the-full-rotation-workflow).
5. **Run [`reconcile_keys`](management-commands.md#reconcile_keys).** Its pass
   over the old KMS reports each key there that no data key uses any more as an
   orphan. The admin's Reconcile Keys page runs the pass for the `default` key set's store only, so it
   does not report them.
6. **Schedule the old key encryption keys** from the Key Encryption Keys
   changelist, filtered on the old KMS, with **Schedule deletion of selected key
   encryption key(s)**.
7. **Wait out the deletion window**
   ([`KEY_DELETION_WINDOW_DAYS`](configuration.md#key_deletion_window_days)).
8. **Delete them** with **Delete selected expired key encryption key(s)**. Each
   deletion goes through the provisioner of the old block, subject to the usual
   [deletion gates](management-commands.md#the-deletion-gates).
9. **Confirm on the old KMS** that the keys are gone or pending deletion.
10. **Remove the old block.**

The same steps move silo keys off an env store (`"default": "login"`) onto a real
KMS, and move a deployment between two adapters for one provider, such as
`AwsKmsAdapter` and `AwsTinkKmsAdapter`. An env store has no provisioner and no
key to delete, and it keeps wrapping the system silo's keys, so a move off it ends
at step 4.

**A change to a field's `key_set` is not this move.** Moving a set to another store
is a settings change followed by `reencrypt_keys`. Changing which set a field
belongs to points the field at a different key: the
existing values were written under the old set's key and fail authentication under
the new one's. Convert the column with `decrypt_field` under the old `key_set`
and `encrypt_field` under the new one (see
[Adopting and removing encryption](adopting-and-removing-encryption.md)).

### Retiring the old KMS

`reencrypt_keys` moves the data keys and leaves the old KMS's key encryption keys
alone. They stay `active` on their rows and keep existing on the old KMS until
something deletes them, and you pay for both KMSs until then.

**The move is reversible until those keys are deleted.** Point `KEY_SETS` back at
the old block and run `reencrypt_keys` again.

**The package deletes them while the old block is still configured** (steps 5 to
8). The purge refuses a key the package cannot prove is its own, with a named
reason:

- a provisioner that cannot delete (`provisioner_cannot_delete`);
- a key outside the owner prefix (`not_owned_by_deployment`);
- a shared key encryption key, or a `KEK_MAP` key without
  [`KEK_MAP_DESTROYABLE`](configuration.md#kek_map_destroyable)
  (`shared_or_opaque_disposition`).

For those, **delete the key by hand, then record it.** Use the provider's console
or CLI, then record the deletion with **Record selected as deleted in the key store**,
or with
[`record_key_event`](management-commands.md#record_key_event)
`--key-store <old block> --event deleted --kek-resource-name <name>`.

**Remove the old block last.** A row that records a removed block is out of the
package's reach: reads fail with `kms_provider_mismatch`, `reencrypt_keys` skips
the row and names it, reconcile runs no pass over that KMS, and the purge has no
provisioner to delete the key with.

---

## Provider note: AWS KMS

AWS rotates key material **in place** — the key ID, ARN and alias never change,
and neither does the key encryption key each DEK references. After a
rotation the only visible movement is in the envelope itself: new ciphertext
bytes and an incremented `reencryption_count`. Do not expect the resource name to
change; it not changing is the correct outcome.

Keys the package provisions can be put on an automatic schedule at creation:
set `KEK_ROTATION_PERIOD_DAYS` in `KEK_PROVISIONER_OPTIONS` and `AwsKekProvisioner`
calls `EnableKeyRotation` with it. AWS accepts 90 to 2560 days. See
[automatic key rotation](kek-provisioning.md#automatic-key-rotation).

Rotate on demand rather than waiting for the annual schedule:

```bash
aws kms rotate-key-on-demand --key-id alias/your-key-name
```

On-demand rotation is limited to 10 rotations per key, for the life of the key,
and applies only to symmetric encryption keys whose material AWS generated.

To confirm a rotation happened, use the AWS console: **Key Management Service
(KMS)** → **Customer managed keys** → click the key → the **Key material and
rotations** tab, which lists each rotation and its date.

**Step 5 of the workflow above does not apply to AWS.** AWS retains every
rotation's material for the lifetime of the key and offers no way to disable or
destroy an individual version, so old material cannot be decommissioned. On AWS,
re-encryption buys you compliance with a rotation policy and limits which
material protects current envelopes — it does not let you retire anything. If
your goal is to genuinely stop relying on a piece of key material, the AWS-shaped
equivalent is a whole-key migration: create a second key, repoint
`KEK_TEMPLATE` at it, run `reencrypt_keys`, then disable the original key and
confirm reads still work. That is a name rollover, so the naming rule in the next
section applies to it.

---

## Name rollover

Everything above assumes the provider can rotate key material behind a stable
name. Most can: AWS KMS, Azure Key Vault, Google Cloud KMS, HashiCorp Vault, IBM
Key Protect and OCI Vault all rotate in place, and this package can put the keys
it provisions on an automatic schedule on each of them — on OCI only in a virtual
private vault. See
[automatic key rotation](kek-provisioning.md#automatic-key-rotation).

**If your provider rotates in place, use that.** What follows is a workaround for
providers that offer no rotation at all, and it costs more than a rotation does:
a second key per silo for as long as both generations exist, a full re-wrap pass
over every data encryption key, and old keys you have to clean up yourself. Fly.io
KMS is the example — it has no rotation of its own, so on Fly this is not a
workaround but the only path, and it has [its own section](#provider-note-flyio-kms)
below.

A name rollover means: leave the existing key alone, create a second key under a
new name, move every DEK's wrapper onto it, then retire the first.

### The naming rule

**Put the generation marker after `{silo_uid}`, never before it.**

```
KEK_TEMPLATE = "kms_{silo_uid}_v2"      # correct
KEK_TEMPLATE = "kms_v2_{silo_uid}"      # breaks ownership
```

The package identifies the keys it owns by the literal text of `KEK_TEMPLATE`
before the `{silo_uid}` placeholder — the owner prefix. It decides which keys are
listed from the provider during reconcile, which keys the deletion gates
authorize, and which keys belong to this deployment rather than another sharing
the same KMS.

Change that prefix and the previous generation stops being yours as far as the
package is concerned. It is no longer enumerated, no longer reported as an orphan,
and the admin refuses to delete it — while the keys stay on the provider, still
billable, removable only through the provider's own console or CLI. Keep the
prefix fixed and both generations remain owned, listed and deletable for the whole
rollover.

`reencrypt_keys --provision` enforces this: it checks every key it is about to
roll off against the live owner prefix and refuses the entire run if the prefix
has moved, before creating anything.

### The rollover

1. Point `KEK_TEMPLATE` at the next generation.
2. Deploy. New silos provision under the new name; existing rows still reference
   the old key and keep decrypting.
3. `python manage.py reencrypt_keys --provision --dry-run` — contacts no KMS,
   lists the key names it would create, and refuses if the owner prefix changed. If see any issues at this point, back out the change in step 1, and redeploy.
4. `python manage.py reencrypt_keys --provision` — provisions each silo's new key,
   then unwraps and rewraps each DEK onto it.
5. Confirm every `reencryption_count` incremented, then retire the old keys:
   Reconcile Keys to refresh the orphan flags, then the Key Encryption Keys
   changelist filtered on **Orphaned** to schedule them, and delete after the
   restore window.

> **Do not act on the orphan report until step 4 has finished.** Reconcile decides
> what is orphaned by resolving the *current* template for every live silo, so the
> previous generation is reported as orphaned the moment step 2 deploys — while
> every data encryption key still depends on it. Deleting a key at that point
> destroys the only thing that can unwrap the DEKs still referencing it.

---

## Provider note: Fly.io KMS

Fly KMS has no rotation and no soft delete. Deleting a key destroys it
immediately, and Fly is explicit that this is the design — deleting the key is how
you make the data it protected unreadable, so there is deliberately no recovery
path.

`flyctl` shows secretkeys with version suffixes (`myencrkeyv0`, `myencrkeyv1`) and
a version column, which suggests the provider tracks generations behind a name. It
does not. Those suffixes are parsed client-side by the CLI; on the Machines API
and the `/.fly/api` socket this package uses, a suffixed name is just a literal
name with no version field, encrypting against the unsuffixed base name returns
404, and deletion targets the exact literal name. There is no "encrypt with the
latest version" on this path.

So rotation on Fly is the name rollover described above, and Fly is the one
provider where that is the primary procedure rather than a fallback. Because Fly
deletes immediately, the ordering warning matters more here than anywhere else:
an old-generation key removed before the rewrap completes cannot be recovered by
the provider, by support, or by this package.

### Reading `fly secrets keys list` after a rollover

A `_v2`-style generation marker collides with the CLI's own suffix parsing, so
the listing splits your key names apart:

```
 LABEL           │ NAME          │ VERSION │ TYPE
 kms_team_2d1_v4 │ kms_team_2d1_ │ 4       │ encrypting (xaes256gcm)
```

**`LABEL` is the key.** `kms_team_2d1_v4` is the literal name the Machines API
stores, the socket encrypts under, and deletion targets. `NAME` and `VERSION` are
the CLI stripping a trailing `v4` client-side — which is why `NAME` ends in a
stray underscore, and why the version column reads `unspec` for a key whose name
carries no such suffix.

There is no key called `kms_team_2d1_`, and no version history behind it. Read the
table as one row per independent key, and use `LABEL` when naming a key to any
other tool.

The step-by-step walkthrough, with the Fly-specific commands, is in
[Getting started on Fly.io](getting-started-fly.md#rotating-a-key-encryption-key).

---

## The two rotation dates

Each `DataEncryptionKey` row carries two dates. They answer the same question —
*when did this row last move onto fresh key material?* — one layer apart, and
neither can answer for the other.

| Column | Layer | Written when | Answers |
|---|---|---|---|
| `key_material_last_generated_at` | DEK | the data key's bytes are generated | how old the data key itself is |
| `last_reencrypted_at` | KEK | `reencrypt_keys` rewraps the row | how long ago this row moved onto current KEK material |

A third column, `dek_key_version`, counts generations of the data key's own
material: `1` for the first key, one higher on each data key rotation and on each
revival of a deleted key. It is **not** a provider identifier (`kek_key_version`
is), and it is **not** `reencryption_count`, which counts every write of new
encrypted key material to the row — a re-wrap of the same material as well as a
rotation's swap.

**Why `last_reencrypted_at` records the rewrap and not the rotation.** Rotating
a key encryption key at the provider accomplishes nothing for data already
stored: until `reencrypt_keys` runs, every stored envelope is still protected by
the old material — which is why an old version cannot be retired before
re-encryption finishes. The rotation is the precondition; the rewrap is the act
that ends the old material's role for a given row, so the rewrap is what carries
the date. It is also a fact the application performs and records transactionally
with the act, at the per-row grain the question is actually asked at, on every
provider — including AWS KMS and Fly KMS, where the *version* is unknowable but
"every envelope was rewrapped at time T" is the meaningful claim anyway.

**Why the material date is not `created_at`.** Deleting a data key leaves the row
behind as a tombstone, and provisioning that silo again reuses it. The revived
row gets brand-new material while keeping the creation date of its first life, so
`created_at` would date fresh bytes to whenever the silo first had a key.

**What moves them, and what does not.** A rewrap moves `last_reencrypted_at` and
leaves `key_material_last_generated_at` alone — the data key's bytes are
identical, only the envelope changed. New data key material moves
`key_material_last_generated_at`: a first provision, a revived tombstone, and a
data key rotation's swap.

### Seeing which keys are due

Declare a cryptoperiod with
[`DEK_ROTATION_PERIOD_DAYS`](configuration.md#dek_rotation_period_days) and the
Data encryption keys changelist gains a **Rotation due** column and filter,
computed from `key_material_last_generated_at` at display time. The detail page
adds a **Re-encryption due** reading for the layer above, dated from
`last_reencrypted_at` against the `KEK_ROTATION_PERIOD_DAYS` you gave the KEK
provisioner. Both say nothing at all when the period is not declared or the date
is not recorded — a guess would be read as a compliance statement.

Neither reading blocks, refuses, or schedules anything. They report; you act.

### Seeing that a key was rotated at all

A key encryption key rotated in the provider's console leaves no trace here on
its own. Reconcile finds it: each pass asks the provider for the current version
of every key it knows, and a version that differs from the one last recorded
appends a `rotated` event to that key's
[lifecycle record](key-lifecycle-events.md) and stamps the new value on the row,
where the KMS Keys changelist shows it as **KEK key version**. A key with no
version recorded yet is a first sighting rather than a rotation: the value is
stamped and nothing is recorded.

The verb records the *cause*; the obligation it creates is already reported as
"Key re-encryption due", which is what you act on. Rotation detection needs only
a version lookup, not a listing, so it runs even on a deployment whose
provisioner cannot enumerate keys. Like the state check it is bounded by a probe
budget, orphans first; the run log says `probes_capped=True` when a pass stopped
at that boundary and so covered only part of the keys.

A data key rotation records its own verbs — `rotation_started` when it opens,
`rotated` at the swap, `rotation_abandoned` if it is undone — described in the
next section. `rotated` is the one verb both layers share; `silo=` and
`purpose=` on the log line tell a data key's apart from a key encryption key's.

---

## Rotating a data encryption key

`reencrypt_keys` re-wraps keys and never touches data. Replacing a silo's data
key is `reencrypt_data`: it decrypts every encrypted field and file in the silo
under the current key, encrypts it again under freshly generated material, and
only then swaps that material in as the silo's key. See
[`reencrypt_data`](management-commands.md#reencrypt_data) for every option.

```bash
python manage.py reencrypt_data --dry-run                 # what a run would do
python manage.py reencrypt_data --silo-uid "team-42"       # fields, then files
```

A [user-specific key set](user-specific-silos.md) rotates one user at a time with `--key-set user --silo-uid "user-42"`. Without `--silo-uid`, `--key-set user` rotates every user, and `reencrypt_keys --key-set user` moves or re-wraps that key set's keys, between an env store and a KMS store included.

### Blocked operations

The data key under rotation is **fenced**: its status is `reencrypting`, and for
that silo and purpose every encrypted read yields the fallback and every encrypted
write fails with `dek_reencryption_in_progress`, until every row is back on one
keyset. Unencrypted columns are untouched, and the silo's other purpose is
unaffected — a field rotation leaves file content readable, though file *names*
are field data and go dark with it. See
[handling errors](handling-errors.md#while-a-data-key-is-being-rotated) for what an
application sees.

The fence is up for the whole sweep plus an idle wait before it: the command
waits a full `DEK_CACHE_TTL` plus a margin, so that no process still holds the
old key in its cache when conversion starts. It says so when the wait begins. The
wait is measured from when the fence went up, so interrupting it is safe — a
rerun waits out only the rest. `--purpose all` (the default) serves the wait once
per purpose.

### Resuming

Every step is recorded as it happens, so rerunning the same command resumes: an
interrupted wait finishes, a half-built list of rows is rebuilt, a sweep carries
on from the first row it had not converted, and a run killed just before the swap
swaps. Nothing is converted twice.

### Unconvertible rows

A row that fails is recorded and skipped; the sweep carries on to the end, then
**refuses to swap and leaves the fence up**, because swapping would destroy the
key that row is still encrypted under. The command prints each outstanding row —
model, primary key, field or file, error code, and each AAD-bound column marked
populated or empty — and ends with the two ways out:

- **Repair and rerun.** A storage timeout or an unreachable provider clears on a
  rerun alone. A changed or emptied AAD-bound column, ciphertext that no longer
  authenticates, or a row in the wrong silo is a defect that predates the
  rotation: restore the value, correct the assignment, or delete a row whose
  plaintext is gone, then rerun. Rows already converted stay converted.
- **Roll back** with `--abort`, which moves converted rows back onto the old key
  and lowers the fence, putting the silo back in service while the rows are
  repaired at leisure. It can discard hours of conversion over a failure a rerun
  would have stepped past, which is why the command never chooses it for you.

Both need the KMS: finishing unwraps both keysets, and rolling back re-encrypts
under the old one, so an unreachable provider holds the fence up until it answers.

### Rolling back

```bash
python manage.py reencrypt_data --silo-uid "team-42" --purpose field --abort
```

A rollback is the sweep run backwards, and it is resumable the same way: an
interrupted one continues backwards on any rerun, `--abort` or not. When no row
is left on the new key, the rotation is abandoned — the new material is
discarded and the key returns to `active` on its old material.

### Deleting a key mid-rotation

Deletion wins. Scheduling a rotating key for deletion moves only its status; the
rotation and its progress survive the restore window, so restoring the key
returns it to `reencrypting` and a rerun finishes the sweep. If the window runs
out instead, the deletion abandons the rotation (`rotation_abandoned`, reason
`dek_deleted`) and destroys the incoming key with the old one.

---

## Rotating a blind index key

A silo's [blind index](encrypted-data.md#finding-a-row-by-its-value) key is a
third `DataEncryptionKey` purpose, so it rotates with the command that rotates
the other two:

```bash
python manage.py reencrypt_data --silo-uid "team-42" --purpose index
```

It inherits the fence, the wait, the dry run, `--abort`, the tally and the
per-purpose report. `--purpose all`, the default, rotates fields, then files,
then indexes wherever a field declares one.

Two things make it unlike the other two purposes.

**It reads with a key it is not rotating.** A digest is a one-way hash of the
plaintext, so the only way to produce the new digest is to decrypt the value
under the silo's *field* key and hash it again. So an index rotation decrypts
every indexed value — where a field rotation at least had to decrypt it anyway —
and it needs the field key to be usable. The opening line says so rather than
naming a backend template, because no crypto backend produces this key.

**No value is rewritten.** Only digests move. A row that fails leaves the value
readable and merely unfindable until the item is retried, and `--abort` restores
the old digests by doing the same work with the keys the other way round —
nothing has to be remembered about the digest that was there before.

While the fence is up, lookups on that silo's indexed columns are refused rather
than answered against two generations of key at once. That is a lookup outage for
one silo for the length of the run, which is the same trade a data key rotation
already makes for reads and writes.

`reencrypt_data --purpose field` leaves digests alone, because the index key is
not the data key. The two move on separate decisions.

## Rotating a system key

The system silo's keys are a silo's keys — field, file and blind index data keys
on rows whose silo uid is `system`, wrapped by one key encryption key. Both rotations
above therefore apply, through the same commands with `--key-set system`. What
differs is the cost of the fence and where the key encryption key comes from.

The system silo's keys are never deleted. Its adapter sets `prevents_key_delete`, so
the deletion gate refuses them even when
[`KEY_DELETION_CAN_RENDER_DATA_INACCESSIBLE`](configuration.md#key_deletion_can_render_data_inaccessible)
is on.

### The key encryption key: `ENV_KEY_STORES`

[`ENV_KEY_STORES`](configuration.md#env_key_stores) maps versions to key material; the
highest version wraps new keys. No outage:

1. Add the next version beside the current one and deploy.
2. Once every machine runs the new release, re-wrap the system silo's rows under
   it:

   ```bash
   python manage.py reencrypt_keys --key-set system
   ```

3. Drop the old version once no row records it.

One deploy is enough: nothing wraps under the new version until `reencrypt_keys`
runs, except a system key created for the first time during the rollout, which a
machine on the old release cannot unwrap until it updates.

**Dropping a version a row still records is unrecoverable.** The material exists
only in your settings, so there is no restore behind it. Every system key that
version wrapped stops unwrapping, sign-in with it: the log names the missing
version (`kek_not_provisioned`). Run `reencrypt_keys --key-set system`, confirm it
skipped nothing, then drop the version.

### The data keys: a sign-in outage

```bash
python manage.py reencrypt_data --key-set system                    # field, file, then index
python manage.py reencrypt_data --key-set system --purpose index     # the index key alone
```

This is the [data key rotation](#rotating-a-data-encryption-key) above, with the
same fence, resume and rollback. The difference is what the fence covers. A silo's
fence blocks one team; the system silo's blocks every `key_set="system"` column for the
whole deployment — and sign-in reads them. For the sweep plus the
`DEK_CACHE_TTL` wait, nobody can sign in. Run it in a maintenance window. The
command prints a warning before the wait begins.

---

## Rotation frequency

There is no single answer. Common practices:

- **Annual rotation** — satisfies most compliance frameworks (SOC 2, PCI DSS)
- **Quarterly rotation** — a more conservative posture for sensitive data
- **On-demand rotation** — after a suspected compromise or personnel change
- **Automatic rotation** — six providers accept a schedule, and the package
  writes it from one option, `KEK_ROTATION_PERIOD_DAYS`: AWS KMS (90 days and up),
  GCP Cloud KMS and HashiCorp Vault transit (1 day and up), Azure Key Vault
  (7 days and up), IBM Key Protect (30 to 360 days, in whole months), and OCI
  Vault (60 to 365 days, and — as of August 2026 — only in a virtual private
  vault, a path untested here; Oracle lists automatic rotation for standard
  vaults as *coming soon*). Fly KMS and
  Infisical have no schedule at all. The floors and ceilings are in
  [Automatic key rotation](kek-provisioning.md#automatic-key-rotation). The old
  version remains available for decrypt, but you still need to re-encrypt to
  retire it

Whatever your cadence, the important thing is to re-encrypt after each
rotation so that you can eventually retire old key versions.
