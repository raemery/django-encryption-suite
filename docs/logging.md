# Logging

django-encryption-suite emits structured entries through Python's standard
`logging` module. This page is the system log: what each line means, which level
it carries, and how to route it.

The log is not the record of what happened to a key. That is the
[key lifecycle record](key-lifecycle-events.md), which is stored in the database,
rendered in the reader's language, and kept for as long as the row exists. The log
is English-pinned, rotated, and routinely cut below WARNING by the pipeline that
ingests it, and nothing in the package ever reads it back.
[Auditing](auditing.md) is the one-page guide to which of the two answers a
given question.

## Logger namespacing

Every logger is named for the module that defines it, so they all sit under the
`encryption_suite` namespace and handlers set on an ancestor apply to every
descendant. Configuring `encryption_suite` alone therefore captures everything
the package emits, while a longer name narrows the routing to one part of it:

| Logger name | Emits |
|---|---|
| `encryption_suite.engine` | Decryption success/failure, missing keys, auto-provisioning, key-state refusals |
| `encryption_suite.deletion` | Key deletion: schedule, restore, delete, retain, refuse |
| `encryption_suite.reconcile_service` | Reconcile findings from a pass, wherever it was run from |
| `encryption_suite.management.commands.<command>` | One pair of lines per run of that privileged command: what it was pointed at, and what it did |
| `encryption_suite.storage` | Encrypted file storage backend failures, and file decryption failures |
| `encryption_suite.admin_test_console` | Admin test console actions — route this one to an append-only sink |
| `encryption_suite.silos` | Silo enumeration failures raised outside an adapter |
| `encryption_suite.fields` | Field-level housekeeping failures (e.g. a superseded encrypted file left in storage) |
| `encryption_suite.apps` | Startup and silo-creation signal failures |
| `encryption_suite.adapters.…` | Per-adapter events (e.g. `…adapters.keks.provisioners` for key encryption key deletion) |

The table above is one axis — which part of the package a line comes from.
Raised errors have a second: the line opens with a sentence saying what
happened, and the `error_code=` field after it names the condition.
[error-codes.md](error-codes.md) is the catalog, including which logger emits
each code and a formatter that prints the logger name alongside it.

---
## Logged events

### Successful field decryption (INFO)

`LOG_DECRYPTS` (default `False`) controls this line. When enabled, every
successful field decryption emits:

```
INFO encryption_suite.engine An encrypted field value was decrypted. silo="<uid>" field="<app.Model.field>"
```

Example:

```
INFO encryption_suite.engine An encrypted field value was decrypted. silo="team-42" field="myapp.Patient.national_id" <identity>
```

`row_identity` (the row pk and any AAD-bound columns) is deliberately omitted from this entry. Those values can contain PII and success entries are high-volume — every read emits one — so they are more likely to end up in a general-purpose log aggregator with broader access and shorter retention than error entries. The full scope including row context still appears on the error path, where it is needed to diagnose a security-relevant event.

This tells you which silo's key was used and which field was read. Whether it
also names the reader depends on
[`USER_IDENTITY`](configuration.md#user_identity): under `SCOPE = all_acts`
the identity tail is appended like any other line, so a read is attributed as
far as `LOGS` lists anything; under `privileged_acts` it is not, since a read is
nobody's privileged act and no ledger row records one. If you need attributed
reads under that scope, log access in your own views or middleware.

### Successful file decryption (INFO)

`LOG_DECRYPTS` also controls this line. The package emits it when a decrypting stream
opens for an encrypted file:

```
INFO encryption_suite.engine An encrypted file was decrypted. silo="<uid>" field="<app.Model.field>"
```

Row context is omitted for the same reason as field decryption above: AAD-bound
column values may contain PII and success entries are high-volume. Row context
still appears in error entries for the same stream.

### Decryption failures (ERROR)

The package emits this line regardless of `LOG_DECRYPTS` whenever field or file
decryption fails (malformed ciphertext, wrong silo context, AAD mismatch,
corruption):

```
ERROR encryption_suite.engine Could not decrypt a field value. error_code=field_decryption_failed silo="<uid>" field="<app.Model.field>" row="pk=<pk>" detail="<backend error>" hint="Likely causes: row reassigned to a different silo, ciphertext corruption, or, for AAD-bound rows, an AAD-bound column was changed without re-encryption. See docs/security.md."
```

A failure on the file path is the same event on a different surface, and it is
reported on `encryption_suite.storage` rather than the engine. Its scope carries
`file=<storage path>` inside the row value, and its code is
`file_decryption_failed` — the counterpart to the field path's
`field_decryption_failed`:

```
ERROR encryption_suite.storage Could not decrypt file. error_code=file_decryption_failed silo="<uid>" field="<app.Model.field>" row="pk=<pk>,file=<path>" detail="<backend error>" hint="Likely causes: ..."
```

The row and file parts are omitted when not available (e.g. when `pk` is not
yet set or AAD columns are not configured). The exception raised to application
code is `"Decryption failed."` — it deliberately omits the silo UID and
field name to avoid leaking internal state to end users. Full details are in
the server log only.

#### Decrypt-failure fields

A field that declares `aad=` binds its ciphertext to those
columns, and the `row=` value names each of them — but whether it carries their
**values** is [`LOG_AAD_VALUES`](configuration.md#log_aad_values)'s decision, so
you can tell what your aggregator already holds:

| `LOG_AAD_VALUES` | `row=` on a model binding `person` and `email` |
|---|---|
| `False` *(default)* | `row="pk=42,person_id=<populated>,email=<empty>"` |
| `True` | `row="pk=42,person_id=7,email=ann@example.com"` |

The primary key is always there: it is what locates the row. Off, each bound
column says only whether it holds a value, which is usually the diagnosis anyway
— a bound column that was changed or emptied is why the read failed.
`reencrypt_data`'s per-row failure line follows the same setting.

### A model's `__str__` with no silo (WARNING)

The package wraps `__str__` on every model with an encrypted field. When a
`__str__` reads an encrypted field whose key set has no silo in the current
context, the package refuses the read before it decrypts, `str(obj)` returns
Django's default `<Model> object (<pk>)`, and the package logs this line on
`encryption_suite.fields`:

```
WARNING encryption_suite.fields A model's __str__ read an encrypted field with no silo in the current context, so it returned the default label. field="<app.Model.field>" key_set=<key set> hint="No silo found in the current context. ..."
```

The line is a WARNING because it marks a degraded result: a task that sent an
email or wrote a file with the label in it ran to the end, and this line is the
trace of its missing silo context. The package raises nothing, so the line carries
no `error_code`. A delete in the site-wide admin writes one line for each row in
its cascade whose `__str__` reads an encrypted field, because that page runs with
no silo in context. An instance that `EncryptionAdminMixin` loaded writes nothing,
because the admin refuses every encrypted read by design. Inside `strict_mode()`
the package does not refuse the read, and the engine logs its `configuration_error`
ERROR line instead. See [A model's `__str__`](encrypted-data.md#a-models-__str__).

### Missing encryption keys (ERROR)

When the engine cannot find a `DataEncryptionKey` row for the current
silo:

```
ERROR encryption_suite.engine No field data encryption key found for this silo. error_code=missing_dek purpose=field silo="<uid>" hint="Has setup_encryption_keys been run?"
ERROR encryption_suite.engine No file data encryption key found for this silo. error_code=missing_dek purpose=file silo="<uid>" hint="Has setup_encryption_keys been run?"
```

The first is emitted for field operations (`PURPOSE_FIELD`), the second for
file operations (`PURPOSE_FILE`). Both are always emitted regardless of
`LOG_DECRYPTS`.

### KEK not found on KMS (ERROR)

When the KMS reports the KEK does not exist at the expected resource name:

```
ERROR encryption_suite.engine The KMS reported that the configured KEK does not exist. error_code=kek_not_provisioned kek="<kek_id>" silo="<uid>" strategy="<strategy>" provisioner="<provisioner>" detail="<provider error>" hint="Likely a wrong KMS endpoint, credentials, or auth: the call failed before it reached the key, and a 404/not-found often means this — check the underlying error in detail first. …"
```

The `hint` leads with the credentials/endpoint explanation on purpose: a call
that fails *before* reaching the key often reports "not found", so a genuinely
missing key is the second thing to check, not the first. When the adapter can
tell that the stored resource name belongs to a different account, project, or
region than it is configured for, a `possible_cause` field says so.

### KEK provisioner failure (ERROR)

When a configured `KEK_PROVISIONER_ADAPTER` fails to ensure the KEK exists:

```
ERROR encryption_suite.engine The KEK provisioner could not ensure the KEK exists. error_code=kek_not_provisioned provisioner="<provisioner>" kek="<kek_id>" silo="<uid>" detail="<provider error>"
```

### Log levels

**WARNING** for anything that destroys key material, or starts a countdown that
ends in material being destroyed, and for every privileged management command as
it starts. **INFO** for everything else.

The countdown clause is the one people miss: production
log levels commonly cut INFO, so a line at INFO is a line some deployments never
see. Scheduling a deletion is fully reversible, which argues for INFO — but the
soft-delete window exists so that somebody can intervene, and an event nobody
sees cannot be intervened on. By the time the destruction itself logs, the moment
to act has passed.

The same reasoning covers a deletion run that silently skipped every row: safe,
but indistinguishable from one with nothing to do, and usually caused by a run
pointed at the wrong settings module.

A command earns WARNING for a different reason: the pair of lines may be the only
evidence it ran. A run that changes nothing — a reconcile that finds no drift, a
dry run — writes no ledger row, so those two lines are all there is of it. Each
names the command, the options that say what it was pointed at, and who ran it,
and never a secret: the command that rotates a HashiCorp AppRole logs the role
and the accessor of the credential it issued, never the credential or the admin
token it takes. A scheduled reconcile emits a pair per run. That is accepted — a
run nobody expected is what the lines are for.

**Every privileged command writes both halves, at the same level.** It opens on
`A privileged management command started; …` before it validates anything, and
closes on `A privileged management command finished. …` carrying the counts of
what it did and the same identity tail. It closes on every ending it reaches on
purpose — a normal finish, a refusal, a dry run, a stop that left a silo fenced —
so **an opening line with no closing line after it is a run that did not reach an
ending it knows about**: killed, or dead on an error it could not report. Both at
WARNING is what makes that read safe; a closing line at INFO would go missing on
the many deployments that cut INFO, and every run would look like it died.

Errors keep **ERROR**, and advisory probe failures that degrade to "no
information" stay at WARNING — they say a report is less complete than it looks.

**DEBUG** is for a reader reproducing a problem rather than one operating the
system: which code path ran, what an optional check found. A DEBUG line is never
the only record of a condition that changes what the system reports — where a
failure degrades a result, the line that names the fallback is at WARNING.

### Line format

A line opens with a sentence saying what happened and what follows from it, then
carries its particulars as `key=value` fields. Only raised errors carry an
identifier: `error_code=<slug>`, catalogued in
[error-codes.md](error-codes.md). Everything else is identified by its logger and
its level — there is no marker to grep for, and none to keep in sync.

Three field conventions are worth knowing before you write a query:

* A **plural key holds a joined set** (`reasons=a,b`); a singular key always holds
  one value.
* A **count is named for what it counts** (`keys=3`), never for what happened.
* Where a line names an act the [key lifecycle record](key-lifecycle-events.md)
  also holds, it carries that record's own word in `event=` — so the log and the
  record cannot spell one act two ways.

### Key deletion — schedule, restore, delete (WARNING / INFO)

A silo deletion is a two-sided, reversible act, and both sides are gated by the
same soft-delete window (`KEY_DELETION_WINDOW_DAYS`): *scheduling* flags the
keys but destroys nothing, *restoring* reverses it while the window is open,
and *deleting* (the admin delete action, run by a person once the window has
closed) is where material is actually destroyed. Every step that names a
recorded act carries that act's own word in `event=`, so the destructive path is
queryable by the same vocabulary the ledger uses and survives a production
INFO-only log level:

```
WARNING encryption_suite.deletion Key deletion was scheduled; … event=deletion_scheduled keys=<count> silo="<uid>"
INFO    encryption_suite.deletion Scheduled key deletion was canceled; … event=restored keys=<count> silo="<uid>"
ERROR   encryption_suite.deletion Failed to record key deletion for an already deleted silo; the keys stay unscheduled. error_code=kek_deletion_record_failed detail="<operator detail>"
WARNING encryption_suite.deletion A data key rotation was abandoned because the key it was rotating was destroyed; … event=rotation_abandoned reason=dek_deleted silo="<uid>" purpose=<purpose>
WARNING encryption_suite.deletion Key material was destroyed; … event=deleted silo="<uid>" purpose=<purpose> kek="<kek_id>"
WARNING encryption_suite.adapters.keks.provisioners Deletion was requested at the provider; … event=deletion_requested effective="<iso8601>" silo=<uid|n/a> kek="<kek_id>"
INFO    encryption_suite.deletion Key deletion was refused; … event=deletion_failed reason=<slug> kek="<kek_id>"
INFO    encryption_suite.deletion Key deletion was refused; … event=deletion_failed reason=<slug> silo="<uid>"
WARNING encryption_suite.deletion An operator tried to schedule keys that a gate would not allow; … event=deletion_schedule_failed reasons=<slug,slug> keys=<count> silos=<uid,uid> kind=<kek|data_encryption_key> <identity>
WARNING encryption_suite.deletion The silo adapter could not say whether this silo still exists; … reason=silo_check_failed silo="<uid>" detail="<operator detail>"
WARNING encryption_suite.deletion This key is on a KMS no KMS_KEY_STORES block names, so the purge left it untouched; … reason=kms_not_configured kek="<kek_id>" key_store=<name>
ERROR   encryption_suite.adapters.keks.provisioners Scheduling deletion of a provisioned KEK failed. error_code=kek_delete_failed detail="<operator detail>"
```

- **Scheduling** (`event=deletion_scheduled`, WARNING) — a silo was deleted and its active DEK rows
  (and, for a silo-exclusive KEK, the matching `KeyEncryptionKey` rows) were moved to status
  `deletion_scheduled` by the `post_delete` connector
  (`ENCRYPTION['SILO_AUTO_KEY_DELETION']`). This only *schedules*; nothing is destroyed
  and the keys stay fully restorable until the window expires. `keys` is the
  number of rows scheduled this call.
- **Restoring** (`event=restored`, INFO) — a scheduled deletion was reversed while the
  window was still open (a pure DB state flip back to `active`). `keys` is the
  number of rows returned to service.
- `kek_deletion_record_failed` is **ERROR** — scheduling the deletion failed (a
  database or strategy error). The operator's delete still proceeds; the
  un-scheduled key stays recoverable via the KMS-side reconcile path. See the
  `kek_deletion_record_failed` code in [error-codes.md](error-codes.md).
- **Destroying a data key** (`event=deleted` on `encryption_suite.deletion`, WARNING) — at deletion the DEK row's wrapped keyset
  (`encrypted_keyset`) was cleared. That field is the only durable copy of the
  wrapped DEK, so clearing it **is** the crypto-shred; the row survives as a
  `deleted` tombstone. Logged at the destruction point for every caller. A data
  key rotation still open on the key is abandoned first, in the same
  transaction, and says so on its own line (`event=rotation_abandoned
  reason=dek_deleted`) — its incoming key is destroyed with the old one.
- **Deleting a key encryption key** (`event=deletion_requested` or `event=deleted` on the provisioner, WARNING) — deleting a KEK is irreversible (it makes every
  DEK wrapped under it permanently unwrappable). It is logged at the destruction
  point (the provisioner's `delete_kek`), so it fires for every caller (command
  and admin alike). `event=deletion_requested` means the provider scheduled deletion for
  `effective` and its recovery window is now running (the `KeyEncryptionKey` row goes to
  `deletion_requested`, confirmed `deleted` only when reconcile enumeration later
  finds the key gone); `event=deleted` means the key was deleted immediately
  with no recovery window (e.g. Fly) and the row goes straight to `deleted`.
- **A refused key encryption key** (`event=deletion_failed` with a `kek` field, INFO) — at deletion a scheduled key encryption key failed one of the
  deletion gates (it is still in use, shared, not owned by this deployment, or the
  provisioner cannot delete); `reason` is one of the stable retain slugs. The row
  records a `deletion_failed` event and moves to status `retained`, which takes it off
  the scheduled queue so it is not retried. This is a **policy outcome,
  not a fault** — scheduling pre-checks only the disposition gate, so any
  deployment whose provisioner cannot delete puts every scheduled key here. The
  key still exists on the provider and still costs money; the Reconcile Keys page
  names it under manual cleanup, and the restore action returns it to `active` if
  the refusal is dealt with. The recorded event is `deletion_failed`, the same verb
  a provider error records; the `retained` status is what says nothing errored.

  Recorded whether or not anything else in the same run was destroyed. A
  selection in which *every* key is refused shows no confirmation screen, since
  there is nothing to confirm — but that request is the operator's completed
  attempt, not a preview they can still back out of, so the refusal is recorded
  against each key with the acting user. On a deployment whose provisioner
  cannot delete, this is the only path a deletion ever takes.
- **A refused data key** (`event=deletion_failed` with a `silo` field, INFO) — at deletion a scheduled data encryption key was not
  shredded because the silo it belongs to still exists, or because the silo
  adapter could not say whether it does. The attempt is recorded as a
  `deletion_failed` event, but the status does not move: every refusal on this
  side is transient, so the row stays scheduled and deleting the silo (or
  implementing `silo_exists()`) and retrying works. Governed by
  [`KEY_DELETION_CAN_RENDER_DATA_INACCESSIBLE`](configuration.md#key_deletion_can_render_data_inaccessible);
  with it on, this gate is skipped entirely and the shred proceeds.
- **A liveness check that raised** (`reason=silo_check_failed`, WARNING not INFO) — asking the silo
  adapter whether the silo still exists *raised*. Distinct from the adapter
  answering "cannot say", which is a capability limit and logs a refusal
  with `reason=silo_liveness_unknown`. This one means something is broken and the
  deletion is refusing until it is fixed, so it is worth alerting on.
- **A refused scheduling attempt** (`event=deletion_schedule_failed`, WARNING) —
  an operator selected keys for deletion and a gate turned them away before any
  window started. Each refused row also gets a `deletion_schedule_failed` event; no
  status moves, because nothing about the key changed and it stays schedulable
  once the reason is dealt with. WARNING because the refused case is the one worth
  seeing: on either changelist it means somebody tried to destroy a key that live
  data still depends on, and the *allowed* case has always been recorded. Fields:
  `reasons`, `keys`, `silos`, `kind`, `user`.
- **An unconfigured KMS** (`reason=kms_not_configured`, WARNING) — the purge left
  a scheduled KEK untouched because its `key_store` matches no `KMS_KEY_STORES`
  block, so nothing here can reach the key. It is a warning because a run that
  skipped every row looks exactly like one with nothing to do, and the usual cause
  is a run pointed at the wrong settings module.
- **A key row that could not be written** (WARNING) — the best-effort `KeyEncryptionKey` row upsert
  the engine does when it provisions a KEK could not be written. Like the creation
  event below it is additive (reconcile discovery backfills the row), so the
  failure is logged and swallowed rather than breaking encryption.
- **A ledger event that could not be appended** (WARNING) — a best-effort creation event
  (`created`) could not be appended to the
  [key lifecycle record](key-lifecycle-events.md). Creation
  events are an additive record, so the failure is logged and swallowed rather
  than breaking encryption (unlike deletion events, which are written
  transactionally with the destructive act).
- `kek_delete_failed` is **ERROR** — a provider error or an ownership-guard
  refusal during deletion. See the `kek_delete_failed` code in
  [error-codes.md](error-codes.md).

### Blocked key use — rotating, scheduled or deleted (ERROR)

Scheduling a key for deletion blocks both encryption and decryption for it, and
so does a data key rotation in progress. The check runs when a key is loaded, so
it takes effect immediately in the database and within `DEK_CACHE_TTL` in each
running process — a worker holding a cached key keeps using it until that entry
expires. (A rotation waits out that TTL before converting anything, for exactly
this reason.)

```
ERROR   encryption_suite.engine The DEK is being rotated; its silo's data is fenced until every row is on one keyset. error_code=dek_reencryption_in_progress silo="<uid>" purpose=<purpose> hint="Clears when reencrypt_data swaps or finishes a rollback. …"
ERROR   encryption_suite.engine The DEK is scheduled for deletion; refusing to use it. error_code=dek_deletion_scheduled silo="<uid>" undeletable_until="<date>" hint="Restore the key to resume, or let the window expire."
ERROR   encryption_suite.engine The DEK was deleted; its wrapped material is gone and the value cannot be decrypted. error_code=dek_deleted silo="<uid>"
```

- `dek_reencryption_in_progress` is **ERROR** — a read or write hit a key whose
  silo is mid-rotation. It clears by itself when the rotation swaps or is rolled
  back; one that persists is a rotation that ended with rows outstanding, which
  the `reencrypt_data` run reported. See [error-codes.md](error-codes.md).

- `dek_deletion_scheduled` is **ERROR** — a read or write hit a key inside its
  soft-delete window. Recoverable: restore the key, or let the window expire if
  the deletion was intended. See the `dek_deletion_scheduled` code in
  [error-codes.md](error-codes.md).
- `dek_deleted` is **ERROR** — a read hit a tombstone whose wrapped
  material has been cleared. Not recoverable for existing ciphertext. On a *write*
  this is instead a revival signal: a reused silo UID transparently gets a fresh
  key when `KEY_AUTO_PROVISION` is on. See the `dek_deleted` code in
  [error-codes.md](error-codes.md).

### Data key rotation (WARNING / ERROR)

[`reencrypt_data`](management-commands.md#reencrypt_data) echoes each ledger row
it writes, at WARNING: opening a rotation fences a silo's data and heads toward
overwriting its key material, the swap overwrites it, and abandoning one discards
the incoming material. Each line carries `silo=` and `purpose=` — which separate a
data key's `rotated` from a key encryption key's — and who ran the command, and
never a row value:

```
WARNING encryption_suite.management.commands.reencrypt_data A privileged management command started; … command=reencrypt_data key_set=<key set> dry_run=False abort=False check=False only_outdated=False purpose=all silo="<uid|all>" [converts="<move>"] <identity>
WARNING encryption_suite.rotation A data key rotation started; … event=rotation_started silo="<uid>" purpose=<purpose> kek="<kek_id>" <identity>
ERROR   encryption_suite.rotation A row could not be converted and stays on its current keyset; … error_code=<code> silo="<uid>" purpose=<purpose> model=<app.Model> pk=<pk> target=<field> aad="<col>=<populated>,<col>=<empty>" <identity>
WARNING encryption_suite.rotation A data key rotation finished; … event=rotated silo="<uid>" purpose=<purpose> dek_key_version=<n> reencrypted=<n> <identity>
WARNING encryption_suite.rotation A data key rotation was abandoned; … event=rotation_abandoned reason=<none|unconvertible_rows> silo="<uid>" purpose=<purpose> moved_back=<n> <identity>
WARNING encryption_suite.management.commands.reencrypt_data A privileged management command finished. command=reencrypt_data key_set=<key set> dry_run=False abort=False purpose=all silo="<uid|all>" rotated=<n> abandoned=<n> skipped=<n> fenced=<n> failed=<n> current=<n> <identity>
```

The rotation's own lines close each *rotation*; the command's last line closes the
*run*, which is a different thing on a run over many silos and the only line there
is on a run that rotated nothing. Its counts are silo-and-purpose pairs, not rows:
`rotated=` swapped onto new material, `abandoned=` rolled back, `skipped=` declined
with a reason on the console, `fenced=` left with the silo's data blocked, `failed=`
raised, `current=` left alone by `--only-outdated`. A dry run counts the same way,
reporting what it would have done. `converts=` names each backend and algorithm
move the run makes, and is absent when there is none.

One rotation is open per data key at a time, so a closing line pairs with the
most recent `rotation_started` for the same silo and purpose. A resumed run
writes no second opening line, so an opening line with no closing line after it
is a rotation that never finished — the silo is still fenced.

`reencrypted=` and `moved_back=` count what that one run moved: values onto the
incoming keyset, or back onto the old one. They are the only record of how much
data a rotation re-encrypted, because moving a value between keysets holds both
of them directly and never reaches the decryption path `LOG_DECRYPTS` records — a rotation emits no
per-value decrypt entries whatever that setting is, and a control worded as one
record per decrypt is not satisfied by these counts. The per-row line is the one place a rotation
could mention row contents, and its `aad=` follows
[`LOG_AAD_VALUES`](#decrypt-failure-fields); `error_code` is a copy of
the code the conversion raised, such as `field_decryption_failed` for a tampered
bound column or `file_storage_error` for a storage outage.

### Key re-encryption (WARNING / ERROR)

[`reencrypt_keys`](management-commands.md#reencrypt_keys) writes the usual pair.
Everything else it reports — the per-row results, the skip reasons, the
provider-mismatch hint — goes to stdout only, except a failed check of a new
wrap, which is also an ERROR line.

```
WARNING encryption_suite.management.commands.reencrypt_keys A privileged management command started; … command=reencrypt_keys dry_run=False provision=False silo="<uid|all>" <identity>
WARNING encryption_suite.management.commands.reencrypt_keys A privileged management command finished. command=reencrypt_keys dry_run=False silo="<uid|all>" reencrypted=<n> skipped=<n> failed=<n> <identity>
ERROR   encryption_suite.management.commands.reencrypt_keys A rewrapped data key did not unwrap to the key it was made from, so the old wrap was kept. error_code=kek_unavailable silo="<key_set:uid>" kek="<kek_id>"
```

Before saving, each new wrap is unwrapped with the key name and version that will
be recorded. A wrap the provider refuses to unwrap is logged by the engine's KMS
error funnel like any other key failure, naming the operation `key wrap check`.
One that unwraps to different key material gets the ERROR line above. Either
way the row keeps its old wrap, and its data stays readable.

The closing line is the only durable record of the *run*. Each row that moved
appends its own `reencrypted` event to the [key lifecycle
record](key-lifecycle-events.md), but a row the run skipped, a row that failed,
and a dry run that moved nothing all leave the ledger untouched — and a scheduled
run writes its console output to nowhere anybody reads. The counts are the three
the console reports —
`reencrypted=` data keys moved onto current key material (a rotation's incoming
keyset rewraps with the row that holds it, and is not counted separately),
`skipped=` rows the run declined and said why on the console, `failed=` rows that
raised, each already logged as its own ERROR. A run that never closed left the
rows it had already written written — a rewrap is per-row and is not rolled back
as a whole.

### The remaining privileged commands (WARNING)

Three commands have nothing else to say in the log, and write only the pair:

```
WARNING encryption_suite.management.commands.setup_encryption_keys A privileged management command finished. command=setup_encryption_keys dry_run=False silo_model="<dotted|auto>" field_keys_created=<n> file_keys_created=<n> skipped=<n> <identity>
WARNING encryption_suite.management.commands.record_key_event A privileged management command finished. command=record_key_event event=<verb> kek="<kek_id>" recorded=<0|1> <identity>
WARNING encryption_suite.management.commands.encryption_suite_rotate_hashicorp_approle A privileged management command finished. command=encryption_suite_rotate_hashicorp_approle role="<role>" mount="<mount>" wrapped=<bool> issued=<0|1> accessor="<accessor>" <identity>
```

- `setup_encryption_keys` creates a `created` ledger event per key it makes, and
  nothing for a silo that already had keys, a dry run, or a run that ended part
  way through the list of silos with the rest still unkeyed. `skipped=` counts
  keysets that already existed, field and file separately.
- `record_key_event` writes one ledger row, which is the whole point of it, so
  `recorded=` says whether that row was written: `0` is a run refused before writing —
  no operating-system login account to attribute it to, or no KMS provider to
  name.
- `encryption_suite_rotate_hashicorp_approle` writes no ledger row at all and
  prints its result to standard output, so these two lines are the only record
  that a credential was rotated. `accessor=` names the secret-id (or wrapping
  token) Vault issued, which identifies it without being usable to authenticate
  as it; the secret-id itself and the admin token the command takes never reach
  the log. `issued=0` is a run that ended without one — a missing `VAULT_ADDR` (or
  `--vault-addr`) or `VAULT_TOKEN` (or `--admin-token`), or a Vault that refused.

### Storage backend failures (ERROR)

Encrypted file storage wraps the configured backend, so a backend failure is
reported as an infrastructure problem rather than a cryptographic one.

```
ERROR   encryption_suite.storage An encrypted file could not be written to storage. error_code=file_storage_error operation=write backend="<class>" key="<path>" detail="<backend error>"
ERROR   encryption_suite.storage Encrypted file existence check failed. error_code=file_storage_error operation=exists backend="<class>" key="<path>" detail="<backend error>"
ERROR   encryption_suite.storage An encrypted file could not be read from storage. error_code=file_storage_error operation=read backend="<class>" key="<path>" detail="<backend error>"
```

- `file_storage_error` is **ERROR** — the underlying backend (S3, GCS, disk, …)
  failed a write, existence check, or open. `operation` names which of the three
  it was. **Not** a decryption failure: the ciphertext was never reached. See the
  `file_storage_error` code in [error-codes.md](error-codes.md).

### Reconcile — discovery and detection availability (WARNING / INFO / ERROR)

The Reconcile Keys page and the `reconcile_keys` command enumerate silos and,
where the provisioner supports it, the key encryption keys this deployment owns
on the KMS, then record what they found. Neither destroys anything.

```
INFO    encryption_suite.reconcile_service Reconciled keys. key_store=<name> discovered=<n> observed_pending=<n> confirmed=<n> kek_delete_on_kms_overdue=<n> kek_missing_on_kms=<n> rotated=<n> probes_capped=<bool> dek_orphans=<n|n/a> kek_orphans=<n|n/a> data_reencrypt_due=<n|n/a> key_reencrypt_due=<n|n/a> unavailable_detection=<slug,slug|-> <identity>
WARNING encryption_suite.management.commands.reconcile_keys A privileged management command finished. command=reconcile_keys key_store=<name> discovered=<n> observed_pending=<n> confirmed=<n> kek_delete_on_kms_overdue=<n> kek_missing_on_kms=<n> rotated=<n> probes_capped=<bool> dek_orphans=<n|n/a> kek_orphans=<n|n/a> data_reencrypt_due=<n|n/a> key_reencrypt_due=<n|n/a> unavailable_detection=<slug,slug|-> <identity>
WARNING encryption_suite.reconcile_service The provider would not report this key's current version, … kek="<kek_id>" detail="<operator detail>"
WARNING encryption_suite.reconcile_service The expected key encryption key name could not be resolved for some live silos, … key_store=<name> silos=<n> first_silo="<key_set:uid>" detail="<operator detail>"
ERROR   encryption_suite.reconcile_service The silo adapter's listing failed, so this reconcile pass reports no orphans. error_code=silo_enumeration_unavailable adapter=<class> detail="<operator detail>"
WARNING encryption_suite.engine Provisioning a silo's data key could not clear the stale orphan annotation … kek="<kek_id>" silo="<uid>" detail="<operator detail>"
ERROR   encryption_suite.silos The silo adapter cannot list every live silo. error_code=silo_enumeration_unavailable detail="<operator detail>"
ERROR   encryption_suite.adapters.keks.provisioners The KEK provisioner cannot list this deployment's KEKs. error_code=kek_enumeration_unavailable detail="<operator detail>"
```

- The first two lines are one summary with the same fields, and a pass writes
  one of them, never both:
  - The Reconcile Keys page writes the **INFO** line on
    `encryption_suite.reconcile_service`, and only when a pass changed
    something. The page reconciles on every load, where a line per pass would be
    noise.
  - `reconcile_keys` writes the **WARNING** line as its closing line, at the
    level of its opening one, on **every** run, whether or not anything changed:
    a scheduled run needs a trace proving the schedule is alive. This line is why
    no reconcile-run table exists.
- The summary's fields:
  - `discovered` counts key encryption keys that got a new `KeyEncryptionKey`
    row — each also appends a status-neutral `discovered` event to the
    [key lifecycle record](key-lifecycle-events.md), recording when a key this
    deployment did not create first became observable.
  - `observed_pending` counts keys the provider reports as already scheduled
    for deletion.
  - `confirmed` counts keys whose provider-window deletion the enumeration
    observed as complete (`deletion_requested` → `deleted`).
  - `kek_delete_on_kms_overdue` counts keys still listed past their effective
    deletion date, and `kek_missing_on_kms` owned keys absent from the listing.
    Drift is reported for an operator, never auto-actioned.
  - `rotated` counts keys whose material the provider reports at a new version,
    and `probes_capped` says the version check stopped at its probe budget.
  - `dek_orphans` and `kek_orphans` count orphaned keys, `data_reencrypt_due`
    and `key_reencrypt_due` keys behind on material, and
    `unavailable_detection` names the checks that could not run.
  - `n/a` marks a dimension that could not be inspected, and is not the same as
    `0`.
- **A stale orphan annotation** (WARNING) — provisioning a silo's data key
  could not clear the stale orphan annotation on the key encryption key behind it.
  Best-effort by design: the annotation is display-only, and failing a key
  provision over a cosmetic flag would trade a working silo for a tidy changelist.
  The next reconcile corrects the flag.
- **A version probe that failed** (WARNING) — reconcile asked the provider
  which key version a new wrap would use, and the lookup failed. That key's rows
  are left out of the "key re-encryption due" finding rather than reported as
  current, so the consequence is an under-report, not a wrong one. Not an ERROR
  because the rest of the pass is unaffected and the next run retries.
- **A key name that could not be resolved** (WARNING) — the strategy could not
  name the expected key encryption key for one or more live silos. One line per
  pass, with the count and the first silo, and only on a pass that lists the
  KMS — a store with no owner prefix, such as a `KEK_MAP` with no
  `KEK_TEMPLATE`, never lists its keys and never writes it. On a store with a
  template it means a real configuration problem, which `detail` names: a name
  longer than the provider allows, or a template that cannot be filled in.
  Such a silo's key is still expected
  when a data key references it; a key no data key uses yet may be reported as an
  orphan this pass. The deletion gates still refuse any key a data key uses.
- `silo_enumeration_unavailable` / `kek_enumeration_unavailable` are **ERROR**
  — an enumeration that was expected to work failed. Each is raised through the
  shared helper, so it is logged by whichever module raised it: the silo one from
  `encryption_suite.silos` or a silo adapter, the KEK one from the provisioner. A
  silo adapter that raises some other error mid-listing is logged by
  `encryption_suite.reconcile_service` under the same slug, naming the adapter
  class. Reconcile degrades to
  reporting *nothing* for that dimension rather than inferring, since a false
  orphan would end in a deleted key. See the matching codes in
  [error-codes.md](error-codes.md).

### Double-encryption guard (ERROR)

Two lines share the `field_already_encrypted` slug. The engine writes the first
when a value that is already ciphertext is passed to `encrypt()`:

```
ERROR encryption_suite.engine Refused to encrypt a field value that is already encrypted. error_code=field_already_encrypted field="<app.Model.field>" hint="The engine takes plaintext. …"
```

Only a direct `get_engine().encrypt()` call reaches this one. A migration helper
re-run over rows it has already converted passes an already-encrypted value
through untouched, which is what makes it idempotent.

The field writes the second when a model save holds a value with the shape of
stored ciphertext (`~^Dv`, a version number, and a colon) that was not read
from the database — usually ciphertext copied from another row and submitted
through a form or an API:

```
ERROR encryption_suite.fields Refused to save a value that looks like ciphertext but was not read from the database. error_code=field_already_encrypted field="<app.Model.field>" hint="The value has the shape of stored ciphertext but was not read from this row, … treat this as a possible injection attempt and check which account submitted it." <identity>
```

The save raises `FieldAlreadyEncryptedError` and nothing is written. A model
field re-saving an instance it has already encrypted, or a value equal to what
the row already holds, is written back unchanged and logs nothing. Where the
line carries the [actor identity](#actor-identity), a run of these lines from
one account is worth reading as an attempt to replay stolen ciphertext.

A value already encrypted under any silo's key, the system silo's included, is
refused: encrypting it again would store its marker text as though it were data.
See [Stored formats](concepts.md#stored-formats).

There is no file equivalent. The `~^Dv1:` prefix marks a field value; `encrypt_file`
writes the file as raw streaming-AEAD output with no marker, so a doubly-encrypted file
cannot be detected the same way.

### Data key creation (INFO / ERROR)

Every data key created gets one line, written beside its `created` ledger row
whichever path created it. The sentence names the act that caused the key, and
`reason=` carries the same slug the ledger row does:

```
INFO  encryption_suite.engine A data key was created for a newly created silo. event=created reason=silo_created silo="<uid>" purpose=field kek="<kek_id>" <identity>
INFO  encryption_suite.engine A data key was created on the silo's first encryption. event=created reason=first_encryption silo="<uid>" purpose=<field|file> kek="<kek_id>" <identity>
INFO  encryption_suite.engine A data key was created for this silo. event=created reason=none silo="<uid>" purpose=<field|file> kek="<kek_id>" <identity>
ERROR encryption_suite.apps A silo was created but its encryption keyset could not be provisioned; … silo="<uid>"
```

- **A newly created silo** — [`SILO_AUTO_KEY_CREATION`](configuration.md#silo_auto_key_creation)
  created the silo's field key as the silo was saved.
- **First encryption** — [`KEY_AUTO_PROVISION`](configuration.md#key_auto_provision)
  created the key the first time the silo encrypted a value or a file, or revived
  a deleted one. A silo's file key usually arrives this way.
- **For this silo**, `reason=none` — `setup_encryption_keys` created it; the
  operator is in `os_user`, where `LOGS` lists it.

A new key encryption key behind it is logged separately, by the provisioner that
created it. The ERROR is the silo-creation signal failing; the silo has no key
until something creates one.

### KMS credential refresh (WARNING)

KMS adapters emit this line when a request fails due to a credential error and they
attempt a refresh and retry:

```
WARNING encryption_suite.adapters.key_stores.aws The call was rejected as unauthenticated, so credentials are being refreshed and the call retried once. operation=encrypt_key
WARNING encryption_suite.adapters.key_stores.gcp The call was rejected as unauthenticated, so credentials are being refreshed and the call retried once. http_status=401
```

Most KMS adapters (AWS KMS, GCP Cloud KMS, HashiCorp Vault, IBM Key Protect,
Infisical) emit this line under their own
`encryption_suite.adapters.key_stores.<provider>` logger, carrying whichever of
`operation`, `http_status`, `method` and `path` that provider can name.

A retry that also fails is reported once by the shared base, which names the
adapter in a field because the namespace at that point is the base module:

```
WARNING encryption_suite.adapters.key_stores.base A call was rejected as unauthenticated, and retrying it with fresh credentials failed too, so further retries on authentication errors are suppressed for a cooldown. adapter=<AdapterClass> cooldown_seconds=<n>
```


---

## Admin test console log

The test console records every call it is asked to make, so a compromised admin
session leaves a trace. Its lines come from
`encryption_suite.admin_test_console`, which is where an append-only sink is
worth pointing — see [Routing logs with Django's LOGGING
setting](#routing-logs-with-djangos-logging-setting).

Every entry is **INFO**, including the deletion ones — the console only ever
destroys the throwaway keys it created itself, so nothing here is the
key-destroying act that earns a WARNING elsewhere on this page. The failures
worth alerting on are this logger's ERROR lines — a panel that would not render,
a check that raised, a throwaway key that could not be deleted.

Each carries `key_stores=<name>`, the [`KMS_KEY_STORES`](configuration.md#kms_key_stores)
name of the KMS the line concerns (or `system`), and the identity tail described
under [Actor identity](#actor-identity), naming the person at the screen. A line about
several KMSs lists them separated by commas: `key_stores=fly,system`.

### Test run

```
INFO encryption_suite.admin_test_console Ran <field in-memory|file in-memory|field KMS|file KMS|storage reachability> test. key_stores=<name>
INFO encryption_suite.admin_test_console The <type> test reported a failure. key_stores=<name>
```

The run line is emitted before the test executes, so it is present even if the
run never returns; the failure line follows it when the test completed and
reported a failure.

### Error and rate limit

```
INFO encryption_suite.admin_test_console The <type> test could not complete. key_stores=<name> error_code=<slug>
INFO encryption_suite.admin_test_console Rate limit reached; the request was rejected. key_stores=<name>
INFO encryption_suite.admin_test_console Cleared test results. key_stores=<name,name>
```

The could-not-complete line means the test raised rather than returning a
verdict. The test is named in the sentence rather than carried in a field. It
carries `error_code=<slug>` for a typed package error and `error=<ExcType>` for
anything else, so the two are never read as one field.
The cleared-results line records the button that clears the stored results — a
state change to the panel an operator is reading, so it is recorded like the rest.
It clears every KMS's results, so it lists every configured KMS.

### Delete

```
INFO encryption_suite.admin_test_console Deleted test key(s). key_stores=<name,name> deks_deleted=<n> deks_retained=<n> keks_deleted=<n> keks_retained=<n>
INFO encryption_suite.admin_test_console Test key deletion failed. key_stores=<name,name> error=<ExcType>
```

Delete processes the test keys on every KMS that holds one, and lists each of
those KMSs.

---

## Actor identity

Lines that report an act a person asked for end with an identity tail, shown as
`<identity>` in the sample lines on this page. It renders the items
[`USER_IDENTITY`](configuration.md#user_identity)'s `LOGS` list names, always in
this order:

```
user_id=<pk> user_name="<user.get_username()>" user_str="<str(user)>" ip_address=<address> os_user="<account>"
```

`LOGS` is empty by default, so the tail is too, and no line names anybody until
the deployment lists something. Each key means one thing in every deployment:
`user_id` is the primary key the [key lifecycle record](key-lifecycle-events.md)
stores, so a line and its row join on it; `user_name` is `get_username()`;
`user_str` is `str(user)`, what the admin's **User** column shows. The log list
is independent of the record's: a line can name an address the record does not
keep, and the record can keep one no line names.

The free-text fields are quoted, stripped and escaped: a swappable user model's
values and an operating-system account name are not the package's to predict,
and an unquoted value containing a space would swallow the fields after it. A
double quote or a backslash inside a value is written with a backslash before
it, and a line break or any other non-printing character as its escape
sequence (`\n`, ` `), so a value cannot close its own field or start a
second line. The row identity, file name and storage key on a decrypt or
storage failure line are escaped the same way. A listed
item with no value renders `?` — `os_user` on a request, `ip_address` on a
command — and an unlisted item is absent.

It reaches a line one of two ways:

- **Passed**, where the call site holds the identity — the deletion and restore
  lines, every refusal, the line recording that key material was destroyed, the
  reconcile summary, and the test console's audit lines.
- **Appended**, everywhere else. Modules take their logger from
  `encryption_suite._logging.get_logger`, which attaches a filter that adds the
  tail from the request-time context. That is how a line raised deep in an
  adapter — several frames below anyone who knows who acted — can still name
  them, without a `user` argument being threaded through provider code. It
  requires `SCOPE = all_acts` and the middleware that populates that context;
  under `privileged_acts` there is nothing to append.

A line whose call site passed a tail is left alone, even when that tail is empty
because `LOGS` lists nothing, so the two mechanisms cannot put two identity tails
on one line. The filter recognizes a passed tail by its type, so a call site
must hand it to the logger as an argument of its own rather than format it into
another string.

## Configuration

### Enabling decrypt logs

```python
ENCRYPTION = {
    # ...
    "LOG_DECRYPTS": True,   # opt-in — log every successful decrypt
}
```

Default is `False`. On read-heavy paths the one-entry-per-decrypt volume can
overwhelm log pipelines and incur real ingestion costs. Enable when you need a
compliance audit trail (PCI, HIPAA, SOC 2) and have sized your log sink for
the throughput. All `ERROR`-level entries are always emitted regardless of this
setting.

### Routing logs with Django's LOGGING setting

django-encryption-suite does not configure any handlers. Every logger in the
package is named for its module and sits under the `encryption_suite` namespace,
so one entry routes all of them and a longer name narrows the routing to one
part of the package.

**Route the package to a dedicated audit file:**

```python
LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "audit": {
            "format": "%(asctime)s %(levelname)s %(name)s %(message)s",
        },
    },
    "handlers": {
        "audit_file": {
            "class": "logging.FileHandler",
            "filename": "/var/log/app/encryption_suite-audit.log",
            "formatter": "audit",
        },
    },
    "loggers": {
        "encryption_suite": {
            "handlers": ["audit_file"],
            "level": "INFO",
            "propagate": False,
        },
    },
}
```

Every module logger is a descendant of `encryption_suite`, so it inherits the
handler above. To route one part of the package separately, name it explicitly —
the test console is the usual candidate, because an append-only sink for it
preserves the "every call logged" property against an admin-UI compromise:

```python
"loggers": {
    "encryption_suite": {
        "handlers": ["engine_file"],
        "level": "INFO",
        "propagate": False,
    },
    "encryption_suite.admin_test_console": {
        "handlers": ["console_audit_file"],
        "level": "INFO",
        "propagate": False,
    },
},
```

**Send to an external service via JSON to stdout:**

```python
LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "json": {
            "()": "pythonjsonlogger.jsonlogger.JsonFormatter",
            "format": "%(asctime)s %(name)s %(levelname)s %(message)s",
        },
    },
    "handlers": {
        "stdout_json": {
            "class": "logging.StreamHandler",
            "formatter": "json",
        },
    },
    "loggers": {
        "encryption_suite": {
            "handlers": ["stdout_json"],
            "level": "INFO",
            "propagate": False,
        },
    },
}
```

**Suppress INFO-level entries (not recommended):**

```python
LOGGING = {
    "version": 1,
    "loggers": {
        "encryption_suite": {
            "level": "WARNING",  # silences INFO decrypt entries; ERROR entries still emit
        },
    },
}
```


---

## Raised errors

Every typed error the package raises logs one clean line: a short English
sentence saying what happened, then its stable slug as `error_code=<slug>` — the
same string the exception carries on `exc.code`. The sentence is there so a line
reads without the catalog open; the slug is there so it greps and alerts without
depending on the wording. Those are not listed here: adding an error means adding a class, and
[error-codes.md](error-codes.md) is the single catalog, with the meaning of each
code, which logger emits it, and the fields that accompany it. Every one of them
is at ERROR.

## Building alerts

There is no table of every line here, because there is no identifier to tabulate:
a line is identified by the logger that emitted it and the level it carries. Route
and alert on those.

ERROR and WARNING both warrant attention. The difference is that an ERROR reports
something that did not work, while a WARNING reports work that succeeded without
something it asked for — a missing tag, an unreadable state, a blob left behind —
or a countdown that ends in key material being destroyed.

Three acts are worth alerting on regardless of level, because they destroy key
material or start the window that ends in it. All three carry the lifecycle
record's word, so the field is the handle:

* `event=deletion_scheduled` — a countdown started; it can still be canceled.
* `event=deleted` — material was destroyed, on a data key or at the provider.
* `event=deletion_requested` — the provider's own deletion window started.

The durable record of those is the
[key lifecycle record](key-lifecycle-events.md), not the log: it is append-only,
kept for as long as the row exists, and unaffected by a pipeline that drops INFO.
Alert from the log if that suits your tooling; audit from the record.

---

## Recommendations

1. **Route `encryption_suite` to an append-only sink** (a dedicated log file,
   S3 bucket, or SIEM) so that audit records cannot be tampered with by someone
   who compromises the application.

2. **Correlate with request logs.** If your web server logs include a request ID,
   add that to your Django log formatter so you can tie a decrypt event back to
   the HTTP request — and user — that triggered it.

3. **Monitor ERROR-level entries.** A spike in decryption failures may indicate
   data corruption, a misconfigured key rotation, or an attempted attack.

4. **Set appropriate retention.** Audit logs for sensitive data access may be
   subject to compliance requirements (HIPAA, SOC 2, GDPR). Configure your
   log retention policy accordingly.
