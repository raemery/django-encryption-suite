# Key lifecycle events

Every state transition on a key — provisioning, creation, re-encryption,
scheduling, refusal, deletion — appends one row to the `KeyLifecycleEvent`
record, in the same database transaction as the act it records. Rows are never
updated or deleted; a later state is a new row. No key material, wrapped or
plain, is ever stored here.

This is the record, not the log. Its verbs map to key statuses, so a row both
reports the change and is the authority for it; it is stored, filtered, and
rendered through translated labels for as long as the row exists. The
[system log](logging.md) is the other register — English-pinned, rotated, read by
nobody — and [auditing](auditing.md) is the one-page guide to which of the two
answers a given question.

## Reading the ledger

- **Key Lifecycle Events** in the Django admin — the full record, registered
  strictly read-only (no add, change, or delete), filterable by event and key
  kind and searchable by silo UID and key resource name.
- **On each key** — the same rows appear as an inline on the Data Encryption Key
  and Key Encryption Key detail pages, oldest first — a key's history read as
  the story it is, ending where the row stands now. The changelist is the other
  way round, newest first, because there the question is what happened lately
  across every key.
- **`record_key_event`** — the management command for entering an act performed
  outside the application (a deletion done in the provider's console, say). See
  [management-commands.md](management-commands.md).

## The columns

| Column | Kind | Answers |
|---|---|---|
| `event` | closed | **what** happened to the key |
| `trigger` | closed, mandatory | **how it came about** |
| `reason` | closed slugs | **why**, where the verb does not say |

A silo's keys are identified by their **key set** and the silo adapter's uid. Every
event that records a silo uid records its `key_set` beside it, because the same uid in
two key sets bound to different adapters names two silos.

Plus `user` or `os_user` (**who**), `ip_address` (**where from**, on the client side),
`created_at` (**when**), and `kek_resource_name` / `key_store` (**where**, on the provider
side).

`user` is a reference to the model `AUTH_USER_MODEL` names, shown as `str(user)`
— the same label every other admin screen shows for that person, so overriding
`__str__` changes it everywhere at once. The reference carries no database
constraint, so deleting a user never blocks and never destroys a row; the column
then reads `Deleted user #<id>`. `os_user` holds a composed account name
with the uid that ran the command, described under
[record_key_event](management-commands.md#recorded-actor).

`os_user` and `ip_address` each point at a row of their own that holds the value
once, in plaintext or encrypted under the system silo's keys, so rotating those
keys re-encrypts the rows and never rewrites an event. The admin shows the value
either way.

[`USER_IDENTITY`](configuration.md#user_identity) decides which of `user`, `os_user`
and `ip_address` an event records, and in which form; by default it
records none of them. A change between the plaintext and encrypted forms applies
to later events only: earlier events keep pointing at values in the form they
were written in. See [auditing](auditing.md) for what a user deletion takes with
it.

### Data key protection

Each data encryption key event records the key's protection state **after** the
act:

| Column | Holds |
|---|---|
| `wrapping_kek` | The key encryption key that wraps the data key — a reference to its row, which is never deleted. |
| `key_store` | That key encryption key's key store. |
| `kek_key_version` | The key encryption key version that wrapped it, where the provider reports one. |
| `crypto_backend` | The backend that generated the keyset (`cryptography`, `tink`); blank for a blind index key. |
| `algorithm` | The algorithm the keyset was generated for (see [crypto backends](crypto-backends.md#the-recorded-algorithm)). |

The event before it holds the state before, so a key's history shows every
change: `reencrypted` marks a move to another key encryption key, version or KMS,
and `rotated` a move to new key material, which may be a different backend or
algorithm. Events that change no protection — scheduling, restoring, deleting —
repeat the current state, so any event read alone says what protected the key
at that point.

`wrapping_kek` differs from `kek`, which says which key the event is *about*. A
key encryption key's own events record only `kek_key_version`: the version last
observed at the provider, after the act. A `rotated` event holds the new
version, and the event before it the old one. The other four columns are blank,
because the key's row names its KMS.

## `event`

| Value | Applies to | Meaning |
|---|---|---|
| `created` | both | the key was made, and its row first recorded |
| `discovered` | key encryption key | a key already at the provider, met for the first time — no claim about who made it |
| `reencrypted` | both | the keyset was rewrapped under a key encryption key: same material, new wrapping |
| `rotation_started` | data key | a re-encryption sweep opened; that key — one silo, one purpose — is fenced while it runs |
| `rotated` | both | the key's material changed — observed at the provider for a key encryption key, completed by the sweep for a data key |
| `rotation_abandoned` | data key | a sweep ended without a swap |
| `deletion_scheduled` | both | our own deletion window opened: restorable, provider untouched |
| `deletion_schedule_failed` | both | a gate turned the scheduling away, so no window ever started |
| `deletion_requested` | key encryption key | the provider's delete API was called and its recovery window is running |
| `deletion_failed` | both | a deletion did not happen: a gate of ours refused, or the provider call raised |
| `deleted` | both | the material is gone — the keyset cleared for a data key, the provider's delete confirmed for a key encryption key |
| `restored` | both | a scheduled deletion was cancelled |
| `silo_found` | both | a live silo resolves to this key |
| `silo_not_found` | both | no live silo resolves to this key |

## `trigger`

| Value | Meaning |
|---|---|
| `direct` | A person asked for *this key event*. Admin actions, hand-recorded attestations. |
| `indirect` | A person asked for something else and this followed — the silo cascade, provisioning during a user's request, a reconcile pass started from the admin page. |
| `automated` | A script or schedule did it — the `reconcile_keys` command, maintenance commands. |

`trigger` is the first thing to read when something looks wrong, because it says
whether to look at a person, at configuration, or at a scheduled job.

The same work can arrive either way, and the trigger is what tells the two
apart. A reconcile pass started from the **Reconcile Keys** page is `indirect`
and carries the operator who pressed the button; the same pass run by
[`reconcile_keys`](management-commands.md) is `automated` and carries the OS
account in `os_user`. Neither is `direct`: the pass goes looking, and
nobody asked for the findings it returns by name.

## `reason`

| Slug | Family |
|---|---|
| `recorded_by_operator` | epistemic — an unverified human claim |
| `observed_at_provider` | epistemic — a provider call told us |
| `confirmed_by_reconcile` | epistemic — enumeration witnessed a key gone |
| `determined_by_reconcile` | epistemic — comparison against live silos set the annotation |
| `silo_created` | silo lifecycle |
| `silo_deleted` | silo lifecycle |
| `first_encryption` | the first value encrypted for a silo, where no key existed yet |
| `silo_reacquired` | a live silo turned up for a previously-orphaned key |
| `failed_at_provider` | failure — a provider call was made and raised |
| `dek_deleted` | abandonment — the data key was destroyed under an open rotation |
| `unconvertible_rows` | abandonment — an unattended run unwound rather than leave the fence up |
| refusal reasons (8) | a deletion gate declined to act — see [Refused attempts](#refused-attempts--terminal-and-transient) |

**Invariant:** where `trigger` is `indirect`, `reason` is always populated. An indirect event
happened because of some other act, so there is always an act to name. `direct` and `automated`
may legitimately leave it empty.

## Refused attempts — terminal and transient

Two verbs record an attempt that a gate turned away:

| Verb | Written when |
|---|---|
| `deletion_schedule_failed` | Scheduling was refused, so no window ever started |
| `deletion_failed` | The deletion ran and a gate refused the key |

`deletion_failed` is the same verb a provider error records, because a deletion
that did not happen is one outcome however it was stopped. What the gates decided
is in the event's `reason` — a refusal slug from the table below for a refusal,
`failed_at_provider` for an error — and for a refusal that slug also decides
whether the row moves.

**Terminal** — the refusal comes from how the deployment is configured, so
retrying gives the same answer forever. The row moves to `retained` and leaves
the scheduled queue; the operator deletes the key at the provider, or changes the
configuration.

**Transient** — the refusal comes from current state, which changes without
touching the key. The row stays where it is and the next run retries it.

| Slug | Kind | Cause | Clears when |
|---|---|---|---|
| `shared_or_opaque_disposition` | terminal | `SharedKekStrategy`, or a `KEK_MAP` key without `KEK_MAP_DESTROYABLE` | The configuration changes |
| `provisioner_cannot_delete` | terminal | The provisioner's `supports_delete` is off | The configuration changes |
| `not_owned_by_deployment` | terminal | The key name does not carry this deployment's owner prefix, and the key is not a `KEK_MAP` value marked `KEK_MAP_DESTROYABLE` | The configuration changes |
| `in_use_by_other_silo` | transient | Live keysets still reference the key | Those data encryption keys are deleted |
| `no_provisioner` | transient | No KEK provisioner is configured | One is configured |
| `silo_still_exists` | transient | The silo is still alive | The silo is deleted |
| `silo_liveness_unknown` | transient | The silo adapter cannot enumerate | The adapter gains the capability |
| `silo_check_failed` | transient | The liveness probe errored | The probe succeeds |

The last three all mean *this key still backs something live, or we cannot prove
it does not* — the case
[`KEY_DELETION_CAN_RENDER_DATA_INACCESSIBLE`](configuration.md#key_deletion_can_render_data_inaccessible)
overrides.

`deletion_schedule_failed` never moves a row, on any slug above: the key is
untouched and stays schedulable once the reason is dealt with.

## Valid combinations

| Event | Trigger | Reason |
|---|---|---|
| `created` | direct | — |
| `created` | direct | `recorded_by_operator` |
| `created` | indirect | `silo_created` |
| `created` | indirect | `first_encryption` |
| `created` | automated | — |
| `discovered` | direct | `observed_at_provider` |
| `discovered` | indirect | `observed_at_provider` |
| `discovered` | automated | `observed_at_provider` |
| `reencrypted` | direct | — |
| `reencrypted` | automated | — |
| `rotation_started` | automated | — |
| `rotated` | automated | — |
| `rotated` | automated | `observed_at_provider` |
| `rotated` | indirect | `observed_at_provider` |
| `rotation_abandoned` | automated | — |
| `rotation_abandoned` | automated | `unconvertible_rows` |
| `rotation_abandoned` | direct | `dek_deleted` |
| `deletion_scheduled` | direct | — |
| `deletion_scheduled` | direct | `recorded_by_operator` |
| `deletion_scheduled` | indirect | `silo_deleted` |
| `deletion_schedule_failed` | direct | *refusal reason* |
| `deletion_requested` | direct | `observed_at_provider` |
| `deletion_requested` | direct | `recorded_by_operator` |
| `deletion_requested` | indirect | `observed_at_provider` |
| `deletion_requested` | automated | `observed_at_provider` |
| `deletion_failed` | direct | *refusal reason* |
| `deletion_failed` | direct | `failed_at_provider` |
| `deleted` | direct | — |
| `deleted` | direct | `observed_at_provider` |
| `deleted` | direct | `recorded_by_operator` |
| `deleted` | automated | `confirmed_by_reconcile` |
| `deleted` | indirect | `confirmed_by_reconcile` |
| `restored` | direct | — |
| `restored` | direct | `recorded_by_operator` |
| `silo_found` | direct | — |
| `silo_found` | direct | `silo_reacquired` |
| `silo_found` | indirect | `silo_created` |
| `silo_found` | indirect | `first_encryption` |
| `silo_found` | indirect | `silo_reacquired` |
| `silo_found` | automated | — |
| `silo_found` | automated | `silo_reacquired` |
| `silo_found` | indirect | `determined_by_reconcile` |
| `silo_found` | automated | `determined_by_reconcile` |
| `silo_not_found` | indirect | `silo_deleted` |
| `silo_not_found` | indirect | `determined_by_reconcile` |
| `silo_not_found` | automated | `determined_by_reconcile` |

These are the combinations the package itself writes. A project that calls a
deletion entry point from its own tooling rather than from the admin — [`purge_expired_deks`](management-commands.md) is the documented case — supplies its own
trigger, so in such a deployment the deletion verbs also carry `automated`.


`failed_at_provider` marks the branch where the provider was asked and the call raised
(`deletion._record_kek_failure`). It is the counterpart to a refusal slug on the same verb:
a refusal means nothing was asked, so nothing could fail. The provider's own words are not
recorded — the log already carries them untruncated under `error_code=kek_delete_failed`,
with the KEK resource name, key set and silo uid beside them, which is what joins a log line
to a ledger row.

`rotation_abandoned` takes a slug naming what ended the rotation, where something other
than the operator did: `dek_deleted` when the deletion that destroys the data key abandons
the rotation with it, `unconvertible_rows` when `reencrypt_data --abort-on-unconvertible`
unwound rather than leave the fence up. A plain `--abort` records none — the operator
decided, and there is nothing further to name.

The combinations table above is the vocabulary as designed. The rules that give
a combination meaning — an operator attestation is always `direct`, a reconcile
finding never is, an `indirect` event always names the act that caused
it — are enforced by running the write sites and checking the rows they produce,
in `tests/test_key_event_vocabulary.py`.

`rotation_started` and `rotation_abandoned` are **data encryption key only** —
they track a data re-encryption sweep, which has no key encryption key
equivalent. `rotation_started` is always `automated`: a sweep is a maintenance run
of [`reencrypt_data`](management-commands.md#reencrypt_data), and the operator who
ran it is in `os_user`. It moves the key to `reencrypting`. A resumed run
records no second one, so every rotation in the record opens and closes exactly
once. `rotation_abandoned` is `automated` from the command, and takes the trigger
of the deleting act when a deletion abandons one: the purge that destroys a rotating
key is a person on the changelist, so `direct`. Neither is manually recordable.

`rotated` tracks a completed rotation in a data encryption key or key encryption
key. On a data encryption key it is written by `reencrypt_data`'s swap, always
`automated`, and returns the key to `active`. On a key encryption key it always
has an `automated` trigger and an `observed_at_provider` reason, and is written
by a reconcile pass that finds the provider reporting a new version; the key's
status does not move.

`restored` on a data encryption key whose rotation survived its deletion window
returns it to `reencrypting` rather than `active`: the silo is still split between
two keys until the rotation is finished or aborted.

`silo_found` / `silo_not_found` record the orphan annotation whenever its value
is not already determined by the event beside it. `restored` is always `direct` —
either someone acted in the admin, or someone attested to cancelling a deletion
in the KMS console.

