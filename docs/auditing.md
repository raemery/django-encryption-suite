# Auditing

The package keeps two records, and they answer different questions. Almost every
"can I see what happened to this key?" question is answered by one of them, and
picking the wrong one wastes an afternoon — so this page is the fork, and holds
nothing else.

## The two records

**The [key lifecycle record](key-lifecycle-events.md)** is the account of what
happened to a key. Every state transition writes one row in the same database
transaction as the act, so a key is never created, re-encrypted, scheduled or
destroyed without a trace. Its verbs map to key statuses, which makes a row both
the report of a change and the authority for it. It is stored, filtered, rendered
through translated labels, and is kept as long as the row exists.

**The [system log](logging.md)** is the evidence of processing. It reports errors,
degraded capabilities, and the handful of routine operations worth a line. It is
English-pinned regardless of the reader's language, rotated, sampled, and
routinely cut below WARNING by the pipeline that ingests it. Nothing in the
package ever reads it back.

## Choosing a record

| Question | Read |
|---|---|
| When was this key created, scheduled, deleted — and by whom? | The lifecycle record |
| Why is this key `retained` instead of deleted? | The lifecycle record |
| Did the deletion I requested last week actually happen? | The lifecycle record |
| Which KMS, key and algorithm protected this key last year? | The lifecycle record |
| Why did this decrypt fail? | The log |
| Is the KMS reachable, and are its credentials good? | The log |
| Did the scheduled reconcile run at all? | The log |
| Is my configuration wrong? | The log |

The dividing line is whether a key changed state. Configuration faults, silo
enumeration failures and storage errors never touch a key, so they can never be
lifecycle events; they exist only in the log. In the other direction, routine
successes are recorded as rows and deliberately not logged, because one line per
key operation would drown the log without telling anyone anything.

Where both have something to say about the same moment, the log carries the
detail the record deliberately leaves out — a provider's own error text, for
instance, is logged untruncated beside the key's resource name and never copied
into a row.

Language is the reason the log needs stable error codes at all. It is English, so
an operator who does not read English needs a language-neutral handle in the
line; that is what the `error_code=<slug>` field on every raised error is for.
The codes are catalogued in [error-codes.md](error-codes.md). The lifecycle record has no such
problem — it stores constants and renders labels in the reader's language.

## Actors and user deletion

The lifecycle record names who acted in four columns: `user`, a reference to the
model named by `AUTH_USER_MODEL`; `os_user`, the operating-system account behind
a command; `ip_address`, the address the act came from; and `trigger`, whether a
person asked for this key event, it followed another act, or a script did it.
`os_user` and `ip_address` point at rows of their own, each holding one value in
plaintext or encrypted under the system silo's keys. Which of the three identity
columns are written at all is
[`USER_IDENTITY`](configuration.md#user_identity)'s business: its
`KEY_LIFECYCLE_EVENTS` list names them, and is empty under the shipped defaults,
so out of the box no act records who did it. The log has a list of its own,
`LOGS`, decided separately: an address can be kept in the record and out of the
log, or the other way round.

**`os_user` distinguishes people only where the operating system does.** On
a host with named accounts it names one, with the uid that ran the command
beside it. On a single-tenant container every operator arrives through the same
account and every row records the same value; attribution for those sessions
is in the platform's own access log, outside this package.

**A hard delete of a user account does not survive in the record.** The reference
is kept without a database constraint, so deleting a user never blocks and never
destroys ledger rows — the rows stay, and the column shows `Deleted user #<id>`.
That is coherent under an erasure request (the identity is gone structurally) and
cheap under a deactivate-and-scrub policy, but it must be stated rather than
discovered.

The id is **never re-issued** on PostgreSQL or SQLite: PostgreSQL serves
automatic keys from a sequence that never goes backward, and Django's SQLite
backend emits `AUTOINCREMENT`, which carries the same guarantee. Confirm the
equivalent on any other backend before relying on it. These operator actions
re-issue an id and silently re-point history to somebody else, which is worse
than losing it: an explicit primary key on insert, including `loaddata` on a
fixture that carries one; `sqlsequencereset`, a direct `setval`, or a
`sqlite_sequence` write; `flush` or `TRUNCATE ... RESTART IDENTITY`; and
restoring a dump into a database whose ledger rows are newer than the dump. None
is reachable from an application path.

**The erasure argument covers the user reference only.** The recorded addresses
and OS accounts, and the identity fields on log lines, are values rather than
references to a user: deleting a user touches none of them, and their rows are
never deleted, since the ledger rows point at them. The package ships no
redaction path — discharging an erasure request over them is the deploying
project's own work. `user_id` is the handle for it; on rows written with no user,
the OS account is matchable only as a string. Encrypting them keeps the values
out of the database in the clear, which is not the same as erasing them.

## Gaps in both records

- **Which user triggered a decryption, under the shipped default.** A read is
  not a key lifecycle act, so no row records one, and under `privileged_acts` the
  log line does not name a reader either. Setting
  [`USER_IDENTITY`](configuration.md#user_identity)'s `SCOPE` to `all_acts`,
  with items listed in `LOGS`, attributes those lines — but they remain log
  entries only, subject to whatever
  retention the pipeline gives them, and they appear at all only under
  [`LOG_DECRYPTS`](configuration.md#log_decrypts). For a durable record of who
  read what, log access in your own views.

- **Each value a data key rotation read.** `reencrypt_data` re-encrypts values
  holding both keysets directly, so it emits no per-value decrypt entries even
  under [`LOG_DECRYPTS`](configuration.md#log_decrypts). Its own lines carry a
  count of what the run moved, and the ledger records that the rotation ran.

- **The plaintext value.** Plaintext never appears in a log entry or a
  lifecycle row.

- **Key material.** Neither record stores a key, wrapped or plain.

- **Encryption events.** Only decryptions are logged, since encryptions happen on
  write — when the data is already known to the caller — and carry a lower audit
  risk than reads of stored data.
