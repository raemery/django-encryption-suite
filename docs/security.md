# Security Model

This page describes what this package protects against, what it does not
protect against, and how the isolation model interacts with different
multi-tenancy approaches.

To report a vulnerability, see [SECURITY.md](../SECURITY.md).

---

## Protections

### Compromised database

If an attacker obtains a dump of your database — through a SQL injection, a
misconfigured backup, a rogue DBA, or a cloud storage misconfiguration —
encrypted fields are unreadable without the corresponding key encryption key. The
ciphertext stored in the database is meaningless without access to the KMS
service that encrypts the per-silo keyset.

That holds for an attacker who also has an ordinary account in the
application. The application decrypts only values it read from the database,
so ciphertext taken from the dump and submitted through a form or an API is
never decrypted on its way back: the save is refused with
`FieldAlreadyEncryptedError`, and the submitted value is not stored.

This is the primary threat this package is designed to address.

### Insider access to the database

An employee or contractor with read access to the database cannot read
encrypted field values without also having access to the KMS service. Access
to the KMS service should be restricted to the application's service account
and controlled via your cloud provider's IAM policies.

### Cross-silo isolation

Each silo has its own Data Encryption Key (DEK). A ciphertext
produced under team A's DEK cannot be decrypted under team B's DEK —
the AEAD authentication check rejects it. This is the package's
strongest isolation guarantee and is unconditional: there is no
setting that turns it off.

If a row is reassigned across silos (in the admin panel, by an
attacker with database write access, or by a buggy migration), reads
of the row's encrypted fields fail loudly. The corruption is not
silently masked.

### Row-identity binding (optional)

By passing `aad=` to an encrypted field (see
[Binding a value to its row](encrypted-data.md#binding-a-value-to-its-row)),
the field's ciphertext is additionally bound to the listed columns on the
same row. The threat to plan for is someone holding a copy of the database
and an ordinary account in the application, in the same silo as the data they
want. Every row in a silo is under one data encryption key, so a value copied
from someone else's row onto their own would decrypt there and be shown to
them. The application refuses that copy when it arrives through a form or an
API (see [Compromised database](#compromised-database)), but a copy made in
the database itself — through write access, a SQL injection, or a restored
backup with edits — is outside what the field can see. With the field bound
to the row, the copied value fails to decrypt instead. The same binding catches
a foreign key reattached to point a record at a different parent.

Honest framing of what this does and doesn't buy you:

* **It catches:** same-column row swaps when the row's primary key or
  another immutable anchor is in `aad=`; foreign-key tampering when the
  foreign key is in `aad=`; accidental column-mixing from buggy migrations
  or raw SQL. Each value is length-prefixed in the AAD, so no bound value
  can be crafted to read as another row's columns.
* **It does not catch:** relational restructuring outside the listed
  columns; tampering with non-AAD columns; key compromise. AAD is an
  integrity / fail-mode control, not a prevention control.
* **Failure mode is fail-closed:** tampered rows do not silently
  produce wrong-attribution data; they raise on decrypt. Recovery
  requires either reverting the change or re-encrypting via the
  `reencrypt_for_aad_change` migration helper. Without backups or an
  audit trail of original column values, a tampered row is not
  recoverable to plaintext.
* **A tampered row holds up a data key rotation rather than being
  laundered by it.** `reencrypt_data` decrypts under the row's own AAD, so
  it cannot convert a row whose bound columns moved: it reports the row,
  refuses to swap, and leaves the fence up until the row is restored or the
  rotation is aborted. See [Rotating a data encryption key](key-rotation.md#rotating-a-data-encryption-key).
* **Bound values stay out of the log by default.** A failed read names each
  bound column and says whether it holds a value; the values themselves
  appear only under [`LOG_AAD_VALUES`](configuration.md#log_aad_values).
* **It does not keep anything secret from someone holding the DEK.** This
  is the limit most easily misread, so it is worth stating plainly. AAD is
  *authenticated*, not *encrypted*: in AES-GCM the ciphertext is the
  plaintext XORed with a keystream derived from the key and nonce alone,
  and the AAD only feeds the authentication tag. Anyone holding the DEK can
  therefore recover the plaintext **without knowing the AAD at all** — the
  library refuses on a tag mismatch, but that is a library check, not a
  cryptographic barrier, and raw AES-CTR against the same key and nonce
  bypasses it. The same is true of file segments. Treat AAD as an
  authorization and integrity check enforced *inside the application*, and
  never as a reason to consider a value confidential. In particular,
  putting a sensitive identifier in `aad=` does not conceal it — and
  does not need to, since the column it is read from is plaintext in the
  database anyway.
* **A tenant column is worth binding only when tenants share a silo.** When
  each tenant is its own silo, the per-silo DEK already refuses a row moved
  between tenants, and a read under the wrong silo — including one caused by
  an adapter returning the wrong silo — fails without any AAD. When several
  tenants or cells share one silo (a composite adapter in tenant-level mode,
  for example), they share a DEK, and binding the column that tells them apart
  is what keeps a row from moving between them. The same reasoning covers
  [user silos](user-specific-silos.md): each user's data is under that user's
  own keys, so a value moved onto another user's row already fails to decrypt.

### Field AAD vs KMS AAD

These are two different AADs in two different layers:

* **Field AAD** is the AAD passed to the crypto backend when encrypting
  and decrypting field values. Configurable via
  `aad=` on each encrypted field. Defends against the
  within-silo transplant cases above. It never leaves the application
  process.
* **File AAD** is the same value, bound into every segment of a streamed
  file rather than into a single tag. Both crypto backends support AAD on
  both surfaces — Tink through `Aead` and `StreamingAead`, the
  pyca-cryptography backend through its configured AEAD for fields and its STREAM
  implementation for files — so there is no coverage gap between them.
* **KMS AAD** is the AAD passed to KMS `Encrypt` / `Decrypt` calls
  when wrapping or unwrapping the DEK with the KEK. Always includes
  the silo UID. Defends against unwrapping a DEK on behalf of a
  different silo. Unlike field AAD, this value **is transmitted to your
  KMS provider** on every wrap and unwrap, and may appear in their
  request logs — so an identifier that is harmless in field AAD can be a
  disclosure here.

The two layers serve different purposes. Code, settings, and
operational runbooks should keep them separate.

---

## Limits of protection

### A compromised application server

If an attacker has code execution on the application server, they can:
- Impersonate any silo (by setting the thread-local or connection tenant)
- Request KMS decryption for any silo's keyset
- Read plaintext values from any field they can load

This package does not protect against application-layer compromise. Defense
against this requires KMS key policies that restrict which resources can
decrypt which keys (e.g. tying a KMS key to a specific service account or
IAM role), and network-level controls on KMS access.

The adapter's authentication method decides what you can do after you find the
compromise. Most adapters hold a credential, such as an IAM role session or an
OIDC-federated token. You can revoke a credential, and access ends when it
expires. Others rely on access the process already has — a machine-local socket,
or a key encryption key held in settings — and you can only cut that off by
stopping the process. The
[credential strategies table](kms-adapters.md#credential-strategies) shows which
kind each adapter uses.

### Auditing someone with a shell

The same access defeats the package's own records. Someone at a shell on the
application host can call the engine without writing a ledger row, and can edit
or delete ledger rows directly: the record is append-only because the admin
offers no way to change it, not because the database refuses. Every management
command logs a WARNING line as it starts, naming who ran it — but a command's
log lines go wherever that process's output goes, and in an interactive session
(`fly ssh console`, `kubectl exec`, `heroku run`) that is the operator's
terminal, not the platform's log stream.

So the audit trail for this kind of access has to live where the person being
audited cannot reach it:

- **Audit the session, not what happens in it.** The platform records a shell
  being opened, in infrastructure the session cannot change — Fly, for
  instance, logs `New SSH session` with the account that opened it. Alert on
  that line.
- **Record the session itself** where shell access is routine: host command
  auditing (`auditd`), session recording, or brokered access such as Teleport,
  AWS Session Manager, or HashiCorp Boundary.
- **Ship logs off the host at once**, to a store whose credentials the
  application host does not hold. A log the person who acted can delete records
  nothing. Route the `encryption_suite` logger there alongside Django's own, and
  a management command writes to the same place as the server.
- **Run privileged work as a defined job.** A command started by a pipeline or
  as a one-off machine has its invocation recorded and its output collected,
  which leaves an interactive shell as the exception worth alerting on.
- **Read the KMS provider's audit log.** Decrypting any protected value means
  unwrapping a data key, which means calling the KMS, and a provider that keeps
  an audit log records the call — including one made with the application's own
  credentials from a shell. Under a per-silo key encryption key strategy, the
  record also says whose data was touched. It is the one trail a compromised host
  cannot avoid creating. Check that it is enabled: on some providers the record
  of a decrypt call is off by default.

A deployment can also make the ledger append-only in the database, by revoking
`UPDATE` and `DELETE` on its table from the application's database role. Plan for
one exception: the test console deletes the ledger rows of its own throwaway
keys when it cleans up, so that cleanup needs a role that still can.

#### Copying an interactive command's lines into the platform log

Until every log leaves the host, one smaller step closes the gap that matters
most here. A container platform typically collects the output of the
container's first process. A command started from a shell session is a different
process, so its lines go to the operator's terminal — but written to the first
process's output instead, they reach the platform's log stream beside the
server's.

Check that your platform collects it first. From a shell on the running
container:

```bash
echo "pipe test" > /proc/1/fd/1
```

If `pipe test` appears in the platform's log — it does on Fly.io — add this to
the settings module that deployment uses. It assumes your `LOGGING` already
configures an `encryption_suite` logger and a formatter, as
[Logging](logging.md) recommends; use your own formatter's name.

```python
import os
import sys

MACHINE_LOG = "/proc/1/fd/1"
if sys.stderr.isatty() and os.access(MACHINE_LOG, os.W_OK):
    LOGGING["handlers"]["machine_log"] = {
        "class": "logging.FileHandler",
        "filename": MACHINE_LOG,
        "formatter": "verbose",
        "delay": True,
    }
    LOGGING["loggers"]["encryption_suite"]["handlers"] = [
        *LOGGING["loggers"]["encryption_suite"]["handlers"],
        "machine_log",
    ]
```

Three conditions keep it correct:

- **Interactive sessions only** (`sys.stderr.isatty()`). The server, and any
  command the platform runs itself — a `migrate` at release, say — already have
  their output collected. Copying theirs as well would put every line in the log
  twice.
- **Root only** (`os.access`). The first process's output belongs to root, so a
  command run as another account cannot open it, and runs without the copy. A
  session that never escalates is not captured this way.
- **Opened on the first line** (`"delay": True`). A failure to open costs that
  line an error report instead of stopping the command.

Run a command from a shell session and its pair of lines should appear in the
platform's log, behind whatever timestamp and source the platform puts on the
server's own lines:

```
WARNING "encryption_suite.management.commands.reconcile_keys" A privileged management command started; this line records that it ran, including a run that changes nothing. command=reconcile_keys <identity>
WARNING "encryption_suite.management.commands.reconcile_keys" A privileged management command finished. command=reconcile_keys key_store=fly discovered=0 observed_pending=0 confirmed=0 … <identity>
```

A start with no finish after it is a run that did not reach an ending it knows
about — including one whose session was cut off mid-run, which is the case this
copy exists to catch.

Where the platform also records a shell being opened, that line sits just before
it. The platform's line says who opened the shell; the package's says what ran in
it. Neither attributes the act alone. The copy is still written to a log the host can
reach, so it narrows the gap rather than closing it — shipping logs off the host
is what closes it.

### Static credentials in process memory

Credential strategies that use static secrets (HashiCorp Vault `token`,
Infisical `token`) hold those values as plain Python
attributes for the lifetime of the process.  If process memory is
dumped, these credentials are recoverable.  This is inherent to how static
credentials work in Python.

Prefer short-lived, automatically rotated credential strategies in
production: `iam_role` or `oidc` for AWS, `adc` or `oidc` for GCP,
`managed_identity` or `oidc` for Azure, `iam_aws` or `oidc` for HashiCorp Vault,
`universal_auth` or `oidc` for Infisical, and `container` or `vpc_instance` for
IBM Key Protect on IBM compute (`iam_assume` elsewhere). See
[KMS adapters](kms-adapters.md) for details.

### OIDC token sources

The `oidc` credential strategy delegates JWT acquisition to a pluggable
token source — Fly.io socket, file-based (Kubernetes / IRSA / Azure
Workload Identity / Nomad), GCP metadata, Vercel, or SPIFFE. There are
operational requirements that are easy to miss because the package
"just works" once configured but matter for the security properties:

- **The `"file"` source** trusts whatever is at `PATH`. That path —
  *and every parent directory on it* — must be writable only by the
  orchestrator. If an unprivileged process can replace the file or
  swap a symlink, it can forge a JWT and impersonate your workload.
  The standard targets (`/var/run/secrets/...`,
  `AWS_WEB_IDENTITY_TOKEN_FILE`, `AZURE_FEDERATED_TOKEN_FILE`) already
  satisfy this; custom paths need explicit attention.
- **HashiCorp Vault / Infisical** must be reached over `https://`.
  The JWT travels in the request body and is exposed in transit
  otherwise. The package logs a warning at startup if a non-localhost
  endpoint is configured with `http://`.
- **All `OIDC_SOURCE_OPTIONS` keys** (`PATH`, `SOCKET_PATH`, `HOST`,
  `VAULT_JWT_MOUNT`, etc.) must come from trusted configuration —
  never from untrusted user input.

See [OIDC token sources — Security considerations](kms-adapters.md#security-considerations-for-oidc-sources)
for the full guidance.

### Queries and indexes

Encrypted fields store ciphertext, which differs on every write, so the database
cannot compare the stored value to anything. A lookup by value is refused rather
than answered with no rows — see
[blind index leakage](#blind-index-leakage) for the one
exception, an exact match against a
[blind index](encrypted-data.md#finding-a-row-by-its-value), and what it
discloses.

Sorting and ranges have no equivalent and are not coming: a keyed hash answers
whether two values are equal and nothing else, and the schemes that do preserve
order publish the column's order to anyone who can read the table. Order and
filter on a column you did not encrypt.

Three ORM surfaces reach the column without going through the field, and none of
them decrypts. `values()` and `values_list()` return the stored value as it
stands. `order_by()` sorts by it. An `aggregate` or `distinct` over it groups it.
None raises, because each is reached from code this package cannot see — a
third-party model's own queries included — and a page that renders unreadable
text is better than one that 500s. What you get is visibly not plaintext.

### Key management lifecycle

This package manages the key lifecycle from the application side: it provisions
key encryption keys, re-wraps and rotates keys, schedules and performs deletion
behind its own gates, and records every key event in the
[key lifecycle record](key-lifecycle-events.md). The KMS provider remains the
authority on the key material itself. Its access policies decide who can use or
delete a key, and its audit log records every call made with the key, so
configure both there as well.

### KMS availability

If the KMS service is unavailable, encrypted fields cannot be decrypted (unless
the value is already in the in-process cache). Design your application to
handle KMS unavailability gracefully — consider circuit breakers and appropriate
`DEK_CACHE_TTL` values for your availability requirements.

### Encryption count per data key

Field values are encrypted under a nonce drawn at random for every encryption.
If two encryptions under one key draw the same nonce, the key's AES-GCM output
reveals the XOR of the two plaintexts and lets an attacker forge ciphertexts. The
chance of a repeat grows with the number of encryptions made under the key, so
each data key has a limit:

| Field algorithm | Nonce | Limit per data key |
|---|---|---|
| `AES256_GCM` (the default), `CHACHA20_POLY1305`, Tink `AES128_GCM` | 96 bits, random | 2^32 encryptions. This is the [NIST SP 800-38D](https://csrc.nist.gov/pubs/sp/800/38/d/r1/iprd) bound for random IVs, and it keeps the chance of a repeat below 2^-32. |
| `AES256_GCM_SIV` | 96 bits, random | About 2^50 messages. A repeated nonce reveals only whether two plaintexts are equal. |
| Tink `AES256_EAX` | 128 bits, random | The 2^32 figure does not apply. |

The package does not count encryptions or stop at a limit. Keeping each key under
its limit is the operator's job, and rotation is the tool for it.

Every encrypted-field write counts once. A save re-encrypts each accessed encrypted
field, even when its value did not change, and `reencrypt_data` writes every field
it moves. Reads do not count. File contents do not count toward this limit: each
file stream derives its own key from a random salt, so its nonces are unique to
that stream.

**The system key set reaches the limit first.** Every row of every system-keyed
column shares one data key (see [System keys](#system-keys)), so the writes of all
users count together. A per-team key sees only that team's writes, so the limit
seldom applies to it.

**Rotation starts the count again.** `reencrypt_data` replaces a silo's data key
with new material and re-encrypts its fields under it, so the new key starts from
zero. For the system key set, rotate with `reencrypt_data --key-set system` on a
schedule set by the estimate below. See
[Rotating a system key](key-rotation.md#rotating-a-system-key).

**Estimate the schedule.** Count the encrypted-field writes made under one key per
day, and rotate before the running total reaches 2^30 (about 1.07 billion). That
leaves a margin of four below the 2^32 limit. For example, a system key that takes
10 million field writes a day reaches 2^30 in about 107 days.

---

## Production safeguards

### Keys on an env key store

An env key store wraps every silo under it with one key encryption key held in
your settings. Anyone who can read `ENV_KEY_STORES` can unwrap every key under
it, nothing ever deletes that KEK, and a rotation covers every silo at once. It is
a supported production option, and its protection is the secrecy of the key
material and wherever you keep it. There is no provider-side access policy, no
audit log and no HSM, and rotation is manual through `KEKS` versions.

A `KEY_SETS` entry that gives the `system` key set a KMS store instead draws
`manage.py check` warning `W058`: sign-in would then stop working when the KMS is
unreachable. An empty `KEKS` fails the
check outright (`E039`), because the package never generates key material.

### Constrain key deletion at the provider, not only in the app

Destroying a KEK is the one irreversible act in this package. Data encrypted
under it cannot be recovered afterwards — not from a database backup, because
what is lost is the key that backup's ciphertext depends on. Everything else the
package does is recoverable; this is not.

Four gates guard that act before the deletion calls the provider: no data key may
still be wrapped by the KEK, the KEK must be
[silo-exclusive](kek-strategies.md), the provisioner must set `supports_delete`,
and the key's name must carry this deployment's owner prefix. They are worth
having, and the deletion re-derives the owner prefix from the running configuration
on every run rather than trusting the value stored on the row.

But all four read state the application can reach. A compromised process, a
buggy data migration, or an edited row is reasoning about inputs it also
controls. **Put a boundary outside the application as well**, evaluated by the
provider on the key's own attributes:

| Provider | Mechanism |
|---|---|
| AWS KMS | IAM condition on `kms:ResourceTag/<key>` for `kms:ScheduleKeyDeletion` — see [Getting started with AWS](getting-started-aws.md#narrowing-kmsschedulekeydeletion-to-keys-the-app-created) |
| GCP Cloud KMS | IAM Conditions over Resource Manager tags, or a key ring dedicated to this deployment |
| OCI Vault | Policy conditions on defined tags, or a dedicated compartment |
| Azure Key Vault | No data-plane tag condition; scope the role assignment to a dedicated vault |
| Fly, HashiCorp, IBM, Infisical | No tag reaches an individual key, so their provisioners cannot tag. Isolate with a dedicated app, mount, instance, or project |

On IBM the distinction is worth stating plainly, because IBM Cloud does have a
full tagging system: the **Key Protect instance** is taggable like any account
resource, but the **keys inside it** are not — the create call takes no tag, and
Global Tagging rejects a key CRN outright. The instance is provisioned outside
this package, so its tags are yours to manage and owe nothing to `TAGS`.

The tagging providers write whatever you put in `TAGS` verbatim, so the tag your
policy matches on is the tag the provisioner attaches. Set it before the first
key is created: tags are written at creation, and a key created without them is
outside the condition's reach.

The simplest version of this principle needs no tags at all — if the application
is never granted the provider's delete permission, no bug and no tampering can
destroy a key, and the deletion records each one as `retained` for an operator to
handle by hand. That is a perfectly good posture, and the default: a provisioner
reports `supports_delete` only where its provider leg implements deletion, and
where the provider guards deletion on the key itself, only when the deployment
has also opted in (HashiCorp Vault's `ALWAYS_ALLOW_KEY_DELETION`).

### Error handling in production

django-encryption-suite raises typed exceptions that all subclass
`EncryptionError` (itself a `ValueError`, so a broad `except ValueError`
around a save still catches them; prefer catching `EncryptionError`).
Whatever the failure — a decryption/authentication failure, an operational
KMS error, or a **configuration error** (a missing/invalid option, an unknown
credential strategy, an incompatible KEK strategy) — the message carried on the
exception (`str(exc)`) is **generic and translated** (e.g. "Decryption failed.",
"Encryption and decryption are unavailable for this data."). It never includes silo
UIDs, key names, option values, or provider error text.

The actionable detail is written to the `encryption_suite` logger at `ERROR`
level and, for configuration errors, also attached to the exception's `detail`
attribute. `detail` is for **operator-facing** surfaces only: the logs, the
deploy-time [system checks](configuration.md#system-checks), and the admin
[test console](admin-panel.md#test-console), which shows it beside the error
code because its reader is an operator diagnosing their own KMS wiring. The
console requires its own permission (`encryption_suite.run_test_console`), so
grant it only to people entitled to see infrastructure detail. No other screen
or response renders `detail`.

However, whether those messages reach end users depends on your
application's error handling, not on this package.  To ensure users see
a friendly error page rather than exception text:

**1. Set `DEBUG=False` in production.**  With `DEBUG=True`, Django
displays full tracebacks — including exception messages and local
variables — to anyone who triggers an error.  This is the single most
important setting for production security.

**2. Configure a custom 500 error template.**  Create
`templates/500.html` with a user-friendly message (e.g. "Something went
wrong.  Please try again later.").  Django will serve this automatically
for unhandled exceptions when `DEBUG=False`.

**3. Set up admin error notifications.**  Configure `ADMINS` and an
email backend so that Django emails a full traceback to your team on
every 500 error:

```python
ADMINS = [("Ops Team", "ops@example.com")]
SERVER_EMAIL = "django@example.com"
```

Alternatively, use a service like Sentry, Datadog, or Rollbar for
structured error tracking.

**4. If you use Django REST Framework**, check what your exception handler
returns for a server error. DRF's default handler returns nothing for an
exception it does not recognize, so Django answers with your 500 page, which
carries no exception text. The package's
[`api_exception_handler`](working-with-django-rest-framework.md#errors) puts
`str(exc)` in its response at every status, 500 included. That is safe for an
`EncryptionError`, because its message is one of the generic, translated strings
described above. It never puts `exc.detail` in a response. A handler you write
yourself should follow the same split: `str(exc)` for an `EncryptionError` is
safe to return, and `exc.detail`, or the message of any other exception, is not.

**5. Route the `encryption_suite` logger** to a persistent log sink.
When an error does occur, the detailed log entry (including silo
UID, field name, and the underlying exception) is the diagnostic
starting point.  See [Logging](logging.md) for routing
examples.

The principle: django-encryption-suite provides safe exception messages and
detailed server-side logs.  Your application controls what the user sees
and how your team is notified.

---

## Isolation model: django-tenants vs. row-based tenancy

The value of this package differs significantly depending on your tenancy
approach.

### django-tenants (schema isolation)

Schema isolation is enforced at the database level. A query in tenant A's
context physically cannot see tenant B's tables. Encryption adds a second
independent layer on top of this:

- An attacker who defeats schema isolation (e.g. via `search_path` manipulation
  or direct superuser access) still cannot read sensitive fields without the key encryption key
- The two defenses are independent — neither depends on the other working

In this setup, encryption is **defense in depth**.

### Row-based tenancy (Pegasus teams, custom org models)

All tenants share the same database tables. Isolation is enforced entirely at
the application layer — a `filter(team=request.team)` in a queryset is the
only thing separating teams.

In this setup, encryption does significantly more work:

- A missing queryset filter that would expose all teams' data in plaintext
  instead returns a pile of ciphertext — unreadable without the correct team's
  key in context
- An IDOR vulnerability (e.g. manipulating a team ID in a URL) returns
  ciphertext that cannot be decrypted without the correct silo context
- A SQL injection that returns rows from multiple teams returns mixed
  ciphertexts, each readable only with its own team's key

In this setup, encryption is **actively compensating for weaker isolation**,
not just adding an extra layer.

---

## Silo context integrity

The silo context (which tenant/team is active) is set by middleware and
read by the silo adapter on every field access. If the context is wrong,
decryption will fail loudly — AEAD authentication will reject the ciphertext
encrypted under a different silo's key. This fail-loud behavior is
intentional and important.

### Context state leakage across requests and tasks

The risks below are about the *adapter's* backing state, not the package
itself. The package's job is to consult the adapter; the adapter's job is to
return the right answer. See
[Silo adapters — Adapter contract](silo-adapters.md#adapter-contract)
for the formal requirements, and
[Cross-request tenant-isolation hazards](cross-request-tenant-isolation-hazards.md)
for the broader inventory of shared-state surfaces in the same hazard class.

**Background tasks and workers.** A task that accesses encrypted fields
without setting the silo context explicitly fails with
`EncryptionConfigurationError` (no silo active): a write raises, and a lenient
read degrades to the fallback value and logs the cause. This is the correct
failure mode. The
risk to guard against is a task that *incorrectly inherits* a stale value
from a previous request in the same worker. Always use
`clear_current_silo()` in a `finally` block in middleware, and use
`override_current_silo()` as a context manager in tasks.

**ASGI servers and `sync_to_async`.** The built-in
`PegasusTeamSiloAdapter` and the generic
`GenericModelSiloAdapter` use `contextvars.ContextVar`, which isolates
per `asyncio.Task` and propagates correctly across `sync_to_async` calls and
the per-task `ThreadPoolExecutor` that asgiref uses to run sync code. This
combination has been verified empirically under concurrent requests from
distinct users on `gunicorn -k uvicorn.workers.UvicornWorker --threads N`:
silo resolution stays correct on every request.

**Custom adapters using thread-locals.** If you write an adapter that backs
its state with `threading.local` rather than a `ContextVar`, you must clear
it in a `finally` block at every boundary that hands the thread back to a
pool — middleware, Celery task, or any sync executor. A missed cleanup means
the next caller on that thread reads the previous caller's silo.
Prefer `ContextVar` unless you have a specific reason not to.

**A wrong silo fails closed on its own.** If the adapter returns the wrong
silo for a request, the engine uses that silo's DEK, and the row's
ciphertext — encrypted under its own silo's DEK — fails to decrypt. No
`aad=` binding is needed for that. See
[Row-identity binding](#row-identity-binding-optional) for what binding adds
inside a silo.

---

## Audit logging

`LOG_DECRYPTS` defaults to `False`; enable it to emit one `INFO`
entry per successful field decryption recording the silo UID and
field name. It is off by default because read-heavy paths will saturate
most log pipelines — turn it on for compliance use cases after sizing
your sink for the throughput. Decryption failures and missing-key errors
are always logged at `ERROR` regardless of this setting, while the
exceptions raised to application code stay generic to avoid leaking
internal identifiers.

See [Logging](logging.md) for full details on what is logged, how to route it,
and integration recommendations. [Auditing](auditing.md) says which questions
the log answers and which belong to the key lifecycle record.

---

## Envelope encryption

This package uses **envelope encryption**:

1. Each silo's data is encrypted with a **data encryption key (DEK)** —
   generated by the configured crypto backend (AES-256-GCM by default) and
   unique to that silo.
2. The DEK is encrypted by a **key encryption key (KEK)** held in your KMS
   provider. The encrypted DEK is stored in `DataEncryptionKey`.
3. The plaintext DEK exists only in memory, briefly, during a field read or
   write. It is never written to disk.
4. Decrypted DEKs are cached in-process for `DEK_CACHE_TTL` seconds to avoid
   a KMS call on every field access.

The consequence of this design: compromising the database exposes only
encrypted keysets (useless without KMS access). Compromising the KMS service
exposes only KEKs (useless without the encrypted keysets in the database).
Both would need to be compromised simultaneously for an attacker to read plaintext data — and even then, only if they have access to the ciphertext in the database.

---

## User keys

A [user-specific key set](user-specific-silos.md) reads a user's data under keys
chosen by the acting user. The web layer then shows another user's rows, a staff
member's view of them included, as the fallback label or a ciphertext preview. A write
uses the acting user's keys too, except under `ActingUserOrOwnerSiloAdapter` while
nobody is acting, when it uses the keys of the user the row belongs to.

**What it protects.** Reading one user's data while a different user is acting, through
the application. With a key encryption key per user at a KMS, shredding a user also
survives a restored backup.

**What it does not protect.** The application chooses the key, and the application holds
the key encryption key. Someone with a shell, the database and the key encryption key
can decrypt any user's data, and an impersonation tool acts as the user it impersonates.
Under a shared key encryption key or an env store, a restored backup brings a shredded
user's data keys back. Under `ActingUserOrOwnerSiloAdapter`, an anonymous endpoint that
lets request input set a row's owner lets a caller write into another user's silo; see
[Who chooses the silo](user-specific-silos.md#who-chooses-the-silo).

---

## System keys

[System-wide silos](system-wide-silos.md) use the envelope above, with
one difference at the top: the system silo's key encryption key is `ENV_KEY_STORES`,
in your settings, and the env key store that wraps with it makes no call off the
machine. That is deliberate: these columns include the ones a sign-in reads, and
a login that depended on a team's KMS would lock an operator out of the screen
that diagnoses that KMS.

The protection is therefore weaker, and worth stating plainly.

**What it protects.** A lost, stolen or subpoenaed database; a backup or a dump;
anything read out through SQL injection. In all of those the attacker has the
ciphertext and not the key.

**What it does not protect.** Anything that reaches the running application. The
process holds `ENV_KEY_STORES` because it must, so an attacker with code execution, a
shell, or the ability to read the environment has it too. This is the same bargain
as any at-rest encryption whose key the application holds, and it is strictly
weaker than a silo's envelope, where the key encryption key never leaves the KMS.

In practice that means the two kinds of column defend against different things, and
it is worth being deliberate about which one a given column needs. A silo's
business data belongs under the envelope. A user's email address has to be
readable before the envelope works at all.

**One data key for every user.** The system silo has one data encryption key,
and every row of every system-keyed column is under it. The per-silo isolation
that keeps one team's value from decrypting on another team's row does not
exist here, so a value copied in the database from one user's row onto another's
decrypts on the second row unless the field binds the row. Bind each
system-keyed field with `aad=` to an immutable row anchor: a client-assigned
primary key, a `row_uuid` column, or a foreign key that never changes. Never
bind a mutable column such as a slug or a username, because changing it makes
the field fail to decrypt on that row. See
[Binding a system-keyed field to a row anchor](adopting-and-removing-encryption.md#binding-a-system-keyed-field-to-a-row-anchor)
for adding an anchor to a table that already has rows.

### Blind index leakage

Any encrypted column can declare
[`blind_index=True`](encrypted-data.md#finding-a-row-by-its-value), which stores
a keyed hash of the value where a database can index it so the column can be
searched. The hash reveals **equality**: two rows holding the same value index
alike.

Someone with the database but not the keys can therefore learn which rows share a
value, and how often each distinct value occurs. If they know one person's value
from elsewhere, they can find every row that holds it. They cannot recover a value
they do not already have, because the hash is keyed — an unkeyed hash of an email
address is recovered by hashing a word list, which is why a separate key exists for
this.

Which key, and what that buys, depends on the column's `key`. A `key_set="system"`
column hashes under the system silo's index key, wrapped by `ENV_KEY_STORES` from the
settings, so the digest is computable by anything holding the settings and the
database. A [silo column](encrypted-data.md#finding-a-row-by-its-value) hashes
under the silo's own index key, wrapped by the silo's KEK, which raises the bar
twice: a reader of the database cannot test a guess at all without the KMS,
and destroying a silo's KEK destroys its digests along with its data rather than
leaving rows that can still be matched. It also means two silos holding one value
index differently, so one silo's rows cannot be matched against another's.

The disclosure is proportional to how repetitive the column is. For an email
address or a username, where nearly every value occurs once, the frequency table
says almost nothing. For a column with a small range of values — a birth date, a
postal code, a status — it gives away most of what encrypting the column was for.

So index it only where a lookup genuinely needs it. A column with no index is
still encrypted; it simply cannot be searched.

### Length, for both kinds of column

Ciphertext length tracks plaintext length, so a stored value reveals roughly how
long the value was. That is true of the silo fields as well, and is not something
either kind of column hides.

### Key storage

Hold `ENV_KEY_STORES` as you hold `SECRET_KEY`: in your platform's secret store, read
into settings from the environment. A key written into a settings file is a key in
your version control, and every backup of it.

Dropping one of its versions is irreversible in a way a KMS-held key is not: no
provider holds the material, so there is no deletion window and no restore. See
[Rotating a system key](key-rotation.md#rotating-a-system-key).
