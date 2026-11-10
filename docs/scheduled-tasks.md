# Scheduled commands and tasks

Some of the package's work runs best on a schedule, and some of your own code that
reads encrypted data runs outside a request.

## Scheduled work

| Work | How | Notes |
|---|---|---|
| Find drift between key records, live silos and the KMS | [`reconcile_keys`](management-commands.md#reconcile_keys) | It records only what it observed and never deletes anything. Daily is a sensible start. |
| Keep a record of what protects your data | [`crypto_inventory`](management-commands.md#crypto_inventory) | It changes nothing. A JSON report from each run gives a reviewer something to compare with the last one. |
| Re-wrap data keys after the provider rotates a key encryption key | [`reencrypt_keys`](management-commands.md#reencrypt_keys) | `reconcile_keys` counts the keys due as `key_reencryption_due`. See [Key rotation](key-rotation.md#re-encryption-after-rotation). |
| Replace data encryption key material | [`reencrypt_data`](management-commands.md#reencrypt_data) | Nothing rotates a data encryption key on its own: [`DEK_ROTATION_PERIOD_DAYS`](configuration.md#dek_rotation_period_days) only marks keys as due. For unattended runs, see [`--abort-on-unconvertible`](management-commands.md#--abort-on-unconvertible) and [`--only-outdated`](management-commands.md#rotating-only-outdated-keys). |
| Issue a fresh HashiCorp Vault AppRole `secret_id` | [`encryption_suite_rotate_hashicorp_approle`](management-commands.md#encryption_suite_rotate_hashicorp_approle) | Only HashiCorp Vault uses it. |
| Destroy keys whose deletion window has passed | The admin's purge action | The package deliberately ships no command for this. If you script it, read [Destroying keys](management-commands.md#destroying-keys) first. |
| Your own work on encrypted data | A Celery task, a cron job, or a management command | Exports, notifications and re-processing jobs each need a silo context, and usually `strict_mode()`. |

## Examples

- [Celery and background tasks](silo-adapters.md#celery-and-background-tasks) shows
  a task that sets its silo context and reads encrypted fields.
- [Outside a request](encrypted-data.md#outside-a-request) sets and clears the silo
  context by hand in a command, task or script.
- [User-specific silos](user-specific-silos.md) sets the acting user in a task, for a
  key set bound to a user silo adapter.
- [Via a staff-only endpoint or admin action](key-rotation.md#via-a-staff-only-endpoint-or-admin-action)
  runs `reencrypt_keys` from an admin action and from a Celery task.
- [Via platform-specific one-off commands](key-rotation.md#via-platform-specific-one-off-commands)
  runs a command as a job on a hosting platform.
- [If you cannot expose the admin](management-commands.md#if-you-cannot-expose-the-admin)
  calls the key purge from your own code, and lists what to weigh before you
  schedule it.
- [Example: scheduled rotator in CI](getting-started-hashicorp.md#example-scheduled-rotator-in-ci)
  rotates an AppRole `secret_id` weekly from a CI scheduler.

## Silo context

Middleware sets a request's silo. A task or a scheduled command has no request, so
it sets the silo itself, with `override_current_silo` or your framework's own
context helper, such as `schema_context` for django-tenants. Context variables do
not travel from the code that queues a task to the worker that runs it.

With no silo in context, the engine picks no key:

- A write raises `EncryptionConfigurationError`.
- A read returns the fallback label, and the engine logs an ERROR line saying that
  no silo was in context.
- `str(obj)` on a model whose `__str__` reads an encrypted field returns Django's
  default `<Model> object (<pk>)`, and the package logs a WARNING line that names
  the field. See [A model's `__str__`](encrypted-data.md#a-models-__str__).

Columns in the `system` key set always use the system silo, so they need no
context. The package's own commands need none either, because they work on keys
and ciphertext rather than on a silo's plaintext.

## Strict mode

A lenient read keeps a web page rendering when a value cannot be decrypted, which
suits a person looking at a screen. A task's output is usually the data itself: an
export file, an email, a record sent to another system. There, a fallback label is a
wrong result that looks like a success. Wrap such work in `strict_mode()`, and any
read that cannot produce plaintext raises instead:

```python
import csv

from celery import shared_task
from encryption_suite import strict_mode
from encryption_suite.adapters.silos.context import override_current_silo


@shared_task
def export_patients(team_pk: int, path: str) -> None:
    team = Team.objects.get(pk=team_pk)
    with override_current_silo(team), strict_mode(), open(path, "w", newline="") as f:
        writer = csv.writer(f)
        for patient in Patient.objects.filter(team=team).iterator():
            writer.writerow([patient.pk, str(patient), patient.notes])
```

Without the `override_current_silo` line, the first row raises
`EncryptionConfigurationError`, and the engine logs the reason. That includes
`str(patient)`, which outside `strict_mode()` writes `Patient object (12)` into the
file. With the context set, the task reads plaintext as usual, and a value that
fails to decrypt raises its own typed error instead of putting the fallback label
in the export.

Keep `strict_mode()` around the work that produces data, not around a whole request
or a whole worker. It covers everything called inside its block, so pages that rely
on the fallback, such as the admin's delete confirmation, raise instead. See
[Decryption modes](encrypted-data.md#decryption-modes-lenient-vs-strict).

## Command output

Four commands can hand their results to another tool: `crypto_inventory`,
`reconcile_keys`, `reencrypt_keys` and `reencrypt_data`. Each takes the same two
options for this.

| Option | Effect |
|---|---|
| `--format json` | The command writes one JSON document to standard output when it ends. Everything it writes for a person goes to standard error instead, so standard output holds the document and nothing else. |
| `--output FILENAME` | The command writes the JSON document to `FILENAME` and leaves standard output empty. It needs `--format json`. |

The package does not store these documents. Your scheduler, log collector or
compliance tool keeps them, compares one run with the next, and holds them for as
long as your retention rules require. They name key stores and keys but carry no
key material and no plaintext. Keep them where you keep other records about your
infrastructure.

### Report format

Every document starts with the same four keys. `schema_version` is the format's
version, and the package raises it only when it renames or removes a key, so a
difference between two runs tells a format change from a change in the deployment.
`command` names the command, and `started_at` and `finished_at` record the run's
start and end as ISO 8601 timestamps. `crypto_inventory` adds the inventory. The
other three add `passes`, a list with one entry per store (`reconcile_keys`) or per
`--key` pass (the two re-encrypt commands).

### Exit status

A command exits 0 when it finished and did all its work. It exits non-zero in three
cases:

- It refused to start, because an option or the configuration was wrong. It writes
  no report.
- `reencrypt_keys` failed to re-encrypt a row. It still tries every other row,
  writes its report, and then exits non-zero.
- `reencrypt_data` stopped with a fence up, a rotation failed, or `--check` found a
  value with no digest. It writes its report, and then exits non-zero.

`reconcile_keys` exits 0 even when some of its checks could not run, because a check
it could not run limits what it saw rather than failing the run. It writes those
checks to standard error, and its JSON lists them under `could_not_run`. Alert on
either.

### Checking a report

`jq -e` exits non-zero when its expression is false, so a scheduler can alert on a
reconcile run that missed a check:

```bash
python manage.py reconcile_keys --format json --output reconcile.json
jq -e 'all(.passes[]; .could_not_run == [])' reconcile.json
```

To see what changed between two inventories, compare them without the run
timestamps:

```bash
diff <(jq -S 'del(.started_at, .finished_at)' last.json) <(jq -S 'del(.started_at, .finished_at)' inventory.json)
```

### Logs and standard output

The commands send their start line and closing counts through Python logging, not
standard output. Django's default console handler writes to standard error, which
keeps those lines out of the JSON. If your project sends log records to standard
output, they land inside the document, so use `--output`.

## Settings module

A job runs under whatever `DJANGO_SETTINGS_MODULE` its environment sets, and that is
not always the module your web processes use. Under the wrong module, a command can
finish cleanly and do nothing, because no configured key store matches the stores
its rows record. The commands say so when that happens; see the note on
`skipped_key_stores` in
[If you cannot expose the admin](management-commands.md#if-you-cannot-expose-the-admin).
Give your jobs the same settings module as your web processes.

## Command logs

Every command the package ships logs a WARNING line as it starts, carrying the
options it ran with. Every one except `crypto_inventory` logs a second WARNING line
as it finishes, carrying its counts. For those commands, an opening line with no
closing line after it marks a run that was killed, or that died on an error it could
not report. See [Log levels](logging.md#log-levels).

[`USER_IDENTITY`](configuration.md#user_identity)'s `LOGS` list decides which
identity items a line carries. A command has no Django user, so `os_user` is the item
that names something: the operating-system account the process runs under. In a
scheduled job, that account belongs to your scheduler or container, so it identifies
the job rather than a person. See [Actor identity](logging.md#actor-identity).

A job's lines go wherever its process's output goes. Route the `encryption_suite`
logger to the same place as your web processes' logs, ideally a store off the host.
See [Auditing someone with a shell](security.md#auditing-someone-with-a-shell).

## Sensitive data in logs

A job that reads every row writes far more than a request does. Three settings
decide what that output can carry:

- [`LOG_DECRYPTS`](configuration.md#log_decrypts) writes one INFO line for each value
  decrypted, so a task that exports a table writes one line per row and column. Size
  your log sink for that, or leave the setting off. `reencrypt_data` writes none of
  these lines, whatever the setting says.
- [`LOG_AAD_VALUES`](configuration.md#log_aad_values) decides whether a line that
  identifies a row it could not read carries the values of the row's AAD-bound
  columns. A batch job produces such lines many at a time. `reencrypt_data
  --show-aad-values` prints the values whatever the setting says, and a scheduler
  that keeps a job's output keeps them too, so use that option only in interactive
  runs.
- [`USER_IDENTITY`](configuration.md#user_identity) decides which identity items
  each line carries.

## Long-running workers

A worker process caches each data key it uses for
[`DEK_CACHE_TTL`](configuration.md#dek_cache_ttl) seconds, as a web process does,
so a rotated or revoked key reaches a running worker when that entry expires. Each
worker process holds its own cache, so a pool of workers makes its own KMS calls on
top of your web processes'. See
[Operational concerns](operations.md#multi-process-deployments-gunicorn-uvicorn-with---workers).

## Related

- [Management commands](management-commands.md): every command and its options
- [Silo adapters](silo-adapters.md): setting and reading a silo context
- [Logging](logging.md): every line the package emits
- [Key rotation](key-rotation.md): rotating both layers of keys
