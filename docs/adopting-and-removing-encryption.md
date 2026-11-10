# Adopting and Removing Encryption

This guide covers the migration workflow for adding encryption to existing
fields and removing encryption from fields that no longer need it.

## Choosing a procedure

| Your situation | Procedure |
|---|---|
| A brand new encrypted field, with no existing data to convert | [Adding a new encrypted field to a model](#adding-a-new-encrypted-field-to-a-model) |
| A value column that already holds plaintext, owned by a silo | [Adding encryption to an existing field](#adding-encryption-to-an-existing-field) |
| A `FileField` that already holds uploads | [Adding encryption to an existing file column](#adding-encryption-to-an-existing-file-column) |
| A system-wide column no group of users scopes — typically the ones a sign-in reads | [Adopting a system encrypted column](#adopting-a-system-encrypted-column) |
| A column declared in a third-party model | [Columns another package owns](#columns-another-package-owns) |
| An encrypted column that no longer needs to be | [Removing encryption from a field](#removing-encryption-from-a-field) |
| A field's `aad=` changing on a model that already has rows | [Changing a field's AAD binding](#changing-a-fields-aad-binding) |
| A fresh project with nothing to convert | [Starting with a fresh project](#starting-with-a-fresh-project) |

Every procedure below is built from the same handful of helpers, imported from
`encryption_suite.migration_helpers` and called from a `RunPython` migration:

| Helper | Converts | Needs a silo and a KMS |
|---|---|---|
| `encrypt_field` / `decrypt_field` | one value column, row by row, under each row's own silo key — or, for a [`key_set="system"` column](system-wide-silos.md), under the system silo's key with its blind index digests | yes, except for a `key_set="system"` column |
| `encrypt_file_field` | one silo file column — the blob, its storage path, and its display name | yes |
| `reencrypt_for_aad_change` | every named field on a model, onto a new AAD policy | yes, except that a `key_set="system"` field needs no silo |

None of them goes through the field protocol: each reads and writes the column
directly, which is what lets them run against rows the deployed field class
cannot yet read.

---

## Adding a new encrypted field to a model

This is the common case when integrating django-encryption-suite for the first
time: you're adding a brand new field that has no existing data to
migrate, only a schema change.

### Non-null encrypted fields

When you add a `NOT NULL` column, Django requires a default value and
emits roughly:

```sql
ALTER TABLE myapp_patient ADD COLUMN notes text DEFAULT '<prepared>';
ALTER TABLE myapp_patient ALTER COLUMN notes DROP DEFAULT;
```

The default would reach every existing row as plaintext, because nothing
encrypts it on that path, so the encrypted field refuses to write it and the
migration fails. Encrypting those rows needs a **current silo context** for
each one, and `migrate` has none — no HTTP request, no tenant scope.

Note: `blank=True` only affects Django form validation. It does **not**
make the column nullable. The column is still `NOT NULL` at the database
level unless you also pass `null=True`.

You have two supported patterns. Pick based on whether you can tolerate
`NULL` values in the new column.

### Pattern A: Nullable column (simple)

If your model can tolerate `NULL` for the new field, this is the
recommended approach:

```python
class Patient(models.Model):
    team = models.ForeignKey("teams.Team", on_delete=models.CASCADE)
    notes = EncryptedTextField(null=True, blank=True)
```

> **Binding data within a silo:** each silo has its own DEK, so a row moved to
> another silo already fails to decrypt. To tie encrypted data to something
> *inside* a silo — the user who owns it, or the parent record it belongs to —
> pass those columns to each encrypted field's `aad=`, e.g.
> `aad=("owner",)`. If one of them is changed, for example to hand a record to
> another user on the same team, its encrypted fields fail to decrypt instead
> of reading as the new owner's. See
> [Row-identity binding](security.md#row-identity-binding-optional).
> If you add or change a field's `aad=` on a model with existing data, see
> [Changing a field's AAD binding](#changing-a-fields-aad-binding) below.

```bash
python manage.py makemigrations
python manage.py migrate
```

`migrate` emits `ALTER TABLE ... ADD COLUMN notes text NULL` with no
backfill value, so nothing is written to existing rows and the engine is not
called. Existing
rows get `NULL`; new writes encrypt normally because they happen inside
a request with silo context.

Your application code must handle `None` when reading the field.

### Pattern B: Two-phase backfill (required for NOT NULL)

If the field must be `NOT NULL`, you need three migrations. This mirrors the
established pattern for adding `NOT NULL` columns to large tables.

| | Kind | What it does |
|---|---|---|
| 1 | schema migration | Adds the column as `null=True` |
| 2 | data migration | Backfills a value per row, with the row's silo set |
| 3 | schema migration | Drops the `NULL` constraint |

#### 1. Add the column as nullable — schema migration

```python
class Patient(models.Model):
    team = models.ForeignKey("teams.Team", on_delete=models.CASCADE)
    notes = EncryptedTextField(null=True, blank=True)  # nullable for now
```

```bash
python manage.py makemigrations
```

#### 2. Set a value per silo — data migration

The data migration must set the current silo before each row's
save so the field has what it needs to encrypt. Use
`override_current_silo` from the context-adapter helpers — this is
the same mechanism middleware uses during normal request handling, so
the backfill path exercises the same code as production writes.

```python
# 0045_backfill_patient_notes.py
from django.db import migrations


def forwards(apps, schema_editor):
    from encryption_suite.adapters.silos.context import (
        override_current_silo,
    )

    Patient = apps.get_model("myapp", "Patient")

    for patient in Patient.objects.filter(notes__isnull=True).iterator():
        with override_current_silo(patient.team):
            patient.notes = ""  # or whatever default your model needs
            patient.save(update_fields=["notes"])


def backwards(apps, schema_editor):
    Patient = apps.get_model("myapp", "Patient")
    Patient.objects.update(notes=None)


class Migration(migrations.Migration):
    dependencies = [("myapp", "0044_add_patient_notes")]
    operations = [migrations.RunPython(forwards, backwards)]
```

`override_current_silo` works only when your silo adapter
extends `ContextSiloAdapter` (which is the common case). If you
use a different adapter, pass the silo explicitly through the
engine instead.

Important: use `apps.get_model()` so the migration works even if the
model changes later. Use `.iterator()` for large tables to avoid loading
all rows into memory.

#### 3. Alter the column to NOT NULL — schema migration

```python
class Patient(models.Model):
    team = models.ForeignKey("teams.Team", on_delete=models.CASCADE)
    notes = EncryptedTextField()  # no null=True now
```

```bash
python manage.py makemigrations
python manage.py migrate
```

Django generates an `AlterField` that drops the `NULL` constraint. Since
every row already has a non-null (encrypted) value from step 2, the
alter succeeds.

### Skipping encryption during migrate

It would be tempting for the field to detect that it's being called from
`schema_editor` and emit the plaintext default unchanged. Do not do
this. It produces ciphertext-shaped columns that sometimes contain
plaintext, silently, with no reliable way for later code to tell the
difference. Explicit nullable-or-backfill is safer.

---

## Adding encryption to an existing field

### Overview

When you change an existing field to an encrypted field, two things must
happen:

1. **Schema change** — the column type may change (e.g. `date` → `text`
   for `DateField` → `EncryptedDateField`).  For fields already stored as
   `text` (e.g. `TextField` → `EncryptedTextField`), no schema change is
   needed.
2. **Data migration** — existing plaintext values must be encrypted.

These must happen in the right order, and the encrypted field class should
not be deployed until **after** the data migration has run.  Otherwise,
the app will try to decrypt plaintext values and fail.

### Code to write

| | Kind | What it does |
|---|---|---|
| 1 | schema migration | Widens the column to `text`, by hand — the field class in `models.py` does not change yet. Skip it where the column is already `text`. |
| 2 | data migration | `encrypt_field` converts every row in place |
| 3 | deploy | Runs migration 2 against the old field class. The column now holds ciphertext the app reads as raw text. |
| 4 | schema migration + deploy | Changes the field class in `models.py` and deploys it, so reads decrypt again |
| 5 | management commands | Only for a column declaring `blind_index=True`: builds the digests, which the data migration could not |

Steps 3 and 4 are a transitional state — see [Zero-downtime
considerations](#zero-downtime-considerations) before scheduling them.

### Step-by-step

#### 1. Widen the column, if the type changes — schema migration

If the column type changes (e.g. `IntegerField` → `EncryptedIntegerField`),
Django's `makemigrations` will generate an `AlterField` operation.  If the
column type stays the same (e.g. `TextField` → `EncryptedTextField`), no
schema migration is needed — but you may still want to generate one as a
dependency anchor for the data migration.

**Important:** Do not change the field class in `models.py` yet.  Instead,
create a manual schema migration that changes only the column type:

```python
# 0043_prepare_patient_encryption.py
from django.db import migrations, models

class Migration(migrations.Migration):
    dependencies = [("myapp", "0042_previous")]
    operations = [
        migrations.AlterField(
            model_name="patient",
            name="national_id",
            field=models.TextField(null=True),  # widen to text
        ),
    ]
```

For `TextField` and `CharField` fields that already map to `text`, skip
this step.

#### 2. Convert the rows — data migration

Create a data migration that encrypts all existing values using the
`encrypt_field` helper:

```python
# 0044_encrypt_patient_national_id.py
from django.db import migrations

def forwards(apps, schema_editor):
    from encryption_suite.migration_helpers import encrypt_field
    encrypt_field(
        apps, "myapp", "Patient", "national_id",
        silo_fk="team",
        silo_uid_field="pk",
        silo_label="team",
    )

def backwards(apps, schema_editor):
    from encryption_suite.migration_helpers import decrypt_field
    decrypt_field(
        apps, "myapp", "Patient", "national_id",
        silo_fk="team",
        silo_uid_field="pk",
        silo_label="team",
    )

class Migration(migrations.Migration):
    dependencies = [("myapp", "0043_prepare_patient_encryption")]
    operations = [migrations.RunPython(forwards, backwards)]
```

The `backwards` function uses `decrypt_field` to reverse the migration if
needed.

#### 3. Deploy the data migration — deploy

Deploy and run the data migration.  At this point, the app is still using
the original (unencrypted) field class.  The database column now contains
ciphertext, but the app doesn't know that — it sees the raw ciphertext
strings as regular text values.

This is a brief transitional state.  Proceed to step 4 promptly.

#### 4. Change the field class — schema migration + deploy

Now change the field class in `models.py`:

```python
# Before
national_id = models.IntegerField(null=True)

# After
national_id = EncryptedIntegerField(null=True)
```

Run `makemigrations` to capture the field class change, then deploy.
The encrypted field now decrypts the ciphertext when the attribute is read,
and encrypts in `pre_save` on write.

#### 5. Build the blind index digests — management commands

Only for a column declaring `blind_index=True`. Skip this step if it does not.

The rows are encrypted but **not findable yet**. `encrypt_field` converted the
value and left the digest alone, which is the only thing it could do: the
migration that called it ran while the column was still declared as a plain
`TextField`, so there was no `blind_index` on the historical field to read and —
under the default `blind_index_storage="column"` — no digest column in the schema
to write to. That column arrived with the field class, in step 4.

So the digests are built afterwards, by the same two commands that would rebuild
them after an index key rotation:

```bash
python manage.py setup_encryption_keys
python manage.py reencrypt_data --purpose index
```

`setup_encryption_keys` provisions the index key for any silo that has none — it
could not have done so before now, because it only provisions one where a field
declaring an index is actually deployed. `reencrypt_data --purpose index` then
decrypts each value under the silo's field key and recomputes its digest, which
fills every digest the migration left empty. It fences each silo's lookups while
it runs, as any index rotation does.

Until that finishes, a lookup against the column **matches nothing rather than
failing**, which reads as "no such row" — so gate the release that starts relying
on the lookup on a clean report from:

```bash
python manage.py reencrypt_data --purpose index --check
```

That reads the stored column only: no decrypt, no silo, no KMS. It exits non-zero
while any indexed value holds no digest. See
[`reencrypt_data --check`](management-commands.md#reporting-digests-that-were-never-built).

A column declaring `unique_in_silo=True` deserves one extra thought here. `NULL`
digests are distinct to the database, so the constraint over them accepts every
unbuilt row, and the uniqueness guarantee only begins once the digests exist. If
the plaintext already held a duplicate, step 5 is where it surfaces.

### Parameter reference

Both `encrypt_field` and `decrypt_field` accept:

| Parameter | Required | Description |
|-----------|----------|-------------|
| `apps` | Yes | The `apps` registry from the `RunPython` callback |
| `app_label` | Yes | Django app label (e.g. `"myapp"`) |
| `model_name` | Yes | Model class name (e.g. `"Patient"`) |
| `field_name` | Yes | Field name to encrypt/decrypt (e.g. `"national_id"`) |
| `silo_fk` | Yes | FK field on the model pointing to the silo (e.g. `"team"`) |
| `silo_uid_field` | No | Field on the silo model used in the UID (default: `"pk"`) |
| `silo_label` | Yes | The label your silo adapter puts before the id in a silo uid (e.g. `"team"`) |
| `batch_size` | No | Rows between progress log entries (default: `500`) |

The `silo_label` and `silo_uid_field` must match what
your silo adapter's `get_silo_uid()` produces.  For example,
if your adapter returns `"team-42"`, then `silo_label="team"`
and `silo_uid_field="pk"` (assuming the team's PK is `42`).

### Unconvertible rows

This applies to all three helpers.

A row that cannot be converted — ciphertext that will not authenticate, an
AAD-bound column that has gone `NULL`, a row whose silo FK is empty — does
not end the run where it stands. Each one is logged against its primary key
with its own reason and a stable [error code](error-codes.md), the walk
continues, and the helper raises at the end naming how many rows were left
and which they were.

Finishing the walk is the point: an abort on the first bad row tells you
about exactly one, so finding the extent of the problem means re-running the
migration once per row. Inside an atomic migration the closing error rolls
the work back exactly as an abort would have, and you still get the whole
list from the one run.

A failure that is *not* a property of one row — the KEK cannot be reached,
the silo has no data encryption key — ends the run immediately instead. It
would fail identically for every remaining row, and logging an outage once
per row helps nobody.

### Field type considerations

Every encrypted field type stores its ciphertext in a `text` column, under either
`key`, so the schema question has one answer per original field:

| Original field | Encrypted field | Schema change needed? |
|---|---|---|
| `TextField` | `EncryptedTextField` | No — both use `text` |
| `CharField` | `EncryptedCharField` | Maybe — the encrypted column is `text`, `CharField` is `varchar` |
| `EmailField` | `EncryptedEmailField` | Maybe — same as `CharField` |
| `URLField` | `EncryptedURLField` | Maybe — same as `CharField` |
| `IntegerField` | `EncryptedIntegerField` | Yes — `integer` → `text` |
| `DateField` | `EncryptedDateField` | Yes — `date` → `text` |
| `DateTimeField` | `EncryptedDateTimeField` | Yes — `timestamp` → `text` |
| `JSONField` | `EncryptedJSONField` | Yes — the database's own JSON type → `text` |
| `FileField` | `EncryptedFileField` | Yes, and a different procedure — see [Adding encryption to an existing file column](#adding-encryption-to-an-existing-file-column). `encrypt_file_field` converts silo file columns only. |

When the column type changes, the database casts existing values to text during
the schema migration (`42` → `"42"`, `2024-03-15` → `"2024-03-15"`), and the
helper handles those string representations.

Three declarations change the answer:

- **`varchar_column=True`** keeps the column `varchar` rather than widening it
  to `text`, for the case where another package indexes it. Adopting a
  `CharField` whose `max_length` is wide enough for ciphertext then needs no
  schema change at all — and a width that is *not* enough is reported by a
  [system check](configuration.md#system-checks) rather than failing the
  migration.
- **`blind_index=True`** adds a companion digest column, and `unique=True`
  with it adds a constraint over that column. Both are contributed by the
  field, so `makemigrations` writes them into the schema migration with
  nothing else asked of you. `blind_index_storage="table"` stores the digests
  as rows in the package's own table instead, and adds no column.

  On a silo column, the schema is all `encrypt_field` does for the index: it
  writes the value and leaves the digest `NULL`, so the digests are built
  afterwards — [step 5](#5-build-the-blind-index-digests--management-commands).
  For a `key_set="system"` column, `encrypt_field` writes both, because its
  migration runs with the encrypted field already in place.
- **`EncryptedJSONField`** makes the `AlterField`
  to `text` a hard requirement *before* the `RunPython`, not just a
  convention. Run the conversion while the historical field is still a
  `JSONField` and the helper is handed a decoded `dict`, whose `str()` is a
  Python repr — `{'a': 1}`, with single quotes — and that is what gets
  encrypted. It will not parse back as JSON. The other types are safe in
  either order, because `str()` of an `int` or a `date` is the same string the
  text column holds.

  The cast itself is lossless as to content but not as to formatting: on a
  database that stores JSON in a canonicalizing type, such as PostgreSQL's
  `jsonb`, the text the column yields has already lost the original key order
  and whitespace. That is the text that gets encrypted.

---

## Adding encryption to an existing file column

A file column cannot be rewritten in place the way a value column can: the
blob and the name that reaches it are two different things, and the name is
itself data. `encrypt_file_field` converts both. For each row it reads the
blob the column points at, encrypts it under the silo's file key, writes it
under a fresh opaque name, moves the column onto that name, and deletes the
original object. The filename the old path carried — `pay_stub_q1.pdf` — is
what an opaque name stops saying out loud, so it is encrypted into the
companion display-name column in the same write. That column is where an
encrypted file field keeps the name a person sees; a row converted without it
has lost its filename for good.

### Code to write

| | Kind | What it does |
|---|---|---|
| 1 | schema migration | Adds the display-name column and changes the field class to `EncryptedFileField`, both at once. Hold the deploy. |
| 2 | data migration | `encrypt_file_field` converts every blob, path and name |
| 3 | deploy | Runs migration 2, then deploys the new field class |

Unlike a value column, the field class changes in the *first* migration: the
helper reads the storage and the `display_name_field` off the historical model,
so a column still declared as a plain `FileField` has neither and the run
refuses.

### Step-by-step

#### 1. Add the display-name column and change the field class — schema migration

Both in one schema migration, and deploy neither yet:

```python
class Document(models.Model):
    upload = EncryptedFileField(display_name_field="upload_name", null=True, blank=True)
    upload_name = EncryptedCharField(max_length=255, null=True, blank=True)
```

Run `makemigrations`, then hold the deploy: between this migration and the
data migration below, the application would try to decrypt blobs that are
still plaintext.

#### 2. Convert the blobs — data migration

```python
# 0044_encrypt_document_uploads.py
from django.db import migrations

def forwards(apps, schema_editor):
    from encryption_suite.migration_helpers import encrypt_file_field
    encrypt_file_field(
        apps, "myapp", "Document", "upload",
        silo_fk="team",
        silo_uid_field="pk",
        silo_label="team",
        aad_columns=("team",),   # match aad= on the file field and its display-name field
    )

class Migration(migrations.Migration):
    dependencies = [("myapp", "0043_encrypted_upload_column")]
    operations = [migrations.RunPython(forwards, migrations.RunPython.noop)]
```

There is no reverse. Going back means decrypting every blob to a plaintext
name of your choosing, and only you know what those names should be —
`upload_name` holds what the old paths said, which is a starting point rather
than an answer.

#### 3. Deploy

Run the migration, then deploy the application against the new field class.

### Killed runs

Each blob is written, read back, and verified before the column moves, and the
original is deleted only after. So a run killed anywhere leaves either a row
still pointing at its plaintext original, or a converted row — never a row
pointing at a blob nothing has checked. Rerun it: a converted row is
recognized by its display-name column and skipped.

Two leftovers are possible and neither is fixed by a rerun. A blob written for
a row that then failed to convert is stray, and is logged as a warning naming
its path. A plaintext original that would not delete after its row converted is
worse — the file is still readable where it always was — and is logged at
ERROR naming the path, because nothing else will remove it.

### Parameters

It takes exactly the parameters `encrypt_field` takes: `apps`,
`app_label`, `model_name`, `field_name`, `silo_fk`, `silo_uid_field`,
`silo_label`, `aad_columns`, `batch_size`. The display-name column is not
a parameter — the field already names it.

The blob is bound to `aad_columns` exactly as an upload through the field
protocol would be, and so is the display name. Declare the same columns in
`aad=` on both the file field and its display-name field.

---

## Adopting a system encrypted column

Everything above is about a column encrypted under a silo's data key. A
[`key_set="system"` column](system-wide-silos.md) uses the same two helpers, with
no silo arguments, and one difference in timing that matters.

### Code to write

| | Kind | What it does |
|---|---|---|
| 1 | schema + data migration, in one file | `AlterField` to the encrypted field with `key_set="system"`, then `RunPython` calling `encrypt_field` |
| 2 | deploy | Runs migration 1 and the new field class together |

One migration rather than two, because here the column change and the
conversion have to ship together — see [Ship the conversion with the column
change](#ship-the-conversion-with-the-column-change-not-after-it).

```python
from encryption_suite.migration_helpers import decrypt_field, encrypt_field


def forwards(apps, schema_editor):
    encrypt_field(apps, "users", "CustomUser", "email")


def backwards(apps, schema_editor):
    decrypt_field(apps, "users", "CustomUser", "email")


class Migration(migrations.Migration):
    dependencies = [("users", "0002_previous")]

    operations = [
        migrations.AlterField(model_name="customuser", name="email", field=...),
        migrations.RunPython(forwards, backwards),
    ]
```

For a `key_set="system"` column neither helper needs a silo, so there is no silo
foreign key to name and no `silo_label` to get right. `encrypt_field` creates
the system silo's keys if they do not exist yet. Both read `key`, `blind_index` and
`normalize` off the historical field, so a migration never restates what the model
already declares — which means the `AlterField` has to come **before** the
`RunPython`, so the historical model carries the new field. Run in the wrong order,
the helper reads a plain column, asks for the silo arguments a silo column needs,
and writes nothing.

Both skip rows that are already in the state they are converting to, so a re-run is
idempotent, and a row that cannot be converted is logged and the run then fails with
all of them reported rather than stopping at the first.

### Converting to or from a user key set

A column in a [user-specific key set](user-specific-silos.md) has one silo per user, so
the helpers take the silo arguments a team column takes: `silo_fk` names the model's
foreign key to the user, and `silo_label` is `"user"`.

```python
def forwards(apps, schema_editor):
    encrypt_field(apps, "notes", "Note", "body", silo_fk="owner", silo_label="user")
```

The helpers write the same `user-<pk>` uids the adapter reads.

### Ship the conversion with the column change, not after it

This is the one real difference from a silo column. The guidance above — do not
deploy the encrypted field class until after the data migration — does not apply
here, because there is a worse failure available.

A value with no marker is read back as it stands, so an unconverted row is
*readable* either way. What it cannot be is *found*: a lookup matches the
[blind index](system-wide-silos.md#looking-a-value-up), and a plaintext row has
none. If these columns are the ones a sign-in reads — which is the usual reason to
use them — then between the release and the conversion nobody can sign in at all.

So put the `AlterField` and the `RunPython` in the same migration, and let the
release that introduces the field be the release that converts the rows.

### Afterwards

A machine still running the previous release during a rolling deploy can write a
plaintext row *after* the migration has run. Such a row has no digest, so the
digest check reports it:

```bash
python manage.py reencrypt_data --key-set system --purpose index --check   # non-zero while any is left
```

Convert what it reports by calling `encrypt_field` again, from a shell with the
live registry (`from django.apps import apps`); it skips every row already
encrypted.

### Columns another package owns

A column declared in a third-party model cannot be altered by a migration in your
app — an `AlterField` reaches only models in its own app — so it can be encrypted
only if that package lets you choose its field class or swap its model.
django-allauth does neither; see
[Working with django-allauth](working-with-django-allauth.md) for what stays in
plaintext.

---

## Removing encryption from a field

### Overview

Removing encryption is the reverse: decrypt all values first, then change
the field class back to the original type.

**Critical:** The key encryption keys and `DataEncryptionKey` records must
still exist when the decryption migration runs.  Do not delete them until
after the migration has completed successfully and you have verified the
data.

### Code to write

| | Kind | What it does |
|---|---|---|
| 1 | data migration | `decrypt_field` converts every row back to plaintext |
| 2 | deploy | Runs migration 1 against the encrypted field class |
| 3 | schema migration | Changes the field class in `models.py` back, narrowing the column to its original type |
| 4 | deploy | Ships the field class change |
| 5 | cleanup, optional | Removes the `DataEncryptionKey` rows and the KEKs, once the data is verified |

Steps 2 and 3 are a transitional state, and a worse one than adoption's: the
column holds plaintext the deployed field class refuses to read. Schedule them
back-to-back — see [Zero-downtime
considerations](#zero-downtime-considerations).

### Step-by-step

#### 1. Decrypt the rows — data migration

```python
# 0050_decrypt_patient_national_id.py
from django.db import migrations

def forwards(apps, schema_editor):
    from encryption_suite.migration_helpers import decrypt_field
    decrypt_field(
        apps, "myapp", "Patient", "national_id",
        silo_fk="team",
        silo_uid_field="pk",
        silo_label="team",
    )

def backwards(apps, schema_editor):
    from encryption_suite.migration_helpers import encrypt_field
    encrypt_field(
        apps, "myapp", "Patient", "national_id",
        silo_fk="team",
        silo_uid_field="pk",
        silo_label="team",
    )

class Migration(migrations.Migration):
    dependencies = [("myapp", "0049_previous")]
    operations = [migrations.RunPython(forwards, backwards)]
```

#### 2. Deploy and run the data migration — deploy

All values are now plaintext in the `text` column.

#### 3. Change the field class back — schema migration

```python
# Before
national_id = EncryptedIntegerField(null=True)

# After
national_id = models.IntegerField(null=True)
```

Run `makemigrations`.  If the column type changes (e.g. `text` →
`integer`), the database will cast the plaintext strings back to the
original type.

#### 4. Deploy

Deploy the field class change and schema migration.

#### 5. Clean up (optional)

Once you have verified that all data is correct:

- Remove the `DataEncryptionKey` records for the affected
  silos (only if no other fields remain encrypted for those
  silos).
- Remove the key encryption keys in your provider (only if they are no longer
  needed for any purpose).

**Do not rush this step.** Keep the keys until you are certain the
decrypted data is correct and your backups do not contain encrypted
values that you might need to restore.

---

## Zero-downtime considerations

Both adoption and removal involve a brief transitional state between the
data migration and the code deploy.  During this window:

- **Adoption (step 3 → 4):** The database has ciphertext but the app
  reads it as raw text.  This means users might briefly see ciphertext
  strings in the UI.  To avoid this, schedule the data migration and
  code deploy back-to-back during low traffic, or put the affected views
  behind a maintenance page.

- **Removal (step 2 → 3–4):** The database has plaintext but the app
  still has the encrypted field class.  Reads return the plaintext as it
  stands, because a value without the `~^Dv1:` prefix is treated as not yet
  encrypted, but every save encrypts the row again. Deploy the data migration
  and code change back-to-back.

For applications that cannot tolerate any downtime, consider using a
phased approach with a new column: add the encrypted column alongside the
original, backfill it, switch reads to the new column, then drop the old
one.  This is more work but eliminates the transitional state entirely.

---

## Starting with a fresh project

If you are adding django-encryption-suite to a new project with no existing
data, none of the above applies.  Simply use encrypted field classes in
your models from the start.  No data migrations are needed — all data
will be encrypted from the first write.

---

## Migrating mixed plaintext/ciphertext rows

Decryption always raises on a value missing the `~^Dv1:` ciphertext
prefix ([Stored formats](concepts.md#stored-formats)), so the field protocol cannot be used to read mixed
plaintext/ciphertext rows. This is deliberate: a "tolerant read" mode
would silently mask the same signal that detects a wrong-key, AAD-
mismatch, or tampered-row failure, defeating the AEAD authentication
guarantee.

Use the `encrypt_field` and `decrypt_field` migration helpers instead.
They encrypt or decrypt all rows in a single deterministic pass and
bypass the field protocol entirely.

---

## Changing a field's AAD binding

Adding, removing, or modifying a field's `aad=` on a model that already
has encrypted rows needs a **data migration**. Existing ciphertexts were
bound under the old AAD policy and will not decrypt under the new one.
Without a migration step, every read of the affected field fails.

`aad=` is a field option, so changing it makes `makemigrations` write an
`AlterField` operation. The operation changes no column; the
`reencrypt_for_aad_change` helper is what converts the rows. The
recommended sequence:

1. Schedule downtime (or read-only mode) for the affected models. A
   partially-completed run leaves the table in a half-migrated state
   where some rows decrypt under the old policy and some under the
   new — neither path will work cleanly until the migration finishes.
2. Change `aad=` on the fields and run `makemigrations`.
3. Add a `RunPython` operation to the generated migration, after the
   `AlterField` operations, that calls the helper:

   ```python
   from encryption_suite.migration_helpers import reencrypt_for_aad_change

   def forwards(apps, schema_editor):
       reencrypt_for_aad_change(
           apps, "myapp", "MedicalRecord",
           field_names=("notes", "diagnosis"),
           silo_fk="team",
           silo_label="team",
           old_aad_columns=(),                  # was: no AAD
           new_aad_columns=("pk", "person"),    # now: row-identity bound
       )
   ```

4. Deploy the code change and run `migrate`.
5. Resume application traffic.

The helper accepts every encrypted field whose AAD policy is changing
in the same way in `field_names`. Pass them all at once: the helper
re-encrypts them together within a single row read, so the row sees a
consistent policy state. Fields whose bindings change differently need
one call each.

`silo_fk` and `silo_label` are needed only when a listed field is a silo
field. A `key_set="system"` field is encrypted under the system silo on
every row, so the call names neither.

### Binding a system-keyed field to a row anchor

A system-keyed field shares one data encryption key across every row, so
nothing but its AAD stops a value from being copied onto another row. Bind it
to a column that never changes for the life of the row. This example adds a
`row_uuid` anchor to an existing `Team` table and binds the team name to it:

```python
import uuid

class Team(models.Model):
    row_uuid = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    name = EncryptedCharField(max_length=100, key_set="system", aad=("row_uuid",))
```

Django cannot add a unique column with a generated default to a table that
already has rows in one step, because the default is computed once and every
row would get the same value. Add the anchor in three migrations, then bind
the field in a fourth.

1. Add the column as nullable:

   ```python
   # 0010_team_row_uuid.py
   operations = [
       migrations.AddField(
           model_name="team",
           name="row_uuid",
           field=models.UUIDField(null=True, editable=False),
       ),
   ]
   ```

2. Give each row its own value:

   ```python
   # 0011_fill_team_row_uuid.py
   import uuid

   def fill(apps, schema_editor):
       Team = apps.get_model("myapp", "Team")
       for team in Team.objects.filter(row_uuid__isnull=True).only("pk"):
           Team.objects.filter(pk=team.pk).update(row_uuid=uuid.uuid4())

   operations = [migrations.RunPython(fill, migrations.RunPython.noop)]
   ```

3. Make it unique and non-nullable:

   ```python
   # 0012_team_row_uuid_unique.py
   operations = [
       migrations.AlterField(
           model_name="team",
           name="row_uuid",
           field=models.UUIDField(default=uuid.uuid4, unique=True, editable=False),
       ),
   ]
   ```

4. Bind the field and re-encrypt the rows. No silo arguments are passed:

   ```python
   # 0013_bind_team_name.py
   from encryption_suite.migration_helpers import reencrypt_for_aad_change

   def forwards(apps, schema_editor):
       reencrypt_for_aad_change(
           apps, "myapp", "Team",
           field_names=("name",),
           old_aad_columns=(),
           new_aad_columns=("row_uuid",),
       )

   operations = [
       migrations.AlterField(
           model_name="team",
           name="name",
           field=encryption_suite.fields.EncryptedCharField(
               aad=("row_uuid",), key_set="system", max_length=100
           ),
       ),
       migrations.RunPython(forwards, migrations.RunPython.noop),
   ]
   ```

For applications that cannot tolerate downtime, the package does not
provide an online dual-read mechanism — apply-once-and-deploy is the
supported pattern. If you need zero-downtime AAD policy transitions,
you'll need to layer a versioning shim of your own at the
application level.

### Recovering from accidental AAD-column changes

When an AAD-bound column is changed on a row outside of the
recommended migration flow (e.g. an admin user reassigns a record's
`person` foreign key), every field on the row that binds it fails to
decrypt on the next read. Recovery requires either:

* Reverting the column change to its original value, restoring the
  AAD that the ciphertext was bound to. Read access resumes.
* Running `reencrypt_for_aad_change` for the affected row(s),
  supplying the *original* column values as the `old_aad_columns`
  context — typically requires an audit log or backup that captured
  the previous values.

Without one of those, the ciphertext is intact but the binding is
lost, and the plaintext is not recoverable from the package.
