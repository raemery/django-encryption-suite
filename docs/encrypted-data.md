# Encrypted data

django-encryption-suite encrypts two kinds of data: **model field values**
(strings, dates, integers — stored in database columns) and **uploaded
files** (bytes — stored in a storage backend). You configure both in
the same project, often on the same model. This page covers both.

Assumes you have already completed [Getting started](getting-started.md).

## One package, two paths

| | Fields | Files |
|---|---|---|
| What's encrypted | Python values (str, date, int, ...) | Raw file bytes |
| Where stored | Database column | Storage backend (S3, disk, ...) |
| Django mechanism | `pre_save` encrypts; the field's descriptor decrypts on attribute access | Storage protocol (`_save` / `_open`) |
| Primitive | AEAD | Streaming AEAD |
| DEK purpose | `PURPOSE_FIELD` | `PURPOSE_FILE` |

The two paths share the same silo, the same KMS, and the same
`DataEncryptionKey` table — but they use different DEK rows and
different primitives, so a field ciphertext can never be decrypted
as a file and vice versa.

You can freely mix both on one model:

```python
from django.db import models
from encryption_suite.fields import EncryptedCharField, EncryptedDateField, EncryptedFileField

class Patient(models.Model):
    team = models.ForeignKey('teams.Team', on_delete=models.CASCADE)
    first_name = EncryptedCharField(max_length=100)                  # field
    date_of_birth = EncryptedDateField(null=True, blank=True)        # field
    scan = EncryptedFileField(                                       # file
        display_name_field='scan_name', null=True, blank=True
    )
    scan_name = EncryptedCharField(max_length=255, null=True, blank=True)
```

> **Binding data within a silo:** each silo has its own DEK, so a row moved to
> another silo already fails to decrypt. To tie encrypted data to something
> *inside* a silo — the user who owns it, or the parent record it belongs to —
> pass those columns to each encrypted field's `aad=`, e.g.
> `aad=("owner",)`. If one of them is changed, for example to hand a record to
> another user on the same team, its encrypted fields fail to decrypt instead
> of reading as the new owner's. See
> [Row-identity binding](security.md#row-identity-binding-optional).

## Silo context

Every encrypt and decrypt — field or file — needs to know **which
silo** the row belongs to so the engine can look up the right
DEK. The adapter reads this from a context variable that your
middleware sets per request:

```python
set_current_silo(request.team)
# ... field reads/writes and file uploads/downloads during this request
#     all use request.team's DEKs
clear_current_silo()
```

### Outside a request

Anywhere silo context is not set — management commands, Celery
tasks, migrations, shell scripts — set it yourself before touching an
encrypted field or opening an encrypted file:

```python
from encryption_suite.adapters.silos.context import (
    set_current_silo,
    clear_current_silo,
)

set_current_silo(team)
try:
    patient = Patient.objects.get(pk=pk, team=team)
    patient.first_name = 'Jane'
    patient.save()
    patient.scan.open().read()
finally:
    clear_current_silo()
```

Without silo context the engine never picks a key. A write raises
`EncryptionConfigurationError`, a file open raises it too, and a read degrades
to the fallback value in lenient mode (or raises in strict mode), with the
cause logged.

---

## Encrypted fields

### Field catalog

```python
from encryption_suite.fields import (
    EncryptedCharField,
    EncryptedTextField,
    EncryptedEmailField,
    EncryptedURLField,
    EncryptedIntegerField,
    EncryptedDateField,
    EncryptedDateTimeField,
    EncryptedJSONField,
)
```

| Field | Django equivalent | Notes |
|---|---|---|
| `EncryptedCharField` | `CharField` | `max_length` applies to plaintext |
| `EncryptedTextField` | `TextField` | Arbitrary-length |
| `EncryptedEmailField` | `EmailField` | Validates email before encrypting |
| `EncryptedURLField` | `URLField` | |
| `EncryptedIntegerField` | `IntegerField` | Stored as encrypted decimal string |
| `EncryptedDateField` | `DateField` | ISO 8601 internally |
| `EncryptedDateTimeField` | `DateTimeField` | Timezone-aware, ISO 8601 |
| `EncryptedJSONField` | `JSONField` | Stored as encrypted JSON text; nothing can query inside it |

All encrypted fields are backed by the database's text column type regardless
of the underlying type. On read they return **native Python types** — your
templates, forms, and serializers don't need to know the field is
encrypted.

Two things are particular to `EncryptedJSONField`. The column is text rather than
the database's own JSON type, so `filter(data__key=...)` and anything else that
reaches inside the value cannot work — where parts of a payload are queried,
encrypt those parts as columns of their own instead. And a failed lenient read
gives back an **empty dict** rather than the fallback sentinel, because callers
read the field as a mapping; such a read is recognised through
`instance.encryption_suite_errors` rather than by looking at the value.

For the same field types under a key that belongs to the deployment rather than to
a silo, see [system-wide silos](system-wide-silos.md).

```python
patient = Patient.objects.create(
    first_name='Jane',
    date_of_birth=date(1990, 3, 15),
)
patient.refresh_from_db()
patient.first_name          # 'Jane'
patient.date_of_birth       # datetime.date(1990, 3, 15)
type(patient.date_of_birth) # <class 'datetime.date'>
```

The only differences from their plaintext equivalents:

- **No database filtering, unless the column declares a blind index.**
  `filter(first_name='Jane')` won't work — the column holds ciphertext. A
  field declaring `blind_index=True` also stores a keyed digest of its value,
  which answers `exact`, `iexact` and `in`, and nothing else; see
  [Finding a row by its value](#finding-a-row-by-its-value). Sort and range
  on plaintext columns only.
- **Larger rows.** Ciphertext is longer than plaintext, and every
  encrypted field uses a text column.
- **Optional fields must be nullable.** An encrypted column holds ciphertext,
  and "no value" has none — the empty string is not something the engine can
  encrypt and read back. Django reaches for `""` whenever a `blank=True` column
  is not nullable, both as the form's empty value and as the default a
  migration adds the column with, so pair `blank=True` with `null=True` on
  every optional encrypted field. System check
  [`E025`](configuration.md#system-checks) reports the pair that is missing
  `null=True`.
- **A value cannot have the shape of stored ciphertext.** Every stored value
  starts with `~^Dv`, a version number and a colon (`~^Dv1:` today), and the
  field writes back unchanged only such a value it read from the database. A
  save of any other value with that shape — usually ciphertext copied from
  another row — is refused with `FieldAlreadyEncryptedError`, whose message is
  "Encryption failed." Reading such a value off an unsaved instance returns it
  as it stands; it is never decrypted. A value that merely starts with `~^D`,
  such as `~^D hello`, is ordinary plaintext and is encrypted like any other.

### Supported databases

Encrypted fields store ciphertext in the database's text column type per django's database implmentations: `text`
on PostgreSQL and SQLite, `LONGTEXT` on MySQL and MariaDB, and `NCLOB` on
Oracle.

#### `varchar_column=True`, for a column somebody else indexes

One exception, and it is not about anything this package does: MySQL and Oracle
refuse an index containing a text column, and fail the migration that adds one.
If another package's `Meta` declares an index or a uniqueness rule over a column
you have encrypted — and you cannot edit that `Meta` — the column has to be a
bounded `varchar` for their declaration to be legal at all.

```python
email = EncryptedEmailField(key_set="system", max_length=254, varchar_column=True)
```

The width is computed, never declared: the marker plus headroom for any crypto
backend's per-value overhead, then base64 of the nonce, the ciphertext and the
tag. A `max_length=254` field becomes
`varchar(399)`.

Two things change about that field:

- **`max_length` counts bytes, not characters**, because the stored width follows
  the plaintext's encoded length — a character outside ASCII costs up to four of
  them. A value whose UTF-8 encoding is longer than `max_length` is refused by
  the field, with a message naming both numbers, rather than truncated by the
  database.
- **A `max_length` too large to be indexed anywhere is refused at deploy** by
  [`E028`](configuration.md#system-checks), which names the `max_length` that
  would have fitted. An index key on the strictest backend runs to 3072 bytes at
  4 bytes a character, so the ceiling is a stored width of 766.

Their declaration becomes *legal*; it does not become *useful*. Every write
stores a different value, so a uniqueness rule over the column still cannot
fire. [`W056`](configuration.md#system-checks), which reports such a rule
everywhere else, stays quiet about one that names only `varchar_column=True`
columns: the rule is not yours to change, so there is nothing left to act on.

So: `varchar_column=True` ensures every database can apply the migration, but
only if the stored width is not too long — which the system check catches.

Because the column holds ciphertext, no database can index it, enforce
uniqueness on it, or filter or sort by its value. A
[blind index](#finding-a-row-by-its-value) puts a keyed digest of the value
somewhere a database *can* index, which buys exact matching and per-silo
uniqueness — over the digest, never over the column. Sorting and ranges have no
equivalent at all. What reads `field.unique` and no longer finds it is listed
under [Code that reads `unique`](#code-that-reads-unique).

### Finding a row by its value

Ciphertext gets a fresh nonce every time, so two writes of one value look
nothing alike and the database cannot compare them. A field declaring
`blind_index=True` stores a keyed digest of its value as well, and `exact`,
`iexact` and `in` are rewritten to compare that:

```python
class Member(BaseTeamModel):
    handle = EncryptedCharField(max_length=150, blind_index=True, normalize="casefold")

Member.for_team.get(handle="ANN")      # found, case-insensitively
Member.for_team.filter(handle__contains="nn")   # FieldError
```

Every other lookup is refused rather than answered with no rows. A `contains`
that quietly returned nothing reads as "no such member", which is the answer
that hides a bug.

`normalize="casefold"` indexes and matches the case-folded value, which is what an
email address or a username wants. Without it, matching is case-sensitive and
`__iexact` is refused, because an index built on the value as given cannot answer
a case-insensitive question. `isnull` needs no index.

**How is a blind index different from a regular index?** Both let you search an
exact value and find any matches. A blind index is an index of hashed values,
which is why we call it blind. It doesn't let you sort, order, or filter on a
range the way you can with a regular index. A declaration that tries to —
`Meta.ordering`, or a `ModelAdmin.ordering` — is reported by
[`W055`](configuration.md#system-checks).

The digest is computed under the silo's **own** index key, a third
`DataEncryptionKey` purpose beside field and file. Three things follow from
that:

- **Destroying the silo's KEK destroys its digests** along with its data,
  instead of leaving rows that can still be matched.
- **A reader of the database cannot test a guess**, because computing a digest
  needs a key only the KMS can unwrap.
- **Two silos holding one value index differently**, so neither silo's rows can
  be matched against the other's. The unlinkability is in the key, so nothing
  depends on a silo's identifier being stable.

The cost is that a lookup needs the silo's key, and so the KMS, once per
[`DEK_CACHE_TTL`](configuration.md#dek_cache_ttl). Nothing in a silo is readable
without a data key, so that is no new dependency — but a key scheduled for
deletion blocks a lookup exactly as it blocks an encrypt, and a
[re-index](key-rotation.md) fences lookups while it runs. The key is provisioned
on first use, or by `setup_encryption_keys`, and only where a field asks for one.

Declaring the index on a column that already holds rows takes one step more than
the conversion: the migration helper writes the value and not the digest, so the
digests are built afterwards and
[`reencrypt_data --purpose index --check`](management-commands.md#reporting-digests-that-were-never-built)
reports any still missing. See [Adopting and removing
encryption](adopting-and-removing-encryption.md#5-build-the-blind-index-digests--management-commands).

#### Leaked information

A blind index gives away equality within a silo. Rows holding the same value are recognizable to anyone
reading the table, common values show up as frequent digests, and a value known
from elsewhere locates every row holding it. For an address or an account name,
where almost every value appears once, that costs little. For a date, a postal
code or a small integer range it gives away most of what encrypting the column
was for — so declare the index only where a lookup genuinely needs it. A column
with no index is still encrypted; it just cannot be searched.

A digest is not bound into the value's associated data. A digest edited in the
database therefore does not stop its row being read; it makes the row answer to a
value it does not hold, which is found by recomputing digests from the plaintext
rather than by a failed read.

#### Uniqueness, per silo

```python
handle = EncryptedCharField(max_length=150, blind_index=True, unique_in_silo=True)
```

Spelled for what it enforces. The digest is computed under the silo's own key, so
a constraint over the digest holds a value unique *within* a silo and says nothing
across them — two silos may each hold one address and both are valid. Django's
`unique` promises the whole table, which no rule on this column could deliver, so
writing it is reported by [`E026`](configuration.md#system-checks) rather than
read as the same thing.

A duplicate inside one silo is a `ValidationError` keyed on the field, through
`full_clean` and so through a ModelForm, carrying Django's own translated
message. The residual edge is the one plain `unique=True` has: a concurrent
insert between validation and commit still surfaces as `IntegrityError`.

#### Code that reads `unique`

A uniqueness rule applies to the digest, so the field reports `field.unique` as
`False`, under `unique_in_silo=True` and under `unique=True` on a
[`key_set="system"` column](system-wide-silos.md#looking-a-value-up) alike. It
has to, or the database would get a request for a unique index over a text
column, which MySQL and Oracle reject outright. The guarantee is there; Django
just does not look for it in that place. `index_unique` is the attribute that
answers "is this column's plaintext held unique", for your own code and for
anything else that needs to ask.

Four things read the flag, and each gets a different answer:

| Reader | What happens |
|---|---|
| `full_clean()` and a ModelForm | Answered. The package runs the check Django would have run, against the digest, and raises the same translated `"… with this … already exists."` keyed on the field — so a form renders it beside the input, and an `error_messages={"unique": ...}` override still applies. |
| A DRF `ModelSerializer` | Answered, by [`EncryptionSerializerMixin`](working-with-django-rest-framework.md#uniqueness). Mix it in and a duplicate is a 400 naming the field rather than an `IntegrityError`. Without the mixin, an API write skips the check that an ORM or form write gets. |
| `auth.W004`, for an encrypted `USERNAME_FIELD` | Not answerable, and true as stated: the column is not unique, a constraint over its digest is. Add `SILENCED_SYSTEM_CHECKS = ["auth.W004"]`. |
| `ForeignKey(to_field=...)` | Refused, correctly. A foreign key cannot point at a column whose every write differs. |

`db_index=True` needs nothing beyond [its own check](configuration.md#system-checks):
nothing in Django branches on that flag, it only emits DDL, and the digest column
carries the index.

#### Digest storage

```python
handle = EncryptedCharField(max_length=150, blind_index=True, blind_index_storage="table")
```

| | `column` (default) | `table` |
|---|---|---|
| Where | a companion column on the model's own table | a row in the package's `BlindIndexEntry` |
| Writes | the same statement as the value | a second statement, in the same transaction |
| Deletes | the row delete takes it | a signal removes it, which costs Django's fast-delete path |
| Needs | a column in the model's app | nothing from the model at all |

The axis is **reach against integrity and cost**, not capability: both answer the
same lookups, enforce the same uniqueness, and disclose the same equality. Prefer
`column` — one table, no join, the digest written and deleted by the database
alongside the value. Reach for `table` when the model belongs to a package you
cannot change, because a companion column would need a migration inside that
package's app. Reaching another package's column also needs that package to let
you name the field class, usually through a setting it reads; without that hook
the column cannot be encrypted at all, whichever storage would have held its
digest.

### Binding a value to its row

By default, encrypted values are isolated only by the per-silo DEK: a value
encrypted under team A's key cannot be decrypted under team B's key, but
ciphertext can be moved between rows *within* the same silo without
detection. To bind a value to the row it lives on, pass `aad=` to the field:

```python
class MedicalRecord(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    person = models.ForeignKey(Person, on_delete=models.CASCADE)
    notes = EncryptedTextField(aad=("pk", "person"))
    diagnosis = EncryptedTextField(aad=("pk", "person"))
```

The field binds its ciphertext to the listed columns via Additional
Authenticated Data (AAD). Changing a listed column on an existing row makes
the field fail to decrypt on the next read. Each field declares its own
binding, so two fields on one model may bind different columns; an
`EncryptedFileField` and its `display_name_field` each take their own `aad=`
too. Names follow Django conventions: `"pk"` is canonical for the primary key,
and a foreign key may be named by the field (`"person"`) or its attname
(`"person_id"`). Both resolve to the raw column on this row, never traversing
the relationship.

The AAD is the field's `app.Model.field` label followed by each bound column
and its value, with every element length-prefixed so that no value can move a
boundary. Each value passes through its field's `to_python` first, so a UUID
assigned as a hex string binds the same as a `UUID`.

`aad=` is recorded in migrations like any other field option. Changing it
generates an `AlterField` migration, and that migration must be paired with a
data migration that calls
[`reencrypt_for_aad_change`](adopting-and-removing-encryption.md#changing-a-fields-aad-binding):
the stored values were written under the old binding, and none of them decrypt
under the new one until they are re-encrypted.

Field AAD is distinct from the AAD passed to the KMS when wrapping the DEK;
see [Field AAD vs KMS AAD](security.md#field-aad-vs-kms-aad).

| Identifier | Layer | Where it's used | Effect of changing |
|---|---|---|---|
| Columns listed in a field's `aad=` | Field | Bound into that field's value on each row | Existing rows will not decrypt; call the [`reencrypt_for_aad_change`](adopting-and-removing-encryption.md) migration helper from a data migration |
| Silo UID | Wrap | Bound into every wrapped DEK on KMS adapters that support AAD (most do) | Existing wrapped DEKs cannot be unwrapped — every encrypted field and file under that silo becomes unreadable |

Limitations:

- `QuerySet.values()` and `values_list()` return the stored ciphertext on
  every model with encrypted fields, because decryption happens when an
  instance's attribute is read. Iterate the queryset to get instances, or read
  `instance.field` after a normal load.
- `QuerySet.update(...)` and `bulk_update(...)` skip `pre_save`. The field
  refuses a plaintext value written to an encrypted column this way, and an
  update to an AAD-bound column leaves the row's encrypted values bound to the
  old value, so they no longer decrypt. Save changes through `instance.save()`
  instead.
- The primary key must be known at insert time when `"pk"` is listed. Use a
  client-assigned primary key (for example a `UUIDField` with
  `primary_key=True`); an auto-incrementing one is reported by system check
  [`E021`](configuration.md#system-checks).

See [Row-identity binding](security.md#row-identity-binding-optional) for
what this does and does not protect against.

### Processing pattern: Encrypted fields vs fields

Switching from a plaintext field to an encrypted field keeps the same
Django form/view/template shape. The differences are in the model
declaration, what is stored in the database, and what you can and cannot
do at the query layer.

- Forms, `ModelForm`, and `EncryptionModelForm` work identically on the
  outside; no template changes are required for normal reads.
- Encrypted field values are stored as ciphertext. Filter and order only
  on plaintext columns.
- `EncryptionModelForm` (in place of `ModelForm`) prevents a lenient-mode
  decrypt failure from overwriting ciphertext with a fallback string on save.

#### Baseline: unencrypted field flow

```python
# models.py
from django.db import models


class Record(models.Model):
    notes = models.TextField(blank=True)
```

```python
# forms.py
from django import forms

from .models import Record


class RecordForm(forms.ModelForm):
    class Meta:
        model = Record
        fields = ['notes']
```

```python
# views.py
from django.shortcuts import get_object_or_404, redirect, render

from .forms import RecordForm
from .models import Record


def create_record(request):
    form = RecordForm(request.POST or None)
    if form.is_valid():
        form.save()
        return redirect('record_list')
    return render(request, 'records/form.html', {'form': form})
```

```html
<!-- templates/records/detail.html -->
<p>{{ object.notes }}</p>
```

#### Encrypted field flow

```python
# models.py
from django.db import models
from encryption_suite.fields import EncryptedTextField


class Record(models.Model):
    notes = EncryptedTextField(blank=True, null=True)
```

```python
# forms.py
from django import forms
from encryption_suite import EncryptionModelForm

from .models import Record


class RecordForm(EncryptionModelForm):
    class Meta:
        model = Record
        fields = ['notes']
```

```python
# views.py — identical to the unencrypted version
from django.shortcuts import get_object_or_404, redirect, render

from .forms import RecordForm
from .models import Record


def create_record(request):
    form = RecordForm(request.POST or None)
    if form.is_valid():
        form.save()
        return redirect('record_list')
    return render(request, 'records/form.html', {'form': form})
```

The view is identical to the unencrypted version because encryption happens
transparently in `pre_save`. That same `pre_save` reaches the KMS, though, so
the save can fail — see
[Handling encryption errors on save](#handling-encryption-errors-on-save)
below for the error-handling variant.

In templates, successful decryption renders the value as normal. To
handle a decrypt failure explicitly, branch on `encryption_suite_errors`:

```html
<!-- templates/records/detail.html -->
{% if object.encryption_suite_errors.notes %}
  <p class="error">Unable to decrypt notes.</p>
{% else %}
  <p>{{ object.notes }}</p>
{% endif %}
```

### Handling encryption errors on save

Saving a model with encrypted fields encrypts them in `pre_save`, which can
reach the KMS. So a save can raise `EncryptionError` when the key is not
provisioned or the KMS is unavailable (`KekNotProvisionedError`,
`KekUnavailableError`), when the value starts with the ciphertext marker
(`FieldAlreadyEncryptedError`), or — rarely — when the encrypt operation itself fails
(`EncryptedFieldEncryptionError` for a field, `EncryptedFileEncryptionError` for
a file). This is **not** specific to files: a plain `EncryptedCharField` /
`EncryptedTextField` save can raise the field variant just as a file save can
raise the file variant. It is the write-side counterpart to the lenient/strict
read behavior below.

Catch the base `EncryptionError` around the save and surface it inline:

```python
from encryption_suite.exceptions import EncryptionError

def create_record(request):
    form = RecordForm(request.POST or None)
    if form.is_valid():
        try:
            form.save()
        except EncryptionError as exc:
            form.add_error(None, str(exc))  # already translated and user-safe
        else:
            return redirect('record_list')
    return render(request, 'records/form.html', {'form': form})
```

[Handling save / encryption failures](serving-encrypted-files.md#handling-save--encryption-failures)
covers the single-handler rationale, saves that trigger key provisioning (e.g.
creating a team or the first write for a new tenant), customizing the message,
and configuration errors such as a missing silo context or a KEK
misconfiguration.

### Decryption modes: lenient vs. strict

When reading an encrypted field fails, the field behaves one of two ways.
There is **no project-wide setting** for this — the mode is resolved per read,
in this order:

1. **Per-field `decrypt_mode="strict"`** — declared on the field, e.g.
   `notes = EncryptedTextField(decrypt_mode="strict")`. That field always
   raises on a failed read.
2. **`strict_mode()` context manager** — escalates *every* decrypt inside a
   `with` block to strict, regardless of per-field declarations. It is a
   runtime scope (a `ContextVar`, propagating across `sync_to_async`), **not**
   a Django setting. Use it around code that must not silently degrade —
   serializers, exports, background jobs:

   ```python
   from encryption_suite import strict_mode

   with strict_mode():
       data = RecordSerializer(instance).data
   ```

   Over a Django REST Framework API, a strict read fails the whole response,
   where a lenient read with `EncryptionSerializerMixin` returns the good fields
   and rows and marks the failed ones. See
   [Strict reads](working-with-django-rest-framework.md#strict-reads).
3. **Lenient** — the default when neither of the above applies.

Each mode handles a failed read as follows:

- **Lenient (default):** returns an `UndecryptableValue` sentinel that
  stringifies to a translatable fallback label (override per field with
  `fallback_label=`), and records the cause in `object.encryption_suite_errors[
  <field>]`. The read never raises, so a template renders the fallback instead
  of 500-ing. This degradation applies to **any** `EncryptionError` — not
  only ciphertext rejection (`EncryptedFieldDecryptionError`) but also a
  missing DEK (`MissingDekError`) or an unavailable key encryption key
  (`KekUnavailableError`, e.g. an expired Vault token).
- **Strict:** re-raises the underlying `EncryptionError`, for paths that must
  hard-fail rather than continue with a sentinel. Catch it with
  `except EncryptionError` (see
  [serving encrypted files](serving-encrypted-files.md#handling-save--encryption-failures)).

`decrypt_mode` and `strict_mode()` apply to encrypted **value** fields
(`EncryptedCharField`, `EncryptedTextField`, `EncryptedIntegerField`, …). They
do **not** apply to `EncryptedFileField` content — see
[decrypt mode for file content](serving-encrypted-files.md#decrypt-mode-for-file-content)
for how file decryption failures are handled instead.

#### A model's `__str__`

A `__str__` that returns an encrypted field works as written:
`def __str__(self): return self.name` gives the plaintext whenever the
read succeeds. Python requires `__str__` to return a `str`, and Django
calls `str(obj)` in places your code cannot intercept, such as the admin's
page titles, its history log, and the list of rows a delete will cascade
to. So the package wraps `__str__` on every model with an encrypted field,
and the wrapper returns Django's default `<Model> object (<pk>)` instead
in three cases:

- **No silo in the current context.** The `__str__` reads a field whose key
  set has no current silo, as in the site-wide admin or a task that never set
  its context. The wrapper refuses the read before it decrypts, and the
  package logs one WARNING line that names the field, so the missing context
  leaves a trace; see
  [Logging](logging.md#a-models-__str__-with-no-silo-warning). A field declared
  with `decrypt_mode="strict"` gets the label too, because nothing reads its
  value.
- **A failed lenient read.** The read returned the `UndecryptableValue`
  sentinel, and has logged its error. A strict read raises as usual.
- **An instance `EncryptionAdminMixin` loaded.** The wrapper refuses every
  encrypted read, so the admin never decrypts through `__str__`. See
  [the mixin](admin-panel.md#the-mixin).

In every other case the wrapper returns what your `__str__` returns.

Inside `strict_mode()`, the first case does not apply. A read with no silo in
context goes on to fail the way a strict read does: the engine logs its
`No silo in the current context` ERROR line and raises
`EncryptionConfigurationError`, so `str(obj)` raises rather than returning a
label. Use `strict_mode()` around code whose output is the data, such as an
export, where a row written as `Patient object (12)` is a wrong result rather
than a display fallback; see [Strict mode](scheduled-tasks.md#strict-mode).
An instance the admin loaded still gets the label, because the admin never
decrypts. `strict_mode()` covers everything called inside its block, so a
project that wraps whole requests in it makes `str(obj)` raise on every page
that renders a row with no silo in context, including the admin's delete
confirmation.

#### Encrypted field flow with silo: Pegasus teams example

You may be using a silo that isolates data for a group of users.
This could be composite, custom, the built-in support for Pegasus teams, or the
optional simple team app.

When using Pegasus teams as the silo, each team has its own
encryption keys. The model, form, and template are the same as above.
Only the model's ownership field and the views differ.

Add a `team` foreign key to the model:

```python
# models.py — add team ownership
from django.db import models
from encryption_suite.fields import EncryptedTextField


class Record(models.Model):
    team = models.ForeignKey('teams.Team', on_delete=models.CASCADE)
    notes = EncryptedTextField(blank=True, null=True)
```

In views, use `@login_and_team_required` and scope all queries to
`request.team`. The team silo middleware sets the encryption
context for the request automatically.

```python
# views.py
from django.http import HttpResponseRedirect
from django.shortcuts import get_object_or_404, render
from django.urls import reverse

from apps.teams.decorators import login_and_team_required

from .forms import RecordForm
from .models import Record


@login_and_team_required
def create_record(request, team_slug: str):
    form = RecordForm(request.POST or None)
    if form.is_valid():
        instance = form.save(commit=False)
        instance.team = request.team
        instance.save()
        return HttpResponseRedirect(reverse('records:list', kwargs={'team_slug': team_slug}))
    return render(request, 'records/form.html', {'form': form})


@login_and_team_required
def record_detail(request, team_slug: str, pk):
    obj = get_object_or_404(Record, pk=pk, team=request.team)
    return render(request, 'records/detail.html', {'object': obj})
```

URLs for team-scoped views follow the `/a/<team_slug>/` prefix pattern:

```python
# urls.py
from django.urls import path

from . import views

team_urlpatterns = [
    path('records/new/', views.create_record, name='create'),
    path('records/<int:pk>/', views.record_detail, name='detail'),
]
```

#### Encrypted field flow with silo: simple team app example

The optional [`simpleteams` app](silo-adapters.md#simpleteamsiloadapter) gives a
project with no team model of its own the same per-team keys. The model, form
and template are again the same as above. Only the ownership field and the views
differ, because there is no `request.team` and no team in the URL: the
middleware sets the current team from the signed-in user's membership.

Point the model's `team` foreign key at `SimpleTeam`, with `PROTECT` so a team
deleted from under its rows cannot leave data nobody is meant to read:

```python
# models.py — add team ownership
from django.db import models
from encryption_suite.contrib.simpleteams.models import SimpleTeam
from encryption_suite.fields import EncryptedTextField


class Record(models.Model):
    team = models.ForeignKey(SimpleTeam, on_delete=models.PROTECT)
    notes = EncryptedTextField(blank=True, null=True)
```

In views, use `@login_required` and scope all queries to the user's team. A user
with no team gets a 404 here, and the middleware sets no encryption context for
them, so encrypted access fails rather than reading under another team's keys.

```python
# views.py
from django.contrib.auth.decorators import login_required
from django.http import HttpResponseRedirect
from django.shortcuts import get_object_or_404, render
from django.urls import reverse
from encryption_suite.contrib.simpleteams.models import SimpleTeamMembership

from .forms import RecordForm
from .models import Record


@login_required
def create_record(request):
    membership = get_object_or_404(SimpleTeamMembership, user=request.user)
    form = RecordForm(request.POST or None)
    if form.is_valid():
        instance = form.save(commit=False)
        instance.team = membership.team
        instance.save()
        return HttpResponseRedirect(reverse('records:list'))
    return render(request, 'records/form.html', {'form': form})


@login_required
def record_detail(request, pk):
    membership = get_object_or_404(SimpleTeamMembership, user=request.user)
    obj = get_object_or_404(Record, pk=pk, team=membership.team)
    return render(request, 'records/detail.html', {'object': obj})
```

The URLs carry no team prefix:

```python
# urls.py
from django.urls import path

from . import views

app_name = 'records'
urlpatterns = [
    path('records/new/', views.create_record, name='create'),
    path('records/<int:pk>/', views.record_detail, name='detail'),
]
```

Teams and their members are managed in the Django admin. See
[`SimpleTeamSiloAdapter`](silo-adapters.md#simpleteamsiloadapter) for the settings.

---

### Optional encrypted fields

An optional encrypted field must use `null=True`. Unlike stock Django
`CharField` and `FileField`, encrypted fields cannot store the empty string.
Django's migration system uses `""` as the default for a `blank=True` column
that is not nullable, and the encryption layer rejects that default at migrate
time. Always pair `blank=True` with `null=True`, including on the companion
display-name column of an `EncryptedFileField` and on the file field itself
when the file is optional.

---

### Adding a field to an existing model

**Nullable (simple).** When the field can tolerate `NULL`, this is the
recommended path:

```python
class Patient(models.Model):
    notes = EncryptedTextField(null=True, blank=True)
```

```bash
python manage.py makemigrations
python manage.py migrate
```

`ALTER TABLE ... ADD COLUMN notes text NULL` runs without a default, so
nothing is written to existing rows and no silo context is required. Existing
rows get `NULL`; new writes encrypt normally because they happen inside a
request.

Application code must handle `None` on read.

> `blank=True` controls Django form validation only. It does **not**
> make the column nullable. Use `null=True` for that.

**`NOT NULL` (two-phase backfill).** A `NOT NULL` column needs a default
for the rows already there, and the field refuses one: the default would reach
those rows as plaintext. Encrypting them needs silo context, which `migrate`
does not have. The safe pattern is three migrations: add nullable ->
backfill per silo -> alter to `NOT NULL`. See
[Adopting and removing encryption](adopting-and-removing-encryption.md#pattern-b-two-phase-backfill-required-for-not-null)
for the recipe.

---

## Encrypted files

File content goes through Django's storage layer rather than the field
protocol, so files have a field type of their own: `EncryptedFileField`. It
encrypts under the current silo's file key, or under the system silo's with
[`key_set="system"`](system-wide-silos.md#files). The file key is not the
silo's field key, and the two use different primitives. The
[two-paths table](#one-package-two-paths) above compares them.

[Encrypted file storage](encrypted-files.md) describes the design and links to
the guides for setup, backends, serving, and management.

---

## Related

- [Adopting and removing encryption](adopting-and-removing-encryption.md)
  — per-silo backfill skeletons, removing encryption
- [Core concepts](concepts.md) — DEKs, purposes, envelope encryption
- [Configuration reference](configuration.md) — `KEY_AUTO_PROVISION`,
  `DEK_CACHE_TTL`, `STORAGE_SPOOL_*`, `LOG_DECRYPTS`
- [Moving to production](production.md) — real KMS, deployment checklist
