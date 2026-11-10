# django-tenants Integration

This page covers everything specific to using this package with
[django-tenants](https://django-tenants.readthedocs.io/).

---

## Schema placement

django-tenants splits your apps in two: `SHARED_APPS` are created once, in the
`public` schema, and `TENANT_APPS` are created in every tenant's schema. Your
encrypted models go in `TENANT_APPS` — that is what you came to django-tenants
for. Where `encryption_suite` goes is a separate choice, and it settles one
question: **who can administer whose keys.**

Put it in `TENANT_APPS` alongside the data it protects:

```python
SHARED_APPS = [
    "django_tenants",
    "yourapp.tenants",            # your Tenant + Domain models
    "django.contrib.contenttypes",
]

TENANT_APPS = [
    "django.contrib.contenttypes",
    "django.contrib.auth",        # users per tenant
    "encryption_suite",           # key records per tenant
    "yourapp",                    # your encrypted models
]

INSTALLED_APPS = list(SHARED_APPS) + [app for app in TENANT_APPS if app not in SHARED_APPS]
```

Each tenant then owns its data keys, key encryption keys and lifecycle ledger,
in the same schema as the rows they protect. An administrator working in `acme`
can reach `acme`'s keys and nothing else, because that is all their connection
resolves.

### Match it to where your users live

The package's key changelists show every row they can see — nothing filters them
by tenant, and nothing can, since a key row's silo UID is not a tenant the admin
knows how to scope to. So the schema is the boundary, and the placement has to
agree with `django.contrib.auth`:

| `django.contrib.auth` | `encryption_suite` | What an administrator can act on |
|---|---|---|
| `TENANT_APPS` | `TENANT_APPS` | Their own tenant's keys. **The usual choice.** |
| `TENANT_APPS` | `SHARED_APPS` | Every tenant's keys, from any tenant's admin. **Don't.** |
| `SHARED_APPS` | `TENANT_APPS` | Every tenant's keys, one tenant at a time — and no tenant's key records sit in a table another tenant shares. |
| `SHARED_APPS` | `SHARED_APPS` | Every tenant's keys, in one list. Simplest to operate; see below. |

The second row is the one to avoid: per-tenant staff with a shared key table
means anyone holding the key permissions in their own tenant can schedule or
delete another tenant's keys. Nothing in the package stops them, because from
the database's point of view they are looking at their own rows.

### Choosing `SHARED_APPS`

One group of operators running keys for the whole deployment — a platform team,
not the tenants themselves — is what the shared placement is for. It requires
shared users, and it buys back the questions that span tenants:

```python
SHARED_APPS = [
    "django_tenants",
    "yourapp.tenants",
    "django.contrib.contenttypes",
    "django.contrib.auth",        # one user table for the deployment
    "encryption_suite",           # one set of key tables
]

TENANT_APPS = [
    "django.contrib.contenttypes",
    "yourapp",                    # encrypted data stays per-tenant
]
```

The package's tables are then in `public`, and django-tenants' tenant-then-public
search path resolves them from inside any tenant with no routing code. One
reconcile pass covers every tenant, one changelist lists every key, the key
encryption key deletion gate sees every row that might still depend on a key,
and `SILO_AUTO_KEY_CREATION` works (its `post_save` fires in `public`, which is
now the right schema).

Two things are worth being clear-eyed about before choosing it. Every tenant's
key records — including who acted on them, and when — share one table, and every
operator who can open the changelist sees all of them. And it is only defensible
while users are shared: if you later move `django.contrib.auth` into
`TENANT_APPS`, you have to move `encryption_suite` with it.

What sits in `public` is each tenant's data key wrapped by that tenant's own key
encryption key, which is useless without the KMS. That bounds the exposure. It
does not remove it.

### Cost of `TENANT_APPS`

Per-tenant key tables mean a connection sees one tenant's rows at a time, so
three things become per-schema operations rather than one:

- **Reconcile runs per tenant.** It enumerates silos from the tenant table in
  `public` but reads key rows through the current connection, so a pass run from
  one schema reports every other tenant's keys as missing. Run it per schema and
  read each run as being about that tenant.
- **`SILO_AUTO_KEY_CREATION` is unavailable.** Creating a tenant happens in
  `public`, so its `post_save` fires in the wrong schema for a per-tenant key
  table. Leave `KEY_AUTO_PROVISION` at its default and each tenant's keys are
  created on its first encrypt — which is also when its KEK is provisioned.
- **`setup_encryption_keys` runs per tenant**, through django-tenants' wrapper:
  `python manage.py tenant_command setup_encryption_keys --schema=acme`.

One thing is not merely operational. The key encryption key deletion gate can
only see the schema it runs in, so it is safe when each silo owns its KEK — as
`PerSiloKekStrategy` with a `{silo_uid}` template gives you — and unsafe under a
strategy that shares one KEK across tenants, where another schema's data can
still depend on the key being destroyed. Do not combine a shared KEK with
`TENANT_APPS`.

Placement changes none of this: configuration is process-wide either way, and a
`KEK_TEMPLATE` interpolating `{silo_uid}` gives each tenant its own KMS key
under both.

---

## Basic setup (tenant-level encryption)

Each tenant gets one KEK and one encryption keyset. All encrypted fields for
that tenant are encrypted under the same key.

```python
# settings.py
ENCRYPTION = {
    "KEY_SETS": {"default": {"silo": "encryption_suite.adapters.silos.tenants.DjangoTenantsSiloAdapter", "key_store": "main"}},
    "KMS_KEY_STORES": {
        "main": {
            "ADAPTER": "encryption_suite.adapters.key_stores.gcp.GcpKmsAdapter",
            "OPTIONS": {
                "GCP_PROJECT_ID":   "my-project",
                "GCP_KMS_LOCATION": "global",
                "GCP_KMS_KEY_RING": "my-key-ring",
                "KEK_TEMPLATE":     "encryption_suite-{silo_uid}",  # one key per tenant
            },
            "KEK_STRATEGY_ADAPTER": "encryption_suite.adapters.keks.PerSiloKekStrategy",
        },
    },
}
```

No custom middleware is needed — `DjangoTenantsSiloAdapter` reads the
current tenant directly from `connection.tenant`, which the django-tenants
middleware sets automatically.

### Key provisioning

`KEY_AUTO_PROVISION` defaults to `True`, so the first encrypt inside a tenant's
request creates that tenant's keyset (and provisions its KEK). No bootstrap step is
needed. To create keys up front instead — to avoid first-request latency —
`python manage.py setup_encryption_keys` creates any that are missing — once per
tenant under `TENANT_APPS` (`tenant_command setup_encryption_keys
--schema=acme`), or in one pass under `SHARED_APPS`. With shared key tables you
can also set `SILO_AUTO_KEY_CREATION` on your tenant model, which creates a
tenant's keys as the tenant is created; it does not work with per-tenant key
tables, for the reason given under [Schema placement](#schema-placement).

### Rotating a tenant's data key

`DjangoTenantsSiloAdapter` supports [`reencrypt_data`](management-commands.md#reencrypt_data)
without configuration. A tenant's rows carry no column naming the tenant, so the
adapter answers the rotation's lookup itself — every row of the model in the
tenant's schema — and enters that schema around each tenant's work. The rotation
reads and rewrites data in the tenant's schema and records its progress and
ledger rows in the package's tables, wherever the placement above puts them, in
one transaction on one database.

### Rotating a cell's data key

`DjangoTenantsCompositeSiloAdapter` enters the schema too, but does not answer
the lookup: with cell encryption on, the silo is a cell, and a tenant's schema
holds every cell's rows. Until a deployment says which rows belong to which
cell, `manage.py check` reports `encryption_suite.W053` and `reencrypt_data`
refuses, before any fence goes up — rotating blind would swap the key while
unmatched rows stayed on the old one, and the swap destroys the old material.

Saying so takes two things.

**Record the cell on the row.** The cell is ambient: your middleware puts it in
a context variable and the engine reads it from there to choose the key. Nothing
writes it down, so add a column and populate it where the row is saved:

```python
class Secret(models.Model):
    department = models.ForeignKey(
        "yourapp.Department", on_delete=models.PROTECT, null=True, blank=True
    )
    notes = EncryptedTextField(null=True, blank=True)


class SecretForm(EncryptionModelForm):
    class Meta:
        model = Secret
        fields = ["notes"]

    def save(self, commit=True):
        from encryption_suite.adapters.silos.composite import get_current_cell

        secret = super().save(commit=False)
        secret.department = get_current_cell()
        if commit:
            secret.save()
        return secret
```

**Implement [`queryset_for_silo()`](silo-adapters.md#finding-a-silos-rows)** in a
subclass, and point `KEY_SETS` at it. `get_cell_uid()` builds
`tenant-<schema>-cell-<pk>`, so the cell's pk is the part after the last
`-cell-`; a UID without one is the tenant itself, meaning the rows that belong
to no cell:

```python
# yourapp/silo.py
from encryption_suite.adapters.silos.composite import DjangoTenantsCompositeSiloAdapter


class MyCompositeSiloAdapter(DjangoTenantsCompositeSiloAdapter):
    supports_silo_data_lookup = True

    def queryset_for_silo(self, model, silo_uid):
        # use_silo() has already entered the tenant's schema, so this filter
        # only has to separate the cells within it.
        rows = model._base_manager.all()
        if "-cell-" not in silo_uid:
            return rows.filter(department__isnull=True)
        return rows.filter(department_id=int(silo_uid.rsplit("-cell-", 1)[1]))
```

`reencrypt_data --silo-uid tenant-acme-cell-1` then rotates that cell alone:
every other cell in the same schema keeps its ciphertext and its key version.

> **Rows saved before you added the column have no cell**, so the lookup cannot
> see them and a rotation would leave them on a key that no longer exists.
> Backfill the column before the first rotation. Doing so is safe as long as the
> column is not listed in any field's `aad=` — it records a fact
> about the row rather than changing what decrypts it.

---

## Editing encrypted data

The Django admin **cannot create or edit encrypted fields** — `EncryptionAdminMixin`
excludes them by design (the admin renders rows outside a single silo context).
Edit encrypted data through a per-silo frontend instead; the django-tenants
`TenantMainMiddleware` already sets the silo context for the request, so a normal
create/update view encrypts under the active tenant. See
[Silo adapters — Editing encrypted data](silo-adapters.md#editing-encrypted-data).

## Encrypted files: per-tenant isolation on object storage

`EncryptedFileField` stores encrypted files through the `"encrypted"` storage alias. On
a **filesystem** backend, django-tenants' `TenantFileSystemStorage` /
`MULTITENANT_RELATIVE_MEDIA_ROOT` (`%s` → `schema_name`) keep each tenant's files
in their own directory — but those are filesystem-only and **do not apply to
S3-compatible object storage** (django-storages `S3Boto3Storage`, etc.).

For object storage, two layers give you isolation:

1. **Cryptographic (automatic):** each tenant's files are encrypted under that
   tenant's own DEK, so another tenant cannot decrypt them even if the blobs
   share a bucket.
2. **Keyspace (recommended, project-side):** prefix the object key with the
   active schema so blobs are physically partitioned and can't collide:

   ```python
   from django.db import connection

   def tenant_encrypted_upload_to(instance, filename):
       schema = getattr(connection, "schema_name", "public")
       return f"{schema}/encryption_suite/{uuid.uuid4().hex}.bin"

   class Secret(models.Model):
       file = EncryptedFileField(upload_to=tenant_encrypted_upload_to,
                                 display_name_field="file_display_name", ...)
   ```

## Composite setup (mixed tenant/cell encryption)

Some tenants may require stronger isolation — different cells (sub-divisions)
within the same tenant each get their own KEK. Others use a single tenant-level
key. The composite adapter handles both.

### 1. Add a flag to your Tenant model

```python
# yourapp/models.py
from django_tenants.models import TenantMixin

class Client(TenantMixin):
    uses_cell_encryption = models.BooleanField(default=False)
    # ... your other fields
```

Migrate after adding this field.

### 2. Add a tenant FK to your cell model

The composite adapter uses `cell.tenant` to namespace cell UIDs. Your cell
model (e.g. a department) needs a FK back to the tenant:

```python
# yourapp/models.py
class Department(models.Model):
    name = models.CharField(max_length=100)
    tenant = models.ForeignKey(
        "yourapp.Client",
        on_delete=models.CASCADE,
        related_name="departments",
    )
```

### 3. Add cell-setting middleware

```python
# yourapp/middleware.py
from django.db import connection
from encryption_suite.adapters.silos.composite import (
    set_current_cell,
    clear_current_cell,
)

class CellEncryptionMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        tenant = connection.tenant
        if getattr(tenant, "uses_cell_encryption", False):
            set_current_cell(self._resolve_cell(request))
        try:
            return self.get_response(request)
        finally:
            clear_current_cell()

    def _resolve_cell(self, request):
        # your logic — e.g. from URL kwargs, request.user membership, etc.
        department_pk = request.resolver_match.kwargs.get("department_pk")
        if department_pk:
            return Department.objects.filter(pk=department_pk).first()
        return None
```

Add it to `MIDDLEWARE` after the django-tenants middleware:

```python
MIDDLEWARE = [
    "django_tenants.middleware.main.TenantMainMiddleware",
    # ...
    "yourapp.middleware.CellEncryptionMiddleware",
]
```

### 4. Configure the composite adapter

```python
ENCRYPTION = {
    "KEY_SETS": {"default": {"silo": "encryption_suite.adapters.silos.composite.DjangoTenantsCompositeSiloAdapter", "key_store": "main"}},
    "KMS_KEY_STORES": {
        "main": {
            "ADAPTER": "...",
            "OPTIONS": { ... },
            "KEK_STRATEGY_ADAPTER": "encryption_suite.adapters.keks.PerSiloKekStrategy",
        },
    },
}
```

### 5. Generate keys

For tenants without cell encryption, run the standard command:

```bash
python manage.py setup_encryption_keys
```

For cells within cell-encrypted tenants, you need to generate a key for each
cell explicitly. Use the `--silo-model` flag within a tenant schema
context:

```bash
# Using django-tenants' tenant_command wrapper:
python manage.py tenant_command setup_encryption_keys --silo-model yourapp.Department --schema=acme
```

Or write a management command that iterates over tenants and their cells using
`schema_context` from django-tenants.

---

## Silo UID structure

| Scenario | `silo_uid` example |
|---|---|
| Tenant-level key | `tenant-acme` |
| Cell-level key (composite) | `tenant-acme-cell-7` |

Cell UIDs are namespaced under the tenant schema name. This ensures UIDs are
globally unique even if two tenants both have a cell with `pk=7`.

---

## Behavior when no cell is active (composite mode)

If a tenant has `uses_cell_encryption=True` but `CellEncryptionMiddleware`
did not set a cell (e.g. the request has no department context), the composite
adapter raises `EncryptionConfigurationError` (slug `configuration_error`)
immediately rather than silently falling back to tenant-level encryption. This is intentional — silent fallback would encrypt
data under the wrong key if middleware is misconfigured.

To handle unauthenticated or non-department requests on a cell-encrypted
tenant, either set a default cell in middleware or check `uses_cell_encryption`
before accessing encrypted fields in views.
