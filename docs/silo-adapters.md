# Silo Adapters

A silo adapter serves the key sets bound to it in [`KEY_SETS`](configuration.md#key_sets).
The usual one is `default`: the groups of users your project defines, such as teams
or tenants. (The `system` key set is built in and has its own adapter, described
under [`SystemSiloAdapter`](#systemsiloadapter).) Key sets bound to one adapter
share its silos, and an operation that concerns a silo asks the adapter once. It
does two things in one class:

1. **Resolves** the current silo from ambient runtime state — answering
   "which tenant or team is active right now?" on every field read or write.
2. **Identifies** a silo object by producing a stable unique string
   (`silo_uid`) used to look up its encryption keyset.

It may *optionally* do a third: **enumerate** every live silo (answering "which
silos exist?"), used by `setup_encryption_keys` and KEK reconcile. This is an
opt-in capability — see [Enumerating silos](#enumerating-silos) below.

Bind it to a key set in `KEY_SETS`:

```python
ENCRYPTION = {
    "KEY_SETS": {"default": {"silo": "path.to.YourSiloAdapter", "key_store": "aws"}},
}
```

An adapter also declares the models whose instances are its silos, in
`silo_model_labels`. The `model_label` an adapter sets is its one model; an
adapter whose silos span several models, such as a composite adapter's tenant and
cell, overrides the property. [`SILO_AUTO_KEY_CREATION`](configuration.md#silo_auto_key_creation)
and [`SILO_AUTO_KEY_DELETION`](configuration.md#silo_auto_key_deletion) connect
their signals to those models, and an adapter that declares none cannot use either
setting.

---

## Adapter contract

Every adapter — built-in or custom — must satisfy four requirements. The
package's per-silo isolation guarantees rest on these holding for every
request and every background task.

1. **`get_current_silo()` must return the silo authoritative for
   the calling request or task.** A wrong return value silently routes the
   encrypt or decrypt operation to the wrong DEK, defeating cross-silo
   isolation at the field layer. (KEK-wrap AAD will still catch it on adapters
   that bind the silo UID at unwrap, but treat that as a backstop, not
   the primary boundary.)

2. **Backing state must isolate per concurrent caller.** A single process
   typically serves many requests in parallel — multiple threads, async tasks,
   or worker greenlets. The adapter's source of truth (a `ContextVar`,
   thread-local, request attribute, etc.) must give each concurrent caller its
   own value. `contextvars.ContextVar` is the recommended primitive: it
   isolates per `asyncio.Task` automatically, propagates correctly across
   `asgiref.sync.sync_to_async` boundaries, and behaves like a thread-local
   for sync code. Module-global mutable state (a plain dict, a class
   attribute) does **not** satisfy this requirement.

3. **State must be cleared when the request or task ends.** Otherwise a
   recycled thread or worker can inherit a stale silo from a previous
   request and silently encrypt or decrypt under it. Clear in a `finally`
   block in middleware, or via the `override_current_silo()` context
   manager in tasks (see below).

4. **A silo UID must never be reissued.** Uniqueness among *live* silos is not
   enough. Key rows outlive the silos they belonged to — a scheduled key keeps
   its UID for the whole restore window, and a tombstone keeps it
   permanently — and the deletion gate asks "does a silo with this UID still
   exist?" before destroying a key. Hand the same UID to a second silo and that
   gate reads the newcomer as proof the original is still in use, refusing to
   delete a key whose silo is long gone.

   Derive the UID from something the database will not hand out twice. A
   surrogate primary key is the usual answer: `PegasusTeamSiloAdapter` uses
   `team-{pk}` for exactly this reason. Anything an operator can free and re-take
   — a slug, a schema name, an email address — is unsafe on its own. See
   [Deleting keys that data still depends on](configuration.md#key_deletion_can_render_data_inaccessible)
   for what the gate does with the answer.

The built-in adapters meet these requirements. If you write a custom adapter,
verify all four explicitly — bugs here are silent at the application level
and only surface as confused-deputy or cross-tenant data exposure. A read under
the wrong silo fails to decrypt on its own, because each silo has its own DEK.
If an adapter maps several tenants to one silo, they share a DEK; binding the
column that tells them apart with each encrypted field's `aad=` keeps a row
from moving between them — see
[Security model — Row-identity binding](security.md#row-identity-binding-optional).
[Cross-request tenant-isolation hazards](cross-request-tenant-isolation-hazards.md)
covers the broader hazard class this contract defends.

---

## Built-in adapters

### `DjangoTenantsSiloAdapter`

**Path:** `encryption_suite.adapters.silos.tenants.DjangoTenantsSiloAdapter`

For apps using [django-tenants](https://django-tenants.readthedocs.io/). Reads
the current tenant from `connection.tenant`, which the django-tenants middleware
sets automatically on every request. No custom middleware required.

```python
"KEY_SETS": {"default": {"silo": "encryption_suite.adapters.silos.tenants.DjangoTenantsSiloAdapter", "key_store": "aws"}}
```

The `silo_uid` is `tenant-{schema_name}`, using the schema name as a
stable identifier. See [django-tenants integration](django-tenants.md) for
schema placement and migration notes.

A tenant's rows carry no column naming the tenant — the tenant is the schema — so
this adapter answers [`queryset_for_silo()`](#finding-a-silos-rows) itself with
everything in the tenant's schema, and `use_silo()` enters that schema.

> **Do not reuse a schema name.** Unlike a primary key, a schema name is yours to
> free and re-take, and requirement 4 of the [adapter contract](#adapter-contract)
> forbids it. Dropping a tenant and creating a new one with the same
> `schema_name` gives the newcomer the old tenant's `silo_uid`, and the deletion
> gate then reads it as evidence the original silo is still live — refusing to
> delete the dead tenant's key while the new tenant's own encryption is blocked by
> the leftover scheduled row. Recovering means restoring that row or turning the
> gate off. Retire schema names rather than recycling them.

---

### `PegasusTeamSiloAdapter`

**Path:** `encryption_suite.adapters.silos.pegasus.PegasusTeamSiloAdapter`

For apps built on [SaaS Pegasus](https://www.saaspegasus.com/). Reads the
current team from `apps.teams.context.get_current_team()`, which the Pegasus
team middleware sets automatically. No custom middleware required.

```python
"KEY_SETS": {"default": {"silo": "encryption_suite.adapters.silos.pegasus.PegasusTeamSiloAdapter", "key_store": "aws"}}
```

The `silo_uid` is `team-{pk}`.

Auto-create keys for new teams:

```python
"SILO_AUTO_KEY_CREATION": ["apps.teams.models.Team"]
```

---

### `GenericModelSiloAdapter`

**Path:** `encryption_suite.adapters.silos.generic.GenericModelSiloAdapter`

For apps with a custom team or organization model. Reads the current silo
from a context variable that your middleware sets.

Subclass it and configure `model_label`, `uid_field`, and `label`:

```python
# yourapp/encryption.py
from encryption_suite.adapters.silos.generic import GenericModelSiloAdapter

class TeamSiloAdapter(GenericModelSiloAdapter):
    model_label = "yourapp.Team"
    uid_field = "pk"          # field used in the silo_uid (default: "pk")
    label = "team"       # stored in DataEncryptionKey.silo_label
```

Or use the factory function:

```python
from encryption_suite.adapters.silos.generic import make_silo_adapter

TeamSiloAdapter = make_silo_adapter(
    model_label="yourapp.Team",
    uid_field="pk",
    label="team",
)
```

The `silo_uid` is `{label}-{uid_field_value}`, e.g. `team-42`.

**Required middleware** — set the current silo at the start of each
request:

```python
# yourapp/middleware.py
from encryption_suite.adapters.silos.context import (
    set_current_silo,
    clear_current_silo,
)

class EncryptionSiloMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if hasattr(request, "team") and request.team:
            set_current_silo(request.team)
        try:
            return self.get_response(request)
        finally:
            clear_current_silo()
```

---

### `SimpleTeamSiloAdapter`

**Path:** `encryption_suite.contrib.simpleteams.adapter.SimpleTeamSiloAdapter`

For projects with no team or tenant model of their own. The optional
`encryption_suite.contrib.simpleteams` app ships the team model, this adapter, the
middleware and an admin, so there is nothing to write but settings. The adapter is
a [`GenericModelSiloAdapter`](#genericmodelsiloadapter) over the app's
`SimpleTeam` model, so enumeration, `silo_exists()`, `describe_silo()` and
`reencrypt_data`'s foreign-key introspection all work as they do there.

See [Simple teams](simple-teams.md) for setup, the models, the middleware,
managing teams in the admin, and keys.

---

### `DjangoTenantsCompositeSiloAdapter`

**Path:** `encryption_suite.adapters.silos.composite.DjangoTenantsCompositeSiloAdapter`

For django-tenants apps where some tenants encrypt at the tenant level and
others encrypt at the cell level (different cells, i.e. sub-divisions within the
same tenant, get separate KEKs).

See [django-tenants integration](django-tenants.md) for full setup instructions.

For other frameworks (SaaS Pegasus, custom organization models), subclass
`AbstractCompositeSiloAdapter` and implement `get_current_tenant()`,
`is_tenant()`, `get_tenant_uid()`, and `get_cell_uid()`.

---

### `SystemSiloAdapter`

**Path:** `encryption_suite.adapters.silos.system.SystemSiloAdapter`

The adapter of the built-in `system` key set, and of any `KEY_SETS` entry whose
`silo` is `"system"`. The registry returns it for the `system` key set, so
`KEY_SETS` need not list it, and giving `system` any other `silo` there is an error. Its
silo is the one silo, whose uid is `system`. The adapter lists that silo, answers
`silo_exists()` with `True` for its uid and `False` for any other, and names it
"System". It sets `prevents_key_delete`, described below.

Every row of a model with a `key_set="system"` column belongs to the system silo,
so the adapter sets `supports_silo_data_lookup` and answers `queryset_for_silo()`
with every row of the model, read through `_base_manager`. `reencrypt_data`
therefore rotates a system key set through the same code as every other key set.

The system silo always exists, but a deployment may never encrypt anything under
it. The adapter's `is_in_use()` answers `False` until a model declares a system
column, `KEY_LIFECYCLE_EVENTS` lists an `encrypted_*` item, or a system key exists.

---

### `ActingUserSiloAdapter`

**Path:** `encryption_suite.adapters.silos.user.ActingUserSiloAdapter`

Makes each user a silo. The model is `AUTH_USER_MODEL`, the uid is `user-<pk>`, and the
label is `user`. The adapter enumerates every user, answers `silo_exists()` and
`silo_for_uid()` with a query by primary key, and describes a silo by the primary key
alone, never the username or the email. `get_silo_uid()` accepts a user instance or a
primary key.

Its current silo is the acting user's primary key, read from the user context that
`UserContextMiddleware` fills for a request and `override_current_user()` fills
elsewhere. The adapter sets `reads_user_context`, which tells the middleware to fill the
context for every request. With no acting user the adapter returns no silo, and a read
or write fails like a team silo with no team.

`GenericModelSiloAdapter` and every other adapter built on `ContextSiloAdapter` read one
shared context variable, the one `set_current_silo()` sets. Two such adapters in one
project, for teams and for users, would both read the same value.
`ActingUserSiloAdapter` reads the user context instead, a separate variable, so it can
run beside a team adapter. See [User-specific silos](user-specific-silos.md).

---

### `ActingUserOrOwnerSiloAdapter`

**Path:** `encryption_suite.adapters.silos.user.ActingUserOrOwnerSiloAdapter`

A subclass of `ActingUserSiloAdapter` with its own label, `user_owner`, and uid,
`user_owner-<pk>`. Reads, and writes while a user is acting, behave as they do in
`ActingUserSiloAdapter`. A write with nobody acting goes to the silo of the user the
row belongs to. The adapter sets `writes_to_row_silo_without_context` and implements
`silo_for_row()`, which answers with the row's own primary key on the user model and
with the value of the row's one foreign key to `AUTH_USER_MODEL` on any other model.
See [User-specific silos](user-specific-silos.md#who-chooses-the-silo).

---

## Editing encrypted data

`EncryptionAdminMixin` (which you should add to any `ModelAdmin` for a model with
encrypted fields) **excludes the encrypted fields from the admin change form by
design**. The admin is a forensic, ciphertext-only view: list columns show a
non-decrypting ciphertext preview, and encrypted fields don't appear on the
add/change form at all. This is intentional — the site-wide admin renders rows
outside any single silo context, so decrypting (or editing) there is unsafe.

Consequently you **cannot create or edit encrypted values through the admin**.
Provide a per-silo frontend instead — ordinary views + forms where the silo
context is set (by your tenant/team middleware) for the request:

```python
# forms.py
from encryption_suite import EncryptionModelForm

class SecretForm(EncryptionModelForm):     # decrypts current values into the form
    class Meta:
        model = Secret
        fields = ["name", "notes", "file", "file_display_name"]

# views.py — a normal create/update view; encryption happens on save() under the
# active silo. For encrypted files, serve downloads via:
from encryption_suite.file_view_helpers import encrypted_file_download_view
```

---

## Context helpers

When using `GenericModelSiloAdapter` or a custom context-based adapter,
these module-level functions are available for use in middleware, Celery tasks,
and tests:

```python
from encryption_suite.adapters.silos.context import (
    set_current_silo,
    get_current_silo,
    clear_current_silo,
    override_current_silo,   # context manager
)

# In tests:
with override_current_silo(team):
    assert MyModel.objects.get(pk=pk).sensitive_field == "expected value"
```

---

## Writing a custom adapter

Subclass `AbstractSiloAdapter` and implement three methods:

```python
from encryption_suite.adapters.silos.base import AbstractSiloAdapter

class MySiloAdapter(AbstractSiloAdapter):

    def get_current_silo(self):
        """
        Return the active silo object for the current request/thread,
        or None if none is active. When None is returned and a field is
        accessed, the engine raises EncryptionConfigurationError
        (slug `configuration_error`) — logged with the operator detail,
        with a generic translated message for the user.
        """
        return get_current_silo()   # or read from connection, request, etc.

    def get_silo_uid(self, silo) -> str:
        """
        Return a globally unique, stable string for this silo.
        Used as the lookup key in DataEncryptionKey.
        Must be stable — changing it orphans existing encrypted data.
        """
        return f"org-{silo.slug}"

    def get_silo_label(self) -> str:
        """
        Return a stable human-readable label for this adapter's silos.
        Stored as metadata in DataEncryptionKey.silo_label.
        """
        return "organization"
```

> **Important:** `get_silo_uid()` must be stable. If it returns a
> different value for the same silo after deployment, the engine will
> look up the wrong (or missing) keyset and decryption will fail for all
> existing data.

### Adapter flags

An adapter declares its optional capabilities with boolean class attributes. Each
one defaults to `False`.

| Flag | What it does | Set it `True` when | Leave it `False` when |
|---|---|---|---|
| `supports_enumeration` | Lets setup, reconcile and the Reconcile Keys page list every silo through `iter_silos()`. See [Enumerating silos](#enumerating-silos). | The adapter can list every live silo. | The adapter can list only some silos. A partial list makes live silos look orphaned. |
| `supports_silo_data_lookup` | Lets `reencrypt_data` ask `queryset_for_silo()` for a silo's rows of a model that introspection cannot resolve. See [Finding a silo's rows](#finding-a-silos-rows). | A model reaches its silo through a related model, has more than one key to the silo model, or a silo is a database schema. | Each model has one foreign key to the `model_label` model. |
| `prevents_key_delete` | Refuses to delete any key of the adapter's silos, whatever the operator override says. See [Silos that always exist](#silos-that-always-exist-prevents_key_delete). | The adapter's silos can never go away. | A silo can be deleted. |
| `reads_user_context` | Tells `UserContextMiddleware` to set the acting user for every request. | `get_current_silo()` reads the user context. | The adapter reads its silo from anywhere else. |
| `writes_to_row_silo_without_context` | Sends an encrypted field's write with no current silo to the silo `silo_for_row()` names, rather than failing it. Reads never follow it. See [The row's silo](#the-rows-silo-silo_for_row). | Each row has one owning silo that server code sets, and rows are written while nothing is acting. | A write with no current silo must fail. |

---

## Enumerating silos

Beyond resolving the *current* silo, an adapter may **enumerate** every live
silo — answering "which silos exist?". Two package features consume this:

- **`setup_encryption_keys`** — to create a keyset for each silo up front.
- **KEK reconcile** (admin) — to find KEKs on the KMS that no live silo claims,
  so they can be cleaned up.

Enumeration is **opt-in**, declared by a class attribute and a method:

```python
class MySiloAdapter(AbstractSiloAdapter):
    supports_enumeration = True            # default is False

    def iter_silos(self):
        return MyOrg.objects.all()         # every live silo, no filtering
```

The flag is the contract; callers check it to decide whether enumeration is
available before calling `iter_silos()`. If you set the flag, you must provide an
`iter_silos()` that lists **every** live silo.

### The single-model shortcut

If your adapter already declares a `model_label` (as `GenericModelSiloAdapter`
does), you get `iter_silos()` **for free** — the base implementation returns that
model's full queryset. You only need to set the flag:

```python
class TeamSiloAdapter(GenericModelSiloAdapter):
    model_label = "yourapp.Team"
    supports_enumeration = True
```

The built-in single-model adapters already set this: `GenericModelSiloAdapter`,
`PegasusTeamSiloAdapter`, and `DjangoTenantsSiloAdapter` all enumerate
automatically. You override `iter_silos()` only when your silos span more than
one model, or come from somewhere other than a single queryset.

### Hiding an unused adapter from the Reconcile page

`is_in_use()` returns `True` by default. The Reconcile page lists the silos of an
adapter only when it answers `True`. Override it to answer `False` for an adapter
whose silos always exist but that a deployment may never use. `iter_silos()` still
lists every live silo whatever `is_in_use()` answers, because reconcile must not
mistake a silo for an orphan.

### Safety: list *every* silo, or leave the flag off

> **A partial `iter_silos()` is more dangerous than none.** KEK reconcile treats
> any key encryption key with no matching live silo as an **orphan** — a candidate for
> deleting, which is **irreversible**. If your `iter_silos()` omits live
> silos, their KEKs look orphaned and a live tenant's data can be destroyed.

So:

- If you cannot list **all** silos, leave `supports_enumeration = False`. Callers
  then degrade to *detection-unavailable* — `setup_encryption_keys` asks you to
  pass `--silo-model`, and reconcile reports "enumeration unavailable, audit
  manually" rather than inferring (and destroying) orphans.
- `AbstractCompositeSiloAdapter` ships with the flag **off** for exactly this
  reason: its silos are tenants **and** cells, and the package cannot know your
  cell model. Listing tenants only would make every live cell look orphaned.
  Override `iter_silos()` to yield **both**, then set the flag:

```python
class MyCompositeSiloAdapter(DjangoTenantsCompositeSiloAdapter):
    supports_enumeration = True

    def iter_silos(self):
        from django_tenants.utils import get_tenant_model
        for tenant in get_tenant_model()._base_manager.exclude(schema_name="public"):
            yield tenant
        # ...and every cell, under each cell-encrypted tenant:
        yield from Department._base_manager.all()
```

If `iter_silos()` cannot complete (a missing dependency, a malformed model
label, an uninstalled app), raise — or let the base raise —
`SiloEnumerationError` (slug `silo_enumeration_unavailable`). Route it through
`log_and_raise_enumeration_error(logger, "operator detail")` from
`encryption_suite.exceptions` so it logs one clean line and surfaces a generic
user-safe message instead of a traceback. **Never** return an empty or partial
list to signal failure — callers cannot tell that apart from "no silos", and on
the reconcile path that gap destroys keys.

### Default managers that filter

**The package enumerates rows, not your default manager's view of them.** The
built-in single-model path reads through `Model._base_manager`, and an
`iter_silos()` you write yourself should too.

This matters because a filtering default manager is the most common kind:

```python
class TeamManager(models.Manager):
    def get_queryset(self):
        return super().get_queryset().filter(deleted_at__isnull=True)
```

A soft-deleted team, a suspended tenant, an archived workspace — every one of
those still owns every row it ever had, and someone can still restore it and
read them. `objects` hides them because that is what the admin and your list
views should show. Enumeration is asking a different question: *is there
ciphertext here that still matters?*

Get it wrong and the silo reads as an orphan. Reconcile flags its keys,
`silo_exists()` answers `False`, and the deletion gate destroys a key whose data
is still there. That gate refuses to shred on *cannot say* as carefully as on
*yes* — but a filtered manager produces neither. It produces a confident wrong
answer, which is the one thing the gate acts on.

The same rule carries through `queryset_for_silo()`, so a deployment cannot
faithfully rotate a row its default manager hides and then destroy the key of the
silo that owns it.

**To exclude something from encryption, override `iter_silos()`.** A template
tenant, a demo workspace, a seed row — say it there, where it is a statement
about silos, rather than leaving it to a manager that is a statement about list
views:

```python
class TeamSiloAdapter(GenericModelSiloAdapter):
    model_label = "yourapp.Team"
    supports_enumeration = True

    def iter_silos(self):
        return super().iter_silos().exclude(is_template=True)
```

One consequence to check on upgrade: if your default manager was already hiding
rows, those silos now appear. `setup_encryption_keys` will create a field key and
a file key for each, and under a per-silo `KEK_TEMPLATE` provision a KEK per silo
— a real, billable KMS key. Run it with `--dry-run` first and read the counts.

### Answering about one silo: `silo_exists()`

Enumeration answers "which silos exist?". The key-deletion gate needs something
much smaller: "does *this* UID still belong to a live silo?" That is
`silo_exists(silo_uid)`, and it returns three answers:

| Return | Meaning |
|---|---|
| `True` | a live silo currently has this UID |
| `False` | none does |
| `None` | this adapter cannot say |

`None` is not a failure to be smoothed over. Callers must treat it as *no
information* — never as either answer.

You get a working implementation for free when `supports_enumeration` is on: the
default walks `iter_silos()` looking for the UID. Adapters with a cheaper lookup
should override, because this is a point query and scanning every silo to answer
it gets expensive as a deployment grows:

```python
class MySiloAdapter(AbstractSiloAdapter):
    def silo_exists(self, silo_uid):
        if not silo_uid.startswith("org-"):
            return False
        return Org._base_manager.filter(pk=silo_uid.removeprefix("org-")).exists()
```

**Worth implementing even when you cannot enumerate.** This is a strictly weaker
capability. A composite adapter refuses enumeration because it must list *every*
silo across two model types and a partial list would make live cells look
orphaned — but answering about one UID carries no such risk. Without it, the
deletion gate has to refuse work it cannot verify, and the operator's only escape
is turning off the protection globally:

```python
class MyCompositeAdapter(AbstractCompositeSiloAdapter):
    # Enumeration stays off — we cannot list every cell.
    def silo_exists(self, silo_uid):
        if silo_uid.startswith("tenant-"):
            return Tenant._base_manager.filter(pk=silo_uid.removeprefix("tenant-")).exists()
        if silo_uid.startswith("cell-"):
            return Cell._base_manager.filter(pk=silo_uid.removeprefix("cell-")).exists()
        return None
```

Let a genuine failure raise rather than returning `None`. A transient error (the
database is down) and a permanent inability (this adapter has no way to check)
are different facts, and the gate treats them differently — one is worth
retrying, the other needs code.

Note `_base_manager` in both examples, for the reason
[a filtering default manager](#default-managers-that-filter) is dangerous here:
this answer is a deletion gate, and a silo your application has stopped showing
is not a silo whose data has stopped existing.

### Naming a silo: `describe_silo()`

A UID must be derived from something that can never be reissued, which in
practice means a surrogate key — so it identifies a silo exactly and describes it
not at all. `describe_silo(silo_uid)` is the trip back: return a human-readable
name, or `""` when there is none to give. The admin shows it on the data encryption
key changelist and detail page, beside the UID that every destructive action is
confirmed by. The changelist calls it once per row, so keep it to one query.

```python
class MySiloAdapter(AbstractSiloAdapter):
    def describe_silo(self, silo_uid):
        if not silo_uid.startswith("org-"):
            return ""
        org = Org._base_manager.filter(pk=silo_uid.removeprefix("org-")).first()
        return str(org) if org else ""
```

As with `silo_exists()`, enumerable adapters get a working default that walks
`iter_silos()` — and overriding matters more here, because this runs while
rendering a page.

Two rules, both because this is **purely informational** and nothing gates on it:

- **Return `""` rather than raising.** The default swallows enumeration errors
  for the same reason. A name that cannot be looked up must never break the page
  displaying it, and must never block a lifecycle action.
- **Do not confuse "no name" with "no silo".** `""` covers both a deleted silo
  and an adapter that cannot look one up; the admin distinguishes them by asking
  `silo_exists()` afterwards. Key rows outlive their silos by design, so a
  tombstone with no name is the expected end state, not a fault.

When `silo_for_uid()` returns a model instance registered in the admin, the
detail page also links the name to that instance's admin page.

### Silos that always exist: `prevents_key_delete`

Set `prevents_key_delete = True` on an adapter whose silos always exist. The
deletion gate then refuses to delete the keys of that adapter's silos, whatever
`KEY_DELETION_CAN_RENDER_DATA_INACCESSIBLE` says, and reports the reason `silo still
exists`. The flag is `False` by default, and the built-in system adapter sets it.

The flag has one meaning: these silos cannot go away. It is not a general way to
protect keys from deletion.

### Provisioning without full enumeration

Even with the flag off, you can still provision keysets for a specific model via
`setup_encryption_keys --silo-model app_label.ModelName` (e.g. a composite cell
model). This is the **provisioning** path — it only ever *creates* keysets, so an
explicit model is safe here. It is deliberately separate from reconcile, which
never accepts a model override (a wrong model there could delete a live KEK).

### Testing your `iter_silos()`

Because a wrong result can cost data, test enumeration directly:

```python
@pytest.mark.django_db
def test_iter_silos_lists_every_live_silo():
    a = Org.objects.create(slug="a")
    b = Org.objects.create(slug="b")
    adapter = MySiloAdapter()

    uids = {adapter.get_silo_uid(s) for s in adapter.iter_silos()}

    assert uids == {"org-a", "org-b"}           # completeness — nothing omitted
    assert adapter.supports_enumeration is True  # flag matches reality
```

For a composite adapter, assert that the result includes **both** a tenant UID
and a cell UID, so a regression that drops one model is caught. For an adapter
you intend *not* to support enumeration, assert `supports_enumeration is False`
and that `iter_silos()` raises `SiloEnumerationError` — that proves callers will
take the safe detection-unavailable branch.

---

## Finding a silo's rows

A silo names its keys, not its data: the engine takes the silo from context, or
under [`silo_for_row()`](#the-rows-silo-silo_for_row) from the row, when it encrypts,
and nothing records which rows belong to which silo.
[`reencrypt_data`](management-commands.md#reencrypt_data) has to go the other way
— from a silo to every row encrypted under its key — and it asks the adapter for
three things to do it.

### Row selection: introspection first, then `queryset_for_silo()`

The command walks every installed model with an encrypted field declared on its
own table. For each one it looks for **exactly one foreign key to the model your
adapter names in `model_label`**, and filters on it. That covers the common case
with nothing to write: a model that points at its team or organization directly.

So `model_label` does two jobs. The default `iter_silos()` reads it to enumerate
silos, and the rotation reads it to find the foreign key pointing at the silo. An
adapter that leaves it unset gives up both.

Where introspection has no answer — no `model_label`, a model that reaches its
silo through a related model rather than a key of its own, or one with more than
one key to the silo model — set `supports_silo_data_lookup = True` and implement
`queryset_for_silo(model, silo_uid)`: hand it a model, return that silo's rows.

```python
class MySiloAdapter(GenericModelSiloAdapter):
    model_label = "yourapp.Organization"
    supports_silo_data_lookup = True

    def queryset_for_silo(self, model, silo_uid):
        org_pk = silo_uid.removeprefix("organization-")
        if model is Invoice:  # reaches its organization through a project
            return Invoice._base_manager.filter(project__organization_id=org_pk)
        return model._base_manager.filter(organization_id=org_pk)
```

It is asked only about models introspection could not resolve. Two rules:

- **Use `model._base_manager`, never `objects`.** A default manager that filters
  — soft deletes, archived rows — hides live rows from the rotation, and the swap
  then replaces the key those rows are encrypted under without them. The
  package's own introspected lookup uses the base manager for the same reason.
- **A partial answer is worse than none**, exactly as with `iter_silos()`. A row
  the answer leaves out keeps its data on a key the rotation is about to destroy.

Declaring the flag without implementing the method is a configuration fault: the
base method raises `EncryptionConfigurationError` naming both.

A model nothing can resolve is reported, never skipped. `manage.py check` warns
(`encryption_suite.W053`) and names it — a warning rather than an error, because a
deployment that never rotates a data key should not fail to deploy over a command
it does not run — and `reencrypt_data` refuses to start, naming the same models,
before any silo is fenced.

### From a UID to a silo: `silo_for_uid()`

The command holds a UID — from `--silo-uid`, or from the key row it is rotating —
and the introspected filter needs the silo row. `silo_for_uid(silo_uid)` is the
reverse of `get_silo_uid()`, which only the adapter can perform. The default walks
`iter_silos()` where enumeration is on and returns `None` where it is not;
`GenericModelSiloAdapter`, `PegasusTeamSiloAdapter` and `DjangoTenantsSiloAdapter`
override it with a point query, and answer `silo_exists()` from the same query.

A UID that comes back `None` stops the run before any fence, naming the UID and
this method. **An adapter that leaves both `silo_for_uid()` and enumeration
alone cannot rotate a single silo, and nothing says so until the command runs.**
Override it if you override `silo_exists()` — it is usually the same query.

A run without `--silo-uid` rotates every silo, which needs `supports_enumeration`:
the command will not sweep only the silos it happens to see. An adapter without
enumeration can still rotate, one silo per run.

### Making a silo current: `use_silo()`

`use_silo(silo_uid)` returns a context manager that the command enters once around
each silo's work. The default does nothing, which is right wherever a silo is a
column. **Where a silo is a database schema, override it** — rows are not visible
outside their schema, so without it a rotation reads the wrong one in silence.
`DjangoTenantsSiloAdapter` and `DjangoTenantsCompositeSiloAdapter` both enter the
schema the UID names; see [django-tenants](django-tenants.md#rotating-a-tenants-data-key).

### The row's silo: `silo_for_row()`

`silo_for_row(instance)` answers the opposite question to `queryset_for_silo()`: given
one row, which silo does it belong to? `reencrypt_data` never asks it. An encrypted
field calls it while it writes *instance*, and only when the adapter sets
`writes_to_row_silo_without_context` and `get_current_silo()` returns `None`. Return
anything `get_silo_uid()` accepts, or `None` when the row names no silo. `None` fails
the write as a missing current silo does.

The field encrypts the value and computes its blind index digest under the same silo,
so an exact lookup made in that silo finds the row. A file field and
`QuerySet.update()` have no row in hand and never call it.

Declaring the flag without implementing the method is a configuration fault: the base
method raises `EncryptionConfigurationError` naming both. `manage.py check` warns
(`encryption_suite.W061`) for a model on such a key set that is not the `model_label`
model and has no foreign key, or more than one, to it.

---

## Celery and background tasks

Context variables do not propagate to Celery workers automatically. Any
task that accesses encrypted fields must explicitly set the silo context:

```python
from encryption_suite import strict_mode
from encryption_suite.adapters.silos.context import (
    override_current_silo,
)

@app.task
def process_patient_data(team_pk):
    team = Team.objects.get(pk=team_pk)
    with override_current_silo(team), strict_mode():
        # encrypted field access works here
        records = Patient.objects.filter(team=team)
        ...
```

`strict_mode()` makes a read raise when it cannot produce plaintext, instead of
returning the fallback label, so a task that processes plaintext fails rather than
processing the label. See
[Strict mode](scheduled-tasks.md#strict-mode).

For django-tenants or Pegasus, use their own task context utilities (e.g.
`schema_context` for django-tenants) which set the framework context that the
silo adapter reads from.
