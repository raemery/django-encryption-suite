# Cross-request tenant-isolation hazards

This page covers a class of bug in which **shared mutable state** in a multi-tenant
Django process returns the wrong value for the current request, silently routing one
tenant's request to another tenant's data. The unifying threat model is
**confused deputy via state-isolation failure**: the package or the host
trusts a piece of state to represent the current caller, but that state was
last written by a different caller.

This page is an inventory of where the pattern can show up in a
django-encryption-suite deployment, what the package does to prevent it, and what
the host application must do to keep the boundary tight. None of the entries
below are active bugs in the package as shipped — they are the surfaces an
auditor or contributor should examine.

For the bigger-picture security framing, see [Security model](security.md);
for the formal requirements on adapters, see
[Silo adapters — Adapter contract](silo-adapters.md#adapter-contract).

---

## 1. In-process DEK cache

**Where:** `encryption_suite.engine._aead_cache` — a module-level
`dict[str, tuple[Aead, float]]` mapping `f"field:{silo_uid}"` (and the
analogous `"file:..."` key for streaming AEAD and `"index:..."` key for the
blind index) to a crypto-backend primitive plus its TTL expiry.

**Potential issue.** A process-global cache that returns an AEAD
primitive on every encrypted-field access. If the cache ever returned the
wrong tenant's primitive, that tenant's DEK would be used to encrypt or
decrypt — a complete cross-tenant boundary failure.

**Safeguards.**

1. Cache key includes the silo UID verbatim (`f"field:{silo_uid}"`).
   No sanitization, hashing, or truncation at the cache layer, so distinct
   UIDs cannot collide on the same cache entry.
2. The loader (`_decrypt_to_aead(uid)`) filters the database row by
   `silo_uid=uid` before unwrapping. The primitive returned to the
   cache is bound by query to the requested UID's keyset.
3. The KMS adapter binds the silo UID as AAD at unwrap. `EnvKeyStoreAdapter`
   and `FlyKmsAdapter` use `_wrap_aad(silo_uid)`; AWS uses
   `EncryptionContext`. A swapped wrapped-DEK row in the database fails to
   unwrap.
4. A primitive is bound to one key when it is loaded, under either crypto
   backend, and exposes no way to rebind it. Once cached, the primitive
   cannot be mutated to point at another DEK.
5. Per-key load locks (`_primitive_locks`) plus a global cache mutex
   (`_cache_lock`) prevent torn writes during concurrent first-load.
6. The cache is per-process. There is no shared distributed cache, so an
   exploit on one process cannot propagate via this surface.

**Residual risk.** Effectively zero, given the safeguards above. The cache
faithfully serves what it is keyed with, so the only way it can return a
"wrong" primitive is if the *caller* asks for the wrong UID — which is the
silo-adapter risk covered in §2 below, not a cache risk.

**Defense in depth.** The KMS-wrap AAD (safeguard 3) is itself the
cryptographic backstop beneath the cache. Even a hypothetical cache key
collision (which the code structurally prevents) would still fail at the
unwrap layer because the KMS adapter would reject the wrong-AAD ciphertext.

---

## 2. Silo context (`ContextVar`, thread-local, request attribute)

**Where:** the source of truth read by the configured silo adapter's
`get_current_silo()`. For the built-in `PegasusTeamSiloAdapter`,
this is `apps.teams.context._context`, a `contextvars.ContextVar`. For
custom adapters it might be a `threading.local`, an attribute on the
`request` object, or a token derived from `request.user`. The package's own
`_strict_mode_var` (in `encryption_suite.fields`) is a `ContextVar` of
the same shape.

**Potential issue.** Every encrypt and decrypt consults the adapter once per
field access. If the adapter returns a stale or wrong silo for the
current request, the engine routes the operation to the wrong DEK, and the
cross-tenant boundary collapses at the field layer.

**Safeguards.**

1. **Per-`asyncio.Task` isolation by design.** `ContextVar` is the PEP 567
   primitive specifically intended for this: each task has an independent
   context lookup, and concurrent tasks cannot see each other's mutations.
2. **`asgiref.sync.sync_to_async` uses `copy_context().run(...)`.** When
   Django dispatches a sync view or sync middleware from the ASGI handler,
   the sync code runs in a copy of the calling task's context. Mutations in
   the copy do not leak back to the parent task or to other concurrent
   requests sharing the same OS thread.
3. **Middleware clears in `finally`.** The Pegasus `TeamsMiddleware`
   (and any well-formed custom middleware) calls
   `unset_current_team(token)` regardless of whether the view returns
   normally or raises. The token-based reset restores the prior value,
   which is correct under nested middleware.
4. **Empirically verified.** Under
   `gunicorn -k uvicorn.workers.UvicornWorker --threads 8` with concurrent
   users from different teams, silo resolution stays correct on
   every request (verified during a confused-deputy investigation;
   diagnostic instrumentation showed `gk` matching the request URL on
   every decrypt).
5. **`_strict_mode_var`** is mutated only through the `strict_mode()`
   context manager, which sets and resets via token. No leak surface in
   normal usage.

**Residual risk.** All host-side, none in the package itself:

- A custom adapter using `threading.local` instead of `ContextVar` and
  running under `asgiref.sync.sync_to_async`'s reused thread pool will
  leak unless every entry point clears the local in `finally`.
- A signal handler or post-response hook that calls `set_current_team`
  without a matching `unset` leaves the value live for the next request
  on the same task or thread.
- A Celery task that does not wrap its work in
  `override_current_silo()` may inherit context from a previous
  task in the same worker.

These risks are documented in
[Security model — Context state leakage](security.md#context-state-leakage-across-requests-and-tasks)
and [Silo adapters — Celery and background tasks](silo-adapters.md#celery-and-background-tasks).

**A wrong silo fails closed on its own.** If leaked context makes the adapter
return the wrong silo, the engine uses that silo's DEK, and a row encrypted
under another silo's DEK fails to decrypt. No
[row-identity binding](security.md#row-identity-binding-optional) is needed
for that.

### Worked example: a cell-resolution middleware that leaked

This failure is easy to introduce. A composite (tenant + cell) setup used
middleware that set the cell **only when** a request named one, and otherwise
relied on the previous request's clear:

```python
# LEAKY — do not copy
def __call__(self, request):
    if getattr(connection.tenant, "uses_cell_encryption", False):
        dept = request.GET.get("department")
        if dept:                                  # only sets sometimes
            set_current_cell(Department.objects.filter(pk=dept).first())
    try:
        return self.get_response(request)
    finally:
        clear_current_cell()                      # relies on this to reset
```

Under `gunicorn -k uvicorn.workers.UvicornWorker`, a request that named **no**
department inherited the **last cell used** on that reused context and silently
encrypted under the wrong cell — the write succeeded and only failed later on
decrypt. (The engine itself behaved correctly: it used the cell the context
reported, and when the context was genuinely empty it **failed closed** with
`EncryptionConfigurationError`. The bug was entirely in the middleware.)

The fix is the rule for **all** silo/cell context middleware: **establish the
value explicitly on every request** — to the resolved object *or* `None` — and
never depend on a prior request's clear. Use the token-reset context manager so
nesting is correct:

```python
# CORRECT
def __call__(self, request):
    cell = None
    if getattr(connection.tenant, "uses_cell_encryption", False):
        dept = request.GET.get("department")
        if dept:
            cell = Department.objects.filter(pk=dept).first()
    with override_current_cell(cell):   # sets every request (even None), resets on exit
        return self.get_response(request)
```

The same shape applies to `override_current_silo()` for top-level silo
middleware. Pair it with
[row-identity AAD binding](security.md#row-identity-binding-optional) where the
row carries a silo/cell FK, so a leak fails closed cryptographically rather than
disclosing data.

---

## 3. Per-instance plaintext cache on `__dict__`

**Where:** `encryption_suite.fields.EncryptedAttributeDescriptor`
populates `instance.__dict__[attname]` with the decrypted plaintext (or
`UndecryptableValue` sentinel) on first read of an encrypted field. This is
how subsequent reads on the same instance avoid re-decryption.

**Potential issue.** The plaintext is held on the Python object for the
lifetime of the object. If the host application caches model instances
*across* requests — a custom in-process LRU keyed by primary key, an
object-graph cache in a long-lived service, a background task that holds
references to instances created during a previous request — then a future
request with a different silo context can read the plaintext directly
out of `instance.__dict__` without ever consulting the engine, the
adapter, or the DEK.

**Safeguards.**

1. **Django's normal request lifecycle scopes instances to the request.**
   `get_object_or_404`, `Model.objects.get`, queryset iteration — all
   produce instances tied to the request that constructed them. When the
   request ends, the instances become garbage, and the plaintext goes with
   them.
2. **Decryption is gated by the silo context at the moment of
   first read.** Plaintext only enters `__dict__` if the adapter returned
   a silo whose DEK could decrypt the ciphertext. A request without
   the right context will fail before populating the cache.

**Residual risk.** Host-side. Any of the following patterns reintroduce
the hazard:

- `functools.lru_cache` or a `cachetools` cache wrapping a function that
  returns model instances of an encrypted model.
- A Django signal handler that retains references to model instances in
  a module-level list or dict.
- A long-running management command, Celery task, or websocket consumer
  that holds an instance across multiple "logical request" boundaries
  and switches silo context between them.
- Custom session backends that pickle and reuse instances rather than
  serializing the IDs.

**Defense in depth.** The same row-identity AAD binding that defends §2
also helps here: a cached instance whose ciphertext is decrypted under
silo A then re-read after a switch to silo B will fail at
decrypt only on the *first* read in the new context. If that first read
already happened under A (and is sitting in `__dict__`), AAD does not
help — the plaintext is already exposed in process memory. Avoid
cross-request instance reuse.

---

## 4. Host-side patterns to audit

Two more shapes of the same bug class. They occur in host application code,
not in the package, but they're worth checking when reviewing a deployment
that uses django-encryption-suite.

### Class-level mutable QuerySet cache

A common Django pattern places a queryset on a view class:

```python
class InvitationViewSet(viewsets.ModelViewSet):
    queryset = Invitation.objects.all()
```

The class attribute is shared across every instance of the view, and every
request handled by the class. `.filter()` and `.exclude()` return *new*
QuerySet objects, so deriving a per-request queryset (`self.queryset.filter(...)`)
is safe. The hazard is direct evaluation of the class-level QuerySet:
`MyView.queryset.first()` populates `_result_cache` on the shared object,
and every subsequent reader sees the cached results regardless of their
tenant context.

**Mitigation:** never evaluate a class-level QuerySet directly; always
derive a fresh one with `.filter()` or override `get_queryset()`. DRF and
the Django admin already follow this pattern.

### Database session state (`SET LOCAL`, RLS, `search_path`)

Hosts that use Postgres row-level security, `SET LOCAL` to scope queries by
tenant, or `django-tenants`-style `search_path` switching are setting
state on the database connection. Connection pooling (PgBouncer in
transaction or session mode, Django's persistent connections) can carry
that state to the next request handled by the same connection unless the
host explicitly resets it.

**Mitigation:** use the framework-provided context manager
(`schema_context` for django-tenants), set RLS state inside an explicit
transaction that resets it on commit, or use `RESET ALL` between requests
if the pooler permits.

This class of issue is outside django-encryption-suite's scope — the package
operates above the connection layer — but a context leak at the database
layer can present identically to a silo-context leak at the
application layer, so it is worth ruling out during incident response.

---

## Investigating a suspected leak

When a cross-tenant disclosure is reported and you are not sure which layer
is at fault, the fastest discriminator is to ask:

1. **What silo UID did the engine resolve for the offending
   request?** Add a temporary `WARNING` log in the engine's
   `decrypt()` printing `pid`, thread name, resolved `silo_uid`,
   and `field_name` / `row_identity`. Compare to the request URL.
2. **What was the value of the silo context at request entry and
   exit?** Add the same instrumentation in the host's tenant-resolving
   middleware.
3. **Did the decrypt actually succeed, or did the user see a fallback?**
   In lenient mode, `EncryptedAttributeDescriptor` returns
   `UndecryptableValue` and stores the exception on
   `instance._encryption_suite_errors[attname]`. Check whether the rendered
   string is real plaintext or a fallback label.

These three signals together pin the failure to a specific layer: cache,
context, or row state. The package itself emits an `ERROR`-level log on
every decryption failure (regardless of `LOG_DECRYPTS`), so check
your log pipeline before assuming a silent success.

---

## Related reading

- [Security model](security.md) — full threat model, including
  cross-silo isolation and KMS AAD.
- [Security model — Context state leakage across requests and tasks](security.md#context-state-leakage-across-requests-and-tasks) — extended discussion of the §2 risk.
- [Security model — Row-identity binding](security.md#row-identity-binding-optional) — a field's `aad=` as cryptographic defense in depth.
- [Silo adapters — Adapter contract](silo-adapters.md#adapter-contract) — the four formal requirements every adapter must satisfy.
- [Silo adapters — Celery and background tasks](silo-adapters.md#celery-and-background-tasks) — how to set context in worker tasks without leaking it.
- [Operations](operations.md) — DEK cache TTL, multi-process workers, ASGI behavior.
