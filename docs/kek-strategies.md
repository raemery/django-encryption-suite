# KEK strategies

A KEK strategy adapter decides *which* key encryption key (KEK) is used to
encrypt the data encryption key (DEK) for a given silo. It
sits between the silo layer, which identifies the active
tenant or team, and the KMS adapter, which talks to the cloud KMS.

If you are new to envelope encryption, read
[concepts.md](concepts.md) first for the high-level KEK / DEK model,
and [how-kms-works.md](how-kms-works.md) for what the KMS sees on
each request.

---

## Extension point rationale

Different deployments have different KEK-provisioning policies, and
there is no single right answer. Some common shapes:

- **One KEK per silo.** Strongest isolation. Each tenant can
  be independently rotated, revoked, or deleted. Costs
  scale with the number of tenants, and some KMS providers have
  quotas on distinct keys.
- **One shared KEK.** Cheapest. DEKs still differ per silo
  (each silo has its own DEK), so tenant data stays
  cryptographically separated at the DEK layer — but the KEK itself
  cannot be rotated or revoked for a single tenant.
- **Cohort-based KEKs.** One KEK per region, environment, or
  compliance class. Balances operational cost against isolation.
  HIPAA tenants share KEK-A, non-HIPAA share KEK-B, etc.
- **Composite-aware KEKs.** Mirrors a
  [composite silo](silo-adapters.md#djangotenantscompositesiloadapter)
  setup. Top-level tenants that encrypt at the tenant level get one
  KEK each; tenants that encrypt at the sub-group level get one KEK
  per group.
- **BYOK (Bring Your Own Key).** Each tenant supplies their own KEK
  identifier — typically an ARN or resource name stored on the
  tenant model. Common in enterprise multi-tenant products where
  customers require control of their own keys.

The KEK strategy adapter is a single, focused extension point that
covers all of these without adding flags to the KMS adapter.

The strategy only decides the KEK *name*. Ensuring a KEK with that name
actually exists on the KMS is a separate concern handled by the
[KEK provisioner](kek-provisioning.md), which defaults to a no-op so that
keys are assumed to be provisioned outside this application.

---

## Selecting a strategy

Every [`KMS_KEY_STORES`](configuration.md#kms_key_stores) block requires
`KEK_STRATEGY_ADAPTER`. Set it
to the dotted path of the strategy class you want.

```python
ENCRYPTION = {
    "KEY_SETS": {"default": {"silo": "...", "key_store": "main"}},
    "KMS_KEY_STORES": {
        "main": {
            "ADAPTER": "...",
            "OPTIONS": {
                "AWS_REGION": "us-east-1",
                "KEK_TEMPLATE": "alias/encryption_suite-{silo_uid}",
            },
            "KEK_STRATEGY_ADAPTER": (
                "encryption_suite.adapters.keks.PerSiloKekStrategy"
            ),
        },
    },
}
```

---

## Built-in strategies

### `PerSiloKekStrategy`

This strategy gives each silo its own KEK. It resolves the KEK ID in this order:

1. `KEK_MAP[silo_uid]` — **exact match** against the raw,
   *unsanitized* silo UID. Use this when your KMS provider
   identifies keys by UUID or OCID, where a naming convention is
   impractical. Map keys must match the silo UID byte-for-byte
   (e.g. `"team-42"` exactly — not a sanitized or templated variant).
2. `KEK_TEMPLATE.format(silo_uid=…)` — naming-convention
   fallback. The silo UID is sanitized to the KMS adapter's allowed
   charset (default `[a-zA-Z0-9_-]`) via a bijective UTF-8 hex encoding
   before substitution. A normal UID like `team-42` already fits the
   default charset and passes through unchanged; any character outside
   the charset is hex-escaped (e.g. `@` → `_40`). Allowed charsets vary
   by provider — see [KMS adapters](kms-adapters.md).
3. `EncryptionConfigurationError` if neither is configured.

`KEK_MAP` and `KEK_TEMPLATE` are **not symmetric**: the map is
keyed on the raw UID, the template receives the sanitized UID. A
UID that is absent from `KEK_MAP` falls through to `KEK_TEMPLATE`
using the sanitized form; it does not retry the map with a
sanitized key. This is intentional — map values are typically
opaque identifiers (UUIDs, OCIDs) that have no relationship to the
UID, while template values embed the UID into a key name and so
must conform to KMS naming rules.

If you populate `KEK_MAP` with sanitized keys and your silo
UIDs contain characters outside `[a-zA-Z0-9_-]`, the map lookup
will miss and the resolver will fall through to the template (or
raise if no template is configured). Either keep the map keyed on
the raw UID, or restrict silo UIDs to characters that survive
sanitization unchanged.

```python
"OPTIONS": {
    "KEK_TEMPLATE": "alias/encryption_suite-{silo_uid}",
    # or, for UUID-keyed providers:
    "KEK_MAP": {
        "team-1": "ocid1.key.oc1..aaa",
        "team-2": "ocid1.key.oc1..bbb",
    },
},
```

#### Deleting mapped keys: `KEK_MAP_DESTROYABLE`

The two resolution paths are classified differently for deletion. A key named by
`KEK_TEMPLATE` was named by this deployment, so it is **silo-exclusive** and
eligible. A key named by `KEK_MAP` is an opaque identifier you supplied, so it is
**shared/opaque** and every deletion path refuses it — the assumption being that
something else may depend on a key this deployment did not create.

Set `KEK_MAP_DESTROYABLE` to `True` in `OPTIONS` to opt mapped keys into
deletion. It changes nothing about resolution. It makes every mapped key both
deletable (the disposition gate lets it through) and owned (the ownership gate
accepts it without a `KEK_TEMPLATE` prefix), so it works for OCIDs, UUIDs and ARNs,
and for a store that has a `KEK_MAP` and no `KEK_TEMPLATE`. Default `False`.

A mapped key is deleted only when it passes every gate: no live data key uses it,
the setting is on, the provisioner can delete, and the key is not held back by a
changed owner prefix. See [the deletion gates](management-commands.md#the-deletion-gates).

```python
"OPTIONS": {
    "KEK_MAP": {"team-1": "ocid1.key.oc1..aaa"},
    "KEK_MAP_DESTROYABLE": True,
},
```

The classification is asked two ways, and they agree: by silo UID when a silo is
in hand, and by stored key name when one is not — a key encryption key row has no
silo UID, since a discovered orphan never had one and a shared key has many. See
[the deletion gates](management-commands.md#the-deletion-gates).

### `SharedKekStrategy`

Every silo encrypts its DEK under a single shared KEK, read
from `SHARED_KEK_ID` in `OPTIONS`.

```python
"OPTIONS": {
    "AWS_REGION": "us-east-1",
    "SHARED_KEK_ID": "alias/encryption_suite-shared",
},
"KEK_STRATEGY_ADAPTER": (
    "encryption_suite.adapters.keks.SharedKekStrategy"
),
```

Under `SharedKekStrategy` the per-tenant cryptographic boundary at the
KEK layer comes from the wrap-layer AAD (every wrapped DEK is bound
to its `silo_uid` via `AbstractKmsAdapter._wrap_aad`, or via the
provider-native equivalent on AWS and OCI), not from KEK separation. KMS
adapters whose wrap operation cannot bind associated data cannot
provide that boundary and reject `SharedKekStrategy` at construction
with `EncryptionConfigurationError`, which `manage.py check` reports as
`encryption_suite.E003`:

| KMS adapter        | `SharedKekStrategy` |
|--------------------|---------------------|
| System             | supported (it is the env key store's own strategy) |
| AWS KMS            | supported           |
| AWS KMS (Tink)     | supported           |
| GCP Cloud KMS      | supported           |
| GCP Cloud KMS (Tink)| supported          |
| Fly                | supported           |
| OCI                | supported           |
| IBM Key Protect    | supported           |
| Azure Key Vault    | supported           |
| HashiCorp Vault | **rejected** (transit `context` requires derived keys) |
| Infisical          | **rejected** (KMS API has no AAD-equivalent field) |

Use `PerSiloKekStrategy` with the rejected adapters, or switch
to one whose wrap operation supports AAD without extra setup.

---

## Writing a custom strategy

Subclass `AbstractKekStrategyAdapter` and implement `get_kek_id`.
The base class stores the `OPTIONS` dict as `self.options`, so
your strategy reads its own configuration from the same place as
the KMS adapter it sits in front of.

```python
from encryption_suite.adapters.keks import (
    AbstractKekStrategyAdapter,
)


class RegionCohortKekStrategy(AbstractKekStrategyAdapter):
    """One KEK per region. Region is resolved from the current
    tenant via a callable in OPTIONS["REGION_RESOLVER"]."""

    def get_kek_id(self, silo_uid: str) -> str:
        from django.utils.module_loading import import_string
        resolver = import_string(self.options["REGION_RESOLVER"])
        region = resolver(silo_uid)
        return f"alias/encryption_suite-region-{region}"
```

Then wire it up:

```python
"KEK_STRATEGY_ADAPTER": "yourapp.encryption.RegionCohortKekStrategy",
"OPTIONS": {
    "REGION_RESOLVER": "yourapp.encryption.resolve_region",
    ...
},
```

A strategy that can resolve two silos to one key, as this one does, should
also override `shared_kek_problem()` and return a sentence saying so. The
HashiCorp Vault and Infisical adapters cannot bind associated data into a
wrapped DEK, so they call it at construction and refuse any configuration it
reports. The base class returns `None`, which those adapters read as one key
per silo.

```python
    def shared_kek_problem(self) -> str | None:
        return "RegionCohortKekStrategy resolves every silo in a region to one key."
```

### Composite-aware example

If you use a
[composite silo](silo-adapters.md#djangotenantscompositesiloadapter),
your silo UIDs already encode the distinction between
top-level tenants and sub-groups (for example `tenant-acme` vs
`tenant-acme-cell-42`). A composite-aware strategy can branch on
the UID shape:

```python
class CompositeKekStrategy(AbstractKekStrategyAdapter):

    def get_kek_id(self, silo_uid: str) -> str:
        # tenant-acme           -> alias/encryption_suite-tenant-acme
        # tenant-acme-cell-42   -> alias/encryption_suite-tenant-acme-cell-42
        return f"alias/encryption_suite-{self._sanitize_uid(silo_uid)}"
```

In practice this is what `PerSiloKekStrategy` already does,
because the composite silo adapter produces globally unique
UIDs for both tenants and groups. Writing your own strategy only
becomes necessary when you want to branch the KEK *shape* on the
key set or silo type — for example, to put all group KEKs in a
different region or key ring from tenant KEKs.

### BYOK example

For a Bring Your Own Key setup where each tenant stores their own
KEK ARN on the tenant model:

```python
class ByokKekStrategy(AbstractKekStrategyAdapter):

    def get_kek_id(self, silo_uid: str) -> str:
        from django.db import connection
        tenant = connection.tenant  # django-tenants
        kek_arn = tenant.kek_arn
        if not kek_arn:
            raise ValueError(
                f"Tenant {silo_uid} has no kek_arn set."
            )
        return kek_arn
```

The strategy is instantiated once per process, so it is safe to
cache immutable lookups, but any per-request state must come from
the ambient context (as in the `connection.tenant` read above), not
from instance attributes.

---

## Interaction with the KMS adapter

The KMS adapter calls `self._kek_strategy.get_kek_id(uid)` from
`_resolve_kek_id`. Concrete KMS adapters (AWS, GCP, Azure, Vault,
etc.) do not need to know about the strategy — they continue to
call `self._resolve_kek_id(silo_uid)` and receive a
provider-specific identifier back, just as before. Swapping
strategies does not require any KMS-adapter changes.

The strategy is resolved once at first use, cached by the registry
for the lifetime of the process, and shared across all KMS calls.
If you change `KEK_STRATEGY_ADAPTER` in a test, call
`encryption_suite.registry.reset()` to clear the cache.

---

## Alternatives to a new strategy

If the only thing varying is a small set of explicit
UID → KEK mappings, prefer `KEK_MAP` in `OPTIONS` with the
built-in `PerSiloKekStrategy`. Writing a custom strategy
only pays off when the mapping is derived from state held
outside `OPTIONS` — the tenant model, a region resolver, a
feature flag, or the shape of the silo UID itself.
