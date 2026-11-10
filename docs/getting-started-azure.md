# Getting started with Azure Key Vault

This step-by-step guide walks you through wiring django-encryption-suite to Azure Key Vault in
production. This page assumes you have already followed
[Getting started](getting-started.md) for the basic Django setup
(`INSTALLED_APPS`, migrations, a silo adapter) and now need to swap
the local dev KMS for a real Key Vault.

The two decisions that drive everything else on this page:

1. **Shared KEK or per-silo KEK?**
   One key for the whole application vs. one key per tenant/team.
2. **Auto-provision or manual?**
   Let the application create keys on first encrypt vs. provision them
   outside this application (Azure Bicep / Terraform / portal) before the application sees
   them.

The rest of this guide walks through each combination end-to-end.

---

## Prerequisites

- An Azure subscription, a resource group, and a region you intend to
  deploy in (this guide uses `eastus`).
- An existing Azure Key Vault. Vaults are **never** auto-created — they
  are tenant-level resources with soft-delete and purge-protection
  semantics that don't fit on-demand provisioning.
- Permission to grant Key Vault role assignments (or set Access Policies
  on legacy vaults) for your application's identity.
- The `azure` extra installed:

  ```bash
  uv add 'django-encryption-suite[azure]'
  ```

- A working `ENCRYPTION` block in `settings.py` from
  [Getting started](getting-started.md). You will replace the
  env key store configuration with a `AzureKeyVaultAdapter` block below.

### A note on Key Vaults

Azure Key Vaults have two important behaviors to know about up front:

- **Soft delete** is enabled by default and cannot be disabled. Deleted
  keys remain recoverable for 7–90 days; you cannot reuse a name during
  that window.
- **Purge protection**, when enabled (often required by compliance),
  means deleted keys cannot be permanently removed even by Key Vault
  administrators until the retention period expires.

This means key names burn slowly. Don't auto-provision keys with names
derived from short-lived identifiers — pick a stable convention.

`AzureKeyVaultAdapter` uses **AES-256-GCM** encrypt/decrypt to wrap
DEKs. The provisioner therefore creates **symmetric** keys (`oct-HSM`,
256-bit by default) with `encrypt`/`decrypt` operations enabled — not
the `wrapKey`/`unwrapKey` operations sometimes used in other Azure
tutorials, and not the RSA keys most Key Vault examples show.

> **This requires a Premium vault, and the key type is in preview.**
> Standard vaults offer RSA and EC only. Symmetric (`oct-HSM`) keys need
> Premium, where Microsoft ships them as a **public preview**: provided
> as-is, with no SLA, and not recommended by Microsoft for production
> workloads. A Standard vault rejects key creation, and the provisioner
> rewrites that rejection to name the SKU. You can upgrade a vault in
> place — `az keyvault update --name <vault> --set
> properties.sku.name=premium` — but existing RSA keys stay
> software-protected.

AES-GCM is used because it is the only Key Vault algorithm that accepts
**associated data**. Every wrapped DEK is bound to its silo UID, so a
wrapped DEK moved between silos in the database fails to decrypt. That
binding is what AWS gets from `EncryptionContext` and GCP from
`additionalAuthenticatedData`; RSA-OAEP has no equivalent.

---

## Decision 1 — shared vs per-silo KEK

### Shared KEK

One Key Vault key encrypts every silo's DEK. Simpler operationally;
one role assignment, one key to rotate, one key in the vault audit log.
The trade-off is blast radius: if that single key is compromised or
accidentally destroyed, every tenant's encrypted data is at risk
simultaneously.

Pick this when:

- You have a single-tenant deployment (one organization, many teams that
  don't need cryptographic isolation between them).
- You want the lightest operational footprint and the per-tenant blast
  radius is not a compliance requirement.

### Per-silo KEK

Each tenant/team gets its own Key Vault key. Compromise or destruction
of one key affects only that tenant. Required by some compliance regimes
(HIPAA multi-tenant scenarios, customer-managed keys for B2B contracts).
Costs scale with key count, and on Azure they scale with **key versions** — see
[Cost](#cost) below before choosing per-silo keys.

Pick this when:

- You're a multi-tenant SaaS where tenants must be cryptographically
  isolated.
- You need to demonstrate per-tenant key custody to auditors.
- You want the option to revoke a single tenant's data by disabling one
  key.

### Settings mapping

| Choice | `KEK_STRATEGY_ADAPTER` | `OPTIONS` key |
|---|---|---|
| Shared | `SharedKekStrategy` | `SHARED_KEK_ID` |
| Per-silo | `PerSiloKekStrategy` | `KEK_TEMPLATE` (or `KEK_MAP`) |

The `KEK_TEMPLATE` value is a key **name** within the configured
vault (e.g. `encryption-suite-{silo_uid}`) — not a full key URI. The
adapter combines it with `AZURE_VAULT_ENDPOINT` to fetch the key at
request time.

Both strategies are supported. Under `SharedKekStrategy` the
per-tenant boundary comes from the AES-GCM associated data rather than
from separate keys: every wrapped DEK is bound to its silo UID, so one
moved between silos fails to decrypt even though both silos use the same
key.

---

## Cost

Worth understanding before you pick a KEK strategy or a rotation period, because
the billing unit is not the one most people assume.

`oct-HSM` keys are HSM-protected, and Azure bills HSM-protected keys **per key
version per month** — not per key. A version is created every time a key is
created *or* rotated, and every version keeps costing until the key is purged. So
the monthly figure is roughly:

```
(number of silos) × (1 + rotations per month) × per-version rate
```

Three consequences:

- **Per-silo keys multiply the bill by your tenant count**, unlike a shared KEK,
  which is one key however many silos use it. That is a real trade against the
  isolation a per-silo key buys, not a rounding error.
- **A rotation policy compounds it.** `KEK_ROTATION_PERIOD_DAYS` adds a billable
  version per key per period, indefinitely. A 7-day policy across 100 tenants is
  400 new billable versions a month. Key Vault's floor is 7 days; something on
  the order of 180 or 365 is the sane production setting, and the package's
  default is no policy at all.
- **Deleting is not enough to stop it.** A soft-deleted HSM key can keep
  incurring the per-version charge for up to 30 days if a version was used
  recently. Purging is what ends it — `az keyvault key purge`, or
  `az keyvault purge` for the whole vault.

A Standard vault with RSA keys avoids the per-version charge entirely, at the
cost of the AAD binding this adapter relies on. That is the honest trade behind
the symmetric-key requirement: it buys a per-tenant cryptographic boundary and it
is not free.

Test deployments are where this bites hardest, because testing creates versions
far faster than production does — each manual rotation, each recreated key. Leave
`KEK_ROTATION_PERIOD_DAYS` unset on a testbed, and purge keys rather than leaving
them soft-deleted when you are done with them.

---

## Decision 2 — manual vs auto provisioning

### Manual (`NullKekProvisioner`, the default)

Someone (or something) creates the key in the vault before the
application tries to use it. Typical flows:

- **Azure Bicep / ARM templates / Terraform** — keys defined as IaC,
  reviewed in PRs, applied at deploy time.
- **Bootstrap script** — a one-off `az keyvault key create` per tenant.
- **Manual portal action** — admin opens the Azure portal and clicks
  through Generate/Import.

The application's identity only needs the **Key Vault Crypto User** role
(or, on Access Policy vaults, `get` + `encrypt` + `decrypt` permissions
on keys) — it cannot create keys, which is the safer posture for most
production deployments.

When a missing key is hit at runtime, the engine raises
`KekNotProvisionedError` with a translated user-facing message
("Encryption and decryption are unavailable for this data.") and an
English admin log entry naming the missing key and the strategy in use.
The Django admin **Reconcile Keys** page (described later) is the
operator workflow for catching this before users do.

### Auto (`AzureKekProvisioner`)

The application creates the key the first time a new silo
encrypts data. Typical use case: multi-tenant SaaS where new tenants
sign up mid-request and you don't want a manual provisioning step
blocking their first save.

The application's identity needs the **Key Vault Crypto Officer** role
(or `create` + `get` permissions on keys via Access Policy) in addition
to encrypt/decrypt. This is a wider blast radius — a compromised
application can create arbitrary keys in the vault, exhaust quotas, or
set unusual key parameters. Some compliance regimes forbid it.

### Combinations

| KEK choice | Provisioning | Per-tenant ops |
|---|---|---|
| Per-silo | Manual | New tenant ⇒ admin creates key in vault, then tenant can encrypt |
| Per-silo | Auto | New tenant ⇒ first encrypt creates the key; zero operator setup |

Either KEK strategy works here; the combinations below use per-silo
keys, which is the usual choice for multi-tenant deployments.

---

## Combination A — per-silo KEK, manual provisioning

Best fit: multi-tenant SaaS that needs per-tenant isolation but cannot
grant key-create rights to the application.

### Step 1: pick a naming convention

The convention is encoded as a template containing `{silo_uid}`.
Key Vault key names must match `[a-zA-Z0-9-]{1,127}`; the engine
sanitizes the silo UID with a **bijective** hex encoding before
substitution. Each character outside the allowed set is replaced by the
escape character (`-` for Azure) followed by the two-hex-digit value of
each UTF-8 byte; because `-` is itself the escape char, a separator hyphen
in the UID is doubled. The mapping is reversible, so e.g. `team-1` and
`team_1` can never collide.

```
encryption-suite-{silo_uid}
# silo_uid "team-42" -> "team--42"  (Azure's escape char is "-", so the
#                                    separator hyphen is doubled)
# resolved name:  encryption_suite-team--42
```

Remember Key Vault soft-delete: a name you create today is reserved for
the retention period (7–90 days) even after deletion. Pick a convention
that does not recycle names.

### Step 2: configure `ENCRYPTION`

```python
ENCRYPTION = {
    "KEY_SETS": {"default": {"silo": "...", "key_store": "azure"}},
    "KMS_KEY_STORES": {
        "azure": {
            "ADAPTER": "encryption_suite.adapters.key_stores.azure.AzureKeyVaultAdapter",
            "OPTIONS": {
                "AZURE_VAULT_ENDPOINT": "https://my-vault.vault.azure.net",
                "CREDENTIAL_STRATEGY": "managed_identity",
                "KEK_TEMPLATE": "encryption-suite-{silo_uid}",
            },
            "KEK_STRATEGY_ADAPTER": "encryption_suite.adapters.keks.PerSiloKekStrategy",
        },
    },
}
```

### Step 3: grant the runtime identity access

A vault-scoped role assignment covers every key in the vault, current
and future. With RBAC:

```bash
az role assignment create \
  --role "Key Vault Crypto User" \
  --assignee <app-managed-identity-object-id> \
  --scope $(az keyvault show --name my-vault --query id -o tsv)
```

If your security model requires per-key role assignments (no
vault-wide grant), you'll need to update RBAC each time a tenant is
added — Azure Bicep/Terraform-driven, ideally.

### Step 4: provisioning workflow per new tenant

For each new silo:

1. **Find out which key it needs.** Open the Django admin, go to
   **Data Encryption Keys → Reconcile Keys** (object-tools link,
   top right of the change list). Or visit:

   ```
   /admin/encryption_suite/dataencryptionkey/reconcile-keys/
   ```

   The page lists every silo, the resolved key name the
   application would try to use, and a **Needs setup** flag for those
   without a DEK row yet.

2. **Create the key.** Via Azure Bicep (preferred):

   ```bicep
   resource tenant42Key 'Microsoft.KeyVault/vaults/keys@2023-07-01' = {
     name: 'my-vault/encryption_suite-team--42'
     properties: {
       kty: 'oct-HSM'
       keySize: 256
       keyOps: [ 'encrypt', 'decrypt' ]
       attributes: { enabled: true }
       tags: { silo_uid: 'team-42' }
     }
   }
   ```

   Or via Azure CLI for one-offs:

   ```bash
   az keyvault key create \
     --vault-name my-vault \
     --name encryption_suite-team--42 \
     --kty oct-HSM \
     --size 256 \
     --ops encrypt decrypt \
     --tags silo_uid=team-42
   ```

3. **Verify on the admin page.** Refresh the Reconcile Keys page; the
   row's status changes to **Ready** once the DEK is created (immediately
   if you also run `setup_encryption_keys`, or on the next encrypt with
   `KEY_AUTO_PROVISION = True`).

4. **Trigger DEK creation.** With `KEY_AUTO_PROVISION = True` (default),
   the next encrypt for that tenant creates the DEK automatically.
   Otherwise:

   ```bash
   python manage.py setup_encryption_keys
   ```

Until the key exists, any encrypt for that tenant raises
`KekNotProvisionedError`. The translated user-facing message is
`"Encryption and decryption are unavailable for this data."`; the log
entry contains the missing key name and the silo UID.

---

## Combination B — per-silo KEK, auto provisioning

Best fit: multi-tenant SaaS that can grant key-create rights on a vault
and wants zero per-tenant manual steps.

### Step 1: configure `ENCRYPTION`

Same `OPTIONS` as Combination A, plus a provisioner:

```python
ENCRYPTION = {
    "KEY_SETS": {"default": {"silo": "...", "key_store": "azure"}},
    "KMS_KEY_STORES": {
        "azure": {
            "ADAPTER": "encryption_suite.adapters.key_stores.azure.AzureKeyVaultAdapter",
            "OPTIONS": {
                "AZURE_VAULT_ENDPOINT": "https://my-vault.vault.azure.net",
                "CREDENTIAL_STRATEGY": "managed_identity",
                "KEK_TEMPLATE": "encryption-suite-{silo_uid}",
            },
            "KEK_STRATEGY_ADAPTER": "encryption_suite.adapters.keks.PerSiloKekStrategy",

            "KEK_PROVISIONER_ADAPTER": "encryption_suite.adapters.keks.AzureKekProvisioner",
            "KEK_PROVISIONER_OPTIONS": {
                "AZURE_VAULT_ENDPOINT": "https://my-vault.vault.azure.net",
                "CREDENTIAL_STRATEGY": "managed_identity",   # may differ from OPTIONS
                "KEY_SIZE": 256,                             # or 128, 192
                "KEY_OPS": ["encrypt", "decrypt"],
                "KEK_ROTATION_PERIOD_DAYS": 180,             # optional; 7-day floor
                "TAGS": {"app": "encryption_suite", "env": "production"},
            },
        },
    },
}
```

`KEK_PROVISIONER_OPTIONS` is intentionally separate from `OPTIONS`
so that you can point the provisioner at a different identity or
different credentials than the runtime encrypt/decrypt path uses. In
most deployments they are the same, but separating them lets you e.g.
use a narrower runtime identity.

### Step 2: grant the application identity broader access

The **Key Vault Crypto Officer** role grants both create and
encrypt/decrypt — one role assignment covers everything:

```bash
az role assignment create \
  --role "Key Vault Crypto Officer" \
  --assignee <app-managed-identity-object-id> \
  --scope $(az keyvault show --name my-vault --query id -o tsv)
```

If your tenant requires more granular permissions, define a custom role
that grants exactly:

- `Microsoft.KeyVault/vaults/keys/create/action`
- `Microsoft.KeyVault/vaults/keys/read`
- `Microsoft.KeyVault/vaults/keys/encrypt/action`
- `Microsoft.KeyVault/vaults/keys/decrypt/action`
- `Microsoft.KeyVault/vaults/keys/delete` — to delete a key encryption key
- `Microsoft.KeyVault/vaults/keys/list/action` — for the Reconcile Keys page
- `Microsoft.KeyVault/vaults/keys/rotate/action` and the rotation-policy
  permissions — only if you set `KEK_ROTATION_PERIOD_DAYS`

The last three are for the key lifecycle, not for encryption. Without
`delete` the key is **retained** instead of destroyed, with the reason
recorded; without `list` reconcile
degrades to *detection-unavailable* rather than reporting silos as
orphaned; without the rotation permissions the key is still created and
used, and a warning naming the key and the interval says it will not
rotate on its own.

### Step 3: deploy and forget

Each new silo now triggers, on first encrypt:

1. `AzureKekProvisioner.ensure_kek` calls `KeyClient.get_key` for the
   resolved name.
2. If `ResourceNotFoundError`, checks that no soft-deleted key holds the
   name, then calls `create_oct_key`. On race (another process won),
   `get_key` succeeds the second time and is treated as success.
3. The new key encrypts a freshly generated DEK; the encrypted DEK is
   stored as a `DataEncryptionKey` row.
4. Subsequent encrypts skip provisioning (in-process cache + Key Vault
   already has the key).

The provisioner is idempotent and tolerates concurrent first-encrypts
in multi-process / multi-host deployments.

### Step 4: monitoring

Watch Key Vault's Azure Monitor logs for `KeyCreate` events on first
signup; spikes can mean something is hammering tenant creation. The
`encryption_suite` logger emits an `INFO`-level entry on each
successful provision:

```
AzureKekProvisioner: ensured KEK 'encryption_suite-team--42' for silo 'team-42'.
```

---

## Credential strategies

`AzureKeyVaultAdapter` and `AzureKekProvisioner` both support three
credential strategies, selected by `CREDENTIAL_STRATEGY`:

| Strategy | Use case |
|---|---|
| `managed_identity` | Uses `DefaultAzureCredential` from azure-identity. Tries Managed Identity, environment variables, Azure CLI, etc. in order. Recommended for Azure-hosted deployments (App Service, Functions, AKS). |
| `client_secret` | Explicit Azure AD app: `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`. Use only when Managed Identity is unavailable; the secret is static and rotation requires a redeploy. |
| `oidc` | AAD exchanges a platform-issued OIDC token for an AAD token through a federated identity credential (FIC) on the app, so no secret is stored. |

The right strategy depends on where the application runs:

- **On Azure compute** (App Service, Container Apps, AKS, a VM), use
  `managed_identity`. Prefer a user-assigned identity. Azure deletes a
  system-assigned identity along with the app, so recreating the app creates
  a new principal, and you must grant the vault role again.
- **Off Azure, where every instance presents the same `sub`**, use `oidc`.
  Azure matches a federated identity credential (FIC) on the exact `sub` and
  accepts no wildcards for issuers outside Microsoft, so one FIC covers the
  whole workload only when the subject is stable.
- **Off Azure, where `sub` names the individual instance**, use
  `client_secret`. Each instance would need its own FIC, an app holds at most
  20, and a new instance fails to authenticate until someone adds its FIC.

For `oidc`, add a FIC to the app registration for each subject:

```bash
az ad app federated-credential create --id <app-id> --parameters '{
  "name": "<credential-name>",
  "issuer": "<issuer-url>",
  "subject": "<subject>",
  "audiences": ["api://AzureADTokenExchange"]
}'
```

**On Fly.io**, `sub` is `<org>:<app>:<machine-name>`, so each machine needs
its own FIC, and an app that scales is better served by `client_secret`. See
[Fly.io as an OIDC token source](getting-started-fly.md#flyio-as-an-oidc-token-source).

> **`managed_identity` trap — stray `AZURE_*` env vars silently win.**
> `DefaultAzureCredential` walks an ordered chain, and **EnvironmentCredential
> is first**. If `AZURE_TENANT_ID` + `AZURE_CLIENT_ID` + `AZURE_CLIENT_SECRET`
> are all present in the process environment, it authenticates as that AD app
> and **never reaches the managed identity** — no error, you simply get the
> wrong principal (and a confusing `Forbidden`/`KekNotProvisioned` later if that
> app lacks the vault role). On Azure compute, set **only** `AZURE_CLIENT_ID`
> (the user-assigned managed identity's *client* id, so the chain targets the
> right identity when more than one could apply) and leave `AZURE_CLIENT_SECRET`
> / `AZURE_TENANT_ID` unset. A system-assigned identity needs none of them.
> Confirm from the logs that the token came from the managed identity, not the
> environment.

See [KMS adapters](kms-adapters.md) and the docstrings in
`adapters/credentials/azure.py` for the full required-options list per
strategy.

---

## The Reconcile Keys admin page

For Combination A in particular, this page is the operator workflow. It lists
every silo with the key name resolved from the template, flags the ones whose
first encryption is still pending, and shows the strategy and provisioner in
effect so you can confirm which combination is live. See
[Reconcile Keys page](admin-panel.md#reconcile-keys-page) for the full
description and the three ways to reach it.

The intended workflow with `NullKekProvisioner`:

1. New tenant signs up.
2. Admin opens the Reconcile Keys page.
3. Copies the resolved name (e.g. `encryption_suite-team--42`) into their
   Key Vault portal / Azure Bicep / `az` script.
4. Creates the key in the vault.
5. The next encrypt for that tenant creates the DEK automatically (with
   `KEY_AUTO_PROVISION = True`) and the row flips to **Ready**.

---

## Deleting a key encryption key

Deleting a KEK here is Key Vault's **soft delete**: the key leaves the vault
listing, becomes unusable for everything but recovery, and Key Vault purges it at
the end of the vault's retention period. It is the same shape as an AWS key
inside its pending-deletion window.

Four things to know before the first deletion:

- **The Reconcile Keys page keeps showing a soft-deleted key.** Its deletion has
  not finished while it is still recoverable. The key dropping out of the listing
  at purge is what confirms the deletion completed.
- **The vault decides how long that takes.** `softDeleteRetentionInDays` is set
  when the vault is created (7 to 90 days) and cannot be changed afterwards.
  `PROVIDER_DELETION_WINDOW_DAYS` is refused by this provisioner precisely
  because nothing it sends could alter that period. See
  [the two deletion windows](kek-provisioning.md#the-two-deletion-windows).
- **The name stays reserved for the whole period**, so a silo pointed at that
  name cannot provision until the key is recovered or purged.
- **A soft-deleted key stops billing**, unlike an AWS key in its pending window.

To reclaim a name sooner, purge it by hand — `az keyvault key purge --name <key>
--vault-name <vault>` — which needs the separate **Key Vault Purge Operator**
role and is refused outright on a vault with purge protection enabled.

---

## Rotating a key encryption key

Rotation is supported and needs no re-wrapping to keep existing data readable.
Each DEK row records the key version that wrapped it, so adding a version leaves
old rows decryptable while new wraps use the new version.

Set `KEK_ROTATION_PERIOD_DAYS` in `KEK_PROVISIONER_OPTIONS` and the provisioner puts
a rotation policy on each key it creates. Key Vault's floor is 7 days, and Azure
bills per scheduled rotation.

To rotate on demand, add a version:

```bash
az keyvault key create --vault-name my-vault --name encryption_suite-team--42 --kty oct-HSM --size 256 --ops encrypt decrypt
```

Creating over an existing name adds a version rather than replacing the key. The
portal's **Rotate Now** button is not offered for symmetric keys, and its Create
Version dialog lists only the asymmetric types — both are gaps in the preview's
portal support, not in the service. Azure Cloud Shell has `az` preinstalled if
you would rather not install it locally.

Two things to know when you verify a rotation:

- **Tags do not carry to the new version.** Key Vault holds them per version, and
  this package writes them at creation, so a rotated key's current version is
  untagged. With a rotation policy configured that happens on a schedule.
- **Restart the application (or wait out `DEK_CACHE_TTL`) before concluding
  anything.** `reencrypt_keys` invalidates the key cache in its own process; the
  web workers keep serving a cached primitive, so a read after the re-wrap may
  never reach Azure. Nothing is at risk — re-wrapping does not change the
  plaintext DEK, so a cached primitive stays correct — but the read proves
  nothing until the cache is cold.

After rotating, run [`reencrypt_keys`](management-commands.md) to move existing
DEKs onto the new version. **Leave the old version enabled until it finishes** —
anything still wrapped under it cannot be read otherwise. A worker picks up a new
version within `KEY_VERSION_TTL_SECONDS` (default 300), so wraps continue under
the old version for up to that long after the rotation.

---

## Failure modes and what they look like

### Key missing in the vault

`KekNotProvisionedError` is raised by the engine. The user sees:

> Encryption and decryption are unavailable for this data.

The admin sees an `ERROR`-level log entry naming the resolved key name,
the silo UID, the strategy, and the provisioner. With
`NullKekProvisioner` the message points to provisioning outside this application;
with `AzureKekProvisioner` the message also names the underlying Azure
error (e.g. `Forbidden` if the identity lacks
`Microsoft.KeyVault/vaults/keys/create/action`).

### Soft-deleted key collision

If you (or someone before you) deleted a key with the same name within the
retention window, the name is still reserved. The provisioner detects this
before attempting the creation and raises `KekPendingDeletionError` naming
the scheduled purge date, rather than letting Key Vault return
`Conflict: A key with this name is currently in a deleted state` about a
key that does not appear in the vault listing. Recover the key
(`az keyvault key recover`), purge it, or point the silo at a different
name — the collision itself is Key Vault platform behavior and cannot be
worked around.

### Identity has no token

`DefaultAzureCredential` raises `CredentialUnavailableError` when no
authentication source succeeds. Most common cause: running locally
without `az login`, or running on an Azure host where Managed Identity
is not assigned.

### Wrong vault URL

`AzureKeyVaultAdapter` does not infer the vault — `AZURE_VAULT_ENDPOINT`
must be set explicitly. A typo points at a non-existent DNS name;
azure-identity surfaces a generic resolution error.

---

## Related reading

- [KEK strategies](kek-strategies.md) — full strategy reference, including
  cohort and BYOK.
- [KEK provisioning](kek-provisioning.md) — strategy-vs-provisioner split,
  the full provisioner table, and writing custom provisioners.
- [KMS adapters](kms-adapters.md) — adapter / credential strategy
  reference for Azure and the other providers.
- [Configuration reference](configuration.md) — every `ENCRYPTION`
  setting, including `KEY_AUTO_PROVISION`, `DEK_CACHE_TTL`, and
  `LOG_DECRYPTS`.
- [Key rotation](key-rotation.md) — rotating KEKs and re-encrypting.
- [Getting started with AWS KMS](getting-started-aws.md) and
  [Getting started with GCP Cloud KMS](getting-started-gcp.md) — same
  workflow shape, other providers.
