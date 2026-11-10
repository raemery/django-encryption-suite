# Getting started with GCP Cloud KMS

This step-by-step guide walks you through wiring django-encryption-suite to GCP Cloud KMS in
production. This page assumes you have already followed
[Getting started](getting-started.md) for the basic Django setup
(`INSTALLED_APPS`, migrations, a silo adapter) and now need to swap
the local dev KMS for real Cloud KMS.

The two decisions that drive everything else on this page:

1. **Shared KEK or per-silo KEK?**
   One CryptoKey for the whole application vs. one CryptoKey per
   tenant/team.
2. **Auto-provision or manual?**
   Let the application create CryptoKeys on first encrypt vs. provision
   them outside this application (Terraform / IaC / console) before the application
   sees them.

The rest of this guide walks through each combination end-to-end.

---

## Prerequisites

- A GCP project and a Cloud KMS location you intend to deploy in
  (this guide uses project `my-project` and location `us-central1`).
- The Cloud KMS API enabled in that project:

  ```bash
  gcloud services enable cloudkms.googleapis.com --project=my-project
  ```

- Permission to create at least one **key ring** in that project, and
  the ability to grant Cloud KMS IAM roles on it.
- The extra installed. Use `gcp` for `GcpKmsAdapter`, or `gcp-tink`
  for `GcpTinkKmsAdapter` (it additionally pulls in `google-cloud-kms`,
  which Tink's GCP integration requires):

  ```bash
  uv add 'django-encryption-suite[gcp]'        # GcpKmsAdapter
  uv add 'django-encryption-suite[gcp-tink]'   # GcpTinkKmsAdapter
  ```

- A working `ENCRYPTION` block in `settings.py` from
  [Getting started](getting-started.md). You will replace the
  env key store configuration with a `GcpKmsAdapter` block below.

### A note on key rings

GCP groups CryptoKeys inside **key rings**. Key rings belong to a single
location (regional, multi-regional, or `global`), and **cannot be
deleted** once created. CryptoKeys cannot be deleted either — only key
versions can be scheduled for destruction (with a 24-hour to 30-day
delay).

This means:

- You only need one key ring per environment per location. Reuse it.
- Pick the location carefully — keys cannot move between locations.
  Choose the region nearest the host the application runs on to keep KMS
  round-trips low. There may be no GCP region in your exact area — pick
  the closest one. `global` is a multi-region and convenient but not the
  lowest latency.
- The auto-provisioner does not create key rings (granting
  `cloudkms.keyRings.create` to app runtimes is rarely justified). The
  ring must already exist before the application starts.

---

## Running the setup commands: gcloud, Cloud Shell, or Console

The path validated end-to-end for this guide is **gcloud run from
Cloud Shell** — the browser terminal in the Console, with gcloud
pre-installed and nothing to install locally. It is the most reliable
option: it needs no local toolchain and is unaffected by the Console UI
issue described below.

The only step verified through the Console UI here is enabling the API:

| Setup step | Console location |
|---|---|
| Enable the Cloud KMS API | APIs & Services → Library → "Cloud Key Management Service API" → Enable |

Every other step in this guide (key ring, CryptoKey, IAM bindings,
service account, custom role, JSON key) was performed with gcloud in
Cloud Shell. Those features do exist in the Console — under Security →
Key Management and IAM & Admin — but the Key Management pages can fail to
load (see the first note below), so this guide does not document a
click-through path for them. If you prefer the Console, try those areas,
and fall back to Cloud Shell if a page does not load.

If the **Security → Key Management** page does not show your key rings
(a redirect to the API page, or an empty list despite rings existing),
it usually means the Cloud KMS API is not enabled on the selected
project or the account lacks a Cloud KMS viewer role. Cloud Shell
sidesteps this — `gcloud kms keyrings list --location=<loc>` confirms the
rings directly.

---

## Choosing the adapter variant: GcpKmsAdapter vs GcpTinkKmsAdapter

Two GCP Cloud KMS adapters ship with django-encryption-suite, and they are
interchangeable from the engine's perspective:

| Adapter | `ADAPTER` value | Provider ID |
|---|---|---|
| `GcpKmsAdapter` | `encryption_suite.adapters.key_stores.gcp.GcpKmsAdapter` | `"gcp"` |
| `GcpTinkKmsAdapter` | `encryption_suite.adapters.key_stores.gcp_tink.GcpTinkKmsAdapter` | `"gcp-tink"` |

Both call Cloud KMS, support `KEK_TEMPLATE` / `KEK_MAP` / `SHARED_KEK_ID`,
and work with `GcpKekProvisioner`. The deciding difference is
**authentication**: `GcpKmsAdapter` exposes a pluggable
`CREDENTIAL_STRATEGY` (Application Default Credentials, explicit
service-account JSON, or keyless OIDC via Workload Identity Federation),
while `GcpTinkKmsAdapter` always uses ADC and must run on GCP itself.
`GcpTinkKmsAdapter` also stores Tink's own ciphertext envelope on the
wire rather than the raw Cloud KMS ciphertext.

**`GcpKmsAdapter` is the usual choice** — it works on or off GCP, and is
the only option for keyless OIDC from a non-GCP host (e.g. Fly.io with
`CREDENTIAL_STRATEGY: "oidc"`). The rest of this page documents
`GcpKmsAdapter`.

**Choose `GcpTinkKmsAdapter` only if** you deploy on GCP (Cloud Run, GKE,
Compute Engine) *and* have a business reason for Tink (organizational
crypto standard, or wanting Tink's envelope format on the wire). It is
documented separately, since its auth model and setup differ:
**[Getting started with GCP Cloud KMS via Tink](getting-started-gcp-tink.md)**.

> **Ciphertext is not interchangeable between the two adapters.** Only the
> adapter that wrapped a DEK can unwrap it, so each key row records the name of
> the `KMS_KEY_STORES` block that wrapped it. To switch adapters on an existing
> deployment, configure both as separate blocks, point the key set's `key_store` at the new one,
> and run `reencrypt_keys` — see
> [Moving to another KMS](key-rotation.md#moving-to-another-kms).

---

## Decision 1 — shared vs per-silo KEK

### Shared KEK

One Cloud KMS CryptoKey encrypts every silo's DEK. Simpler
operationally; one IAM binding, one key to rotate, one key to monitor in
Cloud Audit Logs. The trade-off is blast radius: if that single key is
compromised or accidentally destroyed, every tenant's encrypted data is
at risk simultaneously.

Pick this when:

- You have a single-tenant deployment (one organization, many teams that
  don't need cryptographic isolation between them).
- You want the lightest operational footprint and the per-tenant blast
  radius is not a compliance requirement.

### Per-silo KEK

Each tenant/team gets its own CryptoKey. Compromise or destruction of
one key affects only that tenant. Required by some compliance regimes
(HIPAA multi-tenant scenarios, customer-managed encryption keys for B2B
contracts). Costs scale with key count: GCP charges per active key
version per month plus per-API-call.

Pick this when:

- You're a multi-tenant SaaS where tenants must be cryptographically
  isolated.
- You need to demonstrate per-tenant key custody to auditors.
- You want the option to revoke a single tenant's data by destroying
  one key's versions.

### Settings mapping

| Choice | `KEK_STRATEGY_ADAPTER` | `OPTIONS` key |
|---|---|---|
| Shared | `SharedKekStrategy` | `SHARED_KEK_ID` (CryptoKey name within the ring) |
| Per-silo | `PerSiloKekStrategy` | `KEK_TEMPLATE` (or `KEK_MAP`) |

The `SHARED_KEK_ID` and `KEK_TEMPLATE` values are CryptoKey **names**
within the configured ring (e.g. `encryption_suite` or
`encryption_suite-{silo_uid}`) — not full resource paths. The adapter
combines them with `GCP_PROJECT_ID`, `GCP_KMS_LOCATION`, and
`GCP_KMS_KEY_RING` to build the full path at request time.

---

## Decision 2 — manual vs auto provisioning

### Manual (`NullKekProvisioner`, the default)

Someone (or something) creates the CryptoKey before the application
tries to use it. Typical flows:

- **Terraform** — keys defined as IaC, reviewed in PRs, applied at
  deploy time.
- **Bootstrap script** — a one-off `gcloud kms keys create` per tenant.
- **Manual console action** — admin opens the GCP console and clicks
  through Create Key.

The application's service account only needs
`cloudkms.cryptoKeyEncrypterDecrypter` on the ring (or specific keys) —
it cannot create keys, which is the safer posture for most production
deployments.

When a missing key is hit at runtime, the engine raises
`KekNotProvisionedError` with a translated user-facing message
("Encryption and decryption are unavailable for this data.") and an
English admin log entry naming the missing key and the strategy in use.
The Django admin **Reconcile Keys** page (described later) is the
operator workflow for catching this before users do.

### Auto (`GcpKekProvisioner`)

The application creates the CryptoKey the first time a new silo
encrypts data. Typical use case: multi-tenant SaaS where new tenants
sign up mid-request and you don't want a manual provisioning step
blocking their first save.

The application's service account needs `cloudkms.cryptoKeys.create` and
`cloudkms.cryptoKeys.get` on the **ring** in addition to encrypt/decrypt
on the keys. This is a wider blast radius — a compromised application
can create arbitrary keys in the ring, exhaust quotas, or set rotation
periods however it likes. Some compliance regimes forbid it.

### Combinations

| KEK choice | Provisioning | Per-tenant ops |
|---|---|---|
| Shared | Manual | Create one CryptoKey once, configure name, done |
| Shared | Auto | Rare — one key only, manual is just as easy |
| Per-silo | Manual | New tenant ⇒ admin creates CryptoKey in ring, then tenant can encrypt |
| Per-silo | Auto | New tenant ⇒ first encrypt creates the CryptoKey; zero operator setup |

The four combinations below give you concrete `settings.py` snippets and
operator workflows for each.

---

## Combination A — shared KEK, manual provisioning

Best fit: small / single-tenant deployments.

### Step 1: create the key ring and CryptoKey

Either via Terraform:

```hcl
resource "google_kek_ring" "encryption_suite" {
  name     = "encryption_suite-prod"
  location = "us-central1"
  project  = "my-project"
}

resource "google_kms_crypto_key" "shared" {
  name            = "encryption_suite"
  key_ring        = google_kek_ring.encryption_suite.id
  purpose         = "ENCRYPT_DECRYPT"
  rotation_period = "7776000s"   # 90 days

  version_template {
    algorithm        = "GOOGLE_SYMMETRIC_ENCRYPTION"
    protection_level = "SOFTWARE"
  }

  labels = { app = "encryption_suite", env = "production" }
}
```

Or via gcloud:

```bash
gcloud kms keyrings create encryption_suite-prod \
  --location=us-central1 --project=my-project

gcloud kms keys create encryption_suite \
  --location=us-central1 \
  --keyring=encryption_suite-prod \
  --purpose=encryption \
  --rotation-period=90d \
  --next-rotation-time=$(date -u -d '+90 days' +%Y-%m-%dT%H:%M:%SZ) \
  --project=my-project
```

### Step 2: grant the application service account access

```bash
gcloud kms keys add-iam-policy-binding encryption_suite \
  --location=us-central1 \
  --keyring=encryption_suite-prod \
  --member="serviceAccount:encryption_suite-app@my-project.iam.gserviceaccount.com" \
  --role="roles/cloudkms.cryptoKeyEncrypterDecrypter" \
  --project=my-project
```

### Step 3: configure `ENCRYPTION`

```python
ENCRYPTION = {
    "KEY_SETS": {"default": {"silo": "...", "key_store": "gcp"}},  # whatever you use
    "KMS_KEY_STORES": {
        "gcp": {
            "ADAPTER": "encryption_suite.adapters.key_stores.gcp.GcpKmsAdapter",
            "OPTIONS": {
                "GCP_PROJECT_ID": "my-project",
                "GCP_KMS_LOCATION": "us-central1",
                "GCP_KMS_KEY_RING": "encryption_suite-prod",
                "CREDENTIAL_STRATEGY": "adc",      # default for non-Fly hosts
                "SHARED_KEK_ID": "encryption_suite",
            },
            "KEK_STRATEGY_ADAPTER": "encryption_suite.adapters.keks.SharedKekStrategy",
            # KEK_PROVISIONER_ADAPTER omitted — defaults to NullKekProvisioner
        },
    },
}
```

The adapter resolves `SHARED_KEK_ID` against the configured project /
location / ring to form the full resource path
`projects/my-project/locations/us-central1/keyRings/encryption_suite-prod/cryptoKeys/encryption_suite`.

### Step 4: create DEKs

Each silo still needs its own DEK row, encrypted under the shared
KEK. Either let the engine create them lazily on first encrypt
(`KEY_AUTO_PROVISION = True`, the default) or pre-create them in bulk:

```bash
python manage.py setup_encryption_keys
```

That's it. The application is now encrypting under one shared CryptoKey.

---

## Combination B — per-silo KEK, manual provisioning

Best fit: multi-tenant SaaS that needs per-tenant isolation but cannot
grant `cloudkms.cryptoKeys.create` to the application.

### Step 1: pick a naming convention

The convention is encoded as a template containing `{silo_uid}`.
GCP CryptoKey names must match `[a-zA-Z0-9_-]{1,63}`. The engine
sanitizes the silo UID into that set with a **bijective**
(reversible) encoding before substitution: allowed characters pass
through unchanged, and any other character is encoded as its UTF-8 bytes,
each byte written as `_` followed by two lowercase hex digits (a literal
`_` is itself doubled to `__`).

```
encryption_suite-{silo_uid}
# silo_uid "team-1" matches [a-zA-Z0-9_-] — used unchanged
# (a char outside the set would be hex-escaped, e.g. "@" -> "_40")
# resolved name:  encryption_suite-team-1
```

### Step 2: configure `ENCRYPTION`

```python
ENCRYPTION = {
    "KEY_SETS": {"default": {"silo": "...", "key_store": "gcp"}},
    "KMS_KEY_STORES": {
        "gcp": {
            "ADAPTER": "encryption_suite.adapters.key_stores.gcp.GcpKmsAdapter",
            "OPTIONS": {
                "GCP_PROJECT_ID": "my-project",
                "GCP_KMS_LOCATION": "us-central1",
                "GCP_KMS_KEY_RING": "encryption_suite-prod",
                "CREDENTIAL_STRATEGY": "adc",
                "KEK_TEMPLATE": "encryption_suite-{silo_uid}",
            },
            "KEK_STRATEGY_ADAPTER": "encryption_suite.adapters.keks.PerSiloKekStrategy",
        },
    },
}
```

### Step 3: grant the runtime service account access

Bind `cloudkms.cryptoKeyEncrypterDecrypter` at the **ring** level so a
single binding covers every tenant key created within it:

```bash
gcloud kms keyrings add-iam-policy-binding encryption_suite-prod \
  --location=us-central1 \
  --member="serviceAccount:encryption_suite-app@my-project.iam.gserviceaccount.com" \
  --role="roles/cloudkms.cryptoKeyEncrypterDecrypter" \
  --project=my-project
```

If your security model requires per-key bindings (no ring-wide grant),
you'll need to update IAM each time a tenant is added — Terraform-driven,
ideally.

### Step 4: provisioning workflow per new tenant

For each new silo:

1. **Find out which key it needs.** Open the Django admin, go to
   **Data Encryption Keys → Reconcile Keys** (object-tools link,
   top right of the change list). Or visit:

   ```
   /admin/encryption_suite/dataencryptionkey/reconcile-keys/
   ```

   The page lists every silo, the resolved CryptoKey name the
   application would try to use, and a **Needs setup** flag for those
   without a DEK row yet.

2. **Create the CryptoKey.** Via Terraform (preferred):

   ```hcl
   resource "google_kms_crypto_key" "tenant_42" {
     name            = "encryption_suite-team-42"
     key_ring        = google_kek_ring.encryption_suite.id
     purpose         = "ENCRYPT_DECRYPT"
     rotation_period = "7776000s"   # 90 days

     version_template {
       algorithm        = "GOOGLE_SYMMETRIC_ENCRYPTION"
       protection_level = "SOFTWARE"
     }

     labels = { silo_uid = "team-42" }
   }
   ```

   Or via gcloud for one-offs:

   ```bash
   gcloud kms keys create encryption_suite-team-42 \
     --location=us-central1 \
     --keyring=encryption_suite-prod \
     --purpose=encryption \
     --rotation-period=90d \
     --next-rotation-time=$(date -u -d '+90 days' +%Y-%m-%dT%H:%M:%SZ) \
     --project=my-project
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

Until the CryptoKey exists, any encrypt for that tenant raises
`KekNotProvisionedError`. The translated user-facing message is
`"Encryption and decryption are unavailable for this data."`; the log
entry contains the missing key name and the silo UID.

---

## Combination C — per-silo KEK, auto provisioning

Best fit: multi-tenant SaaS that can grant `cloudkms.cryptoKeys.create`
on a ring and wants zero per-tenant manual steps.

### Step 1: configure `ENCRYPTION`

Same `OPTIONS` as Combination B, plus a provisioner:

```python
ENCRYPTION = {
    "KEY_SETS": {"default": {"silo": "...", "key_store": "gcp"}},
    "KMS_KEY_STORES": {
        "gcp": {
            "ADAPTER": "encryption_suite.adapters.key_stores.gcp.GcpKmsAdapter",
            "OPTIONS": {
                "GCP_PROJECT_ID": "my-project",
                "GCP_KMS_LOCATION": "us-central1",
                "GCP_KMS_KEY_RING": "encryption_suite-prod",
                "CREDENTIAL_STRATEGY": "adc",
                "KEK_TEMPLATE": "encryption_suite-{silo_uid}",
            },
            "KEK_STRATEGY_ADAPTER": "encryption_suite.adapters.keks.PerSiloKekStrategy",

            "KEK_PROVISIONER_ADAPTER": "encryption_suite.adapters.keks.GcpKekProvisioner",
            "KEK_PROVISIONER_OPTIONS": {
                "GCP_PROJECT_ID": "my-project",
                "GCP_KMS_LOCATION": "us-central1",
                "GCP_KMS_KEY_RING": "encryption_suite-prod",
                "CREDENTIAL_STRATEGY": "adc",       # may differ from OPTIONS
                "PURPOSE": "ENCRYPT_DECRYPT",       # default
                "ALGORITHM": "GOOGLE_SYMMETRIC_ENCRYPTION",
                "PROTECTION_LEVEL": "SOFTWARE",     # or "HSM"
                "KEK_ROTATION_PERIOD_DAYS": 90,
                "TAGS": {"app": "encryption_suite", "env": "production"},
            },
        },
    },
}
```

`KEK_PROVISIONER_OPTIONS` is intentionally separate from `OPTIONS`
so that you can point the provisioner at a different service account or
different credentials than the runtime encrypt/decrypt path uses. In
most deployments they are the same, but separating them lets you e.g.
use a narrower runtime account.

The provisioner needs `GCP_PROJECT_ID`, `GCP_KMS_LOCATION`, and
`GCP_KMS_KEY_RING` of its own because it constructs Cloud KMS resource
paths independently of the adapter — this lets you provision into a
different ring than the runtime reads from, in advanced deployments
(uncommon).

### Step 2: grant the application service account broader access

Two bindings are needed: encrypt/decrypt on the keys, plus create/get on
the ring.

```bash
# Encrypt/decrypt on every key in the ring (current and future).
gcloud kms keyrings add-iam-policy-binding encryption_suite-prod \
  --location=us-central1 \
  --member="serviceAccount:encryption_suite-app@my-project.iam.gserviceaccount.com" \
  --role="roles/cloudkms.cryptoKeyEncrypterDecrypter" \
  --project=my-project

# Create new keys in the ring + read existing ones (for the idempotency probe).
# The GCP-managed `roles/cloudkms.admin` role is too broad; bind a custom role
# with exactly cloudkms.cryptoKeys.create and cloudkms.cryptoKeys.get.
```

A custom role definition (apply with `gcloud iam roles create`):

```yaml
title: "encryption_suite KEK provisioner"
description: "Create and read CryptoKeys for django-encryption-suite auto-provisioning"
stage: GA
includedPermissions:
  - cloudkms.cryptoKeys.create
  - cloudkms.cryptoKeys.get
  # Key lifecycle — omit these to keep the application out of key destruction.
  - cloudkms.cryptoKeys.list
  - cloudkms.cryptoKeyVersions.list
  - cloudkms.cryptoKeyVersions.destroy
  - cloudkms.cryptoKeyVersions.update
  - cloudkms.cryptoKeys.update
```

The first two permissions are all provisioning needs. The rest cover the key
lifecycle, and leaving them out is a defensible choice if your organization does
not allow the application to destroy keys:

- Without `cryptoKeyVersions.destroy` and `cryptoKeyVersions.update`, a deleted
  tenant's key is *retained* — the deletion run records the refusal and the key keeps
  costing money until you destroy it by hand. Versions are disabled before being
  destroyed, which is what the `constraints/cloudkms.disableBeforeDestroy` org
  policy requires, so `update` is needed alongside `destroy`.
- Without `cryptoKeys.list` and `cryptoKeyVersions.list`, the Reconcile Keys page
  reports the KMS side as detection-unavailable: no orphaned key encryption keys,
  no live existence column, and no confirmation that a destroyed key is really
  gone.
- `cryptoKeys.update` is only used to clear a rotation schedule at deletion time.
  It is unnecessary if no key sets `KEK_ROTATION_PERIOD_DAYS` — but with rotation
  configured and this permission missing, Cloud KMS adds a fresh enabled version
  to a key the application just destroyed, and the deletion silently undoes
  itself.

Bind it to the ring:

```bash
gcloud kms keyrings add-iam-policy-binding encryption_suite-prod \
  --location=us-central1 \
  --member="serviceAccount:encryption_suite-app@my-project.iam.gserviceaccount.com" \
  --role="projects/my-project/roles/encryption_suiteKekProvisioner" \
  --project=my-project
```

### Step 3: deploy and forget

Each new silo now triggers, on first encrypt:

1. `GcpKekProvisioner.ensure_kek` calls `cryptoKeys.get` for the resolved
   key name.
2. If 404, calls `cryptoKeys.create` (returns 409 if a concurrent
   process won the race — treated as success).
3. The new CryptoKey encrypts a freshly generated DEK; the encrypted DEK
   is stored as a `DataEncryptionKey` row.
4. Subsequent encrypts skip provisioning (in-process cache + Cloud KMS
   already has the key).

The provisioner is idempotent and tolerates `409 ALREADY_EXISTS` from
concurrent first-encrypts in multi-process / multi-host deployments.

### Step 4: monitoring

Watch Cloud Audit Logs for `CreateCryptoKey` events on first signup;
spikes can mean something is hammering tenant creation. The
`encryption_suite` logger emits an `INFO`-level entry on each
successful provision:

```
GcpKekProvisioner: created KEK 'encryption_suite-team-42' for silo 'team-42'.
```

---

## Combination D — shared KEK, auto provisioning

Rarely useful in production. With a shared KEK there is exactly one
CryptoKey to create; doing that via Terraform once is faster than
configuring a provisioner. Provided for completeness — same shape as
Combination C but with `SharedKekStrategy` and a single `SHARED_KEK_ID`.

If you do need it (e.g. a one-shot dev environment that creates its
shared key on first boot), set `SHARED_KEK_ID` to the CryptoKey name
the provisioner should create:

```python
"OPTIONS": {
    "GCP_PROJECT_ID": "my-project",
    "GCP_KMS_LOCATION": "us-central1",
    "GCP_KMS_KEY_RING": "encryption_suite-prod",
    "SHARED_KEK_ID": "encryption_suite",
},
"KEK_STRATEGY_ADAPTER": "encryption_suite.adapters.keks.SharedKekStrategy",
"KEK_PROVISIONER_ADAPTER": "encryption_suite.adapters.keks.GcpKekProvisioner",
"KEK_PROVISIONER_OPTIONS": {
    "GCP_PROJECT_ID": "my-project",
    "GCP_KMS_LOCATION": "us-central1",
    "GCP_KMS_KEY_RING": "encryption_suite-prod",
},
```

The provisioner is called once per silo (which always resolves to
the same name), so the in-process cache makes this near-free after the
first call.

---

## Credential strategies

`GcpKmsAdapter` and `GcpKekProvisioner` both support three credential
strategies, selected by `CREDENTIAL_STRATEGY` in their respective
options dicts:

| Strategy | Use case |
|---|---|
| `adc` | Application Default Credentials. Works on Cloud Run, GKE, Compute Engine, and locally with `gcloud auth application-default login`. Recommended for GCP-hosted deployments. |
| `service_account_key` | Explicit service account JSON key, either a file path (`SERVICE_ACCOUNT_KEY_FILE`) or inline JSON (`SERVICE_ACCOUNT_KEY_JSON`). Use when ADC is unavailable — e.g. any non-GCP host. |
| `oidc` | OIDC JWT → GCP STS token exchange + service-account impersonation (Workload Identity Federation). Keyless auth from outside GCP. Requires `OIDC_SOURCE` (e.g. `"fly"`) — see [OIDC token sources](kms-adapters.md#oidc-token-sources). |

If `CREDENTIAL_STRATEGY` is unset, both `GcpKmsAdapter` and
`GcpKekProvisioner` default to `adc`. The `oidc` strategy must be opted
into explicitly along with an `OIDC_SOURCE`.

> **ADC is only available on GCP-hosted runtimes (or a work station
> running `gcloud auth application-default login`).** Application Default
> Credentials read a GCP metadata server or a locally cached credential
> file; neither exists on a non-GCP host such as Fly.io, Render, or
> another cloud. On those hosts the `adc` default fails at the first KMS
> call — use `service_account_key` or `oidc` instead. The snippets above
> use `adc` for brevity; swap in one of the following on a non-GCP host.

### Running on Cloud Run

On Cloud Run, ADC resolves to the service's runtime service account through
the metadata server, so `adc` needs no settings beyond the default. Create a
service account, grant it the Cloud KMS roles for your combination, and deploy
the service with it:

```bash
gcloud run deploy my-app --image <image> --service-account encryption_suite-app@my-project.iam.gserviceaccount.com
```

With auto provisioning, the first encrypt for a new silo creates its key in
the key ring under that service account.

### Other GCP runtimes

`adc` works the same way on any GCP runtime where the workload runs as a
service account, such as Compute Engine or GKE. The package needs no other
settings: give that service account the Cloud KMS roles for your combination,
and the adapter and provisioner pick it up. How the workload gets its service
account is platform setup. A GKE pod, for example, has none by default, so
it needs Google's
[Workload Identity Federation for GKE](https://cloud.google.com/kubernetes-engine/docs/how-to/workload-identity).

### `service_account_key` example

Set `CREDENTIAL_STRATEGY` to `service_account_key` and supply the key as
inline JSON (recommended for secret managers) or a file path. The same
keys apply to both `OPTIONS` and `KEK_PROVISIONER_OPTIONS`:

```python
"OPTIONS": {
    "GCP_PROJECT_ID": "my-project",
    "GCP_KMS_LOCATION": "us-east4",
    "GCP_KMS_KEY_RING": "encryption_suite",
    "KEK_TEMPLATE": "encryption_suite-{silo_uid}",
    "CREDENTIAL_STRATEGY": "service_account_key",
    "SERVICE_ACCOUNT_KEY_JSON": env("GCP_SA_KEY_JSON"),  # inline JSON
    # or, instead of the line above:
    # "SERVICE_ACCOUNT_KEY_FILE": "/run/secrets/gcp-sa.json",
},
```

Pass the JSON in through your platform's secret store rather than committing
it. Load the file directly, for example with `"$(cat encryption_suite-sa.json)"`
as the value, so nobody has to paste the credential by hand. Delete the local
key file once the secret store holds it. `service_account_key` is a
long-lived credential; prefer `oidc` (keyless) where the host supports it.

### `oidc` example (Workload Identity Federation)

Keyless: the host issues a short-lived OIDC JWT, the adapter exchanges it
with GCP STS, then impersonates a service account to get a Cloud KMS
token. No downloadable key to store or rotate. The steps below work for any
source in [OIDC token sources](kms-adapters.md#oidc-token-sources); the
comments give the Fly.io values, and
[Fly.io as an OIDC token source](getting-started-fly.md#flyio-as-an-oidc-token-source)
explains them.

The same option block goes in both `OPTIONS` and
`KEK_PROVISIONER_OPTIONS`:

```python
"OPTIONS": {
    "GCP_PROJECT_ID": "my-project",
    "GCP_KMS_LOCATION": "us-east4",
    "GCP_KMS_KEY_RING": "encryption_suite",
    "KEK_TEMPLATE": "encryption_suite-{silo_uid}",
    "CREDENTIAL_STRATEGY": "oidc",
    "OIDC_SOURCE": "<source>",                                # "fly" on Fly.io
    "GCP_PROJECT_NUMBER": env("GCP_PROJECT_NUMBER"),          # numeric, not the project ID
    "GCP_WORKLOAD_IDENTITY_POOL_ID": env("GCP_WIF_POOL_ID"),
    "GCP_WORKLOAD_IDENTITY_PROVIDER_ID": env("GCP_WIF_PROVIDER_ID"),
    "GCP_SERVICE_ACCOUNT_EMAIL": env("GCP_SERVICE_ACCOUNT_EMAIL"),
},
```

**Prerequisite — enable the IAM Service Account Credentials API.** WIF
impersonation calls `generateAccessToken`, which is behind
`iamcredentials.googleapis.com`. The `adc` and `service_account_key`
paths never touch it, so a project that has only ever used those will
have it disabled, and *every* KMS call fails with a bare
`403 Forbidden` (see [Failure modes](#oidc-403-on-every-call)). Enable it
once:

```bash
gcloud services enable iamcredentials.googleapis.com --project=my-project
```

Run the GCP setup in Cloud Shell. The Console can do it too, but the provider
and the impersonation grant are harder to get right there. Substitute your
project number, the token source's issuer, and the service account:

```bash
PROJECT_NUMBER=123456789012
POOL_ID=app-pool
PROVIDER_ID=app-provider
SA_EMAIL=encryption_suite-app@my-project.iam.gserviceaccount.com
ISSUER_URI=<issuer-url>   # https://oidc.fly.io/<org> on Fly.io
PROVIDER_RESOURCE="//iam.googleapis.com/projects/${PROJECT_NUMBER}/locations/global/workloadIdentityPools/${POOL_ID}/providers/${PROVIDER_ID}"

# Pool
gcloud iam workload-identity-pools create $POOL_ID --location=global

# OIDC provider. allowed-audiences MUST be the //iam.googleapis.com
# resource string above. The adapter requests exactly that aud, and a
# source with a fixed audience must carry it. The https:// form will not
# match.
gcloud iam workload-identity-pools providers create-oidc $PROVIDER_ID \
  --location=global --workload-identity-pool=$POOL_ID \
  --issuer-uri="$ISSUER_URI" \
  --allowed-audiences="$PROVIDER_RESOURCE" \
  --attribute-mapping="google.subject=assertion.sub"

# Let identities from the pool impersonate the service account. The
# principalSet below trusts the whole pool, which covers every Fly.io
# machine. Where the issuer gives every instance the same sub, bind that
# single subject (principal://.../subject/<sub>) instead.
gcloud iam service-accounts add-iam-policy-binding $SA_EMAIL \
  --role=roles/iam.workloadIdentityUser \
  --member="principalSet://iam.googleapis.com/projects/${PROJECT_NUMBER}/locations/global/workloadIdentityPools/${POOL_ID}/*"
```

The impersonated service account needs the same Cloud KMS roles as any
other strategy (per combination above) — granting WIF impersonation does
not grant KMS access.

Then give the application `GCP_PROJECT_NUMBER`, `GCP_WIF_POOL_ID`,
`GCP_WIF_PROVIDER_ID` and `GCP_SERVICE_ACCOUNT_EMAIL` as environment
variables. None of them is key material, so they can go in plain
configuration as well as a secret store.

A newly created pool, provider, or impersonation binding takes a few
minutes to propagate; an immediate first call can `403` transiently
before it goes live.

See [KMS adapters](kms-adapters.md) and the docstrings in
`adapters/credentials/gcp.py` for the full required-options list per
strategy.

---

## The Reconcile Keys admin page

For Combination B in particular, this page is the operator workflow. It lists
every silo with the CryptoKey resolved from the template, flags the ones
whose first encryption is still pending, and shows the strategy and provisioner
in effect so you can confirm which combination is live. See
[Reconcile Keys page](admin-panel.md#reconcile-keys-page) for the full
description and the three ways to reach it.

Keys are shown by **full resource path**
(`projects/…/keyRings/…/cryptoKeys/encryption_suite-team-42`), not by the bare
name the template renders. That is the form recorded on every row, and the page
compares resolved names against recorded and live ones — showing the bare name
would compare two different strings and report a mismatch on every healthy silo.
The key ring is therefore part of the identity: point the deployment at a
different ring and its existing keys stop being recognized as its own.

The intended workflow with `NullKekProvisioner`:

1. New tenant signs up.
2. Admin opens the Reconcile Keys page.
3. Copies the last path segment (e.g. `encryption_suite-team-42`) into their
   Cloud KMS console / Terraform / `gcloud` script.
4. Creates the CryptoKey in the configured ring.
5. The next encrypt for that tenant creates the DEK automatically (with
   `KEY_AUTO_PROVISION = True`) and the row flips to **Ready**.

---

## Deleting a key encryption key

Cloud KMS cannot delete a CryptoKey or a key ring — they are permanent, and
free. Key *material* is held in the versions, so deleting a KEK here destroys
every version the key has. That is what makes the DEKs wrapped under it
unrecoverable; the empty CryptoKey shell stays in the ring, billing nothing.

Two consequences worth knowing before the first deletion:

- **The Reconcile Keys page reports a fully destroyed key as gone**, even though
  `gcloud kms keys list` still shows it. Cloud KMS never removes the shell, so
  counting it as present would leave every deletion permanently unconfirmed and
  reported as drift.
- **The provider's window is fixed when the key is created.**
  `PROVIDER_DELETION_WINDOW_DAYS` becomes the key's `destroyScheduledDuration`,
  so changing it later affects only keys created after the change. The default is
  7 days, which is *shorter* than what Cloud KMS applies to a key created without
  the field — so keys this deployment provisioned before the package set it will
  show a longer window in the console, and there is no way to shorten them.
  Destroyed versions are restorable at the provider
  (`gcloud kms keys versions restore`) until it expires — but by then the
  data encryption key is already crypto-shredded, so what that recovers is a key
  encryption key that no longer wraps anything. See
  [the two deletion windows](kek-provisioning.md#the-two-deletion-windows).
- **The test console's key is created with the 24-hour floor**, whatever
  `PROVIDER_DELETION_WINDOW_DAYS` says, so the delete-and-verify cycle takes a day
  rather than a week. This is applied at creation, so a console key provisioned
  earlier keeps its original window until you delete it and let the console make a
  new one.

Two org policies interact with this, and both are worth setting:
`constraints/cloudkms.disableBeforeDestroy` (the provisioner already disables
each version before destroying it, so this costs nothing) and
`constraints/cloudkms.minimumDestroyScheduledDuration`, which raises the floor
under `PROVIDER_DELETION_WINDOW_DAYS` regardless of what is configured here.

If any key sets `KEK_ROTATION_PERIOD_DAYS`, the application needs
`cloudkms.cryptoKeys.update`: the rotation schedule is cleared before the versions
are destroyed. Without it, Cloud KMS adds a fresh enabled version to the key
minutes later and the deletion silently undoes itself, leaving a live billable key
that reconcile reports as an orphan forever.

---

## Failure modes and what they look like

### CryptoKey missing in the ring

`KekNotProvisionedError` is raised by the engine. The user sees:

> Encryption and decryption are unavailable for this data.

The admin sees an `ERROR`-level log entry naming the resolved key path,
the silo UID, the strategy, and the provisioner. With
`NullKekProvisioner` the message points to provisioning outside this application;
with `GcpKekProvisioner` the message also names the underlying GCP
error (e.g. `403 PERMISSION_DENIED` if the service account lacks
`cloudkms.cryptoKeys.create`).

### `oidc`: 403 on every call

With `CREDENTIAL_STRATEGY: "oidc"`, the credential is fetched in three
legs — token source → GCP STS exchange → `generateAccessToken`
impersonation — before any KMS call. A failure in any leg surfaces as the
same generic `KMS key unwrap failed ... HTTP Error 403: Forbidden`,
because the engine wraps the whole unwrap. The log line does not say
which leg failed, and STS/impersonation denials are Data Access audit
events (off by default), so they do not appear in Logs Explorer.

The most common cause is the **IAM Service Account Credentials API being
disabled** (see the prerequisite above) — `generateAccessToken` returns
`403 SERVICE_DISABLED`. To find which leg is failing, run the three calls
yourself from inside the host (so the token source is reachable) and see
which one returns an error instead of a token. Open a shell in the
workload (`fly ssh console` on Fly.io), then:

```sh
AUD='//iam.googleapis.com/projects/<NUMBER>/locations/global/workloadIdentityPools/<POOL>/providers/<PROVIDER>'
SA=encryption_suite-app@my-project.iam.gserviceaccount.com

# Leg 1 — token source. Fetch a token for $AUD the way your source does;
# this is the Fly.io socket. Should print a JWT.
JWT=$(curl -s --unix-socket /.fly/api -X POST -H 'Content-Type: application/json' \
  -d "{\"aud\":\"$AUD\"}" http://localhost/v1/tokens/oidc)

# Leg 2 — STS exchange. Should print access_token; a 400 here means
# issuer/audience mismatch against the provider config.
FED=$(curl -s -X POST https://sts.googleapis.com/v1/token \
  -d grant_type=urn:ietf:params:oauth:grant-type:token-exchange \
  -d audience="$AUD" -d scope=https://www.googleapis.com/auth/cloud-platform \
  -d requested_token_type=urn:ietf:params:oauth:token-type:access_token \
  -d subject_token_type=urn:ietf:params:oauth:token-type:jwt \
  --data-urlencode subject_token="$JWT" \
  | grep -o '"access_token": "[^"]*"' | cut -d'"' -f4)

# Leg 3 — impersonation. The raw error here names the real cause
# (SERVICE_DISABLED, missing workloadIdentityUser, etc.).
curl -s -X POST \
  "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/$SA:generateAccessToken" \
  -H "Authorization: Bearer $FED" -H "Content-Type: application/json" \
  -d '{"scope":["https://www.googleapis.com/auth/cloudkms"]}'
```

The leg that returns an error JSON (rather than a token) is the one to
fix.

### Service account credentials expired

The adapter retries once on `401 Unauthorized` after invalidating the
cached token from the credential strategy. Persistent failures fall
through to the caller as a `urllib.error.HTTPError`.

### Wrong location or ring

`GcpKmsAdapter` does not infer location or ring — both must be set in
`OPTIONS`. A CryptoKey named `encryption_suite-team-42` in
`us-central1/encryption_suite-prod` is invisible from a client targeting
`us-east1/encryption_suite-prod` even though the underlying project is the
same.

### Trying to delete a key

Cloud KMS does not allow CryptoKey deletion — only versions can be
scheduled for destruction (24h–30d delay, then irreversible). If you
auto-provisioned a key for a now-departed tenant and want to clean up,
the most you can do is destroy its key versions; the empty CryptoKey
shell remains in the ring.

---

## Related reading

- [KEK strategies](kek-strategies.md) — full strategy reference, including
  cohort and BYOK.
- [KEK provisioning](kek-provisioning.md) — strategy-vs-provisioner split,
  the full provisioner table, and writing custom provisioners.
- [KMS adapters](kms-adapters.md) — adapter / credential strategy
  reference for GCP and the other providers.
- [Configuration reference](configuration.md) — every `ENCRYPTION`
  setting, including `KEY_AUTO_PROVISION`, `DEK_CACHE_TTL`, and
  `LOG_DECRYPTS`.
- [Key rotation](key-rotation.md) — rotating KEKs and re-encrypting.
- [Getting started with AWS KMS](getting-started-aws.md) — same workflow
  shape, AWS-flavored.
