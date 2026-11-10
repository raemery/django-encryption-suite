# Getting started with HashiCorp Vault

This step-by-step guide walks you through wiring django-encryption-suite to HashiCorp Vault's
transit secrets engine in production. This page assumes you have
already followed [Getting started](getting-started.md) for the basic
Django setup (`INSTALLED_APPS`, migrations, a silo adapter) and
now need to swap the local dev KMS for a real HashiCorp Vault cluster.

The two decisions that drive everything else on this page:

1. **Shared KEK or per-silo KEK?**
   One transit key for the whole application vs. one key per
   tenant/team.
2. **Auto-provision or manual?**
   Let the application create transit keys on first encrypt vs.
   provision them outside this application (Terraform / `vault` CLI / UI) before the
   application sees them.

The rest of this guide walks through each combination end-to-end.

---

## Prerequisites

- A running Vault cluster reachable from your application (this guide
  uses `https://vault.example.com:8200`). Self-hosted, HCP Vault, and
  Vault Enterprise all work the same way at this layer.
- The **transit secrets engine enabled** at a known mount path
  (default: `transit/`). Engines are admin-level resources and the
  provisioner does **not** mount them — that step is yours.

  ```bash
  vault secrets enable transit
  # or, for a custom mount:
  vault secrets enable -path=encryption_suite-transit transit
  ```

- An auth method configured for the application's identity (token,
  AWS IAM, Kubernetes, AppRole, etc.). This guide covers the two that
  ship with django-encryption-suite credential strategies: static **token**
  and **AWS IAM**.
- For Vault Enterprise / HCP Vault: the namespace path your application
  belongs to (e.g. `admin/dev`).
- No Python extras required — the Vault adapter speaks the HTTP API
  directly using stdlib `urllib`.
- A working `ENCRYPTION` block in `settings.py` from
  [Getting started](getting-started.md). You will replace the
  env key store configuration with a `HashiCorpVaultAdapter` block below.

### A note on the transit engine

The transit engine is a "crypto as a service" mount: keys live inside Vault,
plaintext never does. Two operational properties shape this guide:

- **Mounts are admin scope.** Mounting `transit/` requires `sudo` /
  `root` capability and is typically done once per Vault cluster, not
  per tenant. The provisioner expects the mount to exist already.
- **`POST /transit/keys/{name}` is idempotent.** Vault treats the call
  as a no-op if the key already exists, so the auto-provisioner does
  not need a separate "does this exist?" probe — it just calls create.

`HashiCorpVaultAdapter` uses transit's `encrypt` / `decrypt` actions
(symmetric AEAD) to wrap DEKs. The provisioner therefore creates
symmetric keys (`aes256-gcm96` by default).

### Accessing the Vault web UI

Several steps in this guide (rotating keys, editing min-decryption-version,
inspecting key versions) use the **Vault web UI**. How you reach it depends on
how Vault is hosted:

**Self-managed / Vault Enterprise.** The UI is served by the cluster itself —
browse to the Vault address (e.g. `https://vault.example.com:8200/ui`) and log
in with a token or your configured auth method.

**HCP Vault Dedicated.** The UI is behind the HashiCorp Cloud Platform
portal; the Vault cluster is *not* the first thing you see after logging in.
Drill down:

1. Sign in to the HCP portal (`https://portal.cloud.hashicorp.com`). You land
   on the **organization** dashboard.
2. Left nav → **Projects** → click your project. You land on the **Project
   dashboard**.
3. Under **Services**, click **Vault Dedicated** (or the matching card on the
   dashboard).
4. Click your Vault **cluster** to open its **Overview** page.
5. Top-right → **Launch Web UI**. This opens the Vault UI in a new tab at the
   cluster's own address.
6. Log in with an admin token. HCP issues one from the cluster Overview page
   (**Generate token**). These tokens are **short-lived and expire** — if UI
   or API calls suddenly return `permission denied` / `403`, regenerate the
   token (and update the `VAULT_TOKEN` your application reads, if it uses the
   static-token strategy).

Once you're in the Vault UI, the left nav shows Vault's own menu
(**Secrets engines**, **Access**, **Policies**, …). Your transit keys live under
**Secrets engines → your transit mount → Keys**.

---

## Decision 1 — shared vs per-silo KEK

### Shared KEK

One transit key encrypts every silo's DEK. Simpler operationally;
one ACL policy, one key to rotate, one key in the Vault audit log.
The trade-off is blast radius: if that single key is compromised or
deleted (a Vault operator can delete transit keys), every tenant's
encrypted data is at risk simultaneously.

Pick this when:

- You have a single-tenant deployment (one organization, many teams
  that don't need cryptographic isolation between them).
- You want the lightest operational footprint and the per-tenant blast
  radius is not a compliance requirement.

### Per-silo KEK

Each tenant/team gets its own transit key. Compromise or deletion of
one key affects only that tenant. Required by some compliance regimes
(HIPAA multi-tenant scenarios, customer-supplied custody for B2B
contracts). Vault has no per-key billing — the cost is operational,
not financial.

Pick this when:

- You're a multi-tenant SaaS where tenants must be cryptographically
  isolated.
- You need to demonstrate per-tenant key custody to auditors.
- You want the option to rotate or delete a single tenant's data by
  acting on one transit key.

### Settings mapping

| Choice | `KEK_STRATEGY_ADAPTER` | `OPTIONS` key |
|---|---|---|
| Per-silo | `PerSiloKekStrategy` | `KEK_TEMPLATE` (or `KEK_MAP`) |

The `KEK_TEMPLATE` value is a transit key **name** within the
configured mount (e.g. `encryption_suite-{silo_uid}`) — not a full
API path. The adapter combines it with `VAULT_ENDPOINT` and the implicit
`transit/` mount to build the full URL at request time.

> **`SharedKekStrategy` is not supported with HashiCorp Vault
> transit.** The transit engine's `encrypt`/`decrypt` API has a `context`
> field, but it is honored only for keys created with
> `derived: true` (Vault uses the context for key derivation, not as
> conventional AEAD AAD). django-encryption-suite does not currently
> provision derived keys, so wrapped DEKs cannot be bound to a
> specific silo at the wrap layer; with a shared KEK and no
> AAD, an attacker who swaps wrapped DEK rows between silos
> in the database gets clean decrypts. `HashiCorpVaultAdapter` rejects
> this combination at construction with `EncryptionConfigurationError`. It
> rejects the same result reached through `PerSiloKekStrategy`: a
> `KEK_TEMPLATE` with no `{silo_uid}` placeholder, and a `KEK_MAP` that
> names one key for two silos. Use
> `PerSiloKekStrategy` with Vault (the per-tenant boundary
> comes from distinct transit keys, enforced by Vault ACL policy and
> key-name separation), or switch to a KMS provider whose wrap
> operation supports AAD without extra setup (AWS, GCP, Fly, OCI,
> IBM, Local).

---

## Decision 2 — manual vs auto provisioning

### Manual (`NullKekProvisioner`, the default)

Someone (or something) creates the transit key before the application
tries to use it. Typical flows:

- **Terraform** (`hashicorp/vault` provider) — keys defined as IaC,
  reviewed in PRs, applied at deploy time.
- **Bootstrap script** — a one-off `vault write -f transit/keys/<name>`
  per tenant.
- **Manual UI action** — admin opens the Vault UI and creates the key.

The application's Vault policy only needs `update` on
`transit/encrypt/<name>` and `transit/decrypt/<name>` — it cannot
create keys, which is the safer posture for most production
deployments.

When a missing key is hit at runtime, the engine raises
`KekNotProvisionedError` with a translated user-facing message
("Encryption and decryption are unavailable for this data.") and an
English admin log entry naming the missing key and the strategy in use.
The Django admin **Reconcile Keys** page (described later) is the
operator workflow for catching this before users do.

### Auto (`HashiCorpVaultKekProvisioner`)

The application creates the transit key the first time a new
silo encrypts data. Typical use case: multi-tenant SaaS where
new tenants sign up mid-request and you don't want a manual
provisioning step blocking their first save.

The application's Vault policy needs `create` and `read` on
`transit/keys/<name>` in addition to encrypt/decrypt. This is a wider
blast radius — a compromised application can create arbitrary transit
keys, set unusual key types, or potentially exhaust storage. Some
compliance regimes forbid it.

### Combinations

| KEK choice | Provisioning | Per-tenant ops |
|---|---|---|
| Per-silo | Manual | New tenant ⇒ admin creates transit key, then tenant can encrypt |
| Per-silo | Auto | New tenant ⇒ first encrypt creates the key; zero operator setup |

`SharedKekStrategy` is not supported with HashiCorp Vault transit — see
[Decision 1](#settings-mapping).

---

## Combination A — per-silo KEK, manual provisioning

Best fit: multi-tenant SaaS that needs per-tenant isolation but cannot
grant key-create capability to the application.

### Step 1: pick a naming convention

The convention is encoded as a template containing `{silo_uid}`.
The engine sanitizes the silo UID to the charset `[A-Za-z0-9_-]`
before substitution, using a **bijective** (reversible) encoding rather
than a lossy replace: each character outside the charset is emitted as
`_` followed by two lowercase hex digits per UTF-8 byte, and a literal
`_` is doubled to `__`. (See `adapters/keks/sanitization.py`.)

```
encryption_suite-{silo_uid}
# silo_uid "team-42" needs no escaping — hyphen is allowed; any char
# outside [A-Za-z0-9_-] is hex-escaped (e.g. "@" -> "_40")
# resolved name:  encryption_suite-team-42
```

The encoding is reversible by design (so distinct UIDs never collide on
one key name). A normal UID like `team-1` is already valid and is used
unchanged (`encryption_suite-team-1`); a slash, space, or any other
character outside `[A-Za-z0-9_-]` is hex-escaped, and a literal `_` is
doubled to `__` — so a UID with unusual characters is not guessable by eye.
When you need the exact
key name (to rotate it, write a tight ACL, or inspect it in the Vault UI),
read it from the **Reconcile Keys** admin page (below) or list the keys from Vault
directly — do not reconstruct it from the UID.

### Step 2: configure `ENCRYPTION`

```python
ENCRYPTION = {
    "KEY_SETS": {"default": {"silo": "...", "key_store": "vault"}},
    "KMS_KEY_STORES": {
        "vault": {
            "ADAPTER": "encryption_suite.adapters.key_stores.hashicorp.HashiCorpVaultAdapter",
            "OPTIONS": {
                "VAULT_ENDPOINT": "https://vault.example.com:8200",
                "CREDENTIAL_STRATEGY": "iam_aws",
                "AWS_IAM_VAULT_ROLE": "encryption_suite-app",
                "KEK_TEMPLATE": "encryption_suite-{silo_uid}",
            },
            "KEK_STRATEGY_ADAPTER": "encryption_suite.adapters.keks.PerSiloKekStrategy",
        },
    },
}
```

### Step 3: write and assign an ACL policy

A glob policy covers every tenant key without per-tenant policy
edits:

```hcl
# encryption_suite-runtime.hcl
path "transit/encrypt/encryption_suite-*" {
  capabilities = ["update"]
}
path "transit/decrypt/encryption_suite-*" {
  capabilities = ["update"]
}
```

```bash
vault policy write encryption_suite-runtime encryption_suite-runtime.hcl
```

Bind the policy to whichever auth method your application uses (token,
AWS IAM role, Kubernetes service account, AppRole, etc.). For example,
with AWS IAM auth:

```bash
vault write auth/aws/role/encryption_suite-app \
  auth_type=iam \
  bound_iam_principal_arn="arn:aws:iam::<account-id>:role/encryption_suite-app" \
  policies=encryption_suite-tenant-* \
  ttl=1h
```

If your security model requires per-key policies (no glob patterns),
you'll need to update the policy each time a tenant is added —
Terraform-driven, ideally.

### Step 4: provisioning workflow per new tenant

For each new silo:

1. **Find out which key it needs.** Open the Django admin, go to
   **Data Encryption Keys → Reconcile Keys** (object-tools
   link, top right of the change list). Or visit:

   ```
   /admin/encryption_suite/dataencryptionkey/reconcile-keys/
   ```

   The page lists every silo, the resolved transit key name the
   application would try to use, and a **Needs setup** flag for those
   without a DEK row yet.

2. **Create the transit key.** Via Terraform (preferred):

   ```hcl
   resource "vault_transit_secret_backend_key" "tenant_42" {
     backend = "transit"
     name    = "encryption_suite-team-42"
     type    = "aes256-gcm96"
   }
   ```

   Or via `vault` CLI for one-offs:

   ```bash
   vault write -f transit/keys/encryption_suite-team-42 type=aes256-gcm96
   ```

3. **Verify on the admin page.** Refresh the Reconcile Keys page;
   the row's status changes to **Ready** once the DEK is created
   (immediately if you also run `setup_encryption_keys`, or on the
   next encrypt with `KEY_AUTO_PROVISION = True`).

4. **Trigger DEK creation.** With `KEY_AUTO_PROVISION = True`
   (default), the next encrypt for that tenant creates the DEK
   automatically. Otherwise:

   ```bash
   python manage.py setup_encryption_keys
   ```

Until the transit key exists, any encrypt for that tenant raises
`KekNotProvisionedError`. The translated user-facing message is
`"Encryption and decryption are unavailable for this data."`; the
log entry contains the missing key name and the silo UID.

---

## Combination B — per-silo KEK, auto provisioning

Best fit: multi-tenant SaaS that can grant key-create capability on
the transit mount and wants zero per-tenant manual steps.

### Step 1: configure `ENCRYPTION`

Same `OPTIONS` as Combination A, plus a provisioner:

```python
ENCRYPTION = {
    "KEY_SETS": {"default": {"silo": "...", "key_store": "vault"}},
    "KMS_KEY_STORES": {
        "vault": {
            "ADAPTER": "encryption_suite.adapters.key_stores.hashicorp.HashiCorpVaultAdapter",
            "OPTIONS": {
                "VAULT_ENDPOINT": "https://vault.example.com:8200",
                "CREDENTIAL_STRATEGY": "iam_aws",
                "AWS_IAM_VAULT_ROLE": "encryption_suite-app",
                "KEK_TEMPLATE": "encryption_suite-{silo_uid}",
            },
            "KEK_STRATEGY_ADAPTER": "encryption_suite.adapters.keks.PerSiloKekStrategy",

            "KEK_PROVISIONER_ADAPTER": "encryption_suite.adapters.keks.HashiCorpVaultKekProvisioner",
            "KEK_PROVISIONER_OPTIONS": {
                "VAULT_ENDPOINT": "https://vault.example.com:8200",
                "CREDENTIAL_STRATEGY": "iam_aws",     # may differ from OPTIONS
                "AWS_IAM_VAULT_ROLE": "encryption_suite-app",
                "VAULT_MOUNT_PATH": "transit",              # default
                "KEY_TYPE": "aes256-gcm96",           # default
                "EXPORTABLE": False,                  # default
                "ALLOW_PLAINTEXT_BACKUP": False,      # default
            },
        },
    },
}
```

`KEK_PROVISIONER_OPTIONS` is intentionally separate from `OPTIONS`
so that you can point the provisioner at a different Vault role or
different credentials than the runtime encrypt/decrypt path uses. In
most deployments they are the same, but separating them lets you e.g.
use a narrower runtime role.

The provisioner takes its own `VAULT_ENDPOINT` and `VAULT_MOUNT_PATH` because it
constructs transit URLs independently of the adapter — this lets you
provision into a different mount than the runtime reads from, in
advanced deployments (uncommon).

### Step 2: extend the policy

Add `create` and `read` on `transit/keys/<name>` for the
auto-provisioner's idempotent create call:

```hcl
# encryption_suite-runtime-with-provisioner.hcl
path "transit/encrypt/encryption_suite-*" {
  capabilities = ["update"]
}
path "transit/decrypt/encryption_suite-*" {
  capabilities = ["update"]
}
path "transit/keys/encryption_suite-*" {
  capabilities = ["create", "read", "update"]
}
```

```bash
vault policy write encryption_suite-runtime encryption_suite-runtime-with-provisioner.hcl
```

If you want the provisioner to use a separate, narrower role, define a
second auth-method binding with only the `transit/keys/encryption_suite-*`
capabilities and point `KEK_PROVISIONER_OPTIONS["AWS_IAM_VAULT_ROLE"]`
at it.

### Step 3: deploy and forget

Each new silo now triggers, on first encrypt:

1. `HashiCorpVaultKekProvisioner.ensure_kek` reads
   `GET /v1/transit/keys/{name}` and, on a 404, creates the key with
   `POST /v1/transit/keys/{name}`.
2. The transit key encrypts a freshly generated DEK; the encrypted
   DEK is stored as a `DataEncryptionKey` row.
3. Subsequent encrypts skip provisioning (in-process cache).

Vault's create endpoint is itself idempotent — a `POST` against an existing key
is a no-op and does not rotate or replace its material — so the read is not
needed for correctness. The provisioner does it anyway, to match the other
provisioners: it keeps create events out of the Vault audit log for keys that
already exist, and it means the `create` capability is not exercised on every
encrypt of a key that has been there for months.

### Step 4: monitoring

Watch Vault's audit log for `transit/keys/<name>` create events on
first signup; spikes can mean something is hammering tenant creation.
The `encryption_suite` logger emits an `INFO`-level entry when a key is
actually created:

```
HashiCorpVaultKekProvisioner: created KEK 'encryption_suite-team-42' for silo 'team-42'.
```

A silo whose key already existed logs nothing — the read-first probe is what
lets the provisioner tell the two cases apart.

---

## Credential strategies

`HashiCorpVaultAdapter` and `HashiCorpVaultKekProvisioner` both support
four credential strategies, selected by `CREDENTIAL_STRATEGY`:

| Strategy | Use case |
|---|---|
| `token` | Static Vault token from `OPTIONS["VAULT_TOKEN"]` or the `VAULT_TOKEN` environment variable. Use for local development or short-lived test environments. The token cannot be auto-renewed; revocation surfaces as a `403` and re-raises. |
| `approle` | Vault's AppRole auth method. POSTs `VAULT_ROLE_ID` + `VAULT_SECRET_ID` (or reads the secret_id from `VAULT_SECRET_ID_FILE`) to `/v1/auth/{mount}/login` and caches the returned client token. On `403` the adapter calls `invalidate()` and re-logs in. Recommended for workloads on platforms without a Vault-trusted runtime identity (generic VMs, on-prem hosts, edge/PaaS environments). Override the mount path with `VAULT_APPROLE_MOUNT` (default `approle`). |
| `iam_aws` | Vault's AWS IAM auth method. Boto3 signs an STS `GetCallerIdentity` request, Vault verifies the signature and returns a leased Vault token. Token is cached for its lease and re-fetched on `403`. Recommended for AWS-hosted deployments using Vault. |
| `oidc` | Vault's JWT/OIDC auth method. The adapter obtains a JWT from a configured `OidcTokenSource` (Kubernetes projected SA, GCP metadata, SPIFFE, file-on-disk, plus several PaaS-specific sources) and posts it to `/v1/auth/{VAULT_JWT_MOUNT}/login` with `VAULT_JWT_ROLE`. Requires the workload to have a verifiable runtime identity. |

For Vault Enterprise / HCP Vault, set `VAULT_NAMESPACE` (e.g. `admin`)
on both `OPTIONS` and `KEK_PROVISIONER_OPTIONS`.

If you need an auth method beyond these four, write a small custom
credential strategy by subclassing `AbstractCredentialStrategy` from
`encryption_suite.adapters.credentials.base`. The four built-in
strategies are reference implementations.

---

## Setting up AppRole (first-time)

Getting an application onto the `approle` strategy is four Vault-side steps
plus the application config. **Mind the UI/API split:** enabling the auth
method and writing the policy can be done in the Vault web UI, but **AppRole
*role* management cannot.** On HCP Vault the role screen states outright:
*"The Vault UI only supports configuration for this authentication method. For
management, the API or CLI should be used."* So creating the role and reading
the `role_id` / minting a `secret_id` must go through the CLI or the HTTP API.

The examples below use the HTTP API via `curl` (works with no `vault` CLI
installed). On HCP Vault, every call needs `-H "X-Vault-Namespace: admin"`
and the cluster's **public** address. For the UI steps, see
[Accessing the Vault web UI](#accessing-the-vault-web-ui) — on HCP that's a
multi-step drill-down through the cloud portal.

### 1. Enable the AppRole auth method

- **UI:** Access → Authentication Methods → Enable new method → **AppRole** →
  mount path `approle` → Enable. (The method's "Configure" page only tunes the
  mount — leases, HMAC, lockout — and is optional.)
- **CLI:** `vault auth enable approle`

### 2. Write a least-privilege runtime policy

The AppRole token should be scoped to exactly what the runtime needs — not the
broad admin token. This is fully supported in the UI: Policies → ACL Policies
→ Create ACL policy.

```hcl
# encryption_suite-runtime.hcl
path "transit/encrypt/kms-*" { capabilities = ["update"] }
path "transit/decrypt/kms-*" { capabilities = ["update"] }
# Only if you use HashiCorpVaultKekProvisioner (auto-provisioning) and/or the
# Reconcile Keys admin page: create lets the app provision new kms-<uid> keys; read
# backs describe_kek on the Reconcile Keys page. Drop this path for manual
# provisioning with no Reconcile-Keys-page key inspection.
path "transit/keys/kms-*"    { capabilities = ["create", "read", "update"] }
```

Match the path prefix to your `KEK_TEMPLATE` (here `kms-{silo_uid}` →
`kms-*`) and your mount path.

### 3. Create the role (API/CLI only — not the UI)

```bash
curl -s -H "X-Vault-Token: $VAULT_TOKEN" -H "X-Vault-Namespace: admin" \
  -X POST \
  -d '{"token_policies":"encryption_suite-runtime","token_ttl":"20m","token_max_ttl":"1h","secret_id_ttl":"168h","secret_id_num_uses":0}' \
  "$VAULT_ENDPOINT/v1/auth/approle/role/encryption_suite"
# HTTP 204, empty body on success
```

`secret_id_num_uses=0` means unlimited uses until the TTL expires; the app
re-logs in automatically when its short-lived token expires.

### 4. Read role_id and mint a secret_id (API/CLI only)

```bash
# role_id — stable, treat as config (VAULT_ROLE_ID)
curl -s -H "X-Vault-Token: $VAULT_TOKEN" -H "X-Vault-Namespace: admin" \
  "$VAULT_ENDPOINT/v1/auth/approle/role/encryption_suite/role-id"

# secret_id — sensitive, shown once (VAULT_SECRET_ID)
curl -s -H "X-Vault-Token: $VAULT_TOKEN" -H "X-Vault-Namespace: admin" \
  -X POST \
  "$VAULT_ENDPOINT/v1/auth/approle/role/encryption_suite/secret-id"
```

(`encryption_suite_rotate_hashicorp_approle` does exactly this `secret-id` call for you;
see *Operating AppRole in production* below.)

### 5. Point the application at AppRole

Set `CREDENTIAL_STRATEGY="approle"` plus `VAULT_ROLE_ID` and `VAULT_SECRET_ID` in
both `OPTIONS` and `KEK_PROVISIONER_OPTIONS`. The strategy selector is
explicit — `CREDENTIAL_STRATEGY` decides which auth method runs; the mere
presence of `VAULT_TOKEN` vs `VAULT_ROLE_ID` does **not** switch it, and the
default when unset is `token`. Remove any `VAULT_TOKEN` so there's no stale
static-token config and the AppRole path is unambiguous.

On the first encrypt/decrypt the adapter POSTs `role_id`+`secret_id` to
`/v1/auth/approle/login`, caches the returned client token, and refreshes it
on `403`.

---

## Operating AppRole in production

HashiCorp's
[Secure introduction of Vault clients](https://developer.hashicorp.com/vault/tutorials/app-integration/secure-introduction)
identifies three canonical patterns for getting a workload its initial
Vault credentials. Pick the highest one your platform supports:

1. **Platform-native identity** — preferred when available. The runtime
   mints a verifiable identity (cloud IAM role, Kubernetes service
   account token, SPIFFE JWT, or a PaaS-issued OIDC token) that Vault
   validates against the platform's issuer. No shared secret,
   nothing to rotate. Use the `oidc` or `iam_aws` credential strategy.
   encryption_suite ships `OidcTokenSource` implementations for GCP
   metadata, Kubernetes projected SA tokens, SPIFFE, arbitrary
   file-on-disk JWTs, and several PaaS-specific sources.

2. **Vault Agent sidecar** — when the platform has no Vault-trusted
   identity but you can deploy a co-located process. Vault Agent
   authenticates (typically via AppRole), maintains a renewed client
   token, and writes the secret_id (or a rendered template) to disk for
   the app to consume. encryption_suite's `VAULT_SECRET_ID_FILE` option
   reads the secret_id from a path on every login, so Agent's
   `auto_auth.sink.file` integrates without code changes.

3. **Trusted orchestrator** — when neither of the above fits (generic
   VMs, on-prem hosts, edge/PaaS environments with no Vault-trusted
   IdP). A privileged process — CI job, scheduled rotator, ops
   automation — periodically generates a fresh secret_id and delivers
   it to the workload via the platform's secrets store (Kubernetes
   Secret, hosting-provider secret API, env var). The workload never
   holds admin credentials.

### secret_id TTL and rotation cadence

For pattern 3, set a finite `secret_id_ttl` when creating the AppRole
role so a leaked secret_id has bounded blast radius:

```bash
curl -X POST -H "X-Vault-Token: $VAULT_TOKEN" -H "X-Vault-Namespace: admin" \
  -d '{"token_policies":"encryption_suite","token_ttl":"1h","token_max_ttl":"4h","secret_id_ttl":"168h"}' \
  $VAULT_ENDPOINT/v1/auth/approle/role/encryption_suite
```

Rotate at half the TTL (with `secret_id_ttl=168h`, rotate every 84h)
so the new value is delivered before the old one expires. The role_id
is permanent; only the secret_id rotates.

### Rotator management command

The package ships
`manage.py encryption_suite_rotate_hashicorp_approle` to handle the Vault side
of the rotation. **Run it from the privileged context, not the app.**

```bash
# Trusted orchestrator (CI / ops machine). Plain secret_id.
VAULT_ENDPOINT=https://vault.example.com:8200 \
VAULT_TOKEN=<admin token> \
VAULT_NAMESPACE=admin \
  python manage.py encryption_suite_rotate_hashicorp_approle --role encryption_suite

# Output:
# {"secret_id":"...", "secret_id_accessor":"...", "secret_id_ttl":604800, ...}

# Pipe into whatever secret store your workload reads from. Examples:
#   Kubernetes:    kubectl create secret generic vault-approle ...
#   Hashicorp Nomad: nomad var put ...
#   Hosting platform: <provider-cli> secrets set ...
```

For higher-trust delivery channels (anywhere the raw secret_id might be
logged, cached, or seen by extra eyes), use **response wrapping** — the
command emits a single-use wrapping token instead, and the workload
unwraps it once at startup against `/sys/wrapping/unwrap`:

```bash
python manage.py encryption_suite_rotate_hashicorp_approle \
  --role encryption_suite --wrap --wrap-ttl 5m
# {"wrapping_token":"hvs.abc...","wrapping_token_ttl":300, ...}
```

Wrapping tokens are single-use and short-lived; if a wrapping token is
intercepted and unwrapped by an attacker, the legitimate workload's
unwrap attempt fails and the breach surfaces immediately.

### Example: scheduled rotator in CI

The shape is the same regardless of where you push the rotated value.
Sketch:

```yaml
name: rotate-vault-approle
on:
  schedule:
    - cron: "0 3 * * 0"   # weekly, Sundays 03:00 UTC
jobs:
  rotate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.12" }
      - run: pip install -e .
      - name: Rotate secret_id and update the workload's secret store
        env:
          VAULT_ENDPOINT: ${{ secrets.VAULT_ENDPOINT }}
          VAULT_TOKEN: ${{ secrets.VAULT_ADMIN_TOKEN }}
          VAULT_NAMESPACE: ${{ secrets.VAULT_NAMESPACE }}
        run: |
          SID=$(python manage.py encryption_suite_rotate_hashicorp_approle \
            --role encryption_suite | jq -r .secret_id)
          # Replace with the command for your hosting platform's secret
          # store — e.g. `kubectl create secret`, `nomad var put`,
          # `<provider> secrets set`, or a write to your CD pipeline.
          your-secret-store set VAULT_SECRET_ID "$SID"
```

Use a Vault admin token scoped narrowly to
`auth/approle/role/encryption_suite/secret-id` for the rotator — it does not
need full admin.

---

## Setting up OIDC (platform-native, no static secret)

The `oidc` strategy is pattern 1 above. The workload's runtime mints a
signed JWT proving its identity, Vault verifies the signature against the
platform's public keys, and there is **no shared secret to store or
rotate**. It is the preferred strategy on any platform that issues a
Vault-verifiable workload identity.

Once configured, this setup runs **indefinitely with no periodic renewal**.
The workload mints a fresh short-lived JWT for each login, Vault returns a
short-lived client token that the adapter refreshes on expiry, and Vault
re-fetches the platform's signing keys from the discovery URL on its own.
Only *configuration* changes break authentication: renaming whatever the
bound claims or the issuer URL name, or tearing down the Vault cluster.
Running **many instances at once** needs no extra setup either. Every instance
presents its own JWT, they all match the same role's `bound_claims`, and each
gets its own client token.

The steps below use placeholders and give the Fly.io values after each one.
[Fly.io as an OIDC token source](getting-started-fly.md#flyio-as-an-oidc-token-source)
explains those values.

**Same UI/API split as AppRole:** enabling the JWT auth method and writing
the policy can be done in the Vault web UI, but **JWT *role* management
cannot** — create the role and read it back through the CLI or HTTP API.
The `curl` examples assume HCP Vault: every call carries
`-H "X-Vault-Namespace: admin"` and the cluster's **public** address.

### 1. Enable the JWT auth method

```bash
curl -s -H "X-Vault-Token: $VAULT_TOKEN" -H "X-Vault-Namespace: admin" \
  -X POST -d '{"type":"jwt"}' \
  "$VAULT_ENDPOINT/v1/sys/auth/jwt"
# HTTP 204, empty body on success
```

> **Verify this step succeeded.** If the enable call runs with a token that
> lacks `sys/auth` permission (or no token at all), it fails *silently* from
> the caller's view, and every later login returns
> `{"errors":["permission denied"]}` — which reads like a policy problem but
> is really "the mount does not exist." Confirm the mount is live by reading
> the config back (step 2); a missing mount returns
> `no handler for route "auth/jwt/config"`.

The UI equivalent: Access → Authentication Methods → Enable new method →
**JWT** → mount path `jwt` → Enable.

### 2. Configure trust in the platform's OIDC issuer

Point Vault at the issuer's OIDC discovery URL so it can fetch the public
keys (JWKS) used to verify token signatures.

```bash
curl -s -H "X-Vault-Token: $VAULT_TOKEN" -H "X-Vault-Namespace: admin" \
  -X POST -d '{"oidc_discovery_url":"<issuer-url>"}' \
  "$VAULT_ENDPOINT/v1/auth/jwt/config"
```

**On Fly.io**, the issuer is `https://oidc.fly.io/<org>`. It is per org, not
per app, so the discovery URL alone proves only that the token came from some
machine in the org. The role's `bound_claims` (step 3) decide which app is
allowed.

Read it back to confirm `oidc_discovery_url` is stored and Vault can reach
the issuer:

```bash
curl -s -H "X-Vault-Token: $VAULT_TOKEN" -H "X-Vault-Namespace: admin" \
  "$VAULT_ENDPOINT/v1/auth/jwt/config"
```

### 3. Create the role (API/CLI only — not the UI)

Bind on claims that are the same for every instance of the workload. Bind on
`sub` only if the issuer keeps it stable across instances.

```bash
curl -s -H "X-Vault-Token: $VAULT_TOKEN" -H "X-Vault-Namespace: admin" \
  -X POST -d '{
    "role_type":"jwt",
    "bound_audiences":["encryption_suite"],
    "bound_claims":{"<claim>":"<value>"},
    "user_claim":"sub",
    "token_policies":["encryption_suite-runtime"],
    "token_ttl":"20m",
    "token_max_ttl":"30m"
  }' \
  "$VAULT_ENDPOINT/v1/auth/jwt/role/encryption_suite"
```

**On Fly.io**, `sub` contains the machine name, which changes as the app
scales, so bind the app and org claims instead:
`"bound_claims":{"app_name":"<app>","org_name":"<org-name>"}`. The
`org_name` value can differ from the slug in the issuer URL, so read it from a
real token.

Reuse the same `encryption_suite-runtime` policy from the AppRole section — the
runtime permissions are identical regardless of how the token was obtained.

Before trusting the binding, decode a token the platform actually issues and
confirm that `iss`, `aud` and the bound claims match. On Fly.io,
[Fetching a token by hand](getting-started-fly.md#fetching-a-token-by-hand)
shows how; request the audience `encryption_suite`.

### 4. Point the application at OIDC

Set `CREDENTIAL_STRATEGY="oidc"`, plus:

- `OIDC_SOURCE` names the token source that fetches the JWT (`fly` on
  Fly.io, which needs no `OIDC_SOURCE_OPTIONS`).
- `VAULT_JWT_ROLE` names the role from step 3 (`encryption_suite`).
- `VAULT_JWT_MOUNT` defaults to `jwt`; set it only if you mounted the method
  elsewhere.
- `VAULT_JWT_AUDIENCE` is optional and **defaults to the role name**. The
  audience the workload presents and `bound_audiences` on the role must agree,
  so the default works when they are the same string. A source whose platform
  fixes the audience ignores this option, so set the audience in the
  platform's configuration instead.

As with AppRole, the selector is explicit — presence of `VAULT_TOKEN` or
`VAULT_ROLE_ID` does not switch strategy. Remove any stale `VAULT_TOKEN`.

On the first encrypt/decrypt the adapter asks the source for a JWT, POSTs
`{role, jwt}` to `/v1/auth/jwt/login`, caches the returned client token, and
refreshes on `403`.

> **A custom token source must return the bare JWT.** Issuers differ in
> whether they return it raw or wrapped as `{"token": "..."}`; Fly.io returns
> it raw under an `application/json` content type, and `FlySocketTokenSource`
> accepts both shapes. Check which shape your issuer returns.

---

## The Reconcile Keys admin page

For Combination A in particular, this page is the operator workflow. It lists
every silo with the transit key name resolved from the template, flags the ones
whose first encryption is still pending, and shows the strategy and provisioner
in effect so you can confirm which combination is live. See
[Reconcile Keys page](admin-panel.md#reconcile-keys-page) for the full
description and the three ways to reach it.

The intended workflow with `NullKekProvisioner`:

1. New tenant signs up.
2. Admin opens the Reconcile Keys page.
3. Copies the resolved name (e.g. `encryption_suite-team-42`) into their
   Vault UI / Terraform / `vault` script.
4. Creates the transit key.
5. The next encrypt for that tenant creates the DEK automatically
   (with `KEY_AUTO_PROVISION = True`) and the row flips to **Ready**.

---

## Failure modes and what they look like

### transit key missing

`KekNotProvisionedError` is raised by the engine. The user sees:

> Encryption and decryption are unavailable for this data.

The admin sees an `ERROR`-level log entry naming the resolved key
name, the silo UID, the strategy, and the provisioner. With
`NullKekProvisioner` the message points to provisioning outside this application;
with `HashiCorpVaultKekProvisioner` the message also names the
underlying Vault error (e.g. `403 permission denied` if the policy
lacks `create` on `transit/keys/<name>`).

### transit mount missing

If the mount itself is not present, Vault returns a `404` on the
encrypt call. The adapter surfaces this as a `urllib.error.HTTPError`
that the engine wraps into the same `KekNotProvisionedError`. The
provisioner cannot recover — mounting is an admin operation. Fix it
with `vault secrets enable transit` (or whatever path you chose).

### Token expired or revoked

The adapter receives a `403`, calls `invalidate()` on the credential
strategy, and retries once. With `iam_aws` this triggers a fresh
login. With `token` (static), there's nothing to refresh — the second
attempt fails the same way and the original error propagates.

### Wrong namespace (HCP / Enterprise)

Without `VAULT_NAMESPACE` on a namespaced Vault, requests land in the
wrong namespace's policy scope and return `permission denied` even
with a valid token. Set the same namespace on both `OPTIONS` and
`KEK_PROVISIONER_OPTIONS`.

### Sealed Vault

A sealed Vault returns `503` on every request. The adapter does not
distinguish sealed-vault from other 5xx errors — it simply propagates.
Monitor your Vault cluster's seal status separately; this is a
cluster-level concern, not an application-level one.

---

## Rotating transit keys

HashiCorp Vault transit keys are versioned. Rotating bumps the key to a new version,
which becomes the default for new encrypt/wrap operations while **older
versions are retained for decrypt**. Existing wrapped DEKs therefore keep
working with no immediate action — re-encryption is what moves them onto the
new version so the old one can eventually be retired. See
[Key rotation](key-rotation.md) for the cross-provider model; the Vault
specifics are below.

### Workflow

1. **Inventory first.** Run `reencrypt_keys --dry-run` in your deployed
   environment to list the silo records and their resolved transit key
   names. This contacts no KMS and changes nothing — it tells you exactly
   which keys you need to rotate and gives you a record count to verify
   against in step 4.

   ```bash
   python manage.py reencrypt_keys --dry-run
   # [dry-run] Would re-encrypt: team-1 [field]
   # [dry-run] Would re-encrypt: team-2 [field]
   # ...
   # [dry-run] Done. Re-encrypted: 5, Skipped: 0, Failed: 0.
   ```

   Note the count (here, 5). Resolve the exact key names from this output, the
   **Reconcile Keys** admin page, or `vault list transit/keys` — they are
   hex-sanitized, not literal (see *Step 1: pick a naming convention* above).

2. **Rotate each silo key.** Open the Vault web UI (see
   [Accessing the Vault web UI](#accessing-the-vault-web-ui) — on HCP Vault
   this is a multi-step drill-down through the cloud portal, not a direct
   login). Then: **Secrets engines → your transit mount → Keys → `<key>` →
   Details → Versions tab → Rotate key**, and confirm the dialog. Or via CLI:
   `vault write -f transit/keys/<key>/rotate`. The latest version increments
   (e.g. v1 → v2); v1 remains for decrypt.

   Rotate **only** the keys that back silos (those resolved in step 1).
   A transit mount usually also holds unrelated keys — Vault's default
   `sample-key`, keys for other apps, smoke-test keys — **leave those alone**.
   Rotate every silo key, not just some; a partial rotation leaves a mix
   of versions, which is harmless but defeats the point of retiring the old
   version later.

3. **Re-wrap the DEKs.** Run `reencrypt_keys` (no `--dry-run`) in your deployed
   environment. encryption_suite decrypts each stored DEK with the retained old
   version and re-wraps it under the new latest version:

   ```bash
   python manage.py reencrypt_keys
   # Done. Re-encrypted: 5, Skipped (concurrent): 0, Failed: 0.
   ```

   Confirm the **re-encrypted count matches the dry-run inventory** from
   step 1, and that **Failed: 0**.

4. **Verify decryption still works.** Before retiring anything, exercise a
   real encrypt/decrypt **roundtrip** — e.g. the Reconcile Keys admin page's test
   console, or read an existing encrypted field and write a new one. Both a
   text field and an `EncryptedFileField` are worth checking, since file
   content uses Streaming AEAD. This proves the freshly re-wrapped DEKs unwrap
   under the new version. (Reads already worked before re-encryption via the
   retained old version; this step confirms the *new* wraps are good.)

5. **Retire the old version (optional).** Only after step 4 passes, raise the
   key's **minimum decryption version** in the Vault UI (the *Edit key* form)
   or `vault write transit/keys/<key>/config min_decryption_version=<N>`.
   This blocks the now-unused old versions from decrypt.

> **Order matters.** Rotate → `reencrypt_keys` → verify roundtrip → *then*
> raise `min_decryption_version`. Raising it before re-encrypting makes the
> still-old wrapped DEKs undecryptable, and `reencrypt_keys` — which must
> first decrypt the old wrap — will fail.

### Use `reencrypt_keys`, not Vault's native Rewrap

The transit engine exposes a **Rewrap** action (`transit/rewrap/<key>`) that
re-wraps a ciphertext to the latest version. **Do not use it here.** The
wrapped DEKs are stored in the `DataEncryptionKey` table, which Vault knows
nothing about; only `reencrypt_keys` reads those rows, re-wraps each DEK, and
writes back the new ciphertext, KEK reference, and incremented `reencryption_count`.

### Automatic rotation

Transit keys carry an **auto-rotation period** (`auto_rotate_period`, "never"
by default). Setting it lets Vault rotate on a schedule, an alternative to
step 1. It does **not** re-encrypt your stored DEKs — you still run
`reencrypt_keys` afterward to move them onto the new version and retire the
old one.

To have the provisioner set it on every key it creates, put
`KEK_ROTATION_PERIOD_DAYS` in `KEK_PROVISIONER_OPTIONS`. The floor is 1 day. It is
written in a second call after the key is created, so it needs `update` on
`transit/keys/<name>/config` in the policy; without that capability the key is
still created and usable, and one WARNING line says rotation was not set on it.

Existing keys are left alone — the provisioner only writes the schedule on keys
it creates, so changing the setting later does not reach keys already out there.
Set those with `vault write transit/keys/<name>/config auto_rotate_period=...`.

---

## Deleting a KEK

HashiCorp Vault is the only provider in these guides that guards deletion on the key
itself. Every key is created with `deletion_allowed: false`, and Vault refuses
`DELETE /transit/keys/<name>` while that holds. Deleting from the application
therefore overrides a Vault-side protection, and is off unless you ask for it:

```python
"KEK_PROVISIONER_OPTIONS": {
    "ALWAYS_ALLOW_KEY_DELETION": True,
},
```

The policy also needs the capabilities for both calls:

```hcl
path "transit/keys/encryption_suite-*" {
  capabilities = ["create", "read", "update", "delete"]
}
path "transit/keys/encryption_suite-*/config" {
  capabilities = ["update"]
}
```

**What deletion does here has no equivalent on the other providers.** It removes
the key and every one of its versions in a single call. There is no scheduled
window, no soft-delete, no restore, and nothing to delete afterwards — anything
still wrapped under that key is unrecoverable the moment the call returns. AWS,
GCP, OCI and IBM all give you days to change your mind; Vault gives you none.

The package's own `KEY_DELETION_WINDOW_DAYS` is therefore the *only* waiting
period in front of a transit deletion, and the **Restore** admin action during
that window is the only way back. Set it with that in mind.

With the option left off, the run stops at its capability gate, keeps the key,
and records *key deletion is not enabled for this provisioner* as the reason.
Nothing is attempted at Vault. That is a reasonable posture to run in
permanently: delete keys by hand, on the provider, where the destruction is
deliberate.

---

## Related reading

- [KEK strategies](kek-strategies.md) — full strategy reference,
  including cohort and BYOK.
- [KEK provisioning](kek-provisioning.md) — strategy-vs-provisioner
  split, the full provisioner table, and writing custom provisioners.
- [KMS adapters](kms-adapters.md) — adapter / credential strategy
  reference for Vault and the other providers.
- [Configuration reference](configuration.md) — every
  `ENCRYPTION` setting, including `KEY_AUTO_PROVISION`,
  `DEK_CACHE_TTL`, and `LOG_DECRYPTS`.
- [Key rotation](key-rotation.md) — rotating KEKs and re-encrypting.
- [Getting started with AWS KMS](getting-started-aws.md),
  [GCP Cloud KMS](getting-started-gcp.md), and
  [Azure Key Vault](getting-started-azure.md) — same workflow shape,
  other providers.
