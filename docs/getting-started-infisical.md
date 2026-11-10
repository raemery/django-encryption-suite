# Getting started with Infisical KMS

This step-by-step guide walks you through wiring django-encryption-suite to Infisical KMS in
production. This page assumes you have already followed
[Getting started](getting-started.md) for the basic Django setup
(`INSTALLED_APPS`, migrations, a silo adapter) and now need to
swap the local dev KMS for real Infisical KMS.

Works with both **Infisical Cloud** (`https://app.infisical.com`) and
**self-hosted Infisical** instances — only the `INFISICAL_ENDPOINT`
differs.

The two decisions that drive everything else on this page:

1. **Shared KEK or per-silo KEK?**
   One KMS key for the whole application vs. one key per tenant/team.
2. **How will you provision keys?**
   Either let the application **auto-provision** a key per silo on
   first use (`KEK_TEMPLATE` + `InfisicalKekProvisioner`), or create keys
   **outside this application** (Infisical web UI / Terraform provider) and reference
   them by UUID (`KEK_MAP` + `NullKekProvisioner`).

The rest of this guide walks through each combination end-to-end.

---

## Prerequisites

- An Infisical account (Cloud or self-hosted) and a project that holds
  KMS keys.
- A **Machine Identity** with Universal Auth enabled (recommended) or a
  static service token, scoped to the project that contains the KMS
  keys.
- Permission in that project to create KMS keys — granted to the Machine
  Identity itself if you want auto-provisioning, or to a security/platform
  team if you provision outside this application (in which case the application only
  needs read/encrypt/decrypt on the existing keys).
- The `django-encryption-suite` package installed — **no extra is required**
  for Infisical; the adapter uses `urllib` from the stdlib:

  ```bash
  uv add django-encryption-suite
  ```

- A working `ENCRYPTION` block in `settings.py` from
  [Getting started](getting-started.md). You will replace the
  env key store configuration with a `InfisicalKmsAdapter` block below.

---

## Provisioning on Infisical

Infisical KMS keys are identified by **server-assigned UUID**, which the
KEK strategy cannot predict before the key exists. Infisical also lets a
key be fetched by its operator-chosen **name**, and that lookup is what
makes auto-provisioning possible without the strategy ever needing to
know the UUID up front:

1. `PerSiloKekStrategy` renders a deterministic slug name from the
   silo UID via `KEK_TEMPLATE` (e.g.
   `encryption-suite-{silo_uid}`).
2. `InfisicalKekProvisioner` ensures a key with that name exists in the
   project, creating it on first encrypt.
3. `InfisicalKmsAdapter` resolves the name to its UUID via
   `GET /api/v1/kms/keys/key-name/{name}` (cached per process) and stores
   the UUID in the wrapped-key record. Decryption reads the UUID straight
   from the record, so it never needs the name lookup.

This is the same predictable-name approach AWS, GCP, Azure, Vault, and
IBM use; Infisical reaches it through the by-name lookup rather
than a directly predictable identifier. Key names must be *slugs* — lowercase
alphanumeric groups joined by single hyphens (`[a-z0-9-]`, ≤32 chars). With an
`encryption-suite-` prefix (17 chars), keep silo UIDs short and lowercase: each
uppercase or non-ASCII character hex-expands and eats into the 32-char budget.

If you would rather create keys outside this application and reference them by UUID,
use `KEK_MAP` and keep the default `NullKekProvisioner` (Combination A
below).

Infisical rotates keys on demand only — there is no rotation schedule to set, so
`KEK_ROTATION_PERIOD_DAYS` is refused at `manage.py check` rather than ignored.
Rotate from the Infisical UI or API, then run
[`reencrypt_keys`](management-commands.md) on your own cadence.

---

## Choosing a credential strategy

Select one with `OPTIONS["CREDENTIAL_STRATEGY"]`:

| Strategy | When to use | Required options |
|---|---|---|
| `universal_auth` *(default)* | Production — Machine Identity client ID + secret, token refreshed automatically | `INFISICAL_CLIENT_ID`, `INFISICAL_CLIENT_SECRET` |
| `token` | Short-lived processes / debug — a pre-fetched static service token | `INFISICAL_TOKEN` |
| `oidc` | Keyless federation — the workload presents a platform OIDC JWT (Fly, GKE, Kubernetes, Vercel, SPIFFE) exchanged for an access token; no stored secret | `INFISICAL_IDENTITY_ID`, `OIDC_SOURCE` |

`universal_auth` is the right default in production. The strategy
exchanges client ID + secret for an access token, caches it until 5
minutes before its `expiresIn` expiry, and refreshes transparently. On
a 401, the adapter invalidates the cached token and retries once.

`token` does **not** auto-renew — once the static token expires,
encrypts/decrypts will 401 and stay 401 until the process restarts with
a new token. Reserve it for short-lived jobs and one-shot scripts.

`oidc` is keyless: the workload obtains a short-lived OIDC JWT from its
platform (via an `OIDC_SOURCE` token source — see
[KMS adapters](kms-adapters.md) for the source list) and exchanges it for an
Infisical access token through the Machine Identity's **OIDC Auth** method, so
nothing secret is stored in the application. Configure the OIDC auth method on
the identity with your platform's **issuer** and an **audience** matching
`INFISICAL_OIDC_AUDIENCE` (defaults to the identity ID). The optional
**subject** binding pins trust to a specific workload; leaving it unset trusts
any workload from that issuer presenting the right audience, so the issuer
should be as narrow as your platform allows. Like `universal_auth`, the
exchanged token is cached until 5 minutes before expiry and re-exchanged on a
401.

`universal_auth` and `token` read from `OPTIONS` first, then fall back to
the environment variable of the same name.

---

## Choosing the site URL

`OPTIONS["INFISICAL_ENDPOINT"]` defaults to the Infisical Cloud
endpoint (`https://app.infisical.com`). Override it for:

- **Self-hosted Infisical** — point at your instance's external URL
  (e.g. `https://infisical.internal.example.com`).
- **Air-gapped / private cloud** — same as above plus `TLS_EXTRA_CA`
  (or `TLS_CA_BUNDLE`) in `OPTIONS` if the instance uses a private
  CA.

The same Machine Identity is scoped to one site — you cannot use Cloud
credentials against a self-hosted instance or vice versa.

---

## Decision 1 — shared vs per-silo KEK

### Shared KEK

One Infisical KMS key encrypts every silo's DEK. Simpler
operationally; one Machine Identity policy, one key to rotate, one key
to monitor in Infisical audit logs. The trade-off is blast radius: if
that single key is compromised or deleted, every tenant's encrypted
data is at risk simultaneously.

Pick this when:

- You have a single-tenant deployment (one organization, many teams that
  don't need cryptographic isolation between them).
- You want the lightest operational footprint and the per-tenant blast
  radius is not a compliance requirement.

### Per-silo KEK

Each tenant/team gets its own Infisical KMS key. Compromise or deletion
of one key affects only that tenant. Required by some compliance
regimes.

Pick this when:

- You're a multi-tenant SaaS where tenants must be cryptographically
  isolated.
- You need to demonstrate per-tenant key custody to auditors.
- You want the option to revoke a single tenant's data by deleting one
  key.

### Settings mapping

| Choice | `KEK_STRATEGY_ADAPTER` | `OPTIONS` key | Provisioner |
|---|---|---|---|
| Per-silo, created outside this application | `PerSiloKekStrategy` | `KEK_MAP` (UID → UUID) | `NullKekProvisioner` |
| Per-silo, auto-provisioned | `PerSiloKekStrategy` | `KEK_TEMPLATE` (UID → slug name) | `InfisicalKekProvisioner` |

`KEK_MAP` matches a silo UID to a key **UUID** you provisioned
yourself. `KEK_TEMPLATE` renders a key **name** that the adapter resolves
to its UUID (and the provisioner creates on first use) — see
[How provisioning works](#provisioning-on-infisical) above.

> **`SharedKekStrategy` is not supported with Infisical.** Infisical's
> KMS encrypt/decrypt API takes only `plaintext` / `ciphertext`; there
> is no AAD-equivalent field. Wrapped DEKs cannot be bound to a
> specific silo at the wrap layer; with a shared KEK and no
> AAD, an attacker who swaps wrapped DEK rows between silos in
> the database gets clean decrypts. `InfisicalKmsAdapter` rejects
> this combination at construction with `EncryptionConfigurationError`. It
> rejects the same result reached through `PerSiloKekStrategy`: a
> `KEK_TEMPLATE` with no `{silo_uid}` placeholder, and a `KEK_MAP` that
> names one key for two silos. Use
> `PerSiloKekStrategy` with Infisical (the per-tenant boundary
> comes from distinct keys, enforced by Infisical's per-key access
> control), or switch to a KMS provider whose wrap operation
> supports AAD (AWS, GCP, Fly, OCI, IBM, Local).

---

## Combination A — per-silo KEK, created outside this application (`KEK_MAP`)

Best fit: multi-tenant SaaS that needs per-tenant cryptographic
isolation, where keys are created by a security/platform team and the
application is granted only read/encrypt/decrypt.

### Step 1: provision a key per silo

For each new tenant (Terraform preferred — keys are defined in IaC alongside
everything else):

**Caution:** Infisical caps KMS key names at **32 characters** and requires
them to be *slugs*: lowercase alphanumeric groups joined by single hyphens
(`[a-z0-9-]`, no two hyphens in a row, none at the start or end). Keep the prefix short and UIDs lowercase —
uppercase and non-ASCII characters hex-expand and can overflow the limit.

```hcl
resource "infisical_kek" "tenant_42" {
  project_id           = infisical_project.encryption_suite.id
  name                 = "encryption_suite-team-42"
  encryption_algorithm = "aes-256-gcm"
}

output "tenant_42_kek_id" {
  value = infisical_kek.tenant_42.id
}
```

Or via the web UI: **KMS → Add Key → name `encryption_suite-team-42`**, then
copy the resulting UUID.

### Step 2: configure `ENCRYPTION` with `KEK_MAP`

```python
ENCRYPTION = {
    "KEY_SETS": {"default": {"silo": "...", "key_store": "infisical"}},
    "KMS_KEY_STORES": {
        "infisical": {
            "ADAPTER": "encryption_suite.adapters.key_stores.infisical.InfisicalKmsAdapter",
            "OPTIONS": {
                "CREDENTIAL_STRATEGY": "universal_auth",
                "INFISICAL_CLIENT_ID": os.environ["INFISICAL_CLIENT_ID"],
                "INFISICAL_CLIENT_SECRET": os.environ["INFISICAL_CLIENT_SECRET"],
                "KEK_MAP": {
                    "team-42": "9f3a8e1b-...",
                    "team-43": "1c2d3e4f-...",
                    # ...
                },
            },
            "KEK_STRATEGY_ADAPTER": "encryption_suite.adapters.keks.PerSiloKekStrategy",
        },
    },
}
```

For deployments with many tenants, generate `KEK_MAP` from Terraform
output (a JSON file mounted as a config secret, or rendered into
`settings.py` via a deploy step) rather than hand-editing settings.

### Step 3: grant the Machine Identity access to the project

A single project-scoped role covers every key in the project. If your
security model requires per-key permissions, write one rule per key
UUID — but that scales poorly with tenant count, which is why
project-scoped rules are the norm.

### Step 4: per-new-tenant workflow

For each new silo:

1. **Find out which UID it has.** Open the Django admin, go to
   **Data Encryption Keys → Reconcile Keys** (object-tools link,
   top right of the change list). Or visit:

   ```
   /admin/encryption_suite/dataencryptionkey/reconcile-keys/
   ```

   The page lists every silo, the KEK identifier the application
   would try to use (it will read `<missing>` for any UID not in
   `KEK_MAP`), and a **Needs setup** flag for those without a DEK row
   yet.

2. **Provision the Infisical KMS key** (Terraform / web UI as above)
   and capture the UUID.

3. **Update `KEK_MAP`** with the new UID → UUID entry and redeploy
   (or reload the secret backing it).

4. **Verify on the admin page.** Refresh the Reconcile Keys page; the
   row's resource changes from `<missing>` to the UUID and flips to
   **Ready** once the next encrypt creates the DEK.

5. **Trigger DEK creation.** With `KEY_AUTO_PROVISION = True` (default),
   the next encrypt for that tenant creates the DEK automatically.
   Otherwise:

   ```bash
   python manage.py setup_encryption_keys
   ```

Until the UUID is in `KEK_MAP`, any encrypt for that tenant raises
`KekNotProvisionedError`. The translated user-facing message is
`"Encryption and decryption are unavailable for this data."`; the log
entry contains the missing UID and the silo.

---

## Combination B — per-silo KEK, auto-provisioned (`KEK_TEMPLATE`)

Best fit: multi-tenant SaaS that needs per-tenant isolation and is
willing to let the application create its own keys, so new tenants need
no manual provisioning step.

### Step 1: grant the Machine Identity create permission

The Machine Identity needs **create KMS key** permission on the project
(in addition to read/encrypt/decrypt), so the provisioner can create a
key the first time a new tenant encrypts.

Two further permissions are optional, and each unlocks one feature:

- **list KMS keys** — lets [Reconcile Keys](admin-panel.md#reconcile-keys-page)
  check the provider side, so a key no silo claims is reported as orphaned
  instead of the page degrading to *detection-unavailable*.
- **delete KMS key** — lets the deletion destroy a tenant's key when its silo is
  deleted. Without it the key is *retained* and the reason recorded, and you
  delete it yourself.

Grant them deliberately. Deletion on Infisical is **immediate and
irreversible** — there is no recovery window on the provider side, so anything
still wrapped by that key is unrecoverable the moment the call returns.

### Step 2: configure `ENCRYPTION` with `KEK_TEMPLATE` and the provisioner

**Caution:** Infisical caps KMS key names at **32 characters** and requires
them to be slug-friendly (`[a-z0-9-]`). The rendered name is prefix + sanitized
UID, so keep the prefix short and UIDs lowercase — uppercase and non-ASCII
characters hex-expand and can overflow the limit.

**No underscores in the prefix.** Only `{silo_uid}` is sanitized; the literal
part of `KEK_TEMPLATE` is passed through exactly as written. An underscore there
reaches Infisical unchanged and is rejected at key creation with
`Key name field can only contain lowercase letters, numbers, and hyphens` — a
422 that surfaces as `KekNotProvisionedError` on the first encrypt, not as a
configuration error at deploy. Use `encryption-suite-`, not
`encryption_suite-`.

**Infisical enforces more than that message says.** A key name may also not
contain two hyphens in a row, and may not begin or end with one. Neither rule
appears in the error text, which quotes only the permitted characters. The
adapter accounts for both: it escapes disallowed characters with the letter `z`
rather than a hyphen, so `team-1` renders as `encryption-suite-team-1` and an
escaped leading character can never produce a name starting with a hyphen. A
silo UID that breaks the rule on its own — one holding `--`, or ending in `-` —
is refused with a message naming the problem, rather than reaching Infisical and
returning a 422 that appears to contradict itself.

```python
ENCRYPTION = {
    "KEY_SETS": {"default": {"silo": "...", "key_store": "infisical"}},
    "KMS_KEY_STORES": {
        "infisical": {
            "ADAPTER": "encryption_suite.adapters.key_stores.infisical.InfisicalKmsAdapter",
            "OPTIONS": {
                "CREDENTIAL_STRATEGY": "universal_auth",
                "INFISICAL_CLIENT_ID": os.environ["INFISICAL_CLIENT_ID"],
                "INFISICAL_CLIENT_SECRET": os.environ["INFISICAL_CLIENT_SECRET"],
                "INFISICAL_PROJECT_ID": os.environ["INFISICAL_PROJECT_ID"],
                # Renders a slug name per silo; the adapter resolves it to a UUID.
                "KEK_TEMPLATE": "encryption-suite-{silo_uid}",
            },
            "KEK_STRATEGY_ADAPTER": "encryption_suite.adapters.keks.PerSiloKekStrategy",
            "KEK_PROVISIONER_ADAPTER": "encryption_suite.adapters.keks.InfisicalKekProvisioner",
            "KEK_PROVISIONER_OPTIONS": {
                "CREDENTIAL_STRATEGY": "universal_auth",
                "INFISICAL_CLIENT_ID": os.environ["INFISICAL_CLIENT_ID"],
                "INFISICAL_CLIENT_SECRET": os.environ["INFISICAL_CLIENT_SECRET"],
                "INFISICAL_PROJECT_ID": os.environ["INFISICAL_PROJECT_ID"],
                "ENCRYPTION_ALGORITHM": "aes-256-gcm",
            },
        },
    },
}
```

**Finding the project ID.** It is a UUID, not the project slug, and the console
leads with the project *name* rather than the ID. To get it: open the project,
click **Settings** in the left-hand menu, and use the **Copy Project ID** button
at the top right of the Project Settings screen.

It is also in the browser URL while you are inside the project — the **second**
UUID, after the organization's:

```
https://app.infisical.com/organizations/<org-id>/projects/kms/<project-id>/overview
```

The admin test console shows this same ID on its KMS Instance line, so either
route lets you match the two up.

`INFISICAL_PROJECT_ID` is required in both `OPTIONS` (for the
name → UUID lookup) and `KEK_PROVISIONER_OPTIONS` (for key creation).
The provisioner takes its own options because provisioning may use a
different (higher-privilege) credential than routine encrypt/decrypt;
here they reuse the same Machine Identity for simplicity.

### Step 3: per-new-tenant workflow — nothing to do

With `KEY_AUTO_PROVISION = True` (default), the first encrypt for a new
silo resolves the template name, the provisioner creates the
Infisical key if absent, and the DEK is wrapped under it. No manual
provisioning, no `KEK_MAP` edit, no redeploy. The provisioner is
idempotent and caches "already ensured" names per process; a "key
already exists" race between workers is tolerated.

Key names must be *slugs* — lowercase alphanumeric groups joined by single
hyphens (`[a-z0-9-]`, ≤32 chars) — so no two hyphens in a row, and none at the
start or end. Disallowed characters
are hex-encoded behind the letter `z` — chosen so hyphens in the UID pass
through untouched and an escape never introduces one (e.g. `team-42` →
`encryption-suite-team-42`, `team:42` → `encryption-suite-teamz3a42`). Keep UIDs
short and lowercase to stay within the 32-char limit.

---

## The Reconcile Keys admin page

For Combination A in particular, this page is the operator workflow. It lists
every silo with the Infisical KMS UUID the application would use, and flags the
ones whose first encryption is still pending. See
[Reconcile Keys page](admin-panel.md#reconcile-keys-page) for the full
description and the three ways to reach it.

Because this combination resolves keys through `KEK_MAP`, a silo with no entry
in the map shows its expected key as `<missing>` and is flagged **Needs setup**
just like one whose key has not been created — add the mapping, then create the
key it names.

---

## Failure modes and what they look like

### KEK missing in `KEK_MAP`

`KekNotProvisionedError` is raised by the engine before any Infisical
call. The user sees:

> Encryption and decryption are unavailable for this data.

The admin sees an `ERROR`-level log entry naming the missing silo
UID, the strategy, and the provisioner. Add the UUID to `KEK_MAP` and
redeploy.

### Key deleted in Infisical

Infisical returns 404 from the encrypt/decrypt endpoint. The adapter's
default not-found heuristic translates this to
`KekNotProvisionedError`. **Note**: ciphertext encrypted under the deleted key
is unrecoverable.

Recovery depends on which combination you run. Under `KEK_MAP` (Combination A),
recreate the key and update the map with its new UUID — Infisical does not reuse
UUIDs. Under `KEK_TEMPLATE` (Combination B) the *name* is what is recorded, so
recreating a key under the same name is enough; the provisioner will do it on
the next encrypt, and the adapter resolves the new UUID from the name. Existing
ciphertext is still unrecoverable either way — a key with the same name is not
the same key.

### Token expired / revoked

The adapter retries once on a 401 from the encrypt/decrypt endpoint
after invalidating the cached token. If the second attempt also fails,
a 30-second cooldown suppresses further retries (auth circuit breaker)
and the underlying `urllib.error.HTTPError` propagates.

For `universal_auth`: rotate the Machine Identity client secret in your
secret store and redeploy. For `token`: there is no auto-renew — the
static token must be replaced and the process restarted.

### Wrong site URL

The adapter does not infer the site — it must be set in
`OPTIONS["INFISICAL_ENDPOINT"]` (or left as the Cloud default).
Self-hosted instances have their own key namespace; a UUID created on
Cloud is invisible from a self-hosted instance and vice versa.

### Self-hosted with private CA

Set `OPTIONS["TLS_EXTRA_CA"]` to your internal CA bundle path so
the adapter trusts both public CAs and your internal one. Use
`TLS_CA_BUNDLE` to *replace* the system trust store entirely (private
CA only).

---

## Related reading

- [KEK strategies](kek-strategies.md) — full strategy reference, including
  cohort and BYOK.
- [KEK provisioning](kek-provisioning.md) — strategy-vs-provisioner split,
  and how `InfisicalKekProvisioner` auto-creates keys via the by-name lookup.
- [KMS adapters](kms-adapters.md) — adapter / credential strategy
  reference for Infisical and the other providers.
- [Configuration reference](configuration.md) — every `ENCRYPTION`
  setting, including `KEY_AUTO_PROVISION`, `DEK_CACHE_TTL`, and
  `LOG_DECRYPTS`.
- [Key rotation](key-rotation.md) — rotating KEKs and re-encrypting.
