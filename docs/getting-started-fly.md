## Getting started with Fly.io KMS

This step-by-step guide walks you through wiring django-encryption-suite to Fly.io KMS
(secretkeys) in production. This page assumes you have already
followed [Getting started](getting-started.md) for the basic Django
setup (`INSTALLED_APPS`, migrations, a silo adapter) and now need
to swap the local dev KMS for Fly KMS on a Django app deployed to
Fly.io.

The two decisions that drive everything else on this page:

1. **Shared KEK or per-silo KEK?**
   One secretkey for the whole application vs. one secretkey per
   tenant/team.
2. **Auto-provision or manual?**
   Let the application create secretkeys on first encrypt vs.
   provision them outside this application (`flyctl` / a release script) before
   the application sees them.

The rest of this guide walks through each combination end-to-end.

---

## Prerequisites

- A Fly.io account, organization, and a Fly **app** that hosts your
  Django process (this guide uses `my-fly-app` as the app name).
- The `flyctl` CLI installed and authenticated (`fly auth login`).
- Your Django app deployed to Fly. The KMS adapter (encrypt/decrypt)
  talks to the local `/.fly/api` Unix socket and **only runs inside a
  Fly machine** — there is no external transport for that path. The
  KEK provisioner (key creation) talks to the public Fly Machines API
  at `https://api.machines.dev` with a `FLY_API_TOKEN`; see
  [Provisioner authentication](#provisioner-authentication-fly_api_token)
  below.
- No extra Python packages needed. Fly KMS uses only `urllib` and
  `http.client` from the standard library.

> **A note on the app name.** Fly injects `FLY_APP_NAME` as an
> environment variable into every machine. Both the KMS adapter and
> the KEK provisioner pick it up automatically, so you do **not** need
> to set `FLY_APP_NAME` in `OPTIONS` / `KEK_PROVISIONER_OPTIONS`
> when running on Fly. The examples below omit it for that reason. If
> you set it explicitly, the environment variable still wins — that
> way a machine can never be tricked into talking to the wrong app
> via a stale settings file.

### A note on Fly KMS (secretkeys)

Fly KMS exposes per-app named secretkeys over the Machines API. The
encrypt/decrypt endpoints are restricted to processes running inside
machines that belong to the same app — Fly authenticates by socket
mount, not by token. External callers, even with a valid Fly API
token, receive HTTP 403 on `/encrypt` and `/decrypt`.

Three consequences for the operator:

- **You cannot test encrypt/decrypt from a work station.** Verification has
  to happen inside a running Fly machine — the `/encrypt` and
  `/decrypt` endpoints accept only the local `/.fly/api` socket
  transport. (See the
  [security note](#security-note-socket-auth-token-exposure-and-rce-blast-radius)
  below.)
- **The local socket does NOT authorize key creation.** Calling
  `POST /v1/apps/{app}/secretkeys/{name}/generate` over `/.fly/api`
  returns HTTP 403 `unauthorized`, regardless of the OS user. Fly
  requires a bearer token for management operations. The provisioner
  shipped here therefore talks to the public Machines API
  (`https://api.machines.dev`) with `FLY_API_TOKEN`. The provisioner
  can run from inside or outside a Fly machine as long as the token is
  available, but it is normally driven from Django at runtime.
- **`/generate` overwrites in place with no version history.** If you
  call generate twice on the same key name, every ciphertext encrypted
  under the previous material becomes permanently unrecoverable. The
  provisioner shipped here is GET-first and never re-generates an
  existing key, but if you reach for `flyctl` directly, treat
  `secretkeys generate <name>` as destructive on existing names.

### A note on key types

Fly secretkeys come in several types: `xaes256gcm`, `hs256`, `hs384`,
`hs512`, `nacl_auth`, `nacl_box`, `nacl_secretbox`, `nacl_sign`. Only
**`xaes256gcm`** is an AEAD primitive suitable for envelope
encryption; the others are MAC or signing types. The adapter and
provisioner default to `xaes256gcm`. Do not change that unless you
know exactly what you are doing.

---

## Choosing the adapter variant

There is one Fly KMS adapter:

| Adapter | `ADAPTER` value | Provider ID |
|---|---|---|
| Fly secretkeys | `encryption_suite.adapters.key_stores.fly.FlyKmsAdapter` | `"fly"` |

It supports `KEK_TEMPLATE` / `KEK_MAP` / `SHARED_KEK_ID`. It works
with `FlyKmsKekProvisioner` for application-driven provisioning, or
with `NullKekProvisioner` (the default) when keys are managed
outside this application.

Unlike GCP and AWS, there is **no Tink-backed variant**. Fly's
secretkeys API is simple enough that wrapping it with Tink would
add no functional benefit.

---

## Decision 1 — shared vs per-silo KEK

### Shared KEK

One Fly secretkey encrypts every silo's DEK. Simpler operationally;
one key to monitor, one key to manage. The trade-off is blast radius: if
that single key is compromised or accidentally regenerated, every
tenant's encrypted data is at risk simultaneously.

Pick this when:

- You have a single-tenant deployment.
- You want the lightest operational footprint and the per-tenant blast
  radius is not a compliance requirement.

### Per-silo KEK

Each tenant/team gets its own secretkey. Compromise or destruction of
one key affects only that tenant. Required by some compliance regimes
(HIPAA multi-tenant scenarios, customer-managed encryption keys for
B2B contracts).

Pick this when:

- You're a multi-tenant SaaS where tenants must be cryptographically
  isolated.
- You need to demonstrate per-tenant key custody to auditors.
- You want the option to revoke a single tenant's data by destroying
  one key (Fly secretkeys can be deleted via the API).

### Settings mapping

| Choice | `KEK_STRATEGY_ADAPTER` | `OPTIONS` key |
|---|---|---|
| Shared | `SharedKekStrategy` | `SHARED_KEK_ID` (secretkey name) |
| Per-silo | `PerSiloKekStrategy` | `KEK_TEMPLATE` (or `KEK_MAP`) |

### Name constraints (important)

Fly secretkey names must match `[A-Za-z0-9_]+` — letters, digits, and
underscore only. No hyphens, no slashes, no dots.

Under `KEK_TEMPLATE`, the strategy escapes the silo UID to fit: every other
character becomes `_` plus its UTF-8 bytes in hex, and an underscore already in
the UID is doubled. The encoding is reversible, so two distinct UIDs never
share a key name:

```python
"KEK_TEMPLATE": "encryption_suite_{silo_uid}",
# silo_uid "42"      → "encryption_suite_42"
# silo_uid "team-42" → "encryption_suite_team_2d42"
# silo_uid "team_42" → "encryption_suite_team__42"
```

Only the UID is escaped. The template's literal text must conform on its own,
which is why the prefix above uses underscores. `FlyKmsKekProvisioner` checks
every name before it creates a key and raises a `ValueError` naming one that
does not conform.

To choose the key names yourself, use `KEK_MAP`. Its values are used exactly as
given, so each must conform:

```python
"KEK_MAP": {
    "team-42": "encryption_suite_team_42",
    "acme.inc": "encryption_suite_acme_inc",
},
```

---

## Decision 2 — manual vs auto provisioning

### Manual (`NullKekProvisioner`, the default)

Someone (or something) creates the secretkey before the application
tries to use it. Typical flows:

- **`flyctl`** — the `fly secrets keys` subcommands manage the
  KMS-key surface from your work station, but **not** for creating a
  suite KEK (its `generate` makes the wrong primitive — see below). Use
  it for `list`/`delete`; provision via the raw API or the auto-provisioner.
  Note that `fly secrets keys` (KMS-managed encryption keys, exposed
  to running machines under `/.fly/kms`) is a different surface from
  `fly secrets` (env-var secrets, materialized as environment
  variables at deploy time). The `keys` subcommand is the right one
  here. Quick reference:

  ```bash
  fly secrets keys list -a my-fly-app --json   # secret_type shows the primitive
  fly secrets keys delete <name> -a my-fly-app
  # NOT for a suite KEK: `fly secrets keys generate encrypting <name>` makes a
  # nacl_secretbox key — provision xaes256gcm via the raw /generate API instead.
  ```

  `flyctl` takes a *semantic* type (`encrypting` or `signing`), not the
  underlying primitive — and `encrypting` resolves to a **`nacl_secretbox`**
  key, **not** the `xaes256gcm` primitive the suite's KEY_TYPE expects
  (confirmed via `fly secrets keys list --json`, which shows `secret_type`).
  So the CLI `generate` is the wrong tool for a suite KEK: provision with the
  raw `/generate` API and `{"type":"xaes256gcm"}` (shown below), or simply let
  `FlyKmsKekProvisioner` create the `xaes256gcm` key on first use. The CLI
  `list`/`delete` subcommands are fine.

- **A management command run via `release_command`** — pre-create keys
  for a list of existing tenants when first adopting the package.
  Requires `FLY_API_TOKEN` set on the app (see
  [Provisioner authentication](#provisioner-authentication-fly_api_token));
  the release machine cannot create secretkeys via the local socket.

With `NullKekProvisioner` the running application itself does **not**
need `FLY_API_TOKEN` at runtime — the local socket mount is sufficient
for encrypt/decrypt. The operator's `flyctl` auth covers the
provisioning step separately.

When a missing key is hit at runtime, the engine raises
`KekNotProvisionedError` with a translated user-facing message
("Encryption and decryption are unavailable for this data.") and an
English admin log entry naming the missing key and the strategy in
use. The Django admin
[**Reconcile Keys** page](admin-panel.md#reconcile-keys-page) is the operator
workflow for catching this before users do.

### Auto (`FlyKmsKekProvisioner`)

The application creates the secretkey the first time a new silo
encrypts data. Typical use case: multi-tenant SaaS where new tenants
sign up mid-request and you don't want a manual provisioning step
blocking their first save.

The provisioner talks to Fly's public Machines API at
`https://api.machines.dev` with a bearer token (set up in
[Provisioner authentication](#provisioner-authentication-fly_api_token)
below). This is the path Fly authorizes for secretkey creation; the
local socket the adapter uses does not. What the provisioner adds:

1. A `GET /v1/apps/{app}/secretkeys/{name}` probe before any create.
2. A `POST /v1/apps/{app}/secretkeys/{name}/generate` only when the
   probe returns 404.
3. An in-process "already ensured" cache so subsequent encrypts skip
   the probe.

The probe-first behavior is **not optional**: Fly's `/generate`
overwrites key material in place with no version history, so calling
it on an existing key would destroy every ciphertext encrypted under
the previous material. The provisioner is hard-coded to never do that.

### Combinations

| KEK choice | Provisioning | Per-tenant ops |
|---|---|---|
| Shared | Manual | Create one secretkey once via `flyctl`, configure name, done |
| Shared | Auto | Rare — one key only, manual is just as easy |
| Per-silo | Manual | New tenant ⇒ admin creates secretkey, then tenant can encrypt |
| Per-silo | Auto | New tenant ⇒ first encrypt creates the secretkey; zero operator setup |

The four combinations below give you concrete `settings.py` snippets
and operator workflows for each.

---

## Combination A — shared KEK, manual provisioning

Best fit: small / single-tenant deployments.

### Step 1: create the secretkey

Provision with the raw `/generate` API on the `fly secrets keys` surface
(distinct from `fly secrets`, which manages env-var secrets) so the key is
the `xaes256gcm` primitive the suite expects. Do **not** use
`fly secrets keys generate` here — its `encrypting` semantic type creates a
`nacl_secretbox` key, the wrong primitive (confirmed via
`fly secrets keys list --json`, which reports `secret_type`). Better still,
skip this step entirely and let `FlyKmsKekProvisioner` create the key on
first use.

```bash
curl -i \
  https://api.machines.dev/v1/apps/my-fly-app/secretkeys/encryption_suite/generate \
  -H "Authorization: Bearer $FLY_API_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"type":"xaes256gcm"}'
fly secrets keys list -a my-fly-app --json   # confirm secret_type=xaes256gcm
```

Replace `my-fly-app` with the actual app name.

### Step 2: configure `ENCRYPTION`

```python
ENCRYPTION = {
    "KEY_SETS": {"default": {"silo": "...", "key_store": "fly"}},  # whatever you use
    "KMS_KEY_STORES": {
        "fly": {
            "ADAPTER": "encryption_suite.adapters.key_stores.fly.FlyKmsAdapter",
            "OPTIONS": {
                "SHARED_KEK_ID": "encryption_suite",
            },
            "KEK_STRATEGY_ADAPTER": "encryption_suite.adapters.keks.SharedKekStrategy",
            # KEK_PROVISIONER_ADAPTER omitted — defaults to NullKekProvisioner
        },
    },
}
```

The adapter resolves `SHARED_KEK_ID` against the Fly app it is running
in (read from `FLY_APP_NAME`) to build the request path
`/v1/apps/my-fly-app/secretkeys/encryption_suite/encrypt` etc.

### Step 3: create DEKs

Each silo still needs its own DEK row, encrypted under the shared
secretkey. Either let the engine create them lazily on first encrypt
(`KEY_AUTO_PROVISION = True`, the default) or pre-create them in bulk.
Run this **inside a Fly machine**, e.g. via `release_command` or
`fly machine exec`:

```bash
python manage.py setup_encryption_keys
```

That's it. The application is now encrypting under one shared
secretkey.

---

## Combination B — per-silo KEK, manual provisioning

Best fit: multi-tenant SaaS that wants per-tenant isolation but does
not want application code creating keys.

### Step 1: pick a naming convention

Fly secretkey names must match `[A-Za-z0-9_]+` (see [Name
constraints](#name-constraints-important) above). The convention is
encoded as a template containing `{silo_uid}`:

```
encryption_suite_{silo_uid}
# silo_uid "42"      → "encryption_suite_42"
# silo_uid "team_42" → "encryption_suite_team_42"
# silo_uid "team-42" → rejected at runtime — re-map via KEK_MAP
```

If your silo UIDs contain characters outside the allowed set,
prefer `KEK_MAP` over `KEK_TEMPLATE`:

```python
"KEK_MAP": {
    "team-42": "encryption_suite_team_42",
    "acme.inc": "encryption_suite_acme_inc",
},
```

### Step 2: configure `ENCRYPTION`

```python
ENCRYPTION = {
    "KEY_SETS": {"default": {"silo": "...", "key_store": "fly"}},
    "KMS_KEY_STORES": {
        "fly": {
            "ADAPTER": "encryption_suite.adapters.key_stores.fly.FlyKmsAdapter",
            "OPTIONS": {
                "KEK_TEMPLATE": "encryption_suite_{silo_uid}",
            },
            "KEK_STRATEGY_ADAPTER": "encryption_suite.adapters.keks.PerSiloKekStrategy",
        },
    },
}
```

### Step 3: provisioning workflow per new tenant

For each new silo:

1. **Find out which key it needs.** Open the Django admin, go to
   **Data Encryption Keys → Reconcile Keys** (object-tools link, top
   right of the change list). Or visit:

   ```
   /admin/encryption_suite/dataencryptionkey/reconcile-keys/
   ```

   The page lists every silo, the resolved secretkey name the
   application would try to use, and a **Needs setup** flag for those
   without a DEK row yet.

2. **Create the secretkey.** Provision via the raw `/generate` API so the
   key is the `xaes256gcm` primitive the suite expects — `fly secrets keys
   generate` is the wrong tool here (its `encrypting` type yields a
   `nacl_secretbox` key). This is the KMS-key surface, distinct from
   `fly secrets` which manages env-var secrets:

   ```bash
   curl -i \
     https://api.machines.dev/v1/apps/my-fly-app/secretkeys/encryption_suite_team_42/generate \
     -H "Authorization: Bearer $FLY_API_TOKEN" \
     -H 'Content-Type: application/json' \
     -d '{"type":"xaes256gcm"}'
   ```

   Verify the primitive with:

   ```bash
   fly secrets keys list -a my-fly-app --json   # confirm secret_type=xaes256gcm
   ```

3. **Verify on the admin page.** Refresh the Reconcile Keys page; the row's
   status changes to **Ready** once the DEK is created (immediately if
   you also run `setup_encryption_keys`, or on the next encrypt with
   `KEY_AUTO_PROVISION = True`).

4. **Trigger DEK creation.** With `KEY_AUTO_PROVISION = True`
   (default), the next encrypt for that tenant creates the DEK
   automatically. Otherwise, run `setup_encryption_keys` inside a
   machine.

Until the secretkey exists, any encrypt for that tenant raises
`KekNotProvisionedError`. The translated user-facing message is
`"Encryption and decryption are unavailable for this data."`; the
log entry contains the missing key name and the silo UID.

---

## Combination C — per-silo KEK, auto provisioning

Best fit: multi-tenant SaaS that wants zero per-tenant manual steps.

### Step 1: configure `ENCRYPTION`

Same `OPTIONS` as Combination B, plus a provisioner block:

```python
ENCRYPTION = {
    "KEY_SETS": {"default": {"silo": "...", "key_store": "fly"}},
    "KMS_KEY_STORES": {
        "fly": {
            "ADAPTER": "encryption_suite.adapters.key_stores.fly.FlyKmsAdapter",
            "OPTIONS": {
                "KEK_TEMPLATE": "encryption_suite_{silo_uid}",
            },
            "KEK_STRATEGY_ADAPTER": "encryption_suite.adapters.keks.PerSiloKekStrategy",

            "KEK_PROVISIONER_ADAPTER": "encryption_suite.adapters.keks.FlyKmsKekProvisioner",
            "KEK_PROVISIONER_OPTIONS": {
                # "KEY_TYPE": "xaes256gcm",   # default; leave alone
            },
        },
    },
}
```

`KEK_PROVISIONER_OPTIONS` is intentionally separate from `OPTIONS`
so that other providers can point the provisioner at different
credentials than the runtime path. For Fly there is no credential
distinction — both talk to the same socket and pick up `FLY_APP_NAME`
from the machine environment — so this block can be empty in most
deployments.

### Step 2: deploy and forget

Each new silo now triggers, on first encrypt:

1. `FlyKmsKekProvisioner.ensure_kek` calls
   `GET /v1/apps/{app}/secretkeys/{name}` over the local socket.
2. If 404, calls `POST .../generate` with `{"type": "xaes256gcm"}`.
3. The new secretkey encrypts a freshly generated DEK; the encrypted
   DEK is stored as a `DataEncryptionKey` row.
4. Subsequent encrypts skip provisioning (in-process cache + Fly
   already has the key).

The provisioner is idempotent. Concurrent first-encrypts from
different machines will each GET successfully (or both see the same
404 + generate; the second generate is a no-op overwrite of identical
material the first generate just produced — undesirable but not
data-destroying because no ciphertext exists yet at that point). The
in-process cache ensures subsequent calls within the same process skip
both the GET and the generate.

### Step 3: monitoring

The `encryption_suite` logger emits an `INFO`-level entry on each
successful provision:

```
FlyKmsKekProvisioner: generated KEK 'encryption_suite_team_42' for silo 'team-42'.
```

There is no Fly-side audit log surface comparable to Cloud Audit Logs
(GCP) or CloudTrail (AWS). If you need a durable record of key
creation, route this logger to a persistent sink (Sentry, Loki,
CloudWatch, etc.).

---

## Combination D — shared KEK, auto provisioning

Rarely useful in production. With a shared KEK there is exactly one
secretkey to create; doing that via `flyctl` once is faster than
configuring a provisioner. Provided for completeness — same shape as
Combination C but with `SharedKekStrategy` and a single
`SHARED_KEK_ID`.

```python
"OPTIONS": {
    "SHARED_KEK_ID": "encryption_suite",
},
"KEK_STRATEGY_ADAPTER": "encryption_suite.adapters.keks.SharedKekStrategy",
"KEK_PROVISIONER_ADAPTER": "encryption_suite.adapters.keks.FlyKmsKekProvisioner",
"KEK_PROVISIONER_OPTIONS": {},
```

The provisioner is called once per silo (which always resolves
to the same name), so the in-process cache makes this near-free after
the first call.

---

## Authentication

Fly KMS uses two distinct transports with two distinct auth models:

| Operation | Transport | Auth |
|---|---|---|
| `/encrypt`, `/decrypt` (adapter) | Local `/.fly/api` Unix socket | Mount-based — must run inside a Fly machine that belongs to the app. No token. |
| `/generate`, `GET secretkey` (provisioner) | Public `https://api.machines.dev` | Bearer token via `FLY_API_TOKEN`. |

The split is a Fly platform constraint, not a package design choice.
The local socket is intentionally restricted to encrypt/decrypt; key
management endpoints reject it with HTTP 403 `unauthorized`. There is
no single transport that covers both.

The adapter has one knob, `FLY_SOCKET_PATH` (default `/.fly/api`),
useful in tests where you want to point at a fake socket. In
production, leave it at the default.

Pointing it at a path with no socket is also the cleanest way to see what an
unreachable KMS actually does to your application, on a staging deployment: every
wrap and unwrap fails, so silo-encrypted fields and files degrade to their
fallback label while plaintext columns and
[system encrypted ones](system-wide-silos.md) carry on — including, if you
use them for it, the columns a sign-in reads. Construction is I/O-free, so a bogus
path still passes `manage.py check` and still deploys; the failure arrives at the
first read. Make it an environment-backed setting rather than a literal if you want
to try this without a rebuild.

### Provisioner authentication (`FLY_API_TOKEN`)

If you are using `FlyKmsKekProvisioner` (Combinations C and D), the
provisioner needs a Fly auth token to call the secretkeys management
API. If you are using `NullKekProvisioner` (Combinations A and B —
manual provisioning), this section does not apply: `flyctl` from your
work station already has its own token via `fly auth login`, and the running
Django app never needs one.

#### 1. Mint a deploy-scoped token

A deploy-scoped token only grants management rights for one app, which
is the right blast radius for a key provisioner. Run on your work station:

```bash
fly tokens create deploy -a my-fly-app --expiry 8760h
```

Copy the printed token (starts with `FlyV1 fm2_…`).

#### 2. Set it as a Fly app secret

```bash
fly secrets set FLY_API_TOKEN="<paste-token-here>" -a my-fly-app
```

Fly redeploys the app and exposes the value as the `FLY_API_TOKEN`
environment variable inside every machine. The provisioner reads it
directly from `os.environ`; you do **not** need to add anything to
`settings.py`. The variable is consumed only by this provisioner, so
threading it through Django settings would add noise without
information (the Fly-injected `FLY_APP_NAME` is handled the same way
for the same reason).

#### 3. Operational notes

- **Rotation.** When the token nears expiry, repeat steps 1 and 2.
  `fly secrets set` triggers a redeploy, so plan rotation around a
  deploy window.
- **Local development.** The provisioner is unreachable without a Fly
  machine running the application anyway (the adapter cannot dial
  `/.fly/api` from your work station), so no local token is needed.
- **Missing token at runtime.** `ensure_kek` raises `RuntimeError`
  naming the variable; the engine wraps it as `KekNotProvisionedError`
  with the translated user-facing message, and the admin log records
  the underlying error.

#### Failure surface

| Symptom | Cause |
|---|---|
| `RuntimeError: FLY_API_TOKEN is not set` | Secret not set on the app, or app not redeployed since `fly secrets set` |
| HTTP 401 from provisioner | Token expired or revoked; mint a new one |
| HTTP 403 from provisioner | Token does not authorize the target app (wrong scope) |
| HTTP 403 from adapter on `/encrypt` | Process is not inside a Fly machine in this app — `FLY_API_TOKEN` would not help, and is not consulted by the adapter |

---

## Fly.io as an OIDC token source

A Fly app can also reach a KMS outside Fly without a stored secret. Every Fly
machine can mint a signed OIDC token, and AWS, GCP, Azure, HashiCorp Vault and
Infisical can all trust it through their `oidc` credential strategy. Set
`"OIDC_SOURCE": "fly"` in that KMS's options; the source needs no
`OIDC_SOURCE_OPTIONS`. The provider guides use the values below as their
worked example. [OIDC federation](how-oidc-works.md) explains the exchange
itself.

### Issuer

The issuer is `https://oidc.fly.io/<org>`, where `<org>` is your organization
slug. It is per organization, not per app: every machine in the org gets
tokens from the same issuer, so the subject binding is what limits trust to
one app.

The discovery document is public:

```bash
curl https://oidc.fly.io/<org>/.well-known/openid-configuration
```

Its `jwks_uri` is `https://oidc.fly.io/<org>/.well-known/jwks`. A provider
that guesses `jwks.json` instead gets a 404, so let the provider discover the
path from the document.

### Claims

| Claim | Value |
|---|---|
| `iss` | `https://oidc.fly.io/<org>` |
| `aud` | Whatever the workload requested |
| `sub` | `<org>:<app>:<machine-name>` |
| `app_name` | The app name |
| `org_name` | The org name, which can differ from the slug in the issuer URL |
| `machine_name` | The machine name |

A machine keeps its name across autostop and autostart. Recreating a machine
or scaling the app creates new names, and one app can serve traffic from
several machines at once. A binding that pins one exact `sub` therefore
breaks as soon as another machine answers.

### Binding the subject

Each provider binds the app in its own way:

| Provider | Binding |
|---|---|
| AWS | `StringLike` on `oidc.fly.io/<org>:sub` with `<org>:<app>:*` |
| GCP | The workload identity pool, or one subject per machine |
| Azure | One federated identity credential per machine `sub`, at most 20 per app, so `client_secret` suits an app that scales |
| HashiCorp Vault | `bound_claims` on `app_name` and `org_name` |
| Infisical | A glob subject, `<org>:<app>:*` |

### Fetching a token by hand

To read the claims a machine actually presents, open a shell with
`fly ssh console` and ask the local socket for a token:

```bash
TOK=$(curl -s --unix-socket /.fly/api -X POST \
  -H "Content-Type: application/json" \
  http://localhost/v1/tokens/oidc -d '{"aud":"<audience>"}')
echo "$TOK" | cut -d. -f2 | base64 -d 2>/dev/null; echo
```

The socket returns the raw JWT as the response body, even though it labels
the response `application/json`. A token expires after about ten minutes, and
the package fetches a fresh one for each exchange. The token is a live
credential, so read its claims and never paste the token itself anywhere.

The application user needs access to the socket, as described in
[Granting the application user access to `/.fly/api`](#granting-the-application-user-access-to-flyapi).

---

## Security note: socket auth, token exposure, and RCE blast radius

There are two distinct capabilities sitting inside a Fly machine that
runs the FlyKmsAdapter and (optionally) the FlyKmsKekProvisioner.
Each grants a different set of operations and each has a different
revocation story.

### Capability 1: the `/.fly/api` socket (always present)

The `/.fly/api` socket is authenticated by mount, which means **any
process inside the machine can call `/encrypt` and `/decrypt` on
every secretkey in the app**. Code execution in the application
container grants the ability to call `/encrypt` and `/decrypt` until
the RCE is lost or the machine stops. The Fly-specific property is
that there is no credential to expire or revoke — the mount itself
is the capability. The chown-then-drop pattern in
[Granting the application user access to `/.fly/api`](#granting-the-application-user-access-to-flyapi)
does not change this; once the socket is reachable by *any* process
in the machine, RCE inside that process inherits the capability.

Cloud KMS adapters share the underlying RCE-implies-decrypt-access
property during an active session, but their credentials have finite
TTLs and can be invalidated by rotating the role or revoking the
OIDC trust. See [Security model — A compromised application
server](security.md#a-compromised-application-server) for the
generic property.

### Capability 2: `FLY_API_TOKEN` (only with auto-provisioning)

`FlyKmsKekProvisioner` requires a `FLY_API_TOKEN` app secret (see
[Provisioner authentication](#provisioner-authentication-fly_api_token)).
Fly materializes app secrets as environment variables inside every
machine, so the token is readable by **any process running in the
machine**, including a compromised Django process. With the token,
an attacker can call the public Machines API for the app and:

- create new secretkeys (`POST .../secretkeys/{name}/generate`);
- **overwrite existing secretkeys** by calling `/generate` on a name
  that already exists — this destroys every ciphertext encrypted
  under the previous material, with no recovery path;
- delete secretkeys (`DELETE .../secretkeys/{name}`), again
  destroying every ciphertext under that key;
- list secretkey names.

Compared with the socket-only capability, this is a *destructive*
escalation: the socket lets an attacker decrypt while present; the
token lets the same attacker permanently destroy ciphertexts that
outlive the RCE.

`FLY_API_TOKEN` does have a finite lifetime and can be revoked. If
you suspect compromise:

```bash
fly tokens list -a my-fly-app          # find the token
fly tokens revoke <token-id>           # revoke it
fly tokens create deploy -a my-fly-app --expiry 8760h  # mint a new one
fly secrets set FLY_API_TOKEN="<new>" -a my-fly-app
```

Revocation invalidates the token immediately (subsequent calls return
401) but does **not** undo any destructive operations the attacker
performed before revocation. Rotation cadence and detection latency
matter.

### Mitigations

These limits are operational, and this package cannot configure them:

- **Use `NullKekProvisioner` whenever possible.** With manual
  provisioning, the running machine carries no `FLY_API_TOKEN` at
  all and the destructive escalation in Capability 2 is unavailable
  to an attacker. The trade-off is operator effort per new tenant;
  see [Combination B](#combination-b--per-silo-kek-manual-provisioning).
- **Scope `FLY_API_TOKEN` tightly.** Always use a deploy-scoped
  token (`fly tokens create deploy -a <app>`) rather than a personal
  org-wide token. A deploy token's authority is limited to the one
  app it was minted for, so a compromised machine cannot reach
  secretkeys in other apps in the org.
- **Set a short token expiry and rotate.** A 1-year expiry is a
  reasonable default; shorter is better if your deploy cadence
  supports it. `fly secrets set` triggers a redeploy, so plan
  rotation around a deploy window.
- **Run trusted code only in the application machine.** Apply the
  same RCE-defense hygiene as for AWS-instance-IAM or
  GCP-metadata-token deployments — input validation, dependency
  pinning, sandboxing of any user-supplied content.
- **Per-silo KEKs** reduce blast radius for *partial-information*
  attacks against one tenant, but do nothing against full RCE inside
  the application process — RCE inherits both capabilities for every
  tenant.
- **Do not run the web server as root.** The chown-then-drop pattern
  earlier in this guide is the recommended approach. Running as root
  doesn't widen *this section's* capabilities (RCE-as-root vs.
  RCE-as-appuser both reach the socket and the env), but it widens
  the blast radius along orthogonal axes (writable codebase, ability
  to install tooling for persistence, etc.).

If your threat model puts RCE inside the application container in
scope and you cannot tolerate the destructive-escalation property of
Capability 2, the stronger posture is to keep the KEK in a *different*
trust domain (AWS KMS, GCP Cloud KMS, Vault, etc.) reached via OIDC
federation from the Fly machine. Both `FLY_API_TOKEN` and an
OIDC-federated cloud credential are time-bounded, but the practical
lifetimes differ by orders of magnitude: `FLY_API_TOKEN` is a static
bearer token sitting in the machine's env for whatever expiry you
set at `fly tokens create` time (typically months to a year, until
manually rotated), whereas an OIDC-federated credential is minted on
demand and rotated per-request by the SDK with a TTL measured in
minutes. A stolen OIDC credential is useful only briefly; a stolen
`FLY_API_TOKEN` is useful until you notice and revoke. See
[OIDC token sources](kms-adapters.md#oidc-token-sources) for the
federation path — Fly→AWS, Fly→GCP, Fly→Azure, Fly→Vault are all
supported.

---

## Rotating a key encryption key

Fly KMS has no rotation of its own and no soft delete: removing a key destroys it
immediately, and Fly is explicit that this is the design — deleting a key is how
you make the data it protected unreadable, so there is deliberately no backup or
recovery path to undo it.

What Fly suggests instead is a **name rollover**: create a second key under a new
name and move to it, rather than replacing the key behind one name. Their CLI
hints at the convention by appending a version suffix (`myencrkeyv0`), but that
suffix is a flyctl convention rather than a platform feature — the socket API
this package uses sees two independent keys with two names.

So a rotation here is a configuration change plus a re-wrap. The general rules for
a name rollover are in [Key rotation](key-rotation.md#name-rollover);
this is the Fly walkthrough.

### Put the generation marker after `{silo_uid}`

Write the new template as `kms_{silo_uid}_v2`, not `kms_v2_{silo_uid}`.

This package identifies the keys it owns by the literal text of `KEK_TEMPLATE`
*before* the `{silo_uid}` placeholder — the owner prefix. That one string decides
which keys are listed from the provider during reconcile, which keys the deletion
gates will authorize, and which keys count as this deployment's rather than
another's.

Move the prefix and the previous generation stops being yours as far as the
package is concerned: it is no longer listed, no longer reported, and the admin
will refuse to delete it. The keys remain on Fly, billable, removable only with
`flyctl` or the dashboard. Keep the prefix fixed and both generations stay owned,
listed and deletable throughout.

A `_v2` suffix does make `fly secrets keys list` split the name across its `NAME`
and `VERSION` columns — a CLI artifact, not a provider one. See [reading the
listing after a
rollover](key-rotation.md#reading-fly-secrets-keys-list-after-a-rollover).

### The rollover

1. Point `KEK_TEMPLATE` at the next generation, e.g. `kms_{silo_uid}_v2`.
2. Deploy. New silos provision under the new name; existing rows still reference
   the old key and keep decrypting.
3. Preview the move:

```
python manage.py reencrypt_keys --provision --dry-run
```

   This contacts no KMS. It lists the key names it would create, and refuses
   outright if the owner prefix has changed — at that point nothing has been
   created and backing the template change out returns you to where you started.

4. Run it for real:

```
python manage.py reencrypt_keys --provision
```

   Each silo's new key is provisioned, then each data encryption key is unwrapped
   under the old key and rewrapped under the new one. The DEK's own material never
   changes; only its wrapper moves.

5. Confirm every record's `reencryption_count` incremented, then remove the old
   keys — Reconcile Keys to refresh the orphan flags, then the Key Encryption Keys
   changelist filtered on **Orphaned**, where the old generation can be selected
   and scheduled in one action. Delete them after the restore window.

> **Wait for step 4 before touching the orphan report.** Reconcile decides what is
> orphaned by resolving the *current* template for every live silo, so the moment
> step 2 deploys, the previous generation is reported as orphaned — while every
> data encryption key still depends on it. Deleting a key at that point destroys
> the only thing that can unwrap the DEKs still referencing it.

Because each generation is a separate key, the old one stays listed for as long as
you keep it, and the orphan report becomes trustworthy once the rewrap has
finished.

---

## Failure modes and what they look like

### Secretkey missing in the app

`KekNotProvisionedError` is raised by the engine. The user sees:

> Encryption and decryption are unavailable for this data.

The admin sees an `ERROR`-level log entry naming the resolved key name,
the silo UID, the strategy, and the provisioner. With
`NullKekProvisioner` the message points to provisioning outside this application;
with `FlyKmsKekProvisioner` the message also names the underlying
HTTP error (typically 401 if `FLY_API_TOKEN` is missing/expired, or
403 if the token does not authorize the target app).

### Running the adapter outside a Fly machine

The adapter dials the local `/.fly/api` Unix socket unconditionally.
If you run it somewhere that has no `/.fly/api` (your work station, GitHub
Actions, a non-Fly host), the socket dial fails with
`FileNotFoundError`. There is no fallback transport for encrypt /
decrypt — Fly's `/encrypt` and `/decrypt` would return 403 from any
external client anyway, with or without a token.

The provisioner is a separate component and can run anywhere
`FLY_API_TOKEN` is available, since it talks to the public Machines
API. In practice, however, the provisioner is invoked from the
running Django process, which on Fly always runs inside a machine.
For ad-hoc provisioning outside this application from your work station, use `flyctl`
(it carries its own token and is the simpler tool).

### Secretkey name does not match `[A-Za-z0-9_]+`

`FlyKmsKekProvisioner` raises `ValueError` in `ensure_kek`, before it creates
the key. The error message names the offending key and tells you to adjust
`KEK_TEMPLATE` / `KEK_MAP`. The silo UID itself is always escaped to fit, so
the cause is the template's literal text or a `KEK_MAP` value; see [Name
constraints](#name-constraints-important).

### Calling `/generate` on an existing key

This package never does so on its own — `FlyKmsKekProvisioner` is
GET-first. The risk is elsewhere: re-running
`fly secrets keys generate <name>` (or its raw-API equivalent,
`POST /v1/apps/{app}/secretkeys/{name}/generate`) on an
already-provisioned name will silently overwrite the key material,
and every ciphertext encrypted under the previous material becomes
unrecoverable. There is no way to recover. Treat `secrets keys
generate` and the `/generate` endpoint as destructive on existing
names; always check `fly secrets keys list` (or GET the key) first.

For controlled rotation, see [Key rotation](key-rotation.md) — the
right pattern is to introduce a new secretkey under a new name, run
`reencrypt_keys`, and then delete the old key.

---

## Granting the application user access to `/.fly/api`

If your container runs Gunicorn (or any non-root process) as a
dedicated application user — the standard hardened pattern — the
default Fly socket permissions will block it. Fly creates `/.fly/api`
as **root-owned with no group access**, which produces:

```
PermissionError: [Errno 13] Permission denied
```

the first time the `FlyKmsAdapter` calls `/encrypt` or `/decrypt`.
Running the whole container as root makes the error go away but is
the wrong fix; the right fix is to start the container as root,
chown the socket to your application user, and drop privileges before
exec-ing the web server. The minimal reference below shows the three
moving parts (Dockerfile, startup script, `fly.toml`) and is intended
to be adapted to whatever paths and process layout your project
already uses. Replace `appuser`, the project path, and the WSGI/ASGI
target with the values your own project uses.

### Dockerfile

Keep your existing application user (here `appuser`) and codebase
ownership, but switch the final stage to start as root and invoke a
startup script as `CMD`:

```dockerfile
# Normalize line endings (in case the script was authored on Windows)
# and make sure it is executable.
RUN sed -i 's/\r$//' /app/docker_startup.sh && chmod +x /app/docker_startup.sh

# Container starts as root so the startup script can chown the Fly KMS
# Unix socket (/.fly/api) to the application user before dropping
# privileges and starting the web server. Fly mounts the socket as
# root-owned with no group read/write; an unprivileged process cannot
# open it without this fix-up step.
USER root

CMD ["bash", "/app/docker_startup.sh"]
```

### Startup script

The script runs any pre-flight tasks (migrations, etc.), fixes the
socket ownership, and exec-s the web server as the application user
via `su`:

```bash
#!/bin/bash

set -o errexit
set -o pipefail
set -o nounset

# Path to Fly's per-machine KMS API socket. The FlyKmsAdapter dials it
# for /encrypt and /decrypt. Fly creates the socket as root-owned;
# the application user needs ownership to open it.
SOCKET_PATH="/.fly/api"
APP_USER="appuser"

echo "Django migrate"
python manage.py migrate --noinput

echo "Run Gunicorn"
if [ "$(id -u)" -eq 0 ]; then
  if [ -e "$SOCKET_PATH" ]; then
    chown "$APP_USER":"$APP_USER" "$SOCKET_PATH" || true
  fi
  exec su -s /bin/bash "$APP_USER" -c 'gunicorn --bind 0.0.0.0:8080 --workers 1 --threads 8 --timeout 0 your_project.asgi:application -k uvicorn.workers.UvicornWorker'
fi

# Already running as a non-root user (for example, local Docker
# development without the chown step). Skip the chown branch and exec
# directly.
exec gunicorn --bind 0.0.0.0:8080 --workers 1 --threads 8 --timeout 0 your_project.asgi:application -k uvicorn.workers.UvicornWorker
```

### `fly.toml`

Point the process command at the startup script so Fly invokes it
instead of the web server directly:

```toml
[processes]
  app = 'bash /app/docker_startup.sh'
```

### Notes

- **The chown is per-machine.** `/.fly/api` is created by the platform
  every time a machine starts, so the chown step must run on every
  boot — it cannot be baked into the image.
- **`su` vs. `gosu`.** `gosu` is the more common tool for "drop to a
  user and exec" but is not in `python:slim` (or most other slim
  Debian-based images) by default. `su -s /bin/bash <user> -c '<cmd>'`
  is in coreutils and fine for this single exec, with the minor caveat
  that signals and terminal handling differ slightly from `gosu`. For
  one-shot startup this does not matter; if you already use `gosu` or
  `tini`, slot them in instead.
- **The `|| true` on chown.** The startup script tolerates the chown
  failing (e.g. socket missing during a non-Fly boot) so the same
  script also works for local Docker development without `/.fly/api`.
  The non-root branch covers the case where a developer already runs
  the container as the application user.
- **Why not run as root.** Running the web server as root broadens
  the blast radius of any RCE inside the application to "every process
  and file inside the container," including the right to open
  arbitrary Unix sockets. The chown-then-drop pattern keeps the
  running process unprivileged.
- **Other web servers.** The same pattern works for uWSGI, Daphne, or
  Hypercorn — replace the `gunicorn …` line with whatever your project
  uses. The only constraint is that whatever exec-s the web server
  must run after the chown.

---

## Related reading

- [KEK strategies](kek-strategies.md) — full strategy reference, including
  cohort and BYOK.
- [KEK provisioning](kek-provisioning.md) — strategy-vs-provisioner split,
  the full provisioner table, and writing custom provisioners.
- [KMS adapters](kms-adapters.md) — adapter reference for Fly and the
  other providers, including the OIDC federation path
  (Fly→AWS / GCP / Azure / Vault).
- [Configuration reference](configuration.md) — every `ENCRYPTION`
  setting, including `KEY_AUTO_PROVISION`, `DEK_CACHE_TTL`, and
  `LOG_DECRYPTS`.
- [Key rotation](key-rotation.md) — rotating KEKs and re-encrypting.
- [Getting started with GCP Cloud KMS](getting-started-gcp.md) — same
  workflow shape, GCP-flavored, when you want the KEK in a different
  trust domain than your Fly app.
