# Getting started with IBM Key Protect / HPCS

This step-by-step guide walks you through wiring django-encryption-suite to IBM Cloud Key Protect
or Hyper Protect Crypto Services (HPCS) in production. This page assumes
you have already followed [Getting started](getting-started.md) for the
basic Django setup (`INSTALLED_APPS`, migrations, a silo adapter)
and now need to swap the local dev KMS for real IBM KMS.

The same adapter (`IbmKmsAdapter`) and provisioner (`IbmKekProvisioner`)
serve both Key Protect and HPCS — the wire protocol is identical; only
the endpoint URL differs. Use Key Protect for FIPS 140-2 Level 3 and
HPCS for FIPS 140-2 Level 4 (Keep Your Own Key with single-tenant HSMs).

The two decisions that drive everything else on this page:

1. **Shared KEK or per-silo KEK?**
   One root key for the whole application vs. one key per tenant/team.
2. **Auto-provision or manual?**
   Let the application create root keys on first encrypt vs. provision
   them outside this application (Terraform / IaC / Console) before the application
   sees them.

The rest of this guide walks through each combination end-to-end.

---

## Prerequisites

- An IBM Cloud account and a Key Protect or HPCS service instance in the
  region you intend to deploy in (this guide uses `us-south`).
- The service instance GUID (visible on the instance details page or via
  `ibmcloud resource service-instance <name>`).
- Permission in that service instance to either (a) create root keys
  yourself, or (b) grant the `Writer` role to your application's service
  ID for the Key Protect/HPCS instance.
- The `django-encryption-suite` package installed — **no extra is required**
  for IBM; the adapter uses `urllib` from the standard library:

  ```bash
  uv add django-encryption-suite
  ```

- A working `ENCRYPTION` block in `settings.py` from
  [Getting started](getting-started.md). You will replace the
  env key store configuration with a `IbmKmsAdapter` block below.

---

## Choosing a credential strategy

Select one with `OPTIONS["CREDENTIAL_STRATEGY"]`:

| Strategy | When to use | Extra | Required options |
|---|---|---|---|
| `api_key` *(default)* | Production — exchange an IBM Cloud API key for an IAM bearer token, refreshed automatically | none | `IBM_API_KEY` |
| `iam_assume` | Take on a **trusted profile** identity from anywhere (including non-IBM compute such as a Fly.io app) | none | `IBM_API_KEY` + exactly one of `IBM_TRUSTED_PROFILE_ID` / `IBM_TRUSTED_PROFILE_CRN` / `IBM_TRUSTED_PROFILE_NAME` |
| `container` | Keyless trusted-profile auth for a workload running **on IBM Code Engine or IKS** | `[ibm]` | one of `IBM_TRUSTED_PROFILE_ID` / `IBM_TRUSTED_PROFILE_NAME`; optional `IBM_CR_TOKEN_FILENAME` |
| `vpc_instance` | Keyless trusted-profile auth for a workload running **on an IBM VPC virtual server** | `[ibm]` | optional `IBM_TRUSTED_PROFILE_ID` *or* `IBM_TRUSTED_PROFILE_CRN` (omit both for the VSI's default linked profile) |

`api_key` and `iam_assume` are built in (no extra). `container` and
`vpc_instance` delegate to `ibm-cloud-sdk-core` and need the `ibm` extra
(`pip install django-encryption-suite[ibm]`). All strategies read their options
from `OPTIONS` first, then fall back to the environment variable of the
same name.

`api_key` is the right default in production. The strategy fetches an
IAM bearer token from `https://iam.cloud.ibm.com/identity/token` using
the `urn:ibm:params:oauth:grant-type:apikey` grant, caches it until 5
minutes before expiry, and refreshes transparently. On a 401 from Key
Protect, the adapter invalidates the cached token and retries once.

`iam_assume` is the two-step "assume a trusted profile" flow. It first
mints an API-key token exactly as `api_key` does, then exchanges that
token at the same endpoint using the
`urn:ibm:params:oauth:grant-type:assume` grant plus a trusted-profile
selector, and caches the resulting profile-scoped token. Use it when you
want IAM access governed by a **trusted profile** (one shared identity
with its own access policies) rather than a service ID's own API key —
for example, a workload running outside IBM Cloud that still needs a
trusted-profile identity. Set **exactly one** profile selector
(`IBM_TRUSTED_PROFILE_ID`, `_CRN`, or `_NAME`); setting none or more than
one is a configuration error caught at startup.

`container` and `vpc_instance` are the **keyless** trusted-profile
strategies for workloads running **on** IBM compute — no API key is
stored or exchanged. They delegate to `ibm-cloud-sdk-core` (hence the
`ibm` extra), which owns the platform handshakes:

- `container` (IBM Code Engine / IKS) reads a compute-resource (CR) token
  the platform mounts into the container and exchanges it for a
  trusted-profile token. The trusted profile is bound to the workload by
  the platform (a Code Engine *project* / IKS trusted-profile link), so
  set `IBM_TRUSTED_PROFILE_ID` (or `_NAME`) to the profile to assume. The
  SDK's default CR-token path is the IKS one; on Code Engine set
  `IBM_CR_TOKEN_FILENAME` to
  `/var/run/secrets/codeengine.cloud.ibm.com/compute-resource-token/token`.
- `vpc_instance` (IBM VPC virtual server) fetches an instance-identity
  token from the VPC metadata service and exchanges it. Set
  `IBM_TRUSTED_PROFILE_ID` or `IBM_TRUSTED_PROFILE_CRN`, or omit both to
  use the trusted profile linked to the instance. The VSI must have the
  metadata service enabled (`--metadata-service true` at create) and a
  linked trusted profile (`--default-trusted-profile <id>
  --default-trusted-profile-auto-link true`, or a
  `trusted-profile-link-create` with `--cr-type VSI`).

  > **Running the app in a container on the VSI?** The metadata service has
  > an IP hop limit (default **1**). A container on a docker **bridge**
  > network adds a hop, so the token request is dropped and the strategy
  > fails to reach `169.254.169.254` (the same constraint as AWS IMDSv2).
  > Either run the container with host networking, or create the VSI with
  > `--metadata-service-response-hop-limit 2`.

Selecting either strategy without the `ibm` extra installed raises a
configuration error at startup naming the missing package.

---

## Choosing the endpoint

`IbmKmsAdapter` requires exactly one of:

- `IBM_REGION` — region slug (e.g. `us-south`, `eu-gb`,
  `au-syd`). Constructs `https://<region>.kms.cloud.ibm.com`
  automatically. Use this for **Key Protect**.
- `IBM_ENDPOINT` — full base URL. Overrides `IBM_REGION`. Use
  this for:
  - **HPCS** — `https://<instance>.api.<region>.hs-crypto.appdomain.cloud`
  - **Private endpoints** — `https://private.<region>.kms.cloud.ibm.com`
  - **Cross-region failover** with a custom DNS alias.

`IBM_INSTANCE_ID` is required regardless — it goes in the
`bluemix-instance` header on every request and identifies which Key
Protect / HPCS instance the call targets.

---

## Decision 1 — shared vs per-silo KEK

### Shared KEK

One root key encrypts every silo's DEK. Simpler operationally;
one IAM policy, one key to rotate, one key to monitor in IBM Cloud
Activity Tracker. The trade-off is blast radius: if that single key is
compromised or scheduled for deletion, every tenant's encrypted data is
at risk simultaneously.

Pick this when:

- You have a single-tenant deployment (one organization, many teams that
  don't need cryptographic isolation between them).
- You want the lightest operational footprint and the per-tenant blast
  radius is not a compliance requirement.

### Per-silo KEK

Each tenant/team gets its own root key. Compromise or scheduled deletion
of one key affects only that tenant. Required by some compliance
regimes. Both Key Protect and HPCS price per active key version per
month plus per-API-call.

Pick this when:

- You're a multi-tenant SaaS where tenants must be cryptographically
  isolated.
- You need to demonstrate per-tenant key custody to auditors.
- You want the option to revoke a single tenant's data by scheduling one
  key for deletion.

### Settings mapping

| Choice | `KEK_STRATEGY_ADAPTER` | `OPTIONS` key |
|---|---|---|
| Shared | `SharedKekStrategy` | `SHARED_KEK_ID` (a key name or UUID) |
| Per-silo | `PerSiloKekStrategy` | `KEK_TEMPLATE` (or `KEK_MAP`) |

Key Protect / HPCS addresses keys by **UUID** only — `/api/v2/keys/{id}`
and the wrap/unwrap endpoints do not accept a key name. So when you use a
human-readable name (via `KEK_TEMPLATE` or `SHARED_KEK_ID`), the adapter
resolves it to the key's UUID by listing keys and matching the `name`
field, caching the result. Supplying explicit UUIDs (via `KEK_MAP`) skips
that lookup. Note Key Protect does not enforce unique names; the resolver
takes the first match, and the auto-provisioner checks for an existing
name before creating so it does not make duplicates.

---

## Decision 2 — manual vs auto provisioning

### Manual (`NullKekProvisioner`, the default)

Someone (or something) creates the root key before the application tries
to use it. Typical flows:

- **Terraform** — keys defined as IaC via the `ibm_kms_key` resource,
  reviewed in PRs, applied at deploy time.
- **`ibmcloud kp` CLI** — a one-off shell script run during initial
  deploy.
- **Manual Console action** — admin opens the IBM Cloud Console and
  clicks through Add Key.

The application's service ID only needs the `Reader` role (covers wrap
and unwrap), which is the safer posture for most production
deployments.

When a missing KEK is hit at runtime, the engine raises
`KekNotProvisionedError` with a translated user-facing message
("Encryption and decryption are unavailable for this data.") and an
English admin log entry naming the missing KEK and the strategy in use.
The Django admin **Reconcile Keys** page (described later) is the
operator workflow for catching this before users do.

### Auto (`IbmKekProvisioner`)

The application creates the root key the first time a new silo
encrypts data. Typical use case: multi-tenant SaaS where new tenants
sign up mid-request and you don't want a manual provisioning step
blocking their first save.

The application's service ID needs the `Writer` role on the Key Protect
/ HPCS instance, which adds `POST /api/v2/keys` to the wider list of
allowed operations. Some compliance regimes forbid this.

### Combinations

| KEK choice | Provisioning | Per-tenant ops |
|---|---|---|
| Shared | Manual | Create one key once, configure name, done |
| Shared | Auto | Rare — one key only, manual is just as easy |
| Per-silo | Manual | New tenant ⇒ admin creates root key, configures name, then tenant can encrypt |
| Per-silo | Auto | New tenant ⇒ first encrypt creates the key; zero operator setup |

The four combinations below give you concrete `settings.py` snippets and
operator workflows for each.

---

## Combination A — shared KEK, manual provisioning

Best fit: small / single-tenant deployments.

### Step 1: create the root key

Either via Terraform:

```hcl
resource "ibm_kms_key" "encryption_suite" {
  instance_id  = ibm_resource_instance.kp.guid
  key_name     = "encryption_suite-shared-kek"
  standard_key = false   # root key (never extractable)
  force_delete = false
}
```

Or via the `ibmcloud kp` CLI:

```bash
ibmcloud kp key create encryption_suite-shared-kek \
  -i "$INSTANCE_ID" \
  --standard-key=false
```

### Step 2: grant the application service ID `Reader` access

```bash
ibmcloud iam service-policy-create encryption_suite-app \
  --roles Reader \
  --service-name kms \
  --service-instance "$INSTANCE_ID"
```

Reader on the instance covers both wrap and unwrap on every key inside.
For per-key scoping, replace `--service-instance` with `--resource
key-id=<uuid>` (less common — key counts grow with tenants).

### Step 3: configure `ENCRYPTION`

```python
ENCRYPTION = {
    "KEY_SETS": {"default": {"silo": "...", "key_store": "ibm"}},  # whatever you use
    "KMS_KEY_STORES": {
        "ibm": {
            "ADAPTER": "encryption_suite.adapters.key_stores.ibm.IbmKmsAdapter",
            "OPTIONS": {
                "CREDENTIAL_STRATEGY": "api_key",   # default
                "IBM_API_KEY": os.environ["IBM_API_KEY"],
                "IBM_REGION": "us-south",
                "IBM_INSTANCE_ID": os.environ["IBM_INSTANCE_ID"],
                "SHARED_KEK_ID": "encryption_suite-shared-kek",
            },
            "KEK_STRATEGY_ADAPTER": "encryption_suite.adapters.keks.SharedKekStrategy",
            # KEK_PROVISIONER_ADAPTER omitted — defaults to NullKekProvisioner
        },
    },
}
```

For HPCS, swap `IBM_REGION` for `IBM_ENDPOINT`:

```python
"IBM_ENDPOINT": "https://<instance>.api.us-south.hs-crypto.appdomain.cloud",
```

### Step 4: create DEKs

Each silo still needs its own DEK row, encrypted under the shared
KEK. Either let the engine create them lazily on first encrypt
(`KEY_AUTO_PROVISION = True`, the default) or pre-create them in bulk:

```bash
python manage.py setup_encryption_keys
```

That's it. The application is now encrypting under one shared root key.

---

## Combination B — per-silo KEK, manual provisioning

Best fit: multi-tenant SaaS that needs per-tenant isolation but cannot
grant `Writer` to the application.

### Step 1: pick a naming convention

The convention is encoded as a template containing `{silo_uid}`.
Names are easier to manage than UUIDs because the name encodes which
tenant the key belongs to.

```
encryption_suite-{silo_uid}
# silo_uid "team-42" needs no escaping — hyphen is allowed; any char
# outside [A-Za-z0-9_-] is hex-escaped (e.g. "@" -> "_40")
# resolved name: encryption_suite-team-42
```

### Step 2: configure `ENCRYPTION`

```python
ENCRYPTION = {
    "KEY_SETS": {"default": {"silo": "...", "key_store": "ibm"}},
    "KMS_KEY_STORES": {
        "ibm": {
            "ADAPTER": "encryption_suite.adapters.key_stores.ibm.IbmKmsAdapter",
            "OPTIONS": {
                "CREDENTIAL_STRATEGY": "api_key",
                "IBM_API_KEY": os.environ["IBM_API_KEY"],
                "IBM_REGION": "us-south",
                "IBM_INSTANCE_ID": os.environ["IBM_INSTANCE_ID"],
                "KEK_TEMPLATE": "encryption_suite-{silo_uid}",
            },
            "KEK_STRATEGY_ADAPTER": "encryption_suite.adapters.keks.PerSiloKekStrategy",
        },
    },
}
```

### Step 3: grant the runtime service ID `Reader` on the instance

Same as Combination A — instance-scoped Reader covers every key the
application provisions under that instance.

### Step 4: provisioning workflow per new tenant

For each new silo:

1. **Find out which name it needs.** Open the Django admin, go to
   **Data Encryption Keys → Reconcile Keys** (object-tools link,
   top right of the change list). Or visit:

   ```
   /admin/encryption_suite/dataencryptionkey/reconcile-keys/
   ```

   The page lists every silo, the resolved key name the
   application would try to use, and a **Needs setup** flag for those
   without a DEK row yet.

2. **Create the root key.** Via Terraform (preferred — keys are defined in IaC
   alongside everything else):

   ```hcl
   resource "ibm_kms_key" "tenant_42" {
     instance_id  = ibm_resource_instance.kp.guid
     key_name     = "encryption_suite-team-42"
     standard_key = false
     force_delete = false
   }
   ```

   Or via CLI for one-offs:

   ```bash
   ibmcloud kp key create encryption_suite-team-42 \
     -i "$INSTANCE_ID" --standard-key=false
   ```

3. **Verify on the admin page.** Refresh the Reconcile Keys page; the
   row's status changes to **Ready** once you trigger an encrypt (or
   immediately after you also create the DEK).

4. **Trigger DEK creation.** With `KEY_AUTO_PROVISION = True` (default),
   the next encrypt for that tenant creates the DEK automatically.
   Otherwise:

   ```bash
   python manage.py setup_encryption_keys
   ```

Until the root key exists, any encrypt for that tenant raises
`KekNotProvisionedError`. The translated user-facing message is
`"Encryption and decryption are unavailable for this data."`; the log
entry contains the missing name and the silo UID.

---

## Combination C — per-silo KEK, auto provisioning

Best fit: multi-tenant SaaS that can grant `Writer` on the instance and
wants zero per-tenant manual steps.

### Step 1: configure `ENCRYPTION`

Same `OPTIONS` as Combination B, plus a provisioner:

```python
ENCRYPTION = {
    "KEY_SETS": {"default": {"silo": "...", "key_store": "ibm"}},
    "KMS_KEY_STORES": {
        "ibm": {
            "ADAPTER": "encryption_suite.adapters.key_stores.ibm.IbmKmsAdapter",
            "OPTIONS": {
                "CREDENTIAL_STRATEGY": "api_key",
                "IBM_API_KEY": os.environ["IBM_API_KEY"],
                "IBM_REGION": "us-south",
                "IBM_INSTANCE_ID": os.environ["IBM_INSTANCE_ID"],
                "KEK_TEMPLATE": "encryption_suite-{silo_uid}",
            },
            "KEK_STRATEGY_ADAPTER": "encryption_suite.adapters.keks.PerSiloKekStrategy",

            "KEK_PROVISIONER_ADAPTER": "encryption_suite.adapters.keks.IbmKekProvisioner",
            "KEK_PROVISIONER_OPTIONS": {
                "CREDENTIAL_STRATEGY": "api_key",   # may be different from OPTIONS
                "IBM_API_KEY": os.environ["IBM_PROVISIONER_API_KEY"],
                "IBM_REGION": "us-south",
                "IBM_INSTANCE_ID": os.environ["IBM_INSTANCE_ID"],
                "EXTRACTABLE": False,   # root key — never leaves the HSM
                "KEY_DESCRIPTION": "django-encryption-suite KEK",
            },
        },
    },
}
```

`KEK_PROVISIONER_OPTIONS` is intentionally separate from `OPTIONS` so
that you can point the provisioner at a different IBM service ID (with
`Writer`) than the runtime encrypt/decrypt path uses (which needs only
`Reader`). In most deployments they are the same, but separating them
lets you e.g. use a narrower runtime service ID.

### Step 2: grant the provisioner service ID `Writer` access

```bash
ibmcloud iam service-policy-create encryption_suite-provisioner \
  --roles Writer \
  --service-name kms \
  --service-instance "$INSTANCE_ID"
```

`Writer` on the instance covers `POST /api/v2/keys` (create) plus all
the operations `Reader` covers. It cannot be scoped to a specific
not-yet-existing key — instance-scoped is the inherent grain, which is
the main reason some organizations forbid auto-provisioning.

**Use `Manager` instead if you want the package to delete keys or set a rotation
schedule.** Deleting is what the admin delete action and the test console's cleanup do;
`Writer` cannot delete, so the deletion is refused and recorded rather
than failing. See [Deleting a key encryption key](#deleting-a-key-encryption-key)
and [Automatic rotation](#automatic-rotation).

### Step 3: deploy and forget

Each new silo now triggers, on first encrypt:

1. `IbmKekProvisioner.ensure_kek` lists keys and looks for a live one with the
   name. Key Protect has no lookup-by-name endpoint —
   `GET /api/v2/keys/{name}` always 404s, because keys are addressed by UUID.
2. If none is found, it calls `POST /api/v2/keys` with the name and
   `extractable: false`.
3. The new KEK encrypts (wraps) a freshly generated DEK; the encrypted
   DEK is stored as a `DataEncryptionKey` row.
4. Subsequent encrypts skip provisioning (in-process cache + IBM already
   has the name).

The provisioner is idempotent and tolerates `409 Conflict` from
concurrent first-encrypts in multi-process / multi-host deployments.

### Step 4: monitoring

Watch IBM Cloud Activity Tracker for `kms.secrets.create` events on
first signup; spikes can mean something is hammering tenant creation.
The `encryption_suite` logger emits an `INFO`-level entry on each
successful provision:

```
IbmKekProvisioner: created KEK 'encryption_suite-team-42' for silo 'team-42'.
```

---

## Combination D — shared KEK, auto provisioning

Rarely useful in production. With a shared KEK there is exactly one key
to create; doing that via Terraform once is faster than configuring a
provisioner. Provided for completeness — same shape as Combination C
but with `SharedKekStrategy` and a single `SHARED_KEK_ID`.

If you do need it (e.g. a one-shot dev environment that creates its
shared key on first boot), set `SHARED_KEK_ID` to the name the
provisioner should create:

```python
"OPTIONS": {
    "IBM_API_KEY": os.environ["IBM_API_KEY"],
    "IBM_REGION": "us-south",
    "IBM_INSTANCE_ID": os.environ["IBM_INSTANCE_ID"],
    "SHARED_KEK_ID": "encryption_suite-shared-kek",
},
"KEK_STRATEGY_ADAPTER": "encryption_suite.adapters.keks.SharedKekStrategy",
"KEK_PROVISIONER_ADAPTER": "encryption_suite.adapters.keks.IbmKekProvisioner",
"KEK_PROVISIONER_OPTIONS": {
    "IBM_API_KEY": os.environ["IBM_API_KEY"],
    "IBM_REGION": "us-south",
    "IBM_INSTANCE_ID": os.environ["IBM_INSTANCE_ID"],
    "KEY_DESCRIPTION": "django-encryption-suite shared KEK",
},
```

The provisioner is called once per silo (which always resolves to
the same name), so the in-process cache makes this near-free after the
first call.

---

## Example: the `container` strategy on IBM Code Engine

This section works through the **`container`** credential strategy — keyless
trusted-profile auth for a Django app running on IBM Code Engine. (This section
is specific to `container`; the other strategies are covered above, and
`vpc_instance` is analogous but runs on a VPC virtual server.) The app reads a
compute-resource (CR) token that Code Engine mounts into the container and
exchanges it for a trusted-profile token — no API key is stored. Replace every
`<PLACEHOLDER>` with your own value.

The CLI steps below need the
[IBM Cloud CLI](https://cloud.ibm.com/docs/cli?topic=cli-install-ibmcloud-cli)
with the `code-engine` and `container-registry` plugins, logged in to your
account and region:

```
ibmcloud plugin install code-engine container-registry
ibmcloud login --sso -r <REGION>
ibmcloud target -g <RESOURCE_GROUP>
```

### Console setup (one-time)

Do these steps in the IBM Cloud Console before the CLI steps below. Note that `container`
is keyless — unlike `api_key` / `iam_assume` it needs **no service ID and no API
key**; the app's identity comes from the Code Engine CR token, trusted via the
link in step 3.

1. **Provision a Key Protect instance.** Catalog → Security and Identity →
   Key Protect → pick a region (allow **public** network access so an app can
   reach it over the internet) → Create. On the instance's **Details**, copy
   the **GUID** — this is `IBM_INSTANCE_ID`.
2. **Create a trusted profile.** Manage → Access (IAM) → **Trusted profiles** →
   Create. Name it. At "Select trusted entity type" choose **Decide later** —
   the Code Engine compute-resource trust is added by CLI below, not in this
   wizard. Finish, then open the profile's **Details** and copy the **Profile
   ID** (`Profile-…`) — this is `IBM_TRUSTED_PROFILE_ID`.
3. **Grant the profile Key Protect access.** On the profile → **Access** tab →
   Assign access → **Access policy** → Service **Key Protect** → scope to the
   instance from step 1 → Service access **Writer** (Writer if you
   auto-provision keys, else **Reader**) → Add → Assign.

### App settings and deploy

**1. Point the adapter at the `container` strategy** (in your production
settings):

```python
ENCRYPTION = {
    "KEY_SETS": {"default": {"silo": "...", "key_store": "ibm"}},
    "KMS_KEY_STORES": {
        "ibm": {
            "ADAPTER": "encryption_suite.adapters.key_stores.ibm.IbmKmsAdapter",
            "OPTIONS": {
                "IBM_INSTANCE_ID": os.environ["IBM_INSTANCE_ID"],
                "IBM_REGION": "<REGION>",                 # e.g. us-east
                "CREDENTIAL_STRATEGY": "container",
                "IBM_TRUSTED_PROFILE_ID": os.environ["IBM_TRUSTED_PROFILE_ID"],
                # Code Engine's CR-token mount path (the SDK default is the IKS path):
                "IBM_CR_TOKEN_FILENAME": "/var/run/secrets/codeengine.cloud.ibm.com/compute-resource-token/token",
                "KEK_TEMPLATE": "encryption_suite-{silo_uid}",
            },
            "KEK_STRATEGY_ADAPTER": "encryption_suite.adapters.keks.PerSiloKekStrategy",
            # optional auto-provisioning:
            "KEK_PROVISIONER_ADAPTER": "encryption_suite.adapters.keks.IbmKekProvisioner",
            "KEK_PROVISIONER_OPTIONS": { ... },              # same IBM_KP_* + container options
        },
    },
}
```

**2. Install the `ibm` extra in the image.** `container` needs
`ibm-cloud-sdk-core`. Code Engine source builds **cannot pass Docker
`--build-arg`**, so install the extra directly in your Dockerfile rather than
parameterizing it — e.g. `pip install 'django-encryption-suite[ibm]'` (or, with uv,
add it to the synced groups).

**3. Add a Code Engine trust link to the profile** (the profile and its Key
Protect access were created in Console setup above). This is what lets the app's
CR token assume the profile. The link's component type **must be `application`**
for an app:

```
ibmcloud iam trusted-profile-link-create <PROFILE_ID> \
  --name ce-<APP_NAME> \
  --cr-type CE \
  --link-crn <CODE_ENGINE_PROJECT_CRN> \
  --link-component-type application \
  --link-component-name <APP_NAME>
```

> The CR token a Code Engine *application* presents carries
> `component_type: "application"`. The CLI also accepts `--link-component-type
> app`, but it stores that string verbatim and it will **not** match the token —
> the assume then fails with `BXNIM0398E "Selected trusted profile not
> eligible."` Use `application` (use `job` for a Code Engine job).

**4. Set up a registry for the cloud source build.** A source build pushes the
built image to IBM Container Registry, so create a namespace and a push secret:

```
ibmcloud cr region-set <CR_REGION>            # e.g. us-south -> us.icr.io
ibmcloud cr namespace-add <NAMESPACE>
ibmcloud ce registry create --name <REGISTRY_SECRET> \
  --server <CR_SERVER> --username iamapikey --password <IAM_API_KEY>
```

**5. Add a `.ceignore`.** Code Engine's local source upload honors **`.ceignore`**
(not `.dockerignore`). Without it the upload can exceed the size limit. Exclude
the heavy directories:

```
.git
.venv
node_modules
media
static_root
```

**6. Deploy with the cloud source build and the CR-token mount:**

```
ibmcloud ce app create --name <APP_NAME> \
  --build-source . \
  --build-dockerfile <DOCKERFILE> \
  --image <CR_SERVER>/<NAMESPACE>/<APP_NAME> \
  --registry-secret <REGISTRY_SECRET> \
  --trusted-profiles-enabled=true \
  --port 8080 \
  --env DJANGO_SETTINGS_MODULE=<your.production.settings> \
  --env IBM_INSTANCE_ID=<KP_INSTANCE_ID> \
  --env IBM_TRUSTED_PROFILE_ID=<PROFILE_ID>
```

`--trusted-profiles-enabled=true` is what mounts the CR token;
`IbmContainerStrategy` reads it, exchanges it for a trusted-profile token, and
all Key Protect calls run as the profile. The build runs in the cloud, so no
local Docker is required.

---

## Automatic rotation

Key Protect can rotate a root key on a schedule. Set `KEK_ROTATION_PERIOD_DAYS` in
`KEK_PROVISIONER_OPTIONS` and the provisioner writes a rotation policy onto every
key it creates:

```python
"KEK_PROVISIONER_OPTIONS": {
    # ...
    "KEK_ROTATION_PERIOD_DAYS": 90,   # every 3 months
},
```

**Only multiples of 30, up to 360.** Key Protect expresses the interval in whole
months and defines a month as exactly 30 days for this purpose, so 30 / 60 / 90 …
360 convert exactly and nothing in between does. A value like 100 is **refused at
`manage.py check`**, naming 90 and 120, rather than being rounded — a rotation
interval you did not choose is worse than one that is refused, and nothing would
ever surface the difference.

> The interval is set through the `interval_month` API parameter, which accepts 1
> to 12 — so 360 days is the ceiling.

Three things to know before turning it on:

- **It needs the `Manager` role.** With only `Writer`, keys are still created and
  work, but the policy call fails.
- **A failure does not fail the encrypt.** The policy is a second call after key
  creation, and if it fails the key is kept and one `WARNING` is logged
  (a warning naming the key and the interval). Breaking a
  tenant's first save over a schedule would be the wrong trade — but that warning
  is the *only* signal that a key is silently on manual rotation, so alert on it.
- **It applies at creation only.** Keys already in the instance are untouched,
  whether they were adopted or created under an earlier setting. Set the policy
  by hand on those, or in the Key Protect console.

Rotation adds a key version and retires the previous one for wrapping; existing
data stays readable, and [`reencrypt_keys`](management-commands.md#reencrypt_keys)
moves rows onto the new version.

**Key Protect permits one rotation per root key per hour.** A second attempt
inside that window is refused with a 409. This applies to manual rotation, from
the console or the API — a scheduled policy never approaches it. Worth knowing
for an emergency rotation, where the instinct to rotate again after a failed step
is exactly what the limit blocks.

---

## Deleting a key encryption key

Key Protect's delete is a soft delete. `DELETE /api/v2/keys/{id}` stops the key
serving wrap and unwrap immediately — which is what crypto-shreds every DEK
wrapped under it — and keeps it restorable for **30 days**, after which its
contents are destroyed. Deleting takes every version of the key with it.

Four things follow that are worth knowing before you run a deletion:

- **The 30 days are not configurable.** No request, option or account setting
  changes the retention period, so `PROVIDER_DELETION_WINDOW_DAYS` is rejected at
  construction rather than silently ignored. Compare
  [the two deletion windows](kek-provisioning.md#the-two-deletion-windows).
- **A purge can end the retention early — at IBM, by hand.** Key Protect lets an
  authorized operator purge a deleted key, destroying it ahead of the 30 days,
  from **4 hours** after the deletion. That is an action at IBM Cloud and not
  something this package performs or can trigger: nothing here calls it, and the
  package's own restore window is unaffected either way. It is the answer to a
  test-instance key you do not want to pay for over a month — the deletion alone
  will not stop that clock. See [Deleting and purging
  keys](https://cloud.ibm.com/docs/key-protect?topic=key-protect-delete-purge-keys)
  for the authority required and the exact procedure.
- **`Manager` is required.** `Writer` can create but not delete. Without
  Manager, the key is retained and the refusal recorded.
- **A deleted key stays listed.** Key Protect keeps it visible, flagged
  `deleted`, for the whole restore window. The package filters those out
  everywhere — reconcile reports the name as gone (it can no longer wrap
  anything), and a later `ensure_kek` for the same name creates a fresh key
  rather than adopting the dead one.

To restore inside the window, use Key Protect directly
(`POST /api/v2/keys/{id}/restore`, Manager role). Restoring recovers the key, not
the data: the package cleared the DEK's `encrypted_keyset` when its own window
expired, so the recovered key wraps nothing. What restoring protects against is
operator error on the key itself.

---

## The Reconcile Keys admin page

For Combination B in particular, this page is the operator workflow. It lists
every silo with the key name the application would use, flags the ones whose
first encryption is still pending, and shows the strategy and provisioner in
effect so you can confirm which combination is live. See
[Reconcile Keys page](admin-panel.md#reconcile-keys-page) for the full
description and the three ways to reach it.

The intended workflow with `NullKekProvisioner`:

1. New tenant signs up.
2. Admin opens the Reconcile Keys page.
3. Copies the resource name (e.g. `encryption_suite-team-42`) into their Key
   Protect Console / Terraform / CLI script.
4. Creates the root key in IBM.
5. The next encrypt for that tenant creates the DEK automatically (with
   `KEY_AUTO_PROVISION = True`) and the row flips to **Ready**.

---

## Failure modes and what they look like

### KEK missing in IBM

`KekNotProvisionedError` is raised by the engine. The user sees:

> Encryption and decryption are unavailable for this data.

The admin sees an `ERROR`-level log entry naming the name, the
silo UID, the strategy, and the provisioner. With
`NullKekProvisioner` the message points to provisioning outside this application;
with `IbmKekProvisioner` the message also names the underlying error
(e.g. `Forbidden` if the service ID lacks `Writer`).

### IAM token expired / revoked

The adapter retries once on a 401 from the wrap/unwrap endpoint after
invalidating the cached token. If the second attempt also fails, a
30-second cooldown suppresses further retries (auth circuit breaker)
and the underlying `urllib.error.HTTPError` propagates.

For `api_key`: rotate the IBM Cloud API key in your secret store and
redeploy.

### Wrong endpoint

The adapter does not infer the endpoint — it must be set in
`OPTIONS["IBM_REGION"]` or `OPTIONS["IBM_ENDPOINT"]`.
Keys belong to a single instance in a single region; an instance in
`us-south` is invisible from a client targeting `eu-gb` even though the
account is the same.

### Private endpoint with private CA

For private Key Protect / HPCS endpoints fronted by a private CA, set
`OPTIONS["TLS_EXTRA_CA"]` to your internal CA bundle path so the
adapter trusts both public CAs and your internal one. Use
`TLS_CA_BUNDLE` to *replace* the system trust store entirely (private
CA only).

---

## Related reading

- [KEK strategies](kek-strategies.md) — full strategy reference, including
  cohort and BYOK.
- [KEK provisioning](kek-provisioning.md) — strategy-vs-provisioner split,
  the full provisioner table, and writing custom provisioners.
- [KMS adapters](kms-adapters.md) — adapter / credential strategy
  reference for IBM and the other providers.
- [Configuration reference](configuration.md) — every `ENCRYPTION`
  setting, including `KEY_AUTO_PROVISION`, `DEK_CACHE_TTL`, and
  `LOG_DECRYPTS`.
- [Key rotation](key-rotation.md) — rotating KEKs and re-encrypting.
