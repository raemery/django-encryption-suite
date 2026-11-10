# Getting started with OCI Vault KMS

This step-by-step guide walks you through wiring django-encryption-suite to Oracle Cloud Infrastructure
(OCI) Vault in production. This page assumes you have already followed
[Getting started](getting-started.md) for the basic Django setup
(`INSTALLED_APPS`, migrations, a silo adapter) and now need to swap the
local dev KMS for real OCI Vault.

The two decisions that drive everything else on this page:

1. **Shared KEK or per-silo KEK?**
   One key for the whole application vs. one key per tenant/team.
2. **How will you address and provision keys?**
   By **OCID** (you create the key outside this application — Terraform / Console / CLI —
   and hand the adapter the resulting OCID), or by **display name** (you give
   the adapter a naming convention and let `OciKekProvisioner` create the key
   on first use). Auto-provisioning **is** supported — see
   [Key provisioning on OCI](#key-provisioning-on-oci).

The rest of this guide walks through each combination end-to-end.

---

## Prerequisites

- An OCI tenancy and a region you intend to deploy in (this guide uses
  `us-ashburn-1`).
- A **Vault** in that region (Virtual Private or Default). OCI Vault
  master encryption keys live inside a vault and inherit its cryptographic
  endpoint URL.
- Permission in that tenancy to either (a) create vaults and keys yourself,
  or (b) delegate key creation to a security/platform team. Auto-provisioning
  needs **manage keys** (broader than the **use keys** the encrypt/decrypt
  path needs).
- The `oci` extra installed:

  ```bash
  uv add 'django-encryption-suite[oci]'
  ```

- A working `ENCRYPTION` block in `settings.py` from
  [Getting started](getting-started.md). You will replace the
  env key store configuration with a `OCIVaultAdapter` block below.

---

## The two OCI Vault endpoints

Every OCI vault exposes two URLs:

- a **cryptographic** endpoint — for encrypt/decrypt, and
- a **management** endpoint — for create/list/rotate.

```
https://<vault-id-suffix>-crypto.kms.<region>.oraclecloud.com
https://<vault-id-suffix>-management.kms.<region>.oraclecloud.com
```

Which one django-encryption-suite calls depends on how you address keys:

| You address keys by… | Crypto endpoint | Management endpoint |
|---|---|---|
| **OCID** (`KEK_MAP` / `SHARED_KEK_ID`) | required | not used |
| **display name** (`KEK_TEMPLATE`) | required | required — to resolve name → OCID, and to provision |

So an OCID-only deployment needs `OCI_VAULT_CRYPTO_ENDPOINT` alone. A
display-name deployment (auto-provisioning, or names mapped to OCIDs at
runtime) also needs `OCI_VAULT_MANAGEMENT_ENDPOINT` and `OCI_COMPARTMENT_OCID`.

Find both on the vault's detail page in the Console, or via:

```bash
oci kms management vault get --vault-id <vault-ocid> \
  --query 'data.{crypto:"crypto-endpoint",mgmt:"management-endpoint"}'
```

---

## Key provisioning on OCI

OCI keys are identified by a server-assigned **OCID** the KEK strategy cannot
predict — but each key also carries an operator-chosen **display name**, and
the management API can list and create keys. That display name is the hinge
that makes auto-provisioning work (the same pattern the Infisical provisioner
uses for its server-assigned UUIDs):

1. `PerSiloKekStrategy` renders a deterministic **display name** from the
   silo UID via `KEK_TEMPLATE` (e.g. `"encryption_suite-{silo_uid}"`).
2. `OciKekProvisioner.ensure_kek` lists keys in the compartment, finds one with
   that display name, and creates it (tagged with the silo UID) if it's
   absent. It then **waits for the new key to reach `ENABLED`** before
   returning — OCI key creation is asynchronous and the crypto endpoint returns
   a 404 until the key settles. This wait is a one-time cost on a silo's
   first encrypt only.
3. `OCIVaultAdapter` resolves the display name to its OCID (cached per process)
   before each encrypt, and stores the OCID in the wrap metadata so decrypt
   stays a direct OCID call with no lookup.

> **Display names are not unique in OCI.** The provisioner tags created keys
> with the silo UID, and the adapter refuses to guess if a name resolves
> to more than one live key (it raises rather than pick one). In-process
> creation is serialized; a cross-process race (two app instances provisioning
> the same brand-new tenant at the same instant) can still produce two keys
> with one name — the adapter surfaces that as a clear "multiple distinct OCI
> keys" error to resolve outside this application. To avoid the race entirely, provision
> ahead of time (see [Combination C](#combination-c--per-silo-kek-auto-provisioned)).

If you'd rather create keys yourself, keep the default `NullKekProvisioner` and
address keys by OCID via `KEK_MAP` / `SHARED_KEK_ID` — the provisioner treats
an OCID-form identifier as already-provisioned and is a no-op for it.

---

## Choosing a credential strategy

Select one with `OPTIONS["CREDENTIAL_STRATEGY"]` (and, for auto-provisioning,
the same key in `KEK_PROVISIONER_OPTIONS`):

| Strategy | When to use | Keyless |
|---|---|---|
| `api_key` *(default)* | Any host **outside** OCI — local dev, CI/CD, PaaS (Fly/Render/Heroku), containers | No (signing key) |
| `instance_principal` | Django on an OCI **Compute** instance | Yes |
| `resource_principal` | OCI **Functions** / **Container Instances** | Yes |
| `oke_workload_identity` | Pods on OCI **Container Engine for Kubernetes** (OKE) | Yes |

The three keyless strategies fetch and auto-refresh a security token from the
OCI runtime, so no static credentials sit on disk. Prefer them whenever the
host is OCI-native. `oke_workload_identity` is distinct from
`resource_principal`: an OKE pod has no Functions/Container-Instances runtime to
read, so it exchanges the pod's Kubernetes service-account token instead.

### `api_key` — two sources

`api_key` reads credentials from one of two places, checked in this order:

1. **Inline** — supply the credential fields (including the private signing key
   as a PEM string) directly in options. No file on disk. This is the path for
   hosts outside OCI with no `~/.oci/config`. Presence of **any** inline field
   selects this path, so a partial set fails loudly rather than silently
   falling back to a config file:

   | Option | Required | Notes |
   |---|---|---|
   | `OCI_TENANCY_OCID` | yes | tenancy OCID |
   | `OCI_USER_OCID` | yes | user the signing key belongs to |
   | `OCI_FINGERPRINT` | yes | the uploaded public key's fingerprint |
   | `OCI_REGION` | yes | e.g. `us-ashburn-1` |
   | `OCI_PRIVATE_KEY_CONTENT` | yes | PEM private key, full text with newlines |
   | `OCI_PRIVATE_KEY_PASSPHRASE` | no | if the PEM is encrypted |

2. **Config file** — the standard `oci.config.from_file` flow, when no inline
   fields are present. Options: `OCI_CONFIG_FILE` (default `~/.oci/config`),
   `OCI_CONFIG_PROFILE` (default `DEFAULT`).

To generate a signing keypair and upload the public key, see Oracle's
[Required Keys and OCIDs](https://docs.oracle.com/en-us/iaas/Content/API/Concepts/apisigningkey.htm).

### `resource_principal` — Container Instances and Functions

On OCI Container Instances (and Functions) there is **no per-resource toggle** to
enable a resource principal and **no credential options** to set — the strategy
is selected by name alone (`"CREDENTIAL_STRATEGY": "resource_principal"`), and the
runtime injects the signing material. Authorization is granted entirely through
IAM:

1. Create a **dynamic group** whose rule matches the resource, e.g.
   `ALL {resource.type='computecontainerinstance'}` (Functions use
   `resource.type='fnfunc'`). The matching `resource.type` alone is enough;
   narrowing by `resource.compartment.id` is optional.
2. Put the dynamic group in the **Default identity domain.** Infrastructure
   resource principals do **not** match a dynamic group created in a non-default
   domain — the policy silently authorizes nothing and every KMS call fails.
3. Attach the same `use keys` / `manage keys` + `read vaults` policy you would
   use for `instance_principal` (see the combinations below). For
   auto-provisioning the policy must grant **`manage keys`** — `manage vaults`
   alone does **not** authorize `CreateKey`; the symptom is a
   `404 NotAuthorizedOrNotFound` on `create_key`, surfaced to the user as
   *"Encryption and decryption are unavailable for this data."*

No signing key, fingerprint, or `~/.oci/config` is involved — the absence of any
credential option is the point. If you also pull the application image from a
**private** OCI Registry repo using the same resource principal, that pull needs
its own `read repos` grant on the dynamic group; that is an image-deployment
concern, separate from django-encryption-suite's KMS access.

---

## Decision 1 — shared vs per-silo KEK

### Shared KEK

One OCI Vault key encrypts every silo's DEK. Simpler operationally;
one IAM policy, one key to rotate, one key to monitor in OCI Audit. The
trade-off is blast radius: if that single key is compromised or scheduled
for deletion, every tenant's encrypted data is at risk simultaneously.

Even under a shared KEK, the per-silo boundary is preserved at the
wrap layer: each DEK is wrapped with the silo UID bound into OCI's
`associated_data` (additional authenticated data), so a ciphertext wrapped for
one silo cannot be decrypted in the context of another.

Pick this when you have a single-tenant deployment and the per-tenant blast
radius is not a compliance requirement.

### Per-silo KEK

Each tenant/team gets its own OCI master encryption key. Compromise or
scheduled deletion of one key affects only that tenant. Required by some
compliance regimes. Costs scale with tenant count: OCI charges per active
key version per month plus per-API-call.

Pick this when you're a multi-tenant SaaS that needs cryptographic isolation,
must demonstrate per-tenant key custody, or wants to revoke one tenant's data
by scheduling a single key for deletion.

### Settings mapping

| Choice | `KEK_STRATEGY_ADAPTER` | KEK addressing |
|---|---|---|
| Shared | `SharedKekStrategy` | `SHARED_KEK_ID` (an OCID) |
| Per-silo, by OCID | `PerSiloKekStrategy` | `KEK_MAP` (UID → OCID) |
| Per-silo, by name | `PerSiloKekStrategy` | `KEK_TEMPLATE` (UID → display name) + `OciKekProvisioner` |

`KEK_MAP` takes precedence per UID when both it and `KEK_TEMPLATE` are present —
handy for pinning a few tenants to specific OCIDs while the rest auto-provision.

---

## Combination A — shared KEK

Best fit: small / single-tenant deployments.

### Step 1: create the vault and key

Either via Terraform:

```hcl
resource "oci_kms_vault" "encryption_suite" {
  compartment_id = var.compartment_ocid
  display_name   = "encryption_suite-vault"
  vault_type     = "DEFAULT"
}

resource "oci_kek" "encryption_suite" {
  compartment_id      = var.compartment_ocid
  display_name        = "encryption_suite-shared-kek"
  management_endpoint = oci_kms_vault.encryption_suite.management_endpoint

  key_shape {
    algorithm = "AES"
    length    = 32
  }

  protection_mode = "HSM"
}
```

Or via the OCI CLI:

```bash
VAULT_ID=$(oci kms management vault create \
  --compartment-id "$COMPARTMENT_OCID" \
  --display-name encryption_suite-vault \
  --vault-type DEFAULT \
  --query 'data.id' --raw-output)

MGMT=$(oci kms management vault get --vault-id "$VAULT_ID" \
  --query 'data."management-endpoint"' --raw-output)

KEY_ID=$(oci kms management key create \
  --compartment-id "$COMPARTMENT_OCID" \
  --display-name encryption_suite-shared-kek \
  --key-shape '{"algorithm":"AES","length":32}' \
  --endpoint "$MGMT" \
  --query 'data.id' --raw-output)

oci kms management vault get --vault-id "$VAULT_ID" \
  --query 'data."crypto-endpoint"'
```

Record the **key OCID** and the **crypto endpoint** — both go into
`settings.py` below.

### Step 2: grant the application IAM access

Create a dynamic group for the application's compute resource (or use a
user group for local dev) and attach a policy:

```
allow dynamic-group encryption_suite-app to use keys in compartment id <ocid>
allow dynamic-group encryption_suite-app to read vaults in compartment id <ocid>
```

The `use keys` verb covers `KMS_ENCRYPT` and `KMS_DECRYPT`, which is all the
runtime needs for an OCID-addressed shared key.

### Step 3: configure `ENCRYPTION`

```python
ENCRYPTION = {
    "KEY_SETS": {"default": {"silo": "...", "key_store": "oci"}},  # whatever you use
    "KMS_KEY_STORES": {
        "oci": {
            "ADAPTER": "encryption_suite.adapters.key_stores.oci.OCIVaultAdapter",
            "OPTIONS": {
                "OCI_VAULT_CRYPTO_ENDPOINT": "https://bxxx-crypto.kms.us-ashburn-1.oraclecloud.com",
                "CREDENTIAL_STRATEGY": "instance_principal",   # or "api_key" off-OCI
                "SHARED_KEK_ID": "ocid1.key.oc1.iad.bxxx.aaaa...",
            },
            "KEK_STRATEGY_ADAPTER": "encryption_suite.adapters.keks.SharedKekStrategy",
            # KEK_PROVISIONER_ADAPTER omitted — defaults to NullKekProvisioner
        },
    },
}
```

### Step 4: create DEKs

Each silo still needs its own DEK row, encrypted under the shared
KEK. Either let the engine create them lazily on first encrypt
(`KEY_AUTO_PROVISION = True`, the default) or pre-create them in bulk:

```bash
python manage.py setup_encryption_keys
```

---

## Combination B — per-silo KEK, addressed by OCID

Best fit: multi-tenant SaaS that provisions keys outside this application (Terraform /
Console / CLI) and pins each tenant to a specific OCID.

### Step 1: provision a key per silo

For each new tenant (Terraform preferred — keys are defined in IaC alongside
everything else). Tag each key with the silo UID so operators can
correlate them:

```hcl
resource "oci_kek" "tenant_42" {
  compartment_id      = var.compartment_ocid
  display_name        = "encryption_suite-team-42"
  management_endpoint = oci_kms_vault.encryption_suite.management_endpoint

  key_shape {
    algorithm = "AES"
    length    = 32
  }

  protection_mode = "HSM"
  freeform_tags   = { silo_uid = "team-42" }
}

output "tenant_42_kek_ocid" {
  value = oci_kek.tenant_42.id
}
```

Capture the resulting OCID.

### Step 2: configure `ENCRYPTION` with `KEK_MAP`

```python
ENCRYPTION = {
    "KEY_SETS": {"default": {"silo": "...", "key_store": "oci"}},
    "KMS_KEY_STORES": {
        "oci": {
            "ADAPTER": "encryption_suite.adapters.key_stores.oci.OCIVaultAdapter",
            "OPTIONS": {
                "OCI_VAULT_CRYPTO_ENDPOINT": "https://bxxx-crypto.kms.us-ashburn-1.oraclecloud.com",
                "CREDENTIAL_STRATEGY": "instance_principal",
                "KEK_MAP": {
                    "team-42": "ocid1.key.oc1.iad.bxxx.aaaa...",
                    "team-43": "ocid1.key.oc1.iad.bxxx.bbbb...",
                    # ...
                },
            },
            "KEK_STRATEGY_ADAPTER": "encryption_suite.adapters.keks.PerSiloKekStrategy",
        },
    },
}
```

For deployments with many tenants, generate `KEK_MAP` from Terraform output (a
JSON file mounted as a config secret, or rendered into `settings.py` via a
deploy step) rather than hand-editing settings.

### Step 3: grant the runtime IAM access

A single compartment-scoped policy covers every key:

```
allow dynamic-group encryption_suite-app to use keys in compartment id <ocid>
allow dynamic-group encryption_suite-app to read vaults in compartment id <ocid>
```

### Step 4: per-new-tenant workflow

For each new silo: provision the OCI key, capture its OCID, add the
`UID → OCID` entry to `KEK_MAP`, and redeploy (or reload the secret backing
it). Until the OCID is in `KEK_MAP`, any encrypt for that tenant raises
`KekNotProvisionedError`. Use the [Reconcile Keys admin page](#the-reconcile-keys-admin-page)
to see which UIDs are still `<missing>`.

---

## Combination C — per-silo KEK, auto-provisioned

Best fit: multi-tenant SaaS that wants new tenants to "just work" without an
provisioning outside this application step or a `KEK_MAP` edit per tenant.

Here you address keys by **display name** via `KEK_TEMPLATE`, and
`OciKekProvisioner` creates each key on first use. No `KEK_MAP` to maintain.

### Step 1: grant the runtime **manage keys**

Provisioning creates keys, so the runtime needs more than `use keys`:

```
allow dynamic-group encryption_suite-app to manage keys in compartment id <ocid>
allow dynamic-group encryption_suite-app to read vaults in compartment id <ocid>
```

`manage keys` also covers `ScheduleKeyDeletion`, `ListKeys` and `GetKey`, so
deleting a KEK and reconciling against the compartment need nothing further.

### Step 2: configure `ENCRYPTION` with `KEK_TEMPLATE` + the provisioner

```python
_OCI_CRED = {
    "CREDENTIAL_STRATEGY": "instance_principal",   # or "api_key" off-OCI
    # (+ inline api_key fields here if using api_key off-OCI)
}

ENCRYPTION = {
    "KEY_SETS": {"default": {"silo": "...", "key_store": "oci"}},
    "KMS_KEY_STORES": {
        "oci": {
            "ADAPTER": "encryption_suite.adapters.key_stores.oci.OCIVaultAdapter",
            "OPTIONS": {
                "OCI_VAULT_CRYPTO_ENDPOINT": "https://bxxx-crypto.kms.us-ashburn-1.oraclecloud.com",
                # Management endpoint + compartment let the adapter resolve a display
                # name to its OCID.
                "OCI_VAULT_MANAGEMENT_ENDPOINT": "https://bxxx-management.kms.us-ashburn-1.oraclecloud.com",
                "OCI_COMPARTMENT_OCID": "ocid1.compartment.oc1..aaaa...",
                "KEK_TEMPLATE": "encryption_suite-{silo_uid}",
                **_OCI_CRED,
            },
            "KEK_STRATEGY_ADAPTER": "encryption_suite.adapters.keks.PerSiloKekStrategy",
            "KEK_PROVISIONER_ADAPTER": "encryption_suite.adapters.keks.OciKekProvisioner",
            "KEK_PROVISIONER_OPTIONS": {
                "OCI_VAULT_MANAGEMENT_ENDPOINT": "https://bxxx-management.kms.us-ashburn-1.oraclecloud.com",
                "OCI_COMPARTMENT_OCID": "ocid1.compartment.oc1..aaaa...",
                "OCI_KEY_PROTECTION_MODE": "HSM",   # or "SOFTWARE"
                "OCI_KEY_ALGORITHM": "AES",
                "OCI_KEY_LENGTH": 32,               # bytes; 16/24/32 = AES-128/192/256
                "OCI_KEY_PROVISION_TIMEOUT_SECONDS": 60,
                "PROVIDER_DELETION_WINDOW_DAYS": 7,   # OCI accepts 7-30
                # "KEK_ROTATION_PERIOD_DAYS": 90,     # optional; 60-365, private vault only
                **_OCI_CRED,
            },
        },
    },
}
```

`KEK_PROVISIONER_OPTIONS` reference:

| Option | Required | Default | Notes |
|---|---|---|---|
| `OCI_VAULT_MANAGEMENT_ENDPOINT` | yes | — | where keys are created/listed |
| `OCI_COMPARTMENT_OCID` | yes | — | compartment new keys are created in |
| `OCI_KEY_PROTECTION_MODE` | no | `HSM` | `HSM` or `SOFTWARE` (Software is free; HSM is billed) |
| `OCI_KEY_ALGORITHM` | no | `AES` | |
| `OCI_KEY_LENGTH` | no | `32` | key length in **bytes** |
| `OCI_KEY_PROVISION_TIMEOUT_SECONDS` | no | `60` | max wait for a new key to reach `ENABLED` before encrypt |
| `PROVIDER_DELETION_WINDOW_DAYS` | no | `7` | days until OCI destroys a scheduled key; OCI accepts 7-30 and has no immediate option |
| `KEK_ROTATION_PERIOD_DAYS` | no | — | automatic rotation interval; OCI accepts 60-365. **Runs only in a virtual private vault**, a path untested here — see [Automatic key rotation](#automatic-key-rotation) |
| `CREDENTIAL_STRATEGY` (+ its options) | no | `api_key` | how the provisioner authenticates to the management endpoint |

### Step 3: first encrypt provisions the key

With `KEY_AUTO_PROVISION = True` (default), the first encrypt for a new tenant:

1. resolves `KEK_TEMPLATE` to the display name `encryption_suite-team-42`,
2. `OciKekProvisioner` creates the key (if absent) and waits for it to reach
   `ENABLED` — a one-time pause of a few seconds on that first request,
3. the adapter resolves the name to its OCID and encrypts.

No per-tenant deploy or `KEK_MAP` edit. Confirm on the
[Reconcile Keys admin page](#the-reconcile-keys-admin-page) that the row flipped to **Ready**.

> **Tuning the wait.** `OCI_KEY_PROVISION_TIMEOUT_SECONDS` bounds how long the
> provisioner blocks waiting for `ENABLED`. Software keys settle in seconds;
> raise it for HSM keys or slow regions. To take the wait out of the request
> path entirely, pre-provision (call `setup_encryption_keys`, or run a small
> management step when a tenant is created) so the key already exists by the
> time the first user encrypts.

---

## Tagging keys

Both are optional, both are written only when a key is **created**, and they are
configured separately because their shapes differ.

| | Freeform tags | Defined tags |
|---|---|---|
| Option | `TAGS` | `DEFINED_TAGS` |
| Shape | `{"key": "value"}` | `{"namespace": {"key": "value"}}` |
| Setup needed | none | the namespace and each key must exist in the tenancy first |
| Governed | no — anyone who can tag can invent a key | yes — the namespace defines which keys exist |
| Usable for cost tracking | **no** | **yes**, when the key definition is marked cost-tracking |

The practical consequence: **chargeback on OCI needs defined tags.** Freeform
tags are the direct equivalent of AWS tags or Azure tags and are what `TAGS`
means on every other provider, but OCI's Cost Analysis and budgets only see
cost-tracking keys, which only exist inside a namespace.

```python
"KEK_PROVISIONER_OPTIONS": {
    # …
    "TAGS": {"app": "my-app", "managed-by": "encryption-suite"},
    "DEFINED_TAGS": {"finance": {"cost-center": "engineering"}},
},
```

### Creating the namespace first

A `DEFINED_TAGS` entry naming a namespace or key that does not exist makes OCI
reject the **key creation** — so a tagging mistake surfaces as a tenant's first
encrypt failing, which is nowhere near the setting that caused it. Create them
before deploying:

1. **Governance & Administration → Tag Namespaces → Create Namespace.** Pick the
   compartment, give it a name (`finance`), and leave the "Add tag" section on
   that form empty — those tags go *on the namespace resource*, and are not the
   keys you are defining.
2. Open the namespace → **Create Tag Key Definition** → name the key
   (`cost-center`), and choose a value type. Static value is the simplest.
3. Tick **cost-tracking** on the key definition if it is for chargeback. A
   tenancy allows ten cost-tracking keys.

Your keys will also carry Oracle's own `Oracle-Tags.CreatedBy` and
`Oracle-Tags.CreatedOn`, applied by the tenancy's tag defaults. That is expected
and untouched: the package adds what you configured and never removes or
rewrites anything else.

### No tag synchronization

Tags are written at creation and never synchronized afterwards. A key that
already exists when you add `TAGS` keeps whatever it has — change it at the
provider (`oci kms management key update`) using the Key Encryption Keys
changelist as the inventory of what this deployment owns.

---

## Automatic key rotation

Set `KEK_ROTATION_PERIOD_DAYS` in `KEK_PROVISIONER_OPTIONS` and every key the
provisioner creates from then on carries an OCI auto-rotation schedule. OCI
accepts **60 to 365 days**; a value outside that is refused at `manage.py check`,
not at a tenant's first encrypt.

> **This works only in a virtual private vault.** As of August 2026, OCI runs
> automatic rotation for virtual private vaults only; a standard vault refuses
> the schedule, and Oracle lists the feature for standard vaults as *coming
> soon*. A private vault is also billed differently from the standard one — price
> it before turning this on.
>
> **Untested here.** This package writes the schedule and handles a standard
> vault's refusal, which was verified against a live vault. The accepted path — a
> schedule OCI takes and runs — has not been exercised against a virtual private
> vault.

On a standard vault the key is still **created and usable**, and one line goes to
the `encryption_suite` log:

```
OCI refused the auto-rotation schedule; the key works but will not rotate on its own.
Automatic rotation runs only in a virtual private vault — a standard vault leaves its keys
on manual rotation. Move the vault, or remove KEK_ROTATION_PERIOD_DAYS and rotate by hand.
kek="encryption_suite-team-42" days=90 key_preexisting=False detail="..."
```

That warning is the only signal — nothing else reports a key quietly left on
manual rotation — so do not filter it. The alternative would have been to refuse
the option at startup, which is what every other provider does, but that needs
the vault type, and reading it needs a permission `manage keys` does not include.

Two things the schedule does **not** do:

- **It does not touch keys that already exist.** The schedule is written on the
  create call, so keys provisioned before you set the option stay on manual
  rotation, and a key created outside this application keeps its operator's
  policy. Set it at the provider (`oci kms management key update`) for those.
- **It does not require re-wrapping.** OCI resolves the key version from the
  ciphertext, so DEKs wrapped under an older version keep decrypting untouched.
  Run [`reencrypt_keys`](management-commands.md#reencrypt_keys) when you want an
  old version *emptied* — OCI bills per key version, so that is a cost question
  rather than a correctness one.

---

## The Reconcile Keys admin page

For Combinations B and C, this page is the operator workflow. It lists every
silo with the key identifier the application would use, and flags the ones
whose first encryption is still pending. See
[Reconcile Keys page](admin-panel.md#reconcile-keys-page) for the full
description and the three ways to reach it.

The identifier shown is an OCID under `KEK_MAP`, or the display name rendered
from `KEK_TEMPLATE`. A silo that resolves to neither shows `<missing>` and is
flagged **Needs setup** just like one whose key has not been created.

---

## Failure modes and what they look like

### KEK missing (unmapped name / OCID)

`KekNotProvisionedError` is raised by the engine before any OCI call. The user
sees:

> Encryption and decryption are unavailable for this data.

The admin sees an `ERROR`-level log entry naming the silo UID, the
strategy, and the provisioner. Under Combination B, add the OCID to `KEK_MAP`
and redeploy. Under Combination C, this usually means the provisioner lacks
`manage keys` — check the IAM policy. If the log shows a
`404 NotAuthorizedOrNotFound` on `create_key`, the policy almost certainly grants
only `manage vaults` (or `use keys`); creating a key needs **`manage keys`**. On
a keyless host, also confirm the dynamic group is in the **Default** domain (see
[`resource_principal`](#resource_principal--container-instances-and-functions)).

### Newly provisioned key not yet usable

If a freshly created key hasn't reached `ENABLED`, the crypto endpoint returns
`404 NotAuthorizedOrNotFound`. The provisioner waits for `ENABLED` (bounded by
`OCI_KEY_PROVISION_TIMEOUT_SECONDS`) precisely to avoid this. If you still see
it, the wait timed out — raise the timeout, or pre-provision.

### Multiple keys with the same display name

OCI does not enforce unique display names. If a `KEK_TEMPLATE` name resolves to
more than one live key, the adapter raises rather than guess. Disable or delete
the duplicate so the name resolves to a single OCID, or pin the tenant to an
OCID via `KEK_MAP`.

### Key disabled or pending deletion in OCI

OCI returns a `KeyNotEnabled` / `KeyDisabled` error from the crypto endpoint.
Re-enable the key in the Console (or cancel the scheduled deletion) and retry.

If the key is scheduled for deletion, provisioning will not quietly create a
replacement under the same display name: OCI does not enforce unique names, so
doing that would leave two keys answering to one name and only one of them
holding the material that decrypts existing data. Cancel the deletion
(`oci kms management key cancel-deletion --key-id <ocid>`) to recover the key, or
point the tenant at a different name.

This also applies to the **admin test console**: deleting its key schedules that
key at OCI, and because OCI's minimum window is 7 days, the console cannot
recreate it under the same name until then. Cancel the deletion to get the
console back the same day —
`oci kms management key cancel-deletion --key-id <ocid> --endpoint <management-endpoint>`,
or **Cancel Deletion** on the key in the Console.

### Wrong vault crypto endpoint

The adapter does not infer the endpoint — it must be set in
`OCI_VAULT_CRYPTO_ENDPOINT`. The crypto endpoint is vault- and region-specific;
an endpoint for a vault in `us-ashburn-1` cannot encrypt against a key in
`us-phoenix-1`.

### Credentials expired

`api_key`: rotate the signing key (in `~/.oci/config`, or the
`OCI_PRIVATE_KEY_CONTENT` secret for the inline path). The adapter picks up the
new key on next process restart.

Keyless strategies (`instance_principal` / `resource_principal` /
`oke_workload_identity`): the OCI SDK signer refreshes its token automatically.
Persistent failures usually mean the dynamic group / policy no longer matches
the running resource.

---

## Related reading

- [KEK strategies](kek-strategies.md) — full strategy reference, including
  cohort and BYOK.
- [KEK provisioning](kek-provisioning.md) — strategy-vs-provisioner split and
  the OCI name-lookup provisioning pattern.
- [KMS adapters](kms-adapters.md) — adapter / credential strategy
  reference for OCI and the other providers.
- [Configuration reference](configuration.md) — every `ENCRYPTION`
  setting, including `KEY_AUTO_PROVISION`, `DEK_CACHE_TTL`, and
  `LOG_DECRYPTS`.
- [Key rotation](key-rotation.md) — rotating KEKs and re-encrypting.
