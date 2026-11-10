# KEK provisioning

A KEK provisioner creates the KEK on the KMS provider when it does not
already exist. It complements the [KEK strategy](kek-strategies.md): the
strategy decides the KEK's identifier for a given silo, the
provisioner ensures a key with that identifier actually exists on the KMS.

Splitting the two concerns lets you mix any naming policy with any
provisioning policy. For example:

- `PerSiloKekStrategy` + `NullKekProvisioner` — one KEK per silo,
  provisioned outside this application (Terraform, CI script).
- `PerSiloKekStrategy` + `AwsKekProvisioner` — one KEK per silo,
  created by the application on demand.
- `SharedKekStrategy` + `NullKekProvisioner` — one KEK for all silos,
  created once at deploy time.
- a custom bring-your-own-key strategy + `NullKekProvisioner` — customer-supplied
  KEK ARNs, created by the customer. Not a shipped class: see the
  [`ByokKekStrategy` worked example](kek-strategies.md#writing-a-custom-strategy)
  for one you write yourself.

---

## Extension point rationale

Some KMS providers — notably AWS KMS and GCP Cloud KMS — support programmatic
key creation, but most organizations want tight control over who creates
keys and how they are tagged, policied, and audited. The two operational
patterns are:

1. **Out-of-band provisioning.** An IaC tool or bootstrap script creates
   the KEK before the application tries to use it. The application's IAM
   role only has `Encrypt`, `Decrypt`, and `GenerateDataKey` permissions.
   This is the safer default and what the library assumes when no
   provisioner is configured.

2. **Application-driven provisioning.** The application creates the KEK on
   demand the first time a new silo encrypts data. This simplifies
   per-tenant isolation in multi-tenant SaaS — each new signup automatically
   gets its own KEK — at the cost of granting the application `CreateKey`
   permissions.

The `KEK_PROVISIONER_ADAPTER` setting selects between them.

---

## Selecting a provisioner

`KEK_PROVISIONER_ADAPTER` defaults to
`encryption_suite.adapters.keks.NullKekProvisioner`, which does nothing.
To enable application-driven provisioning, point the setting at a
provider-specific class and configure it via `KEK_PROVISIONER_OPTIONS`:

```python
ENCRYPTION = {
    "KEY_SETS": {"default": {"silo": "...", "key_store": "main"}},
    "KMS_KEY_STORES": {
        "main": {
            "ADAPTER": "encryption_suite.adapters.key_stores.aws.AwsKmsAdapter",
            "OPTIONS": {
                "AWS_REGION": "us-east-1",
                "KEK_TEMPLATE": "alias/encryption_suite-{silo_uid}",
            },
            "KEK_STRATEGY_ADAPTER": (
                "encryption_suite.adapters.keks.PerSiloKekStrategy"
            ),
            "KEK_PROVISIONER_ADAPTER": "encryption_suite.adapters.keks.AwsKekProvisioner",
            "KEK_PROVISIONER_OPTIONS": {
                "KEY_SPEC": "SYMMETRIC_DEFAULT",
                "KEY_USAGE": "ENCRYPT_DECRYPT",
                "TAGS": {"app": "encryption_suite", "env": "production"},
            },
        },
    },
}
```

---

## Built-in provisioners

All provisioners live under `encryption_suite.adapters.keks` and accept
their own `KEK_PROVISIONER_OPTIONS` dict (separate from `OPTIONS`) so
that provisioning credentials can differ from runtime encrypt/decrypt
credentials.

| Class | Provider | Key naming |
|---|---|---|
| `NullKekProvisioner` | any | does nothing (default) |
| `AwsKekProvisioner` | AWS KMS | name = key ARN or `alias/...` |
| `GcpKekProvisioner` | GCP Cloud KMS | name = CryptoKey name within a pre-existing key ring |
| `AzureKekProvisioner` | Azure Key Vault | name = key name within a pre-existing vault |
| `HashiCorpVaultKekProvisioner` | HashiCorp Vault | name = transit key name |
| `IbmKekProvisioner` | IBM Key Protect / HPCS | name = root key name (2-90 chars, not required to be unique); resolved to UUID by the adapter |
| `FlyKmsKekProvisioner` | Fly.io KMS | name = secretkey name (`[A-Za-z0-9_]+`) |
| `InfisicalKekProvisioner` | Infisical KMS | name = slug key name (`[a-z0-9-]+`, ≤32); resolved to UUID by the adapter |
| `OciKekProvisioner` | OCI Vault | name = key display name; resolved to OCID by the adapter |

Each non-trivial provisioner reuses the same credential-strategy classes
as its corresponding KMS adapter (`CREDENTIAL_STRATEGY` keyed under
`KEK_PROVISIONER_OPTIONS`), maintains a process-local "already ensured"
cache, and tolerates "key already exists" races from the provider.

### `NullKekProvisioner`

This provisioner is the default and does nothing. KEKs must exist on the KMS provider before the
application tries to encrypt a DEK under them. If the KEK is missing, the
first encryption attempt raises `KekNotProvisionedError` with a translated
user-facing message (`"Encryption and decryption are unavailable for this
data."`) and an English admin log entry naming the missing KEK, the
strategy in use, and the provisioner in use.

This is the safe default for production deployments that provision keys
outside this application.

### `AwsKekProvisioner`

This provisioner creates a symmetric `ENCRYPT_DECRYPT` KMS key. If the resource name starts
with `alias/`, it also creates an alias pointing at the new key.

```python
"KEK_PROVISIONER_ADAPTER": "encryption_suite.adapters.keks.AwsKekProvisioner",
"KEK_PROVISIONER_OPTIONS": {
    "AWS_REGION": "us-east-1",
    "CREDENTIAL_STRATEGY": "iam_role",   # iam_role | oidc
    # When CREDENTIAL_STRATEGY="oidc", OIDC_SOURCE is required:
    # "OIDC_SOURCE": "fly",   # for example
    # "OIDC_SOURCE_OPTIONS": {},
    "KEY_SPEC": "SYMMETRIC_DEFAULT",     # default
    "KEY_USAGE": "ENCRYPT_DECRYPT",      # default
    "KEY_DESCRIPTION": "django-encryption-suite KEK",
    "TAGS": {"app": "encryption_suite", "env": "production"},
    # "POLICY": "...JSON key policy...",
    # "CUSTOM_KEY_STORE_ID": "cks-1234567890abcdef0",  # optional; CloudHSM key store
    # "KEK_ROTATION_PERIOD_DAYS": 365,     # optional; AWS accepts 90-2560
    # "PROVIDER_DELETION_WINDOW_DAYS": 7,  # default; AWS accepts 7-30
    # "ALIAS_PROPAGATION_TIMEOUT_SECONDS": 10,  # default
},
```

Required IAM: `kms:DescribeKey`, `kms:CreateKey`, `kms:CreateAlias`,
`kms:TagResource`. Add `kms:ScheduleKeyDeletion` for deletion,
`kms:ListAliases` for reconcile, and `kms:EnableKeyRotation` if
`KEK_ROTATION_PERIOD_DAYS` is set.

**Rotation** calls `EnableKeyRotation` after the key is created, with
`KEK_ROTATION_PERIOD_DAYS` as `RotationPeriodInDays` (AWS refuses anything under 90
days, or over 2560). Nothing has to be re-wrapped afterwards: rotation adds new
backing key material and keeps the old material for decrypt, and AWS resolves
the backing key from the ciphertext itself. Turning rotation on needs a
permission that key creation does not, so a refusal is logged as a warning
naming the key rather than failing the request — the key is created and works,
it just will not rotate on its own.

**Custom key store.** Set `CUSTOM_KEY_STORE_ID` to create the keys in an AWS
CloudHSM key store, a single-tenant HSM cluster you control, instead of in AWS
KMS's shared HSMs. The provisioner passes it to `CreateKey` with
`Origin=AWS_CLOUDHSM`. `Origin` is not a separate option: it is sent only with
`CUSTOM_KEY_STORE_ID`, and AWS defaults it to `AWS_KMS` otherwise. External key
stores and imported key material are not supported. The key store must already
exist and be connected when a key is created. AWS does not
rotate keys in a custom key store, so the provisioner refuses
`KEK_ROTATION_PERIOD_DAYS` alongside it at construction, and `manage.py check`
reports the conflict. To keep some keys in CloudHSM and others in standard KMS,
define two stores in `KMS_KEY_STORES` that differ only in this option, and point
each key set at the one it needs.

**Alias propagation.** `CreateAlias` is eventually consistent — it returns
before the alias is readable. Because the first encrypt under a new KEK runs in
the same request that provisioned it, that encrypt can fail with
`NotFoundException` on a key that demonstrably exists. `ensure_kek` therefore
polls `DescribeKey` after creating an alias until it resolves, for up to
`ALIAS_PROPAGATION_TIMEOUT_SECONDS`. The cost is paid once per KEK, on the
create path only. If the timeout expires the key is left uncached rather than
raising: the key exists and the next request will find it.

**Deletion** calls `ScheduleKeyDeletion`, passing
`PROVIDER_DELETION_WINDOW_DAYS` as AWS's `PendingWindowInDays`. See
[the two deletion windows](#the-two-deletion-windows) for how that relates to
`KEY_DELETION_WINDOW_DAYS`. The alias is left attached on purpose: AWS deletes
it with the key, so it is what keeps the pending key visible to enumeration
until it is really gone. A silo whose key is in the waiting period cannot
encrypt; if one comes back, cancel the deletion at the provider first.

**State checks** call `DescribeKey` and report `KeyState`, so a key already
inside AWS's pending-deletion window is recognized without attempting to use it.
Reconcile probes this for keys it would otherwise report as orphaned — a
discovered row is born `active` because that is the field default, not because
anyone checked, so without the probe a key mid-deletion reads as work still
awaiting a decision. A key AWS has no record of reports *unknown* rather than
active, and a failed probe changes nothing.

**Enumeration** calls `ListAliases`, because a KMS key has no name of its own.
That works only when the KEKs are alias-form: with a `KEK_TEMPLATE` that renders
a bare key id or ARN there is nothing to list, and rather than report "no keys
exist" the provisioner degrades to *detection-unavailable*.

### `GcpKekProvisioner`

This provisioner creates symmetric `ENCRYPT_DECRYPT` CryptoKeys inside an **existing** key
ring. The key ring itself is not created — granting
`cloudkms.keyRings.create` to app runtimes is rarely justified.

```python
"KEK_PROVISIONER_ADAPTER": "encryption_suite.adapters.keks.GcpKekProvisioner",
"KEK_PROVISIONER_OPTIONS": {
    "GCP_PROJECT_ID": "my-project",
    "GCP_KMS_LOCATION": "us-central1",
    "GCP_KMS_KEY_RING": "encryption_suite-prod",
    "CREDENTIAL_STRATEGY": "adc",        # adc | oidc | service_account_key
    # When CREDENTIAL_STRATEGY="oidc", OIDC_SOURCE is required:
    # "OIDC_SOURCE": "fly",   # for example
    # "OIDC_SOURCE_OPTIONS": {},
    "PURPOSE": "ENCRYPT_DECRYPT",        # default
    "ALGORITHM": "GOOGLE_SYMMETRIC_ENCRYPTION",
    "PROTECTION_LEVEL": "SOFTWARE",      # or "HSM"
    # "KEK_ROTATION_PERIOD_DAYS": 90,    # 1-day floor on Cloud KMS
    # "PROVIDER_DELETION_WINDOW_DAYS": 7,  # default; 24-hour floor
    "TAGS": {"app": "encryption_suite"},
},
```

Required IAM: `cloudkms.cryptoKeys.create`, `cloudkms.cryptoKeys.get` on
the key ring. Add `cloudkms.cryptoKeys.list`, `cloudkms.cryptoKeyVersions.list`,
`cloudkms.cryptoKeyVersions.destroy` and `cloudkms.cryptoKeyVersions.update` for
deletion and reconcile, plus `cloudkms.cryptoKeys.update` if any key carries a
rotation schedule.

**Deletion destroys versions, because Cloud KMS cannot delete a key.** A
CryptoKey and its key ring are permanent — and free. Key *material* is held in the
versions, so deleting a KEK here destroys every version it has, which is what
crypto-shreds the DEKs wrapped under it. The empty CryptoKey shell stays in the
ring forever, billing nothing.

Every version is disabled before it is destroyed: a destroy on an enabled version
is refused outright under the `constraints/cloudkms.disableBeforeDestroy` org
policy, and disabling one already on its way out costs nothing. Any rotation
schedule on the key is cleared first — otherwise Cloud KMS adds a fresh enabled
version to a key this deployment believes it destroyed, resurrecting it as a
live, billable key that reconcile then reports as an orphan forever.

`PROVIDER_DELETION_WINDOW_DAYS` becomes the key's `destroyScheduledDuration`, so
unlike AWS it is fixed **at creation** and cannot be changed for keys that
already exist. The default is 7 days, which *overrides* the longer default Cloud
KMS would otherwise apply; the floor is 24 hours, and the
`constraints/cloudkms.minimumDestroyScheduledDuration` org policy can raise it
above whatever is configured. See
[the two deletion windows](#the-two-deletion-windows) for how the provider's
window relates to `KEY_DELETION_WINDOW_DAYS`.

**Enumeration** calls `cryptoKeys.list` on the configured ring and returns full
resource names — the same form recorded on the row, so reconcile compares like
with like. Keys in other rings are not listed at all, since the ring is part of
the path.

A key whose every version is destroyed is reported *gone* even though the
CryptoKey resource still exists. Cloud KMS never removes that shell, so counting
it as present would leave every deletion this deployment performs permanently
unconfirmed and reported as drift. The primary version answers this without a
second round trip in the common case; only when the primary is destroyed are the
versions listed, because destroying the primary at the console can leave an older
version enabled, and that key can still decrypt.

**State checks** read the primary version's state, so a key inside Cloud KMS's
destroy-scheduled window is recognized without attempting to use it. A key Cloud
KMS has no record of reports *unknown* rather than active, and so does any state
other than enabled or destroy-scheduled — a disabled version is not being
deleted, but it is not usable either.

### `AzureKekProvisioner`

This provisioner creates symmetric AES (`oct-HSM`) keys in an **existing** Key Vault. It defaults to
`encrypt`/`decrypt` key operations to match `AzureKeyVaultAdapter`'s AES-GCM
usage.

```python
"KEK_PROVISIONER_ADAPTER": "encryption_suite.adapters.keks.AzureKekProvisioner",
"KEK_PROVISIONER_OPTIONS": {
    "AZURE_VAULT_ENDPOINT": "https://my-vault.vault.azure.net",
    "CREDENTIAL_STRATEGY": "managed_identity",   # or "client_secret", "oidc"
    "KEY_SIZE": 256,                             # or 128, 192
    "KEY_OPS": ["encrypt", "decrypt"],
    "KEK_ROTATION_PERIOD_DAYS": 180,             # optional; 7-day floor
    "TAGS": {"app": "encryption_suite"},
},
```

> **Premium vault required, and a Microsoft preview feature.** Standard vaults
> offer RSA and EC only; symmetric keys need Premium, where Microsoft ships them
> as a public preview — no SLA, and not recommended by Microsoft for production
> workloads. A Standard vault rejects the creation, and this provisioner rewrites
> that rejection to name the SKU rather than leaving an operator with Key Vault's
> "unsupported key type" on a tenant's first encrypt.

Required role: `Key Vault Crypto Officer`, or a custom role granting
`keys/create` and `keys/get`, plus `keys/list` and `keys/delete` for enumeration
and deletion, and the rotation-policy permissions if `KEK_ROTATION_PERIOD_DAYS` is
set.

**Deletion is Key Vault's soft delete.** The key becomes unusable for everything
but recovery, stays recoverable until `scheduled_purge_date`, and Key Vault
purges it at the end of the vault's retention period. That is the same shape as
an AWS key inside its pending-deletion window. The name stays reserved for the
whole period, so provisioning refuses a name held by a deleted key rather than
letting Key Vault reject the creation — that key is absent from the vault
listing, so the raw conflict names something the operator cannot see. Recover it
(`az keyvault key recover`), purge it, or point the silo at a different name.

**`PROVIDER_DELETION_WINDOW_DAYS` is refused here**, at construction. Azure's
recovery period is the vault's `softDeleteRetentionInDays` — 7 to 90 days, chosen
when the vault is created and unchangeable afterwards — so nothing this
provisioner sends could alter it. Accepting the option would let an operator
believe they had shortened a window they had not. The vault reports the real
dates instead: `scheduled_purge_date` on a deleted key, and `recoverable_days` on
a live one as the fallback.

**Enumeration lists live and deleted-not-yet-purged keys**, since a recoverable
key's deletion has not completed. It drops out of the listing at purge, which is
what lets reconcile confirm the deletion.

**State checks** read the live key first and fall back to the deleted one, so a
key inside the retention period is recognized without attempting to use it. A key
in neither half reports *unknown* rather than active — it may have been deleted,
or be unreadable by this identity, and neither is evidence of health.

### `HashiCorpVaultKekProvisioner`

This provisioner creates transit keys through the HashiCorp Vault HTTP API. The transit secrets
engine must already be mounted (default: `transit/`).

```python
"KEK_PROVISIONER_ADAPTER": "encryption_suite.adapters.keks.HashiCorpVaultKekProvisioner",
"KEK_PROVISIONER_OPTIONS": {
    "VAULT_ENDPOINT": "https://vault.example.com:8200",
    "CREDENTIAL_STRATEGY": "token",      # token | approle | iam_aws | oidc
    "VAULT_TOKEN": "...",                # for the "token" strategy
    # For "approle":
    # "VAULT_ROLE_ID": "...",
    # "VAULT_SECRET_ID": "...",          # or VAULT_SECRET_ID_FILE
    "VAULT_NAMESPACE": "...",            # optional, HCP / Enterprise
    "VAULT_MOUNT_PATH": "transit",       # default
    "KEY_TYPE": "aes256-gcm96",          # default
    # "KEK_ROTATION_PERIOD_DAYS": 90,    # optional; 1-day floor
    # "ALWAYS_ALLOW_KEY_DELETION": True, # required to delete at all — see below
},
```

Required HashiCorp Vault policy: `create` and `read` on `transit/keys/<name>`,
`list` on `transit/keys` for reconcile, and — only if you enable deletion —
`update` on `transit/keys/<name>/config` plus `delete` on `transit/keys/<name>`.
The `POST /transit/keys/{name}` endpoint is itself idempotent, so this
provisioner does not need a probe call.

#### `ALWAYS_ALLOW_KEY_DELETION`

HashiCorp Vault is the one provider here that guards deletion on the key itself.
Every transit key carries a `deletion_allowed` flag, false when created, and
Vault refuses `DELETE /transit/keys/{name}` while it is false. Deleting from this application
therefore **overrides a protection the provider applies by default**, which is
why it is opt-in and defaults to `False`.

With it off, the provisioner reports itself as unable to delete: the run stops at
its capability gate, retains the key, and records *key deletion is not enabled
for this provisioner* as the reason. Nothing is attempted at HashiCorp Vault, so
nothing fails. Deletion by hand at the provider, or a separate rotation of the
mount, remains available and is a perfectly good posture.

With it on, `_do_delete_kek` sets `deletion_allowed` and then deletes, in two
calls. Arming immediately before the delete rather than at creation keeps keys
protected for the whole of their working life. If the delete then fails, the key
is left armed — that is deliberate; disarming in a handler risks replacing the
real error with the error from the disarm, and the retry re-arms it anyway.

**Deleting a transit key is immediate, total, and irreversible.** It removes every
version of the key at once, with no window and no restore, so anything still
wrapped under it is unrecoverable the instant the call returns. There is nothing
to delete afterwards and nothing to cancel. The package's own
`KEY_DELETION_WINDOW_DAYS` is the only waiting period in front of it.

### `IbmKekProvisioner`

This provisioner creates root keys in IBM Key Protect / HPCS by **name**. Key Protect has no
lookup-by-name endpoint and does not require names to be unique, so existence is
checked by listing keys and matching the `name` field; a key is created only when
no live key of that name is found.

```python
"KEK_PROVISIONER_ADAPTER": "encryption_suite.adapters.keks.IbmKekProvisioner",
"KEK_PROVISIONER_OPTIONS": {
    "IBM_INSTANCE_ID": "...",         # service instance GUID
    "IBM_REGION": "us-south",         # or IBM_ENDPOINT for HPCS / private endpoints
    "CREDENTIAL_STRATEGY": "api_key",    # default
    "IBM_API_KEY": "...",                # for "api_key"
    "EXTRACTABLE": False,                # default — root key, never leaves
    "KEY_DESCRIPTION": "django-encryption-suite KEK",
    # "KEK_ROTATION_PERIOD_DAYS": 90,    # optional; multiples of 30, up to 360
},
```

Required IAM: the **Manager** role on the Key Protect instance. It covers key
creation, listing, reading, deletion and rotation policies; wrap and unwrap are
the runtime adapter's, and can be held by a narrower identity. Restoring a
deleted key needs Manager too.

**Automatic rotation** is written as a second call after key creation
(`PUT /api/v2/keys/{id}/policies?policy=rotation`), because Key Protect's create
call takes no policy. `KEK_ROTATION_PERIOD_DAYS` must be a multiple of 30 and no more
than 360 — see [automatic key rotation](#automatic-key-rotation). It applies to
keys this deployment **creates**; a key adopted rather than created keeps
whatever policy it has, and changing the option later does not touch existing
keys.

`PROVIDER_DELETION_WINDOW_DAYS` is **refused at construction** — see
[the two deletion windows](#the-two-deletion-windows).

**Deletion is Key Protect's soft delete.** `DELETE /api/v2/keys/{id}` takes the
key out of service at once — which is what crypto-shreds the DEKs wrapped under
it — and starts a **fixed 30-day** restore window, reported as the outcome's
effective date. Deleting takes every version of the key with it. The name is
resolved to a UUID by listing first, and both a name with no live key behind it
and a 404 from the delete itself count as already deleted, so a repeated deletion is
harmless.

**Enumeration** lists the instance's keys and returns the live ones' names.
Deleted keys are filtered out even though Key Protect keeps them listed and
restorable: a deleted key can no longer wrap anything, so reporting it as present
would let reconcile call a shredded key healthy. Duplicate names collapse to one
entry.

**The state probe** reports a live key as active, a deleted-but-restorable one as
pending deletion with the end of its 30-day window, and a name with neither
behind it as unknown — it may have been deleted, or be unreadable by this
identity, and neither is evidence the key is healthy.

**Tags are not supported on a key.** Two routes, both closed: the create-key call
takes no tag metadata, and Global Tagging — where IBM Cloud tags live — refuses a
key CRN with `TAG_RESOURCE_NOT_SUPPORTED`. A configured `TAGS` is therefore
reported as undeliverable by the startup check.

The Key Protect **instance** is taggable, and normally is: it is an ordinary
account resource, tagged at creation or from the Resource list. That is outside
what this package provisions — it creates keys inside an instance you supply —
so instance tags are yours to set and are unaffected by `TAGS`. For a tag-based
ownership boundary, the instance is the grain IBM offers.

### `FlyKmsKekProvisioner`

This provisioner creates Fly.io secretkeys of type `xaes256gcm` over the local
`/.fly/api` Unix socket. The provisioner only runs inside a Fly
machine — there is no external fallback because django-encryption-suite is
a Django package and Django on Fly always runs inside a machine
already.

```python
"KEK_PROVISIONER_ADAPTER": "encryption_suite.adapters.keks.FlyKmsKekProvisioner",
"KEK_PROVISIONER_OPTIONS": {
    # Optional:
    # "FLY_APP_NAME": "my-fly-app",   # defaults to the FLY_APP_NAME
    #                                  # environment variable that Fly
    #                                  # injects into every machine.
    #                                  # The env var takes precedence
    #                                  # when both are set.
    # "KEY_TYPE": "xaes256gcm",       # default; the only AEAD type Fly exposes
    # "FLY_SOCKET_PATH": "/.fly/api", # default; override only for tests
},
```

There are no credential options — the socket is authenticated by mount.

The provisioner is **GET-first and never re-generates existing keys**.
Fly's `POST /generate` overwrites key material in place with no
version history, so calling it on an existing name would destroy every
ciphertext encrypted under the previous material. The provisioner
probes with `GET .../secretkeys/{name}`; on `404 not_found` it calls
`POST .../secretkeys/{name}/generate` once. On `200 OK` it caches the
result and returns. Manual `flyctl secrets create` is not subject to
this guard — avoid it on existing names.

Secretkey names must match `[A-Za-z0-9_]+` (letters, digits,
underscore). The strategy escapes the silo UID into that charset reversibly
(`team-1` becomes `team_2d1`), so the remaining sources of a bad name are the
template's literal text and `KEK_MAP` values, which are used as given. The
provisioner checks every name and raises `ValueError` for one that does not
conform. Use a `KEK_TEMPLATE` whose literal text conforms (e.g.
`encryption_suite_{silo_uid}`), or `KEK_MAP` values that use only those
characters.

See [Getting started with Fly KMS](getting-started-fly.md) for the
full setup and per-tenant workflows.

### `InfisicalKekProvisioner`

Infisical KMS identifies keys by server-assigned UUID, which the KEK strategy
cannot predict — but Infisical also exposes a *get key by name* endpoint, and
that lookup is what makes provisioning work without mutating `KEK_MAP`. The
strategy renders a deterministic slug name from the silo UID via
`KEK_TEMPLATE` (for example `encryption-suite-{silo_uid}`), the provisioner
ensures a key with that name exists in the project, and the adapter resolves the name to
its UUID (cached per process) before each encrypt.

**The key name is what gets recorded**, not the UUID it resolves to. A UUID is
assigned by Infisical, so it cannot be derived from a silo UID — and an *owner
prefix* has no UUID form at all, which would leave the ownership gate comparing a
name prefix against UUID-shaped values and matching nothing, silently refusing
every deletion and reporting KMS-side reconcile as finding no keys. So names are
the name space every layer shares, and decrypt resolves one to its UUID through
the same per-process cache encrypt uses. A `KEK_MAP` entry that is already a UUID
is recorded as itself; those deployments derive no owner prefix, so reconcile is
unavailable to them, and deletion is available only for keys marked
`KEK_MAP_DESTROYABLE`.

Deletion is **immediate and irreversible** — `DELETE /kms/keys/{keyId}` removes
the key at once, with no recovery window behind it. The package's own
`KEY_DELETION_WINDOW_DAYS` is therefore the only period in which a scheduled key
can still be restored; once the deletion runs, the key is gone.

`KEK_PROVISIONER_OPTIONS` requires `INFISICAL_PROJECT_ID` and accepts the same
`CREDENTIAL_STRATEGY` options as the adapter (`universal_auth`, `token`,
`oidc`), plus an optional `ENCRYPTION_ALGORITHM` (default `aes-256-gcm`). Pair it
with `PerSiloKekStrategy` and `KEK_TEMPLATE`. Key names must be *slugs* —
lowercase alphanumeric groups joined by single hyphens (`[a-z0-9-]`, ≤32 chars)
— so no two hyphens in a row and none at the start or end, rules Infisical
enforces but does not report. Since only
`{silo_uid}` is sanitized, the template's literal prefix has to satisfy them
too: use `encryption-suite-{silo_uid}`, not `encryption_suite-{silo_uid}`. See
[Getting started with Infisical KMS](getting-started-infisical.md).

To reference keys provisioned outside this application by UUID instead, list them in
`OPTIONS["KEK_MAP"]` and keep the default `NullKekProvisioner`.

### `OciKekProvisioner`

OCI Vault identifies keys by server-assigned OCID, which the KEK strategy cannot
predict — but each key also carries an operator-chosen **display name**, and the
management API can list and create keys. That display name is the by-name
resolution path (the same idea as Infisical's get-key-by-name). The strategy
renders a deterministic display name from the silo UID via `KEK_TEMPLATE`
(for example `encryption_suite-{silo_uid}`), the provisioner ensures a key with that
name exists in the compartment, and the adapter
resolves the name to its OCID (cached per process) before each crypto call.

**The display name is what gets recorded**, not the OCID it resolves to. An OCID
is assigned by OCI, so it cannot be derived from a silo UID — and an *owner
prefix* has no OCID form at all, which would leave the ownership gate comparing a
display-name prefix against OCID-shaped names and matching nothing, silently
refusing every deletion and reporting KMS-side reconcile as finding no keys. So
display names are the name space every layer shares, and decrypt resolves one to
an OCID through the same cache encrypt uses. A `KEK_MAP` / `SHARED_KEK_ID` entry
that is already an OCID is still recorded as itself; those deployments derive no
owner prefix, so neither deletion nor reconcile is available to them anyway.

OCI key creation is asynchronous, so the provisioner **waits for the new key to
reach `ENABLED`** before returning — a one-time cost on a silo's first
encrypt, bounded by `OCI_KEY_PROVISION_TIMEOUT_SECONDS` (default 60). OCI does
not enforce unique display names; the provisioner serializes in-process creation
and the adapter refuses to guess if a name resolves to more than one live key.

`KEK_PROVISIONER_OPTIONS` requires `OCI_VAULT_MANAGEMENT_ENDPOINT` and
`OCI_COMPARTMENT_OCID`, and accepts the same `CREDENTIAL_STRATEGY` options as the
adapter plus key-shape knobs (`OCI_KEY_PROTECTION_MODE`, `OCI_KEY_ALGORITHM`,
`OCI_KEY_LENGTH`) and `OCI_KEY_PROVISION_TIMEOUT_SECONDS`. It also accepts both
OCI tag systems — `TAGS` for freeform tags and `DEFINED_TAGS` for defined tags
(`{namespace: {key: value}}`), which is the one OCI uses for cost tracking — plus
`PROVIDER_DELETION_WINDOW_DAYS` (default 7, which is also OCI's floor) and
`KEK_ROTATION_PERIOD_DAYS` (60 to 365). The
provisioning identity needs **manage keys** (broader than the **use keys** the
adapter needs); nothing further is required for deletion or reconcile, since
`manage keys` already covers `ScheduleKeyDeletion`, `ListKeys` and `GetKey`.
Pair it with `PerSiloKekStrategy` and `KEK_TEMPLATE`; see
[Getting started with OCI Vault KMS](getting-started-oci.md).

**Automatic rotation** rides on the create call — `CreateKeyDetails` carries
`auto_key_rotation_details`, so no second request is needed. OCI accepts an
interval of 60 to 365 days, and both bounds are refused at `manage.py check`.

> **Only a virtual private vault rotates keys automatically.** As of August 2026,
> a standard vault rejects the schedule and Oracle lists automatic rotation there
> as *coming soon*; a virtual private vault runs it today, but is not free.
> **This package has not been tested against automatic rotation on a virtual
> private vault** — the refusal path below was verified live on a standard vault,
> the accepted path was not. This provisioner does
> not read the vault to find out which one it has: the vault type is on a
> resource that needs a different client, a vault OCID this configuration never
> carries, and an inspect permission outside the `manage keys` everything else
> here asks for. So a rejected schedule degrades — the key is created without it
> and one WARNING names the key, the interval and
> the reason. Watch for that line after enabling the option; a key silently left
> on manual rotation is what it exists to prevent.

Like tags, the schedule is written **at creation only**. A key that already
exists is adopted untouched, so changing `KEK_ROTATION_PERIOD_DAYS` later leaves
existing keys on the schedule they were made with — and a key created outside
this application keeps whatever policy its operator gave it.

**Deletion** calls `ScheduleKeyDeletion` with a `time_of_deletion` of now plus
`PROVIDER_DELETION_WINDOW_DAYS`. OCI accepts 7 to 30 days and has no immediate
option. The key keeps its display name for the whole window, which is what keeps
it visible to enumeration until it is really gone. See
[the two deletion windows](#the-two-deletion-windows) for how that relates to
`KEY_DELETION_WINDOW_DAYS`.

Because OCI does not enforce unique display names, nothing at the provider would
stop a *second* key being created under a name whose first key is on its way
out — leaving two keys answering to one name, only one of which holds the
material that decrypts what came before. Provisioning therefore refuses a name
held by a key inside the deletion window rather than creating over it. Cancel the
deletion at the provider (`oci kms management key cancel-deletion`) to recover
that key, or point the silo at a different name. For the same reason, resolution
and deletion refuse a name that matches more than one live key instead of
choosing between them.

**State checks** read the key's `lifecycle_state`, so a key inside OCI's deletion
window is recognized without attempting to use it. A name OCI has no live or
pending key for reports *unknown* rather than active.

**Enumeration** calls `ListKeys` on the compartment and returns display names —
the form recorded on the row, so reconcile compares like with like. Keys inside
the deletion window are included, because that deletion has not completed; a name
dropping out of the listing is what confirms it did.

To reference keys provisioned outside this application by OCID instead, list them in
`OPTIONS["KEK_MAP"]` and keep the default `NullKekProvisioner` — the
provisioner treats an OCID-form identifier as already-provisioned and is a no-op
for it.

---

## The two deletion windows

Deleting a KEK crosses two waiting periods, owned by two different parties. They
run in sequence, not in parallel.

| | `KEY_DELETION_WINDOW_DAYS` | `PROVIDER_DELETION_WINDOW_DAYS` |
|---|---|---|
| Owner | this package | the KMS provider |
| Set in | `ENCRYPTION` settings | `KEK_PROVISIONER_OPTIONS` |
| Default | 14 days | 7 days |
| Status while running | `deletion_scheduled` | `deletion_requested` |
| Starts when | the silo is deleted | the deletion calls the provider |
| Reversible | yes — the **Restore** admin action | only at the provider, by hand |
| Ends when | the deletion run finds it expired | reconcile stops seeing the key |

The provider window is **not** a data-recovery window. The data encryption key
was crypto-shredded the moment our window expired — its `encrypted_keyset` is
already cleared — so canceling the provider's deletion afterwards recovers a
key encryption key that no longer wraps anything. What it protects against is
operator error on the key itself, and what it costs is billing: the key is charged
for the whole period. That is why the default here is 7 days — shorter than what
AWS or GCP would apply on their own — and why the Key Encryption Keys changelist
keeps showing the key, with its date, until enumeration confirms it is gone.
Together with the package's own 14-day default, a KEK deletion takes 21 days end
to end unless you shorten either half.

Both bounds are refused at construction, so `manage.py check` reports an
out-of-range value at deploy rather than the provider rejecting key creation.
Providers differ in whether the option applies at all:

| Provider | Applies | Range | Notes |
|---|---|---|---|
| AWS | yes | 7-30 | `PendingWindowInDays` on `ScheduleKeyDeletion` |
| GCP | at creation only | 1+ | the key's `destroyScheduledDuration`. Fixed when the key is created, so changing it does not affect existing keys |
| OCI | yes | 7-30 | `time_of_deletion` on `ScheduleKeyDeletion`, sent as now + this many days |
| Azure | **refused** | — | the vault's `softDeleteRetentionInDays` decides (7-90, fixed when the vault is created). The option cannot reach Azure, so it is rejected at construction rather than ignored |
| Fly | no | — | deletion is immediate and irreversible — no provider window |
| Infisical | no | — | `DELETE /kms/keys/{keyId}` removes the key at once — no provider window |
| IBM | **refused** | — | Key Protect's restore window is a fixed 30 days that no request can change, so the option is rejected at construction rather than ignored |
| HashiCorp Vault | no | — | `DELETE /transit/keys/{name}` removes the key and all its versions at once — no provider window |

### The test console always uses the provider's minimum

The admin test console's sentinel keys ignore `PROVIDER_DELETION_WINDOW_DAYS` and
use the provider's floor instead — 7 days on AWS and OCI, 24 hours on GCP.
(Azure and IBM have no such option: the vault and the service respectively own
the period, and the console cannot shorten it.) The console
already bypasses the package's window entirely (it deletes at the provider
directly and hard-deletes its rows, rather than scheduling and waiting for a
deletion), because its keys hold no tenant data and exist to be created and
destroyed repeatedly. Leaving them to sit out a production-length provider window
would contradict that: it bills for a key nobody can use, and it stalls the one
workflow that proves deletion works end to end.

Where that value is read is provider-specific, and it matters. A provider that
takes the window as an argument to its delete call (AWS) reads it at deletion, so
the exception applies to keys that already exist. A provider that fixes the window
on the key at creation (GCP) must read it in `ensure_kek` — which means a console
key created *before* this behavior existed keeps whatever window it was born with.
Delete that key and let the console recreate it to pick up the minimum.

Providers declare their floor as `minimum_deletion_window_days` on the
provisioner; `None` means the provider has no window to shorten.

### Deploy-time floor check

A `PROVIDER_DELETION_WINDOW_DAYS` below the provider's floor is refused when the
provisioner is constructed, so `manage.py check` reports it (as `E004`) rather
than letting the provider reject it at the first encrypt — where it arrives as a
key *creation* failure complaining about deletion timing, for whichever tenant
happens to provision first.

The mistake it catches: wiring this option to the same value as the package's
`KEY_DELETION_WINDOW_DAYS`. That one legitimately accepts `0`, meaning
"immediately eligible for deletion"; this one is the provider's and has a hard floor
(24 hours on GCP, 7 days on AWS). Give them separate settings.

An org policy can raise the floor above what the provider itself enforces —
`constraints/cloudkms.minimumDestroyScheduledDuration` on GCP — which no
config check can see. That case still surfaces at key creation, but the error
names `PROVIDER_DELETION_WINDOW_DAYS` and the policy rather than only the
duration.

## The owner-prefix drift check

Scheduling a key encryption key for deletion snapshots the owner prefix in force
at that moment onto the row. When the deletion runs — a soft-delete window later —
it compares that snapshot against the prefix the *live* configuration derives,
and refuses the deletion if they differ, recording `retained` with the
`not_owned_by_deployment` reason.

The window is the reason. A `KEK_TEMPLATE` changed between scheduling and deletion
means the key was scheduled under naming assumptions that no longer hold, and the
deletion would otherwise destroy a key nobody currently chose. Authorization itself
always comes from the live configuration; the snapshot can only ever **withhold**
permission, never grant it. That asymmetry is deliberate — a stored value that
could grant permission would let anything able to write the column steer an
irreversible destruction.

**This check applies only to a `KEK_TEMPLATE` under a per-silo strategy.** Shared
and map-only deployments derive no owner prefix at all, so the snapshot and the
live value are both empty, they always match, and the check never fires. Every path
that schedules a key records the store's prefix for it, a `KEK_MAP` key marked
`KEK_MAP_DESTROYABLE` included, so a mapped key never reads as drift. Shared keys
are refused earlier and for a different reason: the disposition gate, which never
deletes a shared or opaque key. If you see a key retained on such a deployment, read
the reason on its `retained` event rather than the empty owner prefix — they are
unrelated.

The prefix is the literal text before `{silo_uid}` in `KEK_TEMPLATE`, which is
why a generation marker belongs after it (`kms_{silo_uid}_v2`, never
`kms_v2_{silo_uid}`) — moving the prefix strands the previous generation as
unowned. See [Key rotation](key-rotation.md#the-naming-rule).

## Automatic key rotation

`KEK_ROTATION_PERIOD_DAYS` in `KEK_PROVISIONER_OPTIONS` puts an automatic rotation
schedule on every key the provisioner creates. One option, one unit, across
providers — each provisioner renders it in its provider's own terms:

| Provider | Floor | Ceiling | Written as |
|---|---|---|---|
| AWS KMS | 90 days | 2560 days | `EnableKeyRotation`'s `RotationPeriodInDays`, in days |
| GCP Cloud KMS | 1 day | — | the CryptoKey's `rotationPeriod`, in seconds, paired with `nextRotationTime` |
| Azure Key Vault | 7 days | — | a key rotation policy, `timeAfterCreate` as an ISO 8601 duration |
| IBM Key Protect | 30 days | 360 days | a key rotation policy, `interval_month` in whole months — so the value must also be a **multiple of 30** |
| HashiCorp Vault | 1 day | — | the key's `auto_rotate_period`, in seconds |
| OCI Vault | 60 days | 365 days | `CreateKey`'s `auto_key_rotation_details`, in days — but **only a virtual private vault runs the schedule**, and that path is untested here |
| others | — | — | not supported; the option is **refused at construction** |

Both bounds are refused at construction, so `manage.py check` reports them at
deploy. A dash means the ceiling has not been established for that provider —
*undeclared*, not *unlimited*: an over-large value there surfaces as the
provider's own rejection at key creation instead.

Days is the shared unit because it converts exactly to all of them. An ISO
duration in months or years could not become Cloud KMS seconds without assuming
a month length.

IBM is the one provider whose own unit is coarser than the option. Key Protect
defines a month as exactly 30 days for this purpose, so the conversion is exact —
but only for multiples of 30. A value in between is **refused, never rounded**:
rotating every 90 days because 100 was configured would give a deployment a
cryptoperiod nobody chose, and nothing would ever surface it. The error names the
two nearest legal values.

Azure, IBM and HashiCorp Vault all write the policy in a **second call** after key
creation. Azure and IBM have no choice — neither create call carries one — while
Vault is
written that way deliberately, so a deployment that can create keys but not write
their config gets a usable KEK plus one clear line saying rotation is not on it. A failure there is logged at WARNING and
does not fail the encrypt — the key exists and works, and breaking a tenant's
first save over a schedule would be the wrong trade. That warning is the only
signal, so do not filter it: a key silently left on manual rotation is the one
outcome nothing else detects.

OCI is the one provider where the option can be honorable or not depending on
something outside the key: automatic rotation runs only in a **virtual private
vault**, and a standard vault refuses the schedule. Refusing at construction
would mean reading a vault the provisioning identity is not entitled to read, so
the key is created without the schedule instead and one WARNING
WARNING says so. That is the deliberate exception to the rule below — everywhere
else, unhonorable means unhonorable for the *provider*, which is knowable at
deploy.

A provisioner that cannot set a schedule refuses the option rather than ignoring
it — the failure mode being avoided is a deployment that believes its keys rotate
when nothing ever scheduled them. Rotate at the provider instead, and run
[`reencrypt_keys`](management-commands.md) afterwards. A value outside the
provider's declared range is refused the same way, at `manage.py check` rather
than at the first encrypt.

**What rotation costs you afterwards differs by provider**, and it is worth
knowing before turning it on:

- **AWS and GCP**: nothing. Their ciphertext identifies the key material that
  produced it, so the provider resolves the right version and old DEKs keep
  decrypting untouched. Re-wrapping is optional housekeeping.
- **Azure**: each DEK row records the key version that wrapped it, because an AES
  ciphertext names nothing. Old rows stay readable, but the old version must stay
  enabled until `reencrypt_keys` has moved them over.
- **OCI**: nothing, for the same reason as AWS and GCP — the ciphertext carries
  the version and OCI resolves it. The version is still recorded on each row,
  because OCI bills per key version and can delete one on its own, which makes
  "is anything still wrapped under version 1?" a question worth being able to
  answer. `reencrypt_keys` is what empties an old version so it can go.

Rotation also has a price on some providers — Azure bills per scheduled rotation
— and setting the policy needs a permission beyond key creation (`keys/rotate`
on Azure, `kms:EnableKeyRotation` on AWS). On both, a schedule that cannot be
written is logged at WARNING and the key is still created
and used: the request is not failed over metadata, but the key will not rotate on
its own until the schedule is applied.

## Tagging provisioned keys

`TAGS` in `KEK_PROVISIONER_OPTIONS` is written verbatim onto every key the
provisioner creates. The package adds nothing of its own, removes nothing, and
reorders nothing, so what is set on a key is exactly what you configured. The
option has the same name on every provider; each maps it to that provider's own
field (AWS `Tags`, Azure `tags`, GCP `labels`, OCI `freeform_tags`).

Tags are written **at creation only**. `ensure_kek` returns early when the key
already exists, so changing `TAGS` later leaves existing keys as they were, and
nothing in the package reads tags back. Retagging is out of scope: use
`aws kms tag-resource`, `gcloud kms keys update --update-labels`,
`az keyvault key update`, or OCI's update-key, with the **Key Encryption Keys** changelist
as your inventory of what this deployment knows about.

Four provisioners can carry tags — AWS, GCP, Azure, and OCI. Fly, HashiCorp,
Infisical, and IBM take no metadata at key creation, and setting `TAGS` on one of
them raises `encryption_suite.W051` at `manage.py check`. That is a warning, not
an error: it will not stop a deploy.

### Per-tenant and derived values

A static dict cannot express a value that varies by tenant. Subclass the
provisioner and override `build_tags`:

```python
class TenantTaggedAwsProvisioner(AwsKekProvisioner):
    def build_tags(self, silo_uid):
        tags = super().build_tags(silo_uid)
        tags["cost-center"] = cost_center_for(silo_uid)
        return tags
```

Three hazards:

- Under `SharedKekStrategy` every silo resolves to one KEK and only the first
  silo to encrypt triggers creation, so a per-tenant value permanently labels
  that key with one arbitrary tenant. The same applies to `KEK_MAP` entries you
  have pointed at a shared key.
- `ensure_kek` runs on the first-encrypt path **inside a user request**. A
  synchronous call to an accounting API puts its latency and its outages in front
  of a tenant's first write. Cache it, or read a value already denormalized onto
  the tenant row.
- If the override raises, the engine funnel turns it into
  `KekNotProvisionedError` — a broken tag lookup becomes a failed encryption.
  **No tag beats no key.**

On GCP, values must satisfy the label charset (lowercase, `[a-z0-9_-]`, ≤63).
`TAGS` is passed through untouched so an invalid value is rejected by GCP with a
clear error rather than silently rewritten; for derived values,
`self._sanitize_label(value)` coerces them for you.

### Example: ownership (ABAC)

Tags become an ownership boundary the KMS itself enforces, rather than one this
package enforces in Python. Set the key names your organization mandates:

```python
"KEK_PROVISIONER_OPTIONS": {
    "AWS_REGION": "us-east-1",
    "TAGS": {"ManagedBy": "encryption-suite", "Deployment": "prod-eu"},
},
```

then deny destruction of anything lacking them — on AWS, a key policy or SCP
denying `kms:ScheduleKeyDeletion` unless
`aws:ResourceTag/ManagedBy = encryption-suite`.

**Sequence matters.** Tag every existing key *before* attaching the policy.
Attaching it first makes the untagged keys undeletable — this package's gates
pass, and the provider refuses. Recovering means editing the policy.

This does not change `owns_kek`, which stays name-prefix based: a tag check
there would refuse every key on a provider that cannot tag. Override it to also
require the tag if you want the package's own gate tightened, though the provider
policy is what actually enforces it.

**Azure does not participate.** Azure ABAC conditions cover Key Vault *secrets*
only — keys are not among the supported data actions — so no role assignment can
be conditioned on a key's tags. `TAGS` on Azure is inventory and cost metadata.
Restrict destruction there with vault-scoped RBAC (withhold `keys/delete`) and
purge protection. Note too that Key Vault holds tags per key *version*: a version
added by a rotation does not inherit them, and this package writes tags at
creation only.

**GCP does not participate.** IAM conditions match Resource Manager tags, which
attach to key *rings*, not keys — and this provisioner never creates a ring.
`TAGS` on GCP writes labels, which are for organization and billing export only.
Restrict destruction there with ring-scoped IAM plus the
`constraints/cloudkms.disableBeforeDestroy` and
`constraints/cloudkms.minimumDestroyScheduledDuration` org policies.

### Example: cost allocation

For values uniform across the deployment, static config is enough:

```python
"KEK_PROVISIONER_OPTIONS": {
    "AWS_REGION": "us-east-1",
    "TAGS": {"Environment": "production", "Product": "vault", "CostCenter": "cc-4471"},
},
```

Remember that a per-tenant cost tag makes N tenants into N dimensions in your
billing export, which is rarely what an accounting team wants — prefer bounded
values, and reach for a `build_tags` override only when chargeback genuinely
needs per-tenant granularity.

On OCI, cost-tracking tags are **defined** tags, so chargeback there uses
`DEFINED_TAGS` rather than `TAGS`:

```python
"KEK_PROVISIONER_OPTIONS": {
    "OCI_VAULT_MANAGEMENT_ENDPOINT": "https://...-management.kms.us-ashburn-1.oraclecloud.com",
    "OCI_COMPARTMENT_OCID": "ocid1.compartment.oc1..…",
    "TAGS": {"app": "encryption_suite"},
    "DEFINED_TAGS": {"Operations": {"CostCenter": "cc-4471"}},
},
```

`build_defined_tags` is the override seam for those, matching `build_tags`.

---

## Writing a custom provisioner

Subclass `AbstractKekProvisioner` and implement `ensure_kek`. The method
must be idempotent — it is called every time a new silo's DEK is
created, and may be called repeatedly for the same KEK if caches are
flushed or multiple processes race on first encrypt.

```python
from encryption_suite.adapters.keks import AbstractKekProvisioner


class AwsKekProvisioner(AbstractKekProvisioner):
    """Create one AWS KMS key per silo, with alias."""

    def __init__(self, options: dict) -> None:
        super().__init__(options)
        self._client = None
        self._ensured: set[str] = set()

    def _get_client(self):
        if self._client is None:
            import boto3
            self._client = boto3.client("kms", region_name=self.options["AWS_REGION"])
        return self._client

    def ensure_kek(self, kek_resource_name: str, silo_uid: str) -> None:
        if kek_resource_name in self._ensured:
            return

        client = self._get_client()
        alias = kek_resource_name  # "alias/encryption_suite-team-42"

        try:
            client.describe_key(KeyId=alias)
            self._ensured.add(kek_resource_name)
            return
        except client.exceptions.NotFoundException:
            pass

        response = client.create_key(
            KeySpec=self.options.get("KEY_SPEC", "SYMMETRIC_DEFAULT"),
            KeyUsage=self.options.get("KEY_USAGE", "ENCRYPT_DECRYPT"),
            Tags=[
                {"TagKey": k, "TagValue": v}
                for k, v in self.build_tags(silo_uid).items()
            ],
        )
        client.create_alias(
            AliasName=alias,
            TargetKeyId=response["KeyMetadata"]["KeyId"],
        )
        self._ensured.add(kek_resource_name)
```

Key points:

- **Idempotency.** Guard with a local set, a `describe_key` probe, or both.
  Under concurrent first-encrypts for the same silo, the library's
  per-silo lock serializes provisioning within a process, but
  multi-process deployments can still race — `ensure_kek` must tolerate
  "key already exists" errors from the KMS and treat them as success.
- **Separate credentials.** The provisioner is passed
  `KEK_PROVISIONER_OPTIONS`, not `OPTIONS`. This lets you point it at
  a different IAM role — typically one with `CreateKey` / `CreateAlias`
  permissions that the runtime role does not have.
- **No name derivation.** The KEK name is the responsibility of the
  strategy. The provisioner receives the already-resolved name and must
  use it verbatim. `silo_uid` is supplied only for tagging and
  logging.
- **Tagging.** Take the tags from `self.build_tags(silo_uid)` rather than reading
  `TAGS` directly, so operator pass-through and any `build_tags` override behave
  the same as they do on the shipped provisioners. Set
  `supports_tagging = True` on the class if your provider's create call carries
  them — the flag drives the startup check and the test console, and
  `build_tags` returns `{}` while it is `False`.

---

## Security and compliance implications

Application-driven provisioning requires the application's IAM role to
have elevated permissions:

| Provider | Additional permissions |
|---|---|
| AWS KMS | `kms:CreateKey`, `kms:CreateAlias`, `kms:TagResource` |
| GCP Cloud KMS | `cloudkms.cryptoKeys.create` on the key ring |
| Azure Key Vault | `keys/create` on the vault, plus `keys/list` and `keys/delete` for deletion and reconcile |
| HashiCorp Vault | `create` on the transit mount path |
| OCI Vault | `manage keys` in the compartment (the encrypt/decrypt path needs only `use keys`) |
| Fly.io KMS | none — every process inside the Fly machine can already create secretkeys via `/.fly/api`. The provisioner does not widen the blast radius beyond what mount-authenticated socket access already gives the application. |

Some organizations forbid application-created KEKs because the same
blast-radius-widening IAM change that lets the app create keys also lets a
compromised app create keys for any purpose, tag them freely, or exhaust
provider quotas. If that applies to your deployment, keep
`NullKekProvisioner` and rely on the clear `KekNotProvisionedError` path
plus provisioning outside this application.

BYOK strategies (where each tenant supplies their own KEK ARN) are
incompatible with real provisioners — you cannot create a key into someone
else's account. Leave `NullKekProvisioner` in place for BYOK deployments.

---

## Interaction with `KEY_AUTO_PROVISION`

These two settings handle different halves of the same problem:

- `KEY_AUTO_PROVISION` controls whether the **DEK** is created on demand
  (a row in `DataEncryptionKey`).
- `KEK_PROVISIONER_ADAPTER` controls whether the **KEK** is created on
  demand (a key resource on the KMS).

The typical combinations:

| `KEY_AUTO_PROVISION` | Provisioner | Behavior |
|---|---|---|
| `True` | `NullKekProvisioner` | DEK created on first encrypt. KEK must already exist on KMS; if not, `KekNotProvisionedError` is raised. |
| `True` | Real provisioner | Both DEK and KEK created on first encrypt. Zero operator setup per tenant. |
| `False` | `NullKekProvisioner` | Everything must be set up ahead of time via `setup_encryption_keys`. Strictest. |
| `False` | Real provisioner | Unusual. `setup_encryption_keys` will still invoke the provisioner, so KEKs get created at bulk-provisioning time. |

---

## Admin page: Reconcile Keys

django-encryption-suite ships an admin page listing every silo the configured
silo adapter can enumerate, the KEK resource name the application expects for
each, and whether that key and its data encryption keys exist yet. See
[Reconcile Keys page](admin-panel.md#reconcile-keys-page) for the full
description and the three ways to reach it.

It is the intended operator workflow for deployments that keep the default
`NullKekProvisioner`: a new tenant is created, an admin opens this page,
copies the resource name into the KMS console or IaC tool, creates the
KEK, and the next encryption succeeds (creating the DEK automatically
when `KEY_AUTO_PROVISION` is enabled).

## User-facing failures

When the KEK does not exist and cannot be created, the engine raises
`encryption_suite.exceptions.KekNotProvisionedError`, which subclasses
`ValueError` so that existing application code catching `ValueError` around
encrypt calls continues to work.

The exception message is translated via `gettext_lazy`:

> Encryption and decryption are unavailable for this data.

The package ships translations of this string in every locale it supports. See
[Internationalization](internationalization.md).

In parallel, an English-language `ERROR`-level log entry is emitted via
the `encryption_suite` logger. It names the missing KEK, the silo
UID, the strategy in use, and the provisioner in use, so an administrator
can diagnose and remediate without reading source.
