# KMS Adapters

The KMS adapter encrypts and decrypts the DEKs stored in
`DataEncryptionKey`. It is the only component in this package that
communicates with an external service.

Configure it in a named block of
[`KMS_KEY_STORES`](configuration.md#kms_key_stores), and name that block as the
`key_store` of the key sets in [`KEY_SETS`](configuration.md#key_sets) that make new silo keys:

```python
ENCRYPTION = {
    "KMS_KEY_STORES": {
        "main": {
            "ADAPTER": "path.to.KmsAdapter",
            "OPTIONS": { ... },
            "KEK_STRATEGY_ADAPTER": "...",
        },
    },
}
```

The snippets on this page show the `ADAPTER` and `OPTIONS` keys of one block.
You choose the block's name, and the package records it on every key row the
block creates, so never rename a block once rows use it. To move silo keys to
another block and retire the old one, see
[Moving to another KMS](key-rotation.md#moving-to-another-kms). The *provider ID*
in the table below names the adapter class, not your block.

## Per-silo KEK

Each silo (team) gets its own master encryption key (KEK) in the KMS.
One of two keys in the block's `OPTIONS` configures it:

- **`KEK_TEMPLATE`** — a format string with a `{silo_uid}` placeholder.
  Best for KMS providers that use human-readable key names (AWS aliases, HashiCorp Vault
  transit keys, Azure key names, GCP key names).

  ```python
  "KEK_TEMPLATE": "alias/encryption_suite-{silo_uid}",
  # silo_uid "team-42" → "alias/encryption_suite-team-42"
  ```

  A prefix or suffix around `{silo_uid}` is **optional** — the only
  hard requirement is that the placeholder appears. `"{silo_uid}"`
  alone is valid and names the key after the (sanitized) UID. A prefix such
  as `encryption_suite-` is still recommended so the package's keys are
  distinguishable from other keys in a shared vault, key ring, or namespace.

  > **Do not omit the placeholder.** A template with no `{silo_uid}`
  > (e.g. `"encryption_suite-shared"`) formats to the same literal string for
  > every silo, silently collapsing per-silo isolation into a
  > de-facto shared KEK — without the safeguards of `SharedKekStrategy`.
  > The library does not reject this. If you want one shared KEK, use
  > `SharedKekStrategy` with `SHARED_KEK_ID` instead.

  Some providers constrain the template's shape: AWS KMS aliases must begin
  with `alias/`; Fly secretkey names allow
  only `[A-Za-z0-9_]` (no hyphen). The provider's getting-started guide notes
  any such rule.

- **`KEK_MAP`** — an explicit dict mapping `silo_uid` to provider-specific
  key identifiers.  Best for UUID-based providers (OCI OCIDs, Infisical UUIDs,
  IBM key UUIDs) or when you need full control.

  ```python
  "KEK_MAP": {
      "team-1": "ocid1.key.oc1.iad.aaaaaa",
      "team-2": "ocid1.key.oc1.iad.bbbbbb",
  },
  ```

Resolution order: `KEK_MAP` is checked first (exact match on `silo_uid`),
then `KEK_TEMPLATE`.  If neither is configured, `EncryptionConfigurationError`
is raised.

UIDs are sanitized for template use via a bijective UTF-8 hex encoding:
each character outside the provider's charset becomes the escape char plus
two hex digits per UTF-8 byte. A normal UID like `"team-42"` fits the default
charset (`[A-Za-z0-9_-]`) and passes through unchanged. Charsets differ by
provider: Azure forbids `_` and uses `-` as its escape char, so a separator
hyphen is doubled (`"team-42"` → `"team--42"`); Fly forbids `-`, so the hyphen
is hex-escaped (`"team-42"` → `"team_2d42"`). The encoding is reversible, so
distinct UIDs never collide. `KEK_MAP` keys are used as-is without sanitization.

---

## Quick reference

### Adapters

| Provider | Class | Provider ID | Extra | Extra deps |
|----------|-------|-------------|-------|------------|
| GCP Cloud KMS | `GcpKmsAdapter` | `"gcp"` | `[gcp]` | `google-auth>=2.0` |
| GCP Cloud KMS (Tink) | `GcpTinkKmsAdapter` | `"gcp-tink"` | `[gcp-tink]` | `tink>=1.10.0`, `google-auth>=2.0`, `google-cloud-kms>=2.0` |
| AWS KMS | `AwsKmsAdapter` | `"aws"` | `[aws]` | `boto3>=1.26` |
| AWS KMS (Tink) | `AwsTinkKmsAdapter` | `"aws-tink"` | `[aws-tink]` | `tink>=1.10.0`, `boto3>=1.26` |
| Azure Key Vault | `AzureKeyVaultAdapter` | `"azure"` | `[azure]` | `azure-identity>=1.12`, `azure-keyvault-keys>=4.8` |
| HashiCorp Vault | `HashiCorpVaultAdapter` | `"hashicorp"` | `[hashicorp]` | none |
| IBM Key Protect / HPCS | `IbmKmsAdapter` | `"ibm"` | `[ibm]` (only for the `container` and `vpc_instance` strategies) | `ibm-cloud-sdk-core>=3.20` |
| Oracle OCI Vault | `OCIVaultAdapter` | `"oci"` | `[oci]` | `oci>=2.0` |
| Infisical | `InfisicalKmsAdapter` | `"infisical"` | `[infisical]` | none |
| Fly.io KMS (secretkeys) | `FlyKmsAdapter` | `"fly"` | — | none |
| System (built in) | `EnvKeyStoreAdapter` | `"system"` | — | none |

### Provisioner tagging support

This column shows whether the matching KEK provisioner can carry `TAGS` onto keys it
creates — that is, whether the provider's create-key call accepts metadata at all. Setting
`TAGS` where it is not supported warns as `encryption_suite.W051` at
`manage.py check` and the tags are not written. See
[KEK provisioning](kek-provisioning.md#tagging-provisioned-keys).

| Provisioner | Tags | Written to |
|---|---|---|
| `AwsKekProvisioner` | yes | `Tags` on `CreateKey` |
| `GcpKekProvisioner` | yes | CryptoKey `labels` (GCP labels, *not* Resource Manager tags) |
| `AzureKekProvisioner` | yes | key `tags` (held per key *version*, so a rotation produces an untagged version) |
| `OciKekProvisioner` | yes | `freeform_tags`, plus `DEFINED_TAGS` → `defined_tags` |
| `FlyKmsKekProvisioner` | no | secretkeys carry no metadata |
| `HashiCorpVaultKekProvisioner` | no | transit key creation takes no metadata |
| `IbmKekProvisioner` | no | — (a key cannot be tagged; the *instance* can, outside this package) |
| `InfisicalKekProvisioner` | no | — |

### Provisioner deletion, enumeration and state-check support

These columns show whether the matching KEK provisioner can **delete** a key it provisioned (the
deletion half of the key lifecycle), **list** this deployment's keys on the
provider (the KMS half of [Reconcile Keys](admin-panel.md#reconcile-keys-page)),
and **read one key's lifecycle state** there. Where a column says no, the
provisioner inherits the base default and the operation degrades safely — a
deletion *retains* the key and records why, reconcile reports
*detection-unavailable* rather than treating every silo as orphaned, and a state
probe returns *unknown* rather than failing the page it annotates.

| Provisioner | Delete | Enumerate | State check |
|---|---|---|---|
| `FlyKmsKekProvisioner` | yes — immediate, no recovery window | yes — `GET /secretkeys` | no — with no deletion window a key either lists or is gone |
| `AwsKekProvisioner` | yes — `ScheduleKeyDeletion`, 7-30 day window | yes — `ListAliases` (alias-form names only) | yes — `DescribeKey`'s `KeyState` |
| `GcpKekProvisioner` | yes — destroys every CryptoKey version, 24-hour minimum window | yes — `cryptoKeys.list` on the configured ring | yes — the primary version's `state` |
| `AzureKekProvisioner` | yes — soft delete, recoverable until the vault purges it | yes — `list_properties_of_keys` plus `list_deleted_keys` | yes — `get_key`, falling back to the deleted-key read |
| `OciKekProvisioner` | yes — `ScheduleKeyDeletion`, 7-30 day window | yes — `ListKeys` on the configured compartment | yes — the key's `lifecycle_state` |
| `InfisicalKekProvisioner` | yes — immediate, no recovery window | yes — `GET /kms/keys` on the configured project | no — with no deletion window a key either lists or is gone |
| `IbmKekProvisioner` | yes — soft delete, restorable for a fixed 30 days | yes — `GET /api/v2/keys` on the configured instance | yes — the live listing, then the `deleted` flag |
| `HashiCorpVaultKekProvisioner` | yes — immediate, no recovery window; **off unless `ALWAYS_ALLOW_KEY_DELETION`** | yes — `LIST /transit/keys` on the configured mount | no — with no deletion window a key either lists or is gone |

Both tables list provisioners, so the env key store appears in neither: it has no
provisioner at all. Its key encryption key is a settings value, with no provider
holding it — nothing to create, delete or list — which is why a deletion there
always refuses at a gate and records why. See [Env key store](#env-key-store).

A state check only earns its round trip where the provider has a deletion
window, which is why the three immediate-deletion providers do not implement
one: there is no state between *live* and *gone* for it to report. Reconcile
calls it for keys it would otherwise report as orphaned, so that a key already
being deleted is not presented as awaiting a decision.

Azure needs both listing calls because a soft-deleted key leaves the live
listing while it is still recoverable — the deletion has not finished, so the key
has to keep being reported until the vault purges it.

IBM is the mirror image: a deleted Key Protect key *stays* in the one listing,
flagged `deleted`, so the provisioner filters it out. The key stops wrapping the
moment it is deleted, and a name whose key can no longer wrap is a name reconcile
must report as gone.

GCP is the exception to what *deleted* means. Cloud KMS cannot remove a CryptoKey
or a key ring, so deletion destroys the key's versions — where the material is held
— and enumeration reports a key with no surviving version as gone even though the
empty shell is still listed by `gcloud`. See
[Deleting a key encryption key](getting-started-gcp.md#deleting-a-key-encryption-key).

### Credential strategies

| Strategy | Provider | Use case |
|----------|----------|----------|
| `iam_role` | AWS | boto3's default credential chain — attached IAM role (EC2 / ECS / Lambda) or static `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` in the process environment (incl. non-AWS hosts) |
| `oidc` | AWS, GCP, Azure, HashiCorp Vault, Infisical | Keyless auth via OIDC JWT from a configurable token source (Fly.io, file-based, GCP metadata, Vercel, SPIFFE). Requires `OIDC_SOURCE`. |
| `adc` | GCP | GCP-hosted (Cloud Run, GKE, GCE) or local `gcloud auth` |
| `service_account_key` | GCP | Explicit service account JSON key file |
| `managed_identity` | Azure | Azure-hosted with a managed identity assigned |
| `client_secret` | Azure | Explicit Azure AD app credentials |
| `token` | HashiCorp Vault | Static Vault token |
| `approle` | HashiCorp Vault | AppRole auth — `role_id` + `secret_id` exchanged for a short-lived client token |
| `iam_aws` | HashiCorp Vault | AWS IAM authentication |
| `api_key` | IBM | API key / access key exchange for a short-lived token |
| `api_key` | OCI | OCI config file, or inline signing key in options (off-OCI hosts) |
| `instance_principal` | OCI | OCI Compute instance metadata service |
| `resource_principal` | OCI | OCI Functions and Container Instances |
| `oke_workload_identity` | OCI | OKE (Kubernetes) pod service-account token |
| `universal_auth` | Infisical | Machine Identity client ID + secret |
| `token` | Infisical | Static Infisical access token |
| — | GCP (Tink) | Tink's client always uses Application Default Credentials, so the adapter takes no strategy setting and must run on GCP. For keyless auth off GCP, use `GcpKmsAdapter` with `oidc`. |
| — | AWS (Tink) | Tink's client always uses boto3's default credential chain, which finds an attached IAM role or static keys in the process environment, so the adapter takes no strategy setting. For keyless auth off AWS, use `AwsKmsAdapter` with `oidc`. |
| — | Fly.io | The adapter holds no credential. The machine-local `/.fly/api` socket authenticates by mount, so only stopping the machine revokes access. |
| — | System | The adapter holds no credential. The key encryption key is a settings value that the process holds. |

### Authentication retry and circuit breaker

Most KMS adapters (AWS KMS, GCP Cloud KMS, HashiCorp Vault, IBM Key Protect,
Infisical) retry once on authentication errors (401 or 403).  The retry flow
is:

1. The original request fails with an auth error.
2. The credential strategy is invalidated (cached token cleared).
3. A fresh token is obtained and the request is retried.

If the retry with fresh credentials **also** fails, the adapter enters a
**cooldown period** during which auth-error retries are skipped entirely —
the original error is raised immediately.  This prevents hammering the KMS
with requests that will keep failing, which could lead to rate-limiting or
account lockout.

The cooldown is controlled by the `AUTH_RETRY_COOLDOWN` class attribute on
`AbstractKmsAdapter`, defaulting to **30 seconds**.  A successful request
at any point clears the cooldown.

To override the cooldown for a specific adapter:

```python
from encryption_suite.adapters.key_stores.hashicorp import HashiCorpVaultAdapter

class MyHashiCorpVaultAdapter(HashiCorpVaultAdapter):
    AUTH_RETRY_COOLDOWN = 60  # 60-second cooldown instead of 30
```

---

## Key versions on the row

Where the provider reports one, the version that wrapped a data encryption key is
stored on its row as `kek_key_version`, alongside — never inside — the key's name.
The key encryption key row stays one-per-key, because a version is neither
deletable, listable, nor ownable on its own.

| Adapter | `kek_key_version` | Why |
|---|---|---|
| Azure Key Vault | recorded, **load-bearing** | An AES ciphertext names no version, and Key Vault addresses every operation by version. Without the row the value cannot be unwrapped after a rotation |
| GCP Cloud KMS | recorded, informational | The ciphertext carries its own version and symmetric decrypt takes the key path, so unwrapping never needs it |
| GCP Cloud KMS (Tink) | empty | Tink's primitive returns ciphertext alone; the version in the API response is not surfaced |
| IBM Key Protect / HPCS | recorded, informational | The wrap response names the version it used, so it costs nothing. Unwrapping resolves the version from the ciphertext |
| OCI Vault | recorded, informational | Read from the key's current version; unwrapping resolves its own |
| Infisical | recorded, informational | Read from the key lookup; unwrapping resolves its own |
| HashiCorp Vault | recorded, informational | The ciphertext names its own version in its `vault:v3:` prefix, so it costs nothing and unwrapping needs no help |
| AWS KMS, Fly.io, others | empty | No per-version identity is exposed. AWS rotation replaces the material behind one key id |

Recording it where it is merely informational buys two things:

- **You can tell what a version still holds.** "Is anything still wrapped under
  version 3?" is a query, answerable before you disable or destroy that version.
  Without it the only way to find out is to unwrap every row.
- **`reencrypt_keys` skips rows already on the current version**, so a run costs
  KMS round trips only for rows that need moving. An empty value always
  re-wraps — safe, only wasteful.

Answering "which version is current?" costs one lookup, cached for
`KEY_VERSION_TTL_SECONDS` (default 300) so re-encrypting a whole deployment does
not pay for it per row. Rows written before an adapter gained version recording
carry an empty value and pick one up the first time they are re-wrapped.

---

## GCP Cloud KMS

**Path:** `encryption_suite.adapters.key_stores.gcp.GcpKmsAdapter`

**Extra:** `pip install 'django-encryption-suite[gcp]'`

```python
"ADAPTER": "encryption_suite.adapters.key_stores.gcp.GcpKmsAdapter",
"OPTIONS": {
    "GCP_PROJECT_ID":   "my-project",
    "GCP_KMS_LOCATION": "global",       # or "us-central1", etc.
    "GCP_KMS_KEY_RING": "my-key-ring",
    "KEK_TEMPLATE":     "encryption_suite-{silo_uid}",  # key name within the ring
    # Optional:
    "CREDENTIAL_STRATEGY": "adc",       # see below
    "KEY_VERSION_TTL_SECONDS": 300,     # how often the key's primary version is re-read
},
```

The adapter records which key version wrapped each data encryption key — see
[Key versions on the row](#key-versions-on-the-row).

### Credential strategies

| Strategy | Value | When to use |
|---|---|---|
| Application Default Credentials (default) | `"adc"` *(or omit)* | GCP-hosted (Cloud Run, GKE, GCE) or local `gcloud auth` |
| Service account key | `"service_account_key"` | Explicit service-account key; requires `SERVICE_ACCOUNT_KEY_FILE` or `SERVICE_ACCOUNT_KEY_JSON` |
| OIDC (Workload Identity Federation) | `"oidc"` | Keyless auth from outside GCP (Fly.io, etc.) using an OIDC JWT exchanged for a federated GCP token. Requires `OIDC_SOURCE`. |

**`service_account_key` additional options:**

```python
"SERVICE_ACCOUNT_KEY_FILE": "/path/to/key.json",
# or the key's JSON content itself:
# "SERVICE_ACCOUNT_KEY_JSON": "{...}",
```

`SERVICE_ACCOUNT_KEY_JSON` takes precedence when both are set.

**`oidc` additional options:**

```python
"GCP_PROJECT_NUMBER":                "123456789012",
"GCP_WORKLOAD_IDENTITY_POOL_ID":     "my-pool",
"GCP_WORKLOAD_IDENTITY_PROVIDER_ID": "my-provider",
"GCP_SERVICE_ACCOUNT_EMAIL":         "kms-user@my-project.iam.gserviceaccount.com",
"OIDC_SOURCE":                       "<source>",   # required — which token source
"OIDC_SOURCE_OPTIONS":               {},      # optional, source-specific
```

See [OIDC token sources](#oidc-token-sources) below for the list of
supported sources and their options.

---

## GCP Cloud KMS (Tink)

**Path:** `encryption_suite.adapters.key_stores.gcp_tink.GcpTinkKmsAdapter`

**Extra:** `pip install 'django-encryption-suite[gcp-tink]'`

Alternative to `GcpKmsAdapter` that delegates all crypto and authentication to
Tink's built-in `gcpkms` integration.  No credential strategies to configure —
Tink always uses [Application Default Credentials](https://cloud.google.com/docs/authentication/application-default-credentials).
Run it on GCP (Cloud Run, GKE, GCE), where ADC resolves to the host's
metadata-server credentials with no auth setup.

```python
"ADAPTER": "encryption_suite.adapters.key_stores.gcp_tink.GcpTinkKmsAdapter",
"OPTIONS": {
    "GCP_PROJECT_ID":   "my-project",
    "GCP_KMS_LOCATION": "global",
    "GCP_KMS_KEY_RING": "my-key-ring",
    "KEK_TEMPLATE":     "encryption_suite-{silo_uid}",
},
```

> **When to use this vs `GcpKmsAdapter`:**  Reach for `GcpTinkKmsAdapter` only
> when you deploy on GCP itself (so ADC is keyless automatically) **and** you
> have a business reason for Tink — e.g. Tink is your organization's crypto
> standard, or you want Tink's ciphertext envelope on the wire.  Otherwise use
> `GcpKmsAdapter`, which also covers off-GCP keyless OIDC (e.g. Fly.io),
> explicit service-account keys, and other credential strategies.

**One divergence from `GcpKmsAdapter`: no key version is recorded.** Cloud KMS
names the version it used in its encrypt response, and `GcpKmsAdapter` stores it
on the row (see [Key versions on the row](#key-versions-on-the-row)). Tink's
primitive returns ciphertext alone, so that field stays empty here. Nothing
breaks — decryption never needed it — but two things are unavailable: you cannot
tell from the database which rows still sit on an old key version, and
`reencrypt_keys` re-wraps every row rather than skipping the current ones.

---

## AWS KMS

**Path:** `encryption_suite.adapters.key_stores.aws.AwsKmsAdapter`

**Extra:** `pip install 'django-encryption-suite[aws]'`

```python
"ADAPTER": "encryption_suite.adapters.key_stores.aws.AwsKmsAdapter",
"OPTIONS": {
    "AWS_REGION":    "us-east-1",
    "KEK_TEMPLATE":  "alias/encryption_suite-{silo_uid}",
    # Optional:
    "CREDENTIAL_STRATEGY": "iam_role",  # see below
},
```

### Credential strategies

| Strategy | Value | When to use |
|---|---|---|
| Default chain (default) | `"iam_role"` | boto3's default credential chain finds an attached IAM role (EC2, ECS, Lambda), **or** static `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` in the process environment, including on a host outside AWS. |
| OIDC (AssumeRoleWithWebIdentity) | `"oidc"` | STS exchanges an OIDC JWT for temporary credentials, for keyless auth from outside AWS. It requires `OIDC_SOURCE`. |

> **Static access keys?** There is no separate strategy for them. Set
> `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` (and optionally
> `AWS_SESSION_TOKEN`) as environment variables and keep the default
> `iam_role` strategy — boto3's default chain picks them up.
>
> **Prefer `iam_role` (with a real role) or `oidc` in production.** Both
> use short-lived, automatically rotated credentials. Static long-lived
> access keys are a weaker posture: they don't rotate on their own and
> are held in process memory for the lifetime of the process.

**`oidc` additional options:**

```python
"AWS_ROLE_ARN":          "arn:aws:iam::123456789012:role/my-role",
"AWS_ROLE_SESSION_NAME": "django-encryption-suite",   # optional
"AWS_OIDC_AUDIENCE":     "amazonaws.com",        # optional
"OIDC_SOURCE":           "<source>",             # required — which token source
"OIDC_SOURCE_OPTIONS":   {},                     # optional, source-specific
```

The adapter refreshes expired STS sessions on its own. See
[OIDC token sources](#oidc-token-sources) below for the supported sources and
their options. The `AWS_ROLE_ARN` role needs a trust policy that federates the
token source's issuer; [Getting started with AWS KMS](getting-started-aws.md#oidc-example)
gives the policy, the subject binding and the debugging steps.

---

## AWS KMS (Tink)

**Path:** `encryption_suite.adapters.key_stores.aws_tink.AwsTinkKmsAdapter`

**Extra:** `pip install 'django-encryption-suite[aws-tink]'`

Alternative to `AwsKmsAdapter` that delegates all crypto and authentication to
Tink's built-in `awskms` integration.  No credential strategies to configure —
Tink uses the default boto3 credential chain (environment variables, IAM role,
instance profile, etc.).

```python
"ADAPTER": "encryption_suite.adapters.key_stores.aws_tink.AwsTinkKmsAdapter",
"OPTIONS": {
    "AWS_REGION":   "us-east-1",
    "KEK_TEMPLATE": "alias/encryption_suite-{silo_uid}",
},
```

> **When to use this vs `AwsKmsAdapter`:**  Use `AwsTinkKmsAdapter` when the
> default boto3 credential chain is sufficient (most AWS-hosted deployments).
> Use `AwsKmsAdapter` when you need OIDC (e.g. Fly.io keyless) or other
> explicit credential strategies.

---

## Azure Key Vault

**Path:** `encryption_suite.adapters.key_stores.azure.AzureKeyVaultAdapter`

**Extra:** `pip install 'django-encryption-suite[azure]'`

Uses AES-256-GCM via Azure Key Vault Keys to encrypt keysets.

```python
"ADAPTER": "encryption_suite.adapters.key_stores.azure.AzureKeyVaultAdapter",
"OPTIONS": {
    "AZURE_VAULT_ENDPOINT": "https://my-vault.vault.azure.net",
    "KEK_TEMPLATE":        "encryption_suite-{silo_uid}",  # key name in the vault
    # Optional:
    "CREDENTIAL_STRATEGY": "managed_identity",  # see below
    "AZURE_KEY_VERSION":   "abc123...",   # pin wrapping to one key version
    "KEY_VERSION_TTL_SECONDS": 300,       # how often the current version is re-read
},
```

> **Premium vault required, and the key type is a Microsoft preview feature.**
> The keys are `oct-HSM` (symmetric AES), which Standard vaults do not offer.
> Microsoft ships symmetric keys in vaults as a public preview: no SLA, and not
> recommended by Microsoft for production workloads. Weigh that before choosing
> this adapter.

**Why symmetric.** AES-GCM is the only Key Vault algorithm that accepts
associated data, so it is what lets a wrapped DEK be bound to its silo — the same
binding AWS gets from `EncryptionContext` and GCP from
`additionalAuthenticatedData`. RSA-OAEP has no such parameter, which would leave
`SharedKekStrategy` with no per-tenant boundary at all. AES-KW would also work
for wrapping but takes no AAD either, so AES-GCM is used through
encrypt/decrypt rather than the semantically tidier `wrapKey`.

**Stored blob layout.** Key Vault returns the `iv` and authentication `tag`
alongside the ciphertext and needs all three back, so the adapter packs them into
the one stored value: a format byte, then length-prefixed `iv` and `tag`, then
the ciphertext. This is a permanent property of the stored data — a deployment
cannot change wrapping algorithm under existing rows.

**Rotation is supported**, and needs no re-wrapping to keep old data readable.
Key Vault addresses every cryptographic operation by key *version*, and an AES
ciphertext carries no pointer back to the version that produced it — unlike an
AWS or GCP ciphertext, which the provider resolves itself. So each DEK row
records the versioned key URI that wrapped it (the form
[Microsoft asks applications to store](https://learn.microsoft.com/azure/key-vault/keys/how-to-configure-key-rotation)),
and unwrapping uses it. Adding a version — `az keyvault key rotate`, or a
rotation policy — leaves existing DEKs readable; new wraps use the new version,
and [`reencrypt_keys`](management-commands.md) moves the old ones over so the
previous version can be disabled.

The *key encryption key* is recorded as `keys/<name>` — vault-relative and
version-free — wherever the lifecycle acts on it (deletion, enumeration,
ownership), because a version cannot be deleted, listed, or owned on its own.
The vault comes from `AZURE_VAULT_ENDPOINT`, the way an AWS alias leaves the
account and region to configuration.

`KEY_VERSION_TTL_SECONDS` (default 300) is how long a process reuses the current
version before looking it up again. Without a refresh, a long-running worker
would keep wrapping under the version it first saw and a rotation would stay
half-applied with nothing to show it. `AZURE_KEY_VERSION` pins the wrapping
version outright and skips the lookup.

### Credential strategies

| Strategy | Value | When to use |
|---|---|---|
| Managed Identity (default) | `"managed_identity"` | Azure-hosted with a managed identity assigned |
| Client secret | `"client_secret"` | Explicit Azure AD app credentials |
| OIDC (Workload Identity Federation) | `"oidc"` | Keyless auth from outside Azure (Fly.io, GCP, Vercel, ...) using an OIDC JWT exchanged for an AAD token via federated credentials. Requires `OIDC_SOURCE`. |

**`client_secret` additional options:**

```python
"AZURE_TENANT_ID":     "your-tenant-id",
"AZURE_CLIENT_ID":     "your-client-id",
"AZURE_CLIENT_SECRET": "your-client-secret",
```

**`oidc` additional options:**

```python
"AZURE_TENANT_ID":     "your-tenant-id",
"AZURE_CLIENT_ID":     "your-client-id",
"AZURE_OIDC_AUDIENCE": "api://AzureADTokenExchange",   # optional; AAD default
"OIDC_SOURCE":         "<source>", # required — which token source
"OIDC_SOURCE_OPTIONS": {},         # optional, source-specific
```

The Azure AD app registration must have a [federated identity credential](https://learn.microsoft.com/azure/active-directory/workload-identities/workload-identity-federation)
configured that trusts the issuer/subject/audience of the JWT produced by
the chosen source. See [OIDC token sources](#oidc-token-sources) for the
list of supported sources.

> **One federated credential per subject.** An Azure federated identity
> credential (FIC) matches the token's **exact** `sub`, and Azure rejects
> wildcard or expression matching for issuers outside Microsoft
> (`InvalidFederatedIdentityCredentialValue: Expression is not supported …`).
> An issuer that gives every instance the same `sub` needs one FIC for the
> whole workload. An issuer that puts the instance in `sub`, such as Fly.io
> (`<org>:<app>:<machine-name>`), needs one FIC per instance. Azure caps an
> app at 20 FICs, and each new instance fails to authenticate until someone
> adds its FIC. For those issuers, use `client_secret` off Azure and
> `managed_identity` on Azure compute. Infisical, by contrast, accepts a glob
> subject such as `<org>:<app>:*` (see the Infisical
> [subject binding](#infisical) below).

---

## HashiCorp Vault

**Path:** `encryption_suite.adapters.key_stores.hashicorp.HashiCorpVaultAdapter`

**Extra:** none — uses `urllib` from the standard library only

Uses HashiCorp Vault's [transit secrets engine](https://developer.hashicorp.com/vault/docs/secrets/transit)
to encrypt and decrypt key material.

```python
"ADAPTER": "encryption_suite.adapters.key_stores.hashicorp.HashiCorpVaultAdapter",
"OPTIONS": {
    "VAULT_ENDPOINT":         "https://vault.example.com:8200",
    "KEK_TEMPLATE":       "encryption_suite-{silo_uid}",  # transit key name
    "VAULT_NAMESPACE":    "my-namespace",   # optional — HCP Vault or Enterprise
    "VAULT_MOUNT_PATH":   "transit",        # optional — transit mount, default "transit"
    # Optional:
    "CREDENTIAL_STRATEGY": "token",         # see below
},
```

### Credential strategies

| Strategy | Value | When to use |
|---|---|---|
| Static token (default) | `"token"` | Simple setups; token from `OPTIONS` or `VAULT_TOKEN` env var |
| AppRole | `"approle"` | Workloads without native cloud identity (Fly.io, generic VMs, on-prem). Provision `role_id` + `secret_id` in HashiCorp Vault, exchange for short-lived client tokens at runtime. |
| AWS IAM auth | `"iam_aws"` | Apps running on AWS that authenticate to HashiCorp Vault via IAM |
| JWT / OIDC auth | `"oidc"` | Keyless auth using an OIDC JWT against HashiCorp Vault's [JWT auth method](https://developer.hashicorp.com/vault/docs/auth/jwt). Requires `OIDC_SOURCE`. |

**`token` additional options:**

```python
"VAULT_TOKEN": "hvs.your-vault-token",
# Or omit and set the VAULT_TOKEN environment variable
```

**`approle` additional options:**

```python
"VAULT_ROLE_ID":        "role-uuid",            # required
"VAULT_SECRET_ID":      "secret-uuid",          # required (or use *_FILE)
"VAULT_SECRET_ID_FILE": "/run/secrets/sid",     # alternative — path to file
"VAULT_APPROLE_MOUNT":  "approle",              # optional, default "approle"
```

Either `VAULT_SECRET_ID` or `VAULT_SECRET_ID_FILE` is required. Both
fall back to the `VAULT_SECRET_ID` / `VAULT_SECRET_ID_FILE` environment
variables when absent from `OPTIONS`. The file form is useful when
the secret_id is delivered via a mounted secret rather than an env var.

**`iam_aws` additional options:**

```python
"AWS_IAM_VAULT_ROLE": "my-vault-role",   # optional, default: "default"
```

**`oidc` additional options:**

```python
"VAULT_JWT_ROLE":      "my-vault-jwt-role",   # required
"VAULT_JWT_MOUNT":     "jwt",                 # optional, default "jwt"
"VAULT_JWT_AUDIENCE":  "vault",               # optional, defaults to VAULT_JWT_ROLE
"OIDC_SOURCE":         "<source>",            # required — which token source
"OIDC_SOURCE_OPTIONS": {},                    # optional, source-specific
```

The HashiCorp Vault JWT auth method must be enabled and configured with a role bound
to the issuer/audience of the JWT produced by the chosen source. See
[OIDC token sources](#oidc-token-sources) for the list of supported sources.

The adapter automatically re-authenticates on 403 responses — token expiry
is handled transparently for the `approle`, `iam_aws`, and `oidc` strategies.

### Recorded name

Rows carry the **bare transit key name** — the value `KEK_TEMPLATE` renders, the
name the provisioner lists, and the string the owner prefix is a prefix of. The
mount and cluster address are request coordinates, not part of the name: folding
them in would pin every stored row to an address that can change without the key
changing, and would leave the ownership gate comparing a bare prefix against
qualified values, matching nothing.

Rows written by earlier versions carry a `{addr}/{mount}/{name}` URL. Those keep
decrypting — the adapter reduces that form to the name it ends with — and pick up
the bare form the next time they are re-wrapped.

### Key versions

HashiCorp Vault versions each transit key: a rotation adds a version and keeps the previous ones
available for decryption. Every ciphertext names the version that produced it in
its own prefix (`vault:v3:…`), so `kek_key_version` is recorded from the wrap
result at no extra cost, and decryption never needs it — the transit engine reads
the version out of the ciphertext.

`current_kek_version()` reads `latest_version` from the key's metadata, cached for
`KEY_VERSION_TTL_SECONDS` (default 300). That is what lets `reencrypt_keys` skip
rows already on the current version.

---

## Env key store

**Path:** `encryption_suite.adapters.key_stores.environment.EnvKeyStoreAdapter`

An env key store is key material your settings supply to the process. The package
builds one adapter per [`ENV_KEY_STORES`](configuration.md#env_key_stores) entry, so
it takes no `KMS_KEY_STORES` block, and a key set reaches it by an entry of
[`KEY_SETS`](configuration.md#key_sets) that names it
(`"system": {"key_store": "login"}`).

It wraps DEKs with AES-256-GCM under that material, through the `cryptography`
library directly, whatever `CRYPTO_BACKEND` says. It makes no remote call, and
it adds no protection beyond the secrecy of the material and wherever you keep
it: no provider-side access policy, no audit log, no HSM. A key committed to the
repository protects nothing.

```python
"ENV_KEY_STORES": {"login": {"KEKS": {1: env("ENC_LOGIN_KEK")}}},  # openssl rand -base64 32
```

Every silo under the store shares one key encryption key, `shared` unless the
entry's `SHARED_KEK_ID` says otherwise, so the KEK layer isolates no silo from
another: deleting one silo's data key affects only that silo, and scheduling the
key encryption key affects every silo wrapped under it. That suits development, a
deployment that only uses the system-wide silo, and a deployment that accepts
the tradeoff; a HashiCorp Vault dev server gives development per-silo keys instead.

**Versions.** `KEKS` maps positive integer versions to key material. The
highest version wraps new keys, and each row records the version that wrapped it
in `kek_key_version`. To rotate, add the next version, deploy, and run
`reencrypt_keys`, which moves every row onto the highest version. Then drop the
old one. A row that records a dropped version fails to unwrap with
`kek_not_provisioned`, and `crypto_inventory` reports it.

This store has no KEK provisioner and nothing ever deletes its key, so the key
lifecycle (deletion, KMS-side reconcile) stays inert here. Exercise it against a
real provider.

There is no ephemeral key. An empty or missing `KEKS` fails `manage.py check`
(`E039`) and raises a typed `EncryptionConfigurationError` at first use, so a
missing variable can never silently produce a new key that orphans what was
written under the old one.

---

## IBM Key Protect / HPCS

**Path:** `encryption_suite.adapters.key_stores.ibm.IbmKmsAdapter`

**Extra:** none for `api_key` / `iam_assume` (they use the `urllib` standard
library). The compute-native `container` / `vpc_instance` strategies need
`pip install 'django-encryption-suite[ibm]'` (pulls in `ibm-cloud-sdk-core`).

Supports both [IBM Key Protect](https://cloud.ibm.com/docs/key-protect) and
[IBM Hyper Protect Crypto Services (HPCS)](https://cloud.ibm.com/docs/hs-crypto).
The encrypt/decrypt REST API is identical between the two services; only the base
endpoint URL differs.

- **Key Protect** endpoints are derived automatically from `IBM_REGION`.
- **HPCS** uses an instance-specific crypto endpoint — set `IBM_ENDPOINT` directly.

HPCS is backed by FIPS 140-2 Level 4 HSMs, the highest commercially available
assurance level.

```python
"ADAPTER": "encryption_suite.adapters.key_stores.ibm.IbmKmsAdapter",
"OPTIONS": {
    "IBM_INSTANCE_ID": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",  # service instance GUID
    "KEK_TEMPLATE":       "encryption_suite-{silo_uid}",           # root key UUID or alias
    # Or use KEK_MAP for explicit UUID mapping:
    # "KEK_MAP": {"team-1": "uuid-1", "team-2": "uuid-2"},
    # Key Protect: provide region and endpoint is built automatically
    "IBM_REGION":      "us-south",
    # HPCS: provide the instance-specific crypto endpoint instead
    # "IBM_ENDPOINT":  "https://<instance>.api.us-south.hs-crypto.appdomain.cloud",
    # Optional:
    "CREDENTIAL_STRATEGY": "api_key",  # see below
},
```

**Key names must be 2-90 characters.** A longer rendered name is refused with a
configuration error naming the limit, rather than reaching Key Protect and coming
back as a provider rejection on a tenant's first encrypt. Letters, digits,
underscores and hyphens all pass through a `KEK_TEMPLATE` unchanged; anything
else in the silo UID is hex-escaped.

Key Protect does **not** require key names to be unique — it will happily create
a second key with a name already in use. Nothing in the package creates a
duplicate (a key is only created when no live key of that name is found), but a
duplicate made outside the application leaves the adapter and the provisioner
both taking the first live match, and a deletion then removes only one of them.

### The recorded name

Key Protect addresses keys by a server-assigned UUID, but rows record the key
**name**. The UUID cannot be derived from a silo UID, and an *owner prefix* has
no UUID at all — recording UUIDs would leave the ownership gate comparing a name
prefix against UUID-shaped values, silently refusing every deletion and reporting
KMS-side reconcile as finding nothing. The name is resolved to a UUID at the
point of each wrap or unwrap, cached per process.

That cache is invalidated by the provider's answer rather than on a timer: a key
recreated under a name an older key used gets a **new** UUID, and a worker still
holding the dead one would fail every wrap. Key Protect answers a deleted key's
UUID with `410 Gone`, and a UUID the instance never held with `404`; either one
re-resolves the name and retries once. Rows
written before names were recorded hold a full resource URL and still unwrap —
the UUID is read straight out of it.

### Key rotation

Rotating a root key (`POST /api/v2/keys/{id}/actions/rotate`, or the console)
keeps the key's name and UUID and adds a new version. Key Protect retires the
previous version for wrapping and keeps it available for unwrapping, so data
wrapped before a rotation stays readable with nothing to do.

Key Protect can also rotate on a schedule. Set `KEK_ROTATION_PERIOD_DAYS` in
`KEK_PROVISIONER_OPTIONS` and `IbmKekProvisioner` puts a rotation policy on every
key it creates. Key Protect counts in whole months of exactly 30 days, 1 to 12,
so the value must be a **multiple of 30 and at most 360** — anything in between
is refused rather than rounded. See
[automatic key rotation](kek-provisioning.md#automatic-key-rotation).

The version current at wrap time is recorded on the row as `kek_key_version`,
taken from the wrap response itself — so it costs no extra call and cannot be
mislabeled by a rotation that happens mid-request. It is informational: unwrapping
resolves the version from the ciphertext. See
[Key versions on the row](#key-versions-on-the-row).

Run [`reencrypt_keys`](management-commands.md#reencrypt_keys) after a rotation to
move existing rows onto the new version. Key Protect keeps every retired version
until the key itself is deleted, and exposes no way to destroy one on its own, so
crypto-shredding is key-granular: deleting the key takes all its versions.

### Credential strategies

| Strategy | Value | Extra | When to use |
|----------|-------|-------|-------------|
| API key (default) | `"api_key"` | none | IBM Cloud API key; token auto-refreshed before expiry |
| Assume trusted profile | `"iam_assume"` | none | API key exchanged for a trusted-profile identity; works from anywhere, incl. non-IBM compute |
| Container (CR token) | `"container"` | `[ibm]` | Keyless trusted profile on IBM Code Engine / IKS |
| VPC instance | `"vpc_instance"` | `[ibm]` | Keyless trusted profile on an IBM VPC virtual server |

**`api_key` additional options:**

```python
"IBM_API_KEY": "your-ibm-cloud-api-key",
# Or omit and set the IBM_API_KEY environment variable
```

**`iam_assume` additional options:**

```python
"IBM_API_KEY": "your-ibm-cloud-api-key",
# Plus exactly one trusted-profile selector:
"IBM_TRUSTED_PROFILE_ID": "Profile-xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
# or "IBM_TRUSTED_PROFILE_CRN": "crn:v1:bluemix:public:iam-identity::...",
# or "IBM_TRUSTED_PROFILE_NAME": "my-trusted-profile",
```

**`container` additional options** (needs the `[ibm]` extra):

```python
"IBM_TRUSTED_PROFILE_ID": "Profile-xxxxxxxx-...",  # or IBM_TRUSTED_PROFILE_NAME
# On Code Engine, point at the platform's CR-token file:
"IBM_CR_TOKEN_FILENAME": "/var/run/secrets/codeengine.cloud.ibm.com/compute-resource-token/token",
```

**`vpc_instance` additional options** (needs the `[ibm]` extra):

```python
"IBM_TRUSTED_PROFILE_ID": "Profile-xxxxxxxx-...",  # or IBM_TRUSTED_PROFILE_CRN
# Omit both to use the trusted profile linked to the VSI.
```

`api_key` and `iam_assume` are built in (no extra). `container` and
`vpc_instance` are keyless but run only on the matching IBM compute and
require the `ibm` extra (`ibm-cloud-sdk-core`); selecting them without it
raises a configuration error at startup. The adapter automatically
re-authenticates on 401 responses — token expiry is handled transparently.

---

## Oracle OCI Vault

**Path:** `encryption_suite.adapters.key_stores.oci.OCIVaultAdapter`

**Extra:** `pip install 'django-encryption-suite[oci]'`

Uses the [OCI Key Management Cryptographic API](https://docs.oracle.com/en-us/iaas/Content/KeyManagement/Concepts/keyoverview.htm)
via the official `oci` Python SDK. Request signing is handled by the SDK.

The vault's **cryptographic endpoint** URL is per-vault and can be found in the
OCI Console under **Vault → Vault Information**.

OCI keys are identified by server-assigned **OCID**. You can address them two
ways: directly by OCID (`KEK_MAP` / `SHARED_KEK_ID`), or by **display name**
(`KEK_TEMPLATE`), which the adapter resolves to an OCID via the management
endpoint and which `OciKekProvisioner` can auto-create.

```python
"ADAPTER": "encryption_suite.adapters.key_stores.oci.OCIVaultAdapter",
"OPTIONS": {
    "OCI_VAULT_CRYPTO_ENDPOINT": "https://xxxx-crypto.kms.us-ashburn-1.oraclecloud.com",
    # Address keys by OCID …
    "KEK_MAP": {
        "team-1": "ocid1.key.oc1.iad.aaaaaa",
        "team-2": "ocid1.key.oc1.iad.bbbbbb",
    },
    # … or by display name (needs the management endpoint + compartment so the
    # adapter can resolve name → OCID; pairs with OciKekProvisioner):
    #   "KEK_TEMPLATE": "encryption_suite-{silo_uid}",
    #   "OCI_VAULT_MANAGEMENT_ENDPOINT": "https://xxxx-management.kms.us-ashburn-1.oraclecloud.com",
    #   "OCI_COMPARTMENT_OCID": "ocid1.compartment.oc1..aaaa",
    "CREDENTIAL_STRATEGY": "api_key",  # see below
},
```

Keys are **recorded by the identifier you configured** — the display name under
`KEK_TEMPLATE`, the OCID under `KEK_MAP` — not by the OCID a name resolves to. An
OCID is assigned by OCI, so an owner prefix has no OCID form, and recording OCIDs
would leave key ownership (and with it deletion and KMS-side reconcile) unable to
match anything. Decrypt resolves a stored display name back to an OCID through
the same per-process cache encrypt uses, so a name-addressed deployment needs the
management endpoint and compartment on the read path too.

**Rotation is supported**, and needs no re-wrapping to keep old data readable:
OCI resolves the key version from the ciphertext, so DEKs wrapped under an
earlier version keep decrypting untouched. The version current at wrap time is
recorded on the row as `kek_key_version` — not needed to decrypt, but OCI bills
per key version and can delete one on its own, so "is anything still wrapped
under version 1?" is worth being able to answer. It is cached for
`KEY_VERSION_TTL_SECONDS` (default 300) so a rotation reaches long-running
workers without a restart.

`OciKekProvisioner` can also put an automatic schedule on the keys it creates via
`KEK_ROTATION_PERIOD_DAYS` (60 to 365), but **only a virtual private vault runs one** —
as of August 2026 a standard vault refuses the schedule and Oracle lists the
feature there as *coming soon*, and the private-vault path is untested here. See
[automatic key rotation](kek-provisioning.md#automatic-key-rotation).

Per-silo AAD: each DEK is wrapped with the silo UID bound into OCI's
`associated_data`, preserving the per-silo boundary even under a shared
KEK. See [Getting started with OCI Vault KMS](getting-started-oci.md) for the
full shared / per-silo / auto-provisioning walkthrough.

### Credential strategies

| Strategy | Value | When to use |
|----------|-------|-------------|
| API key (default) | `"api_key"` | `~/.oci/config`, **or** inline signing key in options for hosts outside OCI |
| Instance principal | `"instance_principal"` | Apps running on OCI Compute instances |
| Resource principal | `"resource_principal"` | OCI Functions and Container Instances |
| OKE workload identity | `"oke_workload_identity"` | Pods on OCI Container Engine for Kubernetes (OKE) |

**`api_key` — config file options:**

```python
"OCI_CONFIG_FILE":    "~/.oci/config",   # optional — default path
"OCI_CONFIG_PROFILE": "DEFAULT",         # optional — default profile
```

**`api_key` — inline options** (for hosts with no `~/.oci/config`; supplying any
one selects the inline path):

```python
"OCI_TENANCY_OCID":           "ocid1.tenancy.oc1..aaaa",
"OCI_USER_OCID":              "ocid1.user.oc1..aaaa",
"OCI_FINGERPRINT":            "aa:bb:cc:...",
"OCI_REGION":                 "us-ashburn-1",
"OCI_PRIVATE_KEY_CONTENT":    "-----BEGIN PRIVATE KEY-----\n...",  # PEM text
"OCI_PRIVATE_KEY_PASSPHRASE": "",  # optional, if the PEM is encrypted
```

The keyless strategies (`instance_principal`, `resource_principal`,
`oke_workload_identity`) use credentials injected by the OCI runtime; no static
secrets are required.

---

## Infisical

**Path:** `encryption_suite.adapters.key_stores.infisical.InfisicalKmsAdapter`

**Extra:** `pip install 'django-encryption-suite[infisical]'` (no extra deps — uses stdlib `urllib`)

Uses the [Infisical KMS API](https://infisical.com/docs/documentation/platform/kms/overview).
Works with both Infisical Cloud and self-hosted Infisical instances. Because
Infisical is open source and self-hostable, this adapter gives teams full data
control without managing HashiCorp Vault infrastructure.

Keys can be referenced by UUID (`KEK_MAP`, created outside this application) or by a
template-rendered name that the adapter resolves to its UUID and
`InfisicalKekProvisioner` creates on first use (`KEK_TEMPLATE`). See
[KEK provisioning](kek-provisioning.md#infisicalkekprovisioner).

**Caution:** Infisical caps KMS key names at **32 characters** and requires
them to be *slugs* — lowercase alphanumeric groups joined by single hyphens
(`[a-z0-9-]`). Keep the `KEK_TEMPLATE` prefix short
and UIDs lowercase — uppercase and non-ASCII characters hex-expand and can
overflow the limit.

Infisical also accepts fewer names than its error message describes: no two
hyphens in a row, and no leading or trailing hyphen. Only `{silo_uid}` is
sanitized, so the template's literal prefix must satisfy those rules itself —
`encryption-suite-{silo_uid}`, not `encryption_suite-{silo_uid}`. The adapter
escapes disallowed characters with the letter `z` rather than a hyphen, so
hyphens in the UID survive intact and an escape never introduces one.

```python
"ADAPTER": "encryption_suite.adapters.key_stores.infisical.InfisicalKmsAdapter",
"OPTIONS": {
    # Reference keys you created in the dashboard by UUID:
    "KEK_MAP": {
        "team-1": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
        "team-2": "yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy",
    },
    # — or, for auto-provisioning, render a slug name per silo that
    #   the adapter resolves to a UUID (requires INFISICAL_PROJECT_ID and
    #   the InfisicalKekProvisioner; drop KEK_MAP):
    # "KEK_TEMPLATE":       "encryption-suite-{silo_uid}",
    # "INFISICAL_PROJECT_ID": "your-project-id",
    # Optional — required for self-hosted:
    "INFISICAL_ENDPOINT":   "https://infisical.example.com",
    # Optional:
    "CREDENTIAL_STRATEGY":  "universal_auth",  # see below
    "KEY_VERSION_TTL_SECONDS": 300,            # how often the current version is re-read
},
```

**Rotation is supported**, and needs no re-wrapping to keep old data readable. A
rotation keeps the key's name and UUID and adds new material; Infisical retains
every previous version and resolves the one that produced a ciphertext from the
ciphertext itself, so existing wrapped DEKs keep decrypting untouched.

Rotation is **on demand only** — Infisical has no rotation schedule, so
`InfisicalKekProvisioner` sets `supports_rotation_policy = False` and
`KEK_ROTATION_PERIOD_DAYS` is refused at construction rather than silently ignored.
Rotate from the Infisical UI or API on whatever cadence you keep.

The version current at wrap time is recorded on the row as `kek_key_version`.
Decrypt never reads it — it is there so `manage.py reencrypt_keys` can skip rows
already on current material, and so "is anything still wrapped under the retired
version?" is answerable without unwrapping every row. It rides the name→UUID
lookup the wrap already performs and is cached for `KEY_VERSION_TTL_SECONDS`
(default 300), so a rotation reaches long-running workers without a restart. A
`KEK_MAP` UUID reports no version, and a failed lookup degrades to unknown; both
simply mean `reencrypt_keys` re-wraps every row.

**Infisical exposes no way to list, view, or delete individual key versions** —
they are retained permanently and automatically. So the recorded version is the
only place a "what is still on the old material?" answer exists, and retiring
material means deleting the whole key rather than a version of it.

### Credential strategies

| Strategy | Value | When to use |
|----------|-------|-------------|
| Universal Auth (default) | `"universal_auth"` | Machine Identity; token auto-refreshed before expiry |
| Static token | `"token"` | Pre-obtained access token from `OPTIONS` or `INFISICAL_TOKEN` env var |
| OIDC | `"oidc"` | Machine Identity OIDC auth — exchange a JWT for an Infisical access token. Requires `OIDC_SOURCE`. |

**`universal_auth` additional options:**

```python
"INFISICAL_CLIENT_ID":     "your-machine-identity-client-id",
"INFISICAL_CLIENT_SECRET": "your-machine-identity-client-secret",
# Or omit and set INFISICAL_CLIENT_ID / INFISICAL_CLIENT_SECRET environment variables
```

**`token` additional options:**

```python
"INFISICAL_TOKEN": "your-access-token",
# Or omit and set the INFISICAL_TOKEN environment variable
```

**`oidc` additional options:**

```python
"INFISICAL_IDENTITY_ID":   "your-machine-identity-id",   # required
"INFISICAL_OIDC_AUDIENCE": "infisical",                  # optional, defaults to identity ID
"OIDC_SOURCE":             "<source>",                   # required — which token source
"OIDC_SOURCE_OPTIONS":     {},                           # optional, source-specific
```

The Infisical Machine Identity must be configured with an OIDC auth method
whose trusted audience matches `INFISICAL_OIDC_AUDIENCE`. See
[OIDC token sources](#oidc-token-sources) for the list of supported sources.

> **Subject binding for multi-instance workloads.** Infisical's OIDC auth method
> validates the JWT's issuer, audience, and — optionally — subject. Many
> platforms encode a per-instance identifier in the `sub` claim, so an exact
> subject ties the identity to a single instance and starts returning
> `403 "OIDC subject not allowed"` the moment the platform brings up another one
> — autoscaling, restart, redeploy, or a load balancer spreading requests across
> instances. Bind the **Subject** with a glob over the *stable* portion of the
> claim and wildcard only the per-instance segment, so the binding spans every
> instance of the same workload. Fly.io is a concrete example: its `sub` is
> `<org>:<app>:<machine-name>`, so bind `<org>:<app>:*` to pin trust to one app
> while tolerating machine recreate and scale (each machine gets a new name, and
> Fly autostarts stopped machines to serve traffic). Leaving the subject empty
> also authenticates, but then trust rests only on the issuer and audience — any
> workload the issuer covers (for Fly, its whole organization) that can request
> the configured audience can authenticate as the identity. Prefer the narrowest
> glob that still spans your instances; reserve an empty subject for when the
> issuer is itself a tight trust boundary.

The adapter automatically re-authenticates on 401 responses — token expiry
is handled transparently for the `universal_auth` and `oidc` strategies.

---

## Fly.io KMS (secretkeys)

**Path:** `encryption_suite.adapters.key_stores.fly.FlyKmsAdapter`

**Extra:** none — uses `urllib` and `http.client` from the standard library only

Wraps the per-app
[Fly Machines secretkeys API](https://docs.machines.dev/) for envelope
encryption with `xaes256gcm` keys. Each silo's DEK is encrypted
under a Fly secretkey resolved by `KEK_TEMPLATE` / `KEK_MAP` /
`SHARED_KEK_ID`.

```python
"ADAPTER": "encryption_suite.adapters.key_stores.fly.FlyKmsAdapter",
"OPTIONS": {
    "KEK_TEMPLATE": "encryption_suite_{silo_uid}",
    # Optional:
    # "FLY_APP_NAME": "my-fly-app",     # defaults to the FLY_APP_NAME
    #                                    # environment variable that Fly
    #                                    # injects into every machine.
    #                                    # The env var takes precedence
    #                                    # when both are set.
    # "FLY_SOCKET_PATH": "/.fly/api",   # default; override only for tests
},
```

### Transport — machine-only

The adapter dials only the local `/.fly/api` Unix socket. Fly's
`/encrypt` and `/decrypt` endpoints are restricted to processes inside
machines that belong to the same app and return HTTP 403 to external
callers, so this is the only transport that ever works for the hot
path. Since django-encryption-suite is invoked exclusively from Django,
and Django on Fly always runs inside a Fly machine, no other transport
is exposed.

There are **no credential strategies** to configure. The socket is
authenticated by mount: only processes inside the machine can dial it,
and Fly's platform enforces "this socket = this machine = this app,
allow operations on this app's resources."

> **Security implication.** Any process inside the Fly machine can
> call `/encrypt` and `/decrypt` on every secretkey in the app. RCE
> in the Django container = full KMS access. This is the same property
> as a compromised application server reading its own AWS instance
> credentials, but more visible because there is no per-call IAM check.
> See [Getting started with Fly KMS](getting-started-fly.md#security-note-socket-auth-token-exposure-and-rce-blast-radius)
> for the full discussion. If your threat model puts RCE in scope,
> keep the KEK in a different trust domain (AWS / GCP / Azure / HashiCorp Vault)
> reached via OIDC from the Fly machine — see
> [OIDC token sources](#oidc-token-sources) below.

### Name constraints

Fly secretkey names must match `[A-Za-z0-9_]+` (letters, digits,
underscore — no hyphens, no dots, no slashes). Under `KEK_TEMPLATE`, the
strategy hex-escapes every other character of the silo UID with `_`, and
doubles an underscore that is already there, so distinct UIDs always produce
distinct names: `team-42` becomes `team_2d42`, and `team_42` becomes
`team__42`. Only the UID is escaped, so the template's literal text must
conform on its own — `encryption_suite_{silo_uid}`, not
`encryption-suite-{silo_uid}`.

`KEK_MAP` values are used as given, so each one must already use only those
characters. A mapped name need not resemble the template's names, and it must not
start with the template's prefix (`manage.py check` reports it as `E046`). The
package decides whether it owns a mapped key from
[`KEK_MAP_DESTROYABLE`](configuration.md#kek_map_destroyable), never from the key's name:

```python
"KEK_MAP": {
    "team-42": "acme_team_42",
    "acme.inc": "acme_inc_key",
},
```

`FlyKmsKekProvisioner` checks every name before creating a key and raises
`ValueError` for one that does not conform.

### Associated data

The AAD bound to every ciphertext is
`b"django-encryption-suite:dek:" + silo_uid.encode("utf-8")`,
constructed by `AbstractKmsAdapter._wrap_aad` and shared with the
System, Tink-backed AWS/GCP, GCP, Azure Key Vault, and IBM
adapters. AWS KMS and OCI Vault take AAD as a key-value dict instead
(AWS `EncryptionContext`, OCI `associated_data`), binding the same
silo UID as structured, audit-queryable fields. Fly's
`xaes256gcm` enforces it cryptographically:

- A ciphertext minted for silo A cannot be opened as if it
  belonged to silo B even when both share a KEK (for example
  under `SharedKekStrategy`).
- A ciphertext minted by another Fly secretkey consumer in the same
  app is rejected.

This is a defense-in-depth layer on top of any per-silo KEK
separation the strategy already provides.

### Destructive `/generate`

Fly's `POST /generate` overwrites key material in place with no
version history. Calling it on an already-provisioned name destroys
every ciphertext encrypted under the previous material. The adapter
itself never calls `/generate`; the matching `FlyKmsKekProvisioner`
is GET-first and refuses to regenerate existing keys. The risk is
outside this application: avoid `flyctl secrets create` on a name that already
exists. For controlled rotation see
[Key rotation](key-rotation.md).

### Failure modes

- **Secretkey missing.** HTTP 404 on encrypt/decrypt; surfaced as
  `KekNotProvisionedError`. Provision the key with
  `FlyKmsKekProvisioner` or outside this application via `flyctl`.
- **Outside a Fly machine.** Socket dial raises `FileNotFoundError`.
  Intentional — there is no external fallback.
- **Non-conforming name.** `FlyKmsKekProvisioner` raises `ValueError`
  with the offending name and guidance to adjust the `KEK_TEMPLATE` prefix
  or the `KEK_MAP` value.

For a full step-by-step setup including IAM-equivalent considerations
and per-tenant workflows, see
[Getting started with Fly KMS](getting-started-fly.md).

---

## OIDC token sources

The `oidc` credential strategy is available on **AWS KMS, GCP Cloud KMS,
Azure Key Vault, HashiCorp Vault, and Infisical**. It is
split into two configurable axes:

1. A **token source** that produces a signed OIDC JWT for a given audience.
2. A **provider exchange** that consumes that JWT and returns provider
   credentials. Each KMS provides its own exchange protocol:
   - AWS — STS `AssumeRoleWithWebIdentity`
   - GCP — Workload Identity Federation + service-account impersonation
   - Azure — Azure AD Workload Identity Federation (`client_assertion`)
   - HashiCorp Vault — JWT auth method (`POST /v1/auth/{mount}/login`)
   - Infisical — Machine Identity OIDC auth (`POST /api/v1/auth/oidc-auth/login`)

This split lets you pair any source with any provider — e.g. a GCP-hosted
app reaching an AWS KMS, a Fly.io app reaching Azure Key Vault, or a Vercel
function reaching HashiCorp Vault — without a strategy per source/provider
combination. OCI Vault is the lone holdout: OCI does not currently accept
arbitrary external OIDC JWTs, so its own strategies (`api_key`,
`instance_principal`, `resource_principal`, `oke_workload_identity`) remain the
only options.

The source is chosen via the **required** `OIDC_SOURCE` option whenever
`CREDENTIAL_STRATEGY="oidc"` is set. Source-specific options live under
`OIDC_SOURCE_OPTIONS`. There is no default — misconfiguration is caught
at `manage.py check` / `runserver` startup.

| Source value | Description | `OIDC_SOURCE_OPTIONS` |
|---|---|---|
| `"fly"` | JWT from a Fly.io machine's local Unix socket. | `SOCKET_PATH` (default `/.fly/api`), `ENDPOINT` (default `/v1/tokens/oidc`) — both rarely overridden outside tests. |
| `"file"` | Pre-issued JWT read from a file (Kubernetes projected SA token, AWS IRSA `AWS_WEB_IDENTITY_TOKEN_FILE`, Azure Workload Identity `AZURE_FEDERATED_TOKEN_FILE`, Nomad Workload Identity). The file is re-read on every call so orchestrator-driven rotation is picked up automatically. | `PATH` (required) — absolute path to the JWT file. The audience is fixed by the issuer at write time. |
| `"gcp_metadata"` | JWT from the GCE/GKE metadata server's identity endpoint. Use when a GCP-hosted runtime needs to authenticate to a *non-GCP* KMS (AWS, Azure, HashiCorp Vault). For GCP-to-GCP, prefer `"adc"`. | `SERVICE_ACCOUNT` (default `"default"`), `HOST` (default `metadata.google.internal`), `FORMAT` (default `"full"`) — rarely overridden. |
| `"vercel"` | JWT read from `VERCEL_OIDC_TOKEN`. Vercel's `aud` claim is configured per project in the Vercel dashboard, not at runtime — align the consumer's expected audience with the project's issuer config. | `ENV_VAR` (default `VERCEL_OIDC_TOKEN`) — only override if you intentionally rename the variable. |
| `"spiffe"` | JWT-SVID from a SPIFFE Workload API socket. Requires the optional `py-spiffe` package. | `SOCKET_PATH` (optional) — defaults to the value of `SPIFFE_ENDPOINT_SOCKET` set by the SPIFFE agent. |

> The `OidcTokenSource` protocol in
> `encryption_suite.adapters.credentials.oidc_sources` is intentionally
> small so applications can register their own sources by passing a
> custom object directly to `AwsOidcStrategy` /
> `GcpWorkloadIdentityStrategy`. The factory above is a convenience for
> settings-driven configuration.

### Security considerations for OIDC sources

A few operational requirements are easy to miss because the package
"just works" once configured. Get these wrong and an attacker can
impersonate the workload to your KMS.

**`"file"` source — protect the JWT file path.**
The `PATH` you configure must be writable only by the orchestrator
(root, the kubelet, or the equivalent service account on your
platform). This includes every parent directory on the path. If an
unprivileged process can write to the file, replace it, or swap a
symlink along the path, it can substitute a forged JWT and obtain
provider credentials as your workload. The standard targets — Kubernetes
projected service-account tokens at
`/var/run/secrets/kubernetes.io/serviceaccount/token`, AWS IRSA's
`AWS_WEB_IDENTITY_TOKEN_FILE`, Azure Workload Identity's
`AZURE_FEDERATED_TOKEN_FILE` — already satisfy this; the warning matters
when you point `PATH` at a custom location. (Symlinks are deliberately
followed because Kubernetes rotates tokens via atomic symlink swap.)

**HashiCorp Vault / Infisical — use `https://` URLs.**
`VAULT_ENDPOINT` and `INFISICAL_ENDPOINT` accept any
scheme, but the JWT is sent in the request body. Over plaintext `http://`
to a non-localhost host the JWT (and the provider token returned in the
response) are visible to anyone on the network path. The library logs a
warning at strategy construction in this case; treat that warning as a
deployment defect, not noise. Localhost URLs are exempt because they're
common in dev and sidecar-proxy setups that handle TLS upstream.

**`"gcp_metadata"` source — only override `HOST` if you understand it.**
The default (`metadata.google.internal`) is an unencrypted link-local
endpoint by design, and the audience claim it returns is non-secret. If
you override `HOST` to anything else, you're sending the audience name
in plaintext to a host you control — usually fine, but worth knowing.

**`"vercel"` source — `aud` is fixed by Vercel project config.**
The `audience` your consumer (AWS STS, GCP WIF, etc.) expects must match
exactly what Vercel was configured to issue, or the exchange fails.
There's no way to negotiate this at runtime — the JWT is pre-issued.

**Trusted-config assumption throughout.**
Every option here (`PATH`, `SOCKET_PATH`, `HOST`, `VAULT_JWT_MOUNT`, ...)
is read from your Django settings and assumed to come from a trusted
source. Don't populate these from untrusted user input.

Each provider's section above lists its `oidc` options. The provider guides
walk through the trust setup, with Fly.io as the worked example; see
[Fly.io as an OIDC token source](getting-started-fly.md#flyio-as-an-oidc-token-source).

---

## Writing a custom KMS adapter

Subclass `AbstractKmsAdapter` and implement three methods:

```python
from encryption_suite.adapters.key_stores.base import AbstractKmsAdapter, KmsMetadata

class MyKmsAdapter(AbstractKmsAdapter):

    def encrypt_key(self, plaintext: bytes, silo_uid: str) -> tuple[bytes, KmsMetadata]:
        """
        Encrypt plaintext bytes with the per-silo KEK.
        Use self._resolve_kek_id(silo_uid) to get the key identifier
        from KEK_TEMPLATE or KEK_MAP.
        Return (ciphertext, metadata).
        """
        key_id = self._resolve_kek_id(silo_uid)
        ciphertext = ...
        return ciphertext, KmsMetadata(
            kek_resource_name=key_id,
            kms_provider="my-kms",
        )

    def decrypt_key(self, ciphertext: bytes, metadata: KmsMetadata) -> bytes:
        """Decrypt ciphertext bytes using the KEK identified by metadata."""
        key_id = metadata.kek_resource_name
        return ...

    def describe_kek(self) -> str:
        """Human-readable description of the current KEK (for logging/commands)."""
        return "My KMS key: ..."
```
