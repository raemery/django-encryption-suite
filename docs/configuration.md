# Configuration Reference

All settings go under the `ENCRYPTION` key in your Django `settings.py`.

```python
ENCRYPTION = {
    "KEY_SETS": {             # one silo adapter and one key store per key set
        "default": {"silo": "...", "key_store": "aws"},
    },
    "KMS_KEY_STORES": {       # one block per KMS, under a name you choose
        "aws": {
            "ADAPTER": "...",               # required
            "OPTIONS": {},                  # content varies by KMS adapter
            "KEK_STRATEGY_ADAPTER": "...",  # required
        },
    },
    # optional settings below
}
```

## All settings at a glance

| Setting | Default | Purpose |
|---|---|---|
| [`KEY_SETS`](#key_sets) | `{}` | The key sets: each one binds a silo adapter, which says which tenant, team or user is active, to a named key store. |
| [`KMS_KEY_STORES`](#kms_key_stores) | `{}` | The key management services this deployment uses, one named block each. |
| [`ENV_KEY_STORES`](#env_key_stores) | `{}` | Key material your settings supply to the process, one named entry each, by version. |
| [`KEY_AUTO_PROVISION`](#key_auto_provision) | `True` | Create a silo's keys lazily on first encrypt. |
| [`SILO_AUTO_KEY_CREATION`](#silo_auto_key_creation) | `[]` | Key sets whose silos get a DEK when they are created. |
| [`SILO_AUTO_KEY_DELETION`](#silo_auto_key_deletion) | `[]` | Key sets whose silos' keys are scheduled for deletion when the silo is deleted. |
| [`KEY_DELETION_WINDOW_DAYS`](#key_deletion_window_days) | `14` | Days a scheduled key stays restorable before deletion. |
| [`DEK_ROTATION_PERIOD_DAYS`](#dek_rotation_period_days) | `None` | Declared DEK cryptoperiod. Display only — flags overdue keys in the admin. |
| [`KEY_DELETION_CAN_RENDER_DATA_INACCESSIBLE`](#key_deletion_can_render_data_inaccessible) | `False` | Permit destroying a key that live data still depends on. |
| [`DEK_CACHE_TTL`](#dek_cache_ttl) | `300` | Seconds to cache a decrypted DEK in-process. |
| [`DEK_CACHE_MAX`](#dek_cache_max) | `{}` | Per key set, the most decrypted DEKs the in-process cache holds. |
| [`DEK_FAILURE_CACHE_TTL`](#dek_failure_cache_ttl) | `5` | Seconds to cache a *failed* key encryption key operation. |
| [`CRYPTO_BACKEND`](#crypto_backend-and-crypto_backend_options) | pyca-cryptography | Engine that performs the local field/file encryption. |
| [`CRYPTO_BACKEND_OPTIONS`](#crypto_backend-and-crypto_backend_options) | `{}` | Algorithm and segment-size choices for that engine. |
| [`STORAGE_ALIAS`](#storage_alias) | `"encrypted"` | `STORAGES` alias backing `EncryptedFileField`. |
| [`STORAGE_SPOOL_ENABLED`](#storage_spool_enabled) | `True` | Spool the encrypted upload instead of holding it in memory. |
| [`STORAGE_SPOOL_THRESHOLD`](#storage_spool_threshold) | `None` | Bytes above which the spool spills to disk. |
| [`STORAGE_SPOOL_DIR`](#storage_spool_dir) | `None` | Directory for the spool file. |
| [`LOG_DECRYPTS`](#log_decrypts) | `False` | Log one `INFO` entry per successful decryption. |
| [`LOG_AAD_VALUES`](#log_aad_values) | `False` | Let log lines carry the values of AAD-bound columns, not just their names. |
| [`USER_IDENTITY`](#user_identity) | nothing recorded or logged | What the key lifecycle record and the log keep about who acted. |
| [`STARTUP_CHECK_WARN_ONLY`](#startup_check_warn_only) | `False` | Downgrade the builder checks to warnings. |
| [`TEST_CONSOLE_FIELD_UID`](#test_console_field_uid-test_console_file_uid-and-test_console_kek_uid) | `"enctestfieldkey"` | Row key for the admin test console's field key. |
| [`TEST_CONSOLE_FILE_UID`](#test_console_field_uid-test_console_file_uid-and-test_console_kek_uid) | `"enctestfilekey"` | Row key for the admin test console's file key. |
| [`TEST_CONSOLE_KEK_UID`](#test_console_field_uid-test_console_file_uid-and-test_console_kek_uid) | `"enctestkey"` | Silo UID the console's KMS calls are made under, and the name its test KEK is derived from. |

That table is every key `ENCRYPTION` itself accepts. A `KMS_KEY_STORES` block takes
five keys of its own, described [under that setting](#kms_key_stores). Some keys
hold a **nested group of settings** whose contents depend on which adapter,
provisioner, or backend you configured. The component that reads each group
documents it, so each has exactly one description and it cannot drift from the
code. The index below is complete: the table above, the block keys, or one hop
from here reaches every option the package accepts.

## Nested settings groups

| Setting | Contents depend on | Keys documented in |
|---|---|---|
| [`OPTIONS`](#options) | the block's `ADAPTER` | [KMS adapters](kms-adapters.md) — one section per provider. The [`OPTIONS`](#options) section below describes the keys every adapter shares (`TLS_CA_BUNDLE`, `TLS_EXTRA_CA`, `KMS_REQUEST_TIMEOUT_SECONDS`). |
| [`KEK_PROVISIONER_OPTIONS`](#kek_provisioner_options) | the block's `KEK_PROVISIONER_ADAPTER` | [KEK provisioning](kek-provisioning.md) — one section per provisioner. |
| [`CRYPTO_BACKEND_OPTIONS`](#crypto_backend-and-crypto_backend_options) | `CRYPTO_BACKEND` | [Crypto backends](crypto-backends.md) — algorithm and segment-size choices. |
| `OIDC_SOURCE_OPTIONS` | `OIDC_SOURCE` | [KMS adapters → OIDC token sources](kms-adapters.md#oidc-token-sources). It sits inside a block's `OPTIONS` and `KEK_PROVISIONER_OPTIONS`, not at the top level. |

`CREDENTIAL_STRATEGY` and the per-strategy keys it enables (role ARNs, tokens,
mount paths) are ordinary keys inside a block's `OPTIONS` and
`KEK_PROVISIONER_OPTIONS`. Each provider's "Credential strategies" section in
[KMS adapters](kms-adapters.md) lists its own.

Each encrypted field configures its own row-identity binding; see
[Row-identity binding](#row-identity-binding-aad).

---

## Required settings

### `KEY_SETS`

**Type:** `dict` of key set name → `{"silo": dotted path, "key_store": store name}` | **Default:** `{}`

A **silo** is any group of data that shares key isolation: a team, a tenant, a
user. A **key set** is one silo adapter and one key store. The adapter tells the
package which silo is active and how to identify it; the store holds the key
encryption keys. A field names its key set with `key_set` and never names a
store.

| Key set | What it is |
|---|---|
| `default` | The key set a field gets when it names none. The package supplies the name only. You declare it, with your silo adapter and a store, whenever a field uses it. |
| `system` | Built in, so it needs no entry. One silo, uid `system`, served by the built-in system adapter. Declare it only to choose its store: `"system": {"key_store": "login"}`. The system key set always uses the system silo, so a `silo` is unnecessary. Naming `"system"` there is accepted, and naming any other silo fails `manage.py check` (`E038`). |
| any other name | A further key set, on the same adapter as another key set or on its own. |

An entry has two keys:

- **`silo`** is the dotted path of a silo adapter class, or `"system"` for the
  built-in system adapter. Use `"silo": "system"` for further key sets whose
  data belongs to no team, such as names shown in a list across teams.
- **`key_store`** is the name of a store from [`KMS_KEY_STORES`](#kms_key_stores) or
  [`ENV_KEY_STORES`](#env_key_stores). An entry that leaves it out uses the only
  configured store, so a project with one store names none.

```python
# Your own team/org model: a GenericModelSiloAdapter subclass that sets model_label
"KEY_SETS": {"default": {"silo": "yourapp.encryption.TeamSiloAdapter", "key_store": "aws"}}

# django-tenants
"KEY_SETS": {"default": {"silo": "encryption_suite.adapters.silos.tenants.DjangoTenantsSiloAdapter", "key_store": "aws"}}

# SaaS Pegasus
"KEY_SETS": {"default": {"silo": "encryption_suite.adapters.silos.pegasus.PegasusTeamSiloAdapter", "key_store": "aws"}}

# Several key sets: the system key set on an env store, and a stricter store for one team key set
"KEY_SETS": {
    "default": {"silo": "yourapp.encryption.TeamSiloAdapter", "key_store": "aws"},
    "restricted": {"silo": "yourapp.encryption.TeamSiloAdapter", "key_store": "hsm"},
    "system": {"key_store": "login"},  # no silo: the system key set always uses the system silo
}
```

A key set name is lowercase letters, digits and underscores, starts with a
letter, and has at most 32 characters. Key set names are global: two adapters
never share one.

A stored key is identified by its key set and the adapter's raw uid, so two
adapters may use the same uid. Key sets bound to one adapter share its silos:
the keys of team 5 in `default` and in `restricted` are two keys of one silo. An
operation that concerns a silo asks the adapter once and applies to every key set
bound to it. An adapter that cannot enumerate silos takes the
`silo_liveness_unknown` path.

A **key store** is where key encryption keys live. There are two kinds:

- **An env store** is key material your settings supply to the process, wrapped
  locally with AES-256-GCM. See [`ENV_KEY_STORES`](#env_key_stores).
- **A KMS store** is a remote service that wraps keys. See
  [`KMS_KEY_STORES`](#kms_key_stores).

A store is a complete bundle: its connection, its KEK strategy and the options
that strategy reads (`KEK_TEMPLATE`, `KEK_MAP`, `SHARED_KEK_ID`), and its
provisioner. A per-silo store and a shared-KEK store on one KMS are two entries.

Each per-silo store serves one silo adapter. Key sets of different adapters take
different stores. See [Keeping silos on separate KEKs](#keeping-silos-on-separate-keks).

- A project with a KMS store and an env store names a store for every key set. An
  entry with no `key_store` and several stores fails `manage.py check` (`E038`), as
  does a `key_store` that does not exist.
- A key set that a field uses and `KEY_SETS` does not declare fails
  `manage.py check` (`E041`).
- Development with no KMS points `default` at an env store:
  `"default": {"silo": "...", "key_store": "login"}`. Team keys then share one
  settings-held key encryption key, which nothing ever deletes.
- An entry that no field uses is allowed.
- Changing an entry moves nothing. Existing rows keep reading through the store
  they recorded, and `reencrypt_keys` re-wraps them onto the new one.
- Changing a field's `key_set` points the field at a different key, so it is a
  data migration, never a settings change. See
  [Switching what protects your data](switching.md).

The `system` key set and its env store load without any other entry or KMS store
configured, so sign-in survives a KMS outage or a missing setting.

See [Silo adapters](silo-adapters.md) for details on each adapter.

---

### `KMS_KEY_STORES`

**Type:** `dict` of name → block | **Default:** `{}`

Each block configures one key management service. You choose the name; the
package records it on every key encryption key row the block creates, and
every unwrap of that row goes through the block of the same name.

```python
"KMS_KEY_STORES": {
    "aws": {
        "ADAPTER": "encryption_suite.adapters.key_stores.aws.AwsKmsAdapter",
        "OPTIONS": {
            "AWS_REGION": "us-east-1",
            "KEK_TEMPLATE": "alias/encryption_suite-{silo_uid}",
        },
        "KEK_STRATEGY_ADAPTER": "encryption_suite.adapters.keks.PerSiloKekStrategy",
        "KEK_PROVISIONER_ADAPTER": "encryption_suite.adapters.keks.AwsKekProvisioner",
    },
},
```

**Never rename a block once rows use it.** A key row on a name with no block
cannot be unwrapped: decryption fails with
[`kms_provider_mismatch`](error-codes.md), and `reencrypt_keys` skips the row
and names it. Keep a retired block configured until `reencrypt_keys` has moved
every row off it.

**Several blocks at once.** Configure the KMS you are leaving and the one you
are moving to side by side, point the key set's `key_store` in
[`KEY_SETS`](#key_sets) at the new one, and run `reencrypt_keys`:
it reads each row through the block the row records and re-wraps it under the
new store. See [Moving to another KMS](key-rotation.md#moving-to-another-kms).

Store names are unique across `KMS_KEY_STORES` and
[`ENV_KEY_STORES`](#env_key_stores); a name in both fails `manage.py check`
(`E037`). The recorded name is the bare name.

When more than one store uses `PerSiloKekStrategy`, give each `KEK_TEMPLATE` a literal
prefix and keep the prefixes prefix-free across stores. See
[Keeping silos on separate KEKs](#keeping-silos-on-separate-keks).

A block takes these keys:

| Key | Default | Purpose |
|---|---|---|
| [`ADAPTER`](#adapter) | — *(required)* | Which key management service wraps the DEK. |
| [`OPTIONS`](#options) | `{}` | Per-provider KMS configuration. |
| [`KEK_STRATEGY_ADAPTER`](#kek_strategy_adapter) | — *(required)* | Which KEK a given silo's DEK is encrypted under. |
| [`KEK_PROVISIONER_ADAPTER`](#kek_provisioner_adapter) | `NullKekProvisioner` | Creates the KEK on demand when it does not exist. |
| [`KEK_PROVISIONER_OPTIONS`](#kek_provisioner_options) | `{}` | Per-provisioner configuration. |

#### `ADAPTER`

**Type:** `str` (dotted Python path)

Dotted path to the KMS adapter class. This class encrypts and decrypts the
DEK using an external key management service.

```python
"ADAPTER": "encryption_suite.adapters.key_stores.gcp.GcpKmsAdapter"
"ADAPTER": "encryption_suite.adapters.key_stores.aws.AwsKmsAdapter"
"ADAPTER": "encryption_suite.adapters.key_stores.azure.AzureKeyVaultAdapter"
"ADAPTER": "encryption_suite.adapters.key_stores.hashicorp.HashiCorpVaultAdapter"
```

See [KMS adapters](kms-adapters.md) for configuration details for each provider.

#### `OPTIONS`

**Type:** `dict` | **Default:** `{}`

Configuration passed directly to the block's KMS adapter. Keys vary by
provider — see [KMS adapters](kms-adapters.md).

Two keys are common to every adapter and control TLS trust for HTTPS
calls made inside the library:

| Key | Effect |
|---|---|
| `TLS_CA_BUNDLE` | Path to a CA file or directory. **Replaces** the system trust store entirely — only CAs in this bundle are trusted. Use when a private CA signs your KMS endpoint and you do not want to trust public CAs. |
| `TLS_EXTRA_CA` | Path to a CA file or directory. **Adds to** the system trust store. The more common option for on-premise KMS deployments that must trust both public services and an internal CA. |

If both are set, `TLS_CA_BUNDLE` wins.

**Plaintext endpoints.** An endpoint option set to an `http://` URL
(`VAULT_ENDPOINT`, `INFISICAL_ENDPOINT`, `IBM_ENDPOINT`, `FLY_API_ENDPOINT`)
logs a WARNING when its KMS adapter or KEK provisioner is constructed, which
includes `manage.py check`. Credentials, provider tokens and plaintext data
encryption keys all cross that connection. A loopback host (`localhost`,
`127.0.0.1`, `::1`) is not warned about, so a local sidecar that terminates
TLS stays quiet.

**Scope.** These options apply only to HTTPS calls the library makes
through `urllib` — namely the HashiCorp Vault, GCP (urllib), IBM, and Infisical
KMS adapters, their token-based credential strategies, and the
corresponding KEK provisioners. SDK-backed adapters (AWS boto3, Azure
SDK, OCI SDK, Tink's native AWS/GCP KMS clients) do not receive this
context. Configure their TLS trust through the SDK's own mechanism:

| Adapter | Configure via |
|---|---|
| AWS (boto3 + Tink) | `AWS_CA_BUNDLE` env var, or `~/.aws/config` `ca_bundle` |
| Azure Key Vault | `REQUESTS_CA_BUNDLE` / `SSL_CERT_FILE` env vars |
| OCI Vault | `REQUESTS_CA_BUNDLE` env var |
| GCP Tink | `SSL_CERT_FILE` env var (google-auth honors it) |

A third common key controls the per-request HTTP timeout for the same
`urllib`-based call paths:

| Key | Effect |
|---|---|
| `KMS_REQUEST_TIMEOUT_SECONDS` | Seconds to wait on each HTTP request before timing out. **Default `10`.** Provider-neutral — applies to the HashiCorp Vault, GCP (urllib), IBM, and Infisical KMS adapters, their token-based credential strategies, and the corresponding KEK provisioners (which read it from `KEK_PROVISIONER_OPTIONS`). |

Lower it (e.g. `3`) when a fast, predictable failure matters more than
tolerating a sluggish KMS — for example so a page does not stall while the
package tries an unreachable KMS endpoint. Pair it with
[`DEK_FAILURE_CACHE_TTL`](#dek_failure_cache_ttl), which ensures every encrypted
value on the page does not pay for the same timeout again. Raise it if a
healthy KMS legitimately responds slowly under load and you see spurious
timeouts. SDK-backed adapters (AWS boto3, Azure SDK, OCI SDK, Tink's native
AWS/GCP clients) ignore this key and use their own SDK timeout and retry
defaults; tune those through the SDK's configuration.

#### `KEK_STRATEGY_ADAPTER`

**Type:** `str` (dotted Python path)

Dotted path to a KEK strategy adapter class. The strategy decides
which key encryption key (KEK) encrypts the DEK for a given silo — for
example, one KEK per silo, one shared KEK, one KEK per cohort,
or a BYOK key (Bring Your Own Key: the tenant supplies the KEK
identifier, typically stored on their tenant record).

Two strategies ship with the library:

| Strategy                                                   | Behavior                                                                                               |
| ---------------------------------------------------------- | ------------------------------------------------------------------------------------------------------ |
| `encryption_suite.adapters.keks.PerSiloKekStrategy` | One KEK per silo. Resolves KEK ID via `KEK_TEMPLATE` or `KEK_MAP` from the block's `OPTIONS`.          |
| `encryption_suite.adapters.keks.SharedKekStrategy`        | Every silo encrypts its DEK under a single shared KEK. Reads `SHARED_KEK_ID` from the block's `OPTIONS`. |

##### `PerSiloKekStrategy` resolution order

A store has one `KEK_TEMPLATE` and one `KEK_MAP`, and every key set on the store
shares them. `KEK_TEMPLATE` is a string; `KEK_MAP` is a dict of silo uid to key
identifier.

```python
"OPTIONS": {
    "KEK_TEMPLATE": "alias/encryption_suite-team-{silo_uid}",
    "KEK_MAP": {"team-42": "arn:aws:kms:us-east-1:111:alias/acme"},
},
```

**The templates' literal prefixes must be prefix-free across stores.** No store's
literal prefix (the template text before the first placeholder) may be a prefix
of another store's. Ownership tests and the destruction guard match names with
`startswith`, so an overlap would let one store's reconcile read another store's
keys as orphans. `manage.py check` reports an overlap (`E037`). A store served
only by `KEK_MAP` has no prefix, so KMS-side orphan detection is off for it.
Shared KEK ids are fixed and carry no prefix; two deployments sharing one
provider account must still use distinct prefixes.

For a silo with uid *uid*, the strategy resolves the KEK ID as follows:

1. **`KEK_MAP[uid]` (if configured)**: Check for an exact match against the raw silo UID.
   Use this when the KMS provider identifies keys by **opaque identifiers** (UUIDs, ARNs, OCIDs)
   rather than names. **Important limitation**: you write the map at deployment time, so
   `KEK_MAP` only works when all silo UIDs are known in advance. Common scenarios:
   - **One-time data migration**: Importing pre-existing silos with assigned key IDs.
   - **Controlled provisioning**: Terraform or scripts create silos outside this
     application, and their UIDs and KEK IDs are documented together before deployment.

   For systems that create silos at runtime (e.g., user signup),
   use `KEK_TEMPLATE` instead. For enterprise BYOK (tenant brings their own key), implement
   a custom strategy that reads the KEK ID from the tenant model.

   Example: OCI Vault environment with pre-provisioned silos:
   ```python
   "OPTIONS": {
       "KEK_MAP": {
           "acme-corp": "ocid1.key.oc1.phx.aabbcc...",
           "acme-corp:billing": "ocid1.key.oc1.phx.xxyyzz...",
       },
   },
   ```

2. **`KEK_TEMPLATE` (if configured)**: Derive the KEK ID from a naming pattern.
   The strategy sanitizes the silo UID (encoding disallowed characters per KMS provider rules)
   and substitutes it into the template. This is the common case for systems where key names
   follow a convention (one key per tenant, named after the tenant).

   Example: AWS KMS environment using naming convention:
   ```python
   "OPTIONS": {
       "KEK_TEMPLATE": "alias/encryption_suite-{silo_uid}",
   },
   ```
   A silo UID like `"team-42"` already fits the default charset
   (`[A-Za-z0-9_-]`), so the strategy uses it unchanged: `alias/encryption_suite-team-42`.
   The strategy hex-encodes characters outside a provider's charset (e.g. on Fly, which
   forbids `-`, the hyphen becomes `_2d`). The exact encoding depends on the KMS
   provider's allowed charset — see the KMS adapter's `_UID_ALLOWED_CHARS`,
   `_UID_ESCAPE_CHAR`, and `_UID_MAX_LENGTH`.

   **Mind the provider's key-name length limit.** Each KMS provider caps key
   names, and `_UID_MAX_LENGTH` enforces that cap on the whole rendered name —
   the template's prefix and suffix plus the sanitized UID. Limits vary widely — AWS aliases allow 256 characters, but
   **Infisical caps KMS key names at 32** and requires them to be *slugs* —
   lowercase alphanumeric groups joined by single hyphens (`[a-z0-9-]`), so no
   underscores, no two hyphens in a row, and none at the start or end. Because
   disallowed and non-ASCII characters hex-expand (often 3 characters per byte),
   a permissive UID can blow past a tight limit unexpectedly. On constrained
   providers, prefer a **shorter template prefix** and keep UIDs lowercase and
   ASCII.

3. **Error** if neither is configured.

**Note:** `KEK_MAP` and `KEK_TEMPLATE` are not symmetric. The map uses the raw,
unsanitized UID as its key; the template receives the sanitized UID. For a UID
absent from `KEK_MAP`, the strategy tries `KEK_TEMPLATE`, and raises if no template exists.
Do not populate `KEK_MAP` with sanitized keys — always use the raw silo UID as the map key.

##### Keeping silos on separate KEKs

Deleting a KEK makes every data key wrapped under it unreadable. When two silos
reach one KEK, deleting it to shred one silo also shreds the other. These rules
keep each per-silo KEK reachable from one silo, and `manage.py check` enforces them
for stores whose strategy is `PerSiloKekStrategy` or a subclass of it. Stores with
`SharedKekStrategy`, env stores and stores with any other strategy are exempt.

- **Serve one silo adapter per per-silo store** (`E042`). Key sets of one adapter
  may share a store, and so a KEK: they share their silos, so deleting that KEK
  shreds the one silo, as intended. Key sets of different adapters on one store
  can produce the same uid, and so the same KEK name. To use two adapters on one
  provider account, configure two store blocks with the same options and different
  templates.
- **Give every `KEK_TEMPLATE` a literal prefix when more than one per-silo store
  exists** (`E043`), and keep the prefixes prefix-free across stores (`E037`). A
  template with no prefix could produce any name, so no comparison with the other
  stores' names can rule out a collision. A store that has a `KEK_MAP` and no
  template is exempt.
- **List each key once in a `KEK_MAP`** (`E044`). A map marked
  `KEK_MAP_DESTROYABLE` that sends two silos to one key makes deleting the key
  shred both. In a map without that setting, a repeated key is a warning (`W059`),
  because the package never deletes those keys and the repetition can be deliberate
  sharing.
- **Keep every `KEK_MAP` value out of reach of the other names** (`E045`, `E046`).
  A value must appear in no other store's map, and must not start with any store's
  template prefix, its own included. A value that starts with a prefix can equal
  the name that template gives to some other silo. The package treats a
  [destroyable](#kek_map_destroyable) mapped key as owned because of the setting, so
  its name never needs the prefix.
- **Re-encrypt a silo before removing its `KEK_MAP` entry.** Once the entry is
  gone, the silo's uid resolves through the template, and its old mapped key reads
  as a key this deployment owns. The package still refuses to delete the key while
  any live data key depends on it.

The checks read configuration only. They cannot see two store blocks that address
one provider account with names whose overlap the rules above do not reveal, a KEK
deleted in the key store's own console, or the effect of
`KEY_DELETION_CAN_RENDER_DATA_INACCESSIBLE`, which turns off the purge gate that
refuses to delete a KEK a live data key still uses.

##### `KEK_MAP_DESTROYABLE`

This setting decides whether the package may delete the keys named in `KEK_MAP`.
**Defaults to `False`.** A mapped identifier is an opaque value you supplied — a UUID, an OCID,
a BYOK ARN — so the package treats it as *yours*: it classifies the key as
shared/opaque and every deletion path refuses it, whatever the deletion window
says. Set it to `True` to opt those keys into deletion:

```python
"OPTIONS": {
    "KEK_MAP": {"team-1": "ocid1.key.oc1..aaa"},
    "KEK_MAP_DESTROYABLE": True,
},
```

It affects **deletion only** — never which key a silo resolves to. It makes the
mapped keys both deletable and owned: a key is owned when its name carries the
store's `KEK_TEMPLATE` prefix, or when it is a `KEK_MAP` value and this setting is
on. The setting therefore works for an OCID, a UUID or an ARN, and for a store that
has a `KEK_MAP` and no `KEK_TEMPLATE`. The package still deletes a key only when no
live data key uses it.

Leave it off unless the mapped keys exist solely for this deployment and nothing
else uses them; another system often shares exactly this kind of key. Keys named by
`KEK_TEMPLATE` are unaffected: this deployment named them, so they are already
eligible.

**For runtime silo creation**: If you need to assign different KEK IDs
to different silos but cannot pre-populate a static map, implement a custom
KEK strategy that reads the KEK ID from your silo model or external service.
See [KEK strategies](kek-strategies.md) for BYOK and custom strategy examples.

For any other policy (cohort-based, composite-aware, BYOK), subclass `encryption_suite.adapters.keks.AbstractKekStrategyAdapter`
and point this key at your class. See
[KEK strategies](kek-strategies.md) for the full interface and
worked examples.

#### `KEK_PROVISIONER_ADAPTER`

**Type:** `str` (dotted Python path) | **Default:** `"encryption_suite.adapters.keks.NullKekProvisioner"`

Dotted path to a KEK provisioner adapter class. The provisioner creates the
KEK on the KMS provider when it does not already exist. The engine calls it once
per silo at DEK creation time, just before the KMS `encrypt_key` call
that encrypts the newly generated DEK.

The default `NullKekProvisioner` does nothing — you provision KEKs outside this
application (Terraform, CI bootstrap script, manual console action) before
the application tries to encrypt a DEK under them. If the KEK is missing,
the first encryption attempt raises `KekNotProvisionedError` with a
translated user-facing message and an English admin log entry that names
the missing KEK and the strategy in use.

Set this to a provider-specific provisioner if you want the application to
create KEKs on demand. See [KEK provisioning](kek-provisioning.md) for the
strategy-vs-provisioner split, IAM implications, and examples.

#### `KEK_PROVISIONER_OPTIONS`

**Type:** `dict` | **Default:** `{}`

Configuration passed to the block's KEK provisioner. It stays separate from
`OPTIONS` because provisioning typically needs different credentials, tags, key
specs, or key policies than routine encrypt/decrypt. Keys vary by
provisioner — see [KEK provisioning](kek-provisioning.md).

One key here can override a protection the KMS applies to its own keys, so read
about it before the per-provisioner sections:

| Key | Provisioner | Effect |
|---|---|---|
| [`ALWAYS_ALLOW_KEY_DELETION`](kek-provisioning.md#always_allow_key_deletion) | HashiCorp Vault | The transit engine marks each key `deletion_allowed: false` at creation and refuses to delete it. Setting this to `True` lets the deletion clear that flag and delete the key — every version at once, immediately, with no restore. Default `False`, in which case the package retains keys and records the reason. |

---

### `ENV_KEY_STORES`

**Type:** `dict` of name → entry | **Default:** `{}`

An env store is key material the project supplies to the process through
settings. `KEKS` is a plain version map, so your settings decide where the bytes
come from: an environment variable, a mounted secret file, or a secret manager
read at startup. The package does not know or care.

```python
"ENV_KEY_STORES": {"login": {"KEKS": {1: env("ENC_LOGIN_KEK")}}},
```

Each version maps to 32 random bytes, base64 encoded. Generate one with:

```bash
openssl rand -base64 32
```

- **A supported production option.** Its protection is the secrecy of the key
  material and wherever you keep it. Against a KMS it has no provider-side
  access policy, no audit log and no HSM, and rotation is manual through `KEKS`
  versions. A key committed to the repository protects nothing.
- **One shared key per store.** `EnvKeyStoreAdapter` wraps data keys with
  AES-256-GCM under the highest version, through the `cryptography` library
  directly, whatever [`CRYPTO_BACKEND`](#crypto_backend-and-crypto_backend_options)
  says. Per-silo data keys sit under it: deleting one silo's data key affects only
  that silo, and scheduling the key encryption key affects every silo wrapped
  under it.
- **Versions.** The highest version wraps new keys. Each data key row records the
  version that wrapped it in `kek_key_version`, and `reencrypt_keys` moves rows to
  the highest. A version still referenced by a row but absent from `KEKS` is
  reported by `crypto_inventory` and refused at use; a wrong value fails the
  AES-GCM tag check, so nothing decrypts to garbage.
- **No ephemeral key.** An empty or missing `KEKS` is an error check at deploy
  (`E039`) and a typed `EncryptionConfigurationError` at first use. The package
  never generates material, so a missing variable can never silently produce a
  new key that orphans what was written under the old one. Nothing depends on
  `DEBUG`.
- **Same value in every process.** Processes that share a database must read the
  same `KEKS`. If a web process and a worker read different values, each writes
  data keys the other cannot unwrap.
- An entry takes `KEKS` and an optional `SHARED_KEK_ID` (default `shared`).
  It takes no per-silo setting.

**Rotating.** Add the next version beside the current one, deploy, and run
`reencrypt_keys`: it re-wraps every row on an older version under the highest.
Drop an old version only after that run, because a row that still records it
cannot be unwrapped.

```python
"ENV_KEY_STORES": {
    "login": {"KEKS": {1: env("ENC_LOGIN_KEK"), 2: env("ENC_LOGIN_KEK_2")}},
},
```

---

## Optional settings

### Key provisioning and lifecycle

#### `KEY_AUTO_PROVISION`

**Type:** `bool` | **Default:** `True`

When `True`, the engine lazily creates a `DataEncryptionKey` the first
time a silo tries to encrypt data, instead of requiring
`setup_encryption_keys` or the `SILO_AUTO_KEY_CREATION` signal to have run
first. This is the recommended default for applications where silos
(teams, tenants) are created mid-request — e.g. SaaS Pegasus team signup,
django-tenants schema creation — so that a transient KMS outage at
silo-creation time does not break the user-facing flow.

Decryption is never lazy. A missing DEK on read always raises, because no
ciphertext could have been produced under a DEK that does not exist.

Set to `False` in deployments that require every encryption key to be
provisioned explicitly and audited before first use. It governs only this
lazy path: `setup_encryption_keys`, `reencrypt_data`, `reencrypt_keys
--provision`, the test console and the `SILO_AUTO_KEY_CREATION` signal
provision keys whatever it is set to.

```python
"KEY_AUTO_PROVISION": True
```

---

#### `SILO_AUTO_KEY_CREATION`

**Type:** `list[str]` | **Default:** `[]`

A list of key set names. For each key set listed, a `post_save` signal is
registered on the silo models that key set's adapter declares
(`silo_model_labels`). It generates and stores the key set's field
`DataEncryptionKey` whenever a new silo is created. The choice is per key set:
list `default` to make its key at creation and leave `restricted` to be made on
first use.

```python
"SILO_AUTO_KEY_CREATION": ["default"]
```

An adapter that declares no silo models cannot use this setting.

This is most useful when new silos are created through normal application
flow. For bulk imports or pre-existing records, use
`python manage.py setup_encryption_keys` instead.

---

#### `SILO_AUTO_KEY_DELETION`

**Type:** `list[str]` | **Default:** `[]`

The symmetric counterpart to `SILO_AUTO_KEY_CREATION`: a list of key set names.
Listing a key set selects its silo adapter. On `post_delete` of a silo of that
adapter, every `DataEncryptionKey` row for the silo, in every key set bound to the
adapter, is flipped to `deletion_scheduled`, and — only when the KEK is
silo-exclusive — its `KeyEncryptionKey` row is scheduled too. Both sit inside the
same soft-delete window (see [`KEY_DELETION_WINDOW_DAYS`](#key_deletion_window_days)).
Listing a key set never limits the deletion to that key set, because keys left
behind by a deleted silo are never wanted.

```python
"SILO_AUTO_KEY_DELETION": ["default"]
```

Scheduling never destroys anything, and neither does the window closing. An
operator deletes the expired work from the admin later, re-checking the deletion
gates at that point, so a scheduled key stays restorable for the whole window and
is destroyed only when someone decides to. Because scheduling is only
a recording step, a failure to record it is swallowed rather than allowed to
break the operator's delete — it surfaces as a `kek_deletion_record_failed`
entry in the log (see [Error codes](error-codes.md)).

A composite silo adapter declares both its tenant and its cell model, so deleting
either schedules the keys.

**The package acts on real deletes only.** A row your application hides — a
soft-delete flag, an archived status, a default manager that filters them out —
is still a live row as far as the package is concerned: hiding a silo schedules
none of its keys, and a [data key rotation](key-rotation.md#rotating-a-data-encryption-key)
converts hidden rows like any other, because it reads through each model's base
manager rather than its default one.

Empty by default — opt in per silo adapter. See [Key lifecycle
events](key-lifecycle-events.md) for what each transition records, and
[Logging](logging.md) for how the deletion run reports consuming them.

---

#### `KEY_DELETION_WINDOW_DAYS`

**Type:** `int` (days) | **Default:** `14`

How long a scheduled key stays restorable before a deletion run may destroy it.
One window covers both sides of a deletion: the DEK row's app-enforced
soft-delete (its `encrypted_keyset` is cleared — the crypto-shred) and the
silo-exclusive KEK's deletion at the provider. Restoring during the window
reverses both together.

```python
"KEY_DELETION_WINDOW_DAYS": 14
```

`0` means schedule-equals-immediately-eligible: the next deletion run may act at
once. Even then the row is recorded as scheduled first, so the act is always
auditable. Note that a *scheduled* key already blocks new encrypts and decrypts
for that silo once the in-process [`DEK_CACHE_TTL`](#dek_cache_ttl) entry
expires — the window governs recoverability, not availability.

This is the only window the package controls. Most KMS providers impose a second
one of their own once the deletion run actually asks them to delete the key
(`PROVIDER_DELETION_WINDOW_DAYS` in `KEK_PROVISIONER_OPTIONS`). The two run in
sequence, and only the first can be reversed from the admin — the provider's own
window is cancelable only at the provider. See
[the two deletion windows](kek-provisioning.md#the-two-deletion-windows).

---

#### `DEK_ROTATION_PERIOD_DAYS`

**Type:** `int` (days) or `None` | **Default:** `None`

The cryptoperiod you have declared for a silo's data encryption key — how long
one key's material may stay in service before it should be replaced.

```python
"DEK_ROTATION_PERIOD_DAYS": 365
```

**It is display only.** Nothing rotates a data encryption key on its own when
the period elapses — [`reencrypt_data`](management-commands.md#reencrypt_data)
does, when you run it — and nothing is blocked, refused, or logged. Setting it turns
on one thing: the **Rotation due** column and filter on the Data encryption keys
changelist, which flags rows whose material is older than the period. Left at
`None`, the admin makes no claim about any key being due, because without a
declared period the question has no answer.

`0` is a real setting, not an absent one: it declares a period that has already
elapsed, so every key reads as overdue. That is the quickest way to see the
overdue rendering without waiting out a real period. Anything that is not a
non-negative whole number (or `None`) is reported in the log and then ignored —
a typo cannot be honored, and guessing at one would put a wrong date in front of
an auditor.

The age is measured from `key_material_last_generated_at` — when the bytes now
in use were generated. Re-encrypting a data key onto a new key encryption key
deliberately does **not** reset it: the material is unchanged, only its
wrapping. See [Key rotation](key-rotation.md#the-two-rotation-dates) for the two
dates and which layer each one answers for.

The name mirrors `KEK_ROTATION_PERIOD_DAYS` in
[`KEK_PROVISIONER_OPTIONS`](#kek_provisioner_options), which is the same idea one
layer up. That one is not display only — it writes a real rotation schedule at
the provider — and the admin reads it to date the matching key-encryption-key
answer, so there is no second setting to keep in step.

---

#### `KEY_DELETION_CAN_RENDER_DATA_INACCESSIBLE`

**Type:** `bool` | **Default:** `False`

Permit destroying a key that data still in use depends on, making that data
permanently unreadable while its rows remain.

```python
"KEY_DELETION_CAN_RENDER_DATA_INACCESSIBLE": False
```

Off by default because the ordinary deletion path destroys keys whose silo is
already gone. Refusing the other case is what stops a mis-selection from taking a
live tenant's data with it — the operator picked a key from a changelist, and
nothing else would have told them a live silo was still behind it.

"Still depends on" means a data encryption key row that references this key and
still holds its wrapped key material. Shredded tombstones do not count: they
record that a silo *used* the key, not that it still needs it.

**Turn it on for a real requirement.** The usual one is an erasure obligation
that must render personal data unreadable while the records themselves are
retained: destroy the key, keep the rows. Without this setting the only way to
satisfy that is to delete the very rows you are required to keep.

It governs **both halves** of a deletion:

| Half | Refused when off |
|---|---|
| Key encryption key | It still wraps live keysets. The deletion confirmation counts the silos that would lose data. |
| Data encryption key | The silo it belongs to still exists — or the silo adapter cannot say whether it does. |

A silo adapter that sets `prevents_key_delete` is refused whatever this setting says.
The built-in system silo adapter sets it, so the system silo's data keys are never
deleted.

**With it off, the key-encryption-key refusal happens at *scheduling*, not at
deletion.** Scheduling a key the deletion could never destroy would leave it sitting out
a restore window under a promise nothing would keep, and the operator would learn
only after it expired.

**The data-encryption-key gate needs [`silo_exists()`](silo-adapters.md#answering-about-one-silo-silo_exists).**
Where the silo adapter cannot answer, the key is retained rather than destroyed on a
question nobody answered. That is a real cost for composite and custom adapters:
implement `silo_exists()` — a few lines, and far weaker than full enumeration — or
the ordinary teardown refuses too. Three refusals are reported apart, because the
remedies differ:

| Reason | Meaning | Fix |
|---|---|---|
| `silo_still_exists` | The silo is live | Delete the silo, or turn this setting on |
| `silo_liveness_unknown` | The adapter cannot check | Implement `silo_exists()` or `iter_silos()` |
| `silo_check_failed` | The check raised | Investigate and retry — logged at WARNING |

A refused data encryption key is left **entirely unchanged**: still scheduled,
still restorable, no ledger event. Resolve the cause and delete again. A refused
key encryption key is recorded `retained` with its reason, because the deletion moves
it off the scheduled queue rather than retrying it forever.

> **This setting depends on silo UIDs never being reissued.** The gate asks
> whether a silo with this UID still exists; if a UID can be handed to a second
> silo, that answer is about the wrong silo. See requirement 4 of the
> [adapter contract](silo-adapters.md#adapter-contract) — and note that
> `DjangoTenantsSiloAdapter` keys on `schema_name`, which *is* re-takeable.

---

### Caching and performance

#### `DEK_CACHE_TTL`

**Type:** `int` (seconds) | **Default:** `300`

How long to cache a decrypted AEAD primitive in-process before
re-fetching and decrypting it from KMS. Increasing this reduces KMS API calls
at the cost of slower propagation if a key is rotated or revoked.

Set to `0` to disable caching (a KMS call will occur on every field access —
not recommended for production).

```python
"DEK_CACHE_TTL": 300   # 5 minutes
```

Each key set has its own cache in each process. A cache hit takes no lock, and the
cache never scans its entries on a lookup, so a deployment with thousands of active
silos pays no more per field read than one with a few. Expired entries are removed
at most once a minute, and a lookup always checks its own entry's expiry first.

---

#### `DEK_CACHE_MAX`

**Type:** `dict` of key set name → `int` | **Default:** `{}`

The most decrypted DEKs the in-process cache of a key set holds. When a key set's
cache is over its limit, it drops the DEK that was loaded longest ago, and the next
read of that DEK decrypts it from the KMS again. A key set with no entry has no limit.

```python
"DEK_CACHE_MAX": {"default": 5000}
```

Set a limit when a key set has so many silos that holding every one of their DEKs
for `DEK_CACHE_TTL` seconds would use more memory than you want to give the cache.
A value that is not a positive whole number means no limit.

A [user-specific key set](user-specific-silos.md) has one silo per user, so give it a
limit of its own, such as `{"user": 10_000}`. The package ships no default for a key set
name your project chooses.

---

#### `DEK_FAILURE_CACHE_TTL`

**Type:** `int` (seconds) | **Default:** `5`

How long to remember a *failed* key encryption key operation in-process, keyed per
silo. When the KEK cannot be reached or used — a dead or slow KMS
endpoint, expired credentials, or a not-yet-provisioned KEK — the failure is
cached so subsequent encrypted reads short-circuit instead of each re-paying
the (potentially multi-second) KMS round trip. Without this, a single page
that displays *N* encrypted values would block for *N* KMS timeouts in
sequence; with it, the page pays roughly one.

Keep this short — far below `DEK_CACHE_TTL`. It blocks *all* reads for the
silo while the entry is cached, so a healthy-but-briefly-slow backend that
trips it once should be retried almost immediately rather than treated as down
for minutes. The default of 5 seconds is enough to collapse one request's
reads into a single attempt without masking a recovered backend for long.

Only operational KMS failures (`KekUnavailableError`, `KekNotProvisionedError`)
are cached. A missing DEK row or a configuration error is a fast local check
whose state can flip the moment a key is provisioned, so those are always
re-checked and never cached.

A successful decrypt supersedes any cached failure for that silo
immediately. Set to `0` to disable negative caching entirely.

```python
"DEK_FAILURE_CACHE_TTL": 5
```

---

### Crypto backend

#### `CRYPTO_BACKEND` and `CRYPTO_BACKEND_OPTIONS`

**`CRYPTO_BACKEND`** — **Type:** `str` | **Default:**
`"encryption_suite.adapters.crypto_backends.cryptography.CryptographyCryptoEngine"`

Dotted path to the data-plane crypto backend (the engine that does the actual
field/file encryption and generates the DEK; the KMS only wraps the DEK). The
default is the pyca-cryptography backend (`cryptography` is a core dependency).
The Tink backend (`...crypto_backends.tink.TinkCryptoEngine`) is available via
the `[tink]` extra.

**`CRYPTO_BACKEND_OPTIONS`** — **Type:** `dict` | **Default:** `{}`

Backend-specific algorithm/tuning options. The keys differ per backend:

| Backend | Options |
|---|---|
| pyca-cryptography | `AEAD` (`AES256_GCM` \| `CHACHA20_POLY1305` \| `AES256_GCM_SIV`, applies to both fields and files), `SEGMENT_SIZE` (file segment bytes, default `4096`) |
| Tink | `AEAD_KEY_TEMPLATE` (`AES256_GCM` \| `AES128_GCM` \| `AES256_EAX`), `STREAMING_AEAD_KEY_TEMPLATE` (`AES256_GCM_HKDF_4KB` \| `AES256_GCM_HKDF_1MB` \| `AES128_GCM_HKDF_4KB`) |

Changing an algorithm only affects newly generated keys; existing data is
decrypted under whatever it was created with. **Backends are not interoperable —
a backend is a permanent choice for a deployment.** See
[Crypto backends](crypto-backends.md) for the full guide, the algorithm
trade-offs, and the non-interoperability details.

---

#### Row-identity binding (`aad=`)

Row-identity binding is configured per field, not as a global setting.
Pass `aad=` to each encrypted field that should be bound:

```python
class MedicalRecord(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    person = models.ForeignKey(Person, on_delete=models.CASCADE)
    notes = EncryptedTextField(aad=("pk", "person"))
```

See [Binding a value to its row](encrypted-data.md#binding-a-value-to-its-row)
and the [security model](security.md#row-identity-binding-optional) for
threat-model context, naming rules, and operational caveats.

---

### Encrypted file storage

These four settings apply to `EncryptedFileField`, under either `key`, and have
no effect on encrypted model fields. See [Managing encrypted
files](managing-encrypted-files.md#configuration) for the full storage guide.

#### `STORAGE_ALIAS`

**Type:** `str` | **Default:** `"encrypted"`

The alias in Django's `STORAGES` setting whose backend holds `EncryptedFileField`
content, under either `key`. The backend class at that alias is composed at runtime
with `SiloEncryptedStorageMixin`, so you never instantiate a storage class
yourself. If the alias is not defined, the `"default"` alias is used
instead.

```python
STORAGES = {
    "default": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
    "encrypted": {"BACKEND": "storages.backends.s3.S3Storage", "OPTIONS": {...}},
}
```

Keeping encrypted uploads on a dedicated alias lets you point sensitive files
at a different bucket — or an entirely different backend — from public media.

---

#### `STORAGE_SPOOL_ENABLED`

**Type:** `bool` | **Default:** `True`

When `True`, the encrypted upload is held in a
`SpooledTemporaryFile` that spills to disk above
[`STORAGE_SPOOL_THRESHOLD`](#storage_spool_threshold), keeping peak memory flat
for large uploads.

Set it to `False` on runtimes where the temporary directory is backed by memory
— Cloud Run, Kubernetes `emptyDir: {medium: Memory}`, explicit tmpfs mounts.
There, spilling costs the same memory it was meant to save and only adds
syscall overhead; size the container's memory limit for
`concurrency × max_upload_size` instead.

---

#### `STORAGE_SPOOL_THRESHOLD`

**Type:** `int` (bytes) | `None` | **Default:** `None`

Byte threshold above which the ciphertext spool spills from memory to disk.
`None` means "use Django's `FILE_UPLOAD_MAX_MEMORY_SIZE`", which matches the
memory/disk split Django already applies to the unencrypted upload side.

```python
"STORAGE_SPOOL_THRESHOLD": 5 * 1024 * 1024
```

---

#### `STORAGE_SPOOL_DIR`

**Type:** `str` | `None` | **Default:** `None`

Directory for the spool file. `None` lets `tempfile` choose, honoring
`TMPDIR` / `TMP` / `TEMP`. Point it at a mounted volume when the rootfs is too
small for concurrent uploads (Fly machines, Fargate ephemeral storage,
disk-backed Kubernetes nodes).

```python
"STORAGE_SPOOL_DIR": "/mnt/spool"
```

---

### Logging and diagnostics

#### `LOG_DECRYPTS`

**Type:** `bool` | **Default:** `False`

When `True`, each successful field or file decryption emits an `INFO`-level log
entry via the `encryption_suite` logger, recording the silo UID and
field label (`app.Model.field`) when available. Route this logger to your audit log sink
to maintain a record of when sensitive data was accessed.

Defaults to `False`: on read-heavy paths one log line per decrypted field
will overwhelm most logging pipelines and inflate ingestion costs. Enable
explicitly when you need a compliance audit trail (PCI, HIPAA, SOC 2) and
have sized your log sink accordingly. Error-level entries (decryption
failures, missing keys) are always emitted regardless of this setting.

A data key rotation ([`reencrypt_data`](management-commands.md#reencrypt_data))
emits none of these entries, whatever this setting is: it re-encrypts each
value holding both keysets directly, so it never reaches the path that logs
them. The rotation's own lines carry a count of what it moved instead. A control worded as
one record per decrypt is met by application reads only.

See [Logging](logging.md) for routing examples and integration
recommendations.

If your Django `LOGGING` config does not route the `encryption_suite`
logger namespace (or root logger) to a formatted handler, Python may emit
warning/error entries through its fallback handler, which often appears as
message-only lines in process output. This is a host-app logging
configuration issue, not a loss of audit context in encryption_suite itself.

Quick fix (example): explicitly route `encryption_suite` to your normal
formatted handler.

```python
LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "verbose": {
            "format": "[{asctime}] {levelname} \"{name}\" {message}",
            "style": "{",
        },
    },
    "handlers": {
        "console": {"class": "logging.StreamHandler", "formatter": "verbose"},
    },
    "loggers": {
        "django": {"handlers": ["console"], "level": "INFO"},
        "encryption_suite": {"handlers": ["console"], "level": "INFO"},
    },
}
```

---

#### `LOG_AAD_VALUES`

**Type:** `bool` | **Default:** `False`

Whether a log line may carry the **values** of a field's
[AAD-bound columns](#row-identity-binding-aad). One
switch, because the disclosure is one question — does your schema bind personal
data — and it has two writers:

- every decrypt-failure line, which identifies the row it could not read;
- `reencrypt_data`'s line for each row it could not convert.

Off, a line names each bound column and says only whether it holds a value —
`pk=42,person_id=<populated>,email=<empty>` — which is what locates the row, and
usually the whole diagnosis: the column that moved or emptied is the one to look
at. On, the values themselves appear: `pk=42,person_id=7,email=ann@example.com`.
Turn it on only if nothing you bind is personal data, since every failed read
then writes those values to wherever your logs go. See
[decrypt-failure fields](logging.md#decrypt-failure-fields).

It must be a real `True` or `False`: the string `"False"` would read as on, the
wrong direction for a switch that governs disclosure, so `manage.py check`
rejects anything else (`encryption_suite.E032`).
`reencrypt_data --show-aad-values` prints the values to the terminal whatever
this says, and never to the log.

---

#### `USER_IDENTITY`

**Type:** `dict` | **Default:**

```python
"USER_IDENTITY": {
    "KEY_LIFECYCLE_EVENTS": [],
    "LOGS": [],
    "SCOPE": "privileged_acts",
    "IP_PROXY_COUNT": 0,
}
```

This setting defines if, when, what, and how user information is
[logged](logging.md#actor-identity) and tracked with keys in their
[key lifecycle event](key-lifecycle-events.md) records. `KEY_LIFECYCLE_EVENTS`
and `LOGS` each define a list of items that can be tracked about each user.

`SCOPE` defines when user information is tracked: privileged acts, normally
reserved for admin users, or all acts, which can include customer actions.

`IP_PROXY_COUNT` must be configured correctly if your server uses a reverse
proxy and you wish to track a user's IP address.

By default, no user information is output to logs or key lifecycle events. You
must opt in to tracking user information in either place.

##### Encryption

Logs can only output unencrypted data. If you wish to display the minimum
possible information about a user while still providing some user tracking,
select `user_id`. This logs the ID of the user without displaying any personal
information. To log more information, you can choose `user_name` and/or
`user_str`.

Key lifecycle events can store user information as encrypted or unencrypted
values. Information stored with the user can be encrypted by defining important
user fields in the model named by `AUTH_USER_MODEL` as
[system columns](system-wide-silos.md). The IP address and the
operating-system account can each be included as an unencrypted or an
encrypted item.

##### The items

| Item | `KEY_LIFECYCLE_EVENTS` | `LOGS` |
|---|---|---|
| `user_id` | the user, as a reference to `AUTH_USER_MODEL` | `user_id=<pk>` |
| `user_name` | — | `user_name="<user.get_username()>"` |
| `user_str` | — | `user_str="<str(user)>"` |
| `ip_address` | the address, stored as plaintext | `ip_address=<address>` |
| `encrypted_ip_address` | the address, stored encrypted | — |
| `os_user` | the operating-system account behind a command, stored as plaintext | `os_user="<account>"` |
| `encrypted_os_user` | the same, stored encrypted | — |

One item names one field, under the same name wherever it applies. `user_name`
and `user_str` are separate items, so each log key means one thing in every
deployment; list both if you want both. Logs are never encrypted, so the
`encrypted_*` items belong to `KEY_LIFECYCLE_EVENTS` alone, and the record holds
the user as a reference, so the two name items belong to `LOGS` alone. List at
most one form of each value: `ip_address` or `encrypted_ip_address`, `os_user` or
`encrypted_os_user`.

The record does not hold an address or an OS user in its own row. It points at a
row in one of two lookup tables, which holds the value once — in plaintext or
encrypted under the [system silo's keys](system-wide-silos.md#keys), as the
list said when that row was written. **Switching between the two forms applies to later events only.**
Earlier events keep pointing at rows in the form they were written in; nothing
converts them. Listing an `encrypted_*` item needs [`ENV_KEY_STORES`](#env_key_stores),
which `manage.py check` requires (`E040`). Should the keys still be unusable
when an event is written, that value is left off the record and the key act goes
ahead, since an audit detail must never be what stops a key operation.

##### `SCOPE`

**Default:** `"privileged_acts"`. Shared by both lists.

| Value | Takes an identity from |
|---|---|
| `privileged_acts` *(default)* | Only a call site that passes one explicitly: admin actions, the test console, management commands. An ambient read returns nobody. |
| `all_acts` | The above, plus acts that resolve an identity from the request context — lazy provisioning on first encrypt, the silo-creation and silo-deletion cascades, and any log line raised during a request. |

The default is `privileged_acts` because the ambient sites can name a
**customer** rather than staff: a key provisioned while serving someone's
request, and the key deletion a silo's own deletion cascades into. Every other
site is staff in the admin or an operator at a command line.

`all_acts` needs `encryption_suite.user_context.UserContextMiddleware` in
`MIDDLEWARE`, **below** `django.contrib.auth.middleware.AuthenticationMiddleware`
(or an equivalent setter of your own populating the context). `MIDDLEWARE` is
outermost-first, so placing it above reads `request.user` before anything sets
it and records nobody on every request, exactly as omitting it does — which
`encryption_suite.W052` warns about while either list is non-empty.
`privileged_acts` needs no middleware at all.

```python
MIDDLEWARE = [
    # ...
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "encryption_suite.user_context.UserContextMiddleware",
    # ...
]
```

With nothing listed, a hand-recorded attestation still has to be offered an
identity — `record_key_event` and the admin's record actions refuse without one —
and is still recorded unattributed. The lists are a posture about identities, not
about the key event: a settings value must not silently disable a management
command.

The admin shows the user as `str(user)`, the same label every other admin screen
shows for that person, so overriding `__str__` on your user model changes it
everywhere at once — and in the log too, where `user_str` is listed. A row whose
user has since been deleted renders as `Deleted user #<id>`.

##### `IP_PROXY_COUNT`

**Type:** `int` (0 or more) | **Default:** `0`

How many proxies in front of this application are under the deployment's
control.

`0` (the default) disregards `X-Forwarded-For` entirely and reads the address
from `REMOTE_ADDR`. A count of *N* takes the entry *N* from the right of that
header; entries further left are client-supplied and are never read.
`REMOTE_ADDR` is the fallback when the header is absent, carries fewer than *N*
entries, or the selected entry does not parse as an address — and the first such
mismatch logs one warning per process, since the header is client-controlled and
a per-request line would be remotely triggerable log volume.

Three things to weigh before setting it:

- **Over-counting records a client-supplied value.** Reaching further left than
  your own proxies reads whatever the client put there.
- **A recorded address is not unconditionally a client's.** Above `0`, the
  `REMOTE_ADDR` fallback is as likely to be one of your own proxies as a client.
- **It governs this package's reading of that header alone.** Do not mirror it
  onto another library's proxy-count setting: those are read on their own paths
  and need their own verification.

##### An example

A configuration that records the operator and the encrypted address, and logs
the user and the address:

```python
"USER_IDENTITY": {
    "KEY_LIFECYCLE_EVENTS": ["user_id", "encrypted_ip_address", "os_user"],
    "LOGS": ["user_id", "user_name", "ip_address", "os_user"],
}
```

---

#### `STARTUP_CHECK_WARN_ONLY`

**Type:** `bool` | **Default:** `False`

Controls the severity of the builder checks `encryption_suite.E001`–`E006`
(see [ID numbering](#id-numbering)).

When `False` (the default) they are reported as **errors**, so `manage.py
check` fails and a deploy that runs it as a release step is blocked until the
configuration is fixed. Set to `True` to downgrade them to **warnings**
(reported as `W001`–`W006`), letting a deploy proceed against a deliberately
broken configuration — useful for exercising the request-time error handling on
a staging/test deployment. Leave it `False` in normal operation so
misconfiguration fails fast at deploy rather than at the first encrypt/decrypt
request.

```python
"STARTUP_CHECK_WARN_ONLY": False
```

##### Deploying to debug a broken connection

This setting exists for one situation. The application and the KMS are not
talking, and the operator wants the deployment up anyway — so they can open the
[test console](admin-panel.md#test-console), run a round-trip, and read the log
lines it produces.

Most connection failures do not need this setting at all. Building an adapter
performs no I/O — credential strategies defer every network and SDK call to
first use — so an unreachable endpoint, a key name that does not exist, an
expired token, or a trust policy that does not match the workload produces a
check run that passes. The deployment goes out, and the failure surfaces where
it can be read: on the console, and in the log.

What does block a deploy is the configuration failing to *construct* — a dotted
path that does not import, an optional provider SDK missing from the image, an
unrecognized `CREDENTIAL_STRATEGY`, a required option absent, an AAD-incompatible
adapter and KEK strategy paired together. Those are `E001`–`E006`, and setting
`STARTUP_CHECK_WARN_ONLY = True` reports them as `W001`–`W006` so the release
step completes. Nothing else is downgraded, and nothing else needs to be: the
validator checks cannot be tripped by a connection problem, only by a settings
value or a model declaration that is wrong on its own terms.

Note that **`migrate` runs the full system-check suite**, so a release pipeline
is gated by these checks even when it never calls `manage.py check` itself.
(`collectstatic` runs only the staticfiles checks, and serving under
gunicorn/uvicorn runs none.)

Once the deployment is up, the console is built to stay readable while the
pipeline is broken:

- each status panel — cryptographic engine, KMS, storage — catches its own
  failure and renders the reason in place, so one broken layer does not take the
  page down or hide what the others report;
- a failed round-trip logs the operator detail together with the test that
  produced it and the stable [error code](error-codes.md) for the failure;
- a construction failure raises `EncryptionConfigurationError`, so the console
  shows the operator-facing detail — the option or path at fault — rather than
  the generic message an end user would see.

Put it back to `False` once the connection works. Left on, it converts every
future construction mistake into a warning that a deploy will scroll past.

---

#### `TEST_CONSOLE_FIELD_UID`, `TEST_CONSOLE_FILE_UID` and `TEST_CONSOLE_KEK_UID`

**Type:** `str` | **Defaults:** `"enctestfieldkey"` / `"enctestfilekey"` / `"enctestkey"`

Sentinel silo UIDs the [admin test console](admin-panel.md#test-console) uses for
its two isolated test keys, keeping test traffic off every real silo's key.

```python
"TEST_CONSOLE_FIELD_UID": "enctestfieldkey",
"TEST_CONSOLE_FILE_UID": "enctestfilekey",
"TEST_CONSOLE_KEK_UID": "enctestkey",
```

They do **not** all do the same job:

| Setting | Role |
|---|---|
| `TEST_CONSOLE_FIELD_UID` | Row key for the field test's data encryption key, recorded under the key set being tested. Never reaches the KMS. |
| `TEST_CONSOLE_FILE_UID` | Row key for the file test's data encryption key, recorded the same way. Never reaches the KMS. |
| `TEST_CONSOLE_KEK_UID` | The UID both tests make their KMS calls under, and therefore the one the test **key encryption key** is named from. On an env store, the test KEK is recorded under this UID itself, `enctestkey`. |

The two row keys are separate because a `DataEncryptionKey` row is unique on
`(key_set, silo_uid, purpose)` and both console rows use the same `test` purpose, so the
two tests need distinct UIDs to coexist as rows. The KMS identity is separate
from both so the console provisions **one** test key encryption key rather than
one per test, with a name that says what it is instead of borrowing the field
test's.

All three must never collide with a real silo UID. A collision on a row key would
share a row with that silo; a collision on the KMS UID would point the console's
key encryption key at that silo's key. The defaults deliberately avoid the
`label-value` shape the shipped silo adapters produce, so override them only if a
real UID in your deployment could match.

Keep any override of `TEST_CONSOLE_KEK_UID` short and provider-safe — it is
templated into a KEK name subject to the provider's length cap and charset (see
[`KEK_TEMPLATE`](#persilokekstrategy-resolution-order)). The two row keys are
never templated into a provider name, so they are unconstrained beyond the
collision rule.

Changing `TEST_CONSOLE_KEK_UID` on a live deployment renames the key the console
asks for, so the next test provisions a new one and leaves the previous key
behind — it will show up on [Reconcile Keys](admin-panel.md#reconcile-keys-page) as an
orphaned test key to clean up.

---

## System checks

django-encryption-suite registers [Django system
checks](https://docs.djangoproject.com/en/stable/topics/checks/) that run on
`manage.py check` and at `runserver` startup. Run `manage.py check` (or
`check --deploy`, which also runs them) as a release/deploy step to catch
misconfiguration *before* the application serves traffic, rather than at the
first request that touches an encrypted field.

| ID | Level | Trips when |
|----|-------|-----------|
| `encryption_suite.E001` | error | A `KMS_KEY_STORES` block's `OPTIONS["CREDENTIAL_STRATEGY"]` is `"oidc"` but `OIDC_SOURCE` is missing or not resolvable. The message names the block. |
| `encryption_suite.E002` | error | Same as `E001`, for the block's `KEK_PROVISIONER_OPTIONS`. |
| `encryption_suite.E003` | error | A block's KMS adapter fails to construct — bad `OPTIONS`, an unknown `CREDENTIAL_STRATEGY`, or an AAD-incompatible adapter / `SharedKekStrategy` pairing. The message names the block. |
| `encryption_suite.E004` | error | A block's KEK provisioner fails to construct — bad `KEK_PROVISIONER_OPTIONS` or `KEK_PROVISIONER_ADAPTER`. The message names the block. |
| `encryption_suite.E005` | error | The configured crypto backend fails to construct — bad `CRYPTO_BACKEND`. |
| `encryption_suite.E006` | error | The configured silo adapter fails to construct — bad `silo` in a [`KEY_SETS`](#key_sets) entry, or its options. |
| `encryption_suite.W001`–`W006` | warning | `E001`–`E006` with [`STARTUP_CHECK_WARN_ONLY`](#startup_check_warn_only) set: the same six builder failures, downgraded so the deploy proceeds. |
| `encryption_suite.E020` | error | A field's [`aad=`](#row-identity-binding-aad) cannot be resolved — a single string where a tuple belongs, a non-string entry, traversal syntax (`'person.id'`, `'person__name'`), a name matching no field, or a reverse relation. |
| `encryption_suite.E021` | error | A field's `aad=` includes `'pk'` but the model's primary key is an `AutoField` / `BigAutoField` / `SmallAutoField`. The database assigns those on insert, so the value is not available when AAD is computed. |
| `encryption_suite.E022` | error | A field's `aad=` names an encrypted column. Building the AAD reads the column, and reading an encrypted column decrypts it, so one field's read depends on another's. |
| `encryption_suite.E023` | error | `EncryptedFileField(display_name_field=...)` names a field that does not exist on the model. |
| `encryption_suite.E024` | error | `EncryptedFileField(display_name_field=...)` names a field that is not an `EncryptedCharField`, or one with a different `key_set` from the file's. The original filename is user data and is stored encrypted beside the blob, under the same kind of key as the file. |
| `encryption_suite.E025` | error | An encrypted field sets `blank=True` without `null=True`. Encrypted columns hold ciphertext and have none for "no value", while Django fills a blank, non-nullable column with `""` — as the form's empty value and as the default a migration adds the column with. Applies to `EncryptedFileField` and its companion display-name column too. |
| `encryption_suite.E026` | error | An encrypted field declares a uniqueness rule it cannot honor: `unique=True` on a system key set field, or `unique_in_silo=True` on a silo field, without `blind_index=True`; `unique=True` on a silo field, whose uniqueness is held per silo (use `unique_in_silo=True`); or `unique_in_silo=True` on a system key set field (use `unique=True`). Every write stores different ciphertext, so a rule over the column itself could never fire. With the index, the field puts the constraint over the digest instead, and the database holds the plaintext unique. |
| `encryption_suite.E027` | error | An encrypted field sets `db_index=True` without `blind_index=True`. No lookup on an encrypted column is allowed to compare the stored value, so an index over the ciphertext can serve no query. With the index, `db_index=True` indexes the digest instead. |
| `encryption_suite.E028` | error | An encrypted field sets `varchar_column=True` with no `max_length`, or with one whose stored value is too wide to be indexed on every database Django supports. Bounding the column has one purpose — letting another package's index or constraint over it be legal — and an index key on the strictest backend runs to 3072 bytes at 4 bytes per character, so a wider column fails the migration that adds that index. The error names the `max_length` that would fit. Reported here rather than discovered at `migrate` on the one backend that refuses it. |
| `encryption_suite.E029` | error | [`USER_IDENTITY`](#user_identity)'s `SCOPE` is not `all_acts` or `privileged_acts`. |
| `encryption_suite.E030` | error | `USER_IDENTITY`'s `IP_PROXY_COUNT` is not an integer of 0 or more. `True` is rejected, since it would quietly mean one proxy. |
| `encryption_suite.E031` | error | `django.contrib.auth` is not installed, so the ledger's user reference has no model to point at. |
| `encryption_suite.E032` | error | [`LOG_AAD_VALUES`](#log_aad_values) is not a boolean. A truthy string would turn on the disclosure it governs. |
| `encryption_suite.E033` | error | `USER_IDENTITY` is not a dict, holds a key other than `KEY_LIFECYCLE_EVENTS` / `LOGS` / `SCOPE` / `IP_PROXY_COUNT`, or one of its two lists is not a list. |
| `encryption_suite.E034` | error | A `USER_IDENTITY` list holds an item it cannot: an unknown name, an `encrypted_*` item in `LOGS` (logs are never encrypted), or `user_name` / `user_str` in `KEY_LIFECYCLE_EVENTS` (the record holds the user as a reference). |
| `encryption_suite.E035` | error | A `USER_IDENTITY` list names both forms of one value: `ip_address` with `encrypted_ip_address`, or `os_user` with `encrypted_os_user`. |
| `encryption_suite.E036` | error | An `EncryptedFileField`'s storage does not include `SiloEncryptedStorageMixin`, so nothing stands in front of the backend and every upload is stored unencrypted. Only reachable through `storage=` on the field; the default resolves the right one. See [Advanced: storage class composition](managing-encrypted-files.md#advanced-storage-class-composition). |
| `encryption_suite.E037` | error | A store registry or a store's template options are malformed: [`KMS_KEY_STORES`](#kms_key_stores) or [`ENV_KEY_STORES`](#env_key_stores) is not a dict, a KMS block has no `ADAPTER`, an env entry holds a per-silo setting, a name is in both registries, a per-silo KMS block that a key set reaches has no `KEK_TEMPLATE` or `KEK_MAP`, a `KEK_TEMPLATE` is not a string or a `KEK_MAP` is not a dict, or two stores' `KEK_TEMPLATE` prefixes overlap (one is a prefix of the other). |
| `encryption_suite.E038` | error | A key set is malformed or resolves to no store or silo: [`KEY_SETS`](#key_sets) is not a dict, an entry is not a dict, has a malformed key set name, names a `key_store` that does not exist, names no `silo` (or names one other than `"system"` for `system`); or several stores are configured and an entry that a field uses has no `key_store` choosing one. The message names the fields. |
| `encryption_suite.E039` | error | An env store's `KEKS` is not a dict of positive integer versions to 32 bytes of base64 key material, or is empty. |
| `encryption_suite.E040` | error | A [`USER_IDENTITY`](#user_identity) `encrypted_*` item is listed, and the `system` key set resolves to no store. The package's own identity tables are encrypted under it. Silent where `E037`–`E039` already report the store. |
| `encryption_suite.E041` | error | An encrypted field's `key_set` is not declared in [`KEY_SETS`](#key_sets), or is not a valid name: a lowercase letter followed by lowercase letters, digits or underscores, at most 32 characters. |
| `encryption_suite.E042` | error | Key sets bound to different silo adapters share one per-silo store. The message names the store and the key sets. See [Keeping silos on separate KEKs](#keeping-silos-on-separate-keks). |
| `encryption_suite.E043` | error | More than one per-silo store exists and a store's `KEK_TEMPLATE` has no literal prefix before `{silo_uid}`, so the prefixes of the stores cannot be compared. A store with a `KEK_MAP` and no template is exempt. |
| `encryption_suite.E044` | error | A `KEK_MAP` marked [`KEK_MAP_DESTROYABLE`](#kek_map_destroyable) maps more than one silo to one key. |
| `encryption_suite.E045` | error | A `KEK_MAP` value appears in another store's `KEK_MAP`, or starts with another store's `KEK_TEMPLATE` prefix. |
| `encryption_suite.E046` | error | A `KEK_MAP` value starts with its own store's `KEK_TEMPLATE` prefix, so a mapped silo could reach the name the template gives another silo. |
| `encryption_suite.W050` | warning | A registered `ModelAdmin` renders a model with silo encrypted fields but does not use `EncryptionAdminMixin`. Opened outside a silo context, the page shows the fallback label for every value, logs an error per value, and cannot save. See [Rendering models with encrypted fields in the admin](admin-panel.md#rendering-models-with-encrypted-fields-in-the-admin). |
| `encryption_suite.W051` | warning | `KEK_PROVISIONER_OPTIONS` sets `TAGS` (or `DEFINED_TAGS`) but the configured provisioner cannot tag the keys it creates, so they are silently not written. Never an error — an undeliverable tag does not stop a deploy. |
| `encryption_suite.W052` | warning | `USER_IDENTITY`'s `SCOPE` is `all_acts` and one of its lists is non-empty, but `UserContextMiddleware` is missing from `MIDDLEWARE`, or listed above `AuthenticationMiddleware` — both record nobody on every request. |
| `encryption_suite.W053` | warning | `reencrypt_data` cannot find which rows belong to a silo for one or more models holding encrypted data, in any silo adapter's key sets; the models are named. The command refuses to rotate until each resolves — see [Finding a silo's rows](silo-adapters.md#finding-a-silos-rows). A warning, so a deployment that never rotates a data key still deploys. |
| `encryption_suite.W054` | warning | A column named in a field's `aad=` is nullable — a foreign key with `on_delete=SET_NULL` reaches that on one delete of the row it points at. Encryption refuses to write a row whose AAD column is `None`, and a row whose column went `None` after it was written can no longer be decrypted. A warning, because the schema is legal and the rows already written are readable; it is worth saying at deploy because that is while it is still a schema decision rather than a migration over live ciphertext. |
| `encryption_suite.W055` | warning | A `Meta.ordering` or `ModelAdmin.ordering` declaration names an encrypted column. Encrypted columns hold a different value on every write, so the rows come back in an order unrelated to the plaintext, and a blind index cannot answer it either — it holds hashes, whose order says nothing about the values'. A warning rather than an error because the declaration is not always the project's to change: a model from another package can order by a column this project chose to encrypt. |
| `encryption_suite.W056` | warning | A table-level rule — `Meta.unique_together`, a `UniqueConstraint`, or an `Index` — names an encrypted column. A uniqueness rule over it can never fire, because every write stores a different value, so duplicates are accepted in silence; an index containing a text column is rejected outright by MySQL and Oracle, failing the migration that adds it. There is no composite equivalent: a blind index holds *one* column's plaintext unique (`unique=True` on a system field, `unique_in_silo=True` on a silo field, already per silo there), and a rule spanning an encrypted column and another is not available. A warning rather than an error because another package's model can carry such a declaration over a column this project chose to encrypt. One warning per model, listing every such rule. A rule naming only [`varchar_column=True`](encrypted-data.md#varchar_columntrue-for-a-column-somebody-else-indexes) columns is not reported: that keyword is for a rule in a `Meta` the project cannot edit, which leaves nothing to act on. |
| `encryption_suite.W057` | warning | The storage an `EncryptedFileField` writes through is set to overwrite a file that already holds the name, so a name clash would leave two rows pointing at one blob. Recognizes Django's `FileSystemStorage` (`allow_overwrite`) and the django-storages S3, Google Cloud Storage (`file_overwrite`), Azure (`overwrite_files`), Dropbox (`write_mode`) and FTP (`allow_overwrite`) backends; any other backend is not inspected. See [No-overwrite requirement](storage-backends.md#no-overwrite-requirement). |
| `encryption_suite.W058` | warning | A system key set field resolves to a KMS store through [`KEY_SETS`](#key_sets), so sign-in would stop working when the KMS is unreachable. The message names the fields. |
| `encryption_suite.W059` | warning | A `KEK_MAP` without `KEK_MAP_DESTROYABLE` maps more than one silo to one key. The package never deletes the keys of such a map, so the duplicate can be deliberate sharing. |
| `encryption_suite.W060` | warning | A key set is bound to a silo adapter that reads the acting user, such as `ActingUserSiloAdapter`, but `UserContextMiddleware` is missing from `MIDDLEWARE`, or listed above `AuthenticationMiddleware`, so no request sets a user and every read of that key set has no silo, and so does every write the adapter cannot send to the row's owner. The message names the key sets. |
| `encryption_suite.W061` | warning | A key set is bound to a silo adapter that writes to the row's silo while nobody is acting, such as `ActingUserOrOwnerSiloAdapter`, but a model holding its encrypted fields is not the adapter's `model_label` model and has no foreign key, or more than one, to it. A row of that model has no owner, so a write while nobody is acting fails. One warning per model, naming the key set and the model. See [The row's silo](silo-adapters.md#the-rows-silo-silo_for_row). |

The builder checks construct each block's KMS adapter and KEK provisioner, and the
crypto backend, silo adapter, and OIDC token source at check time — an I/O-free
operation, since credential strategies defer all network and SDK work to first
use — and report the actionable configuration detail.

### ID numbering

The number names the condition and the letter names the severity, so a check
reported at both severities keeps one number and swaps the letter. No number is
ever held by both a native error and a native warning, which is what makes that
swap unambiguous: `W004` is always `E004` said more quietly, never something
else.

| Band | Holds |
|------|-------|
| `001`–`019` | **Builder** errors, and the `W` twins [`STARTUP_CHECK_WARN_ONLY`](#startup_check_warn_only) downgrades them to. |
| `020`–`049` | **Validator** errors. Their `W` twins stay reserved rather than reassigned. |
| `050`–`099` | Native **warnings**, reported at that severity always. |

A **builder** check constructs something: it imports a dotted path and runs an
adapter's `__init__`. That is work the package does not control, so a builder
check can fail over the environment — a missing optional SDK, a provider library
that changed — while the configuration is correct. Those are the checks
`STARTUP_CHECK_WARN_ONLY` downgrades, so a deploy is not blocked by a check that
is wrong about the machine it runs on.

A **validator** check is a predicate over data the package fully owns: is this
value a boolean, is this string one of three, does this field exist on the
model, is this column nullable. No environment makes the answer come out
differently, and deploying past one means running under an undefined reading of
a setting — several of which govern disclosure. Nothing downgrades them.

Among the validators, `E020`–`E028`, `E036`, `E041` and `W054` are reported by an
encrypted field against the model that declares it, so the message names the
offending model and column; `E029`–`E035` answer for the other settings and the
installed apps, and `E037`–`E040` and `E042`–`E046` for the store and key set settings. The
builder checks `E001`–`E006` are about adapters.

---

## Related

- [KMS adapters](kms-adapters.md) — the keys a block's `OPTIONS` takes, per provider.
- [KEK provisioning](kek-provisioning.md) — the keys a block's `KEK_PROVISIONER_OPTIONS` takes.
- [Crypto backends](crypto-backends.md) — algorithm choices for `CRYPTO_BACKEND_OPTIONS`.
- [Managing encrypted files](managing-encrypted-files.md) — storage aliases and upload spooling in context.
- [Admin panel](admin-panel.md) — the Reconcile Keys page, key changelists, and the test console.
- [Management commands](management-commands.md) — `setup_encryption_keys`, `reencrypt_keys`, and friends.
