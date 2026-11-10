# Getting started with AWS KMS

This step-by-step guide walks you through wiring django-encryption-suite to AWS KMS in production.
This page assumes you have already followed [Getting started](getting-started.md)
for the basic Django setup (`INSTALLED_APPS`, migrations, a silo
adapter) and now need to swap the local dev KMS for real AWS KMS.

The two decisions that drive everything else on this page:

1. **Shared KEK or per-silo KEK?**
   One key for the whole application vs. one key per tenant/team.
2. **Auto-provision or manual?**
   Let the application create KEKs on first encrypt vs. provision them
   outside this application (Terraform / IaC / console) before the application sees them.

The rest of this guide walks through each combination end-to-end.

---

## Prerequisites

- An AWS account and a region you intend to deploy in (this guide uses
  `us-east-1`).
- Permission in that AWS account to either (a) create KMS keys yourself, or
  (b) delegate `kms:CreateKey` to your application's IAM role.
- The `aws` extra installed:

  ```bash
  uv add 'django-encryption-suite[aws]'
  ```

- A working `ENCRYPTION` block in `settings.py` from
  [Getting started](getting-started.md). You will replace the
  env key store configuration with a `AwsKmsAdapter` block below.

---

## Choosing the adapter variant: native vs Tink

Two AWS KMS adapters ship with django-encryption-suite, and they are
interchangeable from the engine's perspective:

| Adapter | `ADAPTER` value | Provider ID |
|---|---|---|
| Native | `encryption_suite.adapters.key_stores.aws.AwsKmsAdapter` | `"aws"` |
| Tink-backed | `encryption_suite.adapters.key_stores.aws_tink.AwsTinkKmsAdapter` | `"aws-tink"` |

Both call AWS KMS. Both support `KEK_TEMPLATE` / `KEK_MAP` /
`SHARED_KEK_ID`. Both work with `AwsKekProvisioner`. The differences
that matter:

- **Crypto path.** The native adapter calls `kms:Encrypt` / `kms:Decrypt`
  directly and stores the AWS-native ciphertext blob. The Tink adapter
  wraps the call in Tink's `Aead` primitive and stores Tink's own
  envelope format on top of AWS KMS's ciphertext.
- **Authentication.** The native adapter exposes a pluggable
  `CREDENTIAL_STRATEGY` setting that supports the boto3 default chain
  (`iam_role`) and keyless OIDC (`oidc`) with a configurable token source.
  The Tink adapter delegates entirely to boto3's default
  credential chain — no `CREDENTIAL_STRATEGY` setting, no OIDC support.
- **Retry and refresh.** The native adapter rebuilds its boto3 client
  on credential-expiry errors and retries once. The Tink adapter relies
  on whatever boto3's chain provides.

**Pick the native adapter when:**

- You need keyless auth from outside AWS via OIDC (see
  [Credential strategies](#credential-strategies)).
- You aren't already using Tink primitives elsewhere in the project.

**Pick the Tink adapter when:**

- You're already using Google Tink for other crypto in the project and
  want a single AEAD interface across the board.
- You want Tink's ciphertext envelope on the wire (e.g. for forensic /
  format-version reasons).
- The boto3 default credential chain is sufficient for your hosting
  environment (EC2 / ECS / Lambda IAM role, environment variables, or
  `~/.aws/credentials`).

**Ciphertext is not interchangeable between the two adapters.** Only the
adapter that wrapped a DEK can unwrap it, so each key row records the name of the
`KMS_KEY_STORES` block that wrapped it. To move an existing deployment, configure
both adapters as separate blocks, point the key set's `key_store` at the new one, and run
`reencrypt_keys`: it unwraps each row through the block the row records and
re-wraps it under the new one. See
[Moving to another KMS](key-rotation.md#moving-to-another-kms).

The combinations below use `AwsKmsAdapter` (native) in the snippets.
To use the Tink variant, set the block's `ADAPTER` to
`encryption_suite.adapters.key_stores.aws_tink.AwsTinkKmsAdapter` and remove
`CREDENTIAL_STRATEGY` from its `OPTIONS`. Everything else
(`AWS_REGION`, `KEK_TEMPLATE` / `SHARED_KEK_ID`, the provisioner
config, the IAM policies) is identical. See
[Getting started with AWS KMS via Tink](getting-started-aws-tink.md) for the
Tink-specific details (keyless boto3-chain auth, bare-alias → ARN expansion,
ciphertext compatibility).

---

## Decision 1 — shared vs per-silo KEK

### Shared KEK

One AWS KMS key encrypts every silo's DEK. Simpler operationally; one
IAM policy, one key to rotate, one key to monitor in CloudTrail. The
trade-off is blast radius: if that single key is compromised or accidentally
deleted, every tenant's encrypted data is at risk simultaneously.

Pick this when:

- You have a single-tenant deployment (one organization, many teams that
  don't need cryptographic isolation between them).
- You want the lightest operational footprint and the per-tenant blast
  radius is not a compliance requirement.

### Per-silo KEK

Each tenant/team gets its own AWS KMS key. Compromise or deletion of one
key affects only that tenant. Required by some compliance regimes (HIPAA
multi-tenant scenarios, PCI scoping). Costs scale with tenant count: AWS
charges per key per month plus per-API-call.

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

---

## Decision 2 — manual vs auto provisioning

### Manual (`NullKekProvisioner`, the default)

Someone (or something) creates the KMS key before the application tries to
use it. Typical flows:

- **Terraform / CloudFormation** — keys defined as IaC, reviewed in PRs,
  applied at deploy time.
- **Bootstrap script** — a one-off shell or Python script run during
  initial deploy.
- **Manual console action** — admin opens AWS console and clicks through
  Create Key.

The application's IAM role only needs `kms:Encrypt`, `kms:Decrypt`, and
`kms:DescribeKey` — it cannot create keys, which is the safer posture for
most production deployments.

When a missing KEK is hit at runtime, the engine raises
`KekNotProvisionedError` with a translated user-facing message
("Encryption and decryption are unavailable for this data.") and an
English admin log entry naming the missing KEK and the strategy in use.
The Django admin **Reconcile Keys** page (described later) is the
operator workflow for catching this before users do.

### Auto (`AwsKekProvisioner`)

The application creates the KMS key the first time a new silo
encrypts data. Typical use case: multi-tenant SaaS where new tenants sign
up mid-request and you don't want a manual provisioning step blocking
their first save.

The application's IAM role needs `kms:CreateKey`, `kms:CreateAlias`, and
`kms:TagResource` in addition to encrypt/decrypt. This is a wider blast
radius — a compromised application can create arbitrary keys, exhaust
quotas, or tag keys however it likes. Some compliance regimes forbid it.

### Combinations

| KEK choice | Provisioning | Per-tenant ops |
|---|---|---|
| Shared | Manual | Create one key once, configure ARN, done |
| Shared | Auto | Rare — one key only, manual is just as easy |
| Per-silo | Manual | New tenant ⇒ admin creates KEK in AWS, configures alias, then tenant can encrypt |
| Per-silo | Auto | New tenant ⇒ first encrypt creates the KEK; zero operator setup |

The four combinations below give you concrete `settings.py` snippets and
operator workflows for each.

---

## Combination A — shared KEK, manual provisioning

Best fit: small / single-tenant deployments.

### Step 1: create the KMS key

Either via Terraform:

```hcl
resource "aws_kek" "encryption_suite" {
  description             = "django-encryption-suite shared KEK"
  key_usage               = "ENCRYPT_DECRYPT"
  customer_master_key_spec = "SYMMETRIC_DEFAULT"
  enable_key_rotation     = true

  tags = { app = "encryption_suite", env = "production" }
}

resource "aws_kms_alias" "encryption_suite" {
  name          = "alias/encryption_suite"
  target_key_id = aws_kek.encryption_suite.key_id
}
```

Or via the AWS CLI:

```bash
aws kms create-key \
  --description "django-encryption-suite shared KEK" \
  --key-usage ENCRYPT_DECRYPT \
  --key-spec SYMMETRIC_DEFAULT \
  --tags TagKey=app,TagValue=encryption_suite

aws kms create-alias \
  --alias-name alias/encryption_suite \
  --target-key-id <KeyId-from-previous-output>
```

### Step 2: grant the application IAM role access

Attach this policy (substituting the alias or ARN) to the IAM role your
Django app runs under:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["kms:Encrypt", "kms:Decrypt", "kms:DescribeKey"],
    "Resource": "arn:aws:kms:us-east-1:<account-id>:alias/encryption_suite"
  }]
}
```

### Step 3: configure `ENCRYPTION`

```python
ENCRYPTION = {
    "KEY_SETS": {"default": {"silo": "...", "key_store": "aws"}},  # whatever you use
    "KMS_KEY_STORES": {
        "aws": {
            "ADAPTER": "encryption_suite.adapters.key_stores.aws.AwsKmsAdapter",
            "OPTIONS": {
                "AWS_REGION": "us-east-1",
                "CREDENTIAL_STRATEGY": "iam_role",   # default
                "SHARED_KEK_ID": "alias/encryption_suite",
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

That's it. The application is now encrypting under one shared KEK.

---

## Combination B — per-silo KEK, manual provisioning

Best fit: multi-tenant SaaS that needs per-tenant isolation but cannot
grant `kms:CreateKey` to the application.

### Step 1: pick a naming convention

The convention is encoded as a template containing `{silo_uid}`.
Aliases are easier to manage than raw key IDs because the alias name
encodes which tenant the key belongs to.

```
alias/encryption_suite-{silo_uid}
# silo_uid "team-42" needs no escaping — hyphen is allowed; any char
# outside [A-Za-z0-9_-] is hex-escaped (e.g. "@" -> "_40")
# resolved name:  alias/encryption_suite-team-42
```

### Step 2: configure `ENCRYPTION`

```python
ENCRYPTION = {
    "KEY_SETS": {"default": {"silo": "...", "key_store": "aws"}},
    "KMS_KEY_STORES": {
        "aws": {
            "ADAPTER": "encryption_suite.adapters.key_stores.aws.AwsKmsAdapter",
            "OPTIONS": {
                "AWS_REGION": "us-east-1",
                "CREDENTIAL_STRATEGY": "iam_role",
                "KEK_TEMPLATE": "alias/encryption_suite-{silo_uid}",
            },
            "KEK_STRATEGY_ADAPTER": "encryption_suite.adapters.keks.PerSiloKekStrategy",
        },
    },
}
```

### Step 3: grant the runtime IAM role access

Use a wildcard so a single policy covers every tenant key:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["kms:Encrypt", "kms:Decrypt", "kms:DescribeKey"],
    "Resource": [
      "arn:aws:kms:us-east-1:<account-id>:key/*",
      "arn:aws:kms:us-east-1:<account-id>:alias/encryption_suite-*"
    ]
  }]
}
```

If your security model requires explicit per-tenant resources (no
wildcards), you'll need to update the policy each time a tenant is
added — Terraform-driven, ideally.

### Step 4: provisioning workflow per new tenant

For each new silo:

1. **Find out which alias it needs.** Open the Django admin, go to
   **Data Encryption Keys → Reconcile Keys** (object-tools link,
   top right of the change list). Or visit:

   ```
   /admin/encryption_suite/dataencryptionkey/reconcile-keys/
   ```

   The page lists every silo, the resolved KEK alias the
   application would try to use, and a **Needs setup** flag for those
   without a DEK row yet.

2. **Create the KMS key.** Via Terraform (preferred — keys are defined in IaC
   alongside everything else):

   ```hcl
   resource "aws_kek" "tenant_42" {
     description = "encryption_suite KEK for team-42"
     key_usage   = "ENCRYPT_DECRYPT"
     customer_master_key_spec = "SYMMETRIC_DEFAULT"
     enable_key_rotation = true
     tags = { silo_uid = "team-42" }
   }

   resource "aws_kms_alias" "tenant_42" {
     name          = "alias/encryption_suite-team-42"
     target_key_id = aws_kek.tenant_42.key_id
   }
   ```

   Or via CLI for one-offs:

   ```bash
   KEY_ID=$(aws kms create-key \
     --description "encryption_suite KEK for team-42" \
     --tags TagKey=silo_uid,TagValue=team-42 \
     --query KeyMetadata.KeyId --output text)
   aws kms create-alias \
     --alias-name alias/encryption_suite-team-42 \
     --target-key-id "$KEY_ID"
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

Until the KEK exists, any encrypt for that tenant raises
`KekNotProvisionedError`. The translated user-facing message is
`"Encryption and decryption are unavailable for this data."`; the log
entry contains the missing alias and the silo UID.

---

## Combination C — per-silo KEK, auto provisioning

Best fit: multi-tenant SaaS that can grant `kms:CreateKey` and wants
zero per-tenant manual steps.

### Step 1: configure `ENCRYPTION`

Same `OPTIONS` as Combination B, plus a provisioner:

```python
ENCRYPTION = {
    "KEY_SETS": {"default": {"silo": "...", "key_store": "aws"}},
    "KMS_KEY_STORES": {
        "aws": {
            "ADAPTER": "encryption_suite.adapters.key_stores.aws.AwsKmsAdapter",
            "OPTIONS": {
                "AWS_REGION": "us-east-1",
                "CREDENTIAL_STRATEGY": "iam_role",
                "KEK_TEMPLATE": "alias/encryption_suite-{silo_uid}",
            },
            "KEK_STRATEGY_ADAPTER": "encryption_suite.adapters.keks.PerSiloKekStrategy",

            "KEK_PROVISIONER_ADAPTER": "encryption_suite.adapters.keks.AwsKekProvisioner",
            "KEK_PROVISIONER_OPTIONS": {
                "AWS_REGION": "us-east-1",
                "CREDENTIAL_STRATEGY": "iam_role",   # may be different from OPTIONS
                "KEY_DESCRIPTION": "django-encryption-suite KEK",
                "TAGS": {"app": "encryption_suite", "env": "production"},
                # "KEK_ROTATION_PERIOD_DAYS": 365,  # optional; AWS accepts 90-2560
            },
        },
    },
}
```

`KEK_PROVISIONER_OPTIONS` is intentionally separate from `OPTIONS` so
that you can point the provisioner at a different IAM role or different
credentials than the runtime encrypt/decrypt path uses. In most
deployments they are the same, but separating them lets you e.g. use a
narrower runtime role.

The provisioner can also create the keys in an AWS CloudHSM key store instead of
standard KMS. See [custom key store](kek-provisioning.md#awskekprovisioner).

### Step 2: grant the application IAM role broader access

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["kms:Encrypt", "kms:Decrypt", "kms:DescribeKey"],
      "Resource": [
        "arn:aws:kms:us-east-1:<account-id>:key/*",
        "arn:aws:kms:us-east-1:<account-id>:alias/encryption_suite-*"
      ]
    },
    {
      "Effect": "Allow",
      "Action": ["kms:CreateKey", "kms:TagResource"],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": ["kms:CreateAlias"],
      "Resource": [
        "arn:aws:kms:us-east-1:<account-id>:alias/encryption_suite-*",
        "arn:aws:kms:us-east-1:<account-id>:key/*"
      ]
    },
    {
      "Effect": "Allow",
      "Action": ["kms:ScheduleKeyDeletion"],
      "Resource": "arn:aws:kms:us-east-1:<account-id>:key/*"
    },
    {
      "Effect": "Allow",
      "Action": ["kms:ListAliases"],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": ["kms:EnableKeyRotation"],
      "Resource": "arn:aws:kms:us-east-1:<account-id>:key/*"
    }
  ]
}
```

`kms:CreateKey` cannot be scoped to a specific resource (the resource
doesn't exist yet) — this is an inherent AWS IAM limitation and the main
reason some organizations forbid auto-provisioning.

The last three statements are optional and cover the key lifecycle rather than
provisioning. Without `kms:ScheduleKeyDeletion`, a deleted tenant's key is
*retained* — the deletion run records the refusal and the key keeps costing money
until you delete it by hand. Without `kms:ListAliases`, the Reconcile Keys page
reports the KMS side as detection-unavailable and cannot confirm that a
scheduled key was actually destroyed. `kms:EnableKeyRotation` is needed only if
you set `KEK_ROTATION_PERIOD_DAYS`; without it the keys are created and work, and a
warning names each one that will not rotate on its own. Leaving the first two out
is a defensible choice if
your organization does not allow the application to destroy keys; see
[the two deletion windows](kek-provisioning.md#the-two-deletion-windows) for what
the app does once it can.

#### Narrowing `kms:ScheduleKeyDeletion` to keys the app created

`kms:ScheduleKeyDeletion` above is scoped to `key/*` — every customer-managed key
in the account and region, including keys belonging to other applications. It has
to be: the deletion call takes a key id, and the alias that identifies *your*
keys cannot be used to scope the statement.

Tags close that gap. `AwsKekProvisioner` writes the `TAGS` you configure onto
every key it creates, so a condition on one of them limits deletion to keys of
the application's own making:

```json
{
  "Effect": "Allow",
  "Action": ["kms:ScheduleKeyDeletion"],
  "Resource": "arn:aws:kms:us-east-1:<account-id>:key/*",
  "Condition": {
    "StringEquals": { "kms:ResourceTag/managed-by": "encryption-suite" }
  }
}
```

with the matching tag configured on the provisioner:

```python
"KEK_PROVISIONER_OPTIONS": {
    "TAGS": {"managed-by": "encryption-suite"},
},
```

This is the one control that holds when the application itself is wrong. Every
in-app deletion gate — disposition, `supports_delete`, the owner prefix — reads
state the application can reach, so a compromised process or an edited database
row is reasoning about inputs it also controls. An IAM condition is evaluated by
AWS, on the key's own tags, and is unaffected by any of that. Prefer it over the
in-app gates as your outer boundary; treat the gates as defense in depth.

Two things to get right, or the condition is worse than nothing:

- **Set the tag before the first key is created.** The condition matches on the
  key's tags, and a key created without them can never be deleted by this policy
  — you would have to delete it by hand or retag it. Tags are written at
  `CreateKey`; nothing retroactively tags existing keys.
- **Keep `kms:TagResource` scoped or the tag becomes decorative.** A role that
  can freely retag keys can grant itself deletion rights on any key by adding the
  tag. If that matters in your account, restrict `kms:TagResource` with an
  `aws:RequestTag` condition, or split provisioning and deletion across two
  roles.

The same shape works for GCP (IAM Conditions over Resource Manager tags) and OCI
(policy conditions on defined tags), whose provisioners also write `TAGS`.
Azure Key Vault has no equivalent data-plane tag condition; scope the role
assignment to a vault dedicated to this deployment instead. Fly, HashiCorp
Vault, IBM, and Infisical create keys through APIs that carry no metadata, so
their provisioners cannot tag at all — for those, isolation has to come from a
dedicated project, mount, or instance rather than from a tag.

### Step 3: deploy and forget

Each new silo now triggers, on first encrypt:

1. `AwsKekProvisioner.ensure_kek` calls `kms:DescribeKey` for the alias.
2. If 404, calls `kms:CreateKey` then `kms:CreateAlias`.
3. The new KEK encrypts a freshly generated DEK; the encrypted DEK is
   stored as a `DataEncryptionKey` row.
4. Subsequent encrypts skip provisioning (in-process cache + AWS already
   has the alias).

The provisioner is idempotent and tolerates `AlreadyExistsException`
from concurrent first-encrypts in multi-process / multi-host deployments.

### Step 4: monitoring

Watch CloudTrail for `CreateKey` events on first signup; spikes can mean
something is hammering tenant creation. The `encryption_suite` logger
emits an `INFO`-level entry on each successful provision:

```
AwsKekProvisioner: created KEK 'alias/encryption_suite-team-42' (KeyId=...) for silo 'team-42'.
```

---

## Combination D — shared KEK, auto provisioning

Rarely useful in production. With a shared KEK there is exactly one key
to create; doing that via Terraform once is faster than configuring a
provisioner. Provided for completeness — same shape as Combination C
but with `SharedKekStrategy` and a single `SHARED_KEK_ID`.

If you do need it (e.g. a one-shot dev environment that creates its
shared key on first boot), set `SHARED_KEK_ID` to the alias the
provisioner should create:

```python
"OPTIONS": {
    "AWS_REGION": "us-east-1",
    "SHARED_KEK_ID": "alias/encryption_suite",
},
"KEK_STRATEGY_ADAPTER": "encryption_suite.adapters.keks.SharedKekStrategy",
"KEK_PROVISIONER_ADAPTER": "encryption_suite.adapters.keks.AwsKekProvisioner",
"KEK_PROVISIONER_OPTIONS": {
    "AWS_REGION": "us-east-1",
    "KEY_DESCRIPTION": "django-encryption-suite shared KEK",
},
```

The provisioner is called once per silo (which always resolves to
the same alias), so the in-process cache makes this near-free after the
first call.

---

## Credential strategies

`AwsKmsAdapter` and `AwsKekProvisioner` both support two credential
strategies, selected by `CREDENTIAL_STRATEGY`:

| Strategy | Use case |
|---|---|
| `iam_role` (default) | boto3's default credential chain finds an attached IAM role, or static `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` in the process environment. |
| `oidc` | STS `AssumeRoleWithWebIdentity` exchanges a platform-issued OIDC token for temporary role credentials, with no stored key. It requires `AWS_ROLE_ARN` and `OIDC_SOURCE`. |

The right strategy depends on where the application runs:

- **On AWS compute that takes an IAM role** (ECS and Fargate, EC2, Lambda),
  keep the `iam_role` default and attach a role. No keys are involved. On ECS,
  grant KMS access to the **task role**, the identity the application runs
  as, and not to the execution role, which only pulls the image and writes
  logs.
- **On AWS compute that cannot take a role** (Lightsail container services),
  create a dedicated IAM user with the KMS policy, pass its access key pair as
  environment variables, and keep the `iam_role` default. boto3's chain reads
  the keys from the environment.
- **Off AWS**, use `oidc` where the platform issues OIDC tokens, and static
  keys as above where it does not. Static keys do not rotate on their own and
  stay in process memory for the life of the process.

The same option block goes in both `OPTIONS` and
`KEK_PROVISIONER_OPTIONS`.

### `oidc` example

```python
"OPTIONS": {
    "AWS_REGION": "us-east-1",
    "KEK_TEMPLATE": "alias/encryption_suite-{silo_uid}",
    "CREDENTIAL_STRATEGY": "oidc",
    "AWS_ROLE_ARN": env("AWS_ROLE_ARN"),
    "AWS_OIDC_AUDIENCE": "sts.amazonaws.com",   # optional; default "amazonaws.com"
    "OIDC_SOURCE": "<source>",                  # "fly" on Fly.io
},
```

Set up AWS in three steps:

1. **Register the issuer.** In IAM, add an OpenID Connect identity provider
   with the token source's issuer URL and the audience above.
2. **Create the role** with the KMS policy for your combination and a trust
   policy that federates that provider. The condition keys are the issuer URL
   without its scheme, followed by `:aud` or `:sub`.
3. **Set `AWS_ROLE_ARN`** to the role's ARN.

```json
{
  "Effect": "Allow",
  "Principal": { "Federated": "arn:aws:iam::<account-id>:oidc-provider/<issuer-host-and-path>" },
  "Action": "sts:AssumeRoleWithWebIdentity",
  "Condition": {
    "StringEquals": { "<issuer-host-and-path>:aud": "sts.amazonaws.com" },
    "StringLike":   { "<issuer-host-and-path>:sub": "<subject-pattern>" }
  }
}
```

Bind `:sub` as tightly as the issuer allows. Where every instance presents the
same `sub`, match it exactly with `StringEquals`. Where `sub` names the
instance, match the stable part with a `StringLike` glob.

**On Fly.io**, the issuer host and path is `oidc.fly.io/<org>`, and `sub` is
`<org>:<app>:<machine-name>`, so the subject pattern is `<org>:<app>:*`. See
[Fly.io as an OIDC token source](getting-started-fly.md#flyio-as-an-oidc-token-source).

When the exchange fails, the error type says where to look.
`InvalidIdentityToken` means AWS could not validate the token: check the
issuer registration and the audience. `AccessDenied` means the token was
valid and the trust policy refused it. AWS returns only
`"An unknown error occurred"` for that, so read the failed
`AssumeRoleWithWebIdentity` event in CloudTrail, which shows the role and
identity provider AWS actually evaluated. Look in the region of the STS
endpoint the call used, which is us-east-1 for the global endpoint, not
necessarily the region your keys are in. A literal `<account-id>` left in
`Principal.Federated` is a common cause: the role then trusts a provider
that does not exist.

---

## The Reconcile Keys admin page

For Combination B in particular, this page is the operator workflow. It lists
every silo with the alias the application would ask KMS for, flags the ones
whose first encryption is still pending, and shows the strategy and provisioner
in effect so you can confirm which combination is live. See
[Reconcile Keys page](admin-panel.md#reconcile-keys-page) for the full
description and the three ways to reach it.

The intended workflow with `NullKekProvisioner`:

1. New tenant signs up.
2. Admin opens the Reconcile Keys page.
3. Copies the resource name (e.g. `alias/encryption_suite-team-42`) into
   their KMS console / Terraform / CLI script.
4. Creates the KEK in AWS.
5. The next encrypt for that tenant creates the DEK automatically (with
   `KEY_AUTO_PROVISION = True`) and the row flips to **Ready**.

---

## Failure modes and what they look like

### KEK missing on AWS

`KekNotProvisionedError` is raised by the engine. The user sees:

> Encryption and decryption are unavailable for this data.

The admin sees an `ERROR`-level log entry naming the alias, the
silo UID, the strategy, and the provisioner. With
`NullKekProvisioner` the message points to provisioning outside this application;
with `AwsKekProvisioner` the message also names the underlying AWS
error (e.g. `AccessDenied` if the IAM role lacks `kms:CreateKey`).

### IAM credentials expired

The adapter rebuilds its boto3 client on `ExpiredTokenException` /
`InvalidClientTokenId` / `AuthFailure` / `UnrecognizedClientException`
and retries once. Persistent failures fall through to the caller as the
underlying `botocore.exceptions.ClientError`.

### Wrong region

`AwsKmsAdapter` does not infer region — it must be set in
`OPTIONS["AWS_REGION"]`. Aliases belong to a single region; an alias
in `us-east-1` is invisible from a client targeting `us-west-2` even
though the underlying account is the same.

---

## Related reading

- [KEK strategies](kek-strategies.md) — full strategy reference, including
  cohort and BYOK.
- [KEK provisioning](kek-provisioning.md) — strategy-vs-provisioner split,
  the full provisioner table, and writing custom provisioners.
- [KMS adapters](kms-adapters.md) — adapter / credential strategy
  reference for AWS and the other providers.
- [Configuration reference](configuration.md) — every `ENCRYPTION`
  setting, including `KEY_AUTO_PROVISION`, `DEK_CACHE_TTL`, and
  `LOG_DECRYPTS`.
- [Key rotation](key-rotation.md) — rotating KEKs and re-encrypting.
