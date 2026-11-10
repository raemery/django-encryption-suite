# Getting started with AWS KMS via Tink

This page covers the Tink-backed AWS adapter, `AwsTinkKmsAdapter`. It wraps AWS
KMS in [Google Tink](https://developers.google.com/tink)'s `Aead` primitive and
stores Tink's envelope format on top of the KMS ciphertext.

The **shared** setup — KEK strategies (shared vs per-silo), the four
provisioning combinations, the IAM policies, and `AwsKekProvisioner` — is
identical to the native adapter and is documented once in
[Getting started with AWS KMS](getting-started-aws.md). This page only covers
what differs for the Tink variant; read that page first.

---

## Choosing this adapter

Both AWS adapters call AWS KMS and are interchangeable from the engine's
perspective. The native/Tink trade-off (crypto path, authentication, retry
behavior, ciphertext format) is laid out in
[Getting started with AWS KMS → native vs Tink](getting-started-aws.md#choosing-the-adapter-variant-native-vs-tink).

In short, pick the Tink adapter when you already use Tink primitives elsewhere
and want one `Aead` interface, or want Tink's envelope on the wire — and the
boto3 default credential chain is sufficient for your host.

---

## Keyless authentication

The Tink adapter has **no `CREDENTIAL_STRATEGY` setting**. It delegates
authentication entirely to boto3's default credential chain. There is no OIDC
option (that option is on the native adapter).

This makes it **keyless only where AWS feeds an IAM role into that chain**:

- **ECS / Fargate** — the task role, via the container-credentials endpoint.
- **EC2 / ECS-on-EC2** — the instance profile, via instance metadata.

On those hosts the deployment needs **no access keys at all** — the role *is*
the identity. This is the adapter's intended home: same-cloud, keyless.

Off AWS, or on an AWS host with no IAM-role mechanism, boto3's chain has nothing
to find except static `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` in the
environment. The adapter still works, but it is **not** keyless there — you
supply and rotate keys yourself. (If you need keyless auth off AWS, that is what
the native adapter's `CREDENTIAL_STRATEGY: "oidc"` is for.)

---

## Configuration

```python
ENCRYPTION = {
    "KEY_SETS": {"default": {"silo": "...", "key_store": "aws"}},
    "KMS_KEY_STORES": {
        "aws": {
            "ADAPTER": "encryption_suite.adapters.key_stores.aws_tink.AwsTinkKmsAdapter",
            "OPTIONS": {
                "AWS_REGION": "us-east-1",
                "KEK_TEMPLATE": "alias/encryption_suite-{silo_uid}",
                # No CREDENTIAL_STRATEGY — boto3 default chain only.
                # "AWS_ACCOUNT_ID": "123456789012",  # optional; see Key URIs below
            },
            "KEK_STRATEGY_ADAPTER": "encryption_suite.adapters.keks.PerSiloKekStrategy",
            "KEK_PROVISIONER_ADAPTER": "encryption_suite.adapters.keks.AwsKekProvisioner",
        },
    },
}
```

`AWS_REGION`, `KEK_TEMPLATE` / `KEK_MAP` / `SHARED_KEK_ID`, the KEK strategy, and
`AwsKekProvisioner` all behave exactly as for the native adapter. The only
removed knob is `CREDENTIAL_STRATEGY`.

---

## Key URIs — bare alias vs full ARN

Tink's `AwsKmsClient` requires a **full ARN** key URI
(`arn:aws:kms:<region>:<account>:alias/...` or `.../key/...`). The native
adapter hands a bare `alias/...` straight to boto3, which resolves it; Tink will
not.

The adapter bridges this automatically: a bare `alias/...` or `key/...` value
(what `KEK_TEMPLATE` and the provisioner produce) is **expanded to a full ARN**
before it reaches Tink. So you configure `KEK_TEMPLATE` exactly as for the native
adapter — no ARN bookkeeping.

The expansion needs the account id:

- Set `AWS_ACCOUNT_ID` in `OPTIONS` to provide it explicitly, **or**
- leave it unset and the adapter resolves it once via STS `GetCallerIdentity`
  (which requires no IAM permission).

The region comes from `AWS_REGION` (and Tink reads it back out of the ARN).
Values that are already a full ARN — e.g. explicit entries in `KEK_MAP` — pass
through unchanged.

### Keep `KEK_TEMPLATE` in alias form

Because Tink needs an ARN, a full-ARN `KEK_TEMPLATE` looks like the natural
choice here. Use the bare `alias/...` form instead and let the adapter expand it.

The reason is enumeration: a KMS key has no name of its own, so
`AwsKekProvisioner` lists keys via `ListAliases`, and it can only recognize this
deployment's keys when their names begin with `alias/`. Configure an ARN template
and the Reconcile Keys page reports the KMS side as detection-unavailable — no
orphaned key encryption keys, no live existence column, and no confirmation that
a scheduled key was actually destroyed. Deletion itself still works (DescribeKey
resolves an ARN), but nothing verifies it afterward.

The same applies to explicit `KEK_MAP` entries: ARN values pass through to Tink
correctly and are excluded from KMS-side reconcile.

---

## Ciphertext compatibility

A DEK wrapped by the Tink adapter carries Tink's envelope, and only the Tink
adapter can unwrap it; the same holds the other way round. Each key row records
the name of the `KMS_KEY_STORES` block that wrapped it, and every unwrap goes
through that block.

To move an existing deployment between the two, configure both adapters as
separate blocks, point the key set's `key_store` at the new one, and run `reencrypt_keys`. It
unwraps each row through the block the row records and re-wraps it under the new
one. Keep the old block configured until the run finishes. See
[Moving to another KMS](key-rotation.md#moving-to-another-kms).

---

## Troubleshooting

- **`invalid key URI`** — a KEK id reached Tink without being expanded to an ARN.
  Confirm `AWS_REGION` is set so the adapter can build
  `arn:aws:kms:<region>:<account>:<id>`; supply `AWS_ACCOUNT_ID` if STS is
  unavailable in your environment.
- **An error reported as "key not found" that is really credentials/region** —
  Tink collapses botocore's structured error code into an opaque string, so a
  credential, region, or config problem can surface looking like a missing KEK.
  The `encryption_suite.engine` line reports what the KMS said — that the key
  does not exist — and its `hint` field leads with this possibility, beside the
  underlying error in `detail`. Read those two first, then verify the region and
  the role's KMS permissions before assuming the key is absent.

---

## Related reading

- [Getting started with AWS KMS](getting-started-aws.md) — shared setup: KEK
  strategies, provisioning combinations, IAM policies, the Reconcile Keys admin page.
- [KMS adapters](kms-adapters.md) — adapter reference.
- [Key rotation](key-rotation.md) — re-encrypting when switching adapters.
