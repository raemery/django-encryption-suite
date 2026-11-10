# Getting started with GCP Cloud KMS via Tink (`GcpTinkKmsAdapter`)

This step-by-step guide walks you through wiring django-encryption-suite to GCP Cloud KMS using the
**Tink** adapter, `GcpTinkKmsAdapter`. This page assumes you have already
followed [Getting started](getting-started.md) for the basic Django setup
(`INSTALLED_APPS`, migrations, a silo adapter).

`GcpTinkKmsAdapter` is one of two GCP Cloud KMS adapters. The other,
`GcpKmsAdapter`, is documented in
[Getting started with GCP Cloud KMS](getting-started-gcp.md) and is the usual
choice. **Read that page first** — most of the configuration (key rings, the
shared-vs-per-silo decision, manual-vs-auto provisioning, the Reconcile Keys admin
page, IAM) is identical between the two adapters. This page covers only what is
different about the Tink variant.

---

## Choosing `GcpTinkKmsAdapter`

Both adapters call Cloud KMS and are interchangeable from the engine's
perspective. They support the same `KEK_TEMPLATE` / `KEK_MAP` / `SHARED_KEK_ID`
options, the same KEK strategies, and the same `GcpKekProvisioner`. The
differences that matter:

| | `GcpKmsAdapter` | `GcpTinkKmsAdapter` |
|---|---|---|
| `ADAPTER` | `encryption_suite.adapters.key_stores.gcp.GcpKmsAdapter` | `encryption_suite.adapters.key_stores.gcp_tink.GcpTinkKmsAdapter` |
| Provider ID on rows | `"gcp"` | `"gcp-tink"` |
| Crypto path | Cloud KMS `:encrypt` / `:decrypt` directly | Tink `Aead` envelope over the Cloud KMS ciphertext |
| Authentication | pluggable `CREDENTIAL_STRATEGY` (`adc` / `service_account_key` / `oidc`) | **ADC only — no `CREDENTIAL_STRATEGY` hook** |
| Required extra | `django-encryption-suite[gcp]` | `django-encryption-suite[gcp-tink]` |

**Pick `GcpTinkKmsAdapter` only when both hold:**

1. You deploy **on GCP itself** — Cloud Run, GKE, or Compute Engine — so
   Application Default Credentials resolve to the host's metadata-server
   identity with zero credential configuration, and
2. You have a business reason for Tink, e.g. Tink is your organization's crypto
   standard, or you want Tink's ciphertext envelope on the wire for
   forensic / format-versioning reasons.

Off GCP, or without a Tink-specific reason, use `GcpKmsAdapter`. In particular,
for keyless authentication from outside GCP, `GcpKmsAdapter` with
`CREDENTIAL_STRATEGY: "oidc"` is the right tool — the Tink adapter cannot do it,
because Tink's GCP client delegates authentication to ADC and exposes no
credential hook.

> **Ciphertext is not interchangeable between the two adapters.** Only the
> adapter that wrapped a DEK can unwrap it, so each key row records the name of
> the `KMS_KEY_STORES` block that wrapped it. To switch adapters on an existing
> deployment, configure both as separate blocks, point the key set's `key_store` at the new one,
> and run `reencrypt_keys` — see
> [Moving to another KMS](key-rotation.md#moving-to-another-kms).

---

## The authentication model: ADC, keyless on GCP

`GcpTinkKmsAdapter` always authenticates through **Application Default
Credentials**. On a GCP-hosted runtime, ADC resolves to the service identity
attached to the host, so there is no key file to create, store, or rotate.

On Cloud Run, that identity is the service's *runtime service account*,
reached through the metadata server. Other GCP runtimes work the same way once
the workload runs as a service account; see
[Other GCP runtimes](getting-started-gcp.md#other-gcp-runtimes) in the GCP
guide.

You do not set `CREDENTIAL_STRATEGY` anywhere for this adapter — supplying it has
no effect on the KMS path. All you do is grant the host's service account the
Cloud KMS roles below; the adapter picks the identity up automatically.

> ADC only works on a GCP runtime (or locally with
> `gcloud auth application-default login`). There is no metadata server on a
> non-GCP host, so the Tink adapter is not usable off GCP. Use `GcpKmsAdapter`
> there.

The `GcpKekProvisioner` (if you auto-provision, below) authenticates the same
way — its `CREDENTIAL_STRATEGY` defaults to `adc`, so one mechanism covers both
the encrypt/decrypt path and key creation, with no credential wiring.

---

## Prerequisites

- A GCP project, a Cloud KMS location, and an existing **key ring** in that
  location (the provisioner creates keys *in* a ring but never creates the ring
  itself). This guide uses project `my-project`, location `us-east4`, and ring
  `encryption_suite`.
- The Cloud KMS API enabled:

  ```bash
  gcloud services enable cloudkms.googleapis.com --project=my-project
  ```

- A GCP-hosted runtime with a service account you can grant Cloud KMS roles to
  (e.g. a Cloud Run service's runtime service account).
- The `gcp-tink` extra installed. It pulls in `google-cloud-kms`, which Tink's
  GCP integration (`tink.integration.gcpkms`) requires on top of the base GCP
  dependencies:

  ```bash
  uv add 'django-encryption-suite[gcp-tink]'
  ```

> If you build a container image, make sure the build actually installs the
> `gcp-tink` dependency group. A build that installs only the base or `gcp`
> group will start, then fail at the first KMS call with an import error for
> Tink's GCP integration.

See [Getting started with GCP Cloud KMS](getting-started-gcp.md#a-note-on-key-rings)
for key-ring guidance (rings and keys cannot be deleted; pick the location
nearest your runtime; reuse one ring per environment per location).

---

## Configure `ENCRYPTION`

The Tink adapter slots into any of the four KEK / provisioning combinations
described in
[the GCP guide](getting-started-gcp.md#decision-1--shared-vs-per-silo-kek).
The only changes versus those snippets are:

- `ADAPTER` → the Tink path, and
- **omit `CREDENTIAL_STRATEGY` from `OPTIONS`** (the Tink adapter ignores
  it — it is ADC-only).

Everything else — `GCP_PROJECT_ID`, `GCP_KMS_LOCATION`, `GCP_KMS_KEY_RING`, the
KEK template / shared id, the provisioner block, the IAM bindings — is identical.

The example below is **per-silo KEK with auto-provisioning** (Combination
C: each tenant gets its own CryptoKey, created on first encrypt), the most
common multi-tenant setup:

```python
ENCRYPTION = {
    "KEY_SETS": {"default": {"silo": "...", "key_store": "gcp"}},  # whatever you use
    "KMS_KEY_STORES": {
        "gcp": {
            "ADAPTER": "encryption_suite.adapters.key_stores.gcp_tink.GcpTinkKmsAdapter",
            "OPTIONS": {
                "GCP_PROJECT_ID": "my-project",
                "GCP_KMS_LOCATION": "us-east4",
                "GCP_KMS_KEY_RING": "encryption_suite",
                # No CREDENTIAL_STRATEGY — GcpTinkKmsAdapter is ADC-only.
                "KEK_TEMPLATE": "encryption_suite-{silo_uid}",
            },
            "KEK_STRATEGY_ADAPTER": "encryption_suite.adapters.keks.PerSiloKekStrategy",

            "KEK_PROVISIONER_ADAPTER": "encryption_suite.adapters.keks.GcpKekProvisioner",
            "KEK_PROVISIONER_OPTIONS": {
                "GCP_PROJECT_ID": "my-project",
                "GCP_KMS_LOCATION": "us-east4",
                "GCP_KMS_KEY_RING": "encryption_suite",
                # CREDENTIAL_STRATEGY defaults to "adc" — keyless on a GCP runtime.
                "PURPOSE": "ENCRYPT_DECRYPT",       # default
                "ALGORITHM": "GOOGLE_SYMMETRIC_ENCRYPTION",
                "PROTECTION_LEVEL": "SOFTWARE",     # or "HSM"
                "KEK_ROTATION_PERIOD_DAYS": 90,
                "TAGS": {"app": "encryption_suite"},
            },
        },
    },
}
```

`KEK_TEMPLATE` and `SHARED_KEK_ID` are CryptoKey **names** within the ring, not
full resource paths. The adapter combines them with `GCP_PROJECT_ID`,
`GCP_KMS_LOCATION`, and `GCP_KMS_KEY_RING` to build the full path at request
time. Silo UIDs are sanitized into GCP's allowed name set with a bijective
encoding before substitution (e.g. `team-2` matches GCP's name set and is used
unchanged, so `encryption_suite-{silo_uid}` resolves to `encryption_suite-team-2`); see
[the GCP guide](getting-started-gcp.md#step-1-pick-a-naming-convention) for the
details.

For shared-KEK or manual-provisioning variants, follow the corresponding
combination in the GCP guide and apply the same two changes (Tink `ADAPTER`,
no `CREDENTIAL_STRATEGY`).

---

## Grant the runtime service account access

These bindings are identical to the `GcpKmsAdapter` case — the adapter choice
does not change which Cloud KMS permissions the identity needs. For Combination
C (per-silo + auto-provision), the host's service account needs two grants
on the **ring**: encrypt/decrypt on the keys, plus create/read so the
provisioner can make new keys.

```bash
SA_EMAIL="my-runtime-sa@my-project.iam.gserviceaccount.com"

# Day-to-day: encrypt/decrypt every key in the ring (current and future).
gcloud kms keyrings add-iam-policy-binding encryption_suite \
  --location=us-east4 \
  --member="serviceAccount:${SA_EMAIL}" \
  --role="roles/cloudkms.cryptoKeyEncrypterDecrypter" \
  --project=my-project

# Auto-provisioning: create new keys + read existing ones (idempotency probe).
# A custom role with exactly cloudkms.cryptoKeys.create + .get is tighter than
# the broad roles/cloudkms.admin; bind whichever your policy allows on the ring.
gcloud kms keyrings add-iam-policy-binding encryption_suite \
  --location=us-east4 \
  --member="serviceAccount:${SA_EMAIL}" \
  --role="projects/my-project/roles/encryption_suiteKekProvisioner" \
  --project=my-project
```

If you provision keys outside this application (manual / Terraform), drop the second grant
and use `NullKekProvisioner` instead — see
[Combination B](getting-started-gcp.md#combination-b--per-silo-kek-manual-provisioning).

The custom-role definition and the shared-KEK / manual variants are in
[Combination C, Step 2](getting-started-gcp.md#step-2-grant-the-application-service-account-broader-access).

---

## Verify it works

After deploying with the config above:

1. Exercise an encrypt — sign in and create a record on an encrypted model for a
   new silo (tenant/team).
2. Watch the application logs. On first encrypt for a silo you should see
   the engine auto-provision its keyset, then a successful provisioner call —
   for example:

   ```
   A data key was created on the silo's first encryption. event=created reason=first_encryption silo="team-2" purpose=field kek="…"
   ```

   with **no** following `403`.
3. In the Cloud KMS console (or `gcloud kms keys list --keyring=encryption_suite
   --location=us-east4`), confirm a new CryptoKey `ck-<sanitized_uid>` (e.g.
   `encryption_suite-team-2`) appears in the ring — proof the provisioner ran under ADC with
   no credential wiring.
4. Read the record back; the value should decrypt cleanly.

The Django admin **Reconcile Keys** page shows, per silo, the resolved
CryptoKey and whether its data encryption keys exist — the same operator
workflow as for `GcpKmsAdapter`. See
[Reconcile Keys page](admin-panel.md#reconcile-keys-page).

Key deletion, KMS-side reconcile and provider state checks all behave exactly as
they do for `GcpKmsAdapter`: they belong to the shared `GcpKekProvisioner`, and
this adapter records the same full resource path on the row, so nothing about
them is Tink-specific. See
[Deleting a key encryption key](getting-started-gcp.md#deleting-a-key-encryption-key).

---

## Failure modes specific to this adapter

Most failure modes are shared with `GcpKmsAdapter` — see
[Failure modes](getting-started-gcp.md#failure-modes-and-what-they-look-like).
Two are worth calling out for the Tink path:

### Silo keys still on the env key store

If new silo keys land on the env store in production, `KEY_SETS` still gives
the `default` key set that store as its `key_store`: the settings module that defines the Tink block is
not the one in effect. Confirm that `DJANGO_SETTINGS_MODULE` points at it.

### KEK provisioner `403 Forbidden` against the wrong location

If the resolved key-ring path uses the wrong location, `GcpKekProvisioner` calls
a ring the service account has no access to (or that does not exist) and the
provision fails with a bare `HTTP Error 403: Forbidden`:

```
KEK provisioner 'GcpKekProvisioner(ring=projects/my-project/locations/global/keyRings/encryption_suite)'
failed to ensure KEK 'encryption_suite-team-2' for silo 'team-2': HTTP Error 403: Forbidden
```

`GCP_KMS_LOCATION` defaults to `global`. If you intended a regional ring (e.g.
`us-east4`) and see `locations/global` in the error, the location did not reach
the running process — verify it is set in both `OPTIONS` and
`KEK_PROVISIONER_OPTIONS`, and that your IAM bindings are on the ring in that
same location. The adapter does not infer location; a key in
`us-east4/encryption_suite` is invisible to a client targeting `global/encryption_suite`.

---

## Related reading

- [Getting started with GCP Cloud KMS](getting-started-gcp.md) — the full
  combination matrix, key-ring guidance, the Reconcile Keys admin page, IAM details, and
  shared failure modes. The companion to this page.
- [KMS adapters](kms-adapters.md) — adapter reference for GCP and other
  providers.
- [KEK strategies](kek-strategies.md) and
  [KEK provisioning](kek-provisioning.md) — strategy / provisioner reference.
- [Key rotation](key-rotation.md) — rotating KEKs and re-encrypting (including
  switching between the `gcp` and `gcp-tink` adapters).
- [Configuration reference](configuration.md) — every `ENCRYPTION` setting.
