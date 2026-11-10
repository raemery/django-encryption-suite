# KMS internals

This document explains what a Key Management System (KMS) actually does when
django-encryption-suite calls it — what data is sent on encryption, what data is
sent on decryption, and how the KMS internally maps a key resource name to the
actual key material.

If you are new to envelope encryption, read [concepts.md](concepts.md) first
for the high-level KEK / DEK model.

---

## Encryption payload

When the engine generates a new DEK for a silo and needs to
encrypt it for storage, it calls
`kms_adapter.encrypt_key(plaintext, silo_uid)`. The adapter in turn
makes an API call to the KMS provider.

The adapter delegates the choice of key to a [KEK strategy](kek-strategies.md),
which turns the silo UID into a provider-specific KEK identifier. The built-in
`PerSiloKekStrategy` maps one silo to one KEK via `KEK_TEMPLATE` or `KEK_MAP`,
and `SharedKekStrategy` maps every silo to one KEK. Each encryption request
carries four things:

1. **The caller's identity**, proven by the request signature or bearer token
   attached by the credential strategy. The KMS uses it for IAM authorization
   and audit logging.
2. **The KEK resource name** — an ARN, key path, URL, or OCID. This tells the
   KMS which key to use.
3. **The plaintext DEK bytes** — the newly generated DEK, sent over TLS.
4. **The silo UID as associated data**, on every adapter whose provider accepts
   it: AWS KMS as `EncryptionContext`, OCI Vault as `associated_data`, and GCP
   Cloud KMS, Azure Key Vault, IBM Key Protect, Fly.io and the Tink adapters as
   AAD bytes. The KMS binds it to the ciphertext and refuses a decrypt that
   supplies a different value, so a wrapped DEK cannot be opened on behalf of
   another silo. The HashiCorp Vault and Infisical adapters send no associated
   data, which is why they refuse `SharedKekStrategy`.

On Azure Key Vault the caller can also pin a specific key version
(`AZURE_KEY_VERSION`); without it, the adapter wraps under the current version.

The KMS returns one thing: the **ciphertext blob**. This blob contains
provider-specific metadata in its header — most importantly, the version of
the KEK that was used to encrypt. That metadata is what makes decryption
version-aware without the caller having to remember which version was used.

The application stores the ciphertext blob in the `encrypted_keyset` column of
the `DataEncryptionKey` record, alongside the KEK resource name and the
provider identifier. The plaintext DEK bytes are discarded (see
[security.md](security.md) for memory-lifetime details).

---

## Decryption payload

When a user accesses an encrypted field, the engine needs to decrypt the
stored DEK. This happens inside `EncryptionEngine._decrypt_to_aead`:

1. The engine looks up the `DataEncryptionKey` row in the application
   database by `silo_uid`.
2. The row holds `encrypted_keyset` (the encrypted DEK) and a reference to the
   `KeyEncryptionKey` row, which carries the key's identifier and KMS.
3. The engine builds a `KmsMetadata` object from those columns and calls
   `kms_adapter.decrypt_key(encrypted_keyset, metadata)`.

The adapter sends four things to the KMS:

1. **The caller's identity** (same as encryption — request signature or
   bearer token).
2. **The KEK resource name** from the metadata.
3. **The ciphertext blob** (`encrypted_keyset`).
4. **The silo UID as associated data**, on the same adapters as encryption. A
   value that differs from the one bound at encryption fails the decrypt.

The KMS returns the **plaintext DEK bytes** over TLS. The engine parses those
bytes into a crypto-backend primitive, caches the primitive for `DEK_CACHE_TTL`, and
uses it to decrypt the requested field.

### Key targeting

Two complementary mechanisms ensure decryption targets the correct key:

1. **The app specifies the KEK.** The referenced key encryption key names the exact KEK the
   KMS should use. The KMS does not need to guess.
2. **The ciphertext is bound to the KEK.** AWS KMS, GCP Cloud KMS, and most
   other providers embed key-version metadata in the ciphertext header. If the
   app accidentally supplied a different `KeyId` pointing at an unrelated key,
   the KMS would fail the decrypt — the blob only decrypts under the key that
   originally encrypted it.

AWS in particular allows the caller to omit `KeyId` entirely on `Decrypt`,
because the ciphertext header is sufficient. django-encryption-suite still passes
it for clarity in the audit log and as a defense-in-depth check.

### What the KMS audit log shows

A KMS audit log records the caller, the key and the time of each call. Where the
provider logs associated data — AWS CloudTrail records `EncryptionContext`, for
example — it records the silo UID too, so treat the UID as visible to whoever
reads that log. A KMS call happens once per `DEK_CACHE_TTL` per process, not
once per field read, so the log does not show individual reads. For a record of
each decrypt with its `silo_uid`, enable `LOG_DECRYPTS`.

The binding between a silo UID and its KEK is stored in the application database.
If a row's key reference were pointed at another tenant's KEK, and the app's IAM
role could use both, the decrypt fails: the ciphertext only decrypts under the
key that produced it. If the ciphertext were swapped in too, the associated data
catches it on the adapters that send it, because that ciphertext is bound to the
other tenant's silo UID. On the HashiCorp Vault and Infisical adapters, which
send no associated data, keeping each silo on its own KEK
(`PerSiloKekStrategy`) and protecting the database is what holds the mapping.

---

## Resource name mapping

A key encryption key row holds an **identifier**, not key material. The
KMS provider maintains its own internal mapping from identifier to the actual
cryptographic key inside its HSM or secure enclave. The details differ per
provider, but the overall shape is the same everywhere.

### AWS KMS

Resource names look like these:

- ARN: `arn:aws:kms:us-east-1:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab`
- Alias: `alias/encryption_suite-team-42`
- Bare key ID: `1234abcd-12ab-34cd-56ef-1234567890ab`

Internal flow on `Decrypt`:

1. **Identifier resolution.** If the caller supplied an alias, AWS resolves it
   via the alias table to the target key ID. Aliases are mutable pointers
   that can be repointed to a different key without callers noticing.
2. **Key lookup.** The key ID is looked up in the KMS's internal metadata
   store. This yields the list of key versions, the key state
   (enabled/disabled/pending deletion), the region, the account, and the HSM
   domain where the actual material is held.
3. **IAM check.** KMS evaluates the caller's IAM policy, the key's resource
   policy, and any grants. Unauthorized calls fail here before any key
   material is touched.
4. **Key material retrieval.** The ciphertext header contains the key version
   used to encrypt. KMS fetches that version's material from the HSM and
   performs the decrypt *inside the HSM*. The plaintext DEK is returned over
   TLS.

### GCP Cloud KMS

Resource names take this format:
`projects/P/locations/L/keyRings/R/cryptoKeys/K` (optionally suffixed with
`/cryptoKeyVersions/N` to pin a version).

Internal flow:

1. **URL routing.** The resource name is the URL path of the API call, so
   GCP's front-end routes the request directly to the key ring's backend in
   the specified location.
2. **Key lookup.** Within the key ring, `cryptoKeys/K` names a logical key
   with one or more versions. Each version has its own key material.
3. **IAM check** against the resource's IAM policy (inherited from
   project/folder/org plus any direct bindings).
4. **Version selection.** For `encrypt`, GCP uses the key's *primary*
   version, which rotation moves forward. For `decrypt`, GCP parses the
   ciphertext blob for the version number that was used to encrypt, and uses
   that version's material regardless of which version is currently primary.
5. **Crypto operation** happens inside the KMS service's HSM (for HSM-backed
   keys) or its software-backed secure store. Plaintext is returned over TLS.

### Azure Key Vault

Resource names include the vault URL, key name, and an optional version:

- `https://myvault.vault.azure.net/keys/my-key` — latest version
- `https://myvault.vault.azure.net/keys/my-key/abc123...` — pinned version

The internal flow is the same shape as the above: the URL routes to the
vault, the vault looks up the key by name, RBAC is evaluated, the version is
resolved (from the URL or from the ciphertext envelope), and the crypto
operation runs in an HSM or in a software-backed store depending on how the
key was created.

### HashiCorp Vault

The resource name is a key name within a Transit mount, for example `encryption_suite-team-42`.

Unlike cloud KMS providers, Vault stores key material itself (inside its
encrypted storage backend, sealed with the Vault unseal key — no external HSM
unless explicitly configured). On `decrypt`:

1. Vault parses the ciphertext, which is prefixed like `vault:v2:<base64>`.
   The `v2` segment encodes the key version.
2. Vault looks up the named key in its storage backend.
3. ACL check runs against the caller's token policies.
4. Vault decrypts with the version indicated by the ciphertext prefix.

---

## The common pattern

Every KMS provider does essentially the same thing:

```
caller identity + resource name + ciphertext blob
                         ↓
        [name → logical key → version → material]
                         ↓
               IAM / policy check
                         ↓
             crypto operation in HSM
                         ↓
                    plaintext out
```

Three properties fall out of this design:

- **The resource name is a lookup key**, not the key itself. It's just a name
  that the KMS resolves internally against its own metadata store.
- **The ciphertext blob carries the version** used to encrypt. This is why
  the KMS can still decrypt data after the key has been rotated — old
  versions are retained and used when indicated by the ciphertext header.
- **Key material never appears in any of the lookups** visible to the caller.
  The KMS only retrieves it from the HSM or secure enclave at the moment of
  performing the crypto operation, and the plaintext key is never transmitted
  on the wire in either direction.

This is also why rotation is transparent. After rotating the KEK, old
ciphertexts still decrypt (old version retained), new encryptions use the new
primary version. The key's resource name in your database stays the same —
only what it resolves to inside the KMS changes. Running
`reencrypt_keys` after a rotation causes the application to re-encrypt each
stored DEK under the new primary version, which lets you eventually disable
or destroy the old version.
