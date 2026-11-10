# Crypto backends

The **crypto backend** is the data-plane engine that performs the actual local
encryption: it generates the data-encryption key (DEK) and does the field (AEAD)
and file (streaming AEAD) encrypt/decrypt. It is separate from the **KMS**, which
only wraps the DEK. You choose it with two settings (the default is shown):

```python
ENCRYPTION = {
    # …
    "CRYPTO_BACKEND": "encryption_suite.adapters.crypto_backends.cryptography.CryptographyCryptoEngine",
    "CRYPTO_BACKEND_OPTIONS": {},  # backend-specific (see below)
}
```

Two backends ship:

- **pyca-cryptography** (default) — uses pyca-cryptography (the `cryptography`
  PyPI package, from the Python Cryptographic Authority), a **core dependency**,
  so it works on a bare `pip install django-encryption-suite` with no extra. Adds
  ChaCha20-Poly1305 (fast in software without AES-NI) and AES-GCM-SIV, with a
  freely tunable file segment size.
- **Tink** (the `[tink]` extra) — uses Google Tink. Offers AES-128-GCM and
  AES-256-EAX beside AES-256-GCM, a choice of streaming segment sizes, and a
  Tink ecosystem that includes KMS adapters for major clouds (see
  [Choosing](#choosing-a-backend-and-algorithm)).

## ⚠️ Backend incompatibility

**One backend cannot read another backend's data, even with the same algorithm
and the same KEK.** "Same algorithm" (e.g. AES-256-GCM) is not the same as "same
wire format." The two backends differ at three independent layers, any one of
which prevents one from reading the other's data:

1. **DEK serialization** — Tink stores a serialized Tink *keyset* (protobuf);
   pyca-cryptography stores a compact `version | aead_id | key` blob.
2. **Field ciphertext framing** — Tink prepends a 5-byte key-ID prefix then its
   IV/ciphertext/tag; pyca-cryptography writes `version | nonce | ciphertext`.
3. **File/stream framing** — header contents, HKDF `info`, and the per-segment
   nonce encoding are each library's own.

Every data key row records the backend that produced it, and the package reads
each row with that backend, whatever `CRYPTO_BACKEND` says now. `CRYPTO_BACKEND`
chooses the backend for new keys only. A row whose recorded backend cannot be
built here (its dependency is not installed), or whose keyset does not parse
under it, raises `CryptoBackendMismatchError` rather than returning garbage.

### Switching backends

1. Install both backends' dependencies, so the old rows stay readable.
2. Change `CRYPTO_BACKEND` and deploy. New silos get keys under the new backend;
   existing silos keep reading under the old one.
3. Run `reencrypt_data`. It rotates each silo's data key onto the new backend,
   re-encrypting its fields and files on the way, and its output names the move.
   The rotation fences each silo while it runs — see
   [Rotating a data encryption key](key-rotation.md#rotating-a-data-encryption-key).
4. Run `reencrypt_data --key-set system` to move the system silo's keys, which
   protect the [system-wide silo's columns](system-wide-silos.md). The
   default pass rotates only the silos' keys, and `--key-set all` runs every key set.
5. Remove the old backend's dependency only after every silo, the system silo
   included, has moved.

A change of options alone, such as a new `AEAD`, follows steps 2 to 4 with
`--only-outdated`, which rotates only the keys generated under the old options.
See [The recorded algorithm](#the-recorded-algorithm).

## Tink backend

```bash
pip install 'django-encryption-suite[tink]'
```

`CRYPTO_BACKEND_OPTIONS`:

| Option | Default | Values |
| --- | --- | --- |
| `AEAD_KEY_TEMPLATE` | `"AES256_GCM"` | `AES256_GCM`, `AES128_GCM`, `AES256_EAX` — field encryption |
| `STREAMING_AEAD_KEY_TEMPLATE` | `"AES256_GCM_HKDF_4KB"` | `AES256_GCM_HKDF_4KB`, `AES256_GCM_HKDF_1MB`, `AES128_GCM_HKDF_4KB` — file encryption |

The file **segment size** is baked into the streaming template (the `4KB` / `1MB`
suffix) and therefore into the keyset — it is a property of the key, fixed when
the key is created. Changing it only affects keys generated afterwards; existing
files keep decrypting under their own keyset.

## pyca-cryptography backend (default)

This backend needs no extra — `cryptography` is a core dependency, so it is active
out of the box (`pip install django-encryption-suite`). It is configured with:

```python
ENCRYPTION = {
    # …
    "CRYPTO_BACKEND": "encryption_suite.adapters.crypto_backends.cryptography.CryptographyCryptoEngine",
    "CRYPTO_BACKEND_OPTIONS": {"AEAD": "AES256_GCM", "SEGMENT_SIZE": 4096},
}
```

`CRYPTO_BACKEND_OPTIONS`:

| Option | Default | Notes |
| --- | --- | --- |
| `AEAD` | `"AES256_GCM"` | One algorithm for **both** fields and files (no field/file split): `AES256_GCM`, `CHACHA20_POLY1305`, `AES256_GCM_SIV` |
| `SEGMENT_SIZE` | `4096` | File streaming segment size in bytes (a performance knob, not an algorithm) |

Algorithm guidance:

- **`AES256_GCM`** — AES-NI-fast; matches the Tink default.
- **`CHACHA20_POLY1305`** — fast in software *without* AES-NI hardware.
- **`AES256_GCM_SIV`** — nonce-misuse resistant. It raises the limit on
  encryptions per key from about 2^32 to about 2^50 messages; see
  [Encryption count per data key](security.md#encryption-count-per-data-key).
  For files
  it is redundant (the streaming format already guarantees unique nonces) but
  harmless, and offered for a consistent menu.

### Per-file segment size

Unlike Tink, the pyca-cryptography backend stores the segment size **in each
file's header**, not in the key. So `SEGMENT_SIZE` is a live performance dial:

- Change it whenever you like. New uploads use the new size immediately, even for
  silos whose key already exists.
- Existing files are always decrypted under **the size they were written with**
  (read from their header) — changing the setting never makes old files
  unreadable.
- To change an *existing* file's segment size, re-upload it.

Smaller segments (e.g. 4 KB) lower latency-to-first-byte and memory per stream;
larger segments (e.g. 1 MB) reduce per-segment tag overhead for big files.

## The recorded algorithm

Every data key row records, in `algorithm`, what its keyset was generated for,
and every ledger event on the key copies it (see
[key lifecycle events](key-lifecycle-events.md#data-key-protection)). The
value is taken from the backend at generation, never read back out of the key
material:

| Backend | Field key | File key |
|---|---|---|
| pyca-cryptography | the `AEAD` option: `AES256_GCM`, `CHACHA20_POLY1305`, `AES256_GCM_SIV` | the same name with `_STREAM` appended, for the STREAM construction over that AEAD |
| Tink | the `AEAD_KEY_TEMPLATE` option (e.g. `AES256_GCM`) | the `STREAMING_AEAD_KEY_TEMPLATE` option (e.g. `AES256_GCM_HKDF_4KB`) |

A blind index key records `HMAC_SHA256` and no backend. pyca-cryptography's
segment size is not part of the value: it is written into each file, not the
key. Tink's streaming template names its segment size, so there it is.

Changing an option changes what new keys record; existing keys keep the value
they were generated with until `reencrypt_data` rotates them.
[`reencrypt_data --only-outdated`](management-commands.md#reencrypt_data) rotates
only the keys whose recorded backend or algorithm differs from what the settings
generate now, and skips the rest as current. The
[`crypto_inventory`](management-commands.md#crypto_inventory) command shows both
side by side.

## Choosing a backend and algorithm

There is no automatic winner — choose deliberately:

- **Tink** is Google's standard crypto library, battle-tested across Google
  products (Google Pay, Firebase, Android, and others). It offers AES-128-GCM and
  AES-256-EAX for fields, and the Tink ecosystem includes KMS adapters for the major
  clouds: if you deploy on Google Cloud or AWS, the Tink-based KMS adapters wrap
  DEKs through Cloud KMS / AWS KMS — see
  [Getting started: GCP KMS via Tink](getting-started-gcp-tink.md) and
  [Getting started: AWS KMS via Tink](getting-started-aws-tink.md).
- **pyca-cryptography** is built on the `cryptography` package — one of the most
  widely used Python libraries (a top-tier PyPI download), so it is frequently
  *already present* in a Django project's dependency tree (common TLS, JWT, and
  WebAuthn libraries pull it in), meaning no new heavyweight dependency. It adds
  ChaCha20-Poly1305 (fast in software without AES-NI hardware), AES-GCM-SIV
  (nonce-misuse resistant), and a freely tunable file segment size.
- **Regulatory or policy constraints often drive this choice.** Your compliance
  regime (FIPS, sector rules, internal policy) may approve only certain
  algorithms or implementations; the approved set — not raw performance — is
  usually the deciding factor. Confirm what's permitted before choosing.

And remember the choice is permanent for a given deployment's data (see above).
