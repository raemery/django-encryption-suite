# Switching what protects your data

Each layer of the encryption changes through one setting and one command. Change
the setting and deploy, and new keys follow it; run the command, and existing
keys and data move onto it.

| To change | Change this | Then run | What moves |
|---|---|---|---|
| [The KMS](key-rotation.md#moving-to-another-kms) | `KMS_KEY_STORES` (add a block), `KEY_SETS` | `reencrypt_keys [--provision]` | The data keys' wrapping, onto the new KMS |
| [The key encryption key](key-rotation.md#the-full-rotation-workflow), by provider rotation | nothing here: rotate at the provider | `reencrypt_keys` | The data keys' wrapping, onto the current version |
| [The env key store's key](key-rotation.md#rotating-a-system-key) | `ENV_KEY_STORES` (add a version) | `reencrypt_keys --key-set system` | The system silo's data keys' wrapping, onto the highest version |
| [The crypto backend](crypto-backends.md#switching-backends) | `CRYPTO_BACKEND` (with both backends installed) | `reencrypt_data`, then `reencrypt_data --key-set system` | The data keys, and the data under them |
| [The algorithm or other backend options](crypto-backends.md#the-recorded-algorithm) | `CRYPTO_BACKEND_OPTIONS` | `reencrypt_data --only-outdated` | The data keys, and the data under them |
| [A silo's data key](key-rotation.md#rotating-a-data-encryption-key), at the end of its cryptoperiod | nothing | `reencrypt_data` | The data keys, and the data under them |
| [A blind index key](key-rotation.md#rotating-a-blind-index-key) | nothing | `reencrypt_data --purpose index` | The index keys, and the digests under them |
| [The system silo's data keys](key-rotation.md#the-data-keys-a-sign-in-outage) | nothing | `reencrypt_data --key-set system` | The system silo's data keys, and the `key_set="system"` data under them |
| [The storage backend](managing-encrypted-files.md#moving-to-another-storage-backend) | `STORAGES` | nothing: copy the files with the provider's tools | The file objects, unchanged |

`reencrypt_keys` re-wraps the data keys and leaves the data alone, so it fences
nothing and needs no outage. `reencrypt_data` replaces the data keys and
re-encrypts the data under them, and it fences each silo's data for one purpose
at a time while it runs. See [Blocked operations](key-rotation.md#blocked-operations).
The system silo's fence covers sign-in, so run `reencrypt_data --key-set system` in a
maintenance window.

Old data stays readable through every switch until it moves. Each data key row
records its key store, key version, crypto backend and algorithm, and every read uses
what the row records. The settings decide new keys only.
