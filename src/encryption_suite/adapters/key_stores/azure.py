"""
Azure Key Vault adapter (wraps DEKs with a symmetric AES key).

Requires the ``azure`` extra: ``pip install django-encryption-suite[azure]``

Each silo gets its own Key Vault key, resolved via ``KEK_TEMPLATE``
or ``KEK_MAP`` in ``OPTIONS``.  The template value is the key **name**
within the vault (e.g. ``"encryption_suite-{silo_uid}"``).

Credential strategy is selected via OPTIONS['CREDENTIAL_STRATEGY']:
  "managed_identity"   (default) — AzureManagedIdentityStrategy
  "client_secret"                — AzureClientSecretStrategy
  "oidc"                         — AzureWorkloadIdentityFederationStrategy
                                   (OIDC token source via the required
                                   OIDC_SOURCE option)

See ``adapters.credentials.azure`` and ``adapters.credentials.oidc_sources``
for strategy details and required options.

Required OPTIONS keys (all strategies):
  AZURE_VAULT_ENDPOINT  : str   e.g. "https://my-vault.vault.azure.net"
  KEK_TEMPLATE         : str   e.g. "encryption_suite-{silo_uid}"
                                 (or KEK_MAP for explicit mapping)
  AZURE_KEY_VERSION    : str   (optional) pin wrapping to one key version
                               instead of whichever version the vault
                               currently reports. Unwrapping always uses the
                               version recorded on the row.
  KEY_VERSION_TTL_SECONDS : int  (optional, default 300) how long the current
                               version is reused before it is looked up again,
                               so a rotation reaches long-running processes.

**Symmetric keys only.** This adapter wraps with AES-256-GCM (``A256GCM``)
against an ``oct-HSM`` key, which requires a **Premium** vault — Standard has no
symmetric key type. Symmetric key support in vaults is a Microsoft **preview**
feature: no SLA, and Microsoft does not recommend it for production workloads.
Weigh that before choosing this adapter.

AES-GCM is used rather than the semantically tidier AES-KW key wrap because only
AES-GCM accepts associated data. That binding — the silo UID, mixed into every
wrap — is what stops a wrapped DEK moved between silos in the database from
decrypting, and it is why this adapter works with either KEK strategy.

Key Vault returns the ``iv`` and authentication ``tag`` alongside the ciphertext
and needs all three back to decrypt, so this adapter frames them into the single
stored blob (see :func:`_frame` / :func:`_unframe`). That framing is a permanent
property of the stored data: a deployment cannot switch algorithms under existing
rows.

**Rotation is supported.** Key Vault addresses every cryptographic operation by
key *version*, and an AES ciphertext carries no pointer back to the version that
produced it — unlike an AWS or GCP ciphertext, which the provider resolves
itself. So the version that wrapped a DEK is recorded on that row's own
``kek_key_version`` field, and unwrapping addresses it.
Adding a version (``az keyvault key rotate``, or a rotation policy) therefore
leaves existing DEKs readable; new wraps use the new version, and
``manage.py reencrypt_keys`` moves the old ones over.
"""

from __future__ import annotations

import threading
import time

from ..._logging import get_logger
from ...exceptions import log_and_raise_configuration_error
from ..credentials.azure import (
    AzureClientSecretStrategy,
    AzureManagedIdentityStrategy,
    AzureWorkloadIdentityFederationStrategy,
)
from ..credentials.oidc_sources import build_oidc_source
from ..keks.sanitization import ALNUM_HYPHEN
from .base import AbstractKmsAdapter, KmsMetadata

logger = get_logger(__name__)

_PROVIDER = "azure"

# Wrapped-DEK frame version. Key Vault hands back iv/tag/ciphertext as three
# separate values and needs all three to decrypt, so they travel together in the
# one stored blob. The leading byte lets a later format be told apart from this
# one instead of being guessed at from lengths.
_FRAME_VERSION = 1

_DEFAULT_KEY_VERSION_TTL_SECONDS = 300.0


def _frame(iv: bytes, tag: bytes, ciphertext: bytes) -> bytes:
    """Pack the three parts of an AES-GCM result into one stored blob."""
    if len(iv) > 255 or len(tag) > 255:
        raise ValueError("Key Vault returned an iv or authentication tag longer than the frame allows.")
    return bytes([_FRAME_VERSION, len(iv)]) + iv + bytes([len(tag)]) + tag + ciphertext


def _unframe(blob: bytes) -> tuple[bytes, bytes, bytes]:
    """Split a stored blob back into ``(iv, tag, ciphertext)``.

    Raises ``ValueError`` on anything that is not a frame this adapter wrote —
    a truncated row, or one wrapped by a different algorithm. The engine funnels
    that into a typed decrypt error rather than handing Key Vault bytes it would
    reject with a less legible message.
    """
    if len(blob) < 3 or blob[0] != _FRAME_VERSION:
        raise ValueError(
            f"Wrapped DEK is not an Azure frame version {_FRAME_VERSION} blob. It was written by a "
            "different adapter or algorithm, which cannot unwrap it."
        )
    iv_length = blob[1]
    iv_end = 2 + iv_length
    if len(blob) < iv_end + 1:
        raise ValueError("Wrapped DEK frame is truncated: the iv extends past the end of the value.")
    tag_length = blob[iv_end]
    tag_end = iv_end + 1 + tag_length
    if len(blob) <= tag_end:
        raise ValueError("Wrapped DEK frame is truncated: no ciphertext follows the authentication tag.")
    return blob[2:iv_end], blob[iv_end + 1 : tag_end], blob[tag_end:]


class AzureKeyVaultAdapter(AbstractKmsAdapter):
    """
    Azure Key Vault Keys adapter using AES-256-GCM to encrypt DEKs.

    Delegates authentication entirely to the configured credential strategy.
    ``CryptographyClient`` instances are cached per key version.
    """

    kms_provider = _PROVIDER
    _INSTANCE_OPTION_KEYS = ("AZURE_VAULT_ENDPOINT",)
    _REQUIRED_OPTION_KEYS = ("AZURE_VAULT_ENDPOINT",)

    _HONORS_TLS_OPTIONS = False
    _TLS_SDK_HINT = (
        "The Azure SDK uses its own HTTP transport. To trust a private CA "
        "for Key Vault calls, set REQUESTS_CA_BUNDLE=/path/to/ca-bundle.pem "
        "and SSL_CERT_FILE=/path/to/ca-bundle.pem on the process."
    )

    # Azure Key Vault key names allow letters, digits, and hyphens only (no underscore),
    # capped at 127 characters by the Key Vault REST API.
    _UID_ALLOWED_CHARS = ALNUM_HYPHEN
    _UID_ESCAPE_CHAR = "-"
    _UID_MAX_LENGTH = 127

    def __init__(self, options: dict, kek_strategy) -> None:
        super().__init__(options, kek_strategy)
        self._strategy = self._build_strategy(options)
        # Keyed by the versioned key id, so a client always speaks to exactly
        # one version: the current one for wrapping, whichever version a row
        # records for unwrapping.
        self._crypto_clients: dict[str, object] = {}
        # Current version per key name, with the time it was read. Reused for a
        # short window so a rotation reaches a long-running process without
        # paying a lookup on every wrap.
        self._current_versions: dict[str, tuple[str, float]] = {}
        self._lock = threading.Lock()

    @staticmethod
    def _build_strategy(options: dict):
        strategy_name = options.get("CREDENTIAL_STRATEGY", "managed_identity")
        if strategy_name == "managed_identity":
            return AzureManagedIdentityStrategy()
        elif strategy_name == "client_secret":
            return AzureClientSecretStrategy(options)
        elif strategy_name == "oidc":
            source_name = options.get("OIDC_SOURCE")
            if not source_name:
                log_and_raise_configuration_error(logger, "CREDENTIAL_STRATEGY='oidc' requires OIDC_SOURCE in OPTIONS.")
            source = build_oidc_source(source_name, options.get("OIDC_SOURCE_OPTIONS", {}))
            return AzureWorkloadIdentityFederationStrategy(options, source)
        else:
            log_and_raise_configuration_error(
                logger,
                f"Unknown CREDENTIAL_STRATEGY '{strategy_name}'. Valid options: managed_identity, client_secret, oidc",
            )

    # ------------------------------------------------------------------
    # Key identifiers
    # ------------------------------------------------------------------

    def _vault_url(self) -> str:
        return self.options["AZURE_VAULT_ENDPOINT"].rstrip("/")

    @classmethod
    def _split_key_id(cls, value: str) -> tuple[str, str]:
        """Split any form of key identifier into ``(name, version)``.

        Accepts the strategy's bare name, a version-free URI, and a versioned
        one. The version is ``""`` when the identifier does not carry one.
        """
        tail = value.rstrip("/")
        if "/keys/" in tail:
            tail = tail.rsplit("/keys/", 1)[-1]
        elif tail.startswith("keys/"):
            # The stored form: vault-relative, so there is no leading slash to
            # split on. Handled here rather than by the caller, because every
            # form a caller might hold has to land on the same bare name.
            tail = tail[len("keys/") :]
        else:
            return tail, ""
        parts = tail.split("/")
        return parts[0], parts[1] if len(parts) > 1 else ""

    @classmethod
    def _key_name(cls, value: str) -> str:
        """Return the bare key name from a bare name or any key URI form."""
        return cls._split_key_id(value)[0]

    def canonical_kek_name(self, kek_id: str) -> str:
        """Return the vault-relative identifier for *kek_id*: ``keys/<name>``.

        Vault-*relative*, like the AWS adapter's ``alias/…``: the vault comes
        from ``AZURE_VAULT_ENDPOINT`` rather than being repeated on every row, so
        moving a deployment to another vault does not rewrite its rows. The trade
        is that two vaults holding the same key names produce identical rows,
        where an AWS ARN would carry the region that tells them apart.

        Version-free, because the key encryption key's identity is the key rather
        than one rotation of it: deleting, listing and ownership all act on the
        key, and a version cannot be deleted or listed on its own. The version of
        the material that wrapped a given data encryption key is recorded on that
        row instead.

        Accepts a bare name, a relative form, or a full versioned URI, so the
        same transform applies to the owner prefix and stays a prefix of every
        name it produces.
        """
        return f"keys/{self._key_name(kek_id)}"

    def _versioned_kek_name(self, key_name: str, version: str) -> str:
        return f"{self._vault_url()}/keys/{key_name}/{version}"

    # ------------------------------------------------------------------
    # Clients
    # ------------------------------------------------------------------

    @staticmethod
    def _import_crypto():
        try:
            from azure.keyvault.keys.crypto import CryptographyClient, EncryptionAlgorithm
        except ImportError as exc:
            raise RuntimeError(
                "azure-keyvault-keys is required for AzureKeyVaultAdapter. Install django-encryption-suite[azure]."
            ) from exc
        return CryptographyClient, EncryptionAlgorithm

    def _client_for(self, versioned_key_id: str):
        """Return a ``CryptographyClient`` bound to exactly *versioned_key_id*.

        Built from the identifier rather than a fetched key object: an
        ``oct-HSM`` key never releases its material, so every operation is a
        service call regardless, and this way unwrapping costs no extra lookup.
        """
        client = self._crypto_clients.get(versioned_key_id)
        if client is not None:
            return client
        CryptographyClient, _ = self._import_crypto()
        with self._lock:
            client = self._crypto_clients.get(versioned_key_id)
            if client is None:
                client = CryptographyClient(versioned_key_id, credential=self._strategy.get_credentials())
                self._crypto_clients[versioned_key_id] = client
        return client

    def _current_version(self, key_name: str) -> str:
        """Return the version Key Vault currently reports for *key_name*.

        Cached briefly rather than for the process lifetime: a rotation adds a
        version, and a worker that never looked again would keep wrapping under
        the old one indefinitely — leaving the rotation half-done in a way
        nothing surfaces. ``AZURE_KEY_VERSION`` pins it outright and skips the
        lookup.
        """
        pinned = self.options.get("AZURE_KEY_VERSION")
        if pinned:
            return pinned

        ttl = float(self.options.get("KEY_VERSION_TTL_SECONDS", _DEFAULT_KEY_VERSION_TTL_SECONDS))
        cached = self._current_versions.get(key_name)
        if cached is not None and (time.monotonic() - cached[1]) < ttl:
            return cached[0]

        try:
            from azure.keyvault.keys import KeyClient
        except ImportError as exc:
            raise RuntimeError(
                "azure-keyvault-keys is required for AzureKeyVaultAdapter. Install django-encryption-suite[azure]."
            ) from exc

        key_client = KeyClient(vault_url=self._vault_url(), credential=self._strategy.get_credentials())
        version = key_client.get_key(key_name).properties.version
        with self._lock:
            self._current_versions[key_name] = (version, time.monotonic())
        return version

    # ------------------------------------------------------------------
    # Wrap / unwrap
    # ------------------------------------------------------------------

    def current_kek_version(self, silo_ref: str) -> str:
        """The version a new wrap for *silo_ref* would use.

        Read through the same short-lived cache the wrap path uses, so asking
        does not cost a lookup per row when re-encrypting a whole deployment.
        """
        return self._current_version(self._resolve_kek_id(silo_ref))

    def encrypt_key(self, plaintext: bytes, silo_ref: str) -> tuple[bytes, KmsMetadata]:
        _, EncryptionAlgorithm = self._import_crypto()

        key_name = self._resolve_kek_id(silo_ref)
        version = self._current_version(key_name)
        versioned = self._versioned_kek_name(key_name, version)
        result = self._client_for(versioned).encrypt(
            EncryptionAlgorithm.a256_gcm,
            plaintext,
            additional_authenticated_data=self._wrap_aad(silo_ref),
        )
        return _frame(result.iv, result.tag, result.ciphertext), KmsMetadata(
            kek_resource_name=self.canonical_kek_name(key_name),
            kms_provider=_PROVIDER,
            # An AES ciphertext names no key version, so the row is the only
            # record of which material can unwrap it.
            kek_key_version=version,
        )

    def decrypt_key(
        self,
        ciphertext: bytes,
        metadata: KmsMetadata,
        silo_ref: str,
    ) -> bytes:
        _, EncryptionAlgorithm = self._import_crypto()

        iv, tag, wrapped = _unframe(ciphertext)
        # The row records the version that wrapped this DEK — an older one once
        # the key has been rotated, which is the whole point of recording it. A
        # row with no version (one written before the key was ever rotated, or a
        # KEK_MAP entry naming a bare key) falls back to the current version.
        key_name = self._key_name(metadata.kek_resource_name)
        version = metadata.kek_key_version or self._current_version(key_name)
        versioned = self._versioned_kek_name(key_name, version)

        result = self._client_for(versioned).decrypt(
            EncryptionAlgorithm.a256_gcm,
            wrapped,
            iv=iv,
            authentication_tag=tag,
            additional_authenticated_data=self._wrap_aad(silo_ref),
        )
        return result.plaintext

    def describe_kek(self) -> str:
        vault_url = self.options["AZURE_VAULT_ENDPOINT"]
        template = self.options.get("KEK_TEMPLATE", "")
        if template:
            return f"Azure Key Vault keys: {vault_url}/keys/{template}"
        return f"Azure Key Vault: {vault_url}"
