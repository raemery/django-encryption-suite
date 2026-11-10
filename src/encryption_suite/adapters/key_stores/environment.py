"""
Env key store adapter — one instance per ``ENV_KEY_STORES`` entry.

Wraps data keys with AES-256-GCM under raw 32-byte key material the project
supplies to the process through settings, through the ``cryptography`` library
directly. No crypto backend is involved: the wrap is the key store's, and tying it
to ``CRYPTO_BACKEND`` would make the material unportable across a change of that
setting.

One key encryption key for every silo under the store, named ``shared``
unless the entry says otherwise, versioned the way a provider that rotates behind
a stable name is. ``KEKS`` maps positive integer versions to base64 key material;
the highest version wraps new keys, and each data key row records the version
that wrapped it in ``kek_key_version`` so an unwrap picks the right material.
``reencrypt_keys`` moves rows onto the highest version, after which an older
version can be dropped.

The package does not know where the bytes come from: ``KEKS`` is a plain version
map, so the project's settings may read an environment variable, a mounted secret
file or a secret manager. The protection is the secrecy of that material. A key
encryption key is shared by every silo wrapped under it, never deleted by the
package, and rotated for all of them at once.

There is no ephemeral key. An empty or missing ``KEKS`` is a configuration error,
so a missing variable can never silently produce a new key that orphans what was
written under the old one.
"""

from __future__ import annotations

import base64
import binascii
import os

from ..._logging import get_logger
from ...exceptions import (
    GENERIC_ENCRYPT_DECRYPT_UNAVAILABLE_MESSAGE,
    KekNotProvisionedError,
    log_and_raise_configuration_error,
)
from .base import AbstractKmsAdapter, KmsMetadata

logger = get_logger(__name__)

_PROVIDER = "env"

#: Bytes of key material per version, and of the GCM nonce on each wrap.
ENV_KEK_BYTES = 32
_NONCE_BYTES = 12


def parse_env_keks(value, label: str) -> tuple[dict[int, bytes], str]:
    """Return ``(versions, problem)`` for the ``KEKS`` value of the store *label* names.

    *versions* maps each version to its decoded material; *problem* is an empty
    string when the value is well formed, or the operator sentence saying what is
    wrong with it. *label* is the setting path, such as
    ``ENCRYPTION['ENV_KEY_STORES']['login']['KEKS']``. Shared by the adapter's
    constructor and the deploy-time check, so the two cannot disagree on what a
    valid value is. An empty map is well formed here; whether that is acceptable
    is the caller's say.
    """
    if not isinstance(value, dict):
        return {}, f"{label} must be a dict of version to key material, got {type(value).__name__}."
    versions: dict[int, bytes] = {}
    for version, encoded in value.items():
        if isinstance(version, bool) or not isinstance(version, int) or version < 1:
            return {}, f"{label} version {version!r} is not a positive integer."
        try:
            material = base64.b64decode(encoded, validate=True)
        except (binascii.Error, TypeError, ValueError):
            material = b""
        if len(material) != ENV_KEK_BYTES:
            return {}, (
                f"{label} version {version} is not {ENV_KEK_BYTES} bytes of base64. "
                "Generate one with: openssl rand -base64 32"
            )
        versions[version] = material
    return versions, ""


class EnvKeyStoreAdapter(AbstractKmsAdapter):
    """Key store adapter for one ``ENV_KEY_STORES`` entry, keyed by its ``KEKS``."""

    kms_provider = _PROVIDER

    def __init__(self, options: dict, kek_strategy) -> None:
        super().__init__(options, kek_strategy)
        self._versions, problem = parse_env_keks(options.get("KEKS", {}), "ENCRYPTION['ENV_KEY_STORES'][...]['KEKS']")
        if problem:
            log_and_raise_configuration_error(logger, problem)
        if not self._versions:
            log_and_raise_configuration_error(
                logger,
                "ENCRYPTION['ENV_KEY_STORES'][...]['KEKS'] is empty. Set at least one version "
                "(openssl rand -base64 32); the package never generates key material.",
            )

    def _material_by_version(self) -> dict[int, bytes]:
        return self._versions

    def _aead(self, material: bytes):
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        return AESGCM(material)

    # ------------------------------------------------------------------
    # AbstractKmsAdapter implementation
    # ------------------------------------------------------------------

    def current_kek_version(self, silo_ref: str) -> str:
        return str(max(self._material_by_version()))

    def encrypt_key(self, plaintext: bytes, silo_ref: str) -> tuple[bytes, KmsMetadata]:
        versions = self._material_by_version()
        version = max(versions)
        nonce = os.urandom(_NONCE_BYTES)
        ciphertext = nonce + self._aead(versions[version]).encrypt(nonce, plaintext, self._wrap_aad(silo_ref))
        return ciphertext, KmsMetadata(
            kek_resource_name=self.resolve_kek_name(silo_ref),
            kms_provider=_PROVIDER,
            kek_key_version=str(version),
        )

    def decrypt_key(self, ciphertext: bytes, metadata: KmsMetadata, silo_ref: str) -> bytes:
        versions = self._material_by_version()
        recorded = metadata.kek_key_version
        material = versions.get(int(recorded)) if recorded.isdigit() else None
        if material is None:
            detail = (
                f'The data key row records env key store key encryption key version "{recorded}", which '
                f"the env key store's KEKS no longer holds (configured: "
                f"{', '.join(str(v) for v in sorted(versions))}). Restore that version to read the row."
            )
            logger.error(
                '%s error_code=%s silo="%s"',
                detail,
                KekNotProvisionedError.code,
                silo_ref,
            )
            raise KekNotProvisionedError(GENERIC_ENCRYPT_DECRYPT_UNAVAILABLE_MESSAGE, detail=detail)
        nonce, body = ciphertext[:_NONCE_BYTES], ciphertext[_NONCE_BYTES:]
        return self._aead(material).decrypt(nonce, body, self._wrap_aad(silo_ref))

    def describe_kek(self) -> str:
        return f"Env key store key encryption key (versions {', '.join(map(str, sorted(self._versions)))})"
