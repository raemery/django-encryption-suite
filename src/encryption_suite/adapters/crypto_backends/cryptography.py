"""pyca-cryptography crypto backend.

The default crypto backend, built on the pyca-cryptography library (the
``cryptography`` PyPI package, a core dependency). Field values use a one-shot
AEAD; files use the STREAM construction in :mod:`._stream`.
The DEK is a small self-describing blob (version + AEAD id + key), so a stored
DEK records its own algorithm and a later config change can't misread existing
data.

Configured via ``CRYPTO_BACKEND_OPTIONS`` and validated at construction (so a bad
value fails the deploy-time system check). **One algorithm applies to both
fields and files** — there is no field/file method split:

* ``AEAD`` (default ``"AES256_GCM"``) — ``AES256_GCM`` | ``CHACHA20_POLY1305`` |
  ``AES256_GCM_SIV``.
* ``SEGMENT_SIZE`` (default ``4096``) — STREAM plaintext segment size in bytes
  (files only; a performance knob, not an algorithm choice). It is recorded
  **per file** (in the stream header, not the key), so it can be changed at any
  time: new uploads use the new size while existing files still decrypt under
  the size they were written with (re-upload a file to change its size).

Note: ``AES256_GCM_SIV`` is nonce-misuse resistant, a real safety margin for
*fields* (random per-encrypt nonces). For *files* it is redundant — STREAM
derives a fresh per-stream subkey and uses a counter nonce, so nonces never
repeat — but it is offered there too for a consistent menu, and is harmless.

This backend is NOT interoperable with the Tink backend: the DEK serialization
and the field/file ciphertext framing are library-specific, so data written
under one is only ever read by the same one. Each data key row records its
backend and is loaded through it; moving a silo to the other backend is a
``reencrypt_data`` rotation (see the crypto backends docs). The same algorithm
name does not imply a shared wire format.
"""

from __future__ import annotations

import os

from ..._logging import get_logger
from ...exceptions import log_and_raise_configuration_error
from .base import AbstractCryptoEngine, FieldPrimitive, FilePrimitive

try:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM, AESGCMSIV, ChaCha20Poly1305

    from ._stream import TAG_LEN, DecryptingStream, EncryptingStream
except ImportError as exc:  # pragma: no cover
    raise ImportError(
        "encryption_suite.adapters.crypto_backends.cryptography requires the "
        "cryptography library (a core dependency of django-encryption-suite). "
        "Reinstall django-encryption-suite to restore it: pip install django-encryption-suite."
    ) from exc

logger = get_logger(__name__)

KEY_LEN = 32
_DEK_VERSION = 1
_FIELD_CT_VERSION = 1
_FIELD_NONCE_LEN = 12
_DEFAULT_SEGMENT_SIZE = 4096
# Upper bound on segment size: one segment is buffered in memory per stream, so
# cap it to keep memory bounded even if misconfigured (64 MiB).
_MAX_SEGMENT_SIZE = 64 * 1024 * 1024

# name -> (stable AEAD id stored in the DEK, pyca AEAD class). Identical for
# fields and files (every method must be usable on both surfaces). Each AEAD
# here is a one-shot seal with a 12-byte nonce and a 16-byte tag, so it works
# directly as a field primitive and as a STREAM per-segment primitive.
_AEADS = {
    "AES256_GCM": (1, AESGCM),
    "CHACHA20_POLY1305": (2, ChaCha20Poly1305),
    "AES256_GCM_SIV": (3, AESGCMSIV),
}
_AEAD_BY_ID = {aead_id: cls for (aead_id, cls) in _AEADS.values()}


class _CryptographyFieldPrimitive:
    """Field AEAD primitive. Ciphertext = version(1) | nonce(12) | aead_ct."""

    def __init__(self, aead) -> None:
        self._aead = aead

    def encrypt(self, plaintext: bytes, associated_data: bytes) -> bytes:
        nonce = os.urandom(_FIELD_NONCE_LEN)
        return bytes([_FIELD_CT_VERSION]) + nonce + self._aead.encrypt(nonce, plaintext, associated_data)

    def decrypt(self, ciphertext: bytes, associated_data: bytes) -> bytes:
        if len(ciphertext) < 1 + _FIELD_NONCE_LEN + TAG_LEN or ciphertext[0] != _FIELD_CT_VERSION:
            raise InvalidTag("malformed pyca field ciphertext")
        nonce = ciphertext[1 : 1 + _FIELD_NONCE_LEN]
        return self._aead.decrypt(nonce, ciphertext[1 + _FIELD_NONCE_LEN :], associated_data)


class _CryptographyFilePrimitive:
    """File primitive over the STREAM construction (see :mod:`._stream`).

    ``encrypt_segment_size`` is the size used for *new* encryptions (from current
    config). Decryption ignores it — each stream's segment size is read from its
    own header — so retuning the config never affects existing files.
    """

    def __init__(self, aead_cls, master_key: bytes, encrypt_segment_size: int) -> None:
        self._aead_cls = aead_cls
        self._master_key = master_key
        self._encrypt_segment_size = encrypt_segment_size

    def new_encrypting_stream(self, ciphertext_destination, associated_data: bytes):
        return EncryptingStream(
            ciphertext_destination, self._aead_cls, self._master_key, self._encrypt_segment_size, associated_data
        )

    def new_decrypting_stream(self, ciphertext_source, associated_data: bytes):
        return DecryptingStream(ciphertext_source, self._aead_cls, self._master_key, associated_data)


class CryptographyCryptoEngine(AbstractCryptoEngine):
    """Crypto backend built on pyca-cryptography (the ``cryptography`` package)."""

    backend_id = "cryptography"

    def __init__(self, options: dict) -> None:
        super().__init__(options)
        self._aead_name = options.get("AEAD", "AES256_GCM")
        self._aead_id, self._aead_cls = self._resolve_aead(self._aead_name)
        self._segment_size = self._resolve_segment_size(options.get("SEGMENT_SIZE", _DEFAULT_SEGMENT_SIZE))

    def describe_config(self) -> list[tuple[str, str]]:
        # The same AEAD covers both field and file surfaces; files add a STREAM
        # segment size. Show the human AEAD name (not the numeric DEK id) + size.
        return [("cipher", self._aead_name), ("segment_size", str(self._segment_size))]

    @staticmethod
    def _resolve_aead(name):
        try:
            return _AEADS[name]
        except (KeyError, TypeError):
            log_and_raise_configuration_error(
                logger,
                f"Unknown AEAD '{name}' for the pyca-cryptography backend. Valid options: {', '.join(_AEADS)}.",
            )

    @staticmethod
    def _resolve_segment_size(value) -> int:
        try:
            size = int(value)
        except (TypeError, ValueError):
            log_and_raise_configuration_error(
                logger,
                f"SEGMENT_SIZE must be a positive integer for the pyca-cryptography backend, got {value!r}.",
            )
        if size <= 0 or size > _MAX_SEGMENT_SIZE:
            log_and_raise_configuration_error(
                logger,
                f"SEGMENT_SIZE must be between 1 and {_MAX_SEGMENT_SIZE} bytes for the "
                f"pyca-cryptography backend, got {size}.",
            )
        return size

    def _new_dek(self) -> bytes:
        # Field and file DEKs share the same self-describing format
        # (version | aead_id | key); segment size lives per-file in the stream
        # header, not in the key. Fresh random key per call (purpose-separated by
        # the engine's field/file rows).
        return bytes([_DEK_VERSION, self._aead_id]) + os.urandom(KEY_LEN)

    def generate_field_dek(self) -> bytes:
        return self._new_dek()

    def generate_file_dek(self) -> bytes:
        return self._new_dek()

    def algorithm_id(self, purpose: str) -> str:
        # Files add the STREAM construction over the same AEAD. The segment size
        # is left out: it is written per file, not into the key.
        if purpose == "field":
            return self._aead_name
        if purpose == "file":
            return f"{self._aead_name}_STREAM"
        raise ValueError(f"No algorithm for purpose {purpose!r}.")

    def _parse_dek(self, dek_bytes: bytes):
        if len(dek_bytes) != 2 + KEY_LEN or dek_bytes[0] != _DEK_VERSION:
            raise ValueError("malformed pyca-cryptography DEK")
        aead_cls = _AEAD_BY_ID.get(dek_bytes[1])
        if aead_cls is None:
            raise ValueError(f"unknown pyca-cryptography AEAD id {dek_bytes[1]}")
        return aead_cls, dek_bytes[2:]

    def load_field_primitive(self, dek_bytes: bytes) -> FieldPrimitive:
        aead_cls, key = self._parse_dek(dek_bytes)
        return _CryptographyFieldPrimitive(aead_cls(key))

    def load_file_primitive(self, dek_bytes: bytes) -> FilePrimitive:
        aead_cls, key = self._parse_dek(dek_bytes)
        # The configured segment size is used only for new encryptions; decrypt
        # reads each file's size from its header.
        return _CryptographyFilePrimitive(aead_cls, key, self._segment_size)
