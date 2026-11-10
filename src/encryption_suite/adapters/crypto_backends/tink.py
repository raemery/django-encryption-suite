"""
Tink crypto backend.

Wraps Google Tink for the data plane: a DEK is a Tink keyset serialized to
binary, AEAD covers field values, Streaming AEAD covers files. This is the
default backend and preserves the original on-disk ciphertext format.

Primitive choice is read from ``CRYPTO_BACKEND_OPTIONS``:

* ``AEAD_KEY_TEMPLATE`` (default ``"AES256_GCM"``) — field AEAD.
* ``STREAMING_AEAD_KEY_TEMPLATE`` (default ``"AES256_GCM_HKDF_4KB"``) — files.

Both are validated at construction so an unknown template fails the
``check_crypto_backend_construction`` system check rather than the first
encrypt request.
"""

from __future__ import annotations

import io

from ..._logging import get_logger
from ...exceptions import log_and_raise_configuration_error
from .base import AbstractCryptoEngine, FieldPrimitive, FilePrimitive

try:
    import tink
    from tink import aead, cleartext_keyset_handle, streaming_aead
except ImportError as exc:  # pragma: no cover
    raise ImportError(
        "The Tink crypto backend requires Google Tink. Install the optional extra: "
        "pip install 'django-encryption-suite[tink]'."
    ) from exc

logger = get_logger(__name__)

# One-time Tink primitive registration (idempotent).
aead.register()
streaming_aead.register()

_AEAD_TEMPLATES: dict[str, tink.KeyTemplate] = {
    "AES256_GCM": aead.aead_key_templates.AES256_GCM,
    "AES128_GCM": aead.aead_key_templates.AES128_GCM,
    "AES256_EAX": aead.aead_key_templates.AES256_EAX,
}

_STREAMING_AEAD_TEMPLATES: dict[str, tink.KeyTemplate] = {
    "AES256_GCM_HKDF_4KB": streaming_aead.streaming_aead_key_templates.AES256_GCM_HKDF_4KB,
    "AES256_GCM_HKDF_1MB": streaming_aead.streaming_aead_key_templates.AES256_GCM_HKDF_1MB,
    "AES128_GCM_HKDF_4KB": streaming_aead.streaming_aead_key_templates.AES128_GCM_HKDF_4KB,
}

_DEFAULT_AEAD = "AES256_GCM"
_DEFAULT_STREAMING_AEAD = "AES256_GCM_HKDF_4KB"


class TinkCryptoEngine(AbstractCryptoEngine):
    """Crypto backend backed by Google Tink keysets."""

    backend_id = "tink"

    def __init__(self, options: dict) -> None:
        super().__init__(options)
        self._field_template_name = options.get("AEAD_KEY_TEMPLATE", _DEFAULT_AEAD)
        self._file_template_name = options.get("STREAMING_AEAD_KEY_TEMPLATE", _DEFAULT_STREAMING_AEAD)
        self._field_template = self._resolve_template(
            self._field_template_name,
            _AEAD_TEMPLATES,
            "AEAD_KEY_TEMPLATE",
        )
        self._file_template = self._resolve_template(
            self._file_template_name,
            _STREAMING_AEAD_TEMPLATES,
            "STREAMING_AEAD_KEY_TEMPLATE",
        )

    def describe_config(self) -> list[tuple[str, str]]:
        # Tink encodes the streaming segment size in the streaming template name
        # (e.g. AES256_GCM_HKDF_4KB), so the two template names cover primitive +
        # segment together.
        return [
            ("field_aead", self._field_template_name),
            ("file_streaming_aead", self._file_template_name),
        ]

    @staticmethod
    def _resolve_template(name: str, table: dict[str, tink.KeyTemplate], option: str) -> tink.KeyTemplate:
        try:
            return table[name]
        except KeyError:
            log_and_raise_configuration_error(
                logger,
                f"Unknown {option} '{name}' for the Tink crypto backend. Valid options: {', '.join(table)}.",
            )

    @staticmethod
    def _serialize_keyset(handle: tink.KeysetHandle) -> bytes:
        buf = io.BytesIO()
        cleartext_keyset_handle.write(tink.BinaryKeysetWriter(buf), handle)
        data = buf.getvalue()
        buf.close()
        return data

    def generate_field_dek(self) -> bytes:
        return self._serialize_keyset(tink.new_keyset_handle(self._field_template))

    def generate_file_dek(self) -> bytes:
        return self._serialize_keyset(tink.new_keyset_handle(self._file_template))

    def algorithm_id(self, purpose: str) -> str:
        if purpose == "field":
            return self._field_template_name
        if purpose == "file":
            return self._file_template_name
        raise ValueError(f"No algorithm for purpose {purpose!r}.")

    def load_field_primitive(self, dek_bytes: bytes) -> FieldPrimitive:
        handle = cleartext_keyset_handle.read(tink.BinaryKeysetReader(dek_bytes))
        return handle.primitive(aead.Aead)

    def load_file_primitive(self, dek_bytes: bytes) -> FilePrimitive:
        handle = cleartext_keyset_handle.read(tink.BinaryKeysetReader(dek_bytes))
        return handle.primitive(streaming_aead.StreamingAead)
