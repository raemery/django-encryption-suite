"""
Crypto backend interface.

A backend turns silo DEK material into the AEAD / streaming-AEAD
primitives the engine uses, and back. The engine never imports a concrete
crypto library directly — it goes through :class:`AbstractCryptoEngine`, so the
underlying library (Tink, pyca-cryptography, …) is a configuration choice.

The two primitive shapes the engine consumes are documented as protocols below.
They are deliberately the duck-typed shape that Google Tink's ``Aead`` and
``StreamingAead`` already satisfy, so the Tink backend is a thin pass-through
and any alternative backend simply has to match the same call surface.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from contextlib import AbstractContextManager
from typing import BinaryIO, Protocol, runtime_checkable


@runtime_checkable
class FieldPrimitive(Protocol):
    """AEAD primitive for field values. Matches Tink ``aead.Aead``."""

    def encrypt(self, plaintext: bytes, associated_data: bytes) -> bytes: ...

    def decrypt(self, ciphertext: bytes, associated_data: bytes) -> bytes: ...


@runtime_checkable
class FilePrimitive(Protocol):
    """Streaming-AEAD primitive for files. Matches Tink ``streaming_aead.StreamingAead``.

    ``new_encrypting_stream`` returns a writable context manager that the engine
    feeds plaintext chunks into; ``new_decrypting_stream`` returns a readable
    object the engine pulls plaintext from while it lazily consumes ciphertext.
    """

    def new_encrypting_stream(
        self, ciphertext_destination: BinaryIO, associated_data: bytes
    ) -> AbstractContextManager: ...

    def new_decrypting_stream(self, ciphertext_source: BinaryIO, associated_data: bytes): ...


class AbstractCryptoEngine(ABC):
    """
    Interface for the local data-plane crypto library.

    A concrete backend is constructed once per process by the registry with the
    ``CRYPTO_BACKEND_OPTIONS`` dict and cached. Construction must be I/O-free so
    a misconfiguration (e.g. an unknown primitive name, a missing optional
    dependency) can be surfaced by the ``check_crypto_backend_construction``
    system check at deploy time. Validate options in ``__init__`` and route any
    failure through
    :func:`~encryption_suite.exceptions.log_and_raise_configuration_error`.

    The :attr:`backend_id` is stored on every ``DataEncryptionKey`` row so
    the engine can refuse to load a DEK produced by a different backend (whose
    serialized form it cannot parse) — see
    :class:`~encryption_suite.exceptions.CryptoBackendMismatchError`.
    """

    # Stable short identifier written to DataEncryptionKey.crypto_backend
    # and compared on read. Must not change for an existing backend or stored
    # rows become unreadable.
    backend_id: str = ""

    def __init__(self, options: dict) -> None:
        self.options = options

    @abstractmethod
    def generate_field_dek(self) -> bytes:
        """Return a fresh serialized DEK for field (AEAD) encryption."""

    @abstractmethod
    def generate_file_dek(self) -> bytes:
        """Return a fresh serialized DEK for file (streaming AEAD) encryption."""

    @abstractmethod
    def algorithm_id(self, purpose: str) -> str:
        """Return the algorithm a DEK generated now for *purpose* holds.

        *purpose* is ``"field"`` or ``"file"``. The value is a stable identifier
        recorded on the data key row and its ledger events, never a translated
        label. It describes what the current options generate, so it is read at
        generation and never parsed back out of a stored DEK.
        """

    @abstractmethod
    def load_field_primitive(self, dek_bytes: bytes) -> FieldPrimitive:
        """Build a :class:`FieldPrimitive` from a serialized field DEK."""

    @abstractmethod
    def load_file_primitive(self, dek_bytes: bytes) -> FilePrimitive:
        """Build a :class:`FilePrimitive` from a serialized file DEK."""

    def describe(self) -> str:
        """Human-readable description for logs / management commands."""
        return self.backend_id or type(self).__name__

    def describe_config(self) -> list[tuple[str, str]]:
        """Return ``(key, value)`` rows describing the configured primitives.

        Presentation-neutral: each *key* is a stable identifier (e.g. ``"cipher"``,
        ``"segment_size"``) that a UI maps to a localized label; *value* is the
        display string. Used by the admin test console to show the configured
        AEAD and streaming segment size. Default returns no rows.
        """
        return []
