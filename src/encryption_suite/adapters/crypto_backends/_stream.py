"""STREAM segmented authenticated encryption for the pyca-cryptography backend.

Implements the **STREAM** construction (Hoang, Reyhanitabar, Rogaway, Vizár,
*Online Authenticated-Encryption and its Nonce-Reuse Misuse-Resistance*, CRYPTO
2015) over pyca/cryptography one-shot AEADs. Written from the published
construction — not ported from any implementation — so it carries no
third-party license.

It gives Tink-Streaming-AEAD-equivalent behavior (encrypt/decrypt arbitrarily
large files without holding them in memory) for the pyca-cryptography backend.

On-disk format of an encrypted stream::

    header = MAGIC(4) | VERSION(1) | segment_size(4, big-endian) | salt(16) | nonce_prefix(7)
    body   = segment_0 | segment_1 | ... | segment_{n-1}

The ``segment_size`` is stored **per file** (in the header), not in the key, so
it can be retuned for performance at any time: new uploads use the configured
size, existing files keep decrypting under the size they were written with.

Each segment is one AEAD sealing of up to ``segment_size`` plaintext bytes::

    seg_key   = HKDF-SHA256(master_key, salt=salt, info=HKDF_INFO, length=32)
    nonce_i   = nonce_prefix(7) | counter_i(4, big-endian) | last_flag(1)
    segment_i = AEAD.encrypt(seg_key, nonce_i, plaintext_i, aad=header | caller_aad)

``last_flag`` is ``1`` for the final segment, ``0`` otherwise.

Why a per-stream subkey: a fresh 16-byte random ``salt`` derives a unique
``seg_key`` per stream, so the 7-byte random ``nonce_prefix`` never needs to be
globally unique — nonce uniqueness holds *within* a stream by the counter and
*across* streams by the distinct subkey. This is what makes random-nonce AEADs
(AES-GCM, ChaCha20-Poly1305) safe here at scale.

Security properties:

* Confidentiality + integrity per segment (the underlying AEAD).
* Reorder / duplicate resistance: the segment index is in the nonce, so a
  misplaced segment decrypts under the wrong nonce and fails.
* Truncation / extension resistance: the final segment is sealed with
  ``last_flag=1``; dropping it (or appending) makes the decryptor reconstruct
  the wrong nonce for the boundary segment, so verification fails.
* Header integrity: the whole header is bound as associated data on every
  segment, so tampering with salt / nonce_prefix / version is detected.
"""

from __future__ import annotations

import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

MAGIC = b"CKS1"
VERSION = 1
SEG_SIZE_LEN = 4
SALT_LEN = 16
PREFIX_LEN = 7
COUNTER_LEN = 4
FLAG_LEN = 1
TAG_LEN = 16  # AES-GCM / ChaCha20-Poly1305 / AES-GCM-SIV all use a 128-bit tag
HEADER_LEN = len(MAGIC) + 1 + SEG_SIZE_LEN + SALT_LEN + PREFIX_LEN
HKDF_INFO = b"django-encryption-suite:stream:v1"
_MAX_COUNTER = (1 << (COUNTER_LEN * 8)) - 1
# Cap the segment size a decryptor will honor from a (yet-unauthenticated)
# header, so a tampered header can't drive a huge read before the tag check
# fails. Matches the engine's construction-time cap.
_MAX_SEGMENT_SIZE = 64 * 1024 * 1024


def _derive_segment_key(master_key: bytes, salt: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=HKDF_INFO).derive(master_key)


def _nonce(prefix: bytes, counter: int, last: bool) -> bytes:
    return prefix + counter.to_bytes(COUNTER_LEN, "big") + (b"\x01" if last else b"\x00")


class StreamFormatError(ValueError):
    """Raised when a ciphertext stream is malformed or fails authentication.

    The engine wraps the file streaming calls and normalizes any failure into a
    typed ``EncryptionError``; this internal type just distinguishes a
    format/authentication problem from a programming error.
    """


class EncryptingStream:
    """Writable, context-managed stream that seals plaintext into STREAM segments.

    The caller writes plaintext via :meth:`write` (any chunk sizes); full
    segments are sealed and flushed as they fill. The final (possibly short, or
    empty) segment is sealed with ``last_flag=1`` when the context manager exits
    cleanly. Matches the surface the engine uses for Tink's encrypting stream.
    """

    def __init__(self, destination, aead_cls, master_key: bytes, segment_size: int, associated_data: bytes) -> None:
        self._dest = destination
        salt = os.urandom(SALT_LEN)
        self._prefix = os.urandom(PREFIX_LEN)
        self._aead = aead_cls(_derive_segment_key(master_key, salt))
        self._segment_size = segment_size
        header = MAGIC + bytes([VERSION]) + segment_size.to_bytes(SEG_SIZE_LEN, "big") + salt + self._prefix
        self._aad = header + associated_data
        self._buffer = bytearray()
        self._counter = 0
        self._closed = False
        self._dest.write(header)

    def _seal(self, plaintext: bytes, last: bool) -> None:
        if self._counter > _MAX_COUNTER:
            raise StreamFormatError("stream exceeds maximum segment count")
        self._dest.write(self._aead.encrypt(_nonce(self._prefix, self._counter, last), plaintext, self._aad))
        self._counter += 1

    def write(self, data: bytes) -> int:
        if self._closed:
            raise ValueError("write to a finalized EncryptingStream")
        self._buffer += data
        # Flush only while strictly more than a segment remains, so the last
        # buffered segment is never sealed as non-final prematurely — finalize()
        # seals whatever is left (0..segment_size bytes) with last_flag=1.
        while len(self._buffer) > self._segment_size:
            self._seal(bytes(self._buffer[: self._segment_size]), last=False)
            del self._buffer[: self._segment_size]
        return len(data)

    def finalize(self) -> None:
        if self._closed:
            return
        self._seal(bytes(self._buffer), last=True)
        self._buffer.clear()
        self._closed = True

    def __enter__(self) -> EncryptingStream:
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        # Only finalize on a clean exit; a failure mid-write must not emit a
        # final segment over a partial stream.
        if exc_type is None:
            self.finalize()


class DecryptingStream:
    """Readable, context-managed stream that decrypts STREAM segments on demand.

    Reads the header lazily on first :meth:`read`, then pulls and authenticates
    one ciphertext segment at a time, using a one-byte look-ahead to decide
    whether a full-size segment is the final one. Raises
    :class:`StreamFormatError` on any malformed or inauthentic input.
    """

    def __init__(self, source, aead_cls, master_key: bytes, associated_data: bytes) -> None:
        self._source = source
        self._aead_cls = aead_cls
        self._master_key = master_key
        self._caller_aad = associated_data
        self._segment_size = 0  # read from the header
        self._ct_segment_size = 0
        self._aead = None
        self._aad = b""
        self._prefix = b""
        self._counter = 0
        self._pending = b""  # one look-ahead byte belonging to the next segment
        self._plaintext = bytearray()
        self._finished = False
        self._header_read = False

    def _read_exact(self, n: int) -> bytes:
        chunks = []
        remaining = n
        while remaining > 0:
            chunk = self._source.read(remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)

    def _ensure_header(self) -> None:
        if self._header_read:
            return
        header = self._read_exact(HEADER_LEN)
        if len(header) != HEADER_LEN or header[: len(MAGIC)] != MAGIC:
            raise StreamFormatError("bad or missing stream header")
        if header[len(MAGIC)] != VERSION:
            raise StreamFormatError(f"unsupported stream version {header[len(MAGIC)]}")
        offset = len(MAGIC) + 1
        segment_size = int.from_bytes(header[offset : offset + SEG_SIZE_LEN], "big")
        if segment_size <= 0 or segment_size > _MAX_SEGMENT_SIZE:
            raise StreamFormatError(f"invalid stream segment size {segment_size}")
        self._segment_size = segment_size
        self._ct_segment_size = segment_size + TAG_LEN
        salt = header[offset + SEG_SIZE_LEN : offset + SEG_SIZE_LEN + SALT_LEN]
        self._prefix = header[offset + SEG_SIZE_LEN + SALT_LEN :]
        self._aead = self._aead_cls(_derive_segment_key(self._master_key, salt))
        self._aad = header + self._caller_aad
        self._header_read = True

    def _next_segment(self) -> None:
        if self._finished:
            return
        seg = self._pending + self._read_exact(self._ct_segment_size - len(self._pending))
        self._pending = b""
        if len(seg) < TAG_LEN:
            raise StreamFormatError("truncated stream: segment shorter than its tag")
        if len(seg) < self._ct_segment_size:
            last = True
        else:
            self._pending = self._source.read(1) or b""
            last = not self._pending
        from cryptography.exceptions import InvalidTag

        try:
            plaintext = self._aead.decrypt(_nonce(self._prefix, self._counter, last), seg, self._aad)
        except InvalidTag as exc:
            raise StreamFormatError("segment authentication failed") from exc
        self._plaintext += plaintext
        self._counter += 1
        if last:
            self._finished = True

    def read(self, size: int = -1) -> bytes:
        self._ensure_header()
        if size is None or size < 0:
            while not self._finished:
                self._next_segment()
            out = bytes(self._plaintext)
            self._plaintext.clear()
            return out
        while len(self._plaintext) < size and not self._finished:
            self._next_segment()
        out = bytes(self._plaintext[:size])
        del self._plaintext[:size]
        return out

    def readable(self) -> bool:
        return True

    def close(self) -> None:  # caller owns the source; nothing to close here
        pass

    def __enter__(self) -> DecryptingStream:
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()
