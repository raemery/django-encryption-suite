"""
Verifies SiloEncryptedStorageMixin._open streams plaintext instead of
buffering the whole file in memory.

Two tests:

1. ``test_open_reads_ciphertext_lazily`` — wraps the backend file in a byte
   counter and asserts only a small prefix of the ciphertext has been read
   after the first plaintext chunk. This is the deterministic proof of lazy
   streaming, independent of platform memory quirks.

2. ``test_open_peak_memory_below_file_size`` — encrypts a ~32 MB file, then
   reads it back in small chunks while measuring ``tracemalloc`` peak
   allocation. Peak must stay well below the file size.
"""

from __future__ import annotations

import io
import tracemalloc

import pytest
from django.core.files.base import ContentFile
from django.core.files.storage import FileSystemStorage

from encryption_suite.storage import SiloEncryptedStorageMixin


class EncryptedFileSystemStorage(SiloEncryptedStorageMixin, FileSystemStorage):
    pass


class _CountingReader(io.RawIOBase):
    """Wraps a readable stream, counting bytes pulled through it."""

    def __init__(self, inner):
        self._inner = inner
        self.bytes_read = 0

    def readable(self) -> bool:
        return True

    def read(self, size=-1):
        data = self._inner.read(size)
        self.bytes_read += len(data)
        return data

    def readinto(self, b):
        data = self.read(len(b))
        n = len(data)
        b[:n] = data
        return n

    def close(self):
        self._inner.close()
        super().close()


@pytest.fixture
def storage(tmp_path):
    return EncryptedFileSystemStorage(location=str(tmp_path))


def test_roundtrip(storage, silo_context):
    payload = b"hello encrypted world" * 100
    name = storage.save("greeting.txt", ContentFile(payload))

    with storage.open(name) as f:
        assert f.read() == payload


def test_open_reads_ciphertext_lazily(storage, silo_context, monkeypatch):
    """Reading one plaintext chunk must NOT pull the entire ciphertext into memory."""
    file_size = 4 * 1024 * 1024  # 4 MB
    payload = b"A" * file_size
    name = storage.save("big.bin", ContentFile(payload))

    from encryption_suite import registry

    engine = registry.get_engine()
    original_open = engine.open_decrypting_stream
    counters = []

    def wrapped(source, aad=b"", silo=None, **kwargs):
        counter = _CountingReader(source)
        counters.append(counter)
        return original_open(counter, aad, silo)

    monkeypatch.setattr(engine, "open_decrypting_stream", wrapped)

    f = storage.open(name)
    try:
        first_chunk = f.read(4096)
        assert first_chunk == b"A" * 4096
        assert counters, "decrypting stream was never opened"
        # Tink Streaming AEAD uses ~4 KB segments by default — reading one
        # plaintext chunk should pull only a handful of segments, well under
        # the full file size.
        assert counters[0].bytes_read < file_size // 4, (
            f"read {counters[0].bytes_read} of {file_size} ciphertext bytes "
            f"for one 4 KB plaintext chunk — not streaming"
        )
    finally:
        f.close()


def test_open_peak_memory_below_file_size(storage, silo_context):
    """Peak heap growth while streaming must stay well below the file size."""
    file_size = 32 * 1024 * 1024  # 32 MB
    payload = b"B" * file_size
    name = storage.save("big.bin", ContentFile(payload))
    del payload

    tracemalloc.start()
    try:
        tracemalloc.clear_traces()
        f = storage.open(name)
        try:
            read_bytes = 0
            while True:
                chunk = f.read(64 * 1024)
                if not chunk:
                    break
                read_bytes += len(chunk)
            _, peak = tracemalloc.get_traced_memory()
        finally:
            f.close()
    finally:
        tracemalloc.stop()

    assert read_bytes == file_size
    # Generous bound — old code buffered 2x file size (ciphertext + plaintext).
    # Streaming should stay under a few MB regardless of file size.
    assert peak < file_size // 4, f"peak memory {peak} too high for streaming decrypt"
