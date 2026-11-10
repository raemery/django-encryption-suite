"""Tests for the pyca-cryptography crypto backend, incl. the STREAM file format.

Field path: round-trip + tamper/AAD/wrong-key rejection across all AEADs.
File path (STREAM): round-trip across sizes/segment boundaries, per-file segment
size, and a battery of adversarial cases (bit-flip, truncation, reorder,
extension, header tamper, wrong key, AAD mismatch).
"""

from __future__ import annotations

import io
import os

import pytest

pytest.importorskip("cryptography")

from cryptography.exceptions import InvalidTag  # noqa: E402

from encryption_suite.adapters.crypto_backends._stream import HEADER_LEN, TAG_LEN, StreamFormatError  # noqa: E402
from encryption_suite.adapters.crypto_backends.cryptography import (  # noqa: E402
    CryptographyCryptoEngine,
)
from encryption_suite.exceptions import EncryptionConfigurationError  # noqa: E402

AEADS = ["AES256_GCM", "CHACHA20_POLY1305", "AES256_GCM_SIV"]


def _engine(aead="AES256_GCM", segment_size=16):
    return CryptographyCryptoEngine({"AEAD": aead, "SEGMENT_SIZE": segment_size})


def _stream_encrypt(primitive, plaintext, aad=b"", chunk=65536):
    buf = io.BytesIO()
    with primitive.new_encrypting_stream(buf, aad) as enc:
        for i in range(0, len(plaintext), chunk) or [0]:
            enc.write(plaintext[i : i + chunk])
    return buf.getvalue()


def _stream_decrypt(primitive, ciphertext, aad=b""):
    return primitive.new_decrypting_stream(io.BytesIO(ciphertext), aad).read()


# ---------------------------------------------------------------------------
# Field path
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("aead", AEADS)
def test_field_roundtrip(aead):
    eng = _engine(aead)
    prim = eng.load_field_primitive(eng.generate_field_dek())
    ct = prim.encrypt(b"a field secret", b"aad")
    assert prim.decrypt(ct, b"aad") == b"a field secret"


@pytest.mark.parametrize("aead", AEADS)
def test_field_tamper_rejected(aead):
    eng = _engine(aead)
    prim = eng.load_field_primitive(eng.generate_field_dek())
    ct = bytearray(prim.encrypt(b"secret", b""))
    ct[-1] ^= 1
    with pytest.raises(InvalidTag):
        prim.decrypt(bytes(ct), b"")


def test_field_aad_mismatch_rejected():
    eng = _engine()
    prim = eng.load_field_primitive(eng.generate_field_dek())
    ct = prim.encrypt(b"secret", b"aad-1")
    with pytest.raises(InvalidTag):
        prim.decrypt(ct, b"aad-2")


def test_field_wrong_key_rejected():
    eng = _engine()
    prim1 = eng.load_field_primitive(eng.generate_field_dek())
    prim2 = eng.load_field_primitive(eng.generate_field_dek())
    ct = prim1.encrypt(b"secret", b"")
    with pytest.raises(InvalidTag):
        prim2.decrypt(ct, b"")


# ---------------------------------------------------------------------------
# Config validation
# ---------------------------------------------------------------------------


def test_unknown_aead_raises():
    with pytest.raises(EncryptionConfigurationError):
        CryptographyCryptoEngine({"AEAD": "BOGUS"})


@pytest.mark.parametrize("bad", [0, -1, "huge", None])
def test_bad_segment_size_raises(bad):
    with pytest.raises(EncryptionConfigurationError):
        CryptographyCryptoEngine({"SEGMENT_SIZE": bad})


# ---------------------------------------------------------------------------
# File path (STREAM) — round-trip
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("aead", AEADS)
@pytest.mark.parametrize("size", [0, 1, 15, 16, 17, 31, 32, 33, 200])
def test_stream_roundtrip(aead, size):
    eng = _engine(aead, segment_size=16)
    prim = eng.load_file_primitive(eng.generate_file_dek())
    data = os.urandom(size)
    assert _stream_decrypt(prim, _stream_encrypt(prim, data, b"aad"), b"aad") == data


def test_stream_large_default_segment():
    eng = _engine(segment_size=4096)
    prim = eng.load_file_primitive(eng.generate_file_dek())
    data = os.urandom(50_000)
    assert _stream_decrypt(prim, _stream_encrypt(prim, data)) == data


def test_stream_reassembles_tiny_writes():
    eng = _engine(segment_size=16)
    prim = eng.load_file_primitive(eng.generate_file_dek())
    data = os.urandom(100)
    buf = io.BytesIO()
    with prim.new_encrypting_stream(buf, b"") as enc:
        for i in range(0, len(data), 3):
            enc.write(data[i : i + 3])
    assert _stream_decrypt(prim, buf.getvalue()) == data


def test_segment_size_is_per_file_under_one_key():
    # The DEK carries no segment size; size is per-file (in the header). Two
    # engines with different SEGMENT_SIZE load the SAME key and either can decrypt
    # the other's file — proving size is a per-upload knob, not a key property.
    small = _engine(segment_size=16)
    dek = small.generate_file_dek()
    prim16 = small.load_file_primitive(dek)
    prim100 = _engine(segment_size=100).load_file_primitive(dek)
    data = os.urandom(250)
    ct16 = _stream_encrypt(prim16, data)
    ct100 = _stream_encrypt(prim100, data)
    assert ct16 != ct100
    assert _stream_decrypt(prim16, ct100) == data
    assert _stream_decrypt(prim100, ct16) == data


# ---------------------------------------------------------------------------
# File path (STREAM) — adversarial. seg=16 -> ciphertext segment = 16 + tag.
# ---------------------------------------------------------------------------

_CT_SEG = 16 + TAG_LEN


def _multi_segment_ct(aad=b"aad", n_bytes=40):
    eng = _engine(segment_size=16)
    prim = eng.load_file_primitive(eng.generate_file_dek())
    return prim, _stream_encrypt(prim, os.urandom(n_bytes), aad), aad


def test_bitflip_in_segment_rejected():
    prim, ct, aad = _multi_segment_ct()
    bad = bytearray(ct)
    bad[HEADER_LEN] ^= 1  # first plaintext-bearing byte of segment 0
    with pytest.raises(StreamFormatError):
        _stream_decrypt(prim, bytes(bad), aad)


def test_truncation_rejected():
    prim, ct, aad = _multi_segment_ct()
    # Keep only the header + first (non-final) segment; the decryptor now treats
    # that segment as final (last_flag=1) and its tag fails.
    with pytest.raises(StreamFormatError):
        _stream_decrypt(prim, ct[: HEADER_LEN + _CT_SEG], aad)


def test_truncate_mid_final_segment_rejected():
    prim, ct, aad = _multi_segment_ct()
    with pytest.raises(StreamFormatError):
        _stream_decrypt(prim, ct[:-3], aad)


def test_reorder_segments_rejected():
    prim, ct, aad = _multi_segment_ct()
    h = HEADER_LEN
    reordered = ct[:h] + ct[h + _CT_SEG : h + 2 * _CT_SEG] + ct[h : h + _CT_SEG] + ct[h + 2 * _CT_SEG :]
    with pytest.raises(StreamFormatError):
        _stream_decrypt(prim, reordered, aad)


def test_extension_after_full_final_segment_rejected():
    # data == exact multiple of segment -> final segment is full-size, so an
    # appended segment makes the decryptor read the real final as non-final.
    eng = _engine(segment_size=16)
    prim = eng.load_file_primitive(eng.generate_file_dek())
    ct = _stream_encrypt(prim, os.urandom(32), b"aad")
    with pytest.raises(StreamFormatError):
        _stream_decrypt(prim, ct + os.urandom(_CT_SEG), b"aad")


def test_header_salt_tamper_rejected():
    prim, ct, aad = _multi_segment_ct()
    bad = bytearray(ct)
    bad[12] ^= 1  # inside the salt region (after magic/version/segment_size)
    with pytest.raises(StreamFormatError):
        _stream_decrypt(prim, bytes(bad), aad)


def test_header_segment_size_tamper_rejected():
    prim, ct, aad = _multi_segment_ct()
    bad = bytearray(ct)
    bad[5] ^= 0x40  # high byte of the 4-byte segment_size field
    with pytest.raises(StreamFormatError):
        _stream_decrypt(prim, bytes(bad), aad)


def test_wrong_key_rejected():
    eng = _engine(segment_size=16)
    prim1 = eng.load_file_primitive(eng.generate_file_dek())
    prim2 = eng.load_file_primitive(eng.generate_file_dek())
    ct = _stream_encrypt(prim1, os.urandom(40), b"aad")
    with pytest.raises(StreamFormatError):
        _stream_decrypt(prim2, ct, b"aad")


def test_caller_aad_mismatch_rejected():
    prim, ct, _ = _multi_segment_ct(aad=b"right")
    with pytest.raises(StreamFormatError):
        _stream_decrypt(prim, ct, b"wrong")


@pytest.mark.parametrize("garbage", [b"", b"short", b"not-a-valid-encryption_suite-stream-header-at-all"])
def test_bad_header_rejected(garbage):
    eng = _engine()
    prim = eng.load_file_primitive(eng.generate_file_dek())
    with pytest.raises(StreamFormatError):
        _stream_decrypt(prim, garbage)


# ---------------------------------------------------------------------------
# End-to-end through the EncryptionEngine (registry + local KMS wrap/unwrap)
# ---------------------------------------------------------------------------

import copy  # noqa: E402

from django.conf import settings  # noqa: E402
from django.test import override_settings  # noqa: E402

from encryption_suite import registry  # noqa: E402
from encryption_suite.engine import EncryptionEngine  # noqa: E402
from encryption_suite.models import DataEncryptionKey  # noqa: E402

_PYCA_PATH = "encryption_suite.adapters.crypto_backends.cryptography.CryptographyCryptoEngine"


@pytest.fixture
def pyca_engine(db):
    cfg = copy.deepcopy(settings.ENCRYPTION)
    cfg["CRYPTO_BACKEND"] = _PYCA_PATH
    with override_settings(ENCRYPTION=cfg):
        registry.reset()
        EncryptionEngine.invalidate_cache()
        yield registry.get_engine()
    registry.reset()
    EncryptionEngine.invalidate_cache()


def test_engine_field_roundtrip_pyca(pyca_engine, silo_context):
    ct = pyca_engine.encrypt("a field secret", silo=silo_context)
    assert pyca_engine.decrypt(ct, silo=silo_context) == "a field secret"


def test_engine_stamps_pyca_backend(pyca_engine, silo_context):
    pyca_engine.encrypt("x", silo=silo_context)
    row = DataEncryptionKey.objects.get(purpose=DataEncryptionKey.PURPOSE_FIELD)
    assert row.crypto_backend == "cryptography"


def test_engine_file_roundtrip_pyca(pyca_engine, silo_context):
    data = os.urandom(10_000)
    ciphertext = io.BytesIO()
    pyca_engine.encrypt_file(io.BytesIO(data), ciphertext, silo=silo_context)
    ciphertext.seek(0)
    plaintext = io.BytesIO()
    pyca_engine.decrypt_file(ciphertext, plaintext, silo=silo_context)
    assert plaintext.getvalue() == data
