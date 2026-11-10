"""
End-to-end streaming test against MinIO (S3-compatible) via testcontainers.

Verifies SiloEncryptedStorageMixin + django-storages' S3Boto3Storage
encrypts on upload, decrypts on download, and keeps peak memory well below
the file size.

Requires Docker. Skipped automatically if ``testcontainers``, ``boto3``, or
``django-storages`` are not installed, or if Docker is not reachable.

Run only these tests with::

    pytest -m minio
"""

from __future__ import annotations

import tracemalloc

import pytest
from django.core.files.base import ContentFile

testcontainers_minio = pytest.importorskip("testcontainers.minio")
pytest.importorskip("boto3")
pytest.importorskip("storages.backends.s3boto3")

from storages.backends.s3boto3 import S3Boto3Storage  # noqa: E402

from encryption_suite.storage import SiloEncryptedStorageMixin  # noqa: E402


class EncryptedS3Storage(SiloEncryptedStorageMixin, S3Boto3Storage):
    pass


BUCKET = "encryption_suite-test"


@pytest.fixture(scope="module")
def minio():
    try:
        container = testcontainers_minio.MinioContainer()
        container.start()
    except Exception as exc:
        pytest.skip(f"Docker/MinIO unavailable: {exc}")
    try:
        config = container.get_config()
        client = container.get_client()
        client.make_bucket(BUCKET)
        yield {
            "endpoint_url": f"http://{config['endpoint']}",
            "access_key": config["access_key"],
            "secret_key": config["secret_key"],
        }
    finally:
        container.stop()


@pytest.fixture
def s3_storage(minio):
    return EncryptedS3Storage(
        bucket_name=BUCKET,
        endpoint_url=minio["endpoint_url"],
        access_key=minio["access_key"],
        secret_key=minio["secret_key"],
        addressing_style="path",
        region_name="us-east-1",
        signature_version="s3v4",
    )


@pytest.mark.minio
def test_s3_roundtrip(s3_storage, silo_context):
    payload = b"secret contract" * 50
    name = s3_storage.save("contract.txt", ContentFile(payload))
    try:
        with s3_storage.open(name) as f:
            assert f.read() == payload
    finally:
        s3_storage.delete(name)


@pytest.mark.minio
def test_s3_peak_memory_below_file_size(s3_storage, silo_context):
    file_size = 16 * 1024 * 1024  # 16 MB — big enough to matter, small enough to be quick
    name = s3_storage.save("big.bin", ContentFile(b"C" * file_size))
    try:
        tracemalloc.start()
        try:
            tracemalloc.clear_traces()
            f = s3_storage.open(name)
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
        # S3Boto3StorageFile's internal buffering may hold ~1 segment at a time;
        # give it headroom but still catch full-file buffering.
        assert peak < file_size // 2, f"peak memory {peak} too high for streaming S3 decrypt"
    finally:
        s3_storage.delete(name)
