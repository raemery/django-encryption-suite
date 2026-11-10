# Testing encrypted storage locally

django-encryption-suite ships two streaming tests for the encrypted storage
mixin.  Both prove `SiloEncryptedStorageMixin._open` returns a
lazily-decrypting file-like object instead of buffering the whole
plaintext in memory — a regression that would silently defeat
Streaming AEAD.

| Test file | Backend | Requires Docker |
|---|---|---|
| `tests/test_storage_streaming.py` | Django `FileSystemStorage` | No |
| `tests/test_storage_s3_minio.py`  | django-storages `S3Boto3Storage` → MinIO | Yes |

The FileSystem test is deterministic and fast; run it on every change.
The MinIO test exercises the real S3 code path end-to-end — run it before
shipping storage-layer changes.

---

## Prerequisites

Install the dev extras plus whatever backends you plan to test:

```bash
uv sync --extra dev
uv pip install 'django-storages[s3]' testcontainers[minio] boto3
```

The MinIO test auto-skips if any of `testcontainers`, `boto3`, or
`django-storages` are missing, and also if Docker is not reachable — so
there is no harm in leaving `-m minio` enabled in CI for environments
without Docker; the tests simply don't run.

Docker itself must be running locally.  On Docker Desktop (macOS /
Windows) just launch the app.  On Linux, ensure your user is in the
`docker` group or run the tests with `sudo`.

---

## Running the tests

Run all streaming tests:

```bash
pytest tests/test_storage_streaming.py tests/test_storage_s3_minio.py
```

Only the Docker-free tests (fast inner loop):

```bash
pytest tests/test_storage_streaming.py
```

Only the MinIO tests:

```bash
pytest -m minio
```

With live output so you can watch MinIO start up:

```bash
pytest -m minio -s -v
```

---

## Test assertions

### FileSystem tests (`test_storage_streaming.py`)

1. **`test_roundtrip`** — writes plaintext through the mixin, reads it
   back, checks bytes match.  Catches gross breakage.
2. **`test_open_reads_ciphertext_lazily`** — monkey-patches the engine
   to wrap the encrypted source in a byte counter.  After opening the
   file and reading one 4 KB chunk of decrypted content, asserts fewer than a
   quarter of the encrypted bytes have been consumed.  This is the
   deterministic proof that `_open` does not prefetch the whole file —
   independent of platform memory quirks.
3. **`test_open_peak_memory_below_file_size`** — encrypts a 32 MB file,
   reads it back chunk-by-chunk under `tracemalloc`, asserts peak
   allocation stays under 8 MB.  The pre-streaming implementation
   buffered both ciphertext and plaintext, so peak was ~64 MB.

### MinIO tests (`test_storage_s3_minio.py`)

1. **`test_s3_roundtrip`** — the same write-then-read check, but the
   bytes actually travel through the S3 protocol to a real MinIO server
   running in a container.  Catches MRO mistakes, boto3 version skew,
   and `_open` wrapper issues that only surface on a network-backed
   storage backend.
2. **`test_s3_peak_memory_below_file_size`** — 16 MB file over the S3
   API, peak under 8 MB.  Bound is looser than the FileSystem test
   because `S3Boto3StorageFile` keeps an internal read buffer.

---

## Troubleshooting

**`testcontainers` fails with "Cannot connect to the Docker daemon"**
  Docker is not running or the current user cannot talk to the
  daemon socket.  On macOS/Windows, launch Docker Desktop.  On Linux,
  add your user to the `docker` group (`sudo usermod -aG docker $USER`
  then re-login) or run `sudo pytest`.

**MinIO container takes a long time on first run**
  `testcontainers` pulls the `minio/minio` image on first use.  Pre-pull
  with `docker pull minio/minio` to avoid pytest timing out.

**`pytest -m minio` reports "no tests ran"**
  Either the MinIO test file was filtered out by a `testpaths` config,
  or every test inside was skipped because an optional import is
  missing.  Run `pytest tests/test_storage_s3_minio.py -v` to see the
  skip reasons.

**Peak memory assertion fails only in CI**
  CI runners sometimes have additional profilers or coverage collectors
  loaded that inflate `tracemalloc` peaks.  If the failure is
  reproducible, loosen the bound in the test — the goal is to catch
  full-file buffering (which would be ≥ file size), not to enforce a
  tight allocation budget.

---

## Writing similar tests for other backends

The FileSystem test in `test_storage_streaming.py` is backend-agnostic
apart from the storage class it instantiates.  To cover Azure Blob,
GCS (via fake-gcs-server), or a custom backend, copy the file, swap the
storage class, and point its `endpoint_url` / custom endpoint at your
emulator of choice.  The `_CountingReader` trick works for any backend
whose `_open` returns a stream-like file.
