# Operational Concerns

This page covers deployment and runtime behavior that affects performance,
cost, and reliability.  Read this before deploying to production, especially
if you are running multiple worker processes or an async server.

---

## The AEAD cache

Every encrypted field access needs a decrypted AEAD primitive (the crypto
backend object that performs encrypt/decrypt).  Decryption requires a KMS network
call, so the engine caches primitives in a process-level dictionary
(`_aead_cache`) to avoid repeated KMS round-trips.

Key characteristics:

- **One entry per silo per purpose.**  A silo has a field key, a file key, and
  a blind index key where a field declares one, and each gets its own entry.
  100 active silos reading fields only = 100 cache entries, regardless of how
  many users or requests access them.
- **TTL-based refresh.**  Each entry expires after `DEK_CACHE_TTL` seconds
  (default 300).  On the next access after expiry, the engine makes a KMS
  call to re-decrypt the key and replaces the entry.
- **Per-process.**  The cache is a Python dict in process memory.  Each
  operating system process has its own independent cache.  Processes do not
  share cache entries.
- **Negative caching of KMS failures.**  When a key operation fails because the
  KEK cannot be reached or used (a dead or slow KMS endpoint, expired
  credentials, an unprovisioned KEK), the engine records the failure in a
  second per-silo dict (`_aead_failure_cache`) for `DEK_FAILURE_CACHE_TTL`
  seconds (default 5).  Within that window, further encrypted reads for the same
  silo re-raise immediately instead of each re-paying the KMS round trip.
  This bounds the worst case: a page showing *N* encrypted values during a KMS
  outage blocks for roughly one timeout, not *N* in sequence.  The window is
  deliberately short so a backend that recovers is retried almost at once; a
  successful decrypt clears the cached failure immediately.  Missing-DEK and
  configuration errors are fast local checks and are never negatively cached.
  See [`DEK_FAILURE_CACHE_TTL`](configuration.md#dek_failure_cache_ttl).

---

## Multi-process deployments (gunicorn, uvicorn with --workers)

Most production deployments run multiple worker processes for reliability and
throughput.  Each worker process maintains its own AEAD cache, which means:

### KMS call multiplication

If you run N worker processes and have G silos, you can expect up to
**N x G** KMS calls on cold start (e.g., after a deploy), and up to
**N x G** calls every `DEK_CACHE_TTL` seconds in steady state as each
worker independently refreshes its cache.

| Workers | Silos | TTL | KMS calls on cold start | KMS calls per hour (steady state) |
|---|---|---|---|---|
| 4 | 50 | 300s | 200 | 2,400 |
| 4 | 500 | 300s | 2,000 | 24,000 |
| 8 | 500 | 300s | 4,000 | 48,000 |
| 8 | 500 | 600s | 4,000 | 24,000 |

These numbers assume every silo is actively accessed in every worker.
In practice, request routing and access patterns mean not every worker hits
every silo, so actual KMS call volume is usually lower.

### Cost and rate limit implications

Cloud KMS providers charge per API call and enforce rate limits:

- **AWS KMS** — ~$0.03 per 10,000 requests; symmetric cryptographic
  requests share one quota per account per Region (5,500, 10,000, or 50,000
  requests/second, depending on the Region)
- **GCP Cloud KMS** — ~$0.03 per 10,000 operations; 60,000 requests/minute
  per project
- **Azure Key Vault** — ~$0.03 per 10,000 operations; 4,000 transactions/10s
  per vault

For most deployments, KMS costs are negligible.  Monitor your usage if you
have a high silo count combined with many workers and a short TTL.

### Tuning recommendations

- **Increase `DEK_CACHE_TTL`** if KMS costs or rate limits are a concern.
  A longer TTL means fewer KMS calls but a longer window before key
  revocations take effect.  600-900 seconds is reasonable for most
  production workloads.
- **Right-size worker count** based on your actual concurrency needs, not
  a large default.  Fewer workers means fewer independent caches.
- **Monitor KMS usage** via your cloud provider's dashboard.  Set up alerts
  before you approach rate limits.

---

## Async deployments (uvicorn, Daphne)

When running under an ASGI server like uvicorn (single process) or Daphne,
Django handles requests asynchronously on an event loop.

### Encrypted field access under ASGI

Encryption and decryption are synchronous. Encryption runs in the field's
`pre_save`, inside the save. Decryption runs when code first reads an
encrypted attribute on an instance, on whatever thread performs that read —
loading the row does not decrypt anything. So:

1. An async view loads a row with an async ORM method (`aget()`, async
   iteration). Django runs the query through `sync_to_async`; the instance
   comes back holding ciphertext.
2. The view, or the template it renders, reads an encrypted attribute. The
   engine's `decrypt()` runs right there, synchronously.
3. If the cache has a valid entry, `decrypt()` performs only the local
   decryption and returns.
4. If the cache entry is expired or missing, the engine reads the
   `DataEncryptionKey` row and calls the KMS. Read on the event loop, that
   database query raises Django's `SynchronousOnlyOperation`, and the KMS call
   would block the loop.

Read encrypted attributes inside synchronous code: a sync view, or a function
wrapped in `sync_to_async`. Django's ORM and `sync_to_async` default to
`thread_sensitive=True`, which runs that code on one shared thread, so the
event loop stays free while the thread waits for the KMS.

### Sync thread saturation

The risk with ASGI deployments is the sync thread backing up. Under
`thread_sensitive=True` every sync call waits its turn on the same thread, so a
burst of KMS cache misses (cold start, or a cache flush) delays every other
piece of sync work — database queries, field reads, sync middleware — by the
length of those KMS calls (typically 10-100ms each). Code wrapped with
`thread_sensitive=False` runs on asgiref's thread pool instead, sized by the
`ASGI_THREADS` environment variable.

This is unlikely in steady state — the cache TTL means misses are infrequent
and spread over time.  It can happen during:

- **Cold start** — the first request for each silo triggers a KMS call.
  If many silos are accessed in a burst, many threads are consumed
  simultaneously.
- **Cache flush** — calling `EncryptionEngine.invalidate_cache()` without a
  silo UID clears all entries, causing a burst of misses.
- **Mass TTL expiry** — if the process started recently and many silos
  were first accessed at roughly the same time, their cache entries all
  expire around the same time.

### Tuning recommendations for ASGI

- **Stagger cache warming** — if your application has a startup hook, access
  silos sequentially rather than in a burst, so the misses do not queue up
  on the sync thread at once.
- **Use a longer `DEK_CACHE_TTL`** to reduce the frequency of KMS calls and
  spread them out over time.
- **Single vs. multi-process** — running `uvicorn --workers N` gives you N
  processes, each with its own cache and sync thread.  This multiplies KMS
  calls (see above) but also multiplies the sync capacity.

---

## Cold start behavior

When a worker process starts (or restarts after a deploy), its AEAD cache is
empty.  The first request for each silo triggers a KMS call to decrypt
its key.  Subsequent requests for the same silo use the cache until the
TTL expires.

For applications with many silos, cold start can produce a burst of KMS
calls.  This is normal and expected.  The per-silo locking in the
engine ensures that concurrent requests for the same silo share a
single KMS call rather than each making their own.

---

## Monitoring

Watch these metrics:

- **KMS API call volume** — available via your cloud provider's monitoring
  dashboard.  Should correlate with (workers x silos) / TTL.
- **KMS API latency** — increased latency from the KMS provider directly
  impacts encrypted field access times during cache misses.
- **KMS API errors** — 401/403 errors may indicate credential expiry; 429
  errors indicate rate limiting.  Most adapters (AWS, GCP, HashiCorp
  Vault, IBM, Infisical) retry once on auth errors. The package does not
  retry on rate limits.
- **`encryption_suite` log entries** — ERROR-level entries indicate
  decryption failures or missing keys.  See [Logging](logging.md).
