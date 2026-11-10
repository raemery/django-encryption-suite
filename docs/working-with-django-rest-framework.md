# Working with Django REST Framework

This page explains how to serve encrypted fields and files through a Django REST
Framework API. Everything on it is in `encryption_suite.contrib.drf`, behind
the `[drf]` extra, and each piece is opt-in.

A person reading a page can tell the fallback label "Unable to decrypt." from real
data. A machine reading JSON cannot, and it reads HTTP `200` as success. The
pieces below give an API client signals it can parse instead: a stable error code
when a write fails, and a structured marker when a read fails.

## Setup

Install the extra:

```bash
pip install 'django-encryption-suite[drf]'
```

Set the exception handler:

```python
# settings.py
REST_FRAMEWORK = {
    # …
    "EXCEPTION_HANDLER": "encryption_suite.contrib.drf.api_exception_handler",
}
```

Mix `EncryptionSerializerMixin` into each serializer for a model with encrypted
fields:

```python
# serializers.py
from encryption_suite.contrib.drf import EncryptionSerializerMixin
from rest_framework import serializers


class SecureFieldSerializer(EncryptionSerializerMixin, serializers.ModelSerializer):
    class Meta:
        model = SecureField
        fields = ["id", "name", "notes"]
```

A silo-key field needs the current silo during the request, exactly as it does in
a plain Django view. Whatever sets it for your views sets it for your API views;
see [Silo adapters](silo-adapters.md).

## Errors

The exception handler answers any `EncryptionError` with its code and its user
message, instead of an unhandled exception:

```json
HTTP 500
{"code": "configuration_error", "detail": "Encryption and decryption are unavailable for this data."}
```

`code` is the stable slug from [Error codes](error-codes.md). `detail` is the
generic, translated message from `str(exc)`, which names no setting, key, or
provider. The response never carries `exc.detail`: that attribute holds operator
detail, such as a resource name or a provider's error text, and it stays in the
log. Any other exception falls through to DRF's own handler.

The status answers one question: is a retry worth making? `code` carries
everything finer than that.

| Status | Errors | What a client should do |
| --- | --- | --- |
| `502` | `KekUnavailableError` | Retry with a capped backoff. A KMS call failed and the package cannot tell whether it will recover, so no `Retry-After` is sent: the budget is the client's to set. **The only status here worth retrying.** |
| `409` | `MissingDekError`, `KekNotProvisionedError`, `KekPendingDeletionError`, `DekDeletionScheduledError`, `DekDeletedError`, `DekReencryptionInProgressError` | Show `detail`, keep the user's unsaved input, and stop. These clear only when a person provisions a key, cancels a deletion, or finishes a data key rotation, which can take days and cannot be estimated. |
| `500` | Everything else, including any subclass not listed above | Show `detail`, report it, and stop. |

A subclass inherits its parent's status, so `KekPendingDeletionError` follows
`KekNotProvisionedError` without an entry of its own, and an error added in a
later release takes its parent's status rather than the default.

Nothing here promises that a condition is temporary. The user-facing messages
follow the same rule: a message may not say "currently", because a retry that a
missing key or a bad setting will never satisfy costs the server real load and
the user real time. A status code makes that promise to machines, which act on it
far more literally.

## Reads

### Encrypted fields

By default a failed read degrades: the field returns a fallback label and the
cause is recorded on the instance. The mixin turns that into a signal. It sets
the field to `null` and lists the field's code under `encryption_suite_errors`:

```json
HTTP 200
{
  "id": 10,
  "name": "API key",
  "notes": null,
  "encryption_suite_errors": {"notes": {"code": "field_decryption_failed"}}
}
```

The field's type stays stable (`string | null`), and a list still returns its
good rows with only the failed fields marked.

### Encrypted files

An encrypted file field gets the same marker, carrying the code of whatever made
the file unreadable: `missing_dek` when its data key is gone,
`file_storage_error` when the stored file is missing, and
`file_decryption_failed` when the stored file no longer authenticates.

A file fails at a different moment than a field. Serializing a file field renders
its stored name and reads nothing, so nothing has failed yet. What fails is
`probe()`, which opens storage and reads one byte. By default the mixin reports a
file only if something already probed it. A detail view that calls
`obj.file.probe()` before serializing gets the marker for free, because the
result is cached on the file. To have the serializer probe every encrypted file
itself, set `PROBE_ENCRYPTED_FILES`:

```python
class DocumentDetailSerializer(EncryptionSerializerMixin, serializers.ModelSerializer):
    PROBE_ENCRYPTED_FILES = True

    class Meta:
        model = Document
        fields = ["id", "name", "file"]
```

Each probe opens storage once per file per row. A detail endpoint can afford
that. A list endpoint of fifty rows pays fifty storage opens, so leave probing
off there, or give the list and the detail separate serializers.

A file whose display name cannot be decrypted is reported once, under the
display-name field, and not under the file field.

### Strict reads

A field declared with `decrypt_mode="strict"`, or a serializer run inside
[`strict_mode()`](encrypted-data.md), raises instead of degrading. The mixin
never sees the failure: the whole response fails through the exception handler
with that error's code and status, such as `500` for
`field_decryption_failed` or `409` for `missing_dek`. Use strict reads where a
partial response is worse than none. Use the default, with the mixin, where a
list should still return its good rows.

### Renamed fields

On reads, the mixin matches each serializer field name to a model attribute of
the same name. A field renamed with `source` is not marked.

## Uniqueness

`ModelSerializer` builds its uniqueness validators from `field.unique`. An
encrypted field reports `False`, or the database would be asked for a unique
index over a text column. So the mixin attaches the check DRF would have
attached, run against the blind index:

```json
HTTP 400
{"handle": ["This field must be unique."]}
```

The message is DRF's own, so a client that already handles a unique violation on
a plain field handles this one unchanged. **Without the mixin, an API write skips
the check** that an ORM or form write gets, and the duplicate arrives as an
`IntegrityError` from the constraint: a 500 where the client should have had a
400 naming the field. Only fields that declare both a blind index and uniqueness
(`unique=True` on a system field, `unique_in_silo=True` on a silo field) get a
validator.

## Uploads

A `ModelSerializer` accepts an encrypted file upload with no extra code. The model
field encrypts the file on save, stores it under an opaque name, and keeps the
uploaded filename in its display-name column:

```python
class DocumentSerializer(EncryptionSerializerMixin, serializers.ModelSerializer):
    class Meta:
        model = Document
        fields = ["id", "name", "file", "file_display_name"]
        read_only_fields = ["id", "file_display_name"]
        extra_kwargs = {"file": {"use_url": False}}
```

Set `use_url` to `False`. By default DRF renders a file field as
`storage.url()`, a URL that serves the encrypted bytes and that raises on
storage with no public URL. With `use_url` off, the field renders the opaque
stored name instead, and a client downloads the file through an action like the
one under [Downloads](#downloads).

The mixin limits the uploaded filename to the display-name column's
`max_length`, the same limit the field's form applies. Without the mixin,
`ModelSerializer` uses the file column's `max_length` (100 by default), which
bounds the opaque stored name and not the name a client sends. Pass `use_url`
through `extra_kwargs`, as above, rather than declaring the field: a declared
`serializers.FileField` keeps whatever `max_length` it was given, or none.

A failed save raises an `EncryptionError`, which the exception handler answers
as described under [Errors](#errors).

## Downloads

A serializer produces JSON and cannot stream a file. To download a file through
the API, add an action that calls
[`serve_encrypted_file`](serving-encrypted-files.md):

```python
from encryption_suite.contrib.drf import IgnoreClientContentNegotiation
from encryption_suite.file_view_helpers import serve_encrypted_file
from rest_framework.decorators import action


class DocumentViewSet(viewsets.ReadOnlyModelViewSet):
    # …

    @action(detail=True, methods=["get"], content_negotiation_class=IgnoreClientContentNegotiation)
    def download(self, request, *args, **kwargs):
        return serve_encrypted_file(request, self.get_object(), "file")
```

The response streams the decrypted file under its display name. Pass
`as_attachment=False` to serve it inline instead. Inline applies only to the
image and PDF types listed in
[Serving encrypted files](serving-encrypted-files.md#level-1-serve_encrypted_file-core),
and any other file is still sent as an attachment.

`serve_encrypted_file` decrypts the file's first segment, about 1 MiB, before
the response starts. A failure there, which covers a missing data key, a missing
stored file, and a file that does not authenticate, raises an `EncryptionError`
that the exception handler answers with `{"code", "detail"}`. A failure in a
later segment of a larger file happens after the response has started, so it
can only end the stream early. A row with no file attached answers `404`.

`IgnoreClientContentNegotiation` keeps DRF from refusing the request. DRF picks a
renderer before the action runs, and no renderer produces
`application/octet-stream` or `image/jpeg`, so a client that asks for the file's
type would get a `406` before the file is opened. The class skips that check and
picks the view's first renderer, which renders only what DRF renders itself: the
error response. Set it on the action, not the viewset, so the viewset's other
actions keep honoring `Accept`.

## Client contract

A client of your API can rely on these:

- **Writes**: a failure answers a non-2xx status with a JSON body
  `{"code", "detail"}`. Branch on the status for retry policy, and on the
  language-neutral `code` (see the [slug table](error-codes.md)) for what to say
  and offer. Show `detail` to a user: it is already in their language. A client
  that only does `if (status === 502) retry()` is already correct.
- **Reads**: a `2xx` with a field set to `null` **and** an entry for that field
  under `encryption_suite_errors` means that field could not be decrypted. It is
  not real data and must not be treated as such. The other fields and rows are
  valid.
- **Downloads**: a failure found before the file starts streaming answers the
  same `{"code", "detail"}` body as a write. A failure later in a large file
  ends the stream early, which a client sees as an incomplete download.
- **Codes are append-only**: a slug never changes meaning, so it is safe to branch
  on or to map to your own localized messages.

Never branch on the fallback label. It is display-only and may collide with
legitimate plaintext.

## Related

- [Handling encryption_suite errors](handling-errors.md): catching errors in your
  own code.
- [Error codes](error-codes.md): every slug and what it means.
- [Serving encrypted files](serving-encrypted-files.md): the download helpers
  behind the action above.
