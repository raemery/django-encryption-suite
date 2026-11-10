# Serving encrypted files

Files are encrypted at rest, so the storage backend holds only encrypted files.
**Presigned URLs will not work** — the browser would receive encrypted bytes
it cannot decrypt. Always serve through Django so decryption happens
server-side.

This page covers the read path (download/inline views) and the error handling
for both reads and writes. For declaring the field and the upload form, see
[Getting started](getting-started-storage.md).

## Display name, kind, and previews

For reads, use `instance.file.display_name` as the primary display value and
`instance.file.display_name_error` to distinguish a missing value from an
undecryptable one. The display name comes from the companion
`file_display_name` column, decrypted at serve time.

For inline previews, probe before rendering preview UI:

```python
obj.file.probe()
# template can branch on obj.file.is_undecryptable and obj.file.kind
```

`obj.file.kind` returns `"image"`, `"pdf"`, or `"unsupported"` based on the
decrypted display-name extension. It is a pure data value computed from the
extension lists configured on the field (`image_extensions`,
`pdf_extensions`) — the package renders nothing from it. Use it to decide how
to present the file.

```html
<!-- templates/documents/detail.html -->
{% if object.file %}
  {% if object.file.display_name %}
    <span>{{ object.file.display_name }}</span>
  {% elif object.file.display_name_error %}
    <span>Unable to decrypt file name.</span>
  {% endif %}
  <a href="{% url 'document_download' object.pk %}">Download</a>
{% endif %}
```

## View helpers: three levels

django-encryption-suite ships three view helpers at increasing levels of
abstraction. The higher-level helpers are optional conveniences built on the
lower ones. A Django REST Framework API calls `serve_encrypted_file` from an
action; see [Downloads](working-with-django-rest-framework.md#downloads).

### Level 1: `serve_encrypted_file` (core)

This helper is the fundamental building block. It decrypts the file, sets
`Content-Disposition`, and returns a streaming `FileResponse`. It is enough for most
download views and has no opinion on inline rendering, error handling, or query parameters.

```python
from encryption_suite.file_view_helpers import serve_encrypted_file

@login_required
def download_document(request, pk):
    doc = get_object_or_404(Document, pk=pk, team=request.user.team)
    return serve_encrypted_file(request, doc, "file")
```

Default is `Content-Disposition: attachment` (download dialog). Pass
`as_attachment=False` for inline rendering (e.g. images):

```python
return serve_encrypted_file(request, doc, "file", as_attachment=False)
```

Inline serving is limited to files whose display name ends in `png`, `jpg`,
`jpeg`, `gif`, `webp`, or `pdf`. Each is sent as its fixed type (`image/png`,
`image/jpeg`, `image/gif`, `image/webp`, `application/pdf`) with
`X-Content-Type-Options: nosniff`, and any other file is sent as an
attachment. The display name is chosen by whoever uploaded the file, so a
type guessed from it would let an upload named `x.html` or `x.svg` run script
on your site. Renaming a file to one of the allowed extensions only changes
which safe type it is declared as. An extension you add to `image_extensions`
or `pdf_extensions` changes `kind`, but a file with that extension is still
served as an attachment.

The display name in `Content-Disposition` comes from the companion
`file_display_name` column, decrypted at serve time; if unset, the filename
falls back to `download.bin`. Streaming `_open` means this works for
multi-gigabyte files without loading them into memory — Django's
`FileResponse` reads the decrypting stream in `FileResponse.block_size` chunks
(4 KB).

`serve_encrypted_file` raises `EncryptedFileDecryptionError` if the file fails
authentication. Catch it to return a 4xx or redirect rather than a 500.

### Level 2: `serve_encrypted_file_handled` (optional)

This helper wraps level 1 with built-in decrypt-failure handling and `inline_kind`, which
controls the HTTP headers needed when embedding files in iframes or `<img>`
tags.

```python
from encryption_suite.file_view_helpers import serve_encrypted_file_handled

def download_document(request, pk):
    doc = get_object_or_404(Document, pk=pk)
    descriptor = doc.file
    return serve_encrypted_file_handled(
        request, doc, "file",
        mode="inline",
        inline_kind=descriptor.kind,   # "image", "pdf", or "unsupported"
        on_error=lambda exc: HttpResponseRedirect(reverse("doc_detail", args=[pk])),
    )
```

When `inline_kind="pdf"`, this helper adds `X-Frame-Options: SAMEORIGIN` and a
matching `Content-Security-Policy` header so browsers allow the response
inside an `<iframe>`. Those headers are not set for any other kind. Use it
when you want a single call to handle both success and decrypt-failure paths,
or you are serving files inline and need the correct embedding headers.
Download-only or custom-error views are simpler with level 1.

### Level 3: `encrypted_file_download_view` (optional view factory)

This factory produces a complete Django view — instance lookup, the
`?inline=1` query parameter, `inline_kind` selection, error flash messages,
and redirect on failure. It suits the common team-scoped pattern repeated
across many models.

```python
from encryption_suite.file_view_helpers import encrypted_file_download_view

_download = encrypted_file_download_view(
    field_name="file",
    get_instance=lambda request, team_slug, pk: get_object_or_404(
        Document, pk=pk, team=request.team,
    ),
    error_redirect=lambda request, obj: reverse(
        "documents:detail",
        kwargs={"team_slug": request.team.slug, "pk": obj.pk},
    ),
)

@login_and_team_required
def download_document(request, team_slug: str, pk):
    return _download(request, team_slug=team_slug, pk=pk)
```

With `?inline=1` it sets `Content-Disposition: inline` and applies the correct
embedding headers for the file's kind; without it, returns
`Content-Disposition: attachment`. A file that cannot be served inline (see
[level 1](#level-1-serve_encrypted_file-core)) is sent as an attachment even with
`?inline=1`. On decrypt failure in download mode it
flashes an error and redirects to `error_redirect`; in inline mode it returns
a small plain-text error response with the same embedding headers, so an
`<iframe>` displays the error rather than the browser blocking the frame.

A file whose silo is in the middle of a
[data key rotation](key-rotation.md#rotating-a-data-encryption-key) is not
broken, only fenced until the rotation finishes, so both paths answer it
differently: the flash is the package's "Encryption and decryption are
unavailable for this data." instead of your `error_flash_message`, and the
inline response is a `503` with that same text instead of
`inline_error_message` and its `422`.

Use this when the boilerplate is identical across multiple models. For custom
per-request branching, compose level 1 or 2 directly.

## Failures during a download

`serve_encrypted_file` authenticates only the start of a file before it returns.
The probe reads a fixed amount, about 1 MiB, whatever the segment size, and
verifies the segments that cover it. Each later segment is verified as the
response streams.

So a file that is tampered with or truncated past that point fails after the
response has started. The status line, the headers and the plaintext before the
bad segment have already gone to the client. The server then aborts the
connection, and the client receives a short or broken download. No exception
reaches your view, because the view has already returned. A truncated file is
caught only when the stream reaches its final segment, so the failure appears at
the end of the file, not at the cut.

Streaming cannot take back bytes it has sent. If a client must never receive
partial plaintext from a damaged file, verify the whole file before responding:
read it to the end once, discarding the output, and then serve it. This doubles
the read work, which costs time on large files. Writing a decrypted copy to a
temporary file is the other option, but it leaves plaintext on disk. Choose the
option that fits your deployment. The package does not verify whole files for
you.

## Handling save / encryption failures

The serving helpers cover the *read* path. The *write* path can fail too, in
two ways:

- **Storage** — the backend rejects an existence check or an upload (an S3
  `403` from a miss-scoped key, a missing bucket/container, a network error).
  Raised as `EncryptedFileStorageError`.
- **Encryption / key** — the data encryption key cannot be created or the KMS
  cannot wrap it: the KEK is not provisioned (`KekNotProvisionedError`), there
  is no DEK (`MissingDekError`), or the key encryption key is unavailable for operational
  reasons such as an expired Vault token or revoked role
  (`KekUnavailableError`).

### Catch `EncryptionError` — one handler for everything

Every runtime error the package raises subclasses **`EncryptionError`**, so a
single `except EncryptionError` catches the whole family — storage, key, and
decryption errors alike. You do not need to enumerate subtypes unless you want
to branch. In every case:

- the underlying cause (provider HTTP error, `botocore` `ClientError`, storage
  location, …) is chained as `__cause__` **and** written to the
  `encryption_suite` logger at `ERROR` level — including the original error
  text — so operators can diagnose;
- the exception's own message is generic, translatable, and carries no
  infrastructure identifiers, so it is safe to show end users.

Saving an `EncryptedFileField` (or any encrypted field) happens in **your**
view — a form save, a DRF serializer, the admin — so catch where the save
happens:

```python
from encryption_suite.exceptions import EncryptionError

def upload_document(request):
    form = DocumentForm(request.POST or None, request.FILES or None)
    if form.is_valid():
        try:
            form.save()
        except EncryptionError as exc:
            # str(exc) is already translated and user-safe — display it directly.
            form.add_error(None, str(exc))
        else:
            return redirect("documents:list")
    return render(request, "documents/form.html", {"form": form})
```

Surfacing the failure as a **non-field form error** (`form.add_error(None,
...)`) renders it inline with the form's other validation errors — the right
channel for an HTMX partial render, where Django's `messages` framework would
not appear until the next full page load. Use `messages.error(...)` only on
full-page (non-HTMX) flows.

#### Saves that trigger key provisioning

`KEY_AUTO_PROVISION` (on by default) creates a silo's DEK on first use,
and `SILO_AUTO_KEY_CREATION` can provision keys from a signal when a
silo (team/tenant) row is created. Both reach the KMS, so a save that
triggers provisioning can raise `EncryptionError` (`KekNotProvisionedError` /
`KekUnavailableError`) from a place that is not an obvious "encryption" call —
e.g. **creating a team**, or the **first** write for a new tenant. Wrap any
save that may be the first encrypt for a silo in
`try/except EncryptionError`; otherwise a KMS outage during provisioning
surfaces as an unhandled 500. The package raises a typed, translated error —
catching it is the consumer's responsibility, because the triggering view
belongs to your app.

### Configuration / context errors

Developer-fixable misconfigurations raise `EncryptionConfigurationError` (a
`EncryptionError` subclass) — distinct from operational and ciphertext
failures:

- **No silo in context** — an encrypted field was accessed with no
  active team/tenant/group context. Fix the request/middleware wiring or the
  `ENCRYPTION['KEY_SETS']` configuration.
- **`KEK_TEMPLATE` / `KEK_MAP` / `SHARED_KEK_ID` / key-template
  misconfiguration**, or a missing optional dependency for the configured
  adapter — a deploy-time configuration error.

Because these are configuration problems, not package bugs, the package
deliberately avoids a raw traceback (whose frames would wrongly implicate the
package). It logs a fix-your-config message at `ERROR` and, since the type is
a `EncryptionError`, your single `except EncryptionError` handles it: on a
**write** the view shows the message; on a lenient **read** the field degrades
to its fallback (the misconfiguration is in the log, not silently lost).
Strict reads still re-raise.

### Double-encryption guard

Passing an already-encrypted value to `get_engine().encrypt()` raises
`FieldAlreadyEncryptedError` (code `field_already_encrypted`), an
`EncryptionError` subclass, so the single `except EncryptionError` catches it.
It signals a bug in the calling code: encrypting ciphertext again would store a
value no read path can unwrap. Model saves and the migration helpers never
reach it, because they pass an already-encrypted value through untouched.

### Customizing the message

The exception messages are wrapped with `gettext_lazy`, so `str(exc)` resolves
to the active locale (see [Internationalization](internationalization.md)). To
show different wording, supply **your own** `gettext_lazy`-wrapped **English
source string**:

```python
from django.utils.translation import gettext_lazy as _

except EncryptionError:
    form.add_error(None, _("Could not save your file. Please try again."))
```

Do **not** pass `str(exc)` into `gettext()` / `_()` — it is already resolved to
the active language. Override at the source-string level (a new message in
your own catalog) or reuse `str(exc)` as-is; never re-translate resolved text.

### Decrypt mode for file content

The `decrypt_mode` / `strict_mode()` lenient-vs-strict mechanism documented for
[encrypted value fields](encrypted-data.md#decryption-modes-lenient-vs-strict)
does **not** apply to `EncryptedFileField` content. A value field can degrade
to a fallback *string* a template renders in place; a file is a (potentially
large) binary **stream** with no meaningful in-band fallback. So file-content
decryption always **raises** — there is no sentinel — and the graceful
handling is done at the view boundary instead:

- **Downloads:** `serve_encrypted_file` raises the failure before the response
  starts, so your view can catch it; the `serve_encrypted_file_handled` /
  `encrypted_file_download_view` helpers catch it for you and turn it into a
  redirect or inline error.
- **Pre-checks:** `obj.<field>.probe()` returns `False` (and stores the
  exception on `obj.<field>.decryption_error`) instead of raising, so a detail
  template can decide whether to offer the download.

Both paths handle **any** `EncryptionError` — ciphertext rejection
(`EncryptedFileDecryptionError`) and key-acquisition failures
(`MissingDekError`, `KekUnavailableError`, e.g. an expired Vault token that
fails the streaming-key unwrap) alike.

The file's companion **`display_name_field`** is an `EncryptedCharField`, so
the stored **filename** *does* honor `decrypt_mode` and lenient rendering —
only the file **content** does not.
