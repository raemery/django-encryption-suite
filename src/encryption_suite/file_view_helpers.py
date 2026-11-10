"""
View helpers for encrypted file downloads.

``serve_encrypted_file`` streams an :class:`~encryption_suite.fields.EncryptedFileField`,
under either ``key``, as a :class:`~django.http.FileResponse`, using the decrypted display name from the
field's companion column as the download filename.

The caller is responsible for:

- **Authorization.** This helper does not check permissions. Gate it behind
  your own ``@login_required``, object-level permission check, or tenant
  membership test.
- **Silo context.** Opening a silo file decrypts it with the current silo's
  keyset, so the helper must run inside a request or block where the silo
  context variable is set (typically by middleware). A file in a key set bound
  to the system adapter needs no context, because that key set has one silo.

Never hand out a backend ``storage.url()`` for encrypted files — those URLs
point directly at ciphertext. Always serve through this view (or an
equivalent) so the decryption happens server-side.

Decryption-failure handling
---------------------------
Streaming AEAD validates each segment lazily on read, so a key /
AAD / ciphertext mismatch surfaces only when the segment is actually
consumed. Returning a bare ``FileResponse`` would let the failure happen
mid-iteration, after the response status and headers have already been
sent — the caller cannot then return a 4xx or redirect.

``serve_encrypted_file`` performs an eager probe (reads the first segment
into a buffer) before returning the response. Decryption failures raise
:class:`~encryption_suite.exceptions.EncryptedFileDecryptionError`
synchronously, so consuming views can catch the exception and render a
friendly error. On success the buffered bytes are prefixed back onto the
stream so the response body is unchanged for clients.
"""

from __future__ import annotations

import io
import os

from django.core.exceptions import FieldDoesNotExist
from django.http import FileResponse, Http404

from ._internal import DECRYPT_FAILURE_HINT, describe_decryption_target, operator_error_text
from ._logging import get_logger
from .exceptions import (
    GENERIC_DECRYPT_FAILED_USER_MESSAGE,
    EncryptedFileDecryptionError,
    EncryptionError,
)
from .fields import _build_row_identity, _EncryptedFileFieldBase

logger = get_logger(__name__)

# Read this many plaintext bytes during the eager probe. A streaming-AEAD
# backend authenticates a whole segment before releasing any of its plaintext,
# so reading even one byte forces the first segment to be verified — that is
# what lets the probe surface a key/AAD/integrity failure up front. The size is
# set to roughly one segment's worth for the largest segment the shipped
# backends produce by default (Tink's 1 MiB streaming template; the
# pyca-cryptography backend defaults to a much smaller SEGMENT_SIZE), so a short
# file is fully consumed at probe time and replayed from the buffer rather than
# re-read. A backend configured with a segment larger than this still
# authenticates correctly — only more of the first segment is pulled from the
# source after the buffer drains.
_PROBE_SIZE = 1024 * 1024 + 64 * 1024  # 1 MiB + slack for segment overhead

# The only types a file is served inline as, keyed by display-name extension.
# The display name is chosen by whoever uploaded the file, so a type guessed
# from it would let an upload named ``x.html`` or ``x.svg`` render as a page on
# the site's origin. Any other extension is served as an attachment.
_INLINE_CONTENT_TYPES = {
    "png": "image/png",
    "jpg": "image/jpeg",
    "jpeg": "image/jpeg",
    "gif": "image/gif",
    "webp": "image/webp",
    "pdf": "application/pdf",
}


def _inline_content_type(display_name: str) -> str | None:
    """Return the fixed inline type for *display_name*, or ``None`` if it has none."""
    return _INLINE_CONTENT_TYPES.get(os.path.splitext(display_name)[1].lstrip(".").lower())


class _PrefetchedReader:
    """Replay a prefetched buffer first, then read from the wrapped source.

    Used to push already-authenticated bytes back onto the stream so the
    eager probe in :func:`serve_encrypted_file` stays invisible to the
    response body. Closes the wrapped source on ``close()`` so file
    descriptors release at response teardown.
    """

    def __init__(self, prefetch: bytes, source) -> None:
        self._buffer = io.BytesIO(prefetch)
        self._source = source
        self._buffer_exhausted = not prefetch

    def read(self, size: int = -1) -> bytes:
        if not self._buffer_exhausted:
            chunk = self._buffer.read(size)
            if size == -1:
                # Caller wants everything — append the source's remainder.
                self._buffer_exhausted = True
                return chunk + self._source.read()
            if chunk:
                if len(chunk) < size:
                    # Buffer drained mid-request; top up from the source.
                    self._buffer_exhausted = True
                    return chunk + self._source.read(size - len(chunk))
                return chunk
            self._buffer_exhausted = True
        return self._source.read() if size == -1 else self._source.read(size)

    def close(self) -> None:
        try:
            self._source.close()
        finally:
            self._buffer.close()


def serve_encrypted_file(request, instance, field_name: str, *, as_attachment: bool = True):
    """Return a ``FileResponse`` that streams the decrypted file content.

    :param request: current HTTP request (not inspected — present for view
        signature compatibility).
    :param instance: model instance carrying the encrypted file field.
    :param field_name: name of the ``EncryptedFileField`` on ``instance``.
    :param as_attachment: when True (default), sets ``Content-Disposition:
        attachment`` to force a download dialog. Set False to render inline
        (e.g. for images the user is allowed to view in-page). Inline applies
        only to a display name ending in png, jpg, jpeg, gif, webp, or pdf,
        served as that fixed type with ``X-Content-Type-Options: nosniff``;
        any other file is served as an attachment.
    :raises Http404: when no file is attached or the field name is unknown.
    :raises TypeError: when ``field_name`` does not refer to an encrypted
        file field of either kind.
    :raises EncryptedFileDecryptionError: when the file's first segment
        fails authentication (wrong silo, AAD mismatch, swapped
        ciphertext, corruption). Raised before any response is started so
        the caller can return a 4xx, redirect, etc.
    """
    model = type(instance)
    try:
        field = model._meta.get_field(field_name)
    except FieldDoesNotExist as exc:
        raise Http404(f"No field {field_name!r} on {model.__name__}") from exc

    if not isinstance(field, _EncryptedFileFieldBase):
        raise TypeError(f"{model.__name__}.{field_name} is not an encrypted file field")

    file_attr = getattr(instance, field.attname)
    if not file_attr:
        raise Http404("No file attached")
    row_identity = _build_row_identity(model, instance, field)
    file_name = getattr(file_attr, "name", "") or ""
    if file_name and "file=" not in row_identity:
        row_identity = f"{row_identity},file={file_name}" if row_identity else f"file={file_name}"
    target = describe_decryption_target(
        field_label=f"{model._meta.label}.{field.attname}",
        row_identity=row_identity,
    )

    display_name = getattr(instance, field.display_name_field, None) or "download.bin"
    inline_content_type = None if as_attachment else _inline_content_type(display_name)
    if inline_content_type is None:
        as_attachment = True

    # Open and probe synchronously. The decrypting stream raises on the
    # first .read() that would surface a key/AAD/integrity failure; doing
    # it here means the exception escapes serve_encrypted_file before
    # FileResponse is ever constructed, so the calling view still owns
    # the HTTP status.
    # Open inside the try: the streaming-AEAD key is loaded at open time, so a
    # key-acquisition failure (missing DEK, unavailable KEK) surfaces here,
    # not on the first read.
    file_handle = None
    try:
        file_handle = file_attr.open("rb")
        prefetch = file_handle.read(_PROBE_SIZE)
    except EncryptionError:
        # Any typed package error (decryption failure or key acquisition) —
        # propagate as-is so view-layer callers catch the precise type.
        if file_handle is not None:
            file_handle.close()
        raise
    except Exception as exc:
        # Defensive net: any other read-path failure (e.g. raw backend errors
        # from a code path that bypasses ``_DecryptingFile``) is also
        # surfaced as a typed error so view-layer callers can rely on the
        # single exception type.
        if file_handle is not None:
            file_handle.close()
        logger.error(
            'Could not decrypt file. error_code=%s %s detail="%s" hint="%s"',
            EncryptedFileDecryptionError.code,
            target,
            operator_error_text(exc),
            DECRYPT_FAILURE_HINT,
        )
        raise EncryptedFileDecryptionError(
            GENERIC_DECRYPT_FAILED_USER_MESSAGE,
            detail=f"{target}: {operator_error_text(exc)}",
        ) from exc

    response = FileResponse(
        _PrefetchedReader(prefetch, file_handle),
        as_attachment=as_attachment,
        filename=display_name,
        content_type=inline_content_type,
    )
    if not as_attachment:
        # Set here as well as by SecurityMiddleware, so a deployment that
        # disabled it still keeps the browser on the declared type.
        response["X-Content-Type-Options"] = "nosniff"
    return response


# Re-export the higher-level handled helpers so callers can reach them
# from ``encryption_suite.file_view_helpers`` alongside ``serve_encrypted_file``.
from .file_download_view_helper import (  # noqa: E402,F401
    encrypted_file_download_view,
    serve_encrypted_file_handled,
)
