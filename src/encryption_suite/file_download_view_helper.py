"""Higher-level view helper for encrypted file downloads.

:func:`serve_encrypted_file_handled` wraps :func:`serve_encrypted_file`
with decrypt-failure handling and the iframe-embedding headers PDF
inline previews need.

* In ``download`` mode, on failure it calls the caller's ``on_error``
  callback (or re-raises if none).
* In ``inline`` mode with ``inline_kind="pdf"`` it sets
  ``X-Frame-Options: SAMEORIGIN`` and a matching CSP on both the
  success response and the failure response, so the embedding iframe
  can render either outcome. Without this, Django's default
  ``XFrameOptionsMiddleware`` stamps ``X-Frame-Options: DENY`` on the
  successful streaming response and the browser refuses to display
  the PDF.

File-type classification and read-side metadata (display name, kind,
decryption error) live on the
:class:`~encryption_suite.fields.EncryptedFieldFile` descriptor —
access them directly via ``obj.<field>.kind``,
``obj.<field>.display_name``, etc. The view layer owns URL routing
and chooses an ``inline_kind`` from the descriptor's ``kind``.

The low-level :func:`~encryption_suite.file_view_helpers.serve_encrypted_file`
remains the building block for callers that want full control over
error handling.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, Literal

from django.contrib import messages
from django.http import Http404, HttpRequest, HttpResponse, HttpResponseBase, HttpResponseRedirect
from django.utils.translation import gettext_lazy as _

from .exceptions import (
    GENERIC_ENCRYPT_DECRYPT_UNAVAILABLE_MESSAGE,
    DekReencryptionInProgressError,
    EncryptedFileDecryptionError,
    EncryptionError,
)
from .fields import PreviewKind

ServeMode = Literal["download", "inline"]


def _apply_iframe_headers(response: HttpResponseBase, inline_kind: PreviewKind) -> None:
    """Set headers needed for an iframe-embedded inline preview.

    Only applied when ``inline_kind == "pdf"``. Image and unsupported
    inline previews render in ``<img>`` or as plain attachments and
    do not need iframe-embedding permission. ``X-Frame-Options`` is
    set explicitly so it overrides Django's default
    ``XFrameOptionsMiddleware`` value of ``DENY``.
    """
    if inline_kind != "pdf":
        return
    response["X-Frame-Options"] = "SAMEORIGIN"
    response["Content-Security-Policy"] = "frame-ancestors 'self'"


def _inline_failure_response(
    message: str,
    status: int,
    inline_kind: PreviewKind,
) -> HttpResponse:
    """Build the small non-streaming error response for an inline failure."""
    response = HttpResponse(
        message,
        status=status,
        content_type="text/plain; charset=utf-8",
    )
    response["Content-Disposition"] = "inline"
    _apply_iframe_headers(response, inline_kind)
    return response


def serve_encrypted_file_handled(
    request,
    instance,
    field_name: str,
    *,
    mode: ServeMode = "download",
    on_error: Callable[[EncryptionError], HttpResponseBase] | None = None,
    inline_kind: PreviewKind = "unsupported",
    inline_error_message=_("Unable to decrypt file."),
    inline_error_status: int = 422,
) -> HttpResponseBase:
    """Serve an encrypted file with built-in decrypt-failure handling.

    :param mode: ``"download"`` returns a ``FileResponse`` with
        ``Content-Disposition: attachment``; ``"inline"`` returns it
        with ``inline``.
    :param on_error: called with the typed exception when decryption
        fails. Returning a response substitutes it for the failure
        result; raising re-raises. When unset and ``mode="download"``,
        the exception is re-raised so the caller's view layer owns the
        redirect / messages flow. When unset and ``mode="inline"``, a
        small non-streaming response is returned.
    :param inline_kind: drives iframe-embedding headers. ``"pdf"``
        adds ``X-Frame-Options: SAMEORIGIN`` and a matching CSP on
        both the success response and the inline failure response,
        so the embedding iframe can display either outcome. Pass the
        value of ``obj.<field>.kind`` directly — the descriptor's
        ``PreviewKind`` and this helper share the same vocabulary.
    :param inline_error_message: text of the inline failure response.
    :param inline_error_status: its status. Neither applies to a
        :class:`~encryption_suite.exceptions.DekReencryptionInProgressError`:
        a data key rotation's fence says nothing is wrong with the data, so it
        is answered with the package's unavailable message rather than wording
        that reads as corruption. This is a preview pane read by a person, so
        the status carries no retry contract; the machine-facing statuses live
        in :mod:`encryption_suite.contrib.drf`.
    """
    # Lazy import: ``file_view_helpers.py`` re-exports from this module at
    # the bottom, so a top-level import here would close a cycle when
    # ``file_download_view_helper`` is loaded before ``file_view_helpers``
    # (e.g. when a test imports from it directly). The lazy import breaks
    # the cycle without changing public behavior.
    from .file_view_helpers import serve_encrypted_file

    try:
        response = serve_encrypted_file(
            request,
            instance,
            field_name,
            as_attachment=(mode == "download"),
        )
    except EncryptionError as exc:
        # Any package failure serving the file — ciphertext rejection
        # (EncryptedFileDecryptionError) or a key-acquisition failure
        # (MissingDekError, KekUnavailableError). Handle them uniformly.
        if on_error is not None:
            return on_error(exc)
        if mode == "inline":
            if isinstance(exc, DekReencryptionInProgressError):
                # The inline defaults read as permanent corruption. Nothing is
                # wrong with the data — it is mid-rotation — so answer the way
                # an unavailable service answers, without promising when.
                return _inline_failure_response(
                    str(GENERIC_ENCRYPT_DECRYPT_UNAVAILABLE_MESSAGE),
                    503,
                    inline_kind,
                )
            return _inline_failure_response(
                str(inline_error_message),
                inline_error_status,
                inline_kind,
            )
        # download mode without an on_error callback: re-raise so the
        # caller's view layer can decide on redirect / messages / JSON.
        raise
    if mode == "inline":
        _apply_iframe_headers(response, inline_kind)
    return response


def encrypted_file_download_view(
    *,
    field_name: str,
    get_instance: Callable[..., Any],
    error_redirect: Callable[[HttpRequest, Any], str] | None = None,
    inline_error_message=_("Unable to decrypt file."),
    error_flash_message=_("Unable to decrypt file."),
):
    """Build a Django view that serves an encrypted file.

    Wraps :func:`serve_encrypted_file_handled` with the boilerplate
    every consuming app would otherwise re-implement: instance lookup,
    "no file uploaded" branch, ``?inline=1`` query-param handling,
    PDF iframe headers (via the descriptor's ``kind``), and a flash
    + redirect on download-mode decrypt failure.

    :param field_name: name of the :class:`~encryption_suite.fields.EncryptedFileField`
        on the resolved instance.
    :param get_instance: ``(request, **url_kwargs) -> instance``. Owns
        the queryset / authorization. Typical implementation uses
        :func:`~django.shortcuts.get_object_or_404` filtered by team /
        user. Authorization belongs here; this factory does not impose
        any auth model of its own.
    :param error_redirect: ``(request, instance) -> url``. Used both
        for "no file uploaded" and (in download mode) for decrypt
        failure after flashing ``error_flash_message``. When ``None``,
        "no file uploaded" raises 404 and download-mode failures
        re-raise so the caller's view layer can decide.
    :param inline_error_message: text for the small inline failure
        response (passed through to :func:`serve_encrypted_file_handled`).
    :param error_flash_message: text passed to ``messages.error`` on
        download-mode decrypt failure before the redirect. Not used for a
        :class:`~encryption_suite.exceptions.DekReencryptionInProgressError`:
        a data key rotation's fence lifts on its own, so that failure flashes
        the package's unavailable message instead of wording that reads as
        corruption.

    Apply route-level decorators (``login_and_team_required``,
    ``require_GET``, etc.) by wrapping the returned callable in the
    consumer's ``urls.py``. The factory stays auth-agnostic so it can
    serve session-auth, token-auth, and unauthenticated public flows
    equally.
    """

    def view(request: HttpRequest, **url_kwargs):
        instance = get_instance(request, **url_kwargs)
        descriptor = getattr(instance, field_name, None)
        if not descriptor:
            if error_redirect is not None:
                return HttpResponseRedirect(error_redirect(request, instance))
            raise Http404("encrypted file not set")

        is_inline = request.GET.get("inline") == "1"

        on_error: Callable[[EncryptedFileDecryptionError], HttpResponseBase] | None = None
        if not is_inline and error_redirect is not None:

            def on_error(exc):
                # A data key rotation's fence lifts on its own, so it gets the
                # package's unavailable message rather than wording that reads
                # as a file that is broken for good — the same split the inline
                # response makes.
                message = (
                    GENERIC_ENCRYPT_DECRYPT_UNAVAILABLE_MESSAGE
                    if isinstance(exc, DekReencryptionInProgressError)
                    else error_flash_message
                )
                messages.error(request, str(message))
                return HttpResponseRedirect(error_redirect(request, instance))

        return serve_encrypted_file_handled(
            request,
            instance,
            field_name,
            mode="inline" if is_inline else "download",
            inline_kind=descriptor.kind,
            inline_error_message=inline_error_message,
            on_error=on_error,
        )

    view.__name__ = f"encrypted_file_download_{field_name}"
    return view
