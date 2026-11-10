"""Tests for :func:`serve_encrypted_file_handled`.

The helper wraps :func:`serve_encrypted_file` with decrypt-failure
handling and PDF iframe-embedding headers. Tests use fake file /
instance objects so we don't need real encrypted storage.

File-type classification and read-side metadata
(:attr:`obj.<field>.kind`, :attr:`display_name`, etc.) live on the
:class:`~encryption_suite.fields.EncryptedFieldFile` descriptor and
are exercised in ``test_encrypted_file_field_descriptor.py``.
"""

from __future__ import annotations

import io

import pytest
from django.db import models
from django.http import FileResponse, HttpResponse

from encryption_suite.exceptions import EncryptedFileDecryptionError
from encryption_suite.fields import EncryptedFileField
from encryption_suite.file_download_view_helper import serve_encrypted_file_handled

_model_counter = 0


def _make_model(field_name="file", **field_kwargs):
    global _model_counter
    _model_counter += 1
    field_kwargs.setdefault("display_name_field", "file_display_name")
    attrs = {
        "__module__": "tests.test_file_download_view_helper",
        "Meta": type("Meta", (), {"app_label": "tests"}),
    }
    model = type(f"HandledTestModel{_model_counter}", (models.Model,), attrs)
    EncryptedFileField(**field_kwargs).contribute_to_class(model, field_name)
    return model


def _make_instance(model_cls, **attrs):
    inst = model_cls.__new__(model_cls)
    for k, v in attrs.items():
        setattr(inst, k, v)
    return inst


class _FakeFile:
    """Truthy 'attached' fake whose ``open()`` returns a byte stream."""

    def __init__(self, content: bytes = b"plaintext", attached: bool = True):
        self._content = content
        self._attached = attached

    def __bool__(self):
        return self._attached

    def open(self, mode="rb"):
        return io.BytesIO(self._content)


class _FailingFile:
    """``open().read()`` raises a typed decrypt error — emulates the
    swapped-row / AAD mismatch / corruption case."""

    def __bool__(self):
        return True

    def open(self, mode="rb"):
        class _Stream:
            def read(self_inner, *_a, **_k):
                raise EncryptedFileDecryptionError("forced for test")

            def close(self_inner):
                pass

        return _Stream()


@pytest.fixture
def doc_model():
    return _make_model()


@pytest.fixture
def rf():
    from django.test import RequestFactory

    return RequestFactory()


def test_handled_download_success_returns_file_response(rf, doc_model):
    inst = _make_instance(
        doc_model,
        file=_FakeFile(b"hello"),
        file_display_name="invoice.pdf",
    )
    response = serve_encrypted_file_handled(
        rf.get("/"),
        inst,
        "file",
        mode="download",
    )
    assert isinstance(response, FileResponse)
    assert "attachment" in response["Content-Disposition"]


def test_handled_inline_success_returns_file_response(rf, doc_model):
    inst = _make_instance(
        doc_model,
        file=_FakeFile(b"hello"),
        file_display_name="photo.jpg",
    )
    response = serve_encrypted_file_handled(
        rf.get("/"),
        inst,
        "file",
        mode="inline",
    )
    assert isinstance(response, FileResponse)
    assert "inline" in response["Content-Disposition"]


def test_handled_inline_pdf_success_sets_iframe_headers(rf, doc_model):
    """A successful PDF inline response must override Django's
    ``XFrameOptionsMiddleware`` default (``DENY``) so the embedding
    iframe can render the document. Failure responses already do this;
    success must too."""
    inst = _make_instance(
        doc_model,
        file=_FakeFile(b"%PDF-1.4 ..."),
        file_display_name="invoice.pdf",
    )
    response = serve_encrypted_file_handled(
        rf.get("/"),
        inst,
        "file",
        mode="inline",
        inline_kind="pdf",
    )
    assert response["X-Frame-Options"] == "SAMEORIGIN"
    assert "frame-ancestors" in response["Content-Security-Policy"]


def test_handled_inline_image_success_does_not_set_iframe_headers(rf, doc_model):
    """Image inline responses render in ``<img>`` and do not need
    iframe-embedding permission. Leaving the headers off lets Django's
    middleware default (``DENY``) stand, which is the safer choice for
    image content."""
    inst = _make_instance(
        doc_model,
        file=_FakeFile(b"\x89PNG..."),
        file_display_name="photo.png",
    )
    response = serve_encrypted_file_handled(
        rf.get("/"),
        inst,
        "file",
        mode="inline",
        inline_kind="image",
    )
    assert "X-Frame-Options" not in response
    assert "Content-Security-Policy" not in response


def test_handled_download_failure_reraises_without_callback(rf, doc_model):
    inst = _make_instance(
        doc_model,
        file=_FailingFile(),
        file_display_name="x.pdf",
    )
    with pytest.raises(EncryptedFileDecryptionError):
        serve_encrypted_file_handled(
            rf.get("/"),
            inst,
            "file",
            mode="download",
        )


def test_handled_download_failure_invokes_on_error_callback(rf, doc_model):
    inst = _make_instance(
        doc_model,
        file=_FailingFile(),
        file_display_name="x.pdf",
    )
    seen: dict = {}

    def cb(exc):
        seen["exc"] = exc
        return HttpResponse("redirected", status=302)

    response = serve_encrypted_file_handled(
        rf.get("/"),
        inst,
        "file",
        mode="download",
        on_error=cb,
    )
    assert response.status_code == 302
    assert isinstance(seen["exc"], EncryptedFileDecryptionError)


def test_handled_inline_failure_returns_plain_error_response(rf, doc_model):
    inst = _make_instance(
        doc_model,
        file=_FailingFile(),
        file_display_name="photo.jpg",
    )
    response = serve_encrypted_file_handled(
        rf.get("/"),
        inst,
        "file",
        mode="inline",
        inline_kind="image",
        inline_error_message="cannot decrypt",
    )
    assert response.status_code == 422
    assert response.content == b"cannot decrypt"
    # Image inline failure must NOT set iframe-embedding headers.
    assert "X-Frame-Options" not in response
    assert "Content-Security-Policy" not in response
    assert response["Content-Disposition"] == "inline"


def test_handled_inline_pdf_failure_sets_iframe_headers(rf, doc_model):
    inst = _make_instance(
        doc_model,
        file=_FailingFile(),
        file_display_name="x.pdf",
    )
    response = serve_encrypted_file_handled(
        rf.get("/"),
        inst,
        "file",
        mode="inline",
        inline_kind="pdf",
    )
    assert response.status_code == 422
    assert response["X-Frame-Options"] == "SAMEORIGIN"
    assert "frame-ancestors" in response["Content-Security-Policy"]


def test_handled_inline_failure_uses_on_error_when_supplied(rf, doc_model):
    """The callback overrides the default inline failure path so callers
    can substitute a JSON response or anything else they prefer."""
    inst = _make_instance(
        doc_model,
        file=_FailingFile(),
        file_display_name="x.pdf",
    )

    def cb(exc):
        return HttpResponse('{"error":"x"}', status=409, content_type="application/json")

    response = serve_encrypted_file_handled(
        rf.get("/"),
        inst,
        "file",
        mode="inline",
        on_error=cb,
    )
    assert response.status_code == 409
    assert response["Content-Type"] == "application/json"
