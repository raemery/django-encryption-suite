"""Tests for ``serve_encrypted_file`` — the view helper that streams an
EncryptedFileField as a FileResponse with the decrypted display name set
as the download filename.

These tests stub the file attribute so we don't need real encrypted
storage or a silo context — the helper's job is filename wiring
and type/permission checks, not decryption itself.
"""

from __future__ import annotations

import io
import itertools

import pytest
from django.db import models
from django.http import Http404

from encryption_suite.fields import EncryptedFileField
from encryption_suite.file_view_helpers import serve_encrypted_file


class _FakeFile:
    """Stand-in for a FieldFile. Truthy when 'attached', streams bytes on open()."""

    def __init__(self, content: bytes = b"plaintext", attached: bool = True):
        self._content = content
        self._attached = attached

    def __bool__(self):
        return self._attached

    def open(self, mode="rb"):
        return io.BytesIO(self._content)


def _make_instance(model_cls, **attrs):
    inst = model_cls.__new__(model_cls)
    for k, v in attrs.items():
        setattr(inst, k, v)
    return inst


_model_counter = itertools.count(1)


def _make_model(field_class, field_name="file", **field_kwargs):
    """Build a throwaway model class with the given field attached via
    ``contribute_to_class`` — gives us a real ``_meta`` without migrations.
    """
    attrs = {"__module__": "tests.test_download_view"}
    model = type(
        f"DownloadTestModel{next(_model_counter)}",
        (models.Model,),
        {
            **attrs,
            "Meta": type("Meta", (), {"app_label": "tests"}),
        },
    )
    field = field_class(**field_kwargs)
    field.contribute_to_class(model, field_name)
    return model


@pytest.fixture
def doc_model():
    return _make_model(
        EncryptedFileField,
        field_name="file",
        display_name_field="file_display_name",
    )


def test_serves_file_with_decrypted_display_name(rf, doc_model):
    instance = _make_instance(
        doc_model,
        file=_FakeFile(b"hello"),
        file_display_name="invoice.pdf",
    )
    response = serve_encrypted_file(rf.get("/"), instance, "file")
    # FileResponse sets filename via Content-Disposition.
    disposition = response["Content-Disposition"]
    assert "attachment" in disposition
    assert "invoice.pdf" in disposition


def test_inline_disposition_when_as_attachment_false(rf, doc_model):
    instance = _make_instance(
        doc_model,
        file=_FakeFile(b"hello"),
        file_display_name="photo.jpg",
    )
    response = serve_encrypted_file(rf.get("/"), instance, "file", as_attachment=False)
    assert "inline" in response["Content-Disposition"]
    assert response["Content-Type"] == "image/jpeg"
    assert response["X-Content-Type-Options"] == "nosniff"


@pytest.mark.parametrize("display_name", ["evil.html", "evil.svg", "evil.xhtml", "noextension"])
def test_inline_falls_back_to_attachment_for_unlisted_types(rf, doc_model, display_name):
    # The display name is uploader-chosen; only the fixed image/PDF types render inline.
    instance = _make_instance(
        doc_model,
        file=_FakeFile(b"<script>alert(1)</script>"),
        file_display_name=display_name,
    )
    response = serve_encrypted_file(rf.get("/"), instance, "file", as_attachment=False)
    assert response["Content-Disposition"].startswith("attachment")


def test_fallback_filename_when_display_name_missing(rf, doc_model):
    instance = _make_instance(
        doc_model,
        file=_FakeFile(b"hello"),
        file_display_name=None,
    )
    response = serve_encrypted_file(rf.get("/"), instance, "file")
    assert "download.bin" in response["Content-Disposition"]


def test_http404_when_no_file_attached(rf, doc_model):
    instance = _make_instance(
        doc_model,
        file=_FakeFile(attached=False),
        file_display_name="irrelevant.pdf",
    )
    with pytest.raises(Http404):
        serve_encrypted_file(rf.get("/"), instance, "file")


def test_http404_when_field_name_unknown(rf, doc_model):
    instance = _make_instance(
        doc_model,
        file=_FakeFile(b"x"),
        file_display_name="x",
    )
    with pytest.raises(Http404):
        serve_encrypted_file(rf.get("/"), instance, "nonexistent")


def test_typeerror_when_field_is_not_encrypted_file_field(rf):
    """Pointing the helper at a plain FileField is a programming error —
    fail loudly rather than silently serving unencrypted content through
    the wrong plumbing.
    """
    model = _make_model(models.CharField, field_name="name", max_length=100)
    instance = _make_instance(model, name="hello")
    with pytest.raises(TypeError):
        serve_encrypted_file(rf.get("/"), instance, "name")


@pytest.fixture
def rf():
    from django.test import RequestFactory

    return RequestFactory()
