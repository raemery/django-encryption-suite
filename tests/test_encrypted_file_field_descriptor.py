"""Tests for :class:`~encryption_suite.fields.EncryptedFieldFile`.

Covers the read-side ergonomics added so the descriptor mirrors an
unencrypted file: ``display_name``, ``display_name_error``, ``kind``,
``probe``, ``decryption_error``, ``is_undecryptable``.

Tests use dynamically-built models + fake file objects rather than
real encrypted storage. The ``EncryptedFieldFile`` is constructed
directly with a stub field so each property can be exercised without
involving the storage layer.
"""

from __future__ import annotations

import pytest
from django.db import models

from encryption_suite.exceptions import (
    EncryptedFieldDecryptionError,
    EncryptedFileDecryptionError,
)
from encryption_suite.fields import (
    DEFAULT_IMAGE_EXTENSIONS,
    DEFAULT_PDF_EXTENSIONS,
    EncryptedFieldFile,
    EncryptedFileField,
    UndecryptableValue,
    _encryption_suite_errors_getter,
)

_model_counter = 0


def _make_model(field_name="file", **field_kwargs):
    """Build an ad-hoc model with a single ``EncryptedFileField``.

    The package's ``class_prepared`` listener installs the
    ``encryption_suite_errors`` property on models that declare encrypted
    fields. That signal fires inside ``ModelBase.__new__``, so it has
    already run by the time we call ``contribute_to_class`` here —
    the listener never sees our field. Re-attach the property by
    hand so the descriptor's ``display_name_error`` lookup works.
    """
    global _model_counter
    _model_counter += 1
    field_kwargs.setdefault("display_name_field", "file_display_name")
    attrs = {
        "__module__": "tests.test_encrypted_file_field_descriptor",
        "Meta": type("Meta", (), {"app_label": "tests"}),
    }
    model = type(f"DescriptorTestModel{_model_counter}", (models.Model,), attrs)
    EncryptedFileField(**field_kwargs).contribute_to_class(model, field_name)
    model.encryption_suite_errors = property(_encryption_suite_errors_getter)
    return model


def _make_instance(model_cls, **attrs):
    inst = model_cls.__new__(model_cls)
    inst.__dict__.update(attrs)
    return inst


def _make_descriptor(instance, field, name="storage/path.bin"):
    """Build an ``EncryptedFieldFile`` directly for property exercise."""
    return EncryptedFieldFile(instance=instance, field=field, name=name)


# ---------------------------------------------------------------------------
# display_name
# ---------------------------------------------------------------------------


def test_display_name_returns_companion_value():
    model = _make_model()
    inst = _make_instance(model, file_display_name="report.pdf")
    descriptor = _make_descriptor(inst, model._meta.get_field("file"))
    assert descriptor.display_name == "report.pdf"


def test_display_name_empty_when_companion_is_none():
    model = _make_model()
    inst = _make_instance(model, file_display_name=None)
    descriptor = _make_descriptor(inst, model._meta.get_field("file"))
    assert descriptor.display_name == ""


def test_display_name_empty_when_companion_is_undecryptable_sentinel():
    """A sentinel in the companion column must not leak its fallback
    string through ``display_name`` — callers branching on truthiness
    would treat the message as a real filename."""
    model = _make_model()
    sentinel = UndecryptableValue(
        fallback="Unable to decrypt.",
        error=EncryptedFieldDecryptionError("test"),
        field_name="file_display_name",
    )
    inst = _make_instance(model, file_display_name=sentinel)
    descriptor = _make_descriptor(inst, model._meta.get_field("file"))
    assert descriptor.display_name == ""


def test_display_name_empty_when_file_unset():
    """A descriptor with no file name is falsy; its ``display_name``
    short-circuits before touching the instance."""
    model = _make_model()
    inst = _make_instance(model, file_display_name="ignored.pdf")
    descriptor = _make_descriptor(inst, model._meta.get_field("file"), name="")
    assert descriptor.display_name == ""


# ---------------------------------------------------------------------------
# display_name_error
# ---------------------------------------------------------------------------


def test_display_name_error_returns_recorded_exception():
    """The lazy-decrypt descriptor records failures on
    ``instance._encryption_suite_errors``. The file descriptor surfaces the
    companion column's entry so a view can branch on the typed
    exception without re-decrypting."""
    model = _make_model()
    err = EncryptedFieldDecryptionError("test")
    sentinel = UndecryptableValue(
        fallback="Unable to decrypt.",
        error=err,
        field_name="file_display_name",
    )
    inst = _make_instance(
        model,
        file_display_name=sentinel,
        _encryption_suite_errors={"file_display_name": err},
    )
    descriptor = _make_descriptor(inst, model._meta.get_field("file"))
    assert descriptor.display_name_error is err


def test_display_name_error_none_when_companion_decrypted_successfully():
    model = _make_model()
    inst = _make_instance(model, file_display_name="ok.png")
    descriptor = _make_descriptor(inst, model._meta.get_field("file"))
    assert descriptor.display_name_error is None


def test_display_name_error_none_when_file_unset():
    model = _make_model()
    inst = _make_instance(model, file_display_name="x.pdf")
    descriptor = _make_descriptor(inst, model._meta.get_field("file"), name="")
    assert descriptor.display_name_error is None


# ---------------------------------------------------------------------------
# kind
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "name,expected",
    [
        ("photo.png", "image"),
        ("PHOTO.JPG", "image"),  # case-insensitive
        ("invoice.pdf", "pdf"),
        ("notes.txt", "unsupported"),
        ("no_extension", "unsupported"),
        ("", "unsupported"),
    ],
)
def test_kind_classifies_by_extension(name, expected):
    model = _make_model()
    inst = _make_instance(model, file_display_name=name)
    descriptor = _make_descriptor(inst, model._meta.get_field("file"))
    assert descriptor.kind == expected


def test_kind_uses_field_extension_lists_when_customized():
    """Custom extension lists supplied at field declaration drive the
    classification — the defaults are not the only allowed values."""
    model = _make_model(image_extensions=["bmp"], pdf_extensions=["epub"])
    inst = _make_instance(model, file_display_name="diagram.bmp")
    descriptor = _make_descriptor(inst, model._meta.get_field("file"))
    assert descriptor.kind == "image"

    inst.file_display_name = "book.epub"
    assert descriptor.kind == "pdf"

    # PNG is no longer in the image list under this custom config.
    inst.file_display_name = "photo.png"
    assert descriptor.kind == "unsupported"


def test_kind_is_unsupported_when_display_name_undecryptable():
    """If the companion failed to decrypt, ``display_name`` is empty —
    classification falls back to ``unsupported`` so the consumer hides
    the inline preview rather than rendering it for an unknown type."""
    model = _make_model()
    sentinel = UndecryptableValue(
        fallback="Unable to decrypt.",
        error=EncryptedFieldDecryptionError("test"),
        field_name="file_display_name",
    )
    inst = _make_instance(model, file_display_name=sentinel)
    descriptor = _make_descriptor(inst, model._meta.get_field("file"))
    assert descriptor.kind == "unsupported"


# ---------------------------------------------------------------------------
# probe / decryption_error / is_undecryptable
# ---------------------------------------------------------------------------


def test_probe_returns_true_for_decryptable_content(monkeypatch):
    """A successful probe leaves ``decryption_error`` ``None`` and
    ``is_undecryptable`` false."""
    model = _make_model()
    inst = _make_instance(model, file_display_name="ok.pdf")
    descriptor = _make_descriptor(inst, model._meta.get_field("file"))

    monkeypatch.setattr(
        descriptor,
        "_open_decrypting",
        lambda mode="rb": _ContextStream(b"plaintext"),
    )
    assert descriptor.probe() is True
    assert descriptor.decryption_error is None
    assert descriptor.is_undecryptable is False


def test_probe_records_typed_error_on_failure(monkeypatch):
    model = _make_model()
    inst = _make_instance(model, file_display_name="bad.pdf")
    descriptor = _make_descriptor(inst, model._meta.get_field("file"))

    err = EncryptedFileDecryptionError("forced")

    def _raise(*_a, **_k):
        raise err

    monkeypatch.setattr(descriptor, "_open_decrypting", _raise)
    assert descriptor.probe() is False
    assert descriptor.decryption_error is err
    assert descriptor.is_undecryptable is True


def test_probe_caches_result_across_calls(monkeypatch):
    """A second ``probe()`` must not re-open storage. Verified by
    raising from the patched opener after the first call so a second
    open would surface."""
    model = _make_model()
    inst = _make_instance(model, file_display_name="ok.pdf")
    descriptor = _make_descriptor(inst, model._meta.get_field("file"))

    calls = {"n": 0}

    def _open(mode="rb"):
        calls["n"] += 1
        if calls["n"] > 1:
            raise AssertionError("probe should be cached after first call")
        return _ContextStream(b"x")

    monkeypatch.setattr(descriptor, "_open_decrypting", _open)
    assert descriptor.probe() is True
    assert descriptor.probe() is True
    assert calls["n"] == 1


def test_probe_caches_failure(monkeypatch):
    """Cached failures stay failed — the user does not get a different
    answer the second time around."""
    model = _make_model()
    inst = _make_instance(model, file_display_name="bad.pdf")
    descriptor = _make_descriptor(inst, model._meta.get_field("file"))

    err = EncryptedFileDecryptionError("forced")
    calls = {"n": 0}

    def _open(*_a, **_k):
        calls["n"] += 1
        raise err

    monkeypatch.setattr(descriptor, "_open_decrypting", _open)
    assert descriptor.probe() is False
    assert descriptor.probe() is False
    assert calls["n"] == 1
    assert descriptor.decryption_error is err


def test_probe_no_op_when_file_unset():
    """A falsy descriptor (no name) reports trivially decryptable
    without touching storage."""
    model = _make_model()
    inst = _make_instance(model, file_display_name="x.pdf")
    descriptor = _make_descriptor(inst, model._meta.get_field("file"), name="")
    assert descriptor.probe() is True
    assert descriptor.decryption_error is None


def test_is_undecryptable_true_when_companion_failed_even_without_probe():
    """The companion failure short-circuits the consumer's branch
    without requiring an explicit probe of the content."""
    model = _make_model()
    err = EncryptedFieldDecryptionError("test")
    sentinel = UndecryptableValue(
        fallback="Unable to decrypt.",
        error=err,
        field_name="file_display_name",
    )
    inst = _make_instance(
        model,
        file_display_name=sentinel,
        _encryption_suite_errors={"file_display_name": err},
    )
    descriptor = _make_descriptor(inst, model._meta.get_field("file"))
    assert descriptor.is_undecryptable is True


# ---------------------------------------------------------------------------
# field configuration
# ---------------------------------------------------------------------------


def test_field_defaults_for_extension_lists():
    model = _make_model()
    field = model._meta.get_field("file")
    assert field.image_extensions == DEFAULT_IMAGE_EXTENSIONS
    assert field.pdf_extensions == DEFAULT_PDF_EXTENSIONS


def test_field_deconstruct_omits_default_extension_lists():
    """Defaults must not appear in ``deconstruct`` output, so identical
    fields produce identical migration text."""
    model = _make_model()
    field = model._meta.get_field("file")
    _, _, _, kwargs = field.deconstruct()
    assert "image_extensions" not in kwargs
    assert "pdf_extensions" not in kwargs


def test_field_deconstruct_emits_custom_extension_lists():
    model = _make_model(image_extensions=["bmp"], pdf_extensions=["epub"])
    field = model._meta.get_field("file")
    _, _, _, kwargs = field.deconstruct()
    assert kwargs["image_extensions"] == ["bmp"]
    assert kwargs["pdf_extensions"] == ["epub"]


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


class _ContextStream:
    """Bytes stream usable as a context manager for ``probe()``."""

    def __init__(self, payload: bytes):
        self._payload = payload
        self._pos = 0

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False

    def read(self, n: int = -1) -> bytes:
        if n < 0 or n > len(self._payload) - self._pos:
            chunk = self._payload[self._pos :]
            self._pos = len(self._payload)
            return chunk
        chunk = self._payload[self._pos : self._pos + n]
        self._pos += n
        return chunk
