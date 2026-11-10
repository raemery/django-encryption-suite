"""Unit tests for EncryptedFileField behavior that does not require a
fully-migrated model — display-name population, default upload_to,
deconstruct output.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from encryption_suite.fields import (
    EncryptedCharField,
    EncryptedFileField,
    EncryptedIntegerField,
    EncryptedTextField,
    _default_encrypted_upload_to,
)


def _make_field(**kwargs):
    """Construct a field with just enough of Django's bound-to-model state
    to exercise the display-name helper in isolation.
    """
    kwargs.setdefault("display_name_field", "file_display_name")
    field = EncryptedFileField(**kwargs)
    field.attname = "file"
    return field


def test_default_upload_to_generates_opaque_path():
    path = _default_encrypted_upload_to(instance=None, filename="pay_stub_q1.pdf")
    assert path.startswith("encryption_suite_default/")
    assert path.endswith(".bin")
    # Opaque = no trace of the original filename or extension.
    assert "pay_stub" not in path
    assert "pdf" not in path


def test_default_upload_to_is_unique_across_calls():
    a = _default_encrypted_upload_to(None, "x.pdf")
    b = _default_encrypted_upload_to(None, "x.pdf")
    assert a != b


def test_a_string_upload_to_is_a_folder_with_an_opaque_name_under_it():
    path = _make_field(upload_to="patient-scans/").generate_filename(None, "pay_stub_q1.pdf").replace("\\", "/")

    folder, leaf = path.rsplit("/", 1)
    assert folder == "patient-scans"
    assert leaf.endswith(".bin") and len(leaf) == 36
    assert "pay_stub" not in path


def test_a_string_upload_to_does_not_repeat_a_name():
    field = _make_field(upload_to="patient-scans/")

    assert field.generate_filename(None, "x.pdf") != field.generate_filename(None, "x.pdf")


def test_a_string_upload_to_keeps_its_strftime_codes():
    path = _make_field(upload_to="scans/%Y/").generate_filename(None, "x.pdf").replace("\\", "/")

    assert path.split("/")[1].isdigit()


def test_a_callable_upload_to_chooses_the_whole_name():
    field = _make_field(upload_to=lambda instance, filename: "team-42/fixed.bin")

    assert field.generate_filename(None, "x.pdf").replace("\\", "/") == "team-42/fixed.bin"


def test_deconstruct_preserves_display_name_field():
    field = EncryptedFileField(display_name_field="doc_name")
    _, _, _, kwargs = field.deconstruct()
    assert kwargs["display_name_field"] == "doc_name"


def test_deconstruct_strips_default_upload_to():
    field = EncryptedFileField(display_name_field="doc_name")
    _, _, _, kwargs = field.deconstruct()
    # The default is an implementation detail; keeping it in kwargs would
    # pin migrations to the current module path.
    assert "upload_to" not in kwargs


def test_deconstruct_preserves_custom_upload_to():
    def custom_upload_to(instance, filename):
        return f"custom/{filename}"

    field = EncryptedFileField(display_name_field="doc_name", upload_to=custom_upload_to)
    _, _, _, kwargs = field.deconstruct()
    assert kwargs["upload_to"] is custom_upload_to


def test_deconstruct_preserves_naming_convention():
    def convention(instance, original):
        return "x.bin"

    field = EncryptedFileField(display_name_field="doc_name", naming_convention=convention)
    _, _, _, kwargs = field.deconstruct()
    assert kwargs["naming_convention"] is convention


def test_populate_display_name_uses_original_when_no_convention():
    field = _make_field()
    instance = SimpleNamespace(file_display_name=None)
    field._populate_display_name(instance, "invoice.pdf")
    assert instance.file_display_name == "invoice.pdf"


def test_populate_display_name_invokes_naming_convention():
    captured = {}

    def convention(instance, original):
        captured["instance"] = instance
        captured["original"] = original
        return "renamed.pdf"

    field = _make_field(naming_convention=convention)
    instance = SimpleNamespace(file_display_name=None, last="Smith")
    field._populate_display_name(instance, "raw-upload-name.PDF")
    assert instance.file_display_name == "renamed.pdf"
    assert captured["instance"] is instance
    assert captured["original"] == "raw-upload-name.PDF"


def test_populate_display_name_respects_explicit_value():
    def convention(instance, original):
        return "SHOULD_NOT_RUN"

    field = _make_field(naming_convention=convention)
    instance = SimpleNamespace(file_display_name="user_chose_this.pdf")
    field._populate_display_name(instance, "upload.pdf")
    assert instance.file_display_name == "user_chose_this.pdf"


def _bind_companion(field, companion):
    class FakeMeta:
        def get_field(self, name):
            return companion

    field.model = type("FakeModel", (), {"_meta": FakeMeta()})


def test_the_upload_form_limits_the_filename_to_the_display_name_column():
    field = _make_field()
    _bind_companion(field, EncryptedCharField(max_length=120))

    assert field.formfield().max_length == 120


def test_populate_display_name_keeps_the_end_of_an_overlong_upload_name():
    field = _make_field()
    _bind_companion(field, EncryptedCharField(max_length=10))
    instance = SimpleNamespace(file_display_name=None)
    field._populate_display_name(instance, "quarterly-report.pdf")
    assert instance.file_display_name == "report.pdf"


def test_populate_display_name_keeps_the_end_of_an_overlong_convention_name():
    def convention(instance, original):
        return "Smith-Jane-xray.jpg"

    field = _make_field(naming_convention=convention)
    _bind_companion(field, EncryptedCharField(max_length=8))
    instance = SimpleNamespace(file_display_name=None)
    field._populate_display_name(instance, "IMG_4471.JPG")
    assert instance.file_display_name == "xray.jpg"


def test_populate_display_name_leaves_an_upload_name_that_fits():
    field = _make_field()
    _bind_companion(field, EncryptedCharField(max_length=10))
    instance = SimpleNamespace(file_display_name=None)
    field._populate_display_name(instance, "report.pdf")
    assert instance.file_display_name == "report.pdf"


def test_populate_display_name_falls_back_to_empty_when_no_original():
    field = _make_field()
    instance = SimpleNamespace(file_display_name=None)
    field._populate_display_name(instance, "")
    # No convention, no original name: display stays empty. Not ideal, but
    # an explicit invariant — callers who want a default should supply a
    # naming_convention.
    assert instance.file_display_name == ""


def test_check_flags_missing_display_name_field():
    """E023: display_name_field points to a nonexistent model field."""

    class FakeMeta:
        label = "testapp.Document"

        def get_field(self, name):
            from django.core.exceptions import FieldDoesNotExist

            raise FieldDoesNotExist(name)

    field = EncryptedFileField(display_name_field="missing")
    field.model = type("FakeModel", (), {"_meta": FakeMeta()})
    errors = field._check_display_name_field()
    assert len(errors) == 1
    assert errors[0].id == "encryption_suite.E023"


def test_check_flags_non_encrypted_companion():
    """E024: display_name_field points to a plain CharField."""
    from django.db import models

    class FakeMeta:
        label = "testapp.Document"

        def get_field(self, name):
            return models.CharField(max_length=100)

    field = EncryptedFileField(display_name_field="plain_name")
    field.model = type("FakeModel", (), {"_meta": FakeMeta()})
    errors = field._check_display_name_field()
    assert len(errors) == 1
    assert errors[0].id == "encryption_suite.E024"


@pytest.mark.parametrize("companion", [EncryptedIntegerField(), EncryptedTextField()])
def test_check_flags_encrypted_companion_that_is_not_char(companion):
    """E024: display_name_field points to an encrypted field other than EncryptedCharField."""

    class FakeMeta:
        label = "testapp.Document"

        def get_field(self, name):
            return companion

    field = EncryptedFileField(display_name_field="enc_other")
    field.model = type("FakeModel", (), {"_meta": FakeMeta()})
    errors = field._check_display_name_field()
    assert len(errors) == 1
    assert errors[0].id == "encryption_suite.E024"


def test_check_accepts_encrypted_companion():
    class FakeMeta:
        label = "testapp.Document"

        def get_field(self, name):
            return EncryptedCharField(max_length=100)

    field = EncryptedFileField(display_name_field="enc_name")
    field.model = type("FakeModel", (), {"_meta": FakeMeta()})
    errors = field._check_display_name_field()
    assert errors == []
