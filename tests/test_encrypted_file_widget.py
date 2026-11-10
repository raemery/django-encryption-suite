"""Tests for :class:`~encryption_suite.widgets.EncryptedClearableFileInput`,
the default form widget of ``EncryptedFileField``.
"""

from __future__ import annotations

import pytest
from django import forms

from encryption_suite.adapters.silos.context import override_current_silo
from encryption_suite.widgets import EncryptedClearableFileInput
from tests.rotation_helpers import make_document, make_team
from tests.testapp.models import Document

STORAGE_NAME = "encryption_suite/0123456789abcdef.bin"


class _StoredFile:
    """A stored file whose storage has no public URL."""

    name = STORAGE_NAME

    def __str__(self):
        return self.name

    @property
    def url(self):
        raise NotImplementedError("This backend doesn't support absolute paths.")


class DocumentForm(forms.ModelForm):
    class Meta:
        model = Document
        fields = ["upload"]


def _render_upload(instance: Document) -> str:
    return str(DocumentForm(instance=instance)["upload"])


def test_field_supplies_the_widget_by_default():
    assert isinstance(DocumentForm().fields["upload"].widget, EncryptedClearableFileInput)


def test_with_a_file_renders_the_label_not_the_storage_name():
    html = _render_upload(Document(upload=STORAGE_NAME))
    assert "Encrypted file" in html
    assert STORAGE_NAME not in html
    assert "href" not in html


def test_with_no_file_renders_only_the_file_input():
    html = _render_upload(Document())
    assert "Currently" not in html
    assert "Clear" not in html
    assert "Encrypted file" not in html
    assert '<input type="file" name="upload"' in html


def test_renders_on_storage_whose_url_raises():
    html = EncryptedClearableFileInput().render("upload", _StoredFile())
    assert "Encrypted file" in html
    assert STORAGE_NAME not in html


def test_encrypted_text_kwarg_overrides_the_label():
    html = EncryptedClearableFileInput(encrypted_text="Stored securely").render("upload", _StoredFile())
    assert "Stored securely" in html
    assert "Encrypted file" not in html


def test_encrypted_text_subclass_overrides_the_label():
    class Labeled(EncryptedClearableFileInput):
        encrypted_text = "Stored securely"

    html = Labeled().render("upload", _StoredFile())
    assert "Stored securely" in html
    assert "Encrypted file" not in html


def test_an_explicit_widget_still_wins():
    class Custom(forms.FileInput):
        pass

    class WithMetaWidget(DocumentForm):
        class Meta(DocumentForm.Meta):
            widgets = {"upload": Custom}

    assert isinstance(WithMetaWidget().fields["upload"].widget, Custom)
    formfield = Document._meta.get_field("upload").formfield(widget=Custom)
    assert isinstance(formfield.widget, Custom)


@pytest.mark.django_db
def test_clear_empties_the_field_and_deletes_the_old_ciphertext(django_capture_on_commit_callbacks):
    team = make_team()
    document = make_document(team)
    old_name = document.upload.name
    storage = document.upload.storage
    assert storage.exists(old_name)

    with override_current_silo(team):
        form = DocumentForm(data={"upload-clear": "on"}, files={}, instance=document)
        assert form.is_valid(), form.errors
        with django_capture_on_commit_callbacks(execute=True):
            form.save()

    assert not Document.objects.get(pk=document.pk).upload
    assert not storage.exists(old_name)
