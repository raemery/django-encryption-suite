"""``key_set="system"`` files: the encrypted file field under the system silo's file key.

What every encrypted file field shares is tested on ``EncryptedFileField`` with
the default key; what is pinned here is what ``key_set="system"`` changes: no silo is
needed, the blob is stored beside the silo files rather than among them, it is
encrypted under the system silo's own file key, and the display-name companion
must be a ``key_set="system"`` column too.
"""

from __future__ import annotations

import pytest
from django.core.files.base import ContentFile
from django.core.files.storage import FileSystemStorage
from django.db import connection, models
from django.test import RequestFactory

from encryption_suite.conf import SYSTEM_SILO_UID
from encryption_suite.exceptions import EncryptionError
from encryption_suite.fields import EncryptedCharField, EncryptedFileField
from encryption_suite.file_view_helpers import serve_encrypted_file
from encryption_suite.models import DataEncryptionKey
from encryption_suite.storage import get_encrypted_storage


class Badge(models.Model):
    image = EncryptedFileField(key_set="system", display_name_field="image_name", null=True, blank=True)
    image_name = EncryptedCharField(key_set="system", max_length=255, null=True, blank=True)

    class Meta:
        app_label = "tests"


class SiloNamedBadge(models.Model):
    """A system file whose display name would need a silo to read."""

    image = EncryptedFileField(key_set="system", display_name_field="image_name", null=True, blank=True)
    image_name = EncryptedCharField(max_length=255, null=True, blank=True)

    class Meta:
        app_label = "tests"


@pytest.fixture
def badges(db):
    with connection.schema_editor() as editor:
        editor.create_model(Badge)
    try:
        yield Badge
    finally:
        with connection.schema_editor() as editor:
            editor.delete_model(Badge)


def _stored_bytes(row) -> bytes:
    with row.image.storage._open_raw(row.image.name) as raw:
        return raw.read()


@pytest.mark.django_db(transaction=True)
def test_a_file_reads_back_with_no_silo(badges):
    """Nothing here enters a silo context, and a silo file field would refuse."""
    row = badges.objects.create(image=ContentFile(b"portrait bytes", name="portrait.png"))

    loaded = badges.objects.get(pk=row.pk)
    with loaded.image.open("rb") as handle:
        assert handle.read() == b"portrait bytes"
    assert loaded.image.display_name == "portrait.png"


@pytest.mark.django_db(transaction=True)
def test_the_blob_is_stored_beside_the_silo_files_under_the_system_file_key(badges):
    row = badges.objects.create(image=ContentFile(b"portrait bytes", name="portrait.png"))

    assert row.image.name.startswith("encryption_suite_system/")
    assert "portrait" not in row.image.name
    assert b"portrait bytes" not in _stored_bytes(row)
    assert DataEncryptionKey.objects.filter(silo_uid=SYSTEM_SILO_UID, purpose=DataEncryptionKey.PURPOSE_FILE).exists()


def test_the_companion_must_share_the_files_key():
    errors = SiloNamedBadge._meta.get_field("image")._check_display_name_field()

    assert [e.id for e in errors] == ["encryption_suite.E024"]
    assert "same key_set" in errors[0].msg


def test_deconstruct_keeps_the_key_and_leaves_out_the_defaults():
    _, path, _, kwargs = Badge._meta.get_field("image").deconstruct()

    assert path == "encryption_suite.fields.EncryptedFileField"
    assert kwargs["key_set"] == "system"
    assert "upload_to" not in kwargs
    assert kwargs["storage"] is get_encrypted_storage


@pytest.mark.django_db(transaction=True)
def test_the_download_helper_serves_a_system_file(badges):
    row = badges.objects.create(image=ContentFile(b"portrait bytes", name="portrait.png"))

    response = serve_encrypted_file(RequestFactory().get("/"), badges.objects.get(pk=row.pk), "image")

    assert b"".join(response.streaming_content) == b"portrait bytes"
    assert "portrait.png" in response["Content-Disposition"]


@pytest.mark.django_db(transaction=True)
def test_a_system_file_opened_by_name_needs_a_storage_with_the_key_set(badges):
    """A bare ``storage.open`` has no field to name the key set, so the storage's own attribute decides."""
    row = badges.objects.create(image=ContentFile(b"portrait bytes", name="portrait.png"))
    default_storage = type(row.image.storage)()
    system_storage = type("SystemStorage", (type(row.image.storage),), {"key_set": "system"})()

    with pytest.raises(EncryptionError):
        with default_storage.open(row.image.name, "rb") as handle:
            handle.read()
    with system_storage.open(row.image.name, "rb") as handle:
        assert handle.read() == b"portrait bytes"


# ---------------------------------------------------------------------------
# The storage must encrypt
# ---------------------------------------------------------------------------


def _storage_ids(field):
    return [e.id for e in field._check_storage_mixin()]


def test_the_default_storage_encrypts_for_either_key():
    assert _storage_ids(Badge._meta.get_field("image")) == []
    assert _storage_ids(EncryptedFileField(display_name_field="name")) == []


def test_a_storage_with_no_encryption_mixin_is_refused(tmp_path):
    """The worst case: nothing in front of the backend, so files would be stored as plaintext."""
    field = EncryptedFileField(
        key_set="system", display_name_field="name", storage=FileSystemStorage(location=str(tmp_path))
    )

    assert _storage_ids(field) == ["encryption_suite.E036"]
