"""Tests for ``W057``: encrypted file storage configured to overwrite existing files.

The django-storages backends are stood in for by classes carrying their module
and class names, which is all the check matches on, so these run without the
package installed.
"""

from __future__ import annotations

from django.core.files.storage import FileSystemStorage, Storage

from encryption_suite.checks import check_encrypted_file_storage_overwrite, overwrite_warning
from encryption_suite.storage import SiloEncryptedStorageMixin


def _stand_in(module: str, name: str, **attributes):
    cls = type(name, (Storage,), {})
    cls.__module__ = module
    instance = cls()
    for attribute, value in attributes.items():
        setattr(instance, attribute, value)
    return instance


def test_an_overwriting_s3_storage_is_warned_about():
    storage = _stand_in("storages.backends.s3", "S3Storage", file_overwrite=True)

    warning = overwrite_warning(storage, ["tests.Document.file"])

    assert warning.id == "encryption_suite.W057"
    assert "tests.Document.file" in warning.msg
    assert '"file_overwrite": False' in warning.hint


def test_an_s3_storage_that_does_not_overwrite_is_not_warned_about():
    storage = _stand_in("storages.backends.s3", "S3Storage", file_overwrite=False)

    assert overwrite_warning(storage, ["tests.Document.file"]) is None


def test_dropbox_overwrites_by_write_mode():
    storage = _stand_in("storages.backends.dropbox", "DropboxStorage", write_mode="overwrite")

    warning = overwrite_warning(storage, ["tests.Document.file"])

    assert warning.id == "encryption_suite.W057"
    assert "\"write_mode\": 'add'" in warning.hint


def test_a_composed_or_subclassed_backend_still_matches():
    """The storage the field holds is the mixin composed onto the backend, or a project's subclass."""
    base = type(_stand_in("storages.backends.gcloud", "GoogleCloudStorage"))
    composed = type("EncryptedGoogleCloudStorage", (SiloEncryptedStorageMixin, base), {})()
    composed.file_overwrite = True

    assert overwrite_warning(composed, ["tests.Document.file"]).id == "encryption_suite.W057"


def test_django_filesystem_storage_is_read_from_its_own_option():
    assert overwrite_warning(FileSystemStorage(allow_overwrite=True), ["tests.Document.file"]).id == (
        "encryption_suite.W057"
    )
    assert overwrite_warning(FileSystemStorage(), ["tests.Document.file"]) is None


def test_an_unlisted_backend_is_not_inspected():
    storage = _stand_in("myproject.storage", "BucketStorage", file_overwrite=True)

    assert overwrite_warning(storage, ["tests.Document.file"]) is None


def test_the_test_projects_storage_passes():
    assert check_encrypted_file_storage_overwrite(None) == []
