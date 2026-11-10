"""Tests for ``get_encrypted_storage`` — the resolver that turns Django's
``STORAGES`` setting into an encrypted storage instance without requiring
consumers to write their own storage subclass.
"""

from __future__ import annotations

import os

import pytest
from django.core.files.storage import FileSystemStorage
from django.test import override_settings

from encryption_suite import storage as storage_mod
from encryption_suite.storage import (
    SiloEncryptedFileSystemStorage,
    SiloEncryptedStorageMixin,
    get_encrypted_storage,
)


@pytest.fixture(autouse=True)
def _clear_composed_cache():
    """The resolver caches composed classes per backend dotted path. Clear
    before and after each test so earlier tests don't influence later ones.
    """
    storage_mod._composed_storage_cache.clear()
    yield
    storage_mod._composed_storage_cache.clear()


def test_resolver_uses_encrypted_alias():
    """The dedicated alias takes precedence over 'default'."""
    with override_settings(
        STORAGES={
            "default": {
                "BACKEND": "django.core.files.storage.FileSystemStorage",
                "OPTIONS": {"location": "/tmp/public"},
            },
            "encrypted": {
                "BACKEND": "django.core.files.storage.FileSystemStorage",
                "OPTIONS": {"location": "/tmp/private"},
            },
        }
    ):
        instance = get_encrypted_storage()
        assert isinstance(instance, SiloEncryptedStorageMixin)
        assert isinstance(instance, FileSystemStorage)
        assert instance.location == os.path.abspath("/tmp/private")


def test_resolver_falls_back_to_default_when_alias_missing():
    with override_settings(
        STORAGES={
            "default": {
                "BACKEND": "django.core.files.storage.FileSystemStorage",
                "OPTIONS": {"location": "/tmp/only-default"},
            },
        }
    ):
        instance = get_encrypted_storage()
        assert isinstance(instance, SiloEncryptedStorageMixin)
    assert instance.location == os.path.abspath("/tmp/only-default")


def test_resolver_falls_back_to_filesystem_when_no_storages():
    with override_settings(STORAGES={}):
        instance = get_encrypted_storage()
        assert isinstance(instance, SiloEncryptedFileSystemStorage)


def test_resolver_does_not_double_wrap_already_encrypted_backend():
    """If someone points STORAGES at an already-encrypted class, compose
    should be a no-op — we don't stack two copies of the mixin.
    """
    backend = "encryption_suite.storage.SiloEncryptedFileSystemStorage"
    with override_settings(STORAGES={"encrypted": {"BACKEND": backend, "OPTIONS": {}}}):
        instance = get_encrypted_storage()
        assert type(instance) is SiloEncryptedFileSystemStorage


def test_resolver_caches_composed_class_per_backend():
    """Repeated calls with the same backend produce instances of the same
    composed class, not a fresh class each time.
    """
    with override_settings(
        STORAGES={
            "encrypted": {
                "BACKEND": "django.core.files.storage.FileSystemStorage",
                "OPTIONS": {"location": "/tmp/cached"},
            }
        }
    ):
        a = get_encrypted_storage()
        b = get_encrypted_storage()
        assert type(a) is type(b)


def test_resolver_passes_options_to_backend_init():
    """``OPTIONS`` must reach the backend's ``__init__`` — otherwise the
    whole 'configure in settings' promise breaks.
    """
    with override_settings(
        STORAGES={
            "encrypted": {
                "BACKEND": "django.core.files.storage.FileSystemStorage",
                "OPTIONS": {
                    "location": "/tmp/opts",
                    "base_url": "/media/",
                },
            }
        }
    ):
        instance = get_encrypted_storage()
        assert instance.location == os.path.abspath("/tmp/opts")
        assert instance.base_url == "/media/"
