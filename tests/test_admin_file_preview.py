"""Tests for EncryptionAdminMixin's EncryptedFileField list-display
preview — the combined storage-key / display-name-ciphertext cell.
"""

from __future__ import annotations

from unittest.mock import patch

from django.contrib import admin
from django.db import models

from encryption_suite.admin_mixins import EncryptionAdminMixin
from encryption_suite.fields import EncryptedCharField, EncryptedFileField

_model_counter = 0


def _make_model(with_file=True):
    global _model_counter
    _model_counter += 1
    attrs = {
        "__module__": "tests.test_admin_file_preview",
        "Meta": type("Meta", (), {"app_label": "tests"}),
        "pseudonym": models.CharField(max_length=50),
        "first_name": EncryptedCharField(max_length=100),
    }
    model = type(f"AdminPreviewModel{_model_counter}", (models.Model,), attrs)
    if with_file:
        EncryptedCharField(max_length=255, null=True, blank=True).contribute_to_class(model, "scan_display_name")
        EncryptedFileField(display_name_field="scan_display_name", null=True, blank=True).contribute_to_class(
            model, "scan"
        )
    return model


class _BaseAdmin(admin.ModelAdmin):
    pass


def _make_admin(model, list_display):
    cls = type(
        "TestAdmin",
        (EncryptionAdminMixin, _BaseAdmin),
        {"list_display": tuple(list_display)},
    )
    return cls(model, admin.site)


def test_file_field_list_display_uses_combined_preview():
    model = _make_model()
    ma = _make_admin(model, ["pseudonym", "scan", "first_name"])
    result = ma.get_list_display(request=None)
    # pseudonym passes through; scan and first_name get preview methods.
    assert result[0] == "pseudonym"
    assert result[1] == "encryption_suite_preview_scan"
    assert result[2] == "encryption_suite_preview_first_name"

    file_method = ma.encryption_suite_preview_scan
    # File-field preview uses a distinct short_description signaling
    # that the cell shows the companion display-name's ciphertext —
    # the differentiating feature against the plain char-field preview.
    assert "name ciphertext" in file_method.short_description

    char_method = ma.encryption_suite_preview_first_name
    assert "first_name (ciphertext)" == char_method.short_description


def test_file_preview_renders_storage_key_and_companion_ciphertext():
    model = _make_model()
    ma = _make_admin(model, ["scan"])
    ma.get_list_display(request=None)  # ensures method is attached

    instance = model(pk=1)
    storage_key = "encryption_suite/abc123-def456-0000000000000000.bin"
    companion_ct = "AQEBA7x9k2lkjasdf098asdfkljasdf0987asdfkl==="

    class _FakeCursor:
        def __enter__(self_):
            return self_

        def __exit__(self_, *exc):
            return False

        def execute(self_, *args, **kwargs):
            pass

        def fetchone(self_):
            return (storage_key, companion_ct)

    class _FakeConn:
        class ops:
            @staticmethod
            def quote_name(n):
                return f'"{n}"'

        def cursor(self_):
            return _FakeCursor()

    with patch(
        "encryption_suite.admin_mixins.connections",
        new={"default": _FakeConn()},
    ):
        rendered = ma.encryption_suite_preview_scan(instance)

    rendered = str(rendered)
    # Storage key prefix is visible (truncated by CIPHERTEXT_PREVIEW_LENGTH=48).
    assert "encryption_suite/abc123" in rendered
    # Companion ciphertext prefix is visible.
    assert "AQEBA7x9" in rendered
    # Both sides are rendered as <code> with distinct titles.
    assert "storage key" in rendered
    assert "display name (ciphertext" in rendered


def test_file_preview_handles_null_companion():
    model = _make_model()
    ma = _make_admin(model, ["scan"])
    ma.get_list_display(request=None)

    instance = model(pk=1)

    class _FakeCursor:
        def __enter__(self_):
            return self_

        def __exit__(self_, *exc):
            return False

        def execute(self_, *a, **k):
            pass

        def fetchone(self_):
            return ("encryption_suite/x.bin", None)

    class _FakeConn:
        class ops:
            @staticmethod
            def quote_name(n):
                return f'"{n}"'

        def cursor(self_):
            return _FakeCursor()

    with patch(
        "encryption_suite.admin_mixins.connections",
        new={"default": _FakeConn()},
    ):
        rendered = str(ma.encryption_suite_preview_scan(instance))

    assert "encryption_suite/x.bin" in rendered
    # Null companion is omitted entirely (no second <code> block, no
    # em-dash placeholder on the companion side). A missing display name
    # is a normal state for admin uploads, not a degraded one — the
    # storage key alone is the cell's payload.
    assert rendered.count("<code") == 1
    assert "display name" not in rendered


def test_file_preview_unsaved_instance_returns_placeholder():
    model = _make_model()
    ma = _make_admin(model, ["scan"])
    ma.get_list_display(request=None)
    instance = model()  # pk is None
    assert ma.encryption_suite_preview_scan(instance) == "—"
