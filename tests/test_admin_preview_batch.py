"""EncryptionAdminMixin fetches a changelist page's ciphertext in one query.

Each preview cell reads the batch instead of querying its own row, and falls
back to a single-row query outside the changelist.
"""

from __future__ import annotations

import pytest
from django.contrib import admin
from django.contrib.auth import get_user_model
from django.db import connection
from django.test import RequestFactory
from django.test.utils import CaptureQueriesContext

from encryption_suite.admin_mixins import EncryptionAdminMixin, _preview_field_names
from tests.testapp.models import Document, Note

pytestmark = pytest.mark.django_db


def _note_admin():
    cls = type("NoteAdmin", (EncryptionAdminMixin, admin.ModelAdmin), {"list_display": ("id", "title", "body")})
    return cls(Note, admin.site)


def _request():
    request = RequestFactory().get("/admin/testapp/note/")
    request.user = get_user_model().objects.create_superuser("root", "root@example.com", "pw")
    return request


def _cells(ma, cl):
    previews = [name for name in cl.list_display if name.startswith("encryption_suite_preview_")]
    return [[getattr(ma, name)(obj) for name in previews] for obj in cl.result_list]


def _notes(silo_context, count):
    return [Note.objects.create(team=silo_context, title=f"title {i}", body=f"body {i}") for i in range(count)]


def test_previews_read_the_page_batch_without_querying(silo_context):
    _notes(silo_context, 3)
    ma = _note_admin()
    cl = ma.get_changelist_instance(_request())
    with CaptureQueriesContext(connection) as queries:
        cells = _cells(ma, cl)
    assert len(queries) == 0
    assert len(cells) == 3
    for row in cells:
        for cell in row:
            assert "ciphertext (not decrypted)" in cell
            assert "title" not in cell.split(">", 1)[1] and "body" not in cell.split(">", 1)[1]


def test_page_batch_is_one_query_for_every_preview_column(silo_context):
    _notes(silo_context, 3)
    ma = _note_admin()
    request = _request()
    with CaptureQueriesContext(connection) as queries:
        ma.get_changelist_instance(request)
    raw = [q["sql"] for q in queries if '"title"' in q["sql"] and '"body"' in q["sql"] and " IN (" in q["sql"]]
    assert len(raw) == 1


def test_preview_outside_the_changelist_queries_its_row(silo_context):
    (note,) = _notes(silo_context, 1)
    ma = _note_admin()
    ma.get_list_display(None)
    with CaptureQueriesContext(connection) as queries:
        cell = ma.encryption_suite_preview_title(Note.objects.only("id").get(pk=note.pk))
    assert "ciphertext (not decrypted)" in cell
    assert len(queries) == 2  # the instance, then its row's ciphertext


def test_file_preview_batch_includes_the_display_name_column():
    assert _preview_field_names(Document, ["id", "encryption_suite_preview_upload"]) == ["upload", "upload_name"]
