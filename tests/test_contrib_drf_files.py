"""The DRF serializer mixin's file branch: an unreadable encrypted file is marked, not served.

A file field fails when its blob is read, not when it is serialized, so the
mixin reports a probe that already ran and probes only when the serializer asks.
These run against real encrypted storage, so the slug in each marker is the one
the probe actually caught.
"""

from __future__ import annotations

import pytest

pytest.importorskip("rest_framework")

from django.core.files.base import ContentFile  # noqa: E402
from django.core.files.uploadedfile import SimpleUploadedFile  # noqa: E402
from django.db import connection, models  # noqa: E402
from rest_framework import serializers  # noqa: E402
from rest_framework.negotiation import DefaultContentNegotiation  # noqa: E402
from rest_framework.test import APIRequestFactory  # noqa: E402
from rest_framework.views import APIView  # noqa: E402

from encryption_suite.contrib.drf import EncryptionSerializerMixin, IgnoreClientContentNegotiation  # noqa: E402
from encryption_suite.exceptions import EncryptedFieldDecryptionError  # noqa: E402
from encryption_suite.fields import (  # noqa: E402
    EncryptedCharField,
    EncryptedFieldFile,
    EncryptedFileField,
    UndecryptableValue,
)
from encryption_suite.file_view_helpers import serve_encrypted_file  # noqa: E402


class _SystemDoc(models.Model):
    doc = EncryptedFileField(key_set="system", display_name_field="doc_name", null=True, blank=True)
    doc_name = EncryptedCharField(key_set="system", max_length=255, null=True, blank=True)

    class Meta:
        app_label = "tests"


class _SiloDoc(models.Model):
    doc = EncryptedFileField(display_name_field="doc_name", null=True, blank=True)
    doc_name = EncryptedCharField(max_length=255, null=True, blank=True)

    class Meta:
        app_label = "tests"


class _SystemDocSerializer(EncryptionSerializerMixin, serializers.ModelSerializer):
    class Meta:
        model = _SystemDoc
        fields = ["id", "doc", "doc_name"]


class _ProbingSystemDocSerializer(_SystemDocSerializer):
    PROBE_ENCRYPTED_FILES = True


class _ProbingSiloDocSerializer(EncryptionSerializerMixin, serializers.ModelSerializer):
    PROBE_ENCRYPTED_FILES = True

    class Meta:
        model = _SiloDoc
        fields = ["id", "doc", "doc_name"]


@pytest.fixture
def doc_tables(transactional_db):
    with connection.schema_editor() as editor:
        editor.create_model(_SystemDoc)
        editor.create_model(_SiloDoc)
    yield
    with connection.schema_editor() as editor:
        editor.delete_model(_SystemDoc)
        editor.delete_model(_SiloDoc)


def _system_doc(content=b"payload", name="report.pdf"):
    row = _SystemDoc.objects.create(doc=ContentFile(content, name=name))
    return _SystemDoc.objects.get(pk=row.pk)


def _tamper(fieldfile):
    """Flip the last stored byte, so the ciphertext no longer authenticates."""
    path = fieldfile.storage.path(fieldfile.name)
    with open(path, "r+b") as handle:
        handle.seek(-1, 2)
        last = handle.read(1)
        handle.seek(-1, 2)
        handle.write(bytes([last[0] ^ 0xFF]))


def test_a_missing_system_blob_is_null_with_the_slug_the_probe_caught(doc_tables):
    row = _system_doc()
    row.doc.storage.delete(row.doc.name)

    data = _ProbingSystemDocSerializer(row).data

    assert data["doc"] is None
    assert data["doc_name"] == "report.pdf"
    assert data["encryption_suite_errors"] == {"doc": {"code": "file_storage_error"}}


def test_a_tampered_silo_file_is_null_with_the_slug_the_probe_caught(doc_tables, silo_context):
    created = _SiloDoc.objects.create(doc=ContentFile(b"payload", name="report.pdf"))
    row = _SiloDoc.objects.get(pk=created.pk)
    _tamper(row.doc)

    data = _ProbingSiloDocSerializer(row).data

    assert data["doc"] is None
    assert data["encryption_suite_errors"] == {"doc": {"code": "file_decryption_failed"}}


def test_a_readable_file_is_untouched(doc_tables):
    data = _ProbingSystemDocSerializer(_system_doc()).data

    assert data["doc"]
    assert "encryption_suite_errors" not in data


def test_without_probing_a_list_reads_no_blobs(doc_tables, monkeypatch):
    rows = [_system_doc(name=f"r{i}.pdf") for i in range(5)]
    opened = []
    monkeypatch.setattr(EncryptedFieldFile, "_open_decrypting", lambda self, *a, **k: opened.append(self.name))

    data = _SystemDocSerializer(rows, many=True).data

    assert opened == []
    assert all(item["doc"] for item in data)


def test_without_probing_a_probe_the_view_already_ran_is_reported(doc_tables):
    row = _system_doc()
    row.doc.storage.delete(row.doc.name)
    assert row.doc.probe() is False

    data = _SystemDocSerializer(row).data

    assert data["doc"] is None
    assert data["encryption_suite_errors"] == {"doc": {"code": "file_storage_error"}}


def test_a_display_name_failure_is_reported_once_under_its_own_field(doc_tables):
    row = _system_doc()
    error = EncryptedFieldDecryptionError("x")
    row.__dict__["doc_name"] = UndecryptableValue(fallback="Unable to decrypt.", error=error, field_name="doc_name")
    row.__dict__["_encryption_suite_errors"] = {"doc_name": error}
    assert row.doc.is_undecryptable

    data = _ProbingSystemDocSerializer(row).data

    assert data["doc"]
    assert data["doc_name"] is None
    assert data["encryption_suite_errors"] == {"doc_name": {"code": "field_decryption_failed"}}


# ---------------------------------------------------------------------------
# Uploads: a ModelSerializer write goes through the field and the storage
# ---------------------------------------------------------------------------


class _SystemDocUploadSerializer(serializers.ModelSerializer):
    class Meta:
        model = _SystemDoc
        fields = ["id", "doc"]


class _SiloDocUploadSerializer(serializers.ModelSerializer):
    class Meta:
        model = _SiloDoc
        fields = ["id", "doc"]


def _stored_bytes(fieldfile) -> bytes:
    with fieldfile.storage._open_raw(fieldfile.name) as raw:
        return raw.read()


def test_a_system_file_uploaded_through_a_serializer_is_encrypted_and_reads_back(doc_tables):
    serializer = _SystemDocUploadSerializer(data={"doc": SimpleUploadedFile("scan.pdf", b"upload bytes")})
    assert serializer.is_valid(), serializer.errors

    row = _SystemDoc.objects.get(pk=serializer.save().pk)

    assert row.doc.name.startswith("encryption_suite_system/")
    assert "scan" not in row.doc.name
    assert b"upload bytes" not in _stored_bytes(row.doc)
    assert row.doc.display_name == "scan.pdf"
    with row.doc.open("rb") as handle:
        assert handle.read() == b"upload bytes"


def test_a_silo_file_uploaded_through_a_serializer_is_encrypted_and_reads_back(doc_tables, silo_context):
    serializer = _SiloDocUploadSerializer(data={"doc": SimpleUploadedFile("scan.pdf", b"upload bytes")})
    assert serializer.is_valid(), serializer.errors

    row = _SiloDoc.objects.get(pk=serializer.save().pk)

    assert row.doc.name.startswith("encryption_suite_default/")
    assert b"upload bytes" not in _stored_bytes(row.doc)
    assert row.doc.display_name == "scan.pdf"
    with row.doc.open("rb") as handle:
        assert handle.read() == b"upload bytes"


class _MixedSystemDocUploadSerializer(EncryptionSerializerMixin, _SystemDocUploadSerializer):
    pass


class _DeclaredLimitUploadSerializer(EncryptionSerializerMixin, serializers.ModelSerializer):
    doc = serializers.FileField(max_length=20)

    class Meta:
        model = _SystemDoc
        fields = ["id", "doc"]


def test_without_the_mixin_an_upload_name_is_held_to_the_stored_path_column():
    """The defect the mixin corrects: 100 bounds the opaque stored path, not the name a client sends."""
    assert _SystemDocUploadSerializer().fields["doc"].max_length == 100


def test_the_mixin_limits_an_upload_name_to_the_display_name_column_like_the_form():
    model_field = _SystemDoc._meta.get_field("doc")

    assert _MixedSystemDocUploadSerializer().fields["doc"].max_length == 255
    assert model_field.formfield().max_length == 255


def test_a_long_upload_name_is_accepted_and_kept_as_the_display_name(doc_tables):
    name = "a" * 120 + ".pdf"
    serializer = _MixedSystemDocUploadSerializer(data={"doc": SimpleUploadedFile(name, b"upload bytes")})
    assert serializer.is_valid(), serializer.errors

    row = _SystemDoc.objects.get(pk=serializer.save().pk)

    assert row.doc.display_name == name
    assert len(row.doc.name) < 100


def test_a_declared_max_length_is_left_alone():
    assert _DeclaredLimitUploadSerializer().fields["doc"].max_length == 20


# ---------------------------------------------------------------------------
# Downloads: IgnoreClientContentNegotiation
# ---------------------------------------------------------------------------


class _DownloadView(APIView):
    authentication_classes = []
    permission_classes = []
    content_negotiation_class = IgnoreClientContentNegotiation

    def get(self, request, pk):
        return serve_encrypted_file(request, _SystemDoc.objects.get(pk=pk), "doc")


class _NegotiatingDownloadView(_DownloadView):
    content_negotiation_class = DefaultContentNegotiation


@pytest.fixture
def drf_handler(settings):
    settings.REST_FRAMEWORK = {"EXCEPTION_HANDLER": "encryption_suite.contrib.drf.api_exception_handler"}


def _download(view, pk, accept):
    request = APIRequestFactory().get("/", HTTP_ACCEPT=accept)
    return view.as_view()(request, pk=pk)


def test_without_it_drf_refuses_a_client_that_asks_for_the_file(doc_tables, drf_handler):
    row = _system_doc()

    assert _download(_NegotiatingDownloadView, row.pk, "application/octet-stream").status_code == 406


@pytest.mark.parametrize("accept", ["application/octet-stream", "application/pdf", "*/*", "application/json"])
def test_a_file_downloads_whatever_the_client_accepts(doc_tables, drf_handler, accept):
    row = _system_doc(content=b"payload", name="report.pdf")

    response = _download(_DownloadView, row.pk, accept)

    assert response.status_code == 200
    assert b"".join(response.streaming_content) == b"payload"
    assert "report.pdf" in response["Content-Disposition"]


def test_a_failed_download_still_answers_code_and_detail(doc_tables, drf_handler):
    row = _system_doc()
    row.doc.storage.delete(row.doc.name)

    response = _download(_DownloadView, row.pk, "application/octet-stream")
    response.render()

    assert response.status_code == 500
    assert response["Content-Type"].startswith("application/json")
    assert response.data["code"] == "file_storage_error"
