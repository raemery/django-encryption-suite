"""Tests for the optional DRF integration (encryption_suite.contrib.drf).

Covers the exception handler (write-side: EncryptionError -> {code, detail} +
status) and the serializer mixin (read-side: undecryptable field -> null +
encryption_suite_errors marker).
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

pytest.importorskip("rest_framework")

from django.db import models  # noqa: E402
from rest_framework import serializers  # noqa: E402

from encryption_suite.contrib import drf as drf_module  # noqa: E402
from encryption_suite.contrib.drf import (  # noqa: E402
    BlindIndexUniqueValidator,
    EncryptionSerializerMixin,
    api_exception_handler,
)
from encryption_suite.exceptions import (  # noqa: E402
    DekDeletedError,
    DekDeletionScheduledError,
    DekReencryptionInProgressError,
    EncryptedFieldDecryptionError,
    EncryptedFieldEncryptionError,
    EncryptedFileStorageError,
    EncryptionConfigurationError,
    EncryptionError,
    KekNotProvisionedError,
    KekPendingDeletionError,
    KekUnavailableError,
    MissingDekError,
)
from encryption_suite.fields import EncryptedCharField  # noqa: E402

# ---------------------------------------------------------------------------
# Exception handler (write-side)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "exc_cls, expected_status, expected_code",
    [
        # The one upstream failure whose duration nobody knows. A capped
        # client-side backoff is the right answer, so it is the only status a
        # client should retry.
        (KekUnavailableError, 502, "kek_unavailable"),
        # Key states that clear only when a person acts. None can be estimated
        # and all can persist for days, so none may read as temporary.
        (MissingDekError, 409, "missing_dek"),
        (KekNotProvisionedError, 409, "kek_not_provisioned"),
        (DekDeletionScheduledError, 409, "dek_deletion_scheduled"),
        (DekDeletedError, 409, "dek_deleted"),
        (DekReencryptionInProgressError, 409, "dek_reencryption_in_progress"),
        # Ours to fix, not the client's.
        (EncryptionConfigurationError, 500, "configuration_error"),
        (EncryptedFieldEncryptionError, 500, "field_encryption_failed"),
        (EncryptedFieldDecryptionError, 500, "field_decryption_failed"),
        (EncryptedFileStorageError, 500, "file_storage_error"),
    ],
)
def test_handler_maps_encryption_suite_errors(exc_cls, expected_status, expected_code):
    resp = api_exception_handler(exc_cls("boom"), {})
    assert resp.status_code == expected_status
    assert resp.data["code"] == expected_code
    assert "detail" in resp.data


def test_a_subclass_follows_its_parent():
    """The defect this map had: an exact-type lookup missed every subclass.

    ``KekPendingDeletionError`` subclasses ``KekNotProvisionedError`` and has no
    entry of its own, so it used to fall through to the default — reporting the
    opposite retryability from the parent describing the same condition.
    """
    resp = api_exception_handler(KekPendingDeletionError("boom"), {})

    assert resp.status_code == 409
    assert resp.data["code"] == "kek_pending_deletion"


def test_an_entry_of_its_own_beats_the_parents(monkeypatch):
    """Most-derived first, so a project may override an inherited status."""

    class ProjectSpecificMiss(MissingDekError):
        code = "project_specific_miss"

    monkeypatch.setitem(drf_module._HTTP_STATUS, ProjectSpecificMiss, 418)

    assert api_exception_handler(ProjectSpecificMiss("boom"), {}).status_code == 418


def test_an_unclassified_subclass_is_ours_not_the_clients():
    """A subclass nobody has reasoned about must not blame the request."""

    class SomethingNew(EncryptionError):
        code = "something_new"

    assert api_exception_handler(SomethingNew("boom"), {}).status_code == 500


def test_handler_delegates_non_encryption_suite_error():
    # A plain exception is not a EncryptionError; DRF's default handler returns
    # None for an unhandled type, so the handler must pass it through.
    assert api_exception_handler(ValueError("x"), {}) is None


# ---------------------------------------------------------------------------
# Serializer mixin (read-side)
# ---------------------------------------------------------------------------


class _BaseSerializer(serializers.Serializer):
    name = serializers.CharField()
    notes = serializers.CharField()


class _MixedSerializer(EncryptionSerializerMixin, _BaseSerializer):
    pass


def test_mixin_marks_undecryptable_field():
    instance = SimpleNamespace(
        name="ok",
        notes="ignored-sentinel-string",
        _encryption_suite_errors={"notes": EncryptedFieldDecryptionError("x")},
    )
    data = _MixedSerializer().to_representation(instance)
    assert data["name"] == "ok"
    assert data["notes"] is None
    assert data["encryption_suite_errors"] == {"notes": {"code": "field_decryption_failed"}}


def test_mixin_passthrough_when_no_errors():
    instance = SimpleNamespace(name="ok", notes="secret")
    data = _MixedSerializer().to_representation(instance)
    assert data == {"name": "ok", "notes": "secret"}
    assert "encryption_suite_errors" not in data


# ---------------------------------------------------------------------------
# Serializer mixin (write-side: the uniqueness DRF cannot infer)
# ---------------------------------------------------------------------------


class _Uniquely(models.Model):
    """A model whose plaintext is held unique over a digest."""

    handle = EncryptedCharField(key_set="system", max_length=100, null=True, blind_index=True, unique=True)
    plain = models.CharField(max_length=100, blank=True, default="")

    class Meta:
        app_label = "tests"


class _UniquelySerializer(EncryptionSerializerMixin, serializers.ModelSerializer):
    class Meta:
        model = _Uniquely
        fields = ["id", "handle", "plain"]


@pytest.fixture
def uniquely_table(transactional_db):
    from django.db import connection

    with connection.schema_editor() as se:
        se.create_model(_Uniquely)
    yield
    with connection.schema_editor() as se:
        se.delete_model(_Uniquely)


def test_the_indexed_unique_field_gets_a_validator_and_the_others_do_not():
    fields = _UniquelySerializer().get_fields()

    assert any(isinstance(v, BlindIndexUniqueValidator) for v in fields["handle"].validators)
    assert not any(isinstance(v, BlindIndexUniqueValidator) for v in fields["plain"].validators)


def test_a_duplicate_is_a_field_error_rather_than_an_integrity_error(uniquely_table):
    _Uniquely.objects.create(handle="ann")

    serializer = _UniquelySerializer(data={"handle": "ann"})

    assert not serializer.is_valid()
    assert serializer.errors["handle"][0].code == "unique"


def test_a_fresh_value_validates(uniquely_table):
    _Uniquely.objects.create(handle="ann")

    assert _UniquelySerializer(data={"handle": "bob"}).is_valid()


def test_updating_the_row_that_holds_the_value_is_not_a_duplicate_of_itself(uniquely_table):
    row = _Uniquely.objects.create(handle="ann")

    serializer = _UniquelySerializer(instance=row, data={"handle": "ann"})

    assert serializer.is_valid(), serializer.errors


def test_the_validator_is_attached_once_however_often_fields_are_built():
    serializer = _UniquelySerializer()
    first = [v for v in serializer.get_fields()["handle"].validators if isinstance(v, BlindIndexUniqueValidator)]
    second = [v for v in serializer.get_fields()["handle"].validators if isinstance(v, BlindIndexUniqueValidator)]

    assert len(first) == 1 and len(second) == 1
