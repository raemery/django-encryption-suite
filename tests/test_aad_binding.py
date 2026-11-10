"""Tests for AAD (associated data) binding on encrypted fields and files.

Covers two paths driven by a field's ``aad=``:

* **Field encryption** — ``engine.encrypt`` / ``engine.decrypt`` round-trip
  with AAD, the decrypt path on a field that declares ``aad=``, the
  length-prefixed encoding and value normalization, and tamper detection when an AAD column
  changes after a row was written.
* **File content streaming AEAD** — ``engine.encrypt_file`` /
  ``engine.open_decrypting_stream`` round-trip with AAD, the storage mixin
  reading AAD off the content object during ``_save``, and
  ``EncryptedFieldFile`` rebuilding the same AAD from the host instance
  during ``open()``.

Decrypt failures are checked for the row-identity log line so operators
can cross-reference the offending row in the admin (pk + AAD columns +,
for files, the storage path).
"""

from __future__ import annotations

import io
import logging
import uuid
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from django.db import models

from encryption_suite.adapters.silos.context import (
    override_current_silo,
)
from encryption_suite.engine import _CIPHERTEXT_PREFIX
from encryption_suite.fields import (
    EncryptedCharField,
    EncryptedFieldFile,
    EncryptedFileField,
    _build_aad_for_instance,
    _build_row_identity,
    aad_attnames,
    encode_aad,
)
from encryption_suite.registry import get_engine
from encryption_suite.storage import (
    SiloEncryptedStorageMixin,
    _DecryptingFile,
    _NonClosingWriter,
)

# ---------------------------------------------------------------------------
# Test models — defined transiently so we can exercise field protocol and
# AAD-resolution wiring without running migrations.
# ---------------------------------------------------------------------------


_model_counter = 0


def _make_aad_model(aad_columns=("user_id",)):
    """Build a throwaway model whose encrypted fields all declare ``aad=aad_columns``.

    The test model binds ``user_id``, a column the test can mutate. Building
    the class fires ``class_prepared``, which resolves each field's ``aad=``.
    """
    global _model_counter
    _model_counter += 1
    name = f"AadModel{_model_counter}"
    attrs = {
        "__module__": "tests.test_aad_binding",
        "Meta": type("Meta", (), {"app_label": "tests"}),
        "user_id": models.IntegerField(),
        "secret": EncryptedCharField(max_length=200, null=True, blank=True, aad=aad_columns),
        "scan_display_name": EncryptedCharField(max_length=255, null=True, blank=True, aad=aad_columns),
        "scan": EncryptedFileField(display_name_field="scan_display_name", null=True, blank=True, aad=aad_columns),
    }
    return type(name, (models.Model,), attrs)


def _field(model, name="secret"):
    return model._meta.get_field(name)


def _make_no_aad_model():
    global _model_counter
    _model_counter += 1
    name = f"PlainModel{_model_counter}"
    attrs = {
        "__module__": "tests.test_aad_binding",
        "Meta": type("Meta", (), {"app_label": "tests"}),
        "user_id": models.IntegerField(),
        "secret": EncryptedCharField(max_length=200, null=True, blank=True),
    }
    return type(name, (models.Model,), attrs)


@pytest.fixture
def silo():
    """Provide a context-bound silo for engine calls."""
    gk = SimpleNamespace(pk="aad-tests")
    with override_current_silo(gk):
        yield gk


# ---------------------------------------------------------------------------
# AAD helper unit tests — no DB, no engine
# ---------------------------------------------------------------------------


def test_aad_columns_resolved_on_field():
    model = _make_aad_model(aad_columns=("user_id",))
    assert aad_attnames(_field(model)) == ("user_id",)
    assert not hasattr(model, "_encryption_suite_aad_resolved")


def test_build_aad_for_instance_is_length_prefixed_label_then_columns():
    model = _make_aad_model(aad_columns=("user_id",))
    aad = _build_aad_for_instance(model, _field(model), model(user_id=42))
    label = f"{model._meta.label}.secret"
    assert aad == f"{len(label)}:{label}7:user_id2:42".encode()


def test_build_aad_changes_when_aad_column_changes():
    model = _make_aad_model(aad_columns=("user_id",))
    a = _build_aad_for_instance(model, _field(model), model(user_id=1))
    b = _build_aad_for_instance(model, _field(model), model(user_id=2))
    assert a != b


def test_build_aad_empty_when_field_has_no_aad():
    model = _make_no_aad_model()
    instance = model(user_id=1)
    assert _build_aad_for_instance(model, _field(model), instance) == b""


def test_build_aad_raises_on_none_value():
    model = _make_aad_model(aad_columns=("user_id",))
    instance = model(user_id=None)
    with pytest.raises(ValueError, match="AAD column 'user_id' is None"):
        _build_aad_for_instance(model, _field(model), instance)


def test_a_value_cannot_shift_a_boundary():
    """Without length prefixes these two rows would encode to the same bytes."""
    pairs_a = [("author", "a|team=b"), ("team", "c")]
    pairs_b = [("author", "a"), ("team", "b|team=c")]
    assert encode_aad("app.Note.body", pairs_a) != encode_aad("app.Note.body", pairs_b)


def test_encode_aad_is_empty_without_pairs():
    assert encode_aad("app.Note.body", []) == b""


def test_a_uuid_binds_the_same_as_its_hex_string():
    global _model_counter
    _model_counter += 1
    model = type(
        f"UuidAadModel{_model_counter}",
        (models.Model,),
        {
            "__module__": "tests.test_aad_binding",
            "Meta": type("Meta", (), {"app_label": "tests"}),
            "anchor": models.UUIDField(),
            "secret": EncryptedCharField(max_length=200, null=True, aad=("anchor",)),
        },
    )
    value = uuid.uuid4()
    field = _field(model)
    as_uuid = _build_aad_for_instance(model, field, SimpleNamespace(anchor=value))
    as_hex = _build_aad_for_instance(model, field, SimpleNamespace(anchor=value.hex))
    assert as_uuid == as_hex


def test_two_fields_on_one_model_bind_different_columns():
    global _model_counter
    _model_counter += 1
    model = type(
        f"TwoAadModel{_model_counter}",
        (models.Model,),
        {
            "__module__": "tests.test_aad_binding",
            "Meta": type("Meta", (), {"app_label": "tests"}),
            "user_id": models.IntegerField(),
            "other_id": models.IntegerField(),
            "first": EncryptedCharField(max_length=200, null=True, aad=("user_id",)),
            "second": EncryptedCharField(max_length=200, null=True, aad=("other_id",)),
        },
    )
    first, second = _field(model, "first"), _field(model, "second")
    assert aad_attnames(first) == ("user_id",)
    assert aad_attnames(second) == ("other_id",)
    row = model(user_id=1, other_id=2)
    moved = model(user_id=1, other_id=3)
    assert _build_aad_for_instance(model, first, row) == _build_aad_for_instance(model, first, moved)
    assert _build_aad_for_instance(model, second, row) != _build_aad_for_instance(model, second, moved)


def test_build_row_identity_names_aad_columns_without_their_values_by_default():
    """A schema binding a name or an email must not write them to the log."""
    model = _make_aad_model(aad_columns=("user_id",))
    identity = _build_row_identity(model, model(pk=7, user_id=42), _field(model))
    assert identity == "pk=7,user_id=<populated>"


def test_build_row_identity_says_which_bound_column_is_empty():
    model = _make_aad_model(aad_columns=("user_id",))
    assert _build_row_identity(model, model(pk=7, user_id=None), _field(model)) == "pk=7,user_id=<empty>"


def test_build_row_identity_carries_values_when_log_aad_values_is_on(settings):
    settings.ENCRYPTION = {**settings.ENCRYPTION, "LOG_AAD_VALUES": True}
    model = _make_aad_model(aad_columns=("user_id",))
    identity = _build_row_identity(model, model(pk=7, user_id=42), _field(model))
    assert identity == "pk=7,user_id=42"


def test_build_row_identity_skips_pk_in_aad_when_already_listed():
    """``pk`` is added once even if it's also an AAD column."""
    model = _make_aad_model(aad_columns=("pk", "user_id"))
    instance = model(pk=7, user_id=42)
    identity = _build_row_identity(model, instance, _field(model))
    # pk= appears exactly once.
    assert identity.count("pk=") == 1


def test_build_row_identity_empty_when_no_aad_and_no_pk():
    model = _make_no_aad_model()
    instance = model()  # pk is None
    assert _build_row_identity(model, instance, _field(model)) == ""


# ---------------------------------------------------------------------------
# Engine-level AAD round-trip — field AEAD
# ---------------------------------------------------------------------------


@pytest.mark.django_db
def test_engine_encrypt_decrypt_roundtrips_with_aad(silo):
    engine = get_engine()
    aad = b"app.Model.field|user_id=42"
    ct = engine.encrypt("hello", aad=aad)
    assert ct.startswith(_CIPHERTEXT_PREFIX)
    pt = engine.decrypt(ct, aad=aad)
    assert pt == "hello"


@pytest.mark.django_db
def test_engine_decrypt_fails_on_aad_mismatch(silo, caplog):
    engine = get_engine()
    ct = engine.encrypt("hello", aad=b"original-aad")
    with caplog.at_level(logging.ERROR, logger="encryption_suite.engine"):
        with pytest.raises(ValueError, match="Decryption failed"):
            engine.decrypt(
                ct,
                aad=b"tampered-aad",
                field_name="app.Model.secret",
                row_identity="pk=1,user_id=42",
            )
    # Log line carries the row identity for cross-reference.
    assert any('row="pk=1,user_id=42"' in rec.getMessage() for rec in caplog.records)


@pytest.mark.django_db
def test_engine_decrypt_succeeds_with_empty_aad_when_encrypted_empty(silo):
    """Regression: non-AAD models continue to work with empty AAD."""
    engine = get_engine()
    ct = engine.encrypt("plain", aad=b"")
    assert engine.decrypt(ct, aad=b"") == "plain"


# ---------------------------------------------------------------------------
# Engine-level AAD round-trip — file streaming AEAD
# ---------------------------------------------------------------------------


@pytest.mark.django_db
def test_engine_streaming_roundtrips_with_aad(silo):
    engine = get_engine()
    plaintext = b"file content " * 10
    ct_buf = io.BytesIO()
    engine.encrypt_file(io.BytesIO(plaintext), _NonClosingWriter(ct_buf), aad=b"row-aad")
    ct_buf.seek(0)

    pt_buf = io.BytesIO()
    engine.decrypt_file(ct_buf, pt_buf, aad=b"row-aad")
    assert pt_buf.getvalue() == plaintext


@pytest.mark.django_db
def test_engine_streaming_decrypt_fails_on_aad_mismatch(silo):
    engine = get_engine()
    ct_buf = io.BytesIO()
    engine.encrypt_file(io.BytesIO(b"abc"), _NonClosingWriter(ct_buf), aad=b"good-aad")
    ct_buf.seek(0)

    # Tink Streaming AEAD raises on read, not on stream creation.
    stream = engine.open_decrypting_stream(ct_buf, aad=b"bad-aad")
    with pytest.raises(Exception):  # noqa: B017 — Tink raises a generic error on tampered AAD
        stream.read()


@pytest.mark.django_db
def test_engine_open_decrypting_stream_success_log_omits_row_identity(silo, caplog):
    """row_identity is intentionally omitted from the file decrypt success log
    (AAD-bound column values may contain PII; success entries are high-volume).
    Row context still appears on the error path."""
    engine = get_engine()
    ct_buf = io.BytesIO()
    engine.encrypt_file(io.BytesIO(b"data"), ct_buf, aad=b"aad")
    ct_buf.seek(0)
    with caplog.at_level(logging.INFO, logger="encryption_suite.engine"):
        engine.open_decrypting_stream(ct_buf, aad=b"aad", row_identity="pk=1,user_id=42,file=encryption_suite/x.bin")
    msgs = [rec.getMessage() for rec in caplog.records]
    assert not any("pk=1" in m or "user_id=42" in m for m in msgs), (
        "row_identity must not appear in file decrypt success log"
    )


# ---------------------------------------------------------------------------
# _DecryptingFile — read-error logging carries row identity
# ---------------------------------------------------------------------------


def test_decrypting_file_logs_row_identity_on_read_error(caplog):
    class _Boom:
        def read(self, *_a, **_k):
            raise ValueError("Decryption failed (corrupt ciphertext).")

    df = _DecryptingFile(
        decrypting_stream=_Boom(),
        ciphertext_source=io.BytesIO(b""),
        name="encryption_suite/abc.bin",
        row_identity="pk=1,user_id=42,file=encryption_suite/abc.bin",
    )
    with caplog.at_level(logging.ERROR, logger="encryption_suite.storage"):
        with pytest.raises(ValueError):
            df.read()
    assert any('row="pk=1,user_id=42,file=encryption_suite/abc.bin"' in rec.getMessage() for rec in caplog.records)


def test_decrypting_file_no_row_identity_still_logs():
    """When no identity is supplied (direct storage.open path), the log line
    still appears but without the row prefix."""

    class _Boom:
        def read(self, *_a, **_k):
            raise ValueError("boom")

    df = _DecryptingFile(
        decrypting_stream=_Boom(),
        ciphertext_source=io.BytesIO(b""),
        name="x.bin",
    )
    with pytest.raises(ValueError):
        df.read()


# ---------------------------------------------------------------------------
# Storage mixin reads AAD off the content object during _save
# ---------------------------------------------------------------------------


class _CapturingBackend:
    """Stand-in storage backend that captures _save calls without persisting."""

    def __init__(self):
        self.saved = []

    def _save(self, name, content):
        self.saved.append((name, content.read()))
        return name


class _StorageUnderTest(SiloEncryptedStorageMixin, _CapturingBackend):
    pass


def test_storage_save_reads_aad_off_content_attribute():
    storage = _StorageUnderTest()

    captured = {}

    def fake_encrypt_file(input_stream, output_stream, aad=b"", silo=None, key_set=None):
        captured["aad"] = aad
        # Write a sentinel so the content goes through.
        output_stream.write(b"ENCRYPTED")

    fake_engine = MagicMock()
    fake_engine.encrypt_file.side_effect = fake_encrypt_file
    storage._get_engine = lambda: fake_engine

    content = io.BytesIO(b"plaintext")
    content._encryption_suite_aad = b"row-aad"
    storage._save("name.bin", content)

    assert captured["aad"] == b"row-aad"


def test_storage_save_uses_empty_aad_when_attribute_absent():
    storage = _StorageUnderTest()
    captured = {}

    def fake_encrypt_file(input_stream, output_stream, aad=b"", silo=None, key_set=None):
        captured["aad"] = aad
        output_stream.write(b"x")

    fake_engine = MagicMock()
    fake_engine.encrypt_file.side_effect = fake_encrypt_file
    storage._get_engine = lambda: fake_engine

    storage._save("name.bin", io.BytesIO(b"plain"))
    assert captured["aad"] == b""


def test_storage_open_raw_skips_decryption():
    """``_open_raw`` returns the raw underlying file without wrapping it in a
    ``_DecryptingFile``, so :class:`EncryptedFieldFile` can perform an
    AAD-aware decrypt itself."""
    sentinel = io.BytesIO(b"ciphertext")

    class _Backend:
        def _open(self_, name, mode="rb"):
            return sentinel

    class _S(SiloEncryptedStorageMixin, _Backend):
        pass

    s = _S()
    assert s._open_raw("name.bin") is sentinel


def test_open_raw_wraps_backend_failure_as_storage_error():
    """A missing/unreadable blob becomes EncryptedFileStorageError, not a raw
    backend error, so the read path degrades like the write/existence path."""
    from encryption_suite.exceptions import EncryptedFileStorageError

    class _Backend:
        def _open(self_, name, mode="rb"):
            raise FileNotFoundError("File does not exist: encryption_suite/x.bin")

    class _S(SiloEncryptedStorageMixin, _Backend):
        pass

    with pytest.raises(EncryptedFileStorageError):
        _S()._open_raw("encryption_suite/x.bin")


def test_open_raw_passes_through_existing_storage_error():
    """An already-typed EncryptedFileStorageError is not double-wrapped."""
    from encryption_suite.exceptions import EncryptedFileStorageError

    err = EncryptedFileStorageError("already typed")

    class _Backend:
        def _open(self_, name, mode="rb"):
            raise err

    class _S(SiloEncryptedStorageMixin, _Backend):
        pass

    with pytest.raises(EncryptedFileStorageError) as ei:
        _S()._open_raw("x")
    assert ei.value is err


def test_probe_degrades_when_ciphertext_blob_missing():
    """probe() reports the file as undisplayable (not a 500) when the storage
    backend cannot read the ciphertext blob."""
    import encryption_suite.registry as registry_mod
    from encryption_suite.exceptions import EncryptedFileStorageError

    model = _make_no_aad_model()
    EncryptedCharField(max_length=255, null=True, blank=True).contribute_to_class(model, "scan_display_name")
    EncryptedFileField(display_name_field="scan_display_name", null=True, blank=True).contribute_to_class(model, "scan")
    instance = model(pk=1, user_id=10)
    field = model._meta.get_field("scan")

    fake_storage = MagicMock()
    fake_storage._open_raw.side_effect = EncryptedFileStorageError("blob missing")

    fieldfile = EncryptedFieldFile(instance, field, "encryption_suite/missing.bin")
    fieldfile.storage = fake_storage

    original_get_engine = registry_mod.get_engine
    registry_mod.get_engine = lambda: MagicMock()
    try:
        assert fieldfile.probe() is False
    finally:
        registry_mod.get_engine = original_get_engine
    assert isinstance(fieldfile._probe_error, EncryptedFileStorageError)


def test_probe_degrades_when_aad_build_fails():
    """probe() degrades (not a 500) when AAD build raises a raw ValueError —
    e.g. a None AAD column — instead of letting it escape the read path."""
    import encryption_suite.registry as registry_mod
    from encryption_suite.exceptions import EncryptedFileDecryptionError

    model = _make_aad_model(aad_columns=("user_id",))
    instance = model(pk=5, user_id=None)  # None AAD column → raw ValueError in build
    field = model._meta.get_field("scan")

    fieldfile = EncryptedFieldFile(instance, field, "encryption_suite/x.bin")
    fieldfile.storage = MagicMock()

    original_get_engine = registry_mod.get_engine
    registry_mod.get_engine = lambda: MagicMock()
    try:
        assert fieldfile.probe() is False
    finally:
        registry_mod.get_engine = original_get_engine
    assert isinstance(fieldfile._probe_error, EncryptedFileDecryptionError)


# ---------------------------------------------------------------------------
# EncryptedFieldFile rebuilds AAD/identity from the host instance
# ---------------------------------------------------------------------------


def test_encrypted_field_file_passes_aad_and_identity_to_engine():
    """``EncryptedFieldFile._open_decrypting`` must:

    * resolve AAD from the host instance using the field's ``aad=``,
    * build a row-identity string that combines pk, AAD columns, and the
      storage path,
    * call the engine with both, so ciphertext written under the same AAD
      decrypts and any read-time error logs the row identity.
    """
    model = _make_aad_model(aad_columns=("user_id",))
    instance = model(pk=99, user_id=42)
    field = model._meta.get_field("scan")

    fake_storage = MagicMock()
    fake_ciphertext = io.BytesIO(b"ct")
    fake_storage._open_raw.return_value = fake_ciphertext

    captured = {}

    fake_engine = MagicMock()

    def fake_open_stream(source, aad=b"", silo=None, row_identity="", field_name="", key_set="default"):
        captured["aad"] = aad
        captured["row_identity"] = row_identity
        captured["field_name"] = field_name
        return io.BytesIO(b"plaintext")

    fake_engine.open_decrypting_stream.side_effect = fake_open_stream

    fielfile = EncryptedFieldFile(instance, field, "encryption_suite/abc.bin")
    fielfile.storage = fake_storage

    import encryption_suite.fields as fields_mod
    import encryption_suite.registry as registry_mod

    original_get_engine = registry_mod.get_engine
    registry_mod.get_engine = lambda: fake_engine
    fields_mod.get_engine = lambda: fake_engine  # in case re-imported
    try:
        result = fielfile._open_decrypting()
    finally:
        registry_mod.get_engine = original_get_engine

    expected_aad = _build_aad_for_instance(model, _field(model, "scan"), instance)
    assert captured["aad"] == expected_aad
    assert "pk=99" in captured["row_identity"]
    # The bound column is named, its value withheld: LOG_AAD_VALUES is off.
    assert "user_id=<populated>" in captured["row_identity"]
    assert "file=encryption_suite/abc.bin" in captured["row_identity"]
    assert captured["field_name"] == f"{model._meta.label}.scan"
    assert isinstance(result, _DecryptingFile)


def test_encrypted_field_file_uses_empty_aad_for_non_aad_model():
    model = _make_no_aad_model()
    # _make_no_aad_model omits scan; add one for this test.
    EncryptedCharField(max_length=255, null=True, blank=True).contribute_to_class(model, "scan_display_name")
    EncryptedFileField(display_name_field="scan_display_name", null=True, blank=True).contribute_to_class(model, "scan")
    instance = model(pk=1, user_id=10)
    field = model._meta.get_field("scan")

    fake_storage = MagicMock()
    fake_storage._open_raw.return_value = io.BytesIO(b"ct")

    captured = {}
    fake_engine = MagicMock()

    def fake_open_stream(source, aad=b"", silo=None, row_identity="", field_name="", key_set="default"):
        captured["aad"] = aad
        captured["row_identity"] = row_identity
        captured["field_name"] = field_name
        return io.BytesIO(b"plaintext")

    fake_engine.open_decrypting_stream.side_effect = fake_open_stream

    fielfile = EncryptedFieldFile(instance, field, "encryption_suite/x.bin")
    fielfile.storage = fake_storage

    import encryption_suite.registry as registry_mod

    original = registry_mod.get_engine
    registry_mod.get_engine = lambda: fake_engine
    try:
        fielfile._open_decrypting()
    finally:
        registry_mod.get_engine = original

    # No AAD columns → empty AAD; pk is always included in row identity.
    assert captured["aad"] == b""
    assert captured["row_identity"] == "pk=1,file=encryption_suite/x.bin"


# ---------------------------------------------------------------------------
# End-to-end engine round-trip exercising all three layers (field + file)
# under matched and mismatched AAD.
# ---------------------------------------------------------------------------


@pytest.mark.django_db
def test_field_and_file_share_aad_policy_for_same_row(silo):
    """The same model instance state produces the AAD used for both an
    encrypted field and the encrypted file content. Mutating an AAD column
    breaks decrypts on both, demonstrating they bind to the same row identity.
    """
    model = _make_aad_model(aad_columns=("user_id",))
    instance = model(pk=1, user_id=42)

    field_aad = _build_aad_for_instance(model, _field(model), instance)
    file_aad = _build_aad_for_instance(model, _field(model, "scan"), instance)

    engine = get_engine()
    field_ct = engine.encrypt("notes", aad=field_aad)
    file_ct_buf = io.BytesIO()
    engine.encrypt_file(io.BytesIO(b"file body"), _NonClosingWriter(file_ct_buf), aad=file_aad)
    file_ct_buf.seek(0)
    file_ct_bytes = file_ct_buf.read()  # save before decrypt_file closes the buffer

    # Same instance state → both decrypt cleanly.
    assert engine.decrypt(field_ct, aad=field_aad) == "notes"
    pt_buf = io.BytesIO()
    engine.decrypt_file(io.BytesIO(file_ct_bytes), pt_buf, aad=file_aad)
    assert pt_buf.getvalue() == b"file body"

    # Tamper the AAD column → both decrypts fail.
    instance.user_id = 999
    tampered_field_aad = _build_aad_for_instance(model, _field(model), instance)
    tampered_file_aad = _build_aad_for_instance(model, _field(model, "scan"), instance)
    assert tampered_field_aad != field_aad
    assert tampered_file_aad != file_aad

    with pytest.raises(ValueError, match="Decryption failed"):
        engine.decrypt(field_ct, aad=tampered_field_aad)

    stream = engine.open_decrypting_stream(io.BytesIO(file_ct_bytes), aad=tampered_file_aad)
    with pytest.raises(Exception):  # noqa: B017 — Tink raises a generic error on tampered AAD
        stream.read()


# ---------------------------------------------------------------------------
# aad= is a field option, so migrations record it
# ---------------------------------------------------------------------------


def test_changing_aad_produces_an_alter_field():
    from django.db.migrations.autodetector import MigrationAutodetector
    from django.db.migrations.operations import AlterField
    from django.db.migrations.state import ModelState, ProjectState

    def state(aad):
        project = ProjectState()
        project.add_model(
            ModelState(
                "shop",
                "Item",
                [
                    ("id", models.AutoField(primary_key=True)),
                    ("owner", models.IntegerField()),
                    ("notes", EncryptedCharField(max_length=100, null=True, aad=aad)),
                ],
            )
        )
        return project

    # _detect_changes, not changes(): the public entry drops an app with no
    # migration graph unless a questioner agrees to an initial migration.
    changes = MigrationAutodetector(state(()), state(("owner",)))._detect_changes()

    (migration,) = changes["shop"]
    (operation,) = migration.operations
    assert isinstance(operation, AlterField)
    assert operation.name == "notes"
    assert operation.field.aad == ("owner",)
