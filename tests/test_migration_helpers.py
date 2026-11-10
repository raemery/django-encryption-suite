"""The migration helpers must read the column, not the field.

Every one of these tests runs against a **historical** model — the class
``migrate`` rebuilds from the migration files and hands to a ``RunPython``
callback — because that is the only place the fault these helpers had can
exist. A migration file records a field by its import path, so an encrypted
column comes back as a real encrypted field with its decrypting descriptor
attached, and with the ``aad=`` of the migration state, which during a
conversion is not the binding the stored values were written under. Read a
column off that model with ``getattr`` and you get plaintext, or — with no
silo in context, or under the wrong binding — the fallback label. Neither is
the column, and all three helpers used to decide what to write from it.

A test that builds its own ``apps`` double passes against that bug. These
render the real state through ``MigrationLoader``.
"""

from __future__ import annotations

import logging
from base64 import b64encode

import pytest
from django.contrib.auth.models import Group
from django.core.files.base import ContentFile
from django.db import connection
from django.db.migrations.loader import MigrationLoader

from encryption_suite import allow_plaintext_writes
from encryption_suite._internal import raw_cursor_fetch
from encryption_suite.adapters.silos.context import override_current_silo
from encryption_suite.engine import _CIPHERTEXT_PREFIX, is_silo_value
from encryption_suite.exceptions import EncryptionError
from encryption_suite.migration_helpers import (
    decrypt_field,
    encrypt_field,
    encrypt_file_field,
    reencrypt_for_aad_change,
)

pytestmark = pytest.mark.django_db

#: How ``tests.silo.GroupSiloAdapter`` names a silo, spelled out the way a
#: project's own migration would have to spell it.
SILO = {"silo_fk": "team", "silo_uid_field": "pk", "silo_label": "group"}

#: What ``testapp.Note`` declares at runtime.
NOTE_AAD = ("team", "author")

#: What ``testapp.Document`` declares at runtime.
DOCUMENT_AAD = ("team",)


@pytest.fixture
def historical_apps(db):
    """The ``apps`` registry a ``RunPython`` callback in ``testapp`` would receive."""
    loader = MigrationLoader(connection)
    return loader.project_state(("testapp", "0001_initial")).apps


@pytest.fixture
def notes(silo_context):
    """Three encrypted rows in one silo, written through the field protocol."""
    from tests.testapp.models import Note

    return [
        Note.objects.create(team=silo_context, author=f"a{i}", title=f"title {i}", body=f"body {i}") for i in range(3)
    ]


def _model(name):
    from tests.testapp import models

    return getattr(models, name)


def _column(pk, name="title", *, model="Note"):
    """The value actually stored in the column, with no field protocol in the way."""
    return raw_cursor_fetch(_model(model), pk, [name])[0]


def _set_column(pk, value, name="title", *, model="Note"):
    # Past the field on purpose: what these helpers convert is a column written
    # before it was encrypted, and the write that creates one is refused unless
    # it says so.
    with allow_plaintext_writes():
        _model(model).objects.filter(pk=pk).update(**{name: value})


def _read(pk, name="title", *, model="Note"):
    """Read through the runtime model, the way the application will."""
    return getattr(_model(model).objects.get(pk=pk), name)


# ---------------------------------------------------------------------------
# The fault itself
# ---------------------------------------------------------------------------


def test_a_historical_model_still_decrypts_on_attribute_access(historical_apps, notes):
    """Why these helpers may not use ``getattr``, stated once.

    The field survives the rebuild — migration files record its import path — so
    the descriptor is wired up exactly as at runtime, carrying the ``aad=`` of
    the state the migration runs in rather than the binding the value was
    written under.
    """
    Historical = historical_apps.get_model("testapp", "Note")

    assert Historical._meta.get_field("title").aad == ()

    row = Historical.objects.get(pk=notes[0].pk)
    stored = _column(notes[0].pk)

    assert stored.startswith(_CIPHERTEXT_PREFIX)
    assert row.title != stored


# ---------------------------------------------------------------------------
# decrypt_field
# ---------------------------------------------------------------------------


def test_decrypt_field_writes_plaintext_back(historical_apps, notes):
    count = decrypt_field(historical_apps, "testapp", "Note", "title", aad_columns=NOTE_AAD, **SILO)

    assert count == 3
    for i, note in enumerate(notes):
        assert _column(note.pk) == f"title {i}"


def test_decrypt_field_run_twice_changes_nothing(historical_apps, notes):
    decrypt_field(historical_apps, "testapp", "Note", "title", aad_columns=NOTE_AAD, **SILO)
    before = [_column(n.pk) for n in notes]

    count = decrypt_field(historical_apps, "testapp", "Note", "title", aad_columns=NOTE_AAD, **SILO)

    assert count == 0
    assert [_column(n.pk) for n in notes] == before


# ---------------------------------------------------------------------------
# encrypt_field
# ---------------------------------------------------------------------------


def test_encrypt_field_makes_a_plaintext_column_readable(historical_apps, notes):
    """Adoption: the column holds plaintext, and the application must read it after."""
    for i, note in enumerate(notes):
        _set_column(note.pk, f"adopted {i}")

    count = encrypt_field(historical_apps, "testapp", "Note", "title", aad_columns=NOTE_AAD, **SILO)

    assert count == 3
    for i, note in enumerate(notes):
        assert _column(note.pk).startswith(_CIPHERTEXT_PREFIX)
        assert _read(note.pk) == f"adopted {i}"


def test_encrypt_field_leaves_an_already_encrypted_row_alone(historical_apps, notes):
    """The data-loss case: a re-run must not encrypt ciphertext a second time.

    Reading through the descriptor made every row look like plaintext, so a
    second run re-encrypted what it found — and on this model, what it found was
    the fallback label, written over live ciphertext by an ``.update()``.
    """
    before = [_column(n.pk) for n in notes]

    count = encrypt_field(historical_apps, "testapp", "Note", "title", aad_columns=NOTE_AAD, **SILO)

    assert count == 0
    assert [_column(n.pk) for n in notes] == before
    assert _read(notes[0].pk) == "title 0"


def test_encrypt_field_skips_null_columns(historical_apps, silo_context):
    from tests.testapp.models import Note

    note = Note.objects.create(team=silo_context, author="a", title=None, body=None)

    count = encrypt_field(historical_apps, "testapp", "Note", "title", aad_columns=NOTE_AAD, **SILO)

    assert count == 0
    assert _column(note.pk) is None


def test_encrypt_field_uses_the_right_key_for_each_silo(historical_apps, silo_context):
    """Two silos, two keys — the per-migration primitive cache must not cross them."""
    from tests.testapp.models import Note

    other = Group.objects.create(name="other")
    rows = {}
    for team in (silo_context, other):
        # Written through the field protocol first, so each silo has a key of
        # its own; then the column is replaced with the plaintext an adoption
        # migration would find there.
        with override_current_silo(team):
            note = Note.objects.create(team=team, author="a", title="seed", body=None)
        _set_column(note.pk, f"secret for {team.pk}")
        rows[team] = note

    encrypt_field(historical_apps, "testapp", "Note", "title", aad_columns=NOTE_AAD, **SILO)

    for team, note in rows.items():
        with override_current_silo(team):
            assert _read(note.pk) == f"secret for {team.pk}"


# ---------------------------------------------------------------------------
# reencrypt_for_aad_change
# ---------------------------------------------------------------------------


def test_reencrypt_for_aad_change_rewrites_every_row(historical_apps, notes, monkeypatch):
    """The scenario the helper exists for: narrow the AAD, then deploy the change.

    Proof is the deploy half — reading through a model class that declares the
    *new* policy, which is what the application will be running.
    """
    from tests.testapp.models import Note

    before = [_column(n.pk) for n in notes]

    visited = reencrypt_for_aad_change(
        historical_apps,
        "testapp",
        "Note",
        ("title", "body"),
        old_aad_columns=NOTE_AAD,
        new_aad_columns=("team",),
        **SILO,
    )

    assert visited == 3
    assert [_column(n.pk) for n in notes] != before

    for name in ("title", "body"):
        field = Note._meta.get_field(name)
        monkeypatch.setattr(field, "aad", ("team",))
        monkeypatch.setattr(field, "_aad_attnames", ("team_id",))
    for i, note in enumerate(notes):
        assert _read(note.pk) == f"title {i}"
        assert _read(note.pk, "body") == f"body {i}"


def test_reencrypt_for_aad_change_leaves_a_plaintext_row_alone(historical_apps, notes):
    """A half-finished earlier run: a plaintext value is not ciphertext under an unknown policy."""
    _set_column(notes[0].pk, "still plaintext")

    reencrypt_for_aad_change(
        historical_apps,
        "testapp",
        "Note",
        ("title",),
        old_aad_columns=NOTE_AAD,
        new_aad_columns=("team",),
        **SILO,
    )

    assert _column(notes[0].pk) == "still plaintext"


# ---------------------------------------------------------------------------
# Rows that cannot be converted
# ---------------------------------------------------------------------------


def test_one_bad_row_does_not_end_the_run(historical_apps, notes, caplog):
    """A row that will not decrypt used to abort the walk where it stood.

    That left the table half converted and named exactly one bad row per run. The
    walk now finishes, every convertible row is converted, each failure is logged
    against its pk, and the helper fails at the end rather than reporting a
    success it did not have.
    """
    bad = notes[1]
    _set_column(bad.pk, _CIPHERTEXT_PREFIX + b64encode(b"not really ciphertext").decode("ascii"))

    with caplog.at_level(logging.ERROR, logger="encryption_suite.migration_helpers"):
        with pytest.raises(EncryptionError):
            decrypt_field(historical_apps, "testapp", "Note", "title", aad_columns=NOTE_AAD, **SILO)

    assert _column(notes[0].pk) == "title 0"
    assert _column(notes[2].pk) == "title 2"
    assert _column(bad.pk).startswith(_CIPHERTEXT_PREFIX)
    assert str(bad.pk) in caplog.text


# ---------------------------------------------------------------------------
# encrypt_file_field
# ---------------------------------------------------------------------------


@pytest.fixture
def plaintext_documents(silo_context):
    """Two rows as a project has them before adoption.

    The blob is plaintext under a name that says what it is, the display-name
    column is empty because nothing has ever filled it, and both keysets exist —
    the migration converts data, it does not decide whether the silo has keys.
    """
    from encryption_suite.engine import EncryptionEngine
    from encryption_suite.registry import get_engine
    from tests.testapp.models import Document

    # The primitive cache outlives the test database, so without this a keyset
    # from an earlier test reads back what this one wrote under a fresh one.
    EncryptionEngine.invalidate_cache()
    engine = get_engine()
    engine.generate_and_store_keyset(silo_context)
    engine.generate_and_store_file_keyset(silo_context)

    rows = []
    for i in range(2):
        content = f"file body {i}".encode()
        document = Document.objects.create(team=silo_context)
        stored = _storage()._save_raw(f"legacy/report {i}.txt", ContentFile(content))
        Document.objects.filter(pk=document.pk).update(upload=stored)
        rows.append((document.pk, stored, content))
    return rows


def _storage():
    from tests.testapp.models import Document

    return Document._meta.get_field("upload").storage


def _blob(name):
    """The bytes actually in storage, with no decryption in the way."""
    with _storage()._open_raw(name, "rb") as handle:
        return handle.read()


def _read_document(pk, team):
    """The file and its display name as the application reads them."""
    from tests.testapp.models import Document

    with override_current_silo(team):
        document = Document.objects.get(pk=pk)
        with document.upload.open("rb") as handle:
            return handle.read(), document.upload.display_name


def test_encrypt_file_field_converts_the_blob_the_column_points_at(historical_apps, plaintext_documents, silo_context):
    """The whole sequence: fresh opaque name, ciphertext, pointer moved, original gone."""
    count = encrypt_file_field(historical_apps, "testapp", "Document", "upload", aad_columns=DOCUMENT_AAD, **SILO)

    assert count == 2
    for pk, old_name, content in plaintext_documents:
        stored = _column(pk, "upload", model="Document")
        assert stored != old_name
        assert stored.startswith("encryption_suite_default/")
        assert _blob(stored) != content
        assert not _storage().exists(old_name)
        assert _read_document(pk, silo_context) == (content, old_name.rsplit("/", 1)[-1])


def test_encrypt_file_field_fills_the_display_name_from_the_old_path(historical_apps, plaintext_documents):
    """The filename the column stops saying out loud is the one thing a convert can lose."""
    encrypt_file_field(historical_apps, "testapp", "Document", "upload", aad_columns=DOCUMENT_AAD, **SILO)

    for pk, old_name, _ in plaintext_documents:
        assert _column(pk, "upload_name", model="Document").startswith(_CIPHERTEXT_PREFIX)
        assert _read(pk, "upload_name", model="Document") == old_name.rsplit("/", 1)[-1]


def test_encrypt_file_field_respects_a_display_name_already_on_the_row(historical_apps, plaintext_documents):
    """Same rule the field protocol follows for an upload: an explicit name wins."""
    pk, _, _ = plaintext_documents[0]
    _set_column(pk, "invoice for March.pdf", "upload_name", model="Document")

    encrypt_file_field(historical_apps, "testapp", "Document", "upload", aad_columns=DOCUMENT_AAD, **SILO)

    assert _read(pk, "upload_name", model="Document") == "invoice for March.pdf"


def test_encrypt_file_field_leaves_a_converted_row_alone_on_a_rerun(historical_apps, plaintext_documents):
    """A rerun must not encrypt a blob twice — nothing would ever read it again."""
    encrypt_file_field(historical_apps, "testapp", "Document", "upload", aad_columns=DOCUMENT_AAD, **SILO)
    before = [
        (_column(pk, "upload", model="Document"), _column(pk, "upload_name", model="Document"))
        for pk, _, _ in plaintext_documents
    ]

    count = encrypt_file_field(historical_apps, "testapp", "Document", "upload", aad_columns=DOCUMENT_AAD, **SILO)

    assert count == 0
    assert [
        (_column(pk, "upload", model="Document"), _column(pk, "upload_name", model="Document"))
        for pk, _, _ in plaintext_documents
    ] == before


def test_encrypt_file_field_skips_a_row_with_no_file(historical_apps, silo_context):
    from tests.testapp.models import Document

    document = Document.objects.create(team=silo_context)

    count = encrypt_file_field(historical_apps, "testapp", "Document", "upload", aad_columns=DOCUMENT_AAD, **SILO)

    assert count == 0
    assert not _column(document.pk, "upload", model="Document")


def test_encrypt_file_field_reports_a_row_whose_blob_is_gone_and_finishes(
    historical_apps, plaintext_documents, silo_context, caplog
):
    """One unreadable blob must not cost the walk every row behind it."""
    good_pk, good_name, good_content = plaintext_documents[0]
    bad_pk, _, _ = plaintext_documents[1]
    from tests.testapp.models import Document

    Document.objects.filter(pk=bad_pk).update(upload="legacy/never written.txt")

    with caplog.at_level(logging.ERROR, logger="encryption_suite.migration_helpers"):
        with pytest.raises(EncryptionError):
            encrypt_file_field(historical_apps, "testapp", "Document", "upload", aad_columns=DOCUMENT_AAD, **SILO)

    assert _read_document(good_pk, silo_context)[0] == good_content
    assert _column(bad_pk, "upload", model="Document") == "legacy/never written.txt"
    assert str(bad_pk) in caplog.text


def test_encrypt_file_field_refuses_a_column_that_is_not_an_encrypted_file_field(
    historical_apps, plaintext_documents, monkeypatch
):
    """Run before the AlterField and there is no display-name column to write."""
    field = historical_apps.get_model("testapp", "Document")._meta.get_field("upload")
    monkeypatch.setattr(field, "display_name_field", "")

    with pytest.raises(EncryptionError):
        encrypt_file_field(historical_apps, "testapp", "Document", "upload", aad_columns=DOCUMENT_AAD, **SILO)


def test_the_failure_says_how_many_rows_and_which_field(historical_apps, notes):
    """Operator detail on ``detail``, never in the user-facing message."""
    _set_column(notes[1].pk, _CIPHERTEXT_PREFIX + b64encode(b"junk").decode("ascii"))

    with pytest.raises(EncryptionError) as caught:
        decrypt_field(historical_apps, "testapp", "Note", "title", aad_columns=NOTE_AAD, **SILO)

    detail = caught.value.detail
    assert "testapp.Note.title" in detail
    assert str(notes[1].pk) in detail
    assert "testapp.Note.title" not in str(caught.value)


# ---------------------------------------------------------------------------
# encrypt_field / decrypt_field on key_set="system" columns
#
# The same adoption story one layer in: a column already holding plaintext, under
# the system silo's key rather than a silo's. No silo FK to resolve, which is why
# these can run in the release that puts the field in place.
# ---------------------------------------------------------------------------


@pytest.fixture
def member_apps(db):
    """The registry a ``RunPython`` in the migration that adds ``Member`` would get.

    State at the migration that creates the model, not at ``0001_initial``: the
    helpers read ``blind_index`` and ``normalize`` off the historical field, and
    before that migration there is no field to read them from.
    """
    loader = MigrationLoader(connection)
    return loader.project_state(("testapp", "0002_member")).apps


@pytest.fixture
def members(db):
    """Three rows whose system columns still hold plaintext, written past the field."""
    from tests.testapp.models import Member

    rows = [Member.objects.create() for _ in range(3)]
    with allow_plaintext_writes():
        for i, row in enumerate(rows):
            Member.objects.filter(pk=row.pk).update(email=f"Ann{i}@Example.com", handle=f"ann{i}")
    return rows


def _member_column(pk, name="email"):
    from tests.testapp.models import Member

    return raw_cursor_fetch(Member, pk, [name])[0]


def test_encrypt_field_on_a_system_column_makes_a_plaintext_column_readable(member_apps, members):
    from tests.testapp.models import Member

    count = encrypt_field(member_apps, "testapp", "Member", "email")

    assert count == 3
    for i, row in enumerate(members):
        assert is_silo_value(_member_column(row.pk))
        assert Member.objects.get(pk=row.pk).email == f"Ann{i}@Example.com"


def test_encrypt_field_on_a_system_column_writes_the_index_the_lookups_need(member_apps, members):
    """Conversion is what makes a row findable; without it sign-in cannot see it."""
    from tests.testapp.models import Member

    assert not Member.objects.filter(email="ann0@example.com").exists()

    encrypt_field(member_apps, "testapp", "Member", "email")

    assert Member.objects.get(email="ann0@example.com").pk == members[0].pk


def test_encrypt_field_on_a_system_column_run_twice_changes_nothing(member_apps, members):
    encrypt_field(member_apps, "testapp", "Member", "email")
    before = [_member_column(row.pk) for row in members]

    count = encrypt_field(member_apps, "testapp", "Member", "email")

    assert count == 0
    assert [_member_column(row.pk) for row in members] == before


def test_encrypt_field_on_a_system_column_leaves_a_null_alone(member_apps, db):
    from tests.testapp.models import Member

    row = Member.objects.create()

    assert encrypt_field(member_apps, "testapp", "Member", "email") == 0
    assert _member_column(row.pk) is None


def test_decrypt_field_on_a_system_column_returns_the_column_to_plaintext(member_apps, members):
    encrypt_field(member_apps, "testapp", "Member", "email")

    count = decrypt_field(member_apps, "testapp", "Member", "email")

    assert count == 3
    assert _member_column(members[0].pk) == "Ann0@Example.com"


def test_decrypt_field_on_a_system_column_run_twice_changes_nothing(member_apps, members):
    encrypt_field(member_apps, "testapp", "Member", "email")
    decrypt_field(member_apps, "testapp", "Member", "email")

    assert decrypt_field(member_apps, "testapp", "Member", "email") == 0


# ---------------------------------------------------------------------------
# key_set="system" columns: no silo to resolve, and the digest goes with the value
# ---------------------------------------------------------------------------


@pytest.fixture
def system_apps(db):
    """The registry a ``RunPython`` in the package's own initial migration would get."""
    loader = MigrationLoader(connection)
    return loader.project_state(("encryption_suite", "0001_initial")).apps


def test_encrypt_field_converts_a_system_column_with_no_silo_arguments(system_apps):
    from encryption_suite.engine import EncryptionEngine, is_silo_value
    from encryption_suite.models import RecordedOSUser

    row = RecordedOSUser.objects.create(os_user="placeholder")
    with allow_plaintext_writes():
        RecordedOSUser.objects.filter(pk=row.pk).update(os_user=None, encrypted_os_user="deploy (uid 1000)")

    converted = encrypt_field(system_apps, "encryption_suite", "RecordedOSUser", "encrypted_os_user")

    assert converted == 1
    (stored,) = raw_cursor_fetch(RecordedOSUser, row.pk, ["encrypted_os_user"])
    assert is_silo_value(stored)
    EncryptionEngine.invalidate_cache()
    assert RecordedOSUser.objects.get(pk=row.pk).encrypted_os_user == "deploy (uid 1000)"
    # Written with its digest, so a lookup by value finds it.
    assert RecordedOSUser.objects.filter(encrypted_os_user="deploy (uid 1000)").get().pk == row.pk


def test_a_silo_column_without_its_silo_arguments_is_refused(historical_apps):
    with pytest.raises(TypeError, match="silo_fk and silo_label"):
        encrypt_field(historical_apps, "testapp", "Note", "title")


def test_reencrypt_for_aad_change_on_a_system_column_needs_no_silo_arguments(member_apps, monkeypatch):
    """A system column is under the system silo on every row, so there is no silo foreign key to pass."""
    from tests.testapp.models import Member

    rows = [Member.objects.create(handle=f"ann{i}") for i in range(3)]
    before = [_member_column(row.pk, "handle") for row in rows]

    visited = reencrypt_for_aad_change(member_apps, "testapp", "Member", ("handle",), new_aad_columns=("pk",))

    assert visited == 3
    assert [_member_column(row.pk, "handle") for row in rows] != before
    field = Member._meta.get_field("handle")
    monkeypatch.setattr(field, "aad", ("pk",))
    monkeypatch.setattr(field, "_aad_attnames", ("id",))
    for i, row in enumerate(rows):
        assert Member.objects.get(pk=row.pk).handle == f"ann{i}"


def test_reencrypt_for_aad_change_on_a_silo_column_still_needs_its_silo_arguments(historical_apps, notes):
    with pytest.raises(TypeError, match="silo_fk and silo_label"):
        reencrypt_for_aad_change(historical_apps, "testapp", "Note", ("title",), old_aad_columns=NOTE_AAD)
