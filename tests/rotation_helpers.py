"""Shared setup for the data key rotation tests."""

from __future__ import annotations

from io import StringIO

from django.contrib.auth.models import Group
from django.core.files.base import ContentFile
from django.core.management import call_command

from encryption_suite.adapters.silos.context import override_current_silo
from encryption_suite.engine import EncryptionEngine
from encryption_suite.models import DataEncryptionKey
from tests.testapp.models import Document, Note


def uid(team) -> str:
    return f"group-{team.pk}"


def make_team(name="acme") -> Group:
    return Group.objects.create(name=name)


def make_note(team, *, title="title", body="body", author="ann") -> Note:
    with override_current_silo(team):
        return Note.objects.create(team=team, author=author, title=title, body=body)


def make_document(team, content=b"file content", name="report.txt") -> Document:
    with override_current_silo(team):
        document = Document(team=team, upload=ContentFile(content, name=name))
        document.save()
        return document


def read_note(pk, team):
    """``(title, body)`` as a fresh read sees them — plaintext, or the fallback sentinel."""
    EncryptionEngine.invalidate_cache()
    with override_current_silo(team):
        note = Note.objects.get(pk=pk)
        return note.title, note.body


def read_document(pk, team) -> bytes:
    EncryptionEngine.invalidate_cache()
    with override_current_silo(team):
        document = Document.objects.get(pk=pk)
        with document.upload.open("rb") as handle:
            return handle.read()


def dek(team, purpose=DataEncryptionKey.PURPOSE_FIELD) -> DataEncryptionKey:
    return DataEncryptionKey.objects.get(silo_uid=uid(team), purpose=purpose)


def run(*args) -> str:
    """Run reencrypt_data and return everything it printed, stdout then stderr."""
    out, err = StringIO(), StringIO()
    call_command("reencrypt_data", *args, stdout=out, stderr=err)
    return out.getvalue() + err.getvalue()


def run_fenced(*args) -> str:
    """Run reencrypt_data where it must end with the fence up, and return its output."""
    from django.core.management.base import CommandError

    out, err = StringIO(), StringIO()
    try:
        call_command("reencrypt_data", *args, stdout=out, stderr=err)
    except CommandError as exc:
        return out.getvalue() + err.getvalue() + str(exc)
    raise AssertionError(f"expected the run to stop with the fence up:\n{out.getvalue()}{err.getvalue()}")


def tamper_author(note, author="mallory") -> None:
    """Change an AAD-bound column without re-encrypting, so the row stops decrypting."""
    Note.objects.filter(pk=note.pk).update(author=author)


def open_rotation(team, purpose=DataEncryptionKey.PURPOSE_FIELD):
    """Raise the fence on *team*'s key the way a run does, and stop there."""
    from encryption_suite.registry import get_engine, get_silo_adapter
    from encryption_suite.rotation import Rotator
    from encryption_suite.rotation_targets import resolve_targets

    adapter = get_silo_adapter()
    rotator = Rotator(
        engine=get_engine(),
        adapter=adapter,
        resolution=resolve_targets(adapter),
        os_login_user="tester (uid 1000)",
        write=lambda *args: None,
    )
    return rotator._open(dek(team, purpose))
