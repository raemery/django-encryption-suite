"""``reencrypt_data --purpose index --check``: digests that were never built.

An adoption that stops at the column change leaves values encrypted and
unfindable — ``encrypt_field`` writes the value and not the digest, because the
migration that calls it runs while the column is still a plain ``TextField``,
with no ``blind_index`` to read and, under the default storage, no digest column
to write to yet. A lookup against such a row then matches nothing rather than
failing, which reads as "no such row". This is what makes that state say so.

Both storage strategies run here, because where the digest is absent *from* is
the only thing the scan has to know. The models come from the installed test
app, because the scan enumerates the app registry — which is also why the
transient models the rest of the suite declares are invisible to it, and why
every run below sees these two columns and no others.
"""

from __future__ import annotations

import pytest
from django.contrib.auth.models import Group
from django.core.management import call_command
from django.core.management.base import CommandError

from encryption_suite.adapters.silos.context import override_current_silo
from encryption_suite.models import BlindIndexEntry
from tests.testapp.models import Indexed, IndexedShared


@pytest.fixture(params=[Indexed, IndexedShared], ids=["column", "table"])
def model(request, transactional_db):
    return request.param


def label(model) -> str:
    return model._meta.label


def strip_digest(model, pk) -> None:
    """Leave the value and remove the digest, which is what an adoption leaves."""
    if model is IndexedShared:
        BlindIndexEntry.objects.filter(
            model_label=model._meta.label,
            field_name="handle",
            object_pk=str(pk),
        ).delete()
        return
    # update() reaches the column directly: nothing on a field can see an UPDATE
    # the ORM built from the caller's kwargs, which is why this is the shape an
    # unbuilt digest really has.
    model.objects.filter(pk=pk).update(handle_index=None)


def check():
    call_command("reencrypt_data", "--purpose", "index", "--check")


# ---------------------------------------------------------------------------
# What it counts
# ---------------------------------------------------------------------------


def test_a_column_whose_digests_are_all_built_passes(model, silo_context, capsys):
    model.objects.create(team=silo_context, handle="ann")
    model.objects.create(team=silo_context, handle="bob")

    check()

    assert "Every indexed value has a digest." in capsys.readouterr().out


def test_a_value_with_no_digest_fails_the_check(model, silo_context):
    row = model.objects.create(team=silo_context, handle="ann")
    strip_digest(model, row.pk)

    with pytest.raises(CommandError) as caught:
        check()

    assert "1 value(s) hold no digest" in str(caught.value)


def test_the_failure_names_the_commands_that_build_them(model, silo_context):
    row = model.objects.create(team=silo_context, handle="ann")
    strip_digest(model, row.pk)

    with pytest.raises(CommandError) as caught:
        check()

    message = str(caught.value)
    assert "setup_encryption_keys" in message
    assert "reencrypt_data --purpose index" in message


def test_every_unbuilt_row_is_counted_in_one_run(model, silo_context, capsys):
    for handle in ("ann", "bob", "cal"):
        row = model.objects.create(team=silo_context, handle=handle)
        strip_digest(model, row.pk)
    model.objects.create(team=silo_context, handle="dee")

    with pytest.raises(CommandError):
        check()

    assert f"{label(model)}.handle: 3 value(s) with no digest" in capsys.readouterr().out


def test_a_row_holding_no_value_owes_no_digest(model, silo_context, capsys):
    model.objects.create(team=silo_context, handle=None)

    check()

    assert "Every indexed value has a digest." in capsys.readouterr().out


def test_rows_of_every_silo_are_counted(model, transactional_db):
    one = Group.objects.create(name="one")
    two = Group.objects.create(name="two")
    with override_current_silo(one):
        first = model.objects.create(team=one, handle="ann")
    with override_current_silo(two):
        second = model.objects.create(team=two, handle="ann")
    strip_digest(model, first.pk)
    strip_digest(model, second.pk)

    with pytest.raises(CommandError) as caught:
        check()

    # No silo context is active here, and none is needed: the scan reads the
    # stored column, never a key.
    assert "2 value(s) hold no digest" in str(caught.value)


def test_the_scan_decrypts_nothing(model, silo_context, monkeypatch):
    model.objects.create(team=silo_context, handle="ann")
    row = model.objects.create(team=silo_context, handle="bob")
    strip_digest(model, row.pk)

    from encryption_suite.engine import EncryptionEngine

    def refuse(*args, **kwargs):
        raise AssertionError("the check reached the engine")

    monkeypatch.setattr(EncryptionEngine, "decrypt", refuse)
    monkeypatch.setattr(EncryptionEngine, "index_digest", refuse)

    with pytest.raises(CommandError) as caught:
        check()

    assert "1 value(s) hold no digest" in str(caught.value)


# ---------------------------------------------------------------------------
# What it refuses
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("purpose", ["field", "file", "all"])
def test_check_refuses_an_explicit_purpose_other_than_index(purpose, transactional_db):
    """Refused rather than ignored: a digest scan passing under --purpose field would read as a field check."""
    with pytest.raises(CommandError) as caught:
        call_command("reencrypt_data", "--purpose", purpose, "--check")

    assert "--purpose index" in str(caught.value)


def test_check_without_a_purpose_scans_the_digests(model, silo_context, capsys):
    model.objects.create(team=silo_context, handle="ann")

    call_command("reencrypt_data", "--check")

    assert "Every indexed value has a digest." in capsys.readouterr().out


def test_check_refuses_a_silo_uid(transactional_db):
    with pytest.raises(CommandError) as caught:
        call_command("reencrypt_data", "--purpose", "index", "--check", "--silo-uid", "team-1")

    assert "--silo-uid" in str(caught.value)


@pytest.mark.parametrize("flag", ["--dry-run", "--abort", "--abort-on-unconvertible"])
def test_check_refuses_a_flag_that_would_act(flag, transactional_db):
    with pytest.raises(CommandError) as caught:
        call_command("reencrypt_data", "--purpose", "index", "--check", flag)

    assert "already changes nothing" in str(caught.value)
