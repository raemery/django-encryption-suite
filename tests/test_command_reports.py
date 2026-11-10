"""The JSON report and the exit status, as a scheduler sees them.

With ``--format json`` a reporting command writes one document to standard
output, or to ``--output``, and sends everything written for a person to
standard error. A run that fails any of its work still writes its report, then
exits non-zero.
"""

from __future__ import annotations

import json
from io import StringIO

import pytest
from django.core.management import call_command
from django.core.management.base import CommandError

from encryption_suite import rotation
from encryption_suite.engine import EncryptionEngine
from encryption_suite.exceptions import GENERIC_ENCRYPT_DECRYPT_UNAVAILABLE_MESSAGE, KekUnavailableError
from tests.rotation_helpers import make_note, make_team, uid

pytestmark = pytest.mark.django_db

_COMMON = {"schema_version", "command", "started_at", "finished_at"}


@pytest.fixture(autouse=True)
def _no_wait(monkeypatch):
    monkeypatch.setattr(rotation, "_sleep", lambda seconds: None)
    EncryptionEngine.invalidate_cache()
    yield
    EncryptionEngine.invalidate_cache()


def _call(name, *args):
    out, err = StringIO(), StringIO()
    call_command(name, *args, stdout=out, stderr=err)
    return out.getvalue(), err.getvalue()


@pytest.mark.parametrize("name", ["crypto_inventory", "reconcile_keys", "reencrypt_keys", "reencrypt_data"])
def test_standard_output_carries_only_the_report(name):
    team = make_team()
    make_note(team)
    args = ("--dry-run",) if name.startswith("reencrypt") else ()

    out, err = _call(name, "--format", "json", *args)

    document = json.loads(out)
    assert _COMMON <= set(document)
    assert document["command"] == name
    if name == "reconcile_keys":
        # The per-KMS lines a person reads went to standard error instead.
        assert "Key store: local" in err


def test_output_writes_the_report_to_a_file(tmp_path):
    target = tmp_path / "inventory.json"

    out, _err = _call("crypto_inventory", "--format", "json", "--output", str(target))

    assert out == ""
    assert json.loads(target.read_text(encoding="utf-8"))["command"] == "crypto_inventory"


def test_output_needs_the_json_format(tmp_path):
    with pytest.raises(CommandError, match="--format json"):
        _call("crypto_inventory", "--output", str(tmp_path / "x.json"))


def test_reconcile_reports_each_listable_store_pass():
    out, _err = _call("reconcile_keys", "--format", "json")

    passes = json.loads(out)["passes"]
    assert [each["key_store"] for each in passes] == ["local"]
    assert {"orphaned_data_keys", "could_not_run", "not_applicable"} <= set(passes[0])


def test_reencrypt_keys_reports_every_key_set_under_key_set_all():
    make_note(make_team())

    out, _err = _call("reencrypt_keys", "--key-set", "all", "--format", "json")

    passes = json.loads(out)["passes"]
    assert [each["key_set"] for each in passes] == ["default", "system"]
    assert passes[0]["reencrypted"] >= 1 and passes[0]["failed"] == 0


def test_reencrypt_keys_writes_the_report_then_exits_non_zero_on_a_failed_row(tmp_path, monkeypatch):
    from encryption_suite.registry import get_engine

    make_note(make_team())
    adapter = get_engine().silo_kms_adapter
    monkeypatch.setattr(adapter, "decrypt_key", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("down")))
    target = tmp_path / "report.json"

    with pytest.raises(CommandError, match="could not be re-encrypted"):
        _call("reencrypt_keys", "--format", "json", "--output", str(target))

    assert json.loads(target.read_text(encoding="utf-8"))["passes"][0]["failed"] == 1


def test_reencrypt_data_exits_non_zero_on_a_failed_rotation_that_left_no_fence(monkeypatch):
    team = make_team()
    make_note(team)

    def fail(self, *args, **kwargs):
        raise KekUnavailableError(GENERIC_ENCRYPT_DECRYPT_UNAVAILABLE_MESSAGE, detail="down")

    monkeypatch.setattr(rotation.Rotator, "run", fail)

    with pytest.raises(CommandError, match="rotation\\(s\\) failed"):
        _call("reencrypt_data", "--silo-uid", uid(team), "--purpose", "field")
