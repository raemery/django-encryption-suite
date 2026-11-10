"""``setup_encryption_keys`` closes its run on a log line.

The ledger records each key the run created and nothing else about it: a silo
that already had keys, a dry run, and a run that ended part way through the list
of silos leave no row behind. The closing line is what a scheduled run has.
"""

from __future__ import annotations

from io import StringIO

import pytest
from django.contrib.auth.models import Group
from django.core.management import call_command

from encryption_suite.engine import EncryptionEngine

pytestmark = pytest.mark.django_db


@pytest.fixture(autouse=True)
def _clear_cache():
    EncryptionEngine.invalidate_cache()
    yield
    EncryptionEngine.invalidate_cache()


def _run(*args) -> str:
    out = StringIO()
    call_command("setup_encryption_keys", *args, stdout=out, stderr=out)
    return out.getvalue()


def _finished(caplog) -> str:
    """The closing line of the most recent run."""
    return [r.getMessage() for r in caplog.records if "command finished" in r.getMessage()][-1]


def test_the_run_closes_on_a_line_carrying_what_it_created(monkeypatch, caplog):
    monkeypatch.setenv("SUDO_USER", "alice")
    Group.objects.create(name="acme")

    with caplog.at_level("INFO", logger="encryption_suite"):
        _run()

    line = _finished(caplog)
    assert "command=setup_encryption_keys dry_run=False" in line
    assert "field_keys_created=1 file_keys_created=1 index_keys_created=1 skipped=0" in line
    assert 'os_user="alice' in line


def test_a_second_run_closes_saying_it_created_nothing(caplog):
    Group.objects.create(name="acme")
    _run()

    with caplog.at_level("INFO", logger="encryption_suite"):
        _run()

    assert "field_keys_created=0 file_keys_created=0 index_keys_created=0 skipped=3" in _finished(caplog)


def test_a_dry_run_closes_with_the_counts_it_previewed(caplog):
    Group.objects.create(name="acme")

    with caplog.at_level("INFO", logger="encryption_suite"):
        _run("--dry-run")

    line = _finished(caplog)
    assert "dry_run=True" in line
    assert "field_keys_created=1 file_keys_created=1 index_keys_created=1 skipped=0" in line
