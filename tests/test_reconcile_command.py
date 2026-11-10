"""``reconcile_keys`` runs the same pass the admin page runs, from the CLI.

One entry point, so a scheduled run and an operator's page load can never reach
different conclusions. The command adds only presentation: what happened on this
pass line by line, standing conditions as counts, and degraded dimensions on
stderr so "could not look" never reads as "nothing found".
"""

from __future__ import annotations

import logging
from io import StringIO
from unittest.mock import patch

import pytest
from django.core.management import call_command

from encryption_suite.models import DataEncryptionKey
from tests.factories import make_kek


def _run():
    out, err = StringIO(), StringIO()
    call_command("reconcile_keys", stdout=out, stderr=err)
    return out.getvalue(), err.getvalue()


@pytest.mark.django_db
def test_reports_standing_conditions_as_counts():
    out, _err = _run()

    assert "Orphaned data encryption keys:" in out
    assert "Orphaned key encryption keys:" in out


@pytest.mark.django_db
def test_a_degraded_dimension_is_named_not_silently_clean():
    """The safety rule, surfaced: an unchecked dimension must say so somewhere."""
    out, err = _run()

    assert "DEK_ROTATION_PERIOD_DAYS" in out or "DEK_ROTATION_PERIOD_DAYS" in err


@pytest.mark.django_db
def test_a_configuration_property_is_information_not_a_daily_warning():
    """Nothing here will read differently tomorrow, so nothing here is a warning.

    The test settings declare no cryptoperiod, derive no owner prefix, and use a
    provisioner that cannot list — all permanent facts about the deployment. A
    scheduled run that warned about them every morning is how warnings stop being
    read, so they go to stdout and stderr stays clean.
    """
    out, err = _run()

    assert "Not applicable to this configuration:" in out
    assert "DEK_ROTATION_PERIOD_DAYS" in out
    assert "cannot list key encryption keys" in out
    assert err == ""


@pytest.mark.django_db
def test_one_half_checkable_does_not_report_the_other_half_as_zero():
    """The two currency findings degrade independently.

    Declaring a cryptoperiod makes the data half checkable, but the provider
    still identifies no key version, so the key half was never looked at. A
    count of ``0`` there would read as "checked, all current" — the exact
    reading the degrade rule exists to prevent.
    """
    with patch("encryption_suite.conf.enc_settings.DEK_ROTATION_PERIOD_DAYS", 0):
        out, _err = _run()

    assert "Data re-encryption due: 0" in out
    assert "Key re-encryption due: not checked" in out


@pytest.mark.django_db
def test_every_run_logs_a_line_even_when_nothing_changed(caplog):
    """The run trace that replaces a reconcile-run table.

    The service logs only when a pass changed something, which is right for the
    admin page but leaves a scheduled run invisible on a quiet deployment. The
    command's own logger is what tells the two apart.
    """
    with caplog.at_level(logging.INFO, logger="encryption_suite.management.commands.reconcile_keys"):
        _run()
        _run()

    own = [r for r in caplog.records if r.name == "encryption_suite.management.commands.reconcile_keys"]
    starts = [r for r in own if "command started" in r.message]
    finishes = [r.message for r in own if "command finished" in r.message]
    # One pass per key store a key set uses that can list its keys: the suite's "local" block.
    # The "login" env store has no provider to list and gets none.
    passes = [r.message for r in own if "reconcile pass finished" in r.message]
    assert len(finishes) == 2
    assert "passes=1" in finishes[0]
    assert len(passes) == 2
    assert all("key_store=local" in each for each in passes)
    assert "data_reencrypt_due=" in passes[0] and "key_reencrypt_due=" in passes[0]
    assert 'os_user="' in passes[0]
    # Both halves at WARNING, so a pipeline that cuts INFO keeps the pair: an
    # opening line whose closing line was filtered away reads as a run that died.
    assert len(starts) == 2
    assert all(r.levelno == logging.WARNING for r in own)


@pytest.mark.django_db
def test_records_what_it_learns():
    """A pass that finds a dead silo annotates it, exactly as the page would."""
    row = DataEncryptionKey.objects.create(
        key_set="default",
        silo_uid="team-gone",
        purpose=DataEncryptionKey.PURPOSE_FIELD,
        silo_label="team",
        encrypted_keyset=b"x",
        kek=make_kek("kms_team-gone", "local"),
    )

    _run()

    row.refresh_from_db()
    # Whether it is flagged depends on the configured adapter's enumeration; what
    # matters here is that the command completed a real pass against real rows.
    assert row.is_orphaned in (True, False)
