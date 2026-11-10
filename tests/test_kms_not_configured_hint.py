"""The hint KMS-facing commands print when they skip a row for an unconfigured KMS.

A skip is the correct, safe outcome — a key is only ever handed to the KMS its
row names — but the summary line alone cannot distinguish a deployment carrying
keys on a KMS it dropped from a command pointed at the wrong settings module. In
a repository with one settings file per KMS, the latter is a single missing
``--settings``.
"""

from __future__ import annotations

from io import StringIO

import pytest
from django.core.management import call_command

from encryption_suite.management._hints import kms_not_configured_hint
from encryption_suite.models import DataEncryptionKey
from tests.factories import make_kek


class TestHintText:
    def test_names_the_live_settings_module(self):
        # The thing the operator would have to change.
        assert "tests.settings" in kms_not_configured_hint({"gcp"})

    def test_names_the_kms(self):
        assert "'gcp'" in kms_not_configured_hint({"gcp"})

    def test_shows_the_settings_flag(self):
        assert "--settings=" in kms_not_configured_hint({"gcp"})

    def test_allows_for_a_dropped_kms(self):
        # Keys left on a KMS the deployment no longer uses are a real configuration.
        assert "expected" in kms_not_configured_hint({"gcp"})

    def test_lists_every_kms_seen(self):
        assert "'aws', 'gcp'" in kms_not_configured_hint({"gcp", "aws"})


@pytest.mark.django_db
class TestReencryptKeys:
    def _dek(self, key_store):
        return DataEncryptionKey.objects.create(
            key_set="default",
            silo_uid="team-1",
            purpose=DataEncryptionKey.PURPOSE_FIELD,
            encrypted_keyset=b"x",
            kek=make_kek("k", key_store),
        )

    def _dry_run(self) -> str:
        out = StringIO()
        call_command("reencrypt_keys", "--dry-run", stdout=out)
        return out.getvalue()

    def test_hint_follows_an_unconfigured_kms_skip(self):
        # No block in tests/settings.py is named "gcp", so this row is exactly
        # what an operator hits after a missing --settings.
        self._dek("gcp")

        printed = self._dry_run()

        assert "Skipped: default:team-1" in printed
        assert "--settings=" in printed

    def test_no_hint_when_every_row_is_on_a_configured_kms(self):
        self._dek("local")

        assert "--settings=" not in self._dry_run()

    def test_no_hint_when_there_is_nothing_to_do(self):
        assert "--settings=" not in self._dry_run()
