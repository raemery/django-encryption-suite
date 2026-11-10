"""AwsKekProvisioner deletion and enumeration against a fake KMS client.

boto3 is not installed in this environment, so the client is stubbed. That is
also why the provisioner reads AWS error codes off the exception's ``response``
payload instead of by isinstance — see ``_error_code``.
"""

from __future__ import annotations

import datetime

import pytest

from encryption_suite.adapters.keks.provisioners_aws import AwsKekProvisioner
from encryption_suite.exceptions import (
    EncryptionConfigurationError,
    KekEnumerationError,
    KekPendingDeletionError,
)
from encryption_suite.silo_ref import SiloRef

_PREFIX = "alias/es-prod-"
_NAME = _PREFIX + "team-1"
_KEY_ID = "1234abcd-12ab-34cd-56ef-1234567890ab"


class _AwsError(Exception):
    """Stand-in for botocore's ClientError, carrying the same response shape."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.response = {"Error": {"Code": code}}


class _FakePaginator:
    def __init__(self, pages):
        self._pages = pages

    def paginate(self):
        return iter(self._pages)


class _FakeKmsClient:
    def __init__(self, *, metadata=None, deletion_date=None, alias_pages=None):
        self._metadata = metadata
        self._deletion_date = deletion_date
        self._alias_pages = alias_pages or []
        self.calls: list[tuple] = []

    def describe_key(self, KeyId):  # noqa: N803 - boto3's parameter name
        self.calls.append(("describe_key", KeyId))
        if self._metadata is None:
            raise _AwsError("NotFoundException")
        return {"KeyMetadata": self._metadata}

    def schedule_key_deletion(self, KeyId, PendingWindowInDays):  # noqa: N803
        self.calls.append(("schedule_key_deletion", KeyId, PendingWindowInDays))
        return {"KeyId": KeyId, "DeletionDate": self._deletion_date}

    def get_paginator(self, name):
        self.calls.append(("get_paginator", name))
        return _FakePaginator(self._alias_pages)


def _provisioner(client, **options):
    prov = AwsKekProvisioner({"AWS_REGION": "us-east-1", **options})
    prov._client = client
    return prov


def _aware(*args):
    return datetime.datetime(*args, tzinfo=datetime.UTC)


class TestCapabilityFlags:
    def test_supports_delete_and_enumeration(self):
        assert AwsKekProvisioner.supports_delete is True
        assert AwsKekProvisioner.supports_enumeration is True


class TestDelete:
    def test_resolves_alias_to_key_id_and_schedules(self):
        client = _FakeKmsClient(
            metadata={"KeyId": _KEY_ID, "KeyState": "Enabled"},
            deletion_date=_aware(2026, 8, 26),
        )
        prov = _provisioner(client)

        outcome = prov.delete_kek(_NAME, SiloRef("default", "team-1"), owner_prefix=_PREFIX)

        # ScheduleKeyDeletion takes a key id, never an alias. The default window
        # is AWS's minimum of 7, not AWS's own default of 30.
        assert client.calls == [
            ("describe_key", _NAME),
            ("schedule_key_deletion", _KEY_ID, 7),
        ]
        assert outcome.scheduled is True
        assert outcome.effective_at == _aware(2026, 8, 26)

    def test_uses_configured_pending_window(self):
        client = _FakeKmsClient(
            metadata={"KeyId": _KEY_ID, "KeyState": "Enabled"},
            deletion_date=_aware(2026, 8, 26),
        )
        prov = _provisioner(client, PROVIDER_DELETION_WINDOW_DAYS=30)

        prov.delete_kek(_NAME, SiloRef("default", "team-1"), owner_prefix=_PREFIX)

        assert ("schedule_key_deletion", _KEY_ID, 30) in client.calls

    def test_a_test_console_key_uses_the_aws_minimum(self):
        # Raising the window for real keys must not slow the console's cycle.
        # Unlike GCP, the window is an argument to the delete call, so it is read
        # here rather than at creation.
        client = _FakeKmsClient(
            metadata={"KeyId": _KEY_ID, "KeyState": "Enabled"},
            deletion_date=_aware(2026, 8, 26),
        )
        prov = _provisioner(client, PROVIDER_DELETION_WINDOW_DAYS=30)

        prov.delete_kek(_NAME, SiloRef("default", "enctestkey"), owner_prefix=_PREFIX)

        assert ("schedule_key_deletion", _KEY_ID, 7) in client.calls

    def test_absent_key_counts_as_deleted(self):
        client = _FakeKmsClient(metadata=None)
        prov = _provisioner(client)

        outcome = prov.delete_kek(_NAME, SiloRef("default", "team-1"), owner_prefix=_PREFIX)

        assert [c[0] for c in client.calls] == ["describe_key"]
        assert outcome.scheduled is False

    def test_already_scheduled_key_reports_existing_date(self):
        client = _FakeKmsClient(
            metadata={
                "KeyId": _KEY_ID,
                "KeyState": "PendingDeletion",
                "DeletionDate": _aware(2026, 8, 20),
            }
        )
        prov = _provisioner(client)

        outcome = prov.delete_kek(_NAME, SiloRef("default", "team-1"), owner_prefix=_PREFIX)

        # No second ScheduleKeyDeletion — AWS answers that with an invalid-state error.
        assert [c[0] for c in client.calls] == ["describe_key"]
        assert outcome.scheduled is True
        assert outcome.effective_at == _aware(2026, 8, 20)

    def test_missing_deletion_date_falls_back_to_window(self):
        client = _FakeKmsClient(metadata={"KeyId": _KEY_ID, "KeyState": "Enabled"}, deletion_date=None)
        prov = _provisioner(client, PROVIDER_DELETION_WINDOW_DAYS=30)

        outcome = prov.delete_kek(_NAME, SiloRef("default", "team-1"), owner_prefix=_PREFIX)

        from django.utils import timezone

        assert outcome.effective_at > timezone.now() + datetime.timedelta(days=29)

    def test_naive_deletion_date_is_made_aware(self):
        client = _FakeKmsClient(
            metadata={"KeyId": _KEY_ID, "KeyState": "Enabled"},
            deletion_date=datetime.datetime(2026, 8, 26),
        )
        prov = _provisioner(client)

        outcome = prov.delete_kek(_NAME, SiloRef("default", "team-1"), owner_prefix=_PREFIX)

        assert outcome.effective_at.tzinfo is not None

    def test_delete_clears_the_ensured_cache(self):
        client = _FakeKmsClient(metadata={"KeyId": _KEY_ID, "KeyState": "Enabled"}, deletion_date=None)
        prov = _provisioner(client)
        prov._ensured.add(_NAME)

        prov.delete_kek(_NAME, SiloRef("default", "team-1"), owner_prefix=_PREFIX)

        assert _NAME not in prov._ensured


class TestEnsureKekAgainstPendingDeletion:
    def test_refuses_a_key_scheduled_for_deletion(self):
        client = _FakeKmsClient(
            metadata={
                "KeyId": _KEY_ID,
                "KeyState": "PendingDeletion",
                "DeletionDate": _aware(2026, 8, 20),
            }
        )
        prov = _provisioner(client)

        with pytest.raises(KekPendingDeletionError) as excinfo:
            prov.ensure_kek(_NAME, SiloRef("default", "team-1"))

        exc = excinfo.value
        # Typed, so the engine can tell this from a key that was never created.
        assert exc.code == "kek_pending_deletion"
        # The operator text an admin reads in the log; the user message stays generic.
        assert "cancel-key-deletion" in exc.detail
        assert "cancel-key-deletion" not in str(exc)
        # AWS's own destruction date, carried through for the engine to record.
        assert exc.effective_at == _aware(2026, 8, 20)
        assert _NAME not in prov._ensured

    def test_live_key_is_cached(self):
        client = _FakeKmsClient(metadata={"KeyId": _KEY_ID, "KeyState": "Enabled"})
        prov = _provisioner(client)

        prov.ensure_kek(_NAME, SiloRef("default", "team-1"))

        assert _NAME in prov._ensured


class _ProvisioningKmsClient:
    """Fake whose alias stays unresolvable for *unresolved_lookups* DescribeKey calls.

    Models CreateAlias's eventual consistency: the alias 404s for a while after
    it is created.
    """

    def __init__(self, unresolved_lookups: int) -> None:
        self._remaining = unresolved_lookups
        self.calls: list[tuple] = []

    def describe_key(self, KeyId):  # noqa: N803 - boto3's parameter name
        self.calls.append(("describe_key", KeyId))
        if self._remaining > 0:
            self._remaining -= 1
            raise _AwsError("NotFoundException")
        return {"KeyMetadata": {"KeyId": _KEY_ID, "KeyState": "Enabled"}}

    def create_key(self, **kwargs):
        self.calls.append(("create_key", kwargs))
        return {"KeyMetadata": {"KeyId": _KEY_ID}}

    def create_alias(self, AliasName, TargetKeyId):  # noqa: N803
        self.calls.append(("create_alias", AliasName, TargetKeyId))

    def enable_key_rotation(self, KeyId, RotationPeriodInDays):  # noqa: N803
        self.calls.append(("enable_key_rotation", KeyId, RotationPeriodInDays))


class TestAliasPropagation:
    """CreateAlias is eventually consistent, and the first encrypt under a new KEK
    happens in the same request that created it — so ensure_kek must not return
    while the alias is still unresolvable."""

    def test_waits_for_the_alias_to_resolve(self, monkeypatch):
        monkeypatch.setattr("encryption_suite.adapters.keks.provisioners_aws._ALIAS_POLL_INTERVAL", 0)
        # One 404 for the pre-create existence check, two more while propagating.
        client = _ProvisioningKmsClient(unresolved_lookups=3)
        prov = _provisioner(client)

        prov.ensure_kek(_NAME, SiloRef("default", "team-1"))

        assert [c[0] for c in client.calls] == [
            "describe_key",
            "create_key",
            "create_alias",
            "describe_key",
            "describe_key",
            "describe_key",
        ]
        assert _NAME in prov._ensured

    def test_timeout_leaves_the_key_unensured_without_raising(self):
        client = _ProvisioningKmsClient(unresolved_lookups=99)
        prov = _provisioner(client, ALIAS_PROPAGATION_TIMEOUT_SECONDS=0)

        prov.ensure_kek(_NAME, SiloRef("default", "team-1"))

        # The key exists, so raising would be wrong; but caching it as ensured
        # would make every retry skip provisioning and fail on the same 404.
        assert _NAME not in prov._ensured

    def test_existing_alias_is_not_waited_on(self):
        client = _ProvisioningKmsClient(unresolved_lookups=0)
        prov = _provisioner(client)

        prov.ensure_kek(_NAME, SiloRef("default", "team-1"))

        # DescribeKey proved it already resolves — nothing was created.
        assert [c[0] for c in client.calls] == ["describe_key"]
        assert _NAME in prov._ensured

    def test_non_alias_name_skips_the_wait(self, monkeypatch):
        monkeypatch.setattr("encryption_suite.adapters.keks.provisioners_aws._ALIAS_POLL_INTERVAL", 0)
        client = _ProvisioningKmsClient(unresolved_lookups=99)
        prov = _provisioner(client)

        prov.ensure_kek("es-prod-team-1", SiloRef("default", "team-1"))

        # No alias was created, so there is no propagation to wait on.
        assert [c[0] for c in client.calls] == ["describe_key", "create_key"]
        assert "es-prod-team-1" in prov._ensured


class TestRotationPolicy:
    def test_nothing_is_enabled_when_unconfigured(self):
        client = _ProvisioningKmsClient(unresolved_lookups=1)
        prov = _provisioner(client)

        prov.ensure_kek(_NAME, SiloRef("default", "team-1"))

        assert not [c for c in client.calls if c[0] == "enable_key_rotation"]

    def test_the_period_is_passed_in_days(self):
        # KEK_ROTATION_PERIOD_DAYS is provider-neutral; AWS is the one provider that
        # takes days as-is, where Cloud KMS wants seconds and Key Vault ISO 8601.
        client = _ProvisioningKmsClient(unresolved_lookups=1)
        prov = _provisioner(client, KEK_ROTATION_PERIOD_DAYS=365)

        prov.ensure_kek(_NAME, SiloRef("default", "team-1"))

        assert ("enable_key_rotation", _KEY_ID, 365) in client.calls

    def test_it_addresses_the_key_id_not_the_alias(self):
        # CreateAlias is eventually consistent and this runs before the
        # propagation wait, so the alias may not resolve yet.
        client = _ProvisioningKmsClient(unresolved_lookups=1)
        prov = _provisioner(client, KEK_ROTATION_PERIOD_DAYS=90)

        prov.ensure_kek(_NAME, SiloRef("default", "team-1"))

        call = next(c for c in client.calls if c[0] == "enable_key_rotation")
        assert call[1] == _KEY_ID

    def test_a_period_under_the_aws_floor_is_refused_at_construction(self):
        # AWS refuses a RotationPeriodInDays under 90.
        with pytest.raises(EncryptionConfigurationError):
            AwsKekProvisioner({"AWS_REGION": "us-east-1", "KEK_ROTATION_PERIOD_DAYS": 30})


class TestCustomKeyStore:
    def _create_kwargs(self, client) -> dict:
        return next(c[1] for c in client.calls if c[0] == "create_key")

    def test_unset_creates_a_plain_kms_key(self):
        client = _ProvisioningKmsClient(unresolved_lookups=1)
        _provisioner(client).ensure_kek(_NAME, SiloRef("default", "team-1"))

        kwargs = self._create_kwargs(client)
        assert "CustomKeyStoreId" not in kwargs
        assert "Origin" not in kwargs

    def test_set_creates_the_key_in_the_cloudhsm_store(self):
        client = _ProvisioningKmsClient(unresolved_lookups=1)
        _provisioner(client, CUSTOM_KEY_STORE_ID="cks-1234567890abcdef0").ensure_kek(
            _NAME, SiloRef("default", "team-1")
        )

        kwargs = self._create_kwargs(client)
        # CreateKey rejects a CustomKeyStoreId without the matching Origin.
        assert kwargs["CustomKeyStoreId"] == "cks-1234567890abcdef0"
        assert kwargs["Origin"] == "AWS_CLOUDHSM"

    def test_rotation_is_refused_at_construction(self):
        # AWS does not rotate keys in a custom key store; caught here, the
        # refusal reaches manage.py check instead of a post-create warning.
        with pytest.raises(EncryptionConfigurationError) as excinfo:
            AwsKekProvisioner(
                {
                    "AWS_REGION": "us-east-1",
                    "CUSTOM_KEY_STORE_ID": "cks-1234567890abcdef0",
                    "KEK_ROTATION_PERIOD_DAYS": 365,
                }
            )

        assert "CUSTOM_KEY_STORE_ID" in excinfo.value.detail
        assert "CUSTOM_KEY_STORE_ID" not in str(excinfo.value)


class TestRotationPolicyFailure:
    """A rotation that cannot be turned on must be loud, not fatal and not silent."""

    class _RefusingKmsClient(_ProvisioningKmsClient):
        def enable_key_rotation(self, KeyId, RotationPeriodInDays):  # noqa: N803
            raise _AwsError("AccessDeniedException")

    def test_the_key_is_still_usable(self):
        # The key exists and encrypts; failing a tenant's first save over a
        # rotation schedule would be the worse outcome.
        client = self._RefusingKmsClient(unresolved_lookups=1)
        prov = _provisioner(client, KEK_ROTATION_PERIOD_DAYS=90)

        prov.ensure_kek(_NAME, SiloRef("default", "team-1"))

        assert _NAME in prov._ensured

    def test_it_logs_a_warning_naming_the_permission(self, caplog):
        # The retry finds the key already present and never reattempts, so this
        # line is the only notice the operator ever gets.
        import logging

        prov = _provisioner(self._RefusingKmsClient(unresolved_lookups=1), KEK_ROTATION_PERIOD_DAYS=90)
        with caplog.at_level(logging.WARNING, logger="encryption_suite.adapters.keks.provisioners_aws"):
            prov.ensure_kek(_NAME, SiloRef("default", "team-1"))

        line = next(r for r in caplog.records if "will not rotate on its own" in r.getMessage())
        assert line.levelno == logging.WARNING
        assert _KEY_ID in line.getMessage()
        assert "kms:EnableKeyRotation" in line.getMessage()


class TestEnumeration:
    def test_lists_alias_names_across_pages(self):
        client = _FakeKmsClient(
            alias_pages=[
                {"Aliases": [{"AliasName": _PREFIX + "team-1", "TargetKeyId": _KEY_ID}]},
                {"Aliases": [{"AliasName": _PREFIX + "team-2", "TargetKeyId": "other"}]},
            ]
        )
        prov = _provisioner(client)

        assert prov.list_kek_names(_PREFIX) == [_PREFIX + "team-1", _PREFIX + "team-2"]
        assert ("get_paginator", "list_aliases") in client.calls

    def test_skips_aliases_with_no_target_key(self):
        client = _FakeKmsClient(
            alias_pages=[
                {
                    "Aliases": [
                        {"AliasName": _PREFIX + "dangling"},
                        {"AliasName": _PREFIX + "team-1", "TargetKeyId": _KEY_ID},
                    ]
                }
            ]
        )
        prov = _provisioner(client)

        assert prov.list_kek_names(_PREFIX) == [_PREFIX + "team-1"]

    def test_foreign_and_aws_managed_aliases_are_filtered_out(self):
        client = _FakeKmsClient(
            alias_pages=[
                {
                    "Aliases": [
                        {"AliasName": "alias/aws/s3", "TargetKeyId": "aws-managed"},
                        {"AliasName": "alias/other-app-1", "TargetKeyId": "foreign"},
                        {"AliasName": _PREFIX + "team-1", "TargetKeyId": _KEY_ID},
                    ]
                }
            ]
        )
        prov = _provisioner(client)

        assert prov.list_kek_names(_PREFIX) == [_PREFIX + "team-1"]

    def test_empty_account_yields_no_names(self):
        prov = _provisioner(_FakeKmsClient(alias_pages=[{"Aliases": []}]))

        assert prov.list_kek_names(_PREFIX) == []

    def test_non_alias_owner_prefix_degrades_to_detection_unavailable(self):
        # An empty list would read as "no keys exist" and orphan every silo, so
        # this must raise and let reconcile report detection-unavailable.
        prov = _provisioner(_FakeKmsClient(alias_pages=[]))

        with pytest.raises(KekEnumerationError):
            prov.list_kek_names("es-prod-")
