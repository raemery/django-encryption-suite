"""AwsKmsAdapter: which name a wrapped DEK is recorded under.

boto3 is not installed in this environment, so the KMS client is stubbed and the
constructor (which builds a credential strategy) is bypassed.
"""

from __future__ import annotations

from encryption_suite.adapters.key_stores.aws import AwsKmsAdapter

_ALIAS = "alias/es-prod-team-1"
_ARN = "arn:aws:kms:us-east-1:001961766426:key/12345678-1234-4123-8123-123456789abc"


class _FakeStrategy:
    def get_kek_id(self, silo_uid):
        return _ALIAS


class _FakeKmsClient:
    def encrypt(self, KeyId, Plaintext, EncryptionContext):  # noqa: N803 - boto3's parameter names
        self.encrypt_key_id = KeyId
        # KMS answers Encrypt with the resolved key ARN, never the alias it was given.
        return {"CiphertextBlob": b"wrapped", "KeyId": _ARN}


def _adapter():
    adapter = object.__new__(AwsKmsAdapter)
    adapter.options = {"AWS_REGION": "us-east-1"}
    adapter._kek_strategy = _FakeStrategy()
    adapter._client = _FakeKmsClient()
    return adapter


def test_records_the_configured_name_not_the_response_arn():
    """The stored name is the key's identity for ownership and reconcile.

    ``owns_kek`` prefix-matches it against the strategy's owner prefix, and
    reconcile compares it against ListAliases output. An ARN matches neither, so
    recording one silently disables KEK deletion and makes every key read as
    unreconciled.
    """
    adapter = _adapter()

    ciphertext, metadata = adapter._do_encrypt_key(b"dek", "team-1")

    assert ciphertext == b"wrapped"
    assert metadata.kek_resource_name == _ALIAS
    assert metadata.kms_provider == "aws"
    # The alias is still what AWS is asked to encrypt under.
    assert adapter._client.encrypt_key_id == _ALIAS


def test_mismatch_hint_still_reads_arn_form_names():
    """KEK_MAP may point at explicit ARNs, which do carry a region to compare."""
    adapter = _adapter()

    hint = adapter.kek_resource_mismatch_hint("arn:aws:kms:eu-west-1:123456789012:key/abc")

    assert hint is not None
    assert "eu-west-1" in hint


def test_mismatch_hint_ignores_alias_form_names():
    adapter = _adapter()

    assert adapter.kek_resource_mismatch_hint(_ALIAS) is None


class TestDescribeInstance:
    """The console's instance line has to say which account, not just which region.

    One region holds every AWS deployment's keys, so a region alone cannot
    answer "am I pointed at the right place", which is what the line is for.
    """

    def test_the_account_option_is_named_beside_the_region(self):
        adapter = _adapter()
        adapter.options = {"AWS_REGION": "us-east-1", "AWS_ACCOUNT_ID": "001961766426"}

        assert adapter.describe_instance() == "us-east-1 / 001961766426"

    def test_the_account_is_read_off_the_assumed_role_arn(self):
        # Under the oidc strategy the account is already in the options, so it
        # needs no configuration of its own.
        adapter = _adapter()
        adapter.options = {
            "AWS_REGION": "us-east-1",
            "AWS_ROLE_ARN": "arn:aws:iam::001961766426:role/es-kms",
        }

        assert adapter.describe_instance() == "us-east-1 / 001961766426"

    def test_the_region_stands_alone_when_the_account_is_unknowable(self):
        # iam_role with no account option: only STS knows, and describe_instance
        # must not make a call.
        assert _adapter().describe_instance() == "us-east-1"

    def test_a_malformed_role_arn_is_ignored_rather_than_split_blindly(self):
        adapter = _adapter()
        adapter.options = {"AWS_REGION": "us-east-1", "AWS_ROLE_ARN": "es-kms"}

        assert adapter.describe_instance() == "us-east-1"
