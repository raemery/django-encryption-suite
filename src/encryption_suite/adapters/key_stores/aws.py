"""
AWS KMS adapter.

Requires the ``aws`` extra: ``pip install django-encryption-suite[aws]``

Each silo gets its own AWS KMS key, resolved via ``KEK_TEMPLATE`` or
``KEK_MAP`` in ``OPTIONS``.  The template value is the full key ARN or
alias (e.g. ``"alias/encryption_suite-{silo_uid}"``).

Credential strategy is selected via OPTIONS['CREDENTIAL_STRATEGY']:
  "iam_role"   (default) — AwsIamRoleStrategy (boto3 default credential chain,
                            which includes AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY
                            from the process environment)
  "oidc"                  — AwsOidcStrategy (OIDC token source selected via
                            the required OIDC_SOURCE option)

See ``adapters.credentials.aws`` and ``adapters.credentials.oidc_sources``
for strategy details and required options.

Required OPTIONS keys (all strategies):
  AWS_REGION      : str   e.g. "us-east-1"
  KEK_TEMPLATE    : str   e.g. "alias/encryption_suite-{silo_uid}"
                           (or KEK_MAP for explicit mapping)
Optional OPTIONS keys:
  AWS_ACCOUNT_ID  : str   account id. Used only to name the account in the admin
                          test console, which a region alone cannot identify.
                          Unnecessary under the oidc strategy, where the account
                          is read off AWS_ROLE_ARN.
"""

from __future__ import annotations

from ..._logging import get_logger
from ...exceptions import log_and_raise_configuration_error
from ...silo_ref import silo_text
from ..credentials.aws import AwsIamRoleStrategy, AwsOidcStrategy
from ..credentials.oidc_sources import build_oidc_source
from .base import AbstractKmsAdapter, KmsMetadata

logger = get_logger(__name__)

_PROVIDER = "aws"

# botocore error codes that indicate expired or invalid credentials.
_CREDENTIAL_ERROR_CODES = frozenset(
    {"ExpiredTokenException", "InvalidClientTokenId", "AuthFailure", "UnrecognizedClientException"}
)

# botocore error codes that indicate the requested KEK does not exist on KMS.
# ``NotFoundException`` covers missing key IDs, ARNs, and aliases whose target
# key has been deleted.  ``InvalidAliasNameException`` is surfaced when an
# alias name is syntactically valid but the alias itself has never been
# created — practically indistinguishable from a missing KEK for our purposes.
_KEK_NOT_FOUND_ERROR_CODES = frozenset({"NotFoundException", "InvalidAliasNameException"})


def describe_aws_instance(options: dict) -> str | None:
    """Name the account and region the AWS adapters are pointed at.

    Shared by both AWS adapters. A region on its own does not say *which
    account*, which is the question the admin test console's instance line
    exists to answer — one region holds every deployment's keys.

    Option-sourced only, because ``describe_instance`` must not make a call:
    ``AWS_ACCOUNT_ID`` when set, else the account embedded in the assumed
    role's ARN under the oidc strategy. Under ``iam_role`` with neither, the
    account is knowable only from STS, so the line stays at the region rather
    than guessing.
    """
    options = options or {}
    account = options.get("AWS_ACCOUNT_ID") or _account_from_arn(options.get("AWS_ROLE_ARN", ""))
    parts = [str(v) for v in (options.get("AWS_REGION"), account) if v]
    return " / ".join(parts) if parts else None


def _account_from_arn(arn: str) -> str:
    """Return the account id field of an ARN, or empty for anything else.

    ``arn:aws:iam::123456789012:role/name`` → ``123456789012``.
    """
    fields = str(arn).split(":")
    return fields[4] if len(fields) > 5 and fields[0] == "arn" else ""


class AwsKmsAdapter(AbstractKmsAdapter):
    """
    AWS KMS adapter.

    Delegates authentication entirely to the configured credential strategy.
    On credential-expiry errors the KMS client is rebuilt via the strategy,
    which transparently refreshes credentials (e.g. re-fetches STS session for
    the oidc strategy) before retrying once.
    """

    kms_provider = _PROVIDER
    # Not _INSTANCE_OPTION_KEYS: the account may have to be derived from the
    # role ARN rather than read from an option of its own.

    _HONORS_TLS_OPTIONS = False
    _TLS_SDK_HINT = (
        "botocore manages its own trust store. To trust a private CA for "
        "AWS KMS calls, set AWS_CA_BUNDLE=/path/to/ca-bundle.pem on the "
        "process (or REQUESTS_CA_BUNDLE / SSL_CERT_FILE as a fallback)."
    )

    def __init__(self, options: dict, kek_strategy) -> None:
        super().__init__(options, kek_strategy)
        self._strategy = self._build_strategy(options)
        self._client = None

    def describe_instance(self) -> str | None:
        return describe_aws_instance(self.options)

    @staticmethod
    def _build_strategy(options: dict):
        strategy_name = options.get("CREDENTIAL_STRATEGY", "iam_role")
        region = options.get("AWS_REGION", "us-east-1")
        if strategy_name == "iam_role":
            return AwsIamRoleStrategy(region)
        elif strategy_name == "oidc":
            source_name = options.get("OIDC_SOURCE")
            if not source_name:
                log_and_raise_configuration_error(logger, "CREDENTIAL_STRATEGY='oidc' requires OIDC_SOURCE in OPTIONS.")
            source = build_oidc_source(source_name, options.get("OIDC_SOURCE_OPTIONS", {}))
            return AwsOidcStrategy(options, source)
        else:
            log_and_raise_configuration_error(
                logger, f"Unknown CREDENTIAL_STRATEGY '{strategy_name}'. Valid options: iam_role, oidc"
            )

    def _get_client(self):
        if self._client is None:
            try:
                import boto3  # noqa: F401 — imported to give a clear error if missing
            except ImportError as exc:
                raise RuntimeError(
                    "boto3 is required for AwsKmsAdapter. Install the 'aws' extra: "
                    "pip install django-encryption-suite[aws]"
                ) from exc
            session = self._strategy.get_credentials()
            self._client = session.client("kms")
        return self._client

    def _is_credential_error(self, exc: Exception) -> bool:
        try:
            from botocore.exceptions import ClientError

            if isinstance(exc, ClientError):
                return exc.response["Error"]["Code"] in _CREDENTIAL_ERROR_CODES
        except ImportError:
            pass
        return False

    def is_kek_not_found_error(self, exc: BaseException) -> bool:
        try:
            from botocore.exceptions import ClientError

            if isinstance(exc, ClientError):
                return exc.response["Error"]["Code"] in _KEK_NOT_FOUND_ERROR_CODES
        except ImportError:
            pass
        return super().is_kek_not_found_error(exc)

    @staticmethod
    def _encryption_context(silo_ref) -> dict:
        """Return the AWS ``EncryptionContext`` dict bound to a wrapped DEK.

        ``EncryptionContext`` is the AWS-native equivalent of the bytes-form
        AAD other adapters bind via :meth:`AbstractKmsAdapter._wrap_aad`. The
        dict is logged in CloudTrail as structured fields, so the silo
        UID becomes queryable in audit trails. The ``purpose`` key
        future-proofs for separate contexts on file-stream wraps if those
        ever become a thing; KMS treats it as a fixed AAD value either way.
        """
        silo = silo_text(silo_ref)
        if not silo:
            raise ValueError("silo_ref must be a non-empty silo reference when binding AWS EncryptionContext.")
        try:
            silo.encode("ascii", errors="strict")
        except UnicodeEncodeError as exc:
            raise ValueError(
                f"silo_ref must be ASCII-printable for AWS EncryptionContext (got non-ASCII characters in {silo!r})."
            ) from exc
        return {"silo_uid": silo, "purpose": "dek"}

    def encrypt_key(self, plaintext: bytes, silo_ref: str) -> tuple[bytes, KmsMetadata]:
        try:
            result = self._do_encrypt_key(plaintext, silo_ref)
            self._clear_auth_retry_block()
            return result
        except Exception as exc:
            if self._is_credential_error(exc):
                if self._is_auth_retry_blocked():
                    raise
                logger.warning(
                    "The call was rejected as unauthenticated, so credentials are being refreshed "
                    "and the call retried once. operation=%s",
                    "encrypt_key",
                )
                self._client = None
                try:
                    result = self._do_encrypt_key(plaintext, silo_ref)
                    self._clear_auth_retry_block()
                    return result
                except Exception:
                    self._record_auth_retry_failure()
                    raise
            raise

    def _do_encrypt_key(self, plaintext: bytes, silo_ref: str) -> tuple[bytes, KmsMetadata]:
        client = self._get_client()
        kek_id = self._resolve_kek_id(silo_ref)
        response = client.encrypt(
            KeyId=kek_id,
            Plaintext=plaintext,
            EncryptionContext=self._encryption_context(silo_ref),
        )
        ciphertext = response["CiphertextBlob"]
        # The configured KEK name, not the key ARN the response carries. This
        # value is the key's identity everywhere else in the package: the KEK
        # ownership gate prefix-matches it against the strategy's owner_prefix,
        # and reconcile compares it against the provisioner's KMS listing (which
        # is ListAliases — a KMS key has no name of its own). An ARN matches
        # neither, so storing one silently disables both. Every other adapter,
        # AwsTinkKmsAdapter included, stores the configured name.
        #
        # Nothing is lost on the crypto path: for a symmetric KMS key, Decrypt's
        # KeyId is an assertion, not a selector — the ciphertext blob already
        # identifies its key, and AWS fails the call if the two disagree. So a
        # repointed alias surfaces as a loud decrypt failure rather than a
        # decrypt under the wrong key. AWS automatic rotation keeps the same key
        # and never triggers it.
        return ciphertext, KmsMetadata(kek_resource_name=kek_id, kms_provider=_PROVIDER)

    def decrypt_key(
        self,
        ciphertext: bytes,
        metadata: KmsMetadata,
        silo_ref: str,
    ) -> bytes:
        try:
            result = self._do_decrypt_key(ciphertext, metadata, silo_ref)
            self._clear_auth_retry_block()
            return result
        except Exception as exc:
            if self._is_credential_error(exc):
                if self._is_auth_retry_blocked():
                    raise
                logger.warning(
                    "The call was rejected as unauthenticated, so credentials are being refreshed "
                    "and the call retried once. operation=%s",
                    "decrypt_key",
                )
                self._client = None
                try:
                    result = self._do_decrypt_key(ciphertext, metadata, silo_ref)
                    self._clear_auth_retry_block()
                    return result
                except Exception:
                    self._record_auth_retry_failure()
                    raise
            raise

    def _do_decrypt_key(
        self,
        ciphertext: bytes,
        metadata: KmsMetadata,
        silo_ref: str,
    ) -> bytes:
        client = self._get_client()
        response = client.decrypt(
            CiphertextBlob=ciphertext,
            KeyId=metadata.kek_resource_name,
            EncryptionContext=self._encryption_context(silo_ref),
        )
        return response["Plaintext"]

    def kek_resource_mismatch_hint(self, stored_resource_name: str) -> str | None:
        # Only ARN-form names carry a region to compare, so this fires for a
        # KEK_MAP pointing at explicit ARNs (arn:aws:kms:<region>:<account>:key/<id>)
        # and catches a row written by a deployment in another region. Names from
        # a KEK_TEMPLATE are aliases or bare key ids, which name no region — there
        # is nothing to check and they are left alone.
        region = self.options.get("AWS_REGION", "us-east-1")
        if stored_resource_name.startswith("arn:aws:kms:"):
            parts = stored_resource_name.split(":")
            stored_region = parts[3] if len(parts) > 3 else ""
            if stored_region and stored_region != region:
                return f"stored KEK is in region '{stored_region}', but this adapter is configured for '{region}'"
        return None

    def describe_kek(self) -> str:
        template = self.options.get("KEK_TEMPLATE", "")
        kek_map = self.options.get("KEK_MAP")
        if template:
            return f"AWS KMS keys: {template}"
        if kek_map:
            return f"AWS KMS keys: {len(kek_map)} mapped keys"
        return "AWS KMS (no KEK_TEMPLATE or KEK_MAP configured)"
