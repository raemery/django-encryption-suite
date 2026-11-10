"""
AWS KMS adapter using Tink's native ``awskms`` integration.

Alternative to ``AwsKmsAdapter`` — delegates crypto and auth entirely to
Tink's ``AwsKmsClient``, which uses the default boto3 credential chain.
No separate credential strategy is needed.

Requires the ``aws`` extra: ``pip install django-encryption-suite[aws]``

Each silo gets its own AWS KMS key, resolved via ``KEK_TEMPLATE``
or ``KEK_MAP`` in ``OPTIONS``.  The template value may be a full key
ARN or a bare ``alias/...`` / ``key/...`` id
(e.g. ``"alias/encryption_suite-{silo_uid}"``).

Unlike the native ``AwsKmsAdapter`` (which lets boto3 resolve bare
aliases), Tink's ``AwsKmsClient`` requires a full ARN key URI, so a bare
``alias/...`` / ``key/...`` id is expanded to
``arn:aws:kms:<region>:<account>:<id>`` automatically.  The account id is
read from the ``AWS_ACCOUNT_ID`` option if set, otherwise resolved once via
STS ``GetCallerIdentity`` (which requires no IAM permission).

Required OPTIONS keys:
  AWS_REGION    : str   e.g. "us-east-1"
  KEK_TEMPLATE  : str   e.g. "alias/encryption_suite-{silo_uid}"
                          (or KEK_MAP for explicit mapping)
Optional OPTIONS keys:
  AWS_ACCOUNT_ID: str   account id for ARN expansion (else resolved via STS)
"""

from __future__ import annotations

from ..._logging import get_logger
from .aws import describe_aws_instance
from .base import AbstractKmsAdapter, KmsMetadata

logger = get_logger(__name__)

_PROVIDER = "aws-tink"


class AwsTinkKmsAdapter(AbstractKmsAdapter):
    """
    AWS KMS adapter backed by ``tink.integration.awskms``.

    Uses Tink's ``AwsKmsClient`` to obtain an ``Aead`` primitive for each
    KMS key.  Auth is handled by the default boto3 credential chain
    (env vars, IAM role, instance profile, etc.).
    """

    kms_provider = _PROVIDER
    # Not _INSTANCE_OPTION_KEYS: the account may have to be derived from the
    # role ARN rather than read from an option of its own.

    _HONORS_TLS_OPTIONS = False
    _TLS_SDK_HINT = (
        "Tink's AwsKmsClient uses botocore, which manages its own trust "
        "store. To trust a private CA for AWS KMS calls, set "
        "AWS_CA_BUNDLE=/path/to/ca-bundle.pem on the process (or "
        "REQUESTS_CA_BUNDLE / SSL_CERT_FILE as a fallback)."
    )

    def __init__(self, options: dict, kek_strategy) -> None:
        super().__init__(options, kek_strategy)
        self._aeads: dict[str, object] = {}
        self._region = options.get("AWS_REGION", "us-east-1")
        self._account_id: str | None = options.get("AWS_ACCOUNT_ID")

    def describe_instance(self) -> str | None:
        # Deliberately not _resolve_account_id: describe_instance must not call
        # STS. An account resolved earlier by a real encrypt is still shown.
        return describe_aws_instance({**self.options, "AWS_ACCOUNT_ID": self._account_id})

    def _resolve_account_id(self) -> str:
        if self._account_id is None:
            try:
                import boto3
            except ImportError as exc:
                raise RuntimeError(
                    "boto3 is required for AwsTinkKmsAdapter. "
                    "Install the 'aws' extra: pip install django-encryption-suite[aws]"
                ) from exc
            self._account_id = boto3.client("sts", region_name=self._region).get_caller_identity()["Account"]
        return self._account_id

    def _key_uri(self, key_id: str) -> str:
        # Tink's AwsKmsClient requires a full ARN key URI. KEK_TEMPLATE / the
        # provisioner produce bare "alias/..." or "key/..." ids (what the native
        # adapter hands straight to boto3); expand those to an ARN here. Values
        # that are already an ARN or aws-kms:// URI pass through unchanged.
        if key_id.startswith("aws-kms://"):
            return key_id
        if key_id.startswith("arn:aws:kms:"):
            return f"aws-kms://{key_id}"
        return f"aws-kms://arn:aws:kms:{self._region}:{self._resolve_account_id()}:{key_id}"

    def _get_aead(self, key_id: str):
        if key_id in self._aeads:
            return self._aeads[key_id]
        try:
            from tink import aead
            from tink.integration import awskms
        except ImportError as exc:
            raise RuntimeError(
                "tink with AWS KMS integration is required for AwsTinkKmsAdapter. "
                "Install the 'aws' extra: pip install django-encryption-suite[aws]"
            ) from exc
        aead.register()
        uri = self._key_uri(key_id)
        # Second arg is a boto3 credentials *file path*, not the region — leave
        # it empty so Tink uses the default boto3 credential chain (IAM/task
        # role, env, etc.). The region is parsed from the ARN in the URI.
        client = awskms.AwsKmsClient(uri, "")
        primitive = client.get_aead(uri)
        self._aeads[key_id] = primitive
        return primitive

    def encrypt_key(self, plaintext: bytes, silo_ref: str) -> tuple[bytes, KmsMetadata]:
        key_id = self._resolve_kek_id(silo_ref)
        ciphertext = self._get_aead(key_id).encrypt(plaintext, self._wrap_aad(silo_ref))
        return ciphertext, KmsMetadata(
            kek_resource_name=key_id,
            kms_provider=_PROVIDER,
        )

    def decrypt_key(
        self,
        ciphertext: bytes,
        metadata: KmsMetadata,
        silo_ref: str,
    ) -> bytes:
        key_id = metadata.kek_resource_name
        return self._get_aead(key_id).decrypt(ciphertext, self._wrap_aad(silo_ref))

    def describe_kek(self) -> str:
        template = self.options.get("KEK_TEMPLATE", "")
        if template:
            return f"AWS KMS (Tink) keys: {template}"
        kek_map = self.options.get("KEK_MAP")
        if kek_map:
            return f"AWS KMS (Tink) keys: {len(kek_map)} mapped keys"
        return f"AWS KMS (Tink) region={self._region}"
