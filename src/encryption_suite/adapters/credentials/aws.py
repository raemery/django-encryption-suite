"""
AWS credential strategies for the AWS KMS adapter.

Two strategies are available:

    "iam_role"  — AwsIamRoleStrategy
                                boto3 automatic credential chain (IAM role, ECS task
                                role, instance metadata, environment variables such
                                as AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY,
                                ~/.aws/credentials, etc.)
    "oidc"      — AwsOidcStrategy
                                OIDC JWT (from any configured ``OidcTokenSource``)
                                → STS AssumeRoleWithWebIdentity

Each strategy's ``get_credentials()`` returns a ready-to-use ``boto3.Session``.
STS-issued sessions (oidc) are cached until 5 minutes before expiry and
refreshed automatically.

The ``oidc`` strategy delegates JWT acquisition to an injected
``OidcTokenSource`` (see ``adapters.credentials.oidc_sources``), so the same
strategy works on Fly.io, self-hosted Kubernetes, Vercel, SPIFFE, etc. —
whichever source is configured.
"""

from __future__ import annotations

import threading
from datetime import UTC, datetime, timedelta

from ..._logging import get_logger
from .base import AbstractCredentialStrategy

logger = get_logger(__name__)


class AwsIamRoleStrategy(AbstractCredentialStrategy):
    """
    Uses boto3's built-in credential chain (IAM role, ECS task role, EC2
    instance metadata, environment variables, ~/.aws/credentials, etc.).

    boto3 handles credential refresh internally — no extra logic needed here.
    This is the recommended strategy for AWS-hosted deployments.
    """

    def __init__(self, region: str) -> None:
        self._region = region

    def get_credentials(self):
        import boto3

        return boto3.Session(region_name=self._region)


class AwsOidcStrategy(AbstractCredentialStrategy):
    """
    Keyless authentication via OIDC JWT → STS AssumeRoleWithWebIdentity.

    Flow:
      1. Fetch a signed OIDC JWT for the configured audience from the
         injected ``OidcTokenSource`` (Fly socket, file, Vercel, SPIFFE, ...).
      2. Call STS ``AssumeRoleWithWebIdentity`` to exchange it for temporary
         AWS credentials scoped to the configured IAM role.
      3. Return a ``boto3.Session`` built from those credentials.

    The STS session is cached until 5 minutes before its expiry, then
    transparently refreshed on the next ``get_credentials()`` call.

    Required options:
      AWS_ROLE_ARN            : str  ARN of the role to assume
      AWS_REGION              : str
    Optional options:
      AWS_ROLE_SESSION_NAME   : str  (default: "django-encryption-suite")
      AWS_OIDC_AUDIENCE       : str  (default: "amazonaws.com")
    """

    def __init__(self, options: dict, token_source) -> None:
        self._options = options
        self._token_source = token_source
        self._session = None
        self._expires_at: datetime | None = None
        self._lock = threading.Lock()

    def get_credentials(self):
        with self._lock:
            now = datetime.now(tz=UTC)
            if self._session and self._expires_at and self._expires_at > now + timedelta(minutes=5):
                return self._session
            logger.debug("Refreshing the STS session from an OIDC token source.")
            self._session, self._expires_at = self._fetch_session()
            return self._session

    def _fetch_session(self):
        import boto3

        region = self._options.get("AWS_REGION", "us-east-1")
        role_arn = self._options["AWS_ROLE_ARN"]
        session_name = self._options.get("AWS_ROLE_SESSION_NAME", "django-encryption-suite")
        audience = self._options.get("AWS_OIDC_AUDIENCE", "amazonaws.com")

        jwt = self._token_source.get_token(audience)

        sts = boto3.client("sts", region_name=region)
        result = sts.assume_role_with_web_identity(
            RoleArn=role_arn,
            RoleSessionName=session_name,
            WebIdentityToken=jwt,
        )
        creds = result["Credentials"]
        expires_at: datetime = creds["Expiration"]
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=UTC)

        session = boto3.Session(
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"],
            region_name=region,
        )
        return session, expires_at
