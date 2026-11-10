"""
HashiCorp Vault credential strategies for the HashiCorp Vault KMS adapter.

Four strategies are available:

    "token"    — HashiCorpVaultTokenStrategy
                             static Vault token from OPTIONS or VAULT_TOKEN env var
    "approle"  — HashiCorpVaultAppRoleStrategy
                             AppRole auth method — exchanges a role_id and secret_id
                             for a short-lived client token via
                             ``POST /v1/auth/{mount}/login``.
    "iam_aws"  — HashiCorpVaultIamAwsStrategy
                             AWS IAM auth method (requires boto3)
    "oidc"     — HashiCorpVaultJwtAuthStrategy
                             JWT/OIDC auth method — exchanges an OIDC JWT (from any
                             configured ``OidcTokenSource``) for a Vault token via
                             ``POST /v1/auth/{mount}/login``.

Each strategy's ``get_credentials()`` returns a Vault client token string.
Tokens are cached and refreshed on 403 — HashiCorpVaultAdapter calls
``invalidate()`` before retrying.

The ``oidc`` strategy delegates JWT acquisition to an injected
``OidcTokenSource`` (see ``adapters.credentials.oidc_sources``), so the same
strategy works on Fly.io, GCP, Vercel, self-hosted Kubernetes, SPIFFE, etc.
"""

from __future__ import annotations

import base64
import json
import os
import threading

from ..._logging import get_logger
from ...exceptions import log_and_raise_configuration_error
from .._http import resolve_request_timeout, urlopen_with_detail
from .base import AbstractCredentialStrategy

logger = get_logger(__name__)


class HashiCorpVaultTokenStrategy(AbstractCredentialStrategy):
    """
    Static Vault token from OPTIONS['VAULT_TOKEN'] or the VAULT_TOKEN
    environment variable.

    The token is cached after the first retrieval.  If the token is revoked,
    the adapter will receive a 403 and re-raise — static tokens cannot be
    automatically renewed.
    """

    def __init__(self, options: dict) -> None:
        self._options = options
        self._token: str | None = None

    def get_credentials(self) -> str:
        if self._token:
            return self._token
        token = self._options.get("VAULT_TOKEN") or os.environ.get("VAULT_TOKEN")
        if not token:
            log_and_raise_configuration_error(
                logger, "HashiCorpVaultTokenStrategy: VAULT_TOKEN not found in OPTIONS or environment."
            )
        self._token = token
        return token

    def invalidate(self) -> None:
        """Clear the cached token so the next call re-reads from config / env."""
        self._token = None


class HashiCorpVaultAppRoleStrategy(AbstractCredentialStrategy):
    """
    Authenticates to Vault using the AppRole auth method.

    POSTs role_id and secret_id to ``{VAULT_ENDPOINT}/v1/auth/{mount}/login`` and
    caches the returned client token. The HashiCorpVaultAdapter calls
    ``invalidate()`` on a 403, forcing a re-login on the next call (handles
    token TTL expiry without explicit renewal).

    Required options:
      VAULT_ENDPOINT         : str  Vault server address
      VAULT_ROLE_ID      : str  AppRole role_id
    Required (one of):
      VAULT_SECRET_ID    : str  AppRole secret_id (plaintext)
      VAULT_SECRET_ID_FILE : str  path to a file containing the secret_id
    Optional options:
      VAULT_APPROLE_MOUNT : str  Vault mount path (default: "approle")
      VAULT_NAMESPACE    : str  Vault namespace (HCP Vault / Enterprise)
    """

    def __init__(self, options: dict, ssl_context=None) -> None:
        self._options = options
        self._token: str | None = None
        self._ssl_context = ssl_context
        self._lock = threading.Lock()

    def get_credentials(self) -> str:
        with self._lock:
            if self._token:
                return self._token
            self._token = self._login()
            return self._token

    def invalidate(self) -> None:
        with self._lock:
            self._token = None

    def _read_secret_id(self) -> str:
        secret_id = self._options.get("VAULT_SECRET_ID") or os.environ.get("VAULT_SECRET_ID")
        if secret_id:
            return secret_id
        path = self._options.get("VAULT_SECRET_ID_FILE") or os.environ.get("VAULT_SECRET_ID_FILE")
        if path:
            with open(path, encoding="utf-8") as fh:
                return fh.read().strip()
        log_and_raise_configuration_error(
            logger,
            "HashiCorpVaultAppRoleStrategy: provide VAULT_SECRET_ID or VAULT_SECRET_ID_FILE in OPTIONS or environment.",
        )

    def _login(self) -> str:
        import urllib.request

        addr = self._options["VAULT_ENDPOINT"].rstrip("/")
        mount = urllib.parse.quote(self._options.get("VAULT_APPROLE_MOUNT", "approle"), safe="")
        role_id = self._options.get("VAULT_ROLE_ID") or os.environ.get("VAULT_ROLE_ID")
        if not role_id:
            log_and_raise_configuration_error(
                logger, "HashiCorpVaultAppRoleStrategy: VAULT_ROLE_ID not found in OPTIONS or environment."
            )
        secret_id = self._read_secret_id()
        namespace = self._options.get("VAULT_NAMESPACE")

        body = json.dumps({"role_id": role_id, "secret_id": secret_id}).encode()
        headers = {"Content-Type": "application/json"}
        if namespace:
            headers["X-Vault-Namespace"] = namespace

        req = urllib.request.Request(f"{addr}/v1/auth/{mount}/login", data=body, headers=headers)
        logger.debug("Authenticating to Vault. method=approle")
        with urlopen_with_detail(
            req, timeout=resolve_request_timeout(self._options), context=self._ssl_context
        ) as resp:
            data = json.loads(resp.read())
        return data["auth"]["client_token"]


class HashiCorpVaultIamAwsStrategy(AbstractCredentialStrategy):
    """
    Authenticates to Vault using the AWS IAM auth method.

    The Vault token obtained after login is cached and reused.  When the
    HashiCorpVaultAdapter receives a 403 it calls ``invalidate()`` on this
    strategy before retrying, forcing a fresh login.

    Required options:
      VAULT_ENDPOINT         : str  Vault server address
    Optional options:
      AWS_IAM_VAULT_ROLE : str  Vault role name (default: "default")
      VAULT_NAMESPACE    : str  Vault namespace (HCP Vault / Enterprise)
    """

    def __init__(self, options: dict, ssl_context=None) -> None:
        self._options = options
        self._token: str | None = None
        self._ssl_context = ssl_context

    def get_credentials(self) -> str:
        if self._token:
            return self._token
        self._token = self._login()
        return self._token

    def invalidate(self) -> None:
        """Clear the cached token to force a re-login on the next call."""
        self._token = None

    def _login(self) -> str:
        try:
            import boto3
            from botocore.auth import SigV4Auth
            from botocore.awsrequest import AWSRequest
        except ImportError as exc:
            log_and_raise_configuration_error(
                logger, "boto3 (and botocore) are required for HashiCorpVaultIamAwsStrategy.", cause=exc
            )
        import urllib.request

        addr = self._options["VAULT_ENDPOINT"].rstrip("/")
        namespace = self._options.get("VAULT_NAMESPACE")
        vault_role = self._options.get("AWS_IAM_VAULT_ROLE", "default")

        # Build an STS GetCallerIdentity request and sign it with AWS SigV4.
        # Vault replays this signed request against STS to verify our identity,
        # so the headers must contain a valid AWS Signature V4 authorization.
        session = boto3.Session()
        credentials = session.get_credentials().get_frozen_credentials()
        region = session.region_name or "us-east-1"
        endpoint = f"https://sts.{region}.amazonaws.com/"
        body = "Action=GetCallerIdentity&Version=2011-06-15"

        # Create an AWSRequest and sign it.  The resulting headers contain the
        # Authorization, X-Amz-Date, and (if using temporary credentials)
        # X-Amz-Security-Token headers that Vault needs to verify the caller.
        aws_request = AWSRequest(
            method="POST",
            url=endpoint,
            data=body,
            headers={
                "Content-Type": "application/x-www-form-urlencoded; charset=utf-8",
            },
        )
        SigV4Auth(credentials, "sts", region).add_auth(aws_request)

        # Vault expects the signed headers as a JSON object, base64-encoded.
        # Only include headers relevant to the STS signature — Vault will
        # forward them verbatim when replaying the GetCallerIdentity call.
        signed_headers = dict(aws_request.headers)

        payload = json.dumps(
            {
                "role": vault_role,
                "iam_http_request_method": "POST",
                "iam_request_url": base64.b64encode(endpoint.encode()).decode(),
                "iam_request_body": base64.b64encode(body.encode()).decode(),
                "iam_request_headers": base64.b64encode(json.dumps(signed_headers).encode()).decode(),
            }
        ).encode()

        # POST the signed request data to Vault's AWS auth endpoint.
        headers = {"Content-Type": "application/json"}
        if namespace:
            headers["X-Vault-Namespace"] = namespace

        req = urllib.request.Request(f"{addr}/v1/auth/aws/login", data=payload, headers=headers)
        logger.debug("Authenticating to Vault. method=aws_iam")
        with urlopen_with_detail(
            req, timeout=resolve_request_timeout(self._options), context=self._ssl_context
        ) as resp:
            data = json.loads(resp.read())
        return data["auth"]["client_token"]


class HashiCorpVaultJwtAuthStrategy(AbstractCredentialStrategy):
    """
    Authenticates to Vault using the JWT/OIDC auth method.

    Posts the OIDC JWT obtained from the injected ``OidcTokenSource`` to
    ``{VAULT_ENDPOINT}/v1/auth/{VAULT_JWT_MOUNT}/login`` along with the configured
    role. Vault verifies the JWT against its bound issuer/JWKS and returns a
    short-lived Vault token, cached until ``invalidate()`` is called.

    Required options:
      VAULT_ENDPOINT          : str  Vault server address
      VAULT_JWT_ROLE      : str  Vault role bound to the JWT auth method
    Optional options:
      VAULT_JWT_MOUNT     : str  Vault mount path (default: "jwt")
      VAULT_JWT_AUDIENCE  : str  ``aud`` claim requested from the OIDC source
                                 (default: VAULT_JWT_ROLE — many setups bind
                                 the role name itself as the bound audience)
      VAULT_NAMESPACE     : str  Vault namespace (HCP Vault / Enterprise)
    """

    def __init__(self, options: dict, token_source, ssl_context=None) -> None:
        self._options = options
        self._token_source = token_source
        self._token: str | None = None
        self._ssl_context = ssl_context
        self._lock = threading.Lock()

    def get_credentials(self) -> str:
        with self._lock:
            if self._token:
                return self._token
            self._token = self._login()
            return self._token

    def invalidate(self) -> None:
        """Clear the cached token to force a re-login on the next call."""
        with self._lock:
            self._token = None

    def _login(self) -> str:
        import urllib.request

        addr = self._options["VAULT_ENDPOINT"].rstrip("/")
        # Quote the mount path so a misconfigured value with slashes or
        # other URL-meaningful characters can't redirect the login POST.
        mount = urllib.parse.quote(self._options.get("VAULT_JWT_MOUNT", "jwt"), safe="")
        role = self._options["VAULT_JWT_ROLE"]
        audience = self._options.get("VAULT_JWT_AUDIENCE", role)
        namespace = self._options.get("VAULT_NAMESPACE")

        jwt = self._token_source.get_token(audience)
        body = json.dumps({"role": role, "jwt": jwt}).encode()
        headers = {"Content-Type": "application/json"}
        if namespace:
            headers["X-Vault-Namespace"] = namespace

        req = urllib.request.Request(f"{addr}/v1/auth/{mount}/login", data=body, headers=headers)
        logger.debug("Authenticating to Vault. method=jwt_oidc")
        with urlopen_with_detail(
            req, timeout=resolve_request_timeout(self._options), context=self._ssl_context
        ) as resp:
            data = json.loads(resp.read())
        return data["auth"]["client_token"]
