"""
Infisical credential strategies for the Infisical KMS adapter.

Three strategies are available:

    "universal_auth" — InfisicalUniversalAuthStrategy
                           Machine Identity client ID + client secret → access token.
                           Token is cached and refreshed 5 minutes before expiry.
                           Works with both Infisical Cloud and self-hosted instances.
    "token"          — InfisicalTokenStrategy
                           Static access token from OPTIONS or environment variable.
    "oidc"           — InfisicalOidcStrategy
                           Machine Identity OIDC auth — exchanges an OIDC JWT (from
                           any configured ``OidcTokenSource``) for an Infisical
                           access token via ``POST /api/v1/auth/oidc-auth/login``.

Each strategy's ``get_credentials()`` returns an Infisical access token string.

The ``oidc`` strategy delegates JWT acquisition to an injected
``OidcTokenSource`` (see ``adapters.credentials.oidc_sources``), so the same
strategy works on Fly.io, GCP, Vercel, self-hosted Kubernetes, SPIFFE, etc.

No extra Python packages are required — only ``urllib`` from the stdlib.
"""

from __future__ import annotations

import json
import os
import threading
import urllib.request
from datetime import UTC, datetime, timedelta

from ..._logging import get_logger
from ...exceptions import log_and_raise_configuration_error
from .._http import resolve_request_timeout, urlopen_with_detail
from .base import AbstractCredentialStrategy

logger = get_logger(__name__)


class InfisicalUniversalAuthStrategy(AbstractCredentialStrategy):
    """
    Authenticates to Infisical via Universal Auth (Machine Identity).

    Exchanges a client ID and client secret for an access token.  The token is
    cached until 5 minutes before its ``expiresIn`` expiry.  Calling
    ``invalidate()`` forces a re-exchange (used by the adapter's retry-on-401
    logic).

    Works with Infisical Cloud (``https://app.infisical.com``) and self-hosted
    instances.  Set ``INFISICAL_ENDPOINT`` for self-hosted deployments.

    Required options:
      INFISICAL_CLIENT_ID     : str  Machine Identity client ID
      INFISICAL_CLIENT_SECRET : str  Machine Identity client secret
    Optional options:
      INFISICAL_ENDPOINT      : str  (default: "https://app.infisical.com")
    """

    def __init__(self, options: dict, ssl_context=None) -> None:
        self._options = options
        self._ssl_context = ssl_context
        self._token: str | None = None
        self._expires_at: datetime | None = None
        self._lock = threading.Lock()

    def get_credentials(self) -> str:
        with self._lock:
            now = datetime.now(tz=UTC)
            if self._token and self._expires_at and self._expires_at > now + timedelta(minutes=5):
                return self._token
            logger.debug("Fetching an access token. method=universal_auth")
            self._token, self._expires_at = self._fetch_token()
            return self._token

    def invalidate(self) -> None:
        """Clear the cached token to force a re-exchange on the next call."""
        with self._lock:
            self._token = None
            self._expires_at = None

    def _fetch_token(self) -> tuple[str, datetime]:
        client_id = self._options.get("INFISICAL_CLIENT_ID") or os.environ.get("INFISICAL_CLIENT_ID")
        client_secret = self._options.get("INFISICAL_CLIENT_SECRET") or os.environ.get("INFISICAL_CLIENT_SECRET")
        if not client_id or not client_secret:
            log_and_raise_configuration_error(
                logger,
                "InfisicalUniversalAuthStrategy: INFISICAL_CLIENT_ID and "
                "INFISICAL_CLIENT_SECRET must be set in OPTIONS or environment.",
            )
        site_url = self._options.get("INFISICAL_ENDPOINT", "https://app.infisical.com").rstrip("/")
        url = f"{site_url}/api/v1/auth/universal-auth/login"
        body = json.dumps({"clientId": client_id, "clientSecret": client_secret}).encode()
        req = urllib.request.Request(
            url,
            data=body,
            headers={"Content-Type": "application/json", "Accept": "application/json"},
        )
        with urlopen_with_detail(
            req, timeout=resolve_request_timeout(self._options), context=self._ssl_context
        ) as resp:
            data = json.loads(resp.read())
        token: str = data["accessToken"]
        expires_in: int = int(data.get("expiresIn", 7776000))
        expires_at = datetime.now(tz=UTC) + timedelta(seconds=expires_in)
        return token, expires_at


class InfisicalTokenStrategy(AbstractCredentialStrategy):
    """
    Static Infisical access token from OPTIONS or the INFISICAL_TOKEN
    environment variable.

    The token is cached after the first retrieval.  If the token expires, the
    adapter will receive a 401 — static tokens cannot be automatically renewed.
    Call ``invalidate()`` to force a re-read from config / env.

    Required options (one of):
      INFISICAL_TOKEN : str  (OPTIONS or environment variable)
    """

    def __init__(self, options: dict) -> None:
        self._options = options
        self._token: str | None = None

    def get_credentials(self) -> str:
        if self._token:
            return self._token
        token = self._options.get("INFISICAL_TOKEN") or os.environ.get("INFISICAL_TOKEN")
        if not token:
            log_and_raise_configuration_error(
                logger, "InfisicalTokenStrategy: INFISICAL_TOKEN not found in OPTIONS or environment."
            )
        self._token = token
        return token

    def invalidate(self) -> None:
        """Clear the cached token so the next call re-reads from config / env."""
        self._token = None


class InfisicalOidcStrategy(AbstractCredentialStrategy):
    """
    Authenticates to Infisical via the Machine Identity OIDC auth method.

    Exchanges an OIDC JWT (from the injected ``OidcTokenSource``) for an
    Infisical access token via
    ``POST /api/v1/auth/oidc-auth/login``. The Infisical machine identity
    must be pre-configured with an OIDC auth method whose trusted audience
    matches ``INFISICAL_OIDC_AUDIENCE``.

    Token is cached until 5 minutes before expiry. ``invalidate()`` forces
    a re-exchange (used by the adapter's retry-on-401 logic).

    Required options:
      INFISICAL_IDENTITY_ID   : str  Machine Identity ID
    Optional options:
      INFISICAL_ENDPOINT      : str  (default: "https://app.infisical.com")
      INFISICAL_OIDC_AUDIENCE : str  ``aud`` claim requested from the OIDC
                                     source (default: INFISICAL_IDENTITY_ID)
    """

    def __init__(self, options: dict, token_source, ssl_context=None) -> None:
        self._options = options
        self._token_source = token_source
        self._ssl_context = ssl_context
        self._token: str | None = None
        self._expires_at: datetime | None = None
        self._lock = threading.Lock()

    def get_credentials(self) -> str:
        with self._lock:
            now = datetime.now(tz=UTC)
            if self._token and self._expires_at and self._expires_at > now + timedelta(minutes=5):
                return self._token
            logger.debug("Fetching an access token. method=oidc")
            self._token, self._expires_at = self._fetch_token()
            return self._token

    def invalidate(self) -> None:
        """Clear the cached token to force a re-exchange on the next call."""
        with self._lock:
            self._token = None
            self._expires_at = None

    def _fetch_token(self) -> tuple[str, datetime]:
        identity_id = self._options.get("INFISICAL_IDENTITY_ID") or os.environ.get("INFISICAL_IDENTITY_ID")
        if not identity_id:
            log_and_raise_configuration_error(
                logger, "InfisicalOidcStrategy: INFISICAL_IDENTITY_ID must be set in OPTIONS or environment."
            )
        site_url = self._options.get("INFISICAL_ENDPOINT", "https://app.infisical.com").rstrip("/")
        audience = self._options.get("INFISICAL_OIDC_AUDIENCE", identity_id)
        jwt = self._token_source.get_token(audience)

        url = f"{site_url}/api/v1/auth/oidc-auth/login"
        body = json.dumps({"identityId": identity_id, "jwt": jwt}).encode()
        req = urllib.request.Request(
            url,
            data=body,
            headers={"Content-Type": "application/json", "Accept": "application/json"},
        )
        with urlopen_with_detail(
            req, timeout=resolve_request_timeout(self._options), context=self._ssl_context
        ) as resp:
            data = json.loads(resp.read())
        token: str = data["accessToken"]
        expires_in: int = int(data.get("expiresIn", 7776000))
        expires_at = datetime.now(tz=UTC) + timedelta(seconds=expires_in)
        return token, expires_at
