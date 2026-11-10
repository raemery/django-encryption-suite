"""
GCP credential strategies for the GCP Cloud KMS adapter.

Three strategies are available:

    "oidc"                 — GcpWorkloadIdentityStrategy
                                                     OIDC JWT (from any configured ``OidcTokenSource``)
                                                     → GCP STS token exchange → SA impersonation
                                                     → short-lived Cloud KMS token
    "adc"                  — GcpAdcStrategy
                                                     Application Default Credentials (local dev,
                                                     Cloud Run, GKE, Compute Engine)
    "service_account_key"  — GcpServiceAccountKeyStrategy
                                                     explicit SA JSON key file or inline JSON

Each strategy's ``get_credentials()`` returns a GCP bearer token string.
Tokens are cached until 60 seconds before expiry and refreshed automatically.

The ``oidc`` strategy delegates JWT acquisition to an injected
``OidcTokenSource`` (see ``adapters.credentials.oidc_sources``), so the same
strategy works on Fly.io, self-hosted Kubernetes, Vercel, SPIFFE, etc. —
whichever source is configured.
"""

from __future__ import annotations

import json
import threading
from datetime import UTC, datetime, timedelta

from ..._logging import get_logger
from ...exceptions import log_and_raise_configuration_error
from .._http import resolve_request_timeout, urlopen_with_detail
from .base import AbstractCredentialStrategy

logger = get_logger(__name__)


class _TokenCache:
    """Thread-safe short-lived GCP access token cache."""

    def __init__(self) -> None:
        self._token: str | None = None
        self._expires_at: datetime | None = None
        self._lock = threading.Lock()

    def get(self) -> str | None:
        with self._lock:
            if self._token and self._expires_at:
                if self._expires_at > datetime.now(tz=UTC) + timedelta(seconds=60):
                    return self._token
        return None

    def set(self, token: str, expires_at: datetime) -> None:
        with self._lock:
            self._token = token
            self._expires_at = expires_at

    def invalidate(self) -> None:
        with self._lock:
            self._token = None
            self._expires_at = None


class GcpWorkloadIdentityStrategy(AbstractCredentialStrategy):
    """
    Keyless authentication via OIDC JWT → GCP Workload Identity Federation.

    Flow:
      1. Fetch a signed OIDC JWT for the workload identity provider audience
         from the injected ``OidcTokenSource`` (Fly socket, file, Vercel,
         SPIFFE, ...).
      2. Exchange it with GCP STS for a federated access token.
      3. Impersonate the configured service account to get a short-lived
         Cloud KMS-scoped bearer token.

    The resulting token is cached until 60 seconds before expiry.

    Required options:
      GCP_PROJECT_NUMBER                  : str
      GCP_WORKLOAD_IDENTITY_POOL_ID       : str
      GCP_WORKLOAD_IDENTITY_PROVIDER_ID   : str
      GCP_SERVICE_ACCOUNT_EMAIL           : str
    """

    def __init__(self, options: dict, token_source, ssl_context=None) -> None:
        self._options = options
        self._token_source = token_source
        self._cache = _TokenCache()
        self._ssl_context = ssl_context

    def _provider_resource_name(self) -> str:
        o = self._options
        return (
            f"//iam.googleapis.com/projects/{o['GCP_PROJECT_NUMBER']}"
            f"/locations/global/workloadIdentityPools/{o['GCP_WORKLOAD_IDENTITY_POOL_ID']}"
            f"/providers/{o['GCP_WORKLOAD_IDENTITY_PROVIDER_ID']}"
        )

    def _exchange_for_federated_token(self, jwt: str) -> str:
        import urllib.parse
        import urllib.request

        payload = {
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "audience": self._provider_resource_name(),
            "scope": "https://www.googleapis.com/auth/cloud-platform",
            "requested_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "subject_token": jwt,
            "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
        }
        req = urllib.request.Request(
            "https://sts.googleapis.com/v1/token",
            data=urllib.parse.urlencode(payload).encode(),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        with urlopen_with_detail(req, timeout=resolve_request_timeout(self._options), context=self._ssl_context) as r:
            return json.loads(r.read())["access_token"]

    def _impersonate_sa(self, federated_token: str) -> tuple[str, datetime]:
        import urllib.request

        sa_email = self._options["GCP_SERVICE_ACCOUNT_EMAIL"]
        url = f"https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/{sa_email}:generateAccessToken"
        body = json.dumps({"scope": ["https://www.googleapis.com/auth/cloudkms"]}).encode()
        req = urllib.request.Request(
            url,
            data=body,
            headers={"Authorization": f"Bearer {federated_token}", "Content-Type": "application/json"},
        )
        with urlopen_with_detail(req, timeout=resolve_request_timeout(self._options), context=self._ssl_context) as r:
            result = json.loads(r.read())
        expires_at = datetime.fromisoformat(result["expireTime"].replace("Z", "+00:00"))
        return result["accessToken"], expires_at

    def get_credentials(self) -> str:
        cached = self._cache.get()
        if cached:
            return cached
        logger.debug("Refreshing the access token from an OIDC source.")

        jwt = self._token_source.get_token(self._provider_resource_name())
        federated = self._exchange_for_federated_token(jwt)
        token, expires_at = self._impersonate_sa(federated)
        self._cache.set(token, expires_at)
        return token


class GcpAdcStrategy(AbstractCredentialStrategy):
    """
    Application Default Credentials (ADC).

    Works on local workstations (after ``gcloud auth application-default login``),
    Cloud Run, GKE, and Compute Engine with Workload Identity.

    Requires the ``gcp`` extra: ``pip install django-encryption-suite[gcp]``
    """

    def __init__(self) -> None:
        self._cache = _TokenCache()

    def get_credentials(self) -> str:
        cached = self._cache.get()
        if cached:
            return cached
        try:
            import google.auth
            import google.auth.transport.requests
        except ImportError as exc:
            log_and_raise_configuration_error(
                logger,
                "google-auth is required for GcpAdcStrategy. "
                "Install the 'gcp' extra: pip install django-encryption-suite[gcp]",
                cause=exc,
            )
        logger.debug("Refreshing the access token from application default credentials.")
        creds, _ = google.auth.default(scopes=["https://www.googleapis.com/auth/cloudkms"])
        creds.refresh(google.auth.transport.requests.Request())
        now = datetime.now(tz=UTC)
        expiry = creds.expiry
        if expiry is None:
            expires_at = now + timedelta(hours=1)
        elif expiry.tzinfo is None:
            expires_at = expiry.replace(tzinfo=UTC)
        else:
            expires_at = expiry
        self._cache.set(creds.token, expires_at)
        return creds.token


class GcpServiceAccountKeyStrategy(AbstractCredentialStrategy):
    """
    Explicit service account key (JSON string or file path).

    Set ``SERVICE_ACCOUNT_KEY_JSON`` in OPTIONS to the raw JSON content,
    or ``SERVICE_ACCOUNT_KEY_FILE`` to a file path.

    Prefer keyless strategies in production; use this as a last resort.

    Requires the ``gcp`` extra: ``pip install django-encryption-suite[gcp]``
    """

    def __init__(self, options: dict) -> None:
        self._options = options
        self._cache = _TokenCache()

    def get_credentials(self) -> str:
        cached = self._cache.get()
        if cached:
            return cached
        try:
            import google.auth.transport.requests
            import google.oauth2.service_account
        except ImportError as exc:
            log_and_raise_configuration_error(
                logger,
                "google-auth is required for GcpServiceAccountKeyStrategy. Install django-encryption-suite[gcp].",
                cause=exc,
            )
        key_json = self._options.get("SERVICE_ACCOUNT_KEY_JSON")
        key_file = self._options.get("SERVICE_ACCOUNT_KEY_FILE")
        if key_json:
            info = json.loads(key_json)
            creds = google.oauth2.service_account.Credentials.from_service_account_info(
                info, scopes=["https://www.googleapis.com/auth/cloudkms"]
            )
        elif key_file:
            creds = google.oauth2.service_account.Credentials.from_service_account_file(
                key_file, scopes=["https://www.googleapis.com/auth/cloudkms"]
            )
        else:
            log_and_raise_configuration_error(
                logger,
                "GcpServiceAccountKeyStrategy requires either "
                "SERVICE_ACCOUNT_KEY_JSON or SERVICE_ACCOUNT_KEY_FILE in OPTIONS.",
            )
        creds.refresh(google.auth.transport.requests.Request())
        expiry = creds.expiry or (datetime.now(tz=UTC) + timedelta(hours=1))
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=UTC)
        self._cache.set(creds.token, expiry)
        return creds.token
