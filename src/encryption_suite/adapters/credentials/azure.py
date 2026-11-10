"""
Azure credential strategies for the Azure Key Vault KMS adapter.

Three strategies are available:

    "managed_identity"  — AzureManagedIdentityStrategy
                                                DefaultAzureCredential (Managed Identity,
                                                environment variables, CLI, etc.)
    "client_secret"     — AzureClientSecretStrategy
                                                explicit client ID + secret
    "oidc"              — AzureWorkloadIdentityFederationStrategy
                                                OIDC JWT (from any configured
                                                ``OidcTokenSource``) → Azure AD federated
                                                credential (Workload Identity Federation)

Each strategy's ``get_credentials()`` returns an azure-identity credential
object compatible with ``azure-keyvault-keys``.

The ``oidc`` strategy delegates JWT acquisition to an injected
``OidcTokenSource`` (see ``adapters.credentials.oidc_sources``), so the same
strategy works on Fly.io, GCP, Vercel, self-hosted Kubernetes, SPIFFE, etc.

Requires the ``azure`` extra: ``pip install django-encryption-suite[azure]``
"""

from __future__ import annotations

from ..._logging import get_logger
from ...exceptions import log_and_raise_configuration_error
from .base import AbstractCredentialStrategy

logger = get_logger(__name__)


class AzureManagedIdentityStrategy(AbstractCredentialStrategy):
    """
    Uses ``DefaultAzureCredential`` from the Azure SDK.

    Automatically tries Managed Identity, environment variables, Azure CLI,
    and other credential sources in order.  The recommended strategy for
    Azure-hosted deployments.

    Requires the ``azure`` extra: ``pip install django-encryption-suite[azure]``
    """

    def get_credentials(self):
        try:
            from azure.identity import DefaultAzureCredential
        except ImportError as exc:
            log_and_raise_configuration_error(
                logger,
                "azure-identity is required for AzureManagedIdentityStrategy. Install django-encryption-suite[azure].",
                cause=exc,
            )
        return DefaultAzureCredential()


class AzureClientSecretStrategy(AbstractCredentialStrategy):
    """
    Explicit Azure AD client ID + secret.

    Use when Managed Identity is not available.  Note that the secret is
    static — rotation requires a settings change and redeploy.

    Required options:
      AZURE_TENANT_ID      : str
      AZURE_CLIENT_ID      : str
      AZURE_CLIENT_SECRET  : str

    Requires the ``azure`` extra: ``pip install django-encryption-suite[azure]``
    """

    def __init__(self, options: dict) -> None:
        self._options = options

    def get_credentials(self):
        try:
            from azure.identity import ClientSecretCredential
        except ImportError as exc:
            log_and_raise_configuration_error(
                logger,
                "azure-identity is required for AzureClientSecretStrategy. Install django-encryption-suite[azure].",
                cause=exc,
            )
        return ClientSecretCredential(
            tenant_id=self._options["AZURE_TENANT_ID"],
            client_id=self._options["AZURE_CLIENT_ID"],
            client_secret=self._options["AZURE_CLIENT_SECRET"],
        )


class AzureWorkloadIdentityFederationStrategy(AbstractCredentialStrategy):
    """
    Keyless authentication via OIDC JWT → Azure AD Workload Identity Federation.

    The Azure AD app registration must have a federated credential configured
    that trusts the issuer/subject/audience of the JWT produced by the token
    source (see Microsoft docs: "Configure a federated identity credential").

    Flow (handled by ``ClientAssertionCredential``):
      1. Fetch a signed OIDC JWT from the injected ``OidcTokenSource``.
      2. POST it to Azure AD as a ``client_assertion`` with
         ``client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer``.
      3. Receive a short-lived AAD bearer token, scoped per Key Vault request.

    Required options:
      AZURE_TENANT_ID         : str
      AZURE_CLIENT_ID         : str
    Optional options:
      AZURE_OIDC_AUDIENCE     : str  (default: "api://AzureADTokenExchange",
                                      the audience Azure AD expects for federated
                                      credentials)

    Requires the ``azure`` extra: ``pip install django-encryption-suite[azure]``
    """

    def __init__(self, options: dict, token_source) -> None:
        self._options = options
        self._token_source = token_source

    def get_credentials(self):
        try:
            from azure.identity import ClientAssertionCredential
        except ImportError as exc:
            log_and_raise_configuration_error(
                logger,
                "azure-identity is required for "
                "AzureWorkloadIdentityFederationStrategy. "
                "Install django-encryption-suite[azure].",
                cause=exc,
            )

        audience = self._options.get("AZURE_OIDC_AUDIENCE", "api://AzureADTokenExchange")
        token_source = self._token_source

        def _fetch_assertion() -> str:
            return token_source.get_token(audience)

        return ClientAssertionCredential(
            tenant_id=self._options["AZURE_TENANT_ID"],
            client_id=self._options["AZURE_CLIENT_ID"],
            func=_fetch_assertion,
        )
