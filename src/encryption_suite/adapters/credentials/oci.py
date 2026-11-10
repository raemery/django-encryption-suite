"""
Oracle Cloud Infrastructure (OCI) credential strategies for the OCI Vault KMS adapter.

Three strategies are available:

    "api_key"            — OciApiKeyStrategy
                               Reads an OCI config file (~/.oci/config or a custom path).
                               Recommended for local development and CI/CD pipelines.
    "instance_principal" — OciInstancePrincipalStrategy
                               Dynamic credentials from the OCI instance metadata service.
                               Recommended for apps running on OCI Compute instances.
    "resource_principal" — OciResourcePrincipalStrategy
                               Dynamic credentials for OCI Functions and Container Instances.
    "oke_workload_identity" — OciOkeWorkloadIdentityStrategy
                               Dynamic credentials for pods on OCI Container Engine for
                               Kubernetes (OKE), derived from the pod's service account token.

Each strategy's ``get_credentials()`` returns a ``(config, signer)`` tuple:
  - ``api_key``:            ``(oci_config_dict, None)``
  - ``instance_principal``: ``({}, InstancePrincipalsSecurityTokenSigner)``
  - ``resource_principal``: ``({}, resource_principals_signer)``

The OCI Vault adapter uses whichever member of the tuple is non-None to
build an ``oci.key_management.KmsCryptoClient``.

Requires the ``oci`` extra: ``pip install django-encryption-suite[oci]``
"""

from __future__ import annotations

from ..._logging import get_logger
from ...exceptions import log_and_raise_configuration_error
from .base import AbstractCredentialStrategy

logger = get_logger(__name__)


def require_oci():
    """Import and return the ``oci`` SDK, or raise a clear typed error.

    The SDK is an optional extra, so every OCI code path (adapter, provisioner,
    credential strategies) funnels through here. A missing install is a
    configuration problem, so it raises :class:`EncryptionConfigurationError`
    — the engine surfaces that without a traceback and logs the actionable
    message, rather than the cause appearing as a bare ``No module named 'oci'``.
    """
    try:
        import oci

        return oci
    except ImportError as exc:
        log_and_raise_configuration_error(
            logger,
            "oci is required for the OCI Vault adapter/provisioner. Install the "
            "'oci' extra: pip install django-encryption-suite[oci]",
            cause=exc,
        )


class OciApiKeyStrategy(AbstractCredentialStrategy):
    """
    Builds an OCI API-key (signing-key) credential.

    Two sources are supported, checked in this order:

    1. **Inline** — credential fields supplied directly in options, including
       the private signing key as a PEM string. No file on disk. This is the
       method for hosts *outside* OCI that have no ``~/.oci/config`` (PaaS such
       as Fly/Heroku/Render, CI runners, containers). Mirrors the inline path
       GCP's ``service_account_key`` strategy offers via ``SERVICE_ACCOUNT_KEY_JSON``.
    2. **Config file** — the standard ``oci.config.from_file`` flow. Best for
       local development and any host that already has ``~/.oci/config``.

    Requires the ``oci`` extra: ``pip install django-encryption-suite[oci]``

    Inline options (all required together to select the inline path):
      OCI_TENANCY_OCID        : str  tenancy OCID
      OCI_USER_OCID           : str  user OCID the signing key belongs to
      OCI_FINGERPRINT         : str  the uploaded public key's fingerprint
      OCI_REGION              : str  region identifier, e.g. "ca-toronto-1"
      OCI_PRIVATE_KEY_CONTENT : str  PEM private key (full text, with newlines)
    Optional inline option:
      OCI_PRIVATE_KEY_PASSPHRASE : str  passphrase if the PEM is encrypted

    Config-file options (used when no inline fields are present):
      OCI_CONFIG_FILE    : str  path to OCI config file (default: "~/.oci/config")
      OCI_CONFIG_PROFILE : str  profile name (default: "DEFAULT")
    """

    # Inline credential fields. Presence of any one selects the inline path,
    # so a partial set fails loudly rather than silently falling back to a
    # config file the operator did not intend to use.
    _INLINE_REQUIRED = (
        "OCI_TENANCY_OCID",
        "OCI_USER_OCID",
        "OCI_FINGERPRINT",
        "OCI_REGION",
        "OCI_PRIVATE_KEY_CONTENT",
    )

    def __init__(self, options: dict) -> None:
        self._options = options

    def _inline_requested(self) -> bool:
        return any(self._options.get(k) for k in self._INLINE_REQUIRED)

    def get_credentials(self) -> tuple:
        try:
            import oci
        except ImportError as exc:
            log_and_raise_configuration_error(
                logger,
                "oci is required for OciApiKeyStrategy. Install the 'oci' extra: "
                "pip install django-encryption-suite[oci]",
                cause=exc,
            )

        if self._inline_requested():
            return self._inline_config(), None

        config_file = self._options.get("OCI_CONFIG_FILE", oci.config.DEFAULT_LOCATION)
        profile = self._options.get("OCI_CONFIG_PROFILE", oci.config.DEFAULT_PROFILE)
        config = oci.config.from_file(file_location=config_file, profile_name=profile)
        oci.config.validate_config(config)
        return config, None

    def _inline_config(self) -> dict:
        missing = [k for k in self._INLINE_REQUIRED if not self._options.get(k)]
        if missing:
            log_and_raise_configuration_error(
                logger,
                "OciApiKeyStrategy inline credentials are incomplete. Missing: "
                f"{', '.join(missing)}. Supply all of {', '.join(self._INLINE_REQUIRED)} "
                "in OPTIONS, or omit them all to read ~/.oci/config instead.",
            )
        # The OCI SDK builds its Signer from a config dict, accepting the
        # private key inline via "key_content" (PEM string) in place of the
        # "key_file" path. We validate required fields above rather than calling
        # oci.config.validate_config, which is oriented at the file path form.
        config = {
            "tenancy": self._options["OCI_TENANCY_OCID"],
            "user": self._options["OCI_USER_OCID"],
            "fingerprint": self._options["OCI_FINGERPRINT"],
            "region": self._options["OCI_REGION"],
            "key_content": self._options["OCI_PRIVATE_KEY_CONTENT"],
        }
        passphrase = self._options.get("OCI_PRIVATE_KEY_PASSPHRASE")
        if passphrase:
            config["pass_phrase"] = passphrase
        return config


class OciInstancePrincipalStrategy(AbstractCredentialStrategy):
    """
    Dynamic credentials from the OCI Instance Metadata Service (IMDS).

    Recommended for Django apps running on OCI Compute instances.  The signer
    automatically refreshes its security token before expiry.

    Requires the ``oci`` extra: ``pip install django-encryption-suite[oci]``
    """

    def get_credentials(self) -> tuple:
        try:
            from oci.auth.signers import InstancePrincipalsSecurityTokenSigner
        except ImportError as exc:
            log_and_raise_configuration_error(
                logger,
                "oci is required for OciInstancePrincipalStrategy. "
                "Install the 'oci' extra: pip install django-encryption-suite[oci]",
                cause=exc,
            )
        signer = InstancePrincipalsSecurityTokenSigner()
        return {}, signer


class OciResourcePrincipalStrategy(AbstractCredentialStrategy):
    """
    Dynamic credentials for OCI Functions and Container Instances.

    Uses the resource principal signer, which reads credentials injected by
    the OCI runtime environment.

    Requires the ``oci`` extra: ``pip install django-encryption-suite[oci]``
    """

    def get_credentials(self) -> tuple:
        try:
            from oci.auth.signers import get_resource_principals_signer
        except ImportError as exc:
            log_and_raise_configuration_error(
                logger,
                "oci is required for OciResourcePrincipalStrategy. "
                "Install the 'oci' extra: pip install django-encryption-suite[oci]",
                cause=exc,
            )
        signer = get_resource_principals_signer()
        return {}, signer


class OciOkeWorkloadIdentityStrategy(AbstractCredentialStrategy):
    """
    Dynamic credentials for pods on OCI Container Engine for Kubernetes (OKE).

    An OKE pod authenticates with the OKE Workload Identity signer, which
    exchanges the pod's Kubernetes service account token for a resource
    principal. This is distinct from ``resource_principal``: that signer reads
    credentials injected by the Functions / Container Instances runtime, which
    does not exist inside an OKE pod. Grant access with an OKE workload policy
    that maps the pod's namespace + service account to a dynamic group.

    Requires the ``oci`` extra: ``pip install django-encryption-suite[oci]``

    Optional options:
      OCI_OKE_SA_TOKEN_PATH : str  service account token path
                                   (default: the SDK's
                                   /var/run/secrets/kubernetes.io/serviceaccount/token)
      OCI_OKE_SA_TOKEN      : str  the service account token itself, passed
                                   directly instead of read from a path
    """

    def __init__(self, options: dict | None = None) -> None:
        self._options = options or {}

    def get_credentials(self) -> tuple:
        try:
            from oci.auth.signers import get_oke_workload_identity_resource_principal_signer
        except ImportError as exc:
            log_and_raise_configuration_error(
                logger,
                "oci is required for OciOkeWorkloadIdentityStrategy. "
                "Install the 'oci' extra: pip install django-encryption-suite[oci]",
                cause=exc,
            )
        kwargs = {}
        token_path = self._options.get("OCI_OKE_SA_TOKEN_PATH")
        if token_path:
            kwargs["service_account_token_path"] = token_path
        token = self._options.get("OCI_OKE_SA_TOKEN")
        if token:
            kwargs["service_account_token"] = token
        signer = get_oke_workload_identity_resource_principal_signer(**kwargs)
        return {}, signer


def build_oci_credential_strategy(options: dict) -> AbstractCredentialStrategy:
    """
    Select an OCI credential strategy from ``options['CREDENTIAL_STRATEGY']``.

    Shared by the KMS adapter (encrypt/decrypt against the crypto endpoint) and
    the KEK provisioner (create/list against the management endpoint), so both
    authenticate the same way from one option set.
    """
    name = options.get("CREDENTIAL_STRATEGY", "api_key")
    if name == "api_key":
        return OciApiKeyStrategy(options)
    if name == "instance_principal":
        return OciInstancePrincipalStrategy()
    if name == "resource_principal":
        return OciResourcePrincipalStrategy()
    if name == "oke_workload_identity":
        return OciOkeWorkloadIdentityStrategy(options)
    log_and_raise_configuration_error(
        logger,
        f"Unknown CREDENTIAL_STRATEGY '{name}'. Valid options: "
        "api_key, instance_principal, resource_principal, oke_workload_identity",
    )
