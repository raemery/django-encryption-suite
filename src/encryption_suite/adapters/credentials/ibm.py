"""
IBM Cloud credential strategies for the IBM Key Protect / HPCS KMS adapter.

    "api_key"     — IbmApiKeyStrategy
                              IBM Cloud API key → IAM bearer token exchange.
                              Token is cached and refreshed 5 minutes before expiry.
    "iam_assume"  — IbmIamAssumeStrategy
                              IBM Cloud API key → IAM bearer token → assume a
                              trusted profile (two-step exchange). Lets a workload
                              running outside IBM compute (e.g. a Fly.io app) take
                              on a trusted-profile identity. Cached/refreshed like
                              ``api_key``.

    "container"   — IbmContainerStrategy
                              Trusted-profile auth via a compute-resource (CR)
                              token on IBM Code Engine / IKS. SDK-backed.
    "vpc_instance"— IbmVpcInstanceStrategy
                              Trusted-profile auth via the VPC instance metadata
                              service on an IBM VPC virtual server. SDK-backed.

Each strategy's ``get_credentials()`` returns an IAM bearer token string.

The "api_key" / "iam_assume" strategies are built in (use only the ``urllib`` standard library).
The compute-native "container" / "vpc_instance" strategies delegate to
``ibm-cloud-sdk-core`` and require the ``ibm`` extra
(``pip install django-encryption-suite[ibm]``); that SDK is imported only inside
those two classes, never at module top, so the built-in strategies never need it.
"""

from __future__ import annotations

import importlib.metadata
import json
import os
import threading
import urllib.error
import urllib.parse
import urllib.request
from datetime import UTC, datetime, timedelta

from ..._logging import get_logger
from ...exceptions import log_and_raise_configuration_error
from .._http import resolve_request_timeout, urlopen_with_detail
from .base import AbstractCredentialStrategy

logger = get_logger(__name__)

_IAM_TOKEN_URL = "https://iam.cloud.ibm.com/identity/token"


class IbmApiKeyStrategy(AbstractCredentialStrategy):
    """
    Exchanges an IBM Cloud API key for an IAM bearer token.

    The token is cached until 5 minutes before its ``expires_in`` expiry and
    refreshed transparently on the next ``get_credentials()`` call.  Calling
    ``invalidate()`` forces an immediate re-exchange on the next call (used by
    the adapter's retry-on-401 logic).

    Required options:
      IBM_API_KEY : str  IBM Cloud API key
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
            logger.debug("Exchanging an API key for an IAM bearer token.")
            self._token, self._expires_at = self._fetch_token()
            return self._token

    def invalidate(self) -> None:
        """Clear the cached token to force a re-exchange on the next call."""
        with self._lock:
            self._token = None
            self._expires_at = None

    def _fetch_token(self) -> tuple[str, datetime]:
        api_key = self._options.get("IBM_API_KEY") or os.environ.get("IBM_API_KEY")
        if not api_key:
            log_and_raise_configuration_error(
                logger, "IbmApiKeyStrategy: IBM_API_KEY not found in OPTIONS or environment."
            )
        body = urllib.parse.urlencode(
            {
                "grant_type": "urn:ibm:params:oauth:grant-type:apikey",
                "apikey": api_key,
            }
        ).encode()
        req = urllib.request.Request(
            _IAM_TOKEN_URL,
            data=body,
            headers={"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"},
        )
        with urlopen_with_detail(
            req, timeout=resolve_request_timeout(self._options), context=self._ssl_context
        ) as resp:
            data = json.loads(resp.read())
        token: str = data["access_token"]
        expires_in: int = int(data.get("expires_in", 3600))
        expires_at = datetime.now(tz=UTC) + timedelta(seconds=expires_in)
        return token, expires_at


# Maps each accepted option to the IAM "assume" request parameter it supplies.
# Exactly one must be set — IAM accepts only one trusted-profile selector.
_PROFILE_SELECTORS = {
    "IBM_TRUSTED_PROFILE_ID": "profile_id",
    "IBM_TRUSTED_PROFILE_CRN": "profile_crn",
    "IBM_TRUSTED_PROFILE_NAME": "profile_name",
}


class IbmIamAssumeStrategy(AbstractCredentialStrategy):
    """
    Exchanges an IBM Cloud API key for an IAM bearer token, then assumes a
    trusted profile (the IAM two-step "assume" flow).

    Step 1 reuses :class:`IbmApiKeyStrategy` to mint (and cache/refresh) the
    initial API-key token. Step 2 POSTs that token plus a trusted-profile
    selector to the IAM token endpoint with grant type
    ``urn:ibm:params:oauth:grant-type:assume`` and caches the resulting
    profile-scoped token until 5 minutes before its expiry.

    This works from anywhere — including non-IBM compute such as a Fly.io app —
    so it is the way to take on a trusted-profile identity without the
    ``container`` / ``vpc_instance`` strategies (which require running on IBM
    compute and the ``ibm`` extra). Built in.

    Required options:
      IBM_API_KEY : str  IBM Cloud API key
      Exactly one trusted-profile selector:
        IBM_TRUSTED_PROFILE_ID  : str  trusted profile ID (``Profile-...``)
        IBM_TRUSTED_PROFILE_CRN : str  trusted profile CRN
        IBM_TRUSTED_PROFILE_NAME: str  trusted profile name
    """

    def __init__(self, options: dict, ssl_context=None) -> None:
        self._options = options
        self._ssl_context = ssl_context
        # Step-1 token source — reuses the api-key exchange + its caching.
        self._api_key_strategy = IbmApiKeyStrategy(options, ssl_context=ssl_context)
        self._profile_param, self._profile_value = self._resolve_profile(options)
        self._token: str | None = None
        self._expires_at: datetime | None = None
        self._lock = threading.Lock()

    @staticmethod
    def _resolve_profile(options: dict) -> tuple[str, str]:
        present = {
            param: (options.get(opt) or os.environ.get(opt))
            for opt, param in _PROFILE_SELECTORS.items()
            if options.get(opt) or os.environ.get(opt)
        }
        if len(present) != 1:
            log_and_raise_configuration_error(
                logger,
                "IbmIamAssumeStrategy: set exactly one trusted-profile selector "
                f"({', '.join(_PROFILE_SELECTORS)}) in OPTIONS or the environment; "
                f"found {len(present)}.",
            )
        param, value = next(iter(present.items()))
        return param, value

    def get_credentials(self) -> str:
        with self._lock:
            now = datetime.now(tz=UTC)
            if self._token and self._expires_at and self._expires_at > now + timedelta(minutes=5):
                return self._token
            logger.debug("Assuming a trusted profile. profile_param=%s", self._profile_param)
            self._token, self._expires_at = self._assume(self._api_key_strategy.get_credentials())
            return self._token

    def invalidate(self) -> None:
        """Clear both the assumed token and the underlying api-key token."""
        with self._lock:
            self._token = None
            self._expires_at = None
        self._api_key_strategy.invalidate()

    def _assume(self, access_token: str) -> tuple[str, datetime]:
        body = urllib.parse.urlencode(
            {
                "grant_type": "urn:ibm:params:oauth:grant-type:assume",
                "access_token": access_token,
                self._profile_param: self._profile_value,
            }
        ).encode()
        req = urllib.request.Request(
            _IAM_TOKEN_URL,
            data=body,
            headers={"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"},
        )
        with urlopen_with_detail(
            req, timeout=resolve_request_timeout(self._options), context=self._ssl_context
        ) as resp:
            data = json.loads(resp.read())
        token: str = data["access_token"]
        expires_in: int = int(data.get("expires_in", 3600))
        expires_at = datetime.now(tz=UTC) + timedelta(seconds=expires_in)
        return token, expires_at


# ---------------------------------------------------------------------------
# Compute-native trusted-profile strategies ("container", "vpc_instance").
#
# These run only on IBM compute (Code Engine / IKS, or a VPC virtual server) and
# delegate the trusted-profile token exchange to ibm-cloud-sdk-core, which owns
# the fiddly CR-token / instance-metadata handshakes. The SDK is an OPTIONAL
# dependency: it is imported only inside these two classes (never at module top),
# so the built-in "api_key" / "iam_assume" strategies need no extra. Selecting
# "container" / "vpc_instance" without the extra raises a typed configuration
# error pointing at: pip install django-encryption-suite[ibm].
# ---------------------------------------------------------------------------


def _load_ibm_authenticator(class_name: str):
    """Import an ibm-cloud-sdk-core authenticator class, or raise a typed config error.

    Only the "container" / "vpc_instance" strategies call this; the import lives
    here (not at module top) so the built-in strategies never require the extra.
    """
    try:
        import ibm_cloud_sdk_core.authenticators as ibm_authenticators
    except ImportError as exc:
        log_and_raise_configuration_error(
            logger,
            f"ibm-cloud-sdk-core is required for the IBM trusted-profile strategy using "
            f"{class_name}. Install the 'ibm' extra: pip install django-encryption-suite[ibm]",
            cause=exc,
        )
    try:
        return getattr(ibm_authenticators, class_name)
    except AttributeError as exc:
        # The installed ibm-cloud-sdk-core does not expose this authenticator
        # (renamed/removed, or a version mismatch). Funnel it as a typed config
        # error rather than letting a raw AttributeError escape construction.
        try:
            version = importlib.metadata.version("ibm-cloud-sdk-core")
        except importlib.metadata.PackageNotFoundError:
            version = "unknown"
        log_and_raise_configuration_error(
            logger,
            f"ibm-cloud-sdk-core ({version}) does not provide the {class_name} authenticator. "
            f"Upgrade or pin a compatible ibm-cloud-sdk-core.",
            cause=exc,
        )


class _IbmSdkTrustedProfileStrategy(AbstractCredentialStrategy):
    """Base for the SDK-backed compute-native trusted-profile strategies.

    Construction validates options and builds the authenticator (no network I/O —
    the SDK defers the token/metadata call to the first ``get_token()``), so the
    deploy-time system check catches a missing extra or bad option. The SDK
    import is funnelled through :func:`_load_ibm_authenticator` and happens in
    both ``__init__`` (deploy-time guard) and ``get_credentials`` (runtime guard).
    """

    _sdk_class = ""  # subclass sets the ibm-cloud-sdk-core authenticator name

    def __init__(self, options: dict) -> None:
        self._options = options
        self._auth = None
        self._auth_kwargs = self._build_kwargs(options)
        self._ensure_authenticator()

    def _build_kwargs(self, options: dict) -> dict:
        raise NotImplementedError

    def _ensure_authenticator(self):
        if self._auth is None:
            cls = _load_ibm_authenticator(self._sdk_class)
            self._auth = cls(**self._auth_kwargs)
        return self._auth

    def get_credentials(self) -> str:
        return self._ensure_authenticator().token_manager.get_token()

    def invalidate(self) -> None:
        """Force a token refresh on the next call (best-effort; the SDK token
        manager exposes no public invalidate, so reset its cached state)."""
        if self._auth is None:
            return
        token_manager = getattr(self._auth, "token_manager", None)
        if token_manager is not None:
            token_manager.access_token = None
            token_manager.expire_time = 0
            token_manager.refresh_time = 0


class IbmContainerStrategy(_IbmSdkTrustedProfileStrategy):
    """Trusted-profile auth via a compute-resource (CR) token on IBM Code Engine
    or IKS. Requires the ``ibm`` extra: ``pip install django-encryption-suite[ibm]``.

    Required options (one of):
      IBM_TRUSTED_PROFILE_ID   : str  trusted profile ID (``Profile-...``)
      IBM_TRUSTED_PROFILE_NAME : str  trusted profile name
    Optional:
      IBM_CR_TOKEN_FILENAME    : str  CR-token path. The SDK default is the IKS
                                      path; on Code Engine set
                                      ``/var/run/secrets/codeengine.cloud.ibm.com/compute-resource-token/token``.
    """

    _sdk_class = "ContainerAuthenticator"

    def _build_kwargs(self, options: dict) -> dict:
        profile_id = options.get("IBM_TRUSTED_PROFILE_ID") or os.environ.get("IBM_TRUSTED_PROFILE_ID")
        profile_name = options.get("IBM_TRUSTED_PROFILE_NAME") or os.environ.get("IBM_TRUSTED_PROFILE_NAME")
        if not (profile_id or profile_name):
            log_and_raise_configuration_error(
                logger,
                "IbmContainerStrategy requires IBM_TRUSTED_PROFILE_ID or IBM_TRUSTED_PROFILE_NAME "
                "in OPTIONS or the environment.",
            )
        kwargs: dict = {}
        if profile_id:
            kwargs["iam_profile_id"] = profile_id
        else:
            kwargs["iam_profile_name"] = profile_name
        cr_token_filename = options.get("IBM_CR_TOKEN_FILENAME") or os.environ.get("IBM_CR_TOKEN_FILENAME")
        if cr_token_filename:
            kwargs["cr_token_filename"] = cr_token_filename
        return kwargs


class IbmVpcInstanceStrategy(_IbmSdkTrustedProfileStrategy):
    """Trusted-profile auth via the VPC instance metadata service on an IBM VPC
    virtual server. Requires the ``ibm`` extra: ``pip install django-encryption-suite[ibm]``.

    Optional options (at most one — otherwise the VSI's default linked profile):
      IBM_TRUSTED_PROFILE_ID  : str  trusted profile ID (``Profile-...``)
      IBM_TRUSTED_PROFILE_CRN : str  trusted profile CRN
    """

    _sdk_class = "VPCInstanceAuthenticator"

    def _build_kwargs(self, options: dict) -> dict:
        profile_id = options.get("IBM_TRUSTED_PROFILE_ID") or os.environ.get("IBM_TRUSTED_PROFILE_ID")
        profile_crn = options.get("IBM_TRUSTED_PROFILE_CRN") or os.environ.get("IBM_TRUSTED_PROFILE_CRN")
        if profile_id and profile_crn:
            log_and_raise_configuration_error(
                logger,
                "IbmVpcInstanceStrategy: set at most one of IBM_TRUSTED_PROFILE_ID or "
                "IBM_TRUSTED_PROFILE_CRN (omit both to use the VSI's default linked profile).",
            )
        kwargs: dict = {}
        if profile_id:
            kwargs["iam_profile_id"] = profile_id
        elif profile_crn:
            kwargs["iam_profile_crn"] = profile_crn
        return kwargs
