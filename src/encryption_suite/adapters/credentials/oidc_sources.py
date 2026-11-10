"""
OIDC token sources.

A token source produces a signed OIDC JWT for a requested ``audience`` and
hands it to a KMS-side credential strategy (``AwsOidcStrategy``,
``GcpWorkloadIdentityStrategy``, etc.) which exchanges it for provider
credentials. Splitting transport from exchange lets any source pair with any
provider — e.g. Fly→AWS, GCP→AWS, Vercel→GCP — without an N×M strategy
matrix.

Currently implemented:
  "fly"           — FlySocketTokenSource: POST to a Fly machine's local
                    Unix socket.
  "file"          — FileTokenSource: read a pre-issued JWT from a file path.
                    Covers Kubernetes projected SA tokens, AWS IRSA's
                    ``AWS_WEB_IDENTITY_TOKEN_FILE``, Azure Workload
                    Identity's ``AZURE_FEDERATED_TOKEN_FILE``, and Nomad
                    Workload Identity files. The audience is fixed by the
                    issuer at write time and cannot be re-requested per call.
  "gcp_metadata"  — GcpMetadataTokenSource: HTTP GET to the GCE/GKE
                    metadata server's identity endpoint. Returns an OIDC
                    JWT for the requested audience.
  "vercel"        — VercelTokenSource: read ``VERCEL_OIDC_TOKEN`` env var.
                    Vercel's audience is set via project configuration,
                    not at runtime — the ``audience`` argument is ignored.
  "spiffe"        — SpiffeTokenSource: SPIFFE Workload API JWT-SVID via
                    the optional ``py-spiffe`` package.
"""

from __future__ import annotations

from typing import Protocol

from ..._logging import get_logger
from ...exceptions import log_and_raise_configuration_error
from .._http import DEFAULT_KMS_REQUEST_TIMEOUT, urlopen_with_detail

logger = get_logger(__name__)


class OidcTokenSource(Protocol):
    def get_token(self, audience: str) -> str: ...


class FlySocketTokenSource:
    """
    Fetch a signed OIDC JWT from a Fly machine's local metadata socket.

    Fly machines expose a Unix socket at ``/.fly/api`` that issues signed
    OIDC JWTs for the machine's identity. ``socket_path`` and ``endpoint``
    are configurable mainly for testing; production deployments use the
    defaults.

    Every connect and read is bounded by ``timeout``. The credential
    strategies refresh under a lock, so a socket that never answers would
    otherwise hold that lock forever and stall every thread waiting on a KMS
    call. A timeout raises, the engine reports the key as unavailable, and the
    next request after ``DEK_FAILURE_CACHE_TTL`` asks the socket again.
    """

    def __init__(
        self,
        socket_path: str = "/.fly/api",
        endpoint: str = "/v1/tokens/oidc",
        timeout: float = DEFAULT_KMS_REQUEST_TIMEOUT,
    ) -> None:
        self._socket_path = socket_path
        self._endpoint = endpoint
        self._timeout = timeout

    def get_token(self, audience: str) -> str:
        import http.client
        import json
        import socket

        socket_path = self._socket_path

        class _UnixHTTP(http.client.HTTPConnection):
            def connect(self):
                self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                self.sock.settimeout(self.timeout)
                self.sock.connect(socket_path)

        conn = _UnixHTTP("localhost", timeout=self._timeout)
        try:
            body = json.dumps({"aud": audience}).encode()
            conn.request(
                "POST",
                self._endpoint,
                body=body,
                headers={"Content-Type": "application/json"},
            )
            resp = conn.getresponse()
            if resp.status != 200:
                raise RuntimeError(f"Fly OIDC socket returned HTTP {resp.status}")
            raw = resp.read().decode("utf-8").strip()
        finally:
            conn.close()

        # Fly returns the signed JWT directly as the response body (despite an
        # application/json content-type). Some API versions instead wrap it as
        # {"token": "..."}; accept both so a format change on either side does
        # not break authentication.
        if raw.startswith("{"):
            return json.loads(raw)["token"]
        return raw


class FileTokenSource:
    """
    Read a pre-issued OIDC JWT from a file path.

    The orchestrator (Kubernetes, AWS IRSA, Azure Workload Identity, Nomad,
    ...) writes the JWT to disk and the runtime reads it on demand. Because
    the file is pre-issued, the ``audience`` claim is fixed at write time
    and the ``audience`` argument here is ignored — callers must register
    the workload with their identity provider using the audience the
    consumer (AWS STS, GCP WIF, Vault JWT auth, ...) expects.

    The file is re-read on every ``get_token()`` call so that orchestrators
    that rotate the file (Kubernetes does this every ~hour) are picked up
    without restart.

    Security note:
        ``PATH`` MUST point at a location writable only by the orchestrator
        (root or the equivalent service account) — for example
        ``/var/run/secrets/...`` on Kubernetes, or paths under
        ``/run/`` / tmpfs on Linux. If an unprivileged process can write to
        the file or any directory on its path (including via symlink swap),
        it can substitute a forged JWT and impersonate the workload.
        Symlinks are deliberately followed because Kubernetes projected
        service account tokens rotate via atomic symlink swap.
    """

    def __init__(self, path: str) -> None:
        self._path = path

    def get_token(self, audience: str) -> str:
        with open(self._path, encoding="utf-8") as f:
            return f.read().strip()


class GcpMetadataTokenSource:
    """
    Fetch a signed OIDC JWT from the GCE/GKE metadata server.

    Calls
    ``GET http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/{sa}/identity?audience=...&format=full``
    with the required ``Metadata-Flavor: Google`` header. Use this on any
    GCP-hosted runtime (Compute Engine, GKE with Workload Identity,
    Cloud Run) when the *consumer* of the JWT is outside GCP — e.g.
    federating a GCP-hosted app to AWS KMS, Azure Key Vault, or Vault.

    For *GCP-to-GCP* auth, ``GcpAdcStrategy`` is the right choice instead.
    """

    def __init__(
        self,
        service_account: str = "default",
        host: str = "metadata.google.internal",
        format: str = "full",
        timeout: float = 10.0,
    ) -> None:
        self._service_account = service_account
        self._host = host
        self._format = format
        self._timeout = timeout

    def get_token(self, audience: str) -> str:
        import urllib.parse
        import urllib.request

        params = urllib.parse.urlencode({"audience": audience, "format": self._format})
        url = (
            f"http://{self._host}/computeMetadata/v1/instance/service-accounts/"
            f"{self._service_account}/identity?{params}"
        )
        req = urllib.request.Request(url, headers={"Metadata-Flavor": "Google"})
        with urlopen_with_detail(req, timeout=self._timeout) as resp:
            if resp.status != 200:
                raise RuntimeError(f"GCP metadata server returned HTTP {resp.status}")
            return resp.read().decode("utf-8").strip()


class VercelTokenSource:
    """
    Read a Vercel OIDC token from an environment variable.

    Vercel issues an OIDC JWT to each function invocation and exposes it
    via ``VERCEL_OIDC_TOKEN``. The token's ``aud`` claim is configured per
    project in the Vercel dashboard, not negotiated at runtime, so the
    ``audience`` argument here is ignored. Callers must align the consumer
    (AWS STS audience, GCP WIF provider audience, etc.) with whatever
    Vercel was configured to issue.
    """

    def __init__(self, env_var: str = "VERCEL_OIDC_TOKEN") -> None:
        self._env_var = env_var

    def get_token(self, audience: str) -> str:
        import os

        token = os.environ.get(self._env_var)
        if not token:
            log_and_raise_configuration_error(
                logger,
                f"VercelTokenSource: environment variable '{self._env_var}' is not set or is empty.",
            )
        return token


class SpiffeTokenSource:
    """
    Fetch a JWT-SVID from a SPIFFE Workload API endpoint.

    Requires the optional ``py-spiffe`` package, published on PyPI as
    ``spiffe`` (``pip install spiffe``). Connects to the Workload API socket — usually
    ``unix:///run/spire/agent.sock`` — and requests a JWT-SVID for the
    requested audience.
    """

    def __init__(self, socket_path: str | None = None) -> None:
        self._socket_path = socket_path

    def get_token(self, audience: str) -> str:
        try:
            from spiffe import JwtSource
        except ImportError as exc:
            log_and_raise_configuration_error(
                logger,
                "SpiffeTokenSource requires the py-spiffe package. Install it: pip install spiffe",
                cause=exc,
            )

        if self._socket_path:
            jwt_source = JwtSource(spiffe_socket_path=self._socket_path)
        else:
            jwt_source = JwtSource()
        try:
            svid = jwt_source.fetch_svid(audiences={audience})
            return svid.token
        finally:
            jwt_source.close()


def build_oidc_source(name: str, options: dict) -> OidcTokenSource:
    """
    Build an OIDC token source from a name + options dict.

    Source-specific options live under the ``OIDC_SOURCE_OPTIONS`` key in
    OPTIONS (or the equivalent provisioner options dict). Pass that
    sub-dict here.
    """
    if name == "fly":
        return FlySocketTokenSource(
            socket_path=options.get("SOCKET_PATH", "/.fly/api"),
            endpoint=options.get("ENDPOINT", "/v1/tokens/oidc"),
        )
    if name == "file":
        path = options.get("PATH")
        if not path:
            log_and_raise_configuration_error(logger, "OIDC_SOURCE='file' requires PATH in OIDC_SOURCE_OPTIONS.")
        return FileTokenSource(path=path)
    if name == "gcp_metadata":
        return GcpMetadataTokenSource(
            service_account=options.get("SERVICE_ACCOUNT", "default"),
            host=options.get("HOST", "metadata.google.internal"),
            format=options.get("FORMAT", "full"),
        )
    if name == "vercel":
        return VercelTokenSource(
            env_var=options.get("ENV_VAR", "VERCEL_OIDC_TOKEN"),
        )
    if name == "spiffe":
        return SpiffeTokenSource(
            socket_path=options.get("SOCKET_PATH"),
        )
    log_and_raise_configuration_error(
        logger,
        f"Unknown OIDC_SOURCE '{name}'. Valid options: fly, file, gcp_metadata, vercel, spiffe",
    )
