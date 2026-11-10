"""Shared HTTP-transport helpers for the urllib-based KMS adapters,
credential strategies, and KEK provisioners.

The SDK-backed adapters (AWS/boto3, Azure, OCI, Tink's AWS/GCP clients) manage
their own timeouts and retries, so this knob only governs the standard-library ``urllib``
request paths in this package.
"""

from __future__ import annotations

import urllib.error
import urllib.request
from importlib.metadata import PackageNotFoundError, version
from urllib.parse import urlparse

from .._logging import get_logger

logger = get_logger(__name__)

# Default per-request timeout (seconds) for urllib-based KMS / credential /
# provisioner HTTP calls when the options dict does not set KMS_REQUEST_TIMEOUT_SECONDS.
DEFAULT_KMS_REQUEST_TIMEOUT = 10


def _user_agent() -> str:
    try:
        return f"django-encryption-suite/{version('django-encryption-suite')}"
    except PackageNotFoundError:
        return "django-encryption-suite"


# Explicit User-Agent for every urllib request in this package. Some provider
# endpoints are fronted by a WAF (e.g. IBM Key Protect's regional endpoints sit
# behind Cloudflare) that blocks the standard library's default ``Python-urllib/x`` agent
# with an edge 403 (Cloudflare error 1010) before the request reaches the API.
# A named agent passes; it also makes this package's traffic identifiable in
# provider access logs.
_USER_AGENT = _user_agent()

# Cap on how much of an HTTP error response body is folded into the exception
# message, so a large HTML error page cannot flood the logs.
_MAX_HTTP_ERROR_DETAIL = 2000


def resolve_request_timeout(options: dict) -> float:
    """Return the configured HTTP request timeout for urllib-based KMS I/O.

    Read from ``KMS_REQUEST_TIMEOUT_SECONDS`` in the component's options dict
    (the KMS block's ``OPTIONS`` for adapters and credential strategies,
    ``KEK_PROVISIONER_OPTIONS`` for provisioners), falling back to
    :data:`DEFAULT_KMS_REQUEST_TIMEOUT`. Provider-neutral: every urllib-based
    component in this package honors the same key, so a deployment behind a
    slow or unreachable KMS can fail fast (or wait longer) uniformly.
    """
    value = options.get("KMS_REQUEST_TIMEOUT_SECONDS") if options else None
    if value is None:
        return DEFAULT_KMS_REQUEST_TIMEOUT
    return value


_LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})


def warn_if_plaintext_url(url, option_name: str, component_name: str) -> None:
    """Warn at construction if a configured KMS endpoint uses ``http://``.

    Called by every KMS adapter and KEK provisioner that takes its endpoint from
    an option. Everything the component exchanges with that endpoint crosses it:
    the credentials it authenticates with, the tokens it gets back, and the
    plaintext data encryption keys it sends to be wrapped and receives
    unwrapped. Over plaintext HTTP all of it is visible to anyone on the network
    path.

    A warning and not a refusal, because pointing at a sidecar proxy that
    terminates TLS is legitimate. A loopback host is not warned about at all.
    """
    try:
        parsed = urlparse(url)
    except (TypeError, ValueError, AttributeError):
        return
    if parsed.scheme != "http":
        return
    host = (parsed.hostname or "").lower()
    if host in _LOCAL_HOSTS:
        return
    logger.warning(
        "This option is configured with a plaintext http:// URL, so credentials, provider tokens "
        "and data encryption keys sent to it travel unencrypted; use https:// in production. "
        'component=%s option=%s url="%s"',
        component_name,
        option_name,
        url,
    )


def _read_error_body(exc: urllib.error.HTTPError) -> str:
    """Read an HTTPError response body once and normalize it to a log-safe line."""
    try:
        raw = exc.read()
    except Exception:
        return ""
    if not raw:
        return ""
    text = " ".join(raw.decode("utf-8", "replace").split())
    if len(text) > _MAX_HTTP_ERROR_DETAIL:
        text = text[:_MAX_HTTP_ERROR_DETAIL] + " …(truncated)"
    return text


def urlopen_with_detail(req, *, timeout, context=None):
    """``urllib.request.urlopen`` that folds the HTTP error response body into
    the raised ``HTTPError`` message.

    A bare ``urllib.error.HTTPError`` stringifies to just ``HTTP Error 403:
    Forbidden`` — the response body, where providers put the actionable detail
    (e.g. which IAM permission was denied on which resource), is otherwise
    discarded. This package logs these exceptions with ``%s`` and surfaces them
    in the admin test console, so reading the body once and appending it to the
    message makes those diagnostics as useful as the SDK-backed adapters'
    errors. Status-code branching (``exc.code``) is unaffected; only the
    message text is enriched.

    The body is consumed in the process, so a caller that needs to read the
    body itself should call ``urllib.request.urlopen`` directly instead.

    Sets this package's ``User-Agent`` unless the caller already set one, so
    requests are not blocked by WAFs that reject the standard library's default agent.
    """
    if not req.has_header("User-agent"):
        req.add_header("User-Agent", _USER_AGENT)
    try:
        return urllib.request.urlopen(req, timeout=timeout, context=context)
    except urllib.error.HTTPError as exc:
        detail = _read_error_body(exc)
        if detail:
            exc.msg = f"{exc.msg}: {detail}"
        raise
