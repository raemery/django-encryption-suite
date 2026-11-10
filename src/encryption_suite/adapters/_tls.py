"""Shared TLS context builder for adapters.

KMS adapters, credential strategies, and KEK provisioners each make HTTPS
calls and must honor the same ``TLS_CA_BUNDLE`` / ``TLS_EXTRA_CA`` options
so a private-CA configuration applies uniformly across encrypt/decrypt,
auth, and provisioning code paths.
"""

from __future__ import annotations

import os
import ssl

from .._internal import operator_error_text
from .._logging import get_logger
from ..exceptions import log_and_raise_configuration_error

logger = get_logger(__name__)


def build_ssl_context(options: dict) -> ssl.SSLContext:
    """Return an ``ssl.SSLContext`` honoring ``TLS_CA_BUNDLE`` / ``TLS_EXTRA_CA``.

    ``TLS_CA_BUNDLE``
        Path to a CA file or directory. **Replaces** the system trust store.

    ``TLS_EXTRA_CA``
        Path to a CA file or directory. **Adds to** the system trust store.

    If both are set, ``TLS_CA_BUNDLE`` wins. If neither is set the system
    default trust store is returned.

    Raises :class:`~encryption_suite.exceptions.EncryptionConfigurationError`
    at construction time if either option points to a path that does not
    exist, or to a file that cannot be read or parsed as CA certificates, so
    ``manage.py check`` reports it at deploy rather than an opaque
    ``ssl.SSLError`` surfacing on the first outbound handshake.
    """
    ca_bundle = options.get("TLS_CA_BUNDLE")
    extra_ca = options.get("TLS_EXTRA_CA")

    for option_name, path in (("TLS_CA_BUNDLE", ca_bundle), ("TLS_EXTRA_CA", extra_ca)):
        if path and not os.path.exists(path):
            log_and_raise_configuration_error(
                logger,
                f"{option_name} points to {path!r}, which does not exist. "
                "Set it to a readable CA certificate file or directory, or unset it.",
            )

    # A path that exists but cannot be read or parsed as certificates raises
    # ssl.SSLError (an OSError) or PermissionError here, at construction.
    option_name, path = ("TLS_CA_BUNDLE", ca_bundle) if ca_bundle else ("TLS_EXTRA_CA", extra_ca)
    try:
        if ca_bundle:
            if os.path.isdir(ca_bundle):
                return ssl.create_default_context(capath=ca_bundle)
            return ssl.create_default_context(cafile=ca_bundle)

        ctx = ssl.create_default_context()
        if extra_ca:
            if os.path.isdir(extra_ca):
                ctx.load_verify_locations(capath=extra_ca)
            else:
                ctx.load_verify_locations(cafile=extra_ca)
        return ctx
    except OSError as exc:
        log_and_raise_configuration_error(
            logger,
            f"{option_name} points to {path!r}, which could not be loaded as CA certificates: "
            f"{operator_error_text(exc)}. Set it to a readable PEM certificate file or directory, or unset it.",
            cause=exc,
        )
