"""TLS_CA_BUNDLE / TLS_EXTRA_CA failures surface as configuration errors.

A bad CA path is a construction-time problem: it must reach ``manage.py check``
as an ``EncryptionConfigurationError`` carrying the operator detail, never as a
raw ``ssl.SSLError`` or ``ImproperlyConfigured`` traceback.
"""

from __future__ import annotations

import ssl

import pytest

from encryption_suite.adapters._tls import build_ssl_context
from encryption_suite.exceptions import EncryptionConfigurationError


@pytest.mark.parametrize("option", ["TLS_CA_BUNDLE", "TLS_EXTRA_CA"])
def test_a_missing_path_is_a_configuration_error(tmp_path, option):
    missing = tmp_path / "absent.pem"

    with pytest.raises(EncryptionConfigurationError) as exc_info:
        build_ssl_context({option: str(missing)})

    assert option in exc_info.value.detail
    assert "does not exist" in exc_info.value.detail


@pytest.mark.parametrize("option", ["TLS_CA_BUNDLE", "TLS_EXTRA_CA"])
def test_a_file_that_is_not_certificates_is_a_configuration_error(tmp_path, option):
    garbage = tmp_path / "not-a-cert.pem"
    garbage.write_text("this is not a certificate\n")

    with pytest.raises(EncryptionConfigurationError) as exc_info:
        build_ssl_context({option: str(garbage)})

    assert option in exc_info.value.detail
    assert "could not be loaded as CA certificates" in exc_info.value.detail
    assert isinstance(exc_info.value.__cause__, OSError)


def test_no_options_returns_the_default_context():
    assert isinstance(build_ssl_context({}), ssl.SSLContext)
