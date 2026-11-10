"""A configured ``http://`` KMS endpoint is warned about wherever one can be set."""

from __future__ import annotations

import logging

import pytest

from encryption_suite.adapters._http import warn_if_plaintext_url
from encryption_suite.adapters.keks.provisioners_fly import FlyKmsKekProvisioner
from encryption_suite.adapters.keks.provisioners_hashicorp import HashiCorpVaultKekProvisioner
from encryption_suite.adapters.keks.strategies import PerSiloKekStrategy
from encryption_suite.adapters.key_stores.hashicorp import HashiCorpVaultAdapter

_LOGGER = "encryption_suite.adapters._http"


def _warnings(caplog) -> list[str]:
    return [record.getMessage() for record in caplog.records if record.levelno == logging.WARNING]


class TestWarnIfPlaintextUrl:
    def test_warns_on_http(self, caplog):
        with caplog.at_level(logging.WARNING, logger=_LOGGER):
            warn_if_plaintext_url("http://vault.internal:8200", "VAULT_ENDPOINT", "SomeAdapter")
        (line,) = _warnings(caplog)
        assert "data encryption keys" in line
        assert "component=SomeAdapter option=VAULT_ENDPOINT" in line

    @pytest.mark.parametrize(
        "url",
        [
            "https://vault.example.com:8200",
            "http://localhost:8200",
            "http://127.0.0.1:8200",
            "http://[::1]:8200",
            "",
            None,
        ],
    )
    def test_silent_on_https_loopback_and_unparseable(self, caplog, url):
        with caplog.at_level(logging.WARNING, logger=_LOGGER):
            warn_if_plaintext_url(url, "VAULT_ENDPOINT", "SomeAdapter")
        assert _warnings(caplog) == []


class TestComponentsWarn:
    def test_vault_adapter_with_the_default_token_strategy(self, caplog):
        opts = {"VAULT_ENDPOINT": "http://vault.internal:8200", "VAULT_TOKEN": "t", "KEK_TEMPLATE": "k-{silo_uid}"}
        with caplog.at_level(logging.WARNING, logger=_LOGGER):
            HashiCorpVaultAdapter(opts, PerSiloKekStrategy(opts))
        (line,) = _warnings(caplog)
        assert "component=HashiCorpVaultAdapter option=VAULT_ENDPOINT" in line

    def test_vault_provisioner(self, caplog):
        opts = {"VAULT_ENDPOINT": "http://vault.internal:8200", "VAULT_TOKEN": "hvs.test"}
        with caplog.at_level(logging.WARNING, logger=_LOGGER):
            HashiCorpVaultKekProvisioner(opts)
        (line,) = _warnings(caplog)
        assert "component=HashiCorpVaultKekProvisioner option=VAULT_ENDPOINT" in line

    def test_fly_provisioner(self, caplog):
        opts = {"FLY_APP_NAME": "test-app", "FLY_API_TOKEN": "t", "FLY_API_ENDPOINT": "http://proxy.internal"}
        with caplog.at_level(logging.WARNING, logger=_LOGGER):
            FlyKmsKekProvisioner(opts)
        (line,) = _warnings(caplog)
        assert "component=FlyKmsKekProvisioner option=FLY_API_ENDPOINT" in line
