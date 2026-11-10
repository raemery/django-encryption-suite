"""Abstract base for credential strategies."""

from __future__ import annotations

from abc import ABC, abstractmethod


class AbstractCredentialStrategy(ABC):
    """
    Provides authentication credentials to a KMS adapter.

    Implementations are responsible for fetching, caching, and refreshing
    credentials.  The return type of ``get_credentials`` is provider-specific
    (e.g. a bearer token string, a boto3 Session, an azure credential object).
    """

    @abstractmethod
    def get_credentials(self) -> object:
        """Return provider-specific credentials."""
