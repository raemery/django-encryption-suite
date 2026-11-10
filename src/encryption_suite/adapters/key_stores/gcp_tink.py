"""
GCP Cloud KMS adapter using Tink's native ``gcpkms`` integration.

Alternative to ``GcpKmsAdapter`` — delegates crypto and auth entirely to
Tink's ``GcpKmsClient``, which uses Application Default Credentials (ADC).
There is no credential-strategy hook: run this adapter on GCP (e.g. Cloud
Run), where ADC resolves to the host's metadata-server credentials with no
auth config.  For keyless auth off GCP, use the ``GcpKmsAdapter`` with
``CREDENTIAL_STRATEGY="oidc"`` instead.

Requires the ``gcp-tink`` extra: ``pip install django-encryption-suite[gcp-tink]``
(the ``GcpKmsAdapter`` only needs ``gcp``; the Tink integration also
pulls in ``google-cloud-kms``).

Each silo gets its own Cloud KMS key within the configured key ring,
resolved via ``KEK_TEMPLATE`` or ``KEK_MAP`` in ``OPTIONS``.  The
template value is the key **name** only — project, location, and key ring
come from their own options.

Required OPTIONS keys:
  GCP_PROJECT_ID    : str   e.g. "my-project"
  GCP_KMS_LOCATION  : str   e.g. "global" or "us-central1"
  GCP_KMS_KEY_RING  : str
  KEK_TEMPLATE      : str   e.g. "encryption_suite-{silo_uid}"
                              (or KEK_MAP for explicit mapping)
"""

from __future__ import annotations

from ..._logging import get_logger
from .base import AbstractKmsAdapter, KmsMetadata

logger = get_logger(__name__)

_PROVIDER = "gcp-tink"


class GcpTinkKmsAdapter(AbstractKmsAdapter):
    """
    GCP Cloud KMS adapter backed by ``tink.integration.gcpkms``.

    Uses Tink's ``GcpKmsClient`` to obtain an ``Aead`` primitive for each
    KMS key.  Auth is handled by ADC.
    """

    kms_provider = _PROVIDER
    _INSTANCE_OPTION_KEYS = ("GCP_KMS_KEY_RING", "GCP_KMS_LOCATION", "GCP_PROJECT_ID")

    _HONORS_TLS_OPTIONS = False
    _TLS_SDK_HINT = (
        "Tink's GcpKmsClient uses the google-cloud-kms SDK over gRPC. To "
        "trust a private CA for Cloud KMS calls, set "
        "GRPC_DEFAULT_SSL_ROOTS_FILE_PATH=/path/to/ca-bundle.pem on the "
        "process (or SSL_CERT_FILE as an OpenSSL-level fallback)."
    )

    def __init__(self, options: dict, kek_strategy) -> None:
        super().__init__(options, kek_strategy)
        self._aeads: dict[str, object] = {}

    def _configured_ring(self) -> str:
        o = self.options
        return f"projects/{o['GCP_PROJECT_ID']}/locations/{o['GCP_KMS_LOCATION']}/keyRings/{o['GCP_KMS_KEY_RING']}"

    def _key_uri(self, key_name: str) -> str:
        return f"gcp-kms://{self._resource_name(key_name)}"

    def _resource_name(self, key_name: str) -> str:
        return f"{self._configured_ring()}/cryptoKeys/{key_name}"

    def canonical_kek_name(self, kek_id: str) -> str:
        # See GcpKmsAdapter.canonical_kek_name: keys are recorded as the full
        # resource path, so a bare name is qualified with the configured ring.
        if kek_id.startswith("projects/"):
            return kek_id
        return self._resource_name(kek_id)

    def kek_resource_mismatch_hint(self, stored_resource_name: str) -> str | None:
        # See GcpKmsAdapter.kek_resource_mismatch_hint: only a different project,
        # location, or key ring trips this; a rotated key in the same ring does not.
        configured = self._configured_ring()
        if stored_resource_name.startswith("projects/") and not stored_resource_name.startswith(configured + "/"):
            stored_ring = stored_resource_name.rsplit("/cryptoKeys/", 1)[0]
            return f"stored KEK is in '{stored_ring}', but this adapter is configured for '{configured}'"
        return None

    def _get_aead(self, key_name: str):
        if key_name in self._aeads:
            return self._aeads[key_name]
        try:
            from tink import aead
            from tink.integration import gcpkms
        except ImportError as exc:
            raise RuntimeError(
                "tink with GCP KMS integration is required for GcpTinkKmsAdapter. "
                "Install the 'gcp-tink' extra: pip install django-encryption-suite[gcp-tink]"
            ) from exc
        aead.register()
        uri = self._key_uri(key_name)
        client = gcpkms.GcpKmsClient(uri)  # credentials via ADC
        primitive = client.get_aead(uri)
        self._aeads[key_name] = primitive
        return primitive

    def encrypt_key(self, plaintext: bytes, silo_ref: str) -> tuple[bytes, KmsMetadata]:
        key_name = self._resolve_kek_id(silo_ref)
        ciphertext = self._get_aead(key_name).encrypt(plaintext, self._wrap_aad(silo_ref))
        return ciphertext, KmsMetadata(
            kek_resource_name=self._resource_name(key_name),
            kms_provider=_PROVIDER,
        )

    def decrypt_key(
        self,
        ciphertext: bytes,
        metadata: KmsMetadata,
        silo_ref: str,
    ) -> bytes:
        resource = metadata.kek_resource_name
        key_name = resource.rsplit("/cryptoKeys/", 1)[-1] if "/cryptoKeys/" in resource else resource
        return self._get_aead(key_name).decrypt(ciphertext, self._wrap_aad(silo_ref))

    def describe_kek(self) -> str:
        o = self.options
        ring = f"projects/{o['GCP_PROJECT_ID']}/locations/{o['GCP_KMS_LOCATION']}/keyRings/{o['GCP_KMS_KEY_RING']}"
        template = self.options.get("KEK_TEMPLATE", "")
        if template:
            return f"GCP Cloud KMS (Tink) keys: {ring}/cryptoKeys/{template}"
        return f"GCP Cloud KMS (Tink) key ring: {ring}"
