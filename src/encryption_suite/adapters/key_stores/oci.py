"""
Oracle Cloud Infrastructure (OCI) Vault KMS adapter.

Uses the OCI Key Management Cryptographic API (``KmsCryptoClient``) via the
official ``oci`` Python SDK.

Each silo gets its own OCI master encryption key, resolved via
``KEK_MAP`` in ``OPTIONS``.  Because OCI keys are identified by OCID
(not a human-readable name), ``KEK_MAP`` is the primary configuration method.
``KEK_TEMPLATE`` is also supported if you have a naming convention for OCIDs.

Credential strategy is selected via OPTIONS['CREDENTIAL_STRATEGY']:
  "api_key"            (default) — OciApiKeyStrategy  (inline env or config file)
  "instance_principal"            — OciInstancePrincipalStrategy (OCI Compute VM)
  "resource_principal"            — OciResourcePrincipalStrategy (Functions / Container Instances)
  "oke_workload_identity"         — OciOkeWorkloadIdentityStrategy (OKE Kubernetes pods)

See ``adapters.credentials.oci`` for strategy details and required options.

Requires the ``oci`` extra: ``pip install django-encryption-suite[oci]``

Required OPTIONS keys (all strategies):
  OCI_VAULT_CRYPTO_ENDPOINT : str  vault's cryptographic endpoint URL
  KEK_MAP                   : dict e.g. {"team-1": "ocid1.key.oc1..aaa", ...}
                                    (or KEK_TEMPLATE if OCIDs follow a pattern)
"""

from __future__ import annotations

import base64
import threading
import time

from django.core.exceptions import ImproperlyConfigured

from ..._logging import get_logger
from ...exceptions import log_and_raise_configuration_error
from ...silo_ref import silo_text
from ..credentials.oci import build_oci_credential_strategy, require_oci
from .base import AbstractKmsAdapter, KmsMetadata

logger = get_logger(__name__)

_PROVIDER = "oci"

# How long a process may keep reporting a key version it read earlier. Matches
# the GCP and Azure adapters so one KEY_VERSION_TTL_SECONDS means the same
# everywhere.
_DEFAULT_KEY_VERSION_TTL_SECONDS = 300.0

# Lifecycle states in which a key can be used or is becoming usable. Keys that
# are disabled or scheduled for deletion are ignored when resolving a name.
_USABLE_STATES = ("ENABLED", "CREATING", "UPDATING")


def _is_key_ocid(value: str) -> bool:
    """A KEK identifier in OCID form (KEK_MAP / SHARED_KEK_ID) is used directly;
    anything else is a display name (KEK_TEMPLATE) to be resolved to its OCID."""
    return value.startswith("ocid1.key.")


def _select_key_ocid(keys, display_name: str, compartment_id: str) -> str:
    """Pick the single key OCID for *display_name* from a ``list_keys`` result.

    Prefers an ENABLED key; accepts a CREATING/UPDATING one only if nothing is
    ENABLED yet (a key still settling after auto-provision). Raises if no usable
    key matches, or if the name maps to more than one distinct OCID — OCI does
    not enforce unique display names, so duplicates are an operator error the
    adapter must refuse rather than silently pick from.
    """
    matches = [k for k in keys if k.display_name == display_name and k.lifecycle_state in _USABLE_STATES]
    enabled = [k for k in matches if k.lifecycle_state == "ENABLED"]
    candidates = enabled or matches
    distinct = {k.id for k in candidates}
    if not distinct:
        raise ImproperlyConfigured(
            f"OCIVaultAdapter: no usable OCI key named '{display_name}' in "
            f"compartment {compartment_id}. Provision it (auto-provision via "
            "OciKekProvisioner, or outside this application) before encrypting."
        )
    if len(distinct) > 1:
        raise ImproperlyConfigured(
            f"OCIVaultAdapter: multiple distinct OCI keys named '{display_name}' "
            f"in compartment {compartment_id}. OCI does not enforce unique display "
            "names; remove or disable the duplicates so the name resolves to a "
            "single OCID, or address the key by OCID via KEK_MAP."
        )
    return distinct.pop()


class OCIVaultAdapter(AbstractKmsAdapter):
    """
    OCI Vault adapter using the OCI Key Management Cryptographic API.

    ``encrypt_key()`` calls ``KmsCryptoClient.encrypt()`` and ``decrypt_key()``
    calls ``KmsCryptoClient.decrypt()``.  The SDK handles request signing and
    automatic token refresh for instance/resource principal strategies.

    Requires the ``oci`` extra: ``pip install django-encryption-suite[oci]``
    """

    kms_provider = _PROVIDER
    _INSTANCE_OPTION_KEYS = ("OCI_VAULT_CRYPTO_ENDPOINT",)

    _HONORS_TLS_OPTIONS = False
    _TLS_SDK_HINT = (
        "The oci SDK manages its own trust store via the requests library. "
        "To trust a private CA for OCI Vault calls, set "
        "REQUESTS_CA_BUNDLE=/path/to/ca-bundle.pem on the process."
    )

    def __init__(self, options: dict, kek_strategy) -> None:
        super().__init__(options, kek_strategy)
        self._strategy = build_oci_credential_strategy(options)
        if not options.get("OCI_VAULT_CRYPTO_ENDPOINT"):
            log_and_raise_configuration_error(logger, "OCIVaultAdapter requires OCI_VAULT_CRYPTO_ENDPOINT in OPTIONS.")
        self._crypto_endpoint = options["OCI_VAULT_CRYPTO_ENDPOINT"].rstrip("/")
        # Management endpoint + compartment are only needed to resolve a
        # KEK_TEMPLATE display name to its OCID; OCID-addressed KEKs skip this.
        self._management_endpoint = (options.get("OCI_VAULT_MANAGEMENT_ENDPOINT") or "").rstrip("/")
        self._compartment_id = options.get("OCI_COMPARTMENT_OCID")
        self._client = None
        self._mgmt_client = None
        # Resolved display name -> OCID, populated once per process per name.
        self._name_to_ocid: dict[str, str] = {}
        self._name_lock = threading.Lock()
        # Key OCID -> (current version OCID, monotonic timestamp). Expires, so a
        # rotation reaches long-running workers.
        self._current_versions: dict[str, tuple[str, float]] = {}
        self._version_lock = threading.Lock()

    def _get_client(self):
        if self._client is not None:
            return self._client
        require_oci()
        from oci.key_management import KmsCryptoClient

        config, signer = self._strategy.get_credentials()
        if signer is not None:
            self._client = KmsCryptoClient(config, signer=signer, service_endpoint=self._crypto_endpoint)
        else:
            self._client = KmsCryptoClient(config, service_endpoint=self._crypto_endpoint)
        return self._client

    def _get_mgmt_client(self):
        if self._mgmt_client is not None:
            return self._mgmt_client
        if not self._management_endpoint or not self._compartment_id:
            raise ImproperlyConfigured(
                "OCIVaultAdapter needs OCI_VAULT_MANAGEMENT_ENDPOINT and "
                "OCI_COMPARTMENT_OCID in OPTIONS to resolve a KEK_TEMPLATE "
                "display name to its OCID. Set them, or address keys by OCID "
                "via KEK_MAP / SHARED_KEK_ID."
            )
        require_oci()
        from oci.key_management import KmsManagementClient

        config, signer = self._strategy.get_credentials()
        if signer is not None:
            self._mgmt_client = KmsManagementClient(config, signer=signer, service_endpoint=self._management_endpoint)
        else:
            self._mgmt_client = KmsManagementClient(config, service_endpoint=self._management_endpoint)
        return self._mgmt_client

    def _resolve_key_ocid(self, kek_id: str) -> str:
        """Map a strategy-resolved KEK identifier to a key OCID.

        OCID-form identifiers (KEK_MAP / SHARED_KEK_ID) are used as-is. A
        display name (KEK_TEMPLATE) is resolved to its OCID via a compartment
        ``list_keys`` lookup, cached per process. The cache only holds
        successful resolutions, so a not-yet-provisioned key is retried on the
        next call rather than negatively cached.
        """
        if _is_key_ocid(kek_id):
            return kek_id
        cached = self._name_to_ocid.get(kek_id)
        if cached:
            return cached
        with self._name_lock:
            cached = self._name_to_ocid.get(kek_id)
            if cached:
                return cached
            ocid = self._lookup_ocid_by_name(kek_id)
            self._name_to_ocid[kek_id] = ocid
            return ocid

    def _lookup_ocid_by_name(self, display_name: str) -> str:
        oci = require_oci()
        client = self._get_mgmt_client()
        keys = oci.pagination.list_call_get_all_results(client.list_keys, self._compartment_id).data
        return _select_key_ocid(keys, display_name, self._compartment_id)

    def canonical_kek_name(self, kek_id: str) -> str:
        """Record the identifier verbatim — the display name, not the OCID.

        Stated as an override because OCI is the provider where the tempting
        alternative fails. A key's OCID is assigned by the server, so it cannot
        be derived from the silo UID and, crucially, an *owner prefix* has no
        OCID at all: canonicalizing to OCIDs would leave the ownership gate
        comparing a display-name prefix against OCID-shaped names, matching
        nothing. That silently refuses every deletion and reports KMS-side
        reconcile as finding no keys.

        So display names are the name space every layer shares, and the OCID is
        resolved from one at the point of the crypto call. A ``KEK_MAP`` /
        ``SHARED_KEK_ID`` entry that is already an OCID is still recorded as
        itself, which those deployments can afford: they derive no owner prefix,
        so neither deletion nor reconcile is available to them anyway.
        """
        return kek_id

    @staticmethod
    def _associated_data(silo_ref: str) -> dict:
        """Return the OCI ``associated_data`` dict bound to a wrapped DEK.

        OCI's ``EncryptDataDetails.associated_data`` is a ``dict(str, str)`` of
        additional authenticated data, the OCI-native equivalent of the
        bytes-form AAD other adapters bind via
        :meth:`AbstractKmsAdapter._wrap_aad`. Binding the silo UID keeps
        the per-silo boundary at the KEK-wrap layer (confused-deputy
        protection) even under a shared KEK. Mirrors AWS ``EncryptionContext``;
        encrypt and decrypt must build the identical dict.
        """
        if not silo_text(silo_ref):
            raise ValueError("silo_ref must be a non-empty silo reference when binding OCI associated_data.")
        return {"silo_uid": silo_text(silo_ref), "purpose": "dek"}

    def encrypt_key(self, plaintext: bytes, silo_ref: str) -> tuple[bytes, KmsMetadata]:
        require_oci()
        from oci.key_management.models import EncryptDataDetails

        client = self._get_client()
        # _resolve_kek_id returns the strategy value (OCID or display name);
        # _resolve_key_ocid normalizes it to an OCID for the crypto call, which
        # is the only thing OCI's API accepts.
        kek_id = self._resolve_kek_id(silo_ref)
        key_ocid = self._resolve_key_ocid(kek_id)
        b64_plaintext = base64.b64encode(plaintext).decode()
        encrypt_details = EncryptDataDetails(
            key_id=key_ocid,
            plaintext=b64_plaintext,
            associated_data=self._associated_data(silo_ref),
        )
        response = client.encrypt(encrypt_details)
        ciphertext: str = response.data.ciphertext
        # OCI resolves the version from the ciphertext, so this is not needed to
        # decrypt — it is recorded because OCI bills per key version and lets a
        # single version be deleted. "Is anything still wrapped under version 1?"
        # is otherwise unanswerable without unwrapping every row. Absent on older
        # SDK responses, where it degrades to "" like any provider that reports
        # no version.
        key_version = getattr(response.data, "key_version_id", "") or ""
        # Recorded as the identifier, not the OCID it resolved to: the stored
        # name is what ownership, deletion and reconcile compare against, and
        # only the display name carries this deployment's owner prefix. See
        # canonical_kek_name. Decrypt resolves it back to an OCID, at the cost
        # of one cached compartment listing per name per process.
        return ciphertext.encode(), KmsMetadata(
            kek_resource_name=kek_id,
            kms_provider=_PROVIDER,
            kek_key_version=key_version,
        )

    def current_kek_version(self, silo_ref: str) -> str:
        """The key version a new wrap for *silo_ref* would use.

        Read from the key's ``current_key_version`` on the management endpoint,
        so ``reencrypt_keys`` can skip rows already wrapped under it instead of
        re-wrapping every row on every run. Cached briefly rather than for the
        process lifetime: rotation moves the current version, and a worker that
        never looked again would keep reporting the old one.

        Degrades to ``""`` on any failure. This is an optimization, and a broken
        probe must never skip real work — an empty answer re-wraps, which is
        always safe.
        """
        try:
            key_ocid = self._resolve_key_ocid(self._resolve_kek_id(silo_ref))
        except Exception:
            return ""
        ttl = float(self.options.get("KEY_VERSION_TTL_SECONDS", _DEFAULT_KEY_VERSION_TTL_SECONDS))
        cached = self._current_versions.get(key_ocid)
        if cached is not None and (time.monotonic() - cached[1]) < ttl:
            return cached[0]
        try:
            key = self._get_mgmt_client().get_key(key_ocid)
            version = getattr(key.data, "current_key_version", "") or ""
        except Exception:
            return ""
        with self._version_lock:
            self._current_versions[key_ocid] = (version, time.monotonic())
        return version

    def decrypt_key(
        self,
        ciphertext: bytes,
        metadata: KmsMetadata,
        silo_ref: str,
    ) -> bytes:
        require_oci()
        from oci.key_management.models import DecryptDataDetails

        client = self._get_client()
        ciphertext_str = ciphertext.decode()
        # The row records a display name (or, under KEK_MAP, an OCID already);
        # both forms go through the same resolver, which passes an OCID straight
        # through and caches a name lookup for the life of the process.
        decrypt_details = DecryptDataDetails(
            key_id=self._resolve_key_ocid(metadata.kek_resource_name),
            ciphertext=ciphertext_str,
            associated_data=self._associated_data(silo_ref),
        )
        response = client.decrypt(decrypt_details)
        return base64.b64decode(response.data.plaintext)

    def describe_kek(self) -> str:
        kek_map = self.options.get("KEK_MAP")
        if kek_map:
            return f"OCI Vault keys: {len(kek_map)} mapped keys @ {self._crypto_endpoint}"
        template = self.options.get("KEK_TEMPLATE")
        if template:
            return f"OCI Vault keys: template {template!r} @ {self._crypto_endpoint}"
        shared = self.options.get("SHARED_KEK_ID")
        if shared:
            return f"OCI Vault shared key {shared} @ {self._crypto_endpoint}"
        return f"OCI Vault @ {self._crypto_endpoint}"
