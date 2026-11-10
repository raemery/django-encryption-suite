"""Base interfaces for KMS adapters."""

from __future__ import annotations

import ssl
import threading
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from ..._logging import get_logger
from ...exceptions import log_and_raise_configuration_error
from ...silo_ref import silo_text
from .._http import resolve_request_timeout
from .._tls import build_ssl_context
from ..keks.base import AbstractKekStrategyAdapter
from ..keks.sanitization import ALNUM_UNDERSCORE_HYPHEN

logger = get_logger(__name__)


@dataclass
class KmsMetadata:
    """
    Metadata attached to an encrypted keyset record.

    Returned by :meth:`AbstractKmsAdapter.encrypt_key` and passed back to
    :meth:`AbstractKmsAdapter.decrypt_key` so the adapter knows which KEK was used.
    """

    kek_resource_name: str
    kms_provider: str
    #: The KMS name (a ``KMS_KEY_STORES`` block, or ``"system"``) the wrap went
    #: through, recorded on the key encryption key row. Stamped by the engine,
    #: which knows the name it routed by; an adapter leaves it empty.
    kms_name: str = ""
    #: Provider version identifier of the key material used, recorded on the data
    #: encryption key's row. Load-bearing where the ciphertext names no version
    #: and the provider needs it to unwrap; informational elsewhere, making "is
    #: anything still on the retired version?" a query rather than a mass unwrap.
    #: Empty for providers that expose no version identity.
    kek_key_version: str = ""
    extra: dict = field(default_factory=dict)


class AbstractKmsAdapter(ABC):
    """
    Interface for wrapping and unwrapping DEK bytes via an external KMS.

    KEK resolution is delegated to a
    :class:`~encryption_suite.adapters.keks.base.AbstractKekStrategyAdapter`
    injected at construction time.  The KMS adapter does not care *how* a
    silo UID maps to a KEK identifier — only that the strategy returns
    one.  See :mod:`encryption_suite.adapters.keks` for built-in strategies
    (per-silo, shared) and for the interface to implement custom
    policies such as composite-aware or BYOK resolution.
    """

    # Default cooldown period (in seconds) after a retry with fresh credentials
    # also fails.  During the cooldown, auth-error retries are skipped and the
    # original error is raised immediately.  This prevents hammering the KMS
    # with requests that will fail, which could lead to rate-limiting or
    # account lockout.
    AUTH_RETRY_COOLDOWN: int = 30

    # Provider identifier written into ``KmsMetadata.kms_provider`` at wrap time.
    # Names the kind of KMS; which configured KMS a row belongs to is
    # ``kms_name``. Each concrete adapter sets this to its module-level
    # ``_PROVIDER`` constant.
    kms_provider: str = ""

    # The KMS name this instance was built under — a ``KMS_KEY_STORES`` block, or
    # ``"system"`` — set by the registry after construction. Recorded on every
    # key encryption key row this adapter wraps for, and the name an unwrap of
    # such a row routes back to.
    kms_name: str = ""

    # SDK-backed adapters set this to False and provide ``_TLS_SDK_HINT``
    # so that operators who set ``TLS_CA_BUNDLE`` / ``TLS_EXTRA_CA`` in
    # ``OPTIONS`` get a clear startup error pointing at the SDK-native
    # environment variable instead of a silent handshake failure later.
    _HONORS_TLS_OPTIONS: bool = True
    _TLS_SDK_HINT: str = ""

    # Prefix for the canonical bytes-form AAD bound to wrapped DEKs. Subclasses
    # may override to introduce a custom domain separator (e.g. for deployments
    # that share a KEK pool across multiple django-encryption-suite installations).
    # The full AAD is ``_AAD_PREFIX + silo_ref.encode("utf-8")``.
    _AAD_PREFIX: bytes = b"django-encryption-suite:dek:"

    # UID sanitization for KMS key names. Adapters define the charset allowed
    # by their KMS provider; the strategy is built with these via
    # :meth:`build_strategy` so its sanitizer matches the provider's rules.
    # ``_UID_MAX_LENGTH`` is the maximum length of a sanitized UID accepted by
    # the provider's key-naming rules; ``None`` means no enforced cap.
    _UID_ALLOWED_CHARS: frozenset[str] = ALNUM_UNDERSCORE_HYPHEN
    _UID_ESCAPE_CHAR: str = "_"
    _UID_MAX_LENGTH: int | None = None

    # OPTIONS keys that identify the specific KMS instance/vault/region this
    # adapter targets (e.g. the vault URL, key ring, or region). Joined for
    # display in the admin test console — analogous to a storage backend's
    # location. Empty when the provider has no distinct instance (e.g. system).
    _INSTANCE_OPTION_KEYS: tuple[str, ...] = ()

    def __init__(
        self,
        options: dict,
        kek_strategy: AbstractKekStrategyAdapter,
    ) -> None:
        self.options = options
        self._reject_unhonored_tls_options(options)
        self._ssl_context = self._build_ssl_context(options)
        # HTTP request timeout (seconds) for the urllib-based adapters. SDK-
        # backed adapters ignore it and use their own transport defaults.
        self._request_timeout = resolve_request_timeout(options)
        self._auth_retry_blocked_until: float = 0.0
        self._auth_retry_lock = threading.Lock()
        self._kek_strategy = kek_strategy
        self._require_options(options)

    #: Options this adapter cannot work without. Validated at construction so a
    #: missing one is an ``E003`` at ``manage.py check`` rather than a KeyError on
    #: the first encrypt, in a request that has nothing to do with configuration.
    _REQUIRED_OPTION_KEYS: tuple[str, ...] = ()

    def _require_options(self, options: dict) -> None:
        missing = [key for key in self._REQUIRED_OPTION_KEYS if not (options or {}).get(key)]
        if missing:
            log_and_raise_configuration_error(
                logger,
                f"{type(self).__name__} requires {', '.join(missing)} in its KMS_KEY_STORES block's OPTIONS.",
            )

    def _require_one_kek_per_silo(self, kek_strategy: AbstractKekStrategyAdapter, why_no_binding: str) -> None:
        """Refuse a KEK configuration that lets two silos resolve to one key.

        For an adapter whose provider cannot bind associated data into a wrapped
        DEK. With nothing bound, a wrapped DEK moved between two silos that share
        a KEK still unwraps, so a distinct key per silo is the only boundary at
        the wrap layer. *why_no_binding* is the adapter's sentence saying why its
        provider binds nothing.
        """
        problem = kek_strategy.shared_kek_problem()
        if problem is None:
            return
        log_and_raise_configuration_error(
            logger,
            f"{type(self).__name__} cannot bind associated data into the wrapped DEK. {why_no_binding} "
            f"{problem} That leaves no per-silo cryptographic boundary at the KEK layer. Use "
            "PerSiloKekStrategy with a KEK_TEMPLATE that contains {silo_uid} and a KEK_MAP that names "
            "each key once, or switch to a KMS provider whose wrap operation binds associated data.",
        )

    @property
    def kek_strategy(self) -> AbstractKekStrategyAdapter:
        """The KEK strategy paired with this adapter (wired with its charset).

        Exposed for operator-facing tooling — the startup charset check and the
        Status-page reconciliation — which need the strategy's ``owner_prefix``
        and ``validate_literal`` without reaching into a private attribute.
        """
        return self._kek_strategy

    def resolve_kek_name(self, silo_ref) -> str:
        """Return the KEK name for *silo_ref* in the canonical (stored) name space.

        The strategy answers in identifier space; this maps that onto the form
        recorded on the row (see :meth:`canonical_kek_name`). Every comparison
        against a stored or KMS-listed name goes through here, so the two cannot
        drift apart.
        """
        return self.canonical_kek_name(self._kek_strategy.get_kek_id(silo_ref))

    def owner_prefix(self) -> str | None:
        """Return this deployment's KEK owner prefix for this store, canonicalized.

        ``None`` when ownership cannot be derived (shared / ``KEK_MAP`` configs),
        which is what makes the deletion gates refuse. Canonicalized for the same
        reason as :meth:`resolve_kek_name`: the prefix is matched against stored
        and KMS-listed names, so a bare prefix would match nothing on an adapter
        that records qualified names — silently refusing every deletion and
        reporting KMS-side reconcile as unavailable.
        """
        prefix = self._kek_strategy.owner_prefix()
        return self.canonical_kek_name(prefix) if prefix else None

    def mapped_kek_names(self) -> frozenset[str]:
        """Every ``KEK_MAP`` identifier of this store, canonicalized like :meth:`owner_prefix`."""
        return frozenset(self.canonical_kek_name(name) for name in self._kek_strategy.mapped_kek_names())

    def owned_mapped_kek_names(self) -> frozenset[str]:
        """The ``KEK_MAP`` identifiers this deployment owns, canonicalized like :meth:`owner_prefix`.

        A key is owned when its name carries :meth:`owner_prefix` or is in this set.
        """
        return frozenset(self.canonical_kek_name(name) for name in self._kek_strategy.owned_mapped_kek_names())

    def current_kek_version(self, silo_ref: str) -> str:
        """Return the key version new wraps for *silo_ref* would use, if any.

        Empty where the provider exposes no version identity; adapters whose
        provider does report one override this. ``reencrypt_keys`` reads it to
        skip rows already wrapped under the current material instead of
        re-wrapping every row on every run.
        """
        return ""

    def describe_instance(self) -> str | None:
        """Human-readable identifier of the specific KMS instance/vault/region.

        Reads ``self.options`` only — no network or SDK calls — so it is safe to
        call when building the admin test console. Returns ``None`` when the
        provider has no distinct instance to show (e.g. the system adapter).
        Adapters declare the identifying option keys via
        :attr:`_INSTANCE_OPTION_KEYS`; override this only for non-option sources
        (e.g. an environment variable).
        """
        values = [str(v) for k in self._INSTANCE_OPTION_KEYS if (v := (self.options or {}).get(k))]
        return " / ".join(values) if values else None

    @classmethod
    def build_strategy(
        cls,
        strategy_cls: type[AbstractKekStrategyAdapter],
        options: dict,
    ) -> AbstractKekStrategyAdapter:
        """Construct a KEK strategy wired with this adapter's UID sanitization rules.

        The registry uses this to pair a strategy with the KMS adapter that
        will host it, so the strategy's sanitizer matches the provider's
        key-naming charset and length cap. Tests that build adapters directly
        should also use this helper instead of calling the strategy ctor.
        """
        return strategy_cls(
            options,
            allowed=cls._UID_ALLOWED_CHARS,
            escape=cls._UID_ESCAPE_CHAR,
            max_length=cls._UID_MAX_LENGTH,
        )

    @classmethod
    def _reject_unhonored_tls_options(cls, options: dict) -> None:
        """Raise if TLS_CA_BUNDLE / TLS_EXTRA_CA is set on an adapter that ignores it.

        The SSLContext built from those options is only consumed by the
        urllib-based adapters in this library. SDK-backed adapters use their own
        trust stores, so silently ignoring the option would produce a private-CA
        handshake failure at first KMS call. Fail loudly at adapter construction
        instead, pointing the operator at the SDK-native env var.
        """
        if cls._HONORS_TLS_OPTIONS:
            return
        offending = [k for k in ("TLS_CA_BUNDLE", "TLS_EXTRA_CA") if options.get(k)]
        if not offending:
            return
        log_and_raise_configuration_error(
            logger,
            f"{cls.__name__} does not honor {' / '.join(offending)} in OPTIONS. "
            f"{cls._TLS_SDK_HINT} "
            f"Remove {' / '.join(offending)} from this adapter's OPTIONS "
            "once the SDK-native variable is set.",
        )

    # ------------------------------------------------------------------
    # TLS configuration
    # ------------------------------------------------------------------

    @staticmethod
    def _build_ssl_context(options: dict) -> ssl.SSLContext:
        """Build an SSL context for KMS and credential HTTP calls.

        Delegates to :func:`encryption_suite.adapters._tls.build_ssl_context`.
        Retained as a staticmethod for adapter subclasses that subclass-override it.

        Supports two options in ``OPTIONS``:

        ``TLS_CA_BUNDLE``
            Path to a CA certificate file or directory.  **Replaces** the
            system trust store entirely.

        ``TLS_EXTRA_CA``
            Path to a CA certificate file or directory.  **Adds to** the
            system trust store.

        If both are set, ``TLS_CA_BUNDLE`` takes precedence.  If neither is
        set, the system default trust store is used.

        .. note::
           TLS options only apply to HTTP calls made via ``urllib`` inside
           this library: provisioners, token-based credential strategies, and the
           urllib-based KMS adapters. SDK-backed adapters do not receive this
           context and will raise
           :class:`~encryption_suite.exceptions.EncryptionConfigurationError` at
           construction if either option is set. Configure TLS through the SDK's
           own mechanism for those — the guard's error message names the specific
           environment variable for each adapter.
        """
        return build_ssl_context(options)

    # ------------------------------------------------------------------
    # Auth-error retry with circuit breaker
    # ------------------------------------------------------------------

    def _is_auth_retry_blocked(self) -> bool:
        """Return True if a recent retry with fresh credentials also failed.

        During the cooldown period, the adapter should not retry on auth
        errors — the fresh credentials are unlikely to work, and retrying
        would waste a KMS call.
        """
        return time.monotonic() < self._auth_retry_blocked_until

    def _record_auth_retry_failure(self) -> None:
        """Mark that a retry with fresh credentials failed.

        Starts a cooldown period during which ``_is_auth_retry_blocked()``
        returns True.
        """
        with self._auth_retry_lock:
            self._auth_retry_blocked_until = time.monotonic() + self.AUTH_RETRY_COOLDOWN
            logger.warning(
                "A call was rejected as unauthenticated, and retrying it with fresh credentials "
                "failed too, so further retries on authentication errors are suppressed for a "
                "cooldown. adapter=%s cooldown_seconds=%d",
                type(self).__name__,
                self.AUTH_RETRY_COOLDOWN,
            )

    def _clear_auth_retry_block(self) -> None:
        """Clear the cooldown after a successful request.

        A successful request proves the credentials are working again,
        so future auth errors should be retried normally.
        """
        if self._auth_retry_blocked_until > 0:
            with self._auth_retry_lock:
                self._auth_retry_blocked_until = 0.0

    # ------------------------------------------------------------------
    # KEK resolution
    # ------------------------------------------------------------------

    def _resolve_kek_id(self, silo_ref: str) -> str:
        """Return the provider-specific KEK identifier for *silo_ref*.

        Delegates to the injected
        :class:`~encryption_suite.adapters.keks.base.AbstractKekStrategyAdapter`.
        """
        return self._kek_strategy.get_kek_id(silo_ref)

    # ------------------------------------------------------------------
    # Wrap AAD
    # ------------------------------------------------------------------

    def _wrap_aad(self, silo_ref: str) -> bytes:
        """Return the canonical bytes-form AAD bound to a wrapped DEK.

        Used by adapters whose KMS API takes AAD as raw bytes. An adapter whose
        provider takes it in another shape — a string map, say — builds the
        equivalent itself and does not call this hook.

        Adapters whose provider cannot bind AAD at all ignore the ``silo_ref``
        they receive and rely on a startup guard against
        :class:`~encryption_suite.adapters.keks.strategies.SharedKekStrategy`
        instead.

        Subclasses may override to introduce a custom prefix via
        :attr:`_AAD_PREFIX`. Overriding to weaken or remove the binding
        (returning ``b""``) silently disables the per-silo boundary
        at the KEK-wrap layer and is strongly discouraged.
        """
        if not silo_text(silo_ref):
            raise ValueError("silo_ref must be a non-empty silo reference when binding wrap AAD.")
        uid_bytes = silo_text(silo_ref).encode("utf-8")
        return self._AAD_PREFIX + uid_bytes

    # ------------------------------------------------------------------
    # KEK-not-found detection
    # ------------------------------------------------------------------

    def is_kek_not_found_error(self, exc: BaseException) -> bool:
        """Return True if *exc* indicates the configured KEK is missing.

        The engine uses this hook to translate provider-specific "key does
        not exist" errors into
        :class:`~encryption_suite.exceptions.KekNotProvisionedError`, which
        carries a translated user-facing message and triggers an
        admin-oriented English log entry pointing at the missing KEK.

        The default implementation is a conservative heuristic that matches
        ``NotFound``/``does not exist``/``no such key`` on the exception class
        name and message. Provider-specific adapters should override this
        with a precise check against their SDK's typed errors.
        """
        name = type(exc).__name__.lower()
        msg = str(exc).lower()
        return "notfound" in name or "not found" in msg or "does not exist" in msg or "no such key" in msg

    # ------------------------------------------------------------------
    # Canonical KEK naming
    # ------------------------------------------------------------------

    def canonical_kek_name(self, kek_id: str) -> str:
        """Return *kek_id* in the form this adapter records in ``KmsMetadata``.

        The strategy resolves a KEK *identifier* (``KEK_TEMPLATE`` / ``KEK_MAP``);
        some adapters record that verbatim while others qualify it with their
        configured coordinates before storing it, and one whose provider assigns
        an opaque id records the name it resolved from. Everything that compares a
        resolved name against a *stored* one — reconcile's expected set, the
        provisioner's listing, the owner-prefix ownership gate, the Reconcile Keys
        table — has to speak a single name space, and the stored form is the one
        the durable rows already carry.

        The default returns *kek_id* unchanged. An override must be a pure,
        idempotent, **prefix-preserving** concatenation of configured coordinates:
        the same function is applied to the strategy's ``owner_prefix``, and a
        transform that reorders or rewrites the identifier would turn that prefix
        into one no key name starts with, silently disabling deletion and
        KMS-side reconcile.
        """
        return kek_id

    # ------------------------------------------------------------------
    # Resource-coordinate mismatch hint
    # ------------------------------------------------------------------

    def kek_resource_mismatch_hint(self, stored_resource_name: str) -> str | None:
        """Return a short diagnostic if *stored_resource_name* clearly belongs to a
        different KMS account/project/region/key ring than this adapter is
        configured for, else ``None``.

        The engine appends the result to an operational unwrap-failure log (a
        403/404 that classifies as
        :class:`~encryption_suite.exceptions.KekUnavailableError` or
        :class:`~encryption_suite.exceptions.KekNotProvisionedError`) to point
        at the likely real cause: the row was wrapped by a *different deployment
        of the same provider*, so the stored full resource name does not resolve
        under this configuration. This complements the cross-provider guard,
        which catches only the case where the providers themselves differ.

        Default returns ``None``. Only adapters that build resource names from
        configured account/location coordinates can tell, and they override this
        with a format-aware comparison so a legitimately rotated or renamed key
        (same coordinates, different key name) is never flagged.
        """
        return None

    # ------------------------------------------------------------------
    # Abstract interface
    # ------------------------------------------------------------------
    #
    # Async ORM support:
    # As of Django 6.0, the field protocol (get_prep_value, from_db_value)
    # has no async variants, so Django uses sync_to_async internally and
    # the sync encrypt_key/decrypt_key methods below run in a thread pool.
    #
    # When Django introduces an async field protocol, add async_encrypt_key
    # and async_decrypt_key methods to this base class (they do not exist yet).
    # Default implementations should delegate to the sync versions via
    # asyncio.to_thread.  Adapters can then override with native async
    # implementations (e.g. using httpx or aiohttp) for better
    # performance.  The engine's async_encrypt / async_decrypt (also do
    # not exist yet — see EncryptionEngine) should call these async
    # variants.  Their signatures must match the sync versions, including
    # the ``silo_ref`` parameter on async_decrypt_key.
    # ------------------------------------------------------------------

    @abstractmethod
    def encrypt_key(self, plaintext: bytes, silo_ref: str) -> tuple[bytes, KmsMetadata]:
        """
        Encrypt the DEK *plaintext* bytes with the KEK for *silo_ref*.

        Returns ``(encrypted_keyset_bytes, metadata)`` where *metadata* must be
        stored alongside the encrypted keyset so that :meth:`decrypt_key` can
        identify the KEK.

        Adapters that bind associated data at the wrap layer derive it from
        *silo_ref*, via :meth:`_wrap_aad` or the provider's own equivalent.
        """

    @abstractmethod
    def decrypt_key(
        self,
        ciphertext: bytes,
        metadata: KmsMetadata,
        silo_ref: str,
    ) -> bytes:
        """
        Decrypt the encrypted DEK *ciphertext* bytes using the KEK identified by *metadata*.

        *silo_ref* must come from the caller's silo context (e.g.
        the ``silo_ref`` column on the
        :class:`~encryption_suite.models.DataEncryptionKey` row being
        decrypted), **never** from *metadata*. Adapters that bind AAD use it to
        verify the wrapped DEK belongs to the silo the caller is
        operating under; an attacker who swaps wrapped-DEK rows between
        silos in the database cannot forge the AAD, so the KMS decrypt
        fails. Reading the UID from *metadata* would silently remove that
        boundary because *metadata* travels with the swapped row.
        """

    def describe_kek(self) -> str:
        """Human-readable description of the KEK configuration (for logging / management commands).

        Default implementation delegates to the KEK strategy.  Subclasses may
        override to prepend provider-specific context.
        """
        return self._kek_strategy.describe()
