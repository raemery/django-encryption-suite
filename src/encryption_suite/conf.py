"""
Settings access for encryption_suite.

All configuration lives under the ENCRYPTION dict in your Django settings.
Access individual settings via the ``enc_settings`` singleton.
"""

import re
import threading

from django.conf import settings

DEFAULTS = {
    # The key sets this deployment uses: key set name → {"silo": dotted path of
    # a silo adapter class, "key_store": a named key store}. A key set is one silo
    # and one key store. "default" is what an encrypted field gets when it
    # names no key set (Pegasus teams, django-tenants, a custom silo adapter): the
    # project declares it whenever a field uses it. "system" always exists, with
    # the package's system silo, and takes only a "key_store". "silo": "system"
    # in any entry means the system silo. A "key_store" left out means the only
    # configured store.
    "KEY_SETS": {},
    # The KMS key stores this deployment can reach, by a name the project
    # chooses. Each block holds the keys in KMS_BLOCK_DEFAULTS below. A key
    # encryption key row records the name of the store that holds it, and every
    # unwrap routes through that store, so a name must never be renamed once rows
    # use it. Names are unique across KMS_KEY_STORES and ENV_KEY_STORES.
    "KMS_KEY_STORES": {},
    # The env key stores: key material the project supplies to the process through
    # settings. Each entry is {"KEKS": {version: base64 of 32 random bytes}}
    # (openssl rand -base64 32); the highest version wraps new keys and the older
    # ones stay until no data key row records them. An optional SHARED_KEK_ID
    # names the one key encryption key. There is no ephemeral key: an empty KEKS
    # is a configuration error.
    "ENV_KEY_STORES": {},
    # When True, the engine lazily creates a DataEncryptionKey the first
    # time a silo tries to encrypt data, instead of requiring
    # setup_encryption_keys or the auto-create signal to have run first.
    # Decryption is never lazy — a missing DEK on read always raises.
    "KEY_AUTO_PROVISION": True,
    # Dotted path to the crypto backend that performs the local symmetric
    # encryption (field AEAD + file streaming AEAD). The DEK format and
    # ciphertext format are owned by this backend; KMS only wraps the opaque
    # serialized DEK. Defaults to the pyca-cryptography backend (its `cryptography`
    # dependency is core); the Tink backend is opt-in via the [tink] extra.
    "CRYPTO_BACKEND": "encryption_suite.adapters.crypto_backends.cryptography.CryptographyCryptoEngine",
    # Backend-specific configuration dict. pyca-cryptography reads AEAD /
    # SEGMENT_SIZE; the Tink backend reads AEAD_KEY_TEMPLATE /
    # STREAMING_AEAD_KEY_TEMPLATE. Kept separate from a block's OPTIONS because
    # primitive choice is a data-plane concern, not a KMS one.
    "CRYPTO_BACKEND_OPTIONS": {},
    # Seconds to cache plaintext AEAD primitives in-process
    "DEK_CACHE_TTL": 300,
    # Per key set, the most data keys the in-process cache holds; a key set missing
    # here uses DEFAULT_DEK_CACHE_MAX, and one in neither has no cap. The oldest-loaded
    # key goes first.
    "DEK_CACHE_MAX": {},
    # Seconds to cache a *failed* KEK operation (the KEK could not be
    # reached or used — a dead/slow endpoint, expired credentials, a
    # not-yet-provisioned KEK) in-process, keyed per silo. A failure
    # short-circuits subsequent reads so one slow/dead KMS call is not re-paid
    # by every encrypted field on a page. Kept deliberately short — far below
    # DEK_CACHE_TTL — so a healthy-but-briefly-slow backend is retried almost
    # immediately rather than being treated as down for minutes. A missing DEK
    # row or a configuration error is a fast local check and is never cached.
    # Set to 0 to disable negative caching entirely.
    "DEK_FAILURE_CACHE_TTL": 5,
    # When True, SiloEncryptedStorageMixin._save spools ciphertext to a
    # SpooledTemporaryFile that spills to TMPDIR above
    # STORAGE_SPOOL_THRESHOLD bytes.  Keeps memory flat for large uploads.
    # Set False on runtimes where TMPDIR is backed by memory (Cloud Run,
    # k8s emptyDir: {medium: Memory}) — on those platforms spooling costs
    # the same memory and adds syscall overhead.
    "STORAGE_SPOOL_ENABLED": True,
    # Byte threshold above which the ciphertext spool spills from memory to
    # disk.  None means "use Django's FILE_UPLOAD_MAX_MEMORY_SIZE", which
    # matches the plaintext upload side's memory/disk split.
    "STORAGE_SPOOL_THRESHOLD": None,
    # Directory for the ciphertext spool file.  None lets tempfile pick
    # (honors TMPDIR / TMP / TEMP).  Set to a mounted volume path on Fly /
    # Fargate / EKS when the rootfs is too small for concurrent uploads.
    "STORAGE_SPOOL_DIR": None,
    # Alias name in Django's STORAGES setting whose backend is used for
    # EncryptedFileField content.  The backend class at that alias is
    # composed at runtime with SiloEncryptedStorageMixin, so users
    # never instantiate storage classes in Python.  If the alias does not
    # exist, falls back to the "default" alias.  Keeping encrypted uploads
    # on a dedicated alias lets operators point private/sensitive files at
    # a different bucket (or entirely different backend) from public media.
    "STORAGE_ALIAS": "encrypted",
    # List of key set names. When a silo of a listed key set's adapter is created
    # (post_save, created=True), that key set's field key is made. The silo model
    # comes from the adapter.
    "SILO_AUTO_KEY_CREATION": [],
    # List of key set names that select silo adapters. On post_delete of a silo
    # of a listed key set's adapter, every DataEncryptionKey (DEK) row for that
    # silo, in every key set bound to the adapter, is flipped to
    # `deletion_scheduled` and — only when the KEK is
    # silo-exclusive — its KeyEncryptionKey row is scheduled too, both inside the same
    # soft-delete window (see KEY_DELETION_WINDOW_DAYS). Scheduling never
    # destroys a key; the admin purge action processes expired work
    # later (re-checking the deletion gates). Empty default: opt in per silo
    # adapter. Symmetric to SILO_AUTO_KEY_CREATION.
    "SILO_AUTO_KEY_DELETION": [],
    # Days a scheduled key stays restorable before the purge run may destroy it.
    # One window covers both sides of a deletion: the DEK row's app-enforced
    # soft-delete (its `encrypted_keyset` is cleared — the crypto-shred) and the
    # silo-exclusive KEK's provider deletion. A restore during the window reverses
    # both together. 0 means schedule-equals-immediately-eligible (the next purge
    # run may act at once); the row is still recorded scheduled first so the act
    # is always auditable. Default 14 days.
    "KEY_DELETION_WINDOW_DAYS": 14,
    # Permit destroying a key that data still in use depends on, making that data
    # permanently unreadable while its rows remain. Off by default: the ordinary
    # deletion path destroys keys whose silo is already gone, and refusing this
    # case is what stops a mis-selection from taking a live tenant's data with it.
    #
    # Turning it on is a deliberate choice for a real requirement — an erasure
    # obligation that must render personal data unreadable while the records
    # themselves are retained is the usual one. It applies to both halves of a
    # deletion, and both are irreversible once their provider window (if any)
    # closes:
    #
    #   * a key encryption key that still wraps live keysets — every silo counted
    #     on the purge confirmation loses its data;
    #   * a data encryption key whose silo the adapter still enumerates.
    #
    # With it off, the refusal happens at *scheduling* as well as at purge, so a
    # key that can never be destroyed is not left sitting in a window pretending
    # otherwise. The data-encryption-key gate needs live silo enumeration to know
    # whether the silo is still there; where the silo adapter cannot enumerate the
    # gate cannot run, and the purge proceeds as it did before this setting
    # existed.
    "KEY_DELETION_CAN_RENDER_DATA_INACCESSIBLE": False,
    # Cryptoperiod for a silo's data encryption key, in days. Display only: the
    # package never rotates a data key on its own, and nothing is blocked or
    # refused when the period elapses. It sets the point at which the admin calls
    # a key overdue, measured from `key_material_last_generated_at` — the age of
    # the material itself, which a re-encryption onto a new key encryption key
    # deliberately does not reset. None (the default) means no cryptoperiod is
    # declared and the admin makes no claim about any key being due.
    #
    # Paired with the KEK provisioner's KEK_ROTATION_PERIOD_DAYS option, which is
    # the same idea one layer up: that one sets a real rotation schedule at the
    # provider, and the admin reads it to date the matching key-encryption-key
    # answer from `last_reencrypted_at`. The two names differ only in their
    # prefix so neither can be mistaken for the other.
    "DEK_ROTATION_PERIOD_DAYS": None,
    # Sentinel silo UIDs the admin test console uses for its isolated
    # PURPOSE_TEST keys (one for field/AEAD, one for file/streaming). They must
    # never collide with a real silo UID — under a per-silo KEK strategy the
    # test KEK is named from the UID, so a collision would point the test key at
    # a real silo's KEK. The defaults avoid the ``label-value`` shape real
    # adapters produce; override them only if a real UID could match. Keep them
    # short — they are templated into a provider KEK name subject to length caps.
    #
    # The two below are *row* keys only: a data encryption key row is unique on
    # ``(silo_uid, purpose)`` and both console rows share ``PURPOSE_TEST``, so the
    # two tests need distinct UIDs to coexist. Neither reaches the KMS. Each KMS
    # gets its own pair, prefixed with its name: (fly)enctestfieldkey.
    "TEST_CONSOLE_FIELD_UID": "enctestfieldkey",
    "TEST_CONSOLE_FILE_UID": "enctestfilekey",
    # The UID both console tests make their KMS calls under, and therefore the one
    # the test key encryption key is named from. Separate from the two row keys so
    # the console provisions a single test KEK whose name says what it is, rather
    # than borrowing the field test's name for a key that serves both.
    "TEST_CONSOLE_KEK_UID": "enctestkey",
    # When True, the construction-time configuration checks (E003 / E004) are
    # reported as warnings (W003 / W004) instead of errors, so a deploy that runs
    # `manage.py check` proceeds against a broken configuration. Useful for
    # exercising request-time error handling on a staging deployment; leave False
    # in normal operation so misconfiguration fails at deploy rather than at the
    # first encrypt/decrypt. Read directly off the raw ENCRYPTION dict in
    # checks.py — checks must run even when a required setting is missing, which
    # enc_settings refuses to load.
    "STARTUP_CHECK_WARN_ONLY": False,
    # When True, each successful field decryption emits an INFO-level audit log entry
    # recording the silo_uid.  Defaults to False — on read-heavy paths this
    # produces one log line per decrypted field and will overwhelm most logging
    # pipelines.  Enable explicitly for compliance use cases (e.g. PCI, HIPAA) and
    # size your log sink accordingly.  Decrypt *failures* are always logged at
    # ERROR regardless of this setting.
    "LOG_DECRYPTS": False,
    # Whether a log line may carry the *values* of a field's AAD-bound columns
    # (the field's aad=). Off by default: a schema that binds a name
    # or an email would otherwise write them to the log aggregator on every
    # failed read. Off, a line names each bound column and says whether it is
    # populated, which locates the row just as well. Governs both writers — the
    # decrypt-failure lines and reencrypt_data's per-row report line.
    "LOG_AAD_VALUES": False,
    # What is recorded and logged about who acted. Read through
    # user_identity_setting(), which fills a key the project left out from the
    # defaults here, so a project may set only the keys it changes.
    #
    # KEY_LIFECYCLE_EVENTS and LOGS each list the identity items that reach that
    # destination (see the items below); an item in neither is neither recorded
    # nor logged. Both are empty by default, so out of the box nothing about who
    # acted is kept anywhere. Logs are never encrypted, so the encrypted_* items
    # belong to KEY_LIFECYCLE_EVENTS alone.
    #
    # SCOPE, shared by both lists: "privileged_acts" (the default) takes the
    # identity a site passes explicitly — admin actions, the test console,
    # management commands — and resolves nobody from the request context, so a
    # key created while serving a customer's request names no customer.
    # "all_acts" also attributes those ambient acts, and needs
    # UserContextMiddleware below Django's AuthenticationMiddleware.
    #
    # IP_PROXY_COUNT: how many proxies in front of this application are under
    # the deployment's control. 0 disregards X-Forwarded-For entirely and reads
    # the address from REMOTE_ADDR. A count of N takes the Nth entry from the
    # right of the header; entries further left are client-supplied and never
    # read. Governs this package's reading of that header alone — do not assume
    # it matches another library's proxy-count setting.
    "USER_IDENTITY": {
        "KEY_LIFECYCLE_EVENTS": [],
        "LOGS": [],
        "SCOPE": "privileged_acts",
        "IP_PROXY_COUNT": 0,
    },
}

#: The built-in key set: one silo, the package's system adapter, keys that need no request context.
SYSTEM_KEY_SET = "system"
#: What ``"silo"`` holds in a ``KEY_SETS`` entry to name the package's system silo adapter.
SYSTEM_ADAPTER = "system"

#: The two registries a named key store can come from.
STORE_TYPE_ENV = "env"
STORE_TYPE_KMS = "kms"
#: The key set a field belongs to when it names none. A constant of the package,
#: never a setting: a field definition means the same thing in every deployment.
#: The project declares it in ``KEY_SETS`` whenever a field uses it.
DEFAULT_KEY_SET = "default"
#: The two names no project may use for another purpose.
RESERVED_KEY_SETS = (DEFAULT_KEY_SET, SYSTEM_KEY_SET)
#: Key set names are lowercase identifiers of at most ``KEY_SET_MAX_LENGTH`` characters.
KEY_SET_PATTERN = r"[a-z][a-z0-9_]*"
KEY_SET_MAX_LENGTH = 32


def is_valid_key_set(name) -> bool:
    """Whether *name* is a usable key set name: the pattern, within the length limit."""
    return isinstance(name, str) and len(name) <= KEY_SET_MAX_LENGTH and re.fullmatch(KEY_SET_PATTERN, name) is not None


#: The silo UID the system silo's data is encrypted under.
SYSTEM_SILO_UID = "system"

#: The keys of one ``KMS_KEY_STORES`` block, with their defaults. ``ADAPTER`` and
#: ``KEK_STRATEGY_ADAPTER`` have none.
#:
#: ``OPTIONS`` and ``KEK_PROVISIONER_OPTIONS`` are both scoped to one adapter, so
#: neither needs a provider prefix â€” but they spell that differently and a new
#: option should follow the dict it lands in. Keys in ``OPTIONS`` carry the
#: provider (AWS_REGION, IBM_ENDPOINT, VAULT_ENDPOINT): they are what an operator
#: greps for in the provider's own documentation, and a credential strategy reads
#: them beside keys meant for another service. Keys in ``KEK_PROVISIONER_OPTIONS``
#: are bare (KEY_SPEC, POLICY, EXTRACTABLE): each mirrors a field of one
#: provider's create-key call, and the prefix would say twice what the dict
#: already says. The provisioner's options are kept apart from ``OPTIONS`` because
#: provisioning typically needs different credentials, tags, key specs, or key
#: policies than routine encrypt/decrypt.
#:
#: The default provisioner does nothing: key encryption keys are provisioned
#: outside this application (Terraform, a bootstrap script) unless a block names
#: one.
KMS_BLOCK_DEFAULTS = {
    "ADAPTER": None,
    "OPTIONS": {},
    "KEK_STRATEGY_ADAPTER": None,
    "KEK_PROVISIONER_ADAPTER": "encryption_suite.adapters.keks.NullKekProvisioner",
    "KEK_PROVISIONER_OPTIONS": {},
}

#: The key encryption key id every env store shares across all its silos and kinds unless its entry names another.
DEFAULT_ENV_SHARED_KEK_ID = "shared"


def _store_setting(name: str) -> dict:
    value = configured_setting(name)
    return value if isinstance(value, dict) else {}


def kms_block(name: str) -> dict | None:
    """Return the block for named store *name* with its defaults filled, or ``None`` if unconfigured.

    A KMS store is its configured block. An env store has no block of its own, so
    it is given the one every env store shares: the env adapter, one key
    encryption key for every silo under it, nothing ever deleting it. Reads the
    raw setting rather than ``enc_settings`` so the deploy-time checks can ask
    about a block while another setting is still missing.
    """
    block = _store_setting("KMS_KEY_STORES").get(name)
    if isinstance(block, dict):
        return {**KMS_BLOCK_DEFAULTS, **block}
    entry = _store_setting("ENV_KEY_STORES").get(name)
    if isinstance(entry, dict):
        return {
            "ADAPTER": "encryption_suite.adapters.key_stores.environment.EnvKeyStoreAdapter",
            "OPTIONS": {
                "SHARED_KEK_ID": entry.get("SHARED_KEK_ID", DEFAULT_ENV_SHARED_KEK_ID),
                "KEKS": entry.get("KEKS", {}),
            },
            "KEK_STRATEGY_ADAPTER": "encryption_suite.adapters.keks.SharedKekStrategy",
            "KEK_PROVISIONER_ADAPTER": "encryption_suite.adapters.keks.NullKekProvisioner",
            "KEK_PROVISIONER_OPTIONS": {},
        }
    return None


def kms_names() -> list[str]:
    """Every configured named store: the KMS stores first, then the env stores."""
    return [*_store_setting("KMS_KEY_STORES"), *_store_setting("ENV_KEY_STORES")]


def store_type_of(name: str) -> str | None:
    """The type of named store *name*: ``"kms"``, ``"env"``, or ``None`` if there is none."""
    if name in _store_setting("KMS_KEY_STORES"):
        return STORE_TYPE_KMS
    if name in _store_setting("ENV_KEY_STORES"):
        return STORE_TYPE_ENV
    return None


def is_env_store(name: str) -> bool:
    """Whether *name* is an env store: key material held in settings, wrapped locally."""
    return store_type_of(name) == STORE_TYPE_ENV


def key_set_entries() -> dict:
    """The ``KEY_SETS`` setting as given, with the built-in ``system`` entry added when the project has none."""
    entries = dict(_store_setting("KEY_SETS"))
    entries.setdefault(SYSTEM_KEY_SET, {})
    return entries


def key_set_names() -> list[str]:
    """Every key set name: the project's own, then ``system`` unless the project listed it."""
    return list(key_set_entries())


def adapter_path(key_set: str) -> str | None:
    """The dotted path of the silo adapter *key_set* is bound to, :data:`SYSTEM_ADAPTER` for the system adapter.

    ``None`` when the key set has no entry or its entry names no adapter. The
    ``system`` key set is always bound to the system adapter, whatever its entry says.
    """
    if key_set == SYSTEM_KEY_SET:
        return SYSTEM_ADAPTER
    entry = key_set_entries().get(key_set)
    path = entry.get("silo") if isinstance(entry, dict) else None
    return path if isinstance(path, str) and path else None


def is_system_key_set(key_set: str) -> bool:
    """Whether *key_set* is bound to the package's system adapter: one key for the whole table, no silo context."""
    return adapter_path(key_set) == SYSTEM_ADAPTER


def key_sets_of_adapter(path: str) -> list[str]:
    """Every key set bound to the silo adapter at *path*, in settings order."""
    return [name for name in key_set_names() if adapter_path(name) == path]


def store_problem(key_set: str) -> str:
    """Why *key_set* resolves to no store, or ``""`` when it does."""
    entry = key_set_entries().get(key_set)
    if entry is None:
        return f"ENCRYPTION['KEY_SETS'] has no entry for the key set {key_set!r}."
    if not isinstance(entry, dict):
        return f"ENCRYPTION['KEY_SETS'][{key_set!r}] = {entry!r} is not a dict with a 'silo' and a 'key_store'."
    name = entry.get("key_store")
    if name is None:
        names = kms_names()
        if len(names) == 1:
            return ""
        if not names:
            return f"No key store is configured, so the key set {key_set!r} has no store to use."
        return (
            f"Several key stores are configured ({', '.join(names)}) and "
            f"ENCRYPTION['KEY_SETS'][{key_set!r}] has no 'key_store' to choose one."
        )
    if not isinstance(name, str) or name not in kms_names():
        return f"ENCRYPTION['KEY_SETS'][{key_set!r}]['key_store'] = {name!r} names no configured store."
    return ""


def default_kms_name() -> str:
    """The store the ``default`` key set uses, or ``""`` when it resolves to none."""
    return resolve_store(DEFAULT_KEY_SET) or ""


def key_set_choices() -> list[tuple[str, str]]:
    """The key sets an admin screen can offer, as ``(key_set, store)`` pairs, ``default`` first.

    Settings order otherwise. A key set that resolves to no store is left out;
    the deploy-time checks already report it.
    """
    pairs = [(name, store) for name in key_set_names() if (store := resolve_store(name))]
    pairs.sort(key=lambda pair: pair[0] != DEFAULT_KEY_SET)
    return pairs


def key_set_label(key_set: str, store: str) -> str:
    """The selector label for a key set and its store: ``default (fly)``."""
    return f"{key_set} ({store})"


def resolve_store(key_set: str) -> str | None:
    """The named store *key_set* uses, or ``None`` if it resolves to none.

    The entry's ``key_store`` wins; an entry that names none uses the only
    configured store.
    """
    if store_problem(key_set):
        return None
    name = key_set_entries()[key_set].get("key_store")
    return name if name is not None else kms_names()[0]


def configured_setting(name: str):
    """Return the effective value of *name* without loading ``enc_settings``.

    ``enc_settings`` merges the project's dict over :data:`DEFAULTS`; this reads
    the same value without loading it, for callers that must answer while other
    settings are missing or malformed: the deploy-time checks, whose whole job is
    to report that, and the system silo with its env store, which belong to no
    silo adapter and no KMS and must load whatever else the project has left out.
    """
    user = getattr(settings, "ENCRYPTION", {}) or {}
    return user.get(name, DEFAULTS[name])


# --- The settings screen's catalog -----------------------------------------
#
# What the admin's Encryption settings screen may show, and where. Declared here
# beside DEFAULTS so a setting is classified in the file it is defined in, never
# in the view: the screen renders what this says and decides nothing.
#
# Both answers fail safe. A setting this catalog does not know is grouped under
# GROUP_OTHER and its value is hidden, and so is an option key inside the
# options dicts that SHOWN_OPTION_KEYS does not list — a project's ENCRYPTION
# dict may carry keys the package never heard of (``_load`` merges the whole
# dict), and an adapter option added later has not been looked at yet. Hidden is
# the safe way to be wrong: the row still says the option is configured, and
# listing the name here is what makes the value appear.

#: Which silos exist and how they are enumerated.
GROUP_SILO = "silo"
#: The KMS, the key encryption keys on it, and how they are named and made.
GROUP_KMS = "kms"
#: Which engine performs the encryption itself.
GROUP_ENGINE = "engine"
#: How data keys are provisioned, cached, rotated and deleted.
GROUP_KEYS = "keys"
#: Where and how encrypted blobs are written.
GROUP_STORAGE = "storage"
#: Who and what each act records, in the ledger and in the log.
GROUP_RECORDING = "recording"
#: Settings that belong to no one layer.
GROUP_GENERAL = "general"
#: Anything this catalog does not classify.
GROUP_OTHER = "other"

#: Render order on the settings screen. This is the order, not the order of
#: GROUP_LABELS beside the view — the screen walks this tuple and reads a label
#: for each group it reaches.
SETTING_GROUPS = (
    GROUP_GENERAL,
    GROUP_RECORDING,
    GROUP_ENGINE,
    GROUP_SILO,
    GROUP_KMS,
    GROUP_KEYS,
    GROUP_STORAGE,
    GROUP_OTHER,
)

SETTING_CATALOG = {
    "KEY_SETS": GROUP_SILO,
    # Which silos come into existence, rather than what their keys then do.
    "SILO_AUTO_KEY_CREATION": GROUP_SILO,
    "SILO_AUTO_KEY_DELETION": GROUP_SILO,
    "KMS_KEY_STORES": GROUP_KMS,
    # With the key stores rather than the system data keys: an env store's key
    # encryption key, and only its versions are shown.
    "ENV_KEY_STORES": GROUP_KMS,
    "CRYPTO_BACKEND": GROUP_ENGINE,
    "CRYPTO_BACKEND_OPTIONS": GROUP_ENGINE,
    "KEY_AUTO_PROVISION": GROUP_KEYS,
    "DEK_CACHE_TTL": GROUP_KEYS,
    "DEK_CACHE_MAX": GROUP_KEYS,
    "DEK_FAILURE_CACHE_TTL": GROUP_KEYS,
    "DEK_ROTATION_PERIOD_DAYS": GROUP_KEYS,
    "KEY_DELETION_WINDOW_DAYS": GROUP_KEYS,
    "KEY_DELETION_CAN_RENDER_DATA_INACCESSIBLE": GROUP_KEYS,
    # Reserved silo UIDs rather than console trivia: the provisioners and
    # reconcile read them to tell a console key from a real one, so a changed
    # value is what explains a test key reported as an orphan.
    "TEST_CONSOLE_FIELD_UID": GROUP_KEYS,
    "TEST_CONSOLE_FILE_UID": GROUP_KEYS,
    "TEST_CONSOLE_KEK_UID": GROUP_KEYS,
    "STORAGE_ALIAS": GROUP_STORAGE,
    "STORAGE_SPOOL_ENABLED": GROUP_STORAGE,
    "STORAGE_SPOOL_THRESHOLD": GROUP_STORAGE,
    "STORAGE_SPOOL_DIR": GROUP_STORAGE,
    "USER_IDENTITY": GROUP_RECORDING,
    "LOG_DECRYPTS": GROUP_RECORDING,
    "LOG_AAD_VALUES": GROUP_RECORDING,
    "STARTUP_CHECK_WARN_ONLY": GROUP_GENERAL,
}

#: Option keys whose values the settings screen prints. Every option the shipped
#: adapters read is listed except the dozen that carry a credential — a token, a
#: client secret, an API key, a passphrase, raw key material — which render as a
#: sentinel instead. What is left is endpoints, regions, resource identifiers,
#: audiences, key specifications, timeouts and naming templates: the
#: configuration an operator came to this screen to read, and none of it a
#: secret. The paths among them (a service-account key file, a token file) name
#: where a credential is read from without being one, and answer a real question
#: when a deployment cannot authenticate.
#:
#: An option not listed here is hidden, so an adapter option added later is
#: visibly unclassified rather than quietly exposed.
#:
#: The four ``USER_IDENTITY`` keys are listed too: that setting is a dict, and
#: the screen renders every dict through this list. None of them is a
#: credential.
SHOWN_OPTION_KEYS = frozenset(
    {
        "ADAPTER",
        "AEAD",
        "AEAD_KEY_TEMPLATE",
        "ALGORITHM",
        "ALIAS_PROPAGATION_TIMEOUT_SECONDS",
        "ALLOW_PLAINTEXT_BACKUP",
        "ALWAYS_ALLOW_KEY_DELETION",
        "AWS_ACCOUNT_ID",
        "AWS_IAM_VAULT_ROLE",
        "AWS_OIDC_AUDIENCE",
        "AWS_REGION",
        "AWS_ROLE_ARN",
        "AWS_ROLE_SESSION_NAME",
        "AZURE_CLIENT_ID",
        "AZURE_KEY_VERSION",
        "AZURE_OIDC_AUDIENCE",
        "AZURE_TENANT_ID",
        "AZURE_VAULT_ENDPOINT",
        "CREDENTIAL_STRATEGY",
        "CUSTOM_KEY_STORE_ID",
        "DEFINED_TAGS",
        "DERIVED",
        "ENCRYPTION_ALGORITHM",
        "ENDPOINT",
        "ENV_VAR",
        "EXPORTABLE",
        "EXTRACTABLE",
        "FLY_API_ENDPOINT",
        "FLY_APP_NAME",
        "FLY_SOCKET_PATH",
        "FORMAT",
        "GCP_KMS_KEY_RING",
        "GCP_KMS_LOCATION",
        "GCP_PROJECT_ID",
        "GCP_SERVICE_ACCOUNT_EMAIL",
        "HOST",
        "IBM_CR_TOKEN_FILENAME",
        "IBM_ENDPOINT",
        "IBM_INSTANCE_ID",
        "IBM_REGION",
        "IBM_TRUSTED_PROFILE_CRN",
        "IBM_TRUSTED_PROFILE_ID",
        "IBM_TRUSTED_PROFILE_NAME",
        "INFISICAL_CLIENT_ID",
        "INFISICAL_ENDPOINT",
        "INFISICAL_IDENTITY_ID",
        "INFISICAL_OIDC_AUDIENCE",
        "INFISICAL_PROJECT_ID",
        "IP_PROXY_COUNT",
        "KEK_MAP",
        "KEK_MAP_DESTROYABLE",
        "KEK_PROVISIONER_ADAPTER",
        "KEK_PROVISIONER_OPTIONS",
        "KEK_ROTATION_PERIOD_DAYS",
        "KEK_STRATEGY_ADAPTER",
        "KEK_TEMPLATE",
        "KEY_DESCRIPTION",
        "KEY_LIFECYCLE_EVENTS",
        "KEY_OPS",
        "KEY_SIZE",
        "KEY_SPEC",
        "KEY_TYPE",
        "KEY_USAGE",
        "KEY_VERSION_TTL_SECONDS",
        "KMS_REQUEST_TIMEOUT_SECONDS",
        "LOGS",
        "OCI_COMPARTMENT_OCID",
        "OCI_CONFIG_FILE",
        "OCI_CONFIG_PROFILE",
        "OCI_FINGERPRINT",
        "OCI_KEY_ALGORITHM",
        "OCI_KEY_LENGTH",
        "OCI_KEY_PROTECTION_MODE",
        "OCI_KEY_PROVISION_TIMEOUT_SECONDS",
        "OCI_OKE_SA_TOKEN_PATH",
        "OCI_REGION",
        "OCI_TENANCY_OCID",
        "OCI_USER_OCID",
        "OCI_VAULT_CRYPTO_ENDPOINT",
        "OCI_VAULT_MANAGEMENT_ENDPOINT",
        "OIDC_SOURCE",
        "OIDC_SOURCE_OPTIONS",
        "OPTIONS",
        "PATH",
        "POLICY",
        "PROTECTION_LEVEL",
        "PROVIDER_DELETION_WINDOW_DAYS",
        "PURPOSE",
        "SCOPE",
        "SEGMENT_SIZE",
        "SERVICE_ACCOUNT",
        "SERVICE_ACCOUNT_KEY_FILE",
        "SHARED_KEK_ID",
        "SOCKET_PATH",
        "STREAMING_AEAD_KEY_TEMPLATE",
        "TAGS",
        "TLS_CA_BUNDLE",
        "TLS_EXTRA_CA",
        "VAULT_APPROLE_MOUNT",
        "VAULT_ENDPOINT",
        "VAULT_JWT_AUDIENCE",
        "VAULT_JWT_MOUNT",
        "VAULT_JWT_ROLE",
        "VAULT_MOUNT_PATH",
        "VAULT_NAMESPACE",
        "VAULT_SECRET_ID_FILE",
    }
)


#: Settings this catalog places but whose values the screen must never print,
#: because they hold key material rather than configuration. A dict renders as
#: its keys with every value hidden, which leaves exactly what an operator came
#: for: which versions are configured, the highest being the one that wraps.
#:
#: Separate from the unclassified case, which hides a value because nobody has
#: looked at it yet. These have been looked at, and the answer is no.
HIDDEN_SETTINGS = frozenset(
    {
        "ENV_KEY_STORES",
    }
)

#: Settings whose values the screen prints in full, nested keys included,
#: because none of them can hold a credential.
SHOWN_SETTINGS = frozenset(
    {
        "KEY_SETS",
    }
)


def describe_setting(name: str) -> tuple[str, bool]:
    """Return ``(group, hide_value)`` for *name*, hiding what this catalog cannot place."""
    group = SETTING_CATALOG.get(name)
    if group is None:
        return GROUP_OTHER, True
    return group, name in HIDDEN_SETTINGS


#: Keys of a ``STORAGES`` entry's ``OPTIONS`` whose values the settings screen
#: prints. Django owns ``BACKEND`` and ``OPTIONS``; what is inside ``OPTIONS`` is
#: whatever the configured backend takes as constructor arguments, so the names
#: are open-ended — Django's own file backend reads ``location`` and
#: ``base_url``, django-storages' S3 backend ``bucket_name`` and
#: ``endpoint_url``, and the same dict is where a project's access key and secret
#: routinely sit. Listed are the ones that say *where* files go; everything else
#: is hidden, including every key a backend this package has never heard of
#: introduces.
SHOWN_STORAGE_OPTION_KEYS = frozenset(
    {
        "base_url",
        "bucket_name",
        "custom_domain",
        "default_acl",
        "endpoint_url",
        "file_overwrite",
        "location",
        "querystring_auth",
        "region_name",
    }
)


def storage_option_value_is_shown(key: str) -> bool:
    """Whether a storage option's value may be printed. Unlisted means no."""
    return key in SHOWN_STORAGE_OPTION_KEYS


def option_value_is_shown(key: str) -> bool:
    """Whether an option key's value may be printed. Unlisted means no."""
    return key in SHOWN_OPTION_KEYS


# --- USER_IDENTITY vocabulary ------------------------------------------

#: Every act that resolves an identity takes one, including ambient
#: request-time paths that can name a customer rather than staff.
SCOPE_ALL_ACTS = "all_acts"
#: Only an identity a call site passed explicitly is taken; an ambient read
#: returns nobody.
SCOPE_PRIVILEGED_ACTS = "privileged_acts"

USER_IDENTITY_SCOPES = frozenset({SCOPE_ALL_ACTS, SCOPE_PRIVILEGED_ACTS})

#: The identity items. One item names one field, and the name is the same
#: wherever it applies: the log tail key, and the column holding the value.
ITEM_USER_ID = "user_id"
ITEM_USER_NAME = "user_name"
ITEM_USER_STR = "user_str"
ITEM_IP_ADDRESS = "ip_address"
ITEM_ENCRYPTED_IP_ADDRESS = "encrypted_ip_address"
ITEM_OS_USER = "os_user"
ITEM_ENCRYPTED_OS_USER = "encrypted_os_user"

#: What KEY_LIFECYCLE_EVENTS may list. No user_name or user_str: the record
#: holds the user as a reference, and a name is rendered from it.
KEY_LIFECYCLE_EVENT_ITEMS = frozenset(
    {
        ITEM_USER_ID,
        ITEM_IP_ADDRESS,
        ITEM_ENCRYPTED_IP_ADDRESS,
        ITEM_OS_USER,
        ITEM_ENCRYPTED_OS_USER,
    }
)
#: What LOGS may list. Logs are never encrypted, so no encrypted_* item.
LOG_ITEMS = frozenset({ITEM_USER_ID, ITEM_USER_NAME, ITEM_USER_STR, ITEM_IP_ADDRESS, ITEM_OS_USER})

#: Pairs that store one value two ways, so at most one of each may be listed.
EXCLUSIVE_ITEMS = (
    (ITEM_IP_ADDRESS, ITEM_ENCRYPTED_IP_ADDRESS),
    (ITEM_OS_USER, ITEM_ENCRYPTED_OS_USER),
)


def resolve_user_identity(value) -> dict:
    """Return *value* with every ``USER_IDENTITY`` key it leaves out filled from the default.

    ``_load`` merges the ``ENCRYPTION`` dict one level deep, so without this a
    project setting one key would lose the other three. A value that is not a
    dict at all resolves to the defaults; the deploy-time check reports it.
    """
    defaults = DEFAULTS["USER_IDENTITY"]
    return {**defaults, **value} if isinstance(value, dict) else dict(defaults)


def user_identity_setting(name: str):
    """Return the effective value of one ``USER_IDENTITY`` key at runtime."""
    return resolve_user_identity(enc_settings.USER_IDENTITY)[name]


class _EncryptedFieldsSettings:
    """Lazy settings accessor with validation."""

    _lock = threading.Lock()

    def _load(self) -> dict:
        user = getattr(settings, "ENCRYPTION", {})
        merged = {**DEFAULTS, **user}
        return merged

    def __getattr__(self, name: str):
        # Read _cache via __dict__ to avoid re-entering __getattr__ on the
        # first access (hasattr/getattr would recurse infinitely).
        cache = self.__dict__.get("_cache")
        if cache is None:
            with self._lock:
                cache = self.__dict__.get("_cache")
                if cache is None:
                    cache = self._load()
                    object.__setattr__(self, "_cache", cache)
        try:
            return cache[name]
        except KeyError:
            raise AttributeError(f"Unknown ENCRYPTION setting: '{name}'") from None

    def reset(self) -> None:
        """Reset the settings cache. Used in tests when settings change."""
        object.__setattr__(self, "_cache", None)


enc_settings = _EncryptedFieldsSettings()


#: The package's own caps on the in-process data key cache, key set to entry count.
#: Empty: a key set has no cap unless ``DEK_CACHE_MAX`` gives it one.
DEFAULT_DEK_CACHE_MAX: dict[str, int] = {}


def dek_cache_cap(key_set: str) -> int | None:
    """The most data keys the cache of *key_set* holds, or ``None`` for no cap.

    ``DEK_CACHE_MAX`` overrides the package's table. A value that is not a positive
    whole number means no cap, so a typo in one key set cannot stop the cache from
    working.
    """
    configured = enc_settings.DEK_CACHE_MAX
    overrides = configured if isinstance(configured, dict) else {}
    value = overrides.get(key_set, DEFAULT_DEK_CACHE_MAX.get(key_set))
    if isinstance(value, int) and not isinstance(value, bool) and value > 0:
        return value
    return None


def env_test_kek_name() -> str:
    """The name an env store's test KEK is recorded under: the console's KEK UID, ``enctestkey``.

    An env store resolves every UID to its one shared KEK, so the console names
    its own row explicitly instead of sharing ``shared`` with real silos. It
    wraps under the same ``KEKS`` material, at the highest version.
    """
    return enc_settings.TEST_CONSOLE_KEK_UID


def reserved_test_uids() -> frozenset[str]:
    """Every sentinel silo UID the admin test console owns, resolved live.

    The field row key, the file row key and the KMS identity. All must be
    reserved: a real silo colliding with any of them would either share a console
    row or point the console's key encryption key at that silo's key.

    Lives here, beside the settings that define it, rather than in the console:
    the KEK provisioners read it to recognize a console key without importing the
    admin layer.
    """
    return frozenset(
        {enc_settings.TEST_CONSOLE_FIELD_UID, enc_settings.TEST_CONSOLE_FILE_UID, enc_settings.TEST_CONSOLE_KEK_UID}
    )
