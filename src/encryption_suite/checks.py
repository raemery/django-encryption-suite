"""
Django system checks for django-encryption-suite.

Run by ``manage.py check`` and during ``runserver`` startup.

**ID scheme.** The number names the condition and the letter names the
severity, so a check reported at both severities keeps one number and swaps the
letter. No number is ever held by both a native error and a native warning,
which is what makes that swap safe:

* ``001``-``019`` — **builder** errors. These construct something: they import a
  dotted path and run an adapter's ``__init__``, so they can fail over the
  environment (a missing optional SDK, a provider library that changed) while
  the configuration is correct. That is why they are the ones
  ``STARTUP_CHECK_WARN_ONLY`` downgrades, and their ``W`` twins are in use.
* ``020``-``049`` — **validator** errors. These are predicates over data the
  package fully owns: is this value a bool, is this string one of three, does
  this field exist, is this column nullable. No environment makes the answer
  come out differently, so nothing downgrades them. Their ``W`` twins stay
  reserved rather than reassigned, so a blanket warn-only rule could later use
  them without a collision.
* ``050``-``099`` — native **warnings**, reported at that severity always.
"""

from __future__ import annotations

from django.core.checks import Error as CheckError
from django.core.checks import Warning as CheckWarning
from django.core.checks import register

from .checks_kek_names import per_silo_blocks, template_prefix
from .conf import (
    DEFAULTS,
    EXCLUSIVE_ITEMS,
    ITEM_ENCRYPTED_IP_ADDRESS,
    ITEM_ENCRYPTED_OS_USER,
    KEY_LIFECYCLE_EVENT_ITEMS,
    LOG_ITEMS,
    SCOPE_ALL_ACTS,
    USER_IDENTITY_SCOPES,
    configured_setting,
    resolve_user_identity,
)

#: Dotted path of the middleware ``USER_IDENTITY['SCOPE'] = "all_acts"`` needs,
#: and of the authentication middleware it must sit below.
_USER_CONTEXT_MIDDLEWARE = "encryption_suite.user_context.UserContextMiddleware"
_AUTHENTICATION_MIDDLEWARE = "django.contrib.auth.middleware.AuthenticationMiddleware"


def _builder_severity():
    """Return ``(message_cls, id_prefix)`` for the builder checks.

    ``STARTUP_CHECK_WARN_ONLY`` downgrades every check that constructs
    something — read here off the raw ``ENCRYPTION`` dict for the same reason
    :func:`_configured` does. The prefix moves with the severity so a message
    reported at WARNING never carries an ``E`` ID, and the number is untouched:
    ``E004`` downgraded is ``W004``, the same condition said more quietly.
    """
    from django.conf import settings

    config = getattr(settings, "ENCRYPTION", {}) or {}
    warn_only = bool(config.get("STARTUP_CHECK_WARN_ONLY"))
    return (CheckWarning if warn_only else CheckError), ("W" if warn_only else "E")


def _configured(name):
    """Return the effective value of *name*, without loading enc_settings.

    Checks must run against a configuration that ``enc_settings`` would refuse
    to load — a missing required setting is exactly the case they exist to
    report — so the raw dict is read and the package default filled in.
    """
    return configured_setting(name)


#: The two lists, with the items each may hold.
_IDENTITY_LISTS = (
    ("KEY_LIFECYCLE_EVENTS", KEY_LIFECYCLE_EVENT_ITEMS),
    ("LOGS", LOG_ITEMS),
)


@register()
def check_user_identity_settings(app_configs, **kwargs):
    """Validate ``USER_IDENTITY`` at startup.

    Each key is read on a write path deep inside a provisioning or deletion
    transaction, where a bad value would surface as an unrelated failure long
    after the deploy that introduced it. A key the project leaves out takes its
    default, so only what is present is checked.
    """
    raw = _configured("USER_IDENTITY")
    if not isinstance(raw, dict):
        return [
            CheckError(
                f"ENCRYPTION['USER_IDENTITY'] = {raw!r} is not a dict. Set it to a dict with any of the keys: "
                f"{', '.join(DEFAULTS['USER_IDENTITY'])}.",
                id="encryption_suite.E033",
            )
        ]

    errors: list[CheckError] = []
    unknown = sorted(str(key) for key in raw if key not in DEFAULTS["USER_IDENTITY"])
    if unknown:
        errors.append(
            CheckError(
                f"ENCRYPTION['USER_IDENTITY'] holds unknown keys: {', '.join(unknown)}. "
                f"The keys are: {', '.join(DEFAULTS['USER_IDENTITY'])}.",
                id="encryption_suite.E033",
            )
        )
    identity = resolve_user_identity(raw)

    scope = identity["SCOPE"]
    if scope not in USER_IDENTITY_SCOPES:
        errors.append(
            CheckError(
                f"ENCRYPTION['USER_IDENTITY']['SCOPE'] = {scope!r} is not a recognized scope. "
                f"Use one of: {', '.join(sorted(USER_IDENTITY_SCOPES))}.",
                id="encryption_suite.E029",
            )
        )

    count = identity["IP_PROXY_COUNT"]
    # bool is a subclass of int, and True would silently mean one proxy.
    if isinstance(count, bool) or not isinstance(count, int) or count < 0:
        errors.append(
            CheckError(
                f"ENCRYPTION['USER_IDENTITY']['IP_PROXY_COUNT'] = {count!r} is not an integer of 0 or more. "
                "Set it to the number of trusted proxies in front of this application.",
                id="encryption_suite.E030",
            )
        )

    for name, allowed in _IDENTITY_LISTS:
        items = identity[name]
        # A bare string would otherwise be read one character at a time, each
        # reported as an unknown item.
        if not isinstance(items, (list, tuple)):
            errors.append(
                CheckError(
                    f"ENCRYPTION['USER_IDENTITY']['{name}'] = {items!r} is not a list. "
                    f"List the items to keep, from: {', '.join(sorted(allowed))}.",
                    id="encryption_suite.E033",
                )
            )
            continue
        rejected = [item for item in items if not isinstance(item, str) or item not in allowed]
        if rejected:
            errors.append(
                CheckError(
                    f"ENCRYPTION['USER_IDENTITY']['{name}'] lists items it cannot hold: "
                    f"{', '.join(repr(item) for item in rejected)}. It may list: {', '.join(sorted(allowed))}.",
                    id="encryption_suite.E034",
                )
            )
        for pair in EXCLUSIVE_ITEMS:
            # A pair this list cannot hold at all is E034's to report.
            if all(item in items and item in allowed for item in pair):
                errors.append(
                    CheckError(
                        f"ENCRYPTION['USER_IDENTITY']['{name}'] lists both {pair[0]!r} and {pair[1]!r}, which "
                        "store one value two ways. List the one form this deployment records.",
                        id="encryption_suite.E035",
                    )
                )

    return errors


def _listed_encrypted_identity_items() -> list[str]:
    """The encrypted identity items ``KEY_LIFECYCLE_EVENTS`` lists, where it is readable."""
    raw = _configured("USER_IDENTITY")
    items = resolve_user_identity(raw)["KEY_LIFECYCLE_EVENTS"] if isinstance(raw, dict) else ()
    if not isinstance(items, (list, tuple)):
        return []
    return [item for item in (ITEM_ENCRYPTED_IP_ADDRESS, ITEM_ENCRYPTED_OS_USER) if item in items]


@register()
def check_log_aad_values(app_configs, **kwargs):
    """Require ``LOG_AAD_VALUES`` to be a real boolean.

    It governs disclosure, and a string like ``"False"`` is truthy — so a
    mistyped value fails in the one direction that writes personal data to the
    log. Rejecting anything but a bool keeps that from happening quietly.
    """
    value = _configured("LOG_AAD_VALUES")
    if isinstance(value, bool):
        return []
    return [
        CheckError(
            f"ENCRYPTION['LOG_AAD_VALUES'] = {value!r} is not a boolean. Set it to True or False; a string "
            "such as 'False' would read as on.",
            id="encryption_suite.E032",
        )
    ]


def _kms_blocks() -> dict:
    blocks = _configured("KMS_KEY_STORES")
    return blocks if isinstance(blocks, dict) else {}


def _env_entries() -> dict:
    entries = _configured("ENV_KEY_STORES")
    return entries if isinstance(entries, dict) else {}


#: Keys an ``ENV_KEY_STORES`` entry may carry. Anything else is a per-silo setting
#: (a strategy, a template), which a store holding one shared key cannot honor.
_ENV_ENTRY_KEYS = frozenset({"KEKS", "SHARED_KEK_ID"})


def _field_key_set_uses() -> dict[str, list[str]]:
    """Every key set a field declares, with the fields that declare it.

    The package's own identity tables count only where ``KEY_LIFECYCLE_EVENTS``
    lists an ``encrypted_*`` item: they declare system columns on every install, and
    a deployment that never encrypts them needs no store for them.
    """
    from django.apps import apps

    from .fields import EncryptedFileField, _EncryptedFieldMixin
    from .models import RecordedIPAddress, RecordedOSUser

    identity_tables = () if _listed_encrypted_identity_items() else (RecordedIPAddress, RecordedOSUser)
    uses: dict[str, list[str]] = {}
    for model in apps.get_models():
        if model._meta.proxy or model in identity_tables:
            continue
        for field in model._meta.local_fields:
            if isinstance(field, (_EncryptedFieldMixin, EncryptedFileField)):
                uses.setdefault(field.key_set, []).append(f"{model._meta.label}.{field.name}")
    return uses


def _shown(labels: list[str]) -> str:
    return ", ".join(labels[:5]) + (f", and {len(labels) - 5} more" if len(labels) > 5 else "")


@register()
def check_kms_settings(app_configs, **kwargs):
    """Validate ``KMS_KEY_STORES``, ``ENV_KEY_STORES`` and ``KEY_SETS``.

    Every unwrap routes by the name a row records, and nothing builds a store
    until a request first needs it, so a malformed block or a ``KEY_SETS``
    entry that names nothing would otherwise surface on some later request as a
    failure to reach a key. ``E037`` is a badly shaped store registry or
    template set, ``E038`` a key set that resolves to no store or adapter,
    ``E039`` a badly shaped or empty env store.
    Validators, so ``STARTUP_CHECK_WARN_ONLY`` leaves them alone.
    """
    from django.conf import settings

    from .adapters.key_stores.environment import parse_env_keks
    from .conf import (
        KEY_SET_MAX_LENGTH,
        SYSTEM_ADAPTER,
        SYSTEM_KEY_SET,
        is_valid_key_set,
        key_set_entries,
        resolve_store,
        store_problem,
    )

    if not getattr(settings, "ENCRYPTION", None):
        return []

    errors: list[CheckError] = []

    def shape(message, check_id="encryption_suite.E037", hint=None):
        errors.append(CheckError(message, hint=hint, id=check_id))

    kms_setting = _configured("KMS_KEY_STORES")
    if not isinstance(kms_setting, dict):
        shape(
            f"ENCRYPTION['KMS_KEY_STORES'] = {kms_setting!r} is not a dict. Set it to a dict of store name to block, "
            "each block a dict with at least ADAPTER."
        )
    env_setting = _configured("ENV_KEY_STORES")
    if not isinstance(env_setting, dict):
        shape(
            f"ENCRYPTION['ENV_KEY_STORES'] = {env_setting!r} is not a dict. Set it to a dict of store name to "
            'entry, each entry a dict such as {"KEKS": {1: "<base64>"}}.'
        )
    blocks, entries = _kms_blocks(), _env_entries()

    for name, block in blocks.items():
        if not isinstance(block, dict) or not block.get("ADAPTER"):
            shape(
                f"ENCRYPTION['KMS_KEY_STORES']['{name}'] has no ADAPTER. Each block is a dict naming its KMS "
                "adapter class in ADAPTER."
            )
    for name in set(blocks) & set(entries):
        shape(
            f"ENCRYPTION['KMS_KEY_STORES'] and ENCRYPTION['ENV_KEY_STORES'] both have a store named {name!r}. "
            "Store names are unique across both registries.",
            hint="Rename one of them.",
        )

    for name, entry in entries.items():
        label = f"ENCRYPTION['ENV_KEY_STORES']['{name}']"
        if not isinstance(entry, dict):
            shape(f'{label} is not a dict. Use {{"KEKS": {{1: "<base64>"}}}}.', "encryption_suite.E039")
            continue
        extra = sorted(set(entry) - _ENV_ENTRY_KEYS)
        if extra:
            shape(
                f"{label} has {', '.join(extra)}, which an env store cannot honor: it holds one shared key "
                "encryption key and has no per-silo setting.",
                hint="Remove them, or use a KMS_KEY_STORES block.",
            )
        versions, problem = parse_env_keks(entry.get("KEKS", {}), f"{label}['KEKS']")
        if problem:
            shape(
                f'{problem} KEKS maps positive integer versions to base64 key material: {{1: "<base64>"}}.',
                "encryption_suite.E039",
            )
        elif not versions:
            shape(
                f"{label}['KEKS'] is empty. An env store needs at least one version; the package never "
                "generates key material. Generate one with: openssl rand -base64 32",
                "encryption_suite.E039",
            )

    key_sets = _configured("KEY_SETS")
    if not isinstance(key_sets, dict):
        shape(
            f"ENCRYPTION['KEY_SETS'] = {key_sets!r} is not a dict. Set it to a dict of key set name to "
            '{"silo": <silo adapter path>, "key_store": <store name>}.'
        )
        key_sets = {}
    for name, entry in key_sets.items():
        if not is_valid_key_set(name):
            shape(
                f"ENCRYPTION['KEY_SETS'] has the key set {name!r}, which is not a lowercase identifier of at most "
                f"{KEY_SET_MAX_LENGTH} characters.",
                "encryption_suite.E038",
            )
            continue
        if not isinstance(entry, dict):
            shape(
                f"ENCRYPTION['KEY_SETS'][{name!r}] = {entry!r} is not a dict with a 'silo' and a 'key_store'.",
                "encryption_suite.E038",
            )
            continue
        adapter = entry.get("silo")
        if name == SYSTEM_KEY_SET:
            # Naming the system adapter is allowed, for consistency with the other entries.
            if adapter not in (None, SYSTEM_ADAPTER):
                shape(
                    f"ENCRYPTION['KEY_SETS']['system'] names the silo {adapter!r}. The built-in system key set "
                    "always has the package's system silo; leave 'silo' out or set it to \"system\".",
                    "encryption_suite.E038",
                )
        elif not adapter or not isinstance(adapter, str):
            shape(f"ENCRYPTION['KEY_SETS'][{name!r}] has no 'silo'.", "encryption_suite.E038")
        problem = store_problem(name)
        if problem:
            shape(problem, "encryption_suite.E038")

    # Every key set a field declares has a store. A key set no entry declares is reported
    # against the field (E041), so only declared ones are reported here.
    declared = key_set_entries()
    for key_set, labels in sorted(_field_key_set_uses().items()):
        if key_set not in declared or not is_valid_key_set(key_set) or key_set in key_sets:
            continue
        problem = store_problem(key_set)
        if problem:
            shape(f"{problem} Fields using it: {_shown(labels)}.", "encryption_suite.E038")

    # Per-silo strategies: every store a key set resolves to needs a template or a
    # map, and the templates' literal prefixes must not overlap across stores.
    in_use_stores = {resolve_store(key_set) for key_set in {*_field_key_set_uses(), *key_sets}}
    prefixes = {}
    for name, block in per_silo_blocks().items():
        options = block.get("OPTIONS") if isinstance(block.get("OPTIONS"), dict) else {}
        template, kek_map = options.get("KEK_TEMPLATE") or "", options.get("KEK_MAP") or {}
        label = f"ENCRYPTION['KMS_KEY_STORES']['{name}']['OPTIONS']"
        malformed = False
        if not isinstance(template, str):
            shape(f"{label}['KEK_TEMPLATE'] must be a string such as \"alias/team-{{silo_uid}}\".")
            malformed = True
        if not isinstance(kek_map, dict):
            shape(f"{label}['KEK_MAP'] must be a dict of silo uid to key identifier.")
            malformed = True
        if malformed:
            continue
        if name in in_use_stores and not template and not kek_map:
            shape(
                f"ENCRYPTION['KMS_KEY_STORES']['{name}'] uses PerSiloKekStrategy and serves a key set, but its "
                "OPTIONS have no KEK_TEMPLATE or KEK_MAP."
            )
        if prefix := template_prefix(template):
            prefixes[name] = prefix
    for name, prefix in prefixes.items():
        for other, other_prefix in prefixes.items():
            if name != other and other_prefix.startswith(prefix):
                shape(
                    f"ENCRYPTION['KMS_KEY_STORES'] has KEK_TEMPLATE prefixes that overlap: {prefix!r} (store "
                    f"{name!r}) is a prefix of {other_prefix!r} (store {other!r}). A key name would classify "
                    "as both stores.",
                    hint="Give each store a prefix that no other store's begins with.",
                )
    return errors


@register()
def check_system_fields_on_a_kms_store(app_configs, **kwargs):
    """Warn when a system key set field resolves to a KMS store.

    A system column is what signing in reads, so it needs a store that survives a
    KMS outage or a missing setting: an env store. ``KEY_SETS`` giving a system key
    set a KMS store is usually a login field on the wrong store.
    ``W058``.
    """
    from django.conf import settings

    from .conf import is_env_store, is_system_key_set, resolve_store

    if not getattr(settings, "ENCRYPTION", None):
        return []
    labels = []
    for key_set, each in sorted(_field_key_set_uses().items()):
        store = resolve_store(key_set) if is_system_key_set(key_set) else None
        if store is not None and not is_env_store(store):
            labels.extend(each)
    if not labels:
        return []
    return [
        CheckWarning(
            f"These system key set fields use a KMS store ({_shown(labels)}), so they stop working "
            "when the KMS is unreachable, sign-in among them.",
            hint="If they should survive a KMS outage, point the system key set at an env store in "
            "ENCRYPTION['KEY_SETS'].",
            id="encryption_suite.W058",
        )
    ]


@register()
def check_silo_data_lookup(app_configs, **kwargs):
    """Warn when ``reencrypt_data`` could not find a model's rows for a silo.

    A warning, not an error: a deployment that never rotates a data key should
    not fail to deploy over a command it does not run. The command itself
    refuses on the same finding, before any silo is fenced.
    """
    from django.conf import settings

    if not getattr(settings, "ENCRYPTION", None):
        return []
    from . import registry
    from .conf import SYSTEM_ADAPTER, adapter_path, key_set_names
    from .rotation_targets import encrypted_models, resolve_targets

    # Every adapter in use, with the models of its own key sets.
    unresolved = []
    try:
        seen = set()
        for key_set in key_set_names():
            path = adapter_path(key_set)
            if path is None or path == SYSTEM_ADAPTER or path in seen:
                continue
            seen.add(path)
            models = [
                entry for each in key_set_names() if adapter_path(each) == path for entry in encrypted_models(each)
            ]
            unresolved.extend(resolve_targets(registry.get_silo_adapter(key_set), models=models).unresolved)
    except Exception:
        # A silo adapter that cannot be built is reported by the construction
        # check; saying it twice helps nobody.
        return []
    finally:
        registry.reset()
    unresolved = list(dict.fromkeys(unresolved))
    if not unresolved:
        return []
    return [
        CheckWarning(
            "reencrypt_data cannot find which rows belong to a silo, so it will not rotate data keys, for: "
            + "; ".join(f"{label} ({why})" for label, why in unresolved)
            + ".",
            hint=(
                "Give each model one foreign key to the silo adapter's model_label model, or set "
                "supports_silo_data_lookup = True on the silo adapter and implement queryset_for_silo()."
            ),
            id="encryption_suite.W053",
        )
    ]


@register()
def check_auth_installed(app_configs, **kwargs):
    """Require ``django.contrib.auth``, which the ledger's user reference needs.

    ``settings.AUTH_USER_MODEL`` defaults to ``"auth.User"`` even where
    contrib.auth is not installed, so without this a deployment gets an opaque
    missing-FK-target failure instead of a sentence naming the requirement.
    """
    from django.apps import apps

    if apps.is_installed("django.contrib.auth"):
        return []
    return [
        CheckError(
            "django-encryption-suite records who acted on a key as a reference to "
            "AUTH_USER_MODEL, which requires 'django.contrib.auth' in INSTALLED_APPS.",
            id="encryption_suite.E031",
        )
    ]


@register()
def check_user_context_middleware(app_configs, **kwargs):
    """Warn when ``all_acts`` is set but the middleware cannot populate anything.

    Absent from ``MIDDLEWARE``, or listed above ``AuthenticationMiddleware``,
    are the same silent no-op: ``MIDDLEWARE`` is outermost-first, so a
    middleware ahead of the authentication one reads ``request.user`` before
    anything sets it and resolves nobody on every request. Every ambient write
    then records an empty column, which is indistinguishable from nobody having
    acted.

    A warning rather than an error, because a project may populate the context
    from its own setter instead of installing this middleware. Silent while both
    lists are empty: then the context is read for nothing, and nothing is lost.
    """
    from django.conf import settings

    raw = _configured("USER_IDENTITY")
    if not isinstance(raw, dict):
        return []  # E033's to report
    identity = resolve_user_identity(raw)
    if identity["SCOPE"] != SCOPE_ALL_ACTS or not (identity["KEY_LIFECYCLE_EVENTS"] or identity["LOGS"]):
        return []

    middleware = list(getattr(settings, "MIDDLEWARE", None) or [])
    hint = (
        f"Add {_USER_CONTEXT_MIDDLEWARE} to MIDDLEWARE, below "
        f"{_AUTHENTICATION_MIDDLEWARE}, or populate the context from your own setter."
    )
    if _USER_CONTEXT_MIDDLEWARE not in middleware:
        return [
            CheckWarning(
                f"ENCRYPTION['USER_IDENTITY']['SCOPE'] is 'all_acts' but {_USER_CONTEXT_MIDDLEWARE} "
                "is not in MIDDLEWARE, so no request-time act will record a user.",
                hint=hint,
                id="encryption_suite.W052",
            )
        ]
    # Compare positions only when the authentication middleware is present: a
    # project may authenticate some other way.
    if _AUTHENTICATION_MIDDLEWARE in middleware and middleware.index(_USER_CONTEXT_MIDDLEWARE) < middleware.index(
        _AUTHENTICATION_MIDDLEWARE
    ):
        return [
            CheckWarning(
                f"{_USER_CONTEXT_MIDDLEWARE} is listed above {_AUTHENTICATION_MIDDLEWARE} in "
                "MIDDLEWARE, so it never records a user.",
                hint=hint,
                id="encryption_suite.W052",
            )
        ]
    return []


@register()
def check_user_key_set_middleware(app_configs, **kwargs):
    """Warn when a key set reads the user context but the middleware cannot fill it.

    A key set bound to a silo adapter that resolves its silo from the user context
    fails every read that has no user, and every write the adapter cannot send to the
    row's owner. Absent from ``MIDDLEWARE``, or
    listed above ``AuthenticationMiddleware``, the middleware never sets one. A
    warning, as ``W052`` is, because a project may set the context from its own
    code, which this check cannot see.
    """
    from django.conf import settings

    from .conf import adapter_path, key_set_names
    from .user_context import _reads_user_context, user_key_set_bound

    if not isinstance(_configured("KEY_SETS"), dict) or not user_key_set_bound():
        return []
    bound = [name for name in key_set_names() if (path := adapter_path(name)) and _reads_user_context(path)]
    middleware = list(getattr(settings, "MIDDLEWARE", None) or [])
    if _USER_CONTEXT_MIDDLEWARE not in middleware:
        reason = f"{_USER_CONTEXT_MIDDLEWARE} is not in MIDDLEWARE"
    elif _AUTHENTICATION_MIDDLEWARE in middleware and middleware.index(_USER_CONTEXT_MIDDLEWARE) < middleware.index(
        _AUTHENTICATION_MIDDLEWARE
    ):
        reason = f"{_USER_CONTEXT_MIDDLEWARE} is listed above {_AUTHENTICATION_MIDDLEWARE} in MIDDLEWARE"
    else:
        return []
    return [
        CheckWarning(
            f"The key sets {_shown(bound)} read the acting user, but {reason}, so no request sets one.",
            hint=f"Add {_USER_CONTEXT_MIDDLEWARE} to MIDDLEWARE, below {_AUTHENTICATION_MIDDLEWARE}, "
            "or set the user from your own code with set_current_user().",
            id="encryption_suite.W060",
        )
    ]


@register()
def check_row_silo_owner(app_configs, **kwargs):
    """Warn where a key set writes to the row's silo with nobody acting, but a model's rows name no silo.

    The row's silo is found as ``reencrypt_data`` finds a silo's rows: the row is
    itself a silo, or it has one foreign key to the adapter's ``model_label``
    model. A model with none, or with more than one, has no owner to fall back
    to, so its writes need a current silo. A warning, because a project may only
    ever write such a model with someone acting.
    """
    if not isinstance(_configured("KEY_SETS"), dict):
        return []
    from . import registry
    from .conf import is_system_key_set, key_set_names
    from .rotation_targets import _silo_foreign_key, _silo_model, encrypted_models

    found = []
    try:
        for key_set in key_set_names():
            if is_system_key_set(key_set):
                continue
            adapter = registry.get_silo_adapter(key_set)
            silo_model = _silo_model(adapter)
            if not adapter.writes_to_row_silo_without_context or silo_model is None:
                continue
            for model, field_names, _files, _indexes in encrypted_models(key_set):
                if not field_names or model._meta.concrete_model is silo_model:
                    continue
                fk, why = _silo_foreign_key(model, silo_model)
                if fk is None:
                    found.append((key_set, model, why, silo_model._meta.label))
    except Exception:
        # A silo adapter that cannot be built is reported by the construction
        # check; saying it twice helps nobody.
        return []
    finally:
        registry.reset()
    return [
        CheckWarning(
            f"The key set {key_set!r} writes a value to the silo of the row's owner when nobody is acting, "
            f"but {model._meta.label} has {why}, so a row has no owner and a write with nobody acting "
            f"fails. Give {model._meta.label} exactly one foreign key to {silo_label}, set by server code, "
            f"or write it only while someone is acting.",
            obj=model,
            id="encryption_suite.W061",
        )
        for key_set, model, why, silo_label in found
    ]


@register()
def check_ordering_by_an_encrypted_field(app_configs, **kwargs):
    """Warn where an ordering declaration names an encrypted column.

    Ordering compares the stored values, which differ on every write, so the
    rows come back in an order that has nothing to do with the plaintext — and
    a list that is in *some* order is not something anyone looks at twice. A
    blind index does not help: it holds hashes, and hash order says nothing
    about value order.

    A warning rather than an error, because the declaration is not always the
    project's to change. A model from another package can carry
    ``Meta.ordering`` over a column this project chose to encrypt, and an error
    would leave a deploy that cannot be fixed from the project's own code.
    """
    from .fields import _CiphertextFieldMixin, _EncryptedFileFieldBase

    def encrypted_names(model):
        return {
            f.name for f in model._meta.get_fields() if isinstance(f, (_CiphertextFieldMixin, _EncryptedFileFieldBase))
        }

    def named(ordering, encrypted):
        return [term for term in ordering or () if isinstance(term, str) and term.lstrip("-") in encrypted]

    warnings: list[CheckWarning] = []

    def report(where, terms, obj):
        warnings.append(
            CheckWarning(
                f"{where} orders by encrypted {', '.join(repr(t) for t in terms)}. An encrypted field "
                "cannot be ordered on, even with a blind index.",
                obj=obj,
                id="encryption_suite.W055",
            )
        )

    from django.apps import apps

    for model in apps.get_models():
        if model._meta.proxy:
            continue
        encrypted = encrypted_names(model)
        if not encrypted:
            continue
        terms = named(model._meta.ordering, encrypted)
        if terms:
            report(f"{model._meta.label} Meta.ordering", terms, model)

    try:
        from django.contrib import admin
    except Exception:
        return warnings

    for model, model_admin in list(admin.site._registry.items()):
        encrypted = encrypted_names(model)
        if not encrypted:
            continue
        terms = named(model_admin.ordering, encrypted)
        if terms:
            report(
                f"{type(model_admin).__module__}.{type(model_admin).__name__}.ordering ({model._meta.label})",
                terms,
                model_admin,
            )
    return warnings


@register()
def check_table_level_rules_over_encrypted_columns(app_configs, **kwargs):
    """Warn where a table-level index or constraint names an encrypted column.

    ``Meta.unique_together``, a ``UniqueConstraint`` or an ``Index`` naming such
    a column promises something the database cannot deliver. A uniqueness rule
    can never fire, because every write stores a different value, so duplicates
    are accepted in silence — and an index containing a text column is rejected
    outright by MySQL and Oracle, where it fails the migration that adds it
    rather than at the query it was meant to serve.

    There is no composite equivalent to offer instead. A blind index holds one
    column's plaintext unique — ``unique=True`` on a system field,
    ``unique_in_silo=True`` on a silo field, and for a silo the guarantee is
    already per silo because the digest is keyed per silo. A rule spanning two
    columns, one of them encrypted, is not available at all: either the
    encrypted column carries the rule on its own, or the rule stays on columns
    stored in plaintext.

    A warning rather than an error, for the reason
    :func:`check_ordering_by_an_encrypted_field` gives: another package's model
    can carry such a declaration over a column this project chose to encrypt,
    and an error would leave a deploy nobody can fix from their own code.

    A rule naming only ``varchar_column=True`` columns is not reported. That
    keyword exists for a rule in a ``Meta`` the project cannot edit, so the
    project has already done the one thing open to it and a warning would repeat
    on every command with nothing left to act on.

    One warning per model, listing every rule it found there.
    """
    from django.apps import apps

    from .fields import _CiphertextFieldMixin, _EncryptedFileFieldBase

    warnings: list[CheckWarning] = []
    for model in apps.get_models():
        if model._meta.proxy:
            continue
        encrypted_fields = [
            f for f in model._meta.local_fields if isinstance(f, (_CiphertextFieldMixin, _EncryptedFileFieldBase))
        ]
        if not encrypted_fields:
            continue
        encrypted = {f.name for f in encrypted_fields}
        bounded = {f.name for f in encrypted_fields if getattr(f, "varchar_column", False)}

        # Every table-level rule, described the way an operator would find it in
        # the model. The digest columns this package contributes carry the rules
        # that do work, and are not encrypted columns, so they never match here.
        declared: list[tuple[str, tuple[str, ...]]] = [
            ("Meta.unique_together", tuple(group)) for group in (model._meta.unique_together or ())
        ]
        for constraint in model._meta.constraints:
            declared.append((f"Meta.constraints[{constraint.name!r}]", tuple(getattr(constraint, "fields", ()) or ())))
        for index in model._meta.indexes:
            declared.append((f"Meta.indexes[{index.name!r}]", tuple(getattr(index, "fields", ()) or ())))

        found: list[str] = []
        for where, names in declared:
            named = [name.lstrip("-") for name in names if name.lstrip("-") in encrypted]
            if not named or all(name in bounded for name in named):
                continue
            found.append(f"{where} ({', '.join(repr(n) for n in named)})")
        if not found:
            continue
        warnings.append(
            CheckWarning(
                f"{model._meta.label} has table-level rules over encrypted columns: {'; '.join(found)}. "
                "They never enforce uniqueness, and MySQL and Oracle reject the migration for an index.",
                hint=(
                    "For one column, use unique=True (system field) or unique_in_silo=True (silo field). "
                    "On another package's model, set varchar_column=True on the column."
                ),
                obj=model,
                id="encryption_suite.W056",
            )
        )
    return warnings


@register()
def check_encrypted_admins_use_mixin(app_configs, **kwargs):
    """Warn when a registered ``ModelAdmin`` renders a model with
    encrypted fields but does not mix in ``EncryptionAdminMixin``.

    Without the mixin, opening that admin page outside a silo context (e.g.
    the site-wide Django admin for a per-team app) reads each encrypted value
    through the field's descriptor with no silo to resolve. Each read fails
    with ``configuration_error``: a lenient read degrades to the fallback label
    and logs an error, a strict field raises, and the change form cannot save.
    """
    try:
        from django.contrib import admin
    except Exception:
        return []

    try:
        from .admin_mixins import EncryptionAdminMixin
        from .conf import is_system_key_set
        from .fields import EncryptedFileField, _EncryptedFieldMixin
    except Exception:
        return []

    warnings: list[CheckWarning] = []
    for model, model_admin in list(admin.site._registry.items()):
        # Only silo columns need a silo in the context to render; a model whose
        # encrypted columns are all in system key sets opens without one.
        encrypted = [
            f.name
            for f in model._meta.get_fields()
            if isinstance(f, (_EncryptedFieldMixin, EncryptedFileField)) and not is_system_key_set(f.key_set)
        ]
        if not encrypted:
            continue
        if isinstance(model_admin, EncryptionAdminMixin):
            continue
        warnings.append(
            CheckWarning(
                (
                    f"{type(model_admin).__module__}."
                    f"{type(model_admin).__name__} renders "
                    f"{model._meta.label} which has encrypted fields "
                    f"({', '.join(encrypted)}) without encryption_suite.admin_mixins.EncryptionAdminMixin, "
                    "so outside a silo context every encrypted value renders as the fallback label, logs an "
                    "error, and the change form cannot save."
                ),
                obj=model_admin,
                id="encryption_suite.W050",
            )
        )
    return warnings


@register()
def check_oidc_credential_config(app_configs, **kwargs):
    """Validate OIDC credential strategy config at startup.

    When CREDENTIAL_STRATEGY="oidc" is set in a ``KMS_KEY_STORES`` block's
    OPTIONS or KEK_PROVISIONER_OPTIONS, OIDC_SOURCE must be present and
    resolvable. Catches misconfig at ``manage.py check`` / runserver startup
    instead of at first encrypt/decrypt call. Every block is checked, and each
    message names its block.

    A builder check: resolving the source calls ``build_oidc_source``, the same
    construction the credential strategy performs, so it carries the same
    exposure to a missing optional SDK or a changed library as ``E003``-``E006``
    do. ``STARTUP_CHECK_WARN_ONLY`` downgrades it with them, to ``W001`` /
    ``W002``.
    """
    try:
        from django.conf import settings
    except Exception:
        return []

    try:
        from .adapters.credentials.oidc_sources import build_oidc_source
    except Exception:
        return []

    config = getattr(settings, "ENCRYPTION", {}) or {}
    blocks = config.get("KMS_KEY_STORES") or {}
    if not isinstance(blocks, dict):
        return []  # E037 reports the shape
    message_cls, id_prefix = _builder_severity()
    errors: list = []

    for kms_name, block in blocks.items():
        if not isinstance(block, dict):
            continue
        for options_key, code in (
            ("OPTIONS", "001"),
            ("KEK_PROVISIONER_OPTIONS", "002"),
        ):
            check_id = f"encryption_suite.{id_prefix}{code}"
            where = f"ENCRYPTION['KMS_KEY_STORES']['{kms_name}']['{options_key}']"
            options = block.get(options_key) or {}
            if options.get("CREDENTIAL_STRATEGY") != "oidc":
                continue

            source_name = options.get("OIDC_SOURCE")
            if not source_name:
                errors.append(
                    message_cls(
                        f"{where}['CREDENTIAL_STRATEGY'] is 'oidc' but OIDC_SOURCE is not set. Set it to a "
                        "supported source name (e.g. 'fly').",
                        id=check_id,
                    )
                )
                continue

            try:
                build_oidc_source(source_name, options.get("OIDC_SOURCE_OPTIONS", {}) or {})
            except Exception as exc:
                # Prefer the operator detail over the generic user-facing str(exc)
                # that log_and_raise_configuration_error raises — the check output
                # is operator-facing and should name the specific problem.
                reason = getattr(exc, "detail", None) or exc
                errors.append(
                    message_cls(
                        f"{where}['OIDC_SOURCE'] = '{source_name}' is not a valid OIDC token source: {reason}",
                        id=check_id,
                    )
                )

    return errors


def tagging_warnings(provisioner, kms_name: str) -> list:
    """Warn when ``TAGS`` is set on a provisioner that cannot write tags.

    A provider whose create-key API takes no metadata (Fly, HashiCorp,
    Infisical, IBM) silently discards them, which is the same defect class as a
    free-text option that no code reads: the operator configures something,
    nothing objects, and nothing happens. The harm depends on what the tags were
    for — a dropped cost tag misreports chargeback, a dropped ownership tag
    means every key this deployment creates lacks the tag an ABAC policy denies
    destruction without, so that policy either protects nothing or leaves the
    keys undeletable.

    ``Warning``, never ``Error``: this must reach the deploy log where an
    operator sees it, but a tag that cannot be written is not a broken
    deployment and must not stop one.

    Takes an already-constructed provisioner rather than reaching for one. It is
    called from :func:`check_kms_adapter_construction`, which has just built it —
    a second construction here would re-log a construction failure the other
    check has already reported, one line per attempt.
    """
    from .adapters.keks.provisioners import describe_tagging

    status = describe_tagging(provisioner)
    if not status.dropped:
        return []
    return [
        CheckWarning(
            (
                f"ENCRYPTION['KMS_KEY_STORES']['{kms_name}']['KEK_PROVISIONER_OPTIONS'] configures tags "
                f"({status.tag_count} TAGS, {status.defined_tag_namespace_count} DEFINED_TAGS "
                f"namespaces) but {type(provisioner).__name__} cannot tag the keys it creates. "
                "The tags will not be written."
            ),
            hint="Remove the tags, or use a provisioner that can tag keys (AWS, GCP, Azure, OCI).",
            id="encryption_suite.W051",
        )
    ]


@register()
def check_env_store_needed(app_configs, **kwargs):
    """Require a store for the system silo wherever the identity tables encrypt.

    The package's identity tables are encrypted under the system silo where
    ``KEY_LIFECYCLE_EVENTS`` lists an ``encrypted_*`` item, so the ``system`` key set
    must resolve to a store. Reported here so a deploy that left
    it out fails while someone is watching, rather than failing at the first
    sign-in of a running site. A field's own key set is ``E038``'s.

    Not downgradeable, and silent where ``E037``, ``E038`` or ``E039`` already
    speak: a malformed or empty store is theirs. ``E040``.
    """
    from django.conf import settings

    if not getattr(settings, "ENCRYPTION", None):
        return []

    from .conf import SYSTEM_KEY_SET, resolve_store

    identity_items = _listed_encrypted_identity_items()
    if not identity_items or resolve_store(SYSTEM_KEY_SET) is not None:
        return []
    return [
        CheckError(
            f"The USER_IDENTITY items ({', '.join(identity_items)}) are encrypted under the system silo, but "
            "ENCRYPTION['KEY_SETS'] gives it no store.",
            hint='Set ENV_KEY_STORES = {"login": {"KEKS": {1: "<base64>"}}} (generated with: openssl rand -base64 '
            '32) and KEY_SETS = {"system": {"key_store": "login"}}.',
            id="encryption_suite.E040",
        )
    ]


@register()
def check_kms_adapter_construction(app_configs, **kwargs):
    """Construct the configured adapters at startup so a construction-time
    misconfiguration fails ``manage.py check`` instead of the first
    encrypt/decrypt request.

    The registry builds these adapters lazily on first use, *outside* the
    engine's runtime error funnel — so a missing required option, an unknown
    credential strategy, an AAD-incompatible ``SharedKekStrategy`` pairing, or a
    bad/missing dotted path in any of the ``*_ADAPTER`` / ``CRYPTO_BACKEND``
    settings would otherwise surface only when a request first touches an
    encrypted field, where it 500s. Building them here turns every such
    :class:`~encryption_suite.exceptions.EncryptionConfigurationError` (and
    every ``ImportError`` from a bad dotted path) into a ``CheckError``.
    Construction is I/O-free — credential strategies defer all network/SDK work
    to first call — so this is safe at check time. The registry is reset
    afterwards so the check leaves no cached singletons behind.

    The KMS side runs once per ``KMS_KEY_STORES`` block, each message naming its
    block, and one block failing does not stop the next from being built — the
    same independence the registry gives them at runtime. The env key store takes
    no block and is left to ``E039``. The KMS adapter constructs its KEK
    strategy and credential strategy in its own ``__init__``, so a bad
    ``KEK_STRATEGY_ADAPTER`` path or an unknown ``CREDENTIAL_STRATEGY`` is
    reported under the KMS adapter's ``E003`` rather than a separate id.

    Also emits ``W051`` when the provisioner it builds cannot write the
    configured ``TAGS`` — reported from here rather than its own check so the
    provisioner is constructed once per check run instead of twice, which used to
    log a construction failure twice at deploy.

    Default IDs are ``E003`` (KMS adapter, incl. its KEK + credential
    strategies), ``E004`` (KEK provisioner), ``E005`` (crypto backend), and
    ``E006`` (silo adapter). Set
    ``ENCRYPTION["STARTUP_CHECK_WARN_ONLY"] = True`` to downgrade these to
    warnings so a deploy proceeds despite a misconfiguration — useful for
    exercising the request-time error handling against a known-bad config. In
    that mode the IDs become ``W003``-``W006``: the number is the condition, the
    letter is the severity. Leave it unset (the default) in normal operation so
    the deploy fails fast.
    """
    try:
        from django.conf import settings
    except Exception:
        return []

    config = getattr(settings, "ENCRYPTION", None)
    if not config:
        return []

    from . import registry
    from .exceptions import EncryptionError

    warn_only = bool(config.get("STARTUP_CHECK_WARN_ONLY"))
    message_cls, id_prefix = _builder_severity()
    hint = "STARTUP_CHECK_WARN_ONLY is set, so this is a warning, not an error." if warn_only else None

    blocks = config.get("KMS_KEY_STORES") or {}
    block_names = list(blocks) if isinstance(blocks, dict) else []
    key_sets = config.get("KEY_SETS") or {}
    builders = []
    for kms_name in block_names:
        if not isinstance(blocks[kms_name], dict):
            continue  # E037 reports the shape
        builders.append((lambda name=kms_name: registry.get_kms_adapter(name), "003", kms_name))
        builders.append((lambda name=kms_name: registry.get_kek_provisioner(name), "004", kms_name))
    builders.append((registry.get_crypto_backend, "005", ""))
    built_adapters = set()
    for key_set, entry in key_sets.items() if isinstance(key_sets, dict) else ():
        path = entry.get("silo") if isinstance(entry, dict) else None
        if path in built_adapters:
            continue
        built_adapters.add(path)
        builders.append((lambda key_set=key_set: registry.get_silo_adapter(key_set), "006", ""))

    errors: list = []
    try:
        for getter, code, kms_name in builders:
            try:
                built = getter()
                if code == "004":
                    # Inspected here, off the instance just built, so the
                    # provisioner is constructed exactly once per check run.
                    errors.extend(tagging_warnings(built, kms_name))
            except (EncryptionError, ImportError) as exc:
                # EncryptionError covers construction-time config failures,
                # including a bad/missing dotted path: the registry funnels
                # import_string failures through log_and_raise_configuration_error,
                # so the raised EncryptionConfigurationError's detail already
                # names the offending ENCRYPTION setting. ImportError stays caught
                # only as a defensive backstop for a missing optional SDK imported
                # inside an adapter's __init__ that was not itself routed through
                # the helper — without it that would escape as a raw traceback from
                # manage.py check at deploy.
                #
                # Prefer the operator detail (set by log_and_raise_configuration_error)
                # over the generic user-facing str(exc), since the check output is an
                # operator-facing surface that should name the specific fix.
                detail = getattr(exc, "detail", None) or str(exc)
                if kms_name:
                    detail = f"KMS_KEY_STORES['{kms_name}']: {detail}"
                errors.append(message_cls(detail, hint=hint, id=f"encryption_suite.{id_prefix}{code}"))
    finally:
        registry.reset()
    return errors


#: Storage backends that can be told to overwrite a file that already exists:
#: ``(class path, instance attribute, value that overwrites, OPTIONS key, value
#: that does not)``. Matched by name against the backend's MRO, so an optional
#: package is never imported and a project's subclass still matches. A backend
#: not listed here is not inspected.
_OVERWRITE_OPTIONS = (
    ("django.core.files.storage.filesystem.FileSystemStorage", "_allow_overwrite", True, "allow_overwrite", False),
    ("storages.backends.s3.S3Storage", "file_overwrite", True, "file_overwrite", False),
    ("storages.backends.gcloud.GoogleCloudStorage", "file_overwrite", True, "file_overwrite", False),
    ("storages.backends.azure_storage.AzureStorage", "overwrite_files", True, "overwrite_files", False),
    ("storages.backends.dropbox.DropboxStorage", "write_mode", "overwrite", "write_mode", "add"),
    ("storages.backends.ftp.FTPStorage", "allow_overwrite", True, "allow_overwrite", False),
)


def overwrite_warning(storage, field_labels):
    """``W057`` when *storage* is configured to overwrite an existing file, else ``None``."""
    paths = {f"{cls.__module__}.{cls.__qualname__}" for cls in type(storage).__mro__}
    for path, attribute, overwrites, option, safe in _OVERWRITE_OPTIONS:
        if path not in paths:
            continue
        if getattr(storage, attribute, None) != overwrites:
            return None
        return CheckWarning(
            f"The storage behind {', '.join(field_labels)} ({path}) has {option}={overwrites!r}, so a save "
            "replaces a file that already holds the name, leaving two rows on one blob.",
            hint=f'Set "{option}": {safe!r} in the OPTIONS of the STORAGES alias these fields use.',
            id="encryption_suite.W057",
        )
    return None


@register()
def check_encrypted_file_storage_overwrite(app_configs, **kwargs):
    """Warn where an encrypted file field's storage overwrites existing files.

    Django keeps a stored name unique by asking the backend whether it is taken
    and choosing another if so; a backend set to overwrite skips that and writes
    over whatever is there. Only the backends in ``_OVERWRITE_OPTIONS`` are
    inspected. A warning, because the default names are random and a clash is
    not expected; the setting is what decides whether one would be survived.
    """
    from django.apps import apps

    from .fields import _EncryptedFileFieldBase

    # Django resolves a callable storage when the field is built, so this is the
    # instance the field writes through, an alias's OPTIONS included.
    storages: dict[int, tuple[object, list[str]]] = {}
    for model in apps.get_models():
        if model._meta.proxy:
            continue
        for field in model._meta.local_fields:
            if isinstance(field, _EncryptedFileFieldBase):
                entry = storages.setdefault(id(field.storage), (field.storage, []))
                entry[1].append(f"{model._meta.label}.{field.name}")

    warnings = []
    for storage, labels in storages.values():
        warning = overwrite_warning(storage, labels)
        if warning is not None:
            warnings.append(warning)
    return warnings
