"""
Admin test console for django-encryption-suite.

The console runs encryption round-trips against an isolated test keyset and
reports what each layer — cryptographic engine, KMS, storage — is configured to
do. Its views are routed from ``DataEncryptionKeyAdmin.get_urls`` and take that
ModelAdmin as their first argument, so the URL names stay where operators and
templates already expect them.
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict

from django.contrib import messages
from django.http import HttpResponseRedirect
from django.shortcuts import render
from django.urls import reverse
from django.utils.translation import gettext_lazy as _

from . import test_console as _tc
from . import user_context
from ._internal import operator_error_text
from ._logging import get_logger
from .admin_access import PERM_RUN_TEST_CONSOLE, require_screen_access
from .conf import DEFAULT_KEY_SET, DEFAULTS, key_set_choices, key_set_label, resolve_store
from .exceptions import EncryptionError

# Carries this module's audit trail as well as its failures. Route it to an
# append-only sink to preserve the "every call logged" property against an
# admin-UI compromise.
logger = get_logger(__name__)

# Ordered console tests. Each entry: (id, label, components touched). The order
# is the fail-fast "run all" sequence and satisfies the progressive
# dependencies: a full field/file round-trip is only meaningful once its
# in-memory counterpart passes, and the storage probe follows the full-file
# layer. Component columns render in _CONSOLE_COMPONENTS order.
_CONSOLE_COMPONENTS = ("backend", "kms", "storage")
_CONSOLE_TESTS = (
    ("field_memory", _("Field (in memory)"), ("backend",)),
    ("file_memory", _("File (in memory)"), ("backend",)),
    ("field_full", _("Field (via KMS)"), ("backend", "kms")),
    ("file_full", _("File (via KMS)"), ("backend", "kms")),
    ("storage", _("File storage reachable (read-only)"), ("storage",)),
)
_CONSOLE_TEST_LABELS = {tid: label for tid, label, _ in _CONSOLE_TESTS}
_CONSOLE_TEST_COMPONENTS = {tid: comps for tid, _label, comps in _CONSOLE_TESTS}

# English names for the log, which is English-pinned — the labels above are
# translated for the screen and cannot be reused here.
_CONSOLE_TEST_LOG_NAMES = {
    "field_memory": "field in-memory",
    "file_memory": "file in-memory",
    "field_full": "field KMS",
    "file_full": "file KMS",
    "storage": "storage reachability",
}
_CONSOLE_TEST_IDS = frozenset(_CONSOLE_TEST_LABELS)

# Localized labels for the crypto backend's describe_config() keys (the backend
# emits stable identifiers; the admin owns presentation).
_CRYPTO_CONFIG_LABELS = {
    "cipher": _("Cipher"),
    "segment_size": _("File segment size (bytes)"),
    "field_aead": _("Field AEAD"),
    "file_streaming_aead": _("File streaming AEAD"),
}

#: ``CRYPTO_BACKEND_OPTIONS`` name -> the ``describe_config()`` key it feeds, so
#: an engine that could not be built labels its options the way a built one does.
_CRYPTO_OPTION_KEYS = {
    "AEAD": "cipher",
    "SEGMENT_SIZE": "segment_size",
    "AEAD_KEY_TEMPLATE": "field_aead",
    "STREAMING_AEAD_KEY_TEMPLATE": "file_streaming_aead",
}


def _compute_component_status(results: dict) -> dict:
    """Aggregate per-test results into a status for each component box.

    Tests are layered: each one's component tuple lists the layers it exercises,
    deepest last. A failure is therefore blamed on its deepest component only —
    a broken KMS fails ``field_full``, but the backend it also touches is not at
    fault and keeps whatever ``field_memory`` proved about it. Without that rule
    one KMS outage reds every box.

    A component is ``"pass"`` when a touching test passed and no test blaming it
    failed, ``"fail"`` when a test blaming it failed or when its only evidence is
    an unblamed failure (nothing has proved the layer healthy), and ``None`` when
    no touching test has run.
    """
    status: dict[str, str | None] = {}
    for comp in _CONSOLE_COMPONENTS:
        touching = [(tid, comps) for tid, _label, comps in _CONSOLE_TESTS if comp in comps and tid in results]
        if not touching:
            status[comp] = None
        elif any(results[tid]["status"] == "fail" and comps[-1] == comp for tid, comps in touching):
            status[comp] = "fail"
        elif any(results[tid]["status"] == "pass" for tid, _comps in touching):
            status[comp] = "pass"
        else:
            status[comp] = "fail"
    return status


def _operator_error_message(exc: Exception) -> str:
    """Return the message to show on the console for a failed action.

    The console's reader is an operator diagnosing their own KMS wiring, and the
    whole screen is infrastructure detail — adapter names, KEK resource names,
    storage locations. So a typed ``EncryptionError`` surfaces its operator
    ``detail`` here, followed by ``error_code=<slug>`` as the handle to grep the
    log with. This is the one surface in the package that does that; every other
    caller shows ``str(exc)``, the generic translated message.

    Falls back to that generic message when a class carries no detail. Any other
    exception yields a generic translated fallback — a raw exception string is a
    different question and is not opened here.
    """
    if isinstance(exc, EncryptionError):
        detail = getattr(exc, "detail", None)
        if detail:
            return f"{detail} error_code={exc.code}"
        return str(exc)
    return _("There was a problem. Check the server logs for details.")


# Simple in-process per-user rate limit for the test console. Not a substitute
# for an upstream WAF — just a hard brake against a runaway admin session.
_RATE_LIMIT_WINDOW_SECONDS = 60
_RATE_LIMIT_MAX_CALLS = 20
_rate_lock = threading.Lock()
_rate_state: dict[int, list[float]] = defaultdict(list)

# Guards the lazy sentinel enumeration check so it runs at most once per
# process. The no-DB portion runs in apps.ready; this flag gates the
# DB-enumerating portion that was moved out of init to silence Django's
# "database access during app initialization" warning.
_sentinel_check_lock = threading.Lock()
_sentinel_check_done = False


def _ensure_sentinel_check() -> None:
    """Run the DB-enumerating sentinel check once per process."""
    global _sentinel_check_done
    if _sentinel_check_done:
        return
    with _sentinel_check_lock:
        if _sentinel_check_done:
            return
        from .registry import silo_adapter_groups

        try:
            for adapter, _key_sets in silo_adapter_groups():
                _tc.assert_sentinel_not_producible(adapter)
        except _tc.ConsoleSentinelLeakError:
            raise
        except Exception as exc:
            from ._internal import operator_error_text

            logger.debug(
                "The test console could not check that no real silo can take its reserved UIDs, and "
                'will not try again in this process. detail="%s"',
                operator_error_text(exc),
            )
        _sentinel_check_done = True


def _rate_limit_check(user_id: int) -> bool:
    """Return True if the call is within budget; False if it should be rejected."""
    now = time.monotonic()
    cutoff = now - _RATE_LIMIT_WINDOW_SECONDS
    with _rate_lock:
        timestamps = [t for t in _rate_state[user_id] if t >= cutoff]
        if len(timestamps) >= _RATE_LIMIT_MAX_CALLS:
            _rate_state[user_id] = timestamps
            return False
        timestamps.append(now)
        _rate_state[user_id] = timestamps
        return True


def _require_console_access(request) -> None:
    """Reject anyone without the console permission.

    The console creates and deletes data encryption key rows, key encryption key
    rows, and a real key at the provider, so reaching it is a grant of its own —
    not an inference from whoever happens to hold the key models' permissions.
    """
    require_screen_access(request, PERM_RUN_TEST_CONSOLE)


def _log_console_action(request, message: str, *, key_stores, key_set=None, **fields) -> None:
    """Emit the console's audit line — what was asked for, sizes, never content.

    A sentence rather than a slug, like every other line in the package. This is
    the console's audit channel and every act on it was asked for by the person
    at the screen, so each line carries the identity tail naming them, the
    ``KMS_KEY_STORES`` name of each KMS it concerns and, when the act concerns one,
    its key set.
    """
    fields = {"key_stores": _kms_list(key_stores), **({"key_set": key_set} if key_set else {}), **fields}
    pairs = " ".join(f"{k}={v}" for k, v in fields.items())
    tail = user_context.identity_tail(user=request.user, user_ip=user_context.get_user_ip(request))
    # The tail goes in as its own argument: the logging filter recognizes an
    # identity tail by type, and an f-string would hand it a plain str.
    parts = [part for part in (pairs, tail) if part]
    logger.info("%s" + " %s" * len(parts), message, *parts)


def _summarize_tags(status, *, width: int = 70, value_width: int = 20) -> str:
    """Render configured tags as ``key=value`` pairs, trimmed to one line.

    The count alone answers "did my TAGS setting load", which is rarely the
    question — a wrong value is likelier than a missing one, and it is invisible
    until a key is created. So the values are shown, truncated twice: each value
    on its own, so one long value cannot crowd out the others, and the line as a
    whole, so a deployment with fifteen tags degrades to a trailing ``(+N)``
    instead of blowing out the panel.

    OCI's ``DEFINED_TAGS`` are nested namespaces rather than flat pairs, so they
    appear as ``namespace:*`` — enough to see which namespaces are in play
    without inventing a rendering for the tree beneath them.

    Deliberately free of translatable text: ``key=value``, ``…`` and ``(+2)``
    read the same in every language, so this adds no message catalog entries.
    """
    items = [f"{key}={_truncate(value, value_width)}" for key, value in status.tags]
    items += [f"{namespace}:*" for namespace in status.defined_tag_namespaces]
    shown: list[str] = []
    used = 0
    for item in items:
        cost = len(item) + (2 if shown else 0)
        if shown and used + cost > width:
            break
        shown.append(item)
        used += cost
    remainder = len(items) - len(shown)
    line = ", ".join(shown)
    return f"{line} (+{remainder})" if remainder else line


def _truncate(value: str, width: int) -> str:
    return value if len(value) <= width else f"{value[: width - 1]}…"


def _kms_list(names) -> str:
    """One KMS name, or several joined by commas, for a ``key_stores=`` log field."""
    return names if isinstance(names, str) else ",".join(names)


#: Session key holding the console's results: ``{"shared": {test_id: result},
#: "key_sets": {key_set: {test_id: result}}}``. Tests that touch the KMS are kept per
#: key set, so each key set shows its own last outcome; the rest are kept once.
_RESULTS_KEY = "_tc_results"


def _results_for(request, key_set: str) -> dict:
    """The stored results as the page shows them for *key_set*."""
    stored = request.session.get(_RESULTS_KEY) or {}
    return {**stored.get("shared", {}), **stored.get("key_sets", {}).get(key_set, {})}


def _store_results(request, key_set: str, results: dict, *, replace: bool = False) -> None:
    """Merge *results* into the session, each under the bucket its test belongs in.

    With *replace*, the shared bucket and *key_set*'s are cleared first, so a
    run-all cannot leave a stale outcome from an earlier run on a test it stopped
    short of. Other key sets' results are kept.
    """
    stored = request.session.get(_RESULTS_KEY) or {}
    shared = {} if replace else dict(stored.get("shared", {}))
    per_key_set = dict(stored.get("key_sets", {}))
    mine = {} if replace else dict(per_key_set.get(key_set, {}))
    for test_id, result in results.items():
        (mine if "kms" in _CONSOLE_TEST_COMPONENTS[test_id] else shared)[test_id] = result
    per_key_set[key_set] = mine
    request.session[_RESULTS_KEY] = {"shared": shared, "key_sets": per_key_set}


def _console_key_set(request) -> str:
    """The key set the console describes and tests: the session's pick, else ``default``, else the first choice.

    A pick that no longer names a choosable key set falls back rather than failing
    the page, since the console is where an operator sorts a configuration out.
    """
    names = [name for name, _store in key_set_choices()]
    picked = request.session.get("_tc_key_set")
    if picked in names:
        return picked
    return DEFAULT_KEY_SET if DEFAULT_KEY_SET in names else (names[0] if names else DEFAULT_KEY_SET)


def test_console_view(model_admin, request):
    _require_console_access(request)
    _ensure_sentinel_check()
    key_set = _console_key_set(request)
    key_store = resolve_store(key_set) or ""
    results = _results_for(request, key_set)
    comp_status = _compute_component_status(results)
    tests = [
        {
            "id": tid,
            "label": label,
            "components": comps,
            "status": results.get(tid, {}).get("status"),
            "detail": results.get(tid, {}).get("detail", ""),
        }
        for tid, label, comps in _CONSOLE_TESTS
    ]

    context = {
        **model_admin.admin_site.each_context(request),
        "title": _("Test Console"),
        "opts": model_admin.model._meta,
        "run_url": reverse("admin:encryption_suite_test_console_run"),
        "delete_url": reverse("admin:encryption_suite_test_console_delete"),
        "boxes": _build_boxes(comp_status, key_store),
        "key_set_choices": [
            {"key_set": name, "label": key_set_label(name, store)} for name, store in key_set_choices()
        ],
        "key_set": key_set,
        "tests": tests,
        "payload_preview": _tc.TEST_CONSOLE_PLAINTEXT.decode(),
    }
    return render(request, "admin/encryption_suite/test_console.html", context)


#: Stands in for a value only a built adapter can answer, when it could not be
#: built. Not a message — the run below the boxes is what explains a failure.
_UNRESOLVED = "—"


def _raw_config() -> dict:
    """The ``ENCRYPTION`` dict as written, without loading ``enc_settings``.

    The boxes describe the configuration, so they must still describe one that
    ``enc_settings`` would refuse to load.
    """
    from django.conf import settings

    return getattr(settings, "ENCRYPTION", {}) or {}


def _class_name_of(path: str) -> str:
    """The class name from a dotted path, as a built box shows it.

    A built box reports ``type(obj).__name__``, so a fallback that printed the
    whole path would read differently from the box beside it.
    """
    return path.rsplit(".", 1)[-1] if path else _UNRESOLVED


def _backend_id_of(path: str) -> str:
    """The engine's short name (``cryptography`` / ``tink``) from its dotted path.

    ``backend_id`` is a class attribute, so the class answers without being
    constructed — which is the case this is for. A path that cannot be imported
    has nothing to shorten, so it is shown as configured.
    """
    from django.utils.module_loading import import_string

    try:
        return import_string(path).backend_id or path
    except Exception:
        return path


def _log_unbuilt_panel(box: str, exc: BaseException, key_store: str) -> None:
    """Log an adapter the panel could not build, for anything not already typed."""
    if not isinstance(exc, EncryptionError):
        logger.error(
            'A status panel could not be built from the configured adapters. box=%s key_stores=%s detail="%s"',
            box,
            key_store,
            operator_error_text(exc),
        )


def _build_boxes(comp_status: dict, key_store: str) -> list[dict]:
    """Build the three component boxes: configuration values, colored by the tests.

    A box reports what is configured; the KMS box, the key store *key_store* the
    console is testing. Its heading color comes from
    ``comp_status`` — the stored results of the tests below — and never from
    anything this function does. When an adapter cannot be built, the box falls
    back to the values the settings state outright and shows ``—`` for the rest;
    the error itself belongs to the test run, which says it once.

    A line is ``(label, value)``.
    """
    boxes: list[dict] = []

    backend_lines = []
    try:
        from .registry import get_crypto_backend

        backend = get_crypto_backend()
        backend_lines = [(_("Backend"), backend.backend_id)]
        backend_lines += [(_CRYPTO_CONFIG_LABELS.get(k, k), v) for k, v in backend.describe_config()]
    except Exception as exc:
        _log_unbuilt_panel("backend", exc, key_store)
        config = _raw_config()
        path = config.get("CRYPTO_BACKEND", DEFAULTS["CRYPTO_BACKEND"])
        backend_lines = [(_("Backend"), _backend_id_of(path))]
        backend_lines += [
            (_CRYPTO_CONFIG_LABELS.get(_CRYPTO_OPTION_KEYS.get(key, key), key), value)
            for key, value in (config.get("CRYPTO_BACKEND_OPTIONS") or {}).items()
        ]
    boxes.append(
        {
            "key": "backend",
            "title": _("Cryptographic engine"),
            "lines": backend_lines,
            "status": comp_status["backend"],
        }
    )

    kms_lines = []
    try:
        from .adapters.keks.provisioners import describe_tagging
        from .adapters.keks.strategies import PerSiloKekStrategy, SharedKekStrategy
        from .conf import kms_block
        from .registry import (
            get_kek_provisioner,
            get_kek_strategy_adapter,
            get_kms_adapter,
        )

        kms = get_kms_adapter(key_store)
        strategy = get_kek_strategy_adapter(key_store)
        opts = kms_block(key_store)["OPTIONS"] or {}
        if isinstance(strategy, SharedKekStrategy):
            distribution = _("One shared KEK")
            key_name = opts.get("SHARED_KEK_ID") or "<unset>"
        elif isinstance(strategy, PerSiloKekStrategy):
            distribution = _("One KEK per silo")
            if opts.get("KEK_TEMPLATE"):
                key_name = opts["KEK_TEMPLATE"]
            elif opts.get("KEK_MAP"):
                key_name = f"{len(opts['KEK_MAP'])} mapped keys"
            else:
                key_name = "<unset>"
        else:
            distribution = strategy.describe()
            key_name = None
        kms_lines = [
            (_("Key store"), key_store),
            (_("Adapter"), type(kms).__name__),
        ]
        instance = kms.describe_instance()
        if instance:
            kms_lines.append((_("KMS instance"), instance))
        kms_lines.append((_("Key distribution"), distribution))
        if key_name:
            kms_lines.append((_("Key"), key_name))

        # Ownership is name-prefix based regardless of tags (owns_kek reads
        # the prefix), so report it independently. The no-prefix case is the
        # one worth surfacing: deletion is refused for every key, which an
        # operator otherwise discovers only when a deletion refuses.
        owner_prefix = kms.owner_prefix()
        kms_lines.append(
            (
                _("Ownership"),
                (
                    _("Name prefix: %(prefix)s") % {"prefix": owner_prefix}
                    if owner_prefix
                    else _("Not provable — key deletion is refused")
                ),
            )
        )

        tagging = describe_tagging(get_kek_provisioner(key_store))
        if tagging.configured:
            count = tagging.tag_count + tagging.defined_tag_namespace_count
            kms_lines.append(
                (
                    _("Tags"),
                    (
                        _summarize_tags(tagging)
                        if tagging.supported
                        # When nothing will be written, the warning is the
                        # message; the values themselves are beside the point.
                        else _("%(count)s configured — not written by this provisioner") % {"count": count}
                    ),
                )
            )
    except Exception as exc:
        _log_unbuilt_panel("kms", exc, key_store)
        from .conf import kms_block

        block = kms_block(key_store) or {}
        opts = block.get("OPTIONS") or {}
        # Same rows, in the same order, as a built box — with a dash wherever
        # only the adapter could answer.
        kms_lines = [
            (_("Key store"), key_store),
            (_("Adapter"), _class_name_of(block.get("ADAPTER") or "")),
            (_("Key distribution"), _UNRESOLVED),
        ]
        if opts.get("SHARED_KEK_ID"):
            kms_lines.append((_("Key"), opts["SHARED_KEK_ID"]))
        elif opts.get("KEK_TEMPLATE"):
            kms_lines.append((_("Key"), opts["KEK_TEMPLATE"]))
        elif opts.get("KEK_MAP"):
            kms_lines.append((_("Key"), f"{len(opts['KEK_MAP'])} mapped keys"))
        kms_lines.append((_("Ownership"), _UNRESOLVED))
    boxes.append(
        {
            "key": "kms",
            "title": _("Key management system (KMS)"),
            "lines": kms_lines,
            "status": comp_status["kms"],
        }
    )

    storage_lines = []
    try:
        info = _tc.describe_storage_target()
        storage_lines = [(_("Backend"), info["backend"])]
        if info["location"]:
            storage_lines.append((_("Location"), info["location"]))
    except Exception as exc:
        _log_unbuilt_panel("storage", exc, key_store)
        from django.conf import settings

        alias = _raw_config().get("STORAGE_ALIAS", DEFAULTS["STORAGE_ALIAS"])
        configured = (getattr(settings, "STORAGES", {}) or {}).get(alias) or {}
        storage_lines = [(_("Backend"), _class_name_of(configured.get("BACKEND", "")))]
    boxes.append(
        {
            "key": "storage",
            "title": _("Storage"),
            "lines": storage_lines,
            "status": comp_status["storage"],
        }
    )

    return boxes


def test_console_run_view(model_admin, request):
    _require_console_access(request)
    _ensure_sentinel_check()
    console_url = reverse("admin:encryption_suite_test_console")
    if request.method != "POST":
        return HttpResponseRedirect(console_url)

    from .conf import kms_names

    if request.POST.get("reset"):
        request.session.pop(_RESULTS_KEY, None)
        _log_console_action(request, "Cleared test results.", key_stores=kms_names())
        messages.info(request, _("Test results cleared."))
        return HttpResponseRedirect(console_url)

    # The pick is kept per session; each key set keeps its own results, so picking
    # another one shows that key set's last outcome rather than clearing anything.
    picked = request.POST.get("key_set")
    if picked in [name for name, _store in key_set_choices()]:
        request.session["_tc_key_set"] = picked
    # The selector submits the form on its own, with no button pressed: that is a
    # pick, not a run.
    if not (request.POST.get("run_all") or request.POST.get("test")):
        return HttpResponseRedirect(console_url)
    key_set = _console_key_set(request)
    key_store = resolve_store(key_set) or ""

    if not _rate_limit_check(request.user.pk):
        messages.error(request, _("Rate limit exceeded."))
        _log_console_action(
            request, "Rate limit reached; the request was rejected.", key_stores=key_store, key_set=key_set
        )
        return HttpResponseRedirect(console_url)

    # Run all: fail-fast smoke test. Start from a clean slate so a prior
    # failure can't leave a stale green on an untouched component.
    if request.POST.get("run_all"):
        results: dict = {}
        failed = None
        for tid, label, _comps in _CONSOLE_TESTS:
            passed, detail = _safe_run(request, tid, key_set)
            results[tid] = {"status": "pass" if passed else "fail", "detail": detail}
            if not passed:
                failed = (label, detail)
                break
        _store_results(request, key_set, results, replace=True)
        if failed is None:
            messages.success(request, _("All tests passed."))
        else:
            messages.error(
                request,
                _("Stopped at '%(label)s': %(detail)s") % {"label": failed[0], "detail": failed[1]},
            )
        return HttpResponseRedirect(console_url)

    # Single test.
    test_id = request.POST.get("test")
    if test_id not in _CONSOLE_TEST_IDS:
        messages.error(request, _("Unknown test."))
        return HttpResponseRedirect(console_url)

    passed, detail = _safe_run(request, test_id, key_set)
    _store_results(request, key_set, {test_id: {"status": "pass" if passed else "fail", "detail": detail}})
    label = _CONSOLE_TEST_LABELS[test_id]
    if passed:
        messages.success(request, _("%(label)s: passed. %(detail)s") % {"label": label, "detail": detail})
    else:
        messages.error(request, _("%(label)s: failed. %(detail)s") % {"label": label, "detail": detail})
    return HttpResponseRedirect(console_url)


def _safe_run(request, test_id: str, key_set: str) -> tuple[bool, str]:
    """Run one test against *key_set* and its store; return ``(passed, user_message)``.

    The message carries the operator channel (see
    :func:`_operator_error_message`) — this screen exists to say what broke. It
    is coerced to ``str`` so the session (JSON) can store it.
    """
    name = _CONSOLE_TEST_LOG_NAMES[test_id]
    key_store = resolve_store(key_set) or ""
    _log_console_action(request, f"Ran {name} test.", key_stores=key_store, key_set=key_set)
    try:
        passed, detail = _run_single_test(request, test_id, key_set)
        if not passed:
            _log_console_action(request, f"The {name} test reported a failure.", key_stores=key_store, key_set=key_set)
        return passed, str(detail)
    except EncryptionError as exc:
        # The raise site logged the detail in English, but it had no idea it was
        # running inside the console, so its line carries no test id. One line
        # here joins the two.
        logger.error(
            'A console test failed. test=%s key_stores=%s key_set=%s error_code=%s detail="%s"',
            test_id,
            key_store,
            key_set,
            exc.code,
            operator_error_text(exc),
        )
        _log_console_action(
            request,
            f"The {name} test could not complete.",
            key_stores=key_store,
            key_set=key_set,
            error_code=exc.code,
        )
        return False, _operator_error_message(exc)
    except Exception as exc:
        logger.error(
            'A console test raised instead of returning a result. test=%s key_stores=%s key_set=%s detail="%s"',
            test_id,
            key_store,
            key_set,
            operator_error_text(exc),
        )
        _log_console_action(
            request,
            f"The {name} test could not complete.",
            key_stores=key_store,
            key_set=key_set,
            error=type(exc).__name__,
        )
        return False, _operator_error_message(exc)


def _run_single_test(request, test_id: str, key_set: str) -> tuple[bool, str]:
    """Execute one console test on *key_set*; return ``(passed, user_message)``."""
    from .registry import get_kek_provisioner, get_kms_adapter

    key_store = resolve_store(key_set)

    plaintext = _tc.TEST_CONSOLE_PLAINTEXT

    def _roundtrip(result):
        ok = result["matches"]
        return ok, _("Encrypt/decrypt matched.") if ok else _("Encrypt/decrypt mismatch.")

    if test_id == "field_memory":
        return _roundtrip(_tc.ephemeral_aead_roundtrip(plaintext))
    if test_id == "file_memory":
        return _roundtrip(_tc.ephemeral_streaming_roundtrip(plaintext))
    # The console holds a request user, and an internal resolve returns nobody
    # under the default scope, so the identity is threaded rather than resolved.
    identity = {"user": request.user, "user_ip": user_context.get_user_ip(request)}
    if test_id == "field_full":
        return _roundtrip(
            _tc.full_aead_roundtrip(
                get_kms_adapter(key_store), get_kek_provisioner(key_store), plaintext, key_set=key_set, **identity
            )
        )
    if test_id == "file_full":
        return _roundtrip(
            _tc.full_streaming_roundtrip(
                get_kms_adapter(key_store), get_kek_provisioner(key_store), plaintext, key_set=key_set, **identity
            )
        )
    if test_id == "storage":
        _tc.storage_reachable()
        return True, _("Backend reachable.")
    raise ValueError(f"Unknown test {test_id!r}")


def test_console_delete_view(model_admin, request):
    _require_console_access(request)
    _ensure_sentinel_check()
    if request.method != "POST":
        return HttpResponseRedirect(reverse("admin:encryption_suite_test_console"))
    try:
        result = _tc.delete_test_key()
    except Exception as exc:
        key_stores = _tc.test_key_kms_names()
        logger.error(
            'The test key could not be deleted. key_stores=%s detail="%s"',
            _kms_list(key_stores),
            operator_error_text(exc),
        )
        messages.error(request, _operator_error_message(exc))
        _log_console_action(request, "Test key deletion failed.", key_stores=key_stores, error=type(exc).__name__)
        return HttpResponseRedirect(reverse("admin:encryption_suite_test_console"))

    keks = result["keks"]
    deleted = [k for k in keks if k["deleted"]]
    errored = [k for k in keks if k["error"]]
    retained = [k for k in keks if not k["deleted"] and not k["error"]]

    # One message about the DEK rows, then one about the KEKs — no overlap.
    if result["deks_deleted"]:
        messages.success(request, _("Deleted %(n)d test DEK(s).") % {"n": result["deks_deleted"]})
    else:
        messages.info(request, _("No test key rows to delete."))
    if deleted:
        messages.success(request, _("Deleted %(n)d test KEK(s).") % {"n": len(deleted)})
    if errored:
        for k in errored:
            logger.error(
                "A test key encryption key could not be deleted; it still exists at the provider "
                'and still costs money. key_stores=%s kek="%s" detail="%s"',
                k["key_store"],
                k["kek_resource_name"],
                k["error"],
            )
        messages.warning(request, _("%(n)d test KEK(s) could not be deleted — see the log.") % {"n": len(errored)})
    if retained:
        from .deletion import format_retain_reasons

        # Split by what happened to the record: a refused key whose record went
        # reads differently from one whose record is still the record of a live key.
        forgotten = [k for k in retained if k["record_deleted"]]
        kept = [k for k in retained if not k["record_deleted"]]
        if forgotten:
            reasons = format_retain_reasons(k["retained_reason"] for k in forgotten)
            messages.info(
                request,
                _("Retained %(n)d test KEK(s), not deleted (%(reasons)s); deleted their records.")
                % {"n": len(forgotten), "reasons": reasons},
            )
        if kept:
            reasons = format_retain_reasons(k["retained_reason"] for k in kept)
            messages.info(
                request,
                _("Retained %(n)d test KEK(s), not deleted (%(reasons)s).") % {"n": len(kept), "reasons": reasons},
            )
    _log_console_action(
        request,
        "Deleted test key(s).",
        key_stores=result["key_stores"],
        deks_deleted=result["deks_deleted"],
        deks_retained=result["deks_retained"],
        keks_deleted=len(deleted),
        keks_retained=len(retained),
        kek_records_deleted=sum(1 for k in keks if k["record_deleted"]),
    )
    return HttpResponseRedirect(reverse("admin:encryption_suite_test_console"))
