"""Static guards for the package's error-handling and layering conventions.

The conventions are written down in the package docs, and every one of them has
been broken at least once by code that read as reasonable in isolation — a
provisioner raising a typed error the caller never logged, an adapter reaching
back into the registry that built it, a funnel re-raising with a stack trace
into package internals that wrongly implicates the consuming project.

These are source-level checks rather than behavioral ones on purpose: they fire
when the offending line is written, name the file, and cost nothing to run. Each
allow-list below is a documented exception, not a suppression — adding to one
should require the same argument the original entry made.

What is deliberately *not* here: a judge of message quality. Every heuristic
tried for it ("names a CONSTANT_CASE option", "is a full sentence") flagged
messages that are perfectly actionable — "azure-identity is required for
AzureManagedIdentityStrategy. Install django-encryption-suite[azure]." names no
option and needs none. Whether a message helps is a review question. What a test
can enforce is that one exists, carries its slug, and is documented, which
``test_error_codes.py`` already does.
"""

from __future__ import annotations

import ast
import pathlib

PACKAGE = pathlib.Path(__file__).resolve().parents[1] / "src" / "encryption_suite"

# There is no traceback allow-list, deliberately. There used to be one, holding
# admin.py and apps.py, justified as "both sites reach it only after excluding
# EncryptionError". That was true of admin.py and false of apps.py, whose
# SILO_AUTO_KEY_CREATION handler caught every exception — so a KekNotProvisionedError,
# already classified and already logged in one clean line at the raise site, was
# re-logged with a full stack trace through package internals. Found live on the
# Infisical bench 2026-08-03. The exemption existed for a reason that had quietly
# stopped applying to one of its two members, which is the failure mode an
# allow-list has by design. An unexpected exception still deserves a loud, greppable
# line — it does not need a traceback to get one.

# The local dev adapter is the one adapter that needs a collaborator the registry
# owns (the crypto backend, to build its in-process KEK). It is dev-only, never
# talks to a provider, and the import is deferred to first use rather than
# construction. Every other adapter receives what it needs.
_REGISTRY_IMPORT_ALLOWED = {"local.py"}


def _sources(root: pathlib.Path) -> dict[pathlib.Path, str]:
    return {p: p.read_text(encoding="utf-8") for p in root.rglob("*.py")}


def _trees(root: pathlib.Path):
    for path, text in _sources(root).items():
        yield path, ast.parse(text)


def _calls(tree: ast.AST):
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            yield node


def _error_class_names() -> set[str]:
    tree = ast.parse((PACKAGE / "exceptions.py").read_text(encoding="utf-8"))
    return {node.name for node in ast.walk(tree) if isinstance(node, ast.ClassDef) and node.name.endswith("Error")}


def _attr_path(node: ast.AST) -> str:
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


class TestNoTracebacks:
    """A stack trace into package internals is noise that implicates the wrong code.

    An operator reading it sees frames from a dependency they do not maintain,
    for a failure the package already classified and can describe in one line.
    """

    def test_no_logger_exception_anywhere(self):
        offenders = []
        for path, tree in _trees(PACKAGE):
            for call in _calls(tree):
                if _attr_path(call.func).endswith("logger.exception"):
                    offenders.append(f"{path.name}:{call.lineno}")
        assert not offenders, (
            f"logger.exception logs a traceback: {offenders}. Log one clean line with the error's "
            "slug and operator_error_text(exc) instead, or route the failure through a funnel."
        )

    def test_no_exc_info_keyword(self):
        offenders = []
        for path, tree in _trees(PACKAGE):
            for call in _calls(tree):
                for keyword in call.keywords:
                    if keyword.arg == "exc_info":
                        offenders.append(f"{path.name}:{call.lineno}")
        assert not offenders, f"exc_info attaches a traceback to the log record: {offenders}"

    def test_no_traceback_module_use(self):
        offenders = [path.name for path, text in _sources(PACKAGE).items() if "import traceback" in text]
        assert not offenders, f"the traceback module is imported in: {offenders}"


class TestCaughtExceptionsAreLoggedThroughTheHelper:
    """A caught exception must reach a log line via ``operator_error_text``.

    The other half of the apps.py regression: alongside the traceback, the
    handler interpolated the exception object straight into the message. That
    loses the two things an operator needs. ``str(exc)`` on an ``EncryptionError``
    is the *translated, generic* user message, so under a non-English request
    locale the log line is neither English nor specific — and the stable
    ``[slug]`` never appears, which is the language-neutral handle alerting greps
    for. ``operator_error_text`` prefers ``exc.detail``, pins English, and
    prepends the slug.

    Scope is deliberately narrow. Only the name bound by ``except ... as <name>``,
    and only the operator-facing levels — ``logger.debug`` is exempt, because it
    is read by someone actively debugging this package rather than by an operator
    watching production, and the defensive "check skipped" paths use it to say why
    they gave up. Passing the exception to a ``log_and_raise_*`` helper (as the
    message text or as ``cause=``) is the documented funnel and is what builds
    ``exc.detail`` in the first place.
    """

    #: Levels an operator actually reads. ``debug`` is deliberately absent.
    _OPERATOR_LEVELS = ("error", "warning", "info", "critical", "exception")

    @staticmethod
    def _bare_exception_args(call: ast.Call, bound: str):
        """Yield positional args of *call* that reference *bound* unwrapped."""
        for arg in call.args:
            if isinstance(arg, ast.Name) and arg.id == bound:
                yield arg
            elif isinstance(arg, ast.JoinedStr):
                for piece in ast.walk(arg):
                    if isinstance(piece, ast.Name) and piece.id == bound:
                        yield piece

    def test_log_calls_do_not_interpolate_the_exception_directly(self):
        offenders = []
        for path, tree in _trees(PACKAGE):
            for handler in (n for n in ast.walk(tree) if isinstance(n, ast.ExceptHandler)):
                if not handler.name:
                    continue
                for call in (n for n in ast.walk(handler) if isinstance(n, ast.Call)):
                    func = _attr_path(call.func)
                    if func.rsplit(".", 1)[-1] not in self._OPERATOR_LEVELS or "logger" not in func:
                        continue
                    # operator_error_text(exc) is the sanctioned wrapper, so a
                    # reference inside one is not a bare reference.
                    wrapped = {
                        id(inner)
                        for outer in ast.walk(call)
                        if isinstance(outer, ast.Call) and _attr_path(outer.func).endswith("operator_error_text")
                        for inner in ast.walk(outer)
                    }
                    for bad in self._bare_exception_args(call, handler.name):
                        if id(bad) not in wrapped:
                            offenders.append(f"{path.name}:{call.lineno}")
        assert not sorted(set(offenders)), (
            f"log calls interpolating a caught exception directly: {sorted(set(offenders))}. "
            "Wrap it in operator_error_text(exc) so the line stays English and carries the "
            "error's [slug], rather than a translated generic message."
        )


class TestAdaptersDoNotReachTheRegistry:
    """Adapters are built *by* the registry and handed what they need.

    Reaching back for a singleton inverts that: it hides a dependency the
    constructor should declare, makes the adapter untestable without settings,
    and lets a swap in one place silently disagree with another.
    """

    def test_no_registry_import_in_adapters(self):
        offenders = []
        for path, text in _sources(PACKAGE / "adapters").items():
            if path.name in _REGISTRY_IMPORT_ALLOWED:
                continue
            if "registry import" in text or "from ...registry" in text or "from ..registry" in text:
                offenders.append(path.name)
        assert not offenders, (
            f"adapters reaching into the registry: {offenders}. Take the collaborator as a "
            "constructor argument instead — the registry is what builds these."
        )


class TestConstructionErrorsGoThroughTheHelper:
    """Construction runs in the registry singletons, outside every runtime funnel.

    Nothing translates or logs a bare raise there, so it escapes untyped and
    unlogged — as a 500 on some later request, far from the settings that caused
    it. ``log_and_raise_configuration_error`` is what makes it a deploy-time
    ``CheckError`` naming the option.
    """

    def test_adapters_never_raise_the_configuration_error_directly(self):
        offenders = []
        for path, tree in _trees(PACKAGE / "adapters"):
            for node in ast.walk(tree):
                if not isinstance(node, ast.Raise) or node.exc is None:
                    continue
                raised = node.exc.func if isinstance(node.exc, ast.Call) else node.exc
                if _attr_path(raised).endswith("EncryptionConfigurationError"):
                    offenders.append(f"{path.name}:{node.lineno}")
        assert not offenders, (
            f"direct EncryptionConfigurationError raises: {offenders}. Call "
            "log_and_raise_configuration_error(logger, message) so the detail is logged once with "
            "its slug and str(exc) stays a generic, translated, user-safe message."
        )


class TestUserMessagesAreGeneric:
    """``str(exc)`` is the user channel; ``detail`` is the operator channel.

    Nothing in the class hierarchy enforces the split — the message is whatever
    the construction site passes — so this test and the rule in ``CLAUDE.md`` are
    the only things holding it. Eight sites had already drifted before it
    existed, putting a field label, a row pk, AAD column values, a storage path,
    and a raw provider error into a string that a consuming view renders and the
    DRF handler serializes.

    It checks **construction**, not ``raise``: ``safe_queries`` builds two of
    these and returns them rather than raising, so scanning raise statements
    misses a quarter of the surface.

    The map is per class, not one flat allow-list. A flat list would accept
    ``EncryptedFieldEncryptionError(GENERIC_DECRYPT_FAILED_USER_MESSAGE)`` — a
    write reporting itself as a failed read — which is exactly the direction
    confusion the wording was changed to remove. It also doubles as the readable
    index of which class says what, which is the thing a reviewer actually wants
    and which no single constant can show.

    Its remaining limit: it enforces the mapping, not that the mapping is right.
    Only review does that.
    """

    # What each class may say, by constant name. A literal is rejected even when
    # its text is approved: the names are what makes the user-facing surface
    # readable in one place.
    _UNAVAILABLE = "GENERIC_ENCRYPT_DECRYPT_UNAVAILABLE_MESSAGE"
    _ENCRYPT_FAILED = "GENERIC_ENCRYPT_FAILED_USER_MESSAGE"
    _DECRYPT_FAILED = "GENERIC_DECRYPT_FAILED_USER_MESSAGE"

    ALLOWED_BY_CLASS = {
        # The keys cannot be used at all — whatever the reason. Reachable from a
        # read as well as a write, which is why the message names both.
        "EncryptionConfigurationError": {_UNAVAILABLE},
        "MissingDekError": {_UNAVAILABLE},
        "KekNotProvisionedError": {_UNAVAILABLE},
        "KekDeleteError": {_UNAVAILABLE},
        "SiloEnumerationError": {_UNAVAILABLE},
        "KekEnumerationError": {_UNAVAILABLE},
        "KekDeletionRecordError": {_UNAVAILABLE},
        "KeyIdentityImmutableError": {_UNAVAILABLE},
        "KmsProviderMismatchError": {_UNAVAILABLE},
        "CryptoBackendMismatchError": {_UNAVAILABLE},
        "KekUnavailableError": {_UNAVAILABLE},
        "DekDeletionScheduledError": {_UNAVAILABLE},
        "DekDeletedError": {_UNAVAILABLE},
        # A rotation's fence. It clears on its own, but a run can also leave it up
        # until an operator acts, so the message promises nothing: retrying is
        # decided from the type and its code.
        "DekReencryptionInProgressError": {_UNAVAILABLE},
        # The keys were fine and the operation failed. Field and file share each
        # string; the direction is what a user can act on, not the column kind.
        "EncryptedFieldEncryptionError": {_ENCRYPT_FAILED},
        "EncryptedFileEncryptionError": {_ENCRYPT_FAILED},
        # A caller handing ciphertext back to encrypt(). A developer's mistake,
        # but a user reaching it sees only that a write failed, which is the one
        # thing they could act on.
        "FieldAlreadyEncryptedError": {_ENCRYPT_FAILED},
        "EncryptedFieldDecryptionError": {_DECRYPT_FAILED},
        "EncryptedFileDecryptionError": {_DECRYPT_FAILED},
        # The one class spanning both directions: write and exists report an
        # encryption failure, read a decryption one. Django calls exists() from
        # the save path, which is why it sits on the write side.
        "EncryptedFileStorageError": {_ENCRYPT_FAILED, _DECRYPT_FAILED},
    }

    APPROVED_NAMES = {_UNAVAILABLE, _ENCRYPT_FAILED, _DECRYPT_FAILED}

    # KekPendingDeletionError's first positional argument is the *detail*: its
    # own __init__ passes the generic message to super(). It is the one class
    # that already did what this rule generalizes.
    DETAIL_FIRST = {"KekPendingDeletionError"}

    def _error_class_names(self) -> set[str]:
        return _error_class_names()

    def test_every_concrete_class_is_mapped(self):
        """A new error class must declare what it may say, or this fails.

        Without it the mapping silently stops covering the surface: an unmapped
        class is skipped by the construction check below rather than flagged.
        """
        concrete = self._error_class_names() - {"EncryptionError"} - self.DETAIL_FIRST
        unmapped = sorted(concrete - set(self.ALLOWED_BY_CLASS))
        stale = sorted(set(self.ALLOWED_BY_CLASS) - concrete)
        assert not unmapped, (
            f"error classes with no approved message: {unmapped}. Add each to ALLOWED_BY_CLASS, "
            "reusing an existing constant — a new string is a msgid in twelve catalogs."
        )
        assert not stale, f"ALLOWED_BY_CLASS names classes that no longer exist: {stale}"

    def test_every_construction_passes_its_class_approved_message(self):
        offenders = []
        for path, tree in _trees(PACKAGE):
            for call in _calls(tree):
                if not (isinstance(call.func, ast.Name) and call.func.id in self.ALLOWED_BY_CLASS):
                    continue
                if not call.args:
                    continue
                arg = call.args[0]
                allowed = self.ALLOWED_BY_CLASS[call.func.id]
                if isinstance(arg, ast.Name) and arg.id in allowed:
                    continue
                offenders.append(
                    f"{path.name}:{call.lineno} {call.func.id}({ast.unparse(arg)[:60]}) — allowed: {sorted(allowed)}"
                )
        assert not offenders, (
            f"user message is not what the class may say: {offenders}. Pass the constant this "
            "class is mapped to, not a literal and not another class's message. Anything that "
            "varies by site — a field, a row, a path, a provider error — belongs on detail=."
        )

    def _approved_strings(self) -> set[str]:
        from encryption_suite import exceptions as exc_module

        return {str(getattr(exc_module, name)) for name in self.APPROVED_NAMES}

    def test_approved_messages_are_lazy_translation_proxies(self):
        """A plain str would render in the server's language, not the reader's."""
        from django.utils.functional import Promise

        from encryption_suite import exceptions as exc_module

        for name in sorted(self.APPROVED_NAMES):
            assert isinstance(getattr(exc_module, name), Promise), f"{name} is not gettext_lazy"

    def test_approved_messages_all_exist_as_msgids(self):
        """A message a catalog has never seen renders untranslated for every reader."""
        catalogs = sorted((PACKAGE / "locale").glob("*/LC_MESSAGES/django.po"))
        assert catalogs, "no locale catalogs found"
        missing = []
        for catalog in catalogs:
            text = catalog.read_text(encoding="utf-8")
            for message in self._approved_strings():
                if f'msgid "{message}"' not in text:
                    missing.append(f"{catalog.parents[1].name}:{message}")
        assert not missing, f"approved messages absent from catalogs: {missing}"

    def test_detail_reads_on_every_subclass_without_getattr(self):
        """Declared once on the base, so ``exc.detail`` is never a getattr dance."""
        from encryption_suite import exceptions as exc_module

        for name in sorted(self._error_class_names()):
            klass = getattr(exc_module, name)
            assert klass.detail is None, f"{name} declares a non-None class-level detail"


class TestTranslatedMessagesRideOnlyOnTypedErrors:
    """A translated message may only be raised on an ``EncryptionError``.

    ``TestUserMessagesAreGeneric`` above walks *constructions of the error
    classes*, so it can only police raises it already knows are typed. That
    leaves the inverse invisible: a raise of something else carrying a
    translated string. It is not a hypothetical — ``engine.encrypt`` refused a
    double-encrypted value with ``raise ValueError(_("Encryption failed: value
    appears to be already encrypted."))`` through two plans whose whole purpose
    was to eliminate exactly that, because both worked from the class list.

    Translation is the tell, which is why it is the thing checked. ``gettext``
    means a *user* is expected to read the string, and only an
    ``EncryptionError`` carries the two channels that makes safe — a generic
    translated ``str(exc)`` for them, the operator detail on ``detail``. An
    untyped raise has one channel, so a translated message on it is either
    leaking internals to a user or lost on an operator, and it escapes
    ``except EncryptionError`` and the DRF handler on the way past.

    This does *not* say every raise must be typed. The package deliberately
    raises untyped errors: adapters let raw provider errors reach the engine
    funnel that translates them, field construction raises ``TypeError`` the way
    Django's own field API does, and management commands raise ``CommandError``
    with English operator text. All are correct and all stay untranslated.

    There is no allow-list, because nothing needs one today. A Django form or
    admin ``ValidationError`` would be the real argument for the first entry —
    its contract genuinely is translated user text — and it should be made then,
    with the reasoning, rather than pre-approved here.
    """

    GETTEXT = {
        "_",
        "gettext",
        "gettext_lazy",
        "ngettext",
        "ngettext_lazy",
        "pgettext",
        "pgettext_lazy",
    }

    def _is_translated(self, node: ast.AST) -> bool:
        """True for an inline ``_( … )`` call or a reference to an approved constant."""
        if isinstance(node, ast.Call):
            func = node.func
            name = func.id if isinstance(func, ast.Name) else getattr(func, "attr", "")
            return name in self.GETTEXT
        # The constants are lazy proxies, so passing one to an untyped raise is
        # the same defect wearing a name instead of a call.
        return isinstance(node, ast.Name) and node.id in TestUserMessagesAreGeneric.APPROVED_NAMES

    def test_no_untyped_raise_carries_a_translated_message(self):
        typed = _error_class_names()
        offenders = []
        for path, tree in _trees(PACKAGE):
            for node in ast.walk(tree):
                if not isinstance(node, ast.Raise) or not isinstance(node.exc, ast.Call):
                    continue
                func = node.exc.func
                raised = func.id if isinstance(func, ast.Name) else getattr(func, "attr", "")
                if raised in typed:
                    continue
                args = list(node.exc.args) + [kw.value for kw in node.exc.keywords]
                if any(self._is_translated(a) for a in args):
                    offenders.append(f"{path.name}:{node.lineno} raise {raised}(...)")
        assert not offenders, (
            f"translated message raised on a non-EncryptionError: {offenders}. Raise an "
            "EncryptionError subclass so the message reaches a user through str(exc) and the "
            "operator detail through detail=, or drop the translation if the reader is an "
            "operator — their logs and CommandErrors are English-pinned."
        )
