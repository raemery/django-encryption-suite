"""
Who acted — the request-time identity, the OS login account, and the gates that
decide which of them reach the key lifecycle ledger.

The engine creates data encryption keys deep inside the ORM (model save →
encrypt), with no request handle, so it cannot know which user triggered a
creation. This module carries that identity in one ``ContextVar`` the consuming
app populates (via :class:`UserContextMiddleware` or any setter), and every
ambient write site asks for it here. Admin-initiated events pass an identity
explicitly and do not rely on the context.

``contextvars.ContextVar`` isolates the value correctly under both sync workers
(one thread per request) and async workers (uvicorn/Daphne, many requests per
thread via asyncio tasks) — matching the silo context.

Every read of ``USER_IDENTITY['SCOPE']`` lives in this module: the
middleware's early exit and the resolver's context gate. No write site reads
the setting. Which items reach the record is decided by the transition funnel
(:func:`~encryption_suite.models.recorded_identity`), and which reach a log line
by :func:`identity_tail`.
"""

from __future__ import annotations

import getpass
import ipaddress
import os
import re
from contextlib import contextmanager
from contextvars import ContextVar
from functools import cache
from typing import NamedTuple

from asgiref.sync import iscoroutinefunction, markcoroutinefunction
from django.utils.module_loading import import_string
from django.utils.translation import gettext_lazy as _

from . import conf
from ._logging import IdentityTail, get_logger, log_text
from .conf import SCOPE_ALL_ACTS

logger = get_logger(__name__)


class UserContext(NamedTuple):
    """The request-time identity, carried as one immutable value.

    One variable, not several, so the middleware sets and resets the whole thing
    on a single token and a reader can never get a user from one request beside
    an address from another.

    ``username`` and ``label`` are carried because a log line renders them and
    the primary key alone would cost a query to turn back into a name — once per
    *line*, on paths that log per decrypted field. The middleware already holds
    the instance, so it resolves them once and they ride along. Empty means "not
    resolved", and a reader falls back to a lookup.
    """

    user_pk: int | None = None
    ip: str | None = None
    username: str = ""
    label: str = ""


#: The default is an empty pair rather than ``None`` so a reader with no
#: middleware in effect needs no guard. Immutable, so it is safe to share.
_EMPTY_CONTEXT = UserContext()

_current_user: ContextVar[UserContext] = ContextVar("encryption_suite_user", default=_EMPTY_CONTEXT)  # noqa: B039

#: Parameter default meaning "read the context". Distinct from ``None``, which
#: means "record nobody" — a caller that has established there is no human says
#: so with ``None``. Never crosses the funnel: every function taking it resolves
#: it through :func:`resolve_user_and_ip` before passing anything down.
_UNSET = object()

# --- The OS login account --------------------------------------------------

#: Longest name component accepted, per component. The composed worst case is
#: ``"<64> → <64> (uid 4294967295)"`` at 148 characters, inside the column's
#: 200 — so the composed value never needs truncating and the uid, the only
#: kernel-verified part, can never be what gets cut.
_NAME_MAX_LENGTH = 64

#: ASCII letters, digits, and ``. _ - $ @ \`` and space. The backslash and ``@``
#: are there for the Windows domain-qualified forms, the space because Windows
#: permits it in an account name. ASCII-only also excludes bidi overrides and
#: homoglyphs, and a NUL, which Postgres rejects outright and which would abort
#: the enclosing transaction.
#:
#: This is also what makes the rendering parseable rather than merely unforged:
#: ``→``, ``(`` and ``)`` are the structural delimiters and none is an accepted
#: name character, so the parenthesized uid at the end is always the kernel's
#: and can never be a name dressed as one. Weigh any further character admitted
#: later against that property, not only against the injection list.
_ALLOWED_NAME = re.compile(rf"[A-Za-z0-9._\-$@\\ ]{{1,{_NAME_MAX_LENGTH}}}")


def _accepted_name(value: str) -> str:
    """Return *value* if it is an acceptable name component, else ``""``.

    Rejects whole, and never filters and re-emits: stripping the disallowed
    characters out of ``"ad→min"`` manufactures ``admin``, the impersonation
    this check exists to stop. Over-length is a rejection for the same reason —
    truncating ``admin_service`` to a shorter allowed name would manufacture a
    different account.
    """
    if not value:
        return ""
    if _ALLOWED_NAME.fullmatch(value):
        return value
    logger.warning("Rejected an OS account name that is not a plain ASCII account name. name_length=%d", len(value))
    return ""


def get_os_user() -> str:
    """Return a composed description of the login account behind this process.

    For management commands, which run with no request and therefore no Django
    user. Three values compose it: the current uid from ``os.getuid()``, the
    current account name from ``pwd.getpwuid()``, and the originating account
    name from ``SUDO_USER``::

        "deploy (uid 1000)"        no sudo
        "user1 → root (uid 0)"     escalated
        "(uid 1000)"               the uid has no passwd entry
        "deploy (unverified)"      no pwd module, name read from the environment

    The unforgeable value is the uid, which the kernel supplies. The name is a
    lookup into the passwd database, which root can change, so it is only as
    good as that database — which is why the uid is carried alongside the name
    rather than replaced by it. ``SUDO_USER`` is an environment variable and
    therefore a claim: it names a person on the operator's word.

    A rejected name renders as a literal ``?`` where a uid still follows it, so
    an escalation stays visible without forged text being echoed. On the
    non-POSIX branch there is no uid to fall back on, so a rejected name leaves
    ``"(unverified)"`` alone.
    """
    sudo_user = os.environ.get("SUDO_USER", "").strip()
    try:
        import pwd

        uid = os.getuid()
    except (ImportError, AttributeError):
        current = _unverified_account()
    else:
        try:
            # Validated like the environment values: the passwd database is
            # root-mutable, so a name read from it is a claim about a uid, not
            # the uid itself.
            name = _accepted_name(pwd.getpwuid(uid).pw_name)
        except KeyError:
            name = ""
        # The parentheses stay even with no name in front of them: an allowed
        # name can contain digits and a space, so a bare "uid 1000" would read
        # as a name.
        current = f"{name} (uid {uid})" if name else f"(uid {uid})"
    if not current:
        return ""
    if sudo_user:
        return f"{_accepted_name(sudo_user) or '?'} → {current}"
    return current


def _unverified_account() -> str:
    """The non-POSIX rendering: a name from the environment, marked as such.

    ``getpass.getuser()`` reads ``LOGNAME``/``USER``/``LNAME``/``USERNAME``, so
    the value carries no kernel guarantee and is marked so it is not read as a
    verified account. It raises ``OSError`` when none of those is set.
    """
    try:
        name = _accepted_name(getpass.getuser())
    except OSError:
        return ""
    return f"{name} (unverified)" if name else "(unverified)"


# --- The request-time identity ---------------------------------------------


def set_current_user(user_pk: int | None, ip: str | None = None) -> None:
    """Set the acting user for the current context (thread or async task)."""
    _current_user.set(UserContext(user_pk, ip))


def get_current_user() -> UserContext:
    """Return the acting user and address for the current context.

    Never ``None``: with no middleware in effect the default is an empty pair,
    so a reader needs no guard.
    """
    return _current_user.get()


def clear_current_user() -> None:
    """Clear the acting user for the current context."""
    _current_user.set(_EMPTY_CONTEXT)


@contextmanager
def override_current_user(user_pk: int | None, ip: str | None = None):
    """Context manager: set the acting user for the duration of the block."""
    token = _current_user.set(UserContext(user_pk, ip))
    try:
        yield
    finally:
        _current_user.reset(token)


def resolve_user_and_ip(user=_UNSET, user_ip=_UNSET):
    """Return the ``(user, ip)`` to record: what was passed, else the ambient pair.

    The single place every automatic lifecycle path asks who is acting, so a
    deployment-wide change to that policy lands here rather than in each caller.
    Both halves come back from one call: two accessors would let an ambient site
    resolve a user and forget the address, leaving a column that reads as nobody
    having acted.

    ``_UNSET`` means "read the context"; ``None`` means "record nobody", so a
    caller that has genuinely established there is no human can say so.

    **The context branch is gated on ``USER_IDENTITY['SCOPE']``.** Reading the
    context returns nobody unless the scope is ``all_acts``; an identity the
    caller passed is returned unchanged. The setters are public, so a populated
    context is not evidence the scope permits recording it.
    """
    if user is _UNSET or user_ip is _UNSET:
        ambient = recordable_context()
        if user is _UNSET:
            user = ambient.user_pk
        if user_ip is _UNSET:
            user_ip = ambient.ip
    return user, user_ip


def recordable_context() -> UserContext:
    """The ambient identity, where the scope permits an ambient read at all.

    Empty outside ``all_acts``: the setters are public, so a populated context is
    not evidence the scope permits recording it.
    """
    return get_current_user() if conf.user_identity_setting("SCOPE") == SCOPE_ALL_ACTS else _EMPTY_CONTEXT


def _user_object(user):
    """Return a user instance for *user*, given an instance or a primary key."""
    if user is None or hasattr(user, "get_username"):
        return user
    from django.contrib.auth import get_user_model

    return get_user_model().objects.filter(pk=user).first()


def identity_tail(*, user=None, os_login_user="", user_ip=None, username="", label="") -> IdentityTail:
    """Return the ``key=value`` tail naming who acted, for an audit log line.

    Every line that names an act a person asked for appends this, so one shape
    describes an identity everywhere. It renders the items
    ``USER_IDENTITY['LOGS']`` lists, in this order::

        user_id=1 user_name="admin" user_str="admin@example.com" ip_address=127.0.0.1 os_user="deploy (uid 1000)"

    Each key means one thing in every deployment: ``user_id`` is the primary key,
    the value the record's user column holds, so a line and its row join on it;
    ``user_name`` is ``get_username()``; ``user_str`` is ``str(user)``, which is
    what the admin's User column shows. Listing both names is allowed.

    The free-text fields are quoted, stripped and escaped (see
    :func:`~encryption_suite._logging.log_text`). They come from a swappable
    model or the operating system, so their content is not the package's to
    predict: an unquoted value containing a space would swallow the fields
    after it, and a quote or a line break inside one would read as further
    fields or a further line. A listed item with no value renders ``?``; an unlisted one is
    absent, and with nothing listed the tail is empty.

    Returned as :class:`~encryption_suite._logging.IdentityTail` whatever it
    holds, so the logging filter adds no context tail beside it. Pass it to the
    logger as an argument of its own, never formatted into another string.

    *username* and *label* let a caller supply what it already knows. Without
    them a primary key has to be looked up to be rendered, which is one query per
    line on a path that logs per decrypted field.
    """
    items = conf.user_identity_setting("LOGS")
    # The instance, where the caller handed one over, saves a lookup; the line
    # carries its key, never a repr.
    instance = user if hasattr(user, "get_username") else None
    user = getattr(user, "pk", user)
    parts = []
    if conf.ITEM_USER_ID in items:
        parts.append(f"user_id={user if user is not None else '?'}")
    for item, supplied, render in (
        (conf.ITEM_USER_NAME, username, lambda u: u.get_username()),
        (conf.ITEM_USER_STR, label, str),
    ):
        if item not in items:
            continue
        rendered = supplied
        if not rendered and user is not None:
            # Only look the user up for what the caller did not already supply.
            instance = instance or _user_object(user)
            if instance is not None:
                rendered = render(instance)
        parts.append(f'{item}="{log_text((rendered or "").strip()) or "?"}"')
    if conf.ITEM_IP_ADDRESS in items:
        parts.append(f"{conf.ITEM_IP_ADDRESS}={user_ip or '?'}")
    if conf.ITEM_OS_USER in items:
        parts.append(f'{conf.ITEM_OS_USER}="{log_text((os_login_user or "").strip()) or "?"}"')
    return IdentityTail(" ".join(parts))


# --- The client address ----------------------------------------------------

#: One WARNING per process on the first ``X-Forwarded-For`` count mismatch. The
#: header is client-controlled, so a mismatch is ordinary traffic as often as it
#: is misconfiguration, and a per-request line is remotely triggerable log
#: volume. A real misconfiguration shows on the first request either way, so
#: this need not be accurate across workers.
_warned_about_proxy_count = False


def _clean_address(value):
    """Return a validated address string from *value*, or ``None``.

    Strips whitespace, unwraps IPv6 brackets, drops a port, and validates. Never
    raises: the value lands in an ``inet`` column inside a provisioning or
    deletion-schedule transaction, and ``GenericIPAddressField`` only validates
    under ``full_clean()``, so an unchecked address would abort that transaction.
    """
    value = (value or "").strip()
    if not value:
        return None
    if value.startswith("["):
        value = value[1:].partition("]")[0]
    elif value.count(":") == 1:
        # A single colon is a port on an IPv4 address; a bare IPv6 address has
        # several and keeps them.
        value = value.split(":")[0]
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


def get_user_ip(request):
    """Return the client address for *request*, or ``None``.

    With ``USER_IDENTITY['IP_PROXY_COUNT']`` at 0 this is ``REMOTE_ADDR`` and
    ``X-Forwarded-For`` is disregarded entirely. With a count of *N* it is the
    entry *N* from the right of that header; entries further left are
    client-supplied and are never read. ``REMOTE_ADDR`` is the fallback when the
    header is absent, carries fewer than *N* entries, or the selected entry does
    not validate.
    """
    global _warned_about_proxy_count

    count = conf.user_identity_setting("IP_PROXY_COUNT")
    meta = getattr(request, "META", None) or {}
    if count > 0:
        entries = [entry.strip() for entry in (meta.get("HTTP_X_FORWARDED_FOR") or "").split(",") if entry.strip()]
        if len(entries) >= count:
            address = _clean_address(entries[-count])
            if address is not None:
                return address
        elif not _warned_about_proxy_count:
            _warned_about_proxy_count = True
            logger.warning(
                "X-Forwarded-For carried fewer entries than the configured proxy count, so the "
                "address was read from REMOTE_ADDR. entries=%d proxies=%d",
                len(entries),
                count,
            )
    return _clean_address(meta.get("REMOTE_ADDR"))


# --- Rendering a recorded user ---------------------------------------------


class DeletedUser:
    """Typed stand-in for a ledger row whose user account no longer exists.

    Typed, not a string, for the same reason ``UndecryptableValue`` is: a
    fallback string can collide with a real user's label. Callers that need to
    tell an orphan apart test ``isinstance``; everything else renders it.
    """

    def __init__(self, user_id):
        self.user_id = user_id

    def __str__(self) -> str:
        return str(_("Deleted user #%(user_id)s") % {"user_id": self.user_id})

    def __repr__(self) -> str:
        return f"DeletedUser({self.user_id!r})"

    def __eq__(self, other) -> bool:
        return isinstance(other, DeletedUser) and other.user_id == self.user_id

    def __hash__(self) -> int:
        return hash((DeletedUser, self.user_id))


#: User ids already logged as orphans in this context. Deduped so a changelist
#: page of one deleted user's rows writes one line rather than one per row.
_reported_orphans: ContextVar[set | None] = ContextVar("encryption_suite_reported_orphans", default=None)


def _report_orphan(user_id) -> None:
    """Log an orphaned user reference once per id, at INFO.

    INFO, not ERROR: under a deactivate-over-delete policy an orphan is
    expected, not a defect.
    """
    seen = _reported_orphans.get()
    if seen is None:
        seen = set()
        _reported_orphans.set(seen)
    if user_id in seen:
        return
    seen.add(user_id)
    logger.info(
        "A key lifecycle event names a user account that no longer exists; showing the id instead. user=%s",
        user_id,
    )


def user_label_for(event):
    """Return the display value for *event*'s user: a label, or a typed sentinel.

    Reads ``user_id`` and the joined instance, **never** ``event.user`` — the
    forward descriptor queries and raises ``RelatedObjectDoesNotExist`` on an
    orphan. Callers in the admin get the joined value for free from
    ``UserColumnMixin``'s ``select_related``; called outside it, this pays one
    query.
    """
    user_id = getattr(event, "user_id", None)
    if user_id is None:
        return ""
    cache = getattr(getattr(event, "_state", None), "fields_cache", {})
    if "user" in cache:
        user = cache["user"]
    else:
        from django.contrib.auth import get_user_model

        user = get_user_model().objects.filter(pk=user_id).first()
    if user is None:
        _report_orphan(user_id)
        return DeletedUser(user_id)
    return str(user)


# --- The middleware --------------------------------------------------------


@cache
def _reads_user_context(path: str) -> bool:
    """Whether the silo adapter class at *path* declares ``reads_user_context``, without constructing it."""
    try:
        return bool(getattr(import_string(path), "reads_user_context", False))
    except ImportError:
        # The construction check reports a path that does not import.
        return False


def user_key_set_bound() -> bool:
    """Whether any key set is bound to a silo adapter that resolves its silo from the user context."""
    paths = {conf.adapter_path(key_set) for key_set in conf.key_set_names()}
    return any(_reads_user_context(path) for path in paths if path and path != conf.SYSTEM_ADAPTER)


def _context_wanted() -> bool:
    """Whether anything could read the context: a user key set, or scope ``all_acts`` and an item listed."""
    return user_key_set_bound() or (
        conf.user_identity_setting("SCOPE") == SCOPE_ALL_ACTS
        and bool(conf.user_identity_setting("KEY_LIFECYCLE_EVENTS") or conf.user_identity_setting("LOGS"))
    )


def _address_wanted() -> bool:
    """Whether either list names an address, in either form."""
    listed = {*conf.user_identity_setting("KEY_LIFECYCLE_EVENTS"), *conf.user_identity_setting("LOGS")}
    return bool(listed & {conf.ITEM_IP_ADDRESS, conf.ITEM_ENCRYPTED_IP_ADDRESS})


class UserContextMiddleware:
    """Populate the current-user context from the request, for the request.

    Add to ``MIDDLEWARE`` **below** Django's ``AuthenticationMiddleware`` so key
    creations triggered during a request — lazy provisioning on first encrypt,
    say — can be attributed to the logged-in user. ``MIDDLEWARE`` is
    outermost-first, so placing it above reads ``request.user`` before anything
    sets it and records nobody on every request, exactly as omitting it does.

    A key set bound to a silo adapter that reads the user context needs it, and so
    does ``USER_IDENTITY['SCOPE'] = "all_acts"``. With neither, or under
    ``all_acts`` with both lists empty, it returns before touching the user, and
    it reads the address only where a list names one. For the ledger those checks
    are optimizations — the resolver discards the identity and the lists drop what
    they leave out — not the gate.
    """

    async_capable = True
    sync_capable = True

    def __init__(self, get_response):
        self.get_response = get_response
        self.async_mode = iscoroutinefunction(get_response)
        if self.async_mode:
            markcoroutinefunction(self)

    def __call__(self, request):
        if self.async_mode:
            return self.__acall__(request)
        if not _context_wanted():
            return self.get_response(request)
        user = getattr(request, "user", None)
        token = _current_user.set(self._context_for(request, user))
        try:
            return self.get_response(request)
        finally:
            _current_user.reset(token)

    async def __acall__(self, request):
        if not _context_wanted():
            return await self.get_response(request)
        # Never ``request.user`` here: it resolves through the session backend
        # and raises SynchronousOnlyOperation under ASGI.
        user = await request.auser() if hasattr(request, "auser") else None
        # Set and reset on one token inside a single coroutine. A sync_to_async
        # hop runs the body in another context, where the reset would strand the
        # value instead of clearing it.
        token = _current_user.set(self._context_for(request, user))
        try:
            return await self.get_response(request)
        finally:
            _current_user.reset(token)

    def _context_for(self, request, user):
        if user is None or not user.is_authenticated:
            return _EMPTY_CONTEXT
        ip = get_user_ip(request) if _address_wanted() else None
        # Resolved here, from the instance in hand, so no log line pays a query
        # to render a name.
        return UserContext(user.pk, ip, user.get_username() or "", str(user))
