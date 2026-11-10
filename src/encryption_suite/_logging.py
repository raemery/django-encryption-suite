"""
The package's logger factory — one place that decides what every line carries.

Modules take their logger from :func:`get_logger` rather than
``logging.getLogger``, so the identity of whoever acted can be appended to every
line without threading a ``user`` argument down to the adapters, which have no
business knowing about users. Lines whose call site already holds an identity
pass it explicitly instead; this covers the rest.

Imports nothing from the package at module scope, deliberately. Every module
imports this one, including :mod:`~encryption_suite.conf`,
:mod:`~encryption_suite.lifecycle`, :mod:`~encryption_suite.exceptions` and
:mod:`~encryption_suite.checks`, which import nothing intra-package today —
``lifecycle`` documents that as a property, so it stays importable from
migrations and checks without pulling in the ORM. The filter reaches
``user_context`` lazily, at log time, because ``user_context`` takes its own
logger from here.
"""

from __future__ import annotations

import logging

_LOG_TEXT_ESCAPES = {"\\": "\\\\", '"': '\\"', "\n": "\\n", "\r": "\\r", "\t": "\\t"}


def log_text(value) -> str:
    """Render *value* for the inside of a quoted ``key="value"`` log field.

    For text the package does not choose: a user's name, a column value, a
    stored file's name. A double quote in it would close the field early and
    let the rest read as fields of its own, and a line break would start what
    reads as a second log line. So the backslash and the double quote are
    backslash-escaped, and every character that is not printable, line and
    paragraph separators included, is written as its escape sequence. Text with
    none of those is returned unchanged.
    """
    text = str(value)
    if text.isprintable() and '"' not in text and "\\" not in text:
        return text
    return "".join(
        _LOG_TEXT_ESCAPES.get(char) or (char if char.isprintable() else char.encode("unicode_escape").decode("ascii"))
        for char in text
    )


class IdentityTail(str):
    """A rendered identity tail, typed so the filter below can recognize one.

    A site that passes a tail explicitly passes one of these among its log
    arguments, and the filter then leaves the record alone. Recognized by type
    rather than by its text, because the text depends on ``USER_IDENTITY['LOGS']``
    and can be empty: an explicit tail with nothing in it still says the site
    has decided who acted, and a context tail beside it would name a second
    identity on one line.
    """


class _IdentityFilter(logging.Filter):
    """Append the ambient identity to each record, where there is one to append.

    A filter rather than a :class:`logging.LoggerAdapter`: it can rewrite the
    record *after* interpolation, so a username containing a literal ``%`` cannot
    break formatting. An adapter hands the message back to be interpolated, which
    would carry that hazard into every line.

    Never raises. A logging call that failed because of this filter would take a
    real operation down with it, and the tail is the least important thing on the
    line.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            args = record.args if isinstance(record.args, tuple) else ()
            if any(isinstance(arg, IdentityTail) for arg in args):
                return True
            tail = self._tail()
            if tail:
                record.msg = f"{record.getMessage()} {tail}"
                record.args = ()
        except Exception:  # pragma: no cover - defensive; see the docstring
            pass
        return True

    @staticmethod
    def _tail() -> str:
        """The identity tail for the current context, or ``""``.

        Under the default scope nothing populates the context and nothing is
        appended.
        """
        from . import user_context

        ambient = user_context.recordable_context()
        if ambient.user_pk is None and ambient.ip is None:
            return ""
        return user_context.identity_tail(
            user=ambient.user_pk,
            user_ip=ambient.ip,
            username=ambient.username,
            label=ambient.label,
        )


_identity_filter = _IdentityFilter()


def get_logger(name: str) -> logging.Logger:
    """Return the package logger for *name*, carrying the identity filter.

    Attached idempotently: this runs at import in every module, and a repeated
    call would otherwise stack duplicate filters on one logger.
    """
    logger = logging.getLogger(name)
    if not any(isinstance(existing, _IdentityFilter) for existing in logger.filters):
        logger.addFilter(_identity_filter)
    return logger
