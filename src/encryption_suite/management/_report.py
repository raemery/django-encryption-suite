"""The JSON report the reporting commands write for schedulers and log collectors.

A command that takes ``--format json`` writes one JSON document when it ends,
and nothing else, to standard output, or to the file ``--output`` names. Every
line written for a person goes to standard error instead, so a scheduler can
capture standard output whole and parse it. Log lines go wherever the
project's logging sends them; a project that sends them to standard output
must use ``--output`` (the command docs say so).

Every document opens with the same four keys: ``schema_version``, ``command``,
``started_at`` and ``finished_at``. A command raises ``schema_version`` only when
it renames or removes a key, so a diff between two runs can tell a change in
format from a change in the deployment.
"""

from __future__ import annotations

import json
from datetime import datetime

from django.core.management.base import CommandError
from django.utils import timezone


def add_report_arguments(parser) -> None:
    """Add ``--format`` and ``--output`` to a command's parser."""
    parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="text (the default) for a person; json for a scheduler or a record to keep. With json, "
        "standard output carries only the report and everything else goes to standard error.",
    )
    parser.add_argument(
        "--output",
        metavar="FILENAME",
        default=None,
        help="Write the JSON report to FILENAME instead of standard output. Needs --format json.",
    )


def _default(value):
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, (set, frozenset, tuple)):
        return sorted(value) if isinstance(value, (set, frozenset)) else list(value)
    raise TypeError(f"{type(value).__name__} is not JSON serializable")


class Report:
    """One run's JSON report. Construct it first thing in ``handle``.

    With ``--format json`` it moves the command's standard output onto standard
    error, so that text the command writes for a person cannot land inside the
    document. With ``--format text`` it does nothing, and :meth:`write` is a
    no-op.
    """

    def __init__(self, command, name: str, options: dict, *, schema_version: int) -> None:
        self.name = name
        self.schema_version = schema_version
        self.enabled = options.get("format") == "json"
        self.output = options.get("output")
        if self.output and not self.enabled:
            raise CommandError("--output writes the JSON report, so it needs --format json.")
        self.started_at = timezone.now()
        self._stdout = command.stdout
        if self.enabled:
            command.stdout = command.stderr

    def write(self, payload: dict) -> None:
        """Write the document: the four common keys, then *payload*."""
        if not self.enabled:
            return
        document = {
            "schema_version": self.schema_version,
            "command": self.name,
            "started_at": self.started_at,
            "finished_at": timezone.now(),
            **payload,
        }
        text = json.dumps(document, indent=2, default=_default)
        if self.output:
            with open(self.output, "w", encoding="utf-8") as handle:
                handle.write(text + "\n")
        else:
            self._stdout.write(text)
