"""Retired words must not come back into user-facing strings.

Several renames have been done by hand — ``teardown`` → delete, ``purge`` →
delete, ``gatekeeper`` → silo — and nothing prevented a regression. One did
regress: a ``help_text`` written months later reintroduced "purge", and it was
caught by a person reading an admin page rather than by the suite.

This reads the ``en`` catalog, which ``makemessages`` regenerates from every
translatable string in the package — Python and templates alike — so the check
covers strings that do not exist yet, including the next one somebody writes.

It deliberately does **not** police code identifiers, log markers, or docstrings.
``purge_expired_work``, ``[dek_shredded]`` and ``PURGE_RETAINED`` are internal
names an operator never reads, and renaming them is a separate decision. The line
this draws is exactly the one that matters: what reaches a screen.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

CATALOG = (
    Path(__file__).resolve().parent.parent / "src" / "encryption_suite" / "locale" / "en" / "LC_MESSAGES" / "django.po"
)

# Each entry is (retired word, what to use instead). The message is the whole
# point of the test: a failure should not send anyone hunting for the decision.
RETIRED = {
    "purge": "delete / deleting / deletion (the admin action is 'Delete selected expired …')",
    "purged": "deleted",
    "purging": "deleting",
    "teardown": "delete / deletion",
    "gatekeeper": "silo",
    "shred": "delete (crypto-shred stays in the glossary, docstrings and logs — never on a screen)",
    "shredded": "deleted",
}

_MSGID = re.compile(r'^msgid\s+"(.*)"\s*$')
_CONT = re.compile(r'^"(.*)"\s*$')


def _msgids() -> list[str]:
    """Every msgid in the catalog, with continuation lines joined."""
    ids: list[str] = []
    current: str | None = None
    for line in CATALOG.read_text(encoding="utf-8").splitlines():
        match = _MSGID.match(line)
        if match:
            if current:
                ids.append(current)
            current = match.group(1)
            continue
        if current is not None:
            cont = _CONT.match(line)
            if cont:
                current += cont.group(1)
            else:
                if current:
                    ids.append(current)
                current = None
    if current:
        ids.append(current)
    return ids


def test_the_catalog_is_present_and_populated():
    """A missing or empty catalog would make every check below vacuously pass."""
    assert CATALOG.exists(), f"{CATALOG} is missing — run makemessages"
    assert len(_msgids()) > 100


@pytest.mark.parametrize("word,replacement", sorted(RETIRED.items()))
def test_no_user_facing_string_uses_a_retired_word(word, replacement):
    pattern = re.compile(rf"\b{word}\b", re.IGNORECASE)
    offenders = [m for m in _msgids() if pattern.search(m)]
    assert not offenders, (
        f"{len(offenders)} user-facing string(s) use the retired word {word!r}; use {replacement}.\n"
        + "\n".join(f"  - {m[:100]}" for m in offenders[:5])
    )
