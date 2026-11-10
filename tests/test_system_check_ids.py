"""Every system-check ID means one condition, and the table says which.

An operator greps a deploy failure by its ID, so a number covering two unrelated
conditions sends them to the wrong fix — which is what happened while the two
``EncryptedFileField`` checks quietly shared ``E010`` and ``E011`` with two
settings checks. Nothing in Django notices; these tests are what notices.

The table in ``docs/configuration.md`` is the catalog, so it is the reference
both ways: nothing the source emits may be missing from it, and nothing in it
may name a number twice.
"""

from __future__ import annotations

import re
from pathlib import Path

import encryption_suite

SRC = Path(encryption_suite.__file__).parent
TABLE = SRC.parent.parent / "docs" / "configuration.md"

#: An ID as the source writes it.
ID = re.compile(r"encryption_suite\.([EW]\d{3})")
#: An ID inside a table cell, where the prefix is written once and a range's
#: upper bound is left bare.
BARE_ID = re.compile(r"\b([EW]\d{3})\b")
#: A row of the system-checks table, told apart from the other tables on the
#: page whose first cell is also a dotted ``encryption_suite`` name.
CHECK_ROW = re.compile(r"\| `encryption_suite\.[EW]\d")

#: The builder checks, at both severities. Their IDs are built at check time
#: from a severity prefix plus a numeric code rather than written out, so no
#: literal for them appears in the source to be scanned.
DYNAMIC = {f"{kind}{n:03d}" for kind in "EW" for n in range(1, 7)}


def _documented() -> list[str]:
    """IDs named in the leading cell of a system-checks table row, in order.

    Ranges expand, so one row can carry the four construction checks without
    hiding three numbers from this test.
    """
    found: list[str] = []
    for line in TABLE.read_text(encoding="utf-8").splitlines():
        if not CHECK_ROW.match(line):
            continue
        cell = line.split("|")[1]
        names = BARE_ID.findall(cell)
        if len(names) == 2 and "–" in cell:
            kind, first, last = names[0][0], int(names[0][1:]), int(names[1][1:])
            found.extend(f"{kind}{n:03d}" for n in range(first, last + 1))
        else:
            found.extend(names)
    return found


def _emitted() -> dict[str, set[str]]:
    """Every ID literal in the package source, mapped to the files using it."""
    sites: dict[str, set[str]] = {}
    for path in SRC.rglob("*.py"):
        for name in ID.findall(path.read_text(encoding="utf-8")):
            sites.setdefault(name, set()).add(path.name)
    return sites


def test_the_table_is_found_and_read():
    """The three tests below all pass against a table nobody located."""
    assert len(_documented()) > 15


def test_the_catalog_names_no_number_twice():
    documented = _documented()

    assert sorted(documented) == sorted(set(documented))


def test_the_catalog_covers_every_id_the_package_emits():
    missing = set(_emitted()) - set(_documented())

    assert missing == set(), f"undocumented system checks: {sorted(missing)}"


def test_the_catalog_invents_nothing():
    """The other direction: a row for a check no longer emitted is a lie too."""
    extra = set(_documented()) - set(_emitted()) - DYNAMIC

    assert extra == set(), f"documented but never emitted: {sorted(extra)}"


def test_no_id_is_raised_from_two_modules():
    """One condition per number, at the granularity the source makes visible.

    A repeat within a module is fine — ``W052`` reports one condition from two
    branches. A number appearing in two modules is how the ``E010`` collision
    looked, and there is no case where that is what was meant.
    """
    shared = {name: sorted(files) for name, files in _emitted().items() if len(files) > 1}

    assert shared == {}


def test_no_number_is_held_by_both_an_error_and_a_warning():
    """The rule that keeps a downgrade safe.

    ``STARTUP_CHECK_WARN_ONLY`` reports a builder check as ``W`` + the number it
    already had. That only works while no native warning holds that number:
    otherwise ``E002`` downgraded would arrive wearing the tagging warning's ID,
    and an operator grepping for it would read the wrong page.

    Stated over the catalog rather than the source, so it covers the warn-only
    twins too — they have no literal to scan for.
    """
    numbers: dict[str, set[str]] = {}
    for name in _documented():
        numbers.setdefault(name[1:], set()).add(name[0])

    shared = {n: sorted(kinds) for n, kinds in numbers.items() if len(kinds) > 1}

    assert shared == {n: ["E", "W"] for n in sorted(f"{i:03d}" for i in range(1, 7))}


def test_the_bands_hold():
    """Numbers say which kind of check they are, so the rule above stays legible."""
    documented = set(_documented())
    errors = {int(n[1:]) for n in documented if n.startswith("E")}
    warnings = {int(n[1:]) for n in documented if n.startswith("W")}

    assert all(n <= 49 for n in errors), "an error outside the 001-049 error bands"
    # Warnings are either a builder error's twin (001-019) or native (050-099).
    assert all(n <= 19 or n >= 50 for n in warnings), "a warning in the validator band"
