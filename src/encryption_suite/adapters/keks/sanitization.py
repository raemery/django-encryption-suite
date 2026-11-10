"""UID sanitization for KMS key names.

Provides charset-aware encoding of silo UIDs to strings suitable for use
as KMS key/secret names. The encoding is bijective (unique input → unique output),
never raises errors, and accepts any Python string.

Design principle: use UTF-8 bytes as the intermediate representation. Each
disallowed character is encoded via its UTF-8 bytes, each byte emitted as
escape + 2 hex chars. The escape character itself is doubled. This ensures
every encoded unit is exactly 2 hex chars, making the output unambiguously
reversible regardless of input codepoint range.

Example with escape='_' (Fly, default):
    '-'  (U+002D) → UTF-8: 0x2d          → "_2d"
    '€'  (U+20AC) → UTF-8: 0xe2,0x80,0xac → "_e2_80_ac"
    '_'  (escape)                         → "__"

No collision: '_2da' always means '_2d' + 'a' (two units), never '_2da' (one unit).
"""

from __future__ import annotations

from collections.abc import Callable

# Charset constants — named by content, not by which adapter uses them.

# [A-Za-z0-9_] — letters, digits, underscore only
ALNUM_UNDERSCORE: frozenset[str] = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_")

# [A-Za-z0-9_-] — letters, digits, underscore, hyphen (broadest common set)
ALNUM_UNDERSCORE_HYPHEN: frozenset[str] = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-")

# [A-Za-z0-9-] — letters, digits, hyphen only (no underscore)
ALNUM_HYPHEN: frozenset[str] = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-")

# [a-z0-9-] — lowercase letters, digits, hyphen only
LOWER_ALNUM_HYPHEN: frozenset[str] = frozenset("abcdefghijklmnopqrstuvwxyz0123456789-")


def sanitize_uid(uid: str, allowed: frozenset[str], escape: str = "_") -> str:
    """Encode a string to contain only chars from the allowed set.

    Uses UTF-8-based hex encoding for disallowed characters. Each disallowed
    char is encoded via its UTF-8 bytes, each byte emitted as escape + 2
    lowercase hex chars. The escape character itself is doubled.

    Args:
        uid: Input string (any Python string, including non-ASCII).
        allowed: Frozenset of allowed characters.
        escape: Character used as escape prefix (must be in allowed set).

    Returns:
        String containing only characters from `allowed`.

    Raises:
        ValueError: If escape character is not in allowed set.
    """
    if escape not in allowed:
        raise ValueError(
            f"escape character {escape!r} is not in allowed set. "
            "Escape char must be in allowed set to avoid encoding collisions."
        )

    parts = []
    for ch in uid:
        if ch == escape:
            # Escape char itself must be doubled
            parts.append(escape * 2)
        elif ch in allowed:
            # Allowed char passes through as-is
            parts.append(ch)
        else:
            # Disallowed char: encode via UTF-8 bytes as escape + 2 hex each
            for byte in ch.encode("utf-8"):
                parts.append(f"{escape}{byte:02x}")
    return "".join(parts)


def make_sanitizer(allowed: frozenset[str], escape: str = "_") -> Callable[[str], str]:
    """Create a sanitizer function for a specific charset.

    Args:
        allowed: Frozenset of allowed characters.
        escape: Character used as escape prefix (must be in allowed set).

    Returns:
        Callable that takes a UID and returns the sanitized string.
    """
    return lambda uid: sanitize_uid(uid, allowed, escape)
