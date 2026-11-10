"""Row iteration that survives a pooled Postgres connection.

``QuerySet.iterator()`` opens a server-side cursor, which PgBouncer-style
transaction pooling (Neon, Supabase, RDS Proxy) discards between statements —
the walk then dies with ``InvalidCursorName``, intermittently, depending on
whether consecutive statements reach the same backend connection. Found live on
Neon 2026-08-02, on the second of three identical ``reencrypt_keys`` runs.

The pooler cannot be reproduced here, so these tests pin the two properties that
make ``iter_rows`` immune: it must page rather than hold a cursor open, and it
must keep working while the caller writes to the rows it is walking.
"""

from __future__ import annotations

import pytest

from encryption_suite._internal import iter_rows
from encryption_suite.models import DataEncryptionKey

from .factories import make_dek

pytestmark = pytest.mark.django_db


class TestIterRows:
    def test_yields_every_row(self):
        for index in range(7):
            make_dek(f"team-{index}")

        walked = list(iter_rows(DataEncryptionKey.objects.all(), chunk_size=2))

        assert len(walked) == 7

    def test_yields_in_primary_key_order(self):
        # Keyset pagination depends on it, so the order is part of the contract
        # rather than an accident of the backend.
        for index in range(5):
            make_dek(f"team-{index}")

        walked = list(iter_rows(DataEncryptionKey.objects.all(), chunk_size=2))

        assert [row.pk for row in walked] == sorted(row.pk for row in walked)

    def test_an_incoming_ordering_does_not_break_the_walk(self):
        # Ordering is imposed, not inherited: a caller's ORDER BY would make the
        # pk__gt cursor skip rows.
        for index in range(6):
            make_dek(f"team-{index}")

        walked = list(iter_rows(DataEncryptionKey.objects.order_by("-silo_uid"), chunk_size=2))

        assert len(walked) == 6

    def test_no_rows_is_not_an_error(self):
        assert list(iter_rows(DataEncryptionKey.objects.all())) == []

    def test_a_chunk_boundary_landing_on_the_last_row_terminates(self):
        # The off-by-one that would loop forever or drop the final page.
        for index in range(4):
            make_dek(f"team-{index}")

        walked = list(iter_rows(DataEncryptionKey.objects.all(), chunk_size=2))

        assert len(walked) == 4

    def test_writing_to_rows_while_walking_them_visits_each_once(self):
        """What ``reencrypt_keys`` actually does — and what OFFSET would break.

        Each row is saved as it is visited. Under ``LIMIT``/``OFFSET`` a write
        that changed the sort position would shift the window and silently skip
        or repeat rows; keying on the pk cannot.
        """
        for index in range(6):
            make_dek(f"team-{index}")

        seen = []
        for row in iter_rows(DataEncryptionKey.objects.all(), chunk_size=2):
            row.reencryption_count += 1
            row.save(update_fields=["reencryption_count"])
            seen.append(row.pk)

        assert sorted(seen) == sorted(DataEncryptionKey.objects.values_list("pk", flat=True))
        # Every row incremented exactly once, from the field's default of 1.
        assert set(DataEncryptionKey.objects.values_list("reencryption_count", flat=True)) == {2}


def test_no_server_side_cursors_in_package_source():
    """No ``.iterator()`` anywhere in the package.

    The guard that keeps this fixed: the failure is intermittent and
    environment-dependent, so a reintroduced call would pass CI and surface as a
    half-finished data migration on someone's pooled database.
    """
    import ast
    from pathlib import Path

    src = Path(__file__).resolve().parent.parent / "src" / "encryption_suite"
    offenders = []
    for path in src.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            # Parsed rather than grepped, so the prose in docstrings and
            # comments explaining why this rule exists does not trip it.
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "iterator":
                offenders.append(f"{path.relative_to(src).as_posix()}:{node.lineno}")

    assert not offenders, f"use encryption_suite._internal.iter_rows instead of QuerySet.iterator(): {offenders}"
