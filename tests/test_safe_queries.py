"""Tests for the safe-query helpers.

Covers:

* :func:`defer_encrypted` — encrypted columns deferred from the SELECT.
* :func:`probe_decryption` — empty / decryptable / undecryptable states.
* :func:`safe_list_rows` / :func:`safe_detail` — list and detail flows
  with mixed decryptable and undecryptable rows still rendering.
* AAD-mismatch / swapped-row scenarios — undecryptable rows surface as
  probe errors rather than crashing the query.

DB-backed tests build a transient model and create its table via the
schema editor so we don't need a permanent test app.
"""

from __future__ import annotations

import contextlib
from types import SimpleNamespace

import pytest
from django.db import connection, models

from encryption_suite.adapters.silos.context import (
    override_current_silo,
)
from encryption_suite.exceptions import EncryptedFieldDecryptionError
from encryption_suite.fields import (
    EncryptedCharField,
    EncryptedTextField,
)
from encryption_suite.safe_queries import (
    DEFAULT_EMPTY_FIELD_LABEL,
    DEFAULT_ERROR_FIELD_LABEL,
    FieldProbe,
    SafeRow,
    defer_encrypted,
    probe_decryption,
    safe_detail,
    safe_list_rows,
)

_model_counter = 0


def _make_model(*, with_aad: bool = False):
    """Build a transient model whose table can be created by the schema editor.

    Each call yields a unique class so tests don't clash on Django's
    model registry. The ``with_aad`` variant declares ``aad=("user_id",)`` on
    both encrypted fields so AAD-mismatch behavior can be exercised.
    """
    global _model_counter
    _model_counter += 1
    name = f"SafeQueryModel{_model_counter}"
    aad = ("user_id",) if with_aad else ()
    attrs: dict = {
        "__module__": "tests.test_safe_queries",
        "Meta": type("Meta", (), {"app_label": "tests"}),
        "label": models.CharField(max_length=50),
        "user_id": models.IntegerField(default=0),
        "notes": EncryptedTextField(null=True, blank=True, aad=aad),
        "alt_notes": EncryptedCharField(max_length=200, null=True, blank=True, aad=aad),
    }
    return type(name, (models.Model,), attrs)


@contextlib.contextmanager
def _table_for(model):
    """Create the model's table for the duration of the block, then drop it."""
    with connection.schema_editor() as editor:
        editor.create_model(model)
    try:
        yield
    finally:
        with connection.schema_editor() as editor:
            editor.delete_model(model)


@pytest.fixture
def silo():
    gk = SimpleNamespace(pk="safe-queries-tests")
    with override_current_silo(gk):
        yield gk


# ---------------------------------------------------------------------------
# defer_encrypted
# ---------------------------------------------------------------------------


@pytest.mark.django_db(transaction=True)
def test_defer_encrypted_excludes_encrypted_columns_from_select(silo):
    model = _make_model()
    with _table_for(model):
        model.objects.create(label="row", notes="x")
        qs = defer_encrypted(model.objects.all())
        sql = str(qs.query).lower()
        assert '"notes"' not in sql
        assert '"alt_notes"' not in sql
        assert '"label"' in sql


@pytest.mark.django_db(transaction=True)
def test_defer_encrypted_iteration_does_not_decrypt(silo):
    """The whole point: even with no usable plaintext access, iterating
    a deferred queryset must succeed — no ``from_db_value`` runs for
    encrypted columns because they aren't in ``__dict__``."""
    model = _make_model()
    with _table_for(model):
        model.objects.create(label="r1", notes="hello")
        model.objects.create(label="r2", notes="world")
        # Iteration must not raise even if we drop the silo context.
        with override_current_silo(None):
            instances = list(defer_encrypted(model.objects.all()))
        assert {i.label for i in instances} == {"r1", "r2"}


# ---------------------------------------------------------------------------
# probe_decryption
# ---------------------------------------------------------------------------


@pytest.mark.django_db(transaction=True)
def test_probe_decryption_decryptable_state(silo):
    model = _make_model()
    with _table_for(model):
        obj = model.objects.create(label="r", notes="hello world")
        # Reload via deferred query to get a safe shell.
        shell = defer_encrypted(model.objects.all()).get(pk=obj.pk)
        probes = probe_decryption(shell, ["notes"])
        assert probes["notes"].state == "decryptable"
        assert probes["notes"].value == "hello world"
        assert probes["notes"].display == "hello world"
        assert probes["notes"].decryptable is True
        assert probes["notes"].has_encrypted_content is True
        assert probes["notes"].error is None


@pytest.mark.django_db(transaction=True)
def test_probe_decryption_empty_state(silo):
    model = _make_model()
    with _table_for(model):
        obj = model.objects.create(label="r", notes=None)
        shell = defer_encrypted(model.objects.all()).get(pk=obj.pk)
        probes = probe_decryption(shell, ["notes"])
        assert probes["notes"].state == "empty"
        assert probes["notes"].decryptable is False  # not decryptable, just empty
        assert probes["notes"].has_encrypted_content is False
        assert probes["notes"].display == str(DEFAULT_EMPTY_FIELD_LABEL)


@pytest.mark.django_db(transaction=True)
def test_probe_decryption_empty_label_override(silo):
    model = _make_model()
    with _table_for(model):
        obj = model.objects.create(label="r", notes=None)
        shell = defer_encrypted(model.objects.all()).get(pk=obj.pk)
        probes = probe_decryption(
            shell,
            ["notes"],
            empty_labels={"notes": "No notes"},
        )
        assert probes["notes"].display == "No notes"


@pytest.mark.django_db(transaction=True)
def test_probe_decryption_undecryptable_on_aad_mismatch(silo):
    """A row whose AAD column is mutated after write must surface as an
    ``undecryptable`` probe with a typed error — not a crashed query."""
    model = _make_model(with_aad=True)
    with _table_for(model):
        obj = model.objects.create(label="r", user_id=1, notes="secret")
        # Tamper with the AAD column directly so the AAD computed at
        # read time no longer matches what was sealed at write time.
        model.objects.filter(pk=obj.pk).update(user_id=999)
        shell = defer_encrypted(model.objects.all()).get(pk=obj.pk)
        probes = probe_decryption(
            shell,
            ["notes"],
            error_labels={"notes": "Unable to decrypt."},
        )
        assert probes["notes"].state == "undecryptable"
        assert probes["notes"].decryptable is False
        assert probes["notes"].has_encrypted_content is True
        assert probes["notes"].display == "Unable to decrypt."
        assert isinstance(probes["notes"].error, EncryptedFieldDecryptionError)


@pytest.mark.django_db(transaction=True)
def test_probe_decryption_default_error_label(silo):
    model = _make_model(with_aad=True)
    with _table_for(model):
        obj = model.objects.create(label="r", user_id=1, notes="secret")
        model.objects.filter(pk=obj.pk).update(user_id=999)
        shell = defer_encrypted(model.objects.all()).get(pk=obj.pk)
        probes = probe_decryption(shell, ["notes"])
        assert probes["notes"].display == str(DEFAULT_ERROR_FIELD_LABEL)


# ---------------------------------------------------------------------------
# safe_list_rows
# ---------------------------------------------------------------------------


@pytest.mark.django_db(transaction=True)
def test_safe_list_rows_returns_all_rows_with_mixed_states(silo):
    """A page with both decryptable and undecryptable rows must include
    every row. The undecryptable row carries an error probe instead of
    crashing the iteration."""
    model = _make_model(with_aad=True)
    with _table_for(model):
        good = model.objects.create(label="good", user_id=1, notes="ok")  # noqa: F841 — paired with `bad` for contrast
        bad = model.objects.create(label="bad", user_id=2, notes="secret")
        # Tamper the second row's AAD column.
        model.objects.filter(pk=bad.pk).update(user_id=999)

        rows = safe_list_rows(
            model.objects.all().order_by("pk"),
            probe_fields=["notes"],
        )
        assert len(rows) == 2
        by_label = {r.instance.label: r for r in rows}
        assert by_label["good"].probes["notes"].state == "decryptable"
        assert by_label["good"].probes["notes"].value == "ok"
        assert by_label["bad"].probes["notes"].state == "undecryptable"
        assert isinstance(
            by_label["bad"].probes["notes"].error,
            EncryptedFieldDecryptionError,
        )


@pytest.mark.django_db(transaction=True)
def test_safe_list_rows_empty_queryset(silo):
    model = _make_model()
    with _table_for(model):
        assert safe_list_rows(model.objects.all(), probe_fields=["notes"]) == []


@pytest.mark.django_db(transaction=True)
def test_safe_list_rows_batches_probe_fetch(silo, django_assert_num_queries):
    """The list helper batches the probe-column fetch so query count
    stays constant per page rather than growing per row."""
    model = _make_model()
    with _table_for(model):
        for i in range(5):
            model.objects.create(label=f"r{i}", notes=f"note-{i}")
        # Two queries expected: the deferred SELECT for the page, plus
        # the single batched cursor SELECT for the probe columns.
        with django_assert_num_queries(2):
            rows = safe_list_rows(
                model.objects.all(),
                probe_fields=["notes"],
            )
        assert len(rows) == 5
        assert all(r.probes["notes"].state == "decryptable" for r in rows)


# ---------------------------------------------------------------------------
# safe_detail
# ---------------------------------------------------------------------------


@pytest.mark.django_db(transaction=True)
def test_safe_detail_returns_safe_shell_and_probes(silo):
    model = _make_model()
    with _table_for(model):
        obj = model.objects.create(label="row", notes="hello")
        detail = safe_detail(
            model.objects.all(),
            pk=obj.pk,
            probe_fields=["notes"],
        )
        assert isinstance(detail, SafeRow)
        assert detail.instance.label == "row"
        assert detail.probes["notes"].value == "hello"


@pytest.mark.django_db(transaction=True)
def test_safe_detail_undecryptable_does_not_crash(silo):
    """Detail view of a tampered row returns a safe shell plus an error
    state — never raises."""
    model = _make_model(with_aad=True)
    with _table_for(model):
        obj = model.objects.create(label="row", user_id=1, notes="secret")
        model.objects.filter(pk=obj.pk).update(user_id=999)
        detail = safe_detail(
            model.objects.all(),
            pk=obj.pk,
            probe_fields=["notes"],
        )
        assert detail.instance.label == "row"
        assert detail.probes["notes"].state == "undecryptable"


@pytest.mark.django_db(transaction=True)
def test_safe_detail_raises_does_not_exist_when_filtered_out(silo):
    """When the row is outside the supplied queryset's filter (typical
    for tenant scoping), the helper raises ``DoesNotExist`` so callers
    can return 404 cleanly."""
    model = _make_model()
    with _table_for(model):
        obj = model.objects.create(label="row", notes="x")
        with pytest.raises(model.DoesNotExist):
            safe_detail(
                model.objects.filter(label="other"),
                pk=obj.pk,
                probe_fields=["notes"],
            )


# ---------------------------------------------------------------------------
# SafeRow accessors keep raw state primary
# ---------------------------------------------------------------------------


def test_safe_row_accessors_expose_raw_state():
    row = SafeRow(
        instance=object(),
        probes={
            "a": FieldProbe(state="decryptable", display="A", value="A"),
            "b": FieldProbe(
                state="undecryptable",
                display="err",
                error=EncryptedFieldDecryptionError("x"),
            ),
            "c": FieldProbe(state="empty", display="—"),
        },
    )
    assert row.decryptable == {"a": True, "b": False, "c": False}
    assert row.has_encrypted_content == {"a": True, "b": True, "c": False}
    assert row.errors["a"] is None
    assert isinstance(row.errors["b"], EncryptedFieldDecryptionError)
    assert row.errors["c"] is None
    assert row.display == {"a": "A", "b": "err", "c": "—"}
