"""What ``manage.py check`` says about the columns a field's ``aad=`` binds.

AAD is part of the key to the field's encrypted value, so a bound column
has to be readable, present, and stable for as long as the ciphertext is. Two
declarations break that quietly:

* a **nullable** column — encryption refuses to write a row whose AAD column is
  ``None``, and a row whose column went ``None`` afterwards can no longer be
  read. A foreign key with ``on_delete=SET_NULL`` gets there on one delete of
  the row it points at.
* an **encrypted** column — reading it to build the AAD goes through the
  decrypting descriptor, so one decrypt depends on another.

Neither fails at deploy on its own, which is exactly why the checks exist: a
nullable column is still a schema decision at ``check`` time and a migration
over live ciphertext afterwards.
"""

from __future__ import annotations

from django.db import models

from encryption_suite.fields import EncryptedCharField, EncryptedFileField

_counter = 0


def _make_model(aad_columns, **extra_fields):
    """A throwaway model whose ``secret`` field declares ``aad=aad_columns``, never migrated."""
    global _counter
    _counter += 1
    attrs = {
        "__module__": "tests.test_aad_column_checks",
        "Meta": type("Meta", (), {"app_label": "tests"}),
        "team": models.ForeignKey("auth.Group", on_delete=models.CASCADE, related_name="+"),
        "author": models.CharField(max_length=100),
        "secret": EncryptedCharField(max_length=200, null=True, blank=True, aad=aad_columns),
        **extra_fields,
    }
    return type(f"AadCheckModel{_counter}", (models.Model,), attrs)


def _check(model, field_name="secret"):
    return model._meta.get_field(field_name).check()


def _ids(errors):
    return [e.id for e in errors]


def test_columns_that_are_present_and_plain_report_nothing():
    """The shape the checks are protecting: a non-null FK and a non-null column."""
    assert _check(_make_model(("team", "author"))) == []


def test_a_nullable_column_warns():
    model = _make_model(("author",), author=models.CharField(max_length=100, null=True))

    (warning,) = _check(model)

    assert warning.id == "encryption_suite.W054"
    assert "'author'" in warning.msg
    assert "It is nullable." in warning.msg


def test_a_set_null_foreign_key_says_what_makes_it_null():
    """The route worth naming: the column is fine until someone deletes a group."""
    model = _make_model(
        ("team",),
        team=models.ForeignKey("auth.Group", on_delete=models.SET_NULL, null=True, related_name="+"),
    )

    (warning,) = _check(model)

    assert warning.id == "encryption_suite.W054"
    assert "on_delete=SET_NULL" in warning.msg


def test_a_nullable_foreign_key_warns_without_claiming_set_null():
    model = _make_model(
        ("team",),
        team=models.ForeignKey("auth.Group", on_delete=models.CASCADE, null=True, related_name="+"),
    )

    (warning,) = _check(model)

    assert warning.id == "encryption_suite.W054"
    assert "nullable foreign key" in warning.msg
    assert "SET_NULL" not in warning.msg


def test_a_warning_is_a_warning_not_a_deploy_failure():
    """``manage.py check`` exits non-zero on errors only, and the schema is legal."""
    model = _make_model(("author",), author=models.CharField(max_length=100, null=True))

    (warning,) = _check(model)

    assert warning.level < 40  # below ERROR


def test_an_encrypted_column_in_the_tuple_is_an_error():
    """Decrypting the field would depend on decrypting the field."""
    model = _make_model(("author", "secret"))

    ids = _ids(_check(model))

    assert "encryption_suite.E022" in ids


def test_an_encrypted_file_column_in_the_tuple_is_an_error():
    model = _make_model(
        ("scan",),
        scan_name=EncryptedCharField(max_length=255, null=True, blank=True),
        scan=EncryptedFileField(display_name_field="scan_name", null=True, blank=True),
    )

    ids = _ids(_check(model))

    assert "encryption_suite.E022" in ids


def test_an_encrypted_column_is_reported_once_not_also_as_nullable():
    """The nullability of an encrypted AAD column is beside the point."""
    model = _make_model(("secret",))

    (error,) = _check(model)

    assert error.id == "encryption_suite.E022"


def test_a_file_field_checks_its_own_aad():
    model = _make_model(
        (),
        scan_name=EncryptedCharField(max_length=255, null=True, blank=True),
        scan=EncryptedFileField(display_name_field="scan_name", null=True, blank=True, aad=("author", "scan_name")),
    )

    ids = _ids(_check(model, "scan"))

    assert "encryption_suite.E022" in ids


def test_a_malformed_declaration_is_reported():
    model = _make_model("author")

    (error,) = _check(model)

    assert error.id == "encryption_suite.E020"
    assert "aad=" in error.msg


def test_every_bad_column_is_named_not_just_the_first():
    """One ``check`` run, one round of schema edits."""
    model = _make_model(
        ("team", "author", "secret"),
        team=models.ForeignKey("auth.Group", on_delete=models.SET_NULL, null=True, related_name="+"),
        author=models.CharField(max_length=100, null=True),
    )

    ids = _ids(_check(model))

    assert ids.count("encryption_suite.W054") == 2
    assert ids.count("encryption_suite.E022") == 1
