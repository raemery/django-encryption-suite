"""Tests for the ``__str__`` guard on models with encrypted fields.

``str()`` requires a ``str`` back, and Django calls ``str(obj)`` where no project
code can intercept it: the admin's action checkbox, page titles, history log, and
the delete confirmation's list of cascaded rows. A ``__str__`` that reads an
encrypted field falls back to Django's default label when the read cannot or must
not produce plaintext.
"""

from __future__ import annotations

import logging
from unittest.mock import patch

import pytest
from django.contrib import admin
from django.contrib.auth.models import Group
from django.db import models

from encryption_suite.adapters.silos.context import override_current_silo
from encryption_suite.admin_mixins import EncryptionAdminMixin, _AdminModelIterable
from encryption_suite.engine import stamp
from encryption_suite.exceptions import GENERIC_ENCRYPT_DECRYPT_UNAVAILABLE_MESSAGE, EncryptionConfigurationError
from encryption_suite.fields import (
    ADMIN_LOADED,
    EncryptedAttributeDescriptor,
    EncryptedCharField,
    UndecryptableValue,
    strict_mode,
)

CIPHERTEXT = stamp("~^Dv1:c3RvcmVk")

_model_counter = 0


def _make_model(str_field: str, *, key_set: str = "default", bases=(models.Model,), **extra):
    global _model_counter
    _model_counter += 1
    attrs = {
        "__module__": "tests.test_str_guard",
        "Meta": type("Meta", (), {"app_label": "tests", **extra.pop("meta", {})}),
        "__str__": lambda self: getattr(self, str_field),
        **extra,
    }
    if bases == (models.Model,):
        attrs["label"] = models.CharField(max_length=50)
        attrs["secret"] = EncryptedCharField(max_length=100, key_set=key_set)
    return type(f"StrGuardModel{_model_counter}", bases, attrs)


def _make_admin(model):
    cls = type("TestAdmin", (EncryptionAdminMixin, admin.ModelAdmin), {})
    return cls(model, admin.site)


def _admin_loaded(instance):
    instance.__dict__[ADMIN_LOADED] = True
    return instance


def _stored(model, **values):
    """An instance whose encrypted column holds stored ciphertext, as a database read leaves it."""
    instance = model(pk=7, **values)
    instance.__dict__["secret"] = CIPHERTEXT
    return instance


# ---------------------------------------------------------------------------
# Admin-loaded instances: every encrypted read is refused
# ---------------------------------------------------------------------------


def test_admin_loaded_str_reading_encrypted_field_falls_back_to_django_default():
    model = _make_model("secret")
    instance = _admin_loaded(model(pk=7, label="plain", secret="hidden"))
    assert str(instance) == f"{model.__name__} object (7)"


def test_admin_loaded_str_reading_plain_field_is_unchanged():
    model = _make_model("label")
    instance = _admin_loaded(model(pk=7, label="plain", secret="hidden"))
    assert str(instance) == "plain"


def test_admin_loaded_refusal_holds_inside_a_nested_str():
    inner_model = _make_model("secret")
    inner = inner_model(pk=3, label="plain", secret="hidden")
    outer_model = _make_model("label")
    outer_model.__str__ = lambda self: str(inner)
    from encryption_suite.fields import _guard_str

    _guard_str(outer_model)
    outer = _admin_loaded(outer_model(pk=7))
    assert str(outer) == f"{inner_model.__name__} object (3)"


def test_get_queryset_marks_instances_it_loads():
    model = _make_model("secret")
    ma = _make_admin(model)
    qs = ma.get_queryset(request=None)
    assert qs._iterable_class is _AdminModelIterable


# ---------------------------------------------------------------------------
# Every other instance: refused only when the read could only fail
# ---------------------------------------------------------------------------


def test_no_silo_in_context_falls_back_without_decrypting_and_warns_once(caplog):
    model = _make_model("secret")
    instance = _stored(model, label="plain")
    with (
        patch.object(EncryptedAttributeDescriptor, "_decrypt_and_cache") as decrypt,
        caplog.at_level(logging.WARNING, logger="encryption_suite"),
    ):
        assert str(instance) == f"{model.__name__} object (7)"
    decrypt.assert_not_called()
    assert [r.levelno for r in caplog.records] == [logging.WARNING]
    message = caplog.records[0].getMessage()
    assert "error_code=" not in message
    assert f'field="tests.{model.__name__}.secret"' in message
    assert "key_set=default" in message


def test_no_silo_inside_strict_mode_raises_the_typed_error(caplog):
    model = _make_model("secret")
    instance = _stored(model, label="plain")
    with caplog.at_level(logging.WARNING, logger="encryption_suite"), strict_mode():
        with pytest.raises(EncryptionConfigurationError) as excinfo:
            str(instance)
    assert str(excinfo.value) == str(GENERIC_ENCRYPT_DECRYPT_UNAVAILABLE_MESSAGE)
    assert [r.levelno for r in caplog.records] == [logging.ERROR]
    assert "No silo in the current context" in caplog.records[0].getMessage()


def test_admin_loaded_refusal_holds_inside_strict_mode(caplog):
    model = _make_model("secret")
    instance = _admin_loaded(_stored(model, label="plain"))
    with caplog.at_level(logging.WARNING, logger="encryption_suite"), strict_mode():
        assert str(instance) == f"{model.__name__} object (7)"
    assert not caplog.records


def test_admin_loaded_refusal_logs_nothing(caplog):
    model = _make_model("secret")
    instance = _admin_loaded(_stored(model, label="plain"))
    with caplog.at_level(logging.WARNING, logger="encryption_suite"):
        str(instance)
    assert not caplog.records


def test_silo_in_context_decrypts_as_usual():
    model = _make_model("secret")
    instance = _stored(model, label="plain")
    with (
        override_current_silo(Group(pk=1)),
        patch.object(EncryptedAttributeDescriptor, "_decrypt_and_cache", return_value="decrypted") as decrypt,
    ):
        assert str(instance) == "decrypted"
    decrypt.assert_called_once()


def test_system_key_set_decrypts_without_a_silo_in_context():
    model = _make_model("secret", key_set="system")
    instance = _stored(model, label="plain")
    with patch.object(EncryptedAttributeDescriptor, "_decrypt_and_cache", return_value="decrypted"):
        assert str(instance) == "decrypted"


def test_failed_decrypt_falls_back_to_django_default():
    model = _make_model("secret")
    instance = model(pk=7, label="plain")
    instance.__dict__["secret"] = UndecryptableValue("Decryption failed.", RuntimeError(), "secret")
    assert str(instance) == f"{model.__name__} object (7)"


def test_plaintext_on_the_instance_is_returned():
    model = _make_model("secret")
    instance = model(pk=7, label="plain", secret="hidden")
    assert str(instance) == "hidden"


def test_encrypted_reads_work_again_after_a_refused_str():
    model = _make_model("secret")
    instance = _admin_loaded(model(pk=7, label="plain", secret="hidden"))
    str(instance)
    assert instance.secret == "hidden"


# ---------------------------------------------------------------------------
# Installation
# ---------------------------------------------------------------------------


def test_model_without_encrypted_fields_is_not_wrapped():
    global _model_counter
    _model_counter += 1
    model = type(
        f"StrGuardPlain{_model_counter}",
        (models.Model,),
        {
            "__module__": "tests.test_str_guard",
            "Meta": type("Meta", (), {"app_label": "tests"}),
            "label": models.CharField(max_length=50),
        },
    )
    assert not getattr(model.__str__, "_encryption_suite_guarded", False)


def test_proxy_with_its_own_str_over_a_parent_encrypted_field_is_wrapped():
    parent = _make_model("label")
    proxy = _make_model("secret", bases=(parent,), meta={"proxy": True})
    instance = _stored(proxy, label="plain")
    assert str(instance) == f"{proxy.__name__} object (7)"


def test_admin_does_not_wrap_twice():
    model = _make_model("secret")
    wrapped = model.__str__
    _make_admin(model)
    assert model.__str__ is wrapped
