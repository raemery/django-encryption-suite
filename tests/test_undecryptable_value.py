"""What the lenient-read sentinel does when code treats it as a string.

A read that fails hands back an ``UndecryptableValue`` instead of raising. Code
that only displays it is fine; code that calls a string method on it needs the
plaintext and cannot continue. That code gets the underlying error, made
form-visible, rather than an ``AttributeError`` that reaches the user as a 500.
"""

from __future__ import annotations

import copy

import pytest
from django import forms
from django.core.exceptions import ValidationError
from django.template import Context, Template
from django.utils.html import conditional_escape

from encryption_suite.exceptions import GENERIC_ENCRYPT_DECRYPT_UNAVAILABLE_MESSAGE, DekReencryptionInProgressError
from encryption_suite.fields import UndecryptableValue

FALLBACK = "Unable to decrypt."


def _sentinel(error=None):
    error = error or DekReencryptionInProgressError(GENERIC_ENCRYPT_DECRYPT_UNAVAILABLE_MESSAGE, detail="rotating")
    return UndecryptableValue(FALLBACK, error, "email")


@pytest.mark.parametrize("method", ["lower", "strip", "split", "startswith"])
def test_a_str_method_raises_the_underlying_error(method):
    with pytest.raises(DekReencryptionInProgressError) as caught:
        getattr(_sentinel(), method)

    error = caught.value
    assert isinstance(error, ValidationError)
    assert error.code == "dek_reencryption_in_progress"
    assert error.detail == "rotating"
    assert str(error) == "Encryption and decryption are unavailable for this data."


def test_inside_a_form_it_is_a_form_error():
    """allauth signs a user in by comparing ``user.email.lower()`` from clean()."""

    class SignIn(forms.Form):
        login = forms.CharField()

        def clean(self):
            if _sentinel().lower() != self.cleaned_data["login"].lower():
                raise ValidationError("wrong address")
            return self.cleaned_data

    form = SignIn(data={"login": "ann@example.com"})

    assert not form.is_valid()
    assert form.non_field_errors() == ["Encryption and decryption are unavailable for this data."]


def test_display_and_detection_are_unchanged():
    value = _sentinel()

    assert str(value) == FALLBACK
    assert not value
    assert value.field_name == "email"
    assert isinstance(value.error, DekReencryptionInProgressError)
    # Django's own checks probe underscore names; those stay ordinary misses.
    assert not hasattr(value, "__html__")
    assert str(conditional_escape(value)) == FALLBACK
    assert Template("{{ v }}|{{ v|lower }}").render(Context({"v": value})) == "Unable to decrypt.|unable to decrypt."
    assert str(copy.copy(value)) == FALLBACK


def test_a_name_that_is_not_a_str_method_is_an_ordinary_miss():
    with pytest.raises(AttributeError):
        _sentinel().no_such_attribute  # noqa: B018


def test_a_non_package_error_keeps_the_attribute_error():
    """Only an EncryptionError has the typed, translated message to raise."""
    with pytest.raises(AttributeError):
        _sentinel(RuntimeError("boom")).lower  # noqa: B018
