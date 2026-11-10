"""The KMS Keys add form's KMS name field.

Every unwrap, deletion and reconcile pass routes by the KMS name a row records,
and uniqueness is ``(key_store, kek_resource_name)``. A row naming a KMS no block
carries would look tracked and do nothing, so the add form offers the configured
names and nothing else, with ``SILO_KEY_STORES`` preselected. Not ``system``: no KMS
outside this application holds its key, so there is no act there to record.
"""

from __future__ import annotations

import pytest
from django.contrib.admin.sites import AdminSite
from django.contrib.auth.models import User
from django.contrib.messages.storage.fallback import FallbackStorage
from django.test import RequestFactory

from encryption_suite import lifecycle
from encryption_suite.admin_lifecycle import KeyEncryptionKeyAdmin
from encryption_suite.models import KeyEncryptionKey, KeyLifecycleEvent


@pytest.fixture
def model_admin():
    return KeyEncryptionKeyAdmin(KeyEncryptionKey, AdminSite())


@pytest.fixture
def request_with_messages():
    def _build():
        request = RequestFactory().post("/admin/")
        request.user = User(username="alice", is_staff=True, is_superuser=True)
        request.session = {}
        request._messages = FallbackStorage(request)
        return request

    return _build


def _kms_field(model_admin, request):
    form = model_admin.get_form(request, obj=None)
    return form.base_fields["key_store"]


@pytest.mark.django_db
def test_the_field_offers_the_configured_names_with_silo_kms_selected(
    model_admin, request_with_messages, configured_kms
):
    configured_kms("other", silo_kms=False)
    field = _kms_field(model_admin, request_with_messages())

    assert [value for value, _label in field.choices] == ["local", "other"]
    assert field.initial == "local"


@pytest.mark.django_db
def test_an_unconfigured_name_does_not_validate(model_admin, request_with_messages):
    form_class = model_admin.get_form(request_with_messages(), obj=None)
    form = form_class(data={"key_store": "aws", "kek_resource_name": "alias/foreign", "disposition": ""})

    assert not form.is_valid()
    assert "key_store" in form.errors


@pytest.mark.django_db
def test_saving_records_the_created_event(model_admin, request_with_messages):
    request = request_with_messages()
    row = KeyEncryptionKey(key_store="local", kek_resource_name="alias/recorded")

    model_admin.save_model(request, row, form=None, change=False)

    assert KeyLifecycleEvent.objects.filter(kek=row, event=lifecycle.EVENT_CREATED).exists()


@pytest.mark.django_db
def test_an_unreadable_configuration_does_not_break_the_form(model_admin, request_with_messages, monkeypatch):
    # An operator records a key by hand exactly while sorting a configuration out.
    monkeypatch.setattr("encryption_suite.conf.configured_setting", lambda name: None)

    field = _kms_field(model_admin, request_with_messages())

    # Only the env key store is left, and it is not offered: an empty choice, not an error.
    assert list(field.choices) == []
    assert field.initial is None
