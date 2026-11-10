"""The download view factory's flash while a data key rotation fences a file.

A fence lifts on its own, so a download refused by one must not flash the
wording a consumer chose for a file that is broken for good.
"""

from __future__ import annotations

import pytest
from django.contrib.messages import get_messages
from django.contrib.messages.storage.fallback import FallbackStorage
from django.contrib.sessions.backends.db import SessionStore
from django.test import RequestFactory

from encryption_suite import rotation
from encryption_suite.adapters.silos.context import override_current_silo
from encryption_suite.engine import EncryptionEngine
from encryption_suite.exceptions import GENERIC_ENCRYPT_DECRYPT_UNAVAILABLE_MESSAGE
from encryption_suite.file_view_helpers import encrypted_file_download_view
from tests.rotation_helpers import make_document, make_team, open_rotation
from tests.testapp.models import Document

pytestmark = pytest.mark.django_db


@pytest.fixture(autouse=True)
def _no_wait(monkeypatch):
    monkeypatch.setattr(rotation, "_sleep", lambda seconds: None)
    EncryptionEngine.invalidate_cache()
    yield
    EncryptionEngine.invalidate_cache()


def _request():
    request = RequestFactory().get("/download")
    request.session = SessionStore()
    request._messages = FallbackStorage(request)
    return request


def _view():
    return encrypted_file_download_view(
        field_name="upload",
        get_instance=lambda request, pk: Document.objects.get(pk=pk),
        error_redirect=lambda request, obj: f"/documents/{obj.pk}/",
        error_flash_message="This file is corrupted.",
    )


def test_a_fenced_download_flashes_the_unavailable_message_not_the_consumers():
    team = make_team()
    document = make_document(team)
    open_rotation(team, "file")
    request = _request()

    EncryptionEngine.invalidate_cache()
    with override_current_silo(team):
        response = _view()(request, pk=document.pk)

    assert response.status_code == 302
    assert [str(m) for m in get_messages(request)] == [str(GENERIC_ENCRYPT_DECRYPT_UNAVAILABLE_MESSAGE)]


def test_any_other_download_failure_still_flashes_the_consumers_message():
    team = make_team()
    document = make_document(team)
    Document.objects.filter(pk=document.pk).update(team=make_team("other"))
    request = _request()

    EncryptionEngine.invalidate_cache()
    with override_current_silo(team):
        response = _view()(request, pk=document.pk)

    assert response.status_code == 302
    assert [str(m) for m in get_messages(request)] == ["This file is corrupted."]
