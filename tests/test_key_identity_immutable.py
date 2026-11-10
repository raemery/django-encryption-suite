"""A KeyEncryptionKey row's identity is fixed once the row exists.

``key_store`` /``kek_resource_name`` name *which* KMS key a row stands for.
The deletion gates read them, so reassigning them would aim an irreversible
deletion at a key nobody chose.
"""

import pytest

from encryption_suite.exceptions import EncryptionError, KeyIdentityImmutableError
from encryption_suite.models import KeyEncryptionKey
from tests.factories import make_kek_row


@pytest.fixture
def kek(db):
    return make_kek_row(key_store="local", kek_resource_name="kek-1")


@pytest.mark.parametrize(
    ("field", "new_value"),
    [
        ("key_store", "aws"),
        ("kek_resource_name", "alias/somebody-elses-key"),
    ],
)
def test_reassigning_an_identity_field_is_refused(kek, field, new_value):
    setattr(kek, field, new_value)

    with pytest.raises(KeyIdentityImmutableError):
        kek.save()

    kek.refresh_from_db()
    assert getattr(kek, field) != new_value


def test_refusal_is_an_encryption_error_with_generic_message_and_operator_detail(kek):
    """Package standard: typed error, generic translated message, detail on the exception."""
    kek.kek_resource_name = "alias/somebody-elses-key"

    with pytest.raises(EncryptionError) as excinfo:
        kek.save()

    exc = excinfo.value
    assert exc.code == "key_identity_immutable"
    # The user-facing string carries no internals; the operator detail does.
    assert "somebody-elses-key" not in str(exc)
    assert "somebody-elses-key" in exc.detail
    assert "kek-1" in exc.detail


def test_refusal_is_logged_once_with_the_slug(kek, caplog):
    kek.key_store = "aws"

    with caplog.at_level("ERROR", logger="encryption_suite.models"), pytest.raises(EncryptionError):
        kek.save()

    records = [r for r in caplog.records if "key_identity_immutable" in r.getMessage()]
    assert len(records) == 1
    # No traceback attached — an operator reading the log should not see package frames.
    assert records[0].exc_info is None


def test_non_identity_fields_stay_writable(kek):
    """Scheduling writes disposition/owner_prefix on an existing row; that must keep working."""
    kek.disposition = KeyEncryptionKey.DISPOSITION_SILO_EXCLUSIVE
    kek.owner_prefix = "alias/es-prod-"
    kek.save(update_fields=["disposition", "owner_prefix", "updated_at"])

    kek.refresh_from_db()
    assert kek.disposition == KeyEncryptionKey.DISPOSITION_SILO_EXCLUSIVE
    assert kek.owner_prefix == "alias/es-prod-"


def test_repeated_saves_of_an_unchanged_identity_are_fine(kek):
    kek.save()
    kek.save()

    assert KeyEncryptionKey.objects.count() == 1


def test_a_new_row_has_no_prior_identity_to_contradict(db):
    """Creation sets identity for the first time — nothing to compare against."""
    row = KeyEncryptionKey(key_store="aws", kek_resource_name="alias/es-prod-team-1")
    row.save()

    assert row.pk is not None


def test_queryset_update_bypasses_the_guard(kek):
    """Documented limitation: update() does not call save(), and is not covered."""
    KeyEncryptionKey.objects.filter(pk=kek.pk).update(kek_resource_name="alias/whatever")

    kek.refresh_from_db()
    assert kek.kek_resource_name == "alias/whatever"


@pytest.mark.django_db
def test_the_dek_admin_form_cannot_repoint_a_row_at_another_key():
    """Which key wrapped a data encryption key is recorded, never chosen.

    The relation is displayed read-only. Editable, it would let someone point a
    row at a key that never encrypted it — and the next read would fail against a
    key that cannot unwrap it, with no record of what the row used to name.
    """
    from django.contrib import admin as django_admin

    from encryption_suite.admin import DataEncryptionKeyAdmin
    from encryption_suite.models import DataEncryptionKey

    model_admin = DataEncryptionKeyAdmin(DataEncryptionKey, django_admin.site)
    form = model_admin.get_form(request=None, obj=None)

    assert "kek" not in form.base_fields
    assert "encrypted_keyset" not in form.base_fields
