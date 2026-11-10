"""Key sets: a DEK's identity includes the set, and a field names its set with ``key_set``.

The engine-level behavior (two sets in one silo get distinct keys on their own stores) is in
``test_silo_kinds``; the swap through ``reencrypt_keys`` is in ``test_reencrypt_keys_command``.
"""

from __future__ import annotations

import pytest
from django.conf import settings
from django.db import IntegrityError, models, transaction
from django.test import override_settings

from encryption_suite.conf import SYSTEM_SILO_UID
from encryption_suite.engine import SYSTEM_SILO
from encryption_suite.fields import EncryptedCharField, EncryptedFileField
from encryption_suite.models import DataEncryptionKey
from encryption_suite.registry import get_engine
from encryption_suite.silo_ref import SiloRef, silo_filter
from tests.factories import make_kek

_COLD = SiloRef("system_cold", SYSTEM_SILO_UID)
_COLD_SETS = {"system_cold": {"silo": "system", "key_store": "local"}}


class ArchiveFile(models.Model):
    """A file in the ``archive`` set whose display name was left in the default set."""

    scan = EncryptedFileField(key_set="archive", display_name_field="scan_name", null=True, blank=True)
    scan_name = EncryptedCharField(max_length=255, null=True, blank=True)

    class Meta:
        app_label = "tests"


def _cold_stores():
    return override_settings(
        ENCRYPTION={**settings.ENCRYPTION, "KEY_SETS": {**settings.ENCRYPTION["KEY_SETS"], **_COLD_SETS}}
    )


def test_a_field_leaves_the_default_key_set_out_of_a_migration():
    _, _, _, default_kwargs = EncryptedCharField().deconstruct()
    _, _, _, named_kwargs = EncryptedCharField(key_set="archive").deconstruct()
    _, _, _, file_kwargs = EncryptedFileField(key_set="archive", display_name_field="name").deconstruct()

    assert "key_set" not in default_kwargs
    assert named_kwargs["key_set"] == "archive"
    assert file_kwargs["key_set"] == "archive"
    assert "key_set" not in EncryptedCharField(key_set="default").deconstruct()[3]


def test_the_display_name_companion_must_share_the_files_key_set():
    errors = ArchiveFile._meta.get_field("scan")._check_display_name_field()

    assert [e.id for e in errors] == ["encryption_suite.E024"]
    assert "key_set='archive'" in errors[0].msg


@pytest.mark.django_db
def test_a_data_key_names_a_non_default_set_and_one_silo_may_hold_both():
    kek = make_kek("a-kek", "local")
    common = {"silo_uid": "group-1", "silo_label": "group", "kek": kek}
    default = DataEncryptionKey.objects.create(purpose=DataEncryptionKey.PURPOSE_FIELD, **common)
    archive = DataEncryptionKey.objects.create(purpose=DataEncryptionKey.PURPOSE_FIELD, key_set="archive", **common)

    assert default.key_set == "default"
    assert str(archive) == "group:group-1 archive [field]"
    assert str(default) == "group:group-1 [field]"
    with pytest.raises(IntegrityError), transaction.atomic():
        DataEncryptionKey.objects.create(purpose=DataEncryptionKey.PURPOSE_FIELD, key_set="archive", **common)


@pytest.mark.django_db
def test_the_system_silo_keeps_a_full_set_of_keys_per_key_set():
    engine = get_engine()
    with _cold_stores():
        engine.ensure_system_keys()
        assert DataEncryptionKey.objects.filter(**silo_filter(SYSTEM_SILO)).count() == 3

        # The default set being complete does not make the cold set so.
        assert not DataEncryptionKey.objects.filter(**silo_filter(_COLD)).exists()
        engine.ensure_system_keys(key_set="system_cold")

        cold = DataEncryptionKey.objects.select_related("kek").filter(**silo_filter(_COLD))
        assert {row.purpose for row in cold} == {"field", "file", "index"}
        assert {row.kek.key_store for row in cold} == {"local"}


@pytest.mark.django_db
def test_a_blind_index_digest_is_made_under_the_key_of_its_set():
    engine = get_engine()
    with _cold_stores():
        default = engine.index_digest("ann@example.com", context="ctx", silo=SYSTEM_SILO)
        cold = engine.index_digest("ann@example.com", context="ctx", silo=_COLD)

        assert default != cold
        assert engine.index_digest("ann@example.com", context="ctx", silo=_COLD) == cold
