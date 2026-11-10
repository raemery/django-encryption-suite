"""reencrypt_keys and reencrypt_data on the system silo: the --key option.

The default, --silo-kind scoped, leaves the system silo alone; --silo-kind system works on it
alone; --silo-kind all runs every kind, one pass each. setup_encryption_keys creates the
system keys before any silo's.
"""

from __future__ import annotations

from io import StringIO

import pytest
from django.core.management import call_command

from encryption_suite import rotation
from encryption_suite.conf import SYSTEM_SILO_UID
from encryption_suite.contrib.simpleteams.models import SimpleTeam
from encryption_suite.engine import EncryptionEngine
from encryption_suite.models import DataEncryptionKey, KeyLifecycleEvent
from encryption_suite.silo_ref import SYSTEM_SILO_REF
from tests.rotation_helpers import make_note, make_team, read_note

pytestmark = pytest.mark.django_db


@pytest.fixture(autouse=True)
def _no_wait(monkeypatch):
    monkeypatch.setattr(rotation, "_sleep", lambda seconds: None)
    EncryptionEngine.invalidate_cache()
    yield
    EncryptionEngine.invalidate_cache()


def _call(name, *args) -> str:
    out = StringIO()
    call_command(name, *args, stdout=out, stderr=StringIO())
    return out.getvalue()


def _system_field_key():
    return DataEncryptionKey.objects.get(silo_uid=SYSTEM_SILO_UID, purpose=DataEncryptionKey.PURPOSE_FIELD)


def test_reencrypt_data_with_key_system_rotates_the_system_silo_and_its_data_still_reads():
    team = SimpleTeam.objects.create(name="Acme")
    before = _system_field_key().dek_key_version

    _call("reencrypt_data", "--key-set", "system", "--purpose", "field")

    assert _system_field_key().dek_key_version == before + 1
    EncryptionEngine.invalidate_cache()
    assert SimpleTeam.objects.get(pk=team.pk).name == "Acme"


def test_reencrypt_data_by_default_leaves_the_system_silo_alone():
    SimpleTeam.objects.create(name="Acme")
    team = make_team()
    note = make_note(team, title="t", body="b")
    before = _system_field_key().dek_key_version

    _call("reencrypt_data", "--purpose", "field")

    assert _system_field_key().dek_key_version == before
    assert read_note(note.pk, team) == ("t", "b")


def _counts():
    return dict(DataEncryptionKey.objects.values_list("pk", "reencryption_count"))


def _add_system_kek_version(settings):
    import base64

    from encryption_suite import registry

    versions = {**settings.ENCRYPTION["ENV_KEY_STORES"]["login"]["KEKS"], 2: base64.b64encode(b"" * 32).decode()}
    settings.ENCRYPTION = {**settings.ENCRYPTION, "ENV_KEY_STORES": {"login": {"KEKS": versions}}}
    registry.reset()
    EncryptionEngine.invalidate_cache()


def test_reencrypt_keys_with_key_system_rewraps_only_the_system_silo(settings):
    SimpleTeam.objects.create(name="Acme")
    team = make_team()
    make_note(team)
    _add_system_kek_version(settings)
    before = _counts()

    _call("reencrypt_keys", "--key-set", "system")

    after = _counts()
    system = set(DataEncryptionKey.objects.filter(silo_uid=SYSTEM_SILO_UID).values_list("pk", flat=True))
    assert system and all(after[pk] == before[pk] + 1 for pk in system)
    assert all(after[pk] == before[pk] for pk in after if pk not in system)
    assert _system_field_key().kek_key_version == "2"
    EncryptionEngine.invalidate_cache()
    assert SimpleTeam.objects.get(name="Acme").name == "Acme"


def test_reencrypt_keys_by_default_leaves_the_system_silo_alone(settings):
    SimpleTeam.objects.create(name="Acme")
    _add_system_kek_version(settings)
    before = _counts()

    _call("reencrypt_keys")

    assert _counts() == before
    assert _system_field_key().kek_key_version == "1"


def _point_system_at(settings, store):
    from encryption_suite import registry
    from tests.key_set_settings import key_sets

    settings.ENCRYPTION = {**settings.ENCRYPTION, "KEY_SETS": key_sets(system=store)}
    registry.reset()
    EncryptionEngine.invalidate_cache()


def _system_stores():
    rows = DataEncryptionKey.objects.filter(silo_uid=SYSTEM_SILO_UID).select_related("kek")
    return {row.kek.key_store for row in rows}


def test_the_system_key_set_moves_between_an_env_store_and_a_kms_store_and_back(settings):
    """The swap is a settings change and a run, in either direction, with the old store left configured."""
    SimpleTeam.objects.create(name="Acme")
    assert _system_stores() == {"login"}

    _point_system_at(settings, "local")
    # Nothing has moved yet: rows read through the store they name.
    assert SimpleTeam.objects.get(name="Acme").name == "Acme"
    assert _system_stores() == {"login"}

    _call("reencrypt_keys", "--key-set", "system")

    assert _system_stores() == {"local"}
    EncryptionEngine.invalidate_cache()
    assert SimpleTeam.objects.get(name="Acme").name == "Acme"

    _point_system_at(settings, "login")
    _call("reencrypt_keys", "--key-set", "system")

    assert _system_stores() == {"login"}
    EncryptionEngine.invalidate_cache()
    assert SimpleTeam.objects.get(name="Acme").name == "Acme"


def test_silo_uid_with_key_system_is_refused():
    from django.core.management.base import CommandError

    with pytest.raises(CommandError):
        _call("reencrypt_data", "--key-set", "system", "--silo-uid", "group-1")


def test_setup_creates_the_system_keys_before_any_silo(settings):
    identity = {"SCOPE": "all_acts", "KEY_LIFECYCLE_EVENTS": ["encrypted_os_user"]}
    settings.ENCRYPTION = {**settings.ENCRYPTION, "USER_IDENTITY": identity}
    make_team()

    _call("setup_encryption_keys")

    assert set(DataEncryptionKey.objects.filter(silo_uid=SYSTEM_SILO_UID).values_list("purpose", flat=True)) == {
        DataEncryptionKey.PURPOSE_FIELD,
        DataEncryptionKey.PURPOSE_FILE,
        DataEncryptionKey.PURPOSE_INDEX,
    }
    # Made first, so the team keys' events carry the operator's encrypted identity.
    team_events = KeyLifecycleEvent.objects.filter(dek__isnull=False).exclude(silo_uid=SYSTEM_SILO_UID)
    assert team_events.exists() and all(event.os_user_id is not None for event in team_events)


def test_an_env_store_key_can_be_recorded_by_hand():
    from encryption_suite import lifecycle
    from encryption_suite.models import KeyEncryptionKey

    _call("record_key_event", "--event", "deleted", "--kek-resource-name", "shared", "--key-store", "login")

    row = KeyEncryptionKey.objects.get(key_store="login", kek_resource_name="shared")
    assert row.status == lifecycle.STATUS_DELETED


def test_a_system_data_key_is_retained_even_where_in_use_keys_may_be_deleted(settings):
    from encryption_suite.deletion import RETAIN_SILO_LIVE, dek_retain_reason

    settings.ENCRYPTION = {**settings.ENCRYPTION, "KEY_DELETION_CAN_RENDER_DATA_INACCESSIBLE": True}

    assert dek_retain_reason(SYSTEM_SILO_REF) == RETAIN_SILO_LIVE
