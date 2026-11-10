import django
import pytest
from django.conf import settings as django_settings


def pytest_configure(config):
    if not django_settings.configured:
        import tests.settings as s

        django_settings.configure(**{k: getattr(s, k) for k in dir(s) if k.isupper()})
    django.setup()


@pytest.fixture
def tenant(db):
    from django.contrib.auth.models import Group

    return Group.objects.create(name="acme")


@pytest.fixture
def silo_context(tenant):
    from encryption_suite.adapters.silos.context import override_current_silo

    with override_current_silo(tenant):
        yield tenant


@pytest.fixture
def configured_owner_prefix(monkeypatch):
    """Make the live KEK strategy report a given owner prefix and disposition.

    The purge authorizes against the running configuration rather than the values
    stored on the scheduled row, so a test whose rows claim a prefix has to
    configure a strategy that backs it. The test settings use
    ``SharedKekStrategy``, whose owner prefix is ``None`` and whose disposition is
    shared — both of which retain every row.
    """

    def _apply(prefix, disposition=None):
        from encryption_suite.models import KeyEncryptionKey

        resolved = disposition or KeyEncryptionKey.DISPOSITION_SILO_EXCLUSIVE

        class _Strategy:
            def owner_prefix(self):
                return prefix

            def kek_disposition(self, silo_uid):
                return resolved

            def kek_disposition_for_name(self, kek_resource_name, owner_prefix):
                # Same answer from either starting point, which is the property
                # the real strategies are written to hold.
                return resolved

        monkeypatch.setattr("encryption_suite.registry.get_kek_strategy_adapter", lambda name=None: _Strategy())

    return _apply


@pytest.fixture
def configured_kms(settings):
    """Add a ``KMS_KEY_STORES`` block named *name*, by default making it the ``scoped`` kind's KMS store.

    Every path that acts on a key encryption key row routes by the KMS name the
    row records, and skips a name no block carries. A test that installs fake
    adapters by patching the registry's getters still needs its rows' name to be
    a configured one. Built unpatched, the block is the suite's own adapter under
    a key encryption key of its own.
    """

    def _apply(name, *, silo_kms=True):
        encryption = dict(settings.ENCRYPTION)
        encryption["KMS_KEY_STORES"] = {
            **(encryption.get("KMS_KEY_STORES") or {}),
            name: {
                "ADAPTER": "tests.adapters.UnversionedTestKmsAdapter",
                "KEK_STRATEGY_ADAPTER": "encryption_suite.adapters.keks.SharedKekStrategy",
                "OPTIONS": {"SHARED_KEK_ID": f"{name}-kek"},
            },
        }

        if silo_kms:
            key_sets = dict(encryption.get("KEY_SETS") or {})
            key_sets["default"] = {**key_sets.get("default", {}), "key_store": name}
            encryption["KEY_SETS"] = key_sets
        settings.ENCRYPTION = encryption

    return _apply


@pytest.fixture(autouse=True)
def _reset_registry():
    yield
    from encryption_suite import registry
    from encryption_suite.engine import EncryptionEngine

    registry.reset()
    # The primitive cache outlives a test's rolled-back rows. The system silo has
    # one UID in every test, so a key cached by one would answer for the next
    # test's freshly created one.
    EncryptionEngine.invalidate_cache()


@pytest.fixture(autouse=True)
def _reset_encryption_settings():
    """Drop the settings cache whenever a test overrides ``ENCRYPTION``.

    ``enc_settings`` loads once and caches, so a test that reads a setting before
    entering an ``override_settings`` block would keep reading the old value
    inside it. Reading is now common enough — every ledger write asks which
    identities may be recorded — that the trap is easy to walk into.
    """
    from django.test.signals import setting_changed

    from encryption_suite.conf import enc_settings

    def _reset(**kwargs):
        if kwargs.get("setting") == "ENCRYPTION":
            enc_settings.reset()

    setting_changed.connect(_reset)
    yield
    setting_changed.disconnect(_reset)
