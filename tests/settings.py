"""Minimal Django settings for the test suite."""

import tempfile

SECRET_KEY = "test-secret-not-for-production"
DEBUG = True
USE_TZ = True

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": ":memory:",
    },
}

INSTALLED_APPS = [
    "django.contrib.contenttypes",
    "django.contrib.auth",
    "django.contrib.messages",
    "django.contrib.sessions",
    # The package ships a substantial admin (changelist actions, the Reconcile
    # Keys page, the test console), so the admin app is installed here to make
    # that surface testable at all — importing encryption_suite.admin fails
    # without it.
    "django.contrib.admin",
    "encryption_suite",
    "encryption_suite.contrib.simpleteams",
    # Models holding encrypted data in real tables, which reencrypt_data needs to
    # find by itself — the transient models elsewhere in the suite are never
    # registered with an installed app, so nothing enumerates them.
    "tests.testapp",
]

MIDDLEWARE = [
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
]

ROOT_URLCONF = "tests.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "APP_DIRS": True,
        "DIRS": [],
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
MEDIA_ROOT = tempfile.mkdtemp(prefix="encryption_suite-tests-")


ENCRYPTION = {
    # The default key set's keys go to a store whose adapter wraps under fixed test
    # material; the system key set's go to an env store. Pinned, so a test that adds a
    # second KMS block does not make the choice ambiguous.
    "KEY_SETS": {
        "default": {"silo": "tests.silo.GroupSiloAdapter", "key_store": "local"},
        "system": {"key_store": "login"},
    },
    # No external KMS in the suite: scoped keys go to a store whose adapter wraps
    # under fixed test material. One shared KEK for every silo.
    "KMS_KEY_STORES": {
        "local": {
            "ADAPTER": "tests.adapters.UnversionedTestKmsAdapter",
            "KEK_STRATEGY_ADAPTER": "encryption_suite.adapters.keks.SharedKekStrategy",
            "OPTIONS": {"SHARED_KEK_ID": "local-test-kek"},
        },
    },
    # Fixed rather than generated per run, like the system keys below. Test
    # material, with nothing of anybody's behind it.
    "ENV_KEY_STORES": {"login": {"KEKS": {1: "3q2+7wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}}},
    # The suite pins the Tink backend (the default is pyca-cryptography); the pyca
    # backend is exercised separately in tests/test_pyca_backend.py.
    "CRYPTO_BACKEND": "encryption_suite.adapters.crypto_backends.tink.TinkCryptoEngine",
    "KEY_AUTO_PROVISION": True,
    # The suite records and logs who acted unless a test says otherwise, so a
    # test about some other act can still assert who performed it. The shipped
    # default records nothing; the tests of that default clear this explicitly.
    "USER_IDENTITY": {
        "KEY_LIFECYCLE_EVENTS": ["user_id", "os_user"],
        "LOGS": ["user_id", "user_name", "os_user"],
    },
}
