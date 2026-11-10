"""What the console's boxes show when an adapter cannot be built.

A box reports the configuration. Its heading color comes from the tests below
it, so the box has nothing to say about a failure — and a configuration bad
enough to stop an adapter being built is exactly when an operator most wants to
see what the settings actually say. So the box falls back to the file's own
values rather than replacing them with the error, which the test run reports
once.
"""

from __future__ import annotations

from django.test import override_settings

from encryption_suite.admin_test_console import _build_boxes

_NO_STATUS = {"backend": None, "kms": None, "storage": None}


def _box(boxes, key):
    return next(box for box in boxes if box["key"] == key)


def _lines(box):
    return {line[0]: line[1] for line in box["lines"]}


def _boxes(key_store):
    from encryption_suite import registry

    registry.reset()
    try:
        return _build_boxes(_NO_STATUS, key_store)
    finally:
        registry.reset()


@override_settings(
    ENCRYPTION={
        "KEY_SETS": {
            "default": {
                "silo": "encryption_suite.adapters.silos.generic.GenericModelSiloAdapter",
                "key_store": "login",
            }
        },
        "CRYPTO_BACKEND_OPTIONS": {"AEAD": "AES512_GCM"},
    }
)
def test_an_unbuildable_engine_still_shows_the_configured_values():
    """The AEAD name that stopped the engine being built is the thing to show."""
    box = _box(_boxes("login"), "backend")

    lines = _lines(box)
    # The same rows a built engine shows: its short name, and labelled options.
    assert lines["Backend"] == "cryptography"
    assert lines["Cipher"] == "AES512_GCM"
    assert "error" not in box


@override_settings(
    ENCRYPTION={
        "KEY_SETS": {
            "default": {
                "silo": "encryption_suite.adapters.silos.generic.GenericModelSiloAdapter",
                "key_store": "broken",
            }
        },
        "KMS_KEY_STORES": {
            "broken": {
                "ADAPTER": "encryption_suite.adapters.key_stores.nope.NoSuchAdapter",
                "KEK_STRATEGY_ADAPTER": "encryption_suite.adapters.keks.SharedKekStrategy",
                "OPTIONS": {"SHARED_KEK_ID": "some-key"},
            },
        },
    }
)
def test_an_unbuildable_kms_shows_the_settings_and_dashes_the_rest():
    lines = _lines(_box(_boxes("broken"), "kms"))

    # The class name, as a built box reports it — not the configured path.
    assert lines["Key store"] == "broken"
    assert lines["Adapter"] == "NoSuchAdapter"
    assert lines["Key"] == "some-key"
    # Distribution and ownership are the adapter's answers, and there is no adapter.
    assert lines["Key distribution"] == "—"
    assert lines["Ownership"] == "—"


def test_the_kms_box_describes_the_kms_it_was_asked_about():
    lines = _lines(_box(_boxes("login"), "kms"))

    assert lines["Key store"] == "login"
    assert lines["Adapter"] == "EnvKeyStoreAdapter"
    assert lines["Key"] == "shared"


def test_a_box_never_carries_an_error_key():
    """The run below the boxes is the one surface that reports a failure."""
    assert all("error" not in box for box in _boxes("local"))
