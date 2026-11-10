"""Unit tests for UID sanitization in KMS adapters.

Tests the bijective, error-free encoding of silo UIDs to KMS-provider-specific charsets.
"""

from __future__ import annotations

import pytest

from encryption_suite.adapters.keks.base import DISPOSITION_SHARED, DISPOSITION_SILO_EXCLUSIVE
from encryption_suite.adapters.keks.sanitization import (
    ALNUM_HYPHEN,
    ALNUM_UNDERSCORE,
    make_sanitizer,
    sanitize_uid,
)
from encryption_suite.adapters.keks.strategies import PerSiloKekStrategy, SharedKekStrategy
from encryption_suite.adapters.key_stores.fly import FlyKmsAdapter
from encryption_suite.exceptions import EncryptionConfigurationError
from encryption_suite.silo_ref import SiloRef


class TestSanitizeUid:
    """Test the core sanitize_uid function."""

    def test_allowed_chars_pass_through_unchanged(self):
        """Allowed characters are not modified."""
        uid = "team42"
        assert sanitize_uid(uid, ALNUM_UNDERSCORE) == "team42"

    def test_disallowed_char_encoded_as_hex(self):
        """Non-allowed chars are encoded via UTF-8 bytes as hex."""
        # Dash (0x2d) encoded with default escape "_"
        assert sanitize_uid("team-1", ALNUM_UNDERSCORE) == "team_2d1"
        # Period (0x2e) encoded
        assert sanitize_uid("team.1", ALNUM_UNDERSCORE) == "team_2e1"

    def test_escape_char_doubled(self):
        """Escape character in UID is doubled."""
        # Underscore with Fly charset (escape="_") becomes "__"
        assert sanitize_uid("team_1", ALNUM_UNDERSCORE) == "team__1"
        # Hyphen with Azure charset (escape="-") becomes "--"
        assert sanitize_uid("team-1", ALNUM_HYPHEN, escape="-") == "team--1"

    def test_unicode_char_utf8_encoded_as_multiple_bytes(self):
        """Unicode chars are encoded via UTF-8 bytes."""
        # Euro sign (€, U+20AC) → UTF-8: 0xe2, 0x82, 0xac
        result = sanitize_uid("price€50", ALNUM_UNDERSCORE)
        assert result == "price_e2_82_ac50"

    def test_collision_resistance_different_chars_produce_different_output(self):
        """Different input chars produce distinct output strings."""
        # Dash (0x2d) vs period (0x2e) should produce different output
        dash_encoded = sanitize_uid("team-1", ALNUM_UNDERSCORE)
        period_encoded = sanitize_uid("team.1", ALNUM_UNDERSCORE)
        assert dash_encoded != period_encoded
        assert dash_encoded == "team_2d1"
        assert period_encoded == "team_2e1"

    def test_collision_resistance_literal_encoding_doesnt_collide(self):
        """Literal encoded sequence in UID doesn't collide with actual encoding."""
        # "_2d1" literal → escape underscore → "__2d1"
        # "team-1" → "_2d1"
        # These are different
        literal = sanitize_uid("_2d1", ALNUM_UNDERSCORE)
        encoded = sanitize_uid("team-1", ALNUM_UNDERSCORE)
        # literal should be "__2d1" (underscore escaped)
        # encoded should be "team_2d1"
        # They differ in the prefix: "__2d1" vs "team_2d1"
        assert literal == "__2d1"
        assert encoded == "team_2d1"
        assert literal != encoded

    def test_escape_char_not_in_allowed_raises_error(self):
        """Escape char must be in the allowed set."""
        with pytest.raises(ValueError, match="escape character.*not in allowed set"):
            sanitize_uid("uid", ALNUM_UNDERSCORE, escape="-")

    def test_never_errors_on_any_python_string(self):
        """Sanitization never raises for valid Python strings."""
        inputs = [
            "",  # empty
            "hello",  # ASCII
            "café",  # Latin-1
            "你好",  # Chinese
            "🎉",  # emoji
            "\x00\xff",  # control chars and high bytes
        ]
        for uid in inputs:
            # Should not raise
            result = sanitize_uid(uid, ALNUM_UNDERSCORE)
            assert isinstance(result, str)


class TestMakeSanitizer:
    """Test the make_sanitizer factory."""

    def test_returns_callable(self):
        sanitizer = make_sanitizer(ALNUM_UNDERSCORE)
        assert callable(sanitizer)

    def test_sanitizer_produces_same_output_as_function(self):
        uid = "team-1"
        direct = sanitize_uid(uid, ALNUM_UNDERSCORE)
        sanitizer = make_sanitizer(ALNUM_UNDERSCORE)
        via_sanitizer = sanitizer(uid)
        assert direct == via_sanitizer


class TestAdapterConfiguration:
    """Test that ``build_strategy`` wires charset/escape/limit into the strategy."""

    def test_fly_build_strategy_uses_underscore_charset(self):
        """FlyKmsAdapter.build_strategy yields a strategy with Fly's charset."""
        options = {
            "FLY_APP_NAME": "test-app",
            "KEK_TEMPLATE": "kms_{silo_uid}",
        }
        strategy = FlyKmsAdapter.build_strategy(PerSiloKekStrategy, options)
        FlyKmsAdapter(options, strategy)

        # Fly sanitization: dash encoded, underscore doubled
        assert strategy._sanitize_uid("team-1") == "team_2d1"
        assert strategy._sanitize_uid("team_1") == "team__1"

    def test_strategy_applies_fly_charset_to_template(self):
        """KEK resolution uses the adapter's charset via build_strategy."""
        options = {
            "FLY_APP_NAME": "test-app",
            "KEK_TEMPLATE": "kms_{silo_uid}",
        }
        strategy = FlyKmsAdapter.build_strategy(PerSiloKekStrategy, options)
        FlyKmsAdapter(options, strategy)

        # team:1 → colon (0x3a) encoded → team_3a1
        kek_id = strategy.get_kek_id(SiloRef("default", "team:1"))
        assert kek_id == "kms_team_3a1"
        # Valid for Fly (only [A-Za-z0-9_])
        assert all(c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_" for c in kek_id)

    def test_azure_build_strategy_uses_hyphen_charset(self):
        """AzureKeyVaultAdapter.build_strategy wires the hyphen-escape charset and length cap."""
        from encryption_suite.adapters.key_stores.azure import AzureKeyVaultAdapter

        options = {"KEK_TEMPLATE": "ckk-{silo_uid}"}
        strategy = AzureKeyVaultAdapter.build_strategy(PerSiloKekStrategy, options)
        # Underscore is disallowed for Azure → encoded; hyphen is escape → doubled.
        assert strategy._sanitize_uid("team_1") == "team-5f1"
        assert strategy._sanitize_uid("team-1") == "team--1"
        assert strategy._max_length == 127

    def test_name_length_cap_applies_to_rendered_name(self):
        """The provider cap governs the rendered KEK_TEMPLATE name, not the UID alone.

        A UID that fits the cap by itself can still overflow once the template
        prefix is prepended — the cap must be enforced after templating.
        """
        options = {"KEK_TEMPLATE": "pre-{silo_uid}"}
        strategy = PerSiloKekStrategy(options, max_length=6)
        # _sanitize_uid no longer enforces length — it only encodes.
        assert strategy._sanitize_uid("abcd") == "abcd"
        # Rendered "pre-abcd" is 8 chars > 6 → get_kek_id raises a configuration
        # error whose operator detail names the limit.
        with pytest.raises(EncryptionConfigurationError) as exc_info:
            strategy.get_kek_id(SiloRef("default", "abcd"))
        assert "exceeds the 6-character limit" in exc_info.value.detail

    def test_name_within_cap_passes(self):
        """A rendered name within the cap resolves normally."""
        options = {"KEK_TEMPLATE": "pre-{silo_uid}"}
        strategy = PerSiloKekStrategy(options, max_length=8)
        assert strategy.get_kek_id(SiloRef("default", "abcd")) == "pre-abcd"

    def test_kek_map_value_not_length_capped(self):
        """KEK_MAP returns opaque provider IDs verbatim — no length cap applies."""
        long_uuid = "00000000-0000-0000-0000-000000000000"
        options = {"KEK_MAP": {"team:1": long_uuid}}
        strategy = PerSiloKekStrategy(options, max_length=4)
        assert strategy.get_kek_id(SiloRef("default", "team:1")) == long_uuid


class TestKekDisposition:
    """kek_disposition classifies whether a silo's KEK may be auto-destroyed."""

    def test_template_is_silo_exclusive(self):
        strategy = PerSiloKekStrategy({"KEK_TEMPLATE": "es-{silo_uid}"})
        assert strategy.kek_disposition(SiloRef("default", "team-1")) == DISPOSITION_SILO_EXCLUSIVE

    def test_map_entry_is_shared_by_default(self):
        strategy = PerSiloKekStrategy({"KEK_MAP": {"team-1": "opaque-id"}})
        assert strategy.kek_disposition(SiloRef("default", "team-1")) == DISPOSITION_SHARED

    def test_map_entry_destroyable_when_opted_in(self):
        strategy = PerSiloKekStrategy({"KEK_MAP": {"team-1": "opaque-id"}, "KEK_MAP_DESTROYABLE": True})
        assert strategy.kek_disposition(SiloRef("default", "team-1")) == DISPOSITION_SILO_EXCLUSIVE

    def test_map_and_template_resolves_per_uid(self):
        # uid present in the map → shared (opaque); uid absent → template → exclusive.
        strategy = PerSiloKekStrategy({"KEK_MAP": {"team-1": "opaque-id"}, "KEK_TEMPLATE": "es-{silo_uid}"})
        assert strategy.kek_disposition(SiloRef("default", "team-1")) == DISPOSITION_SHARED
        assert strategy.kek_disposition(SiloRef("default", "team-2")) == DISPOSITION_SILO_EXCLUSIVE

    def test_unresolvable_falls_back_to_shared(self):
        # No KEK_MAP and no KEK_TEMPLATE: get_kek_id would raise; disposition
        # must not imply a destroyable key.
        strategy = PerSiloKekStrategy({})
        assert strategy.kek_disposition(SiloRef("default", "team-1")) == DISPOSITION_SHARED

    def test_shared_strategy_is_shared(self):
        strategy = SharedKekStrategy({"SHARED_KEK_ID": "alias/shared"})
        assert strategy.kek_disposition(SiloRef("default", "team-1")) == DISPOSITION_SHARED


class TestKekDispositionForName:
    """kek_disposition_for_name answers the same question from a stored name.

    A key encryption key row carries no silo UID — a discovered orphan never had
    one and a shared key has many — so the schedule action asks by name instead.
    The two paths must agree, or the snapshot written at schedule time contradicts
    what the deletion derives.
    """

    def test_a_name_carrying_the_owner_prefix_is_silo_exclusive(self):
        strategy = PerSiloKekStrategy({"KEK_TEMPLATE": "es-{silo_uid}"})
        assert strategy.kek_disposition_for_name("es-team-1", "es-") == DISPOSITION_SILO_EXCLUSIVE

    def test_a_foreign_name_is_shared(self):
        strategy = PerSiloKekStrategy({"KEK_TEMPLATE": "es-{silo_uid}"})
        assert strategy.kek_disposition_for_name("someone-elses-key", "es-") == DISPOSITION_SHARED

    def test_a_mapped_name_is_shared_by_default(self):
        strategy = PerSiloKekStrategy({"KEK_MAP": {"team-1": "opaque-id"}})
        assert strategy.kek_disposition_for_name("opaque-id", None) == DISPOSITION_SHARED

    def test_a_mapped_name_is_destroyable_when_opted_in(self):
        strategy = PerSiloKekStrategy({"KEK_MAP": {"team-1": "opaque-id"}, "KEK_MAP_DESTROYABLE": True})
        assert strategy.kek_disposition_for_name("opaque-id", None) == DISPOSITION_SILO_EXCLUSIVE

    def test_the_map_wins_over_a_matching_prefix(self):
        """An operator-supplied id that happens to start with the prefix is still
        theirs, so KEK_MAP is consulted first — mirroring get_kek_id's order."""
        strategy = PerSiloKekStrategy({"KEK_MAP": {"team-1": "es-mapped"}, "KEK_TEMPLATE": "es-{silo_uid}"})
        assert strategy.kek_disposition_for_name("es-mapped", "es-") == DISPOSITION_SHARED
        assert strategy.kek_disposition_for_name("es-team-2", "es-") == DISPOSITION_SILO_EXCLUSIVE

    def test_no_prefix_is_shared(self):
        """Ownership underivable — the case that produced a false snapshot."""
        strategy = PerSiloKekStrategy({"KEK_TEMPLATE": "es-{silo_uid}"})
        assert strategy.kek_disposition_for_name("es-team-1", None) == DISPOSITION_SHARED

    def test_shared_strategy_is_always_shared(self):
        strategy = SharedKekStrategy({"SHARED_KEK_ID": "alias/shared"})
        assert strategy.kek_disposition_for_name("alias/shared", None) == DISPOSITION_SHARED
        assert strategy.kek_disposition_for_name("anything", "alias/") == DISPOSITION_SHARED

    def test_both_paths_agree_on_a_destroyable_map(self):
        """The pairing the schedule/deletion split depends on."""
        options = {"KEK_MAP": {"team-1": "opaque-id"}, "KEK_MAP_DESTROYABLE": True}
        strategy = PerSiloKekStrategy(options)
        assert strategy.kek_disposition(SiloRef("default", "team-1")) == strategy.kek_disposition_for_name(
            "opaque-id", None
        )


class TestOwnerPrefix:
    """owner_prefix derives the ownership marker from KEK_TEMPLATE."""

    def test_prefix_is_literal_before_placeholder(self):
        strategy = PerSiloKekStrategy({"KEK_TEMPLATE": "alias/es-prod-{silo_uid}"})
        assert strategy.owner_prefix() == "alias/es-prod-"

    def test_none_without_template(self):
        # KEK_MAP-only configuration has no naming-convention prefix.
        strategy = PerSiloKekStrategy({"KEK_MAP": {"team-1": "opaque-id"}})
        assert strategy.owner_prefix() is None

    def test_none_when_template_starts_with_placeholder(self):
        strategy = PerSiloKekStrategy({"KEK_TEMPLATE": "{silo_uid}-suffix"})
        assert strategy.owner_prefix() is None

    def test_shared_strategy_has_no_prefix(self):
        # Default base implementation: shared keys are not name-filterable.
        strategy = SharedKekStrategy({"SHARED_KEK_ID": "alias/shared"})
        assert strategy.owner_prefix() is None


class TestWrapAadWithUtf8:
    """Test that _wrap_aad uses UTF-8 encoding and never raises."""

    def test_wrap_aad_accepts_non_ascii_uid(self):
        """_wrap_aad should accept non-ASCII UIDs without raising."""
        options = {
            "FLY_APP_NAME": "test-app",
            "KEK_TEMPLATE": "kms_{silo_uid}",
        }
        strategy = PerSiloKekStrategy(options)
        adapter = FlyKmsAdapter(options, strategy)

        # Non-ASCII UID should not raise
        result = adapter._wrap_aad(SiloRef("default", "café"))
        assert isinstance(result, bytes)
        assert result.startswith(b"django-encryption-suite:dek:")

    def test_wrap_aad_utf8_encoded(self):
        """_wrap_aad should use UTF-8 encoding."""
        options = {
            "FLY_APP_NAME": "test-app",
            "KEK_TEMPLATE": "kms_{silo_uid}",
        }
        strategy = PerSiloKekStrategy(options)
        adapter = FlyKmsAdapter(options, strategy)

        # ASCII string
        result_ascii = adapter._wrap_aad(SiloRef("default", "test"))
        expected_ascii = b"django-encryption-suite:dek:default:test"
        assert result_ascii == expected_ascii

        # Non-ASCII string with UTF-8 encoding
        # "café" in UTF-8 is "caf" + 0xc3 + 0xa9
        result_unicode = adapter._wrap_aad(SiloRef("default", "café"))
        expected_unicode = b"django-encryption-suite:dek:default:caf\xc3\xa9"
        assert result_unicode == expected_unicode

    def test_wrap_aad_ascii_unchanged_under_utf8(self):
        """For ASCII-only UIDs the UTF-8 path produces identical bytes to the old ASCII path.

        Confirms the encoding switch doesn't break wire compatibility for ASCII UIDs —
        only the previously-rejected non-ASCII case now succeeds.
        """
        options = {
            "FLY_APP_NAME": "test-app",
            "KEK_TEMPLATE": "kms_{silo_uid}",
        }
        strategy = PerSiloKekStrategy(options)
        adapter = FlyKmsAdapter(options, strategy)

        for uid in ("a", "team-42", "user_99", "tenant:001"):
            assert adapter._wrap_aad(SiloRef("default", uid)) == b"django-encryption-suite:dek:default:" + uid.encode(
                "ascii"
            )

    def test_wrap_aad_requires_non_empty_uid(self):
        """_wrap_aad should reject empty UID."""
        options = {
            "FLY_APP_NAME": "test-app",
            "KEK_TEMPLATE": "kms_{silo_uid}",
        }
        strategy = PerSiloKekStrategy(options)
        adapter = FlyKmsAdapter(options, strategy)

        with pytest.raises(ValueError, match="non-empty silo reference"):
            adapter._wrap_aad(SiloRef("default", ""))
