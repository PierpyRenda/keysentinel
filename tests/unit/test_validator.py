"""Tests for provider detection and input validation."""

import pytest
from keysentinel.core.validator import validate, Provider


class TestProviderDetection:
    def test_openai_key(self):
        info = validate("sk-" + "a" * 48)
        assert info.provider == Provider.OPENAI
        assert info.valid_format is True

    def test_anthropic_key(self):
        info = validate("sk-ant-" + "a" * 48)
        assert info.provider == Provider.ANTHROPIC
        assert info.valid_format is True

    def test_aws_key(self):
        info = validate("AKIA" + "A" * 16)
        assert info.provider == Provider.AWS
        assert info.valid_format is True

    def test_stripe_live(self):
        info = validate("rk_live_" + "a" * 24)
        assert info.provider == Provider.STRIPE_LIVE

    def test_stripe_test(self):
        info = validate("rk_test_" + "a" * 24)
        assert info.provider == Provider.STRIPE_TEST

    def test_github_pat(self):
        info = validate("ghp_" + "a" * 36)
        assert info.provider == Provider.GITHUB

    def test_unknown_provider(self):
        info = validate("somerandombearertoken12345")
        assert info.provider == Provider.UNKNOWN
        assert info.valid_format is False


class TestInputSanitization:
    def test_empty_key_raises(self):
        with pytest.raises(ValueError, match="Empty"):
            validate("")

    def test_too_short_raises(self):
        with pytest.raises(ValueError, match="short"):
            validate("abc")

    def test_too_long_raises(self):
        with pytest.raises(ValueError, match="maximum"):
            validate("a" * 513)

    def test_non_printable_raises(self):
        with pytest.raises(ValueError, match="non-printable"):
            validate("sk-test\x00injected")

    def test_newline_raises(self):
        with pytest.raises(ValueError, match="non-printable"):
            validate("sk-test\ninjected")

    def test_masked_hides_middle(self):
        info = validate("sk-" + "a" * 48)
        assert "****" in info.masked
        assert "a" * 20 not in info.masked
