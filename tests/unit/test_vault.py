"""Tests for SecureBytes — the most security-critical component."""

import pytest
from keysentinel.core.vault import SecureBytes, redact


class TestSecureBytes:
    def test_wipe_zeroes_buffer(self):
        sb = SecureBytes("sk-test1234567890abcdef")
        sb.wipe()
        assert len(sb._buf) == 0

    def test_context_manager_wipes_on_exit(self):
        with SecureBytes("sk-test1234567890abcdef") as sb:
            assert len(sb) > 0
        assert len(sb._buf) == 0

    def test_masked_hides_middle(self):
        sb = SecureBytes("sk-test1234567890abcdef")
        masked = sb.masked()
        assert "****" in masked
        assert masked.startswith("sk-tes")
        assert masked.endswith("cdef")
        assert "test1234567890ab" not in masked

    def test_sha256_is_hex_string(self):
        sb = SecureBytes("sk-test1234567890abcdef")
        h = sb.sha256()
        assert len(h) == 64
        assert all(c in "0123456789abcdef" for c in h)

    def test_sha256_does_not_expose_key(self):
        key = "sk-supersecret1234567890"
        sb = SecureBytes(key)
        assert key not in sb.sha256()

    def test_to_str_returns_correct_value(self):
        sb = SecureBytes("sk-hello")
        s = sb.to_str()
        assert s == "sk-hello"

    def test_short_key_masked_fully(self):
        sb = SecureBytes("short")
        assert sb.masked() == "****"

    def test_repr_does_not_expose_key(self):
        sb = SecureBytes("sk-verysecretkey1234567")
        r = repr(sb)
        assert "verysecretkey" not in r
        assert "****" in r

    def test_empty_key_wipe_safe(self):
        sb = SecureBytes("")
        sb.wipe()  # must not raise
        assert len(sb._buf) == 0

    def test_bytes_input(self):
        sb = SecureBytes(b"sk-byteskey12345")
        assert sb.to_str() == "sk-byteskey12345"


class TestRedact:
    def test_redacts_openai_key(self):
        text = "Error with key sk-abc123defghijklmnop in request"
        result = redact(text)
        assert "abc123defghijklmnop" not in result
        assert "****" in result

    def test_redacts_aws_key(self):
        text = "Using AKIAIOSFODNN7EXAMPLE in config"
        result = redact(text)
        assert "IOSFODNN7EXAMPL" not in result

    def test_redacts_github_token(self):
        text = f"token ghp_{'a' * 36} failed"
        result = redact(text)
        assert "a" * 20 not in result

    def test_no_false_positive_on_normal_text(self):
        text = "Hello world, this is a normal sentence."
        assert redact(text) == text
