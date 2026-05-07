"""Provider detection and key format validation."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum


class Provider(str, Enum):
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    AWS = "aws"
    STRIPE_LIVE = "stripe_live"
    STRIPE_TEST = "stripe_test"
    GITHUB = "github"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class KeyInfo:
    provider: Provider
    masked: str
    length: int
    valid_format: bool
    hint: str


_PATTERNS: list[tuple[Provider, re.Pattern, str]] = [
    (Provider.OPENAI,      re.compile(r"^sk-[A-Za-z0-9\-_]{20,}$"),         "OpenAI API key"),
    (Provider.ANTHROPIC,   re.compile(r"^sk-ant-[A-Za-z0-9\-_]{20,}$"),     "Anthropic API key"),
    (Provider.AWS,         re.compile(r"^AKIA[A-Z0-9]{16}$"),                "AWS Access Key ID"),
    (Provider.STRIPE_LIVE, re.compile(r"^rk_live_[A-Za-z0-9]{20,}$"),       "Stripe Live Secret"),
    (Provider.STRIPE_TEST, re.compile(r"^rk_test_[A-Za-z0-9]{20,}$"),       "Stripe Test Secret"),
    (Provider.GITHUB,      re.compile(r"^ghp_[A-Za-z0-9]{36}$"),            "GitHub Personal Token"),
    (Provider.GITHUB,      re.compile(r"^github_pat_[A-Za-z0-9_]{82}$"),    "GitHub Fine-grained Token"),
]

_MAX_KEY_LENGTH = 512
_MIN_KEY_LENGTH = 8
_SAFE_CHARS = re.compile(r"^[\x20-\x7E]+$")


def validate(raw: str) -> KeyInfo:
    """Detect provider and validate format. Raises ValueError on unsafe input."""
    if not raw:
        raise ValueError("Empty key provided.")
    if len(raw) > _MAX_KEY_LENGTH:
        raise ValueError(f"Key exceeds maximum length ({_MAX_KEY_LENGTH} chars).")
    if len(raw) < _MIN_KEY_LENGTH:
        raise ValueError(f"Key too short (minimum {_MIN_KEY_LENGTH} chars).")
    if not _SAFE_CHARS.match(raw):
        raise ValueError("Key contains non-printable or non-ASCII characters.")

    masked = raw[:6] + "****" + raw[-4:] if len(raw) > 10 else "****"

    for provider, pattern, hint in _PATTERNS:
        if pattern.match(raw):
            return KeyInfo(
                provider=provider,
                masked=masked,
                length=len(raw),
                valid_format=True,
                hint=hint,
            )

    return KeyInfo(
        provider=Provider.UNKNOWN,
        masked=masked,
        length=len(raw),
        valid_format=False,
        hint="Unknown provider — generic scan will be attempted.",
    )
