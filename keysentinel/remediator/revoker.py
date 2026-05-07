"""Auto-revocation of compromised keys per provider."""

from __future__ import annotations

from typing import Any

import httpx

from keysentinel.core.validator import Provider
from keysentinel.core.vault import SecureBytes


def revoke(key: SecureBytes, provider: Provider) -> dict[str, Any]:
    """Attempt automatic revocation of the compromised key."""
    handlers = {
        Provider.STRIPE_LIVE: _revoke_stripe,
        Provider.STRIPE_TEST: _revoke_stripe,
    }

    handler = handlers.get(provider)
    if handler is None:
        return {
            "revoked": False,
            "message": f"Auto-revocation not supported for {provider.value}. "
                       f"See manual steps below.",
            "manual_steps": _manual_steps(provider),
        }

    return handler(key)


def _revoke_stripe(key: SecureBytes) -> dict[str, Any]:
    """Attempt Stripe key revocation via CLI; fall back to manual steps.

    Stripe does not expose a public REST endpoint for API key revocation.
    The official methods are: Stripe Dashboard or Stripe CLI.
    """
    import shutil
    import subprocess

    raw = key.to_str()
    try:
        stripe_bin = shutil.which("stripe")
        if stripe_bin:
            result = subprocess.run(
                [stripe_bin, "keys", "revoke", raw],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode == 0:
                return {"revoked": True, "message": "Stripe key revoked via Stripe CLI."}
            # CLI present but command failed — surface the error
            stderr = result.stderr.strip()
            return {
                "revoked": False,
                "message": f"Stripe CLI returned an error: {stderr or 'unknown'}",
                "manual_steps": _manual_steps(Provider.STRIPE_LIVE),
            }

        # Stripe CLI not installed — guide user
        return {
            "revoked": False,
            "message": (
                "Stripe does not support key revocation via REST API. "
                "Install the Stripe CLI or use the Dashboard."
            ),
            "manual_steps": _manual_steps(Provider.STRIPE_LIVE),
        }
    finally:
        del raw


def _manual_steps(provider: Provider) -> list[str]:
    steps: dict[Provider, list[str]] = {
        Provider.OPENAI: [
            "1. Go to platform.openai.com/api-keys",
            "2. Find the compromised key and click Delete",
            "3. Create a new key and update your .env files",
            "4. Check Usage tab for unexpected charges",
        ],
        Provider.ANTHROPIC: [
            "1. Go to console.anthropic.com/settings/keys",
            "2. Revoke the compromised key",
            "3. Create a new key and update your .env files",
        ],
        Provider.STRIPE_LIVE: [
            "1. Go to dashboard.stripe.com/apikeys",
            "2. Find the key and click 'Revoke'",
            "3. Or install Stripe CLI and run: stripe keys revoke <key>",
            "4. Create a new key and update all services",
            "5. Check dashboard.stripe.com/logs for suspicious transactions",
        ],
        Provider.STRIPE_TEST: [
            "1. Go to dashboard.stripe.com/apikeys (test mode)",
            "2. Find the key and click 'Revoke'",
            "3. Or install Stripe CLI and run: stripe keys revoke <key>",
            "4. Create a new test key and update your .env files",
        ],
        Provider.AWS: [
            "1. Go to IAM console → Users → Security credentials",
            "2. Set the access key status to Inactive, then Delete",
            "3. Create new credentials and rotate in all services",
            "4. Review CloudTrail for unauthorized actions",
        ],
        Provider.GITHUB: [
            "1. Go to github.com/settings/tokens",
            "2. Delete the compromised token",
            "3. Review authorized OAuth apps",
            "4. Check recent repo activity for unauthorized pushes",
        ],
        Provider.UNKNOWN: [
            "1. Identify the provider from the key prefix",
            "2. Revoke via the provider's dashboard",
            "3. Rotate in all services using the key",
        ],
    }
    return steps.get(provider, steps[Provider.UNKNOWN])
