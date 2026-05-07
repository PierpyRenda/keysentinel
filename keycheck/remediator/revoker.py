"""Auto-revocation of compromised keys per provider."""

from __future__ import annotations

from typing import Any

import httpx

from keycheck.core.validator import Provider
from keycheck.core.vault import SecureBytes


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
    raw = key.to_str()
    try:
        with httpx.Client(verify=True, timeout=15) as client:
            resp = client.post(
                "https://api.stripe.com/v1/restricted_keys",
                auth=(raw, ""),
                data={"status": "revoked"},
            )
        if resp.status_code in (200, 204):
            return {"revoked": True, "message": "Stripe key revoked successfully."}
        return {"revoked": False, "message": f"Stripe revocation failed: {resp.status_code}"}
    except httpx.RequestError as exc:
        return {"revoked": False, "message": f"Network error: {type(exc).__name__}"}
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
