"""OpenAI provider — validate key and fetch recent usage."""

from __future__ import annotations

from typing import Any

import httpx

from keysentinel.core.vault import SecureBytes


def audit(key: SecureBytes) -> dict[str, Any]:
    """Check if key is valid and retrieve recent model usage."""
    raw = key.to_str()
    headers = {"Authorization": f"Bearer {raw}"}
    del raw

    try:
        with httpx.Client(verify=True, timeout=15) as client:
            # Validate key
            models_resp = client.get("https://api.openai.com/v1/models", headers=headers)

        if models_resp.status_code == 401:
            return {"valid": False, "summary": "Key is invalid or revoked.", "events": []}
        if models_resp.status_code == 429:
            return {"valid": True, "summary": "Key valid but rate-limited.", "events": []}

        models_resp.raise_for_status()

        return {
            "valid": True,
            "summary": "Key is active. Usage logs require OpenAI dashboard (API not public).",
            "events": [],
            "note": "Visit platform.openai.com/usage for detailed per-key usage.",
        }

    except httpx.RequestError as exc:
        return {"valid": False, "summary": f"Network error: {type(exc).__name__}", "events": []}
