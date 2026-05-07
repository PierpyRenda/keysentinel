"""Groq provider — validate API key via OpenAI-compatible endpoint."""

from __future__ import annotations

from typing import Any

import httpx

from keysentinel.core.vault import SecureBytes


def audit(key: SecureBytes) -> dict[str, Any]:
    raw = key.to_str()
    headers = {"Authorization": f"Bearer {raw}"}
    del raw

    try:
        with httpx.Client(verify=True, timeout=15) as client:
            resp = client.get("https://api.groq.com/openai/v1/models", headers=headers)

        if resp.status_code == 401:
            return {"valid": False, "summary": "Key invalid or revoked.", "events": []}
        if resp.status_code == 429:
            return {"valid": True, "summary": "Key valid but rate-limited.", "events": []}

        resp.raise_for_status()
        models = resp.json().get("data", [])
        model_ids = ", ".join(m.get("id", "?") for m in models[:3])
        return {
            "valid": True,
            "summary": f"Active. Models available: {model_ids}{'...' if len(models) > 3 else ''}",
            "events": [],
        }

    except httpx.RequestError as exc:
        return {"valid": False, "summary": f"Network error: {type(exc).__name__}", "events": []}
