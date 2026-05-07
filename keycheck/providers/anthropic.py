"""Anthropic provider — validate key liveness."""

from __future__ import annotations

from typing import Any

import httpx

from keycheck.core.vault import SecureBytes


def audit(key: SecureBytes) -> dict[str, Any]:
    """Check if Anthropic key is valid by making a minimal API call."""
    raw = key.to_str()
    headers = {
        "x-api-key": raw,
        "anthropic-version": "2023-06-01",
        "content-type": "application/json",
    }
    del raw

    payload = {
        "model": "claude-haiku-4-5-20251001",
        "max_tokens": 1,
        "messages": [{"role": "user", "content": "ping"}],
    }

    try:
        with httpx.Client(verify=True, timeout=15) as client:
            resp = client.post("https://api.anthropic.com/v1/messages", headers=headers, json=payload)

        if resp.status_code == 401:
            return {"valid": False, "summary": "Key invalid or revoked.", "events": []}
        if resp.status_code in (200, 400, 429):
            return {
                "valid": True,
                "summary": "Key is active.",
                "events": [],
                "note": "Anthropic does not expose per-key usage logs via API.",
            }

        return {"valid": False, "summary": f"Unexpected status: {resp.status_code}", "events": []}

    except httpx.RequestError as exc:
        return {"valid": False, "summary": f"Network error: {type(exc).__name__}", "events": []}
