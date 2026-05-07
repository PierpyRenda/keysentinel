"""Replicate provider — validate API token."""

from __future__ import annotations

from typing import Any

import httpx

from keysentinel.core.vault import SecureBytes


def audit(key: SecureBytes) -> dict[str, Any]:
    raw = key.to_str()
    headers = {"Authorization": f"Token {raw}"}
    del raw

    try:
        with httpx.Client(verify=True, timeout=15) as client:
            resp = client.get("https://api.replicate.com/v1/account", headers=headers)

        if resp.status_code == 401:
            return {"valid": False, "summary": "Token invalid or revoked.", "events": []}

        resp.raise_for_status()
        data = resp.json()
        username = data.get("username", "unknown")
        name = data.get("name", "")
        return {
            "valid": True,
            "summary": f"Active. Account: {username}{' (' + name + ')' if name else ''}.",
            "events": [],
        }

    except httpx.RequestError as exc:
        return {"valid": False, "summary": f"Network error: {type(exc).__name__}", "events": []}
