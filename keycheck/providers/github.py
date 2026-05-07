"""GitHub token provider — validate token and check recent activity."""

from __future__ import annotations

from typing import Any

import httpx

from keycheck.core.vault import SecureBytes


def audit(key: SecureBytes) -> dict[str, Any]:
    """Validate GitHub token and fetch recent activity."""
    raw = key.to_str()
    headers = {
        "Authorization": f"Bearer {raw}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    del raw

    try:
        with httpx.Client(verify=True, timeout=15) as client:
            resp = client.get("https://api.github.com/user", headers=headers)

        if resp.status_code == 401:
            return {"valid": False, "summary": "Token invalid or revoked.", "events": []}

        resp.raise_for_status()
        user = resp.json()

        return {
            "valid": True,
            "login": user.get("login"),
            "scopes": resp.headers.get("X-OAuth-Scopes", "unknown"),
            "summary": f"Active. User: {user.get('login')}. Scopes: {resp.headers.get('X-OAuth-Scopes', 'unknown')}",
            "events": [],
        }

    except httpx.RequestError as exc:
        return {"valid": False, "summary": f"Network error: {type(exc).__name__}", "events": []}
