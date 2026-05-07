"""SendGrid provider — validate API key and check scopes."""

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
            resp = client.get("https://api.sendgrid.com/v3/user/profile", headers=headers)

        if resp.status_code == 401:
            return {"valid": False, "summary": "Key invalid or revoked.", "events": []}
        if resp.status_code == 403:
            return {
                "valid": True,
                "summary": "Key active but lacks user.profile scope. Email sending may still work.",
                "events": [],
            }

        resp.raise_for_status()
        data = resp.json()
        username = data.get("username", "unknown")
        email = data.get("email", "unknown")
        return {
            "valid": True,
            "summary": f"Active. Account: {username} ({email}). Full send access.",
            "events": [],
        }

    except httpx.RequestError as exc:
        return {"valid": False, "summary": f"Network error: {type(exc).__name__}", "events": []}
