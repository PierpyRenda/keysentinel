"""Slack provider — validate bot/user token."""

from __future__ import annotations

from typing import Any

import httpx

from keysentinel.core.vault import SecureBytes


def audit(key: SecureBytes) -> dict[str, Any]:
    raw = key.to_str()
    headers = {
        "Authorization": f"Bearer {raw}",
        "Content-Type": "application/json",
    }
    del raw

    try:
        with httpx.Client(verify=True, timeout=15) as client:
            resp = client.post("https://slack.com/api/auth.test", headers=headers)

        resp.raise_for_status()
        data = resp.json()

        if not data.get("ok"):
            error = data.get("error", "unknown")
            return {"valid": False, "summary": f"Token invalid: {error}.", "events": []}

        team = data.get("team", "unknown")
        user = data.get("user", data.get("bot_id", "unknown"))
        url = data.get("url", "")
        return {
            "valid": True,
            "summary": f"Active. Workspace: {team} | User/Bot: {user} | {url}",
            "events": [],
        }

    except httpx.RequestError as exc:
        return {"valid": False, "summary": f"Network error: {type(exc).__name__}", "events": []}
