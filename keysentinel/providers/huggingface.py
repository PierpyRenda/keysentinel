"""HuggingFace provider — validate API token."""

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
            resp = client.get("https://huggingface.co/api/whoami-v2", headers=headers)

        if resp.status_code == 401:
            return {"valid": False, "summary": "Token invalid or revoked.", "events": []}

        resp.raise_for_status()
        data = resp.json()
        username = data.get("name", "unknown")
        role = data.get("type", "user")
        orgs = [o.get("name", "?") for o in data.get("orgs", [])[:2]]
        org_str = f" Orgs: {', '.join(orgs)}" if orgs else ""
        return {
            "valid": True,
            "summary": f"Active. User: {username} ({role}).{org_str}",
            "events": [],
        }

    except httpx.RequestError as exc:
        return {"valid": False, "summary": f"Network error: {type(exc).__name__}", "events": []}
