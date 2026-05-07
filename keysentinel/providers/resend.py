"""Resend provider — validate API key."""

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
            resp = client.get("https://api.resend.com/domains", headers=headers)

        if resp.status_code == 401:
            return {"valid": False, "summary": "Key invalid or revoked.", "events": []}

        resp.raise_for_status()
        data = resp.json()
        domains = data.get("data", [])
        domain_list = ", ".join(d.get("name", "?") for d in domains[:3]) if domains else "none configured"
        return {
            "valid": True,
            "summary": f"Active. Domains: {domain_list}.",
            "events": [],
        }

    except httpx.RequestError as exc:
        return {"valid": False, "summary": f"Network error: {type(exc).__name__}", "events": []}
