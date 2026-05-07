"""Stripe provider — validate key and fetch recent API events."""

from __future__ import annotations

from typing import Any

import httpx

from keysentinel.core.vault import SecureBytes


def audit(key: SecureBytes, limit: int = 20) -> dict[str, Any]:
    """Validate Stripe key and retrieve recent events with IP metadata."""
    raw = key.to_str()
    try:
        with httpx.Client(verify=True, timeout=15) as client:
            resp = client.get(
                "https://api.stripe.com/v1/events",
                auth=(raw, ""),
                params={"limit": limit},
            )
    finally:
        del raw

    if resp.status_code == 401:
        return {"valid": False, "summary": "Key invalid or revoked.", "events": []}

    resp.raise_for_status()
    data = resp.json()
    events = data.get("data", [])

    parsed = [
        {
            "id": e.get("id"),
            "type": e.get("type"),
            "created": e.get("created"),
            "request_ip": e.get("request", {}).get("ip_address", "unknown"),
        }
        for e in events
    ]

    unique_ips = list({e["request_ip"] for e in parsed if e["request_ip"] != "unknown"})

    return {
        "valid": True,
        "summary": f"{len(events)} recent event(s). IPs seen: {', '.join(unique_ips) or 'none'}",
        "events": parsed,
        "unique_ips": unique_ips,
    }
