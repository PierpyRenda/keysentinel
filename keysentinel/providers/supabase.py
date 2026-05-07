"""Supabase provider — validate JWT (anon or service_role key)."""

from __future__ import annotations

import base64
import json
from typing import Any

import httpx

from keysentinel.core.vault import SecureBytes


def _decode_jwt_payload(token: str) -> dict:
    try:
        payload_b64 = token.split(".")[1]
        padding = 4 - len(payload_b64) % 4
        payload_b64 += "=" * (padding % 4)
        return json.loads(base64.urlsafe_b64decode(payload_b64))
    except Exception:
        return {}


def audit(key: SecureBytes) -> dict[str, Any]:
    raw = key.to_str()

    payload = _decode_jwt_payload(raw)
    role = payload.get("role", "unknown")
    iss = payload.get("iss", "")

    if "supabase" not in iss:
        del raw
        return {
            "valid": False,
            "summary": "JWT does not appear to be a Supabase key (iss mismatch).",
            "events": [],
        }

    project_url = iss.rstrip("/")
    headers = {
        "apikey": raw,
        "Authorization": f"Bearer {raw}",
    }
    del raw

    try:
        with httpx.Client(verify=True, timeout=15) as client:
            resp = client.get(f"{project_url}/rest/v1/", headers=headers)

        if resp.status_code in (401, 403):
            return {"valid": False, "summary": "Key rejected by Supabase project.", "events": []}

        risk = "CRITICAL — full DB access" if role == "service_role" else "limited (anon)"
        return {
            "valid": True,
            "summary": f"Active. Role: {role} ({risk}). Project: {project_url}",
            "events": [],
            "role": role,
            "project_url": project_url,
        }

    except httpx.RequestError as exc:
        return {"valid": False, "summary": f"Network error: {type(exc).__name__}", "events": []}
