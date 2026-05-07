"""Google provider — validate API key (Cloud / Gemini)."""

from __future__ import annotations

from typing import Any

import httpx

from keysentinel.core.vault import SecureBytes


def audit(key: SecureBytes) -> dict[str, Any]:
    raw = key.to_str()
    try:
        with httpx.Client(verify=True, timeout=15) as client:
            resp = client.get(
                "https://generativelanguage.googleapis.com/v1/models",
                params={"key": raw},
            )
        del raw

        if resp.status_code == 400:
            data = resp.json()
            msg = data.get("error", {}).get("message", "")
            if "API key not valid" in msg:
                return {"valid": False, "summary": "Key invalid or revoked.", "events": []}
            return {"valid": False, "summary": f"Bad request: {msg}", "events": []}

        if resp.status_code == 403:
            data = resp.json()
            msg = data.get("error", {}).get("message", "")
            if "disabled" in msg.lower():
                return {
                    "valid": True,
                    "summary": "Key valid but Gemini API not enabled for this project.",
                    "events": [],
                }
            return {"valid": False, "summary": f"Forbidden: {msg}", "events": []}

        resp.raise_for_status()
        models = resp.json().get("models", [])
        return {
            "valid": True,
            "summary": f"Active. {len(models)} Gemini models available.",
            "events": [],
        }

    except httpx.RequestError as exc:
        return {"valid": False, "summary": f"Network error: {type(exc).__name__}", "events": []}
