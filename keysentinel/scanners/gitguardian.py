"""GitGuardian scanner — scans key against GitGuardian's secret detection engine.

The key is sent to GitGuardian's /v1/scan endpoint as document content.
GitGuardian detects the secret type, checks its validity, and reports whether
this exact secret has previously appeared in public repository scans (known_secret).
"""

from __future__ import annotations

import os
from typing import Any

import httpx

from keysentinel.core.vault import SecureBytes


_BASE_URL = "https://api.gitguardian.com/v1"


def scan(key: SecureBytes) -> dict[str, Any]:
    """Scan key via GitGuardian's secret detection API.

    Sends the key as document content to /v1/scan. GitGuardian checks:
    - whether it matches a known secret type (policy_breaks)
    - whether it's still valid/revoked (validity)
    - whether it has been seen in previously monitored public repos (known_secret)

    Requires GITGUARDIAN_TOKEN env var (free account at gitguardian.com).
    """
    token = os.getenv("GITGUARDIAN_TOKEN")
    if not token:
        return {
            "found": False,
            "hits": [],
            "summary": "Skipped — set GITGUARDIAN_TOKEN to enable GitGuardian scan.",
        }

    raw = key.to_str()
    # Wrap in a realistic .env line so GitGuardian's pattern engine recognises it
    document = f"SECRET_KEY={raw}"
    del raw

    headers = {
        "Authorization": f"Token {token}",
        "Content-Type": "application/json",
    }

    try:
        with httpx.Client(verify=True, timeout=15) as client:
            resp = client.post(
                f"{_BASE_URL}/scan",
                headers=headers,
                json={"document": document, "filename": ".env"},
            )

        if resp.status_code == 401:
            return {"found": False, "hits": [], "summary": "GitGuardian: invalid token."}
        resp.raise_for_status()

        result = resp.json()
        breaks = result.get("policy_breaks", [])

        if not breaks:
            return {
                "found": False,
                "hits": [],
                "summary": "Not recognised as a known secret type by GitGuardian.",
            }

        # known_secret = True means GitGuardian has seen this exact secret in public repos
        known = [b for b in breaks if b.get("known_secret")]
        validity = breaks[0].get("validity", "unknown")
        secret_type = breaks[0].get("type", "unknown")

        if known:
            return {
                "found": True,
                "hits": known,
                "summary": (
                    f"GitGuardian: secret type '{secret_type}' seen in public leaks. "
                    f"Validity: {validity}. {len(known)} known incident(s)."
                ),
            }

        return {
            "found": False,
            "hits": breaks,
            "summary": (
                f"GitGuardian: secret type '{secret_type}' detected, validity: {validity}. "
                f"Not found in previously monitored public repos."
            ),
        }

    except httpx.RequestError as exc:
        return {"found": False, "hits": [], "summary": f"Network error: {type(exc).__name__}"}
