"""GitGuardian scanner — checks SHA-256 hash of key against breach database.

The plaintext key is NEVER sent to GitGuardian. Only its SHA-256 is transmitted.
"""

from __future__ import annotations

import os
from typing import Any

import httpx

from keysentinel.core.vault import SecureBytes


_BASE_URL = "https://api.gitguardian.com/v1"


def scan(key: SecureBytes) -> dict[str, Any]:
    """Check key hash against GitGuardian's incident database.

    Requires GITGUARDIAN_TOKEN env var (free account available at gitguardian.com).
    """
    token = os.getenv("GITGUARDIAN_TOKEN")
    if not token:
        return {
            "found": False,
            "hits": [],
            "summary": "Skipped — set GITGUARDIAN_TOKEN to enable GitGuardian scan.",
        }

    key_hash = key.sha256()

    headers = {
        "Authorization": f"Token {token}",
        "Content-Type": "application/json",
    }

    try:
        with httpx.Client(verify=True, timeout=15) as client:
            resp = client.post(
                f"{_BASE_URL}/multiscan",
                headers=headers,
                json=[{"document": key_hash, "filename": "secret.txt"}],
            )

        if resp.status_code == 401:
            return {"found": False, "hits": [], "summary": "GitGuardian: invalid token."}
        resp.raise_for_status()

        results = resp.json()
        leaked = [r for r in results if r.get("policy_break_count", 0) > 0]

        if not leaked:
            return {"found": False, "hits": [], "summary": "Not found in GitGuardian database."}

        return {
            "found": True,
            "hits": leaked,
            "summary": f"GitGuardian: {len(leaked)} policy break(s) detected.",
        }

    except httpx.RequestError as exc:
        return {"found": False, "hits": [], "summary": f"Network error: {type(exc).__name__}"}
