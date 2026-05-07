"""GitHub Code Search scanner — finds exposed keys in public repositories."""

from __future__ import annotations

import os
import time
from typing import Any

import httpx

from keycheck.core.vault import SecureBytes


_SEARCH_URL = "https://api.github.com/search/code"
_RATE_LIMIT_DELAY = 2.5  # seconds between requests (30 req/min safe margin)


def scan(key: SecureBytes, github_token: str | None = None) -> dict[str, Any]:
    """Search GitHub public code for the exact key string.

    Args:
        key: SecureBytes instance holding the target key.
        github_token: Optional GitHub PAT to raise the rate limit.

    Returns:
        dict with keys: found (bool), hits (list), summary (str).
    """
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    token = github_token or os.getenv("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"

    raw_key = key.to_str()
    query = f'"{raw_key}"'
    del raw_key

    params = {"q": query, "per_page": 10}

    try:
        with httpx.Client(verify=True, timeout=15) as client:
            time.sleep(_RATE_LIMIT_DELAY)
            resp = client.get(_SEARCH_URL, headers=headers, params=params)

        if resp.status_code == 403:
            return _rate_limited()
        if resp.status_code == 422:
            return {"found": False, "hits": [], "summary": "Query rejected by GitHub (key too short or invalid format)."}
        resp.raise_for_status()

        data = resp.json()
        items = data.get("items", [])
        total = data.get("total_count", 0)

        if total == 0:
            return {"found": False, "hits": [], "summary": "Not found in public GitHub repos."}

        hits = [
            {
                "repo": item["repository"]["full_name"],
                "file": item["path"],
                "url": item["html_url"],
            }
            for item in items
        ]
        return {
            "found": True,
            "hits": hits,
            "summary": f"Found in {total} public file(s). First: {hits[0]['repo']}/{hits[0]['file']}",
        }

    except httpx.HTTPStatusError as exc:
        return {"found": False, "hits": [], "summary": f"HTTP error: {exc.response.status_code}"}
    except httpx.RequestError as exc:
        return {"found": False, "hits": [], "summary": f"Network error: {type(exc).__name__}"}


def _rate_limited() -> dict[str, Any]:
    return {
        "found": False,
        "hits": [],
        "summary": "Rate limited by GitHub. Set GITHUB_TOKEN env var for higher limits.",
    }
