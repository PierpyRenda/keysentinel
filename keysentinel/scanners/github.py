"""GitHub Code Search scanner — finds exposed keys in public repositories."""

from __future__ import annotations

import os
import time
from typing import Any

import httpx

from keysentinel.core.vault import SecureBytes


_SEARCH_URL = "https://api.github.com/search/code"
_MIN_DELAY = 2.2        # seconds between requests (authenticated: 30 req/min)
_MAX_RETRIES = 3
_BACKOFF_BASE = 5       # seconds for exponential backoff on 429/403


def scan(key: SecureBytes, github_token: str | None = None) -> dict[str, Any]:
    """Search GitHub public code for the exact key string.

    Respects X-RateLimit-* headers and retries with exponential backoff
    on 429 / secondary-rate-limit 403 responses.
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

    for attempt in range(_MAX_RETRIES):
        try:
            with httpx.Client(verify=True, timeout=20) as client:
                _smart_sleep(client, headers, attempt)
                resp = client.get(_SEARCH_URL, headers=headers, params=params)

            # Primary rate limit — respect Reset header
            if resp.status_code == 429 or (
                resp.status_code == 403
                and "rate limit" in resp.text.lower()
            ):
                wait = _parse_reset_wait(resp)
                if attempt < _MAX_RETRIES - 1:
                    time.sleep(wait)
                    continue
                return _rate_limited(wait)

            # Unrelated 403 (e.g. no token, blocked)
            if resp.status_code == 403:
                return _rate_limited(0)

            if resp.status_code == 422:
                return {
                    "found": False, "hits": [],
                    "summary": "Query rejected by GitHub (key too short or invalid format).",
                }

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
            if attempt < _MAX_RETRIES - 1:
                time.sleep(_BACKOFF_BASE * (2 ** attempt))
                continue
            return {"found": False, "hits": [], "summary": f"Network error: {type(exc).__name__}"}

    return _rate_limited(0)


def _smart_sleep(client: httpx.Client, headers: dict, attempt: int) -> None:
    """Check remaining quota before the request; sleep if quota is low."""
    try:
        rl = client.get(
            "https://api.github.com/rate_limit",
            headers=headers,
            timeout=5,
        )
        if rl.status_code == 200:
            search = rl.json().get("resources", {}).get("search", {})
            remaining = search.get("remaining", 10)
            reset_at = search.get("reset", 0)
            if remaining <= 1:
                wait = max(0, reset_at - time.time()) + 2
                time.sleep(min(wait, 65))
                return
    except Exception:
        pass
    # Standard inter-request delay + exponential back-off on retries
    time.sleep(_MIN_DELAY + (_BACKOFF_BASE * (2 ** attempt) if attempt > 0 else 0))


def _parse_reset_wait(resp: httpx.Response) -> float:
    """Return seconds to wait based on X-RateLimit-Reset or Retry-After header."""
    retry_after = resp.headers.get("Retry-After")
    if retry_after:
        return float(retry_after) + 1

    reset_ts = resp.headers.get("X-RateLimit-Reset")
    if reset_ts:
        return max(0, float(reset_ts) - time.time()) + 2

    return _BACKOFF_BASE * 4


def _rate_limited(wait: float) -> dict[str, Any]:
    msg = "Rate limited by GitHub."
    if wait > 0:
        msg += f" Retry in {int(wait)}s. Set GITHUB_TOKEN for higher limits."
    else:
        msg += " Set GITHUB_TOKEN env var to authenticate."
    return {"found": False, "hits": [], "summary": msg}
