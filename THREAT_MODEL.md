# Keycheck — Threat Model v1.0

## System Description
CLI tool that accepts API keys, scans public sources for leaks, queries provider audit logs,
and executes remediation (revoke + rotate). Runs locally on the user's machine.

## Trust Boundaries

| Boundary | Protocol | Auth | TLS |
|----------|----------|------|-----|
| User → CLI | stdin / args | none | n/a |
| CLI → GitHub API | HTTPS | user token (optional) | enforced |
| CLI → GitGuardian | HTTPS | user GG token | enforced |
| CLI → Provider APIs | HTTPS | target key being audited | enforced |
| CLI → Disk | filesystem | OS user perms | n/a |

## Assets at Risk

- **Target API key** (highest sensitivity) — must never touch disk or logs in plaintext
- **User's own GitHub/GG tokens** — stored encrypted in OS keychain or env var
- **Scan results** — may reveal what key was compromised; stored locally only

## Entry Points

1. `--key` CLI argument — direct plaintext input
2. `--env FILE` — .env file parsing
3. HTTP responses from GitHub / GitGuardian / providers

## Threat Enumeration

### T1 — Key leaks via CLI history (HIGH)
**Path:** user types `keycheck scan --key sk-abc123` → shell saves to `~/.zsh_history`
**Mitigation:** prompt for key interactively via `typer.prompt(hide_input=True)` as default;
document that `--key` flag should only be used in scripts with env var substitution.

### T2 — Key leaks via crash dump / exception traceback (HIGH)
**Path:** unhandled exception prints locals including the key bytearray
**Mitigation:** global exception handler that redacts any string matching known key patterns
before printing; SecureBytes clears memory on `__del__`.

### T3 — Key transmitted to unintended third party (CRITICAL)
**Path:** dependency or scanner module sends key to external service
**Mitigation:** only GitGuardian receives a SHA-256 hash (never plaintext);
all other calls use the key only against its own provider; dependency audit in CI.

### T4 — MITM on provider API calls (MEDIUM)
**Path:** attacker intercepts HTTPS call containing the key
**Mitigation:** `httpx` with `verify=True` enforced; no user-configurable SSL bypass flag.

### T5 — Malicious .env file (MEDIUM)
**Path:** attacker crafts .env with path traversal or oversized values
**Mitigation:** strict regex parse of .env; max line length 1024; reject non-printable chars.

### T6 — Supply chain attack via dependencies (HIGH)
**Path:** compromised PyPI package exfiltrates key
**Mitigation:** `pip-audit` in CI; pinned hashes in `requirements.lock`; minimal deps.

### T7 — Scan results written insecurely (MEDIUM)
**Path:** `--output report.json` writes key material to disk
**Mitigation:** report contains only masked key (`sk-****...****abc`); never full key.

## Controls Summary

| Control | Implementation |
|---------|---------------|
| Memory safety | `SecureBytes` — bytearray zeroed on scope exit |
| No disk plaintext | Keys never written; reports use masked form |
| No log plaintext | Logger middleware redacts key patterns |
| TLS enforced | `httpx.Client(verify=True)` — no override |
| Hash before external send | GitGuardian receives SHA-256 only |
| Dependency audit | `pip-audit` + `bandit` in GitHub Actions |
| Input validation | Regex + length check on every key input |
