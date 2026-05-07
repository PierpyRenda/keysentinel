# KeySentinel

**A security sentinel that detects compromised API keys, audits provider usage, and automates remediation.**

```bash
pip install keysentinel
keysentinel scan --env .env
```

---

## What it does

| Feature | Detail |
|---------|--------|
| **Leak detection** | Scans GitHub public repos with smart rate-limit handling |
| **Breach database** | Checks GitGuardian (sends SHA-256 only — key never exposed) |
| **Provider audit** | Queries OpenAI, Anthropic, Stripe, AWS, GitHub for live usage |
| **Usage forensics** | Shows IPs, timestamps, and actions performed with stolen keys |
| **Auto-revocation** | Revokes Stripe keys instantly; guided steps for all others |
| **Secure memory** | Keys stored as zeroed bytearrays — never written to disk or logs |

---

## Supported providers

| Provider | Format | Audit logs | Auto-revoke |
|----------|--------|------------|-------------|
| OpenAI | `sk-...` | ✓ validity check | Manual |
| Anthropic | `sk-ant-...` | ✓ validity check | Manual |
| AWS | `AKIA...` | ✓ CloudTrail events + IPs | Manual |
| Stripe Live | `rk_live_...` | ✓ Events + IPs | ✓ Auto |
| Stripe Test | `rk_test_...` | ✓ Events + IPs | ✓ Auto |
| GitHub | `ghp_...` | ✓ validity + scopes | Manual |

---

## Installation

```bash
pip install keysentinel

# Recommended: set tokens for full scan coverage
export GITHUB_TOKEN=ghp_yourtoken          # GitHub Code Search (30→5000 req/min)
export GITGUARDIAN_TOKEN=gg_yourtoken      # GitGuardian breach database
```

---

## Usage

```bash
# Interactive prompt (most secure — key never in shell history)
keysentinel scan

# Scan from .env file
keysentinel scan --env .env.production

# Scan a single key via env var substitution
keysentinel scan --key "$OPENAI_API_KEY"

# Save JSON report
keysentinel scan --env .env --output report.json

# Skip specific scanners
keysentinel scan --env .env --no-github --no-gitguardian

# Revoke a compromised key
keysentinel revoke --key "$STRIPE_KEY"

# Show version
keysentinel version
```

---

## Security design

| Control | Implementation |
|---------|---------------|
| Memory safety | `SecureBytes` — bytearray zeroed via `ctypes.from_buffer()` on exit |
| No disk plaintext | Keys never written; reports use masked form only |
| No log exposure | Global exception hook redacts key patterns before printing |
| TLS enforced | `httpx` with `verify=True` — no user-configurable override |
| Safe external calls | GitGuardian receives SHA-256 hash only, never the raw key |
| Rate limiting | Smart GitHub quota check + exponential backoff on 429/403 |
| Input validation | Regex + length + charset check before any operation |
| Dependency audit | `bandit` + `pip-audit` + TruffleHog in GitHub Actions CI |

---

## Pros and cons

**Pros**
- Entirely local except for the scan calls — no SaaS black box
- Open source and fully auditable
- Smart rate limiting: checks quota before each GitHub request
- Forensics: IPs and timestamps of unauthorized key usage (Stripe, AWS)
- `SecureBytes` wipes memory correctly via `ctypes.from_buffer()`

**Cons**
- OpenAI and Anthropic do not expose per-key usage logs via public API
- AWS requires both Access Key ID and Secret Key for CloudTrail audit
- Auto-revocation only for Stripe in v0.2
- GitGuardian requires a free account registration

---

## Environment variables

| Variable | Required | Description |
|----------|----------|-------------|
| `GITHUB_TOKEN` | Recommended | Raises GitHub search from 10 to 5000 req/min |
| `GITGUARDIAN_TOKEN` | Optional | Enables breach database check |

---

## Roadmap

- [ ] v0.3 — Auto-revocation for OpenAI and GitHub tokens
- [ ] v0.3 — Pastebin and StackOverflow scan
- [ ] v0.4 — AWS auto-revocation via IAM API
- [ ] v0.4 — Slack/Telegram alert on detection
- [ ] v1.0 — Daemon mode: continuous monitoring

---

## Responsible disclosure

Found a security issue in KeySentinel itself? Open a **private security advisory** on GitHub.
Do not create public issues for security vulnerabilities.
