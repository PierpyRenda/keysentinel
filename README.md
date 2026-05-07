# keycheck

**CLI tool to detect compromised API keys, audit their usage, and automate remediation.**

```
pip install keycheck
keycheck scan --key sk-...
```

---

## What it does

| Feature | Detail |
|---------|--------|
| **Leak detection** | Scans GitHub public repos and GitGuardian database |
| **Provider audit** | Queries OpenAI, Anthropic, Stripe, AWS logs for anomalous usage |
| **Usage forensics** | Shows IPs, timestamps, and actions performed with the key |
| **Auto-revocation** | Revokes Stripe keys automatically; guided steps for all others |
| **Git history clean** | Instructions to remove keys from commit history |
| **Secure memory** | Keys are stored as zeroed bytearrays, never written to disk or logs |

---

## Supported providers

| Provider | Format detected | Audit logs | Auto-revoke |
|----------|----------------|------------|-------------|
| OpenAI | `sk-...` | ✓ (validity check) | Manual |
| Anthropic | `sk-ant-...` | ✓ (validity check) | Manual |
| AWS | `AKIA...` | ✓ CloudTrail | Manual |
| Stripe Live | `rk_live_...` | ✓ Events + IPs | ✓ |
| Stripe Test | `rk_test_...` | ✓ Events + IPs | ✓ |
| GitHub | `ghp_...` | ✓ (validity check) | Manual |

---

## Installation

```bash
pip install keycheck

# Optional: set tokens for higher rate limits
export GITHUB_TOKEN=ghp_yourtoken
export GITGUARDIAN_TOKEN=ggtoken
```

---

## Usage

```bash
# Scan a single key (prompted securely)
keycheck scan

# Scan with key as argument (use env var substitution in scripts)
keycheck scan --key "$OPENAI_API_KEY"

# Scan all keys from a .env file
keycheck scan --env .env.production

# Force provider detection
keycheck scan --key "rk_live_..." --provider stripe

# Save JSON report
keycheck scan --key "$MY_KEY" --output report.json

# Revoke a compromised key
keycheck revoke --key "$STRIPE_KEY"
```

---

## Security design

- **Keys never touch disk** — handled as zeroed bytearrays (`SecureBytes`)
- **No plaintext to third parties** — GitGuardian receives SHA-256 hash only
- **TLS enforced** — all HTTP calls use `verify=True`, no override flag
- **Crash-safe** — global exception hook redacts key patterns before printing
- **Minimal dependencies** — `httpx`, `typer`, `rich`, `cryptography`, `pydantic`
- **CI pipeline** — Bandit + pip-audit + TruffleHog on every PR

---

## Pros and cons

**Pros**
- Works entirely offline except for the scan calls
- Open source and auditable — no black-box SaaS
- Handles multiple providers in one command
- Forensics: shows IPs and timestamps of unauthorized usage
- Secure memory handling from day one

**Cons**
- OpenAI and Anthropic do not expose per-key usage logs via public API
- AWS audit requires both Access Key ID and Secret Key
- Auto-revocation only implemented for Stripe in v1
- GitHub scan rate-limited without a token (30 req/min)
- Does not scan private repos or dark web sources

---

## Roadmap

- [ ] v0.2 — Auto-revocation for OpenAI and GitHub tokens
- [ ] v0.2 — Pastebin and StackOverflow scan
- [ ] v0.3 — AWS auto-revocation via IAM API
- [ ] v0.3 — Slack/Telegram alert on detection
- [ ] v1.0 — Daemon mode: continuous monitoring with cron

---

## Responsible disclosure

If you find a security issue in keycheck itself, open a private advisory on GitHub.
Do not open public issues for security bugs.
