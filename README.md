# KeySentinel

**Detect compromised API keys before attackers exploit them.**

KeySentinel is an open-source CLI that runs entirely on your machine. You give it your API keys, it tells you if they have been leaked, whether they are still active, and what to do next. Nothing is sent to any server controlled by us — only to the official APIs of the providers you use.

```bash
# Requires Python 3.10+
pip install keysentinel
keysentinel scan --env .env
```

---

## How it works

KeySentinel runs three independent checks for every key you provide:

```
Your key (stays on your machine)
         │
         ├─ 1. GitHub Code Search ──────► searches the exact key string
         │                                in ALL public GitHub repositories
         │
         ├─ 2. GitGuardian database ────► sends the key as document content
         │                                to GitGuardian's /v1/scan API, which
         │                                detects the secret type, checks validity,
         │                                and flags if seen in monitored public repos
         │
         └─ 3. Provider audit ──────────► calls the provider's own API with
                                          your key to check: is it still active?
                                          what accounts/resources does it access?
```

**The key is sent in plaintext only to APIs you explicitly authorise:** the provider's own audit API (step 3) and GitGuardian's scan API (step 2, requires GITGUARDIAN_TOKEN). GitHub Code Search (step 1) also receives the key string as a search query. No data is sent to any server controlled by us.

---

## Supported providers

| Provider | Key format | Auto-detect | Audit | Auto-revoke |
|----------|-----------|-------------|-------|-------------|
| OpenAI | `sk-proj-...` / `sk-...` | ✓ | ✓ Validity check | Manual |
| Anthropic | `sk-ant-api03-...` | ✓ | ✓ Validity check | Manual |
| Google / Gemini | `AIza...` | ✓ | ✓ Models available | Manual |
| Groq | `gsk_...` | ✓ | ✓ Models available | Manual |
| HuggingFace | `hf_...` | ✓ | ✓ Username + orgs | Manual |
| Replicate | `r8_...` | ✓ | ✓ Account info | Manual |
| Stripe Live | `rk_live_...` | ✓ | ✓ Events + IPs | ✓ CLI / Manual |
| Stripe Test | `rk_test_...` | ✓ | ✓ Events + IPs | ✓ CLI / Manual |
| SendGrid | `SG....` | ✓ | ✓ Account + scopes | Manual |
| Resend | `re_...` | ✓ | ✓ Domains list | Manual |
| Slack | `xoxb-...` / `xoxp-...` | ✓ | ✓ Workspace + user | Manual |
| GitHub PAT | `ghp_...` | ✓ | ✓ Login + scopes | Manual |
| AWS | `AKIA...` | ✓ | ✓ CloudTrail (needs secret key too) | Manual |
| Supabase | `eyJhbGci...` (JWT) | ✓ | ✓ Role + project URL | Manual |

**Any other key** (Twilio, Vercel, Cloudflare, ElevenLabs, Mailchimp, Discord, Airtable…): GitHub search + GitGuardian still run automatically. Only the provider-specific audit is skipped for unsupported formats.

---

## Requirements

- **Python 3.10+** — [download here](https://www.python.org/downloads/) if you don't have it
- macOS, Linux, or Windows

Check your version:
```bash
python3 --version
```

## Installation

```bash
pip install keysentinel
```

### Optional: increase scan coverage

```bash
# GitHub Code Search: 10 req/min unauthenticated → 5000 req/min with token
export GITHUB_TOKEN=ghp_yourtoken

# GitGuardian breach database (free account at gitguardian.com)
export GITGUARDIAN_TOKEN=gg_yourtoken
```

---

## Usage

```bash
# Interactive prompt — most secure, key never visible in shell history
keysentinel scan

# Scan all keys from a .env file
keysentinel scan --env .env.production

# Scan a key from an environment variable (safer than typing the value)
keysentinel scan --key "$OPENAI_API_KEY"

# Save a JSON report
keysentinel scan --env .env --output report.json

# Skip specific checks
keysentinel scan --env .env --no-github --no-gitguardian

# Revoke a compromised Stripe key immediately
keysentinel revoke --key "$STRIPE_LIVE_KEY"

# Show version
keysentinel version
```

---

## What the output means

```
Key: sk-pro****bcde  Provider: openai  ✓ Known format

  ✓ Clean      GitHub           — Not found in any public repository
  ✓ Clean      GitGuardian      — Not found in breach database
  ✓ Active     openai audit     — Key is valid and active

  Scan Summary
  ┌────────────────┬────────┬──────────────────────────────────────┐
  │ Source         │ Status │ Detail                               │
  ├────────────────┼────────┼──────────────────────────────────────┤
  │ github         │ CLEAN  │ Not found in public GitHub repos.    │
  │ gitguardian    │ CLEAN  │ Not found in breach database.        │
  │ provider_audit │ ACTIVE │ Key is active.                       │
  └────────────────┴────────┴──────────────────────────────────────┘
```

| Status | Meaning |
|--------|---------|
| `CLEAN` | Not found in public sources |
| `LEAKED` | Found in a public GitHub repo or breach database — rotate immediately |
| `ACTIVE` | Provider confirmed the key is still live |
| `INACTIVE` | Key is already revoked or invalid |
| `SKIPPED` | Check not possible (e.g. AWS needs both keys) |

---

## Security design

KeySentinel was built to handle credentials without exposing them.

| Control | Implementation |
|---------|---------------|
| **Memory safety** | `SecureBytes` stores keys as bytearrays, zeroed via `ctypes.memset()` on exit |
| **No disk writes** | Keys are never written to disk; JSON reports use masked form only |
| **No log exposure** | Global exception hook redacts key patterns before any error is printed |
| **TLS enforced** | `httpx` with `verify=True` — cannot be overridden |
| **GitGuardian scan** | Key sent as document content to GitGuardian's official scan API; checks type, validity, and known_secret flag |
| **Rate limiting** | Checks GitHub quota before each request; exponential backoff on 429/403 |
| **Input validation** | Regex + length (8–512 chars) + printable ASCII check before any operation |
| **Open source** | Every line of code is auditable — no black box, no SaaS intermediary |

---

## Which keys are most at risk?

Based on real security research (GitGuardian 2024 report, TruffleHog data):

| Risk | Provider | Why |
|------|----------|-----|
| Critical | AWS | Leaked keys spin up compute — $50k+ bills in hours |
| Critical | OpenAI | Token costs with no spend limit = big bill |
| Critical | Stripe Live | Direct access to real money |
| Critical | Google Cloud | Can create VMs, BigQuery jobs, storage |
| High | Supabase service_role | Full database access with no RLS |
| High | GitHub PAT | Push to all repos, read private code |
| High | Twilio | Mass SMS = bill explosion |
| Medium | SendGrid / Resend | Domain reputation + spam campaigns |
| Medium | Groq / Replicate | API cost abuse |
| Medium | Slack / Discord | Internal data exfiltration |

---

## Pros and cons

**Pros**
- Entirely local — no SaaS, no account required (GitHub + GitGuardian tokens are optional)
- 14 providers auto-detected by key format
- Any other key still gets GitHub + GitGuardian scan
- Secure memory: keys zeroed from RAM after use
- Stripe revocation via Stripe CLI (if installed) or guided manual steps

**Cons**
- OpenAI and Anthropic do not expose per-key usage logs via public API (only dashboard)
- AWS CloudTrail audit requires both Access Key ID and Secret Key
- GitGuardian requires a free account for breach database access
- Stripe revocation requires Stripe CLI or Dashboard (no public REST endpoint for key revocation)

---

## Environment variables

| Variable | Required | Purpose |
|----------|----------|---------|
| `GITHUB_TOKEN` | Recommended | Raises rate limit from 10 to 5000 req/min |
| `GITGUARDIAN_TOKEN` | Optional | Enables GitGuardian breach DB check |

---

## Roadmap

- [ ] v0.4 — Twilio, ElevenLabs, Vercel, Cloudflare providers
- [ ] v0.4 — Auto-revocation for OpenAI and GitHub tokens
- [ ] v0.4 — AWS auto-revocation via IAM API
- [ ] v0.4 — Pastebin and StackOverflow scan
- [ ] v1.0 — Daemon mode: continuous monitoring with alerts
- [ ] v1.0 — Slack / Telegram alert on detection

---

## Responsible disclosure

Found a security issue in KeySentinel itself? Open a **private security advisory** on GitHub.
Do not create public issues for security vulnerabilities.
