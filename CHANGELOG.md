# Changelog

All notable changes to KeySentinel are documented here.

---

## [0.3.0] — 2026-05-07

### Added
- 14 provider auto-detect and audit: OpenAI, Anthropic, AWS, Stripe (live/test), GitHub, Google, SendGrid, Resend, Groq, HuggingFace, Slack, Replicate, Supabase
- GitHub Code Search scanner with rate-limit handling and exponential backoff
- GitGuardian scanner via `/v1/scan` — detects secret type, validity, and `known_secret` flag
- `SecureBytes` vault: mutable bytearray zeroed via `ctypes.memset()` on scope exit
- Global exception hook that redacts key patterns before printing errors
- `revoke` command: Stripe CLI auto-revocation + guided manual steps for all providers
- JSON report output with sanitized fields
- Input validation: length (8–512), printable ASCII, non-printable character rejection
- CI pipeline: Bandit static analysis, pip-audit dependency check, Ruff lint, pytest

### Fixed
- GitGuardian: replaced SHA-256 hash approach (wrong API usage) with `/v1/scan` content scan
- Stripe revocation: removed non-existent `POST /v1/restricted_keys` endpoint; now uses Stripe CLI or returns accurate manual steps

---

## [0.2.0] — 2026-05-07

### Added
- Resend, Groq, HuggingFace, Slack, Replicate, Supabase providers
- `THREAT_MODEL.md` and `SECURITY.md`
- GitHub Actions security workflow

---

## [0.1.0] — 2026-05-07

### Added
- Initial release: OpenAI, Anthropic, AWS, Stripe, GitHub, Google, SendGrid providers
- Core CLI with `scan` and `revoke` commands
- `SecureBytes` memory-safe key handling
