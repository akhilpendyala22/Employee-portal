# Security Policy

## Reporting a vulnerability

This is an educational portfolio project. If you find a security weakness:

1. **Do not** open a public issue.
2. Email the project owner with a description, PoC, and suggested fix.
3. Allow 30 days for remediation before public disclosure.

## Supported versions

Latest `main` branch only.

## Security controls in this codebase

See [README.md](./README.md#security-controls--deep-dive) for the full mapping of OWASP Top 10 risks to implemented controls.

## Hardening checklist (production deployment)

- [ ] `SECRET_KEY` loaded from secret manager, not `.env`.
- [ ] PostgreSQL with TLS, not SQLite.
- [ ] Redis for `RATELIMIT_STORAGE_URI` and session backing.
- [ ] TLS termination at reverse proxy (nginx + Let's Encrypt).
- [ ] `FLASK_ENV=production` and `FLASK_CONFIG=production`.
- [ ] OS-level: run app as unprivileged user, read-only filesystem except `uploads/` and `logs/`.
- [ ] Dependency scanning enabled (`pip-audit`, Dependabot, Snyk).
- [ ] WAF in front (Cloudflare, ModSecurity).
- [ ] Backups of `instance/portal.db` and `audit_log` table encrypted at rest.
- [ ] Log shipping to SIEM (Splunk / ELK / Datadog).
- [ ] Periodic key rotation for `SECRET_KEY` (forces session invalidation).
