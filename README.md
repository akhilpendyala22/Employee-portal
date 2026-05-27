# Enterprise Employee Portal — Secured Edition

> Cybersecurity Research Internship Portfolio Project (Project 2)

A hardened Flask-based employee portal demonstrating production-grade defences against the **OWASP Top 10 (2021)**. Built as the "remediated" half of a vulnerable/secure pair — pair this with a vulnerable version of the same app to demonstrate before/after pentest results.

---

## What this project shows

| OWASP Top 10 (2021) Risk          | Mitigation in this codebase                                                                  |
| --------------------------------- | -------------------------------------------------------------------------------------------- |
| A01 Broken Access Control         | `@roles_required` decorator, `@owns_resource` IDOR guard, server-side authorization only     |
| A02 Cryptographic Failures        | Argon2id password hashing, HTTPS-only cookies, `__Host-` cookie prefix in production         |
| A03 Injection                     | SQLAlchemy ORM (parameterized), Jinja2 auto-escape, `bleach` HTML sanitization, regex allowlists |
| A04 Insecure Design               | Rate limiting, account lockout, CSRF tokens, TOTP MFA, deny-by-default routing               |
| A05 Security Misconfiguration     | `Flask-Talisman` security headers, strict CSP, `DEBUG=False`, env-loaded secrets             |
| A06 Vulnerable Components         | Pinned dependency versions in `requirements.txt`, ready for `pip-audit` / Dependabot         |
| A07 Identification & Auth Failures| Argon2id with rehash-on-login, lockout, TOTP MFA, session fixation defence                   |
| A08 Software / Data Integrity     | SHA-256 on uploads, magic-byte MIME verification, immutable audit log table                  |
| A09 Logging & Monitoring Failures | `AuditLog` model + rotating file handler with IP/UA context                                  |
| A10 SSRF                          | No outbound HTTP on user input; only static-resource fetches                                 |

---

## Architecture

```
employee-portal/
├── app.py              # Application factory, routes, error handlers
├── config.py           # Hardened defaults; env-driven secrets
├── models.py           # User, Document, AuditLog (Argon2id, RBAC enum)
├── forms.py            # WTForms with strict validators (CSRF auto)
├── decorators.py       # @roles_required, @owns_resource
├── uploads_util.py     # Magic-byte validation, UUID storage
├── templates/          # Jinja2 (auto-escape on)
├── static/style.css
├── requirements.txt
├── .env.example
└── .gitignore
```

---

## Quick start

```bash
# 1. Clone and enter
cd employee-portal

# 2. Python 3.12+ recommended
python -m venv .venv
source .venv/bin/activate           # Windows: .venv\Scripts\activate

# 3. Install
pip install -r requirements.txt

# 4. (Optional) configure environment
cp .env.example .env
# Edit .env and set SECRET_KEY for production

# 5. Run
python app.py
# Visit http://127.0.0.1:5000
```

**Demo credentials (auto-seeded on first run):**

| User    | Password               | Role     |
| ------- | ---------------------- | -------- |
| admin   | `Admin!Strong#2026`    | admin    |
| alice   | `Employee!Strong#2026` | employee |

> Change these immediately — they exist only so the app runs out of the box for demos.

---

## Production deployment

```bash
export SECRET_KEY="$(python -c 'import secrets; print(secrets.token_hex(64))')"
export FLASK_ENV=production
export FLASK_CONFIG=production
export DATABASE_URL=postgresql://...   # don't ship SQLite to prod

gunicorn -w 4 -b 127.0.0.1:8000 app:app
```

Front it with **nginx** terminating TLS (Let's Encrypt). The app sets HSTS, expects `__Host-` cookies, and refuses non-HTTPS in production mode.

---

## Security controls — deep dive

### Authentication
- **Argon2id** password hashing (`argon2-cffi`), memory-hard against GPU/ASIC attackers (RFC 9106).
- **Account lockout** after 5 failed logins (15 min window). Locked accounts skip password verification to deny timing oracles.
- **Generic error messages** ("Invalid credentials") prevent user enumeration.
- **TOTP MFA** via `pyotp` — QR-code provisioning, RFC 6238 compliant.
- **Session fixation defence** — `session_protection="strong"` invalidates session on IP/User-Agent change.
- **Constant-time verification** via Argon2's `verify` (raises on mismatch — no early return path).

### Session & CSRF
- `HttpOnly` + `Secure` + `SameSite=Lax` cookies.
- `__Host-` cookie prefix in production — browser enforces same-host & secure.
- 30-minute idle timeout, 7-day remember-me lifetime.
- All state-changing requests require a CSRF token (Flask-WTF).
- Open redirect prevention on `?next=` — same-host, relative paths only.

### SQL Injection (A03)
- **100% parameterized** via SQLAlchemy ORM. No raw SQL anywhere.
- The directory search uses `ilike(f"%{q}%")` — `q` is a bind parameter, not interpolated.

### XSS (A03)
- Jinja2 auto-escape on for all HTML contexts.
- Strict Content Security Policy: `default-src 'self'`; `object-src 'none'`; `frame-ancestors 'none'`.
- Bio field passes through `bleach.clean(..., tags=[], strip=True)` before storage — defence in depth.
- No use of `|safe`, `Markup()`, or `innerHTML` anywhere.

### Broken Access Control (A01)
- Every protected route declares its required role(s) via `@roles_required(...)`.
- Per-object access uses `@owns_resource(loader)` — admins bypass, all others must own.
- IDOR attempts return **404** (not 403) to avoid leaking existence of other users' resources.
- User loader coerces `user_id` to `int` to block type-confusion driver bugs.

### File upload security (A04 / A08)
1. Extension **allowlist** (`pdf`, `png`, `jpg`, `jpeg`, `docx`, `txt`).
2. MIME sniffed by **libmagic** (`python-magic`) — not the attacker-controlled `Content-Type` header.
3. Extension and detected MIME must agree (defeats `shell.php.jpg`).
4. Filename is replaced with a server-generated **UUID** — original kept only as metadata. No path traversal possible.
5. Files stored outside the web root, served only via authenticated route.
6. 5 MB hard limit at WSGI layer + re-check after read.
7. Stored with `0640` permissions, never executable.
8. **SHA-256** computed for integrity and forensic reference.

### Rate limiting
- Global default: 200/hour.
- Login: 10/minute.
- Registration: 5/hour.
- Upload: 20/hour.
- Backed by in-memory store for demo — **use Redis in production** (set `RATELIMIT_STORAGE_URI`).

### Security headers (Flask-Talisman + manual extras)
- `Strict-Transport-Security: max-age=31536000; includeSubDomains`
- `X-Frame-Options: DENY`
- `X-Content-Type-Options: nosniff`
- `Referrer-Policy: strict-origin-when-cross-origin`
- `Permissions-Policy: geolocation=(), microphone=(), camera=()`
- `Cross-Origin-Opener-Policy: same-origin`
- `Cross-Origin-Resource-Policy: same-origin`
- CSP with per-request **nonces** for scripts.

### Logging & monitoring (A09)
- Every security-relevant event lands in the `AuditLog` table:
  `login_success`, `login_failed`, `login_locked`, `mfa_enabled`, `mfa_failed`, `authz_denied`, `idor_attempt`, `upload_rejected`, `upload_success`, `download`, `document_deleted`, `user_registered`, `logout`.
- App logger writes to a 1 MiB rotating file (5 backups) with IP + username context.
- Admin panel shows the 50 most recent events.

---

## Testing the security controls (your pentest)

Once you have the app running, here are the OWASP-mapped tests to perform and document for your report:

| Attack                          | How to test                                                                                       | Expected result                                                       |
| ------------------------------- | ------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------- |
| SQL Injection (login)           | Submit `admin' OR '1'='1` as username in Burp                                                     | Rejected by regex validator (400) or returns "Invalid credentials"    |
| SQL Injection (directory)       | Search `') UNION SELECT password_hash FROM users--`                                               | Rejected by allowlist regex                                           |
| Reflected XSS                   | `?q=<script>alert(1)</script>` against directory                                                  | Validator rejects; even if bypassed, CSP blocks inline scripts        |
| Stored XSS                      | Set bio to `<img src=x onerror=alert(1)>`                                                         | `bleach` strips tags; Jinja escapes; CSP blocks                       |
| CSRF                            | Submit logout / delete from external page without token                                           | 400 — CSRF token missing/invalid                                      |
| IDOR                            | `GET /documents/<other_user_id>/download` while logged in as alice                                | 404                                                                   |
| Brute force                     | 10 wrong logins via Hydra / Burp Intruder                                                         | Account locked for 15 min after 5 attempts; HTTP 429 from rate limiter|
| File upload — PHP shell         | Upload `shell.php` renamed to `shell.php.jpg`                                                     | Rejected — MIME/extension mismatch                                    |
| File upload — oversized         | Upload 10 MB file                                                                                 | Rejected at WSGI layer (413)                                          |
| Path traversal (download)       | `GET /documents/../../etc/passwd`                                                                 | 404 — Flask routing rejects                                           |
| Session hijack                  | Steal cookie via XSS                                                                              | Cookie is `HttpOnly` — JS cannot read it; CSP blocks injection anyway |
| Clickjacking                    | Embed portal in `<iframe>` on attacker site                                                       | Blocked by `X-Frame-Options: DENY` + CSP `frame-ancestors 'none'`     |
| Open redirect                   | `/login?next=https://evil.com/`                                                                   | `_safe_redirect` strips it; redirects to dashboard                    |
| MFA bypass                      | Skip directly to `/dashboard` after step 1 of MFA flow                                            | 401 — `pre_2fa_user_id` is not a full login                           |

Document each test with **(a)** payload sent, **(b)** server response, **(c)** screenshot. That becomes your penetration testing report.

---

## What to write in your pentest report

A great report has six sections:

1. **Executive summary** — one paragraph, plain English.
2. **Scope** — your localhost, this app, these versions.
3. **Methodology** — OWASP Testing Guide v4 phases used.
4. **Findings table** — each test from the matrix above with severity (CVSS) and result.
5. **Remediation review** — for the secure version, document which control caught each attack.
6. **Appendix** — raw Burp logs, screenshots, payloads.

---

## Suggested companion: build the vulnerable version too

To make this a **complete** Project 2 deliverable, create a sibling repo `employee-portal-vulnerable/` that re-introduces:

- Raw f-string SQL in the login query.
- `|safe` on the bio field render.
- Removal of `@owns_resource` on document download.
- Acceptance of any file extension, no magic check.

That gives you a clear before/after demo for your interviews. **Never expose the vulnerable version to the internet** — localhost only, as per the ethical rules in your guide.

---

## Ethical use

This repository is for **self-hosted educational research only**. Per OWASP and your internship guide:

- ✅ Localhost / Docker / your own VM
- ✅ Pair with DVWA, OWASP Juice Shop
- ❌ Real companies, public systems, anything you don't own

---

## License

MIT — use, modify, learn from it freely.

## References

- [OWASP Top 10 (2021)](https://owasp.org/Top10/)
- [OWASP ASVS 4.0](https://owasp.org/www-project-application-security-verification-standard/)
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [RFC 9106 — Argon2 password hashing](https://www.rfc-editor.org/rfc/rfc9106.html)
- [Flask-Talisman](https://github.com/wntrblm/flask-talisman)
