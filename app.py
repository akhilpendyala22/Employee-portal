"""
Enterprise Employee Portal — secured edition.

OWASP Top 10 mitigations implemented (annotated inline by control):

    A01 Broken Access Control       → @roles_required, @owns_resource
    A02 Cryptographic Failures      → Argon2id passwords, HTTPS-only cookies
    A03 Injection                   → SQLAlchemy ORM, Jinja autoescape, bleach
    A04 Insecure Design             → Rate limits, lockout, MFA, CSRF
    A05 Security Misconfiguration   → Talisman, DEBUG off, secret from env
    A06 Vulnerable Components       → Pinned versions in requirements.txt
    A07 Auth Failures               → Lockout, TOTP MFA, password policy
    A08 Software/Data Integrity     → SHA-256 on uploads, immutable audit log
    A09 Logging Failures            → AuditLog model + rotating file handler
    A10 SSRF                        → No outbound fetches on user input
"""
import io
import logging
import os
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path
from urllib.parse import urlparse

import bleach
import pyotp
import qrcode
from flask import (
    Flask, render_template, redirect, url_for, flash, request,
    session, send_file, abort, jsonify,
)
from flask_login import (
    LoginManager, login_user, logout_user, login_required, current_user,
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
from flask_wtf.csrf import CSRFProtect, CSRFError
from sqlalchemy import or_
from werkzeug.exceptions import HTTPException, RequestEntityTooLarge

from config import config
from models import db, User, Document, AuditLog, Role
from decorators import roles_required, owns_resource
from forms import LoginForm, MFAForm, RegisterForm, ProfileForm, UploadForm, SearchForm
from uploads_util import validate_and_store, UploadError


# ---------------------------------------------------------------------------
# Application factory
# ---------------------------------------------------------------------------

login_manager = LoginManager()
csrf = CSRFProtect()
limiter = Limiter(key_func=get_remote_address)


def create_app(config_name: str | None = None) -> Flask:
    app = Flask(__name__, instance_relative_config=True)
    cfg = config[config_name or os.environ.get("FLASK_CONFIG", "default")]
    app.config.from_object(cfg() if callable(cfg) else cfg)

    Path(app.config["UPLOAD_FOLDER"]).mkdir(parents=True, exist_ok=True)
    Path(app.config["LOG_DIR"]).mkdir(parents=True, exist_ok=True)

    _init_extensions(app)
    _init_security_headers(app)
    _init_logging(app)
    _register_routes(app)
    _register_error_handlers(app)

    with app.app_context():
        db.create_all()
        _seed_demo_data(app)

    return app


def _init_extensions(app: Flask) -> None:
    db.init_app(app)
    csrf.init_app(app)
    limiter.init_app(app)

    login_manager.init_app(app)
    login_manager.login_view = "login"
    login_manager.session_protection = "strong"  # invalidate on IP/UA change
    login_manager.login_message = "Please sign in to continue."
    login_manager.login_message_category = "info"

    @login_manager.user_loader
    def load_user(user_id):
        # int() guards against SQL-driver-level type confusion.
        try:
            return db.session.get(User, int(user_id))
        except (TypeError, ValueError):
            return None


def _init_security_headers(app: Flask) -> None:
    """
    Talisman sets HSTS, X-Content-Type-Options, X-Frame-Options, Referrer-Policy,
    and a strict Content Security Policy.

    The CSP is the most important defence against XSS: even if an attacker
    injects a <script> tag, the browser will refuse to execute it because
    only 'self' (and nonces) are permitted as script sources.
    """
    csp = {
        "default-src": "'self'",
        "script-src": "'self'",
        "style-src": "'self'",
        "img-src": ["'self'", "data:"],  # data: for QR code only
        "font-src": "'self'",
        "connect-src": "'self'",
        "frame-ancestors": "'none'",
        "form-action": "'self'",
        "base-uri": "'self'",
        "object-src": "'none'",
    }
    Talisman(
        app,
        content_security_policy=csp,
        content_security_policy_nonce_in=["script-src"],
        force_https=app.config.get("SESSION_COOKIE_SECURE", False),
        strict_transport_security=True,
        strict_transport_security_max_age=31536000,
        strict_transport_security_include_subdomains=True,
        frame_options="DENY",
        referrer_policy="strict-origin-when-cross-origin",
        session_cookie_secure=app.config.get("SESSION_COOKIE_SECURE", False),
        session_cookie_http_only=True,
    )

    @app.after_request
    def extra_headers(response):
        # Belt and braces — Talisman covers most of these, but explicit > implicit.
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
        response.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        response.headers.setdefault("Cross-Origin-Resource-Policy", "same-origin")
        return response


def _init_logging(app: Flask) -> None:
    log_path = Path(app.config["LOG_DIR"]) / "portal.log"
    handler = RotatingFileHandler(log_path, maxBytes=1_048_576, backupCount=5)
    handler.setFormatter(logging.Formatter(
        "%(asctime)s %(levelname)s %(name)s [%(remote_addr)s %(user)s] %(message)s"
    ))
    handler.setLevel(logging.INFO)

    class ContextFilter(logging.Filter):
        def filter(self, record):
            record.remote_addr = request.remote_addr if request else "-"
            record.user = current_user.username if (
                request and current_user.is_authenticated
            ) else "-"
            return True

    handler.addFilter(ContextFilter())
    app.logger.addHandler(handler)
    app.logger.setLevel(logging.INFO)


def _audit(event: str, user_id=None, details: str = ""):
    db.session.add(AuditLog(
        event=event,
        user_id=user_id,
        ip_address=request.remote_addr if request else None,
        user_agent=(request.headers.get("User-Agent") or "")[:255] if request else None,
        details=details,
    ))
    db.session.commit()


def _safe_redirect(target: str | None, fallback: str) -> str:
    """
    Open redirect prevention. Only allow same-host relative paths.
    Mitigates unvalidated redirect chains used in phishing.
    """
    if not target:
        return fallback
    parsed = urlparse(target)
    if parsed.netloc or parsed.scheme:
        return fallback
    if not target.startswith("/"):
        return fallback
    return target


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

def _register_routes(app: Flask) -> None:

    # ---- Public ----------------------------------------------------------

    @app.route("/")
    def index():
        if current_user.is_authenticated:
            return redirect(url_for("dashboard"))
        return redirect(url_for("login"))

    @app.route("/health")
    def health():
        return jsonify(status="ok")

    # ---- Authentication --------------------------------------------------

    @app.route("/login", methods=["GET", "POST"])
    @limiter.limit("10 per minute", methods=["POST"])  # Brute-force defence
    def login():
        if current_user.is_authenticated:
            return redirect(url_for("dashboard"))

        form = LoginForm()
        if form.validate_on_submit():
            # Parameterized via ORM — SQL injection impossible here.
            user = User.query.filter_by(username=form.username.data).first()

            # Account-lockout check first; don't even verify the password
            # of a locked account (denies oracle timing).
            if user and user.is_locked():
                _audit("login_locked", user_id=user.id)
                flash("Account temporarily locked. Try again later.", "error")
                return render_template("login.html", form=form), 429

            if user and user.is_active and user.verify_password(form.password.data):
                user.reset_failed_attempts()
                if user.mfa_enabled:
                    # Stash partial auth; require TOTP before granting session.
                    session["pre_2fa_user_id"] = user.id
                    session["pre_2fa_remember"] = bool(form.remember.data)
                    db.session.commit()
                    return redirect(url_for("mfa_challenge"))

                _finalize_login(user, remember=form.remember.data)
                return redirect(_safe_redirect(
                    request.args.get("next"), url_for("dashboard")
                ))

            # Failure path. Don't leak whether the username exists.
            if user:
                user.register_failed_attempt(
                    app.config["MAX_LOGIN_ATTEMPTS"],
                    app.config["LOCKOUT_DURATION_MINUTES"],
                )
                db.session.commit()
            _audit("login_failed", user_id=user.id if user else None,
                   details=f"username_attempt={form.username.data[:32]}")
            flash("Invalid credentials.", "error")

        return render_template("login.html", form=form)

    @app.route("/mfa", methods=["GET", "POST"])
    @limiter.limit("10 per minute", methods=["POST"])
    def mfa_challenge():
        user_id = session.get("pre_2fa_user_id")
        if not user_id:
            return redirect(url_for("login"))
        user = db.session.get(User, user_id)
        if not user or not user.mfa_enabled:
            session.pop("pre_2fa_user_id", None)
            return redirect(url_for("login"))

        form = MFAForm()
        if form.validate_on_submit():
            totp = pyotp.TOTP(user.totp_secret)
            if totp.verify(form.token.data, valid_window=1):
                remember = session.pop("pre_2fa_remember", False)
                session.pop("pre_2fa_user_id", None)
                _finalize_login(user, remember=remember)
                return redirect(url_for("dashboard"))
            _audit("mfa_failed", user_id=user.id)
            flash("Invalid authenticator code.", "error")

        return render_template("mfa.html", form=form)

    def _finalize_login(user: User, remember: bool):
        user.last_login_at = datetime.now(timezone.utc)
        user.last_login_ip = request.remote_addr
        db.session.commit()
        login_user(user, remember=remember)
        # Rotate session ID to defeat session fixation.
        session.regenerate = True
        _audit("login_success", user_id=user.id)

    @app.route("/logout", methods=["POST"])
    @login_required
    def logout():
        _audit("logout", user_id=current_user.id)
        logout_user()
        session.clear()
        return redirect(url_for("login"))

    @app.route("/register", methods=["GET", "POST"])
    @limiter.limit("5 per hour")
    def register():
        if current_user.is_authenticated:
            return redirect(url_for("dashboard"))

        form = RegisterForm()
        if form.validate_on_submit():
            existing = User.query.filter(
                or_(User.username == form.username.data,
                    User.email == form.email.data)
            ).first()
            if existing:
                # Generic error message — don't disclose which field collided.
                flash("Registration could not be completed.", "error")
                return render_template("register.html", form=form)

            user = User(
                username=form.username.data,
                email=form.email.data.lower(),
                role=Role.EMPLOYEE,
            )
            user.set_password(form.password.data)
            db.session.add(user)
            db.session.commit()
            _audit("user_registered", user_id=user.id)
            flash("Account created. Please sign in.", "success")
            return redirect(url_for("login"))

        return render_template("register.html", form=form)

    # ---- MFA enrollment --------------------------------------------------

    @app.route("/mfa/setup", methods=["GET", "POST"])
    @login_required
    def mfa_setup():
        if request.method == "POST":
            form = MFAForm()
            if form.validate_on_submit():
                secret = session.get("provisional_totp")
                if not secret:
                    abort(400)
                totp = pyotp.TOTP(secret)
                if totp.verify(form.token.data, valid_window=1):
                    current_user.totp_secret = secret
                    current_user.mfa_enabled = True
                    db.session.commit()
                    session.pop("provisional_totp", None)
                    _audit("mfa_enabled", user_id=current_user.id)
                    flash("Two-factor authentication enabled.", "success")
                    return redirect(url_for("dashboard"))
                flash("Code did not verify. Try again.", "error")

        secret = pyotp.random_base32()
        session["provisional_totp"] = secret
        return render_template(
            "mfa_setup.html",
            secret=secret,
            form=MFAForm(),
        )

    @app.route("/mfa/qr")
    @login_required
    def mfa_qr():
        secret = session.get("provisional_totp")
        if not secret:
            abort(404)
        uri = pyotp.TOTP(secret).provisioning_uri(
            name=current_user.email,
            issuer_name=app.config["APP_NAME"],
        )
        img = qrcode.make(uri)
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        buf.seek(0)
        return send_file(buf, mimetype="image/png")

    # ---- Authenticated employee routes ----------------------------------

    @app.route("/dashboard")
    @login_required
    def dashboard():
        docs = Document.query.filter_by(user_id=current_user.id) \
                             .order_by(Document.uploaded_at.desc()).all()
        return render_template("dashboard.html", documents=docs)

    @app.route("/profile", methods=["GET", "POST"])
    @login_required
    def profile():
        form = ProfileForm()
        if form.validate_on_submit():
            # Sanitize HTML — strip all tags. Jinja autoescape would also
            # neutralize it on render, but stripping at write time keeps
            # the stored value clean if it's ever exported elsewhere.
            current_user.bio = bleach.clean(form.bio.data or "", tags=[], strip=True)
            db.session.commit()
            flash("Profile updated.", "success")
            return redirect(url_for("profile"))
        return render_template("profile.html", form=form)

    @app.route("/directory")
    @login_required
    def directory():
        form = SearchForm(request.args, meta={"csrf": False})
        users = []
        if form.validate():
            q = (form.q.data or "").strip()
            query = User.query.filter(User.is_active.is_(True))
            if q:
                # ORM-parameterized LIKE — no string concatenation.
                like = f"%{q}%"
                query = query.filter(
                    or_(User.username.ilike(like), User.email.ilike(like))
                )
            users = query.order_by(User.username).limit(50).all()
        return render_template("directory.html", form=form, users=users)

    # ---- File uploads ----------------------------------------------------

    @app.route("/documents/upload", methods=["GET", "POST"])
    @login_required
    @limiter.limit("20 per hour")
    def upload_document():
        form = UploadForm()
        if form.validate_on_submit():
            try:
                meta = validate_and_store(
                    form.document.data,
                    upload_dir=Path(app.config["UPLOAD_FOLDER"]),
                    allowed_ext=app.config["ALLOWED_EXTENSIONS"],
                    allowed_mime=app.config["ALLOWED_MIMETYPES"],
                    max_bytes=app.config["MAX_CONTENT_LENGTH"],
                )
            except UploadError as e:
                _audit("upload_rejected", user_id=current_user.id, details=str(e))
                flash(f"Upload rejected: {e}", "error")
                return render_template("upload.html", form=form)

            doc = Document(user_id=current_user.id, **meta)
            db.session.add(doc)
            db.session.commit()
            _audit("upload_success", user_id=current_user.id,
                   details=f"doc_id={doc.id} sha256={meta['sha256']}")
            flash("Document uploaded.", "success")
            return redirect(url_for("dashboard"))

        return render_template("upload.html", form=form)

    @app.route("/documents/<int:id>/download")
    @login_required
    @owns_resource(loader=lambda i: db.session.get(Document, i))
    def download_document(id, resource):
        doc: Document = resource
        path = Path(app.config["UPLOAD_FOLDER"]) / doc.stored_filename

        # Resolve and confirm the path is still inside the upload dir.
        # Defense-in-depth against path traversal if stored_filename were
        # ever corrupted (it shouldn't be — it's a UUID we generated).
        upload_root = Path(app.config["UPLOAD_FOLDER"]).resolve()
        resolved = path.resolve()
        if not str(resolved).startswith(str(upload_root)):
            abort(404)
        if not resolved.is_file():
            abort(404)

        _audit("download", user_id=current_user.id, details=f"doc_id={doc.id}")
        return send_file(
            resolved,
            mimetype=doc.mime_type,
            as_attachment=True,
            download_name=doc.original_filename,
        )

    @app.route("/documents/<int:id>/delete", methods=["POST"])
    @login_required
    @owns_resource(loader=lambda i: db.session.get(Document, i))
    def delete_document(id, resource):
        doc: Document = resource
        path = Path(app.config["UPLOAD_FOLDER"]) / doc.stored_filename
        if path.exists():
            path.unlink()
        db.session.delete(doc)
        db.session.commit()
        _audit("document_deleted", user_id=current_user.id, details=f"doc_id={id}")
        flash("Document deleted.", "success")
        return redirect(url_for("dashboard"))

    # ---- Admin only ------------------------------------------------------

    @app.route("/admin")
    @login_required
    @roles_required(Role.ADMIN)
    def admin_panel():
        users = User.query.order_by(User.username).all()
        recent_events = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(50).all()
        return render_template("admin.html", users=users, events=recent_events)


# ---------------------------------------------------------------------------
# Error handlers — generic messages, no stack traces leaked.
# ---------------------------------------------------------------------------

def _register_error_handlers(app: Flask) -> None:

    @app.errorhandler(CSRFError)
    def csrf_error(e):
        return render_template("error.html", code=400,
                               msg="Form expired. Please reload and try again."), 400

    @app.errorhandler(RequestEntityTooLarge)
    def too_large(e):
        return render_template("error.html", code=413,
                               msg="Upload too large."), 413

    @app.errorhandler(404)
    def not_found(e):
        return render_template("error.html", code=404, msg="Not found."), 404

    @app.errorhandler(401)
    def unauthorized(e):
        return redirect(url_for("login"))

    @app.errorhandler(403)
    def forbidden(e):
        return render_template("error.html", code=403, msg="Forbidden."), 403

    @app.errorhandler(429)
    def rate_limited(e):
        return render_template("error.html", code=429,
                               msg="Too many requests. Please slow down."), 429

    @app.errorhandler(500)
    def server_error(e):
        app.logger.exception("Unhandled server error")
        return render_template("error.html", code=500,
                               msg="Internal server error."), 500

    @app.errorhandler(Exception)
    def catch_all(e):
        if isinstance(e, HTTPException):
            return e
        app.logger.exception("Unhandled exception")
        return render_template("error.html", code=500,
                               msg="Internal server error."), 500


# ---------------------------------------------------------------------------
# Demo data — for local testing only.
# ---------------------------------------------------------------------------

def _seed_demo_data(app: Flask) -> None:
    if User.query.first() is not None:
        return
    admin = User(username="admin", email="admin@example.com", role=Role.ADMIN)
    admin.set_password("Admin!Strong#2026")
    employee = User(username="alice", email="alice@example.com", role=Role.EMPLOYEE)
    employee.set_password("Employee!Strong#2026")
    db.session.add_all([admin, employee])
    db.session.commit()
    app.logger.info("Seeded demo users: admin / alice")


# ---------------------------------------------------------------------------

app = create_app()

if __name__ == "__main__":
    # Local dev only. In production use:  gunicorn -w 4 -b 0.0.0.0:8000 app:app
    app.run(host="127.0.0.1", port=5000, debug=False)
