"""
Application configuration.

Security note: SECRET_KEY must be loaded from environment in production.
Never hardcode secrets or commit them to source control.
"""
import os
from datetime import timedelta
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent


class Config:
    # --- Core security ---
    # SECRET_KEY signs session cookies and CSRF tokens. If this leaks, an
    # attacker can forge sessions. Always load from environment in prod.
    SECRET_KEY = os.environ.get("SECRET_KEY") or os.urandom(64).hex()

    # --- Database ---
    # Using SQLAlchemy ORM — all queries are parameterized, preventing
    # SQL injection by construction.
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL"
    ) or f"sqlite:///{BASE_DIR / 'instance' / 'portal.db'}"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        "pool_pre_ping": True,
        "pool_recycle": 280,
    }

    # --- Session / cookie hardening ---
    # HttpOnly: JavaScript cannot read the cookie (blocks XSS theft).
    # Secure: cookie only sent over HTTPS (set False only in local dev).
    # SameSite=Lax: protects against most CSRF cross-site attacks.
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SECURE = os.environ.get("FLASK_ENV") == "production"
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_NAME = "__Host-portal_session" if SESSION_COOKIE_SECURE else "portal_session"
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=30)

    REMEMBER_COOKIE_HTTPONLY = True
    REMEMBER_COOKIE_SECURE = SESSION_COOKIE_SECURE
    REMEMBER_COOKIE_SAMESITE = "Lax"
    REMEMBER_COOKIE_DURATION = timedelta(days=7)

    # --- CSRF ---
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = 3600  # 1 hour
    WTF_CSRF_SSL_STRICT = SESSION_COOKIE_SECURE

    # --- File uploads ---
    UPLOAD_FOLDER = BASE_DIR / "uploads"
    MAX_CONTENT_LENGTH = 5 * 1024 * 1024  # 5 MB hard limit
    ALLOWED_EXTENSIONS = {"pdf", "png", "jpg", "jpeg", "docx", "txt"}
    # MIME types verified by libmagic (content sniffing, not just extension).
    ALLOWED_MIMETYPES = {
        "application/pdf",
        "image/png",
        "image/jpeg",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "text/plain",
    }

    # --- Rate limiting ---
    RATELIMIT_DEFAULT = "200 per hour"
    RATELIMIT_STORAGE_URI = "memory://"  # use Redis in production
    RATELIMIT_HEADERS_ENABLED = True

    # --- Account lockout policy ---
    MAX_LOGIN_ATTEMPTS = 5
    LOCKOUT_DURATION_MINUTES = 15

    # --- Password policy ---
    PASSWORD_MIN_LENGTH = 12
    PASSWORD_REQUIRE_UPPER = True
    PASSWORD_REQUIRE_LOWER = True
    PASSWORD_REQUIRE_DIGIT = True
    PASSWORD_REQUIRE_SPECIAL = True

    # --- Logging ---
    LOG_DIR = BASE_DIR / "logs"

    # --- App metadata ---
    APP_NAME = "Enterprise Employee Portal"


class DevConfig(Config):
    DEBUG = False  # Even in dev, leave DEBUG off — debug enables the
    # Werkzeug debugger which is a full RCE if exposed.
    TESTING = False


class ProdConfig(Config):
    DEBUG = False
    TESTING = False

    def __init__(self):
        # Fail loudly if production secrets aren't provided.
        if not os.environ.get("SECRET_KEY"):
            raise RuntimeError("SECRET_KEY must be set in production")


config = {
    "development": DevConfig,
    "production": ProdConfig,
    "default": DevConfig,
}
