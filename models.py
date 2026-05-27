"""
Database models.

Security design:
- Passwords are Argon2id-hashed (memory-hard, OWASP-recommended).
- Roles use a strict enum — no free-form strings to manipulate.
- All authorization checks key off `role`, never client-supplied data.
- Audit fields (created_at, last_login_at, failed_attempts) support
  detection and lockout.
"""
from datetime import datetime, timezone, timedelta
from enum import Enum

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHash
from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Enum as SQLEnum

db = SQLAlchemy()

# Argon2id — memory-hard, side-channel resistant. Parameters tuned for
# ~50ms per hash on commodity hardware (RFC 9106 recommendations).
_hasher = PasswordHasher(
    time_cost=3,
    memory_cost=65536,  # 64 MiB
    parallelism=4,
    hash_len=32,
    salt_len=16,
)


class Role(str, Enum):
    EMPLOYEE = "employee"
    MANAGER = "manager"
    ADMIN = "admin"


class User(db.Model, UserMixin):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(SQLEnum(Role), nullable=False, default=Role.EMPLOYEE)

    # MFA
    totp_secret = db.Column(db.String(64), nullable=True)
    mfa_enabled = db.Column(db.Boolean, default=False, nullable=False)

    # Account state / audit
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    failed_attempts = db.Column(db.Integer, default=0, nullable=False)
    locked_until = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(
        db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False
    )
    last_login_at = db.Column(db.DateTime, nullable=True)
    last_login_ip = db.Column(db.String(45), nullable=True)  # IPv6 fits

    documents = db.relationship(
        "Document", backref="owner", lazy=True, cascade="all, delete-orphan"
    )

    def set_password(self, password: str) -> None:
        """Hash and store a new password. Plaintext never persists."""
        self.password_hash = _hasher.hash(password)

    def verify_password(self, password: str) -> bool:
        """
        Constant-time verification. Argon2's verify raises on mismatch
        rather than returning False, which avoids early-exit timing leaks.
        """
        try:
            _hasher.verify(self.password_hash, password)
        except (VerifyMismatchError, InvalidHash):
            return False

        # If parameters have been upgraded since this hash was created,
        # rehash transparently on successful login.
        if _hasher.check_needs_rehash(self.password_hash):
            self.password_hash = _hasher.hash(password)
            db.session.commit()
        return True

    def is_locked(self) -> bool:
        if self.locked_until is None:
            return False
        # Compare as aware datetimes
        now = datetime.now(timezone.utc)
        locked_until = self.locked_until
        if locked_until.tzinfo is None:
            locked_until = locked_until.replace(tzinfo=timezone.utc)
        return locked_until > now

    def register_failed_attempt(self, max_attempts: int, lockout_minutes: int) -> None:
        self.failed_attempts += 1
        if self.failed_attempts >= max_attempts:
            self.locked_until = datetime.now(timezone.utc) + timedelta(
                minutes=lockout_minutes
            )

    def reset_failed_attempts(self) -> None:
        self.failed_attempts = 0
        self.locked_until = None

    def has_role(self, *roles: Role) -> bool:
        return self.role in roles

    def __repr__(self) -> str:
        return f"<User {self.username} role={self.role.value}>"


class Document(db.Model):
    """User-uploaded document. Files live on disk; metadata in DB."""

    __tablename__ = "documents"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer, db.ForeignKey("users.id"), nullable=False, index=True
    )
    original_filename = db.Column(db.String(255), nullable=False)
    stored_filename = db.Column(db.String(255), nullable=False, unique=True)
    mime_type = db.Column(db.String(100), nullable=False)
    file_size = db.Column(db.Integer, nullable=False)
    sha256 = db.Column(db.String(64), nullable=False)
    uploaded_at = db.Column(
        db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False
    )


class AuditLog(db.Model):
    """Immutable security event log. Append-only — never UPDATE or DELETE."""

    __tablename__ = "audit_log"

    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(
        db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False, index=True
    )
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    event = db.Column(db.String(64), nullable=False, index=True)
    ip_address = db.Column(db.String(45), nullable=True)
    user_agent = db.Column(db.String(255), nullable=True)
    details = db.Column(db.Text, nullable=True)
