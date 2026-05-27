"""
Form definitions with server-side validation.

Mitigates:
- Mass-assignment (only declared fields are accepted).
- Injection (validators sanitize/constrain input).
- CSRF (every form inherits CSRF protection from Flask-WTF).
"""
import re

from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileRequired, FileAllowed
from wtforms import StringField, PasswordField, BooleanField, TextAreaField, SubmitField
from wtforms.validators import (
    DataRequired,
    Length,
    Email,
    EqualTo,
    Regexp,
    ValidationError,
)


# Strict username pattern — letters, digits, underscore, dot, hyphen.
# Rejects anything that could be HTML, SQL meta-chars, path traversal, etc.
USERNAME_REGEX = re.compile(r"^[A-Za-z0-9._-]{3,32}$")


def strong_password(form, field):
    """Enforce password complexity. Configured via app config."""
    from flask import current_app

    cfg = current_app.config
    pw = field.data or ""

    if len(pw) < cfg["PASSWORD_MIN_LENGTH"]:
        raise ValidationError(
            f"Password must be at least {cfg['PASSWORD_MIN_LENGTH']} characters."
        )
    if cfg["PASSWORD_REQUIRE_UPPER"] and not re.search(r"[A-Z]", pw):
        raise ValidationError("Password must contain an uppercase letter.")
    if cfg["PASSWORD_REQUIRE_LOWER"] and not re.search(r"[a-z]", pw):
        raise ValidationError("Password must contain a lowercase letter.")
    if cfg["PASSWORD_REQUIRE_DIGIT"] and not re.search(r"\d", pw):
        raise ValidationError("Password must contain a digit.")
    if cfg["PASSWORD_REQUIRE_SPECIAL"] and not re.search(
        r"[!@#$%^&*()_\-+=\[\]{};:'\",.<>/?\\|`~]", pw
    ):
        raise ValidationError("Password must contain a special character.")


class LoginForm(FlaskForm):
    username = StringField(
        "Username",
        validators=[
            DataRequired(),
            Length(min=3, max=32),
            Regexp(USERNAME_REGEX, message="Invalid characters in username."),
        ],
    )
    password = PasswordField("Password", validators=[DataRequired(), Length(max=128)])
    remember = BooleanField("Remember me")
    submit = SubmitField("Sign in")


class MFAForm(FlaskForm):
    token = StringField(
        "Authenticator code",
        validators=[
            DataRequired(),
            Length(min=6, max=6),
            Regexp(r"^\d{6}$", message="Must be 6 digits."),
        ],
    )
    submit = SubmitField("Verify")


class RegisterForm(FlaskForm):
    username = StringField(
        "Username",
        validators=[
            DataRequired(),
            Length(min=3, max=32),
            Regexp(USERNAME_REGEX, message="Letters, digits, dot, dash, underscore only."),
        ],
    )
    email = StringField("Email", validators=[DataRequired(), Email(), Length(max=120)])
    password = PasswordField("Password", validators=[DataRequired(), strong_password])
    confirm = PasswordField(
        "Confirm password",
        validators=[DataRequired(), EqualTo("password", message="Passwords must match.")],
    )
    submit = SubmitField("Create account")


class ProfileForm(FlaskForm):
    """Profile bio — rendered through bleach + Jinja autoescape."""

    bio = TextAreaField("Bio", validators=[Length(max=500)])
    submit = SubmitField("Save")


class UploadForm(FlaskForm):
    document = FileField(
        "Document",
        validators=[
            FileRequired(),
            FileAllowed(
                ["pdf", "png", "jpg", "jpeg", "docx", "txt"],
                "Only PDF, image, DOCX, or TXT files are allowed.",
            ),
        ],
    )
    submit = SubmitField("Upload")


class SearchForm(FlaskForm):
    """Employee directory search — bound to ORM, no raw SQL."""

    q = StringField(
        "Search",
        validators=[
            Length(max=64),
            Regexp(
                r"^[A-Za-z0-9 ._@-]*$",
                message="Search contains invalid characters.",
            ),
        ],
    )
    submit = SubmitField("Search")
