"""
Authorization decorators.

Mitigates A01:2021 - Broken Access Control.

Key principle: authorization is enforced on the server, never trusted from
the client. Every protected route is wrapped with an explicit role check
and every object access is verified against the current user.
"""
from functools import wraps

from flask import abort, request
from flask_login import current_user

from models import Role, AuditLog, db


def roles_required(*roles: Role):
    """Require the current user to hold one of the listed roles."""

    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if not current_user.is_authenticated:
                abort(401)
            if not current_user.has_role(*roles):
                _log_event(
                    "authz_denied",
                    user_id=current_user.id,
                    details=f"route={request.path} required={[r.value for r in roles]}",
                )
                abort(403)
            return view(*args, **kwargs)

        return wrapped

    return decorator


def owns_resource(loader, owner_attr: str = "user_id"):
    """
    Verify the current user owns the resource being requested.

    `loader` is a callable that takes the route's `id` kwarg and returns
    the resource (or None). Admins bypass the ownership check.

    Mitigates IDOR (Insecure Direct Object Reference).
    """

    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if not current_user.is_authenticated:
                abort(401)

            resource_id = kwargs.get("id") or kwargs.get("resource_id")
            resource = loader(resource_id)
            if resource is None:
                abort(404)

            owner_id = getattr(resource, owner_attr, None)
            if current_user.role != Role.ADMIN and owner_id != current_user.id:
                _log_event(
                    "idor_attempt",
                    user_id=current_user.id,
                    details=f"resource={resource.__class__.__name__} id={resource_id}",
                )
                # Return 404 not 403 — don't leak existence of other users' data.
                abort(404)

            kwargs["resource"] = resource
            return view(*args, **kwargs)

        return wrapped

    return decorator


def _log_event(event: str, user_id=None, details: str = ""):
    entry = AuditLog(
        event=event,
        user_id=user_id,
        ip_address=request.remote_addr,
        user_agent=(request.headers.get("User-Agent") or "")[:255],
        details=details,
    )
    db.session.add(entry)
    db.session.commit()
