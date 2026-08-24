import secrets

from flask import abort, g, request, session

from .models import User, db


WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


def csrf_token():
    if not session.get("csrf_token"):
        session["csrf_token"] = secrets.token_urlsafe(32)
    return session["csrf_token"]


def before():
    g.user = None
    uid = session.get("user_id")
    if uid:
        g.user = db.session.get(User, uid)
        if not g.user or not g.user.is_active or session.get("session_version") != g.user.session_version:
            session.clear()
            g.user = None
    if request.method in WRITE_METHODS:
        token = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token", "")
        if not token or not secrets.compare_digest(token, session.get("csrf_token", "")):
            abort(400, "Invalid form token. Refresh the page and try again.")

