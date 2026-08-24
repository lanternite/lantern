import os
import re
import secrets
import uuid
from datetime import UTC, datetime
from functools import wraps

import click
from flask import Flask, abort, flash, g, redirect, render_template, request, session, url_for
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from markupsafe import Markup
from sqlalchemy import text, update
from sqlalchemy.exc import IntegrityError
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

from .models import Artwork, DailySearchUsage, InviteCode, SiteSetting, User, db
from .scanner import ScannerClient
from .security import csrf_token, before
from .services.matches import normalize_matches_payload

ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp"}
PDQ_RE = re.compile(r"^[0-9a-fA-F]{64}$")


def create_app():
    instance_path = os.environ.get("LANTERN_INSTANCE_PATH")
    app = Flask(__name__, instance_relative_config=True, instance_path=instance_path)
    os.makedirs(app.instance_path, exist_ok=True)
    app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "dev-insecure-change-me")
    app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv(
        "DATABASE_URL", "sqlite:///" + os.path.join(app.instance_path, "lantern.db")
    )
    app.config["MAX_CONTENT_LENGTH"] = 25 * 1024 * 1024
    app.config["SESSION_COOKIE_SECURE"] = os.getenv("FLASK_ENV") == "production"
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    app.config["PERMANENT_SESSION_LIFETIME"] = 60 * 60 * 24 * 14

    db.init_app(app)
    limiter = Limiter(
        get_remote_address, app=app, default_limits=["300 per hour"], storage_uri="memory://"
    )
    scanner = ScannerClient()


    @app.before_request
    def load_current_user_and_check_csrf():
        before()

    @app.context_processor
    def inject_globals():
        invites_enabled = setting_enabled("invites_enabled", default=True)
        return {
            "current_user": g.user,
            "csrf_token": csrf_token,
            "csrf_field": lambda: Markup(
                f'<input type="hidden" name="csrf_token" value="{csrf_token()}">'
            ),
            "invites_enabled": invites_enabled,
            "has_invite_access": bool(g.user and g.user.invite_quota > 0),
        }

    def setting_enabled(key, default=False):
        setting = db.session.get(SiteSetting, key)
        return default if setting is None else setting.value == "1"

    def login_required(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if g.user is None:
                return redirect(url_for("login"))
            return view(*args, **kwargs)
        return wrapped

    def scanner_state(artwork):
        if not artwork.scanner_work_id:
            return {"status": "failed", "matches": []}
        try:
            payload = scanner.matches(artwork.scanner_work_id)
            status = payload.get("status", "done")
            if status == "done" and not artwork.scanned:
                artwork.scanned = True
                db.session.commit()
            return {"status": status, "matches": normalize_matches_payload(payload, artwork), "stale": False}
        except RuntimeError:
            return {
                "status": "done" if artwork.scanned else "queued",
                "matches": [],
                "stale": True,
            }

    def searches_today(user_id):
        usage = db.session.get(DailySearchUsage, (user_id, datetime.now(UTC).date()))
        return usage.count if usage else 0

    def reserve_search(user_id):
        day = datetime.now(UTC).date().isoformat()
        db.session.execute(
            text(
                "INSERT OR IGNORE INTO daily_search_usage (user_id, day, count) "
                "VALUES (:user_id, :day, 0)"
            ),
            {"user_id": user_id, "day": day},
        )
        count = db.session.execute(
            text(
                "UPDATE daily_search_usage SET count = count + 1 "
                "WHERE user_id = :user_id AND day = :day AND count < :limit "
                "RETURNING count"
            ),
            {
                "user_id": user_id,
                "day": day,
                "limit": db.session.get(User, user_id).daily_search_quota,
            },
        ).scalar_one_or_none()
        db.session.commit()
        return count

    def release_search(user_id):
        db.session.execute(
            text(
                "UPDATE daily_search_usage SET count = count - 1 "
                "WHERE user_id = :user_id AND day = :day AND count > 0"
            ),
            {"user_id": user_id, "day": datetime.now(UTC).date().isoformat()},
        )
        db.session.commit()

    @app.get("/health")
    @limiter.exempt
    def health():
        return {"ok": True}

    @app.route("/")
    def login():
        if g.user:
            return redirect(url_for("dashboard"))
        return render_template("login.html")

    @app.post("/login")
    @limiter.limit("10 per minute")
    def do_login():
        username = request.form.get("user", "").strip()
        password = request.form.get("password", "")
        user = User.query.filter_by(username=username).first()
        if user is None or not user.is_active or not check_password_hash(user.password_hash, password):
            flash("Incorrect username or password.")
            return redirect(url_for("login"))
        session.clear()
        session["user_id"] = user.id
        session["session_version"] = user.session_version
        session["csrf_token"] = secrets.token_urlsafe(32)
        session.permanent = True
        return redirect(url_for("dashboard"))

    @app.post("/logout")
    def logout():
        session.clear()
        return redirect(url_for("login"))

    @app.route("/register", methods=["GET", "POST"])
    @limiter.limit("10 per hour", methods=["POST"])
    def register():
        if not setting_enabled("invites_enabled", default=True):
            abort(404)
        if request.method == "GET":
            return render_template("register.html")
        code = request.form.get("invite", "").strip().upper()
        invite = InviteCode.query.filter_by(code=code, used_by_id=None).first()
        if invite is None or (invite.created_by_id and not invite.created_by.is_active):
            flash("That invite code isn't valid.")
            return redirect(url_for("register"))
        session["invite_code"] = invite.code
        return redirect(url_for("register_account"))

    @app.route("/register/account", methods=["GET", "POST"])
    @limiter.limit("10 per hour", methods=["POST"])
    def register_account():
        if not setting_enabled("invites_enabled", default=True):
            session.pop("invite_code", None)
            abort(404)
        code = session.get("invite_code")
        invite = InviteCode.query.filter_by(code=code, used_by_id=None).first() if code else None
        if invite is None or (invite.created_by_id and not invite.created_by.is_active):
            session.pop("invite_code", None)
            flash("That invite code is missing or has already been used.")
            return redirect(url_for("register"))
        if request.method == "GET":
            return render_template("register_account.html")
        email = request.form.get("email", "").strip().lower()[:255]
        username = request.form.get("user", "").strip()[:64]
        password = request.form.get("password", "")
        error = None
        if not email or "@" not in email:
            error = "Enter a valid email."
        elif len(username) < 2:
            error = "Choose a username with at least 2 characters."
        elif len(password) < 10 or len(password) > 256:
            error = "Password must be between 10 and 256 characters."
        elif User.query.filter_by(username=username).first():
            error = "That username is taken."
        elif User.query.filter_by(email=email).first():
            error = "That email is already registered."
        if error:
            flash(error)
            return redirect(url_for("register_account"))
        user = User(email=email, username=username, password_hash=generate_password_hash(password))
        try:
            db.session.add(user)
            db.session.flush()
            claimed = db.session.execute(
                update(InviteCode)
                .where(InviteCode.id == invite.id, InviteCode.used_by_id.is_(None))
                .values(used_by_id=user.id, used_at=datetime.utcnow())
                .execution_options(synchronize_session=False)
            )
            if claimed.rowcount != 1:
                db.session.rollback()
                session.pop("invite_code", None)
                flash("That invite code has already been used.")
                return redirect(url_for("register"))
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            flash("That username or email is already registered.")
            return redirect(url_for("register_account"))
        session.clear()
        session["user_id"] = user.id
        session["session_version"] = user.session_version
        session["csrf_token"] = secrets.token_urlsafe(32)
        session.permanent = True
        return redirect(url_for("dashboard"))

    @app.get("/dashboard")
    @login_required
    def dashboard():
        artworks = Artwork.query.filter_by(user_id=g.user.id).order_by(Artwork.added_at.desc()).all()
        states = {artwork.id: scanner_state(artwork) for artwork in artworks}
        return render_template(
            "dashboard.html", artworks=artworks, states=states,
            scanner_stale=any(state.get("stale") for state in states.values()),
            artwork_limit=g.user.artwork_quota,
        )

    @app.post("/upload")
    @login_required
    @limiter.limit("30 per hour")
    def upload():
        files = [item for item in request.files.getlist("file") if item and item.filename]
        if not files:
            flash("No files selected.")
            return redirect(url_for("dashboard"))
        limit = g.user.artwork_quota
        remaining = None if limit is None else max(limit - Artwork.query.filter_by(user_id=g.user.id).count(), 0)
        if remaining == 0:
            flash(f"You're at your {limit}-artwork limit.")
            return redirect(url_for("dashboard"))
        saved, errors = [], []
        for item in files[:15]:
            if remaining is not None and len(saved) >= remaining:
                break
            filename = secure_filename(item.filename)[:255]
            extension = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
            if extension not in ALLOWED_EXTENSIONS:
                errors.append(f"{filename}: unsupported file type")
                continue
            data = item.read()
            if not data:
                errors.append(f"{filename}: empty file")
                continue
            work_id = uuid.uuid4().hex
            try:
                result = scanner.add_image(work_id, filename, data, item.mimetype)
            except RuntimeError as exc:
                errors.append(f"{filename}: {exc}")
                continue
            db.session.add(Artwork(
                user_id=g.user.id,
                filename=filename,
                scanner_work_id=work_id,
                fingerprint=result["pdq_hex"][0],
                pdq_quality=result.get("quality"),
            ))
            saved.append(filename)
        db.session.commit()
        if saved:
            flash(f"Added {len(saved)} artwork{'s' if len(saved) != 1 else ''} to your watchlist.")
        elif errors:
            flash(errors[0])
        if errors and saved:
            flash(f"{len(errors)} file{'s' if len(errors) != 1 else ''} could not be added.")
        return redirect(url_for("dashboard"))

    @app.post("/artwork/<int:artwork_id>/note")
    @login_required
    def update_note(artwork_id):
        artwork = Artwork.query.filter_by(id=artwork_id, user_id=g.user.id).first_or_404()
        artwork.note = request.form.get("note", "").strip()[:500] or None
        db.session.commit()
        return {"note": artwork.note or ""}

    @app.post("/artwork/<int:artwork_id>/delete")
    @login_required
    def delete_artwork(artwork_id):
        artwork = Artwork.query.filter_by(id=artwork_id, user_id=g.user.id).first_or_404()
        try:
            scanner.delete_work(artwork.scanner_work_id)
        except RuntimeError as exc:
            flash(f"Could not remove {artwork.filename}: {exc}")
            return redirect(url_for("dashboard"))
        filename = artwork.filename
        db.session.delete(artwork)
        db.session.commit()
        flash(f"Removed {filename} from your watchlist.")
        return redirect(url_for("dashboard"))

    @app.get("/matches")
    @login_required
    def matches():
        artwork_id = request.args.get("artwork_id", type=int)
        query = Artwork.query.filter_by(user_id=g.user.id)
        if artwork_id:
            query = query.filter_by(id=artwork_id)
        artworks = query.all()
        results, scanning = [], False
        for artwork in artworks:
            state = scanner_state(artwork)
            scanning = scanning or state["status"] in {"queued", "leased"}
            results.extend(state["matches"])
        return render_template("matches.html", matches=results, artwork_id=artwork_id, scanning=scanning)

    @app.route("/search", methods=["GET", "POST"])
    @login_required
    @limiter.limit("30 per hour", methods=["POST"])
    def search():
        mode = request.values.get("mode", "image")
        mode = mode if mode in {"image", "fingerprint"} else "image"
        fingerprint, error, results = None, None, []
        searched = request.method == "POST"
        if searched and mode == "fingerprint":
            fingerprint = request.form.get("fingerprint", "").strip().lower()
            if not PDQ_RE.fullmatch(fingerprint):
                error = "Invalid hash"
            else:
                try:
                    results = normalize_matches_payload(scanner.exact_hash(fingerprint))
                except RuntimeError as exc:
                    error = str(exc)
        elif searched:
            item = request.files.get("file")
            if not item or not item.filename:
                error = "Choose an image to search."
            else:
                filename = secure_filename(item.filename)[:255]
                reserved_count = reserve_search(g.user.id)
                if reserved_count is None:
                    error = f"You've used all {g.user.daily_search_quota} scans for today."
                else:
                    try:
                        payload = scanner.search_image(filename, item.read(), item.mimetype)
                        fingerprint = payload["pdq_hex"][0]
                        results = normalize_matches_payload(payload)
                    except RuntimeError as exc:
                        release_search(g.user.id)
                        error = str(exc)
        scan_count = searches_today(g.user.id)
        return render_template(
            "search.html", mode=mode, fingerprint=fingerprint, results=results, error=error,
            searched=searched,
            scan_count=scan_count, scan_limit=g.user.daily_search_quota,
        )

    @app.get("/analytics")
    @login_required
    def analytics():
        artworks = Artwork.query.filter_by(user_id=g.user.id).all()
        states = [scanner_state(artwork) for artwork in artworks]
        scanned = sum(state["status"] == "done" for state in states)
        flagged = sum(
            state["status"] == "done" and bool(state["matches"])
            for state in states
        )
        stats = [
            ("Artworks tracked", len(artworks)),
            ("Awaiting scan", sum(state["status"] in {"queued", "leased"} for state in states)),
            ("Scanned clear", scanned - flagged),
            ("Flagged", flagged),
            ("Total matches found", sum(len(state["matches"]) for state in states)),
            ("Member since", g.user.created_at.strftime("%Y-%m-%d")),
        ]
        return render_template("analytics.html", stats=stats)



    @app.route("/invites", methods=["GET", "POST"])
    @login_required
    @limiter.limit("30 per hour", methods=["POST"])
    def user_invites():
        if not setting_enabled("invites_enabled", default=True):
            abort(404)
        remaining = max(g.user.invite_quota - g.user.invites_issued, 0)
        if g.user.invite_quota <= 0:
            abort(404)
        if request.method == "POST":
            code = f"LANTERN-{secrets.token_hex(4).upper()}"
            claimed = db.session.execute(
                update(User)
                .where(User.id == g.user.id, User.invites_issued < User.invite_quota)
                .values(invites_issued=User.invites_issued + 1)
                .execution_options(synchronize_session=False)
            )
            if claimed.rowcount != 1:
                db.session.rollback()
                flash("You have no invites remaining.")
                return redirect(url_for("dashboard"))
            db.session.add(InviteCode(code=code, created_by_id=g.user.id))
            db.session.commit()
            flash(f"Created invite code {code}.")
            return redirect(url_for("user_invites"))
        invites = InviteCode.query.filter_by(created_by_id=g.user.id).order_by(InviteCode.id.desc()).all()
        return render_template("invites.html", invites=invites, remaining=remaining)

    @app.route("/account", methods=["GET", "POST"])
    @login_required
    def account():
        if request.method == "POST":
            current_password = request.form.get("current_password", "")
            new_password = request.form.get("new_password", "")
            confirm_password = request.form.get("confirm_password", "")
            if not check_password_hash(g.user.password_hash, current_password):
                flash("Current password is incorrect.")
            elif len(new_password) < 10 or len(new_password) > 256:
                flash("New password must be between 10 and 256 characters.")
            elif new_password != confirm_password:
                flash("New passwords don't match.")
            else:
                g.user.password_hash = generate_password_hash(new_password)
                g.user.session_version += 1
                db.session.commit()
                session.clear()
                session["user_id"] = g.user.id
                session["session_version"] = g.user.session_version
                session["csrf_token"] = secrets.token_urlsafe(32)
                session.permanent = True
                flash("Password updated.")
            return redirect(url_for("account"))
        return render_template(
            "account.html", artwork_count=Artwork.query.filter_by(user_id=g.user.id).count(),
            artwork_cap=g.user.artwork_quota,
        )

    @app.post("/account/delete")
    @login_required
    @limiter.limit("5 per hour")
    def delete_account():
        password = request.form.get("password", "")
        confirmed = request.form.get("permanently_delete") == "yes"
        if not check_password_hash(g.user.password_hash, password):
            flash("Password is incorrect.")
            return redirect(url_for("account"))
        if not confirmed:
            flash("Confirm that your data will be permanently deleted.")
            return redirect(url_for("account"))
        user = g.user
        for artwork in list(user.artworks):
            if artwork.scanner_work_id:
                try:
                    scanner.delete_work(artwork.scanner_work_id)
                except RuntimeError:
                    pass

        InviteCode.query.filter_by(used_by_id=user.id).delete(synchronize_session=False)
        InviteCode.query.filter_by(created_by_id=user.id, used_by_id=None).delete(
            synchronize_session=False
        )
        InviteCode.query.filter_by(created_by_id=user.id).update(
            {InviteCode.created_by_id: None}, synchronize_session=False
        )
        DailySearchUsage.query.filter_by(user_id=user.id).delete(synchronize_session=False)

        return_code = f"LANTERN-{secrets.token_hex(4).upper()}"
        db.session.add(InviteCode(code=return_code))
        db.session.delete(user)
        db.session.commit()

        session.clear()
        session["deleted_account_invite"] = return_code
        session["csrf_token"] = secrets.token_urlsafe(32)
        return redirect(url_for("account_deleted"))

    @app.get("/account/deleted")
    def account_deleted():
        code = session.get("deleted_account_invite")
        if not code:
            return redirect(url_for("login"))
        return render_template("account_deleted.html", invite_code=code)



    @app.cli.command("init-db")
    def init_db_command():
        db.create_all()
        if InviteCode.query.count() == 0:
            code = os.environ.get("INITIAL_INVITE_CODE") or f"LANTERN-{secrets.token_hex(4).upper()}"
            db.session.add(InviteCode(code=code))
            db.session.commit()
            click.echo(f"Database initialized. Initial invite code: {code}")
        else:
            click.echo("Database initialized.")

    @app.cli.command("add-invite")
    @click.argument("code")
    def add_invite_command(code):
        code = code.strip().upper()
        if InviteCode.query.filter_by(code=code).first():
            click.echo(f"Invite code {code} already exists.")
            return
        db.session.add(InviteCode(code=code))
        db.session.commit()
        click.echo(f"Added invite code: {code}")

    return app


app = create_app()

if __name__ == "__main__":
    app.run(debug=True)
