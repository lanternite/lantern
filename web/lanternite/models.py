from datetime import date, datetime

from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    username = db.Column(db.String(64), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    session_version = db.Column(db.Integer, default=0, nullable=False)
    artwork_quota = db.Column(db.Integer, default=100, nullable=False)
    daily_search_quota = db.Column(db.Integer, default=100, nullable=False)
    invite_quota = db.Column(db.Integer, default=0, nullable=False)
    invites_issued = db.Column(db.Integer, default=0, nullable=False)

    artworks = db.relationship(
        "Artwork", backref="owner", lazy=True, cascade="all, delete-orphan"
    )


class InviteCode(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(32), unique=True, nullable=False)
    used_by_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    created_by_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    used_at = db.Column(db.DateTime, nullable=True)

    used_by = db.relationship("User", foreign_keys=[used_by_id])
    created_by = db.relationship("User", foreign_keys=[created_by_id])


class SiteSetting(db.Model):
    __tablename__ = "site_setting"

    key = db.Column(db.String(64), primary_key=True)
    value = db.Column(db.String(255), nullable=False)


class Artwork(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    scanner_work_id = db.Column(db.String(64), unique=True, nullable=True, index=True)
    added_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    scanned = db.Column(db.Boolean, default=False, nullable=False)
    note = db.Column(db.Text, nullable=True)
    fingerprint = db.Column(db.String(64), nullable=True)
    pdq_quality = db.Column(db.Integer, nullable=True)


class DailySearchUsage(db.Model):
    __tablename__ = "daily_search_usage"

    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), primary_key=True)
    day = db.Column(db.Date, primary_key=True, default=date.today)
    count = db.Column(db.Integer, nullable=False, default=0)
