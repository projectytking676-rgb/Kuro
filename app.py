import os
import re
import hmac
import secrets
import sqlite3
from datetime import datetime, timezone
from functools import wraps

from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, abort
from werkzeug.security import generate_password_hash, check_password_hash

APP_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.environ.get("KURO_DB_PATH", os.path.join(APP_DIR, "kuro.db"))
app = Flask(__name__)
app.secret_key = os.environ.get("KURO_SECRET_KEY")
if not app.secret_key:
    raise RuntimeError("Set KURO_SECRET_KEY in your hosting environment before starting KURO PANEL.")

def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")

def init_db():
    with db() as con:
        con.executescript("""
        CREATE TABLE IF NOT EXISTS admins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS licenses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            license_key TEXT UNIQUE NOT NULL,
            device_id TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT 'active',
            expires_at TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            note TEXT NOT NULL DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS settings (
            name TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        """)
        defaults = {
            "online_update": "1",
            "maintenance": "0",
            "latest_version": "1.0.0",
            "update_url": "",
            "update_message": "A new version is available."
        }
        for key, value in defaults.items():
            con.execute("INSERT OR IGNORE INTO settings(name,value) VALUES(?,?)", (key, value))

        # Optional first-admin bootstrap for hosts without an interactive shell.
        # Set both environment variables on the hosting provider before first deploy.
        admin_username = os.environ.get("KURO_ADMIN_USERNAME", "PROJECT").strip()
        admin_password = os.environ.get("KURO_ADMIN_PASSWORD", "")
        existing_admin = con.execute("SELECT id FROM admins LIMIT 1").fetchone()
        if not existing_admin and len(admin_username) >= 3 and len(admin_password) >= 12:
            con.execute(
                "INSERT INTO admins(username,password_hash) VALUES(?,?)",
                (admin_username, generate_password_hash(admin_password))
            )

def setting(name, default=""):
    with db() as con:
        row = con.execute("SELECT value FROM settings WHERE name=?", (name,)).fetchone()
        return row["value"] if row else default

def set_setting(name, value):
    with db() as con:
        con.execute(
            "INSERT INTO settings(name,value) VALUES(?,?) "
            "ON CONFLICT(name) DO UPDATE SET value=excluded.value",
            (name, str(value))
        )

def admin_required(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if not session.get("admin_id"):
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapped

def csrf_token():
    token = session.get("_csrf")
    if not token:
        token = secrets.token_urlsafe(32)
        session["_csrf"] = token
    return token

@app.context_processor
def inject_csrf():
    return {"csrf_token": csrf_token}

@app.before_request
def protect_forms():
    if request.method == "POST" and request.endpoint not in ("api_verify", "api_config", "api_update"):
        sent = request.form.get("_csrf", "")
        expected = session.get("_csrf", "")
        if not expected or not hmac.compare_digest(sent, expected):
            abort(400, "Invalid form token. Refresh the page and try again.")

@app.route("/")
def index():
    if session.get("admin_id"):
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        with db() as con:
            admin = con.execute("SELECT * FROM admins WHERE username=?", (username,)).fetchone()
        if admin and check_password_hash(admin["password_hash"], password):
            session.clear()
            session["admin_id"] = admin["id"]
            session["username"] = admin["username"]
            flash("Welcome back.", "success")
            return redirect(url_for("dashboard"))
        flash("Invalid username or password.", "error")
    return render_template("login.html")

@app.route("/logout", methods=["POST"])
@admin_required
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/dashboard")
@admin_required
def dashboard():
    with db() as con:
        total = con.execute("SELECT COUNT(*) n FROM licenses").fetchone()["n"]
        active = con.execute("SELECT COUNT(*) n FROM licenses WHERE status='active'").fetchone()["n"]
        bound = con.execute("SELECT COUNT(*) n FROM licenses WHERE device_id<>''").fetchone()["n"]
        recent = con.execute("SELECT * FROM licenses ORDER BY id DESC LIMIT 6").fetchall()
    return render_template("dashboard.html", total=total, active=active, bound=bound, recent=recent,
                           online_update=setting("online_update"), maintenance=setting("maintenance"))

@app.route("/keys", methods=["GET", "POST"])
@admin_required
def keys():
    if request.method == "POST":
        device_id = request.form.get("device_id", "").strip()
        expiry = request.form.get("expires_at", "").strip()
        note = request.form.get("note", "").strip()[:120]
        if len(device_id) > 160:
            flash("Device ID is too long.", "error")
            return redirect(url_for("keys"))
        if expiry and not re.fullmatch(r"\d{4}-\d{2}-\d{2}", expiry):
            flash("Expiry must use YYYY-MM-DD.", "error")
            return redirect(url_for("keys"))
        key = "KURO-" + secrets.token_hex(12).upper()
        with db() as con:
            con.execute(
                "INSERT INTO licenses(license_key,device_id,status,expires_at,created_at,note) VALUES(?,?,?,?,?,?)",
                (key, device_id, "active", expiry, now(), note)
            )
        flash("License created: " + key, "success")
        return redirect(url_for("keys"))
    with db() as con:
        rows = con.execute("SELECT * FROM licenses ORDER BY id DESC").fetchall()
    return render_template("keys.html", rows=rows)

@app.route("/keys/<int:key_id>/status", methods=["POST"])
@admin_required
def key_status(key_id):
    with db() as con:
        row = con.execute("SELECT status FROM licenses WHERE id=?", (key_id,)).fetchone()
        if row:
            new_status = "inactive" if row["status"] == "active" else "active"
            con.execute("UPDATE licenses SET status=? WHERE id=?", (new_status, key_id))
    return redirect(url_for("keys"))

@app.route("/keys/<int:key_id>/delete", methods=["POST"])
@admin_required
def key_delete(key_id):
    with db() as con:
        con.execute("DELETE FROM licenses WHERE id=?", (key_id,))
    flash("Key deleted.", "success")
    return redirect(url_for("keys"))

@app.route("/settings", methods=["GET", "POST"])
@admin_required
def settings():
    if request.method == "POST":
        set_setting("online_update", "1" if request.form.get("online_update") == "on" else "0")
        set_setting("maintenance", "1" if request.form.get("maintenance") == "on" else "0")
        version = request.form.get("latest_version", "1.0.0").strip()[:30]
        update_url = request.form.get("update_url", "").strip()[:500]
        message = request.form.get("update_message", "").strip()[:250]
        if update_url and not update_url.startswith("https://"):
            flash("Update URL must start with https://", "error")
            return redirect(url_for("settings"))
        set_setting("latest_version", version or "1.0.0")
        set_setting("update_url", update_url)
        set_setting("update_message", message)
        flash("Settings saved.", "success")
        return redirect(url_for("settings"))
    return render_template("settings.html",
        online_update=setting("online_update"), maintenance=setting("maintenance"),
        latest_version=setting("latest_version"), update_url=setting("update_url"),
        update_message=setting("update_message"))

def expired(value):
    if not value:
        return False
    try:
        return datetime.strptime(value, "%Y-%m-%d").date() < datetime.now(timezone.utc).date()
    except ValueError:
        return True

@app.post("/api/v1/verify")
def api_verify():
    data = request.get_json(silent=True) or request.form
    key = str(data.get("key", "")).strip().upper()
    device_id = str(data.get("device_id", "")).strip()
    if not key or not device_id or len(device_id) > 160:
        return jsonify(ok=False, message="key and device_id are required"), 400
    if setting("maintenance") == "1":
        return jsonify(ok=False, message="Service is under maintenance"), 503
    with db() as con:
        license_row = con.execute("SELECT * FROM licenses WHERE license_key=?", (key,)).fetchone()
        if not license_row:
            return jsonify(ok=False, message="Invalid key"), 403
        if license_row["status"] != "active":
            return jsonify(ok=False, message="Key is disabled"), 403
        if expired(license_row["expires_at"]):
            return jsonify(ok=False, message="Key expired"), 403
        bound_id = license_row["device_id"]
        if bound_id and not hmac.compare_digest(bound_id, device_id):
            return jsonify(ok=False, message="Key is already linked to another device"), 403
        if not bound_id:
            con.execute("UPDATE licenses SET device_id=? WHERE id=?", (device_id, license_row["id"]))
    return jsonify(ok=True, message="License verified", device_bound=True)

@app.get("/api/v1/config")
def api_config():
    return jsonify(
        online_update=setting("online_update") == "1",
        maintenance=setting("maintenance") == "1",
        latest_version=setting("latest_version"),
        update_url=setting("update_url"),
        update_message=setting("update_message")
    )

@app.get("/api/v1/update")
def api_update():
    current = request.args.get("version", "").strip()
    latest = setting("latest_version")
    enabled = setting("online_update") == "1"
    return jsonify(
        update_enabled=enabled,
        update_available=bool(enabled and latest and current != latest),
        current_version=current,
        latest_version=latest,
        update_url=setting("update_url") if enabled else "",
        message=setting("update_message")
    )

@app.get("/health")
def health():
    return jsonify(status="ok", service="KURO PANEL")

init_db()

if __name__ == "__main__":
    app.run(debug=False)
