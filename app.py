import os
import re
import hmac
import secrets
import sqlite3
import csv
import io

from datetime import datetime, date, timedelta, timezone
from functools import wraps
from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, jsonify, abort, Response
)
from werkzeug.security import generate_password_hash, check_password_hash


# ============================================================
# PROJECT YT - CONFIGURATION
# ============================================================

APP_DIR = os.path.abspath(os.path.dirname(__file__))

# Railway Volume must be mounted at /data.
# Set KURO_DB_PATH=/data/project_yt.db in Railway Variables.
DB_PATH = os.environ.get(
    "KURO_DB_PATH",
    "/data/project_yt.db"
)

# Create the parent directory before SQLite tries to open the DB.
DB_DIR = os.path.dirname(os.path.abspath(DB_PATH))
os.makedirs(DB_DIR, exist_ok=True)

app = Flask(__name__)

app.secret_key = os.environ.get("KURO_SECRET_KEY")
if not app.secret_key:
    raise RuntimeError(
        "Set KURO_SECRET_KEY in your hosting environment before starting PROJECT YT."
    )


def db():
    """Open a SQLite connection and ensure its parent directory exists."""
    os.makedirs(DB_DIR, exist_ok=True)
    con = sqlite3.connect(DB_PATH, timeout=30)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys=ON")
    con.execute("PRAGMA busy_timeout=30000")
    return con


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# ============================================================
# DATABASE INITIALIZATION / MIGRATION
# ============================================================

def init_db():
    with db() as con:
        con.execute("PRAGMA journal_mode=WAL")
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
            note TEXT NOT NULL DEFAULT '',
            device_limit INTEGER NOT NULL DEFAULT 1
        );

        CREATE TABLE IF NOT EXISTS license_devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            license_id INTEGER NOT NULL REFERENCES licenses(id) ON DELETE CASCADE,
            device_id TEXT NOT NULL,
            first_seen TEXT NOT NULL,
            UNIQUE(license_id, device_id)
        );

        CREATE TABLE IF NOT EXISTS settings (
            name TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        """)

        # Upgrade older databases safely.
        cols = {
            r["name"]
            for r in con.execute("PRAGMA table_info(licenses)").fetchall()
        }
        if "device_limit" not in cols:
            con.execute(
                "ALTER TABLE licenses ADD COLUMN device_limit INTEGER NOT NULL DEFAULT 1"
            )

        # Migrate any old single-device bindings into license_devices.
        old = con.execute(
            "SELECT id, device_id FROM licenses WHERE device_id<>''"
        ).fetchall()

        for row in old:
            con.execute(
                """
                INSERT OR IGNORE INTO license_devices
                (license_id, device_id, first_seen)
                VALUES (?, ?, ?)
                """,
                (row["id"], row["device_id"], now())
            )

        defaults = {
            "online_update": "1",
            "maintenance": "0",
            "latest_version": "1.0.0",
            "update_url": "",
            "update_message": "A new version is available."
        }

        for key, value in defaults.items():
            con.execute(
                "INSERT OR IGNORE INTO settings(name, value) VALUES(?, ?)",
                (key, value)
            )

        # Create first admin only when credentials are valid.
        username = os.environ.get(
            "KURO_ADMIN_USERNAME", "PROJECT"
        ).strip()
        password = os.environ.get("KURO_ADMIN_PASSWORD", "")

        admin_exists = con.execute(
            "SELECT id FROM admins LIMIT 1"
        ).fetchone()

        if not admin_exists and len(username) >= 3 and len(password) >= 12:
            con.execute(
                "INSERT INTO admins(username, password_hash) VALUES(?, ?)",
                (username, generate_password_hash(password))
            )


# ============================================================
# SETTINGS HELPERS
# ============================================================

def setting(name, default=""):
    with db() as con:
        row = con.execute(
            "SELECT value FROM settings WHERE name=?",
            (name,)
        ).fetchone()
        return row["value"] if row else default


def set_setting(name, value):
    with db() as con:
        con.execute(
            """
            INSERT INTO settings(name, value)
            VALUES(?, ?)
            ON CONFLICT(name)
            DO UPDATE SET value=excluded.value
            """,
            (name, str(value))
        )


# ============================================================
# AUTHENTICATION / CSRF
# ============================================================

def admin_required(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if not session.get("admin_id"):
            if request.path.startswith("/api/admin/"):
                return jsonify(
                    ok=False,
                    message="Admin login required"
                ), 401
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
    if request.method == "POST" and request.endpoint not in (
        "api_verify",
        "api_config",
        "api_update",
        "api_admin_generate"
    ):
        sent = request.form.get("_csrf", "")
        expected = session.get("_csrf", "")

        if not expected or not hmac.compare_digest(sent, expected):
            # Admin JSON endpoints require a logged-in admin session.
            if not (
                request.path.startswith("/api/admin/")
                and session.get("admin_id")
            ):
                abort(
                    400,
                    "Invalid form token. Refresh the page and try again."
                )


# ============================================================
# ADMIN WEB ROUTES
# ============================================================

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
            admin = con.execute(
                "SELECT * FROM admins WHERE username=?",
                (username,)
            ).fetchone()

        if admin and check_password_hash(admin["password_hash"], password):
            session.clear()
            session["admin_id"] = admin["id"]
            session["username"] = admin["username"]
            flash("Welcome back.", "success")
            return redirect(url_for("dashboard"))

        flash("Invalid username or password.", "error")

    return render_template("login.html")


@app.post("/logout")
@admin_required
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.get("/dashboard")
@admin_required
def dashboard():
    with db() as con:
        total = con.execute(
            "SELECT COUNT(*) n FROM licenses"
        ).fetchone()["n"]

        active = con.execute(
            "SELECT COUNT(*) n FROM licenses WHERE status='active'"
        ).fetchone()["n"]

        bound = con.execute(
            "SELECT COUNT(DISTINCT license_id) n FROM license_devices"
        ).fetchone()["n"]

        recent = con.execute(
            "SELECT * FROM licenses ORDER BY id DESC LIMIT 6"
        ).fetchall()

    return render_template(
        "dashboard.html",
        total=total,
        active=active,
        bound=bound,
        recent=recent,
        online_update=setting("online_update"),
        maintenance=setting("maintenance")
    )


# ============================================================
# LICENSE GENERATION HELPERS
# ============================================================

def expiry_from_form(data):
    plan = str(data.get("plan", "lifetime")).lower().strip()

    if plan == "lifetime":
        return ""

    if plan in ("1d", "7d", "30d", "365d"):
        days = int(plan[:-1])
        return (date.today() + timedelta(days=days)).isoformat()

    if plan == "custom":
        raw = str(data.get("expires_at", "")).strip()
        try:
            parsed = date.fromisoformat(raw)
        except Exception:
            raise ValueError(
                "Custom expiry must be a valid YYYY-MM-DD date."
            )

        if parsed < date.today():
            raise ValueError("Expiry date cannot be in the past.")

        return parsed.isoformat()

    raise ValueError("Choose a valid expiry plan.")


def device_limit_from_form(data):
    mode = str(data.get("device_mode", "single")).lower()

    if mode == "single":
        return 1

    if mode == "multi":
        try:
            number = int(data.get("device_limit", "3"))
        except (TypeError, ValueError):
            raise ValueError("Multi-device limit must be a number.")

        if not 2 <= number <= 10000:
            raise ValueError(
                "Multi-device limit must be between 2 and 10000."
            )
        return number

    if mode == "unlimited":
        return 0

    raise ValueError("Choose a valid device mode.")


def create_keys(count, expires_at, device_limit, note):
    made = []

    with db() as con:
        for _ in range(count):
            for attempt in range(5):
                key = "PROJECT-YT-" + secrets.token_hex(12).upper()

                try:
                    cur = con.execute(
                        """
                        INSERT INTO licenses
                        (license_key, device_id, status, expires_at,
                         created_at, note, device_limit)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            key,
                            "",
                            "active",
                            expires_at,
                            now(),
                            note,
                            device_limit
                        )
                    )
                    made.append((cur.lastrowid, key))
                    break

                except sqlite3.IntegrityError:
                    if attempt == 4:
                        raise

    return made


# ============================================================
# LICENSE MANAGEMENT WEB ROUTES
# ============================================================

@app.route("/keys", methods=["GET", "POST"])
@admin_required
def keys():
    if request.method == "POST":
        try:
            count = int(request.form.get("quantity", "1"))

            if count not in (1, 10, 100, 500):
                raise ValueError(
                    "Choose 1, 10, 100 or 500 keys."
                )

            expiry = expiry_from_form(request.form)
            limit = device_limit_from_form(request.form)
            note = request.form.get("note", "").strip()[:120]

            made = create_keys(count, expiry, limit, note)

            flash(
                f"{len(made)} key(s) generated successfully.",
                "success"
            )

        except ValueError as error:
            flash(str(error), "error")

        return redirect(url_for("keys"))

    query = request.args.get("q", "").strip()[:100]

    with db() as con:
        if query:
            rows = con.execute(
                """
                SELECT l.*,
                (SELECT COUNT(*) FROM license_devices d
                 WHERE d.license_id=l.id) device_count
                FROM licenses l
                WHERE l.license_key LIKE ? OR l.note LIKE ?
                ORDER BY l.id DESC LIMIT 500
                """,
                (f"%{query}%", f"%{query}%")
            ).fetchall()
        else:
            rows = con.execute(
                """
                SELECT l.*,
                (SELECT COUNT(*) FROM license_devices d
                 WHERE d.license_id=l.id) device_count
                FROM licenses l
                ORDER BY l.id DESC LIMIT 500
                """
            ).fetchall()

        total = con.execute(
            "SELECT COUNT(*) n FROM licenses"
        ).fetchone()["n"]

    return render_template(
        "keys.html",
        rows=rows,
        q=query,
        total=total
    )


@app.post("/keys/<int:key_id>/status")
@admin_required
def key_status(key_id):
    with db() as con:
        row = con.execute(
            "SELECT status FROM licenses WHERE id=?",
            (key_id,)
        ).fetchone()

        if row:
            new_status = (
                "inactive" if row["status"] == "active" else "active"
            )
            con.execute(
                "UPDATE licenses SET status=? WHERE id=?",
                (new_status, key_id)
            )

    return redirect(url_for("keys"))


@app.post("/keys/<int:key_id>/delete")
@admin_required
def key_delete(key_id):
    with db() as con:
        con.execute(
            "DELETE FROM licenses WHERE id=?",
            (key_id,)
        )

    flash("Key deleted.", "success")
    return redirect(url_for("keys"))


@app.post("/keys/<int:key_id>/reset")
@admin_required
def key_reset(key_id):
    with db() as con:
        con.execute(
            "DELETE FROM license_devices WHERE license_id=?",
            (key_id,)
        )
        con.execute(
            "UPDATE licenses SET device_id='' WHERE id=?",
            (key_id,)
        )

    flash("Device binding reset.", "success")
    return redirect(url_for("keys"))


@app.get("/keys/export/<fmt>")
@admin_required
def export_keys(fmt):
    if fmt not in ("txt", "csv"):
        abort(404)

    with db() as con:
        rows = con.execute(
            """
            SELECT license_key, status, expires_at,
                   device_limit, note, created_at
            FROM licenses ORDER BY id DESC
            """
        ).fetchall()

    output = io.StringIO()

    if fmt == "csv":
        writer = csv.writer(output)
        writer.writerow([
            "key",
            "status",
            "expires_at",
            "device_limit",
            "note",
            "created_at"
        ])

        for row in rows:
            writer.writerow([
                row["license_key"],
                row["status"],
                row["expires_at"] or "Lifetime",
                (
                    "Unlimited"
                    if row["device_limit"] == 0
                    else row["device_limit"]
                ),
                row["note"],
                row["created_at"]
            ])

        return Response(
            output.getvalue(),
            mimetype="text/csv",
            headers={
                "Content-Disposition":
                "attachment; filename=project_yt_keys.csv"
            }
        )

    for row in rows:
        output.write(row["license_key"] + "\n")

    return Response(
        output.getvalue(),
        mimetype="text/plain",
        headers={
            "Content-Disposition":
            "attachment; filename=project_yt_keys.txt"
        }
    )


# ============================================================
# APP SETTINGS
# ============================================================

@app.route("/settings", methods=["GET", "POST"])
@admin_required
def settings():
    if request.method == "POST":
        set_setting(
            "online_update",
            "1" if request.form.get("online_update") == "on" else "0"
        )
        set_setting(
            "maintenance",
            "1" if request.form.get("maintenance") == "on" else "0"
        )

        version = request.form.get(
            "latest_version", "1.0.0"
        ).strip()[:30]

        update_url = request.form.get(
            "update_url", ""
        ).strip()[:500]

        message = request.form.get(
            "update_message", ""
        ).strip()[:250]

        if update_url and not update_url.startswith("https://"):
            flash("Update URL must start with https://", "error")
            return redirect(url_for("settings"))

        set_setting("latest_version", version or "1.0.0")
        set_setting("update_url", update_url)
        set_setting("update_message", message)

        flash("Settings saved.", "success")
        return redirect(url_for("settings"))

    return render_template(
        "settings.html",
        online_update=setting("online_update"),
        maintenance=setting("maintenance"),
        latest_version=setting("latest_version"),
        update_url=setting("update_url"),
        update_message=setting("update_message")
    )


# ============================================================
# LICENSE VERIFICATION API
# ============================================================

def expired(value):
    if not value:
        return False

    try:
        return date.fromisoformat(value) < date.today()
    except ValueError:
        return True


@app.post("/api/v1/verify")
def api_verify():
    data = request.get_json(silent=True) or request.form

    key = str(data.get("key", "")).strip().upper()
    device_id = str(data.get("device_id", "")).strip()

    if not key or not device_id or len(device_id) > 160:
        return jsonify(
            ok=False,
            message="key and device_id are required"
        ), 400

    if setting("maintenance") == "1":
        return jsonify(
            ok=False,
            message="Service is under maintenance"
        ), 503

    # Serialize device binding checks to avoid exceeding device limits.
    con = db()

    try:
        con.execute("BEGIN IMMEDIATE")

        license_row = con.execute(
            "SELECT * FROM licenses WHERE license_key=?",
            (key,)
        ).fetchone()

        if not license_row:
            con.rollback()
            return jsonify(ok=False, message="Invalid key"), 403

        if license_row["status"] != "active":
            con.rollback()
            return jsonify(ok=False, message="Key is disabled"), 403

        if expired(license_row["expires_at"]):
            con.rollback()
            return jsonify(ok=False, message="Key expired"), 403

        found = con.execute(
            """
            SELECT id FROM license_devices
            WHERE license_id=? AND device_id=?
            """,
            (license_row["id"], device_id)
        ).fetchone()

        if not found:
            count = con.execute(
                """
                SELECT COUNT(*) n FROM license_devices
                WHERE license_id=?
                """,
                (license_row["id"],)
            ).fetchone()["n"]

            limit = license_row["device_limit"]

            if limit != 0 and count >= limit:
                con.rollback()
                return jsonify(
                    ok=False,
                    message="Device limit reached",
                    device_limit=limit
                ), 403

            con.execute(
                """
                INSERT INTO license_devices
                (license_id, device_id, first_seen)
                VALUES (?, ?, ?)
                """,
                (license_row["id"], device_id, now())
            )

        con.commit()

        count = con.execute(
            """
            SELECT COUNT(*) n FROM license_devices
            WHERE license_id=?
            """,
            (license_row["id"],)
        ).fetchone()["n"]

        return jsonify(
            ok=True,
            message="License verified",
            device_bound=True,
            device_count=count,
            device_limit=license_row["device_limit"],
            expires_at=license_row["expires_at"] or None,
            plan=(
                "lifetime"
                if not license_row["expires_at"]
                else "temporary"
            )
        )

    except Exception:
        con.rollback()
        raise

    finally:
        con.close()


# ============================================================
# PUBLIC CONFIG / UPDATE APIs
# ============================================================

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
        update_available=bool(
            enabled and latest and current != latest
        ),
        current_version=current,
        latest_version=latest,
        update_url=setting("update_url") if enabled else "",
        message=setting("update_message")
    )


# ============================================================
# ADMIN JSON APIs
# ============================================================

@app.post("/api/admin/keys")
@admin_required
def api_admin_generate():
    data = request.get_json(silent=True) or {}

    try:
        count = int(data.get("quantity", 1))

        if count not in (1, 10, 100, 500):
            raise ValueError(
                "quantity must be 1, 10, 100 or 500"
            )

        expiry = expiry_from_form(data)
        limit = device_limit_from_form(data)
        note = str(data.get("note", ""))[:120]

        made = create_keys(
            count,
            expiry,
            limit,
            note
        )

        return jsonify(
            ok=True,
            count=len(made),
            keys=[key for _, key in made]
        ), 201

    except ValueError as error:
        return jsonify(
            ok=False,
            message=str(error)
        ), 400


@app.get("/api/admin/keys")
@admin_required
def api_admin_search():
    query = request.args.get("q", "").strip()

    with db() as con:
        rows = con.execute(
            """
            SELECT l.*,
            (SELECT COUNT(*) FROM license_devices d
             WHERE d.license_id=l.id) device_count
            FROM licenses l
            WHERE license_key LIKE ?
            ORDER BY id DESC LIMIT 500
            """,
            (f"%{query}%",)
        ).fetchall()

    return jsonify(
        ok=True,
        keys=[
            {
                "id": row["id"],
                "key": row["license_key"],
                "status": row["status"],
                "expires_at": row["expires_at"] or None,
                "device_limit": row["device_limit"],
                "device_count": row["device_count"],
                "note": row["note"]
            }
            for row in rows
        ]
    )


@app.post("/api/admin/keys/<int:key_id>/disable")
@admin_required
def api_admin_disable(key_id):
    with db() as con:
        cur = con.execute(
            "UPDATE licenses SET status='inactive' WHERE id=?",
            (key_id,)
        )

    return jsonify(ok=cur.rowcount > 0), (
        200 if cur.rowcount else 404
    )


@app.post("/api/admin/keys/<int:key_id>/enable")
@admin_required
def api_admin_enable(key_id):
    with db() as con:
        cur = con.execute(
            "UPDATE licenses SET status='active' WHERE id=?",
            (key_id,)
        )

    return jsonify(ok=cur.rowcount > 0), (
        200 if cur.rowcount else 404
    )


@app.post("/api/admin/keys/<int:key_id>/reset-devices")
@admin_required
def api_admin_reset(key_id):
    with db() as con:
        cur = con.execute(
            "DELETE FROM license_devices WHERE license_id=?",
            (key_id,)
        )

        con.execute(
            "UPDATE licenses SET device_id='' WHERE id=?",
            (key_id,)
        )

        exists = con.execute(
            "SELECT id FROM licenses WHERE id=?",
            (key_id,)
        ).fetchone()

    return jsonify(
        ok=bool(exists),
        removed_devices=cur.rowcount
    ), (200 if exists else 404)


@app.delete("/api/admin/keys/<int:key_id>")
@admin_required
def api_admin_delete(key_id):
    with db() as con:
        cur = con.execute(
            "DELETE FROM licenses WHERE id=?",
            (key_id,)
        )

    return jsonify(ok=cur.rowcount > 0), (
        200 if cur.rowcount else 404
    )



# ============================================================
# API DOCUMENTATION PAGE
# ============================================================

@app.get("/api-docs")
@admin_required
def api_docs():
    # Keep this page self-contained so deployment does not depend
    # on an additional api_docs.html template.
    html = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>PROJECT YT API Docs</title>
<style>
body{font-family:Arial,sans-serif;background:#10111b;color:#f4f4f7;margin:0;padding:22px}
main{max-width:850px;margin:auto}
h1{color:#d7b4ff}
.card{background:#1b1c2a;border:1px solid #38364b;border-radius:12px;padding:16px;margin:14px 0;overflow-wrap:anywhere}
code{color:#b9e6c8;background:#111522;padding:3px 6px;border-radius:5px}
button{background:#8650c8;color:white;border:0;border-radius:7px;padding:9px 13px;margin-top:10px}
small{color:#b8b8c8}
</style>
</head>
<body><main>
<h1>PROJECT YT API Documentation</h1>
<p>Admin key-management endpoints require an authenticated admin browser session.</p>
<div class="card"><b>POST</b> <code>/api/v1/verify</code><p>Verify a license key and bind a device.</p><pre>{"key":"PROJECT-YT-XXXX","device_id":"DEVICE-001"}</pre></div>
<div class="card"><b>GET</b> <code>/api/v1/config</code><p>Read maintenance and app configuration.</p></div>
<div class="card"><b>GET</b> <code>/api/v1/update?version=1.0.0</code><p>Check whether an app update is available.</p></div>
<div class="card"><b>POST</b> <code>/api/admin/keys</code><p>Generate 1, 10, 100 or 500 keys. JSON example:</p><pre>{"quantity":10,"plan":"lifetime","device_mode":"single","note":"Batch A"}</pre></div>
<div class="card"><b>GET</b> <code>/api/admin/keys?q=PROJECT-YT-</code><p>Search license keys.</p></div>
<div class="card"><b>POST</b> <code>/api/admin/keys/KEY_ID/disable</code><p>Disable a key.</p></div>
<div class="card"><b>POST</b> <code>/api/admin/keys/KEY_ID/enable</code><p>Enable a key.</p></div>
<div class="card"><b>POST</b> <code>/api/admin/keys/KEY_ID/reset-devices</code><p>Reset device bindings.</p></div>
<div class="card"><b>DELETE</b> <code>/api/admin/keys/KEY_ID</code><p>Delete a key.</p></div>
<div class="card"><b>GET</b> <code>/health</code><p>Service health check.</p></div>
<p><small>For admin APIs, first log in to the admin panel in the same browser.</small></p>
</main></body></html>"""
    return Response(html, mimetype="text/html")


# ============================================================
# HEALTH CHECK
# ============================================================

@app.get("/health")
def health():
    return jsonify(
        status="ok",
        service="PROJECT YT"
    )


# Initialize database when application starts.
init_db()


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", "5000")),
        debug=False
    )
