"""
CRM REST API — FastAPI endpoints
==================================
"""

import os
import re
import json
import logging
import asyncio
import threading
import time
import secrets
import unicodedata
import io
import base64
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Optional

from fastapi import FastAPI, Query, HTTPException, Request, Depends, Header, UploadFile, File, Form
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse, Response

from dotenv import load_dotenv

load_dotenv()

# 2FA
try:
    import pyotp
    import qrcode
    HAS_2FA = True
except ImportError:
    HAS_2FA = False

# External API v1
from external_api import router as external_api_router, init_api_tables

# Base URL for external access (Cloudflare Tunnel, ngrok, etc.)
# Set via .env or environment: BASE_URL=https://hermes.example.com
BASE_URL = os.getenv("BASE_URL", "").rstrip("/")

from database import init_db, get_db
from models import Contact, Company, Deal, Activity, EmailSyncLog, PIPELINE_STAGES, User

logger = logging.getLogger(__name__)

app = FastAPI(title="Hermes CRM", version="1.0.0")

# Include external API v1 router
app.include_router(external_api_router)

# ─── CORS: restrict methods & headers ────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("CORS_ORIGINS", "http://localhost:8766").split(","),
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "Accept", "X-API-Key"],
)

# ─── Security headers middleware ──────────────────────────────
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://cdn.tailwindcss.com; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
        "font-src 'self' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
        "img-src 'self' data:; "
        "connect-src 'self'"
    )
    return response

# ─── Request logging middleware ───────────────────────────────
@app.middleware("http")
async def log_requests(request: Request, call_next):
    start = time.time()
    response = await call_next(request)
    duration = round((time.time() - start) * 1000, 1)
    logger.info(
        "%s %s %s %sms",
        request.method, request.url.path, response.status_code, duration
    )
    return response

# Serve static files
BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(BASE_DIR, "static")
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

# Sync state (protected by asyncio lock)
_sync_lock = asyncio.Lock()
_sync_state = {
    "running": False,
    "progress": "",
    "last_result": None,
}

# ─── General rate limiting ────────────────────────────────────
_rate_limits = defaultdict(list)      # "endpoint:IP" -> [timestamps]
RATE_LIMIT_DEFAULT = 60               # requests per window
RATE_LIMIT_WINDOW  = 60               # seconds
LOGIN_RATE_LIMIT = 5                  # max login attempts
LOGIN_RATE_WINDOW = 300               # 5 minutes

# ─── Token blacklist — persisted in SQLite ────────────────────
_token_blacklist_cache = set()         # in-memory cache, loaded at startup

def _load_token_blacklist():
    """Load non-expired blacklisted tokens from DB."""
    try:
        with get_db() as conn:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS token_blacklist ("
                "  token TEXT PRIMARY KEY, "
                "  blacklisted_at TEXT DEFAULT (datetime('now')), "
                "  expires_at TEXT"
                ")"
            )
            # Cleanup expired tokens
            conn.execute("DELETE FROM token_blacklist WHERE expires_at < datetime('now')")
            rows = conn.execute("SELECT token FROM token_blacklist").fetchall()
            _token_blacklist_cache.update(r["token"] for r in rows)
    except Exception:
        logger.warning("Could not load token blacklist from DB")

def _blacklist_token(token: str, expires_hours: int = 25):
    """Add token to persistent blacklist."""
    _token_blacklist_cache.add(token)
    try:
        with get_db() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO token_blacklist (token, expires_at) "
                "VALUES (?, datetime('now', '+' || ? || ' hours'))",
                (token, expires_hours)
            )
    except Exception:
        logger.warning("Could not persist token to blacklist DB")


# ─── Helper ──────────────────────────────────────────────────

def _ok(data=None, total=None):
    """Standard success response."""
    resp = {"success": True, "data": data}
    if total is not None:
        resp["total"] = total
    return resp


def _err(message, status_code=400):
    # Don't expose internal errors to client
    if status_code == 500:
        raise HTTPException(status_code=500, detail="Internal server error")
    raise HTTPException(status_code=status_code, detail=message)


# ─── Input sanitisation ──────────────────────────────────────
_SAFE_CODE_RE = re.compile(r"[^a-zA-Z0-9\u00C0-\u024F\u0400-\u04FF _\-]")

def _sanitize_company_code(code: str) -> str:
    """Whitelist sanitise company code to prevent path traversal."""
    code = code.strip()
    # Remove any path traversal components
    code = code.replace("..", "").replace("/", "").replace("\\", "")
    code = _SAFE_CODE_RE.sub("_", code)
    return code[:100]  # Limit length

def _validate_length(value: str, field_name: str, max_len: int = 500):
    """Validate input string length."""
    if value and len(value) > max_len:
        _err(f"{field_name} too long (max {max_len} characters)")

def _validate_email(email: str) -> bool:
    """Basic email format validation."""
    return bool(re.match(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$", email))


def _get_ip(request: Request) -> str:
    """Extract client IP address safely."""
    return request.client.host if request.client else "unknown"


def _validate_numeric(val, field_name="value", allow_zero=True):
    """Validate numeric input is a finite non-negative number."""
    import math
    try:
        v = float(val)
    except (TypeError, ValueError):
        _err(f"Invalid {field_name}: must be a number")
    if math.isnan(v) or math.isinf(v):
        _err(f"Invalid {field_name}: must be a finite number")
    if not allow_zero and v == 0:
        _err(f"Invalid {field_name}: must be non-zero")
    if v < 0:
        _err(f"Invalid {field_name}: must be non-negative")
    return v


def check_rate_limit(ip: str, endpoint: str = "login", max_req: int = None, window: int = None):
    """Check and enforce rate limiting per endpoint + IP."""
    max_req = max_req or (LOGIN_RATE_LIMIT if endpoint == "login" else RATE_LIMIT_DEFAULT)
    window = window or (LOGIN_RATE_WINDOW if endpoint == "login" else RATE_LIMIT_WINDOW)
    key = f"{endpoint}:{ip}"
    now = time.time()
    _rate_limits[key] = [t for t in _rate_limits[key] if now - t < window]
    if len(_rate_limits[key]) >= max_req:
        _err(f"Too many requests. Try again later.", 429)
    _rate_limits[key].append(now)


def log_audit(user_id, action, entity_type=None, entity_id=None, details="", ip="", old_value=None, new_value=None, entity_name=""):
    """Log audit trail for actions."""
    try:
        with get_db() as conn:
            conn.execute(
                "INSERT INTO audit_log (user_id, action, entity_type, entity_id, details, ip_address, old_value, new_value, entity_name) VALUES (?,?,?,?,?,?,?,?,?)",
                (user_id, action, entity_type, entity_id, details, ip,
                 json.dumps(old_value) if old_value else "",
                 json.dumps(new_value) if new_value else "",
                 entity_name)
            )
    except Exception:
        logger.warning("Failed to write audit log: action=%s", action)


# ─── Startup ──────────────────────────────────────────────────
@app.on_event("startup")
async def startup_event():
    """Load persistent token blacklist on startup."""
    _load_token_blacklist()
    init_api_tables()  # Create external API tables if needed
    # Ensure lead_id and company_id columns exist on activities
    try:
        with get_db() as conn:
            cols = [r[1] for r in conn.execute("PRAGMA table_info(activities)").fetchall()]
            if "lead_id" not in cols:
                conn.execute("ALTER TABLE activities ADD COLUMN lead_id INTEGER DEFAULT NULL")
            if "company_id" not in cols:
                conn.execute("ALTER TABLE activities ADD COLUMN company_id INTEGER DEFAULT NULL")
    except Exception:
        pass
    # ─── Phase 3: Service Cloud tables ─────────────────────────
    try:
        with get_db() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS tickets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    subject TEXT NOT NULL DEFAULT '',
                    description TEXT DEFAULT '',
                    status TEXT DEFAULT 'open',
                    priority TEXT DEFAULT 'medium',
                    category TEXT DEFAULT 'general',
                    company_id INTEGER,
                    contact_id INTEGER,
                    assigned_to INTEGER,
                    created_by INTEGER,
                    sla_policy_id INTEGER,
                    first_response_at TEXT,
                    resolved_at TEXT,
                    closed_at TEXT,
                    sla_breach INTEGER DEFAULT 0,
                    tags TEXT DEFAULT '[]',
                    created_at TEXT DEFAULT (datetime('now')),
                    updated_at TEXT DEFAULT (datetime('now'))
                );
                CREATE TABLE IF NOT EXISTS ticket_comments (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ticket_id INTEGER NOT NULL,
                    user_id INTEGER,
                    content TEXT DEFAULT '',
                    is_internal INTEGER DEFAULT 0,
                    created_at TEXT DEFAULT (datetime('now'))
                );
                CREATE TABLE IF NOT EXISTS sla_policies (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL DEFAULT '',
                    priority TEXT DEFAULT 'medium',
                    first_response_hours REAL DEFAULT 4,
                    resolution_hours REAL DEFAULT 24,
                    is_active INTEGER DEFAULT 1,
                    created_at TEXT DEFAULT (datetime('now'))
                );
                CREATE TABLE IF NOT EXISTS kb_articles (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title TEXT NOT NULL DEFAULT '',
                    content TEXT DEFAULT '',
                    category TEXT DEFAULT 'general',
                    tags TEXT DEFAULT '[]',
                    status TEXT DEFAULT 'draft',
                    views INTEGER DEFAULT 0,
                    helpful_yes INTEGER DEFAULT 0,
                    helpful_no INTEGER DEFAULT 0,
                    created_by INTEGER,
                    created_at TEXT DEFAULT (datetime('now')),
                    updated_at TEXT DEFAULT (datetime('now'))
                );
            """)
            # Seed default SLA policies if empty
            existing = conn.execute("SELECT COUNT(*) FROM sla_policies").fetchone()[0]
            if existing == 0:
                conn.executescript("""
                    INSERT INTO sla_policies (name, priority, first_response_hours, resolution_hours) VALUES ('Critical SLA', 'critical', 1, 4);
                    INSERT INTO sla_policies (name, priority, first_response_hours, resolution_hours) VALUES ('High SLA', 'high', 2, 8);
                    INSERT INTO sla_policies (name, priority, first_response_hours, resolution_hours) VALUES ('Medium SLA', 'medium', 4, 24);
                    INSERT INTO sla_policies (name, priority, first_response_hours, resolution_hours) VALUES ('Low SLA', 'low', 8, 48);
                """)
    except Exception as e:
        logger.warning("Phase 3 migration: %s", e)
    # ─── Phase 4: Marketing Cloud tables ──────────────────────────
    try:
        with get_db() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS email_templates (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL DEFAULT '',
                    subject TEXT NOT NULL DEFAULT '',
                    body_html TEXT DEFAULT '',
                    category TEXT DEFAULT 'general',
                    lang TEXT DEFAULT 'en',
                    created_by INTEGER,
                    is_active INTEGER DEFAULT 1,
                    created_at TEXT DEFAULT (datetime('now')),
                    updated_at TEXT DEFAULT (datetime('now'))
                );
                CREATE TABLE IF NOT EXISTS campaigns (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL DEFAULT '',
                    description TEXT DEFAULT '',
                    type TEXT DEFAULT 'email',
                    status TEXT DEFAULT 'draft',
                    template_id INTEGER,
                    target_type TEXT DEFAULT 'all',
                    target_filter TEXT DEFAULT '{}',
                    scheduled_at TEXT,
                    sent_at TEXT,
                    total_recipients INTEGER DEFAULT 0,
                    sent_count INTEGER DEFAULT 0,
                    open_count INTEGER DEFAULT 0,
                    click_count INTEGER DEFAULT 0,
                    created_by INTEGER,
                    created_at TEXT DEFAULT (datetime('now')),
                    updated_at TEXT DEFAULT (datetime('now'))
                );
                CREATE TABLE IF NOT EXISTS campaign_recipients (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    campaign_id INTEGER NOT NULL,
                    recipient_type TEXT DEFAULT 'contact',
                    recipient_id INTEGER,
                    email TEXT,
                    status TEXT DEFAULT 'pending',
                    sent_at TEXT,
                    opened_at TEXT,
                    clicked_at TEXT
                );
                CREATE TABLE IF NOT EXISTS web_forms (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL DEFAULT '',
                    description TEXT DEFAULT '',
                    fields_config TEXT DEFAULT '[]',
                    redirect_url TEXT DEFAULT '',
                    is_active INTEGER DEFAULT 1,
                    form_token TEXT UNIQUE NOT NULL,
                    lead_source TEXT DEFAULT 'web_form',
                    assign_to INTEGER,
                    created_by INTEGER,
                    created_at TEXT DEFAULT (datetime('now'))
                );
            """)
    except Exception as e:
        logger.warning("Phase 4 migration: %s", e)
    logger.info("Token blacklist loaded (%d tokens)", len(_token_blacklist_cache))


# ─── Auth Dependencies ────────────────────────────────────────

async def get_current_user(authorization: str = Header(None)):
    """Get current user from Authorization header."""
    if not authorization or not authorization.startswith("Bearer "):
        return None
    token = authorization.replace("Bearer ", "")
    if token in _token_blacklist_cache:
        return None
    payload = User.verify_token(token)
    if not payload:
        return None
    return payload


async def require_auth(authorization: str = Header(None)):
    """Require authentication."""
    user = await get_current_user(authorization)
    if not user:
        _err("Unauthorized", 401)
    return user


async def require_admin(authorization: str = Header(None)):
    """Require admin role."""
    payload = await require_auth(authorization)
    # Check role from DB to ensure it's current
    user = User.get(payload["user_id"])
    if not user or user.get("role") != "admin":
        _err("Admin access required", 403)
    return payload


def check_permission(module: str, action: str):
    """Create a dependency that checks user permission for module+action."""
    async def _checker(authorization: str = Header(None)):
        payload = await require_auth(authorization)
        user_id = payload["user_id"]
        user = User.get(user_id)
        if not user:
            _err("User not found", 404)
        # Admin bypasses all checks
        if user.get("role") == "admin":
            return payload
        # Check role permissions
        role_id = user.get("role_id")
        if role_id:
            with get_db() as conn:
                role = conn.execute("SELECT permissions FROM roles WHERE id=?", (role_id,)).fetchone()
                if role:
                    perms = json.loads(role[0] or '{}')
                    module_perms = perms.get(module, "")
                    action_map = {"read": "r", "write": "c", "update": "u", "delete": "d", "create": "c"}
                    needed = action_map.get(action, action[0] if action else "r")
                    if needed in module_perms:
                        return payload
        _err(f"Permission denied: {module}/{action}", 403)
    return _checker


# ─── Auth Endpoints ──────────────────────────────────────────

@app.post("/api/auth/login")
async def login(request: Request):
    """Login endpoint with optional 2FA support."""
    client_ip = _get_ip(request)
    check_rate_limit(client_ip, "login")

    data = await request.json()
    # Accept email or username for login
    login_id = data.get("email") or data.get("username", "")
    _validate_length(login_id, "login_id", 200)
    password = data.get("password", "")
    totp_code = data.get("totp_code", "")

    if not login_id or not password:
        _err("Email/username and password are required")
    user = User.authenticate(login_id, password)
    if not user:
        log_audit(None, "login_failed", entity_type="auth", details=f"login_id={login_id}", ip=client_ip)
        _err("Invalid credentials", 401)

    # Check 2FA
    if str(user.get("totp_enabled", "0")) not in ("0", "", "None", "False") and HAS_2FA:
        if not totp_code:
            # Return requires_2fa flag — frontend shows code input
            return _ok({"requires_2fa": True, "user_id": user["id"]})
        # Verify TOTP code
        with get_db() as conn:
            row = conn.execute("SELECT totp_secret, backup_codes FROM users WHERE id = ?", (user["id"],)).fetchone()
            if row and row["totp_secret"]:
                totp = pyotp.TOTP(row["totp_secret"])
                if totp.verify(totp_code, valid_window=1):
                    pass  # Code valid
                else:
                    # Check backup codes
                    backup_codes = json.loads(row["backup_codes"] or "[]")
                    if totp_code in backup_codes:
                        backup_codes.remove(totp_code)
                        conn.execute("UPDATE users SET backup_codes = ? WHERE id = ?",
                                     (json.dumps(backup_codes), user["id"]))
                    else:
                        log_audit(user["id"], "2fa_failed", entity_type="auth", details="Invalid 2FA code", ip=client_ip)
                        _err("Invalid 2FA code", 401)

    token = User.generate_token(user)
    log_audit(user["id"], "login_success", entity_type="auth", details=user.get("email",""), ip=client_ip)
    return _ok({"token": token, "user": user})


@app.get("/api/auth/me")
async def get_me(user=Depends(require_auth)):
    """Get current user info."""
    return _ok(User.get(user["user_id"]))


@app.post("/api/auth/change-password")
async def change_password(request: Request, user=Depends(require_auth)):
    """User changes their own password."""
    data = await request.json()
    old_pw = data.get("old_password", "")
    new_pw = data.get("new_password", "")
    if not old_pw or not new_pw:
        _err("Both old and new password required")
    if len(new_pw) < 10:
        _err("Password must be at least 10 characters")
    if not re.search(r"[A-Z]", new_pw) or not re.search(r"[a-z]", new_pw) or not re.search(r"[0-9]", new_pw):
        _err("Password must contain uppercase, lowercase, and a digit")
    if not User.change_password(user["user_id"], old_pw, new_pw):
        _err("Current password is incorrect", 401)
    log_audit(user["user_id"], "change_password", entity_type="auth", details="Password changed")
    return _ok({"message": "Password changed successfully"})


@app.post("/api/auth/logout")
async def logout_endpoint(request: Request, user=Depends(require_auth), authorization: str = Header(None)):
    """Logout endpoint (persistent token blacklist)."""
    if authorization and authorization.startswith("Bearer "):
        token = authorization.replace("Bearer ", "")
        _blacklist_token(token)
    log_audit(user["user_id"], "logout", entity_type="auth", details="User logged out", ip=_get_ip(request))
    return _ok({"message": "Logged out"})


# ─── 2FA Management API ──────────────────────────────────────

@app.post("/api/auth/2fa/setup")
async def setup_2fa(user=Depends(require_auth)):
    """Generate TOTP secret and QR code for 2FA setup."""
    if not HAS_2FA:
        _err("2FA not available — pyotp/qrcode not installed", 501)
    uid = user["user_id"]
    with get_db() as conn:
        row = conn.execute("SELECT totp_enabled, email FROM users WHERE id = ?", (uid,)).fetchone()
        if row and str(row["totp_enabled"]) not in ("0", "", "None", "False"):
            _err("2FA is already enabled. Disable first to re-setup.")
        secret = pyotp.random_base32()
        conn.execute("UPDATE users SET totp_secret = ? WHERE id = ?", (secret, uid))
        email = row["email"] if row else "user"
        totp = pyotp.TOTP(secret)
        uri = totp.provisioning_uri(name=email, issuer_name="Hermes CRM")
        # Generate QR code as base64
        img = qrcode.make(uri)
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        qr_b64 = base64.b64encode(buf.getvalue()).decode()
    return _ok({"secret": secret, "qr_code": f"data:image/png;base64,{qr_b64}", "uri": uri})


@app.post("/api/auth/2fa/verify")
async def verify_2fa_setup(request: Request, user=Depends(require_auth)):
    """Verify TOTP code and enable 2FA. Also generates backup codes."""
    if not HAS_2FA:
        _err("2FA not available", 501)
    data = await request.json()
    code = data.get("code", "")
    if not code:
        _err("TOTP code is required")
    uid = user["user_id"]
    with get_db() as conn:
        row = conn.execute("SELECT totp_secret FROM users WHERE id = ?", (uid,)).fetchone()
        if not row or not row["totp_secret"]:
            _err("Call /api/auth/2fa/setup first")
        totp = pyotp.TOTP(row["totp_secret"])
        if not totp.verify(code, valid_window=1):
            _err("Invalid TOTP code. Check your authenticator app.", 401)
        # Generate 10 backup codes
        backup_codes = [secrets.token_hex(4).upper() for _ in range(10)]
        conn.execute("UPDATE users SET totp_enabled = 1, backup_codes = ? WHERE id = ?",
                     (json.dumps(backup_codes), uid))
        log_audit(uid, "2fa_enabled", entity_type="auth", details="2FA enabled")
    return _ok({"message": "2FA enabled successfully", "backup_codes": backup_codes})


@app.post("/api/auth/2fa/disable")
async def disable_2fa(request: Request, user=Depends(require_auth)):
    """Disable 2FA. Requires password confirmation."""
    data = await request.json()
    password = data.get("password", "")
    if not password:
        _err("Password required to disable 2FA")
    uid = user["user_id"]
    # Verify password
    with get_db() as conn:
        row = conn.execute("SELECT password_hash FROM users WHERE id = ?", (uid,)).fetchone()
        if not row:
            _err("User not found", 404)
        import bcrypt as _bc
        if not _bc.checkpw(password.encode(), row["password_hash"].encode()):
            _err("Invalid password", 401)
        conn.execute("UPDATE users SET totp_enabled = 0, totp_secret = '', backup_codes = '[]' WHERE id = ?", (uid,))
        log_audit(uid, "2fa_disabled", entity_type="auth", details="2FA disabled")
    return _ok({"message": "2FA disabled"})


@app.get("/api/auth/2fa/status")
async def get_2fa_status(user=Depends(require_auth)):
    """Check if 2FA is enabled for current user."""
    uid = user["user_id"]
    with get_db() as conn:
        row = conn.execute("SELECT totp_enabled FROM users WHERE id = ?", (uid,)).fetchone()
        enabled = (str(row["totp_enabled"]) not in ("0", "", "None", "False")) if row else False
    return _ok({"enabled": enabled, "available": HAS_2FA})


# ─── Roles Management API ────────────────────────────────────

@app.get("/api/roles")
async def list_roles(user=Depends(require_auth)):
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM roles ORDER BY id").fetchall()
        cols = [d[0] for d in conn.execute("SELECT * FROM roles LIMIT 0").description]
        return _ok([dict(zip(cols, r)) for r in rows])

@app.get("/api/roles/{role_id}")
async def get_role(role_id: int, user=Depends(require_auth)):
    with get_db() as conn:
        row = conn.execute("SELECT * FROM roles WHERE id=?", (role_id,)).fetchone()
        if not row:
            _err("Role not found", 404)
        cols = [d[0] for d in conn.execute("SELECT * FROM roles LIMIT 0").description]
        return _ok(dict(zip(cols, row)))

@app.post("/api/roles")
async def create_role(request: Request, user=Depends(require_admin)):
    data = await request.json()
    name = data.get("name", "").strip()
    display_name = data.get("display_name", "").strip()
    if not name or not display_name:
        _err("name and display_name required")
    with get_db() as conn:
        try:
            conn.execute(
                "INSERT INTO roles (name, display_name, display_name_az, display_name_ru, description, permissions) VALUES (?,?,?,?,?,?)",
                (name, display_name, data.get("display_name_az",""), data.get("display_name_ru",""),
                 data.get("description",""), json.dumps(data.get("permissions",{})))
            )
            role_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        except Exception as e:
            _err(f"Role creation failed: {e}")
    log_audit(user["user_id"], "create_role", "role", role_id, entity_name=name)
    return _ok({"id": role_id, "name": name})

@app.put("/api/roles/{role_id}")
async def update_role(role_id: int, request: Request, user=Depends(require_admin)):
    data = await request.json()
    with get_db() as conn:
        old = conn.execute("SELECT * FROM roles WHERE id=?", (role_id,)).fetchone()
        if not old:
            _err("Role not found", 404)
        cols = [d[0] for d in conn.execute("SELECT * FROM roles LIMIT 0").description]
        old_dict = dict(zip(cols, old))
        if old_dict.get("is_system") and data.get("name") and data["name"] != old_dict["name"]:
            _err("Cannot rename system roles")
        updates = []
        vals = []
        for f in ["name","display_name","display_name_az","display_name_ru","description","permissions"]:
            if f in data:
                updates.append(f"{f}=?")
                vals.append(json.dumps(data[f]) if f == "permissions" else data[f])
        if updates:
            vals.append(role_id)
            conn.execute(f"UPDATE roles SET {','.join(updates)} WHERE id=?", vals)
    log_audit(user["user_id"], "update_role", "role", role_id, old_value=old_dict, new_value=data)
    return _ok({"message": "Role updated"})

@app.delete("/api/roles/{role_id}")
async def delete_role(role_id: int, user=Depends(require_admin)):
    with get_db() as conn:
        role = conn.execute("SELECT name, is_system FROM roles WHERE id=?", (role_id,)).fetchone()
        if not role:
            _err("Role not found", 404)
        if role[1]:
            _err("Cannot delete system roles")
        conn.execute("UPDATE users SET role_id=NULL WHERE role_id=?", (role_id,))
        conn.execute("DELETE FROM roles WHERE id=?", (role_id,))
    log_audit(user["user_id"], "delete_role", "role", role_id, entity_name=role[0])
    return _ok({"message": "Role deleted"})

@app.put("/api/users/{user_id}/role")
async def assign_user_role(user_id: int, request: Request, user=Depends(require_admin)):
    data = await request.json()
    role_id = data.get("role_id")
    with get_db() as conn:
        target = conn.execute("SELECT id, username, role_id FROM users WHERE id=?", (user_id,)).fetchone()
        if not target:
            _err("User not found", 404)
        old_role_id = target[2]
        conn.execute("UPDATE users SET role_id=? WHERE id=?", (role_id, user_id))
        # Also update legacy role field
        role_row = conn.execute("SELECT name FROM roles WHERE id=?", (role_id,)).fetchone()
        if role_row:
            legacy_map = {"admin":"admin","sales_manager":"manager","sales_rep":"manager","marketing":"manager","support_agent":"manager","viewer":"viewer"}
            legacy = legacy_map.get(role_row[0], "manager")
            conn.execute("UPDATE users SET role=? WHERE id=?", (legacy, user_id))
    log_audit(user["user_id"], "assign_role", "user", user_id, old_value={"role_id": old_role_id}, new_value={"role_id": role_id})
    return _ok({"message": "Role assigned"})


# ─── User Management Endpoints ───────────────────────────────

@app.get("/api/users")
async def list_users(user=Depends(require_auth)):
    """List all users."""
    users = User.get_all()
    return _ok(users)


@app.post("/api/users")
async def create_user(request: Request, user=Depends(require_admin)):
    """Create new user (admin only)."""
    data = await request.json()
    # Validate before creating
    email = (data.get("email") or "").strip().lower()
    password = data.get("password", "")
    if not email:
        _err("Email is required")
    if not password or len(password) < 6:
        _err("Password must be at least 6 characters")
    # Check if email already exists
    with get_db() as conn:
        existing = conn.execute("SELECT id FROM users WHERE email=? OR username=?",
                                [email, email.split("@")[0]]).fetchone()
        if existing:
            _err("User with this email already exists")
    new_user = User.create(data)
    if not new_user:
        _err("Failed to create user")
    return _ok(new_user)


@app.get("/api/users/{user_id}")
async def get_user(user_id: int, user=Depends(require_auth)):
    """Get user by ID."""
    u = User.get(user_id)
    if not u:
        _err("User not found", 404)
    return _ok(u)


@app.put("/api/users/{user_id}")
async def update_user(user_id: int, request: Request, user=Depends(require_admin)):
    """Update user (admin only)."""
    data = await request.json()
    u = User.update(user_id, data)
    if not u:
        _err("User not found", 404)
    return _ok(u)


@app.put("/api/users/me/profile")
async def update_my_profile(request: Request, user=Depends(require_auth)):
    """Update own profile (any authenticated user)."""
    data = await request.json()
    allowed = {k: v for k, v in data.items() if k in ('first_name', 'last_name', 'full_name')}
    if not allowed:
        _err("No valid fields to update", 400)
    u = User.update(user["id"], allowed)
    if not u:
        _err("User not found", 404)
    return _ok(u)


@app.delete("/api/users/{user_id}")
async def delete_user(user_id: int, user=Depends(require_admin)):
    """Delete user (admin only)."""
    User.delete(user_id)
    return _ok({"deleted": True})


@app.get("/api/users/{user_id}/stats")
async def user_stats(user_id: int, user=Depends(require_auth)):
    """Get user statistics."""
    stats = User.get_stats(user_id)
    return _ok(stats)


# ─── Pipeline Stages API ─────────────────────────────────────

@app.get("/api/pipeline-stages")
async def list_pipeline_stages(user=Depends(require_auth)):
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM pipeline_stages WHERE is_active=1 ORDER BY sort_order").fetchall()
        cols = [d[0] for d in conn.execute("SELECT * FROM pipeline_stages LIMIT 0").description]
        return _ok([dict(zip(cols, r)) for r in rows])

@app.post("/api/pipeline-stages")
async def create_pipeline_stage(request: Request, user=Depends(require_admin)):
    data = await request.json()
    name = data.get("name","").strip().upper()
    display_name = data.get("display_name","").strip()
    if not name or not display_name:
        _err("name and display_name required")
    with get_db() as conn:
        max_order = conn.execute("SELECT COALESCE(MAX(sort_order),0) FROM pipeline_stages").fetchone()[0]
        conn.execute(
            "INSERT INTO pipeline_stages (name,display_name,display_name_az,display_name_ru,color,probability,sort_order,is_won,is_lost) VALUES (?,?,?,?,?,?,?,?,?)",
            (name, display_name, data.get("display_name_az",""), data.get("display_name_ru",""),
             data.get("color","#6366f1"), data.get("probability",0), max_order+1,
             1 if data.get("is_won") else 0, 1 if data.get("is_lost") else 0)
        )
        stage_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    log_audit(user["user_id"], "create_pipeline_stage", "pipeline_stage", stage_id, entity_name=name)
    return _ok({"id": stage_id})

@app.put("/api/pipeline-stages/{stage_id}")
async def update_pipeline_stage(stage_id: int, request: Request, user=Depends(require_admin)):
    data = await request.json()
    with get_db() as conn:
        old = conn.execute("SELECT * FROM pipeline_stages WHERE id=?", (stage_id,)).fetchone()
        if not old:
            _err("Stage not found", 404)
        updates, vals = [], []
        for f in ["name","display_name","display_name_az","display_name_ru","color","probability","sort_order","is_won","is_lost","is_active"]:
            if f in data:
                updates.append(f"{f}=?")
                vals.append(data[f])
        if updates:
            vals.append(stage_id)
            conn.execute(f"UPDATE pipeline_stages SET {','.join(updates)} WHERE id=?", vals)
    return _ok({"message": "Stage updated"})

@app.delete("/api/pipeline-stages/{stage_id}")
async def delete_pipeline_stage(stage_id: int, user=Depends(require_admin)):
    with get_db() as conn:
        conn.execute("UPDATE pipeline_stages SET is_active=0 WHERE id=?", (stage_id,))
    return _ok({"message": "Stage deactivated"})

@app.put("/api/pipeline-stages/reorder")
async def reorder_pipeline_stages(request: Request, user=Depends(require_admin)):
    data = await request.json()
    order = data.get("order", [])  # list of stage IDs in desired order
    with get_db() as conn:
        for i, stage_id in enumerate(order):
            conn.execute("UPDATE pipeline_stages SET sort_order=? WHERE id=?", (i+1, stage_id))
    return _ok({"message": "Stages reordered"})


# ─── Dashboard ───────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def dashboard():
    """Serve the CRM dashboard."""
    index_path = os.path.join(STATIC_DIR, "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    return HTMLResponse("<h1>Hermes CRM</h1><p>Dashboard loading...</p>")


# ─── Contacts ────────────────────────────────────────────────

@app.get("/api/contacts")
async def list_contacts(
    q: str = Query("", description="Search query"),
    company_id: Optional[int] = None,
    source: Optional[str] = None,
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    user=Depends(require_auth),
):
    contacts = Contact.search(
        query=q, company_id=company_id, source=source,
        limit=limit, offset=offset,
    )
    return _ok(contacts, total=Contact.count())


# ─── Silent Contacts (must be before {contact_id} route) ───
@app.get("/api/contacts/silent")
async def silent_contacts(
    days: int = Query(30, ge=1, le=365),
    limit: int = Query(50, ge=1, le=200),
    user=Depends(require_auth),
):
    """Contacts with no email activity for N days, sorted by importance."""
    with get_db() as conn:
        cutoff = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")
        rows = conn.execute(
            "SELECT id, email, name, company_name, role, phone, email_count, last_contact "
            "FROM contacts "
            "WHERE last_contact IS NOT NULL AND last_contact != '' AND last_contact < ? "
            "ORDER BY email_count DESC "
            "LIMIT ?",
            (cutoff, limit)
        ).fetchall()
        total = conn.execute(
            "SELECT COUNT(*) FROM contacts "
            "WHERE last_contact IS NOT NULL AND last_contact != '' AND last_contact < ?",
            (cutoff,)
        ).fetchone()[0]
        return _ok([dict(r) for r in rows], total=total)


@app.get("/api/contacts/{contact_id}")
async def get_contact(contact_id: int, user=Depends(require_auth)):
    contact = Contact.get(contact_id)
    if not contact:
        _err("Contact not found", 404)
    # Include activities
    activities = Activity.get_for_contact(contact_id, limit=20)
    contact["activities"] = activities
    return _ok(contact)


@app.post("/api/contacts")
async def create_contact(request: Request, user=Depends(require_auth)):
    data = await request.json()
    email = (data.get("email") or "").strip()
    if not email:
        _err("Email is required")
    if not _validate_email(email):
        _err("Invalid email format")
    _validate_length(data.get("name", ""), "Name", 200)
    _validate_length(data.get("phone", ""), "Phone", 50)
    _validate_length(data.get("notes", ""), "Notes", 5000)
    data["email"] = email
    contact = Contact.create(data)
    if not contact:
        _err("Failed to create contact")
    log_audit(user["user_id"], "create_contact", "contact", contact.get("id"), ip=_get_ip(request))
    return _ok(contact)


@app.put("/api/contacts/{contact_id}")
async def update_contact(contact_id: int, request: Request, user=Depends(require_auth)):
    data = await request.json()
    contact = Contact.update(contact_id, data)
    if not contact:
        _err("Contact not found", 404)
    log_audit(user["user_id"], "update_contact", "contact", contact_id, ip=_get_ip(request))
    return _ok(contact)


@app.delete("/api/contacts/bulk/no-phone")
async def delete_contacts_without_phone(request: Request, user=Depends(require_admin)):
    """Delete all contacts that have no phone number."""
    with get_db() as conn:
        count = conn.execute(
            "SELECT COUNT(*) FROM contacts WHERE phone IS NULL OR phone = '' OR phone = 'None'"
        ).fetchone()[0]
        if count == 0:
            return _ok({"deleted": 0, "message": "No contacts without phone found"})
        conn.execute("DELETE FROM contacts WHERE phone IS NULL OR TRIM(phone) = '' OR phone = 'None'")
        try:
            log_audit(user["user_id"], "bulk_delete_contacts_no_phone", "contact", 0,
                      details=f"Deleted {count} contacts without phone", ip=_get_ip(request))
        except Exception:
            pass
        return _ok({"deleted": count})


@app.delete("/api/contacts/{contact_id}")
async def delete_contact(contact_id: int, request: Request, user=Depends(require_admin)):
    Contact.delete(contact_id)
    log_audit(user["user_id"], "delete_contact", "contact", contact_id, ip=_get_ip(request))
    return _ok({"deleted": True})


# ─── Companies ───────────────────────────────────────────────

@app.get("/api/companies")
async def list_companies(
    q: str = Query("", description="Search query"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    user=Depends(require_auth),
):
    companies = Company.search(query=q, limit=limit, offset=offset)
    # Annotate each company with has_contracts flag
    with get_db() as conn:
        for c in companies:
            name = c.get("name", "")
            cnt = conn.execute(
                "SELECT COUNT(*) FROM contracts WHERE counterparty LIKE ?",
                (f"%{name}%",)
            ).fetchone()[0]
            c["has_contracts"] = cnt > 0
            c["contracts_count"] = cnt
    return _ok(companies, total=Company.count())


@app.get("/api/companies/{company_id}")
async def get_company(company_id: int, user=Depends(require_auth)):
    company = Company.get(company_id)
    if not company:
        _err("Company not found", 404)
    # Include contacts
    contacts = Contact.search(company_id=company_id, limit=100)
    company["contacts"] = contacts
    return _ok(company)


@app.post("/api/companies")
async def create_company(request: Request, user=Depends(require_auth)):
    data = await request.json()
    if not data.get("name"):
        _err("Name is required")
    company = Company.create(data)
    if not company:
        _err("Failed to create company (possible duplicate)")
    log_audit(user["user_id"], "create_company", "company", company.get("id"), ip=_get_ip(request))
    return _ok(company)


@app.put("/api/companies/{company_id}")
async def update_company(company_id: int, request: Request, user=Depends(require_auth)):
    data = await request.json()
    company = Company.update(company_id, data)
    if not company:
        _err("Company not found", 404)
    log_audit(user["user_id"], "update_company", "company", company_id, ip=_get_ip(request))
    return _ok(company)


@app.put("/api/companies/{company_id}/user-count")
async def update_company_user_count(company_id: int, request: Request, user=Depends(require_auth)):
    """Update user_count for cost model (manually set by admin)."""
    data = await request.json()
    user_count = int(data.get("user_count", 0))
    with get_db() as conn:
        conn.execute("UPDATE companies SET user_count=? WHERE id=?", [user_count, company_id])
    return _ok({"id": company_id, "user_count": user_count})


@app.put("/api/companies/{company_id}/group")
async def update_company_group(company_id: int, request: Request, user=Depends(require_auth)):
    """Update group_name for a company."""
    data = await request.json()
    group_name = data.get("group_name", "").strip()
    with get_db() as conn:
        conn.execute("UPDATE companies SET group_name=? WHERE id=?", [group_name, company_id])
    return _ok({"id": company_id, "group_name": group_name})


@app.put("/api/companies/{company_id}/deactivate")
async def deactivate_company(company_id: int, request: Request, user=Depends(require_auth)):
    """Deactivate a company (cancelled contract / closed). Sets category to 'inactive'."""
    data = await request.json()
    reason = data.get("reason", "").strip()
    with get_db() as conn:
        comp = conn.execute("SELECT name, category FROM companies WHERE id=?", [company_id]).fetchone()
        if not comp:
            _err("Company not found", 404)
        prev_category = comp["category"]
        conn.execute(
            "UPDATE companies SET category='inactive', notes=COALESCE(notes,'') || ? WHERE id=?",
            [f"\n[DEACTIVATED {prev_category}] {reason}" if reason else f"\n[DEACTIVATED {prev_category}]", company_id]
        )
    log_audit(user["user_id"], "deactivate_company", "company", company_id,
              ip=_get_ip(request))
    return _ok({"id": company_id, "status": "inactive", "previous_category": prev_category})


@app.put("/api/companies/{company_id}/reactivate")
async def reactivate_company(company_id: int, request: Request, user=Depends(require_auth)):
    """Reactivate an inactive company back to 'client'."""
    data = await request.json()
    target_category = data.get("category", "client")
    if target_category not in ("client", "prospect"):
        target_category = "client"
    with get_db() as conn:
        conn.execute("UPDATE companies SET category=? WHERE id=? AND category='inactive'",
                     [target_category, company_id])
    return _ok({"id": company_id, "category": target_category})


@app.get("/api/company-groups")
async def list_company_groups(user=Depends(require_auth)):
    """Get all unique company group names from DB + pricing_data.json."""
    groups = set()
    with get_db() as conn:
        for row in conn.execute("SELECT DISTINCT group_name FROM companies WHERE group_name != '' AND group_name IS NOT NULL").fetchall():
            groups.add(row[0])
    # Also merge from pricing_data.json
    pricing_path = os.path.join(STATIC_DIR, "pricing_data.json")
    if os.path.exists(pricing_path):
        with open(pricing_path, encoding="utf-8") as f:
            pd = json.load(f)
        for v in pd.values():
            g = v.get("group", "")
            if g:
                groups.add(g)
    return _ok(sorted(groups))


@app.post("/api/company-groups")
async def create_company_group(request: Request, user=Depends(require_auth)):
    """Create a new group (just validates and returns — groups are stored on companies)."""
    data = await request.json()
    name = data.get("name", "").strip()
    if not name:
        _err("Group name is required", 400)
    return _ok({"name": name, "message": f"Group '{name}' created"})


# ─── Leads ─────────────────────────────────────────────────

LEAD_STATUSES = {"new", "contacted", "qualified", "unqualified", "converted"}
LEAD_SOURCES = {"website", "linkedin", "referral", "cold_call", "exhibition", "partner", "other"}
LEAD_PRIORITIES = {"low", "medium", "high"}

@app.get("/api/leads")
async def list_leads(
    status: Optional[str] = None,
    source: Optional[str] = None,
    q: str = Query("", description="Search query"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    user=Depends(require_auth),
):
    """List leads with optional filtering."""
    with get_db() as conn:
        where = ["1=1"]
        params = []
        if status:
            where.append("l.status=?")
            params.append(status)
        if source:
            where.append("l.source=?")
            params.append(source)
        if q:
            where.append("(l.company_name LIKE ? OR l.contact_name LIKE ? OR l.email LIKE ?)")
            like = f"%{q}%"
            params.extend([like, like, like])
        total = conn.execute(
            f"SELECT COUNT(*) FROM leads l WHERE {' AND '.join(where)}", params
        ).fetchone()[0]
        rows = conn.execute(
            f"""SELECT l.*, u.full_name as assigned_name
                FROM leads l
                LEFT JOIN users u ON u.id = l.assigned_to
                WHERE {' AND '.join(where)}
                ORDER BY
                    CASE l.status WHEN 'new' THEN 0 WHEN 'contacted' THEN 1
                        WHEN 'qualified' THEN 2 WHEN 'unqualified' THEN 3 ELSE 4 END,
                    CASE l.priority WHEN 'high' THEN 0 WHEN 'medium' THEN 1 ELSE 2 END,
                    l.created_at DESC
                LIMIT ? OFFSET ?""",
            params + [limit, offset]
        ).fetchall()
        return _ok({"leads": [dict(r) for r in rows], "total": total})


@app.get("/api/leads/stats")
async def leads_stats(user=Depends(require_auth)):
    """Lead statistics for dashboard (includes prospect companies as new leads)."""
    with get_db() as conn:
        stats = {}
        for s in LEAD_STATUSES:
            stats[s] = conn.execute(
                "SELECT COUNT(*) FROM leads WHERE status=?", [s]
            ).fetchone()[0]
        # Also count prospect companies as new leads, clients as converted, inactive as unqualified
        prospect_count = conn.execute(
            "SELECT COUNT(*) FROM companies WHERE category='prospect'"
        ).fetchone()[0]
        client_count = conn.execute(
            "SELECT COUNT(*) FROM companies WHERE category='client'"
        ).fetchone()[0]
        inactive_count = conn.execute(
            "SELECT COUNT(*) FROM companies WHERE category='inactive'"
        ).fetchone()[0]
        stats["new"] = stats.get("new", 0) + prospect_count
        stats["converted"] = stats.get("converted", 0) + client_count
        stats["unqualified"] = stats.get("unqualified", 0) + inactive_count
        stats["total"] = sum(v for k, v in stats.items() if k != "estimated_pipeline")
        stats["estimated_pipeline"] = conn.execute(
            "SELECT COALESCE(SUM(estimated_value), 0) FROM leads WHERE status IN ('new','contacted','qualified')"
        ).fetchone()[0]
        return _ok(stats)


@app.get("/api/leads/{lead_id}")
async def get_lead(lead_id: int, user=Depends(require_auth)):
    """Get single lead with details."""
    with get_db() as conn:
        row = conn.execute(
            """SELECT l.*, u.full_name as assigned_name
               FROM leads l LEFT JOIN users u ON u.id = l.assigned_to
               WHERE l.id=?""", [lead_id]
        ).fetchone()
        if not row:
            _err("Lead not found", 404)
        return _ok(dict(row))


@app.post("/api/leads")
async def create_lead(request: Request, user=Depends(require_auth)):
    """Create a new lead."""
    data = await request.json()
    company_name = (data.get("company_name") or "").strip()
    if not company_name:
        _err("Company name is required", 400)

    status = data.get("status", "new")
    if status not in LEAD_STATUSES:
        _err(f"Invalid status: {status}", 400)
    source = data.get("source", "other")
    if source and source not in LEAD_SOURCES:
        _err(f"Invalid source: {source}", 400)
    priority = data.get("priority", "medium")
    if priority not in LEAD_PRIORITIES:
        _err(f"Invalid priority: {priority}", 400)

    with get_db() as conn:
        cur = conn.execute(
            """INSERT INTO leads
               (company_name, contact_name, email, phone, source, status, priority,
                estimated_value, estimated_users, industry, website, notes,
                assigned_to, created_by)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            [
                company_name,
                (data.get("contact_name") or "").strip(),
                (data.get("email") or "").strip(),
                (data.get("phone") or "").strip(),
                source,
                status,
                priority,
                _validate_numeric(data.get("estimated_value", 0)),
                int(data.get("estimated_users", 0)),
                (data.get("industry") or "").strip(),
                (data.get("website") or "").strip(),
                (data.get("notes") or "").strip(),
                data.get("assigned_to"),
                user["user_id"],
            ]
        )
        lead_id = cur.lastrowid
        # Auto-assign if not manually assigned
        if not data.get("assigned_to"):
            auto_user = auto_assign_lead(conn, data)
            if auto_user:
                conn.execute("UPDATE leads SET assigned_to=? WHERE id=?", (auto_user, lead_id))
        log_audit(user["user_id"], "create_lead", "lead", lead_id, ip=_get_ip(request))
        return _ok({"id": lead_id, "message": "Lead created"})


@app.put("/api/leads/{lead_id}")
async def update_lead(lead_id: int, request: Request, user=Depends(require_auth)):
    """Update a lead."""
    data = await request.json()
    with get_db() as conn:
        existing = conn.execute("SELECT * FROM leads WHERE id=?", [lead_id]).fetchone()
        if not existing:
            _err("Lead not found", 404)
        if existing["status"] == "converted":
            _err("Cannot edit a converted lead", 400)

        status = data.get("status", existing["status"])
        if status not in LEAD_STATUSES:
            _err(f"Invalid status: {status}", 400)
        source = data.get("source", existing["source"])
        if source and source not in LEAD_SOURCES:
            _err(f"Invalid source: {source}", 400)
        priority = data.get("priority", existing["priority"])
        if priority not in LEAD_PRIORITIES:
            _err(f"Invalid priority: {priority}", 400)

        conn.execute(
            """UPDATE leads SET
               company_name=?, contact_name=?, email=?, phone=?, source=?, status=?,
               priority=?, estimated_value=?, estimated_users=?, industry=?, website=?,
               notes=?, assigned_to=?, updated_at=datetime('now')
               WHERE id=?""",
            [
                (data.get("company_name") or existing["company_name"]).strip(),
                (data.get("contact_name") if "contact_name" in data else existing["contact_name"] or "").strip(),
                (data.get("email") if "email" in data else existing["email"] or "").strip(),
                (data.get("phone") if "phone" in data else existing["phone"] or "").strip(),
                source, status, priority,
                _validate_numeric(data.get("estimated_value", existing["estimated_value"])),
                int(data.get("estimated_users", existing["estimated_users"] or 0)),
                (data.get("industry") if "industry" in data else existing["industry"] or "").strip(),
                (data.get("website") if "website" in data else existing["website"] or "").strip(),
                (data.get("notes") if "notes" in data else existing["notes"] or "").strip(),
                data.get("assigned_to", existing["assigned_to"]),
                lead_id,
            ]
        )
        log_audit(user["user_id"], "update_lead", "lead", lead_id, ip=_get_ip(request))
        return _ok({"id": lead_id, "message": "Lead updated"})


@app.delete("/api/leads/{lead_id}")
async def delete_lead(lead_id: int, request: Request, user=Depends(require_admin)):
    """Delete a lead (admin only)."""
    with get_db() as conn:
        existing = conn.execute("SELECT id FROM leads WHERE id=?", [lead_id]).fetchone()
        if not existing:
            _err("Lead not found", 404)
        conn.execute("DELETE FROM leads WHERE id=?", [lead_id])
        log_audit(user["user_id"], "delete_lead", "lead", lead_id, ip=_get_ip(request))
        return _ok({"message": "Lead deleted"})


@app.post("/api/leads/{lead_id}/convert")
async def convert_lead(lead_id: int, request: Request, user=Depends(require_auth)):
    """Convert a lead into Company + Contact + Deal."""
    with get_db() as conn:
        lead = conn.execute("SELECT * FROM leads WHERE id=?", [lead_id]).fetchone()
        if not lead:
            _err("Lead not found", 404)
        if lead["status"] == "converted":
            _err("Lead is already converted", 400)

        data = {}
        try:
            data = await request.json()
        except Exception:
            pass

        # 1. Create or find Company
        existing_company = conn.execute(
            "SELECT id FROM companies WHERE lower(name)=?",
            [lead["company_name"].lower()]
        ).fetchone()

        if existing_company:
            company_id = existing_company["id"]
        else:
            cur = conn.execute(
                """INSERT INTO companies (name, domain, industry, website, category, notes)
                   VALUES (?,?,?,?,?,?)""",
                [
                    lead["company_name"],
                    (lead["website"] or "").replace("https://","").replace("http://","").split("/")[0],
                    lead["industry"] or "",
                    lead["website"] or "",
                    "client",
                    f"Converted from lead #{lead_id}",
                ]
            )
            company_id = cur.lastrowid

        # 2. Create Contact (if contact_name or email provided)
        contact_id = None
        if lead["contact_name"] or lead["email"]:
            cur = conn.execute(
                """INSERT INTO contacts (name, email, phone, company_id, company_name, source, notes)
                   VALUES (?,?,?,?,?,?,?)""",
                [
                    lead["contact_name"] or "",
                    lead["email"] or "",
                    lead["phone"] or "",
                    company_id,
                    lead["company_name"],
                    lead["source"] or "lead",
                    f"Converted from lead #{lead_id}",
                ]
            )
            contact_id = cur.lastrowid
            # Update company contacts_count
            conn.execute(
                "UPDATE companies SET contacts_count = (SELECT COUNT(*) FROM contacts WHERE company_id=?) WHERE id=?",
                [company_id, company_id]
            )

        # 3. Create Deal
        deal_title = data.get("deal_title") or f"{lead['company_name']} — New Deal"
        cur = conn.execute(
            """INSERT INTO deals (title, company_id, contact_id, stage, value_amount, value_currency,
                                  notes, assigned_to, created_by)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            [
                deal_title,
                company_id,
                contact_id,
                "LEAD",
                lead["estimated_value"] or 0,
                "AZN",
                f"Converted from lead #{lead_id}. {lead['notes'] or ''}".strip(),
                lead["assigned_to"] or user["user_id"],
                user["user_id"],
            ]
        )
        deal_id = cur.lastrowid

        # 4. Mark lead as converted
        conn.execute(
            """UPDATE leads SET status='converted', converted_at=datetime('now'),
               converted_company_id=?, converted_contact_id=?, converted_deal_id=?,
               updated_at=datetime('now')
               WHERE id=?""",
            [company_id, contact_id, deal_id, lead_id]
        )

        log_audit(user["user_id"], "convert_lead", "lead", lead_id, ip=_get_ip(request))
        return _ok({
            "message": "Lead converted successfully",
            "company_id": company_id,
            "contact_id": contact_id,
            "deal_id": deal_id,
        })


# ─── Tasks / Calendar ──────────────────────────────────────

TASK_STATUSES = {"todo", "in_progress", "done", "cancelled"}
TASK_PRIORITIES = {"low", "medium", "high", "urgent"}
TASK_CATEGORIES = {"general", "call", "meeting", "email", "follow_up", "deadline"}


@app.get("/api/tasks")
async def list_tasks(
    status: Optional[str] = None,
    priority: Optional[str] = None,
    category: Optional[str] = None,
    assigned_to: Optional[int] = None,
    company_id: Optional[int] = None,
    deal_id: Optional[int] = None,
    lead_id: Optional[int] = None,
    due_from: Optional[str] = None,
    due_to: Optional[str] = None,
    q: str = Query("", description="Search"),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    user=Depends(require_auth),
):
    """List tasks with filtering."""
    with get_db() as conn:
        where = ["1=1"]
        params = []
        if status:
            where.append("t.status=?")
            params.append(status)
        if priority:
            where.append("t.priority=?")
            params.append(priority)
        if category:
            where.append("t.category=?")
            params.append(category)
        if assigned_to:
            where.append("t.assigned_to=?")
            params.append(assigned_to)
        if company_id:
            where.append("t.company_id=?")
            params.append(company_id)
        if deal_id:
            where.append("t.deal_id=?")
            params.append(deal_id)
        if lead_id:
            where.append("t.lead_id=?")
            params.append(lead_id)
        if due_from:
            where.append("t.due_date >= ?")
            params.append(due_from)
        if due_to:
            where.append("t.due_date <= ?")
            params.append(due_to)
        if q:
            where.append("(t.title LIKE ? OR t.description LIKE ?)")
            like = f"%{q}%"
            params.extend([like, like])

        total = conn.execute(
            f"SELECT COUNT(*) FROM tasks t WHERE {' AND '.join(where)}", params
        ).fetchone()[0]

        rows = conn.execute(
            f"""SELECT t.*,
                       u.full_name as assigned_name,
                       c.name as company_name,
                       co.name as contact_name,
                       d.title as deal_title
                FROM tasks t
                LEFT JOIN users u ON u.id = t.assigned_to
                LEFT JOIN companies c ON c.id = t.company_id
                LEFT JOIN contacts co ON co.id = t.contact_id
                LEFT JOIN deals d ON d.id = t.deal_id
                WHERE {' AND '.join(where)}
                ORDER BY
                    CASE t.status WHEN 'todo' THEN 0 WHEN 'in_progress' THEN 1
                        WHEN 'done' THEN 2 ELSE 3 END,
                    CASE t.priority WHEN 'urgent' THEN 0 WHEN 'high' THEN 1
                        WHEN 'medium' THEN 2 ELSE 3 END,
                    t.due_date ASC NULLS LAST,
                    t.created_at DESC
                LIMIT ? OFFSET ?""",
            params + [limit, offset]
        ).fetchall()
        return _ok({"tasks": [dict(r) for r in rows], "total": total})


@app.get("/api/tasks/stats")
async def tasks_stats(user=Depends(require_auth)):
    """Task statistics."""
    with get_db() as conn:
        counts = {}
        for s in TASK_STATUSES:
            counts[s] = conn.execute(
                "SELECT COUNT(*) FROM tasks WHERE status=?", [s]
            ).fetchone()[0]
        counts["total"] = sum(counts.values())
        # Overdue tasks
        today = datetime.utcnow().strftime("%Y-%m-%d")
        counts["overdue"] = conn.execute(
            "SELECT COUNT(*) FROM tasks WHERE due_date < ? AND status NOT IN ('done','cancelled')",
            [today]
        ).fetchone()[0]
        # Due today
        counts["due_today"] = conn.execute(
            "SELECT COUNT(*) FROM tasks WHERE due_date = ? AND status NOT IN ('done','cancelled')",
            [today]
        ).fetchone()[0]
        # Due this week
        week_end = (datetime.utcnow() + timedelta(days=7)).strftime("%Y-%m-%d")
        counts["due_week"] = conn.execute(
            "SELECT COUNT(*) FROM tasks WHERE due_date BETWEEN ? AND ? AND status NOT IN ('done','cancelled')",
            [today, week_end]
        ).fetchone()[0]
        return _ok(counts)


@app.get("/api/tasks/calendar")
async def tasks_calendar(
    month: int = Query(..., ge=1, le=12),
    year: int = Query(..., ge=2020, le=2100),
    user=Depends(require_auth),
):
    """Get tasks for calendar view — returns tasks grouped by date for a given month."""
    with get_db() as conn:
        start = f"{year:04d}-{month:02d}-01"
        if month == 12:
            end = f"{year+1:04d}-01-01"
        else:
            end = f"{year:04d}-{month+1:02d}-01"
        rows = conn.execute(
            """SELECT t.*, u.full_name as assigned_name, c.name as company_name
               FROM tasks t
               LEFT JOIN users u ON u.id = t.assigned_to
               LEFT JOIN companies c ON c.id = t.company_id
               WHERE t.due_date >= ? AND t.due_date < ?
               ORDER BY t.due_date, t.due_time NULLS LAST,
                   CASE t.priority WHEN 'urgent' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END""",
            [start, end]
        ).fetchall()
        return _ok({"tasks": [dict(r) for r in rows], "month": month, "year": year})


@app.get("/api/tasks/{task_id}")
async def get_task(task_id: int, user=Depends(require_auth)):
    """Get a single task."""
    with get_db() as conn:
        row = conn.execute(
            """SELECT t.*, u.full_name as assigned_name, c.name as company_name,
                      co.name as contact_name, d.title as deal_title
               FROM tasks t
               LEFT JOIN users u ON u.id = t.assigned_to
               LEFT JOIN companies c ON c.id = t.company_id
               LEFT JOIN contacts co ON co.id = t.contact_id
               LEFT JOIN deals d ON d.id = t.deal_id
               WHERE t.id=?""",
            [task_id]
        ).fetchone()
        if not row:
            raise HTTPException(404, "Task not found")
        return _ok(dict(row))


@app.post("/api/tasks")
async def create_task(request: Request, user=Depends(require_auth)):
    """Create a new task."""
    body = await request.json()
    title = (body.get("title") or "").strip()
    if not title:
        raise HTTPException(400, "Title is required")

    status = body.get("status", "todo")
    if status not in TASK_STATUSES:
        raise HTTPException(400, f"Invalid status. Must be one of: {', '.join(TASK_STATUSES)}")
    priority = body.get("priority", "medium")
    if priority not in TASK_PRIORITIES:
        raise HTTPException(400, f"Invalid priority. Must be one of: {', '.join(TASK_PRIORITIES)}")
    category = body.get("category", "general")
    if category not in TASK_CATEGORIES:
        raise HTTPException(400, f"Invalid category. Must be one of: {', '.join(TASK_CATEGORIES)}")

    with get_db() as conn:
        cur = conn.execute(
            """INSERT INTO tasks (title, description, status, priority, due_date, due_time,
                   reminder_at, category, company_id, contact_id, deal_id, lead_id,
                   assigned_to, created_by)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            [
                title,
                (body.get("description") or "").strip(),
                status,
                priority,
                body.get("due_date") or None,
                body.get("due_time") or None,
                body.get("reminder_at") or None,
                category,
                body.get("company_id") or None,
                body.get("contact_id") or None,
                body.get("deal_id") or None,
                body.get("lead_id") or None,
                body.get("assigned_to") or user["user_id"],
                user["user_id"],
            ]
        )
        task_id = cur.lastrowid
        assigned_to = body.get("assigned_to") or user["user_id"]
        # Send notification for task assignment
        if assigned_to and assigned_to != user["user_id"]:
            send_notification(assigned_to, "task_assigned", f"Task assigned: {title}", "", "task", task_id)
        log_audit(user["user_id"], "create_task", "task", task_id, ip=_get_ip(request))
        return _ok({"id": task_id, "message": "Task created"})


@app.put("/api/tasks/{task_id}")
async def update_task(task_id: int, request: Request, user=Depends(require_auth)):
    """Update a task."""
    body = await request.json()
    with get_db() as conn:
        existing = conn.execute("SELECT * FROM tasks WHERE id=?", [task_id]).fetchone()
        if not existing:
            raise HTTPException(404, "Task not found")

        status = body.get("status", existing["status"])
        if status not in TASK_STATUSES:
            raise HTTPException(400, f"Invalid status")
        priority = body.get("priority", existing["priority"])
        if priority not in TASK_PRIORITIES:
            raise HTTPException(400, f"Invalid priority")
        category = body.get("category", existing["category"])
        if category not in TASK_CATEGORIES:
            raise HTTPException(400, f"Invalid category")

        completed_at = existing["completed_at"]
        if status == "done" and existing["status"] != "done":
            completed_at = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        elif status != "done":
            completed_at = None

        conn.execute(
            """UPDATE tasks SET title=?, description=?, status=?, priority=?,
                   due_date=?, due_time=?, reminder_at=?, category=?,
                   company_id=?, contact_id=?, deal_id=?, lead_id=?,
                   assigned_to=?, completed_at=?,
                   updated_at=datetime('now')
               WHERE id=?""",
            [
                (body.get("title") or existing["title"]).strip(),
                (body.get("description") if "description" in body else existing["description"]),
                status,
                priority,
                body.get("due_date", existing["due_date"]) or None,
                body.get("due_time", existing["due_time"]) or None,
                body.get("reminder_at", existing["reminder_at"]) or None,
                category,
                body.get("company_id", existing["company_id"]) or None,
                body.get("contact_id", existing["contact_id"]) or None,
                body.get("deal_id", existing["deal_id"]) or None,
                body.get("lead_id", existing["lead_id"]) or None,
                body.get("assigned_to", existing["assigned_to"]) or None,
                completed_at,
                task_id,
            ]
        )
        log_audit(user["user_id"], "update_task", "task", task_id, ip=_get_ip(request))
        return _ok({"message": "Task updated"})


@app.patch("/api/tasks/{task_id}/status")
async def update_task_status(task_id: int, request: Request, user=Depends(require_auth)):
    """Quick status change for a task."""
    body = await request.json()
    status = body.get("status", "")
    if status not in TASK_STATUSES:
        raise HTTPException(400, f"Invalid status")
    with get_db() as conn:
        existing = conn.execute("SELECT status FROM tasks WHERE id=?", [task_id]).fetchone()
        if not existing:
            raise HTTPException(404, "Task not found")
        completed_at = None
        if status == "done":
            completed_at = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        conn.execute(
            "UPDATE tasks SET status=?, completed_at=?, updated_at=datetime('now') WHERE id=?",
            [status, completed_at, task_id]
        )
        log_audit(user["user_id"], "update_task_status", "task", task_id, ip=_get_ip(request))
        return _ok({"message": "Status updated"})


@app.delete("/api/tasks/{task_id}")
async def delete_task(task_id: int, request: Request, user=Depends(require_auth)):
    """Delete a task (admin or creator only)."""
    with get_db() as conn:
        existing = conn.execute("SELECT created_by FROM tasks WHERE id=?", [task_id]).fetchone()
        if not existing:
            raise HTTPException(404, "Task not found")
        if user["role"] != "admin" and existing["created_by"] != user["user_id"]:
            raise HTTPException(403, "Only admin or task creator can delete")
        conn.execute("DELETE FROM tasks WHERE id=?", [task_id])
        log_audit(user["user_id"], "delete_task", "task", task_id, ip=_get_ip(request))
        return _ok({"message": "Task deleted"})


# ─── Calendar Integration (ICS Feed) ────────────────────────

@app.post("/api/calendar/generate-token")
async def generate_calendar_token(request: Request, user=Depends(get_current_user)):
    """Generate or regenerate a personal calendar token for the user."""
    token = secrets.token_urlsafe(32)
    with get_db() as conn:
        conn.execute("UPDATE users SET calendar_token = ? WHERE id = ?", [token, user["user_id"]])
    return _ok({"token": token})


@app.get("/api/calendar/token")
async def get_calendar_token(user=Depends(get_current_user)):
    """Get the current calendar token for the user."""
    with get_db() as conn:
        row = conn.execute("SELECT calendar_token FROM users WHERE id = ?", [user["user_id"]]).fetchone()
    token = row["calendar_token"] if row and row["calendar_token"] else None
    return _ok({"token": token, "base_url": BASE_URL or None})


@app.get("/api/calendar/feed/{token}.ics")
async def calendar_ics_feed(token: str):
    """
    Public ICS feed endpoint — no JWT required.
    Calendar apps (Apple Calendar, Outlook) subscribe to this URL.
    Returns iCalendar format with all tasks for the user.
    """
    with get_db() as conn:
        user_row = conn.execute("SELECT id, full_name, email FROM users WHERE calendar_token = ?", [token]).fetchone()
        if not user_row:
            raise HTTPException(status_code=404, detail="Invalid calendar token")

        user_id = user_row["id"]
        tasks = conn.execute("""
            SELECT DISTINCT t.*, c.name as company_name
            FROM tasks t
            LEFT JOIN companies c ON t.company_id = c.id
            WHERE t.assigned_to = ? OR t.created_by = ?
            ORDER BY t.due_date ASC NULLS LAST
        """, [user_id, user_id]).fetchall()

    # Build ICS content — simplified format for Apple Calendar compatibility
    now = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    cal_lines = [
        "BEGIN:VCALENDAR",
        "VERSION:2.0",
        "PRODID:-//Hermes CRM//Tasks//EN",
        "CALSCALE:GREGORIAN",
    ]

    cat_icons = {"general": "[Task]", "call": "[Call]", "meeting": "[Meeting]", "email": "[Email]", "follow_up": "[Follow-up]", "deadline": "[Deadline]"}

    for t in tasks:
        uid = f"task-{t['id']}@hermes-crm"
        summary = f"{cat_icons.get(t['category'], '[Task]')} {t['title']}"
        if t["company_name"]:
            summary += f" - {t['company_name']}"

        # Determine date/time
        if t["due_date"]:
            dt_date = t["due_date"].replace("-", "")
            if t["due_time"]:
                dt_start = f"{dt_date}T{t['due_time'].replace(':', '')}00"
                try:
                    start_dt = datetime.strptime(f"{t['due_date']} {t['due_time']}", "%Y-%m-%d %H:%M")
                    end_dt = start_dt + timedelta(hours=1)
                    dt_end = end_dt.strftime("%Y%m%dT%H%M%S")
                except:
                    dt_end = dt_start
                # Use UTC offset instead of TZID for Apple Calendar compatibility
                dtstart_line = f"DTSTART;TZID=Asia/Baku:{dt_start}"
                dtend_line = f"DTEND;TZID=Asia/Baku:{dt_end}"
            else:
                dtstart_line = f"DTSTART;VALUE=DATE:{dt_date}"
                try:
                    next_day = (datetime.strptime(t["due_date"], "%Y-%m-%d") + timedelta(days=1)).strftime("%Y%m%d")
                except:
                    next_day = dt_date
                dtend_line = f"DTEND;VALUE=DATE:{next_day}"
        else:
            continue

        # Simple description without special chars
        desc_parts = []
        if t["description"]:
            desc_parts.append(t["description"])
        if t["company_name"]:
            desc_parts.append(f"Company: {t['company_name']}")
        if t["status"]:
            desc_parts.append(f"Status: {t['status']}")
        description = " | ".join(desc_parts) if desc_parts else ""

        cal_lines.extend([
            "BEGIN:VEVENT",
            f"UID:{uid}",
            f"DTSTAMP:{now}",
            dtstart_line,
            dtend_line,
            f"SUMMARY:{_ics_escape(summary)}",
            f"DESCRIPTION:{_ics_escape(description)}",
            f"STATUS:CONFIRMED",
            "END:VEVENT",
        ])

    cal_lines.append("END:VCALENDAR")

    ics_content = "\r\n".join(cal_lines)
    return Response(
        content=ics_content.encode("utf-8"),
        media_type="text/calendar; charset=utf-8",
        headers={
            "Cache-Control": "no-cache, no-store, must-revalidate",
            "Access-Control-Allow-Origin": "*",
        }
    )


def _ics_escape(text):
    """Escape special characters for ICS format (RFC 5545 Section 3.3.11)."""
    if not text:
        return ""
    # First escape backslashes, then semicolons and commas, then newlines
    text = text.replace("\\", "\\\\")
    text = text.replace(";", "\\;")
    text = text.replace(",", "\\,")
    text = text.replace("\r\n", "\\n").replace("\r", "\\n").replace("\n", "\\n")
    return text


def _ics_fold_line(line):
    """Fold ICS content line per RFC 5545 (max 75 octets per line).
    Long lines are split with CRLF + space continuation."""
    encoded = line.encode("utf-8")
    if len(encoded) <= 75:
        return line
    result = []
    # First line: up to 75 bytes
    chunk = encoded[:75]
    # Don't break in the middle of a UTF-8 multibyte char
    while chunk and (chunk[-1] & 0xC0) == 0x80:
        chunk = chunk[:-1]
    result.append(chunk.decode("utf-8"))
    remaining = encoded[len(chunk):]
    # Continuation lines: space + up to 74 bytes (space counts as 1)
    while remaining:
        chunk = remaining[:74]
        while chunk and (chunk[-1] & 0xC0) == 0x80:
            chunk = chunk[:-1]
        result.append(" " + chunk.decode("utf-8"))
        remaining = remaining[len(chunk):]
    return "\r\n".join(result)


# ─── Deals / Pipeline ───────────────────────────────────────

@app.get("/api/deals")
async def list_deals(
    stage: Optional[str] = None,
    company_id: Optional[int] = None,
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    user=Depends(require_auth),
):
    deals = Deal.search(stage=stage, company_id=company_id, limit=limit, offset=offset)
    return _ok(deals, total=Deal.count())


@app.get("/api/deals/forecast")
async def deals_forecast(
    months: int = Query(6, ge=1, le=24),
    owner_id: Optional[int] = None,
    user=Depends(require_auth),
):
    """Sales forecast: weighted pipeline by expected close month."""
    with get_db() as conn:
        # Get stage probabilities
        stage_probs = {}
        try:
            rows = conn.execute("SELECT name, probability FROM pipeline_stages WHERE is_active=1").fetchall()
            for r in rows:
                stage_probs[r["name"]] = r["probability"]
        except Exception:
            stage_probs = {"LEAD": 10, "QUALIFIED": 25, "PROPOSAL": 50, "NEGOTIATION": 75, "WON": 100, "LOST": 0}

        # Get active deals (not WON/LOST)
        sql = """SELECT d.*, COALESCE(d.expected_close, '') as exp_close
                 FROM deals d WHERE d.stage NOT IN ('WON','LOST')"""
        params = []
        if owner_id:
            sql += " AND d.owner_id = ?"
            params.append(owner_id)
        deals = conn.execute(sql, params).fetchall()

        # Group by month
        from collections import defaultdict
        monthly = defaultdict(lambda: {"total": 0, "weighted": 0, "count": 0, "deals": []})
        now = datetime.now()
        for d in deals:
            d = dict(d)
            amount = d.get("value_amount") or d.get("amount") or 0
            stage = d.get("stage", "LEAD")
            prob = stage_probs.get(stage, 10)
            exp = d.get("exp_close") or d.get("expected_close") or ""
            if exp:
                try:
                    month_key = exp[:7]  # "2026-04"
                except Exception:
                    month_key = now.strftime("%Y-%m")
            else:
                month_key = now.strftime("%Y-%m")
            monthly[month_key]["total"] += amount
            monthly[month_key]["weighted"] += amount * prob / 100
            monthly[month_key]["count"] += 1
            monthly[month_key]["deals"].append({
                "id": d.get("id"), "title": d.get("title"), "amount": amount,
                "stage": stage, "probability": prob
            })

        # Build result for next N months
        result = []
        for i in range(months):
            m = now.month + i
            y = now.year + (m - 1) // 12
            m = ((m - 1) % 12) + 1
            key = f"{y}-{m:02d}"
            data = monthly.get(key, {"total": 0, "weighted": 0, "count": 0, "deals": []})
            result.append({"month": key, **data})

        # Totals
        total_pipeline = sum(r["total"] for r in result)
        total_weighted = sum(r["weighted"] for r in result)
        total_deals = sum(r["count"] for r in result)

    return _ok({
        "months": result,
        "summary": {"total_pipeline": total_pipeline, "total_weighted": total_weighted, "total_deals": total_deals}
    })


@app.get("/api/deals/{deal_id}")
async def get_deal(deal_id: int, user=Depends(require_auth)):
    deal = Deal.get(deal_id)
    if not deal:
        _err("Deal not found", 404)
    return _ok(deal)


@app.post("/api/deals")
async def create_deal(request: Request, user=Depends(require_auth)):
    data = await request.json()
    if not data.get("title"):
        _err("Title is required")
    _validate_length(data.get("title", ""), "Title", 300)
    _validate_length(data.get("notes", ""), "Notes", 5000)
    # Validate stage if provided
    if data.get("stage"):
        with get_db() as conn:
            valid_stages = [r[0] for r in conn.execute("SELECT name FROM pipeline_stages WHERE is_active=1").fetchall()]
        if not valid_stages:
            valid_stages = PIPELINE_STAGES
        if data["stage"] not in valid_stages:
            _err("Invalid stage. Must be one of: %s" % ", ".join(valid_stages))
    # Validate value_amount if provided
    if data.get("value_amount") is not None:
        try:
            val = float(data["value_amount"])
            if val < 0:
                _err("Deal value cannot be negative")
        except (ValueError, TypeError):
            _err("Invalid deal value")
    # Set created_by from current user
    data["created_by"] = user.get("user_id")
    deal = Deal.create(data)
    log_audit(user["user_id"], "create_deal", "deal", deal.get("id"), ip=_get_ip(request))
    return _ok(deal)


@app.put("/api/deals/{deal_id}")
async def update_deal(deal_id: int, request: Request, user=Depends(require_auth)):
    data = await request.json()
    deal = Deal.update(deal_id, data)
    if not deal:
        _err("Deal not found", 404)
    log_audit(user["user_id"], "update_deal", "deal", deal_id, ip=_get_ip(request))
    return _ok(deal)


@app.delete("/api/deals/{deal_id}")
async def delete_deal(deal_id: int, user=Depends(require_admin)):
    """Delete a deal (admin only)."""
    with get_db() as conn:
        conn.execute("DELETE FROM activities WHERE deal_id = ?", (deal_id,))
        conn.execute("DELETE FROM deals WHERE id = ?", (deal_id,))
    return _ok({"deleted": True})


@app.patch("/api/deals/{deal_id}/stage")
async def move_deal_stage(deal_id: int, request: Request, user=Depends(require_auth)):
    data = await request.json()
    new_stage = data.get("stage", "")
    with get_db() as conn:
        valid_stages = [r[0] for r in conn.execute("SELECT name FROM pipeline_stages WHERE is_active=1").fetchall()]
    if not valid_stages:
        valid_stages = PIPELINE_STAGES
    if new_stage not in valid_stages:
        _err("Invalid stage. Must be one of: %s" % ", ".join(valid_stages))
    deal = Deal.move_stage(deal_id, new_stage)
    if not deal:
        _err("Deal not found", 404)
    # Send notification for stage change
    try:
        with get_db() as conn:
            deal_row = conn.execute("SELECT title, assigned_to, value_amount FROM deals WHERE id=?", (deal_id,)).fetchone()
            if deal_row:
                deal_title = deal_row[0] or f"Deal #{deal_id}"
                assigned_to = deal_row[1]
                if new_stage == 'WON':
                    # Notify all admins/managers about won deal
                    users_to_notify = conn.execute("SELECT id FROM users WHERE role IN ('admin','manager')").fetchall()
                    for u in users_to_notify:
                        send_notification(u[0], "deal_won", f"Deal Won: {deal_title}", f"Value: {deal_row[2]}", "deal", deal_id)
                elif new_stage == 'LOST':
                    lost_reason = data.get("lost_reason", "")
                    users_to_notify = conn.execute("SELECT id FROM users WHERE role IN ('admin','manager')").fetchall()
                    for u in users_to_notify:
                        send_notification(u[0], "deal_lost", f"Deal Lost: {deal_title}", lost_reason, "deal", deal_id)
                elif assigned_to and assigned_to != user["user_id"]:
                    send_notification(assigned_to, "deal_stage_changed", f"Deal moved to {new_stage}: {deal_title}", "", "deal", deal_id)
    except Exception as e:
        logger.warning("Notification error: %s", e)
    log_audit(user["user_id"], "move_deal_stage", "deal", deal_id, details=f"stage={new_stage}", ip=_get_ip(request))
    return _ok(deal)


# ─── Activities ──────────────────────────────────────────────

@app.get("/api/activities")
async def list_activities(
    contact_id: Optional[int] = None,
    lead_id: Optional[int] = None,
    company_id: Optional[int] = None,
    limit: int = Query(50, ge=1, le=200),
    user=Depends(require_auth),
):
    if lead_id:
        with get_db() as conn:
            rows = conn.execute(
                "SELECT * FROM activities WHERE lead_id=? ORDER BY timestamp DESC LIMIT ?",
                (lead_id, limit)
            ).fetchall()
            cols = [d[0] for d in conn.execute("SELECT * FROM activities LIMIT 0").description]
            return _ok([dict(zip(cols, r)) for r in rows], total=len(rows))
    if company_id:
        with get_db() as conn:
            rows = conn.execute(
                "SELECT * FROM activities WHERE company_id=? ORDER BY timestamp DESC LIMIT ?",
                (company_id, limit)
            ).fetchall()
            cols = [d[0] for d in conn.execute("SELECT * FROM activities LIMIT 0").description]
            return _ok([dict(zip(cols, r)) for r in rows], total=len(rows))
    if contact_id:
        activities = Activity.get_for_contact(contact_id, limit=limit)
    else:
        activities = Activity.get_recent(limit=limit)
    return _ok(activities, total=Activity.count())


@app.post("/api/activities")
async def create_activity(request: Request, user=Depends(require_auth)):
    data = await request.json()
    lead_id = data.pop("lead_id", None)
    company_id = data.pop("company_id", None)
    activity = Activity.create(data)
    act_id = activity.get("id")
    # If linked to a lead, update the activity record and rescore
    if lead_id and act_id:
        with get_db() as conn:
            conn.execute("UPDATE activities SET lead_id=? WHERE id=?", (lead_id, act_id))
        calculate_lead_score(lead_id)
    # If linked to a company, update the activity record
    if company_id and act_id:
        with get_db() as conn:
            conn.execute("UPDATE activities SET company_id=? WHERE id=?", (company_id, act_id))
    log_audit(user["user_id"], "create_activity", "activity", act_id, ip=_get_ip(request))
    return _ok(activity)


@app.get("/api/activities/company-counts")
async def activity_company_counts(user=Depends(require_auth)):
    """Get activity counts grouped by company_id."""
    with get_db() as conn:
        rows = conn.execute(
            "SELECT company_id, COUNT(*) as cnt, MAX(timestamp) as last_activity FROM activities WHERE company_id IS NOT NULL GROUP BY company_id"
        ).fetchall()
        result = {r[0]: {"count": r[1], "last_activity": r[2]} for r in rows}
        return _ok(result)


# ─── Analytics ───────────────────────────────────────────────

@app.get("/api/analytics/summary")
async def analytics_summary(user=Depends(require_auth)):
    """Dashboard summary stats."""
    pipeline = Deal.pipeline_summary()

    total_value = sum(s["total_value"] for s in pipeline.values())
    active_deals = sum(
        s["count"] for stage, s in pipeline.items()
        if stage not in ("WON", "LOST")
    )

    # Count contracts and company categories
    with get_db() as conn:
        contracts_total = conn.execute("SELECT COUNT(*) FROM contracts").fetchone()[0]
        clients_total = conn.execute("SELECT COUNT(*) FROM companies WHERE category = 'client'").fetchone()[0]
        partners_total = conn.execute("SELECT COUNT(*) FROM companies WHERE category = 'partner'").fetchone()[0]
        contacts_total = conn.execute("SELECT COUNT(*) FROM contacts").fetchone()[0]

    return _ok({
        "clients_total": clients_total,
        "partners_total": partners_total,
        "companies_total": Company.count(),
        "contacts_total": contacts_total,
        "deals_total": Deal.count(),
        "deals_active": active_deals,
        "pipeline_value": total_value,
        "deals_value": total_value,
        "activities_total": Activity.count(),
        "contracts_total": contracts_total,
    })


@app.get("/api/analytics/pipeline")
async def analytics_pipeline(user=Depends(require_auth)):
    """Pipeline breakdown by stage."""
    return _ok(Deal.pipeline_summary())


@app.get("/api/analytics/funnel")
async def analytics_funnel(user=Depends(require_auth)):
    """Conversion funnel data."""
    pipeline = Deal.pipeline_summary()
    stages_order = ["LEAD", "QUALIFIED", "PROPOSAL", "NEGOTIATION", "WON"]
    funnel = []
    for stage in stages_order:
        info = pipeline.get(stage, {"count": 0, "total_value": 0})
        funnel.append({
            "stage": stage,
            "count": info["count"],
            "value": info["total_value"],
        })
    return _ok(funnel)


@app.get("/api/analytics/top_contacts")
async def analytics_top_contacts(user=Depends(require_auth)):
    """Top contacts by email count."""
    with get_db() as conn:
        rows = conn.execute(
            "SELECT id, email, name, company_name, email_count, last_contact "
            "FROM contacts ORDER BY email_count DESC LIMIT 20"
        ).fetchall()
        return _ok([dict(r) for r in rows])


# ─── Search ──────────────────────────────────────────────────

@app.get("/api/search")
async def global_search(q: str = Query("", min_length=1), user=Depends(require_auth)):
    """Search across contacts, companies, and contracts."""
    contacts = Contact.search(query=q, limit=5)
    companies = Company.search(query=q, limit=5)

    # Also search contracts
    with get_db() as conn:
        rows = conn.execute(
            "SELECT id, contract_name, counterparty, contract_type, status "
            "FROM contracts WHERE contract_name LIKE ? OR counterparty LIKE ? "
            "ORDER BY id DESC LIMIT 5",
            (f"%{q}%", f"%{q}%")
        ).fetchall()
        contracts = [dict(r) for r in rows]

    return _ok({
        "contacts": contacts,
        "companies": companies,
        "contracts": contracts,
    })


# ─── Expiring Contracts ─────────────────────────────────────

@app.get("/api/contracts/expiring")
async def expiring_contracts(
    days: int = Query(30, ge=1, le=365),
    limit: int = Query(20, ge=1, le=100),
    user=Depends(require_auth),
):
    """Contracts expiring within N days."""
    with get_db() as conn:
        today = datetime.now().strftime("%Y-%m-%d")
        future = (datetime.now() + timedelta(days=days)).strftime("%Y-%m-%d")
        rows = conn.execute(
            "SELECT * FROM contracts "
            "WHERE end_date != '' AND end_date IS NOT NULL "
            "AND end_date >= ? AND end_date <= ? "
            "AND status IN ('active', 'signed') "
            "ORDER BY end_date ASC LIMIT ?",
            (today, future, limit)
        ).fetchall()
        total = conn.execute(
            "SELECT COUNT(*) FROM contracts "
            "WHERE end_date != '' AND end_date IS NOT NULL "
            "AND end_date >= ? AND end_date <= ? "
            "AND status IN ('active', 'signed')",
            (today, future)
        ).fetchone()[0]
        return _ok([dict(r) for r in rows], total=total)


# ─── Notifications (computed) ────────────────────────────────

@app.get("/api/notifications")
async def get_notifications(user=Depends(require_auth)):
    """Computed notifications from existing data."""
    notifications = []

    with get_db() as conn:
        today = datetime.now().strftime("%Y-%m-%d")
        future30 = (datetime.now() + timedelta(days=30)).strftime("%Y-%m-%d")
        cutoff30 = (datetime.now() - timedelta(days=30)).strftime("%Y-%m-%d %H:%M:%S")

        # 1. Expiring contracts (next 30 days)
        expiring = conn.execute(
            "SELECT id, contract_name, counterparty, end_date FROM contracts "
            "WHERE end_date != '' AND end_date IS NOT NULL "
            "AND end_date >= ? AND end_date <= ? "
            "AND status IN ('active', 'signed') "
            "ORDER BY end_date ASC LIMIT 10",
            (today, future30)
        ).fetchall()
        for r in expiring:
            days_left = (datetime.strptime(r["end_date"], "%Y-%m-%d") - datetime.now()).days
            notifications.append({
                "type": "contract_expiry",
                "severity": "high" if days_left <= 7 else "medium",
                "title": f"Contract expires in {days_left} days",
                "detail": f"{r['contract_name']} ({r['counterparty']})",
                "entity_type": "contract",
                "entity_id": r["id"],
            })

        # 2. Silent important contacts (>30 days, email_count > 5)
        silent = conn.execute(
            "SELECT id, name, email, company_name, email_count, last_contact FROM contacts "
            "WHERE last_contact IS NOT NULL AND last_contact != '' AND last_contact < ? "
            "AND email_count > 5 "
            "ORDER BY email_count DESC LIMIT 10",
            (cutoff30,)
        ).fetchall()
        for r in silent:
            try:
                lc = datetime.strptime(r["last_contact"][:10], "%Y-%m-%d")
                days_ago = (datetime.now() - lc).days
            except Exception:
                days_ago = 30
            notifications.append({
                "type": "silent_contact",
                "severity": "medium" if days_ago < 60 else "high",
                "title": f"No contact for {days_ago} days",
                "detail": f"{r['name'] or r['email']} ({r['company_name'] or ''})",
                "entity_type": "contact",
                "entity_id": r["id"],
            })

        # 3. Contracts stuck in negotiation (>14 days)
        negotiation = conn.execute(
            "SELECT id, contract_name, counterparty, created_at FROM contracts "
            "WHERE status = 'negotiation' ORDER BY created_at ASC LIMIT 10"
        ).fetchall()
        for r in negotiation:
            notifications.append({
                "type": "stuck_negotiation",
                "severity": "low",
                "title": "Contract in negotiation",
                "detail": f"{r['contract_name']} ({r['counterparty']})",
                "entity_type": "contract",
                "entity_id": r["id"],
            })

        # 4. Stored notifications from notifications table
        stored = conn.execute(
            "SELECT id, type, title, message, entity_type, entity_id, is_read, created_at "
            "FROM notifications WHERE user_id = ? ORDER BY created_at DESC LIMIT 20",
            (user["user_id"],)
        ).fetchall()
        for r in stored:
            notifications.append({
                "type": r["type"] or "info",
                "severity": "medium",
                "title": r["title"] or r["message"] or "Notification",
                "detail": r["message"] or "",
                "entity_type": r["entity_type"],
                "entity_id": r["entity_id"],
                "is_read": r["is_read"],
                "created_at": r["created_at"],
            })

        # 5. Overdue tasks
        overdue_tasks = conn.execute(
            "SELECT id, title, due_date FROM tasks "
            "WHERE due_date != '' AND due_date IS NOT NULL AND due_date < ? "
            "AND status NOT IN ('done', 'completed') "
            "ORDER BY due_date ASC LIMIT 5",
            (today,)
        ).fetchall()
        for r in overdue_tasks:
            notifications.append({
                "type": "overdue_task",
                "severity": "high",
                "title": f"Overdue task: {r['title']}",
                "detail": f"Due: {r['due_date']}",
                "entity_type": "task",
                "entity_id": r["id"],
            })

        # 6. Recent deals (last 7 days)
        week_ago = (datetime.now() - timedelta(days=7)).strftime("%Y-%m-%d")
        recent_deals = conn.execute(
            "SELECT id, title, status, created_at FROM deals "
            "WHERE created_at >= ? ORDER BY created_at DESC LIMIT 5",
            (week_ago,)
        ).fetchall()
        for r in recent_deals:
            notifications.append({
                "type": "new_deal",
                "severity": "low",
                "title": f"Deal: {r['title']}",
                "detail": f"Status: {r['status']}",
                "entity_type": "deal",
                "entity_id": r["id"],
                "created_at": r["created_at"],
            })

        # 7. Tasks assigned to current user
        pending_tasks = conn.execute(
            "SELECT COUNT(*) FROM tasks WHERE assigned_to = ? AND status NOT IN ('done', 'completed')",
            (user["user_id"],)
        ).fetchone()[0]
        if pending_tasks > 0:
            notifications.append({
                "type": "pending_tasks",
                "severity": "medium",
                "title": f"You have {pending_tasks} pending task(s)",
                "detail": "Check your task list",
                "entity_type": "task",
                "entity_id": None,
            })

    # Sort: high first, then medium, then low
    sev_order = {"high": 0, "medium": 1, "low": 2}
    notifications.sort(key=lambda n: sev_order.get(n["severity"], 3))

    return _ok(notifications, total=len(notifications))


# ─── Company Contracts ───────────────────────────────────────

@app.get("/api/companies/{company_id}/contracts")
async def company_contracts(company_id: int, user=Depends(require_auth)):
    """Get contracts linked to a company by matching counterparty name."""
    company = Company.get(company_id)
    if not company:
        _err("Company not found", 404)

    with get_db() as conn:
        name = company["name"]
        rows = conn.execute(
            "SELECT * FROM contracts WHERE counterparty LIKE ? ORDER BY id DESC",
            (f"%{name}%",)
        ).fetchall()
        return _ok([dict(r) for r in rows])


# ─── Email Sync ──────────────────────────────────────────────

@app.post("/api/sync")
async def trigger_sync(user=Depends(require_auth)):
    """Trigger email sync in background thread (protected by lock)."""
    log_audit(user["user_id"], "trigger_sync", entity_type="system", details="Manual sync triggered")

    if _sync_state["running"]:
        return _ok({"status": "already_running"})

    async with _sync_lock:
        if _sync_state["running"]:
            return _ok({"status": "already_running"})

        def _run_sync():
            _sync_state["running"] = True
            _sync_state["progress"] = "Scanning Apple Mail..."
            try:
                from apple_mail_sync import sync_emails
                result = sync_emails(limit=500)
                _sync_state["last_result"] = result
                _sync_state["progress"] = "Complete"
            except Exception as e:
                _sync_state["last_result"] = {"error": "Sync failed"}
                _sync_state["progress"] = "Failed"
                logger.error("Sync error: %s", str(e))
            finally:
                _sync_state["running"] = False

        t = threading.Thread(target=_run_sync, daemon=True)
        t.start()

    return _ok({"status": "started"})


@app.get("/api/sync/status")
async def sync_status(user=Depends(require_auth)):
    """Get current sync status."""
    from apple_mail_sync import get_sync_status
    status = get_sync_status()
    status["running"] = _sync_state["running"]
    status["progress"] = _sync_state["progress"]
    status["last_result"] = _sync_state["last_result"]
    return _ok(status)


# ─── Contracts ──────────────────────────────────────────────

@app.get("/api/contracts")
async def list_contracts(
    q: str = Query("", description="Search query"),
    contract_type: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    user=Depends(require_auth),
):
    """List contracts with optional filters."""
    with get_db() as conn:
        sql = "SELECT * FROM contracts WHERE 1=1"
        count_sql = "SELECT COUNT(*) FROM contracts WHERE 1=1"
        params = []
        count_params = []
        if q:
            sql += " AND (contract_name LIKE ? OR counterparty LIKE ? OR summary LIKE ?)"
            count_sql += " AND (contract_name LIKE ? OR counterparty LIKE ? OR summary LIKE ?)"
            params.extend([f"%{q}%"] * 3)
            count_params.extend([f"%{q}%"] * 3)
        if contract_type:
            sql += " AND contract_type = ?"
            count_sql += " AND contract_type = ?"
            params.append(contract_type)
            count_params.append(contract_type)
        if status:
            sql += " AND status = ?"
            count_sql += " AND status = ?"
            params.append(status)
            count_params.append(status)
        sql += " ORDER BY id DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        rows = conn.execute(sql, params).fetchall()
        total = conn.execute(count_sql, count_params).fetchone()[0]
        return _ok([dict(r) for r in rows], total=total)


@app.get("/api/contracts/stats/summary")
async def contracts_stats(user=Depends(require_auth)):
    """Contract statistics — MUST be before {contract_id} route."""
    with get_db() as conn:
        total = conn.execute("SELECT COUNT(*) FROM contracts").fetchone()[0]
        by_type = conn.execute(
            "SELECT contract_type, COUNT(*) as cnt FROM contracts GROUP BY contract_type ORDER BY cnt DESC"
        ).fetchall()
        by_status = conn.execute(
            "SELECT status, COUNT(*) as cnt FROM contracts GROUP BY status ORDER BY cnt DESC"
        ).fetchall()
        return _ok({
            "total": total,
            "by_type": [{"type": r[0], "count": r[1]} for r in by_type],
            "by_status": [{"status": r[0], "count": r[1]} for r in by_status],
        })


# ═══════════════════════════════════════════════════════════════════════════════
# CONTRACT GENERATION ENDPOINTS (must be before {contract_id} wildcard)
# ═══════════════════════════════════════════════════════════════════════════════

@app.post("/api/contracts/import")
async def import_contract(
    file: UploadFile = File(...),
    company_code: str = Form(None),
    user=Depends(require_auth)
):
    """
    Upload a lawyer-supplied .docx file.
    Extracts requisites, saves template, updates company_details.json.
    """
    import tempfile, traceback as _tb
    try:
        import importlib, contract_parser as _cp_mod
        importlib.reload(_cp_mod)
        import_contract_file = _cp_mod.import_contract_file

        # Load pricing keys for auto-detection
        pricing_path = os.path.join(STATIC_DIR, "pricing_data.json")
        with open(pricing_path, encoding="utf-8") as f:
            pricing_keys = list(json.load(f).keys())

        # Sanitize company_code to prevent path traversal
        safe_code = _sanitize_company_code(company_code) if company_code else None

        # Validate file type
        if file.filename and not file.filename.lower().endswith('.docx'):
            return _err("Only .docx files are supported", 400)

        # Save upload to temp file
        content = await file.read()
        if len(content) > 50 * 1024 * 1024:  # 50MB limit
            return _err("File too large (max 50MB)", 400)
        with tempfile.NamedTemporaryFile(delete=False, suffix=".docx") as tmp:
            tmp.write(content)
            tmp_path = tmp.name

        result = import_contract_file(tmp_path, safe_code, pricing_keys)
        os.unlink(tmp_path)

        return _ok({
            "code":    result["code"],
            "data":    result["data"],
            "message": f"Imported successfully for company: {result['code']}"
        })
    except ValueError as e:
        logger.error(f"Import validation error: {e}")
        return _err("Import failed: invalid data", 400)
    except Exception as e:
        logger.error(f"Contract import failed: {_tb.format_exc()}")
        return _err("Contract import failed", 500)


@app.post("/api/contracts/generate")
async def generate_contract_endpoint(request: Request, user=Depends(require_auth)):
    """
    Generate a filled contract .docx.
    Body: { company_code, annex_number, contract_number, signing_date,
            period_start, period_end }
    Returns the file as a download.
    """
    import traceback as _tb
    try:
        import importlib, generate_contract as _gc_mod
        importlib.reload(_gc_mod)
        generate_contract = _gc_mod.generate_contract
        body = await request.json()
        company_code = body.get("company_code")
        if not company_code:
            return _err("company_code is required", 400)
        # Sanitize company_code to prevent path traversal
        company_code = _sanitize_company_code(company_code)
        if not company_code:
            return _err("Invalid company_code", 400)

        params = {k: v for k, v in body.items() if k != "company_code" and v}
        out_path = generate_contract(company_code, params)

        import urllib.parse
        filename = os.path.basename(out_path)
        filename_encoded = urllib.parse.quote(filename, safe='')
        return FileResponse(
            out_path,
            media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            filename=filename,
            headers={"Content-Disposition": f"attachment; filename*=UTF-8''{filename_encoded}"}
        )
    except ValueError as e:
        logger.error(f"Generation validation error: {e}")
        return _err("Generation failed: invalid data", 400)
    except FileNotFoundError as e:
        logger.error(f"Template not found: {e}")
        return _err("Template not found", 404)
    except Exception as e:
        logger.error(f"Contract generation failed: {_tb.format_exc()}")
        return _err("Contract generation failed", 500)


@app.post("/api/contracts/generate-qrp")
async def generate_qrp_endpoint(request: Request, user=Depends(require_auth)):
    """
    Generate QRP (Qiymət Razılaşdırma Protokolu) for a company.
    Uses {company_code}_QRP.docx template from contract_templates/.
    Body: { company_code, annex_number, contract_number, signing_date,
            period_start, period_end }
    """
    import traceback as _tb
    try:
        import importlib, generate_contract as _gc_mod
        importlib.reload(_gc_mod)
        _read_all_parts     = _gc_mod._read_all_parts
        _merge_runs         = _gc_mod._merge_runs
        _replace_variables  = _gc_mod._replace_variables
        _write_docx         = _gc_mod._write_docx

        body = await request.json()
        company_code = body.get("company_code")
        if not company_code:
            return _err("company_code is required", 400)
        company_code = _sanitize_company_code(company_code)
        if not company_code:
            return _err("Invalid company_code", 400)

        templates_dir = os.path.join(BASE_DIR, "contract_templates")
        import unicodedata
        def _nfc(s): return unicodedata.normalize("NFC", s)
        # Try company-specific template first, then fall back to DEFAULT_QRP.docx
        qrp_path = os.path.join(templates_dir, f"{company_code}_QRP.docx")
        if not os.path.exists(qrp_path):
            qrp_path = os.path.join(templates_dir, f"{_nfc(company_code)}_QRP.docx")
        if not os.path.exists(qrp_path):
            qrp_path = os.path.join(templates_dir, "DEFAULT_QRP.docx")
        if not os.path.exists(qrp_path):
            return _err(f"QRP template not found for '{company_code}' and no DEFAULT_QRP.docx exists", 404)

        # Load company details
        details_path = os.path.join(STATIC_DIR, "company_details.json")
        details = {}
        if os.path.exists(details_path):
            with open(details_path, encoding="utf-8") as f:
                all_details = json.load(f)
            details = all_details.get(company_code) or {}
            if not details:
                nfc_code = _nfc(company_code)
                details = next((v for k, v in all_details.items() if _nfc(k) == nfc_code), {})

        # Params from request body
        params = {k: v for k, v in body.items() if k != "company_code" and v}

        # Generate output filename
        annex = params.get("annex_number") or details.get("annex_number", "02")
        out_name = f"{company_code} - Guven Technology - QRP №{annex} - Xidmətlərin Kataloqu.docx"
        out_path = os.path.join(BASE_DIR, "generated", out_name)
        os.makedirs(os.path.dirname(out_path), exist_ok=True)

        # Read template, merge runs, then fill {{placeholders}} with company data
        parts = _read_all_parts(qrp_path)
        raw_xml = parts.get("word/document.xml", b"").decode("utf-8")
        merged_xml = _merge_runs(raw_xml)

        # Build substitution dict from company details + request params
        import unicodedata as _ud
        def _esc(s): return str(s).replace('&','&amp;').replace('<','&lt;').replace('>','&gt;')
        c = details.get("client", {})
        subs = {
            "legal_name":     c.get("legal_name", company_code),
            "voen":           c.get("voen", ""),
            "director_name":  c.get("director_name", ""),
            "director_title": c.get("director_title", "direktoru"),
            "bank":           c.get("bank", ""),
            "bank_voen":      c.get("bank_voen", ""),
            "bank_code":      c.get("bank_code", ""),
            "mh":             c.get("mh", ""),
            "hh":             c.get("hh", ""),
            "swift":          c.get("swift", ""),
            "contract_number": params.get("contract_number") or details.get("contract_number", ""),
            "contract_date":   params.get("contract_date") or details.get("contract_date", ""),
            "qrp_number":      params.get("annex_number") or details.get("annex_number", "02"),
            "signing_date":    params.get("signing_date") or details.get("signing_date", ""),
            "period_start":    params.get("period_start") or details.get("period_start", "01.01.2026"),
            "period_end":      params.get("period_end") or details.get("period_end", "31.12.2026"),
        }

        # Strip trailing " il" from date fields (template already appends " il tarixli" / " il")
        def _strip_il(s):
            s = str(s).strip()
            if s.endswith(" il"):
                s = s[:-3].rstrip()
            return s
        for date_key in ("contract_date", "signing_date"):
            if date_key in subs:
                subs[date_key] = _strip_il(subs[date_key])

        filled_xml = merged_xml
        for key, val in subs.items():
            filled_xml = filled_xml.replace(_esc(f"{{{{{key}}}}}"), _esc(str(val)))

        _write_docx(parts, filled_xml, out_path)

        import urllib.parse
        filename = os.path.basename(out_path)
        filename_encoded = urllib.parse.quote(filename, safe='')
        return FileResponse(
            out_path,
            media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            filename=filename,
            headers={"Content-Disposition": f"attachment; filename*=UTF-8''{filename_encoded}"}
        )
    except FileNotFoundError as e:
        logger.error(f"QRP template not found: {e}")
        return _err("QRP template not found", 404)
    except Exception as e:
        logger.error(f"QRP generation failed: {_tb.format_exc()}")
        return _err("QRP generation failed", 500)


@app.post("/api/contracts/upload-qrp")
async def upload_qrp_template(
    company_code: str = Form(...),
    file: UploadFile = File(...),
    user=Depends(require_auth)
):
    """Upload a QRP template for a company. Saves as {company_code}_QRP.docx."""
    safe_code = _sanitize_company_code(company_code)
    if not safe_code:
        return _err("Invalid company_code", 400)
    templates_dir = os.path.join(BASE_DIR, "contract_templates")
    os.makedirs(templates_dir, exist_ok=True)
    out_path = os.path.join(templates_dir, f"{safe_code}_QRP.docx")
    real_out = os.path.realpath(out_path)
    real_tpl = os.path.realpath(templates_dir)
    if not real_out.startswith(real_tpl):
        return _err("Invalid path", 400)
    content = await file.read()
    with open(out_path, "wb") as f:
        f.write(content)
    return _ok({"message": f"QRP template saved for '{safe_code}'", "code": safe_code})


@app.post("/api/contracts/upload-default-qrp")
async def upload_default_qrp_template(
    file: UploadFile = File(...),
    user=Depends(require_auth)
):
    """Upload the default QRP template used for all companies. Saves as DEFAULT_QRP.docx."""
    templates_dir = os.path.join(BASE_DIR, "contract_templates")
    os.makedirs(templates_dir, exist_ok=True)
    out_path = os.path.join(templates_dir, "DEFAULT_QRP.docx")
    content = await file.read()
    with open(out_path, "wb") as f:
        f.write(content)
    return _ok({"message": "Default QRP template updated"})


@app.get("/api/contracts/companies")
async def get_contract_companies(user=Depends(require_auth)):
    """
    Return list of all companies with their contract status:
    has_template, has_details, last_imported.
    """
    details_path  = os.path.join(STATIC_DIR, "company_details.json")
    pricing_path  = os.path.join(STATIC_DIR, "pricing_data.json")
    templates_dir = os.path.join(BASE_DIR, "contract_templates")

    details = {}
    if os.path.exists(details_path):
        with open(details_path, encoding="utf-8") as f:
            details = json.load(f)

    with open(pricing_path, encoding="utf-8") as f:
        pricing = json.load(f)

    import unicodedata
    def _nfc(s): return unicodedata.normalize("NFC", s)

    # Build NFC-normalized details lookup (keys in JSON may differ in decomposition)
    details_nfc = {_nfc(k): v for k, v in details.items()}

    result = []
    for code, pdata in sorted(pricing.items()):
        # Template file: try exact code, then NFC-normalized version
        tpl_file = os.path.join(templates_dir, f"{code}.docx")
        if not os.path.exists(tpl_file):
            tpl_file = os.path.join(templates_dir, f"{_nfc(code)}.docx")
        # QRP template file: company-specific or default
        qrp_file = os.path.join(templates_dir, f"{code}_QRP.docx")
        if not os.path.exists(qrp_file):
            qrp_file = os.path.join(templates_dir, f"{_nfc(code)}_QRP.docx")
        default_qrp = os.path.join(templates_dir, "DEFAULT_QRP.docx")
        qrp_available = os.path.exists(qrp_file) or os.path.exists(default_qrp)
        det = details.get(code) or details_nfc.get(_nfc(code)) or {}
        total     = sum(
            cat.get("total", 0)
            for cat in pdata.get("categories", {}).values()
        )
        result.append({
            "code":          code,
            "group":         pdata.get("group", ""),
            "legal_name":    det.get("client", {}).get("legal_name", ""),
            "has_template":  os.path.exists(tpl_file),
            "has_qrp":       qrp_available,
            "has_own_qrp":   os.path.exists(qrp_file),
            "has_details":   bool(det),
            "last_imported": det.get("last_imported", ""),
            "annex_number":  det.get("annex_number", ""),
            "contract_number": det.get("contract_number", ""),
            "monthly_total": round(total, 2),
        })
    return _ok(result)


@app.get("/api/contracts/details/{company_code}")
async def get_contract_details(company_code: str, user=Depends(require_auth)):
    """Get stored requisites for a specific company."""
    details_path = os.path.join(STATIC_DIR, "company_details.json")
    if not os.path.exists(details_path):
        return _err("company_details.json not found", 404)
    with open(details_path, encoding="utf-8") as f:
        details = json.load(f)
    if company_code not in details:
        return _err(f"No details for company '{company_code}'", 404)
    return _ok(details[company_code])


@app.put("/api/contracts/details/{company_code}")
async def update_contract_details(company_code: str, request: Request, user=Depends(require_auth)):
    """Update requisites for a company manually."""
    details_path = os.path.join(STATIC_DIR, "company_details.json")
    details = {}
    if os.path.exists(details_path):
        with open(details_path, encoding="utf-8") as f:
            details = json.load(f)
    body = await request.json()
    details[company_code] = body
    with open(details_path, "w", encoding="utf-8") as f:
        json.dump(details, f, ensure_ascii=False, indent=2)
    return _ok({"message": "Updated", "code": company_code})


# ─── Per-contract CRUD (wildcard — must stay AFTER all /contracts/xxx routes) ──

@app.get("/api/contracts/{contract_id}")
async def get_contract(contract_id: int, user=Depends(require_auth)):
    with get_db() as conn:
        row = conn.execute("SELECT * FROM contracts WHERE id = ?", (contract_id,)).fetchone()
        if not row:
            _err("Contract not found", 404)
        return _ok(dict(row))



@app.post("/api/contracts")
async def create_contract(request: Request, user=Depends(require_auth)):
    data = await request.json()
    with get_db() as conn:
        cur = conn.execute(
            """INSERT INTO contracts
               (contract_name, counterparty, contract_type, amount, currency,
                start_date, end_date, status, summary)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                data.get("contract_name", ""),
                data.get("counterparty", ""),
                data.get("contract_type", "other"),
                str(data.get("amount", "")),
                data.get("currency", "AZN"),
                data.get("start_date", ""),
                data.get("end_date", ""),
                data.get("status", "unknown"),
                data.get("summary", ""),
            )
        )
        conn.commit()
        new_id = cur.lastrowid
        row = conn.execute("SELECT * FROM contracts WHERE id = ?", (new_id,)).fetchone()
        log_audit(user["user_id"], "create_contract", "contract", new_id, ip=_get_ip(request))
        return _ok(dict(row))


@app.put("/api/contracts/{contract_id}")
async def update_contract(contract_id: int, request: Request, user=Depends(require_auth)):
    data = await request.json()
    with get_db() as conn:
        fields = []
        params = []
        for key in ("contract_name", "counterparty", "contract_type", "amount", "currency",
                     "start_date", "end_date", "status", "summary"):
            if key in data:
                fields.append(f"{key} = ?")
                params.append(data[key])
        if not fields:
            _err("No fields to update")
        params.append(contract_id)
        conn.execute(f"UPDATE contracts SET {', '.join(fields)} WHERE id = ?", params)
        conn.commit()
        row = conn.execute("SELECT * FROM contracts WHERE id = ?", (contract_id,)).fetchone()
        log_audit(user["user_id"], "update_contract", "contract", contract_id, ip=_get_ip(request))
        return _ok(dict(row))


@app.delete("/api/contracts/{contract_id}")
async def delete_contract(contract_id: int, request: Request, user=Depends(require_admin)):
    with get_db() as conn:
        conn.execute("DELETE FROM contracts WHERE id = ?", (contract_id,))
        conn.commit()
        log_audit(user["user_id"], "delete_contract", "contract", contract_id, ip=_get_ip(request))
        return _ok({"deleted": True})


# ─── Reports ─────────────────────────────────────────────────

@app.get("/api/reports/summary")
async def reports_summary(user=Depends(require_auth)):
    """Summary stats for reports page."""
    with get_db() as conn:
        total_contacts = conn.execute("SELECT COUNT(*) FROM contacts").fetchone()[0]
        total_companies = conn.execute("SELECT COUNT(*) FROM companies").fetchone()[0]
        total_contracts = conn.execute("SELECT COUNT(*) FROM contracts").fetchone()[0]
        total_deals = conn.execute("SELECT COUNT(*) FROM deals").fetchone()[0]
    return _ok({
        "total_contacts": total_contacts,
        "total_companies": total_companies,
        "total_contracts": total_contracts,
        "total_deals": total_deals,
    })


@app.get("/api/reports/contacts-by-company")
async def reports_contacts_by_company(user=Depends(require_auth)):
    """Contacts grouped by company."""
    with get_db() as conn:
        rows = conn.execute(
            "SELECT company_name, COUNT(*) as count FROM contacts "
            "WHERE company_name IS NOT NULL AND company_name != '' "
            "GROUP BY company_name ORDER BY count DESC LIMIT 20"
        ).fetchall()
    return _ok([{"company_name": r[0], "count": r[1]} for r in rows])


@app.get("/api/reports/contracts-by-type")
async def reports_contracts_by_type(user=Depends(require_auth)):
    """Contracts grouped by type with total value."""
    with get_db() as conn:
        rows = conn.execute(
            "SELECT contract_type as type, COUNT(*) as count "
            "FROM contracts GROUP BY contract_type ORDER BY count DESC"
        ).fetchall()
    return _ok([{"type": r[0], "count": r[1], "total_value": 0} for r in rows])


@app.get("/api/reports/contracts-by-status")
async def reports_contracts_by_status(user=Depends(require_auth)):
    """Contracts grouped by status."""
    with get_db() as conn:
        rows = conn.execute(
            "SELECT status, COUNT(*) as count FROM contracts "
            "GROUP BY status ORDER BY count DESC"
        ).fetchall()
    return _ok([{"status": r[0], "count": r[1]} for r in rows])


@app.get("/api/reports/export-csv")
async def reports_export_csv(user=Depends(require_auth)):
    """Export contracts report as CSV."""
    import csv
    import io
    with get_db() as conn:
        rows = conn.execute(
            "SELECT contract_name, counterparty, contract_type, status, "
            "amount, start_date, end_date FROM contracts ORDER BY id DESC"
        ).fetchall()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Contract", "Counterparty", "Type", "Status", "Value", "Start Date", "End Date"])
    for r in rows:
        writer.writerow([r[0], r[1], r[2], r[3], r[4], r[5], r[6]])
    return _ok(output.getvalue())


# ─── Pipeline Stages Info ────────────────────────────────────

@app.get("/api/pipeline/stages")
async def get_pipeline_stages(user=Depends(require_auth)):
    """Return available pipeline stages from DB."""
    with get_db() as conn:
        rows = conn.execute("SELECT name FROM pipeline_stages WHERE is_active=1 ORDER BY sort_order").fetchall()
    if rows:
        return _ok([r[0] for r in rows])
    return _ok(PIPELINE_STAGES)


# ─── Lead Scoring API ────────────────────────────────────────

def calculate_lead_score(lead_id):
    """Calculate lead score based on scoring rules."""
    with get_db() as conn:
        lead = conn.execute("SELECT * FROM leads WHERE id=?", (lead_id,)).fetchone()
        if not lead:
            return 0
        cols = [d[0] for d in conn.execute("SELECT * FROM leads LIMIT 0").description]
        lead_dict = dict(zip(cols, lead))

        rules = conn.execute("SELECT * FROM lead_scoring_rules WHERE is_active=1").fetchall()
        rule_cols = [d[0] for d in conn.execute("SELECT * FROM lead_scoring_rules LIMIT 0").description]

        total = 0
        details = {}
        for rule in rules:
            rd = dict(zip(rule_cols, rule))
            field = rd["field"]
            condition = rd["condition"]
            value = rd["value"]
            points = rd["points"]

            field_val = str(lead_dict.get(field, "")).strip()
            matched = False

            if condition == "equals":
                matched = field_val.lower() == value.lower()
            elif condition == "not_empty":
                matched = bool(field_val)
            elif condition == "contains":
                matched = value.lower() in field_val.lower()
            elif condition == "greater_than":
                try:
                    matched = float(field_val) > float(value)
                except: pass

            if matched:
                total += points
                details[f"{field}_{condition}_{value}"] = points

        # Activity-based scoring
        try:
            act_count = conn.execute(
                "SELECT COUNT(*) FROM activities WHERE lead_id=?", (lead_id,)
            ).fetchone()[0]
            if act_count > 0:
                act_points = min(act_count * 5, 20)  # +5 per activity, max +20
                total += act_points
                details["activities_count"] = act_points
            # Recent activity bonus (last 7 days)
            recent = conn.execute(
                "SELECT COUNT(*) FROM activities WHERE lead_id=? AND timestamp > datetime('now', '-7 days')",
                (lead_id,)
            ).fetchone()[0]
            if recent > 0:
                total += 10
                details["recent_activity_7d"] = 10
            # Decay: no activity for 30+ days
            if act_count > 0:
                last_act = conn.execute(
                    "SELECT MAX(timestamp) FROM activities WHERE lead_id=?", (lead_id,)
                ).fetchone()[0]
                if last_act:
                    from datetime import datetime as dt2
                    try:
                        days_since = (datetime.now() - dt2.fromisoformat(last_act.replace('Z',''))).days
                        if days_since > 30:
                            total -= 15
                            details["inactive_30d"] = -15
                    except: pass
        except Exception:
            pass

        total = max(0, min(100, total))
        now = datetime.now().isoformat()
        conn.execute("UPDATE leads SET score=?, score_details=?, last_scored_at=? WHERE id=?",
                     (total, json.dumps(details), now, lead_id))
        return total

@app.get("/api/lead-scoring-rules")
async def list_scoring_rules(user=Depends(require_auth)):
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM lead_scoring_rules ORDER BY id").fetchall()
        cols = [d[0] for d in conn.execute("SELECT * FROM lead_scoring_rules LIMIT 0").description]
        return _ok([dict(zip(cols, r)) for r in rows])

@app.post("/api/lead-scoring-rules")
async def create_scoring_rule(request: Request, user=Depends(require_admin)):
    data = await request.json()
    with get_db() as conn:
        conn.execute(
            "INSERT INTO lead_scoring_rules (field,condition,value,points,is_active) VALUES (?,?,?,?,?)",
            (data.get("field",""), data.get("condition",""), data.get("value",""),
             data.get("points",0), 1 if data.get("is_active", True) else 0)
        )
        rule_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    return _ok({"id": rule_id})

@app.put("/api/lead-scoring-rules/{rule_id}")
async def update_scoring_rule(rule_id: int, request: Request, user=Depends(require_admin)):
    data = await request.json()
    with get_db() as conn:
        updates, vals = [], []
        for f in ["field","condition","value","points","is_active"]:
            if f in data:
                updates.append(f"{f}=?")
                vals.append(data[f])
        if updates:
            vals.append(rule_id)
            conn.execute(f"UPDATE lead_scoring_rules SET {','.join(updates)} WHERE id=?", vals)
    return _ok({"message": "Rule updated"})

@app.delete("/api/lead-scoring-rules/{rule_id}")
async def delete_scoring_rule(rule_id: int, user=Depends(require_admin)):
    with get_db() as conn:
        conn.execute("DELETE FROM lead_scoring_rules WHERE id=?", (rule_id,))
    return _ok({"message": "Rule deleted"})

@app.post("/api/leads/{lead_id}/rescore")
async def rescore_lead(lead_id: int, user=Depends(require_auth)):
    score = calculate_lead_score(lead_id)
    return _ok({"lead_id": lead_id, "score": score})

@app.post("/api/leads/rescore-all")
async def rescore_all_leads(user=Depends(require_admin)):
    with get_db() as conn:
        leads = conn.execute("SELECT id FROM leads").fetchall()
    count = 0
    for (lid,) in leads:
        calculate_lead_score(lid)
        count += 1
    return _ok({"rescored": count})


# ─── Pricing Data ────────────────────────────────────────────────

@app.get("/api/pricing/data")
async def get_pricing_data(user=Depends(require_auth)):
    """Return pricing data for all companies."""
    pricing_file = os.path.join(STATIC_DIR, "pricing_data.json")
    try:
        with open(pricing_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        return _ok(data)
    except FileNotFoundError:
        _err("Pricing data not found", 404)


@app.put("/api/pricing/data")
async def save_pricing_data(request: Request, user=Depends(require_admin)):
    """Save updated pricing data."""
    pricing_file = os.path.join(STATIC_DIR, "pricing_data.json")
    data = await request.json()
    # Validate numeric fields in all companies
    for company_code, company_data in data.items():
        if isinstance(company_data, dict) and "categories" in company_data:
            for cat, cat_data in company_data["categories"].items():
                if isinstance(cat_data, dict):
                    if "total" in cat_data:
                        cat_data["total"] = _validate_numeric(cat_data["total"], f"{company_code}.{cat}.total")
                    if "services" in cat_data and isinstance(cat_data["services"], list):
                        for svc in cat_data["services"]:
                            if "price" in svc:
                                svc["price"] = _validate_numeric(svc["price"], f"{company_code}.{cat}.service.price")
                else:
                    data[company_code]["categories"][cat] = _validate_numeric(cat_data, f"{company_code}.{cat}")
    try:
        with open(pricing_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        _invalidate_ai_cache()
        return _ok({"saved": True})
    except Exception as e:
        logger.error(f"Failed to save pricing data: {e}")
        _err("Failed to save pricing data", 500)


@app.put("/api/pricing/company/{company_name}")
async def update_company_pricing(company_name: str, request: Request, user=Depends(require_admin)):
    """Update pricing for a single company."""
    pricing_file = os.path.join(STATIC_DIR, "pricing_data.json")
    try:
        with open(pricing_file, 'r', encoding='utf-8') as f:
            all_data = json.load(f)
    except FileNotFoundError:
        _err("Pricing data not found", 404)

    if company_name not in all_data:
        _err(f"Company '{company_name}' not found", 404)

    updates = await request.json()
    # New structure: categories = { "catName": { "total": N, "services": [...] } }
    # Old structure: categories = { "catName": N }
    if "categories" in updates:
        for cat, val in updates["categories"].items():
            if cat in all_data[company_name]["categories"]:
                if isinstance(val, dict):
                    # New nested structure with services
                    # Validate numeric values
                    if "total" in val:
                        val["total"] = _validate_numeric(val["total"], f"{cat}.total")
                    if "services" in val and isinstance(val["services"], list):
                        for svc in val["services"]:
                            if "price" in svc:
                                svc["price"] = _validate_numeric(svc["price"], f"{cat}.service.price")
                    all_data[company_name]["categories"][cat] = val
                else:
                    # Old flat structure (backward compat)
                    val = _validate_numeric(val, f"{cat}")
                    existing = all_data[company_name]["categories"][cat]
                    if isinstance(existing, dict):
                        existing["total"] = val
                    else:
                        all_data[company_name]["categories"][cat] = val
        # Recalculate monthly/annual
        total = 0
        for cat_val in all_data[company_name]["categories"].values():
            if isinstance(cat_val, dict):
                total += cat_val.get("total", 0)
            else:
                total += cat_val
        all_data[company_name]["monthly"] = round(total, 2)
        all_data[company_name]["annual"] = round(total * 12, 2)

    if "group" in updates:
        all_data[company_name]["group"] = updates["group"]

    with open(pricing_file, 'w', encoding='utf-8') as f:
        json.dump(all_data, f, ensure_ascii=False, indent=2)

    _invalidate_ai_cache()
    return _ok(all_data[company_name])


# ─── Pricing Excel Export ────────────────────────────────────────

@app.post("/api/pricing/export")
async def export_pricing_excel(request: Request, user=Depends(require_auth)):
    """Generate Excel export from pricing data with adjustments applied."""
    import sys, uuid, traceback
    from fastapi.responses import FileResponse
    # Ensure export_excel module is importable
    _api_dir = os.path.dirname(os.path.abspath(__file__))
    if _api_dir not in sys.path:
        sys.path.insert(0, _api_dir)

    try:
        from export_excel import load_data, generate_template1, generate_template2

        body = await request.json()
        template = body.get("template", "1")
        adjustments = body.get("adjustments", None)
        effective_date = body.get("effective_date", None)

        data, legal = load_data()
        uid = uuid.uuid4().hex[:8]
        export_dir = os.path.join(STATIC_DIR, "exports")
        os.makedirs(export_dir, exist_ok=True)

        if template == "2":
            path = os.path.join(export_dir, f"SALES_Report_{uid}.xlsx")
            generate_template2(data, legal, adjustments, path, effective_date=effective_date)
            fname = "SALES_Report.xlsx"
        else:
            path = os.path.join(export_dir, f"SALES_Template1_{uid}.xlsx")
            generate_template1(data, legal, adjustments, path, effective_date=effective_date)
            fname = "SALES_2026.xlsx"

        return FileResponse(path, filename=fname, media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
    except Exception as e:
        logger.error(f"Export failed: {traceback.format_exc()}")
        _err("Export failed", 500)


# ─── Parse Calculator XLSX (preview only, no save) ────────────

@app.post("/api/pricing/parse-calculator")
async def parse_calculator_upload(
    file: UploadFile = File(...),
    user=Depends(require_auth)
):
    """Parse an uploaded Excel calculator and return structured pricing data for comparison."""
    import sys, traceback, tempfile
    _api_dir = os.path.dirname(os.path.abspath(__file__))
    if _api_dir not in sys.path:
        sys.path.insert(0, _api_dir)

    try:
        from import_company import parse_calculator_sheet

        if not file.filename.endswith(('.xlsx', '.xlsm')):
            _err("Only .xlsx or .xlsm files are supported", 400)

        # Save to temp file
        with tempfile.NamedTemporaryFile(suffix='.xlsx', delete=False) as tmp:
            contents = await file.read()
            tmp.write(contents)
            tmp_path = tmp.name

        try:
            parsed = parse_calculator_sheet(tmp_path)
        finally:
            try:
                os.remove(tmp_path)
            except OSError:
                pass

        if not parsed.get("categories"):
            _err("No valid categories found in file", 400)

        return _ok(parsed)

    except Exception as e:
        logger.error(f"Parse calculator failed: {traceback.format_exc()}")
        _err(f"Parse failed: {str(e)}", 500)


# ─── Import Company from Excel Upload ──────────────────────────

@app.post("/api/pricing/import")
async def import_company_upload(
    file: UploadFile = File(...),
    company_name: str = Form(...),
    group_name: str = Form(...),
    legal_name: str = Form(""),
    user=Depends(require_auth)
):
    """Import a company from an uploaded Excel calculator file."""
    import sys, traceback, tempfile
    _api_dir = os.path.dirname(os.path.abspath(__file__))
    if _api_dir not in sys.path:
        sys.path.insert(0, _api_dir)

    try:
        from import_company import import_company

        # Validate file type
        if not file.filename.endswith(('.xlsx', '.xlsm')):
            _err("Only .xlsx or .xlsm files are supported", 400)

        # Sanitize filenames to prevent path traversal
        import re
        safe_company = re.sub(r'[^\w\-]', '_', company_name.strip())
        safe_filename = os.path.basename(file.filename or 'upload.xlsx')

        # Save uploaded file temporarily
        upload_dir = os.path.join(STATIC_DIR, "uploads")
        os.makedirs(upload_dir, exist_ok=True)
        tmp_path = os.path.join(upload_dir, f"import_{safe_company}_{safe_filename}")

        contents = await file.read()
        with open(tmp_path, "wb") as f:
            f.write(contents)

        try:
            # Import
            result = import_company(
                filepath=tmp_path,
                company_name=company_name.strip(),
                group_name=group_name.strip(),
                legal_name=legal_name.strip() if legal_name else None
            )
        finally:
            # Always cleanup temp file, even on error
            try:
                os.remove(tmp_path)
            except OSError:
                logger.warning(f"Failed to cleanup temp file: {tmp_path}")

        if result["success"]:
            return _ok(result)
        else:
            return _err(result["message"], 400)

    except Exception as e:
        logger.error(f"Import failed: {traceback.format_exc()}")
        return _err("Import failed", 500)


@app.delete("/api/pricing/company/{company_name}")
async def delete_pricing_company(company_name: str, user=Depends(require_admin)):
    """Delete a company from pricing data."""
    pricing_path = os.path.join(STATIC_DIR, "pricing_data.json")
    with open(pricing_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if company_name not in data:
        _err(f"Company '{company_name}' not found", 404)
    del data[company_name]
    with open(pricing_path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    return _ok({"message": f"Company '{company_name}' deleted", "remaining": len(data)})


@app.get("/api/pricing/groups")
async def get_pricing_groups(user=Depends(require_auth)):
    """Get list of available groups."""
    pricing_path = os.path.join(STATIC_DIR, "pricing_data.json")
    with open(pricing_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    groups = sorted(set(v.get("group", "Unknown") for v in data.values()))
    return _ok(groups)


@app.get("/api/pricing/crm-mapping")
async def get_pricing_crm_mapping(user=Depends(require_auth)):
    """Get full pricing-code → CRM-company mapping + list of all CRM client companies."""
    mapping_path = os.path.join(STATIC_DIR, "pricing_crm_mapping.json")
    if os.path.exists(mapping_path):
        with open(mapping_path, "r", encoding="utf-8") as f:
            mapping = json.load(f)
    else:
        mapping = {}
    # Also return all CRM client companies with group info
    with get_db() as conn:
        rows = conn.execute(
            "SELECT name, group_name FROM companies WHERE category='client' ORDER BY name"
        ).fetchall()
        clients = [{"name": r["name"], "group": r["group_name"] or ""} for r in rows]
    return _ok({"mapping": mapping, "crm_clients": clients})


@app.post("/api/pricing/crm-mapping")
async def update_pricing_crm_mapping(request: Request, user=Depends(require_auth)):
    """Update pricing-code → CRM-company mapping entries."""
    data = await request.json()
    updates = data.get("updates", {})  # {pricing_code: crm_company_name}
    mapping_path = os.path.join(STATIC_DIR, "pricing_crm_mapping.json")
    if os.path.exists(mapping_path):
        with open(mapping_path, "r", encoding="utf-8") as f:
            mapping = json.load(f)
    else:
        mapping = {}
    for code, crm_name in updates.items():
        if crm_name:
            mapping[code] = crm_name
        elif code in mapping:
            del mapping[code]
    with open(mapping_path, "w", encoding="utf-8") as f:
        json.dump(mapping, f, ensure_ascii=False, indent=2)
    return _ok({"mapping": mapping, "updated": len(updates)})


@app.get("/api/pricing/resolve-code/{code}")
async def resolve_pricing_code(code: str, user=Depends(require_auth)):
    """Resolve a pricing code to its mapped CRM company."""
    mapping_path = os.path.join(STATIC_DIR, "pricing_crm_mapping.json")
    if os.path.exists(mapping_path):
        with open(mapping_path, "r", encoding="utf-8") as f:
            mapping = json.load(f)
    else:
        mapping = {}
    crm_name = mapping.get(code)
    # If not in mapping, try direct match (case-insensitive) against CRM companies
    if not crm_name:
        with get_db() as conn:
            row = conn.execute(
                "SELECT name FROM companies WHERE LOWER(name) = LOWER(?) AND category='client' LIMIT 1",
                [code]
            ).fetchone()
            if row:
                crm_name = row["name"]
    return _ok({"code": code, "crm_company": crm_name, "mapped": crm_name is not None})


# ─── Price Changes (approval workflow) ────────────────────────

@app.get("/api/price-changes")
async def list_price_changes(
    status: Optional[str] = None,
    company_code: Optional[str] = None,
    user=Depends(require_auth),
):
    """List price change requests."""
    with get_db() as conn:
        where = ["1=1"]
        params = []
        if status:
            where.append("status = ?")
            params.append(status)
        if company_code:
            where.append("company_code = ?")
            params.append(company_code)
        rows = conn.execute(
            f"SELECT * FROM price_changes WHERE {' AND '.join(where)} ORDER BY created_at DESC",
            params,
        ).fetchall()
        return _ok([dict(r) for r in rows])


@app.post("/api/pricing/direct-save")
async def direct_save_pricing(request: Request, user=Depends(require_admin)):
    """Directly save manual price changes to pricing_data.json (no approval step).
    Also records the change in price_changes table with status='approved' for audit trail."""
    body = await request.json()
    company_code = body.get("company_code")
    new_prices = body.get("new_prices", {})
    notes = body.get("notes", "Birbasa saxlanildi (manual)")

    if not company_code:
        _err("company_code is required")
    if "categories" not in new_prices:
        _err("new_prices.categories is required")

    pricing_file = os.path.join(STATIC_DIR, "pricing_data.json")
    with open(pricing_file, "r", encoding="utf-8") as f:
        all_pricing = json.load(f)

    if company_code not in all_pricing:
        _err(f"Company '{company_code}' not found in pricing data", 404)

    old_prices = {
        "categories": all_pricing[company_code].get("categories", {}),
        "monthly_total": all_pricing[company_code].get("monthly_total", 0),
    }

    # Apply changes
    all_pricing[company_code]["categories"] = new_prices["categories"]
    if "monthly_total" in new_prices:
        all_pricing[company_code]["monthly_total"] = new_prices["monthly_total"]

    with open(pricing_file, "w", encoding="utf-8") as f:
        json.dump(all_pricing, f, ensure_ascii=False, indent=2)
    _invalidate_ai_cache()

    # Record in price_changes for audit trail (auto-approved)
    with get_db() as conn:
        conn.execute(
            "INSERT INTO price_changes (company_code, old_prices, new_prices, status, notes, created_by, approved_by, updated_at) "
            "VALUES (?,?,?,'approved',?,?,?,datetime('now'))",
            [company_code, json.dumps(old_prices, ensure_ascii=False),
             json.dumps(new_prices, ensure_ascii=False), notes,
             user.get("user_id"), user.get("user_id")],
        )

    return _ok({"message": "Qiymetler birbasa yenilendi", "monthly_total": new_prices.get("monthly_total", 0)})


@app.post("/api/price-changes")
async def create_price_change(request: Request, user=Depends(require_admin)):
    """Create a new price change request (pending approval or auto-approved from file upload)."""
    body = await request.json()
    company_code = body.get("company_code")
    new_prices = body.get("new_prices", {})
    notes = body.get("notes", "")
    effective_date = body.get("effective_date")
    auto_approve = body.get("auto_approve", False)
    if not company_code:
        _err("company_code is required")

    pricing_file = os.path.join(STATIC_DIR, "pricing_data.json")
    with open(pricing_file, "r", encoding="utf-8") as f:
        all_pricing = json.load(f)
    old_prices = all_pricing.get(company_code, {})

    status = "approved" if auto_approve else "pending"
    approved_by = user.get("user_id") if auto_approve else None

    with get_db() as conn:
        cur = conn.execute(
            "INSERT INTO price_changes (company_code, old_prices, new_prices, notes, effective_date, created_by, status, approved_by) VALUES (?,?,?,?,?,?,?,?)",
            [company_code, json.dumps(old_prices, ensure_ascii=False),
             json.dumps(new_prices, ensure_ascii=False), notes, effective_date, user.get("user_id"), status, approved_by]
        )
        pc_id = cur.lastrowid

        if auto_approve and "categories" in new_prices:
            if company_code in all_pricing:
                all_pricing[company_code]["categories"] = new_prices["categories"]
                if "monthly_total" in new_prices:
                    all_pricing[company_code]["monthly_total"] = new_prices["monthly_total"]
                with open(pricing_file, "w", encoding="utf-8") as f:
                    json.dump(all_pricing, f, ensure_ascii=False, indent=2)
                _invalidate_ai_cache()

        row = conn.execute("SELECT * FROM price_changes WHERE id=?", [pc_id]).fetchone()
        return _ok(dict(row))



@app.post("/api/price-changes/batch")
async def create_batch_price_changes(request: Request, user=Depends(require_auth)):
    """Create price changes for multiple companies at once (from pricing model tab)."""
    body = await request.json()
    companies = body.get("companies", [])  # list of company codes
    adjustments = body.get("adjustments", {})  # {global, groups, categories, companies}
    effective_date = body.get("effective_date")  # YYYY-MM-DD
    notes = body.get("notes", "")

    if not companies:
        _err("companies list is required")

    pricing_file = os.path.join(STATIC_DIR, "pricing_data.json")
    with open(pricing_file, "r", encoding="utf-8") as f:
        all_pricing = json.load(f)

    global_adj = 1 + (adjustments.get("global", 0) / 100)
    group_adjs = adjustments.get("groups", {})
    cat_adjs = adjustments.get("categories", {})
    comp_adjs = adjustments.get("companies", {})

    created = []
    with get_db() as conn:
        # Ensure effective_date column exists (migration may not have run yet)
        try:
            conn.execute("SELECT effective_date FROM price_changes LIMIT 1")
        except Exception:
            conn.execute("ALTER TABLE price_changes ADD COLUMN effective_date TEXT DEFAULT NULL")
            logger.info("Batch endpoint: added effective_date column on-demand")

        for code in companies:
            if code not in all_pricing:
                continue
            company = all_pricing[code]
            group = company.get("group", "")

            gr = 1 + (group_adjs.get(group, 0) / 100)
            co = 1 + (comp_adjs.get(code, 0) / 100)

            # Build new_prices with adjusted values
            new_cats = {}
            for cat_name, cat_data in company.get("categories", {}).items():
                cr = 1 + (cat_adjs.get(cat_name, 0) / 100)
                multiplier = global_adj * gr * cr * co
                if isinstance(cat_data, dict) and "services" in cat_data:
                    new_services = []
                    cat_total = 0
                    for svc in cat_data["services"]:
                        new_price = round(svc.get("price", 0) * multiplier, 2)
                        new_svc = {**svc, "price": new_price}
                        new_services.append(new_svc)
                        cat_total += new_svc.get("qty", 0) * new_price
                    new_cats[cat_name] = {"services": new_services, "total": round(cat_total, 2)}
                else:
                    val = cat_data.get("total", 0) if isinstance(cat_data, dict) else (cat_data or 0)
                    new_cats[cat_name] = round(val * multiplier, 2)

            new_monthly = sum(
                (c["total"] if isinstance(c, dict) else c) for c in new_cats.values()
            )
            new_prices = {"categories": new_cats, "monthly_total": round(new_monthly, 2)}

            cur = conn.execute(
                "INSERT INTO price_changes (company_code, old_prices, new_prices, notes, effective_date, created_by) VALUES (?,?,?,?,?,?)",
                [code, json.dumps(company, ensure_ascii=False),
                 json.dumps(new_prices, ensure_ascii=False), notes, effective_date, user.get("user_id")],
            )
            created.append({"id": cur.lastrowid, "company_code": code})

    return _ok({"created": len(created), "items": created})


@app.get("/api/price-changes/{pc_id}")
async def get_price_change(pc_id: int, user=Depends(require_auth)):
    """Get a single price change request."""
    with get_db() as conn:
        row = conn.execute("SELECT * FROM price_changes WHERE id=?", [pc_id]).fetchone()
        if not row:
            _err("Price change not found", 404)
        return _ok(dict(row))


@app.put("/api/price-changes/{pc_id}")
async def update_price_change(pc_id: int, request: Request, user=Depends(require_admin)):
    """Update price change (edit prices while pending, or change status)."""
    body = await request.json()
    with get_db() as conn:
        row = conn.execute("SELECT * FROM price_changes WHERE id=?", [pc_id]).fetchone()
        if not row:
            _err("Price change not found", 404)

        new_status = body.get("status")
        current_status = row["status"]

        # If approving — apply prices to pricing_data.json
        if new_status == "approved" and current_status == "pending":
            pricing_file = os.path.join(STATIC_DIR, "pricing_data.json")
            with open(pricing_file, "r", encoding="utf-8") as f:
                all_pricing = json.load(f)

            try:
                new_prices = json.loads(row["new_prices"]) if isinstance(row["new_prices"], str) else row["new_prices"]
            except json.JSONDecodeError:
                logger.error(f"Invalid JSON in new_prices for price change {pc_id}")
                new_prices = {}
            company_code = row["company_code"]
            if company_code in all_pricing and "categories" in new_prices:
                all_pricing[company_code]["categories"] = new_prices["categories"]
                if "monthly_total" in new_prices:
                    all_pricing[company_code]["monthly_total"] = new_prices["monthly_total"]
                with open(pricing_file, "w", encoding="utf-8") as f:
                    json.dump(all_pricing, f, ensure_ascii=False, indent=2)
                _invalidate_ai_cache()

            conn.execute(
                "UPDATE price_changes SET status='approved', approved_by=?, updated_at=datetime('now') WHERE id=?",
                [user.get("user_id"), pc_id],
            )
        elif new_status == "rejected" and current_status == "pending":
            conn.execute(
                "UPDATE price_changes SET status='rejected', updated_at=datetime('now') WHERE id=?",
                [pc_id],
            )
        else:
            # Update new_prices or notes while still pending
            updates = []
            params = []
            if "new_prices" in body and current_status == "pending":
                updates.append("new_prices=?")
                params.append(json.dumps(body["new_prices"], ensure_ascii=False))
            if "notes" in body:
                updates.append("notes=?")
                params.append(body["notes"])
            if updates:
                updates.append("updated_at=datetime('now')")
                params.append(pc_id)
                conn.execute(f"UPDATE price_changes SET {','.join(updates)} WHERE id=?", params)

        row = conn.execute("SELECT * FROM price_changes WHERE id=?", [pc_id]).fetchone()
        return _ok(dict(row))


@app.post("/api/price-changes/{pc_id}/export")
async def export_price_change_docx(pc_id: int, request: Request, user=Depends(require_auth)):
    """Export price change using the company's original agreement template with new prices."""
    import traceback as _tb
    try:
        import importlib, generate_contract as _gc_mod
        importlib.reload(_gc_mod)

        with get_db() as conn:
            row = conn.execute("SELECT * FROM price_changes WHERE id=?", [pc_id]).fetchone()
            if not row:
                _err("Price change not found", 404)

        company_code = row["company_code"]
        try:
            new_prices = json.loads(row["new_prices"]) if isinstance(row["new_prices"], str) else row["new_prices"]
        except json.JSONDecodeError:
            logger.error(f"Invalid JSON in new_prices for price change {pc_id}")
            new_prices = {}

        body = {}
        try:
            body = await request.json()
        except Exception:
            pass

        params = {k: v for k, v in body.items() if v}

        # Ensure every service has 'total' (fix for old records missing it)
        for cat in new_prices.get("categories", {}).values():
            for svc in cat.get("services", []):
                if not svc.get("total"):
                    svc["total"] = round(float(svc.get("qty", 0)) * float(svc.get("price", 0)), 2)

        # Use generate_contract with pricing_override to preserve original template design
        out_path = _gc_mod.generate_contract(
            company_code,
            params=params,
            pricing_override=new_prices,
        )

        import urllib.parse
        filename_encoded = urllib.parse.quote(os.path.basename(out_path), safe='')
        return FileResponse(
            out_path,
            media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            filename=os.path.basename(out_path),
            headers={"Content-Disposition": f"attachment; filename*=UTF-8''{filename_encoded}"}
        )
    except Exception as e:
        logger.error(f"Price change export failed: {_tb.format_exc()}")
        _err("Export failed", 500)


@app.post("/api/price-changes/{pc_id}/export-qrp")
async def export_price_change_qrp(pc_id: int, request: Request, user=Depends(require_auth)):
    """Export a price change as QRP agreement document using the new prices."""
    import traceback as _tb
    try:
        import importlib, generate_contract as _gc_mod
        importlib.reload(_gc_mod)
        _read_all_parts     = _gc_mod._read_all_parts
        _merge_runs         = _gc_mod._merge_runs
        _replace_variables  = _gc_mod._replace_variables
        _write_docx         = _gc_mod._write_docx

        with get_db() as conn:
            row = conn.execute("SELECT * FROM price_changes WHERE id=?", [pc_id]).fetchone()
            if not row:
                _err("Price change not found", 404)

        company_code = row["company_code"]
        try:
            new_prices = json.loads(row["new_prices"]) if isinstance(row["new_prices"], str) else row["new_prices"]
        except json.JSONDecodeError:
            logger.error(f"Invalid JSON in new_prices for price change {pc_id}")
            new_prices = {}

        # Ensure every service has 'total' (fix for old records missing it)
        for cat in new_prices.get("categories", {}).values():
            for svc in cat.get("services", []):
                if not svc.get("total"):
                    svc["total"] = round(float(svc.get("qty", 0)) * float(svc.get("price", 0)), 2)

        body = {}
        try:
            body = await request.json()
        except Exception:
            pass

        import unicodedata
        def _nfc(s): return unicodedata.normalize("NFC", s)

        templates_dir = os.path.join(BASE_DIR, "contract_templates")
        # Try company-specific QRP template first, then fall back to DEFAULT_QRP.docx
        qrp_path = os.path.join(templates_dir, f"{company_code}_QRP.docx")
        if not os.path.exists(qrp_path):
            qrp_path = os.path.join(templates_dir, f"{_nfc(company_code)}_QRP.docx")
        if not os.path.exists(qrp_path):
            qrp_path = os.path.join(templates_dir, "DEFAULT_QRP.docx")
        if not os.path.exists(qrp_path):
            _err("QRP template not found", 404)

        # Load company details
        details_path = os.path.join(STATIC_DIR, "company_details.json")
        details = {}
        if os.path.exists(details_path):
            with open(details_path, encoding="utf-8") as f:
                all_details = json.load(f)
            details = all_details.get(company_code) or {}
            if not details:
                details = next((v for k, v in all_details.items() if _nfc(k) == _nfc(company_code)), {})

        params = {k: v for k, v in body.items() if v}
        c = details.get("client", {})
        def _esc(s): return str(s).replace('&','&amp;').replace('<','&lt;').replace('>','&gt;')
        subs = {
            "legal_name":     c.get("legal_name", company_code),
            "voen":           c.get("voen", ""),
            "director_name":  c.get("director_name", ""),
            "director_title": c.get("director_title", "direktoru"),
            "bank":           c.get("bank", ""),
            "bank_voen":      c.get("bank_voen", ""),
            "bank_code":      c.get("bank_code", ""),
            "mh":             c.get("mh", ""),
            "hh":             c.get("hh", ""),
            "swift":          c.get("swift", ""),
            "contract_number": params.get("contract_number") or details.get("contract_number", ""),
            "contract_date":   params.get("contract_date") or details.get("contract_date", ""),
            "qrp_number":      params.get("annex_number") or details.get("annex_number", "02"),
            "signing_date":    params.get("signing_date") or details.get("signing_date", ""),
            "period_start":    params.get("period_start") or details.get("period_start", "01.01.2026"),
            "period_end":      params.get("period_end") or details.get("period_end", "31.12.2026"),
        }

        def _strip_il(s):
            s = str(s).strip()
            if s.endswith(" il"):
                s = s[:-3].rstrip()
            return s
        for date_key in ("contract_date", "signing_date"):
            if date_key in subs:
                subs[date_key] = _strip_il(subs[date_key])

        parts = _read_all_parts(qrp_path)
        raw_xml = parts.get("word/document.xml", b"").decode("utf-8")
        merged_xml = _merge_runs(raw_xml)
        filled_xml = merged_xml
        for key, val in subs.items():
            filled_xml = filled_xml.replace(_esc(f"{{{{{key}}}}}"), _esc(str(val)))

        # Now rebuild the price table with new_prices data
        # Re-use the generate_contract table-building logic with pricing override
        _get_tables = _gc_mod._get_tables
        rebuild_summary_table = _gc_mod.rebuild_summary_table
        rebuild_detail_table  = _gc_mod.rebuild_detail_table
        CAT_FULL_NAMES        = _gc_mod.CAT_FULL_NAMES

        categories = new_prices.get("categories", {})
        non_zero_cats = [
            (CAT_FULL_NAMES.get(k, k), v["total"])
            for k, v in categories.items()
            if v.get("total", 0) > 0
        ]
        has_service_data = any(
            s.get("total", 0) > 0
            for cat in categories.values()
            for s in cat.get("services", [])
        )

        tables_in_xml = _get_tables(filled_xml)
        if len(tables_in_xml) >= 2:
            new_tbl0 = rebuild_summary_table(tables_in_xml[0], non_zero_cats)
            filled_xml = filled_xml.replace(tables_in_xml[0], new_tbl0, 1)
            if has_service_data:
                tables_in_xml = _get_tables(filled_xml)
                new_tbl1 = rebuild_detail_table(tables_in_xml[1], non_zero_cats, categories)
                filled_xml = filled_xml.replace(tables_in_xml[1], new_tbl1, 1)

        annex = params.get("annex_number") or details.get("annex_number", "02")
        out_name = f"{company_code} - Guven Technology - QRP №{annex} - Yeni Qiymət.docx"
        out_path = os.path.join(BASE_DIR, "generated", out_name)
        os.makedirs(os.path.dirname(out_path), exist_ok=True)
        _write_docx(parts, filled_xml, out_path)

        import urllib.parse
        filename_encoded = urllib.parse.quote(os.path.basename(out_path), safe='')
        return FileResponse(
            out_path,
            media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            filename=os.path.basename(out_path),
            headers={"Content-Disposition": f"attachment; filename*=UTF-8''{filename_encoded}"}
        )
    except Exception as e:
        logger.error(f"Price change QRP export failed: {_tb.format_exc()}")
        _err("QRP export failed", 500)


# ─── Commercial Offers ────────────────────────────────────────

@app.get("/api/offers")
async def list_offers(
    q: str = Query("", description="Search query"),
    status: Optional[str] = None,
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    user=Depends(require_auth),
):
    """List offers with optional filtering."""
    with get_db() as conn:
        where = ["1=1"]
        params = []
        if q:
            where.append("(o.offer_number LIKE ? OR o.client_name LIKE ? OR c.name LIKE ?)")
            params += [f"%{q}%"] * 3
        if status:
            where.append("o.status = ?")
            params.append(status)
        where_sql = " AND ".join(where)
        rows = conn.execute(f"""
            SELECT o.*, c.name as company_name
            FROM offers o
            LEFT JOIN companies c ON o.company_id = c.id
            WHERE {where_sql}
            ORDER BY o.created_at DESC
            LIMIT ? OFFSET ?
        """, params + [limit, offset]).fetchall()
        total = conn.execute(f"SELECT COUNT(*) FROM offers o LEFT JOIN companies c ON o.company_id = c.id WHERE {where_sql}", params).fetchone()[0]
    return _ok([dict(r) for r in rows], total=total)


@app.get("/api/offers/{offer_id}")
async def get_offer(offer_id: int, user=Depends(require_auth)):
    """Get offer details."""
    with get_db() as conn:
        row = conn.execute("""
            SELECT o.*, c.name as company_name
            FROM offers o LEFT JOIN companies c ON o.company_id = c.id
            WHERE o.id = ?
        """, (offer_id,)).fetchone()
    if not row:
        _err("Offer not found", 404)
    return _ok(dict(row))


@app.post("/api/offers")
async def create_offer(request: Request, user=Depends(require_auth)):
    """Create a new offer."""
    data = await request.json()
    with get_db() as conn:
        # Generate next offer number
        year = datetime.now().year
        last = conn.execute(
            "SELECT offer_number FROM offers WHERE offer_number LIKE ? ORDER BY id DESC LIMIT 1",
            (f"GT-OFF-{year}-%",)
        ).fetchone()
        if last:
            try:
                seq = int(last[0].split("-")[-1]) + 1
            except (ValueError, IndexError, TypeError):
                seq = 1
        else:
            seq = 1
        offer_number = f"GT-OFF-{year}-{seq:03d}"

        conn.execute("""
            INSERT INTO offers (offer_number, offer_type, currency, show_vat, vat_pct,
                view_mode, company_id, client_name, client_voen, client_contact,
                client_contract, notes, status, items, valid_until, created_by)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
            offer_number,
            data.get("offer_type", "services"),
            data.get("currency", "AZN"),
            1 if data.get("show_vat") else 0,
            data.get("vat_pct", 18),
            data.get("view_mode", "detailed"),
            data.get("company_id") or None,
            data.get("client_name", ""),
            data.get("client_voen", ""),
            data.get("client_contact", ""),
            data.get("client_contract", ""),
            data.get("notes", ""),
            data.get("status", "draft"),
            json.dumps(data.get("items", []), ensure_ascii=False),
            data.get("valid_until", ""),
            user["user_id"],
        ))
        offer_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    log_audit(user["user_id"], "create_offer", "offer", offer_id, ip=_get_ip(request))
    return _ok({"id": offer_id, "offer_number": offer_number})


@app.put("/api/offers/{offer_id}")
async def update_offer(offer_id: int, request: Request, user=Depends(require_auth)):
    """Update an offer."""
    data = await request.json()
    with get_db() as conn:
        existing = conn.execute("SELECT id FROM offers WHERE id = ?", (offer_id,)).fetchone()
        if not existing:
            _err("Offer not found", 404)
        conn.execute("""
            UPDATE offers SET
                offer_type=?, currency=?, show_vat=?, vat_pct=?,
                view_mode=?, company_id=?, client_name=?, client_voen=?,
                client_contact=?, client_contract=?, notes=?, status=?,
                items=?, valid_until=?, updated_at=datetime('now')
            WHERE id=?
        """, (
            data.get("offer_type", "services"),
            data.get("currency", "AZN"),
            1 if data.get("show_vat") else 0,
            data.get("vat_pct", 18),
            data.get("view_mode", "detailed"),
            data.get("company_id") or None,
            data.get("client_name", ""),
            data.get("client_voen", ""),
            data.get("client_contact", ""),
            data.get("client_contract", ""),
            data.get("notes", ""),
            data.get("status", "draft"),
            json.dumps(data.get("items", []), ensure_ascii=False),
            data.get("valid_until", ""),
            offer_id,
        ))
    log_audit(user["user_id"], "update_offer", "offer", offer_id, ip=_get_ip(request))
    return _ok({"id": offer_id})


@app.delete("/api/offers/{offer_id}")
async def delete_offer(offer_id: int, request: Request, user=Depends(require_auth)):
    """Delete an offer."""
    with get_db() as conn:
        conn.execute("DELETE FROM offers WHERE id = ?", (offer_id,))
    log_audit(user["user_id"], "delete_offer", "offer", offer_id, ip=_get_ip(request))
    return _ok({"deleted": True})


@app.post("/api/offers/{offer_id}/pdf")
async def generate_offer_pdf_endpoint(offer_id: int, request: Request, user=Depends(require_auth)):
    """Generate PDF for an offer."""
    with get_db() as conn:
        row = conn.execute("SELECT * FROM offers WHERE id = ?", (offer_id,)).fetchone()
    if not row:
        _err("Offer not found", 404)
    offer = dict(row)
    try:
        items = json.loads(offer.get("items", "[]"))
    except json.JSONDecodeError:
        logger.error(f"Invalid JSON in items for offer {offer_id}")
        items = []

    try:
        from gen_offer_pdf_api import generate_offer_pdf as _gen_pdf

        out_dir = os.path.join(BASE_DIR, "generated")
        os.makedirs(out_dir, exist_ok=True)
        out_path = os.path.join(out_dir, f"offer_{offer['offer_number']}.pdf")

        _gen_pdf(offer, items, out_path)

        return FileResponse(
            out_path,
            media_type="application/pdf",
            filename=f"{offer['offer_number']}.pdf",
            headers={"Content-Disposition": f'attachment; filename="{offer["offer_number"]}.pdf"'}
        )
    except Exception as e:
        logger.error(f"PDF generation failed for offer {offer_id}: {e}")
        import traceback
        logger.error(traceback.format_exc())
        raise HTTPException(status_code=500, detail="PDF generation failed")


# ═══════════════════════════════════════════════════════════════
# COST MODEL MODULE
# ═══════════════════════════════════════════════════════════════

def _compute_cost_model(conn):
    """Compute full cost model matching GT_Pricing_Calculator_v2.xlsx logic.

    Excel model structure:
    - Section F: Core maya (overhead + IT/InfoSec/Zəng) + Ezam 1% + Risk 5%
    - Section G: Admin overhead (headcount-based allocation) + direct costs per dept
    - Admin overhead = non-tech items (rent, insurance, mobile, backoffice, car, training, AI, GRC, laptop, internet, fw_amort, team_building)
    - Tech infrastructure = cloud, cortex, MS, ServiceDesk, FW license, PAM, LMS → direct to departments
    """
    params = conn.execute("SELECT * FROM pricing_parameters WHERE id=1").fetchone()
    if not params:
        return None
    params = dict(params)

    vat = params["vat_rate"]
    emp_tax = params["employer_tax_rate"]
    risk = params["risk_rate"]
    misc_rate = params["misc_expense_rate"]
    fixed_ratio = params["fixed_overhead_ratio"]
    variable_ratio = 1.0 - fixed_ratio
    total_users_param = params["total_users"]
    # Portfolio users = sum of user_count from client companies (manually set)
    portfolio_users_row = conn.execute(
        "SELECT COALESCE(SUM(user_count),0) FROM companies WHERE category='client' AND user_count > 0"
    ).fetchone()
    portfolio_users = portfolio_users_row[0] if portfolio_users_row else 0
    # If manual mode enabled — always use the parameter; otherwise use portfolio sum if available
    # Always use portfolio sum (no manual override)
    total_users = portfolio_users if portfolio_users > 0 else total_users_param

    # --- Overhead costs: separate ADMIN vs TECH ---
    try:
        conn.execute("SELECT is_admin FROM overhead_costs LIMIT 1")
    except Exception:
        conn.execute("ALTER TABLE overhead_costs ADD COLUMN is_admin INTEGER DEFAULT 1")

    oh_rows = conn.execute("SELECT * FROM overhead_costs ORDER BY sort_order").fetchall()
    admin_overhead = 0.0      # Allocated by headcount (Section G)
    tech_infra_total = 0.0    # Direct to departments
    overhead_breakdown = []
    for row in oh_rows:
        r = dict(row)
        amt = r["amount"]
        if r["is_annual"]:
            amt = amt / 12
        if r["has_vat"]:
            amt = amt * (1 + vat)
        if r["category"] in ("insurance", "mobile"):
            amt = amt * params["total_employees"]
        r["monthly_amount"] = round(amt, 2)
        is_admin = r.get("is_admin", 1)
        if is_admin:
            admin_overhead += amt
        else:
            tech_infra_total += amt
        overhead_breakdown.append(r)

    # --- Employee costs ---
    employees = conn.execute("SELECT * FROM cost_employees").fetchall()
    employees = [dict(e) for e in employees]

    income_tax_rate = 0.14
    dept_costs = {}        # department -> direct labor cost
    back_office_cost = 0.0
    grc_direct_cost = 0.0

    for emp in employees:
        net = emp["net_salary"]
        count = emp["count"]
        gross = net / (1 - income_tax_rate)
        super_gross = gross * (1 + emp_tax)
        total_dept = count * super_gross

        emp["gross_salary"] = round(gross, 2)
        emp["super_gross"] = round(super_gross, 2)
        emp["total_labor_cost"] = round(total_dept, 2)

        dept = emp["department"]
        if dept == "BackOffice":
            back_office_cost += total_dept
        elif emp["in_overhead"]:
            grc_direct_cost += total_dept
        else:
            dept_costs[dept] = dept_costs.get(dept, 0.0) + total_dept

    # --- Admin overhead for allocation ---
    # Section F uses admin items + BackOffice (excl GRC)
    admin_for_f = admin_overhead + back_office_cost
    # Section G uses admin items + BackOffice + GRC (matches Excel 221,047.74)
    admin_for_g = admin_overhead + back_office_cost + grc_direct_cost

    # Total overhead for display
    total_overhead = admin_for_g + tech_infra_total

    # --- Section F: Core maya (Ümumi Maya) ---
    # Only overhead + core engineers (IT + InfoSec + Zəng, excl HelpDesk/ERP/PM/GRC)
    core_labor = dept_costs.get("IT", 0) + dept_costs.get("InfoSec", 0)
    section_f_subtotal = admin_for_f + tech_infra_total + core_labor
    misc = section_f_subtotal * misc_rate
    risk_cost = (section_f_subtotal + misc) * risk
    grand_total_f = section_f_subtotal + misc + risk_cost

    # --- Section G: Department cost distribution ---
    # Admin overhead (221k) allocated by headcount; specific tech items assigned to departments
    all_dept_employees = [e for e in employees if e["department"] != "BackOffice"]
    total_headcount = sum(e["count"] for e in all_dept_employees)

    SERVICE_DEPT_MAP = {
        "permanent_it": ["IT"],
        "infosec": ["InfoSec"],
        "erp": ["ERP"],
        "grc": ["GRC"],
        "projects": ["PM"],
        "helpdesk": ["HelpDesk"],
        "cloud": [],
    }

    # Tech items assigned to specific departments (matches Excel Section G)
    # Cloud + MS → IT direct; Cortex + FW_amort → InfoSec direct
    TECH_DEPT_MAP = {
        "cloud": "cloud",
        "ms_license": "permanent_it",
        "cortex": "infosec",
        "fw_amort": "infosec",
    }
    # Build per-service tech costs from overhead breakdown
    svc_tech_costs = {}
    for oh in overhead_breakdown:
        target_svc = TECH_DEPT_MAP.get(oh["category"])
        if target_svc:
            svc_tech_costs[target_svc] = svc_tech_costs.get(target_svc, 0.0) + oh["monthly_amount"]

    service_costs = {}
    for svc, depts in SERVICE_DEPT_MAP.items():
        direct_labor = sum(dept_costs.get(d, 0.0) for d in depts)
        # GRC direct labor included (Excel includes it as Birbaşa Xərc)
        if svc == "grc":
            direct_labor = grc_direct_cost
        dept_headcount = sum(e["count"] for e in all_dept_employees if e["department"] in depts)
        ratio = dept_headcount / total_headcount if total_headcount > 0 else 0
        admin_share = admin_for_g * ratio
        tech_direct = svc_tech_costs.get(svc, 0.0)
        service_costs[svc] = round(direct_labor + admin_share + tech_direct, 2)

    # Section G total (all departments)
    grand_total_g = sum(service_costs.values())

    # For backward compat / display, store admin_overhead as the G allocation value
    admin_overhead = admin_for_g

    # Use Section G grand total for client margins, Section F for per-user cost
    grand_total = grand_total_g

    # --- Load HelpDesk revenue from pricing_data.json ---
    pricing_path = os.path.join(STATIC_DIR, "pricing_data.json")
    helpdesk_by_company_id = {}
    erp_from_hd_by_company_id = {}
    pricing_total_by_company_id = {}

    # Load dynamic pricing-code → CRM company mapping
    mapping_path = os.path.join(STATIC_DIR, "pricing_crm_mapping.json")
    PRICING_TO_CRM = {}
    if os.path.exists(mapping_path):
        with open(mapping_path, encoding="utf-8") as mf:
            raw_mapping = json.load(mf)
        # Convert CRM names to lowercase for matching
        PRICING_TO_CRM = {k: v.lower() for k, v in raw_mapping.items()}

    if os.path.exists(pricing_path):
        with open(pricing_path, encoding="utf-8") as f:
            pricing_json = json.load(f)

        # Build CRM name -> company id map
        crm_name_to_id = {}
        for cl_row in conn.execute("SELECT id, name FROM companies WHERE category='client'").fetchall():
            crm_name_to_id[cl_row["name"].lower()] = cl_row["id"]

        for pcode, pdata in pricing_json.items():
            cats = pdata.get("categories", {})
            # HelpDesk = ONLY services with "HelpDesk Level" in name
            # ERP += services with "Informational Systems Support Specialist"
            # Everything else in this category stays as Daimi (core revenue)
            hd_cat = cats.get("HelpDesk və Texniki Dəstək", {})
            hd_total = 0.0
            erp_from_hd = 0.0
            for svc in hd_cat.get("services", []):
                svc_total = svc.get("qty", 0) * svc.get("price", 0)
                svc_name = svc.get("name", "")
                if "HelpDesk Level" in svc_name:
                    hd_total += svc_total
                elif "ITAM" in svc_name:
                    hd_total += svc_total
                elif "Informational Systems Support" in svc_name or "İnformational Systems Support" in svc_name:
                    erp_from_hd += svc_total
            # Add ERP services from HelpDesk category to ERP totals
            # (Avtomatlaşdırılmış Sistemlər + SaaS are already counted as ERP via category totals)

            all_total = sum(c.get("total", 0) for c in cats.values() if isinstance(c, dict))

            crm_name = PRICING_TO_CRM.get(pcode, pcode.lower())
            company_id = crm_name_to_id.get(crm_name)
            if company_id:
                # Accumulate in case multiple pricing codes map to same company (e.g. HILTON GARDEN AGHDAM)
                helpdesk_by_company_id[company_id] = helpdesk_by_company_id.get(company_id, 0.0) + hd_total
                erp_from_hd_by_company_id[company_id] = erp_from_hd_by_company_id.get(company_id, 0.0) + erp_from_hd
                pricing_total_by_company_id[company_id] = pricing_total_by_company_id.get(company_id, 0.0) + all_total

    # --- Client-level margin calculation ---
    active_clients = conn.execute("""
        SELECT c.id, c.name, c.cost_code, c.user_count,
               COALESCE((SELECT SUM(cs.monthly_revenue) FROM client_services cs
                         WHERE cs.company_id = c.id AND cs.is_active=1), 0) as total_revenue
        FROM companies c
        WHERE c.category='client'
    """).fetchall()

    # Count clients that have ANY revenue (from client_services OR pricing_data.json)
    clients_with_db_revenue = set(cl["id"] for cl in active_clients if dict(cl)["total_revenue"] > 0)
    clients_with_pricing_revenue = set(pricing_total_by_company_id.keys())
    total_active_clients = len(clients_with_db_revenue | clients_with_pricing_revenue)
    if total_active_clients == 0:
        total_active_clients = max(1, len(active_clients))

    client_data = []
    for cl in active_clients:
        cl = dict(cl)
        users = cl["user_count"] or 0
        db_revenue = cl["total_revenue"] or 0
        fixed_cost = grand_total * fixed_ratio / total_active_clients
        variable_cost = grand_total * variable_ratio * users / total_users if total_users > 0 else 0
        total_cost = fixed_cost + variable_cost

        # Get service breakdown
        svcs = conn.execute(
            "SELECT service_type, monthly_revenue FROM client_services WHERE company_id=? AND is_active=1",
            [cl["id"]]
        ).fetchall()
        services = {s["service_type"]: s["monthly_revenue"] for s in svcs}

        # Lookup HelpDesk revenue from pricing_data.json (mapped by company_id)
        hd_rev = helpdesk_by_company_id.get(cl["id"], 0.0)
        erp_from_hd_rev = erp_from_hd_by_company_id.get(cl["id"], 0.0)
        pricing_rev = pricing_total_by_company_id.get(cl["id"], 0.0)

        # pricing_data.json = contract pricing (59 companies) — primary source
        # client_services = Excel budget (40 companies) — fallback
        effective_revenue = pricing_rev if pricing_rev > 0 else db_revenue
        margin = effective_revenue - total_cost
        margin_pct = (margin / effective_revenue * 100) if effective_revenue > 0 else None

        core_revenue = pricing_rev - hd_rev - erp_from_hd_rev if pricing_rev > 0 else effective_revenue - hd_rev - erp_from_hd_rev
        core_margin = core_revenue - total_cost

        if margin_pct is None:
            status = "no_revenue"
        elif margin_pct >= 15:
            status = "good"
        elif margin_pct >= 0:
            status = "low"
        else:
            status = "loss"

        client_data.append({
            **cl,
            "total_revenue": round(effective_revenue, 2),
            "db_revenue": round(db_revenue, 2),
            "fixed_cost": round(fixed_cost, 2),
            "variable_cost": round(variable_cost, 2),
            "total_cost": round(total_cost, 2),
            "margin": round(margin, 2),
            "margin_pct": round(margin_pct, 2) if margin_pct is not None else None,
            "helpdesk_revenue": round(hd_rev, 2),
            "erp_from_hd_revenue": round(erp_from_hd_rev, 2),
            "pricing_revenue": round(pricing_rev, 2),
            "core_revenue": round(core_revenue, 2),
            "core_margin": round(core_margin, 2),
            "status": status,
            "services": services,
        })

    # --- Service analytics ---
    service_analytics = []
    for svc, cost in service_costs.items():
        svc_revenue = conn.execute(
            "SELECT COALESCE(SUM(monthly_revenue),0) FROM client_services WHERE service_type=? AND is_active=1",
            [svc]
        ).fetchone()[0]
        svc_clients = conn.execute(
            "SELECT COUNT(DISTINCT company_id) FROM client_services WHERE service_type=? AND monthly_revenue>0 AND is_active=1",
            [svc]
        ).fetchone()[0]
        balance = svc_revenue - cost
        svc_emp = sum(e["count"] for e in employees if e["department"] in SERVICE_DEPT_MAP.get(svc, []))
        service_analytics.append({
            "service": svc,
            "cost": round(cost, 2),
            "revenue": round(svc_revenue, 2),
            "balance": round(balance, 2),
            "balance_pct": round(balance / cost * 100, 2) if cost > 0 else 0,
            "employee_count": svc_emp,
            "client_count": svc_clients,
            "status": "profit" if balance >= 0 else "loss",
        })

    total_revenue = sum(c["total_revenue"] for c in client_data)
    total_margin = total_revenue - grand_total
    profitable_clients = sum(1 for c in client_data if c["status"] == "good")
    loss_clients = sum(1 for c in client_data if c["status"] == "loss")
    # Portfolio user count (sum of actual user_count from clients)
    portfolio_users = sum(c.get("user_count", 0) or 0 for c in client_data)
    clients_with_revenue = sum(1 for c in client_data if c["total_revenue"] > 0 or c.get("pricing_revenue", 0) > 0)

    # --- HelpDesk profitability summary ---
    total_helpdesk_revenue = sum(c.get("helpdesk_revenue", 0) for c in client_data)
    total_pricing_revenue = sum(c.get("pricing_revenue", 0) for c in client_data)
    total_core_revenue = total_pricing_revenue - total_helpdesk_revenue
    helpdesk_cost = service_costs.get("helpdesk", 0.0)
    helpdesk_profit = total_helpdesk_revenue - helpdesk_cost
    helpdesk_clients = [c for c in client_data if c.get("helpdesk_revenue", 0) > 0]

    helpdesk_summary = {
        "total_revenue": round(total_helpdesk_revenue, 2),
        "cost": round(helpdesk_cost, 2),
        "profit": round(helpdesk_profit, 2),
        "profit_pct": round(helpdesk_profit / helpdesk_cost * 100, 2) if helpdesk_cost > 0 else 0,
        "client_count": len(helpdesk_clients),
        "total_pricing_revenue": round(total_pricing_revenue, 2),
        "total_core_revenue": round(total_core_revenue, 2),
        "clients": sorted(
            [{"name": c["name"], "id": c["id"], "helpdesk_revenue": c["helpdesk_revenue"],
              "pricing_revenue": c["pricing_revenue"], "core_revenue": c["core_revenue"],
              "total_cost": c["total_cost"], "core_margin": c["core_margin"],
              "user_count": c.get("user_count", 0) or 0}
             for c in helpdesk_clients],
            key=lambda x: x["helpdesk_revenue"], reverse=True
        ),
    }

    return {
        "params": params,
        "overhead_breakdown": overhead_breakdown,
        "total_overhead": round(total_overhead, 2),
        "admin_overhead": round(admin_overhead, 2),
        "tech_infra_total": round(tech_infra_total, 2),
        "employees": employees,
        "dept_costs": {k: round(v, 2) for k, v in dept_costs.items()},
        "section_f_subtotal": round(section_f_subtotal, 2),
        "misc": round(misc, 2),
        "risk_cost": round(risk_cost, 2),
        "grand_total_f": round(grand_total_f, 2),
        "grand_total_g": round(grand_total_g, 2),
        "grand_total": round(grand_total, 2),
        "cost_per_user_f": round(grand_total_f / total_users, 2) if total_users > 0 else 0,
        "cost_per_user": round(grand_total / total_users, 2) if total_users > 0 else 0,
        "total_users": total_users,
        "portfolio_users": portfolio_users,
        "service_costs": {k: round(v, 2) for k, v in service_costs.items()},
        "service_analytics": service_analytics,
        "client_data": client_data,
        "helpdesk_summary": helpdesk_summary,
        "summary": {
            "total_clients": len(client_data),
            "active_clients_with_revenue": total_active_clients,
            "total_revenue": round(total_revenue, 2),
            "grand_total_cost": round(grand_total, 2),
            "grand_total_f": round(grand_total_f, 2),
            "grand_total_g": round(grand_total_g, 2),
            "total_margin": round(total_margin, 2),
            "margin_pct": round(total_margin / total_revenue * 100, 2) if total_revenue > 0 else 0,
            "profitable_clients": profitable_clients,
            "loss_clients": loss_clients,
        },
    }


def _ensure_cost_model_tables(conn):
    """Create cost model tables and seed defaults if missing."""
    conn.execute("""CREATE TABLE IF NOT EXISTS pricing_parameters (
        id INTEGER PRIMARY KEY DEFAULT 1,
        total_users INTEGER DEFAULT 4500,
        total_users_manual INTEGER DEFAULT 0,
        total_employees INTEGER DEFAULT 137,
        technical_staff INTEGER DEFAULT 107,
        back_office_staff INTEGER DEFAULT 30,
        monthly_work_hours INTEGER DEFAULT 160,
        vat_rate REAL DEFAULT 0.18,
        employer_tax_rate REAL DEFAULT 0.175,
        risk_rate REAL DEFAULT 0.05,
        misc_expense_rate REAL DEFAULT 0.01,
        fixed_overhead_ratio REAL DEFAULT 0.25,
        updated_at TEXT DEFAULT (datetime('now')),
        updated_by INTEGER REFERENCES users(id)
    )""")
    conn.execute("""CREATE TABLE IF NOT EXISTS overhead_costs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        category TEXT NOT NULL,
        label TEXT NOT NULL,
        amount REAL DEFAULT 0,
        is_annual INTEGER DEFAULT 0,
        has_vat INTEGER DEFAULT 0,
        is_admin INTEGER DEFAULT 1,
        sort_order INTEGER DEFAULT 0,
        notes TEXT DEFAULT ''
    )""")
    conn.execute("""CREATE TABLE IF NOT EXISTS cost_employees (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        department TEXT NOT NULL,
        position TEXT NOT NULL,
        count INTEGER DEFAULT 1,
        net_salary REAL DEFAULT 0,
        gross_salary REAL DEFAULT 0,
        super_gross REAL DEFAULT 0,
        in_overhead INTEGER DEFAULT 0,
        notes TEXT DEFAULT ''
    )""")
    conn.execute("""CREATE TABLE IF NOT EXISTS client_services (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        company_id INTEGER REFERENCES companies(id) ON DELETE CASCADE,
        company_code TEXT NOT NULL,
        service_type TEXT NOT NULL,
        monthly_revenue REAL DEFAULT 0,
        is_active INTEGER DEFAULT 1,
        notes TEXT DEFAULT ''
    )""")
    conn.execute("""CREATE TABLE IF NOT EXISTS cost_model_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        table_name TEXT,
        record_id INTEGER,
        action TEXT,
        old_value TEXT,
        new_value TEXT,
        changed_by INTEGER REFERENCES users(id),
        changed_at TEXT DEFAULT (datetime('now'))
    )""")
    # Add is_admin column to overhead_costs if missing
    try:
        conn.execute("SELECT is_admin FROM overhead_costs LIMIT 1")
    except Exception:
        conn.execute("ALTER TABLE overhead_costs ADD COLUMN is_admin INTEGER DEFAULT 1")
        # Set tech infra items to is_admin=0
        tech_cats = ("cloud", "cortex", "ms_license", "service_desk", "fw_license", "pam", "lms")
        for tc in tech_cats:
            conn.execute("UPDATE overhead_costs SET is_admin=0 WHERE category=?", [tc])
    # Add columns to companies if missing
    try:
        conn.execute("SELECT user_count FROM companies LIMIT 1")
    except Exception:
        conn.execute("ALTER TABLE companies ADD COLUMN user_count INTEGER DEFAULT 0")
    try:
        conn.execute("SELECT cost_code FROM companies LIMIT 1")
    except Exception:
        conn.execute("ALTER TABLE companies ADD COLUMN cost_code TEXT DEFAULT ''")
    # Seed pricing_parameters if empty
    row = conn.execute("SELECT id FROM pricing_parameters WHERE id=1").fetchone()
    if not row:
        conn.execute("""INSERT OR IGNORE INTO pricing_parameters
            (id, total_users, total_employees, technical_staff, back_office_staff,
             monthly_work_hours, vat_rate, employer_tax_rate, risk_rate, misc_expense_rate, fixed_overhead_ratio)
            VALUES (1, 4500, 137, 107, 30, 160, 0.18, 0.175, 0.05, 0.01, 0.25)""")
    # Seed overhead_costs if empty — data from GT_Pricing_Calculator_v2.xlsx Section B+C+F
    oh_count = conn.execute("SELECT COUNT(*) FROM overhead_costs").fetchone()[0]
    if oh_count == 0:
        overhead_defaults = [
            # (category, label, amount, is_annual, has_vat, is_admin, sort_order, notes)
            # is_admin=0 = Tech Infrastructure (direct to departments)
            # is_admin=1 = Admin overhead (allocated by headcount)
            ("cloud", "Bulud serverləri", 20000, 0, 1, 0, 1, "AZN/ay, ƏDV xaric"),
            ("rent", "Ofis icarəsi", 30000, 0, 0, 1, 2, "AZN/ay birbaşa"),
            ("insurance", "Sığorta (işçi başına)", 40, 0, 0, 1, 3, "×işçi sayı"),
            ("mobile", "Mobil rabitə (işçi başına)", 30, 0, 0, 1, 4, "×işçi sayı"),
            ("cortex", "Cortex/Crowdstrike", 500000, 1, 1, 0, 5, "İllik, ƏDV xaric"),
            ("ms_license", "MS Lisenziya", 6800, 0, 1, 0, 6, "AZN/ay, ƏDV xaric"),
            ("service_desk", "Service Desk", 50000, 1, 1, 0, 7, "İllik, ƏDV xaric"),
            ("car_amort", "Maşın amortizasiyası", 2500, 0, 0, 1, 8, "CAPEX 150k÷60 ay"),
            ("car_expense", "Maşın cari xərcləri", 1200, 0, 0, 1, 9, "Benzin+servis"),
            ("fw_amort", "Firewall amortizasiyası", 1547.62, 0, 0, 1, 10, "CAPEX 130k÷84 ay"),
            ("fw_license", "Firewall Palo Alto lisenziya", 76000, 1, 1, 0, 11, "İllik, ƏDV xaric"),
            ("pam", "PAM lisenziya", 40000, 1, 1, 0, 12, "İllik, ƏDV xaric"),
            ("lms", "LMS platforma", 50000, 1, 1, 0, 13, "İllik, ƏDV xaric"),
            ("training", "Treninqlər", 250000, 1, 0, 1, 14, "İllik, ƏDV yoxdur"),
            ("ai_license", "AI lisenziyaları", 3800, 1, 1, 1, 15, "İllik, ƏDV xaric"),
            ("laptop", "Laptop xərci", 8500, 0, 0, 1, 16, "AZN/ay sabit"),
            ("internet", "İnternet xərci", 439, 0, 0, 1, 17, "AZN/ay sabit"),
            ("team_building", "Team building", 120000, 1, 0, 1, 18, "İllik, ƏDV yoxdur"),
        ]
        for cat, label, amt, is_annual, has_vat, is_admin, sort_order, notes in overhead_defaults:
            conn.execute("INSERT INTO overhead_costs (category, label, amount, is_annual, has_vat, is_admin, sort_order, notes) VALUES (?,?,?,?,?,?,?,?)",
                         [cat, label, amt, is_annual, has_vat, is_admin, sort_order, notes])
    # Seed cost_employees if empty — data from GT_Pricing_Calculator_v2.xlsx Section D
    emp_count = conn.execute("SELECT COUNT(*) FROM cost_employees").fetchone()[0]
    if emp_count == 0:
        income_tax = 0.14
        emp_tax = 0.175
        # (dept, position, count, gross_salary, in_overhead, notes)
        default_employees = [
            ("BackOffice", "HR, Maliyyə, Hüquq, Sürücü", 1, 0, 0, "Cəm NET=80000"),
            ("HelpDesk", "HelpDesk mühəndis", 56, 2017.75, 0, ""),
            ("IT", "SysAdmin", 8, 3479.11, 0, ""),
            ("IT", "NetAdmin", 8, 4112.03, 0, ""),
            ("InfoSec", "InfoSec mütəxəssis", 12, 4187.97, 0, ""),
            ("IT", "Zəng Mərkəzi", 4, 2017.75, 0, "IT-yə daxildir"),
            ("ERP", "ERP komanda", 6, 3694.00, 0, ""),
            ("PM", "PM komanda", 5, 3940.00, 0, ""),
            ("GRC", "GRC komanda", 8, 2847.00, 1, "Overhead-ə daxildir"),
        ]
        for dept, pos, count, gross, in_overhead, notes in default_employees:
            if dept == "BackOffice" and gross == 0:
                # Back-office is a lump sum: NET=80000 total
                net = 80000
                gross_calc = net / (1 - income_tax)
                super_gross = gross_calc * (1 + emp_tax)
            else:
                net = gross * (1 - income_tax)
                gross_calc = gross
                super_gross = gross * (1 + emp_tax)
            conn.execute("INSERT INTO cost_employees (department, position, count, net_salary, gross_salary, super_gross, in_overhead, notes) VALUES (?,?,?,?,?,?,?,?)",
                         [dept, pos, count, round(net, 2), round(gross_calc, 2), round(super_gross, 2), in_overhead, notes])


@app.get("/api/cost-model/analytics")
async def get_cost_model_analytics(user=Depends(require_auth)):
    """Get full cost model analytics."""
    try:
        with get_db() as conn:
            _ensure_cost_model_tables(conn)
            result = _compute_cost_model(conn)
            if not result:
                return _ok({"error": "Cost model not initialized"})
            return _ok(result)
    except Exception as e:
        logger.error(f"Cost model computation error: {e}")
        raise HTTPException(status_code=500, detail="Cost model computation failed")


@app.get("/api/cost-model/parameters")
async def get_cost_parameters(user=Depends(require_auth)):
    with get_db() as conn:
        _ensure_cost_model_tables(conn)
        row = conn.execute("SELECT * FROM pricing_parameters WHERE id=1").fetchone()
        return _ok(dict(row) if row else {})


@app.put("/api/cost-model/parameters")
async def update_cost_parameters(request: Request, user=Depends(require_admin)):
    body = await request.json()
    allowed = ["total_users", "total_users_manual", "total_employees", "technical_staff",
               "back_office_staff", "monthly_work_hours", "vat_rate", "employer_tax_rate",
               "risk_rate", "misc_expense_rate", "fixed_overhead_ratio"]
    # Validate numeric fields
    numeric_fields = allowed[:]  # All of these are numeric
    for key in numeric_fields:
        if key in body:
            body[key] = _validate_numeric(body[key], key)
    with get_db() as conn:
        for key, val in body.items():
            if key in allowed:
                conn.execute(f"UPDATE pricing_parameters SET {key}=?, updated_at=datetime('now'), updated_by=? WHERE id=1",
                             [val, user.get("user_id")])
                conn.execute("INSERT INTO cost_model_log (table_name, record_id, action, new_value, changed_by) VALUES (?,?,?,?,?)",
                             ["pricing_parameters", 1, "update", json.dumps({key: val}), user.get("user_id")])
        row = conn.execute("SELECT * FROM pricing_parameters WHERE id=1").fetchone()
        _invalidate_ai_cache()
        return _ok(dict(row))


@app.get("/api/cost-model/overhead")
async def get_overhead_costs(user=Depends(require_auth)):
    with get_db() as conn:
        _ensure_cost_model_tables(conn)
        rows = conn.execute("SELECT * FROM overhead_costs ORDER BY sort_order").fetchall()
        return _ok([dict(r) for r in rows])


@app.put("/api/cost-model/overhead/{oh_id}")
async def update_overhead_cost(oh_id: int, request: Request, user=Depends(require_admin)):
    body = await request.json()
    if "amount" in body:
        body["amount"] = _validate_numeric(body["amount"], "amount")
    allowed = ["label", "amount", "is_annual", "has_vat", "notes"]
    with get_db() as conn:
        for key, val in body.items():
            if key in allowed:
                conn.execute(f"UPDATE overhead_costs SET {key}=? WHERE id=?", [val, oh_id])
        conn.execute("INSERT INTO cost_model_log (table_name, record_id, action, new_value, changed_by) VALUES (?,?,?,?,?)",
                     ["overhead_costs", oh_id, "update", json.dumps(body), user.get("user_id")])
        row = conn.execute("SELECT * FROM overhead_costs WHERE id=?", [oh_id]).fetchone()
        _invalidate_ai_cache()
        return _ok(dict(row))


@app.get("/api/cost-model/employees")
async def get_cost_employees(user=Depends(require_auth)):
    with get_db() as conn:
        _ensure_cost_model_tables(conn)
        rows = conn.execute("SELECT * FROM cost_employees ORDER BY department, id").fetchall()
        return _ok([dict(r) for r in rows])


@app.post("/api/cost-model/employees")
async def add_cost_employee(request: Request, user=Depends(require_admin)):
    body = await request.json()
    income_tax = 0.14
    emp_tax = 0.175
    net = _validate_numeric(body.get("net_salary", 0), "net_salary")
    count = _validate_numeric(body.get("count", 1), "count", allow_zero=False)
    count = int(count)
    gross = net / (1 - income_tax)
    super_gross = gross * (1 + emp_tax)
    with get_db() as conn:
        cur = conn.execute(
            "INSERT INTO cost_employees (department, position, count, net_salary, gross_salary, super_gross, in_overhead, notes) VALUES (?,?,?,?,?,?,?,?)",
            [body.get("department", "IT"), body.get("position", ""), count,
             round(net, 2), round(gross, 2), round(super_gross, 2),
             int(body.get("in_overhead", 0)), body.get("notes", "")]
        )
        row = conn.execute("SELECT * FROM cost_employees WHERE id=?", [cur.lastrowid]).fetchone()
        _invalidate_ai_cache()
        return _ok(dict(row))


@app.put("/api/cost-model/employees/{emp_id}")
async def update_cost_employee(emp_id: int, request: Request, user=Depends(require_admin)):
    body = await request.json()
    income_tax = 0.14
    emp_tax = 0.175
    with get_db() as conn:
        if "net_salary" in body:
            net = _validate_numeric(body["net_salary"], "net_salary")
            body["net_salary"] = net
            body["gross_salary"] = round(net / (1 - income_tax), 2)
            body["super_gross"] = round(body["gross_salary"] * (1 + emp_tax), 2)
        if "count" in body:
            count = _validate_numeric(body["count"], "count", allow_zero=False)
            body["count"] = int(count)
        allowed = ["department", "position", "count", "net_salary", "gross_salary", "super_gross", "in_overhead", "notes"]
        for key, val in body.items():
            if key in allowed:
                conn.execute(f"UPDATE cost_employees SET {key}=? WHERE id=?", [val, emp_id])
        row = conn.execute("SELECT * FROM cost_employees WHERE id=?", [emp_id]).fetchone()
        _invalidate_ai_cache()
        return _ok(dict(row))


@app.delete("/api/cost-model/employees/{emp_id}")
async def delete_cost_employee(emp_id: int, user=Depends(require_admin)):
    with get_db() as conn:
        conn.execute("DELETE FROM cost_employees WHERE id=?", [emp_id])
        _invalidate_ai_cache()
        return _ok({"deleted": emp_id})


@app.get("/api/cost-model/client-services/{company_id}")
async def get_client_services(company_id: int, user=Depends(require_auth)):
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM client_services WHERE company_id=? ORDER BY service_type",
            [company_id]
        ).fetchall()
        # Also get user_count
        comp = conn.execute("SELECT user_count, cost_code FROM companies WHERE id=?", [company_id]).fetchone()
        return _ok({
            "services": [dict(r) for r in rows],
            "user_count": comp["user_count"] if comp else 0,
            "cost_code": comp["cost_code"] if comp else "",
        })


@app.put("/api/cost-model/client-services/{company_id}")
async def upsert_client_services(company_id: int, request: Request, user=Depends(require_auth)):
    """Update all services for a client at once."""
    body = await request.json()
    services = body.get("services", [])  # [{service_type, monthly_revenue, is_active}]
    user_count = body.get("user_count")
    cost_code = body.get("cost_code")

    with get_db() as conn:
        # Update user_count / cost_code on company
        if user_count is not None:
            conn.execute("UPDATE companies SET user_count=? WHERE id=?", [int(user_count), company_id])
        if cost_code is not None:
            conn.execute("UPDATE companies SET cost_code=? WHERE id=?", [cost_code, company_id])

        for svc in services:
            svc_type = svc.get("service_type")
            revenue = float(svc.get("monthly_revenue", 0))
            is_active = int(svc.get("is_active", 1))
            # Upsert
            existing = conn.execute(
                "SELECT id FROM client_services WHERE company_id=? AND service_type=?",
                [company_id, svc_type]
            ).fetchone()
            if existing:
                conn.execute(
                    "UPDATE client_services SET monthly_revenue=?, is_active=? WHERE id=?",
                    [revenue, is_active, existing["id"]]
                )
            else:
                conn.execute(
                    "INSERT INTO client_services (company_id, company_code, service_type, monthly_revenue, is_active) VALUES (?,?,?,?,?)",
                    [company_id, cost_code or "", svc_type, revenue, is_active]
                )

        rows = conn.execute(
            "SELECT * FROM client_services WHERE company_id=? ORDER BY service_type",
            [company_id]
        ).fetchall()
        comp = conn.execute("SELECT user_count, cost_code FROM companies WHERE id=?", [company_id]).fetchone()
        _invalidate_ai_cache()
        return _ok({
            "services": [dict(r) for r in rows],
            "user_count": comp["user_count"] if comp else 0,
            "cost_code": comp["cost_code"] if comp else "",
        })


@app.post("/api/cost-model/sync-pricing-services")
async def sync_pricing_to_client_services(user=Depends(require_auth)):
    """Sync service data from pricing_data.json into client_services table.
    Uses category-level totals (verified correct) and maps them to 6 CRM service types."""
    import unicodedata

    # Category name (from pricing_data.json) -> CRM service_type
    CATEGORY_MAP = {
        "İT İnfrastruktur": "permanent_it",
        "Məlumat Bazası": "permanent_it",
        "Bulud Xidmətləri": "cloud",
        "Video, Monitorinq": "permanent_it",
        "Avtomatlaşdırılmış Sistemlər": "erp",
        "SaaS Biznes Process": "erp",
        "İnformasiya Təhlükəsizlik": "infosec",
        "Təlim və Maarifləndirmə": "infosec",
        "Konsaltinq və Layihə": "projects",
        "Audit və Uyğunluq": "grc",
        "HelpDesk və Texniki Dəstək": "helpdesk",
    }

    pricing_path = os.path.join(STATIC_DIR, "pricing_data.json")
    mapping_path = os.path.join(STATIC_DIR, "pricing_crm_mapping.json")

    if not os.path.exists(pricing_path):
        raise HTTPException(404, "pricing_data.json not found")

    with open(pricing_path, encoding="utf-8") as f:
        pricing_data = json.load(f)

    # Load company code -> CRM name mapping
    pricing_to_crm = {}
    if os.path.exists(mapping_path):
        with open(mapping_path, encoding="utf-8") as f:
            pricing_to_crm = {k.upper(): v for k, v in json.load(f).items()}

    updated = 0
    skipped = []
    processed = []

    # Normalize category map keys for matching
    norm_cat_map = {}
    for cat_name, crm_type in CATEGORY_MAP.items():
        norm_key = unicodedata.normalize("NFC", cat_name)
        norm_cat_map[norm_key] = crm_type

    with get_db() as conn:
        # Build name -> id lookup (case-insensitive)
        crm_companies = conn.execute("SELECT id, name, cost_code FROM companies WHERE category='client'").fetchall()
        name_to_id = {c["name"].lower(): c["id"] for c in crm_companies}

        for pcode, company in pricing_data.items():
            code = pcode.upper()
            crm_name = pricing_to_crm.get(code, "").lower()
            company_id = name_to_id.get(crm_name)

            if not company_id:
                company_id = name_to_id.get(code.lower())
            if not company_id:
                skipped.append(code)
                continue

            # Aggregate category totals into CRM service types
            service_revenue = {}
            for cat_name_raw, cat_data in company.get("categories", {}).items():
                if not isinstance(cat_data, dict):
                    continue
                cat_name = unicodedata.normalize("NFC", cat_name_raw)
                cat_total = cat_data.get("total", 0)
                if cat_total <= 0:
                    continue

                crm_type = norm_cat_map.get(cat_name, "Daimi IT")
                # Special handling for HelpDesk category: split by service name
                if crm_type == "helpdesk" and "services" in cat_data:
                    for svc in cat_data["services"]:
                        svc_total = svc.get("qty", 0) * svc.get("price", 0)
                        if svc_total <= 0:
                            continue
                        svc_name = svc.get("name", "")
                        if "HelpDesk Level" in svc_name:
                            service_revenue["helpdesk"] = service_revenue.get("helpdesk", 0) + svc_total
                        elif "Informational Systems Support" in svc_name or "İnformational Systems Support" in svc_name:
                            service_revenue["erp"] = service_revenue.get("erp", 0) + svc_total
                        elif "ITAM" in svc_name:
                            service_revenue["helpdesk"] = service_revenue.get("helpdesk", 0) + svc_total
                        else:
                            # Çağırı Mərkəzi -> permanent_it (Daimi)
                            service_revenue["permanent_it"] = service_revenue.get("permanent_it", 0) + svc_total
                else:
                    service_revenue[crm_type] = service_revenue.get(crm_type, 0) + cat_total

            # Upsert each service type
            for svc_type, revenue in service_revenue.items():
                if revenue <= 0:
                    continue
                existing = conn.execute(
                    "SELECT id FROM client_services WHERE company_id=? AND service_type=?",
                    [company_id, svc_type]
                ).fetchone()
                if existing:
                    conn.execute(
                        "UPDATE client_services SET monthly_revenue=?, is_active=1 WHERE id=?",
                        [round(revenue, 2), existing["id"]]
                    )
                else:
                    conn.execute(
                        "INSERT INTO client_services (company_id, company_code, service_type, monthly_revenue, is_active) VALUES (?,?,?,?,1)",
                        [company_id, code, svc_type, round(revenue, 2)]
                    )
                updated += 1

            processed.append({"code": code, "crm_name": crm_name, "services": {k: round(v, 2) for k, v in service_revenue.items()}})

        _invalidate_ai_cache()

    return _ok({"updated": updated, "processed_count": len(processed), "processed": processed, "skipped": skipped})


@app.get("/api/cost-model/client-analytics/{company_id}")
async def get_client_cost_analytics(company_id: int, user=Depends(require_auth)):
    """Get cost/margin analytics for a single client."""
    with get_db() as conn:
        result = _compute_cost_model(conn)
        if not result:
            return _ok({})
        client = next((c for c in result["client_data"] if c["id"] == company_id), None)
        if not client:
            _err("Client not found", 404)
        return _ok({
            "client": client,
            "grand_total": result["grand_total"],
            "cost_per_user": result["cost_per_user"],
            "params": result["params"],
        })


@app.get("/api/cost-model/client-costs")
async def get_client_cost_map(user=Depends(require_auth)):
    """Return lightweight cost map: {company_id: {total_cost, revenue, margin, margin_pct, user_count}}"""
    with get_db() as conn:
        _ensure_cost_model_tables(conn)
        result = _compute_cost_model(conn)
        if not result:
            return _ok({"clients": {}, "portfolio_users": 0, "total_users": 0})
        cost_map = {}
        for c in result["client_data"]:
            cost_map[c["id"]] = {
                "total_cost": c["total_cost"],
                "revenue": c["total_revenue"],
                "margin": c["margin"],
                "margin_pct": c["margin_pct"],
                "user_count": c.get("user_count", 0) or 0,
                "status": c["status"],
            }
        return _ok({
            "clients": cost_map,
            "portfolio_users": result["portfolio_users"],
            "total_users": result["total_users"],
            "grand_total_f": result["grand_total_f"],
            "grand_total_g": result["grand_total_g"],
            "cost_per_user_f": result["cost_per_user_f"],
            "cost_per_user": result["cost_per_user"],
        })


@app.get("/api/cost-model/log")
async def get_cost_model_log(user=Depends(require_auth)):
    with get_db() as conn:
        rows = conn.execute(
            "SELECT l.*, u.full_name FROM cost_model_log l LEFT JOIN users u ON l.changed_by=u.id ORDER BY l.changed_at DESC LIMIT 100"
        ).fetchall()
        return _ok([dict(r) for r in rows])


@app.post("/api/cost-model/seed-clients")
async def seed_clients_from_excel(request: Request, user=Depends(require_admin)):
    """Seed client services from Excel data."""
    body = await request.json()
    clients_data = body.get("clients", [])
    results = {"created": 0, "updated": 0, "not_found": []}

    with get_db() as conn:
        for item in clients_data:
            name = item.get("name", "").strip()
            # Try to find company by name (fuzzy)
            comp = conn.execute(
                "SELECT id FROM companies WHERE LOWER(name) LIKE ? OR cost_code=? LIMIT 1",
                [f"%{name.lower()}%", name.upper()]
            ).fetchone()
            if not comp:
                results["not_found"].append(name)
                continue
            company_id = comp["id"]
            # Update user_count and cost_code
            conn.execute(
                "UPDATE companies SET user_count=?, cost_code=? WHERE id=?",
                [item.get("user_count", 0), name.upper(), company_id]
            )
            # Upsert services
            for svc_type, revenue in item.get("services", {}).items():
                if revenue <= 0:
                    continue
                existing = conn.execute(
                    "SELECT id FROM client_services WHERE company_id=? AND service_type=?",
                    [company_id, svc_type]
                ).fetchone()
                if existing:
                    conn.execute("UPDATE client_services SET monthly_revenue=?, is_active=1 WHERE id=?",
                                 [revenue, existing["id"]])
                    results["updated"] += 1
                else:
                    conn.execute(
                        "INSERT INTO client_services (company_id, company_code, service_type, monthly_revenue, is_active) VALUES (?,?,?,?,1)",
                        [company_id, name.upper(), svc_type, revenue]
                    )
                    results["created"] += 1

    return _ok(results)


# ─── AI Cost Model Analysis ─────────────────────────────────
_ai_analysis_cache = {}  # keyed by tab: {"analytics": {"text":..., "ts":..., "thinking":...}, ...}

def _invalidate_ai_cache():
    """Clear all AI analysis caches when cost model data changes."""
    _ai_analysis_cache.clear()

@app.post("/api/cost-model/ai-analysis")
async def ai_cost_model_analysis(request: Request, user=Depends(require_auth)):
    """Generate AI analysis of cost model data using Claude with extended thinking."""
    import anthropic

    body = {}
    try:
        body = await request.json()
    except Exception:
        pass
    tab = body.get("tab", "analytics")  # analytics, services, clients, overhead, employees
    lang = body.get("lang", "ru")  # en, ru, az

    import dotenv
    env_vals = dotenv.dotenv_values(os.path.join(os.path.dirname(__file__), ".env"))
    api_key = env_vals.get("ANTHROPIC_API_KEY", "").strip() or os.getenv("ANTHROPIC_API_KEY", "").strip()
    if not api_key:
        _err("ANTHROPIC_API_KEY not configured", 500)

    # Cache persists until data changes (_invalidate_ai_cache clears on price/cost/revenue updates)
    cache_key = f"{tab}_{lang}"
    force = body.get("force", False)
    cached = _ai_analysis_cache.get(cache_key)
    if cached and cached.get("text") and not force:
        return _ok({"analysis": cached["text"], "thinking": cached["thinking"], "cached": True})

    # Gather all cost model data
    try:
        with get_db() as conn:
            # Parameters
            params_row = conn.execute("SELECT * FROM pricing_parameters LIMIT 1").fetchone()
            params = dict(params_row) if params_row else {}

            # Employees by department
            employees = conn.execute(
                "SELECT department, position, count, net_salary, in_overhead FROM cost_employees ORDER BY department"
            ).fetchall()
            emp_data = [dict(e) for e in employees]

            # Overhead costs
            overhead = conn.execute(
                "SELECT category, label as name, amount, is_annual, has_vat FROM overhead_costs ORDER BY category"
            ).fetchall()
            oh_data = [dict(o) for o in overhead]

            # Client data with services
            clients_raw = conn.execute("""
                SELECT c.id, c.name, c.user_count, c.category,
                       GROUP_CONCAT(cs.service_type || ':' || cs.monthly_revenue, '|') as services
                FROM companies c
                LEFT JOIN client_services cs ON cs.company_id = c.id
                WHERE c.category = 'client'
                GROUP BY c.id
                ORDER BY c.name
            """).fetchall()

            # --- Load pricing_data.json revenue (same logic as summary endpoint) ---
            pricing_path_ai = os.path.join(STATIC_DIR, "pricing_data.json")
            mapping_path_ai = os.path.join(STATIC_DIR, "pricing_crm_mapping.json")
            pricing_rev_by_id = {}
            if os.path.exists(pricing_path_ai):
                pricing_to_crm_ai = {}
                if os.path.exists(mapping_path_ai):
                    with open(mapping_path_ai, encoding="utf-8") as mf:
                        pricing_to_crm_ai = {k: v.lower() for k, v in json.load(mf).items()}
                crm_name_to_id_ai = {}
                for cl_row in conn.execute("SELECT id, name FROM companies WHERE category='client'").fetchall():
                    crm_name_to_id_ai[cl_row["name"].lower()] = cl_row["id"]
                with open(pricing_path_ai, encoding="utf-8") as f:
                    pricing_json_ai = json.load(f)
                for pcode, pdata in pricing_json_ai.items():
                    cats = pdata.get("categories", {})
                    all_total = sum(c.get("total", 0) for c in cats.values())
                    crm_name = pricing_to_crm_ai.get(pcode, pcode.lower())
                    company_id = crm_name_to_id_ai.get(crm_name)
                    if company_id:
                        pricing_rev_by_id[company_id] = pricing_rev_by_id.get(company_id, 0.0) + all_total

            client_list = []
            for cr in clients_raw:
                svcs = {}
                if cr["services"]:
                    for s in cr["services"].split("|"):
                        parts = s.split(":")
                        if len(parts) == 2:
                            svcs[parts[0]] = float(parts[1])
                db_revenue = sum(svcs.values())
                pricing_rev = pricing_rev_by_id.get(cr["id"], 0.0)
                # Use pricing_data.json as primary source, client_services as fallback
                effective_revenue = pricing_rev if pricing_rev > 0 else db_revenue
                client_list.append({
                    "name": cr["name"],
                    "user_count": cr["user_count"] or 0,
                    "services": svcs,
                    "total_revenue": effective_revenue,
                    "pricing_revenue": pricing_rev,
                    "db_revenue": db_revenue
                })

        # Build summary stats
        total_revenue = sum(c["total_revenue"] for c in client_list)
        total_users = sum(c["user_count"] for c in client_list)
        total_salary = sum(e["count"] * e["net_salary"] for e in emp_data)
        total_overhead = sum(
            (o["amount"] / 12 if o["is_annual"] else o["amount"]) * (1.18 if o["has_vat"] else 1.0)
            for o in oh_data
        )
        burden = float(params.get("employer_tax_rate", 0.175)) * 100
        total_salary_burdened = total_salary * (1 + burden / 100)

        # Departments summary
        dept_summary = {}
        for e in emp_data:
            d = e["department"]
            if d not in dept_summary:
                dept_summary[d] = {"headcount": 0, "salary_cost": 0}
            dept_summary[d]["headcount"] += e["count"]
            dept_summary[d]["salary_cost"] += e["count"] * e["net_salary"] * (1 + burden / 100)

        # Top/bottom clients
        clients_sorted = sorted(client_list, key=lambda x: x["total_revenue"], reverse=True)
        top_clients = clients_sorted[:10]
        zero_revenue = [c for c in client_list if c["total_revenue"] == 0]

        # ─── Build tab-specific prompts ───
        total_headcount = sum(e['count'] for e in emp_data)
        paying_clients = len([c for c in client_list if c["total_revenue"] > 0])
        zero_clients = len([c for c in client_list if c["total_revenue"] == 0])

        base_data = f"""## IT аутсорсинговая компания (Guven Technology) — Модель себестоимости
### Бизнес-контекст:
- Основной продукт: IT-аутсорсинг (HelpDesk, SysAdmin, InfoSec, ERP, GRC, PM для внешних клиентов)
- В 2026 году цены были подняты на 15%
- BackOffice (17 чел.: директор, 2 зама, коммерческий(6), HR(2), финансы(2), админ(2), водители(2), снабжение(1)) — in_overhead, расходы распределяются на клиентов
- HelpDesk: 56 чел. в таблице = 52 на клиентах + 4 call center (внутри отдела ещё 4 на внутренних задачах, 1 начальник ~5000₼ распределён в средней зарплате)
- Доходы клиентов загружены из pricing_data.json (контрактные цены). {zero_clients} клиентов пока без данных о доходе.

### Ключевые показатели:
- Активные клиенты: {len(client_list)} (из них {paying_clients} с данными о доходе)
- Общий доход/мес: {total_revenue:,.2f} ₼ (от {paying_clients} клиентов с данными)
- ФОТ (с нагрузкой {burden}%): {total_salary_burdened:,.2f} ₼
- Накладные расходы (overhead)/мес: {total_overhead:,.2f} ₼
- Себестоимость/мес: {total_salary_burdened + total_overhead:,.2f} ₼
- Маржа/мес: {total_revenue - total_salary_burdened - total_overhead:,.2f} ₼ ({((total_revenue - total_salary_burdened - total_overhead) / total_revenue * 100) if total_revenue > 0 else 0:.1f}%)
- Сотрудников: {total_headcount} | Пользователей клиентов: {total_users}"""

        lang_names = {"ru": "РУССКОМ", "en": "АНГЛИЙСКОМ", "az": "АЗЕРБАЙДЖАНСКОМ"}
        lang_instruction = f"Напиши анализ на {lang_names.get(lang, 'РУССКОМ')} языке."

        if tab == "services":
            # Service-specific data
            svc_summary = {}
            for c in client_list:
                for svc_type, rev in c["services"].items():
                    if svc_type not in svc_summary:
                        svc_summary[svc_type] = {"revenue": 0, "clients": 0}
                    svc_summary[svc_type]["revenue"] += rev
                    if rev > 0:
                        svc_summary[svc_type]["clients"] += 1
            svc_emp = {}
            for e in emp_data:
                d = e["department"]
                if d not in svc_emp:
                    svc_emp[d] = {"count": 0, "cost": 0}
                svc_emp[d]["count"] += e["count"]
                svc_emp[d]["cost"] += e["count"] * e["net_salary"] * (1 + burden / 100)

            data_prompt = f"""{base_data}

### Сервисные направления — Доход:
{chr(10).join(f"- {s}: {v['revenue']:,.2f} ₼/мес, {v['clients']} клиентов" for s, v in sorted(svc_summary.items(), key=lambda x: x[1]['revenue'], reverse=True))}

### Отделы — Затраты:
{chr(10).join(f"- {d}: {v['count']} чел., ФОТ: {v['cost']:,.2f} ₼/мес" for d, v in svc_emp.items())}"""

            system_prompt = f"""Ты — финансовый аналитик IT-аутсорсинговой компании. Проанализируй данные по СЕРВИСНЫМ НАПРАВЛЕНИЯМ.

{data_prompt}

{lang_instruction} Структура:
1. **📊 Оценка направлений** — какие направления прибыльны, какие убыточны (2-3 предложения)
2. **⚠️ Риски по направлениям** — зависимость от одного направления, недозагруженные команды (2-3 пункта)
3. **💡 Рекомендации** — как оптимизировать микс услуг, куда инвестировать (3-4 пункта)
4. **🔍 Наблюдения** — интересные паттерны (2 пункта)

Будь конкретен, используй цифры. Максимум 350 слов."""

        elif tab == "clients":
            client_details = chr(10).join(
                f"- {c['name']}: {c['total_revenue']:,.2f} ₼/мес, {c['user_count']} users, услуги: {', '.join(c['services'].keys()) if c['services'] else 'нет'}"
                for c in clients_sorted[:20]
            )
            data_prompt = f"""{base_data}

### Все клиенты (топ-20 по доходу):
{client_details}

### Клиенты без данных о доходе ({len(zero_revenue)}):
{', '.join(f"{c['name']}({c['user_count']}users)" for c in zero_revenue[:15]) if zero_revenue else 'Все клиенты имеют данные о доходе'}

### Средний доход на клиента (только по {paying_clients} с данными): {(total_revenue / paying_clients if paying_clients > 0 else 0):,.2f} ₼
### Средний доход на пользователя: {(total_revenue / total_users if total_users > 0 else 0):,.2f} ₼"""

            system_prompt = f"""Ты — финансовый аналитик IT-аутсорсинговой компании. Проанализируй данные по КЛИЕНТАМ.

{data_prompt}

{lang_instruction} Структура:
1. **📊 Портфель клиентов** — концентрация дохода, зависимости (2-3 предложения)
2. **⚠️ Риски** — клиенты с нулевым доходом, высокая концентрация, недооцененные клиенты (2-4 пункта)
3. **💡 Рекомендации** — upsell, cross-sell, ценообразование (3-4 пункта)
4. **🔍 Наблюдения** — паттерны в клиентской базе (2 пункта)

Будь конкретен, используй цифры. Максимум 350 слов."""

        elif tab == "overhead":
            oh_details = chr(10).join(
                f"- {o['name']} ({o['category']}): {(o['amount']/12 if o['is_annual'] else o['amount'])*(1.18 if o['has_vat'] else 1.0):,.2f} ₼/мес {'(illik÷12)' if o['is_annual'] else ''} {'(+ƏDV)' if o['has_vat'] else ''}"
                for o in sorted(oh_data, key=lambda x: (x['amount']/12 if x['is_annual'] else x['amount'])*(1.18 if x['has_vat'] else 1.0), reverse=True)
            )
            oh_by_cat = {}
            for o in oh_data:
                cat = o["category"]
                monthly = (o["amount"] / 12 if o["is_annual"] else o["amount"]) * (1.18 if o["has_vat"] else 1.0)
                oh_by_cat[cat] = oh_by_cat.get(cat, 0) + monthly

            data_prompt = f"""{base_data}

### Все overhead расходы:
{oh_details}

### По категориям:
{chr(10).join(f"- {cat}: {amt:,.2f} ₼/мес" for cat, amt in sorted(oh_by_cat.items(), key=lambda x: x[1], reverse=True))}

### Общий overhead/мес: {total_overhead:,.2f} ₼
### Overhead как % от дохода: {(total_overhead / total_revenue * 100) if total_revenue > 0 else 0:.1f}%
### Overhead на сотрудника: {(total_overhead / sum(e['count'] for e in emp_data)):,.2f} ₼ если {sum(e['count'] for e in emp_data)} чел."""

            system_prompt = f"""Ты — финансовый аналитик IT-аутсорсинговой компании. Проанализируй OVERHEAD (накладные расходы).

{data_prompt}

{lang_instruction} Структура:
1. **📊 Оценка расходов** — общий уровень overhead, адекватность (2-3 предложения)
2. **⚠️ Риски** — завышенные статьи, отсутствующие расходы, ƏDV нагрузка (2-3 пункта)
3. **💡 Рекомендации** — оптимизация, какие расходы можно сократить (3-4 пункта)
4. **🔍 Наблюдения** — аномалии, паттерны (2 пункта)

Будь конкретен, используй цифры. Максимум 350 слов."""

        elif tab == "employees":
            emp_details = chr(10).join(
                f"- {e['department']}/{e['position']}: {e['count']} чел., net {e['net_salary']:,.2f} ₼/чел, burdened {e['net_salary'] * (1 + burden/100):,.2f} ₼/чел, ИТОГО: {e['count'] * e['net_salary'] * (1 + burden/100):,.2f} ₼ {'[OVERHEAD]' if e['in_overhead'] else ''}"
                for e in emp_data
            )
            data_prompt = f"""{base_data}

### Штатное расписание:
{emp_details}

### По отделам:
{chr(10).join(f"- {d}: {v['headcount']} чел., ФОТ: {v['salary_cost']:,.2f} ₼/мес" for d, v in dept_summary.items())}

### Общий ФОТ (net): {total_salary:,.2f} ₼
### Общий ФОТ (burdened): {total_salary_burdened:,.2f} ₼
### Средняя зарплата net: {(total_salary / sum(e['count'] for e in emp_data)):,.2f} ₼
### Доход на сотрудника: {(total_revenue / sum(e['count'] for e in emp_data)):,.2f} ₼"""

            system_prompt = f"""Ты — финансовый аналитик IT-аутсорсинговой компании. Проанализируй ШТАТ СОТРУДНИКОВ.

{data_prompt}

{lang_instruction} Структура:
1. **📊 Оценка штата** — эффективность, баланс между отделами (2-3 предложения)
2. **⚠️ Риски** — перегруженные/недозагруженные отделы, зарплатные перекосы (2-3 пункта)
3. **💡 Рекомендации** — оптимизация штата, пересмотр зарплат (3-4 пункта)
4. **🔍 Наблюдения** — паттерны (2 пункта)

Будь конкретен, используй цифры. Максимум 350 слов."""

        else:  # analytics (default)
            data_prompt = f"""{base_data}

### Распределение по отделам:
{chr(10).join(f"- {d}: {v['headcount']} чел., ФОТ: {v['salary_cost']:,.2f} ₼/мес" for d, v in dept_summary.items())}

### Топ-10 клиентов по доходу:
{chr(10).join(f"- {c['name']}: {c['total_revenue']:,.2f} ₼/мес, {c['user_count']} users, услуги: {', '.join(c['services'].keys())}" for c in top_clients)}

### Клиенты без заполненного дохода ({len(zero_revenue)}) — не бесплатные, не внесены сервисы:
{', '.join(c['name'] for c in zero_revenue[:15])}

### Накладные расходы (топ по сумме):
{chr(10).join(f"- {o['name']} ({o['category']}): {(o['amount']/12 if o['is_annual'] else o['amount'])*(1.18 if o['has_vat'] else 1.0):,.2f} ₼/мес" for o in sorted(oh_data, key=lambda x: (x['amount']/12 if x['is_annual'] else x['amount'])*(1.18 if x['has_vat'] else 1.0), reverse=True)[:10])}"""

            system_prompt = f"""Ты — финансовый аналитик IT-аутсорсинговой компании. Проанализируй данные модели себестоимости и дай структурированный анализ.

{data_prompt}

{lang_instruction} Структура:
1. **📊 Общая оценка** — здоровье бизнеса (2-3 предложения)
2. **⚠️ Ключевые риски** — что беспокоит (2-4 пункта)
3. **💡 Рекомендации** — конкретные действия для улучшения маржи (3-5 пунктов)
4. **🔍 Интересные наблюдения** — паттерны в данных (2-3 пункта)

Будь конкретен, используй цифры из данных. Не повторяй данные — анализируй их. Пиши кратко и по делу, максимум 400 слов."""

        import httpx as _httpx
        _async_http_client = _httpx.AsyncClient(verify=False, timeout=300.0)
        client = anthropic.AsyncAnthropic(api_key=api_key, http_client=_async_http_client)
        model = env_vals.get("MANAGER_MODEL", "") or os.getenv("MANAGER_MODEL", "claude-sonnet-4-5-20250929")

        response = await client.messages.create(
            model=model,
            max_tokens=16000,
            thinking={
                "type": "enabled",
                "budget_tokens": 10000
            },
            messages=[{
                "role": "user",
                "content": system_prompt
            }]
        )

        analysis_text = ""
        thinking_text = ""
        for block in response.content:
            if block.type == "thinking":
                thinking_text = block.thinking
            elif block.type == "text":
                analysis_text = block.text

        _ai_analysis_cache[cache_key] = {
            "text": analysis_text,
            "thinking": thinking_text,
            "ts": time.time()
        }

        return _ok({"analysis": analysis_text, "thinking": thinking_text, "cached": False})

    except anthropic.APIError as e:
        logger.error(f"Claude API error: {e}")
        _err("AI service unavailable", 502)
    except Exception as e:
        logging.error(f"AI analysis error: {e}")
        _err("Analysis error", 500)


# ─── Admin Deploy Endpoint ──────────────────────────────────────────────
@app.post("/api/admin/deploy")
async def admin_deploy(request: Request, user=Depends(require_admin)):
    """Deploy files to server and optionally restart gunicorn. Admin only.
    Accepts JSON: {files: [{path: "relative/path", content: "file content"}], restart: bool}
    """
    import subprocess
    body = await request.json()
    files = body.get("files", [])
    do_restart = body.get("restart", False)
    base_dir = os.path.dirname(os.path.abspath(__file__))
    results = []
    for f in files:
        rel_path = f.get("path", "")
        content = f.get("content", "")
        # Security: prevent path traversal
        if ".." in rel_path or rel_path.startswith("/"):
            results.append({"path": rel_path, "status": "rejected", "reason": "invalid path"})
            continue
        full_path = os.path.join(base_dir, rel_path)
        os.makedirs(os.path.dirname(full_path), exist_ok=True)
        try:
            with open(full_path, "w", encoding="utf-8") as fh:
                fh.write(content)
            results.append({"path": rel_path, "status": "ok", "size": len(content)})
        except Exception as e:
            results.append({"path": rel_path, "status": "error", "reason": str(e)})
    restart_result = None
    if do_restart:
        try:
            subprocess.Popen(
                "sleep 1 && pkill -f gunicorn && sleep 1 && "
                "cd /opt/hermes_crm && source venv/bin/activate && "
                "gunicorn api:app -w 2 -k uvicorn.workers.UvicornWorker "
                "--bind 0.0.0.0:8766 --timeout 600 --daemon "
                "--log-file /var/log/hermes.log",
                shell=True, executable="/bin/bash"
            )
            restart_result = "scheduled"
        except Exception as e:
            restart_result = f"error: {e}"
    return _ok({"files": results, "restart": restart_result})


@app.post("/api/admin/exec")
async def admin_exec(request: Request, user=Depends(require_admin)):
    """Execute a shell command on server. Admin only. Use with caution."""
    import subprocess
    body = await request.json()
    cmd = body.get("cmd", "")
    if not cmd:
        _err("No command provided")
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=30,
            executable="/bin/bash"
        )
        return _ok({
            "stdout": result.stdout[-2000:] if result.stdout else "",
            "stderr": result.stderr[-2000:] if result.stderr else "",
            "returncode": result.returncode
        })
    except subprocess.TimeoutExpired:
        _err("Command timed out (30s limit)")
    except Exception as e:
        _err(f"Exec error: {e}")



@app.get("/api/reports/advanced")
async def reports_advanced(user=Depends(require_auth)):
    """Advanced analytics for enhanced Reports page"""
    with get_db() as db:
        data = {}

        # 1. Lead Funnel
        cats = db.execute("SELECT category, COUNT(*) as cnt FROM companies WHERE category IN ('prospect','contacted','qualified','client','not_suitable','inactive','partner') GROUP BY category").fetchall()
        data['lead_funnel'] = {r['category']: r['cnt'] for r in cats}

        # 2. Contract statuses
        cs = db.execute("SELECT status, COUNT(*) as cnt FROM contracts GROUP BY status ORDER BY cnt DESC").fetchall()
        data['contract_statuses'] = [{'status': r['status'], 'count': r['cnt']} for r in cs]

        # 3. Activity by month (last 12 months)
        am = db.execute("""
            SELECT strftime('%Y-%m', timestamp) as month, COUNT(*) as cnt
            FROM activities
            WHERE timestamp >= date('now', '-12 months')
            GROUP BY month ORDER BY month
        """).fetchall()
        data['activity_by_month'] = [{'month': r['month'], 'count': r['cnt']} for r in am]

        # 4. Top 10 companies by contacts count
        tc = db.execute("""
            SELECT c.name, c.contacts_count, c.category, c.domain
            FROM companies c
            WHERE c.contacts_count > 0
            ORDER BY c.contacts_count DESC LIMIT 10
        """).fetchall()
        data['top_companies_contacts'] = [{'name': r['name'], 'contacts': r['contacts_count'], 'category': r['category'], 'domain': r['domain']} for r in tc]

        # 5. Top 10 companies by email activity
        te = db.execute("""
            SELECT co.name, co.category, COUNT(a.id) as emails
            FROM activities a
            LEFT JOIN contacts ct ON a.contact_id = ct.id
            LEFT JOIN companies co ON ct.company_id = co.id
            WHERE 1=1
            GROUP BY co.id
            ORDER BY emails DESC LIMIT 10
        """).fetchall()
        data['top_companies_activities'] = [{'name': r['name'], 'category': r['category'], 'activities': r['emails']} for r in te]

        # 6. Contracts expiring soon (next 90 days)
        exp = db.execute("""
            SELECT contract_name, counterparty, end_date, status,
                CAST(julianday(end_date) - julianday('now') AS INTEGER) as days_left
            FROM contracts
            WHERE end_date IS NOT NULL AND end_date >= date('now') AND end_date <= date('now', '+90 days')
            ORDER BY end_date ASC
        """).fetchall()
        data['expiring_contracts'] = [{'name': r['contract_name'], 'company': r['counterparty'], 'end_date': r['end_date'], 'status': r['status'], 'days_left': r['days_left']} for r in exp]

        # 7. Contracts created by month
        cm = db.execute("""
            SELECT strftime('%Y-%m', created_at) as month, COUNT(*) as cnt
            FROM contracts
            WHERE created_at IS NOT NULL
            GROUP BY month ORDER BY month
        """).fetchall()
        data['contracts_by_month'] = [{'month': r['month'], 'count': r['cnt']} for r in cm]

        # 8. Activity types breakdown
        at = db.execute("SELECT activity_type, COUNT(*) as cnt FROM activities GROUP BY activity_type ORDER BY cnt DESC").fetchall()
        data['activity_types'] = [{'type': r['activity_type'], 'count': r['cnt']} for r in at]

        # 9. Contacts activity health
        inactive = db.execute("""
            SELECT COUNT(*) as cnt FROM contacts
            WHERE last_contact IS NOT NULL AND last_contact < date('now', '-30 days')
        """).fetchone()
        recent = db.execute("""
            SELECT COUNT(*) as cnt FROM contacts
            WHERE last_contact IS NOT NULL AND last_contact >= date('now', '-30 days')
        """).fetchone()
        never = db.execute("""
            SELECT COUNT(*) as cnt FROM contacts WHERE last_contact IS NULL
        """).fetchone()
        data['contact_activity_health'] = {
            'active_30d': recent['cnt'],
            'inactive_30d': inactive['cnt'],
            'never_contacted': never['cnt']
        }

        # 10. Deal pipeline summary
        dp = db.execute("""
            SELECT stage, COUNT(*) as cnt, COALESCE(SUM(value_amount),0) as total_value
            FROM deals GROUP BY stage
        """).fetchall()
        data['deal_pipeline'] = [{'stage': r['stage'], 'count': r['cnt'], 'value': r['total_value']} for r in dp]

        # 11. New companies by month
        ncm = db.execute("""
            SELECT strftime('%Y-%m', created_at) as month, COUNT(*) as cnt
            FROM companies
            WHERE created_at IS NOT NULL
            GROUP BY month ORDER BY month
        """).fetchall()
        data['companies_by_month'] = [{'month': r['month'], 'count': r['cnt']} for r in ncm]

        # 12. Contract types distribution
        ctd = db.execute("SELECT contract_type, COUNT(*) as cnt FROM contracts GROUP BY contract_type ORDER BY cnt DESC").fetchall()
        data['contract_types'] = [{'type': r['contract_type'], 'count': r['cnt']} for r in ctd]

        return {"success": True, "data": data}


# ─── Notifications API ───────────────────────────────────────

def send_notification(user_id, ntype, title, message="", entity_type=None, entity_id=None):
    """Create a notification for a user."""
    try:
        with get_db() as conn:
            # Check user preferences
            pref = conn.execute(
                "SELECT channel_web FROM notification_preferences WHERE user_id=? AND event_type=?",
                (user_id, ntype)
            ).fetchone()
            # Default: web notifications are enabled
            if pref and not pref[0]:
                return
            conn.execute(
                "INSERT INTO notifications (user_id, type, title, message, entity_type, entity_id) VALUES (?,?,?,?,?,?)",
                (user_id, ntype, title, message, entity_type, entity_id)
            )
    except Exception as e:
        logger.warning("Failed to send notification: %s", e)

@app.get("/api/notifications")
async def list_notifications(
    user=Depends(require_auth),
    unread_only: bool = False,
    limit: int = 50,
    offset: int = 0
):
    uid = user["user_id"]
    with get_db() as conn:
        where = "WHERE user_id=?"
        params = [uid]
        if unread_only:
            where += " AND is_read=0"
        total = conn.execute(f"SELECT COUNT(*) FROM notifications {where}", params).fetchone()[0]
        rows = conn.execute(
            f"SELECT * FROM notifications {where} ORDER BY created_at DESC LIMIT ? OFFSET ?",
            params + [limit, offset]
        ).fetchall()
        cols = [d[0] for d in conn.execute("SELECT * FROM notifications LIMIT 0").description]
        unread = conn.execute("SELECT COUNT(*) FROM notifications WHERE user_id=? AND is_read=0", (uid,)).fetchone()[0]
    return _ok({"items": [dict(zip(cols, r)) for r in rows], "total": total, "unread": unread})

@app.put("/api/notifications/{notif_id}/read")
async def mark_notification_read(notif_id: int, user=Depends(require_auth)):
    with get_db() as conn:
        conn.execute("UPDATE notifications SET is_read=1 WHERE id=? AND user_id=?", (notif_id, user["user_id"]))
    return _ok({"message": "Marked as read"})

@app.put("/api/notifications/read-all")
async def mark_all_notifications_read(user=Depends(require_auth)):
    with get_db() as conn:
        conn.execute("UPDATE notifications SET is_read=1 WHERE user_id=? AND is_read=0", (user["user_id"],))
    return _ok({"message": "All marked as read"})

@app.get("/api/notification-preferences")
async def get_notification_preferences(user=Depends(require_auth)):
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM notification_preferences WHERE user_id=?", (user["user_id"],)).fetchall()
        cols = [d[0] for d in conn.execute("SELECT * FROM notification_preferences LIMIT 0").description]
        return _ok([dict(zip(cols, r)) for r in rows])

@app.put("/api/notification-preferences")
async def update_notification_preferences(request: Request, user=Depends(require_auth)):
    data = await request.json()
    prefs = data.get("preferences", [])
    uid = user["user_id"]
    with get_db() as conn:
        for p in prefs:
            event_type = p.get("event_type","")
            if not event_type:
                continue
            conn.execute(
                "INSERT OR REPLACE INTO notification_preferences (user_id,event_type,channel_web,channel_email,channel_telegram) VALUES (?,?,?,?,?)",
                (uid, event_type, p.get("channel_web",1), p.get("channel_email",0), p.get("channel_telegram",0))
            )
    return _ok({"message": "Preferences updated"})


# ─── Audit Log API ───────────────────────────────────────────

@app.get("/api/audit-log")
async def get_audit_log(
    user=Depends(require_admin),
    user_id: Optional[int] = None,
    action: Optional[str] = None,
    entity_type: Optional[str] = None,
    from_date: Optional[str] = None,
    to_date: Optional[str] = None,
    limit: int = 50,
    offset: int = 0
):
    with get_db() as conn:
        where_parts = []
        params = []
        if user_id:
            where_parts.append("a.user_id=?")
            params.append(user_id)
        if action:
            where_parts.append("a.action=?")
            params.append(action)
        if entity_type:
            where_parts.append("a.entity_type=?")
            params.append(entity_type)
        if from_date:
            where_parts.append("a.created_at>=?")
            params.append(from_date)
        if to_date:
            where_parts.append("a.created_at<=?")
            params.append(to_date)

        where = ("WHERE " + " AND ".join(where_parts)) if where_parts else ""

        total = conn.execute(f"SELECT COUNT(*) FROM audit_log a {where}", params).fetchone()[0]
        rows = conn.execute(
            f"SELECT a.*, u.full_name as user_name FROM audit_log a LEFT JOIN users u ON a.user_id=u.id {where} ORDER BY a.created_at DESC LIMIT ? OFFSET ?",
            params + [limit, offset]
        ).fetchall()
        cols = [d[0] for d in rows[0].description] if hasattr(rows[0] if rows else None, 'description') else []
        if rows:
            # Get column names from cursor description
            cursor = conn.execute(f"SELECT a.*, u.full_name as user_name FROM audit_log a LEFT JOIN users u ON a.user_id=u.id LIMIT 0")
            cols = [d[0] for d in cursor.description]
        items = [dict(zip(cols, r)) for r in rows]
    return _ok({"items": items, "total": total})


# ─── Lead Assignment Rules API ────────────────────────────────

_round_robin_idx = {}  # rule_id -> last_assigned_idx

def auto_assign_lead(conn, lead_data):
    """Check assignment rules and auto-assign lead. Returns assigned_to user_id or None."""
    try:
        rules = conn.execute(
            "SELECT * FROM lead_assignment_rules WHERE is_active=1 ORDER BY priority DESC"
        ).fetchall()
    except Exception:
        return None

    for rule in rules:
        rule = dict(rule)
        conditions = json.loads(rule.get("conditions") or "{}")
        match = True
        for field, value in conditions.items():
            lead_val = str(lead_data.get(field, "")).lower()
            if lead_val != str(value).lower():
                match = False
                break
        if not match:
            continue

        if rule["assign_method"] == "round_robin":
            # Get all active managers
            managers = conn.execute(
                "SELECT id FROM users WHERE role IN ('admin','manager') AND is_active=1 ORDER BY id"
            ).fetchall()
            if managers:
                idx = _round_robin_idx.get(rule["id"], -1) + 1
                if idx >= len(managers):
                    idx = 0
                _round_robin_idx[rule["id"]] = idx
                return managers[idx]["id"]
        else:
            return rule.get("assign_to")
    return None


@app.get("/api/lead-assignment-rules")
async def list_lead_assignment_rules(user=Depends(require_auth)):
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM lead_assignment_rules ORDER BY priority DESC").fetchall()
        cols = [d[0] for d in conn.execute("SELECT * FROM lead_assignment_rules LIMIT 0").description]
    return _ok([dict(zip(cols, r)) for r in rows])


@app.post("/api/lead-assignment-rules")
async def create_lead_assignment_rule(request: Request, user=Depends(require_auth)):
    data = await request.json()
    name = (data.get("name") or "").strip()
    if not name:
        _err("Name is required")
    with get_db() as conn:
        cur = conn.execute(
            "INSERT INTO lead_assignment_rules (name, conditions, assign_to, assign_method, priority) VALUES (?,?,?,?,?)",
            [name, json.dumps(data.get("conditions", {})), data.get("assign_to"),
             data.get("assign_method", "direct"), data.get("priority", 0)]
        )
        log_audit(user["user_id"], "create_assignment_rule", "lead_assignment_rule", cur.lastrowid)
    return _ok({"id": cur.lastrowid, "message": "Rule created"})


@app.put("/api/lead-assignment-rules/{rule_id}")
async def update_lead_assignment_rule(rule_id: int, request: Request, user=Depends(require_auth)):
    data = await request.json()
    with get_db() as conn:
        old = conn.execute("SELECT * FROM lead_assignment_rules WHERE id=?", (rule_id,)).fetchone()
        if not old:
            _err("Rule not found", 404)
        sets, params = [], []
        for f in ["name", "conditions", "assign_to", "assign_method", "priority", "is_active"]:
            if f in data:
                val = data[f]
                if f == "conditions":
                    val = json.dumps(val) if isinstance(val, dict) else val
                sets.append(f"{f}=?")
                params.append(val)
        if sets:
            params.append(rule_id)
            conn.execute(f"UPDATE lead_assignment_rules SET {','.join(sets)} WHERE id=?", params)
            log_audit(user["user_id"], "update_assignment_rule", "lead_assignment_rule", rule_id)
    return _ok({"message": "Rule updated"})


@app.delete("/api/lead-assignment-rules/{rule_id}")
async def delete_lead_assignment_rule(rule_id: int, user=Depends(require_auth)):
    with get_db() as conn:
        conn.execute("DELETE FROM lead_assignment_rules WHERE id=?", (rule_id,))
        log_audit(user["user_id"], "delete_assignment_rule", "lead_assignment_rule", rule_id)
    return _ok({"message": "Rule deleted"})


# ─── Deal Team Members API ───────────────────────────────────

@app.get("/api/deals/{deal_id}/team")
async def get_deal_team(deal_id: int, user=Depends(require_auth)):
    with get_db() as conn:
        rows = conn.execute(
            """SELECT dtm.*, u.full_name, u.email, u.avatar_url
               FROM deal_team_members dtm
               JOIN users u ON dtm.user_id = u.id
               WHERE dtm.deal_id = ?
               ORDER BY dtm.added_at""",
            (deal_id,)
        ).fetchall()
        cols = [d[0] for d in rows[0].description] if rows and hasattr(rows[0], 'description') else []
        if rows:
            cursor = conn.execute(
                "SELECT dtm.*, u.full_name, u.email, u.avatar_url FROM deal_team_members dtm JOIN users u ON dtm.user_id = u.id LIMIT 0"
            )
            cols = [d[0] for d in cursor.description]
    return _ok([dict(zip(cols, r)) for r in rows])


@app.post("/api/deals/{deal_id}/team")
async def add_deal_team_member(deal_id: int, request: Request, user=Depends(require_auth)):
    data = await request.json()
    user_id = data.get("user_id")
    role = data.get("role", "member")
    if not user_id:
        _err("user_id is required")
    with get_db() as conn:
        deal = conn.execute("SELECT id FROM deals WHERE id=?", (deal_id,)).fetchone()
        if not deal:
            _err("Deal not found", 404)
        try:
            conn.execute(
                "INSERT INTO deal_team_members (deal_id, user_id, role) VALUES (?,?,?)",
                [deal_id, user_id, role]
            )
        except Exception:
            _err("User already in team")
        log_audit(user["user_id"], "add_deal_team_member", "deal", deal_id,
                  details=f"user_id={user_id}, role={role}")
    return _ok({"message": "Team member added"})


@app.delete("/api/deals/{deal_id}/team/{member_id}")
async def remove_deal_team_member(deal_id: int, member_id: int, user=Depends(require_auth)):
    with get_db() as conn:
        conn.execute("DELETE FROM deal_team_members WHERE id=? AND deal_id=?", (member_id, deal_id))
        log_audit(user["user_id"], "remove_deal_team_member", "deal", deal_id)
    return _ok({"message": "Team member removed"})


# ─── Web-to-Lead (Public API) ────────────────────────────────

_web_lead_rate = {}  # ip -> [timestamps]

@app.post("/api/public/leads")
async def public_create_lead(request: Request):
    """Public web-to-lead endpoint. No auth required, rate limited."""
    client_ip = _get_ip(request)

    # Rate limit: max 5 leads per IP per hour
    now = time.time()
    if client_ip not in _web_lead_rate:
        _web_lead_rate[client_ip] = []
    _web_lead_rate[client_ip] = [t for t in _web_lead_rate[client_ip] if now - t < 3600]
    if len(_web_lead_rate[client_ip]) >= 5:
        _err("Too many submissions. Please try again later.", 429)
    _web_lead_rate[client_ip].append(now)

    data = await request.json()
    company_name = (data.get("company_name") or "").strip()
    contact_name = (data.get("contact_name") or "").strip()
    email = (data.get("email") or "").strip()
    phone = (data.get("phone") or "").strip()
    message = (data.get("message") or "").strip()

    if not company_name and not contact_name:
        _err("Company name or contact name is required", 400)

    # Validate lengths
    for val, name, mx in [(company_name,"company_name",300),(contact_name,"contact_name",200),(email,"email",200),(phone,"phone",50),(message,"message",2000)]:
        _validate_length(val, name, mx)

    with get_db() as conn:
        cur = conn.execute(
            """INSERT INTO leads (company_name, contact_name, email, phone, source, status, priority, notes, created_by)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            [company_name or contact_name, contact_name, email, phone, "website", "new", "medium",
             f"Web form submission:\n{message}" if message else "", None]
        )
        lead_id = cur.lastrowid
        log_audit(None, "web_lead_created", "lead", lead_id, ip=client_ip,
                  details=f"company={company_name}, email={email}")

        # Send notifications to all admins/managers
        try:
            admins = conn.execute("SELECT id FROM users WHERE role IN ('admin','manager') AND is_active=1").fetchall()
            for admin in admins:
                try:
                    send_notification(admin["id"], "lead_new",
                                     f"New web lead: {company_name or contact_name}",
                                     f"From: {contact_name} ({email})", "lead", lead_id)
                except Exception:
                    pass
        except Exception:
            pass

    return _ok({"message": "Thank you! We will contact you soon.", "id": lead_id})


@app.get("/api/public/leads/form-config")
async def web_lead_form_config():
    """Get web form configuration (public)."""
    return _ok({
        "fields": [
            {"name": "company_name", "label": "Company", "type": "text", "required": False},
            {"name": "contact_name", "label": "Your Name", "type": "text", "required": True},
            {"name": "email", "label": "Email", "type": "email", "required": True},
            {"name": "phone", "label": "Phone", "type": "tel", "required": False},
            {"name": "message", "label": "Message", "type": "textarea", "required": False}
        ],
        "submit_url": f"{BASE_URL}/api/public/leads",
        "branding": "Hermes CRM"
    })


@app.get("/api/public/leads/widget.js")
async def web_lead_widget():
    """Embeddable JavaScript widget for web-to-lead form."""
    js = f"""
(function(){{
  var SUBMIT_URL = "{BASE_URL}/api/public/leads";
  var container = document.getElementById('hermes-lead-form') || document.currentScript.parentElement;
  container.innerHTML = '<form id="hermesLeadForm" style="max-width:400px;font-family:sans-serif;">' +
    '<div style="margin-bottom:12px;"><label style="display:block;font-size:13px;margin-bottom:4px;">Your Name *</label><input name="contact_name" required style="width:100%;padding:8px;border:1px solid #ddd;border-radius:4px;"></div>' +
    '<div style="margin-bottom:12px;"><label style="display:block;font-size:13px;margin-bottom:4px;">Email *</label><input name="email" type="email" required style="width:100%;padding:8px;border:1px solid #ddd;border-radius:4px;"></div>' +
    '<div style="margin-bottom:12px;"><label style="display:block;font-size:13px;margin-bottom:4px;">Company</label><input name="company_name" style="width:100%;padding:8px;border:1px solid #ddd;border-radius:4px;"></div>' +
    '<div style="margin-bottom:12px;"><label style="display:block;font-size:13px;margin-bottom:4px;">Phone</label><input name="phone" type="tel" style="width:100%;padding:8px;border:1px solid #ddd;border-radius:4px;"></div>' +
    '<div style="margin-bottom:12px;"><label style="display:block;font-size:13px;margin-bottom:4px;">Message</label><textarea name="message" rows="3" style="width:100%;padding:8px;border:1px solid #ddd;border-radius:4px;"></textarea></div>' +
    '<button type="submit" style="background:#6366f1;color:white;padding:10px 24px;border:none;border-radius:4px;cursor:pointer;font-size:14px;">Submit</button>' +
    '<div id="hermesFormMsg" style="margin-top:8px;font-size:13px;"></div>' +
    '</form>';
  document.getElementById('hermesLeadForm').addEventListener('submit', function(e) {{
    e.preventDefault();
    var fd = new FormData(this);
    var data = {{}};
    fd.forEach(function(v,k){{ data[k]=v; }});
    var msg = document.getElementById('hermesFormMsg');
    msg.textContent = 'Sending...';
    fetch(SUBMIT_URL, {{ method:'POST', headers:{{'Content-Type':'application/json'}}, body:JSON.stringify(data) }})
      .then(function(r){{ return r.json(); }})
      .then(function(d){{ msg.style.color='green'; msg.textContent=d.data?.message||'Thank you!'; document.getElementById('hermesLeadForm').reset(); }})
      .catch(function(){{ msg.style.color='red'; msg.textContent='Error. Please try again.'; }});
  }});
}})();
"""
    return Response(content=js, media_type="application/javascript")


# ─── Phase 3: Service Cloud ──────────────────────────────────

def _ticket_row_to_dict(row, cols):
    d = dict(zip(cols, row))
    if isinstance(d.get("tags"), str):
        try:
            d["tags"] = __import__("json").loads(d["tags"])
        except:
            d["tags"] = []
    return d


@app.get("/api/tickets")
async def list_tickets(
    status: Optional[str] = None,
    priority: Optional[str] = None,
    assigned_to: Optional[int] = None,
    company_id: Optional[int] = None,
    limit: int = Query(100, ge=1, le=500),
    user=Depends(require_auth),
):
    with get_db() as conn:
        where, params = [], []
        if status:
            where.append("t.status=?")
            params.append(status)
        if priority:
            where.append("t.priority=?")
            params.append(priority)
        if assigned_to:
            where.append("t.assigned_to=?")
            params.append(assigned_to)
        if company_id:
            where.append("t.company_id=?")
            params.append(company_id)
        wc = ("WHERE " + " AND ".join(where)) if where else ""
        rows = conn.execute(
            f"""SELECT t.*, u.full_name as assigned_name, c.name as company_name,
                       cr.full_name as creator_name
                FROM tickets t
                LEFT JOIN users u ON t.assigned_to=u.id
                LEFT JOIN companies c ON t.company_id=c.id
                LEFT JOIN users cr ON t.created_by=cr.id
                {wc} ORDER BY t.created_at DESC LIMIT ?""",
            params + [limit]
        ).fetchall()
        cols = [d[0] for d in conn.execute(
            "SELECT t.*, u.full_name as assigned_name, c.name as company_name, cr.full_name as creator_name FROM tickets t LEFT JOIN users u ON t.assigned_to=u.id LEFT JOIN companies c ON t.company_id=c.id LEFT JOIN users cr ON t.created_by=cr.id LIMIT 0"
        ).description]
        total = conn.execute(f"SELECT COUNT(*) FROM tickets t {wc}", params).fetchone()[0]
        return _ok([_ticket_row_to_dict(r, cols) for r in rows], total=total)


@app.post("/api/tickets")
async def create_ticket(request: Request, user=Depends(require_auth)):
    data = await request.json()
    import json as _json
    with get_db() as conn:
        # Auto-assign SLA based on priority
        priority = data.get("priority", "medium")
        sla = conn.execute("SELECT id FROM sla_policies WHERE priority=? AND is_active=1 LIMIT 1", [priority]).fetchone()
        sla_id = sla[0] if sla else None
        tags = _json.dumps(data.get("tags", []))
        cur = conn.execute(
            """INSERT INTO tickets (subject, description, status, priority, category,
               company_id, contact_id, assigned_to, created_by, sla_policy_id, tags)
               VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            [data.get("subject",""), data.get("description",""), "open", priority,
             data.get("category","general"), data.get("company_id"), data.get("contact_id"),
             data.get("assigned_to"), user["user_id"], sla_id, tags]
        )
        tid = cur.lastrowid
        _notify_assigned = data.get("assigned_to") and data["assigned_to"] != user["user_id"]
        _notify_subject = data.get("subject", "")
    # Notification OUTSIDE db block to avoid deadlock
    if _notify_assigned:
        send_notification(data["assigned_to"], "ticket_assigned",
            f"New ticket #{tid}: {_notify_subject}", f"Ticket #{tid} assigned to you", "ticket", tid)
    log_audit(user["user_id"], "create_ticket", "ticket", tid, ip=_get_ip(request))
    return _ok({"id": tid})


@app.get("/api/tickets/stats")
async def ticket_stats(user=Depends(require_auth)):
    with get_db() as conn:
        # Run live SLA breach check on all open tickets
        open_ids = conn.execute("SELECT id FROM tickets WHERE status NOT IN ('closed','resolved') AND sla_policy_id IS NOT NULL").fetchall()
        for oid in open_ids:
            _check_sla_breach(conn, oid[0])
        stats = {}
        for s in ["open", "in_progress", "waiting", "resolved", "closed"]:
            stats[s] = conn.execute("SELECT COUNT(*) FROM tickets WHERE status=?", [s]).fetchone()[0]
        stats["total"] = sum(stats.values())
        stats["breached"] = conn.execute("SELECT COUNT(*) FROM tickets WHERE sla_breach=1").fetchone()[0]
        stats["unassigned"] = conn.execute("SELECT COUNT(*) FROM tickets WHERE assigned_to IS NULL AND status NOT IN ('closed','resolved')").fetchone()[0]
        return _ok(stats)


@app.get("/api/tickets/{ticket_id}")
async def get_ticket(ticket_id: int, user=Depends(require_auth)):
    with get_db() as conn:
        row = conn.execute(
            """SELECT t.*, u.full_name as assigned_name, c.name as company_name,
                      cr.full_name as creator_name
               FROM tickets t
               LEFT JOIN users u ON t.assigned_to=u.id
               LEFT JOIN companies c ON t.company_id=c.id
               LEFT JOIN users cr ON t.created_by=cr.id
               WHERE t.id=?""", [ticket_id]
        ).fetchone()
        if not row:
            _err("Ticket not found", 404)
        cols = [d[0] for d in conn.execute(
            "SELECT t.*, u.full_name as assigned_name, c.name as company_name, cr.full_name as creator_name FROM tickets t LEFT JOIN users u ON t.assigned_to=u.id LEFT JOIN companies c ON t.company_id=c.id LEFT JOIN users cr ON t.created_by=cr.id LIMIT 0"
        ).description]
        ticket = _ticket_row_to_dict(row, cols)
        # Get comments
        comments = conn.execute(
            """SELECT tc.*, u.full_name as user_name FROM ticket_comments tc
               LEFT JOIN users u ON tc.user_id=u.id WHERE tc.ticket_id=? ORDER BY tc.created_at""",
            [ticket_id]
        ).fetchall()
        ccols = [d[0] for d in conn.execute(
            "SELECT tc.*, u.full_name as user_name FROM ticket_comments tc LEFT JOIN users u ON tc.user_id=u.id LIMIT 0"
        ).description]
        ticket["comments"] = [dict(zip(ccols, c)) for c in comments]
        # Live SLA breach check + SLA info
        if ticket.get("sla_policy_id"):
            _check_sla_breach(conn, ticket_id)
            # Re-read breach status after check
            ticket["sla_breach"] = conn.execute("SELECT sla_breach FROM tickets WHERE id=?", [ticket_id]).fetchone()[0]
            sla = conn.execute("SELECT * FROM sla_policies WHERE id=?", [ticket["sla_policy_id"]]).fetchone()
            if sla:
                scols = [d[0] for d in conn.execute("SELECT * FROM sla_policies LIMIT 0").description]
                ticket["sla"] = dict(zip(scols, sla))
        return _ok(ticket)


@app.put("/api/tickets/{ticket_id}")
async def update_ticket(ticket_id: int, request: Request, user=Depends(require_auth)):
    data = await request.json()
    import json as _json
    allowed = {"subject", "description", "status", "priority", "category",
               "company_id", "contact_id", "assigned_to", "tags"}
    updates = {k: v for k, v in data.items() if k in allowed}
    if "tags" in updates and isinstance(updates["tags"], list):
        updates["tags"] = _json.dumps(updates["tags"])
    if not updates:
        _err("No fields to update", 400)
    # Track status changes
    with get_db() as conn:
        old = conn.execute("SELECT status, assigned_to FROM tickets WHERE id=?", [ticket_id]).fetchone()
        if not old:
            _err("Ticket not found", 404)
        # Set timestamps for status transitions
        new_status = updates.get("status")
        if new_status and new_status != old[0]:
            if new_status == "resolved":
                updates["resolved_at"] = "datetime('now')"
            elif new_status == "closed":
                updates["closed_at"] = "datetime('now')"
        # Check first response
        if "assigned_to" in updates or new_status:
            existing = conn.execute("SELECT first_response_at FROM tickets WHERE id=?", [ticket_id]).fetchone()
            if existing and not existing[0]:
                updates["first_response_at"] = "datetime('now')"
        # Build SET clause
        set_parts, vals = [], []
        for k, v in updates.items():
            if v == "datetime('now')":
                set_parts.append(f"{k}=datetime('now')")
            else:
                set_parts.append(f"{k}=?")
                vals.append(v)
        set_parts.append("updated_at=datetime('now')")
        conn.execute(f"UPDATE tickets SET {','.join(set_parts)} WHERE id=?", vals + [ticket_id])
        # SLA breach check
        if new_status in ("resolved", "closed"):
            _check_sla_breach(conn, ticket_id)
        # Prepare notification data (send OUTSIDE db block)
        new_assigned = updates.get("assigned_to")
        _notify_assign = False
        _notify_subj = ""
        if new_assigned and new_assigned != old[1] and new_assigned != user["user_id"]:
            subj = conn.execute("SELECT subject FROM tickets WHERE id=?", [ticket_id]).fetchone()
            _notify_assign = True
            _notify_subj = subj[0] if subj else ""
    # Notification OUTSIDE db block to avoid deadlock
    if _notify_assign:
        send_notification(new_assigned, "ticket_assigned",
            f"Ticket #{ticket_id}: {_notify_subj}", f"Ticket #{ticket_id} assigned to you", "ticket", ticket_id)
    log_audit(user["user_id"], "update_ticket", "ticket", ticket_id, ip=_get_ip(request))
    return _ok({"updated": True})


def _check_sla_breach(conn, ticket_id):
    """Check if ticket breached SLA — covers both responded and no-response cases."""
    row = conn.execute(
        "SELECT sla_policy_id, created_at, first_response_at, resolved_at, status FROM tickets WHERE id=?",
        [ticket_id]
    ).fetchone()
    if not row or not row[0]:
        return False
    sla = conn.execute("SELECT first_response_hours, resolution_hours FROM sla_policies WHERE id=?", [row[0]]).fetchone()
    if not sla:
        return False
    from datetime import datetime, timedelta
    now = datetime.utcnow()
    created = datetime.fromisoformat(row[1].replace("Z", ""))
    breached = 0
    status = row[4] or "open"
    # First response breach: responded late OR no response and deadline passed
    if row[2]:  # first_response_at exists
        fr = datetime.fromisoformat(row[2].replace("Z", ""))
        if (fr - created).total_seconds() > sla[0] * 3600:
            breached = 1
    elif status not in ("closed", "resolved"):
        # No response yet — check if deadline passed
        if (now - created).total_seconds() > sla[0] * 3600:
            breached = 1
    # Resolution breach: resolved late OR not resolved and deadline passed
    if row[3]:  # resolved_at exists
        res = datetime.fromisoformat(row[3].replace("Z", ""))
        if (res - created).total_seconds() > sla[1] * 3600:
            breached = 1
    elif status not in ("closed", "resolved"):
        if (now - created).total_seconds() > sla[1] * 3600:
            breached = 1
    conn.execute("UPDATE tickets SET sla_breach=? WHERE id=?", [breached, ticket_id])
    return breached == 1


@app.delete("/api/tickets/{ticket_id}")
async def delete_ticket(ticket_id: int, request: Request, user=Depends(require_admin)):
    with get_db() as conn:
        conn.execute("DELETE FROM ticket_comments WHERE ticket_id=?", [ticket_id])
        conn.execute("DELETE FROM tickets WHERE id=?", [ticket_id])
    log_audit(user["user_id"], "delete_ticket", "ticket", ticket_id, ip=_get_ip(request))
    return _ok({"deleted": True})


@app.post("/api/tickets/{ticket_id}/comments")
async def add_ticket_comment(ticket_id: int, request: Request, user=Depends(require_auth)):
    data = await request.json()
    with get_db() as conn:
        conn.execute(
            "INSERT INTO ticket_comments (ticket_id, user_id, content, is_internal) VALUES (?,?,?,?)",
            [ticket_id, user["user_id"], data.get("content",""), 1 if data.get("is_internal") else 0]
        )
        # Mark first response if not yet set
        conn.execute(
            "UPDATE tickets SET first_response_at=datetime('now'), updated_at=datetime('now') WHERE id=? AND first_response_at IS NULL",
            [ticket_id]
        )
    return _ok({"added": True})


# ─── SLA Policies ────────────────────────────────────────────

@app.get("/api/sla-policies")
async def list_sla_policies(user=Depends(require_auth)):
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM sla_policies ORDER BY first_response_hours").fetchall()
        cols = [d[0] for d in conn.execute("SELECT * FROM sla_policies LIMIT 0").description]
        return _ok([dict(zip(cols, r)) for r in rows])


@app.post("/api/sla-policies")
async def create_sla_policy(request: Request, user=Depends(require_admin)):
    data = await request.json()
    with get_db() as conn:
        cur = conn.execute(
            "INSERT INTO sla_policies (name, priority, first_response_hours, resolution_hours) VALUES (?,?,?,?)",
            [data.get("name",""), data.get("priority","medium"),
             data.get("first_response_hours", 4), data.get("resolution_hours", 24)]
        )
        return _ok({"id": cur.lastrowid})


@app.put("/api/sla-policies/{policy_id}")
async def update_sla_policy(policy_id: int, request: Request, user=Depends(require_admin)):
    data = await request.json()
    allowed = {"name", "priority", "first_response_hours", "resolution_hours", "is_active"}
    updates = {k: v for k, v in data.items() if k in allowed}
    if not updates:
        _err("No fields", 400)
    parts = [f"{k}=?" for k in updates]
    with get_db() as conn:
        conn.execute(f"UPDATE sla_policies SET {','.join(parts)} WHERE id=?", list(updates.values()) + [policy_id])
    return _ok({"updated": True})


@app.delete("/api/sla-policies/{policy_id}")
async def delete_sla_policy(policy_id: int, user=Depends(require_admin)):
    with get_db() as conn:
        conn.execute("DELETE FROM sla_policies WHERE id=?", [policy_id])
    return _ok({"deleted": True})


# ─── Knowledge Base ──────────────────────────────────────────

@app.get("/api/kb/articles")
async def list_kb_articles(
    category: Optional[str] = None,
    status: Optional[str] = None,
    q: Optional[str] = None,
    user=Depends(require_auth),
):
    with get_db() as conn:
        where, params = [], []
        if category:
            where.append("category=?")
            params.append(category)
        if status:
            where.append("status=?")
            params.append(status)
        if q:
            where.append("(title LIKE ? OR content LIKE ?)")
            params.extend([f"%{q}%", f"%{q}%"])
        wc = ("WHERE " + " AND ".join(where)) if where else ""
        rows = conn.execute(
            f"SELECT a.*, u.full_name as author_name FROM kb_articles a LEFT JOIN users u ON a.created_by=u.id {wc} ORDER BY a.updated_at DESC",
            params
        ).fetchall()
        cols = [d[0] for d in conn.execute("SELECT a.*, u.full_name as author_name FROM kb_articles a LEFT JOIN users u ON a.created_by=u.id LIMIT 0").description]
        return _ok([dict(zip(cols, r)) for r in rows])


@app.post("/api/kb/articles")
async def create_kb_article(request: Request, user=Depends(require_auth)):
    data = await request.json()
    import json as _json
    with get_db() as conn:
        cur = conn.execute(
            "INSERT INTO kb_articles (title, content, category, tags, status, created_by) VALUES (?,?,?,?,?,?)",
            [data.get("title",""), data.get("content",""), data.get("category","general"),
             _json.dumps(data.get("tags",[])), data.get("status","draft"), user["user_id"]]
        )
        return _ok({"id": cur.lastrowid})


@app.get("/api/kb/articles/{article_id}")
async def get_kb_article(article_id: int, user=Depends(require_auth)):
    with get_db() as conn:
        conn.execute("UPDATE kb_articles SET views=views+1 WHERE id=?", [article_id])
        row = conn.execute(
            "SELECT a.*, u.full_name as author_name FROM kb_articles a LEFT JOIN users u ON a.created_by=u.id WHERE a.id=?",
            [article_id]
        ).fetchone()
        if not row:
            _err("Article not found", 404)
        cols = [d[0] for d in conn.execute("SELECT a.*, u.full_name as author_name FROM kb_articles a LEFT JOIN users u ON a.created_by=u.id LIMIT 0").description]
        return _ok(dict(zip(cols, row)))


@app.put("/api/kb/articles/{article_id}")
async def update_kb_article(article_id: int, request: Request, user=Depends(require_auth)):
    data = await request.json()
    import json as _json
    allowed = {"title", "content", "category", "tags", "status"}
    updates = {k: v for k, v in data.items() if k in allowed}
    if "tags" in updates and isinstance(updates["tags"], list):
        updates["tags"] = _json.dumps(updates["tags"])
    if not updates:
        _err("No fields", 400)
    parts = [f"{k}=?" for k in updates]
    parts.append("updated_at=datetime('now')")
    with get_db() as conn:
        conn.execute(f"UPDATE kb_articles SET {','.join(parts)} WHERE id=?", list(updates.values()) + [article_id])
    return _ok({"updated": True})


@app.delete("/api/kb/articles/{article_id}")
async def delete_kb_article(article_id: int, user=Depends(require_admin)):
    with get_db() as conn:
        conn.execute("DELETE FROM kb_articles WHERE id=?", [article_id])
    return _ok({"deleted": True})


@app.post("/api/kb/articles/{article_id}/helpful")
async def kb_article_helpful(article_id: int, request: Request, user=Depends(require_auth)):
    data = await request.json()
    col = "helpful_yes" if data.get("helpful") else "helpful_no"
    with get_db() as conn:
        conn.execute(f"UPDATE kb_articles SET {col}={col}+1 WHERE id=?", [article_id])
    return _ok({"ok": True})


# ─── PHASE 4: Marketing Cloud ─────────────────────────────────────

# ─── Email Templates ──────────────────────────────────────────────
@app.get("/api/email-templates")
async def list_email_templates(
    category: Optional[str] = None,
    lang: Optional[str] = None,
    limit: int = Query(100, ge=1, le=500),
    user=Depends(require_auth),
):
    with get_db() as conn:
        where, params = [], []
        if category:
            where.append("category=?")
            params.append(category)
        if lang:
            where.append("lang=?")
            params.append(lang)
        wc = ("WHERE " + " AND ".join(where)) if where else ""
        rows = conn.execute(
            f"""SELECT t.*, u.full_name as creator_name FROM email_templates t
               LEFT JOIN users u ON t.created_by=u.id
               {wc} ORDER BY t.created_at DESC LIMIT ?""",
            params + [limit]
        ).fetchall()
        cols = [d[0] for d in conn.execute(
            "SELECT t.*, u.full_name as creator_name FROM email_templates t LEFT JOIN users u ON t.created_by=u.id LIMIT 0"
        ).description]
        total = conn.execute(f"SELECT COUNT(*) FROM email_templates {wc}", params).fetchone()[0]
        return _ok([dict(zip(cols, r)) for r in rows], total=total)


@app.post("/api/email-templates")
async def create_email_template(request: Request, user=Depends(require_auth)):
    data = await request.json()
    with get_db() as conn:
        cur = conn.execute(
            """INSERT INTO email_templates (name, subject, body_html, category, lang, created_by, is_active)
               VALUES (?,?,?,?,?,?,?)""",
            [data.get("name",""), data.get("subject",""), data.get("body_html",""),
             data.get("category","general"), data.get("lang","en"), user["user_id"], 1]
        )
        tid = cur.lastrowid
    log_audit(user["user_id"], "create_email_template", "email_template", tid, ip=_get_ip(request))
    return _ok({"id": tid})


@app.get("/api/email-templates/{template_id}")
async def get_email_template(template_id: int, user=Depends(require_auth)):
    with get_db() as conn:
        row = conn.execute(
            """SELECT t.*, u.full_name as creator_name FROM email_templates t
               LEFT JOIN users u ON t.created_by=u.id WHERE t.id=?""",
            [template_id]
        ).fetchone()
        if not row:
            _err("Template not found", 404)
        cols = [d[0] for d in conn.execute(
            "SELECT t.*, u.full_name as creator_name FROM email_templates t LEFT JOIN users u ON t.created_by=u.id LIMIT 0"
        ).description]
        return _ok(dict(zip(cols, row)))


@app.put("/api/email-templates/{template_id}")
async def update_email_template(template_id: int, request: Request, user=Depends(require_auth)):
    data = await request.json()
    allowed = {"name", "subject", "body_html", "category", "lang", "is_active"}
    updates = {k: v for k, v in data.items() if k in allowed}
    if not updates:
        _err("No fields to update", 400)
    parts = [f"{k}=?" for k in updates]
    parts.append("updated_at=datetime('now')")
    with get_db() as conn:
        conn.execute(f"UPDATE email_templates SET {','.join(parts)} WHERE id=?", list(updates.values()) + [template_id])
    log_audit(user["user_id"], "update_email_template", "email_template", template_id, ip=_get_ip(request))
    return _ok({"updated": True})


@app.delete("/api/email-templates/{template_id}")
async def delete_email_template(template_id: int, user=Depends(require_admin)):
    with get_db() as conn:
        conn.execute("DELETE FROM email_templates WHERE id=?", [template_id])
    return _ok({"deleted": True})


# ─── Campaigns ────────────────────────────────────────────────────
@app.get("/api/campaigns/stats")
async def campaign_stats(user=Depends(require_auth)):
    with get_db() as conn:
        stats = {}
        for s in ["draft", "scheduled", "sending", "sent", "cancelled"]:
            stats[s] = conn.execute("SELECT COUNT(*) FROM campaigns WHERE status=?", [s]).fetchone()[0]
        stats["total"] = sum(stats.values())
        return _ok(stats)


@app.get("/api/campaigns")
async def list_campaigns(
    status: Optional[str] = None,
    type: Optional[str] = None,
    limit: int = Query(100, ge=1, le=500),
    user=Depends(require_auth),
):
    with get_db() as conn:
        where, params = [], []
        if status:
            where.append("c.status=?")
            params.append(status)
        if type:
            where.append("c.type=?")
            params.append(type)
        wc = ("WHERE " + " AND ".join(where)) if where else ""
        rows = conn.execute(
            f"""SELECT c.*, u.full_name as creator_name, t.name as template_name FROM campaigns c
               LEFT JOIN users u ON c.created_by=u.id
               LEFT JOIN email_templates t ON c.template_id=t.id
               {wc} ORDER BY c.created_at DESC LIMIT ?""",
            params + [limit]
        ).fetchall()
        cols = [d[0] for d in conn.execute(
            "SELECT c.*, u.full_name as creator_name, t.name as template_name FROM campaigns c LEFT JOIN users u ON c.created_by=u.id LEFT JOIN email_templates t ON c.template_id=t.id LIMIT 0"
        ).description]
        total = conn.execute(f"SELECT COUNT(*) FROM campaigns c {wc}", params).fetchone()[0]
        return _ok([dict(zip(cols, r)) for r in rows], total=total)


@app.post("/api/campaigns")
async def create_campaign(request: Request, user=Depends(require_auth)):
    data = await request.json()
    with get_db() as conn:
        cur = conn.execute(
            """INSERT INTO campaigns (name, description, type, status, template_id, target_type, target_filter, created_by)
               VALUES (?,?,?,?,?,?,?,?)""",
            [data.get("name",""), data.get("description",""), data.get("type","email"),
             "draft", data.get("template_id"), data.get("target_type","all"),
             __import__("json").dumps(data.get("target_filter",{})), user["user_id"]]
        )
        cid = cur.lastrowid
    log_audit(user["user_id"], "create_campaign", "campaign", cid, ip=_get_ip(request))
    return _ok({"id": cid})


@app.get("/api/campaigns/{campaign_id}")
async def get_campaign(campaign_id: int, user=Depends(require_auth)):
    with get_db() as conn:
        row = conn.execute(
            """SELECT c.*, u.full_name as creator_name, t.name as template_name FROM campaigns c
               LEFT JOIN users u ON c.created_by=u.id
               LEFT JOIN email_templates t ON c.template_id=t.id WHERE c.id=?""",
            [campaign_id]
        ).fetchone()
        if not row:
            _err("Campaign not found", 404)
        cols = [d[0] for d in conn.execute(
            "SELECT c.*, u.full_name as creator_name, t.name as template_name FROM campaigns c LEFT JOIN users u ON c.created_by=u.id LEFT JOIN email_templates t ON c.template_id=t.id LIMIT 0"
        ).description]
        campaign = dict(zip(cols, row))
        # Get recipients
        recipients = conn.execute(
            "SELECT * FROM campaign_recipients WHERE campaign_id=? ORDER BY sent_at DESC LIMIT 100",
            [campaign_id]
        ).fetchall()
        rcols = [d[0] for d in conn.execute("SELECT * FROM campaign_recipients LIMIT 0").description]
        campaign["recipients"] = [dict(zip(rcols, r)) for r in recipients]
        return _ok(campaign)


@app.put("/api/campaigns/{campaign_id}")
async def update_campaign(campaign_id: int, request: Request, user=Depends(require_auth)):
    data = await request.json()
    allowed = {"name", "description", "type", "status", "template_id", "target_type", "target_filter", "scheduled_at"}
    updates = {k: v for k, v in data.items() if k in allowed}
    if "target_filter" in updates and isinstance(updates["target_filter"], dict):
        updates["target_filter"] = __import__("json").dumps(updates["target_filter"])
    if not updates:
        _err("No fields to update", 400)
    parts = [f"{k}=?" for k in updates]
    parts.append("updated_at=datetime('now')")
    with get_db() as conn:
        conn.execute(f"UPDATE campaigns SET {','.join(parts)} WHERE id=?", list(updates.values()) + [campaign_id])
    log_audit(user["user_id"], "update_campaign", "campaign", campaign_id, ip=_get_ip(request))
    return _ok({"updated": True})


@app.delete("/api/campaigns/{campaign_id}")
async def delete_campaign(campaign_id: int, user=Depends(require_admin)):
    with get_db() as conn:
        conn.execute("DELETE FROM campaign_recipients WHERE campaign_id=?", [campaign_id])
        conn.execute("DELETE FROM campaigns WHERE id=?", [campaign_id])
    return _ok({"deleted": True})


@app.post("/api/campaigns/{campaign_id}/send")
async def send_campaign(campaign_id: int, request: Request, user=Depends(require_auth)):
    """Simulated campaign send - marks recipients as sent with timestamps."""
    with get_db() as conn:
        campaign = conn.execute("SELECT * FROM campaigns WHERE id=?", [campaign_id]).fetchone()
        if not campaign:
            _err("Campaign not found", 404)

        # Get template to populate recipients if not already done
        if not conn.execute("SELECT COUNT(*) FROM campaign_recipients WHERE campaign_id=?", [campaign_id]).fetchone()[0]:
            # Get contacts to send to
            contacts = conn.execute("SELECT id, email FROM contacts WHERE email IS NOT NULL LIMIT 100").fetchall()
            now = datetime.utcnow().isoformat() + "Z"
            for contact_id, email in contacts:
                conn.execute(
                    """INSERT INTO campaign_recipients (campaign_id, recipient_type, recipient_id, email, status, sent_at)
                       VALUES (?,?,?,?,?,?)""",
                    [campaign_id, "contact", contact_id, email, "sent", now]
                )

        # Mark as sent
        now = datetime.utcnow().isoformat() + "Z"
        total_recipients = conn.execute("SELECT COUNT(*) FROM campaign_recipients WHERE campaign_id=?", [campaign_id]).fetchone()[0]
        conn.execute(
            """UPDATE campaigns SET status='sent', sent_at=?, sent_count=? WHERE id=?""",
            [now, total_recipients, campaign_id]
        )

    log_audit(user["user_id"], "send_campaign", "campaign", campaign_id, ip=_get_ip(request))
    return _ok({"sent": True, "count": total_recipients})


# ─── Web Forms ────────────────────────────────────────────────────
@app.get("/api/web-forms")
async def list_web_forms(
    is_active: Optional[int] = None,
    limit: int = Query(100, ge=1, le=500),
    user=Depends(require_auth),
):
    with get_db() as conn:
        where, params = [], []
        if is_active is not None:
            where.append("is_active=?")
            params.append(is_active)
        wc = ("WHERE " + " AND ".join(where)) if where else ""
        rows = conn.execute(
            f"""SELECT f.*, u.full_name as creator_name FROM web_forms f
               LEFT JOIN users u ON f.created_by=u.id
               {wc} ORDER BY f.created_at DESC LIMIT ?""",
            params + [limit]
        ).fetchall()
        cols = [d[0] for d in conn.execute(
            "SELECT f.*, u.full_name as creator_name FROM web_forms f LEFT JOIN users u ON f.created_by=u.id LIMIT 0"
        ).description]
        total = conn.execute(f"SELECT COUNT(*) FROM web_forms {wc}", params).fetchone()[0]
        return _ok([dict(zip(cols, r)) for r in rows], total=total)


@app.post("/api/web-forms")
async def create_web_form(request: Request, user=Depends(require_auth)):
    data = await request.json()
    token = secrets.token_urlsafe(24)
    with get_db() as conn:
        cur = conn.execute(
            """INSERT INTO web_forms (name, description, fields_config, redirect_url, is_active, form_token, lead_source, assign_to, created_by)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            [data.get("name",""), data.get("description",""), __import__("json").dumps(data.get("fields_config",[])),
             data.get("redirect_url",""), 1, token, "web_form", data.get("assign_to"), user["user_id"]]
        )
        fid = cur.lastrowid
    log_audit(user["user_id"], "create_web_form", "web_form", fid, ip=_get_ip(request))
    return _ok({"id": fid, "token": token})


@app.get("/api/web-forms/{form_id}")
async def get_web_form(form_id: int, user=Depends(require_auth)):
    with get_db() as conn:
        row = conn.execute(
            """SELECT f.*, u.full_name as creator_name FROM web_forms f
               LEFT JOIN users u ON f.created_by=u.id WHERE f.id=?""",
            [form_id]
        ).fetchone()
        if not row:
            _err("Form not found", 404)
        cols = [d[0] for d in conn.execute(
            "SELECT f.*, u.full_name as creator_name FROM web_forms f LEFT JOIN users u ON f.created_by=u.id LIMIT 0"
        ).description]
        form = dict(zip(cols, row))
        if form.get("fields_config"):
            form["fields_config"] = __import__("json").loads(form["fields_config"])
        return _ok(form)


@app.put("/api/web-forms/{form_id}")
async def update_web_form(form_id: int, request: Request, user=Depends(require_auth)):
    data = await request.json()
    allowed = {"name", "description", "fields_config", "redirect_url", "is_active", "assign_to"}
    updates = {k: v for k, v in data.items() if k in allowed}
    if "fields_config" in updates and isinstance(updates["fields_config"], list):
        updates["fields_config"] = __import__("json").dumps(updates["fields_config"])
    if not updates:
        _err("No fields to update", 400)
    parts = [f"{k}=?" for k in updates]
    with get_db() as conn:
        conn.execute(f"UPDATE web_forms SET {','.join(parts)} WHERE id=?", list(updates.values()) + [form_id])
    log_audit(user["user_id"], "update_web_form", "web_form", form_id, ip=_get_ip(request))
    return _ok({"updated": True})


@app.delete("/api/web-forms/{form_id}")
async def delete_web_form(form_id: int, user=Depends(require_admin)):
    with get_db() as conn:
        conn.execute("DELETE FROM web_forms WHERE id=?", [form_id])
    return _ok({"deleted": True})


@app.post("/api/web-forms/submit/{token}")
async def submit_web_form(token: str, request: Request):
    """Public endpoint - no auth required. Creates a lead from web form submission."""
    try:
        data = await request.json()
    except:
        data = dict(await request.form())

    with get_db() as conn:
        form = conn.execute("SELECT * FROM web_forms WHERE form_token=? AND is_active=1", [token]).fetchone()
        if not form:
            _err("Form not found or inactive", 404)

        # Extract form data based on fields_config
        form_data = form[3]  # fields_config
        try:
            fields_config = __import__("json").loads(form_data) if isinstance(form_data, str) else []
        except:
            fields_config = []

        # Create contact from form submission
        email = data.get("email", "")
        name = data.get("name", "")
        company_name = data.get("company", "")
        phone = data.get("phone", "")

        if not email:
            _err("Email is required", 400)

        # Check if contact exists
        existing_contact = conn.execute("SELECT id FROM contacts WHERE email=?", [email]).fetchone()
        if existing_contact:
            contact_id = existing_contact[0]
        else:
            # Create new contact
            company_id = None
            if company_name:
                company = conn.execute("SELECT id FROM companies WHERE name=?", [company_name]).fetchone()
                if company:
                    company_id = company[0]

            cur = conn.execute(
                """INSERT INTO contacts (name, email, phone, company_id, created_at, updated_at)
                   VALUES (?,?,?,?,datetime('now'),datetime('now'))""",
                [name, email, phone, company_id]
            )
            contact_id = cur.lastrowid

        # Store submission metadata as activity
        submission_text = "Form: " + "; ".join([f"{k}={v}" for k,v in data.items() if k in ['name','email','phone','company']])
        conn.execute(
            """INSERT INTO activities (contact_id, type, description, created_at)
               VALUES (?,?,?,datetime('now'))""",
            [contact_id, "web_form_submission", submission_text]
        )

    return _ok({"created": True, "contact_id": contact_id})

