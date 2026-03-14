"""
External REST API v1 — API Key Authentication + Webhooks
==========================================================
Provides external access to Hermes CRM data via API keys.
Mount this router in the main api.py.
"""

import os
import json
import secrets
import hashlib
import hmac
import logging
import time
import asyncio
from datetime import datetime, timedelta
from collections import defaultdict
from typing import Optional

import httpx
from fastapi import APIRouter, HTTPException, Request, Depends, Header, Query
from fastapi.responses import JSONResponse

from database import get_db

logger = logging.getLogger(__name__)

# ─── API Key Tables Schema ──────────────────────────────────
API_TABLES_SQL = """
CREATE TABLE IF NOT EXISTS api_keys (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL,
    key_hash    TEXT UNIQUE NOT NULL,
    key_prefix  TEXT NOT NULL,
    scopes      TEXT DEFAULT '["read"]',
    rate_limit  INTEGER DEFAULT 100,
    is_active   INTEGER DEFAULT 1,
    created_by  INTEGER REFERENCES users(id),
    last_used   TEXT,
    request_count INTEGER DEFAULT 0,
    expires_at  TEXT,
    created_at  TEXT DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash);
CREATE INDEX IF NOT EXISTS idx_api_keys_prefix ON api_keys(key_prefix);

CREATE TABLE IF NOT EXISTS webhooks (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    url         TEXT NOT NULL,
    events      TEXT NOT NULL DEFAULT '[]',
    secret      TEXT,
    is_active   INTEGER DEFAULT 1,
    created_by  INTEGER REFERENCES users(id),
    last_triggered TEXT,
    failure_count INTEGER DEFAULT 0,
    created_at  TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS webhook_logs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    webhook_id  INTEGER REFERENCES webhooks(id),
    event       TEXT NOT NULL,
    payload     TEXT,
    status_code INTEGER,
    response    TEXT,
    created_at  TEXT DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_webhook_logs_webhook ON webhook_logs(webhook_id);
"""


def init_api_tables():
    """Create API key and webhook tables if not exist."""
    with get_db() as conn:
        conn.executescript(API_TABLES_SQL)
    logger.info("External API tables initialized")


# ─── Helpers ─────────────────────────────────────────────────

def _ok(data=None, message="ok"):
    return {"success": True, "data": data, "message": message}


def _err(msg, code=400):
    raise HTTPException(status_code=code, detail=msg)


def hash_key(raw_key: str) -> str:
    """SHA-256 hash of API key for storage."""
    return hashlib.sha256(raw_key.encode()).hexdigest()


def generate_api_key() -> tuple:
    """Generate a new API key. Returns (raw_key, prefix, key_hash)."""
    raw = "hcrm_" + secrets.token_urlsafe(32)
    prefix = raw[:12]
    return raw, prefix, hash_key(raw)


# ─── Rate Limiting (per API key) ────────────────────────────
_key_rate = defaultdict(list)  # key_hash -> [timestamps]


def check_api_rate(key_hash: str, limit: int, window: int = 60) -> bool:
    """Return True if within rate limit."""
    now = time.time()
    _key_rate[key_hash] = [t for t in _key_rate[key_hash] if now - t < window]
    if len(_key_rate[key_hash]) >= limit:
        return False
    _key_rate[key_hash].append(now)
    return True


# ─── API Key Auth Dependency ────────────────────────────────

async def require_api_key(
    x_api_key: Optional[str] = Header(None, alias="X-API-Key")
):
    """Validate API key from X-API-Key header."""
    if not x_api_key:
        _err("Missing X-API-Key header", 401)

    kh = hash_key(x_api_key)
    with get_db() as conn:
        row = conn.execute(
            "SELECT id, name, scopes, rate_limit, is_active, expires_at, created_by "
            "FROM api_keys WHERE key_hash = ?", [kh]
        ).fetchone()

    if not row:
        _err("Invalid API key", 401)

    key_id, name, scopes_json, rate_limit, is_active, expires_at, created_by = row

    if not is_active:
        _err("API key is disabled", 403)

    if expires_at and datetime.fromisoformat(expires_at) < datetime.utcnow():
        _err("API key has expired", 403)

    if not check_api_rate(kh, rate_limit):
        raise HTTPException(status_code=429, detail=f"Rate limit exceeded ({rate_limit}/min)")

    # Update usage stats
    with get_db() as conn:
        conn.execute(
            "UPDATE api_keys SET last_used = datetime('now'), request_count = request_count + 1 WHERE id = ?",
            [key_id]
        )

    scopes = json.loads(scopes_json) if scopes_json else ["read"]
    return {"key_id": key_id, "name": name, "scopes": scopes, "created_by": created_by}


def require_scope(scope: str):
    """Factory for scope-checking dependency."""
    async def checker(api_key=Depends(require_api_key)):
        if scope not in api_key["scopes"] and "admin" not in api_key["scopes"]:
            _err(f"API key missing required scope: {scope}", 403)
        return api_key
    return checker


# ─── Webhook Dispatcher ─────────────────────────────────────

async def fire_webhooks(event: str, payload: dict):
    """Send webhook notifications for an event."""
    with get_db() as conn:
        hooks = conn.execute(
            "SELECT id, url, secret FROM webhooks WHERE is_active = 1 AND events LIKE ?",
            [f'%"{event}"%']
        ).fetchall()

    for hook_id, url, secret in hooks:
        try:
            body = json.dumps({"event": event, "data": payload, "timestamp": datetime.utcnow().isoformat()})
            headers = {"Content-Type": "application/json", "X-Hermes-Event": event}

            if secret:
                sig = hmac.new(secret.encode(), body.encode(), hashlib.sha256).hexdigest()
                headers["X-Hermes-Signature"] = f"sha256={sig}"

            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.post(url, content=body, headers=headers)

            with get_db() as conn:
                conn.execute(
                    "INSERT INTO webhook_logs (webhook_id, event, payload, status_code, response) VALUES (?,?,?,?,?)",
                    [hook_id, event, body[:2000], resp.status_code, resp.text[:500]]
                )
                conn.execute(
                    "UPDATE webhooks SET last_triggered = datetime('now'), failure_count = 0 WHERE id = ?",
                    [hook_id]
                )
        except Exception as e:
            logger.warning(f"Webhook {hook_id} failed: {e}")
            with get_db() as conn:
                conn.execute(
                    "INSERT INTO webhook_logs (webhook_id, event, payload, status_code, response) VALUES (?,?,?,?,?)",
                    [hook_id, event, json.dumps(payload)[:2000], 0, str(e)[:500]]
                )
                conn.execute(
                    "UPDATE webhooks SET failure_count = failure_count + 1 WHERE id = ?",
                    [hook_id]
                )


# ═══════════════════════════════════════════════════════════════
#  Router: /api/v1/
# ═══════════════════════════════════════════════════════════════

router = APIRouter(prefix="/api/v1", tags=["External API v1"])


# ─── API Key Management (admin JWT required, not API key) ────

def _get_admin_from_jwt(authorization: str = Header(None)):
    """Verify admin JWT for key management endpoints."""
    from models import User
    if not authorization or not authorization.startswith("Bearer "):
        _err("Admin JWT required", 401)
    token = authorization.split(" ", 1)[1]
    payload = User.verify_token(token)
    if not payload:
        _err("Invalid or expired token", 401)
    if payload.get("role") != "admin":
        _err("Admin access required", 403)
    return payload


@router.post("/keys")
async def create_api_key(request: Request, admin=Depends(_get_admin_from_jwt)):
    """Create a new API key. Requires admin JWT."""
    body = await request.json()
    name = body.get("name", "").strip()
    if not name:
        _err("Key name is required")

    scopes = body.get("scopes", ["read"])
    valid_scopes = {"read", "write", "delete", "admin"}
    for s in scopes:
        if s not in valid_scopes:
            _err(f"Invalid scope: {s}. Valid: {valid_scopes}")

    rate_limit = body.get("rate_limit", 100)
    expires_days = body.get("expires_days")

    raw_key, prefix, kh = generate_api_key()

    expires_at = None
    if expires_days:
        expires_at = (datetime.utcnow() + timedelta(days=expires_days)).isoformat()

    with get_db() as conn:
        conn.execute(
            "INSERT INTO api_keys (name, key_hash, key_prefix, scopes, rate_limit, created_by, expires_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            [name, kh, prefix, json.dumps(scopes), rate_limit, admin["user_id"], expires_at]
        )

    return _ok({
        "key": raw_key,
        "prefix": prefix,
        "name": name,
        "scopes": scopes,
        "rate_limit": rate_limit,
        "expires_at": expires_at,
        "warning": "Save this key now — it cannot be shown again!"
    })


@router.get("/keys")
async def list_api_keys(admin=Depends(_get_admin_from_jwt)):
    """List all API keys (without the actual key)."""
    with get_db() as conn:
        rows = conn.execute(
            "SELECT id, name, key_prefix, scopes, rate_limit, is_active, last_used, "
            "request_count, expires_at, created_at FROM api_keys ORDER BY created_at DESC"
        ).fetchall()

    keys = []
    for r in rows:
        keys.append({
            "id": r[0], "name": r[1], "prefix": r[2] + "...",
            "scopes": json.loads(r[3]) if r[3] else [],
            "rate_limit": r[4], "is_active": bool(r[5]),
            "last_used": r[6], "request_count": r[7],
            "expires_at": r[8], "created_at": r[9]
        })
    return _ok(keys)


@router.delete("/keys/{key_id}")
async def revoke_api_key(key_id: int, admin=Depends(_get_admin_from_jwt)):
    """Revoke (deactivate) an API key."""
    with get_db() as conn:
        result = conn.execute("UPDATE api_keys SET is_active = 0 WHERE id = ?", [key_id])
        if result.rowcount == 0:
            _err("Key not found", 404)
    return _ok(message=f"API key {key_id} revoked")


# ─── Webhook Management (admin JWT) ─────────────────────────

VALID_EVENTS = [
    "contact.created", "contact.updated", "contact.deleted",
    "company.created", "company.updated",
    "deal.created", "deal.updated", "deal.stage_changed", "deal.won", "deal.lost",
    "lead.created", "lead.updated", "lead.converted",
    "task.created", "task.completed",
    "contract.expiring",
]


@router.post("/webhooks")
async def create_webhook(request: Request, admin=Depends(_get_admin_from_jwt)):
    """Register a webhook endpoint."""
    body = await request.json()
    url = body.get("url", "").strip()
    events = body.get("events", [])

    if not url:
        _err("Webhook URL is required")
    if not events:
        _err(f"At least one event required. Available: {VALID_EVENTS}")

    for ev in events:
        if ev not in VALID_EVENTS:
            _err(f"Invalid event: {ev}")

    wh_secret = secrets.token_urlsafe(24)

    with get_db() as conn:
        cur = conn.execute(
            "INSERT INTO webhooks (url, events, secret, created_by) VALUES (?, ?, ?, ?)",
            [url, json.dumps(events), wh_secret, admin["user_id"]]
        )

    return _ok({
        "id": cur.lastrowid,
        "url": url,
        "events": events,
        "secret": wh_secret,
        "warning": "Save the secret for signature verification!"
    })


@router.get("/webhooks")
async def list_webhooks(admin=Depends(_get_admin_from_jwt)):
    """List all webhooks."""
    with get_db() as conn:
        rows = conn.execute(
            "SELECT id, url, events, is_active, last_triggered, failure_count, created_at "
            "FROM webhooks ORDER BY created_at DESC"
        ).fetchall()

    return _ok([{
        "id": r[0], "url": r[1], "events": json.loads(r[2]) if r[2] else [],
        "is_active": bool(r[3]), "last_triggered": r[4],
        "failure_count": r[5], "created_at": r[6]
    } for r in rows])


@router.delete("/webhooks/{wh_id}")
async def delete_webhook(wh_id: int, admin=Depends(_get_admin_from_jwt)):
    """Delete a webhook."""
    with get_db() as conn:
        result = conn.execute("DELETE FROM webhooks WHERE id = ?", [wh_id])
        if result.rowcount == 0:
            _err("Webhook not found", 404)
    return _ok(message=f"Webhook {wh_id} deleted")


# ═══════════════════════════════════════════════════════════════
#  Data Endpoints (API Key auth)
# ═══════════════════════════════════════════════════════════════

# ─── Contacts ────────────────────────────────────────────────

@router.get("/contacts")
async def v1_list_contacts(
    search: str = "", company_id: int = None,
    limit: int = Query(50, le=200), offset: int = 0,
    api_key=Depends(require_scope("read"))
):
    """List contacts with optional search and pagination."""
    with get_db() as conn:
        sql = "SELECT id, name, email, phone, company_id, company_name, role, source, tags, notes, last_contact, created_at FROM contacts WHERE 1=1"
        params = []
        if search:
            sql += " AND (name LIKE ? OR email LIKE ? OR company_name LIKE ?)"
            params += [f"%{search}%"] * 3
        if company_id:
            sql += " AND company_id = ?"
            params.append(company_id)
        sql += " ORDER BY id DESC LIMIT ? OFFSET ?"
        params += [limit, offset]

        rows = conn.execute(sql, params).fetchall()
        total = conn.execute("SELECT COUNT(*) FROM contacts" + (" WHERE company_id = ?" if company_id else ""),
                             [company_id] if company_id else []).fetchone()[0]

    cols = ["id", "name", "email", "phone", "company_id", "company_name", "role", "source", "tags", "notes", "last_contact", "created_at"]
    contacts = [dict(zip(cols, r)) for r in rows]
    for c in contacts:
        c["tags"] = json.loads(c["tags"]) if c["tags"] else []

    return _ok({"items": contacts, "total": total, "limit": limit, "offset": offset})


@router.get("/contacts/{contact_id}")
async def v1_get_contact(contact_id: int, api_key=Depends(require_scope("read"))):
    """Get a single contact by ID."""
    with get_db() as conn:
        row = conn.execute(
            "SELECT id, name, email, phone, company_id, company_name, role, source, tags, notes, last_contact, created_at, updated_at FROM contacts WHERE id = ?",
            [contact_id]
        ).fetchone()
    if not row:
        _err("Contact not found", 404)
    cols = ["id", "name", "email", "phone", "company_id", "company_name", "role", "source", "tags", "notes", "last_contact", "created_at", "updated_at"]
    c = dict(zip(cols, row))
    c["tags"] = json.loads(c["tags"]) if c["tags"] else []
    return _ok(c)


@router.post("/contacts")
async def v1_create_contact(request: Request, api_key=Depends(require_scope("write"))):
    """Create a new contact."""
    body = await request.json()
    email = body.get("email", "").strip()
    name = body.get("name", "").strip()
    if not email:
        _err("Email is required")

    with get_db() as conn:
        existing = conn.execute("SELECT id FROM contacts WHERE email = ?", [email]).fetchone()
        if existing:
            _err(f"Contact with email {email} already exists (id={existing[0]})")

        cur = conn.execute(
            "INSERT INTO contacts (email, name, phone, company_id, company_name, role, source, tags, notes) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [email, name, body.get("phone"), body.get("company_id"), body.get("company_name"),
             body.get("role"), body.get("source", "API"), json.dumps(body.get("tags", [])), body.get("notes")]
        )
        contact_id = cur.lastrowid

    asyncio.create_task(fire_webhooks("contact.created", {"id": contact_id, "email": email, "name": name}))
    return _ok({"id": contact_id}, "Contact created")


@router.put("/contacts/{contact_id}")
async def v1_update_contact(contact_id: int, request: Request, api_key=Depends(require_scope("write"))):
    """Update an existing contact."""
    body = await request.json()
    with get_db() as conn:
        existing = conn.execute("SELECT id FROM contacts WHERE id = ?", [contact_id]).fetchone()
        if not existing:
            _err("Contact not found", 404)

        fields = []
        params = []
        for col in ["name", "email", "phone", "company_id", "company_name", "role", "source", "notes"]:
            if col in body:
                fields.append(f"{col} = ?")
                params.append(body[col])
        if "tags" in body:
            fields.append("tags = ?")
            params.append(json.dumps(body["tags"]))

        if not fields:
            _err("No fields to update")

        fields.append("updated_at = datetime('now')")
        params.append(contact_id)
        conn.execute(f"UPDATE contacts SET {', '.join(fields)} WHERE id = ?", params)

    asyncio.create_task(fire_webhooks("contact.updated", {"id": contact_id, **body}))
    return _ok({"id": contact_id}, "Contact updated")


@router.delete("/contacts/{contact_id}")
async def v1_delete_contact(contact_id: int, api_key=Depends(require_scope("delete"))):
    """Delete a contact."""
    with get_db() as conn:
        result = conn.execute("DELETE FROM contacts WHERE id = ?", [contact_id])
        if result.rowcount == 0:
            _err("Contact not found", 404)
    asyncio.create_task(fire_webhooks("contact.deleted", {"id": contact_id}))
    return _ok(message="Contact deleted")


# ─── Companies ───────────────────────────────────────────────

@router.get("/companies")
async def v1_list_companies(
    search: str = "", limit: int = Query(50, le=200), offset: int = 0,
    api_key=Depends(require_scope("read"))
):
    """List companies with search and pagination."""
    with get_db() as conn:
        sql = "SELECT id, name, domain, industry, website, category, group_name, user_count, notes, created_at FROM companies WHERE 1=1"
        params = []
        if search:
            sql += " AND (name LIKE ? OR domain LIKE ? OR industry LIKE ?)"
            params += [f"%{search}%"] * 3
        sql += " ORDER BY name LIMIT ? OFFSET ?"
        params += [limit, offset]
        rows = conn.execute(sql, params).fetchall()
        total = conn.execute("SELECT COUNT(*) FROM companies").fetchone()[0]

    cols = ["id", "name", "domain", "industry", "website", "category", "group_name", "user_count", "notes", "created_at"]
    return _ok({"items": [dict(zip(cols, r)) for r in rows], "total": total, "limit": limit, "offset": offset})


@router.get("/companies/{company_id}")
async def v1_get_company(company_id: int, api_key=Depends(require_scope("read"))):
    """Get company details with contact count."""
    with get_db() as conn:
        row = conn.execute(
            "SELECT id, name, domain, industry, website, category, group_name, user_count, notes, cost_code, created_at, last_activity FROM companies WHERE id = ?",
            [company_id]
        ).fetchone()
    if not row:
        _err("Company not found", 404)
    cols = ["id", "name", "domain", "industry", "website", "category", "group_name", "user_count", "notes", "cost_code", "created_at", "last_activity"]
    company = dict(zip(cols, row))
    with get_db() as conn:
        company["contact_count"] = conn.execute("SELECT COUNT(*) FROM contacts WHERE company_id = ?", [company_id]).fetchone()[0]
        company["deal_count"] = conn.execute("SELECT COUNT(*) FROM deals WHERE company_id = ?", [company_id]).fetchone()[0]
    return _ok(company)


@router.post("/companies")
async def v1_create_company(request: Request, api_key=Depends(require_scope("write"))):
    """Create a new company."""
    body = await request.json()
    name = body.get("name", "").strip()
    if not name:
        _err("Company name is required")

    with get_db() as conn:
        cur = conn.execute(
            "INSERT INTO companies (name, domain, industry, website, category, group_name, user_count, notes) VALUES (?,?,?,?,?,?,?,?)",
            [name, body.get("domain"), body.get("industry"), body.get("website"),
             body.get("category"), body.get("group_name"), body.get("user_count", 0), body.get("notes")]
        )
    asyncio.create_task(fire_webhooks("company.created", {"id": cur.lastrowid, "name": name}))
    return _ok({"id": cur.lastrowid}, "Company created")


@router.put("/companies/{company_id}")
async def v1_update_company(company_id: int, request: Request, api_key=Depends(require_scope("write"))):
    """Update a company."""
    body = await request.json()
    with get_db() as conn:
        existing = conn.execute("SELECT id FROM companies WHERE id = ?", [company_id]).fetchone()
        if not existing:
            _err("Company not found", 404)
        fields, params = [], []
        for col in ["name", "domain", "industry", "website", "category", "group_name", "user_count", "notes"]:
            if col in body:
                fields.append(f"{col} = ?")
                params.append(body[col])
        if not fields:
            _err("No fields to update")
        params.append(company_id)
        conn.execute(f"UPDATE companies SET {', '.join(fields)} WHERE id = ?", params)

    asyncio.create_task(fire_webhooks("company.updated", {"id": company_id, **body}))
    return _ok({"id": company_id}, "Company updated")


# ─── Deals ───────────────────────────────────────────────────

@router.get("/deals")
async def v1_list_deals(
    stage: str = None, company_id: int = None,
    limit: int = Query(50, le=200), offset: int = 0,
    api_key=Depends(require_scope("read"))
):
    """List deals with filters."""
    with get_db() as conn:
        sql = "SELECT d.id, d.title, d.company_id, c.name as company_name, d.contact_id, d.stage, d.value_amount, d.value_currency, d.expected_close, d.won_date, d.lost_reason, d.notes, d.created_at, d.updated_at FROM deals d LEFT JOIN companies c ON d.company_id = c.id WHERE 1=1"
        params = []
        if stage:
            sql += " AND d.stage = ?"
            params.append(stage.upper())
        if company_id:
            sql += " AND d.company_id = ?"
            params.append(company_id)
        sql += " ORDER BY d.id DESC LIMIT ? OFFSET ?"
        params += [limit, offset]
        rows = conn.execute(sql, params).fetchall()
        total = conn.execute("SELECT COUNT(*) FROM deals").fetchone()[0]

    cols = ["id", "title", "company_id", "company_name", "contact_id", "stage", "value_amount", "value_currency", "expected_close", "won_date", "lost_reason", "notes", "created_at", "updated_at"]
    return _ok({"items": [dict(zip(cols, r)) for r in rows], "total": total, "limit": limit, "offset": offset})


@router.get("/deals/{deal_id}")
async def v1_get_deal(deal_id: int, api_key=Depends(require_scope("read"))):
    """Get deal details."""
    with get_db() as conn:
        row = conn.execute(
            "SELECT d.id, d.title, d.company_id, c.name as company_name, d.contact_id, ct.name as contact_name, "
            "d.stage, d.value_amount, d.value_currency, d.expected_close, d.won_date, d.lost_reason, "
            "d.assigned_to, d.notes, d.created_at, d.updated_at "
            "FROM deals d LEFT JOIN companies c ON d.company_id = c.id LEFT JOIN contacts ct ON d.contact_id = ct.id "
            "WHERE d.id = ?", [deal_id]
        ).fetchone()
    if not row:
        _err("Deal not found", 404)
    cols = ["id", "title", "company_id", "company_name", "contact_id", "contact_name", "stage", "value_amount", "value_currency", "expected_close", "won_date", "lost_reason", "assigned_to", "notes", "created_at", "updated_at"]
    return _ok(dict(zip(cols, row)))


@router.post("/deals")
async def v1_create_deal(request: Request, api_key=Depends(require_scope("write"))):
    """Create a new deal."""
    body = await request.json()
    title = body.get("title", "").strip()
    if not title:
        _err("Deal title is required")

    with get_db() as conn:
        cur = conn.execute(
            "INSERT INTO deals (title, company_id, contact_id, stage, value_amount, value_currency, expected_close, notes, assigned_to, created_by) "
            "VALUES (?,?,?,?,?,?,?,?,?,?)",
            [title, body.get("company_id"), body.get("contact_id"), body.get("stage", "LEAD"),
             body.get("value_amount"), body.get("value_currency", "AZN"),
             body.get("expected_close"), body.get("notes"),
             body.get("assigned_to"), api_key.get("created_by")]
        )
    asyncio.create_task(fire_webhooks("deal.created", {"id": cur.lastrowid, "title": title, "stage": body.get("stage", "LEAD")}))
    return _ok({"id": cur.lastrowid}, "Deal created")


@router.put("/deals/{deal_id}")
async def v1_update_deal(deal_id: int, request: Request, api_key=Depends(require_scope("write"))):
    """Update a deal. Fires webhook if stage changes."""
    body = await request.json()
    with get_db() as conn:
        old = conn.execute("SELECT stage FROM deals WHERE id = ?", [deal_id]).fetchone()
        if not old:
            _err("Deal not found", 404)
        old_stage = old[0]

        fields, params = [], []
        for col in ["title", "company_id", "contact_id", "stage", "value_amount", "value_currency", "expected_close", "won_date", "lost_reason", "notes", "assigned_to"]:
            if col in body:
                fields.append(f"{col} = ?")
                params.append(body[col])
        if not fields:
            _err("No fields to update")
        fields.append("updated_at = datetime('now')")
        params.append(deal_id)
        conn.execute(f"UPDATE deals SET {', '.join(fields)} WHERE id = ?", params)

    new_stage = body.get("stage", old_stage)
    if new_stage != old_stage:
        asyncio.create_task(fire_webhooks("deal.stage_changed", {"id": deal_id, "old_stage": old_stage, "new_stage": new_stage}))
        if new_stage == "WON":
            asyncio.create_task(fire_webhooks("deal.won", {"id": deal_id}))
        elif new_stage == "LOST":
            asyncio.create_task(fire_webhooks("deal.lost", {"id": deal_id, "reason": body.get("lost_reason")}))

    asyncio.create_task(fire_webhooks("deal.updated", {"id": deal_id, **body}))
    return _ok({"id": deal_id}, "Deal updated")


# ─── Leads ───────────────────────────────────────────────────

@router.get("/leads")
async def v1_list_leads(
    status: str = None, source: str = None,
    limit: int = Query(50, le=200), offset: int = 0,
    api_key=Depends(require_scope("read"))
):
    """List leads with filters."""
    with get_db() as conn:
        sql = "SELECT id, company_name, contact_name, email, phone, source, status, priority, estimated_value, notes, created_at FROM leads WHERE 1=1"
        params = []
        if status:
            sql += " AND status = ?"
            params.append(status)
        if source:
            sql += " AND source = ?"
            params.append(source)
        sql += " ORDER BY id DESC LIMIT ? OFFSET ?"
        params += [limit, offset]
        rows = conn.execute(sql, params).fetchall()
        total = conn.execute("SELECT COUNT(*) FROM leads").fetchone()[0]

    cols = ["id", "company_name", "contact_name", "email", "phone", "source", "status", "priority", "estimated_value", "notes", "created_at"]
    return _ok({"items": [dict(zip(cols, r)) for r in rows], "total": total, "limit": limit, "offset": offset})


@router.post("/leads")
async def v1_create_lead(request: Request, api_key=Depends(require_scope("write"))):
    """Create a new lead."""
    body = await request.json()
    company_name = body.get("company_name", "").strip()
    if not company_name:
        _err("Company name is required")

    with get_db() as conn:
        cur = conn.execute(
            "INSERT INTO leads (company_name, contact_name, email, phone, source, status, priority, estimated_value, estimated_users, industry, website, notes, assigned_to, created_by) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            [company_name, body.get("contact_name"), body.get("email"), body.get("phone"),
             body.get("source", "api"), "new", body.get("priority", "medium"),
             body.get("estimated_value"), body.get("estimated_users"),
             body.get("industry"), body.get("website"), body.get("notes"),
             body.get("assigned_to"), api_key.get("created_by")]
        )
    asyncio.create_task(fire_webhooks("lead.created", {"id": cur.lastrowid, "company_name": company_name}))
    return _ok({"id": cur.lastrowid}, "Lead created")


# ─── Tasks ───────────────────────────────────────────────────

@router.get("/tasks")
async def v1_list_tasks(
    status: str = None, assigned_to: int = None,
    limit: int = Query(50, le=200), offset: int = 0,
    api_key=Depends(require_scope("read"))
):
    """List tasks with filters."""
    with get_db() as conn:
        sql = "SELECT id, title, description, status, priority, due_date, due_time, category, company_id, contact_id, deal_id, assigned_to, created_at FROM tasks WHERE 1=1"
        params = []
        if status:
            sql += " AND status = ?"
            params.append(status)
        if assigned_to:
            sql += " AND assigned_to = ?"
            params.append(assigned_to)
        sql += " ORDER BY due_date ASC NULLS LAST LIMIT ? OFFSET ?"
        params += [limit, offset]
        rows = conn.execute(sql, params).fetchall()
        total = conn.execute("SELECT COUNT(*) FROM tasks").fetchone()[0]

    cols = ["id", "title", "description", "status", "priority", "due_date", "due_time", "category", "company_id", "contact_id", "deal_id", "assigned_to", "created_at"]
    return _ok({"items": [dict(zip(cols, r)) for r in rows], "total": total, "limit": limit, "offset": offset})


@router.post("/tasks")
async def v1_create_task(request: Request, api_key=Depends(require_scope("write"))):
    """Create a new task."""
    body = await request.json()
    title = body.get("title", "").strip()
    if not title:
        _err("Task title is required")

    with get_db() as conn:
        cur = conn.execute(
            "INSERT INTO tasks (title, description, status, priority, due_date, due_time, category, company_id, contact_id, deal_id, lead_id, assigned_to, created_by) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            [title, body.get("description"), "todo", body.get("priority", "medium"),
             body.get("due_date"), body.get("due_time"), body.get("category", "general"),
             body.get("company_id"), body.get("contact_id"), body.get("deal_id"), body.get("lead_id"),
             body.get("assigned_to"), api_key.get("created_by")]
        )
    asyncio.create_task(fire_webhooks("task.created", {"id": cur.lastrowid, "title": title}))
    return _ok({"id": cur.lastrowid}, "Task created")


@router.patch("/tasks/{task_id}/status")
async def v1_update_task_status(task_id: int, request: Request, api_key=Depends(require_scope("write"))):
    """Update task status."""
    body = await request.json()
    new_status = body.get("status")
    if new_status not in ("todo", "in_progress", "done", "cancelled"):
        _err("Invalid status. Use: todo, in_progress, done, cancelled")

    with get_db() as conn:
        old = conn.execute("SELECT status FROM tasks WHERE id = ?", [task_id]).fetchone()
        if not old:
            _err("Task not found", 404)

        updates = "status = ?, updated_at = datetime('now')"
        params = [new_status]
        if new_status == "done":
            updates += ", completed_at = datetime('now')"
        params.append(task_id)
        conn.execute(f"UPDATE tasks SET {updates} WHERE id = ?", params)

    if new_status == "done":
        asyncio.create_task(fire_webhooks("task.completed", {"id": task_id}))
    return _ok({"id": task_id, "status": new_status}, "Task status updated")


# ─── Contracts ───────────────────────────────────────────────

@router.get("/contracts")
async def v1_list_contracts(
    status: str = None, company_id: int = None,
    limit: int = Query(50, le=200), offset: int = 0,
    api_key=Depends(require_scope("read"))
):
    """List contracts."""
    with get_db() as conn:
        sql = "SELECT id, contract_number, company_id, company_name, contract_type, status, start_date, end_date, value, currency, notes, created_at FROM contracts WHERE 1=1"
        params = []
        if status:
            sql += " AND status = ?"
            params.append(status)
        if company_id:
            sql += " AND company_id = ?"
            params.append(company_id)
        sql += " ORDER BY id DESC LIMIT ? OFFSET ?"
        params += [limit, offset]
        rows = conn.execute(sql, params).fetchall()
        total = conn.execute("SELECT COUNT(*) FROM contracts").fetchone()[0]

    cols = ["id", "contract_number", "company_id", "company_name", "contract_type", "status", "start_date", "end_date", "value", "currency", "notes", "created_at"]
    return _ok({"items": [dict(zip(cols, r)) for r in rows], "total": total, "limit": limit, "offset": offset})


# ─── Analytics ───────────────────────────────────────────────

@router.get("/analytics/summary")
async def v1_analytics_summary(api_key=Depends(require_scope("read"))):
    """Get CRM summary analytics."""
    with get_db() as conn:
        contacts = conn.execute("SELECT COUNT(*) FROM contacts").fetchone()[0]
        companies = conn.execute("SELECT COUNT(*) FROM companies").fetchone()[0]
        deals = conn.execute("SELECT COUNT(*) FROM deals").fetchone()[0]
        leads = conn.execute("SELECT COUNT(*) FROM leads WHERE status NOT IN ('converted', 'unqualified')").fetchone()[0]
        tasks_open = conn.execute("SELECT COUNT(*) FROM tasks WHERE status IN ('todo', 'in_progress')").fetchone()[0]
        contracts = conn.execute("SELECT COUNT(*) FROM contracts").fetchone()[0]

        pipeline = conn.execute(
            "SELECT stage, COUNT(*), COALESCE(SUM(value_amount), 0) FROM deals GROUP BY stage"
        ).fetchall()

    return _ok({
        "contacts": contacts, "companies": companies, "deals": deals,
        "active_leads": leads, "open_tasks": tasks_open, "contracts": contracts,
        "pipeline": {r[0]: {"count": r[1], "value": r[2]} for r in pipeline}
    })


# ─── Search ──────────────────────────────────────────────────

@router.get("/search")
async def v1_search(q: str = Query(..., min_length=2), api_key=Depends(require_scope("read"))):
    """Global search across contacts, companies, deals, leads."""
    results = {"contacts": [], "companies": [], "deals": [], "leads": []}
    pat = f"%{q}%"

    with get_db() as conn:
        results["contacts"] = [
            {"id": r[0], "name": r[1], "email": r[2], "company_name": r[3]}
            for r in conn.execute("SELECT id, name, email, company_name FROM contacts WHERE name LIKE ? OR email LIKE ? LIMIT 10", [pat, pat]).fetchall()
        ]
        results["companies"] = [
            {"id": r[0], "name": r[1], "domain": r[2]}
            for r in conn.execute("SELECT id, name, domain FROM companies WHERE name LIKE ? OR domain LIKE ? LIMIT 10", [pat, pat]).fetchall()
        ]
        results["deals"] = [
            {"id": r[0], "title": r[1], "stage": r[2]}
            for r in conn.execute("SELECT id, title, stage FROM deals WHERE title LIKE ? LIMIT 10", [pat]).fetchall()
        ]
        results["leads"] = [
            {"id": r[0], "company_name": r[1], "contact_name": r[2], "status": r[3]}
            for r in conn.execute("SELECT id, company_name, contact_name, status FROM leads WHERE company_name LIKE ? OR contact_name LIKE ? LIMIT 10", [pat, pat]).fetchall()
        ]

    return _ok(results)


# ─── API Info ────────────────────────────────────────────────

@router.get("/")
async def v1_info():
    """API information and available endpoints."""
    return _ok({
        "api": "Hermes CRM External API",
        "version": "v1",
        "auth": "X-API-Key header",
        "docs": "https://hermescrm.xyz/api/v1/docs",
        "endpoints": {
            "contacts": {"list": "GET /api/v1/contacts", "get": "GET /api/v1/contacts/:id", "create": "POST /api/v1/contacts", "update": "PUT /api/v1/contacts/:id", "delete": "DELETE /api/v1/contacts/:id"},
            "companies": {"list": "GET /api/v1/companies", "get": "GET /api/v1/companies/:id", "create": "POST /api/v1/companies", "update": "PUT /api/v1/companies/:id"},
            "deals": {"list": "GET /api/v1/deals", "get": "GET /api/v1/deals/:id", "create": "POST /api/v1/deals", "update": "PUT /api/v1/deals/:id"},
            "leads": {"list": "GET /api/v1/leads", "create": "POST /api/v1/leads"},
            "tasks": {"list": "GET /api/v1/tasks", "create": "POST /api/v1/tasks", "update_status": "PATCH /api/v1/tasks/:id/status"},
            "contracts": {"list": "GET /api/v1/contracts"},
            "analytics": {"summary": "GET /api/v1/analytics/summary"},
            "search": {"global": "GET /api/v1/search?q=..."},
            "keys": {"create": "POST /api/v1/keys (admin JWT)", "list": "GET /api/v1/keys (admin JWT)", "revoke": "DELETE /api/v1/keys/:id (admin JWT)"},
            "webhooks": {"create": "POST /api/v1/webhooks (admin JWT)", "list": "GET /api/v1/webhooks (admin JWT)", "delete": "DELETE /api/v1/webhooks/:id (admin JWT)"},
        },
        "scopes": ["read", "write", "delete", "admin"],
        "webhook_events": VALID_EVENTS,
    })
