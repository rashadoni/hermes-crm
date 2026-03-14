"""
CRM Models — CRUD operations for all entities
===============================================
Pure dataclass models with direct SQL — no ORM.
"""

import json
import logging
import bcrypt
import jwt
import os
from dataclasses import dataclass, field, asdict
from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta

from database import get_db, dict_from_row, rows_to_dicts

logger = logging.getLogger(__name__)

_DEFAULT_SECRET = None

def _get_jwt_secret():
    """Get JWT secret: env var > auto-generated persistent secret."""
    global _DEFAULT_SECRET
    env_secret = os.getenv("JWT_SECRET")
    if env_secret:
        return env_secret
    # Generate and persist a random secret on first run
    secret_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".jwt_secret")
    if _DEFAULT_SECRET:
        return _DEFAULT_SECRET
    if os.path.exists(secret_file):
        with open(secret_file) as f:
            _DEFAULT_SECRET = f.read().strip()
    else:
        import secrets as _secrets
        _DEFAULT_SECRET = _secrets.token_hex(32)
        with open(secret_file, "w") as f:
            f.write(_DEFAULT_SECRET)
        logger.info("Generated new JWT secret (stored in .jwt_secret)")
    return _DEFAULT_SECRET

JWT_SECRET = _get_jwt_secret()
JWT_EXPIRY_HOURS = 24

# ─── Pipeline Stages ─────────────────────────────────────────
PIPELINE_STAGES = ["LEAD", "QUALIFIED", "PROPOSAL", "NEGOTIATION", "WON", "LOST"]


# ─── User ────────────────────────────────────────────────────

class User:
    @staticmethod
    def create(data):
        # type: (Dict[str, Any]) -> Optional[Dict]
        """Create a new user. Requires email and password."""
        email = data.get("email", "").strip().lower()
        password = data.get("password", "")
        if not email or not password:
            return None
        if len(password) < 6:
            return None
        # Generate username from email (part before @)
        username = data.get("username", "").strip().lower()
        if not username:
            username = email.split("@")[0]
        full_name = data.get("full_name", "").strip()
        password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        with get_db() as conn:
            try:
                conn.execute(
                    "INSERT INTO users (username, email, password_hash, full_name, role) VALUES (?, ?, ?, ?, ?)",
                    (username, email, password_hash, full_name, data.get("role", "manager"))
                )
                row = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
                result = dict_from_row(row)
                result.pop("password_hash", None)
                return result
            except Exception:
                return None

    @staticmethod
    def authenticate(email_or_username, password):
        # type: (str, str) -> Optional[Dict]
        """Authenticate user by email (or username) and password."""
        login_val = email_or_username.strip().lower()
        with get_db() as conn:
            # Try email first, then username
            row = conn.execute(
                "SELECT * FROM users WHERE (email = ? OR username = ?) AND is_active = 1",
                (login_val, login_val)
            ).fetchone()
            if not row:
                return None
            user = dict_from_row(row)
            if bcrypt.checkpw(password.encode(), user["password_hash"].encode()):
                user.pop("password_hash", None)
                return user
            return None

    @staticmethod
    def change_password(user_id, old_password, new_password):
        # type: (int, str, str) -> bool
        """User changes their own password. Requires old password."""
        with get_db() as conn:
            row = conn.execute("SELECT password_hash FROM users WHERE id = ?", (user_id,)).fetchone()
            if not row:
                return False
            if not bcrypt.checkpw(old_password.encode(), row["password_hash"].encode()):
                return False
            new_hash = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt()).decode()
            conn.execute("UPDATE users SET password_hash = ? WHERE id = ?", (new_hash, user_id))
            return True

    @staticmethod
    def generate_token(user):
        # type: (Dict) -> str
        """Generate JWT token for user."""
        payload = {
            "user_id": user["id"],
            "username": user["username"],
            "role": user["role"],
            "exp": datetime.utcnow() + timedelta(hours=JWT_EXPIRY_HOURS)
        }
        return jwt.encode(payload, JWT_SECRET, algorithm="HS256")

    @staticmethod
    def verify_token(token):
        # type: (str) -> Optional[Dict]
        """Verify JWT token. Distinguishes expired from invalid."""
        try:
            payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
            return payload
        except jwt.ExpiredSignatureError:
            logger.debug("Token expired")
            return None
        except jwt.InvalidTokenError:
            logger.debug("Invalid token")
            return None

    @staticmethod
    def get(user_id):
        # type: (int) -> Optional[Dict]
        """Get user by ID."""
        with get_db() as conn:
            row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
            if row:
                result = dict_from_row(row)
                result.pop("password_hash", None)
                return result
            return None

    @staticmethod
    def get_all():
        # type: () -> List[Dict]
        """Get all users."""
        with get_db() as conn:
            rows = conn.execute(
                "SELECT id, username, email, full_name, role, is_active, created_at FROM users ORDER BY id"
            ).fetchall()
            return rows_to_dicts(rows)

    @staticmethod
    def update(user_id, data):
        # type: (int, Dict[str, Any]) -> Optional[Dict]
        """Update user."""
        allowed = {"full_name", "role", "is_active", "email"}
        updates = {k: v for k, v in data.items() if k in allowed}
        if data.get("password"):
            updates["password_hash"] = bcrypt.hashpw(data["password"].encode(), bcrypt.gensalt()).decode()
        if not updates:
            return User.get(user_id)
        set_clause = ", ".join(f"{k} = ?" for k in updates.keys())
        vals = list(updates.values())
        with get_db() as conn:
            conn.execute(f"UPDATE users SET {set_clause} WHERE id = ?", vals + [user_id])
        return User.get(user_id)

    @staticmethod
    def delete(user_id):
        # type: (int) -> bool
        """Delete user."""
        with get_db() as conn:
            conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
            return True

    @staticmethod
    def count():
        # type: () -> int
        """Get user count."""
        with get_db() as conn:
            row = conn.execute("SELECT COUNT(*) as cnt FROM users").fetchone()
            return row["cnt"] if row else 0

    @staticmethod
    def get_stats(user_id):
        # type: (int) -> Dict[str, Any]
        """Get user statistics (deals assigned to them)."""
        with get_db() as conn:
            total = conn.execute("SELECT COUNT(*) as cnt FROM deals WHERE assigned_to = ?", (user_id,)).fetchone()["cnt"]
            won = conn.execute("SELECT COUNT(*) as cnt FROM deals WHERE assigned_to = ? AND stage = 'WON'", (user_id,)).fetchone()["cnt"]
            total_value = conn.execute("SELECT COALESCE(SUM(value_amount),0) as s FROM deals WHERE assigned_to = ? AND stage = 'WON'", (user_id,)).fetchone()["s"]
            active = conn.execute("SELECT COUNT(*) as cnt FROM deals WHERE assigned_to = ? AND stage NOT IN ('WON','LOST')", (user_id,)).fetchone()["cnt"]
            conversion = round(won/total*100, 1) if total > 0 else 0
            return {
                "total_deals": total,
                "won_deals": won,
                "active_deals": active,
                "won_value": total_value,
                "conversion": conversion
            }


# ─── Contact ─────────────────────────────────────────────────

@dataclass
class Contact:
    id: Optional[int] = None
    email: str = ""
    name: str = ""
    phone: str = ""
    company_id: Optional[int] = None
    company_name: str = ""
    role: str = ""
    source: str = "EMAIL"
    tags: str = "[]"
    notes: str = ""
    email_count: int = 0
    last_contact: Optional[str] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None

    @staticmethod
    def create(data):
        # type: (Dict[str, Any]) -> Optional[Dict]
        """Create or update contact by email (upsert)."""
        email = data.get("email", "").strip().lower()
        if not email:
            return None

        with get_db() as conn:
            # Check if exists
            row = conn.execute(
                "SELECT * FROM contacts WHERE email = ?", (email,)
            ).fetchone()

            if row:
                # Update existing — increment email_count, update last_contact
                updates = {}
                if data.get("name") and not dict(row).get("name"):
                    updates["name"] = data["name"]
                if data.get("phone") and not dict(row).get("phone"):
                    updates["phone"] = data["phone"]
                if data.get("role") and not dict(row).get("role"):
                    updates["role"] = data["role"]
                if data.get("company_name") and not dict(row).get("company_name"):
                    updates["company_name"] = data["company_name"]
                if data.get("company_id"):
                    updates["company_id"] = data["company_id"]

                set_clause = ", ".join(
                    "%s = ?" % k for k in updates.keys()
                )
                vals = list(updates.values())

                if set_clause:
                    conn.execute(
                        "UPDATE contacts SET %s, email_count = email_count + 1, "
                        "last_contact = datetime('now'), updated_at = datetime('now') "
                        "WHERE email = ?" % set_clause,
                        vals + [email],
                    )
                else:
                    conn.execute(
                        "UPDATE contacts SET email_count = email_count + 1, "
                        "last_contact = datetime('now'), updated_at = datetime('now') "
                        "WHERE email = ?",
                        (email,),
                    )
            else:
                # Insert new
                conn.execute(
                    "INSERT INTO contacts "
                    "(email, name, phone, company_id, company_name, role, source, tags, notes, "
                    "email_count, last_contact) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, datetime('now'))",
                    (
                        email,
                        data.get("name", ""),
                        data.get("phone", ""),
                        data.get("company_id"),
                        data.get("company_name", ""),
                        data.get("role", ""),
                        data.get("source", "EMAIL"),
                        data.get("tags", "[]"),
                        data.get("notes", ""),
                    ),
                )

            # Fetch and return the result from same connection after commit
            result = conn.execute(
                "SELECT * FROM contacts WHERE email = ?", (email,)
            ).fetchone()
            return dict_from_row(result)

    @staticmethod
    def get(contact_id):
        # type: (int) -> Optional[Dict]
        with get_db() as conn:
            row = conn.execute(
                "SELECT * FROM contacts WHERE id = ?", (contact_id,)
            ).fetchone()
            return dict_from_row(row)

    @staticmethod
    def get_by_email(email):
        # type: (str) -> Optional[Dict]
        with get_db() as conn:
            row = conn.execute(
                "SELECT * FROM contacts WHERE email = ?", (email.lower(),)
            ).fetchone()
            return dict_from_row(row)

    @staticmethod
    def search(query="", company_id=None, source=None, limit=50, offset=0):
        # type: (str, Optional[int], Optional[str], int, int) -> List[Dict]
        """Search contacts with optional filters."""
        conditions = []
        params = []

        if query:
            conditions.append(
                "(name LIKE ? OR email LIKE ? OR company_name LIKE ? OR role LIKE ?)"
            )
            q = "%" + query + "%"
            params.extend([q, q, q, q])
        if company_id:
            conditions.append("company_id = ?")
            params.append(company_id)
        if source:
            conditions.append("source = ?")
            params.append(source)

        where = " AND ".join(conditions) if conditions else "1=1"

        with get_db() as conn:
            rows = conn.execute(
                "SELECT * FROM contacts WHERE %s "
                "ORDER BY last_contact DESC NULLS LAST "
                "LIMIT ? OFFSET ?" % where,
                params + [limit, offset],
            ).fetchall()
            return rows_to_dicts(rows)

    @staticmethod
    def update(contact_id, data):
        # type: (int, Dict[str, Any]) -> Optional[Dict]
        allowed = {
            "name", "phone", "company_id", "company_name", "role",
            "source", "tags", "notes",
        }
        updates = {k: v for k, v in data.items() if k in allowed}
        if not updates:
            return Contact.get(contact_id)

        set_clause = ", ".join("%s = ?" % k for k in updates.keys())
        vals = list(updates.values())

        with get_db() as conn:
            conn.execute(
                "UPDATE contacts SET %s, updated_at = datetime('now') "
                "WHERE id = ?" % set_clause,
                vals + [contact_id],
            )
        return Contact.get(contact_id)

    @staticmethod
    def delete(contact_id):
        # type: (int) -> bool
        with get_db() as conn:
            conn.execute("DELETE FROM contacts WHERE id = ?", (contact_id,))
            return True

    @staticmethod
    def count():
        # type: () -> int
        with get_db() as conn:
            row = conn.execute("SELECT COUNT(*) as cnt FROM contacts").fetchone()
            return row["cnt"] if row else 0


# ─── Company ─────────────────────────────────────────────────

@dataclass
class Company:
    id: Optional[int] = None
    name: str = ""
    domain: str = ""
    industry: str = ""
    website: str = ""
    notes: str = ""
    contacts_count: int = 0
    created_at: Optional[str] = None
    last_activity: Optional[str] = None

    @staticmethod
    def create(data):
        # type: (Dict[str, Any]) -> Optional[Dict]
        domain = data.get("domain", "").strip().lower()
        name = data.get("name", "").strip()

        if not domain and not name:
            return None

        with get_db() as conn:
            # Check by domain first
            if domain:
                row = conn.execute(
                    "SELECT * FROM companies WHERE domain = ?", (domain,)
                ).fetchone()
                if row:
                    # Update contacts_count
                    conn.execute(
                        "UPDATE companies SET contacts_count = contacts_count + 1, "
                        "last_activity = datetime('now') WHERE domain = ?",
                        (domain,),
                    )
                    result = conn.execute(
                        "SELECT * FROM companies WHERE domain = ?", (domain,)
                    ).fetchone()
                    return dict_from_row(result)

            conn.execute(
                "INSERT OR IGNORE INTO companies "
                "(name, domain, industry, website, notes, category, group_name, contacts_count) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, 1)",
                (
                    name,
                    domain or None,  # Use NULL for empty domain (UNIQUE allows multiple NULLs)
                    data.get("industry", ""),
                    data.get("website", ""),
                    data.get("notes", ""),
                    data.get("category", ""),
                    data.get("group_name", ""),
                ),
            )

            if domain:
                row = conn.execute(
                    "SELECT * FROM companies WHERE domain = ?", (domain,)
                ).fetchone()
            else:
                row = conn.execute(
                    "SELECT * FROM companies WHERE name = ? ORDER BY id DESC LIMIT 1",
                    (name,),
                ).fetchone()
            return dict_from_row(row)

    @staticmethod
    def get(company_id):
        # type: (int) -> Optional[Dict]
        with get_db() as conn:
            row = conn.execute(
                "SELECT * FROM companies WHERE id = ?", (company_id,)
            ).fetchone()
            return dict_from_row(row)

    @staticmethod
    def get_by_domain(domain):
        # type: (str) -> Optional[Dict]
        with get_db() as conn:
            row = conn.execute(
                "SELECT * FROM companies WHERE domain = ?", (domain.lower(),)
            ).fetchone()
            return dict_from_row(row)

    @staticmethod
    def search(query="", limit=50, offset=0):
        # type: (str, int, int) -> List[Dict]
        if query:
            q = "%" + query + "%"
            sql = (
                "SELECT * FROM companies WHERE name LIKE ? OR domain LIKE ? "
                "ORDER BY contacts_count DESC LIMIT ? OFFSET ?"
            )
            params = [q, q, limit, offset]
        else:
            sql = (
                "SELECT * FROM companies "
                "ORDER BY contacts_count DESC LIMIT ? OFFSET ?"
            )
            params = [limit, offset]

        with get_db() as conn:
            rows = conn.execute(sql, params).fetchall()
            return rows_to_dicts(rows)

    @staticmethod
    def update(company_id, data):
        # type: (int, Dict[str, Any]) -> Optional[Dict]
        allowed = {"name", "domain", "industry", "website", "notes", "category", "group_name"}
        updates = {k: v for k, v in data.items() if k in allowed}
        if not updates:
            return Company.get(company_id)

        set_clause = ", ".join("%s = ?" % k for k in updates.keys())
        vals = list(updates.values())

        with get_db() as conn:
            conn.execute(
                "UPDATE companies SET %s, last_activity = datetime('now') "
                "WHERE id = ?" % set_clause,
                vals + [company_id],
            )
        return Company.get(company_id)

    @staticmethod
    def count():
        # type: () -> int
        with get_db() as conn:
            row = conn.execute("SELECT COUNT(*) as cnt FROM companies").fetchone()
            return row["cnt"] if row else 0


# ─── Deal ────────────────────────────────────────────────────

@dataclass
class Deal:
    id: Optional[int] = None
    title: str = ""
    company_id: Optional[int] = None
    contact_id: Optional[int] = None
    stage: str = "LEAD"
    value_amount: float = 0.0
    value_currency: str = "AZN"
    expected_close: Optional[str] = None
    won_date: Optional[str] = None
    lost_reason: str = ""
    notes: str = ""
    created_at: Optional[str] = None
    updated_at: Optional[str] = None

    @staticmethod
    def create(data):
        # type: (Dict[str, Any]) -> Optional[Dict]
        title = data.get("title", "").strip()
        if not title:
            return None

        with get_db() as conn:
            cursor = conn.execute(
                "INSERT INTO deals "
                "(title, company_id, contact_id, assigned_to, created_by, stage, value_amount, value_currency, "
                "expected_close, notes) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    title,
                    data.get("company_id"),
                    data.get("contact_id"),
                    data.get("assigned_to"),
                    data.get("created_by"),
                    data.get("stage", "LEAD"),
                    data.get("value_amount", 0),
                    data.get("value_currency", "AZN"),
                    data.get("expected_close"),
                    data.get("notes", ""),
                ),
            )
            row = conn.execute(
                "SELECT d.*, c.name as contact_name, c.email as contact_email, "
                "co.name as company_name, u_assigned.username as assigned_to_name, "
                "u_created.username as created_by_name "
                "FROM deals d "
                "LEFT JOIN contacts c ON d.contact_id = c.id "
                "LEFT JOIN companies co ON d.company_id = co.id "
                "LEFT JOIN users u_assigned ON d.assigned_to = u_assigned.id "
                "LEFT JOIN users u_created ON d.created_by = u_created.id "
                "WHERE d.id = ?",
                (cursor.lastrowid,),
            ).fetchone()
            return dict_from_row(row)

    @staticmethod
    def get(deal_id):
        # type: (int) -> Optional[Dict]
        with get_db() as conn:
            row = conn.execute(
                "SELECT d.*, c.name as contact_name, c.email as contact_email, "
                "co.name as company_name, u_assigned.username as assigned_to_name, "
                "u_created.username as created_by_name "
                "FROM deals d "
                "LEFT JOIN contacts c ON d.contact_id = c.id "
                "LEFT JOIN companies co ON d.company_id = co.id "
                "LEFT JOIN users u_assigned ON d.assigned_to = u_assigned.id "
                "LEFT JOIN users u_created ON d.created_by = u_created.id "
                "WHERE d.id = ?",
                (deal_id,),
            ).fetchone()
            return dict_from_row(row)

    @staticmethod
    def search(stage=None, company_id=None, limit=50, offset=0):
        # type: (Optional[str], Optional[int], int, int) -> List[Dict]
        conditions = []
        params = []

        if stage:
            conditions.append("d.stage = ?")
            params.append(stage)
        if company_id:
            conditions.append("d.company_id = ?")
            params.append(company_id)

        where = " AND ".join(conditions) if conditions else "1=1"

        with get_db() as conn:
            rows = conn.execute(
                "SELECT d.*, c.name as contact_name, c.email as contact_email, "
                "co.name as company_name, u_assigned.username as assigned_to_name, "
                "u_created.username as created_by_name "
                "FROM deals d "
                "LEFT JOIN contacts c ON d.contact_id = c.id "
                "LEFT JOIN companies co ON d.company_id = co.id "
                "LEFT JOIN users u_assigned ON d.assigned_to = u_assigned.id "
                "LEFT JOIN users u_created ON d.created_by = u_created.id "
                "WHERE %s "
                "ORDER BY d.updated_at DESC "
                "LIMIT ? OFFSET ?" % where,
                params + [limit, offset],
            ).fetchall()
            return rows_to_dicts(rows)

    @staticmethod
    def update(deal_id, data):
        # type: (int, Dict[str, Any]) -> Optional[Dict]
        allowed = {
            "title", "company_id", "contact_id", "assigned_to", "stage",
            "value_amount", "value_currency", "expected_close",
            "won_date", "lost_reason", "notes",
        }
        updates = {k: v for k, v in data.items() if k in allowed}
        if not updates:
            return Deal.get(deal_id)

        # Auto-set won_date when stage changes to WON
        if updates.get("stage") == "WON" and "won_date" not in updates:
            updates["won_date"] = "datetime('now')"

        set_parts = []
        vals = []
        for k, v in updates.items():
            if v == "datetime('now')":
                set_parts.append("%s = datetime('now')" % k)
            else:
                set_parts.append("%s = ?" % k)
                vals.append(v)

        set_clause = ", ".join(set_parts)

        with get_db() as conn:
            conn.execute(
                "UPDATE deals SET %s, updated_at = datetime('now') "
                "WHERE id = ?" % set_clause,
                vals + [deal_id],
            )
        return Deal.get(deal_id)

    @staticmethod
    def move_stage(deal_id, new_stage):
        # type: (int, str) -> Optional[Dict]
        if new_stage not in PIPELINE_STAGES:
            return None
        return Deal.update(deal_id, {"stage": new_stage})

    @staticmethod
    def count(stage=None):
        # type: (Optional[str]) -> int
        with get_db() as conn:
            if stage:
                row = conn.execute(
                    "SELECT COUNT(*) as cnt FROM deals WHERE stage = ?", (stage,)
                ).fetchone()
            else:
                row = conn.execute(
                    "SELECT COUNT(*) as cnt FROM deals"
                ).fetchone()
            return row["cnt"] if row else 0

    @staticmethod
    def pipeline_summary():
        # type: () -> Dict[str, Any]
        """Get deals grouped by stage with totals."""
        with get_db() as conn:
            rows = conn.execute(
                "SELECT stage, COUNT(*) as count, "
                "COALESCE(SUM(value_amount), 0) as total_value "
                "FROM deals GROUP BY stage"
            ).fetchall()

            result = {}
            for stage in PIPELINE_STAGES:
                result[stage] = {"count": 0, "total_value": 0}
            for r in rows:
                d = dict(r)
                result[d["stage"]] = {
                    "count": d["count"],
                    "total_value": d["total_value"],
                }
            return result


# ─── Activity ────────────────────────────────────────────────

@dataclass
class Activity:
    id: Optional[int] = None
    contact_id: Optional[int] = None
    deal_id: Optional[int] = None
    activity_type: str = "NOTE"
    direction: str = "INBOUND"
    subject: str = ""
    content: str = ""
    metadata: str = "{}"
    timestamp: Optional[str] = None

    @staticmethod
    def create(data):
        # type: (Dict[str, Any]) -> Optional[Dict]
        with get_db() as conn:
            ts = data.get("timestamp")
            status = data.get("status", "completed")
            if ts:
                cursor = conn.execute(
                    "INSERT INTO activities "
                    "(contact_id, deal_id, activity_type, direction, subject, content, metadata, timestamp, status) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        data.get("contact_id"),
                        data.get("deal_id"),
                        data.get("activity_type", "NOTE"),
                        data.get("direction", "INBOUND"),
                        data.get("subject", ""),
                        data.get("content", ""),
                        data.get("metadata", "{}"),
                        ts,
                        status,
                    ),
                )
            else:
                cursor = conn.execute(
                    "INSERT INTO activities "
                    "(contact_id, deal_id, activity_type, direction, subject, content, metadata, status) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        data.get("contact_id"),
                        data.get("deal_id"),
                        data.get("activity_type", "NOTE"),
                        data.get("direction", "INBOUND"),
                        data.get("subject", ""),
                        data.get("content", ""),
                        data.get("metadata", "{}"),
                        status,
                    ),
                )
            row = conn.execute(
                "SELECT * FROM activities WHERE id = ?", (cursor.lastrowid,)
            ).fetchone()
            return dict_from_row(row)

    @staticmethod
    def get_for_contact(contact_id, limit=50):
        # type: (int, int) -> List[Dict]
        with get_db() as conn:
            rows = conn.execute(
                "SELECT * FROM activities WHERE contact_id = ? "
                "ORDER BY timestamp DESC LIMIT ?",
                (contact_id, limit),
            ).fetchall()
            return rows_to_dicts(rows)

    @staticmethod
    def get_recent(limit=50):
        # type: (int) -> List[Dict]
        with get_db() as conn:
            rows = conn.execute(
                "SELECT a.*, c.name as contact_name, c.email as contact_email "
                "FROM activities a "
                "LEFT JOIN contacts c ON a.contact_id = c.id "
                "ORDER BY a.timestamp DESC LIMIT ?",
                (limit,),
            ).fetchall()
            return rows_to_dicts(rows)

    @staticmethod
    def count():
        # type: () -> int
        with get_db() as conn:
            row = conn.execute(
                "SELECT COUNT(*) as cnt FROM activities"
            ).fetchone()
            return row["cnt"] if row else 0


# ─── Email Sync Log ─────────────────────────────────────────

class EmailSyncLog:
    @staticmethod
    def is_synced(message_id):
        # type: (str) -> bool
        with get_db() as conn:
            row = conn.execute(
                "SELECT 1 FROM email_sync_log WHERE message_id = ?",
                (message_id,),
            ).fetchone()
            return row is not None

    @staticmethod
    def mark_synced(message_id, from_addr="", subject=""):
        # type: (str, str, str) -> None
        with get_db() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO email_sync_log "
                "(message_id, from_addr, subject) VALUES (?, ?, ?)",
                (message_id, from_addr, subject),
            )

    @staticmethod
    def count():
        # type: () -> int
        with get_db() as conn:
            row = conn.execute(
                "SELECT COUNT(*) as cnt FROM email_sync_log"
            ).fetchone()
            return row["cnt"] if row else 0
