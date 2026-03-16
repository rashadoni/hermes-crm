"""
CRM Database — PostgreSQL with SQLite compatibility layer
==========================================================
Transparently converts SQLite-style SQL to PostgreSQL so that
the 14,000+ lines in api.py require minimal changes.
"""

import os
import re
import logging
from contextlib import contextmanager

import psycopg2
import psycopg2.extras

logger = logging.getLogger(__name__)

# ─── Connection config ────────────────────────────────────────
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://hermes:hermes@localhost:5432/hermes_crm")
DB_PATH = os.getenv("CRM_DB_PATH", "crm.db")  # kept for migration script reference

SCHEMA_VERSION = 2  # bumped for PostgreSQL migration


# ─── SQL Rewriter ─────────────────────────────────────────────

# Pre-compiled regex patterns for performance
_RE_DATETIME_NOW_OFFSET = re.compile(
    r"datetime\s*\(\s*'now'\s*,\s*'([+-])(\d+)\s+(day|days|hour|hours|minute|minutes|month|months|year|years)'\s*\)",
    re.IGNORECASE,
)
_RE_DATETIME_NOW_CONCAT = re.compile(
    r"datetime\s*\(\s*'now'\s*,\s*'([+-])'\s*\|\|\s*\?\s*\|\|\s*'\s*(hour|hours|day|days|minute|minutes)'\s*\)",
    re.IGNORECASE,
)
_RE_DATETIME_NOW = re.compile(r"datetime\s*\(\s*'now'\s*\)", re.IGNORECASE)
_RE_AUTOINCREMENT = re.compile(r"INTEGER\s+PRIMARY\s+KEY\s+AUTOINCREMENT", re.IGNORECASE)
_RE_INSERT_OR_IGNORE = re.compile(r"INSERT\s+OR\s+IGNORE\s+INTO", re.IGNORECASE)
_RE_INSERT_OR_REPLACE = re.compile(r"INSERT\s+OR\s+REPLACE\s+INTO", re.IGNORECASE)
_RE_REPLACE_INTO = re.compile(r"REPLACE\s+INTO", re.IGNORECASE)
_RE_GROUP_CONCAT = re.compile(
    r"GROUP_CONCAT\s*\((.+?),\s*'([^']*)'\s*\)",
    re.IGNORECASE,
)
_RE_GROUP_CONCAT_SIMPLE = re.compile(
    r"GROUP_CONCAT\s*\((.+?)\)",
    re.IGNORECASE,
)
_RE_PRAGMA_TABLE_INFO = re.compile(r"PRAGMA\s+table_info\s*\(\s*(\w+)\s*\)", re.IGNORECASE)
_RE_PLACEHOLDER = re.compile(r"\?")


def rewrite_sql(sql, params=None):
    """
    Rewrite SQLite-flavored SQL to PostgreSQL.
    Returns (new_sql, new_params).
    """
    if not sql or not sql.strip():
        return sql, params

    original_sql = sql

    # ── datetime('now', '+' || ? || ' hours') → NOW() + ? * INTERVAL '1 hour'
    # This pattern uses a ? param for the offset value
    def _replace_datetime_concat(m):
        sign = m.group(1)
        unit = m.group(2).rstrip('s')  # normalize: hours→hour
        op = '+' if sign == '+' else '-'
        return f"NOW() {op} (%s * INTERVAL '1 {unit}')"

    sql = _RE_DATETIME_NOW_CONCAT.sub(_replace_datetime_concat, sql)

    # ── datetime('now', '-7 days') → NOW() - INTERVAL '7 days'
    def _replace_datetime_offset(m):
        sign = m.group(1)
        num = m.group(2)
        unit = m.group(3)
        op = '+' if sign == '+' else '-'
        return f"NOW() {op} INTERVAL '{num} {unit}'"

    sql = _RE_DATETIME_NOW_OFFSET.sub(_replace_datetime_offset, sql)

    # ── datetime('now') → NOW()
    sql = _RE_DATETIME_NOW.sub("NOW()", sql)

    # ── INTEGER PRIMARY KEY AUTOINCREMENT → SERIAL PRIMARY KEY
    sql = _RE_AUTOINCREMENT.sub("SERIAL PRIMARY KEY", sql)

    # ── INSERT OR REPLACE INTO → INSERT ... ON CONFLICT
    # For INSERT OR REPLACE, we need to extract the table and handle upsert
    # Since this is complex and only used once (notification_preferences),
    # we convert to a simpler pattern
    def _replace_insert_or_replace(m):
        return "INSERT INTO"

    # Handle INSERT OR REPLACE specially — caller must add ON CONFLICT clause
    # We mark it so the wrapper can detect and handle
    if _RE_INSERT_OR_REPLACE.search(sql) or _RE_REPLACE_INTO.search(sql):
        sql = _RE_INSERT_OR_REPLACE.sub("INSERT INTO", sql)
        sql = _RE_REPLACE_INTO.sub("INSERT INTO", sql)
        # Add ON CONFLICT DO UPDATE for known upsert patterns
        if "notification_preferences" in sql.lower():
            sql = sql.rstrip().rstrip(';')
            sql += " ON CONFLICT (user_id, event_type) DO UPDATE SET channel_web=EXCLUDED.channel_web, channel_email=EXCLUDED.channel_email, channel_telegram=EXCLUDED.channel_telegram"
        elif "crm_metadata" in sql.lower():
            sql = sql.rstrip().rstrip(';')
            sql += " ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value"

    # ── INSERT OR IGNORE INTO → INSERT INTO ... ON CONFLICT DO NOTHING
    if _RE_INSERT_OR_IGNORE.search(sql):
        sql = _RE_INSERT_OR_IGNORE.sub("INSERT INTO", sql)
        # Add ON CONFLICT DO NOTHING at end (before trailing semicolon)
        sql = sql.rstrip().rstrip(';')
        sql += " ON CONFLICT DO NOTHING"

    # ── GROUP_CONCAT(expr, sep) → STRING_AGG(expr::TEXT, sep)
    def _replace_group_concat(m):
        expr = m.group(1).strip()
        sep = m.group(2)
        return f"STRING_AGG({expr}::TEXT, '{sep}')"

    sql = _RE_GROUP_CONCAT.sub(_replace_group_concat, sql)

    def _replace_group_concat_simple(m):
        expr = m.group(1).strip()
        return f"STRING_AGG({expr}::TEXT, ',')"

    sql = _RE_GROUP_CONCAT_SIMPLE.sub(_replace_group_concat_simple, sql)

    # ── PRAGMA table_info(table) → information_schema query
    pragma_match = _RE_PRAGMA_TABLE_INFO.search(sql)
    if pragma_match:
        table_name = pragma_match.group(1)
        sql = f"""SELECT ordinal_position - 1 as cid, column_name as name,
                         data_type as type,
                         CASE WHEN is_nullable = 'NO' THEN 1 ELSE 0 END as notnull,
                         column_default as dflt_value,
                         0 as pk
                  FROM information_schema.columns
                  WHERE table_name = '{table_name}'
                  ORDER BY ordinal_position"""
        # PRAGMA doesn't use params
        return sql, params

    # ── TEXT DEFAULT (datetime('now')) already handled by datetime rewrite
    # But we need to handle the parenthesized version in CREATE TABLE
    sql = sql.replace("DEFAULT (NOW())", "DEFAULT NOW()")

    # ── Convert ? placeholders to %s
    if params is not None and '?' in sql:
        sql = _RE_PLACEHOLDER.sub('%s', sql)

    # ── Boolean-safe: PostgreSQL is fine with INTEGER 0/1 for boolean-like columns
    # No conversion needed — we keep INTEGER columns as-is for compatibility

    return sql, params


# ─── DictRow — sqlite3.Row-compatible dict wrapper ────────────

class DictRow(dict):
    """
    A dict subclass that also supports integer index access,
    mimicking sqlite3.Row behavior.
    """
    def __init__(self, cursor_description, values):
        cols = [desc[0] for desc in cursor_description]
        super().__init__(zip(cols, values))
        self._cols = cols
        self._values = list(values)

    def __getitem__(self, key):
        if isinstance(key, int):
            return self._values[key]
        return super().__getitem__(key)

    def __iter__(self):
        return iter(self._values)

    def __len__(self):
        return len(self._values)

    def keys(self):
        return self._cols

    def values(self):
        return self._values

    def items(self):
        return zip(self._cols, self._values)


# ─── Cursor Wrapper ──────────────────────────────────────────

class PgCursorWrapper:
    """
    Wraps a psycopg2 cursor to provide SQLite-compatible API:
    - Auto-converts ? → %s
    - Rewrites SQLite SQL to PostgreSQL
    - Returns DictRow objects
    """
    def __init__(self, cursor, conn):
        self._cursor = cursor
        self._conn = conn
        self.description = cursor.description
        self.lastrowid = None
        self.rowcount = cursor.rowcount
        self._returning_consumed = False

    def execute(self, sql, params=None):
        sql, params = rewrite_sql(sql, params)
        # Convert list params to tuple for psycopg2
        if isinstance(params, list):
            params = tuple(params)

        sql_upper = sql.strip().upper()
        is_insert = sql_upper.startswith("INSERT")
        is_ddl = sql_upper.startswith(("CREATE", "ALTER", "DROP"))

        # Auto-add RETURNING id for INSERT statements (for lastrowid support)
        returning_added = False
        if is_insert and "RETURNING" not in sql.upper():
            sql_clean = sql.rstrip().rstrip(';')
            sql = sql_clean + " RETURNING id"
            returning_added = True

        if is_ddl:
            # DDL statements use savepoints for graceful "already exists" handling
            sp_name = "sp_ddl"
            try:
                self._cursor.execute(f"SAVEPOINT {sp_name}")
                self._cursor.execute(sql, params)
                self._cursor.execute(f"RELEASE SAVEPOINT {sp_name}")
            except (psycopg2.errors.DuplicateTable,
                    psycopg2.errors.DuplicateObject,
                    psycopg2.errors.DuplicateColumn):
                self._cursor.execute(f"ROLLBACK TO SAVEPOINT {sp_name}")
                self._cursor.execute(f"RELEASE SAVEPOINT {sp_name}")
                return self
            except Exception:
                try:
                    self._cursor.execute(f"ROLLBACK TO SAVEPOINT {sp_name}")
                    self._cursor.execute(f"RELEASE SAVEPOINT {sp_name}")
                except Exception:
                    pass
                raise
        else:
            # DML/SELECT — execute directly, no savepoint wrapper
            try:
                self._cursor.execute(sql, params)
            except psycopg2.errors.UndefinedColumn:
                if returning_added:
                    # RETURNING id failed — table has no 'id' column, retry without
                    self._conn.rollback()
                    sql = sql.rsplit(" RETURNING id", 1)[0]
                    returning_added = False
                    self._cursor.execute(sql, params)
                else:
                    raise
            except psycopg2.errors.UniqueViolation:
                self._conn.rollback()
                self.lastrowid = None
                return self

        self.description = self._cursor.description
        self.rowcount = self._cursor.rowcount

        # Get lastrowid from RETURNING clause
        if is_insert and returning_added and self._cursor.description:
            try:
                if self._cursor.rowcount > 0:
                    row = self._cursor.fetchone()
                    self.lastrowid = row[0] if row else None
                else:
                    # ON CONFLICT DO NOTHING — no rows inserted
                    self.lastrowid = None
                self._returning_consumed = True
            except Exception:
                self.lastrowid = None
                self._returning_consumed = True
        elif is_insert:
            try:
                self._cursor.execute("SELECT lastval()")
                row = self._cursor.fetchone()
                self.lastrowid = row[0] if row else None
            except Exception:
                self.lastrowid = None

        return self

    def executemany(self, sql, params_list):
        sql, _ = rewrite_sql(sql, [])  # just rewrite SQL, params handled per-row
        for params in params_list:
            if isinstance(params, list):
                params = tuple(params)
            self._cursor.execute(sql, params)
        self.description = self._cursor.description
        self.rowcount = self._cursor.rowcount
        return self

    def executescript(self, sql_script):
        """
        Execute multiple SQL statements (SQLite executescript equivalent).
        Split on semicolons and execute each statement.
        Uses SAVEPOINTs so individual statement failures don't kill the transaction.
        """
        statements = [s.strip() for s in sql_script.split(';') if s.strip()]
        for i, stmt in enumerate(statements):
            if not stmt:
                continue
            rewritten, _ = rewrite_sql(stmt, None)
            sp_name = f"sp_execscript_{i}"
            try:
                self._cursor.execute(f"SAVEPOINT {sp_name}")
                self._cursor.execute(rewritten)
                self._cursor.execute(f"RELEASE SAVEPOINT {sp_name}")
            except (psycopg2.errors.DuplicateTable,
                    psycopg2.errors.DuplicateObject,
                    psycopg2.errors.DuplicateColumn):
                self._cursor.execute(f"ROLLBACK TO SAVEPOINT {sp_name}")
                self._cursor.execute(f"RELEASE SAVEPOINT {sp_name}")
            except Exception as e:
                logger.warning("executescript statement failed: %s — %s", stmt[:80], e)
                try:
                    self._cursor.execute(f"ROLLBACK TO SAVEPOINT {sp_name}")
                    self._cursor.execute(f"RELEASE SAVEPOINT {sp_name}")
                except Exception:
                    pass
        return self

    def fetchone(self):
        row = self._cursor.fetchone()
        if row is None:
            return None
        if self._cursor.description:
            return DictRow(self._cursor.description, row)
        return row

    def fetchall(self):
        rows = self._cursor.fetchall()
        if not rows or not self._cursor.description:
            return rows
        return [DictRow(self._cursor.description, r) for r in rows]

    def close(self):
        self._cursor.close()

    def __iter__(self):
        return self

    def __next__(self):
        row = self._cursor.fetchone()
        if row is None:
            raise StopIteration
        if self._cursor.description:
            return DictRow(self._cursor.description, row)
        return row


# ─── Connection Wrapper ──────────────────────────────────────

class PgConnectionWrapper:
    """
    Wraps a psycopg2 connection to provide SQLite-compatible API.
    """
    def __init__(self, conn):
        self._conn = conn
        # Set autocommit off — we manage transactions ourselves
        self._conn.autocommit = False

    def execute(self, sql, params=None):
        cursor = self._conn.cursor()
        wrapper = PgCursorWrapper(cursor, self._conn)
        return wrapper.execute(sql, params)

    def executemany(self, sql, params_list):
        cursor = self._conn.cursor()
        wrapper = PgCursorWrapper(cursor, self._conn)
        return wrapper.executemany(sql, params_list)

    def executescript(self, sql_script):
        cursor = self._conn.cursor()
        wrapper = PgCursorWrapper(cursor, self._conn)
        return wrapper.executescript(sql_script)

    def commit(self):
        self._conn.commit()

    def rollback(self):
        self._conn.rollback()

    def close(self):
        self._conn.close()

    def cursor(self):
        cursor = self._conn.cursor()
        return PgCursorWrapper(cursor, self._conn)

    @property
    def row_factory(self):
        return None

    @row_factory.setter
    def row_factory(self, value):
        # Ignored — we always return DictRow
        pass


# ─── Connection functions ────────────────────────────────────

def get_db_path():
    """Return the database path (for backward compat / migration scripts)."""
    if os.path.isabs(DB_PATH):
        return DB_PATH
    base = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base, DB_PATH)


def get_connection():
    """Create a new PostgreSQL connection with SQLite-compatible wrapper."""
    conn = psycopg2.connect(DATABASE_URL)
    return PgConnectionWrapper(conn)


def get_raw_connection():
    """Get a raw psycopg2 connection (for migration/admin tasks)."""
    return psycopg2.connect(DATABASE_URL)


@contextmanager
def get_db():
    """Context manager for database connections."""
    conn = get_connection()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# ─── Read-only connection (for AI analytics) ─────────────────

def get_readonly_connection():
    """
    Get a read-only PostgreSQL connection.
    Used by AI analytics to safely run generated SQL.
    """
    conn = psycopg2.connect(DATABASE_URL, options="-c default_transaction_read_only=on")
    return PgConnectionWrapper(conn)


# ─── Schema ──────────────────────────────────────────────────

SCHEMA_SQL = """
-- Metadata table for tracking schema version
CREATE TABLE IF NOT EXISTS crm_metadata (
    key   TEXT PRIMARY KEY,
    value TEXT
);

-- Users
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL DEFAULT '',
    password_hash TEXT NOT NULL,
    full_name TEXT DEFAULT '',
    role TEXT DEFAULT 'manager',
    is_active INTEGER DEFAULT 1,
    created_at TIMESTAMP DEFAULT NOW(),
    role_id INTEGER,
    department TEXT DEFAULT '',
    phone TEXT DEFAULT '',
    avatar_url TEXT DEFAULT '',
    last_login TIMESTAMP,
    login_count INTEGER DEFAULT 0,
    totp_secret TEXT DEFAULT '',
    totp_enabled INTEGER DEFAULT 0,
    backup_codes TEXT DEFAULT '[]'
);
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);

-- Companies
CREATE TABLE IF NOT EXISTS companies (
    id              SERIAL PRIMARY KEY,
    name            TEXT NOT NULL,
    domain          TEXT UNIQUE,
    industry        TEXT DEFAULT '',
    website         TEXT DEFAULT '',
    notes           TEXT DEFAULT '',
    category        TEXT DEFAULT '',
    contacts_count  INTEGER DEFAULT 0,
    created_at      TIMESTAMP DEFAULT NOW(),
    last_activity   TIMESTAMP DEFAULT NOW()
);

-- Contacts
CREATE TABLE IF NOT EXISTS contacts (
    id              SERIAL PRIMARY KEY,
    email           TEXT UNIQUE NOT NULL,
    name            TEXT DEFAULT '',
    phone           TEXT DEFAULT '',
    company_id      INTEGER REFERENCES companies(id),
    company_name    TEXT DEFAULT '',
    role            TEXT DEFAULT '',
    source          TEXT DEFAULT 'EMAIL',
    tags            TEXT DEFAULT '[]',
    notes           TEXT DEFAULT '',
    email_count     INTEGER DEFAULT 0,
    last_contact    TIMESTAMP,
    created_at      TIMESTAMP DEFAULT NOW(),
    updated_at      TIMESTAMP DEFAULT NOW()
);

-- Deals / Pipeline
CREATE TABLE IF NOT EXISTS deals (
    id              SERIAL PRIMARY KEY,
    title           TEXT NOT NULL,
    company_id      INTEGER REFERENCES companies(id),
    contact_id      INTEGER REFERENCES contacts(id),
    assigned_to     INTEGER DEFAULT NULL REFERENCES users(id),
    created_by      INTEGER DEFAULT NULL REFERENCES users(id),
    stage           TEXT DEFAULT 'LEAD',
    value_amount    REAL DEFAULT 0,
    value_currency  TEXT DEFAULT 'AZN',
    expected_close  TEXT,
    won_date        TEXT,
    lost_reason     TEXT DEFAULT '',
    notes           TEXT DEFAULT '',
    created_at      TIMESTAMP DEFAULT NOW(),
    updated_at      TIMESTAMP DEFAULT NOW()
);

-- Activities
CREATE TABLE IF NOT EXISTS activities (
    id              SERIAL PRIMARY KEY,
    contact_id      INTEGER REFERENCES contacts(id),
    deal_id         INTEGER REFERENCES deals(id),
    activity_type   TEXT DEFAULT 'NOTE',
    direction       TEXT DEFAULT 'INBOUND',
    subject         TEXT DEFAULT '',
    content         TEXT DEFAULT '',
    metadata        TEXT DEFAULT '{}',
    status          TEXT DEFAULT 'completed',
    timestamp       TIMESTAMP DEFAULT NOW()
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_contacts_email ON contacts(email);
CREATE INDEX IF NOT EXISTS idx_contacts_company ON contacts(company_id);
CREATE INDEX IF NOT EXISTS idx_deals_stage ON deals(stage);
CREATE INDEX IF NOT EXISTS idx_deals_company ON deals(company_id);
CREATE INDEX IF NOT EXISTS idx_deals_contact ON deals(contact_id);
CREATE INDEX IF NOT EXISTS idx_activities_contact ON activities(contact_id);
CREATE INDEX IF NOT EXISTS idx_activities_deal ON activities(deal_id);
CREATE INDEX IF NOT EXISTS idx_activities_type ON activities(activity_type);

-- Audit log
CREATE TABLE IF NOT EXISTS audit_log (
    id SERIAL PRIMARY KEY,
    user_id INTEGER,
    action TEXT NOT NULL,
    entity_type TEXT,
    entity_id INTEGER,
    details TEXT DEFAULT '',
    ip_address TEXT DEFAULT '',
    created_at TIMESTAMP DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_audit_log_user ON audit_log(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_action ON audit_log(action);

-- Commercial Offers
CREATE TABLE IF NOT EXISTS offers (
    id SERIAL PRIMARY KEY,
    offer_number TEXT NOT NULL,
    offer_type TEXT DEFAULT 'services',
    currency TEXT DEFAULT 'AZN',
    show_vat INTEGER DEFAULT 0,
    vat_pct REAL DEFAULT 18,
    view_mode TEXT DEFAULT 'detailed',
    company_id INTEGER REFERENCES companies(id),
    client_name TEXT DEFAULT '',
    client_voen TEXT DEFAULT '',
    client_contact TEXT DEFAULT '',
    client_contract TEXT DEFAULT '',
    notes TEXT DEFAULT '',
    status TEXT DEFAULT 'draft',
    items TEXT DEFAULT '[]',
    valid_until TEXT DEFAULT '',
    created_by INTEGER REFERENCES users(id),
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_offers_status ON offers(status);
CREATE INDEX IF NOT EXISTS idx_offers_company ON offers(company_id);

-- Price changes
CREATE TABLE IF NOT EXISTS price_changes (
    id SERIAL PRIMARY KEY,
    company_code TEXT NOT NULL,
    status TEXT DEFAULT 'pending',
    old_prices TEXT DEFAULT '{}',
    new_prices TEXT DEFAULT '{}',
    notes TEXT DEFAULT '',
    effective_date TEXT DEFAULT NULL,
    created_by INTEGER REFERENCES users(id),
    approved_by INTEGER REFERENCES users(id),
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_price_changes_status ON price_changes(status);
CREATE INDEX IF NOT EXISTS idx_price_changes_company ON price_changes(company_code);

-- Pricing parameters
CREATE TABLE IF NOT EXISTS pricing_parameters (
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
    updated_at TIMESTAMP DEFAULT NOW(),
    updated_by INTEGER REFERENCES users(id)
);

-- Overhead costs
CREATE TABLE IF NOT EXISTS overhead_costs (
    id SERIAL PRIMARY KEY,
    category TEXT NOT NULL,
    label TEXT NOT NULL,
    amount REAL DEFAULT 0,
    is_annual INTEGER DEFAULT 0,
    has_vat INTEGER DEFAULT 0,
    sort_order INTEGER DEFAULT 0,
    notes TEXT DEFAULT ''
);

-- Employees / staffing
CREATE TABLE IF NOT EXISTS cost_employees (
    id SERIAL PRIMARY KEY,
    department TEXT NOT NULL,
    position TEXT NOT NULL,
    count INTEGER DEFAULT 1,
    net_salary REAL DEFAULT 0,
    gross_salary REAL DEFAULT 0,
    super_gross REAL DEFAULT 0,
    in_overhead INTEGER DEFAULT 0,
    notes TEXT DEFAULT ''
);

-- Client services
CREATE TABLE IF NOT EXISTS client_services (
    id SERIAL PRIMARY KEY,
    company_id INTEGER REFERENCES companies(id) ON DELETE CASCADE,
    company_code TEXT NOT NULL,
    service_type TEXT NOT NULL,
    monthly_revenue REAL DEFAULT 0,
    is_active INTEGER DEFAULT 1,
    notes TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_client_services_company ON client_services(company_id);
CREATE INDEX IF NOT EXISTS idx_client_services_type ON client_services(service_type);

-- Leads
CREATE TABLE IF NOT EXISTS leads (
    id SERIAL PRIMARY KEY,
    company_name TEXT NOT NULL,
    contact_name TEXT,
    email TEXT,
    phone TEXT,
    source TEXT DEFAULT '',
    status TEXT DEFAULT 'new',
    priority TEXT DEFAULT 'medium',
    estimated_value REAL DEFAULT 0,
    estimated_users INTEGER DEFAULT 0,
    industry TEXT DEFAULT '',
    website TEXT DEFAULT '',
    notes TEXT DEFAULT '',
    assigned_to INTEGER REFERENCES users(id),
    converted_at TIMESTAMP,
    converted_company_id INTEGER REFERENCES companies(id),
    converted_contact_id INTEGER REFERENCES contacts(id),
    converted_deal_id INTEGER REFERENCES deals(id),
    created_by INTEGER REFERENCES users(id),
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Tasks
CREATE TABLE IF NOT EXISTS tasks (
    id SERIAL PRIMARY KEY,
    title TEXT NOT NULL,
    description TEXT DEFAULT '',
    status TEXT DEFAULT 'todo',
    priority TEXT DEFAULT 'medium',
    due_date TEXT,
    due_time TEXT,
    reminder_at TIMESTAMP,
    category TEXT DEFAULT 'general',
    company_id INTEGER REFERENCES companies(id),
    contact_id INTEGER REFERENCES contacts(id),
    deal_id INTEGER REFERENCES deals(id),
    lead_id INTEGER REFERENCES leads(id),
    assigned_to INTEGER REFERENCES users(id),
    created_by INTEGER REFERENCES users(id),
    completed_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_tasks_status ON tasks(status);
CREATE INDEX IF NOT EXISTS idx_tasks_due ON tasks(due_date);
CREATE INDEX IF NOT EXISTS idx_tasks_assigned ON tasks(assigned_to);
CREATE INDEX IF NOT EXISTS idx_tasks_company ON tasks(company_id);
CREATE INDEX IF NOT EXISTS idx_tasks_deal ON tasks(deal_id);

-- Contracts
CREATE TABLE IF NOT EXISTS contracts (
    id SERIAL PRIMARY KEY,
    contract_name TEXT,
    counterparty TEXT,
    contract_type TEXT DEFAULT 'other',
    amount TEXT DEFAULT '',
    currency TEXT DEFAULT '',
    start_date TEXT DEFAULT '',
    end_date TEXT DEFAULT '',
    status TEXT DEFAULT 'unknown',
    summary TEXT DEFAULT '',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_contracts_counterparty ON contracts(counterparty);
CREATE INDEX IF NOT EXISTS idx_contracts_status ON contracts(status);
CREATE INDEX IF NOT EXISTS idx_contracts_end_date ON contracts(end_date);

-- Cost model audit log
CREATE TABLE IF NOT EXISTS cost_model_log (
    id SERIAL PRIMARY KEY,
    table_name TEXT NOT NULL,
    record_id INTEGER,
    action TEXT NOT NULL,
    old_value TEXT,
    new_value TEXT,
    changed_by INTEGER REFERENCES users(id),
    changed_at TIMESTAMP DEFAULT NOW()
);

-- Lead Assignment Rules
CREATE TABLE IF NOT EXISTS lead_assignment_rules (
    id SERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    conditions TEXT DEFAULT '{}',
    assign_to INTEGER REFERENCES users(id),
    assign_method TEXT DEFAULT 'direct',
    priority INTEGER DEFAULT 0,
    is_active INTEGER DEFAULT 1,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Deal Team Members
CREATE TABLE IF NOT EXISTS deal_team_members (
    id SERIAL PRIMARY KEY,
    deal_id INTEGER REFERENCES deals(id),
    user_id INTEGER REFERENCES users(id),
    role TEXT DEFAULT 'member',
    added_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(deal_id, user_id)
);

-- Token blacklist
CREATE TABLE IF NOT EXISTS token_blacklist (
    token TEXT PRIMARY KEY,
    blacklisted_at TIMESTAMP DEFAULT NOW(),
    expires_at TIMESTAMP
);
"""


def init_db():
    """Initialize database schema."""
    logger.info("Initializing CRM database (PostgreSQL)")

    with get_db() as conn:
        # Execute schema — use executescript which handles savepoints
        conn.executescript(SCHEMA_SQL)

        # Migrations — add missing columns safely using savepoints
        def safe_add_column(table, column, col_type):
            cursor = conn._conn.cursor()
            try:
                cursor.execute(f"SAVEPOINT sp_col_{table}_{column}")
                cursor.execute(f"ALTER TABLE {table} ADD COLUMN {column} {col_type}")
                cursor.execute(f"RELEASE SAVEPOINT sp_col_{table}_{column}")
                logger.info("Migration: added '%s' column to %s", column, table)
            except Exception as e:
                cursor.execute(f"ROLLBACK TO SAVEPOINT sp_col_{table}_{column}")
                cursor.execute(f"RELEASE SAVEPOINT sp_col_{table}_{column}")
                if 'already exists' not in str(e).lower() and 'duplicate' not in str(e).lower():
                    logger.debug("Column %s.%s already exists or skipped: %s", table, column, e)

        safe_add_column("companies", "category", "TEXT DEFAULT ''")
        safe_add_column("deals", "assigned_to", "INTEGER DEFAULT NULL REFERENCES users(id)")
        safe_add_column("deals", "created_by", "INTEGER DEFAULT NULL REFERENCES users(id)")
        safe_add_column("users", "email", "TEXT DEFAULT ''")
        safe_add_column("price_changes", "effective_date", "TEXT DEFAULT NULL")
        safe_add_column("companies", "user_count", "INTEGER DEFAULT 0")
        safe_add_column("companies", "cost_code", "TEXT DEFAULT ''")
        safe_add_column("users", "calendar_token", "TEXT DEFAULT NULL")

        # Seed pricing_parameters if empty
        params_count = conn.execute("SELECT COUNT(*) FROM pricing_parameters").fetchone()[0]
        if params_count == 0:
            conn.execute("""INSERT INTO pricing_parameters
                (id, total_users, total_employees, technical_staff, back_office_staff,
                 monthly_work_hours, vat_rate, employer_tax_rate, risk_rate, misc_expense_rate,
                 fixed_overhead_ratio)
                VALUES (1, 4500, 137, 107, 30, 160, 0.18, 0.175, 0.05, 0.01, 0.25)""")
            logger.info("Seeded default pricing_parameters")

        # Seed overhead_costs if empty
        overhead_count = conn.execute("SELECT COUNT(*) FROM overhead_costs").fetchone()[0]
        if overhead_count == 0:
            overheads = [
                ('cloud_servers', 'Bulud serverləri (ƏDV xaric)', 20000, 0, 1, 1),
                ('office_rent', 'Ofis icarəsi', 30000, 0, 0, 2),
                ('insurance', 'İşçi sığortası (1 nəfər/ay)', 40, 0, 0, 3),
                ('mobile', 'Mobil rabitə (1 nəfər/ay)', 30, 0, 0, 4),
                ('cortex', 'Cortex/Crowdstrike (illik, ƏDV xaric)', 500000, 1, 1, 5),
                ('ms_license', 'MS Lisenziya (aylıq, ƏDV xaric)', 6800, 0, 1, 6),
                ('service_desk', 'Service Desk (illik, ƏDV xaric)', 50000, 1, 1, 7),
                ('palo_alto', 'Firewall Palo Alto (illik, ƏDV xaric)', 76000, 1, 1, 8),
                ('pam', 'PAM Lisenziya (illik, ƏDV xaric)', 40000, 1, 1, 9),
                ('lms', 'LMS Platforma (illik, ƏDV xaric)', 50000, 1, 1, 10),
                ('trainings', 'Treninqlər (illik)', 250000, 1, 0, 11),
                ('ai_licenses', 'AI Lisenziyaları (illik, ƏDV xaric)', 3800, 1, 1, 12),
                ('car_amort', 'Maşın amortizasiyası (150k÷60 ay)', 2500, 0, 0, 13),
                ('car_expenses', 'Maşın cari xərcləri', 1200, 0, 0, 14),
                ('firewall_amort', 'Firewall amortizasiyası (130k÷84 ay)', 1547.62, 0, 0, 15),
                ('laptops', 'Laptop xərci', 8500, 0, 0, 16),
                ('internet', 'İnternet xərci', 439, 0, 0, 17),
                ('team_building', 'Team building (illik)', 120000, 1, 0, 18),
            ]
            for cat, label, amount, is_annual, has_vat, sort_order in overheads:
                conn.execute(
                    "INSERT INTO overhead_costs (category, label, amount, is_annual, has_vat, sort_order) VALUES (?,?,?,?,?,?)",
                    [cat, label, amount, is_annual, has_vat, sort_order]
                )
            logger.info("Seeded default overhead_costs")

        # Seed employees if empty
        emp_count = conn.execute("SELECT COUNT(*) FROM cost_employees").fetchone()[0]
        if emp_count == 0:
            employees = [
                ('IT', 'SysAdmin', 8, 2992.19, 0),
                ('IT', 'NetAdmin', 8, 3538.82, 0),
                ('InfoSec', 'InfoSec Engineer', 12, 3603.90, 0),
                ('IT', 'Zəng Mərkəzi', 4, 1737.28, 0),
                ('ERP', 'ERP Specialist', 6, 3177.18, 0),
                ('PM', 'Project Manager', 5, 3389.60, 0),
                ('GRC', 'GRC Specialist', 8, 2451.72, 1),
                ('HelpDesk', 'HelpDesk Operator', 56, 1737.28, 0),
                ('BackOffice', 'Back-office Staff', 30, 80000/30, 0),
            ]
            for dept, pos, count, net_sal, in_overhead in employees:
                gross = net_sal / (1 - 0.14)
                super_gross = gross * 1.175
                conn.execute(
                    "INSERT INTO cost_employees (department, position, count, net_salary, gross_salary, super_gross, in_overhead) VALUES (?,?,?,?,?,?,?)",
                    [dept, pos, count, round(net_sal, 2), round(gross, 2), round(super_gross, 2), in_overhead]
                )
            logger.info("Seeded default cost_employees")

        # Create default admin user if no users exist
        user_count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        if user_count == 0:
            import bcrypt, secrets as _sec
            default_password = _sec.token_urlsafe(12)
            password_hash = bcrypt.hashpw(default_password.encode(), bcrypt.gensalt()).decode()
            conn.execute(
                "INSERT INTO users (username, email, password_hash, full_name, role, is_active) VALUES (?, ?, ?, ?, ?, ?)",
                ("admin", "admin@hermes.local", password_hash, "Administrator", "admin", 1)
            )
            logger.info("=" * 50)
            logger.info("  DEFAULT ADMIN CREDENTIALS")
            logger.info("  Email: admin@hermes.local")
            logger.info("  Password: %s", default_password)
            logger.info("  CHANGE THIS PASSWORD IMMEDIATELY!")
            logger.info("=" * 50)

        # Track schema version
        conn.execute(
            "INSERT INTO crm_metadata (key, value) VALUES (?, ?) ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value",
            ("schema_version", str(SCHEMA_VERSION)),
        )

    logger.info("CRM database initialized (v%d) — PostgreSQL", SCHEMA_VERSION)


def dict_from_row(row):
    """Convert row to dict."""
    if row is None:
        return None
    return dict(row)


def rows_to_dicts(rows):
    """Convert list of rows to list of dicts."""
    return [dict(r) for r in rows]


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    init_db()
    print("Database initialized:", DATABASE_URL.split('@')[1] if '@' in DATABASE_URL else DATABASE_URL)
