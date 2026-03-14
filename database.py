"""
CRM Database — SQLite setup & schema
=====================================
"""

import sqlite3
import os
import logging
from contextlib import contextmanager

logger = logging.getLogger(__name__)

DB_PATH = os.getenv("CRM_DB_PATH", "crm.db")

SCHEMA_VERSION = 1

SCHEMA_SQL = """
-- Metadata table for tracking schema version
CREATE TABLE IF NOT EXISTS crm_metadata (
    key   TEXT PRIMARY KEY,
    value TEXT
);

-- Users
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL DEFAULT '',
    password_hash TEXT NOT NULL,
    full_name TEXT DEFAULT '',
    role TEXT DEFAULT 'manager',
    is_active INTEGER DEFAULT 1,
    created_at TEXT DEFAULT (datetime('now')),
    role_id INTEGER,
    department TEXT DEFAULT '',
    phone TEXT DEFAULT '',
    avatar_url TEXT DEFAULT '',
    last_login TEXT,
    login_count INTEGER DEFAULT 0,
    totp_secret TEXT DEFAULT '',
    totp_enabled INTEGER DEFAULT 0,
    backup_codes TEXT DEFAULT '[]'
);
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);

-- Companies
CREATE TABLE IF NOT EXISTS companies (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    name            TEXT NOT NULL,
    domain          TEXT UNIQUE,
    industry        TEXT DEFAULT '',
    website         TEXT DEFAULT '',
    notes           TEXT DEFAULT '',
    category        TEXT DEFAULT '',
    contacts_count  INTEGER DEFAULT 0,
    created_at      TEXT DEFAULT (datetime('now')),
    last_activity   TEXT DEFAULT (datetime('now'))
);

-- Contacts
CREATE TABLE IF NOT EXISTS contacts (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
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
    last_contact    TEXT,
    created_at      TEXT DEFAULT (datetime('now')),
    updated_at      TEXT DEFAULT (datetime('now'))
);

-- Deals / Pipeline
CREATE TABLE IF NOT EXISTS deals (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
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
    created_at      TEXT DEFAULT (datetime('now')),
    updated_at      TEXT DEFAULT (datetime('now'))
);

-- Activities (emails, calls, notes, tasks)
CREATE TABLE IF NOT EXISTS activities (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    contact_id      INTEGER REFERENCES contacts(id),
    deal_id         INTEGER REFERENCES deals(id),
    activity_type   TEXT DEFAULT 'NOTE',
    direction       TEXT DEFAULT 'INBOUND',
    subject         TEXT DEFAULT '',
    content         TEXT DEFAULT '',
    metadata        TEXT DEFAULT '{}',
    status          TEXT DEFAULT 'completed',
    timestamp       TEXT DEFAULT (datetime('now'))
);

-- Email sync tracking (avoid re-processing)
-- Removed: email_sync_log no longer needed
-- CREATE TABLE IF NOT EXISTS email_sync_log (
--     id              INTEGER PRIMARY KEY AUTOINCREMENT,
--     message_id      TEXT UNIQUE,
--     from_addr       TEXT,
--     subject         TEXT,
--     synced_at       TEXT DEFAULT (datetime('now'))
-- );

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_contacts_email ON contacts(email);
CREATE INDEX IF NOT EXISTS idx_contacts_company ON contacts(company_id);
CREATE INDEX IF NOT EXISTS idx_deals_stage ON deals(stage);
CREATE INDEX IF NOT EXISTS idx_deals_company ON deals(company_id);
CREATE INDEX IF NOT EXISTS idx_deals_contact ON deals(contact_id);
CREATE INDEX IF NOT EXISTS idx_activities_contact ON activities(contact_id);
CREATE INDEX IF NOT EXISTS idx_activities_deal ON activities(deal_id);
CREATE INDEX IF NOT EXISTS idx_activities_type ON activities(activity_type);
-- CREATE INDEX IF NOT EXISTS idx_email_sync_msgid ON email_sync_log(message_id);

-- Audit log
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    action TEXT NOT NULL,
    entity_type TEXT,
    entity_id INTEGER,
    details TEXT DEFAULT '',
    ip_address TEXT DEFAULT '',
    created_at TEXT DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_audit_log_user ON audit_log(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_action ON audit_log(action);

-- Commercial Offers
CREATE TABLE IF NOT EXISTS offers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    offer_number TEXT NOT NULL,
    offer_type TEXT DEFAULT 'services',  -- 'services' or 'equipment'
    currency TEXT DEFAULT 'AZN',          -- 'AZN' or 'USD'
    show_vat INTEGER DEFAULT 0,
    vat_pct REAL DEFAULT 18,
    view_mode TEXT DEFAULT 'detailed',    -- 'detailed' or 'category'
    company_id INTEGER REFERENCES companies(id),
    client_name TEXT DEFAULT '',
    client_voen TEXT DEFAULT '',
    client_contact TEXT DEFAULT '',
    client_contract TEXT DEFAULT '',
    notes TEXT DEFAULT '',
    status TEXT DEFAULT 'draft',          -- 'draft', 'sent', 'accepted', 'rejected'
    items TEXT DEFAULT '[]',              -- JSON array of line items
    valid_until TEXT DEFAULT '',
    created_by INTEGER REFERENCES users(id),
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_offers_status ON offers(status);
CREATE INDEX IF NOT EXISTS idx_offers_company ON offers(company_id);

-- Price changes (pending approval workflow)
CREATE TABLE IF NOT EXISTS price_changes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    company_code TEXT NOT NULL,
    status TEXT DEFAULT 'pending',  -- 'pending', 'approved', 'rejected'
    old_prices TEXT DEFAULT '{}',   -- JSON snapshot of old pricing
    new_prices TEXT DEFAULT '{}',   -- JSON with changed pricing
    notes TEXT DEFAULT '',
    effective_date TEXT DEFAULT NULL, -- date from which new prices apply (YYYY-MM-DD)
    created_by INTEGER REFERENCES users(id),
    approved_by INTEGER REFERENCES users(id),
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_price_changes_status ON price_changes(status);
CREATE INDEX IF NOT EXISTS idx_price_changes_company ON price_changes(company_code);

-- ─── Cost Model Module ────────────────────────────────────────

-- Global pricing parameters (one row)
CREATE TABLE IF NOT EXISTS pricing_parameters (
    id INTEGER PRIMARY KEY DEFAULT 1,
    total_users INTEGER DEFAULT 4500,
    total_users_manual INTEGER DEFAULT 0,  -- 1 = override auto-calc
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
);

-- Overhead costs (one row per category)
CREATE TABLE IF NOT EXISTS overhead_costs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    category TEXT NOT NULL,          -- e.g. 'cloud_servers'
    label TEXT NOT NULL,             -- display name
    amount REAL DEFAULT 0,           -- AZN/month (raw input)
    is_annual INTEGER DEFAULT 0,     -- 1 = divide by 12
    has_vat INTEGER DEFAULT 0,       -- 1 = multiply by (1+vat_rate)
    sort_order INTEGER DEFAULT 0,
    notes TEXT DEFAULT ''
);

-- Employees / staffing table
CREATE TABLE IF NOT EXISTS cost_employees (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    department TEXT NOT NULL,        -- 'IT','InfoSec','ERP','GRC','PM','HelpDesk','BackOffice'
    position TEXT NOT NULL,
    count INTEGER DEFAULT 1,
    net_salary REAL DEFAULT 0,       -- AZN/month per person
    gross_salary REAL DEFAULT 0,     -- net / (1 - income_tax_rate) — calculated
    super_gross REAL DEFAULT 0,      -- gross * (1 + social_rate) — calculated
    in_overhead INTEGER DEFAULT 0,   -- 1 = goes to overhead not direct cost (GRC)
    notes TEXT DEFAULT ''
);

-- Client services (revenue breakdown per client per service)
CREATE TABLE IF NOT EXISTS client_services (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    company_id INTEGER REFERENCES companies(id) ON DELETE CASCADE,
    company_code TEXT NOT NULL,      -- matches pricing_data.json key / CRM code
    service_type TEXT NOT NULL,      -- 'permanent_it','infosec','erp','grc','projects','helpdesk'
    monthly_revenue REAL DEFAULT 0,
    is_active INTEGER DEFAULT 1,
    notes TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_client_services_company ON client_services(company_id);
CREATE INDEX IF NOT EXISTS idx_client_services_type ON client_services(service_type);

-- Leads (potential customers before conversion)
CREATE TABLE IF NOT EXISTS leads (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    company_name TEXT NOT NULL,
    contact_name TEXT,
    email TEXT,
    phone TEXT,
    source TEXT DEFAULT '',              -- website, linkedin, referral, cold_call, exhibition, other
    status TEXT DEFAULT 'new',           -- new, contacted, qualified, unqualified, converted
    priority TEXT DEFAULT 'medium',      -- low, medium, high
    estimated_value REAL DEFAULT 0,
    estimated_users INTEGER DEFAULT 0,
    industry TEXT DEFAULT '',
    website TEXT DEFAULT '',
    notes TEXT DEFAULT '',
    assigned_to INTEGER REFERENCES users(id),
    converted_at TEXT,
    converted_company_id INTEGER REFERENCES companies(id),
    converted_contact_id INTEGER REFERENCES contacts(id),
    converted_deal_id INTEGER REFERENCES deals(id),
    created_by INTEGER REFERENCES users(id),
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now'))
);

-- Tasks / Calendar
CREATE TABLE IF NOT EXISTS tasks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    description TEXT DEFAULT '',
    status TEXT DEFAULT 'todo',             -- todo, in_progress, done, cancelled
    priority TEXT DEFAULT 'medium',         -- low, medium, high, urgent
    due_date TEXT,                          -- YYYY-MM-DD
    due_time TEXT,                          -- HH:MM (optional)
    reminder_at TEXT,                       -- datetime for reminder
    category TEXT DEFAULT 'general',        -- general, call, meeting, email, follow_up, deadline
    company_id INTEGER REFERENCES companies(id),
    contact_id INTEGER REFERENCES contacts(id),
    deal_id INTEGER REFERENCES deals(id),
    lead_id INTEGER REFERENCES leads(id),
    assigned_to INTEGER REFERENCES users(id),
    created_by INTEGER REFERENCES users(id),
    completed_at TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_tasks_status ON tasks(status);
CREATE INDEX IF NOT EXISTS idx_tasks_due ON tasks(due_date);
CREATE INDEX IF NOT EXISTS idx_tasks_assigned ON tasks(assigned_to);
CREATE INDEX IF NOT EXISTS idx_tasks_company ON tasks(company_id);
CREATE INDEX IF NOT EXISTS idx_tasks_deal ON tasks(deal_id);

-- Contracts
CREATE TABLE IF NOT EXISTS contracts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
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
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    table_name TEXT NOT NULL,
    record_id INTEGER,
    action TEXT NOT NULL,            -- 'update','insert','delete'
    old_value TEXT,
    new_value TEXT,
    changed_by INTEGER REFERENCES users(id),
    changed_at TEXT DEFAULT (datetime('now'))
);

-- Lead Assignment Rules
CREATE TABLE IF NOT EXISTS lead_assignment_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    conditions TEXT DEFAULT '{}',
    assign_to INTEGER REFERENCES users(id),
    assign_method TEXT DEFAULT 'direct',
    priority INTEGER DEFAULT 0,
    is_active INTEGER DEFAULT 1,
    created_at TEXT DEFAULT (datetime('now'))
);

-- Deal Team Members
CREATE TABLE IF NOT EXISTS deal_team_members (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    deal_id INTEGER REFERENCES deals(id),
    user_id INTEGER REFERENCES users(id),
    role TEXT DEFAULT 'member',
    added_at TEXT DEFAULT (datetime('now')),
    UNIQUE(deal_id, user_id)
);
"""


def get_db_path():
    """Return absolute path to the database."""
    if os.path.isabs(DB_PATH):
        return DB_PATH
    base = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base, DB_PATH)


def get_connection():
    """Create a new SQLite connection with WAL mode."""
    db_path = get_db_path()
    conn = sqlite3.connect(db_path, timeout=10)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.row_factory = sqlite3.Row
    return conn


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


def init_db():
    """Initialize database schema."""
    db_path = get_db_path()
    logger.info("Initializing CRM database at %s", db_path)

    with get_db() as conn:
        conn.executescript(SCHEMA_SQL)

        # Migrations — add missing columns safely
        try:
            conn.execute("SELECT category FROM companies LIMIT 1")
        except Exception:
            conn.execute("ALTER TABLE companies ADD COLUMN category TEXT DEFAULT ''")
            logger.info("Migration: added 'category' column to companies")

        # Migration: add user fields to deals table
        try:
            conn.execute("SELECT assigned_to FROM deals LIMIT 1")
        except Exception:
            conn.execute("ALTER TABLE deals ADD COLUMN assigned_to INTEGER DEFAULT NULL REFERENCES users(id)")
            logger.info("Migration: added 'assigned_to' column to deals")

        try:
            conn.execute("SELECT created_by FROM deals LIMIT 1")
        except Exception:
            conn.execute("ALTER TABLE deals ADD COLUMN created_by INTEGER DEFAULT NULL REFERENCES users(id)")
            logger.info("Migration: added 'created_by' column to deals")

        # Migration: add email column to users
        try:
            conn.execute("SELECT email FROM users LIMIT 1")
        except Exception:
            conn.execute("ALTER TABLE users ADD COLUMN email TEXT DEFAULT ''")
            # Set email = username for existing users as fallback
            conn.execute("UPDATE users SET email = username WHERE email = '' OR email IS NULL")
            logger.info("Migration: added 'email' column to users")

        # Migration: add effective_date to price_changes
        try:
            conn.execute("SELECT effective_date FROM price_changes LIMIT 1")
        except Exception:
            conn.execute("ALTER TABLE price_changes ADD COLUMN effective_date TEXT DEFAULT NULL")
            logger.info("Migration: added 'effective_date' column to price_changes")

        # Migration: add user_count to companies
        try:
            conn.execute("SELECT user_count FROM companies LIMIT 1")
        except Exception:
            conn.execute("ALTER TABLE companies ADD COLUMN user_count INTEGER DEFAULT 0")
            logger.info("Migration: added 'user_count' column to companies")

        # Migration: add cost_code to companies (short code matching pricing_data.json)
        try:
            conn.execute("SELECT cost_code FROM companies LIMIT 1")
        except Exception:
            conn.execute("ALTER TABLE companies ADD COLUMN cost_code TEXT DEFAULT ''")
            logger.info("Migration: added 'cost_code' column to companies")

        # Migration: add calendar_token to users (for ICS feed)
        try:
            conn.execute("SELECT calendar_token FROM users LIMIT 1")
        except Exception:
            conn.execute("ALTER TABLE users ADD COLUMN calendar_token TEXT DEFAULT NULL")
            logger.info("Migration: added 'calendar_token' column to users")

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
            # gross = net / (1-0.14), super_gross = gross * 1.175
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
            # Generate a random initial password instead of hardcoded default
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

        # Migration: create token_blacklist table for persistent logout
        conn.execute("""
            CREATE TABLE IF NOT EXISTS token_blacklist (
                token TEXT PRIMARY KEY,
                blacklisted_at TEXT DEFAULT (datetime('now')),
                expires_at TEXT
            )
        """)

        # Migration: create indexes for contracts table
        conn.execute("CREATE INDEX IF NOT EXISTS idx_contracts_counterparty ON contracts(counterparty)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_contracts_status ON contracts(status)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_contracts_end_date ON contracts(end_date)")

        # Migration: create offers table if missing
        try:
            conn.execute("SELECT id FROM offers LIMIT 1")
        except Exception:
            logger.info("Migration: creating offers table")
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS offers (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
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
                    created_at TEXT DEFAULT (datetime('now')),
                    updated_at TEXT DEFAULT (datetime('now'))
                );
                CREATE INDEX IF NOT EXISTS idx_offers_status ON offers(status);
                CREATE INDEX IF NOT EXISTS idx_offers_company ON offers(company_id);
            """)

        # Migration: create leads table if missing
        try:
            conn.execute("SELECT id FROM leads LIMIT 1")
        except Exception:
            logger.info("Migration: creating leads table")
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS leads (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
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
                    converted_at TEXT,
                    converted_company_id INTEGER REFERENCES companies(id),
                    converted_contact_id INTEGER REFERENCES contacts(id),
                    converted_deal_id INTEGER REFERENCES deals(id),
                    created_by INTEGER REFERENCES users(id),
                    created_at TEXT DEFAULT (datetime('now')),
                    updated_at TEXT DEFAULT (datetime('now'))
                );
                CREATE INDEX IF NOT EXISTS idx_leads_status ON leads(status);
                CREATE INDEX IF NOT EXISTS idx_leads_source ON leads(source);
                CREATE INDEX IF NOT EXISTS idx_leads_assigned ON leads(assigned_to);
            """)

        # Migration: create tasks table if missing
        try:
            conn.execute("SELECT id FROM tasks LIMIT 1")
        except Exception:
            logger.info("Migration: creating tasks table")
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS tasks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title TEXT NOT NULL,
                    description TEXT DEFAULT '',
                    status TEXT DEFAULT 'todo',
                    priority TEXT DEFAULT 'medium',
                    due_date TEXT,
                    due_time TEXT,
                    reminder_at TEXT,
                    category TEXT DEFAULT 'general',
                    company_id INTEGER REFERENCES companies(id),
                    contact_id INTEGER REFERENCES contacts(id),
                    deal_id INTEGER REFERENCES deals(id),
                    lead_id INTEGER REFERENCES leads(id),
                    assigned_to INTEGER REFERENCES users(id),
                    created_by INTEGER REFERENCES users(id),
                    completed_at TEXT,
                    created_at TEXT DEFAULT (datetime('now')),
                    updated_at TEXT DEFAULT (datetime('now'))
                );
                CREATE INDEX IF NOT EXISTS idx_tasks_status ON tasks(status);
                CREATE INDEX IF NOT EXISTS idx_tasks_due ON tasks(due_date);
                CREATE INDEX IF NOT EXISTS idx_tasks_assigned ON tasks(assigned_to);
                CREATE INDEX IF NOT EXISTS idx_tasks_company ON tasks(company_id);
                CREATE INDEX IF NOT EXISTS idx_tasks_deal ON tasks(deal_id);
            """)

        # Track schema version
        conn.execute(
            "INSERT OR REPLACE INTO crm_metadata (key, value) VALUES (?, ?)",
            ("schema_version", str(SCHEMA_VERSION)),
        )

    logger.info("CRM database initialized (v%d)", SCHEMA_VERSION)


def dict_from_row(row):
    """Convert sqlite3.Row to dict."""
    if row is None:
        return None
    return dict(row)


def rows_to_dicts(rows):
    """Convert list of sqlite3.Row to list of dicts."""
    return [dict(r) for r in rows]


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    init_db()
    print("Database created at:", get_db_path())
