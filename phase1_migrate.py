#!/usr/bin/env python3
"""Phase 1 database migration - safe for re-running"""
import sqlite3, json, sys

DB_PATH = sys.argv[1] if len(sys.argv) > 1 else '/opt/hermes_crm/crm.db'
conn = sqlite3.connect(DB_PATH)
c = conn.cursor()

def safe_exec(sql, params=None):
    try:
        if params:
            c.execute(sql, params)
        else:
            c.execute(sql)
        return True
    except sqlite3.OperationalError as e:
        if 'duplicate column' in str(e) or 'already exists' in str(e):
            return False
        print(f'  WARN: {e}')
        return False

print("=== Phase 1 Migration ===")

# 1. Roles table
print("[1/6] Creating roles table...")
c.executescript("""
CREATE TABLE IF NOT EXISTS roles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    display_name TEXT NOT NULL,
    display_name_az TEXT DEFAULT '',
    display_name_ru TEXT DEFAULT '',
    description TEXT DEFAULT '',
    permissions TEXT DEFAULT '{}',
    is_system INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS user_permissions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER REFERENCES users(id),
    module TEXT NOT NULL,
    action TEXT NOT NULL,
    UNIQUE(user_id, module, action)
);
""")

# Add user columns
for col in [
    "role_id INTEGER REFERENCES roles(id)",
    "department TEXT DEFAULT ''",
    "phone TEXT DEFAULT ''",
    "avatar_url TEXT DEFAULT ''",
    "last_login TEXT",
    "login_count INTEGER DEFAULT 0",
]:
    colname = col.split()[0]
    safe_exec(f"ALTER TABLE users ADD COLUMN {col}")

# Insert default roles
roles_data = [
    ('admin', 'Administrator', 'Administrator', 'Администратор', 'Full system access',
     '{"leads":"crud","deals":"crud","contacts":"crud","contracts":"crud","tasks":"crud","reports":"crud","cost_model":"crud","users":"crud","settings":"crud","offers":"crud"}', 1),
    ('sales_manager', 'Sales Manager', 'Satış Meneceri', 'Менеджер по продажам', 'Manage sales team',
     '{"leads":"crud","deals":"crud","contacts":"crud","contracts":"r","tasks":"crud","reports":"r","cost_model":"r","users":"","settings":"","offers":"crud"}', 1),
    ('sales_rep', 'Sales Representative', 'Satış Nümayəndəsi', 'Торговый представитель', 'Handle leads and deals',
     '{"leads":"cru","deals":"cru","contacts":"cru","contracts":"r","tasks":"cru","reports":"r","cost_model":"","users":"","settings":"","offers":"cru"}', 1),
    ('marketing', 'Marketing', 'Marketinq', 'Маркетинг', 'Manage campaigns and contacts',
     '{"leads":"cr","deals":"r","contacts":"crud","contracts":"r","tasks":"cru","reports":"crud","cost_model":"","users":"","settings":"","offers":"r"}', 1),
    ('support_agent', 'Support Agent', 'Dəstək Agenti', 'Агент поддержки', 'Handle support tasks',
     '{"leads":"r","deals":"r","contacts":"cru","contracts":"r","tasks":"crud","reports":"r","cost_model":"","users":"","settings":"","offers":"r"}', 1),
    ('viewer', 'Viewer', 'İzləyici', 'Наблюдатель', 'Read-only access',
     '{"leads":"r","deals":"r","contacts":"r","contracts":"r","tasks":"r","reports":"r","cost_model":"r","users":"","settings":"","offers":"r"}', 1),
]
for r in roles_data:
    try:
        c.execute("INSERT INTO roles (name,display_name,display_name_az,display_name_ru,description,permissions,is_system) VALUES (?,?,?,?,?,?,?)", r)
    except sqlite3.IntegrityError:
        pass

# Map existing users
c.execute("UPDATE users SET role_id=1 WHERE role='admin' AND role_id IS NULL")
c.execute("UPDATE users SET role_id=2 WHERE role='manager' AND role_id IS NULL")
c.execute("UPDATE users SET role_id=6 WHERE role='viewer' AND role_id IS NULL")
conn.commit()
print(f"  Roles: {c.execute('SELECT count(*) FROM roles').fetchone()[0]}")

# 2. Audit trail enhancement
print("[2/6] Enhancing audit_log...")
for col in ["old_value TEXT DEFAULT ''", "new_value TEXT DEFAULT ''", "entity_name TEXT DEFAULT ''", "user_agent TEXT DEFAULT ''", "session_id TEXT DEFAULT ''"]:
    safe_exec(f"ALTER TABLE audit_log ADD COLUMN {col}")
conn.commit()

# 3. Pipeline stages
print("[3/6] Creating pipeline_stages...")
c.executescript("""
CREATE TABLE IF NOT EXISTS pipeline_stages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    display_name TEXT NOT NULL,
    display_name_az TEXT DEFAULT '',
    display_name_ru TEXT DEFAULT '',
    color TEXT DEFAULT '#6366f1',
    probability INTEGER DEFAULT 0,
    sort_order INTEGER DEFAULT 0,
    is_won INTEGER DEFAULT 0,
    is_lost INTEGER DEFAULT 0,
    is_active INTEGER DEFAULT 1,
    created_at TEXT DEFAULT (datetime('now'))
);
""")
stages = [
    ('LEAD', 'Lead', 'Potensial', 'Лид', '#6366f1', 10, 1, 0, 0),
    ('QUALIFIED', 'Qualified', 'Təsdiqlənmiş', 'Квалифицирован', '#3b82f6', 25, 2, 0, 0),
    ('PROPOSAL', 'Proposal', 'Təklif', 'Предложение', '#f59e0b', 50, 3, 0, 0),
    ('NEGOTIATION', 'Negotiation', 'Danışıq', 'Переговоры', '#f97316', 75, 4, 0, 0),
    ('WON', 'Won', 'Qazanılıb', 'Выиграно', '#22c55e', 100, 5, 1, 0),
    ('LOST', 'Lost', 'İtirildi', 'Проиграно', '#ef4444', 0, 6, 0, 1),
]
for s in stages:
    try:
        c.execute("INSERT INTO pipeline_stages (name,display_name,display_name_az,display_name_ru,color,probability,sort_order,is_won,is_lost) VALUES (?,?,?,?,?,?,?,?,?)", s)
    except: pass
conn.commit()
print(f"  Stages: {c.execute('SELECT count(*) FROM pipeline_stages').fetchone()[0]}")

# 4. Lead scoring
print("[4/6] Setting up lead scoring...")
for col in ["score INTEGER DEFAULT 0", "score_details TEXT DEFAULT '{}'", "last_scored_at TEXT"]:
    safe_exec(f"ALTER TABLE leads ADD COLUMN {col}")

c.executescript("""
CREATE TABLE IF NOT EXISTS lead_scoring_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    field TEXT NOT NULL,
    condition TEXT NOT NULL,
    value TEXT NOT NULL,
    points INTEGER DEFAULT 0,
    is_active INTEGER DEFAULT 1,
    created_at TEXT DEFAULT (datetime('now'))
);
""")
scoring_rules = [
    ('source', 'equals', 'referral', 30),
    ('source', 'equals', 'website', 20),
    ('source', 'equals', 'cold_call', 5),
    ('priority', 'equals', 'high', 25),
    ('priority', 'equals', 'medium', 10),
    ('email', 'not_empty', '', 10),
    ('phone', 'not_empty', '', 10),
    ('status', 'equals', 'qualified', 30),
]
existing = c.execute("SELECT count(*) FROM lead_scoring_rules").fetchone()[0]
if existing == 0:
    for r in scoring_rules:
        c.execute("INSERT INTO lead_scoring_rules (field,condition,value,points) VALUES (?,?,?,?)", r)
conn.commit()
print(f"  Rules: {c.execute('SELECT count(*) FROM lead_scoring_rules').fetchone()[0]}")

# 5. Notifications
print("[5/6] Creating notifications tables...")
c.executescript("""
CREATE TABLE IF NOT EXISTS notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER REFERENCES users(id),
    type TEXT NOT NULL,
    title TEXT NOT NULL,
    message TEXT DEFAULT '',
    entity_type TEXT,
    entity_id INTEGER,
    is_read INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_notifications_user ON notifications(user_id);
CREATE INDEX IF NOT EXISTS idx_notifications_read ON notifications(user_id, is_read);
CREATE TABLE IF NOT EXISTS notification_preferences (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER REFERENCES users(id),
    event_type TEXT NOT NULL,
    channel_web INTEGER DEFAULT 1,
    channel_email INTEGER DEFAULT 0,
    channel_telegram INTEGER DEFAULT 0,
    UNIQUE(user_id, event_type)
);
""")
conn.commit()

# 6. Verify
print("[6/6] Verification...")
tables = [t[0] for t in c.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name").fetchall()]
print(f"  Total tables: {len(tables)}")
print(f"  Roles: {c.execute('SELECT count(*) FROM roles').fetchone()[0]}")
print(f"  Stages: {c.execute('SELECT count(*) FROM pipeline_stages').fetchone()[0]}")
print(f"  Scoring rules: {c.execute('SELECT count(*) FROM lead_scoring_rules').fetchone()[0]}")
print("=== Migration Complete ===")

conn.close()
