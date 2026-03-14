-- ================================================================
-- Hermes CRM — Phase 1 Migration
-- ================================================================

-- 1.1 Roles & Permissions
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

-- Add new columns to users
ALTER TABLE users ADD COLUMN role_id INTEGER REFERENCES roles(id);
ALTER TABLE users ADD COLUMN department TEXT DEFAULT '';
ALTER TABLE users ADD COLUMN phone TEXT DEFAULT '';
ALTER TABLE users ADD COLUMN avatar_url TEXT DEFAULT '';
ALTER TABLE users ADD COLUMN last_login TEXT;
ALTER TABLE users ADD COLUMN login_count INTEGER DEFAULT 0;
ALTER TABLE users ADD COLUMN telegram_id TEXT DEFAULT '';
ALTER TABLE users ADD COLUMN calendar_token TEXT DEFAULT '';

-- Insert default roles
INSERT OR IGNORE INTO roles (name, display_name, display_name_az, display_name_ru, description, permissions, is_system) VALUES
('admin', 'Administrator', 'Administrator', 'Администратор', 'Full system access',
 '{"leads":"crud","deals":"crud","contacts":"crud","contracts":"crud","tasks":"crud","reports":"crud","cost_model":"crud","users":"crud","settings":"crud","offers":"crud"}', 1),
('sales_manager', 'Sales Manager', 'Satış Meneceri', 'Менеджер по продажам', 'Manage sales team and deals',
 '{"leads":"crud","deals":"crud","contacts":"crud","contracts":"r","tasks":"crud","reports":"r","cost_model":"r","users":"","settings":"","offers":"crud"}', 1),
('sales_rep', 'Sales Representative', 'Satış Nümayəndəsi', 'Торговый представитель', 'Handle leads and deals',
 '{"leads":"cru","deals":"cru","contacts":"cru","contracts":"r","tasks":"cru","reports":"r","cost_model":"","users":"","settings":"","offers":"cru"}', 1),
('marketing', 'Marketing', 'Marketinq', 'Маркетинг', 'Manage campaigns and contacts',
 '{"leads":"cr","deals":"r","contacts":"crud","contracts":"r","tasks":"cru","reports":"crud","cost_model":"","users":"","settings":"","offers":"r"}', 1),
('support_agent', 'Support Agent', 'Dəstək Agenti', 'Агент поддержки', 'Handle support tasks',
 '{"leads":"r","deals":"r","contacts":"cru","contracts":"r","tasks":"crud","reports":"r","cost_model":"","users":"","settings":"","offers":"r"}', 1),
('viewer', 'Viewer', 'İzləyici', 'Наблюдатель', 'Read-only access',
 '{"leads":"r","deals":"r","contacts":"r","contracts":"r","tasks":"r","reports":"r","cost_model":"r","users":"","settings":"","offers":"r"}', 1);

-- Map existing users: admin role → role_id=1
UPDATE users SET role_id = 1 WHERE role = 'admin' AND role_id IS NULL;
UPDATE users SET role_id = 2 WHERE role = 'manager' AND role_id IS NULL;
UPDATE users SET role_id = 6 WHERE role = 'viewer' AND role_id IS NULL;

-- 1.2 Audit Trail Enhancement
ALTER TABLE audit_log ADD COLUMN old_value TEXT DEFAULT '';
ALTER TABLE audit_log ADD COLUMN new_value TEXT DEFAULT '';
ALTER TABLE audit_log ADD COLUMN entity_name TEXT DEFAULT '';
ALTER TABLE audit_log ADD COLUMN user_agent TEXT DEFAULT '';
ALTER TABLE audit_log ADD COLUMN session_id TEXT DEFAULT '';

-- 1.3 Pipeline Stages Table
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

INSERT OR IGNORE INTO pipeline_stages (name, display_name, display_name_az, display_name_ru, color, probability, sort_order, is_won, is_lost) VALUES
('LEAD', 'Lead', 'Potensial', 'Лид', '#6366f1', 10, 1, 0, 0),
('QUALIFIED', 'Qualified', 'Təsdiqlənmiş', 'Квалифицирован', '#3b82f6', 25, 2, 0, 0),
('PROPOSAL', 'Proposal', 'Təklif', 'Предложение', '#f59e0b', 50, 3, 0, 0),
('NEGOTIATION', 'Negotiation', 'Danışıq', 'Переговоры', '#f97316', 75, 4, 0, 0),
('WON', 'Won', 'Qazanılıb', 'Выиграно', '#22c55e', 100, 5, 1, 0),
('LOST', 'Lost', 'İtirildi', 'Проиграно', '#ef4444', 0, 6, 0, 1);

-- 1.4 Lead Scoring
ALTER TABLE leads ADD COLUMN score INTEGER DEFAULT 0;
ALTER TABLE leads ADD COLUMN score_details TEXT DEFAULT '{}';
ALTER TABLE leads ADD COLUMN last_scored_at TEXT;

CREATE TABLE IF NOT EXISTS lead_scoring_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    field TEXT NOT NULL,
    condition TEXT NOT NULL,
    value TEXT NOT NULL,
    points INTEGER DEFAULT 0,
    is_active INTEGER DEFAULT 1,
    created_at TEXT DEFAULT (datetime('now'))
);

INSERT OR IGNORE INTO lead_scoring_rules (field, condition, value, points) VALUES
('source', 'equals', 'referral', 30),
('source', 'equals', 'website', 20),
('source', 'equals', 'cold_call', 5),
('priority', 'equals', 'high', 25),
('priority', 'equals', 'medium', 10),
('email', 'not_empty', '', 10),
('phone', 'not_empty', '', 10),
('status', 'equals', 'qualified', 30);

-- 1.5 Notifications
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

-- 1.3 Two-Factor Authentication (2FA)
ALTER TABLE users ADD COLUMN totp_secret TEXT DEFAULT '';
ALTER TABLE users ADD COLUMN totp_enabled INTEGER DEFAULT 0;
ALTER TABLE users ADD COLUMN backup_codes TEXT DEFAULT '[]';

-- 2.3 Lead Assignment Rules
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

-- 2.4 Opportunity (Deal) Teams
CREATE TABLE IF NOT EXISTS deal_team_members (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    deal_id INTEGER REFERENCES deals(id),
    user_id INTEGER REFERENCES users(id),
    role TEXT DEFAULT 'member',
    added_at TEXT DEFAULT (datetime('now')),
    UNIQUE(deal_id, user_id)
);
