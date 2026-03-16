#!/usr/bin/env python3
"""
SQLite → PostgreSQL Data Migration Script
==========================================
Run this on the server after PostgreSQL is set up and before switching over.

Usage:
    python3 migrate_sqlite_to_pg.py [--sqlite-path /opt/hermes_crm/crm.db]

Steps:
1. Reads all data from SQLite
2. Creates PostgreSQL schema via database.py init_db()
3. Inserts all data preserving IDs
4. Resets PostgreSQL sequences to correct values
"""

import os
import sys
import sqlite3
import logging

# Ensure we can import database module
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import psycopg2
import psycopg2.extras

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
logger = logging.getLogger(__name__)

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://hermes:hermes@localhost:5432/hermes_crm")
SQLITE_PATH = os.getenv("SQLITE_PATH", os.path.join(os.path.dirname(os.path.abspath(__file__)), "crm.db"))

# Tables to migrate in dependency order (parents first)
TABLES_ORDER = [
    "crm_metadata",
    "users",
    "companies",
    "contacts",
    "deals",
    "activities",
    "audit_log",
    "offers",
    "price_changes",
    "pricing_parameters",
    "overhead_costs",
    "cost_employees",
    "client_services",
    "leads",
    "tasks",
    "contracts",
    "cost_model_log",
    "lead_assignment_rules",
    "deal_team_members",
    "token_blacklist",
    # Dynamic tables created in api.py
    "email_log",
    "tickets",
    "ticket_messages",
    "kb_articles",
    "sla_policies",
    "campaigns",
    "campaign_contacts",
    "campaign_deals",
    "contact_segments",
    "workflow_rules",
    "workflow_logs",
    "nurture_sequences",
    "nurture_steps",
    "nurture_enrollments",
    "lead_scoring_rules",
    "notification_preferences",
    "notification_log",
    "portal_users",
    "ai_chat_sessions",
    "ai_interaction_logs",
    "custom_fields",
    "documents",
    "knowledge_base_embeddings",
]


def get_sqlite_tables(sqlite_conn):
    """Get list of actual tables in SQLite database."""
    cursor = sqlite_conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
    )
    return [row[0] for row in cursor.fetchall()]


def get_table_columns(sqlite_conn, table):
    """Get column names for a SQLite table."""
    cursor = sqlite_conn.execute(f"PRAGMA table_info({table})")
    return [row[1] for row in cursor.fetchall()]


def migrate_table(sqlite_conn, pg_conn, table, pg_tables):
    """Migrate a single table from SQLite to PostgreSQL."""
    if table not in pg_tables:
        logger.warning("  Table '%s' does not exist in PostgreSQL — skipping", table)
        return 0

    columns = get_table_columns(sqlite_conn, table)

    # Check which columns exist in PostgreSQL
    pg_cursor = pg_conn.cursor()
    pg_cursor.execute(
        "SELECT column_name FROM information_schema.columns WHERE table_name = %s",
        (table,)
    )
    pg_columns = {row[0] for row in pg_cursor.fetchall()}

    # Only migrate columns that exist in both
    common_columns = [c for c in columns if c in pg_columns]
    if not common_columns:
        logger.warning("  No common columns for table '%s' — skipping", table)
        return 0

    # Read all data from SQLite
    cols_str = ", ".join(common_columns)
    rows = sqlite_conn.execute(f"SELECT {cols_str} FROM {table}").fetchall()

    if not rows:
        logger.info("  Table '%s': 0 rows (empty)", table)
        return 0

    # Build INSERT statement with ON CONFLICT DO NOTHING
    placeholders = ", ".join(["%s"] * len(common_columns))
    insert_sql = f"INSERT INTO {table} ({cols_str}) VALUES ({placeholders}) ON CONFLICT DO NOTHING"

    # Insert in batches
    batch_size = 500
    total = 0
    for i in range(0, len(rows), batch_size):
        batch = rows[i:i + batch_size]
        for row in batch:
            values = tuple(row)
            try:
                pg_cursor.execute(insert_sql, values)
                total += 1
            except Exception as e:
                pg_conn.rollback()
                logger.warning("  Row insert failed in '%s': %s — values: %s", table, e, str(values)[:200])
                continue
        pg_conn.commit()

    logger.info("  Table '%s': migrated %d/%d rows (%d columns)", table, total, len(rows), len(common_columns))
    return total


def reset_sequences(pg_conn):
    """Reset PostgreSQL sequences to max(id) + 1 for all SERIAL columns."""
    pg_cursor = pg_conn.cursor()

    # Find all sequences
    pg_cursor.execute("""
        SELECT t.relname as table_name, a.attname as column_name, s.relname as seq_name
        FROM pg_class s
        JOIN pg_depend d ON d.objid = s.oid
        JOIN pg_class t ON d.refobjid = t.oid
        JOIN pg_attribute a ON (a.attrelid = t.oid AND a.attnum = d.refobjsubid)
        WHERE s.relkind = 'S'
    """)
    sequences = pg_cursor.fetchall()

    for table_name, column_name, seq_name in sequences:
        try:
            pg_cursor.execute(f"SELECT COALESCE(MAX({column_name}), 0) FROM {table_name}")
            max_val = pg_cursor.fetchone()[0]
            if max_val and max_val > 0:
                pg_cursor.execute(f"SELECT setval('{seq_name}', {max_val})")
                logger.info("  Reset sequence '%s' to %d", seq_name, max_val)
        except Exception as e:
            logger.warning("  Could not reset sequence '%s': %s", seq_name, e)
            pg_conn.rollback()

    pg_conn.commit()


def main():
    sqlite_path = sys.argv[1] if len(sys.argv) > 1 and sys.argv[1].startswith('/') else SQLITE_PATH

    if not os.path.exists(sqlite_path):
        logger.error("SQLite database not found: %s", sqlite_path)
        sys.exit(1)

    logger.info("=" * 60)
    logger.info("SQLite → PostgreSQL Migration")
    logger.info("  SQLite: %s", sqlite_path)
    logger.info("  PostgreSQL: %s", DATABASE_URL.split('@')[1] if '@' in DATABASE_URL else DATABASE_URL)
    logger.info("=" * 60)

    # Step 1: Initialize PostgreSQL schema
    logger.info("\n[1/4] Initializing PostgreSQL schema...")
    import database
    database.init_db()
    logger.info("  Schema initialized successfully")

    # Step 2: Connect to both databases
    logger.info("\n[2/4] Connecting to databases...")
    sqlite_conn = sqlite3.connect(sqlite_path)
    sqlite_conn.row_factory = None  # plain tuples
    pg_conn = psycopg2.connect(DATABASE_URL)
    pg_conn.autocommit = False

    sqlite_tables = set(get_sqlite_tables(sqlite_conn))
    logger.info("  SQLite tables found: %d", len(sqlite_tables))

    # Get PostgreSQL tables
    pg_cursor = pg_conn.cursor()
    pg_cursor.execute("SELECT tablename FROM pg_tables WHERE schemaname = 'public'")
    pg_tables = {row[0] for row in pg_cursor.fetchall()}
    logger.info("  PostgreSQL tables found: %d", len(pg_tables))

    # Step 3: Migrate data
    logger.info("\n[3/4] Migrating data...")
    total_rows = 0
    migrated_tables = 0

    # First migrate in dependency order
    for table in TABLES_ORDER:
        if table in sqlite_tables:
            count = migrate_table(sqlite_conn, pg_conn, table, pg_tables)
            total_rows += count
            if count > 0:
                migrated_tables += 1

    # Then migrate any remaining tables not in our list
    remaining = sqlite_tables - set(TABLES_ORDER)
    for table in sorted(remaining):
        logger.info("  (extra table: %s)", table)
        count = migrate_table(sqlite_conn, pg_conn, table, pg_tables)
        total_rows += count
        if count > 0:
            migrated_tables += 1

    # Step 4: Reset sequences
    logger.info("\n[4/4] Resetting sequences...")
    reset_sequences(pg_conn)

    # Cleanup
    sqlite_conn.close()
    pg_conn.close()

    logger.info("\n" + "=" * 60)
    logger.info("Migration complete!")
    logger.info("  Tables migrated: %d", migrated_tables)
    logger.info("  Total rows: %d", total_rows)
    logger.info("=" * 60)


if __name__ == "__main__":
    main()
