#!/usr/bin/env python3
"""
Restore tickets and ticket_messages from SQLite backup to PostgreSQL.
"""
import os, sys, glob, sqlite3, psycopg2

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://hermes:hermes@localhost:5432/hermes_crm")

def find_latest_sqlite_backup():
    """Find the most recent SQLite backup."""
    backup_dir = "/opt/hermes_crm/backups"
    pattern = os.path.join(backup_dir, "crm_*.db")
    backups = sorted(glob.glob(pattern))
    if backups:
        return backups[-1]
    # Fallback to main crm.db
    if os.path.exists("/opt/hermes_crm/crm.db"):
        return "/opt/hermes_crm/crm.db"
    return None

def get_columns(sqlite_conn, table):
    cursor = sqlite_conn.execute(f"PRAGMA table_info({table})")
    return [row[1] for row in cursor.fetchall()]

def get_pg_columns(pg_conn, table):
    cur = pg_conn.cursor()
    cur.execute("SELECT column_name FROM information_schema.columns WHERE table_name = %s", (table,))
    return {row[0] for row in cur.fetchall()}

def migrate_table(sqlite_conn, pg_conn, table):
    sqlite_cols = get_columns(sqlite_conn, table)
    pg_cols = get_pg_columns(pg_conn, table)

    if not pg_cols:
        print(f"  Table '{table}' not found in PostgreSQL!")
        return 0

    common = [c for c in sqlite_cols if c in pg_cols]
    if not common:
        print(f"  No common columns for '{table}'")
        return 0

    cols_str = ", ".join(common)
    rows = sqlite_conn.execute(f"SELECT {cols_str} FROM {table}").fetchall()
    print(f"  SQLite '{table}': {len(rows)} rows, columns: {common}")

    if not rows:
        return 0

    placeholders = ", ".join(["%s"] * len(common))

    # Use ON CONFLICT DO NOTHING to skip duplicates
    insert_sql = f"INSERT INTO {table} ({cols_str}) VALUES ({placeholders}) ON CONFLICT DO NOTHING"

    cur = pg_conn.cursor()
    inserted = 0
    for row in rows:
        try:
            cur.execute(insert_sql, tuple(row))
            if cur.rowcount > 0:
                inserted += 1
        except Exception as e:
            pg_conn.rollback()
            print(f"  Error inserting into '{table}': {e}")
            print(f"    Row: {str(tuple(row))[:200]}")
            continue

    pg_conn.commit()
    print(f"  Inserted {inserted} new rows into '{table}' (skipped {len(rows) - inserted} existing)")
    return inserted

def reset_sequence(pg_conn, table):
    cur = pg_conn.cursor()
    try:
        cur.execute(f"""
            SELECT pg_get_serial_sequence('{table}', 'id')
        """)
        seq = cur.fetchone()
        if seq and seq[0]:
            cur.execute(f"SELECT COALESCE(MAX(id), 0) FROM {table}")
            max_id = cur.fetchone()[0]
            if max_id > 0:
                cur.execute(f"SELECT setval('{seq[0]}', {max_id})")
                print(f"  Sequence for '{table}' reset to {max_id}")
        pg_conn.commit()
    except Exception as e:
        pg_conn.rollback()
        print(f"  Could not reset sequence for '{table}': {e}")

def main():
    sqlite_path = find_latest_sqlite_backup()
    if not sqlite_path:
        print("No SQLite backup found!")
        sys.exit(1)

    print(f"SQLite source: {sqlite_path}")
    print(f"PostgreSQL: {DATABASE_URL.split('@')[1] if '@' in DATABASE_URL else DATABASE_URL}")

    sqlite_conn = sqlite3.connect(sqlite_path)
    pg_conn = psycopg2.connect(DATABASE_URL)
    pg_conn.autocommit = False

    # Check current PG state
    cur = pg_conn.cursor()
    for t in ['tickets', 'ticket_messages', 'sla_policies', 'kb_articles']:
        try:
            cur.execute(f"SELECT COUNT(*) FROM {t}")
            cnt = cur.fetchone()[0]
            print(f"  PG '{t}': {cnt} rows currently")
        except:
            pg_conn.rollback()
            print(f"  PG '{t}': table doesn't exist")

    # Check SQLite state
    sqlite_tables = set()
    for row in sqlite_conn.execute("SELECT name FROM sqlite_master WHERE type='table'"):
        sqlite_tables.add(row[0])

    print(f"\nSQLite tables: {sorted(sqlite_tables)}")

    for t in ['tickets', 'ticket_messages', 'sla_policies', 'kb_articles']:
        if t in sqlite_tables:
            cnt = sqlite_conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
            print(f"  SQLite '{t}': {cnt} rows")

    # Migrate
    print("\n--- Migrating ---")
    tables_to_restore = ['sla_policies', 'tickets', 'ticket_messages', 'kb_articles']
    for t in tables_to_restore:
        if t in sqlite_tables:
            migrate_table(sqlite_conn, pg_conn, t)
            reset_sequence(pg_conn, t)

    # Final check
    print("\n--- Final state ---")
    for t in tables_to_restore:
        try:
            cur = pg_conn.cursor()
            cur.execute(f"SELECT COUNT(*) FROM {t}")
            cnt = cur.fetchone()[0]
            print(f"  PG '{t}': {cnt} rows")
        except:
            pg_conn.rollback()

    sqlite_conn.close()
    pg_conn.close()
    print("\nDone!")

if __name__ == "__main__":
    main()
