#!/usr/bin/env python3
"""Diagnose tickets table state in PostgreSQL."""
import os, psycopg2

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://hermes:hermes@localhost:5432/hermes_crm")

conn = psycopg2.connect(DATABASE_URL)
cur = conn.cursor()

print("=== TICKETS TABLE DIAGNOSTICS ===\n")

# 1. Check if table exists and its columns
cur.execute("""
    SELECT column_name, data_type, column_default
    FROM information_schema.columns
    WHERE table_name = 'tickets'
    ORDER BY ordinal_position
""")
cols = cur.fetchall()
if cols:
    print(f"1. tickets table EXISTS with {len(cols)} columns:")
    for c in cols:
        print(f"   {c[0]:25s} {c[1]:20s} default={c[2]}")
else:
    print("1. tickets table DOES NOT EXIST!")

# 2. Row count
try:
    cur.execute("SELECT COUNT(*) FROM tickets")
    print(f"\n2. Row count: {cur.fetchone()[0]}")
except Exception as e:
    conn.rollback()
    print(f"\n2. Error counting: {e}")

# 3. Check ticket_comments / ticket_messages
for tbl in ['ticket_comments', 'ticket_messages']:
    try:
        cur.execute(f"SELECT COUNT(*) FROM {tbl}")
        print(f"   {tbl}: {cur.fetchone()[0]} rows")
    except:
        conn.rollback()
        print(f"   {tbl}: does not exist")

# 4. pg_stat_user_tables
try:
    cur.execute("""
        SELECT n_live_tup, n_dead_tup, n_tup_ins, n_tup_del, n_tup_upd,
               last_autovacuum, last_autoanalyze
        FROM pg_stat_user_tables WHERE relname='tickets'
    """)
    row = cur.fetchone()
    if row:
        print(f"\n3. pg_stat for tickets:")
        print(f"   live_tup={row[0]}, dead_tup={row[1]}")
        print(f"   inserts={row[2]}, deletes={row[3]}, updates={row[4]}")
        print(f"   last_autovacuum={row[5]}, last_autoanalyze={row[6]}")
    else:
        print("\n3. No stats for tickets table")
except Exception as e:
    conn.rollback()
    print(f"\n3. Stats error: {e}")

# 5. Check all tables with row counts
print("\n4. All tables row counts:")
cur.execute("SELECT tablename FROM pg_tables WHERE schemaname='public' ORDER BY tablename")
tables = [r[0] for r in cur.fetchall()]
for t in tables:
    try:
        cur.execute(f"SELECT COUNT(*) FROM {t}")
        cnt = cur.fetchone()[0]
        if cnt > 0 or 'ticket' in t.lower():
            print(f"   {t:40s} {cnt:>6d} rows")
    except:
        conn.rollback()

# 6. Check sequences for tickets
print("\n5. Ticket sequences:")
cur.execute("SELECT sequencename, last_value FROM pg_sequences WHERE sequencename LIKE '%ticket%'")
for row in cur.fetchall():
    print(f"   {row[0]}: last_value={row[1]}")

# 7. Check if any audit_log entries mention ticket operations
try:
    cur.execute("SELECT COUNT(*) FROM audit_log WHERE entity_type ILIKE '%ticket%'")
    cnt = cur.fetchone()[0]
    print(f"\n6. Audit log entries for tickets: {cnt}")
    if cnt > 0:
        cur.execute("SELECT id, action, entity_type, entity_id, created_at FROM audit_log WHERE entity_type ILIKE '%ticket%' ORDER BY id DESC LIMIT 10")
        for r in cur.fetchall():
            print(f"   id={r[0]} action={r[1]} type={r[2]} eid={r[3]} at={r[4]}")
except Exception as e:
    conn.rollback()
    print(f"\n6. Audit error: {e}")

conn.close()
print("\n=== DONE ===")
