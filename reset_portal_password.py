#!/usr/bin/env python3
"""One-time: check/create portal user for rashadrahimsoy@gmail.com"""
import os, bcrypt, psycopg2

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://hermes:hermes@localhost:5432/hermes_crm")
TARGET_EMAIL = "rashadrahimsoy@gmail.com"
NEW_PASSWORD = "R@shad123"

conn = psycopg2.connect(DATABASE_URL)
cur = conn.cursor()

# Ensure portal_users table exists
cur.execute("""CREATE TABLE IF NOT EXISTS portal_users (
    id SERIAL PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    full_name TEXT DEFAULT '',
    company_id INTEGER,
    contact_id INTEGER,
    is_active INTEGER DEFAULT 1,
    last_login TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW()
)""")
conn.commit()

# Show all portal users
cur.execute("SELECT id, email, full_name, company_id, is_active FROM portal_users")
users = cur.fetchall()
print(f"Portal users ({len(users)}):")
for u in users:
    print(f"  id={u[0]} email={u[1]} name={u[2]} company_id={u[3]} active={u[4]}")

# Check if target exists
cur.execute("SELECT id, email, full_name, is_active FROM portal_users WHERE email = %s", (TARGET_EMAIL,))
user = cur.fetchone()

pw_hash = bcrypt.hashpw(NEW_PASSWORD.encode(), bcrypt.gensalt()).decode()

if user:
    print(f"\nFound portal user: id={user[0]} email={user[1]} active={user[3]}")
    cur.execute("UPDATE portal_users SET password_hash = %s, is_active = 1 WHERE email = %s", (pw_hash, TARGET_EMAIL))
    print(f"Updated password and ensured active=1")
else:
    print(f"\nPortal user {TARGET_EMAIL} NOT FOUND — creating...")
    cur.execute(
        "INSERT INTO portal_users (email, password_hash, full_name, is_active) VALUES (%s, %s, %s, 1)",
        (TARGET_EMAIL, pw_hash, "Rashad Rahimov")
    )
    print(f"Created portal user: {TARGET_EMAIL}")

conn.commit()
print(f"Password set to: {NEW_PASSWORD}")
conn.close()
