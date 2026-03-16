#!/usr/bin/env python3
"""One-time password reset script. Delete after use."""
import os, sys, bcrypt, psycopg2

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://hermes:hermes@localhost:5432/hermes_crm")
NEW_PASSWORD = "R@shad123"

conn = psycopg2.connect(DATABASE_URL)
cur = conn.cursor()

# Show all users
cur.execute("SELECT id, username, email, role, is_active FROM users")
users = cur.fetchall()
print(f"Found {len(users)} users:")
for u in users:
    print(f"  id={u[0]} username={u[1]} email={u[2]} role={u[3]} active={u[4]}")

# Hash new password
pw_hash = bcrypt.hashpw(NEW_PASSWORD.encode(), bcrypt.gensalt()).decode()

# Update ALL active users (or just admin)
cur.execute("UPDATE users SET password_hash = %s WHERE is_active = 1", (pw_hash,))
updated = cur.rowcount
conn.commit()
print(f"\nUpdated {updated} user(s) password to: {NEW_PASSWORD}")

conn.close()
