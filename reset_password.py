#!/usr/bin/env python3
"""One-time password reset for specific user. Delete after use."""
import os, bcrypt, psycopg2

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://hermes:hermes@localhost:5432/hermes_crm")
TARGET_EMAIL = "rashadrahimsoy@gmail.com"
NEW_PASSWORD = "R@shad123"

conn = psycopg2.connect(DATABASE_URL)
cur = conn.cursor()

# Check if user exists
cur.execute("SELECT id, username, email, role, is_active FROM users WHERE email = %s", (TARGET_EMAIL,))
user = cur.fetchone()

if not user:
    # User doesn't exist — create it
    pw_hash = bcrypt.hashpw(NEW_PASSWORD.encode(), bcrypt.gensalt()).decode()
    cur.execute(
        "INSERT INTO users (username, email, password_hash, full_name, role, is_active) VALUES (%s, %s, %s, %s, %s, %s)",
        ("rashad", TARGET_EMAIL, pw_hash, "Rashad Rahimov", "admin", 1)
    )
    conn.commit()
    print(f"Created new admin user: {TARGET_EMAIL} with password: {NEW_PASSWORD}")
else:
    # User exists — update password
    pw_hash = bcrypt.hashpw(NEW_PASSWORD.encode(), bcrypt.gensalt()).decode()
    cur.execute("UPDATE users SET password_hash = %s WHERE email = %s", (pw_hash, TARGET_EMAIL))
    conn.commit()
    print(f"Updated password for user id={user[0]} username={user[1]} email={user[2]}: {NEW_PASSWORD}")

# Show all users
cur.execute("SELECT id, username, email, role, is_active FROM users")
for u in cur.fetchall():
    print(f"  id={u[0]} username={u[1]} email={u[2]} role={u[3]} active={u[4]}")

conn.close()
