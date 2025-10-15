import os
import sqlite3
import hashlib
import secrets

DB_PATH = os.path.join(os.getcwd(), "forensic_db.sqlite3")
INIT_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL,
    created_at TEXT NOT NULL
);
"""

def _get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.execute(INIT_SCHEMA)
    return conn

def hash_password(password: str, salt: str=None):
    if salt is None:
        salt = secrets.token_hex(8)
    ph = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 200000)
    return f"{salt}${ph.hex()}"

def verify_password(stored: str, password: str) -> bool:
    try:
        salt, ph = stored.split("$", 1)
        test = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 200000)
        return test.hex() == ph
    except Exception:
        return False

def create_user(username: str, password: str, role: str="operator"):
    conn = _get_conn()
    cur = conn.cursor()
    ph = hash_password(password)
    cur.execute("INSERT INTO users(username,password_hash,role,created_at) VALUES (?,?,?,datetime('now'))", (username, ph, role))
    conn.commit()
    conn.close()

def authenticate(username: str, password: str):
    conn = _get_conn()
    cur = conn.cursor()
    cur.execute("SELECT password_hash, role FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    conn.close()
    if not row:
        return False, None
    pw_hash, role = row
    return verify_password(pw_hash, password), role
