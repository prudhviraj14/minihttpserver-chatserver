# database.py
import sqlite3
import hashlib
from datetime import datetime
from zoneinfo import ZoneInfo

DB_FILE = "data.db"
ZONE = ZoneInfo("Asia/Kolkata")  # IST

def now_ist_iso():
    return datetime.now(ZONE).isoformat(timespec='seconds')

def get_connection():
    conn = sqlite3.connect(DB_FILE, timeout=30, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def hash_pw(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def setup_database():
    db = get_connection()
    cur = db.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        email TEXT,
        reset_code TEXT,
        is_admin INTEGER DEFAULT 0,
        created_at TEXT,
        last_login_at TEXT
    )
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender TEXT NOT NULL,
        receiver TEXT NOT NULL,
        message TEXT,
        file_path TEXT,
        sent_at TEXT
    )
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS feedback (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        type TEXT,
        message TEXT,
        created_at TEXT
    )
    """)
    # create default admin if not exists
    cur.execute("SELECT id FROM users WHERE username = ?", ("admin",))
    if cur.fetchone() is None:
        cur.execute(
            "INSERT INTO users (username,password_hash,email,is_admin,created_at) VALUES (?,?,?,?,?)",
            ("admin", hash_pw("admin123"), "admin@example.com", 1, now_ist_iso())
        )
    db.commit()
    db.close()

# User functions
def add_user(username, password, email=None):
    db = get_connection()
    cur = db.cursor()
    cur.execute(
        "INSERT INTO users (username, password_hash, email, created_at) VALUES (?,?,?,?)",
        (username, hash_pw(password), email, now_ist_iso())
    )
    db.commit()
    db.close()

def get_user(username):
    db = get_connection()
    cur = db.cursor()
    cur.execute("SELECT * FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    db.close()
    return dict(row) if row else None

def verify_user(username, password):
    user = get_user(username)
    if not user:
        return False
    ok = user["password_hash"] == hash_pw(password)
    if ok:
        db = get_connection()
        cur = db.cursor()
        cur.execute("UPDATE users SET last_login_at = ? WHERE username = ?", (now_ist_iso(), username))
        db.commit()
        db.close()
    return ok

def set_reset_code(username, code):
    db = get_connection()
    cur = db.cursor()
    cur.execute("UPDATE users SET reset_code = ? WHERE username = ?", (code, username))
    db.commit()
    db.close()

def verify_reset_code(username, code):
    user = get_user(username)
    if not user:
        return False
    if user.get("reset_code") == code:
        db = get_connection()
        cur = db.cursor()
        cur.execute("UPDATE users SET reset_code = NULL WHERE username = ?", (username,))
        db.commit()
        db.close()
        return True
    return False

def update_password(username, new_password):
    db = get_connection()
    cur = db.cursor()
    cur.execute("UPDATE users SET password_hash = ? WHERE username = ?", (hash_pw(new_password), username))
    db.commit()
    db.close()

def list_users():
    db = get_connection()
    cur = db.cursor()
    cur.execute("SELECT username, email, is_admin, created_at, last_login_at FROM users ORDER BY username COLLATE NOCASE")
    rows = [dict(r) for r in cur.fetchall()]
    db.close()
    return rows

# Messages
def add_message(sender, receiver, message_text=None, file_path=None):
    db = get_connection()
    cur = db.cursor()
    cur.execute(
        "INSERT INTO messages (sender, receiver, message, file_path, sent_at) VALUES (?,?,?,?,?)",
        (sender, receiver, message_text, file_path, now_ist_iso())
    )
    db.commit()
    db.close()

def get_messages_for_pair(user_a, user_b):
    db = get_connection()
    cur = db.cursor()
    cur.execute("""
        SELECT * FROM messages
        WHERE (sender = ? AND receiver = ?) OR (sender = ? AND receiver = ?)
        ORDER BY id ASC
    """, (user_a, user_b, user_b, user_a))
    rows = [dict(r) for r in cur.fetchall()]
    db.close()
    return rows

def get_messages_for_user(username):
    db = get_connection()
    cur = db.cursor()
    cur.execute("SELECT * FROM messages WHERE receiver = ? ORDER BY id DESC", (username,))
    rows = [dict(r) for r in cur.fetchall()]
    db.close()
    return rows

def get_all_messages():
    db = get_connection()
    cur = db.cursor()
    cur.execute("SELECT * FROM messages ORDER BY id DESC")
    rows = [dict(r) for r in cur.fetchall()]
    db.close()
    return rows

# Feedback
def add_feedback(username, fb_type, message):
    db = get_connection()
    cur = db.cursor()
    cur.execute("INSERT INTO feedback (username, type, message, created_at) VALUES (?,?,?,?)",
                (username, fb_type, message, now_ist_iso()))
    db.commit()
    db.close()

def get_all_feedback():
    db = get_connection()
    cur = db.cursor()
    cur.execute("SELECT * FROM feedback ORDER BY id DESC")
    rows = [dict(r) for r in cur.fetchall()]
    db.close()
    return rows
