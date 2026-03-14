import sqlite3
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "auth.db"
SCHEMA_PATH = BASE_DIR / "schema.sql"


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    with open(SCHEMA_PATH, "r", encoding="utf-8") as f:
        conn.executescript(f.read())
    conn.commit()
    conn.close()


def user_count():
    conn = get_db()
    cur = conn.execute("SELECT COUNT(*) AS c FROM users")
    row = cur.fetchone()
    conn.close()
    return row["c"]


def get_user_by_username(username):
    conn = get_db()
    cur = conn.execute(
        "SELECT * FROM users WHERE username = ?",
        (username,)
    )
    row = cur.fetchone()
    conn.close()
    return row


def get_user_by_email(email):
    conn = get_db()
    cur = conn.execute(
        "SELECT * FROM users WHERE email = ?",
        (email,)
    )
    row = cur.fetchone()
    conn.close()
    return row


def get_user_by_id(user_id):
    conn = get_db()
    cur = conn.execute(
        "SELECT * FROM users WHERE id = ?",
        (user_id,)
    )
    row = cur.fetchone()
    conn.close()
    return row


def insert_user(username, email, password_hash, role, now):
    conn = get_db()
    cur = conn.execute(
        """
        INSERT INTO users
        (username, email, password_hash, role, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (username, email, password_hash, role, now, now),
    )
    conn.commit()
    user_id = cur.lastrowid
    conn.close()
    return user_id


def update_last_login(user_id, now):
    conn = get_db()
    conn.execute(
        """
        UPDATE users
        SET last_login_at = ?, updated_at = ?
        WHERE id = ?
        """,
        (now, now, user_id),
    )
    conn.commit()
    conn.close()


def update_user_password(user_id, password_hash, now):
    conn = get_db()
    conn.execute(
        """
        UPDATE users
        SET password_hash = ?, updated_at = ?
        WHERE id = ?
        """,
        (password_hash, now, user_id),
    )
    conn.commit()
    conn.close()


def update_user_profile(user_id, username, email, now):
    conn = get_db()
    conn.execute(
        """
        UPDATE users
        SET username = ?, email = ?, updated_at = ?
        WHERE id = ?
        """,
        (username, email, now, user_id),
    )
    conn.commit()
    conn.close()


def insert_session(
    user_id,
    session_token,
    csrf_token,
    created_at,
    expires_at,
    last_seen_at,
    ip_address,
    user_agent,
):
    conn = get_db()
    cur = conn.execute(
        """
        INSERT INTO sessions
        (
            user_id,
            session_token,
            csrf_token,
            created_at,
            expires_at,
            last_seen_at,
            ip_address,
            user_agent,
            is_revoked
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0)
        """,
        (
            user_id,
            session_token,
            csrf_token,
            created_at,
            expires_at,
            last_seen_at,
            ip_address,
            user_agent,
        ),
    )
    conn.commit()
    session_id = cur.lastrowid
    conn.close()
    return session_id


def get_session_by_token(session_token):
    conn = get_db()
    cur = conn.execute(
        "SELECT * FROM sessions WHERE session_token = ?",
        (session_token,)
    )
    row = cur.fetchone()
    conn.close()
    return row


def revoke_session(session_token):
    conn = get_db()
    conn.execute(
        """
        UPDATE sessions
        SET is_revoked = 1
        WHERE session_token = ?
        """,
        (session_token,),
    )
    conn.commit()
    conn.close()


def touch_session(session_token, now):
    conn = get_db()
    conn.execute(
        """
        UPDATE sessions
        SET last_seen_at = ?
        WHERE session_token = ?
        """,
        (now, session_token),
    )
    conn.commit()
    conn.close()
