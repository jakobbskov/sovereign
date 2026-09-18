import argparse
import os
import re
import sqlite3
from contextlib import closing, contextmanager
from datetime import datetime, timezone
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = Path(os.environ.get("CORE_AUTH_DB_PATH", BASE_DIR / "auth.db"))
SCHEMA_PATH = BASE_DIR / "schema.sql"


def get_db(database=None):
    conn = sqlite3.connect(database if database is not None else DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA foreign_keys = ON")
        if conn.execute("PRAGMA foreign_keys").fetchone()[0] != 1:
            raise sqlite3.DatabaseError("foreign keys unavailable")
    except Exception:
        conn.close()
        raise
    return conn


def init_db(database=None):
    """Apply the additive schema atomically to new or existing databases."""
    schema = SCHEMA_PATH.read_text(encoding="utf-8")
    with closing(get_db(database)) as conn:
        try:
            # executescript commits a pending transaction, so BEGIN belongs inside it.
            conn.executescript("BEGIN IMMEDIATE;\n" + schema)
            if conn.execute("PRAGMA foreign_key_check").fetchone() is not None:
                raise sqlite3.IntegrityError("foreign key check failed")
            conn.commit()
        except Exception:
            conn.rollback()
            raise


@contextmanager
def database_transaction(database=None):
    with closing(get_db(database)) as conn:
        try:
            conn.execute("BEGIN IMMEDIATE")
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise


def validate_app_key(app_key):
    if not isinstance(app_key, str) or re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", app_key) is None:
        raise ValueError("invalid app key")


def validate_user_id(user_id):
    if type(user_id) is not int or not 1 <= user_id <= 9223372036854775807:
        raise ValueError("invalid user id")


def require_entitlement_user(conn, user_id):
    validate_user_id(user_id)
    if conn.execute("SELECT id FROM users WHERE id = ?", (user_id,)).fetchone() is None:
        raise LookupError("user not found")


def list_apps():
    with closing(get_db()) as conn:
        return [dict(row) for row in conn.execute("SELECT key, name FROM apps ORDER BY key")]


def list_user_entitlements(user_id):
    with closing(get_db()) as conn:
        require_entitlement_user(conn, user_id)
        return [row["key"] for row in conn.execute(
            "SELECT apps.key FROM apps JOIN user_apps ON apps.id = user_apps.app_id "
            "WHERE user_apps.user_id = ? ORDER BY apps.key", (user_id,)
        )]


def change_user_entitlement(user_id, app_key, *, grant):
    validate_user_id(user_id)
    validate_app_key(app_key)
    with database_transaction() as conn:
        require_entitlement_user(conn, user_id)
        app_row = conn.execute("SELECT id FROM apps WHERE key = ?", (app_key,)).fetchone()
        if app_row is None:
            raise LookupError("app not found")
        if grant:
            conn.execute(
                "INSERT INTO user_apps (user_id, app_id, created_at) VALUES (?, ?, ?) "
                "ON CONFLICT(user_id, app_id) DO NOTHING",
                (user_id, app_row["id"], datetime.now(timezone.utc).isoformat()),
            )
        else:
            conn.execute("DELETE FROM user_apps WHERE user_id = ? AND app_id = ?",
                         (user_id, app_row["id"]))


def grant_user_entitlement(user_id, app_key):
    change_user_entitlement(user_id, app_key, grant=True)


def revoke_user_entitlement(user_id, app_key):
    change_user_entitlement(user_id, app_key, grant=False)


def register_app(app_key, name, database=None):
    validate_app_key(app_key)
    if not isinstance(name, str) or not name or name != name.strip() or "\x00" in name:
        raise ValueError("invalid app name")
    with database_transaction(database) as conn:
        conn.execute(
            "INSERT INTO apps (key, name, created_at) VALUES (?, ?, ?) "
            "ON CONFLICT(key) DO NOTHING",
            (app_key, name, datetime.now(timezone.utc).isoformat()),
        )


def user_count():
    conn = get_db()
    cur = conn.execute("SELECT COUNT(*) AS c FROM users")
    row = cur.fetchone()
    conn.close()
    return row["c"]


def list_users():
    conn = get_db()
    cur = conn.execute(
        """
        SELECT
            id,
            username,
            email,
            role,
            is_active,
            created_at,
            updated_at,
            last_login_at
        FROM users
        ORDER BY username COLLATE NOCASE ASC
        """
    )
    rows = cur.fetchall()
    conn.close()
    return rows


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
    with closing(get_db()) as conn:
        return conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()


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


def update_user_role(user_id, role, now):
    conn = get_db()
    conn.execute(
        """
        UPDATE users
        SET role = ?, updated_at = ?
        WHERE id = ?
        """,
        (role, now, user_id),
    )
    conn.commit()
    conn.close()


def update_user_active_status(user_id, is_active, now):
    conn = get_db()
    conn.execute(
        """
        UPDATE users
        SET is_active = ?, updated_at = ?
        WHERE id = ?
        """,
        (is_active, now, user_id),
    )
    conn.commit()
    conn.close()


def set_user_must_change_password(user_id, must_change_password, now):
    conn = get_db()
    conn.execute(
        """
        UPDATE users
        SET must_change_password = ?, updated_at = ?
        WHERE id = ?
        """,
        (must_change_password, now, user_id),
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
    with closing(get_db()) as conn:
        return conn.execute(
            "SELECT * FROM sessions WHERE session_token = ?", (session_token,)
        ).fetchone()


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
    with database_transaction() as conn:
        conn.execute(
            "UPDATE sessions SET last_seen_at = ? WHERE session_token = ?",
            (now, session_token),
        )


def main():
    parser = argparse.ArgumentParser(description="Core Auth schema and app catalog")
    parser.add_argument("--database", required=True, type=Path)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("migrate", help="Atomically apply schema; safe to repeat")
    register = commands.add_parser("register-app", help="Register a catalog app without grants")
    register.add_argument("key")
    register.add_argument("name")
    args = parser.parse_args()
    if not args.database.is_file():
        parser.error("database must be an existing file")
    try:
        if args.command == "migrate":
            init_db(args.database)
        else:
            register_app(args.key, args.name, args.database)
    except (sqlite3.Error, ValueError, OSError):
        parser.exit(1, "Database operation failed; transaction rolled back.\n")
    print("Database operation completed; no user entitlements assigned.")


if __name__ == "__main__":
    main()
