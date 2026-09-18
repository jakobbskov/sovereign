import sqlite3
import subprocess
import sys
from contextlib import closing
from pathlib import Path

import pytest

import db
import app as auth


def test_new_database_and_catalog():
    with closing(db.get_db()) as conn:
        tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        assert {"apps", "user_apps", "users", "sessions"} <= tables
        assert conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1
    assert db.list_apps() == [{"key": "writer", "name": "Sovereign Writer"}]


def test_existing_database_migration(tmp_path, monkeypatch, client):
    legacy = tmp_path / "legacy.sqlite"
    old_schema = Path(__file__).parent / "fixtures" / "schema_136e3c9.sql"
    with closing(sqlite3.connect(legacy)) as conn:
        conn.execute("PRAGMA foreign_keys = ON")
        conn.executescript(old_schema.read_text())
    monkeypatch.setattr(db, "DB_PATH", legacy)
    users = {
        role: db.insert_user(role, None, auth.generate_password_hash("test-password-long"), role, auth.now_utc_iso())
        for role in ("admin", "user")
    }
    assert client.post("/api/auth/login", json={"username": "user", "password": "test-password-long"}).status_code == 200
    with closing(db.get_db()) as conn:
        before_users = [tuple(row) for row in conn.execute("SELECT * FROM users")]
        before_sessions = [tuple(row) for row in conn.execute("SELECT * FROM sessions")]
        assert conn.execute("SELECT name FROM sqlite_master WHERE name IN ('apps', 'user_apps')").fetchall() == []
    db.init_db()
    db.init_db()
    with closing(db.get_db()) as conn:
        assert [tuple(row) for row in conn.execute("SELECT * FROM users")] == before_users
        assert [tuple(row) for row in conn.execute("SELECT * FROM sessions")] == before_sessions
    assert db.list_apps() == [{"key": "writer", "name": "Sovereign Writer"}]
    assert all(db.list_user_entitlements(user_id) == [] for user_id in users.values())
    response = client.get("/api/auth/validate")
    assert response.status_code == 200
    assert response.json == {"ok": True, "authenticated": True, "user_id": users["user"],
                             "username": "user", "role": "user", "entitlements": []}


@pytest.mark.parametrize("key", ["", "Writer", "1writer", "a b", "é", "a/", "a" * 65, "a\x00b"])
def test_key_database_constraint(key):
    with closing(db.get_db()) as conn, pytest.raises(sqlite3.IntegrityError):
        conn.execute("INSERT INTO apps (key, name, created_at) VALUES (?, 'Valid', 'now')", (key,))


@pytest.mark.parametrize("name", ["", " ", " Name", "Name ", "\tName", "Name\n", "a\x00b", "\u00a0Name", "Name\u3000"])
def test_name_database_constraint(name):
    with closing(db.get_db()) as conn, pytest.raises(sqlite3.IntegrityError):
        conn.execute("INSERT INTO apps (key, name, created_at) VALUES ('example', ?, 'now')", (name,))


def test_duplicate_and_foreign_key_constraints(users):
    db.grant_user_entitlement(users["user"], "writer")
    with closing(db.get_db()) as conn:
        app_id = conn.execute("SELECT id FROM apps WHERE key='writer'").fetchone()[0]
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute("INSERT INTO user_apps VALUES (?, ?, 'now')", (users["user"], app_id))
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute("INSERT INTO user_apps VALUES (?, ?, 'now')", (max(users.values()) + 1, app_id))
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute("INSERT INTO user_apps VALUES (?, ?, 'now')", (users["admin"], app_id + 1))


@pytest.mark.parametrize("table", ["users", "apps"])
def test_cascade(table, users):
    db.grant_user_entitlement(users["user"], "writer")
    with closing(db.get_db()) as conn:
        if table == "users":
            conn.execute("DELETE FROM users WHERE id = ?", (users["user"],))
        else:
            conn.execute("DELETE FROM apps WHERE key = 'writer'")
        conn.commit()
        assert conn.execute("SELECT COUNT(*) FROM user_apps").fetchone()[0] == 0


def test_migration_rollback(tmp_path, monkeypatch, users):
    broken = tmp_path / "broken.sql"
    broken.write_text(db.SCHEMA_PATH.read_text() + "\nCREATE TABLE rollback_probe(id);\nINVALID SQL;")
    monkeypatch.setattr(db, "SCHEMA_PATH", broken)
    with closing(db.get_db()) as conn:
        conn.execute("DROP TABLE user_apps")
        conn.execute("DROP TABLE apps")
        conn.commit()
    with pytest.raises(sqlite3.Error):
        db.init_db()
    with closing(db.get_db()) as conn:
        names = {row[0] for row in conn.execute("SELECT name FROM sqlite_master")}
        assert not {"apps", "user_apps", "rollback_probe"} & names
        assert conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == len(users)


@pytest.mark.parametrize("grant", [True, False])
def test_mutation_rollback(grant, users):
    if not grant:
        db.grant_user_entitlement(users["user"], "writer")
    with closing(db.get_db()) as conn:
        event = "INSERT" if grant else "DELETE"
        conn.execute(f"CREATE TRIGGER fail_change AFTER {event} ON user_apps BEGIN SELECT RAISE(FAIL, 'test failure'); END")
        conn.commit()
    operation = db.grant_user_entitlement if grant else db.revoke_user_entitlement
    with pytest.raises(sqlite3.IntegrityError):
        operation(users["user"], "writer")
    assert db.list_user_entitlements(users["user"]) == ([] if grant else ["writer"])


def test_registration_and_repeat_migration_preserve_grants(users):
    db.grant_user_entitlement(users["user"], "writer")
    db.register_app("example", "Example")
    db.register_app("example", "Example")
    db.init_db()
    assert db.list_user_entitlements(users["user"]) == ["writer"]
    assert db.list_user_entitlements(users["admin"]) == []


def test_cli(isolated_database, tmp_path):
    command = [sys.executable, str(db.BASE_DIR / "db.py"), "--database", str(isolated_database)]
    for arguments in (["migrate"], ["migrate"], ["register-app", "example", "Example"]):
        assert subprocess.run(command + arguments, capture_output=True).returncode == 0
    missing = tmp_path / "missing.sqlite"
    result = subprocess.run([sys.executable, str(db.BASE_DIR / "db.py"), "--database", str(missing), "migrate"], capture_output=True)
    assert result.returncode != 0
    assert not missing.exists()
