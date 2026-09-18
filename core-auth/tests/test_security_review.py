import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing

import pytest
from markupsafe import escape

import app as auth
import db


def test_database_guard_blocks_real_database_paths():
    with pytest.raises(AssertionError, match="temporary directory"):
        db.get_db(db.BASE_DIR / "auth.db")


@pytest.mark.parametrize("page", ["/login", "/register", "/account"])
def test_return_to_cannot_inject_script(client, login, monkeypatch, page):
    login()
    monkeypatch.setattr(auth, "ALLOW_REGISTRATION", True)
    target = 'https://apps.innosocia.dk/?q=</script><script>window.reviewProbe=1</script>'
    response = client.get(page, query_string={"return_to": target})
    assert response.status_code == 200
    assert '<script>window.reviewProbe=1</script>' not in response.text
    encoded = re.search(r"const returnTo = (.*);", response.text).group(1)
    assert "<" not in encoded
    assert json.loads(encoded) == target


@pytest.mark.parametrize("target", [
    "https://apps.innosocia.dk.attacker.invalid/",
    "https://apps.innosocia.dk@attacker.invalid/",
    "https://apps.innosocia.dk:444/",
    "https://apps.innosocia.dk\\@attacker.invalid/",
    "https://apps.innosocia.dk\n.attacker.invalid/",
    "//apps.innosocia.dk/", "javascript:alert(1)", "https://[broken/",
])
def test_return_to_requires_exact_origin(target):
    with auth.app.test_request_context('/login', query_string={"return_to": target}):
        assert auth.get_safe_return_to() == "https://strength.innosocia.dk"


@pytest.mark.parametrize("origin", sorted(auth.ALLOWED_ORIGINS))
def test_return_to_preserves_existing_app_destinations(origin):
    target = origin + "/path?a=one&b=two#section"
    with auth.app.test_request_context('/login', query_string={"return_to": target}):
        assert auth.get_safe_return_to() == target


def test_account_escapes_stored_profile_values(client, login, users):
    login()
    hostile = '\"><img src=x onerror="window.reviewProbe=1">'
    db.update_user_profile(users["admin"], hostile, hostile, auth.now_utc_iso())
    response = client.get('/account')
    assert response.status_code == 200
    assert hostile not in response.text
    assert str(escape(hostile)) in response.text


@pytest.mark.parametrize("operation", [db.get_db, db.init_db])
def test_missing_database_is_not_created(tmp_path, monkeypatch, operation):
    missing = tmp_path / "missing.sqlite"
    monkeypatch.setattr(db, "DB_PATH", missing)
    with pytest.raises(sqlite3.OperationalError):
        operation()
    assert not missing.exists()


def test_missing_database_bootstrap_fails_closed(client, tmp_path, monkeypatch):
    missing = tmp_path / "missing.sqlite"
    monkeypatch.setattr(db, "DB_PATH", missing)
    response = client.post('/api/auth/bootstrap-admin', json={"username": "review-user", "password": "test-password-long"})
    assert response.status_code == 503
    assert response.json == {"ok": False, "error": "service unavailable"}
    assert not missing.exists()


def test_import_cannot_create_default_database(tmp_path):
    # Import a disposable copy so even a future import regression cannot touch auth.db.
    for filename in ("app.py", "db.py", "schema.sql"):
        shutil.copyfile(db.BASE_DIR / filename, tmp_path / filename)
    environment = dict(os.environ)
    environment.pop("CORE_AUTH_DB_PATH", None)
    environment["PYTHONPATH"] = str(tmp_path)
    result = subprocess.run([sys.executable, "-c", "import app, db"], cwd=tmp_path,
                            env=environment, capture_output=True)
    assert result.returncode == 0, result.stderr
    assert not (tmp_path / "auth.db").exists()


def test_cli_database_overrides_environment_and_requires_explicit_creation(tmp_path):
    target = tmp_path / "selected.sqlite"
    environment_default = tmp_path / "unselected.sqlite"
    environment = dict(os.environ, CORE_AUTH_DB_PATH=str(environment_default))
    command = [sys.executable, str(db.BASE_DIR / "db.py"), "--database", str(target)]
    for arguments in (["init"], ["migrate"], ["register-app", "review-app", "Review App"]):
        result = subprocess.run(command + arguments, env=environment, capture_output=True)
        assert result.returncode == 0, result.stderr
        assert not environment_default.exists()
    with closing(db.get_db(target)) as conn:
        assert conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1
        assert conn.execute("SELECT key FROM apps ORDER BY key").fetchall()[0][0] == "review-app"
        assert conn.execute("SELECT COUNT(*) FROM user_apps").fetchone()[0] == 0
    before = target.read_bytes()
    assert subprocess.run(command + ["init"], env=environment, capture_output=True).returncode == 1
    assert target.read_bytes() == before
    assert target.stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize("helper", [
    "insert_user", "insert_session", "update_last_login", "update_user_password",
    "update_user_profile", "update_user_role", "update_user_active_status",
    "set_user_must_change_password", "revoke_session",
])
def test_legacy_write_failure_releases_connection_and_lock(users, monkeypatch, helper):
    now = auth.now_utc_iso()
    user_id = users["user"]
    db.insert_session(user_id, "review-session", "review-csrf", now, now, now, None, None)
    arguments = {
        "insert_user": ("another-review-user", None, "hash", "user", now),
        "insert_session": (user_id, "second-review-session", "review-csrf", now, now, now, None, None),
        "update_last_login": (user_id, now),
        "update_user_password": (user_id, "replacement", now),
        "update_user_profile": (user_id, "renamed-review-user", None, now),
        "update_user_role": (user_id, "admin", now),
        "update_user_active_status": (user_id, 0, now),
        "set_user_must_change_password": (user_id, 1, now),
        "revoke_session": ("review-session",),
    }
    table = "sessions" if helper in ("insert_session", "revoke_session") else "users"
    event = "INSERT" if helper.startswith("insert_") else "UPDATE"
    with closing(db.get_db()) as conn:
        before = [tuple(row) for row in conn.execute(f"SELECT * FROM {table}")]
        conn.execute(f"CREATE TRIGGER fail_review AFTER {event} ON {table} BEGIN SELECT RAISE(FAIL, 'review failure'); END")
        conn.commit()
    original_get_db = db.get_db
    connections = []
    def tracked_get_db(*args, **kwargs):
        conn = original_get_db(*args, **kwargs)
        connections.append(conn)  # Keep alive: garbage collection must not release the lock for us.
        return conn
    monkeypatch.setattr(db, "get_db", tracked_get_db)
    try:
        with pytest.raises(sqlite3.IntegrityError):
            getattr(db, helper)(*arguments[helper])
        for conn in connections:
            with pytest.raises(sqlite3.ProgrammingError):
                conn.execute("SELECT 1")
        with closing(original_get_db()) as conn:
            conn.execute("PRAGMA busy_timeout = 0")
            conn.execute("BEGIN IMMEDIATE")
            assert [tuple(row) for row in conn.execute(f"SELECT * FROM {table}")] == before
            conn.rollback()
    finally:
        for conn in connections:
            conn.close()


@pytest.mark.parametrize("helper,args", [
    ("user_count", ()), ("list_users", ()),
    ("get_user_by_username", ("user",)), ("get_user_by_email", ("review@example.invalid",)),
])
def test_read_failure_closes_connection(monkeypatch, helper, args):
    original_get_db = db.get_db
    connections = []
    def unreadable_db():
        conn = original_get_db()
        conn.set_authorizer(lambda *args: sqlite3.SQLITE_DENY)
        connections.append(conn)
        return conn
    monkeypatch.setattr(db, "get_db", unreadable_db)
    try:
        with pytest.raises(sqlite3.DatabaseError):
            getattr(db, helper)(*args)
        for conn in connections:
            with pytest.raises(sqlite3.ProgrammingError):
                conn.execute("SELECT 1")
    finally:
        for conn in connections:
            conn.close()


@pytest.mark.parametrize("operation", [db.grant_user_entitlement, db.revoke_user_entitlement])
def test_concurrent_entitlement_changes_are_idempotent(users, operation):
    user_id = users["user"]
    if operation is db.revoke_user_entitlement:
        db.grant_user_entitlement(user_id, "writer")
    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(lambda _: operation(user_id, "writer"), range(12)))
    expected = ["writer"] if operation is db.grant_user_entitlement else []
    assert db.list_user_entitlements(user_id) == expected


@pytest.mark.parametrize("value", [True, False, 1.0, "1", None])
def test_helpers_reject_non_integer_user_id(value):
    with pytest.raises(ValueError, match="invalid user id"):
        db.grant_user_entitlement(value, "writer")


@pytest.mark.parametrize("content_type,body", [
    ("text/plain", '{"app_key":"writer","granted":true}'),
    ("application/x-www-form-urlencoded", 'app_key=writer&granted=true'),
    ("application/json", '{"app_key":"writer","granted":true'),
    ("application/json", 'true'),
])
def test_entitlement_post_rejects_invalid_json(client, login, users, content_type, body):
    token = login()
    response = client.post(f'/api/admin/users/{users["user"]}/entitlements', data=body,
                           content_type=content_type, headers={"X-CSRF-Token": token})
    assert response.status_code == 400
    assert response.json == {"ok": False, "error": "expected app_key and granted"}
    assert db.list_user_entitlements(users["user"]) == []


def test_csrf_error_does_not_log_or_store_submitted_token(client, login, users, caplog):
    login()
    supplied = auth.secrets.token_urlsafe(32)
    response = client.post(f'/api/admin/users/{users["user"]}/entitlements',
                           json={"app_key": "writer", "granted": True}, headers={"X-CSRF-Token": supplied})
    assert response.status_code == 403
    assert response.json == {"ok": False, "error": "invalid csrf token"}
    assert supplied not in caplog.text
    with closing(db.get_db()) as conn:
        assert conn.execute("SELECT COUNT(*) FROM sessions WHERE csrf_token = ?", (supplied,)).fetchone()[0] == 0


@pytest.mark.parametrize("path", [
    "/api/admin/csrf", "/api/%61dmin/csrf", "/api/admin/users/../csrf",
    "/api//admin/csrf", "/api/admin/csrf/", "/api/admin/csrf?origin=trusted",
])
def test_admin_cors_cannot_be_bypassed_with_url_variants(client, login, path):
    login()
    response = client.get(path, headers={"Origin": "https://apps.innosocia.dk"}, follow_redirects=True)
    # Error documents are harmless; an actual token response must never be readable cross-origin.
    if response.status_code == 200:
        assert "Access-Control-Allow-Origin" not in response.headers
        assert response.headers["Cache-Control"] == "no-store"
