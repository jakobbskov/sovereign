import sqlite3
from contextlib import closing

import pytest

import app as auth
import db


@pytest.mark.parametrize("role", ["admin", "user"])
@pytest.mark.parametrize("granted", [False, True])
def test_validate_contract(client, login, users, role, granted):
    login(role)
    if granted:
        db.grant_user_entitlement(users[role], "writer")
        db.grant_user_entitlement(users[role], "writer")
    db.register_app("other", "Other")
    response = client.get("/api/auth/validate")
    assert response.status_code == 200
    assert response.json == {
        "ok": True, "authenticated": True, "user_id": users[role],
        "username": role, "role": role, "entitlements": ["writer"] if granted else [],
    }
    assert response.headers["Cache-Control"] == "no-store"


def test_validate_sorted(client, login, users):
    login("user")
    for key in ("z-app", "writer", "a_app"):
        db.register_app(key, key)
        db.grant_user_entitlement(users["user"], key)
    assert client.get("/api/auth/validate").json["entitlements"] == ["a_app", "writer", "z-app"]


@pytest.mark.parametrize("state", ["missing", "unknown", "expired", "revoked", "inactive", "malformed", "naive"])
def test_invalid_session(client, login, users, state):
    if state == "unknown":
        client.set_cookie(auth.SESSION_COOKIE_NAME, "unknown-test-session")
    elif state != "missing":
        login("user")
        db.grant_user_entitlement(users["user"], "writer")
        with closing(db.get_db()) as conn:
            if state == "expired":
                conn.execute("UPDATE sessions SET expires_at = '2000-01-01T00:00:00+00:00'")
            elif state == "malformed":
                conn.execute("UPDATE sessions SET expires_at = 'invalid'")
            elif state == "naive":
                conn.execute("UPDATE sessions SET expires_at = '2099-01-01T00:00:00'")
            elif state == "revoked":
                conn.execute("UPDATE sessions SET is_revoked = 1")
            else:
                conn.execute("UPDATE users SET is_active = 0 WHERE id = ?", (users["user"],))
            conn.commit()
    response = client.get("/api/auth/validate")
    assert response.status_code == 401
    assert response.json == {"ok": False, "authenticated": False}


@pytest.mark.parametrize("failure", ["lookup", "missing_table", "session"])
def test_validate_database_failure(client, login, monkeypatch, failure):
    login()
    def broken(*args):
        raise sqlite3.OperationalError("private SQL and /internal/path")
    if failure == "lookup":
        monkeypatch.setattr(auth, "list_user_entitlements", broken)
    elif failure == "session":
        monkeypatch.setattr(auth, "get_session_by_token", broken)
    else:
        with closing(db.get_db()) as conn:
            conn.execute("DROP TABLE user_apps")
            conn.commit()
    response = client.get("/api/auth/validate")
    assert response.status_code == 503
    assert response.json == {"ok": False, "authenticated": False, "error": "auth unavailable"}
    assert "entitlements" not in response.json


@pytest.mark.parametrize("role,status", [(None, 401), ("user", 403), ("inactive_admin", 401)])
def test_admin_access_control(client, login, users, role, status):
    if role:
        login("admin" if role == "inactive_admin" else role)
    if role == "inactive_admin":
        db.update_user_active_status(users["admin"], 0, auth.now_utc_iso())
    url = f'/api/admin/users/{users["user"]}/entitlements'
    for path in (url, "/api/admin/apps", "/api/admin/csrf", "/api/admin/users"):
        assert client.get(path).status_code == status
    assert client.post(url, json={"app_key": "writer", "granted": True}).status_code == status
    assert client.post(url, json={"app_key": "writer", "granted": False}).status_code == status
    assert db.list_user_entitlements(users["user"]) == []


def test_admin_grant_revoke_idempotent_and_isolated(client, login, users):
    token = login()
    url = f'/api/admin/users/{users["user"]}/entitlements'
    assert client.get(url).json["entitlements"] == []
    assert client.get("/api/admin/apps").json["items"] == [{"key": "writer", "name": "Sovereign Writer"}]
    for granted in (True, True, False, False):
        response = client.post(url, json={"app_key": "writer", "granted": granted}, headers={"X-CSRF-Token": token})
        assert response.status_code == 200
        assert response.json == {"ok": True, "user_id": users["user"], "entitlements": ["writer"] if granted else []}
        assert client.get(url).json == response.json
        assert db.list_user_entitlements(users["admin"]) == []


@pytest.mark.parametrize("unknown", ["user", "app"])
@pytest.mark.parametrize("granted", [True, False])
def test_unknown_targets(client, login, users, unknown, granted):
    token = login()
    user_id = max(users.values()) + 1 if unknown == "user" else users["user"]
    response = client.post(f"/api/admin/users/{user_id}/entitlements", json={
        "app_key": "missing" if unknown == "app" else "writer", "granted": granted,
    }, headers={"X-CSRF-Token": token})
    assert response.status_code == 404
    assert response.json == {"ok": False, "error": f"{unknown} not found"}


@pytest.mark.parametrize("user_id", ["0", "-1", "abc", "1.0", "9223372036854775808", "9" * 100, "١"])
def test_bad_user_id(client, login, user_id):
    token = login()
    url = f"/api/admin/users/{user_id}/entitlements"
    assert client.get(url).status_code == 400
    assert client.post(url, json={"app_key": "writer", "granted": True}, headers={"X-CSRF-Token": token}).status_code == 400


@pytest.mark.parametrize("key", ["", "Writer", "writer' OR 1=1--", "*", None, [], 1, "a" * 65, "writer\n"])
def test_bad_app_key(client, login, users, key):
    token = login()
    response = client.post(f'/api/admin/users/{users["user"]}/entitlements',
                           json={"app_key": key, "granted": True}, headers={"X-CSRF-Token": token})
    assert response.status_code == 400
    assert db.list_user_entitlements(users["user"]) == []


@pytest.mark.parametrize("payload", [None, [], {}, {"app_key": "writer", "granted": "true"},
                                     {"app_key": "writer", "granted": True, "user_id": "other"}])
def test_bad_payload(client, login, users, payload):
    token = login()
    response = client.post(f'/api/admin/users/{users["user"]}/entitlements', json=payload, headers={"X-CSRF-Token": token})
    assert response.status_code == 400


@pytest.mark.parametrize("endpoint,payload", [
    ("entitlements", {"app_key": "writer", "granted": True}),
    ("role", {"role": "admin"}), ("status", {"is_active": False}), ("reset-password", {}),
])
@pytest.mark.parametrize("token", [None, "wrong"])
def test_admin_csrf_required(client, login, users, endpoint, payload, token):
    login()
    response = client.post(f'/api/admin/users/{users["user"]}/{endpoint}', json=payload,
                           headers={"X-CSRF-Token": token} if token else {})
    assert response.status_code == 403
    assert response.json["error"] == "invalid csrf token"
    assert db.get_user_by_id(users["user"])["role"] == "user"
    assert db.list_user_entitlements(users["user"]) == []


def test_user_cannot_self_grant_or_promote(client, login, users):
    login("user")
    with closing(db.get_db()) as conn:
        token = conn.execute("SELECT csrf_token FROM sessions WHERE user_id = ?", (users["user"],)).fetchone()[0]
    headers = {"X-CSRF-Token": token}
    assert client.post(f'/api/admin/users/{users["user"]}/role', json={"role": "admin"}, headers=headers).status_code == 403
    assert client.post(f'/api/admin/users/{users["user"]}/entitlements',
                       json={"app_key": "writer", "granted": True, "role": "admin"}, headers=headers).status_code == 403
    assert db.list_user_entitlements(users["user"]) == []


def test_csrf_session_bound(client, login, users):
    previous_token = login()
    login()
    response = client.post(f'/api/admin/users/{users["user"]}/entitlements',
                           json={"app_key": "writer", "granted": True}, headers={"X-CSRF-Token": previous_token})
    assert response.status_code == 403


def test_admin_no_cors_or_cache(client, login, users):
    login()
    for path in ("/api/admin/csrf", "/api/admin/apps", "/api/admin/users", "/admin/users",
                 f'/api/admin/users/{users["user"]}/entitlements'):
        response = client.get(path, headers={"Origin": "https://apps.innosocia.dk"})
        assert "Access-Control-Allow-Origin" not in response.headers
        assert response.headers["Cache-Control"] == "no-store"
    response = client.options("/api/admin/unknown", headers={"Origin": "https://apps.innosocia.dk"})
    assert "Access-Control-Allow-Origin" not in response.headers


def test_admin_database_failure(client, login, users):
    token = login()
    with closing(db.get_db()) as conn:
        conn.execute("CREATE TRIGGER fail_grant AFTER INSERT ON user_apps BEGIN SELECT RAISE(FAIL, 'private detail'); END")
        conn.commit()
    response = client.post(f'/api/admin/users/{users["user"]}/entitlements',
                           json={"app_key": "writer", "granted": True}, headers={"X-CSRF-Token": token})
    assert response.status_code == 503
    assert response.json == {"ok": False, "error": "service unavailable"}
    assert db.list_user_entitlements(users["user"]) == []
