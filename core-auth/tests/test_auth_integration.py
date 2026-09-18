import app as auth
import db


def test_login_cookie_me_validate_logout(client, users):
    assert client.get("/api/auth/me").json == {"ok": True, "authenticated": False, "user": None}
    assert client.post("/api/auth/login", json={"username": "user", "password": "wrong"}).status_code == 401
    response = client.post("/api/auth/login", json={"username": "user", "password": "test-password-long"})
    assert response.status_code == 200
    cookie = response.headers["Set-Cookie"]
    assert "HttpOnly" in cookie and "SameSite=Lax" in cookie and "Path=/" in cookie
    assert client.get("/api/auth/me").json["user"]["id"] == users["user"]
    assert client.get("/api/auth/validate").json["entitlements"] == []
    assert client.post("/api/auth/logout").status_code == 200
    assert client.get("/api/auth/validate").status_code == 401


def test_admin_existing_actions_and_password_reset(client, login, users):
    token = login()
    headers = {"X-CSRF-Token": token}
    prefix = f'/api/admin/users/{users["user"]}'
    assert len(client.get("/api/admin/users").json["items"]) == 2
    assert client.post(prefix + "/role", json={"role": "admin"}, headers=headers).json["user"]["role"] == "admin"
    assert db.list_user_entitlements(users["user"]) == []
    assert client.post(prefix + "/role", json={"role": "user"}, headers=headers).status_code == 200
    assert client.post(prefix + "/status", json={"is_active": False}, headers=headers).json["user"]["is_active"] is False
    assert client.post(prefix + "/status", json={"is_active": True}, headers=headers).status_code == 200
    reset = client.post(prefix + "/reset-password", json={}, headers=headers)
    assert reset.status_code == 200
    client.post("/api/auth/logout")
    response = client.post("/api/auth/login", json={"username": "user", "password": reset.json["temporary_password"]})
    assert response.json["user"]["must_change_password"] is True
    assert client.post("/api/auth/complete-password-reset", json={
        "new_password": "replacement-password-long", "confirm_password": "replacement-password-long",
    }).status_code == 200
    assert client.get("/api/auth/me").json["user"]["must_change_password"] is False


def test_bootstrap_and_registration_no_grants(client, monkeypatch):
    response = client.post("/api/auth/bootstrap-admin", json={"username": "owner-test", "password": "test-password-long"})
    assert response.status_code == 201
    assert db.list_user_entitlements(response.json["user"]["id"]) == []
    assert client.post("/api/auth/bootstrap-admin", json={}).status_code == 409
    monkeypatch.setattr(auth, "ALLOW_REGISTRATION", False)
    assert client.post("/api/auth/register", json={}).status_code == 403
    monkeypatch.setattr(auth, "ALLOW_REGISTRATION", True)
    response = client.post("/api/auth/register", json={
        "username": "registered-test", "password": "test-password-long", "confirm_password": "test-password-long",
    })
    assert response.status_code == 200
    assert client.get("/api/auth/validate").json["entitlements"] == []


def test_profile_password_and_pages(client, login):
    login("user")
    assert client.post("/api/auth/update-profile", json={"username": "changed-test"}).status_code == 200
    assert client.post("/api/auth/change-password", json={
        "current_password": "test-password-long", "new_password": "replacement-password-long",
        "confirm_password": "replacement-password-long",
    }).status_code == 200
    for page in ("/", "/login", "/account", "/register"):
        assert client.get(page).status_code == 200
    assert "Vis appadgang" not in client.get("/admin/users").text
    login("admin")
    page = client.get("/admin/users")
    assert "Vis appadgang" in page.text and "Tilbagekald" in page.text and "X-CSRF-Token" in page.text


def test_existing_cors_integration(client):
    for origin in auth.ALLOWED_ORIGINS:
        response = client.get("/api/auth/validate", headers={"Origin": origin})
        assert response.status_code == 401
        assert response.headers["Access-Control-Allow-Origin"] == origin
        assert response.headers["Access-Control-Allow-Credentials"] == "true"
    assert "Access-Control-Allow-Origin" not in client.get("/api/auth/validate", headers={"Origin": "https://untrusted.invalid"}).headers
    response = client.options("/api/auth/login", headers={"Origin": "https://apps.innosocia.dk"})
    assert response.headers["Access-Control-Allow-Origin"] == "https://apps.innosocia.dk"
