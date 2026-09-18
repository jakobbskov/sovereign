import sys
import sqlite3
from pathlib import Path
from urllib.parse import unquote, urlsplit

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import db
import app as auth


@pytest.fixture(autouse=True)
def isolated_database(tmp_path, monkeypatch):
    # No initialization at import time; every test points to its own temporary file.
    original_connect = sqlite3.connect
    def isolated_connect(database, *args, **kwargs):
        location = str(database)
        if location.startswith("file:"):
            location = unquote(urlsplit(location).path)
        if not Path(location).resolve().is_relative_to(tmp_path.resolve()):
            raise AssertionError("Tests may only open databases inside their temporary directory")
        return original_connect(database, *args, **kwargs)
    monkeypatch.setattr(sqlite3, "connect", isolated_connect)
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "auth-test.sqlite")
    db.DB_PATH.touch()
    db.init_db()
    auth.app.config.update(TESTING=True)
    return db.DB_PATH


@pytest.fixture
def client():
    return auth.app.test_client()


@pytest.fixture
def users():
    return {
        role: db.insert_user(role, None, auth.generate_password_hash("test-password-long"), role, auth.now_utc_iso())
        for role in ("admin", "user")
    }


@pytest.fixture
def login(client, users):
    def authenticate(role="admin"):
        response = client.post("/api/auth/login", json={"username": role, "password": "test-password-long"})
        assert response.status_code == 200
        return client.get("/api/admin/csrf").get_json().get("csrf_token")
    return authenticate
