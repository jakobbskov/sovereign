"""Sovereign Chat redirects use the shared validator without expanding CORS."""
from urllib.parse import parse_qs, urlsplit

import pytest

import app as auth
from test_localization import link_to, return_to


@pytest.mark.parametrize("target", [
    "https://chat.innosocia.dk",
    "https://chat.innosocia.dk/",
    "https://chat.innosocia.dk/c/abc",
    "https://chat.innosocia.dk/?project=book#message-4",
])
@pytest.mark.parametrize("page", ["/login", "/register"])
def test_chat_destinations_render_unchanged(client, monkeypatch, target, page):
    monkeypatch.setattr(auth, "ALLOW_REGISTRATION", True)
    response = client.get(page, query_string={"return_to": target})
    assert response.status_code == 200
    assert "Location" not in response.headers
    assert return_to(response.text) == target


@pytest.mark.parametrize("target", [
    "http://chat.innosocia.dk",
    "https://chat.innosocia.dk.evil.example",
    "https://evil-chat.innosocia.dk",
    "https://sub.chat.innosocia.dk",
    "https://chat.innosocia.dk@evil.example",
    "https://evil.example@chat.innosocia.dk",
    "https://chat.innosocia.dk:443",
    "//chat.innosocia.dk",
    "/chat",
    "javascript:alert(1)",
    "https://chat.innosocia.dk\\\\@evil.example",
    "https://chat.innosocia.dk\\r\\nLocation: https://evil.example",
])
def test_unsafe_chat_returns_fall_back(client, monkeypatch, target):
    monkeypatch.setattr(auth, "ALLOW_REGISTRATION", True)
    fallback = "https://strength.innosocia.dk"
    assert auth.safe_return_to(target) == fallback
    for page in ("/login", "/register"):
        response = client.get(page, query_string={"return_to": target})
        assert response.status_code == 200
        assert return_to(response.text) == fallback


def test_chat_redirect_approval_does_not_expand_cors(client):
    chat = "https://chat.innosocia.dk"
    writer = "https://writer.innosocia.dk"
    assert auth.ALLOWED_RETURN_ORIGINS - auth.ALLOWED_ORIGINS == {writer, chat}
    for path in ("/api/auth/validate", "/api/admin/csrf"):
        response = client.get(path, headers={"Origin": chat})
        assert response.status_code == 401
        assert "Access-Control-Allow-Origin" not in response.headers
        preflight = client.options(path, headers={"Origin": chat})
        assert "Access-Control-Allow-Origin" not in preflight.headers
