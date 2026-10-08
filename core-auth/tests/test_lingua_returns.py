"""Lingua redirects use the shared validator without expanding CORS."""
from urllib.parse import parse_qs, urlsplit

import pytest

import app as auth
from test_localization import return_to


@pytest.mark.parametrize("target", [
    "https://lingua.innosocia.dk",
    "https://lingua.innosocia.dk/",
    "https://lingua.innosocia.dk/today",
    "https://lingua.innosocia.dk/course?unit=4#top",
])
@pytest.mark.parametrize("page", ["/login", "/register"])
def test_lingua_destinations_render_unchanged(client, monkeypatch, target, page):
    monkeypatch.setattr(auth, "ALLOW_REGISTRATION", True)
    response = client.get(page, query_string={"return_to": target})
    assert response.status_code == 200
    assert "Location" not in response.headers
    assert return_to(response.text) == target


@pytest.mark.parametrize("target", [
    "http://lingua.innosocia.dk",
    "https://lingua.innosocia.dk.evil.example",
    "https://evil-lingua.innosocia.dk",
    "https://sub.lingua.innosocia.dk",
    "https://lingua.innosocia.dk@evil.example",
    "https://evil.example@lingua.innosocia.dk",
    "https://lingua.innosocia.dk:443",
    "//lingua.innosocia.dk",
    "/lingua",
    "javascript:alert(1)",
    "https://lingua.innosocia.dk\\@evil.example",
    "https://lingua.innosocia.dk\r\nLocation: https://evil.example",
])
def test_unsafe_lingua_returns_fall_back(client, monkeypatch, target):
    monkeypatch.setattr(auth, "ALLOW_REGISTRATION", True)
    fallback = "https://strength.innosocia.dk"
    assert auth.safe_return_to(target) == fallback
    for page in ("/login", "/register"):
        response = client.get(page, query_string={"return_to": target})
        assert response.status_code == 200
        assert return_to(response.text) == fallback


def test_lingua_redirect_approval_does_not_expand_cors(client):
    lingua = "https://lingua.innosocia.dk"
    assert lingua in auth.ALLOWED_RETURN_ORIGINS
    assert lingua not in auth.ALLOWED_ORIGINS
    for path in ("/api/auth/validate", "/api/admin/csrf"):
        response = client.get(path, headers={"Origin": lingua})
        assert response.status_code == 401
        assert "Access-Control-Allow-Origin" not in response.headers
        preflight = client.options(path, headers={"Origin": lingua})
        assert "Access-Control-Allow-Origin" not in preflight.headers
