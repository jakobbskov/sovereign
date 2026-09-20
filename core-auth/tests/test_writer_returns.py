"""Writer redirects use the shared validator, never app authorization."""
from urllib.parse import parse_qs, urlsplit

import pytest

import app as auth
from test_localization import link_to, return_to


@pytest.mark.parametrize("target", [
    "https://writer.innosocia.dk",
    "https://writer.innosocia.dk/",
    "https://writer.innosocia.dk/projects",
    "https://writer.innosocia.dk/projects?open=1",
    "https://writer.innosocia.dk/projects#scene",
])
@pytest.mark.parametrize("page", ["/login", "/register"])
def test_writer_destinations_render_unchanged(client, monkeypatch, target, page):
    monkeypatch.setattr(auth, "ALLOW_REGISTRATION", True)
    response = client.get(page, query_string={"return_to": target})
    assert response.status_code == 200
    # These pages navigate in JavaScript, not HTTP redirects. Real JS flows are
    # executed for Writer in test_localization, including login/register/logout.
    assert "Location" not in response.headers
    assert return_to(response.text) == target


@pytest.mark.parametrize("target", [
    "http://writer.innosocia.dk",
    "https://writer.innosocia.dk.evil.example",
    "https://evil-writer.innosocia.dk",
    "https://sub.writer.innosocia.dk",
    "https://writer.innosocia.dk@evil.example",
    "https://evil.example@writer.innosocia.dk",
    "https://writer.innosocia.dk:444",
    "https://writer.innosocia.dk:443",  # Explicit ports are not approved origins.
    "//writer.innosocia.dk", "/projects", "javascript:alert(1)", "data:text/html,test",
    "https://writer.innosocia.dk\\@evil.example",
    "https://writer.innosocia.dk/\\evil.example",
    "https://writer.innosocia.dk%2eevil.example",
    "https://%77riter.innosocia.dk",
    "https://writer.innosocia.dk%40evil.example",
    "https://evil.example%40writer.innosocia.dk",
    "https://writer.innosocia.dk%2f.evil.example",
    "https://writer.innosocia.dk%5c@evil.example",
    "https://writer.innosocia.dk%3a444",
    "https://writer.innosocia.dk%0d%0a.evil.example",
    "https%3a%2f%2fwriter.innosocia.dk",
    "https://writer.innosocia.dk\r\nLocation: https://evil.example",
    "\r\nhttps://writer.innosocia.dk",
    "https://writer.innosocia.dk\r\n",
    "\thttps://writer.innosocia.dk",
    "https://writer.innosocia.dk/\x00",
    "https://writer.innosocia.dk/\x1f",
    "https://writer.innosocia.dk/\x7f",
])
def test_unsafe_writer_returns_fall_back_through_all_pages(client, monkeypatch, target):
    monkeypatch.setattr(auth, "ALLOW_REGISTRATION", True)
    fallback = "https://strength.innosocia.dk"
    assert auth.safe_return_to(target) == fallback
    for page in ("/login", "/register"):
        response = client.get(page, query_string={"return_to": target})
        assert response.status_code == 200
        assert "Location" not in response.headers
        assert return_to(response.text) == fallback
    account = client.get("/account", query_string={"return_to": target})
    login_url = link_to(account.text, "/login")
    account_url = parse_qs(urlsplit(login_url).query)["return_to"][0]
    assert parse_qs(urlsplit(account_url).query)["return_to"] == [fallback]


@pytest.mark.parametrize("lang", ["da", "en"])
def test_writer_account_round_trip_does_not_grant_entitlement(client, login, lang):
    target = "https://writer.innosocia.dk/projects?open=1#scene"
    account = client.get("/account", query_string={"return_to": target, "lang": lang},
                         headers={"Host": "evil.example"})
    assert account.status_code == 200
    assert "Location" not in account.headers
    login_url = link_to(account.text, "/login")
    query = parse_qs(urlsplit(login_url).query)
    assert query["lang"] == [lang]
    account_url = query["return_to"][0]
    assert urlsplit(account_url).netloc == "auth.innosocia.dk"
    assert parse_qs(urlsplit(account_url).query) == {"return_to": [target], "lang": [lang]}
    login("user")
    assert client.get("/api/auth/validate").json["entitlements"] == []
    # The login fixture's cookie belongs to localhost; the trusted public origin
    # is checked above, so follow its path/query on the same test client host.
    destination = urlsplit(account_url)
    account = client.get(destination.path + "?" + destination.query)
    assert return_to(account.text) == target
    assert client.get("/api/auth/validate").json["entitlements"] == []


def test_redirect_approval_does_not_expand_cors_or_admin_access(client):
    origin = "https://writer.innosocia.dk"
    assert auth.ALLOWED_RETURN_ORIGINS - auth.ALLOWED_ORIGINS == {origin}
    for path in ("/api/auth/validate", "/api/admin/csrf"):
        response = client.get(path, headers={"Origin": origin})
        assert response.status_code == 401
        assert "Access-Control-Allow-Origin" not in response.headers
        preflight = client.options(path, headers={"Origin": origin})
        assert "Access-Control-Allow-Origin" not in preflight.headers
