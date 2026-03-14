import os
import secrets
from datetime import datetime, timedelta, timezone
from urllib.parse import quote

from flask import Flask, jsonify, request, make_response
from werkzeug.security import generate_password_hash, check_password_hash

from db import (
    init_db,
    user_count,
    get_user_by_username,
    get_user_by_email,
    get_user_by_id,
    insert_user,
    update_last_login,
    update_user_password,
    update_user_profile,
    insert_session,
    get_session_by_token,
    revoke_session,
    touch_session,
)

app = Flask(__name__)

SESSION_COOKIE_NAME = os.getenv("SESSION_COOKIE_NAME", "sovereign_session")
SESSION_DAYS = int(os.getenv("SESSION_DAYS", "7"))
COOKIE_DOMAIN = os.getenv("COOKIE_DOMAIN") or None
COOKIE_SECURE = os.getenv("COOKIE_SECURE", "false").lower() == "true"
ALLOW_REGISTRATION = os.getenv("ALLOW_REGISTRATION", "false").lower() == "true"

ALLOWED_ORIGINS = {
    "https://strength.innosocia.dk",
    "https://plants.innosocia.dk",
    "https://finance.innosocia.dk",
    "https://auth.innosocia.dk",
}


@app.after_request
def add_cors_headers(response):
    origin = request.headers.get("Origin", "")
    if origin in ALLOWED_ORIGINS:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Credentials"] = "true"
        response.headers["Vary"] = "Origin"
    return response


@app.route("/api/<path:_any>", methods=["OPTIONS"])
def cors_preflight(_any):
    origin = request.headers.get("Origin", "")
    response = make_response("", 204)
    if origin in ALLOWED_ORIGINS:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Credentials"] = "true"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, PATCH, OPTIONS"
        response.headers["Vary"] = "Origin"
    return response


def now_utc():
    return datetime.now(timezone.utc)


def now_utc_iso():
    return now_utc().isoformat()


def parse_iso_datetime(value):
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except Exception:
        return None


def make_session_tokens():
    return {
        "session_token": secrets.token_urlsafe(32),
        "csrf_token": secrets.token_urlsafe(32),
    }


def set_session_cookie(response, session_token, expires_at):
    response.set_cookie(
        SESSION_COOKIE_NAME,
        session_token,
        expires=expires_at,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="Lax",
        domain=COOKIE_DOMAIN,
        path="/",
    )
    return response


def clear_session_cookie(response):
    response.set_cookie(
        SESSION_COOKIE_NAME,
        "",
        expires=0,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="Lax",
        domain=COOKIE_DOMAIN,
        path="/",
    )
    return response


def get_current_auth():
    session_token = request.cookies.get(SESSION_COOKIE_NAME)
    if not session_token:
        return None, None

    session_row = get_session_by_token(session_token)
    if session_row is None:
        return None, None

    if int(session_row["is_revoked"]) != 0:
        return None, None

    expires_at = parse_iso_datetime(session_row["expires_at"])
    if expires_at is None or expires_at <= now_utc():
        return None, None

    user = get_user_by_id(session_row["user_id"])
    if user is None:
        return None, None

    if int(user["is_active"]) != 1:
        return None, None

    touch_session(session_token, now_utc_iso())
    return user, session_row


def get_safe_return_to(default="https://strength.innosocia.dk"):
    raw = str(request.args.get("return_to", "")).strip()
    if not raw:
        return default

    allowed_prefixes = (
        "https://strength.innosocia.dk",
        "https://plants.innosocia.dk",
        "https://finance.innosocia.dk",
        "https://auth.innosocia.dk",
    )
    if raw.startswith(allowed_prefixes):
        return raw
    return default


def create_session_response(user):
    now_dt = now_utc()
    now_iso = now_dt.isoformat()
    expires_dt = now_dt + timedelta(days=SESSION_DAYS)
    expires_iso = expires_dt.isoformat()

    tokens = make_session_tokens()

    insert_session(
        user_id=user["id"],
        session_token=tokens["session_token"],
        csrf_token=tokens["csrf_token"],
        created_at=now_iso,
        expires_at=expires_iso,
        last_seen_at=now_iso,
        ip_address=request.headers.get("X-Real-IP", request.remote_addr),
        user_agent=request.headers.get("User-Agent"),
    )

    update_last_login(user["id"], now_iso)

    response = make_response(jsonify({
        "ok": True,
        "user": {
            "id": user["id"],
            "username": user["username"],
            "email": user["email"],
            "role": user["role"],
        }
    }), 200)

    return set_session_cookie(response, tokens["session_token"], expires_dt)


@app.get("/api/health")
def health():
    return jsonify({
        "ok": True,
        "service": "sovereign-core-auth"
    })


@app.get("/api/auth/me")
def auth_me():
    user, session_row = get_current_auth()
    if user is None:
        return jsonify({
            "ok": True,
            "authenticated": False,
            "user": None
        }), 200

    return jsonify({
        "ok": True,
        "authenticated": True,
        "user": {
            "id": user["id"],
            "username": user["username"],
            "email": user["email"],
            "role": user["role"],
        }
    }), 200


@app.get("/api/auth/validate")
def auth_validate():
    user, session_row = get_current_auth()
    if user is None:
        return jsonify({
            "ok": False,
            "authenticated": False
        }), 401

    return jsonify({
        "ok": True,
        "authenticated": True,
        "user_id": user["id"],
        "username": user["username"],
        "role": user["role"],
    }), 200


@app.post("/api/auth/bootstrap-admin")
def bootstrap_admin():
    init_db()

    if user_count() > 0:
        return jsonify({
            "ok": False,
            "error": "admin already bootstrapped"
        }), 409

    payload = request.get_json(silent=True) or {}
    username = str(payload.get("username", "")).strip()
    email = str(payload.get("email", "")).strip() or None
    password = str(payload.get("password", "")).strip()

    if not username:
        return jsonify({
            "ok": False,
            "error": "username is required"
        }), 400

    if len(password) < 12:
        return jsonify({
            "ok": False,
            "error": "password must be at least 12 characters"
        }), 400

    existing = get_user_by_username(username)
    if existing is not None:
        return jsonify({
            "ok": False,
            "error": "username already exists"
        }), 409

    if email:
        existing_email = get_user_by_email(email)
        if existing_email is not None:
            return jsonify({
                "ok": False,
                "error": "email already exists"
            }), 409

    now = now_utc_iso()
    password_hash = generate_password_hash(password)

    user_id = insert_user(
        username=username,
        email=email,
        password_hash=password_hash,
        role="admin",
        now=now
    )

    return jsonify({
        "ok": True,
        "user": {
            "id": user_id,
            "username": username,
            "email": email,
            "role": "admin"
        }
    }), 201


@app.post("/api/auth/register")
def auth_register():
    if not ALLOW_REGISTRATION:
        return jsonify({
            "ok": False,
            "error": "registration is disabled"
        }), 403

    payload = request.get_json(silent=True) or {}
    username = str(payload.get("username", "")).strip()
    email = str(payload.get("email", "")).strip() or None
    password = str(payload.get("password", "")).strip()
    confirm_password = str(payload.get("confirm_password", "")).strip()

    if not username:
        return jsonify({
            "ok": False,
            "error": "username is required"
        }), 400

    if len(password) < 12:
        return jsonify({
            "ok": False,
            "error": "password must be at least 12 characters"
        }), 400

    if password != confirm_password:
        return jsonify({
            "ok": False,
            "error": "passwords do not match"
        }), 400

    existing = get_user_by_username(username)
    if existing is not None:
        return jsonify({
            "ok": False,
            "error": "username already exists"
        }), 409

    if email:
        existing_email = get_user_by_email(email)
        if existing_email is not None:
            return jsonify({
                "ok": False,
                "error": "email already exists"
            }), 409

    now = now_utc_iso()
    password_hash = generate_password_hash(password)

    user_id = insert_user(
        username=username,
        email=email,
        password_hash=password_hash,
        role="user",
        now=now
    )

    user = get_user_by_id(user_id)
    return create_session_response(user)


@app.post("/api/auth/login")
def auth_login():
    payload = request.get_json(silent=True) or {}
    username = str(payload.get("username", "")).strip()
    password = str(payload.get("password", "")).strip()

    if not username or not password:
        return jsonify({
            "ok": False,
            "error": "username and password are required"
        }), 400

    user = get_user_by_username(username)
    if user is None:
        return jsonify({
            "ok": False,
            "error": "invalid credentials"
        }), 401

    if int(user["is_active"]) != 1:
        return jsonify({
            "ok": False,
            "error": "user is inactive"
        }), 403

    if not check_password_hash(user["password_hash"], password):
        return jsonify({
            "ok": False,
            "error": "invalid credentials"
        }), 401

    return create_session_response(user)


@app.post("/api/auth/logout")
def auth_logout():
    session_token = request.cookies.get(SESSION_COOKIE_NAME)
    if session_token:
        revoke_session(session_token)

    response = make_response(jsonify({"ok": True}), 200)
    return clear_session_cookie(response)


@app.post("/api/auth/change-password")
def auth_change_password():
    user, session_row = get_current_auth()
    if user is None:
        return jsonify({
            "ok": False,
            "error": "not authenticated"
        }), 401

    payload = request.get_json(silent=True) or {}
    current_password = str(payload.get("current_password", "")).strip()
    new_password = str(payload.get("new_password", "")).strip()
    confirm_password = str(payload.get("confirm_password", "")).strip()

    if not current_password or not new_password or not confirm_password:
        return jsonify({
            "ok": False,
            "error": "all password fields are required"
        }), 400

    if not check_password_hash(user["password_hash"], current_password):
        return jsonify({
            "ok": False,
            "error": "current password is incorrect"
        }), 400

    if len(new_password) < 12:
        return jsonify({
            "ok": False,
            "error": "new password must be at least 12 characters"
        }), 400

    if new_password != confirm_password:
        return jsonify({
            "ok": False,
            "error": "new passwords do not match"
        }), 400

    if current_password == new_password:
        return jsonify({
            "ok": False,
            "error": "new password must be different from current password"
        }), 400

    password_hash = generate_password_hash(new_password)
    update_user_password(user["id"], password_hash, now_utc_iso())

    return jsonify({
        "ok": True,
        "message": "password updated"
    }), 200


@app.post("/api/auth/update-profile")
def auth_update_profile():
    user, session_row = get_current_auth()
    if user is None:
        return jsonify({
            "ok": False,
            "error": "not authenticated"
        }), 401

    payload = request.get_json(silent=True) or {}
    username = str(payload.get("username", "")).strip()
    email = str(payload.get("email", "")).strip() or None

    if not username:
        return jsonify({
            "ok": False,
            "error": "username is required"
        }), 400

    existing_user = get_user_by_username(username)
    if existing_user is not None and int(existing_user["id"]) != int(user["id"]):
        return jsonify({
            "ok": False,
            "error": "username already exists"
        }), 409

    if email:
        existing_email = get_user_by_email(email)
        if existing_email is not None and int(existing_email["id"]) != int(user["id"]):
            return jsonify({
                "ok": False,
                "error": "email already exists"
            }), 409

    update_user_profile(user["id"], username, email, now_utc_iso())
    updated_user = get_user_by_id(user["id"])

    return jsonify({
        "ok": True,
        "message": "profile updated",
        "user": {
            "id": updated_user["id"],
            "username": updated_user["username"],
            "email": updated_user["email"],
            "role": updated_user["role"],
        }
    }), 200


@app.get("/")
def root():
    return (
        '<!doctype html><html lang="da"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        '<title>Sovereign Core Auth</title></head>'
        '<body style="font-family:system-ui,sans-serif;background:#111;color:#eee;padding:32px">'
        '<h1>Sovereign Core Auth</h1>'
        '<p>Auth-service kører.</p>'
        '<p><a href="/login" style="color:#9fd3a8">Gå til login</a></p>'
        '<p><a href="/account" style="color:#9fd3a8">Gå til konto</a></p>'
        '<p><a href="/register" style="color:#9fd3a8">Opret bruger</a></p>'
        '</body></html>'
    )


@app.get("/login")
def login_page():
    return_to = get_safe_return_to()
    return_to_js = quote(return_to, safe=":/?&=%-_~.#")
    register_link = (
        f'<a class="linkbtn" id="registerLink" href="/register?return_to={return_to_js}">Har du ikke en konto? Opret bruger</a>'
        if ALLOW_REGISTRATION else ""
    )

    return f"""
<!doctype html>
<html lang="da">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Sovereign Login</title>
  <style>
    body{{
      margin:0;
      font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;
      background:#111;
      color:#f3f3f3;
      display:grid;
      place-items:center;
      min-height:100vh;
    }}
    .card{{
      width:min(420px, calc(100vw - 32px));
      background:#1b1b1b;
      border:1px solid #2c2c2c;
      border-radius:16px;
      padding:20px;
    }}
    h1{{margin:0 0 10px}}
    p{{color:#b9b9b9}}
    label{{
      display:grid;
      gap:6px;
      margin-top:12px;
      color:#b9b9b9;
      font-size:.95rem;
    }}
    input,button,a{{
      width:100%;
      border-radius:10px;
      border:1px solid #2c2c2c;
      background:#151515;
      color:#f3f3f3;
      padding:10px 12px;
      font:inherit;
      box-sizing:border-box;
      text-decoration:none;
    }}
    button{{
      margin-top:14px;
      cursor:pointer;
      background:#242424;
      font-weight:600;
    }}
    .small{{
      margin-top:10px;
      color:#b9b9b9;
      font-size:.95rem;
    }}
    .err{{color:#e7c27d}}
    .linkbtn{{
      display:block;
      text-align:center;
      margin-top:12px;
    }}
  </style>
</head>
<body>
  <div class="card">
    <h1>Sovereign Login</h1>
    <p>Log ind for at fortsætte til din Sovereign-app.</p>

    <form id="loginForm">
      <label>
        Brugernavn
        <input id="username" name="username" autocomplete="username" required>
      </label>

      <label>
        Password
        <input id="password" name="password" type="password" autocomplete="current-password" required>
      </label>

      <button type="submit">Log ind</button>
    </form>

    {register_link}

    <a class="linkbtn" id="accountLink" href="/account?return_to={return_to_js}">Gå til konto</a>

    <div id="status" class="small">Tjekker loginstatus…</div>
  </div>

  <script>
    const returnTo = {return_to!r};

    async function goIfAlreadyLoggedIn(){{
      try{{
        const res = await fetch("/api/auth/me", {{
          credentials: "include",
          cache: "no-store"
        }});
        const data = await res.json();
        if (data && data.authenticated){{
          location.href = returnTo;
          return true;
        }}
      }}catch(err){{}}
      return false;
    }}

    async function main(){{
      const status = document.getElementById("status");
      const already = await goIfAlreadyLoggedIn();
      if (!already){{
        status.textContent = "Ikke logget ind endnu.";
      }}

      document.getElementById("loginForm").addEventListener("submit", async (ev) => {{
        ev.preventDefault();
        status.textContent = "Logger ind…";
        status.classList.remove("err");

        const username = document.getElementById("username").value.trim();
        const password = document.getElementById("password").value;

        try{{
          const res = await fetch("/api/auth/login", {{
            method: "POST",
            credentials: "include",
            headers: {{"Content-Type": "application/json"}},
            body: JSON.stringify({{username, password}})
          }});

          const data = await res.json().catch(() => ({{}}));
          if (!res.ok){{
            throw new Error(data?.error || `HTTP ${{res.status}}`);
          }}

          status.textContent = "Login OK. Sender videre…";
          location.href = returnTo;
        }}catch(err){{
          status.textContent = "Fejl: " + (err?.message || String(err));
          status.classList.add("err");
        }}
      }});
    }}

    main();
  </script>
</body>
</html>
"""


@app.get("/register")
def register_page():
    return_to = get_safe_return_to()
    return_to_js = quote(return_to, safe=":/?&=%-_~.#")

    if not ALLOW_REGISTRATION:
        return (
            '<!doctype html><html lang="da"><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width,initial-scale=1">'
            '<title>Sovereign Register</title></head>'
            '<body style="font-family:system-ui,sans-serif;background:#111;color:#eee;padding:32px">'
            '<h1>Sovereign Register</h1>'
            '<p>Brugeroprettelse er deaktiveret.</p>'
            '<p><a href="/login" style="color:#9fd3a8">Gå til login</a></p>'
            '</body></html>'
        )

    return f"""
<!doctype html>
<html lang="da">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Opret bruger</title>
  <style>
    body{{
      margin:0;
      font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;
      background:#111;
      color:#f3f3f3;
      display:grid;
      place-items:center;
      min-height:100vh;
    }}
    .card{{
      width:min(460px, calc(100vw - 32px));
      background:#1b1b1b;
      border:1px solid #2c2c2c;
      border-radius:16px;
      padding:20px;
    }}
    h1{{margin:0 0 10px}}
    p{{color:#b9b9b9}}
    form{{display:grid;gap:12px}}
    label{{
      display:grid;
      gap:6px;
      color:#b9b9b9;
      font-size:.95rem;
    }}
    input,button,a{{
      width:100%;
      border-radius:10px;
      border:1px solid #2c2c2c;
      background:#151515;
      color:#f3f3f3;
      padding:10px 12px;
      font:inherit;
      box-sizing:border-box;
      text-decoration:none;
    }}
    button{{
      cursor:pointer;
      background:#242424;
      font-weight:600;
      margin-top:8px;
    }}
    .small{{
      margin-top:10px;
      color:#b9b9b9;
      font-size:.95rem;
    }}
    .err{{color:#e7c27d}}
    .linkbtn{{display:block;text-align:center;margin-top:12px}}
  </style>
</head>
<body>
  <div class="card">
    <h1>Opret bruger</h1>
    <p>Opret en konto og fortsæt direkte til din Sovereign-app.</p>

    <form id="registerForm">
      <label>
        Brugernavn
        <input id="username" name="username" autocomplete="username" required>
      </label>

      <label>
        E-mail
        <input id="email" name="email" type="email" autocomplete="email">
      </label>

      <label>
        Password
        <input id="password" name="password" type="password" autocomplete="new-password" required>
      </label>

      <label>
        Gentag password
        <input id="confirm_password" name="confirm_password" type="password" autocomplete="new-password" required>
      </label>

      <button type="submit">Opret konto</button>
    </form>

    <a class="linkbtn" href="/login?return_to={return_to_js}">Har du allerede en konto? Log ind</a>

    <div id="status" class="small">Klar.</div>
  </div>

  <script>
    const returnTo = {return_to!r};
    const status = document.getElementById("status");

    document.getElementById("registerForm").addEventListener("submit", async (ev) => {{
      ev.preventDefault();
      status.textContent = "Opretter bruger…";
      status.classList.remove("err");

      const username = document.getElementById("username").value.trim();
      const email = document.getElementById("email").value.trim();
      const password = document.getElementById("password").value;
      const confirm_password = document.getElementById("confirm_password").value;

      try{{
        const res = await fetch("/api/auth/register", {{
          method: "POST",
          credentials: "include",
          headers: {{"Content-Type": "application/json"}},
          body: JSON.stringify({{
            username,
            email,
            password,
            confirm_password
          }})
        }});

        const data = await res.json().catch(() => ({{}}));
        if (!res.ok){{
          throw new Error(data?.error || `HTTP ${{res.status}}`);
        }}

        status.textContent = "Bruger oprettet. Sender videre…";
        location.href = returnTo;
      }}catch(err){{
        status.textContent = "Fejl: " + (err?.message || String(err));
        status.classList.add("err");
      }}
    }});
  </script>
</body>
</html>
"""


@app.get("/account")
def account_page():
    user, session_row = get_current_auth()
    return_to = get_safe_return_to()

    if user is None:
        login_target = f"/login?return_to={quote(request.url, safe=':/?&=%-_~.#')}"
        return (
            '<!doctype html><html lang="da"><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width,initial-scale=1">'
            '<title>Sovereign Account</title></head>'
            '<body style="font-family:system-ui,sans-serif;background:#111;color:#eee;padding:32px">'
            '<h1>Sovereign Account</h1>'
            '<p>Du er ikke logget ind.</p>'
            f'<p><a href="{login_target}" style="color:#9fd3a8">Gå til login</a></p>'
            '</body></html>'
        )

    return_to_js = quote(return_to, safe=":/?&=%-_~.#")
    username = user["username"]
    email = user["email"] or ""
    role = user["role"]
    last_login_at = user["last_login_at"] or "ukendt"

    return f"""
<!doctype html>
<html lang="da">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Sovereign Account</title>
  <style>
    body{{
      margin:0;
      font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;
      background:#111;
      color:#f3f3f3;
      display:grid;
      place-items:center;
      min-height:100vh;
      padding:16px 0;
    }}
    .card{{
      width:min(560px, calc(100vw - 32px));
      background:#1b1b1b;
      border:1px solid #2c2c2c;
      border-radius:16px;
      padding:20px;
    }}
    h1,h2{{margin:0 0 10px}}
    p{{color:#b9b9b9}}
    .meta{{
      display:grid;
      gap:8px;
      margin:16px 0 22px;
      padding:14px;
      border:1px solid #2c2c2c;
      border-radius:12px;
      background:#151515;
    }}
    .line{{color:#b9b9b9}}
    .line strong{{color:#f3f3f3}}
    form{{
      display:grid;
      gap:12px;
      margin-top:8px;
    }}
    label{{
      display:grid;
      gap:6px;
      color:#b9b9b9;
      font-size:.95rem;
    }}
    input,button,a{{
      width:100%;
      border-radius:10px;
      border:1px solid #2c2c2c;
      background:#151515;
      color:#f3f3f3;
      padding:10px 12px;
      font:inherit;
      box-sizing:border-box;
      text-decoration:none;
    }}
    button{{
      cursor:pointer;
      background:#242424;
      font-weight:600;
    }}
    .row{{
      display:flex;
      gap:10px;
      flex-wrap:wrap;
      margin-top:16px;
    }}
    .row a, .row button{{
      width:auto;
      min-width:160px;
      text-align:center;
    }}
    .small{{
      margin-top:10px;
      color:#b9b9b9;
      font-size:.95rem;
    }}
    .ok{{color:#9fd3a8}}
    .err{{color:#e7c27d}}
    .section{{
      margin-top:22px;
      padding-top:18px;
      border-top:1px solid #2c2c2c;
    }}
  </style>
</head>
<body>
  <div class="card">
    <h1>Sovereign Account</h1>
    <p>Din centrale konto til Sovereign-suiten.</p>

    <div class="meta">
      <div class="line"><strong>Brugernavn:</strong> {username}</div>
      <div class="line"><strong>E-mail:</strong> {email or "ikke angivet"}</div>
      <div class="line"><strong>Rolle:</strong> {role}</div>
      <div class="line"><strong>Seneste login:</strong> {last_login_at}</div>
    </div>

    <div class="section">
      <h2>Konto-oplysninger</h2>
      <form id="profileForm">
        <label>
          Brugernavn
          <input id="profile_username" name="profile_username" value="{username}" autocomplete="username" required>
        </label>

        <label>
          E-mail
          <input id="profile_email" name="profile_email" type="email" value="{email}" autocomplete="email">
        </label>

        <button type="submit">Gem konto-oplysninger</button>
      </form>

      <div id="profileStatus" class="small">Klar.</div>
    </div>

    <div class="section">
      <h2>Skift password</h2>
      <form id="passwordForm">
        <label>
          Nuværende password
          <input id="current_password" name="current_password" type="password" autocomplete="current-password" required>
        </label>

        <label>
          Nyt password
          <input id="new_password" name="new_password" type="password" autocomplete="new-password" required>
        </label>

        <label>
          Gentag nyt password
          <input id="confirm_password" name="confirm_password" type="password" autocomplete="new-password" required>
        </label>

        <button type="submit">Skift password</button>
      </form>

      <div id="passwordStatus" class="small">Klar.</div>
    </div>

    <div class="row">
      <a id="backLink" href="{return_to_js}">Tilbage til app</a>
      <button id="logoutBtn" type="button">Log ud</button>
    </div>
  </div>

  <script>
    const returnTo = {return_to!r};

    const profileStatusEl = document.getElementById("profileStatus");
    const passwordStatusEl = document.getElementById("passwordStatus");

    document.getElementById("profileForm").addEventListener("submit", async (ev) => {{
      ev.preventDefault();
      profileStatusEl.textContent = "Gemmer konto-oplysninger…";
      profileStatusEl.className = "small";

      const username = document.getElementById("profile_username").value.trim();
      const email = document.getElementById("profile_email").value.trim();

      try{{
        const res = await fetch("/api/auth/update-profile", {{
          method: "POST",
          credentials: "include",
          headers: {{"Content-Type": "application/json"}},
          body: JSON.stringify({{ username, email }})
        }});

        const data = await res.json().catch(() => ({{}}));
        if (!res.ok){{
          throw new Error(data?.error || `HTTP ${{res.status}}`);
        }}

        profileStatusEl.textContent = data?.message || "Konto-oplysninger opdateret.";
        profileStatusEl.className = "small ok";
        location.reload();
      }}catch(err){{
        profileStatusEl.textContent = "Fejl: " + (err?.message || String(err));
        profileStatusEl.className = "small err";
      }}
    }});

    document.getElementById("passwordForm").addEventListener("submit", async (ev) => {{
      ev.preventDefault();
      passwordStatusEl.textContent = "Opdaterer password…";
      passwordStatusEl.className = "small";

      const current_password = document.getElementById("current_password").value;
      const new_password = document.getElementById("new_password").value;
      const confirm_password = document.getElementById("confirm_password").value;

      try{{
        const res = await fetch("/api/auth/change-password", {{
          method: "POST",
          credentials: "include",
          headers: {{"Content-Type": "application/json"}},
          body: JSON.stringify({{
            current_password,
            new_password,
            confirm_password
          }})
        }});

        const data = await res.json().catch(() => ({{}}));
        if (!res.ok){{
          throw new Error(data?.error || `HTTP ${{res.status}}`);
        }}

        passwordStatusEl.textContent = data?.message || "Password opdateret.";
        passwordStatusEl.className = "small ok";
        document.getElementById("passwordForm").reset();
      }}catch(err){{
        passwordStatusEl.textContent = "Fejl: " + (err?.message || String(err));
        passwordStatusEl.className = "small err";
      }}
    }});

    document.getElementById("logoutBtn").addEventListener("click", async () => {{
      try{{
        await fetch("/api/auth/logout", {{
          method: "POST",
          credentials: "include"
        }});
      }}catch(err){{}}
      location.href = `/login?return_to=${{encodeURIComponent(returnTo)}}`;
    }});
  </script>
</body>
</html>
"""


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=8001, debug=False)
