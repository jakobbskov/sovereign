import os
import secrets
from datetime import datetime, timedelta, timezone
from urllib.parse import quote, urlparse, parse_qs

from flask import Flask, jsonify, request, make_response
from werkzeug.security import generate_password_hash, check_password_hash

from db import (
    init_db,
    user_count,
    list_users,
    get_user_by_username,
    get_user_by_email,
    get_user_by_id,
    insert_user,
    update_last_login,
    update_user_password,
    update_user_profile,
    update_user_role,
    update_user_active_status,
    set_user_must_change_password,
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


def get_request_lang(default="da"):
    lang = str(request.args.get("lang", "")).strip().lower()
    if lang in ("da", "en"):
        return lang

    return_to = str(request.args.get("return_to", "")).strip()
    if return_to:
        try:
            parsed = urlparse(return_to)
            qs = parse_qs(parsed.query)
            inherited = str((qs.get("lang") or [""])[0]).strip().lower()
            if inherited in ("da", "en"):
                return inherited
        except Exception:
            pass

    return default


def build_auth_query(return_to: str, lang: str) -> str:
    return f"return_to={quote(return_to, safe=':/?=%-_~.#')}&lang={quote(lang, safe='')}"

AUTH_I18N = {
    "da": {
        "app_title": "Sovereign Account",
        "login_title": "Log ind",
        "login_intro": "Brug din konto til at få adgang til Sovereign-apps.",
        "username": "Brugernavn",
        "password": "Password",
        "login_button": "Log ind",
        "register_link": "Har du ikke en konto? Opret bruger",
        "account_link": "Gå til konto",
        "checking_login": "Tjekker loginstatus…",
        "status_logging_in": "Logger ind…",
        "status_login_ok": "Logget ind. Sender videre…",
        "error_prefix": "Fejl",
        "not_logged_in_yet": "Ikke logget ind endnu.",
        "register_title": "Opret bruger",
        "register_intro": "Opret din centrale konto til Sovereign-apps.",
        "email": "E-mail",
        "confirm_password": "Gentag password",
        "register_button": "Opret bruger",
        "login_link": "Har du allerede en konto? Log ind",
        "status_registering": "Opretter bruger…",
        "status_register_ok": "Bruger oprettet. Sender videre…",
        "account_intro": "Din centrale konto til Sovereign-suiten.",
        "not_specified": "ikke angivet",
        "unknown_value": "ukendt",
        "role_label": "Rolle",
        "last_login_label": "Seneste login",
        "important_label": "Vigtigt",
        "temporary_password_warning": "Dit password er midlertidigt nulstillet. Du skal vælge et nyt password nu.",
        "account_details_title": "Konto-oplysninger",
        "save_account_button": "Gem konto-oplysninger",
        "ready_status": "Klar.",
        "change_password_title": "Skift password",
        "current_password": "Nuværende password",
        "new_password": "Nyt password",
        "confirm_new_password": "Gentag nyt password",
        "change_password_button": "Skift password",
        "back_to_app": "Tilbage til app",
        "logout_button": "Log ud",
        "admin_panel": "Admin-panel",
        "saving_account_status": "Gemmer konto-oplysninger…",
        "account_updated_status": "Konto-oplysninger opdateret.",
        "updating_password_status": "Opdaterer password…",
        "password_updated_status": "Password opdateret.",
        "root_title": "Sovereign Core Auth",
        "root_status": "Auth-service kører.",
        "go_to_login": "Gå til login",
        "go_to_account": "Gå til konto",
        "go_to_admin": "Gå til admin",
        "create_user": "Opret bruger",
        "admin_title": "Sovereign Admin",
        "admin_intro": "Brugeradministration for Sovereign Core Auth.",
        "access_denied": "Adgang nægtet.",
        "resetting_password": "Nulstiller password…",
        "temporary_password_for": "Midlertidigt password for",

    },
    "en": {
        "app_title": "Sovereign Account",
        "login_title": "Log in",
        "login_intro": "Use your account to access Sovereign apps.",
        "username": "Username",
        "password": "Password",
        "login_button": "Log in",
        "register_link": "Don't have an account? Create one",
        "account_link": "Go to account",
        "checking_login": "Checking login status…",
        "status_logging_in": "Logging in…",
        "status_login_ok": "Logged in. Redirecting…",
        "error_prefix": "Error",
        "not_logged_in_yet": "Not logged in yet.",
        "register_title": "Create account",
        "register_intro": "Create your central account for Sovereign apps.",
        "email": "Email",
        "confirm_password": "Confirm password",
        "register_button": "Create account",
        "login_link": "Already have an account? Log in",
        "status_registering": "Creating account…",
        "status_register_ok": "Account created. Redirecting…",
        "account_intro": "Your central account for the Sovereign suite.",
        "not_specified": "not specified",
        "unknown_value": "unknown",
        "role_label": "Role",
        "last_login_label": "Last login",
        "important_label": "Important",
        "temporary_password_warning": "Your password was temporarily reset. You must choose a new password now.",
        "account_details_title": "Account details",
        "save_account_button": "Save account details",
        "ready_status": "Ready.",
        "change_password_title": "Change password",
        "current_password": "Current password",
        "new_password": "New password",
        "confirm_new_password": "Confirm new password",
        "change_password_button": "Change password",
        "back_to_app": "Back to app",
        "logout_button": "Log out",
        "admin_panel": "Admin panel",
        "saving_account_status": "Saving account details…",
        "account_updated_status": "Account details updated.",
        "updating_password_status": "Updating password…",
        "password_updated_status": "Password updated.",
        "root_title": "Sovereign Core Auth",
        "root_status": "Auth service is running.",
        "go_to_login": "Go to login",
        "go_to_account": "Go to account",
        "go_to_admin": "Go to admin",
        "create_user": "Create account",
        "admin_title": "Sovereign Admin",
        "admin_intro": "User administration for Sovereign Core Auth.",
        "access_denied": "Access denied.",
        "resetting_password": "Resetting password…",
        "temporary_password_for": "Temporary password for",

    }
}

def tr_auth(lang: str, key: str) -> str:
    lang = lang if lang in AUTH_I18N else "da"
    return AUTH_I18N.get(lang, AUTH_I18N["da"]).get(key, key)



def require_admin_auth():
    user, session_row = get_current_auth()
    if user is None:
        return None, jsonify({
            "ok": False,
            "error": "not authenticated"
        }), 401

    if str(user["role"]) != "admin":
        return None, jsonify({
            "ok": False,
            "error": "forbidden"
        }), 403

    return user, None, None


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
            "must_change_password": bool(user["must_change_password"]),
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
            "must_change_password": bool(user["must_change_password"]),
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


@app.get("/api/admin/users")
def api_admin_users():
    admin_user, err_response, status = require_admin_auth()
    if err_response is not None:
        return err_response, status

    users = []
    for row in list_users():
        users.append({
            "id": row["id"],
            "username": row["username"],
            "email": row["email"],
            "role": row["role"],
            "is_active": bool(row["is_active"]),
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "last_login_at": row["last_login_at"],
        })

    return jsonify({
        "ok": True,
        "items": users
    }), 200


@app.post("/api/admin/users/<int:user_id>/role")
def api_admin_set_user_role(user_id):
    admin_user, err_response, status = require_admin_auth()
    if err_response is not None:
        return err_response, status

    target_user = get_user_by_id(user_id)
    if target_user is None:
        return jsonify({
            "ok": False,
            "error": "user not found"
        }), 404

    payload = request.get_json(silent=True) or {}
    role = str(payload.get("role", "")).strip()

    if role not in ("admin", "user"):
        return jsonify({
            "ok": False,
            "error": "invalid role"
        }), 400

    update_user_role(user_id, role, now_utc_iso())
    updated_user = get_user_by_id(user_id)

    return jsonify({
        "ok": True,
        "message": "role updated",
        "user": {
            "id": updated_user["id"],
            "username": updated_user["username"],
            "email": updated_user["email"],
            "role": updated_user["role"],
            "is_active": bool(updated_user["is_active"]),
        }
    }), 200


@app.post("/api/admin/users/<int:user_id>/status")
def api_admin_set_user_status(user_id):
    admin_user, err_response, status = require_admin_auth()
    if err_response is not None:
        return err_response, status

    target_user = get_user_by_id(user_id)
    if target_user is None:
        return jsonify({
            "ok": False,
            "error": "user not found"
        }), 404

    payload = request.get_json(silent=True) or {}
    is_active_raw = payload.get("is_active", None)

    if not isinstance(is_active_raw, bool):
        return jsonify({
            "ok": False,
            "error": "is_active must be boolean"
        }), 400

    if int(target_user["id"]) == int(admin_user["id"]) and is_active_raw is False:
        return jsonify({
            "ok": False,
            "error": "cannot deactivate yourself"
        }), 400

    update_user_active_status(user_id, 1 if is_active_raw else 0, now_utc_iso())
    updated_user = get_user_by_id(user_id)

    return jsonify({
        "ok": True,
        "message": "status updated",
        "user": {
            "id": updated_user["id"],
            "username": updated_user["username"],
            "email": updated_user["email"],
            "role": updated_user["role"],
            "is_active": bool(updated_user["is_active"]),
        }
    }), 200


@app.post("/api/admin/users/<int:user_id>/reset-password")
def api_admin_reset_user_password(user_id):
    admin_user, err_response, status = require_admin_auth()
    if err_response is not None:
        return err_response, status

    target_user = get_user_by_id(user_id)
    if target_user is None:
        return jsonify({
            "ok": False,
            "error": "user not found"
        }), 404

    temp_password = "Temp-" + secrets.token_urlsafe(9)
    now = now_utc_iso()
    password_hash = generate_password_hash(temp_password)
    update_user_password(user_id, password_hash, now)
    set_user_must_change_password(user_id, 1, now)

    updated_user = get_user_by_id(user_id)

    return jsonify({
        "ok": True,
        "message": "password reset",
        "temporary_password": temp_password,
        "user": {
            "id": updated_user["id"],
            "username": updated_user["username"],
            "email": updated_user["email"],
            "role": updated_user["role"],
            "is_active": bool(updated_user["is_active"]),
        }
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

    now = now_utc_iso()
    password_hash = generate_password_hash(new_password)
    update_user_password(user["id"], password_hash, now)
    set_user_must_change_password(user["id"], 0, now)

    return jsonify({
        "ok": True,
        "message": "password updated"
    }), 200


@app.post("/api/auth/complete-password-reset")
def auth_complete_password_reset():
    user, session_row = get_current_auth()
    if user is None:
        return jsonify({
            "ok": False,
            "error": "not authenticated"
        }), 401

    if not bool(user["must_change_password"]):
        return jsonify({
            "ok": False,
            "error": "reset not required"
        }), 400

    payload = request.get_json(silent=True) or {}
    new_password = str(payload.get("new_password", "")).strip()
    confirm_password = str(payload.get("confirm_password", "")).strip()

    if not new_password or not confirm_password:
        return jsonify({
            "ok": False,
            "error": "new password fields are required"
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

    password_hash = generate_password_hash(new_password)
    now = now_utc_iso()
    update_user_password(user["id"], password_hash, now)
    set_user_must_change_password(user["id"], 0, now)

    return jsonify({
        "ok": True,
        "message": "password reset complete"
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
    lang = get_request_lang()
    t = lambda key: tr_auth(lang, key)
    return (
        f'<!doctype html><html lang="{lang}"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        f'<title>{t("root_title")}</title></head>'
        '<body style="font-family:system-ui,sans-serif;background:#111;color:#eee;padding:32px">'
        f'<h1>{t("root_title")}</h1>'
        f'<p>{t("root_status")}</p>'
        f'<p><a href="/login?lang={lang}" style="color:#9fd3a8">{t("go_to_login")}</a></p>'
        f'<p><a href="/account?lang={lang}" style="color:#9fd3a8">{t("go_to_account")}</a></p>'
        f'<p><a href="/admin/users?lang={lang}" style="color:#9fd3a8">{t("go_to_admin")}</a></p>'
        f'<p><a href="/register?lang={lang}" style="color:#9fd3a8">{t("create_user")}</a></p>'
        '</body></html>'
    )


@app.get("/login")
def login_page():
    return_to = get_safe_return_to()
    lang = get_request_lang()
    t = lambda key: tr_auth(lang, key)
    auth_query = build_auth_query(return_to, lang)
    return_to_js = quote(return_to, safe=":/?&=%-_~.#")
    register_link = (
        f'<a class="linkbtn" id="registerLink" href="/register?{auth_query}">{t("register_link")}</a>'
        if ALLOW_REGISTRATION else ""
    )

    return f"""
<!doctype html>
<html lang="{lang}">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>{t("app_title")}</title>
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
    <h1>{t("login_title")}</h1>
    <p>{t("login_intro")}</p>

    <form id="loginForm">
      <label>
        {t("username")}
        <input id="username" name="username" autocomplete="username" required>
      </label>

      <label>
        {t("password")}
        <input id="password" name="password" type="password" autocomplete="current-password" required>
      </label>

      <button type="submit">{t("login_button")}</button>
    </form>

    {register_link}

    <a class="linkbtn" id="accountLink" href="/account?{auth_query}">{t("account_link")}</a>

    <div id="status" class="small">{t("checking_login")}</div>
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
        status.textContent = {t('not_logged_in_yet')!r};
      }}

      document.getElementById("loginForm").addEventListener("submit", async (ev) => {{
        ev.preventDefault();
        status.textContent = {t('status_logging_in')!r};
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
        if (data?.user?.must_change_password){{
          location.href = "/account?return_to=" + encodeURIComponent(returnTo);
          return;
        }}
        location.href = returnTo;
        }}catch(err){{
          status.textContent = {t('error_prefix')!r} + ': ' + (err?.message || String(err));
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
    lang = get_request_lang()
    auth_query = build_auth_query(return_to, lang)
    return_to_js = quote(return_to, safe=":/?&=%-_~.#")
    t = lambda key: tr_auth(lang, key)

    if not ALLOW_REGISTRATION:
        return (
            '<!doctype html><html lang="{lang}"><head><meta charset="utf-8">'
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
<html lang="{lang}">
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
        {t("username")}
        <input id="username" name="username" autocomplete="username" required>
      </label>

      <label>
        E-mail
        <input id="email" name="email" type="email" autocomplete="email">
      </label>

      <label>
        {t("password")}
        <input id="password" name="password" type="password" autocomplete="new-password" required>
      </label>

      <label>
        {t("confirm_password")}
        <input id="confirm_password" name="confirm_password" type="password" autocomplete="new-password" required>
      </label>

      <button type="submit">{t("register_button")}</button>
    </form>

    <a class="linkbtn" href="/login?{auth_query}">{t("login_link")}</a>

    <div id="status" class="small" aria-live="polite"></div>
  </div>

  <script>
    const returnTo = {return_to!r};
    const status = document.getElementById("status");

    document.getElementById("registerForm").addEventListener("submit", async (ev) => {{
      ev.preventDefault();
      status.textContent = {t('status_registering')!r};
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

        status.textContent = {t('status_register_ok')!r};
        location.href = returnTo;
      }}catch(err){{
        status.textContent = {t('error_prefix')!r} + ': ' + (err?.message || String(err));
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
    lang = get_request_lang()
    t = lambda key: tr_auth(lang, key)

    if user is None:
        login_target = f"/login?{build_auth_query(request.base_url + f'?lang={lang}', lang)}"
        return (
            f'<!doctype html><html lang="{lang}"><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width,initial-scale=1">'
            f'<title>{t("app_title")}</title></head>'
            '<body style="font-family:system-ui,sans-serif;background:#111;color:#eee;padding:32px">'
            f'<h1>{t("app_title")}</h1>'
            f'<p>{t("not_logged_in_yet")}</p>'
            f'<p><a href="{login_target}" style="color:#9fd3a8">{t("login_button")}</a></p>'
            '</body></html>'
        )

    username = user["username"]
    email = user["email"] or ""
    role = user["role"]
    last_login_at = user["last_login_at"] or t("unknown_value")
    must_change_password = bool(user["must_change_password"])

    admin_link = (
        f'<a id="adminLink" href="/admin/users?lang={lang}" style="width:auto;min-width:160px;text-align:center">{t("admin_panel")}</a>'
        if role == "admin" else ""
    )

    password_warning = (
        f'<div class="meta" style="border-color:#6b5522"><div class="line"><strong>{t("important_label")}:</strong> {t("temporary_password_warning")}</div></div>'
        if must_change_password else ""
    )

    return f"""
<!doctype html>
<html lang="{lang}">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>{t("app_title")}</title>
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
    <h1>{t("app_title")}</h1>
    <p>{t("account_intro")}</p>

    <div class="meta">
      <div class="line"><strong>{t("username")}:</strong> {username}</div>
      <div class="line"><strong>{t("email")}:</strong> {email or t("not_specified")}</div>
      <div class="line"><strong>{t("role_label")}:</strong> {role}</div>
      <div class="line"><strong>{t("last_login_label")}:</strong> {last_login_at}</div>
    </div>

    {password_warning}

    <div class="section">
      <h2>{t("account_details_title")}</h2>
      <form id="profileForm">
        <label>
          {t("username")}
          <input id="profile_username" name="profile_username" value="{username}" autocomplete="username" required>
        </label>

        <label>
          {t("email")}
          <input id="profile_email" name="profile_email" type="email" value="{email}" autocomplete="email">
        </label>

        <button type="submit">{t("save_account_button")}</button>
      </form>

      <div id="profileStatus" class="small">{t("ready_status")}</div>
    </div>

    <div class="section">
      <h2>{t("change_password_title")}</h2>
      <form id="passwordForm">
        <label id="currentPasswordField">
          {t("current_password")}
          <input id="current_password" name="current_password" type="password" autocomplete="current-password" required>
        </label>

        <label>
          {t("new_password")}
          <input id="new_password" name="new_password" type="password" autocomplete="new-password" required>
        </label>

        <label>
          {t("confirm_new_password")}
          <input id="confirm_password" name="confirm_password" type="password" autocomplete="new-password" required>
        </label>

        <button type="submit">{t("change_password_button")}</button>
      </form>

      <div id="passwordStatus" class="small">{t("ready_status")}</div>
    </div>

    <div class="row">
      <a id="backLink" href="{return_to}">{t("back_to_app")}</a>
      {admin_link}
      <button id="logoutBtn" type="button">{t("logout_button")}</button>
    </div>
  </div>

  <script>
    const returnTo = {return_to!r};

    const profileStatusEl = document.getElementById("profileStatus");
    const passwordStatusEl = document.getElementById("passwordStatus");
    window.userMustChangePassword = {str(must_change_password).lower()};
    const currentPasswordFieldEl = document.getElementById("currentPasswordField");
    const currentPasswordInputEl = document.getElementById("current_password");

    if (window.userMustChangePassword){{
      if (currentPasswordFieldEl) currentPasswordFieldEl.style.display = "none";
      if (currentPasswordInputEl){{
        currentPasswordInputEl.required = false;
        currentPasswordInputEl.value = "";
      }}
    }}

    document.getElementById("profileForm").addEventListener("submit", async (ev) => {{
      ev.preventDefault();
      profileStatusEl.textContent = {t("saving_account_status")!r};
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

        profileStatusEl.textContent = data?.message || {t("account_updated_status")!r};
        profileStatusEl.className = "small ok";
        location.reload();
      }}catch(err){{
        profileStatusEl.textContent = {t("error_prefix")!r} + ": " + (err?.message || String(err));
        profileStatusEl.className = "small err";
      }}
    }});

    document.getElementById("passwordForm").addEventListener("submit", async (ev) => {{
      ev.preventDefault();
      passwordStatusEl.textContent = {t("updating_password_status")!r};
      passwordStatusEl.className = "small";

      const current_password = document.getElementById("current_password").value;
      const new_password = document.getElementById("new_password").value;
      const confirm_password = document.getElementById("confirm_password").value;

      const endpoint = window.userMustChangePassword
        ? "/api/auth/complete-password-reset"
        : "/api/auth/change-password";

      const payload = window.userMustChangePassword
        ? {{
            new_password,
            confirm_password
          }}
        : {{
            current_password,
            new_password,
            confirm_password
          }};

      try{{
        const res = await fetch(endpoint, {{
          method: "POST",
          credentials: "include",
          headers: {{"Content-Type": "application/json"}},
          body: JSON.stringify(payload)
        }});

        const data = await res.json().catch(() => ({{}}));
        if (!res.ok){{
          throw new Error(data?.error || `HTTP ${{res.status}}`);
        }}

        passwordStatusEl.textContent = data?.message || {t("password_updated_status")!r};
        passwordStatusEl.className = "small ok";
        document.getElementById("passwordForm").reset();
      }}catch(err){{
        passwordStatusEl.textContent = {t("error_prefix")!r} + ": " + (err?.message || String(err));
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
      location.href = `/login?return_to=${{encodeURIComponent(returnTo)}}&lang={lang}`;
    }});
  </script>
</body>
</html>

"""

@app.get("/admin/users")
def admin_users_page():
    lang = get_request_lang()
    t = lambda key: tr_auth(lang, key)
    admin_user, err_response, status = require_admin_auth()
    if err_response is not None:
        if status == 401:
            login_target = f"/login?{build_auth_query(request.url, lang)}"
            return (
                f'<!doctype html><html lang="{lang}"><head><meta charset="utf-8">'
                '<meta name="viewport" content="width=device-width,initial-scale=1">'
                f'<title>Sovereign Admin</title></head>'
                '<body style="font-family:system-ui,sans-serif;background:#111;color:#eee;padding:32px">'
                f'<h1>Sovereign Admin</h1>'
                f'<p>{t("not_logged_in_yet")}</p>'
                f'<p><a href="{login_target}" style="color:#9fd3a8">{t("go_to_login")}</a></p>'
                '</body></html>'
            )
        return (
            f'<!doctype html><html lang="{lang}"><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width,initial-scale=1">'
            f'<title>Sovereign Admin</title></head>'
            '<body style="font-family:system-ui,sans-serif;background:#111;color:#eee;padding:32px">'
            f'<h1>Sovereign Admin</h1>'
            f'<p>{t("access_denied")}</p>'
            f'<p><a href="/account?lang={lang}" style="color:#9fd3a8">{t("go_to_account")}</a></p>'
            '</body></html>'
        )

    admin_html = """
<!doctype html>
  <html lang="__LANG__">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Sovereign Admin</title>
  <style>
    body{
      margin:0;
      font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;
      background:#111;
      color:#f3f3f3;
      padding:24px;
    }
    .wrap{
      max-width:1100px;
      margin:0 auto;
    }
    .card{
      background:#1b1b1b;
      border:1px solid #2c2c2c;
      border-radius:16px;
      padding:20px;
    }
    h1,h2{margin:0 0 10px}
    p,.small{color:#b9b9b9}
    .toolbar{
      display:grid;
      grid-template-columns:2fr 1fr 1fr;
      gap:10px;
      margin-top:16px;
    }
    .toolbar input,
    .toolbar select,
    .toolbar button,
    .toolbar a{
      border-radius:10px;
      border:1px solid #2c2c2c;
      background:#151515;
      color:#f3f3f3;
      padding:10px 12px;
      font:inherit;
      box-sizing:border-box;
      text-decoration:none;
    }
    .table-scroll{
      overflow-x:auto;
      max-width:100%;
      margin-top:16px;
    }
    table{
      width:100%;
      border-collapse:collapse;
      table-layout:fixed;
    }
    td,th{
      word-wrap:break-word;
      white-space:normal;
    }
    th,td{
      border-bottom:1px solid #2c2c2c;
      padding:10px 8px;
      text-align:left;
      vertical-align:top;
      font-size:.95rem;
    }
    th{color:#b9b9b9}
    button,a{
      border-radius:10px;
      border:1px solid #2c2c2c;
      background:#151515;
      color:#f3f3f3;
      padding:8px 10px;
      font:inherit;
      text-decoration:none;
      cursor:pointer;
    }
    .actions{
      display:flex;
      gap:8px;
      flex-wrap:wrap;
    }
    .row{
      display:flex;
      gap:10px;
      flex-wrap:wrap;
      margin-top:16px;
    }
    .ok{color:#9fd3a8}
    .err{color:#e7c27d}

    /* admin mobile cards */
    @media (max-width:800px){
      .toolbar{
        grid-template-columns:1fr;
      }
      .table-scroll{
        overflow:visible;
      }
      table{
        display:block;
        width:100%;
      }
      thead{
        display:none;
      }
      tbody{
        display:block;
        width:100%;
      }
      tr{
        display:block;
        width:100%;
        margin:0 0 14px 0;
        padding:12px;
        border:1px solid #2c2c2c;
        border-radius:12px;
        background:#151515;
        box-sizing:border-box;
      }
      td{
        display:block;
        width:100%;
        border:none;
        padding:4px 0;
        white-space:normal;
        word-break:break-word;
        box-sizing:border-box;
      }
      td:nth-child(1),
      td:nth-child(6),
      td:nth-child(7){
        display:none;
      }
      td:nth-child(2)::before{
        content:"Brugernavn: ";
        color:#b9b9b9;
        font-weight:600;
      }
      td:nth-child(3)::before{
        content:"E-mail: ";
        color:#b9b9b9;
        font-weight:600;
      }
      td:nth-child(4)::before{
        content:"Rolle: ";
        color:#b9b9b9;
        font-weight:600;
      }
      td:nth-child(5)::before{
        content:"Status: ";
        color:#b9b9b9;
        font-weight:600;
      }
      td:nth-child(8)::before{
        content:"Handlinger:";
        display:block;
        color:#b9b9b9;
        font-weight:600;
        margin-bottom:8px;
      }
      .actions{
        flex-direction:column;
        gap:8px;
      }
      .actions button{
        width:100%;
      }
    }
  </style>
</head>
<body>
  <div class="wrap">
    <div class="card">
      <h1>Sovereign Admin</h1>
      <p>Brugeradministration for Sovereign Core Auth.</p>

      <div class="row">
        <a href="/account?lang=__LANG__">Tilbage til konto</a>
      </div>

      <div class="toolbar">
        <input id="userSearch" type="search" placeholder="Søg på brugernavn eller e-mail">
        <select id="roleFilter">
          <option value="">Alle roller</option>
          <option value="admin">Kun admins</option>
          <option value="user">Kun users</option>
        </select>
        <select id="statusFilter">
          <option value="">Alle statuser</option>
          <option value="active">Kun aktive</option>
          <option value="inactive">Kun inaktive</option>
        </select>
      </div>

      <div id="status" class="small">Indlæser brugere…</div>

      <div class="table-scroll">
        <table>
          <thead>
            <tr>
              <th>ID</th>
              <th>Brugernavn</th>
              <th>E-mail</th>
              <th>Rolle</th>
              <th>Status</th>
              <th>Oprettet</th>
              <th>Seneste login</th>
              <th>Handlinger</th>
            </tr>
          </thead>
          <tbody id="usersBody"></tbody>
        </table>
      </div>
    </div>
  </div>

  <script>
    const statusEl = document.getElementById("status");
    const usersBody = document.getElementById("usersBody");
    const userSearchEl = document.getElementById("userSearch");
    const roleFilterEl = document.getElementById("roleFilter");
    const statusFilterEl = document.getElementById("statusFilter");

    let ALL_USERS = [];

    function esc(value){
      return String(value ?? "")
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;");
    }

    function renderUsers(items){
      usersBody.innerHTML = items.map(user => {
        const roleBtnLabel = user.role === "admin" ? "Gør user" : "Gør admin";
        const nextRole = user.role === "admin" ? "user" : "admin";
        const statusBtnLabel = user.is_active ? "Deaktivér" : "Aktivér";
        const nextStatus = user.is_active ? "false" : "true";

        return `
          <tr data-user-id="${esc(user.id)}">
            <td>${esc(user.id)}</td>
            <td>${esc(user.username)}</td>
            <td>${esc(user.email || "")}</td>
            <td>${esc(user.role)}</td>
            <td>${user.is_active ? "aktiv" : "inaktiv"}</td>
            <td>${esc(user.created_at || "")}</td>
            <td>${esc(user.last_login_at || "")}</td>
            <td>
              <div class="actions">
                <button type="button" data-action="role" data-role="${esc(nextRole)}">${esc(roleBtnLabel)}</button>
                <button type="button" data-action="status" data-active="${esc(nextStatus)}">${esc(statusBtnLabel)}</button>
                <button type="button" data-action="reset-password">Nulstil password</button>
              </div>
            </td>
          </tr>
        `;
      }).join("");

      bindRowActions();
      statusEl.textContent = `${items.length} bruger(e) vist.`;
      statusEl.className = "small ok";
    }

    function getFilteredUsers(){
      const q = userSearchEl.value.trim().toLowerCase();
      const role = roleFilterEl.value;
      const status = statusFilterEl.value;

      return ALL_USERS.filter(user => {
        const haystack = `${user.username || ""} ${user.email || ""}`.toLowerCase();
        if (q && !haystack.includes(q)) return false;
        if (role && user.role !== role) return false;
        if (status === "active" && !user.is_active) return false;
        if (status === "inactive" && user.is_active) return false;
        return true;
      });
    }

    function applyFilters(){
      renderUsers(getFilteredUsers());
    }

    async function loadUsers(){
      statusEl.textContent = "Indlæser brugere…";
      statusEl.className = "small";

      try{
        const res = await fetch("/api/admin/users", {
          credentials: "include",
          cache: "no-store"
        });

        const data = await res.json().catch(() => ({}));
        if (!res.ok){
          throw new Error(data?.error || `HTTP ${res.status}`);
        }

        ALL_USERS = Array.isArray(data?.items) ? data.items : [];
        applyFilters();
      }catch(err){
        ALL_USERS = [];
        usersBody.innerHTML = "";
        statusEl.textContent = "Fejl: " + (err?.message || String(err));
        statusEl.className = "small err";
      }
    }

    function bindRowActions(){
      usersBody.querySelectorAll("button[data-action='role']").forEach(btn => {
        btn.addEventListener("click", async () => {
          const row = btn.closest("tr");
          const userId = row?.getAttribute("data-user-id");
          const role = btn.getAttribute("data-role");

          statusEl.textContent = "Opdaterer rolle…";
          statusEl.className = "small";

          try{
            const res = await fetch(`/api/admin/users/${userId}/role`, {
              method: "POST",
              credentials: "include",
              headers: {"Content-Type": "application/json"},
              body: JSON.stringify({ role })
            });

            const data = await res.json().catch(() => ({}));
            if (!res.ok){
              throw new Error(data?.error || `HTTP ${res.status}`);
            }

            await loadUsers();
          }catch(err){
            statusEl.textContent = "Fejl: " + (err?.message || String(err));
            statusEl.className = "small err";
          }
        });
      });

      usersBody.querySelectorAll("button[data-action='status']").forEach(btn => {
        btn.addEventListener("click", async () => {
          const row = btn.closest("tr");
          const userId = row?.getAttribute("data-user-id");
          const is_active = btn.getAttribute("data-active") === "true";

          statusEl.textContent = "Opdaterer status…";
          statusEl.className = "small";

          try{
            const res = await fetch(`/api/admin/users/${userId}/status`, {
              method: "POST",
              credentials: "include",
              headers: {"Content-Type": "application/json"},
              body: JSON.stringify({ is_active })
            });

            const data = await res.json().catch(() => ({}));
            if (!res.ok){
              throw new Error(data?.error || `HTTP ${res.status}`);
            }

            await loadUsers();
          }catch(err){
            statusEl.textContent = "Fejl: " + (err?.message || String(err));
            statusEl.className = "small err";
          }
        });
      });

      usersBody.querySelectorAll("button[data-action='reset-password']").forEach(btn => {
        btn.addEventListener("click", async () => {
          const row = btn.closest("tr");
          const userId = row?.getAttribute("data-user-id");

          statusEl.textContent = "Nulstiller password…";
          statusEl.className = "small";

          try{
            const res = await fetch(`/api/admin/users/${userId}/reset-password`, {
              method: "POST",
              credentials: "include",
              headers: {"Content-Type": "application/json"},
              body: JSON.stringify({})
            });

            const data = await res.json().catch(() => ({}));
            if (!res.ok){
              throw new Error(data?.error || `HTTP ${res.status}`);
            }

            const username = data?.user?.username || `#${userId}`;
            const tempPassword = data?.temporary_password || "";
            statusEl.textContent = `Midlertidigt password for ${username}: ${tempPassword}`;
            statusEl.className = "small ok";
          }catch(err){
            statusEl.textContent = "Fejl: " + (err?.message || String(err));
            statusEl.className = "small err";
          }
        });
      });
    }

    userSearchEl.addEventListener("input", applyFilters);
    roleFilterEl.addEventListener("change", applyFilters);
    statusFilterEl.addEventListener("change", applyFilters);

    loadUsers();
  </script>
</body>
</html>
"""

    admin_html = admin_html.replace("__LANG__", lang)

    if lang == "en":
        replacements = [
            ("Brugeradministration for Sovereign Core Auth.", "User administration for Sovereign Core Auth."),
            ("Tilbage til konto", "Back to account"),
            ("Søg på brugernavn eller e-mail", "Search by username or email"),
            ("Alle roller", "All roles"),
            ("Kun admins", "Admins only"),
            ("Kun users", "Users only"),
            ("Alle statuser", "All statuses"),
            ("Kun aktive", "Active only"),
            ("Kun inaktive", "Inactive only"),
            ("Indlæser brugere…", "Loading users…"),
            ("Brugernavn:", "Username:"),
            ("E-mail:", "Email:"),
            ("Rolle:", "Role:"),
            ("Status:", "Status:"),
            ("Handlinger:", "Actions:"),
            ("Brugernavn", "Username"),
            ("E-mail", "Email"),
            ("Rolle", "Role"),
            ("Status", "Status"),
            ("Oprettet", "Created"),
            ("Seneste login", "Last login"),
            ("Handlinger", "Actions"),
            ("Gør user", "Make user"),
            ("Gør admin", "Make admin"),
            ("Deaktivér", "Deactivate"),
            ("Aktivér", "Activate"),
            ("Nulstil password", "Reset password"),
            ("bruger(e) vist.", "user(s) shown."),
            ("Indlæser brugere…", "Loading users…"),
            ("aktiv", "active"),
            ("inaktiv", "inactive"),
            ("Fejl: ", "Error: "),
            ("Midlertidigt password for", "Temporary password for"),
        ]
        for old, new in replacements:
            admin_html = admin_html.replace(old, new)

    return admin_html




if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=8001, debug=False)
