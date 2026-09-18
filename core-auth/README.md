# Core Auth operations

Core Auth is a Flask application with SQLite and inline account/admin pages.
The existing runtime entry point is `python core-auth/app.py` (port 8001).
`gunicorn` is a runtime dependency; a WSGI invocation is shown below. This
repository contains no production service, container, proxy, or deployment
configuration, so the actual production restart command and database location
must be established by the operator. Do not infer them from the local defaults.

## Local runtime and tests

Run these commands from the repository root:

```sh
python3 -m venv core-auth/.venv
core-auth/.venv/bin/pip install -r core-auth/requirements-dev.txt
core-auth/.venv/bin/python -m pytest core-auth/tests -q
```

Tests use temporary database files under ignored `core-auth/.pytest-tmp/`,
replace the database path before initialization, reject connections outside each
test's temporary directory, and make no network requests.
They never write `core-auth/auth.db`. There was no pre-existing test suite;
the suite covers schema/migration, validation, administration, and existing
login/session/profile/password/CORS integrations through Flask's test client.

For a disposable local instance, choose a new database explicitly:

```sh
export CORE_AUTH_DB_PATH="$PWD/core-auth/local-test.sqlite"
core-auth/.venv/bin/python core-auth/db.py --database "$CORE_AUTH_DB_PATH" init
core-auth/.venv/bin/python core-auth/app.py
```

The explicit `init` command creates a new file with mode 0600 and refuses an
existing file. If schema initialization fails, the empty file may remain;
investigate the error and use `migrate` to retry. The direct entry point migrates
the selected existing database before serving. Imports, normal connections,
bootstrap requests, and migration never create missing database files. A missing
database fails closed rather than creating a replacement empty auth store.
Do not stage local database files. Without `CORE_AUTH_DB_PATH`, the historical
default path remains `core-auth/auth.db`, but the file must already exist.

A WSGI server imports the app without applying the schema:

```sh
core-auth/.venv/bin/gunicorn --chdir core-auth --bind 127.0.0.1:8001 app:app
```

Explicitly migrate before starting WSGI workers. Keep existing cookie settings
(`SESSION_COOKIE_NAME`, `SESSION_DAYS`, `COOKIE_DOMAIN`, `COOKIE_SECURE`) and
registration settings. These commands do not define production proxy routing.

## Schema and migration

`apps` holds a unique key matching `[a-z][a-z0-9_-]{0,63}`, a nonempty trimmed
name, and a required creation timestamp. SQLite CHECK constraints enforce the
key and name rules, including rejection of embedded NUL. `user_apps` has a
composite primary key `(user_id, app_id)`, required creation timestamp, and
foreign keys to users/apps with `ON DELETE CASCADE`. An app-id index supports
reverse lookups and cascades. The existing sessions-to-users foreign key keeps
its original deletion behavior; removing a user with sessions still requires
handling those sessions first.

All application connections enable and verify SQLite foreign keys. Database
helpers explicitly commit/rollback writes and always close their connections,
including on error. Connections use SQLite `mode=rw` to require an existing file.

There was no migration framework. `init_db()` now applies the additive,
idempotent `schema.sql` inside `BEGIN IMMEDIATE`, runs `foreign_key_check`, then
commits. Errors roll back the entire schema/catalog change. Existing users and
sessions are preserved. `writer` is registered as `Sovereign Writer` through
an insert that does nothing on key conflict; no grants are inserted. Repeated
migration preserves existing catalog entries and explicit grants. This approach
is suitable for this additive change; future destructive/column migrations
need explicit versioned migration logic, not edits to CREATE IF NOT EXISTS.

With `CORE_AUTH_DB_PATH` set to the confirmed existing database file:

```sh
core-auth/.venv/bin/python core-auth/db.py --database "$CORE_AUTH_DB_PATH" migrate
```

The CLI requires an existing file to avoid silently migrating the wrong new
database. It exits nonzero with a generic error on failure. Existing orphaned
foreign keys make migration fail and roll back; investigate those records
before retrying rather than disabling enforcement.

To verify after migration (read-only inspection):

```sh
core-auth/.venv/bin/python - <<'PY'
import os
import sqlite3
from contextlib import closing
from pathlib import Path

uri = Path(os.environ['CORE_AUTH_DB_PATH']).resolve().as_uri() + '?mode=ro'
with closing(sqlite3.connect(uri, uri=True)) as connection:
    connection.execute('PRAGMA foreign_keys = ON')
    assert connection.execute('PRAGMA foreign_keys').fetchone() == (1,)
    assert connection.execute('PRAGMA integrity_check').fetchall() == [('ok',)]
    assert connection.execute('PRAGMA foreign_key_check').fetchall() == []
    assert connection.execute("SELECT name FROM apps WHERE key = 'writer'").fetchone() == ('Sovereign Writer',)
    print('Users:', connection.execute('SELECT count(*) FROM users').fetchone()[0])
    print('Sessions:', connection.execute('SELECT count(*) FROM sessions').fetchone()[0])
    print('Explicit grants:', connection.execute('SELECT count(*) FROM user_apps').fetchone()[0])
PY
```

On the first migration, before explicit administration, grants must be zero.
Repeated migrations must preserve grants, not reset them.

Future apps are catalog entries, not new user columns. Register them using
the operator CLI, substituting the intended stable key and display name:

```sh
core-auth/.venv/bin/python core-auth/db.py --database "$CORE_AUTH_DB_PATH" register-app example-app "Example App"
```

Registration is idempotent by key, preserves an existing name, and never assigns
users. The new app immediately appears in the admin catalog/UI.

## Admin UI and API

Log in as an active Core Auth admin and open `/admin/users` on the Core Auth
origin. On the intended user's row:

1. Click **Vis appadgang** to see the catalog and current grants.
2. Beside **Sovereign Writer (writer)**, click **Tildel** to grant Writer.
3. Click **Vis appadgang** again to read back the saved state.
4. To revoke, click **Tilbagekald** beside Writer, then read back again.

No role automatically confers app access. Administrators may explicitly grant
themselves access through the same controls. Normal users cannot read or change
grants, including their own. Nothing assigns all users or all apps by default.

All endpoints below require the same active admin session cookie:

| Method | Endpoint | Result/body |
|---|---|---|
| GET | `/api/admin/users` | Existing user list, including target IDs |
| GET | `/api/admin/apps` | `{"ok":true,"items":[{"key":"writer","name":"Sovereign Writer"}]}` |
| GET | `/api/admin/csrf` | `{"ok":true,"csrf_token":"..."}` for the current session |
| GET | `/api/admin/users/<user_id>/entitlements` | `ok`, `user_id`, sorted `entitlements` |
| POST | `/api/admin/users/<user_id>/entitlements` | `{"app_key":"writer","granted":true}` to grant |
| POST | `/api/admin/users/<user_id>/entitlements` | `{"app_key":"writer","granted":false}` to revoke |

POST requires JSON and `X-CSRF-Token` from `/api/admin/csrf`. The same header is
now required on existing role, status, and reset-password admin POST endpoints;
the existing admin UI supplies it. External admin scripts must be updated.
Tokens are compared to the current session with constant-time comparison.
Admin responses are `Cache-Control: no-store` and intentionally have no CORS
permission, including for sibling apps, so those apps cannot read admin tokens.
Existing non-admin auth CORS behavior is preserved.

Login/account/register return destinations require an exact trusted origin,
and values embedded in scripts are serialized as HTML-safe JSON. Account fields
are HTML-escaped, and entitlement labels use DOM `textContent`. This prevents
injected scripts on the auth origin from bypassing the session-bound CSRF check.
The CSRF token remains stored in the existing `sessions.csrf_token` field by
design; it is not an extra entitlement record and must not be logged or exposed
outside the active admin's non-cacheable token endpoint.

Both grant and revoke return HTTP 200 with `ok`, target `user_id`, and the current
sorted `entitlements`, even if already granted/revoked. Only existing apps/users
are accepted. Errors are stable: 401 `not authenticated`, 403 `forbidden` for
non-admins, 403 `invalid csrf token`, 400 for invalid IDs/keys/payloads, 404
`user not found` or `app not found`. Unexpected payload fields are rejected;
the target comes exclusively from the URL. SQLite errors return HTTP 503
`{"ok":false,"error":"service unavailable"}` without internal details.
After an ambiguous network failure, read the current grants or repeat the
idempotent operation.

## Validate contract

`GET /api/auth/validate` retains HTTP 200 and all previous successful fields
(`ok`, `authenticated`, `user_id`, `username`, `role`) and adds `entitlements`.
A legitimate empty set is `[]`; a sole Writer grant is `["writer"]`. Arrays
contain only unique app keys in ascending order. Admin role never implies a
grant. Missing/invalid/revoked/expired sessions and inactive users retain HTTP
401 `{"ok":false,"authenticated":false}` and receive no entitlements.

Database failures during validation return HTTP 503
`{"ok":false,"authenticated":false,"error":"auth unavailable"}` with no
entitlements field. This includes a service started before migration. Consumers
must fail closed on 503, missing fields, or malformed responses; never substitute
`[]` or allow access after a failed lookup. Validate responses are not cacheable.
Writer will require the exact `writer` key in its backend in a separate change.

## Deployment and recovery — operator procedure, not run by this change

1. Identify the actual service and database file, record current code/config and
   user/session counts, and stop Core Auth writers for a maintenance window.
   Set `CORE_AUTH_DB_PATH` to that absolute path and `CORE_AUTH_BACKUP_PATH` to a
   new, protected backup filename outside the checkout. Take and verify a SQLite
   backup using the command below. Keep it private: it contains password hashes
   and session credentials. Record its path and ensure it is recoverable.
2. Deploy the Core Auth code/dependencies while workers remain stopped. Preserve
   cookie/domain/security settings and point runtime and migration at the same
   database. Production service commands are not tracked here.
3. Run the explicit `db.py --database ... migrate` command above, then the
   read-only verification. Compare user/session counts to the recorded values;
   confirm Writer is registered and initial grants are zero. On any failure,
   stop and recover/investigate; do not proceed to Writer deployment.
4. Start Core Auth using the site's existing service management and verify both
   an existing session and a fresh login. Validate must return `entitlements: []`
   for users without grants, including admins.
5. In `/admin/users`, explicitly assign `writer` to the intended developer/owner
   account using **Vis appadgang → Tildel**. Identify the account from the UI;
   there is no hardcoded user ID, username, or automatic deployment grant.
6. In that account's authenticated session, request `/api/auth/validate` and
   verify `"entitlements": ["writer"]` (assuming no other explicit grants).
7. Only now deploy Writer code that requires this field and exact key.
8. Verify Writer's 401 for invalid sessions, 403 for authenticated users without
   Writer, and allowed access for an explicitly entitled user.

Verified backup command (run before deployment, from the repository root with
the operator-selected environment variables):

```sh
core-auth/.venv/bin/python - <<'PY'
import os
import sqlite3
from contextlib import closing
from pathlib import Path

source = Path(os.environ['CORE_AUTH_DB_PATH']).resolve()
backup = Path(os.environ['CORE_AUTH_BACKUP_PATH']).resolve()
if not source.is_file() or source == backup:
    raise SystemExit('Invalid source/backup paths')
descriptor = os.open(backup, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
os.close(descriptor)
with closing(sqlite3.connect(source.as_uri() + '?mode=ro', uri=True)) as src:
    with closing(sqlite3.connect(backup)) as dst:
        src.backup(dst)
        assert dst.execute('PRAGMA integrity_check').fetchall() == [('ok',)]
        for table in ('users', 'sessions'):
            assert src.execute(f'SELECT count(*) FROM {table}').fetchone() == dst.execute(f'SELECT count(*) FROM {table}').fetchone()
print('Backup verified')
PY
```

If deployment fails, keep writers stopped. Migration errors already roll back;
do not restore unnecessarily. If restoration is needed, first preserve a
separate verified backup of the failed state using another backup filename.
Restore the recorded code/config and the pre-deployment database together.
With `CORE_AUTH_BACKUP_PATH` pointing to the verified pre-deployment backup:

```sh
core-auth/.venv/bin/python - <<'PY'
import os
import sqlite3
from contextlib import closing
from pathlib import Path

backup = Path(os.environ['CORE_AUTH_BACKUP_PATH']).resolve()
target = Path(os.environ['CORE_AUTH_DB_PATH']).resolve()
if backup == target or not backup.is_file() or not target.is_file():
    raise SystemExit('Invalid recovery paths')
with closing(sqlite3.connect(backup.as_uri() + '?mode=ro', uri=True)) as src:
    assert src.execute('PRAGMA integrity_check').fetchall() == [('ok',)]
    with closing(sqlite3.connect(target.as_uri() + '?mode=rw', uri=True)) as dst:
        src.backup(dst)
        assert dst.execute('PRAGMA integrity_check').fetchall() == [('ok',)]
print('Database restored; verify service configuration before restart')
PY
```

This uses SQLite's backup API, including proper journal handling; do not copy
only a live database file while ignoring WAL files. Restoration discards changes
since the backup, which is why writers stay stopped. Restart the previous Core
Auth code and verify login/session behavior. If Writer already requires
entitlements, roll that deployment back as well or keep it unavailable; never
introduce an authentication-only access fallback.
