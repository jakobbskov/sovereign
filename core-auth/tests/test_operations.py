import os
import re
import sqlite3
import subprocess
import sys
from contextlib import closing

import pytest

import db


def test_documented_backup_verification_and_recovery(isolated_database, tmp_path, users):
    snippets = re.findall(r"python - <<'PY'\n(.*?)\nPY", (db.BASE_DIR / "README.md").read_text(), re.S)
    assert len(snippets) == 3
    environment = dict(os.environ, CORE_AUTH_DB_PATH=str(isolated_database),
                       CORE_AUTH_BACKUP_PATH=str(tmp_path / "verified.sqlite"))
    # README order: post-migration verification, backup, recovery.
    for index in (0, 1):
        result = subprocess.run([sys.executable, "-c", snippets[index]], env=environment, capture_output=True)
        assert result.returncode == 0, result.stderr
    db.grant_user_entitlement(users["user"], "writer")
    result = subprocess.run([sys.executable, "-c", snippets[2]], env=environment, capture_output=True)
    assert result.returncode == 0, result.stderr
    assert db.list_user_entitlements(users["user"]) == []
    assert db.get_user_by_id(users["user"]) is not None
    # A repeated backup must not overwrite the recovery copy.
    result = subprocess.run([sys.executable, "-c", snippets[1]], env=environment, capture_output=True)
    assert result.returncode != 0


def test_migration_rejects_existing_orphans(isolated_database, users):
    with closing(sqlite3.connect(isolated_database)) as conn:
        conn.execute("DROP TABLE user_apps")
        conn.execute("DROP TABLE apps")
        conn.execute(
            "INSERT INTO sessions (user_id, session_token, csrf_token, created_at, expires_at, last_seen_at) "
            "VALUES (?, 'orphan-test-session', 'orphan-test-csrf', 'now', 'later', 'now')",
            (max(users.values()) + 1,),
        )
        conn.commit()
    with pytest.raises(sqlite3.IntegrityError):
        db.init_db()
    with closing(db.get_db()) as conn:
        assert conn.execute("SELECT name FROM sqlite_master WHERE name = 'apps'").fetchone() is None
        assert conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 1


def test_cli_error_is_generic(isolated_database):
    with closing(db.get_db()) as conn:
        conn.execute("DROP TABLE user_apps")
        conn.execute("DROP TABLE apps")
        conn.execute("CREATE TABLE apps (incompatible TEXT)")
        conn.commit()
    result = subprocess.run([
        sys.executable, str(db.BASE_DIR / "db.py"), "--database", str(isolated_database), "migrate",
    ], capture_output=True, text=True)
    assert result.returncode == 1
    assert result.stderr == "Database operation failed; transaction rolled back.\n"
    with closing(db.get_db()) as conn:
        assert conn.execute("SELECT name FROM sqlite_master WHERE name = 'user_apps'").fetchone() is None
