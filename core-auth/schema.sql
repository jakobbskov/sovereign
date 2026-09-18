CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE,
  email TEXT,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK(role IN ('admin','user')),
  is_active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  last_login_at TEXT,
  must_change_password INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS sessions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  session_token TEXT NOT NULL UNIQUE,
  csrf_token TEXT NOT NULL,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  last_seen_at TEXT NOT NULL,
  ip_address TEXT,
  user_agent TEXT,
  is_revoked INTEGER NOT NULL DEFAULT 0,
  FOREIGN KEY(user_id) REFERENCES users(id)
);

CREATE INDEX IF NOT EXISTS idx_sessions_token
ON sessions(session_token);

CREATE INDEX IF NOT EXISTS idx_sessions_user_id
ON sessions(user_id);

CREATE TABLE IF NOT EXISTS apps (
  id INTEGER PRIMARY KEY,
  key TEXT NOT NULL UNIQUE CHECK (
    length(key) BETWEEN 1 AND 64
    AND substr(key, 1, 1) GLOB '[a-z]'
    AND key NOT GLOB '*[^a-z0-9_-]*'
    AND instr(key, char(0)) = 0
  ),
  name TEXT NOT NULL CHECK (
    length(name) > 0
    -- Match the whitespace characters stripped by Python's str.strip().
    AND name = trim(name, char(9,10,11,12,13,28,29,30,31,32,133,160,5760,
                              8192,8193,8194,8195,8196,8197,8198,8199,8200,
                              8201,8202,8232,8233,8239,8287,12288))
    AND instr(name, char(0)) = 0
  ),
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS user_apps (
  user_id INTEGER NOT NULL,
  app_id INTEGER NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY (user_id, app_id),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (app_id) REFERENCES apps(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_user_apps_app_id ON user_apps(app_id);

-- Catalog registration only: never grant access as part of initialization.
INSERT INTO apps (key, name, created_at)
VALUES ('writer', 'Sovereign Writer', strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
ON CONFLICT(key) DO NOTHING;
