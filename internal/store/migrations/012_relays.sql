CREATE TABLE relay_server_keys (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    secret BLOB NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE relays (
    relay_id TEXT PRIMARY KEY,
    public_key TEXT NOT NULL UNIQUE,
    version TEXT NOT NULL DEFAULT '0.0.0',
    is_internal INTEGER NOT NULL DEFAULT 1 CHECK (is_internal IN (0, 1)),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX relays_last_seen_idx ON relays(last_seen_at DESC);
