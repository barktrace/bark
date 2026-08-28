CREATE TABLE transactions (
    id TEXT PRIMARY KEY,
    event_id TEXT NOT NULL,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    release_id TEXT REFERENCES releases(id) ON DELETE SET NULL,
    trace_id TEXT NOT NULL DEFAULT '',
    span_id TEXT NOT NULL DEFAULT '',
    name TEXT NOT NULL,
    operation TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT '',
    environment TEXT NOT NULL DEFAULT '',
    started_at TEXT NOT NULL,
    finished_at TEXT NOT NULL,
    duration_ms REAL NOT NULL,
    span_count INTEGER NOT NULL DEFAULT 0,
    payload BLOB NOT NULL,
    received_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (project_id, event_id)
);
CREATE INDEX transactions_project_finished_idx ON transactions(project_id, finished_at DESC);
CREATE INDEX transactions_project_name_idx ON transactions(project_id, name, finished_at DESC);
CREATE INDEX transactions_trace_idx ON transactions(trace_id) WHERE trace_id != '';

CREATE TABLE logs (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    release_id TEXT REFERENCES releases(id) ON DELETE SET NULL,
    timestamp TEXT NOT NULL,
    level TEXT NOT NULL DEFAULT 'info',
    message TEXT NOT NULL,
    environment TEXT NOT NULL DEFAULT '',
    trace_id TEXT NOT NULL DEFAULT '',
    span_id TEXT NOT NULL DEFAULT '',
    attributes BLOB NOT NULL DEFAULT '{}',
    received_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX logs_project_timestamp_idx ON logs(project_id, timestamp DESC);
CREATE INDEX logs_project_level_timestamp_idx ON logs(project_id, level, timestamp DESC);
CREATE INDEX logs_trace_idx ON logs(trace_id) WHERE trace_id != '';

CREATE TABLE uptime_monitors (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    url TEXT NOT NULL,
    method TEXT NOT NULL DEFAULT 'GET' CHECK (method IN ('GET', 'HEAD')),
    interval_seconds INTEGER NOT NULL DEFAULT 60 CHECK (interval_seconds BETWEEN 30 AND 86400),
    timeout_seconds INTEGER NOT NULL DEFAULT 10 CHECK (timeout_seconds BETWEEN 1 AND 30),
    expected_status_min INTEGER NOT NULL DEFAULT 200,
    expected_status_max INTEGER NOT NULL DEFAULT 399,
    enabled INTEGER NOT NULL DEFAULT 1,
    next_check_at TEXT NOT NULL,
    last_checked_at TEXT,
    last_status TEXT NOT NULL DEFAULT 'pending' CHECK (last_status IN ('pending', 'up', 'down')),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX uptime_monitors_due_idx ON uptime_monitors(enabled, next_check_at);
CREATE INDEX uptime_monitors_project_idx ON uptime_monitors(project_id, created_at DESC);

CREATE TABLE uptime_checks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    monitor_id TEXT NOT NULL REFERENCES uptime_monitors(id) ON DELETE CASCADE,
    status TEXT NOT NULL CHECK (status IN ('up', 'down')),
    status_code INTEGER,
    duration_ms INTEGER NOT NULL,
    error TEXT NOT NULL DEFAULT '',
    checked_at TEXT NOT NULL
);
CREATE INDEX uptime_checks_monitor_time_idx ON uptime_checks(monitor_id, checked_at DESC);

CREATE TABLE uptime_incidents (
    id TEXT PRIMARY KEY,
    monitor_id TEXT NOT NULL REFERENCES uptime_monitors(id) ON DELETE CASCADE,
    started_at TEXT NOT NULL,
    resolved_at TEXT,
    cause TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE UNIQUE INDEX uptime_incidents_open_unique ON uptime_incidents(monitor_id) WHERE resolved_at IS NULL;
CREATE INDEX uptime_incidents_monitor_time_idx ON uptime_incidents(monitor_id, started_at DESC);
