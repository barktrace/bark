ALTER TABLE issues ADD COLUMN priority TEXT NOT NULL DEFAULT 'medium' CHECK (priority IN ('low', 'medium', 'high', 'critical'));
ALTER TABLE issues ADD COLUMN assignee_user_id TEXT REFERENCES users(id) ON DELETE SET NULL;
ALTER TABLE issues ADD COLUMN bookmarked INTEGER NOT NULL DEFAULT 0;
ALTER TABLE issues ADD COLUMN snoozed_until TEXT;

CREATE TABLE issue_activities (
    id TEXT PRIMARY KEY,
    issue_id TEXT NOT NULL REFERENCES issues(id) ON DELETE CASCADE,
    user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
    kind TEXT NOT NULL CHECK (kind IN ('status', 'priority', 'assignment', 'bookmark', 'snooze', 'comment')),
    value TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX issue_activities_issue_time_idx ON issue_activities(issue_id, created_at DESC);

CREATE TABLE api_tokens (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    token_hash BLOB NOT NULL UNIQUE,
    token_prefix TEXT NOT NULL,
    expires_at TEXT,
    last_used_at TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX api_tokens_user_idx ON api_tokens(user_id, created_at DESC);

CREATE TABLE organization_invitations (
    id TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    email TEXT NOT NULL COLLATE NOCASE,
    role TEXT NOT NULL CHECK (role IN ('admin', 'member', 'viewer')),
    invited_by TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash BLOB NOT NULL UNIQUE,
    expires_at TEXT NOT NULL,
    accepted_at TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE UNIQUE INDEX organization_invitations_pending_email ON organization_invitations(organization_id, email) WHERE accepted_at IS NULL;

CREATE TABLE alert_rules (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    trigger TEXT NOT NULL CHECK (trigger IN ('new_issue', 'regression', 'uptime_down')),
    destination_type TEXT NOT NULL CHECK (destination_type IN ('webhook', 'slack')),
    destination_url TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX alert_rules_project_idx ON alert_rules(project_id, created_at DESC);

CREATE TABLE alert_deliveries (
    id TEXT PRIMARY KEY,
    rule_id TEXT NOT NULL REFERENCES alert_rules(id) ON DELETE CASCADE,
    event_type TEXT NOT NULL,
    payload BLOB NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending', 'sent', 'failed')),
    attempts INTEGER NOT NULL DEFAULT 0,
    last_error TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    delivered_at TEXT
);
CREATE INDEX alert_deliveries_pending_idx ON alert_deliveries(status, created_at);

CREATE TABLE project_sessions (
    id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    release_id TEXT REFERENCES releases(id) ON DELETE SET NULL,
    environment TEXT NOT NULL DEFAULT '',
    distinct_id TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'ok',
    started_at TEXT NOT NULL,
    duration REAL,
    errors INTEGER NOT NULL DEFAULT 0,
    received_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(project_id, session_id)
);
CREATE INDEX project_sessions_release_idx ON project_sessions(project_id, release_id, started_at DESC);

CREATE TABLE spans (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    transaction_id TEXT REFERENCES transactions(id) ON DELETE CASCADE,
    trace_id TEXT NOT NULL,
    span_id TEXT NOT NULL,
    parent_span_id TEXT NOT NULL DEFAULT '',
    operation TEXT NOT NULL DEFAULT '',
    description TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT '',
    started_at TEXT NOT NULL,
    finished_at TEXT NOT NULL,
    duration_ms REAL NOT NULL,
    data BLOB NOT NULL DEFAULT '{}',
    UNIQUE(project_id, trace_id, span_id)
);
CREATE INDEX spans_trace_idx ON spans(project_id, trace_id, started_at);

ALTER TABLE organizations ADD COLUMN retention_days INTEGER NOT NULL DEFAULT 30 CHECK (retention_days BETWEEN 1 AND 3650);
