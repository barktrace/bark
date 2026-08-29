ALTER TABLE events ADD COLUMN processed_payload BLOB;

CREATE TABLE blobs (
    id TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    project_id TEXT REFERENCES projects(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    storage_key TEXT NOT NULL,
    checksum TEXT NOT NULL,
    size INTEGER NOT NULL,
    content_type TEXT NOT NULL DEFAULT 'application/octet-stream',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX blobs_project_kind_idx ON blobs(project_id, kind, created_at DESC);

CREATE TABLE project_artifacts (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    release_id TEXT REFERENCES releases(id) ON DELETE CASCADE,
    blob_id TEXT NOT NULL REFERENCES blobs(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    artifact_type TEXT NOT NULL CHECK (artifact_type IN ('source', 'sourcemap', 'debug_file', 'proguard')),
    debug_id TEXT NOT NULL DEFAULT '',
    dist TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(project_id, release_id, name, dist)
);
CREATE INDEX project_artifacts_lookup_idx ON project_artifacts(project_id, release_id, artifact_type, name);
CREATE UNIQUE INDEX project_artifacts_unique_idx ON project_artifacts(project_id, COALESCE(release_id, ''), name, dist);
CREATE INDEX project_artifacts_debug_idx ON project_artifacts(project_id, debug_id) WHERE debug_id != '';

CREATE TABLE cron_monitors (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    slug TEXT NOT NULL,
    name TEXT NOT NULL,
    schedule_type TEXT NOT NULL DEFAULT 'interval' CHECK (schedule_type IN ('interval', 'crontab')),
    schedule_value TEXT NOT NULL DEFAULT '5',
    timezone TEXT NOT NULL DEFAULT 'UTC',
    checkin_margin INTEGER NOT NULL DEFAULT 5,
    max_runtime INTEGER NOT NULL DEFAULT 30,
    status TEXT NOT NULL DEFAULT 'unknown' CHECK (status IN ('unknown', 'ok', 'in_progress', 'error', 'missed')),
    last_checkin_at TEXT,
    next_checkin_at TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(project_id, slug)
);
CREATE INDEX cron_monitors_due_idx ON cron_monitors(next_checkin_at, status);

CREATE TABLE cron_checkins (
    id TEXT PRIMARY KEY,
    checkin_id TEXT NOT NULL,
    monitor_id TEXT NOT NULL REFERENCES cron_monitors(id) ON DELETE CASCADE,
    status TEXT NOT NULL CHECK (status IN ('in_progress', 'ok', 'error', 'missed')),
    duration REAL,
    release TEXT NOT NULL DEFAULT '',
    environment TEXT NOT NULL DEFAULT '',
    started_at TEXT NOT NULL,
    finished_at TEXT,
    payload BLOB NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(monitor_id, checkin_id)
);
CREATE INDEX cron_checkins_monitor_time_idx ON cron_checkins(monitor_id, started_at DESC);

CREATE TABLE event_attachments (
    id TEXT PRIMARY KEY,
    event_id TEXT NOT NULL REFERENCES events(id) ON DELETE CASCADE,
    blob_id TEXT NOT NULL REFERENCES blobs(id) ON DELETE CASCADE,
    filename TEXT NOT NULL,
    attachment_type TEXT NOT NULL DEFAULT 'event.attachment',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX event_attachments_event_idx ON event_attachments(event_id, created_at);

CREATE TABLE user_feedback (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    event_id TEXT NOT NULL DEFAULT '',
    name TEXT NOT NULL DEFAULT '',
    email TEXT NOT NULL DEFAULT '',
    comments TEXT NOT NULL,
    url TEXT NOT NULL DEFAULT '',
    payload BLOB NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX user_feedback_project_time_idx ON user_feedback(project_id, created_at DESC);

CREATE TABLE replays (
    id TEXT PRIMARY KEY,
    replay_id TEXT NOT NULL,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    event_blob_id TEXT REFERENCES blobs(id) ON DELETE SET NULL,
    recording_blob_id TEXT REFERENCES blobs(id) ON DELETE SET NULL,
    segment_id INTEGER NOT NULL DEFAULT 0,
    environment TEXT NOT NULL DEFAULT '',
    release TEXT NOT NULL DEFAULT '',
    user_id TEXT NOT NULL DEFAULT '',
    started_at TEXT NOT NULL,
    finished_at TEXT NOT NULL,
    error_count INTEGER NOT NULL DEFAULT 0,
    url TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(project_id, replay_id, segment_id)
);
CREATE INDEX replays_project_time_idx ON replays(project_id, finished_at DESC);

CREATE TABLE profiles (
    id TEXT PRIMARY KEY,
    profile_id TEXT NOT NULL,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    transaction_id TEXT,
    blob_id TEXT NOT NULL REFERENCES blobs(id) ON DELETE CASCADE,
    platform TEXT NOT NULL DEFAULT '',
    environment TEXT NOT NULL DEFAULT '',
    release TEXT NOT NULL DEFAULT '',
    started_at TEXT NOT NULL,
    duration_ms REAL NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(project_id, profile_id)
);
CREATE INDEX profiles_project_time_idx ON profiles(project_id, started_at DESC);

CREATE TABLE metric_points (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    metric_type TEXT NOT NULL DEFAULT 'gauge',
    value REAL NOT NULL,
    unit TEXT NOT NULL DEFAULT '',
    tags BLOB NOT NULL DEFAULT '{}',
    timestamp TEXT NOT NULL,
    received_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX metric_points_project_name_time_idx ON metric_points(project_id, name, timestamp DESC);

CREATE TABLE client_reports (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    timestamp TEXT NOT NULL,
    payload BLOB NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

ALTER TABLE alert_deliveries RENAME TO alert_deliveries_legacy;
ALTER TABLE alert_rules RENAME TO alert_rules_legacy;
DROP INDEX alert_deliveries_pending_idx;
DROP INDEX alert_rules_project_idx;

CREATE TABLE alert_rules (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    trigger TEXT NOT NULL CHECK (trigger IN ('new_issue', 'regression', 'uptime_down', 'cron_missed', 'metric_threshold', 'user_feedback')),
    destination_type TEXT NOT NULL CHECK (destination_type IN ('webhook', 'slack', 'email')),
    destination_url TEXT NOT NULL DEFAULT '',
    destination_email TEXT NOT NULL DEFAULT '',
    conditions BLOB NOT NULL DEFAULT '{}',
    frequency_minutes INTEGER NOT NULL DEFAULT 0,
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

INSERT INTO alert_rules(id, project_id, name, trigger, destination_type, destination_url, enabled, created_at)
SELECT id, project_id, name, trigger, destination_type, destination_url, enabled, created_at FROM alert_rules_legacy;
INSERT INTO alert_deliveries(id, rule_id, event_type, payload, status, attempts, last_error, created_at, delivered_at)
SELECT id, rule_id, event_type, payload, status, attempts, last_error, created_at, delivered_at FROM alert_deliveries_legacy;
DROP TABLE alert_deliveries_legacy;
DROP TABLE alert_rules_legacy;

ALTER TABLE releases ADD COLUMN released_at TEXT;

CREATE TABLE commits (
    id TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    repository TEXT NOT NULL DEFAULT '',
    external_id TEXT NOT NULL,
    message TEXT NOT NULL DEFAULT '',
    author_name TEXT NOT NULL DEFAULT '',
    author_email TEXT NOT NULL DEFAULT '',
    committed_at TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(organization_id, repository, external_id)
);
CREATE INDEX commits_org_time_idx ON commits(organization_id, committed_at DESC);

CREATE TABLE commit_files (
    commit_id TEXT NOT NULL REFERENCES commits(id) ON DELETE CASCADE,
    filename TEXT NOT NULL,
    change_type TEXT NOT NULL DEFAULT 'M',
    PRIMARY KEY(commit_id, filename)
);

CREATE TABLE release_commits (
    release_id TEXT NOT NULL REFERENCES releases(id) ON DELETE CASCADE,
    commit_id TEXT NOT NULL REFERENCES commits(id) ON DELETE CASCADE,
    sequence INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY(release_id, commit_id)
);
CREATE INDEX release_commits_sequence_idx ON release_commits(release_id, sequence);

CREATE TABLE deploys (
    id TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    release_id TEXT NOT NULL REFERENCES releases(id) ON DELETE CASCADE,
    project_id TEXT REFERENCES projects(id) ON DELETE SET NULL,
    environment TEXT NOT NULL,
    name TEXT NOT NULL DEFAULT '',
    url TEXT NOT NULL DEFAULT '',
    started_at TEXT NOT NULL,
    finished_at TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX deploys_release_time_idx ON deploys(release_id, started_at DESC);

CREATE TABLE issue_suspect_commits (
    issue_id TEXT NOT NULL REFERENCES issues(id) ON DELETE CASCADE,
    commit_id TEXT NOT NULL REFERENCES commits(id) ON DELETE CASCADE,
    score INTEGER NOT NULL DEFAULT 0,
    reason TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY(issue_id, commit_id)
);
