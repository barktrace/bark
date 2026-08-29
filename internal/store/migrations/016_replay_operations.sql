CREATE TABLE replay_views (
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    replay_id TEXT NOT NULL,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    viewed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (project_id, replay_id, user_id)
);
CREATE INDEX replay_views_replay_idx ON replay_views(project_id, replay_id, viewed_at DESC);

CREATE TABLE replay_clicks (
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    replay_id TEXT NOT NULL,
    segment_id INTEGER NOT NULL,
    sequence INTEGER NOT NULL,
    node_id INTEGER NOT NULL,
    timestamp TEXT NOT NULL,
    dom_element TEXT NOT NULL DEFAULT '',
    element TEXT NOT NULL DEFAULT '{}',
    is_dead INTEGER NOT NULL DEFAULT 0,
    is_rage INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (project_id, replay_id, segment_id, sequence)
);
CREATE INDEX replay_clicks_replay_idx ON replay_clicks(project_id, replay_id, timestamp);
CREATE INDEX replay_clicks_selector_idx ON replay_clicks(project_id, dom_element, is_dead, is_rage);

CREATE TABLE replay_deletion_jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    range_start TEXT NOT NULL,
    range_end TEXT NOT NULL,
    environments TEXT NOT NULL DEFAULT '[]',
    query TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'in_progress', 'completed', 'failed')),
    count_deleted INTEGER NOT NULL DEFAULT 0,
    last_error TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX replay_deletion_jobs_pending_idx ON replay_deletion_jobs(status, created_at);
