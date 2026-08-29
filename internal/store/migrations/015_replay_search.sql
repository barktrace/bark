CREATE TABLE replay_error_links (
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    replay_id TEXT NOT NULL,
    segment_id INTEGER NOT NULL DEFAULT 0,
    event_id TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (project_id, replay_id, segment_id, event_id)
);
CREATE INDEX replay_error_links_event_idx ON replay_error_links(project_id, event_id, replay_id);
CREATE INDEX replay_error_links_replay_idx ON replay_error_links(project_id, replay_id, segment_id);

CREATE TABLE blob_deletion_queue (
    storage_key TEXT PRIMARY KEY,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    attempts INTEGER NOT NULL DEFAULT 0,
    last_error TEXT NOT NULL DEFAULT ''
);
