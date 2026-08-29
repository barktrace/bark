ALTER TABLE issues ADD COLUMN issue_type TEXT NOT NULL DEFAULT 'error';
ALTER TABLE issues ADD COLUMN issue_category TEXT NOT NULL DEFAULT 'error';
CREATE INDEX issues_project_type_idx ON issues(project_id, issue_category, issue_type, last_seen_at DESC);

CREATE TABLE replay_issue_occurrences (
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    replay_id TEXT NOT NULL,
    segment_id INTEGER NOT NULL,
    issue_type TEXT NOT NULL CHECK (issue_type IN ('dead_click', 'rage_click')),
    dom_element TEXT NOT NULL,
    element TEXT NOT NULL DEFAULT '{}',
    click_count INTEGER NOT NULL DEFAULT 1,
    timestamp TEXT NOT NULL,
    issue_id TEXT NOT NULL REFERENCES issues(id) ON DELETE CASCADE,
    event_id TEXT NOT NULL REFERENCES events(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (project_id, replay_id, segment_id, issue_type, dom_element),
    UNIQUE (event_id)
);
CREATE INDEX replay_issue_occurrences_replay_idx
    ON replay_issue_occurrences(project_id, replay_id, segment_id);
CREATE INDEX replay_issue_occurrences_issue_idx
    ON replay_issue_occurrences(issue_id, timestamp DESC);
