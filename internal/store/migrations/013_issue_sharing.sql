ALTER TABLE issues ADD COLUMN share_id TEXT;

CREATE UNIQUE INDEX issues_share_id_idx ON issues(share_id) WHERE share_id IS NOT NULL;

CREATE TABLE discarded_issue_fingerprints (
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    fingerprint TEXT NOT NULL,
    discarded_by TEXT REFERENCES users(id) ON DELETE SET NULL,
    discarded_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (project_id, fingerprint)
);
CREATE INDEX discarded_issue_fingerprints_time_idx
    ON discarded_issue_fingerprints(project_id, discarded_at DESC);
