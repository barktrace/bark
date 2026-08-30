CREATE TABLE project_environment_settings (
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    is_hidden INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (project_id, name),
    CHECK (name != '')
);
CREATE INDEX project_environment_settings_visibility_idx
    ON project_environment_settings(project_id, is_hidden, name);
