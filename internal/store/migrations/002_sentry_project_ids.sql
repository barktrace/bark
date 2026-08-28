ALTER TABLE projects ADD COLUMN sentry_id TEXT;
UPDATE projects SET sentry_id = CAST(rowid AS TEXT);
CREATE UNIQUE INDEX projects_sentry_id_unique ON projects(sentry_id);
