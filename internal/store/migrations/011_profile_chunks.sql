ALTER TABLE profiles ADD COLUMN profiler_id TEXT NOT NULL DEFAULT '';
ALTER TABLE profiles ADD COLUMN chunk_id TEXT NOT NULL DEFAULT '';
CREATE INDEX profiles_profiler_time_idx ON profiles(project_id, profiler_id, started_at DESC) WHERE profiler_id != '';
