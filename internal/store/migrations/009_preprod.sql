CREATE TABLE preprod_builds (
    id TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    blob_id TEXT NOT NULL REFERENCES blobs(id) ON DELETE CASCADE,
    checksum TEXT NOT NULL,
    format TEXT NOT NULL DEFAULT '',
    build_configuration TEXT NOT NULL DEFAULT '',
    release_notes TEXT NOT NULL DEFAULT '',
    install_groups BLOB NOT NULL DEFAULT '[]',
    vcs_info BLOB NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(project_id, checksum)
);
CREATE INDEX preprod_builds_org_time_idx ON preprod_builds(organization_id, created_at DESC);

CREATE TABLE snapshot_upload_tokens (
    id TEXT PRIMARY KEY,
    token_hash BLOB NOT NULL UNIQUE,
    organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX snapshot_upload_tokens_expiry_idx ON snapshot_upload_tokens(expires_at);

CREATE TABLE snapshot_objects (
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    object_key TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    blob_id TEXT NOT NULL REFERENCES blobs(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY(project_id, object_key)
);
CREATE INDEX snapshot_objects_hash_idx ON snapshot_objects(project_id, content_hash);

CREATE TABLE preprod_snapshots (
    id TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    app_id TEXT NOT NULL,
    image_count INTEGER NOT NULL,
    manifest BLOB NOT NULL,
    head_sha TEXT NOT NULL DEFAULT '',
    base_sha TEXT NOT NULL DEFAULT '',
    head_ref TEXT NOT NULL DEFAULT '',
    base_ref TEXT NOT NULL DEFAULT '',
    pr_number INTEGER,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX preprod_snapshots_latest_idx ON preprod_snapshots(organization_id, app_id, head_ref, created_at DESC);
