CREATE TABLE upload_chunks (
    organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    checksum TEXT NOT NULL,
    blob_id TEXT NOT NULL REFERENCES blobs(id) ON DELETE CASCADE,
    size INTEGER NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY(organization_id, checksum)
);
CREATE INDEX upload_chunks_created_idx ON upload_chunks(created_at);

CREATE TABLE repositories (
    id TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    url TEXT,
    provider TEXT NOT NULL DEFAULT 'generic',
    status TEXT NOT NULL DEFAULT 'active',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(organization_id, name)
);
CREATE INDEX repositories_org_idx ON repositories(organization_id, name);

CREATE TABLE code_mappings (
    id TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    repository_id TEXT NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    default_branch TEXT NOT NULL DEFAULT '',
    stack_root TEXT NOT NULL,
    source_root TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(project_id, repository_id, stack_root)
);
