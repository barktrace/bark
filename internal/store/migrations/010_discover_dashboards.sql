CREATE TABLE dashboards (
    id TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    project_id TEXT REFERENCES projects(id) ON DELETE CASCADE,
    created_by TEXT REFERENCES users(id) ON DELETE SET NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX dashboards_org_updated_idx ON dashboards(organization_id, updated_at DESC);
CREATE INDEX dashboards_project_updated_idx ON dashboards(project_id, updated_at DESC) WHERE project_id IS NOT NULL;

CREATE TABLE dashboard_widgets (
    id TEXT PRIMARY KEY,
    dashboard_id TEXT NOT NULL REFERENCES dashboards(id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    dataset TEXT NOT NULL CHECK (dataset IN ('errors', 'transactions', 'spans', 'logs', 'metrics')),
    display_type TEXT NOT NULL DEFAULT 'table' CHECK (display_type IN ('table', 'number', 'line', 'bar', 'area')),
    fields BLOB NOT NULL DEFAULT '[]',
    query TEXT NOT NULL DEFAULT '',
    environment TEXT NOT NULL DEFAULT '',
    release TEXT NOT NULL DEFAULT '',
    stats_period TEXT NOT NULL DEFAULT '24h',
    order_by TEXT NOT NULL DEFAULT '',
    result_limit INTEGER NOT NULL DEFAULT 20 CHECK (result_limit BETWEEN 1 AND 100),
    position INTEGER NOT NULL DEFAULT 0,
    layout BLOB NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX dashboard_widgets_dashboard_position_idx ON dashboard_widgets(dashboard_id, position, created_at);
