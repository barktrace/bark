package environments

import (
	"context"
	"database/sql"
	"encoding/json"
	"sort"
	"strings"
)

// Environment is an environment name observed for a project and its persisted
// visibility preference.
type Environment struct {
	Name     string
	IsHidden bool
}

// List discovers environments from every telemetry category that carries an
// environment and overlays the project's persisted visibility settings.
func List(ctx context.Context, db *sql.DB, projectID string) ([]Environment, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT environment FROM (
			SELECT environment FROM events WHERE project_id = ?
			UNION SELECT environment FROM transactions WHERE project_id = ?
			UNION SELECT environment FROM logs WHERE project_id = ?
			UNION SELECT environment FROM project_sessions WHERE project_id = ?
			UNION SELECT cc.environment FROM cron_checkins cc JOIN cron_monitors cm ON cm.id = cc.monitor_id WHERE cm.project_id = ?
			UNION SELECT environment FROM replays WHERE project_id = ?
			UNION SELECT environment FROM profiles WHERE project_id = ?
			UNION SELECT environment FROM deploys WHERE project_id = ?
			UNION SELECT d.environment FROM deploys d JOIN project_releases pr ON pr.release_id = d.release_id WHERE d.project_id IS NULL AND pr.project_id = ?
			UNION SELECT name AS environment FROM project_environment_settings WHERE project_id = ?
		) observed WHERE environment != '' ORDER BY environment`, projectID, projectID, projectID, projectID, projectID, projectID, projectID, projectID, projectID, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	names := make(map[string]bool)
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		if name = strings.TrimSpace(name); name != "" {
			names[name] = false
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	metricRows, err := db.QueryContext(ctx, `SELECT tags FROM metric_points WHERE project_id = ?`, projectID)
	if err != nil {
		return nil, err
	}
	for metricRows.Next() {
		var raw []byte
		if err := metricRows.Scan(&raw); err != nil {
			_ = metricRows.Close()
			return nil, err
		}
		var tags map[string]any
		if json.Unmarshal(raw, &tags) == nil {
			name, _ := tags["environment"].(string)
			if name == "" {
				name, _ = tags["sentry.environment"].(string)
			}
			if name = strings.TrimSpace(name); name != "" {
				names[name] = false
			}
		}
	}
	if err := metricRows.Close(); err != nil {
		return nil, err
	}

	settings, err := db.QueryContext(ctx, `SELECT name, is_hidden FROM project_environment_settings WHERE project_id = ?`, projectID)
	if err != nil {
		return nil, err
	}
	for settings.Next() {
		var name string
		var hidden bool
		if err := settings.Scan(&name, &hidden); err != nil {
			_ = settings.Close()
			return nil, err
		}
		names[name] = hidden
	}
	if err := settings.Close(); err != nil {
		return nil, err
	}

	result := make([]Environment, 0, len(names))
	for name, hidden := range names {
		result = append(result, Environment{Name: name, IsHidden: hidden})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result, nil
}
