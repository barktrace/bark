// Package eventtags derives Sentry-compatible tag distributions from retained
// event payloads without maintaining a second copy of tag data.
package eventtags

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

type Value struct {
	Value     string
	Count     int64
	FirstSeen string
	LastSeen  string
}

type Tag struct {
	Key         string
	Name        string
	TotalValues int64
	Values      []Value
}

// List aggregates tags for a project, optionally restricted to one internal
// issue ID. Rows are streamed so the operation does not retain event payloads.
func List(ctx context.Context, db *sql.DB, projectID, issueID string) ([]Tag, error) {
	query := `
		SELECT e.timestamp, e.environment, e.platform, e.level, COALESCE(r.version, ''),
		       COALESCE(e.processed_payload, e.payload)
		FROM events e LEFT JOIN releases r ON r.id = e.release_id
		WHERE e.project_id = ?`
	arguments := []any{projectID}
	if strings.TrimSpace(issueID) != "" {
		query += ` AND e.issue_id = ?`
		arguments = append(arguments, issueID)
	}
	query += ` ORDER BY e.timestamp DESC`
	rows, err := db.QueryContext(ctx, query, arguments...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	tags := make(map[string]map[string]*Value)
	for rows.Next() {
		var timestamp, environment, platform, level, release string
		var payload []byte
		if err := rows.Scan(&timestamp, &environment, &platform, &level, &release, &payload); err != nil {
			return nil, err
		}
		for key, value := range valuesForEvent(payload, environment, platform, level, release) {
			values := tags[key]
			if values == nil {
				values = make(map[string]*Value)
				tags[key] = values
			}
			item := values[value]
			if item == nil {
				values[value] = &Value{Value: value, Count: 1, FirstSeen: timestamp, LastSeen: timestamp}
				continue
			}
			item.Count++
			if timestamp < item.FirstSeen {
				item.FirstSeen = timestamp
			}
			if timestamp > item.LastSeen {
				item.LastSeen = timestamp
			}
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	result := make([]Tag, 0, len(tags))
	for key, values := range tags {
		tag := Tag{Key: key, Name: displayName(key), Values: make([]Value, 0, len(values))}
		for _, value := range values {
			tag.TotalValues += value.Count
			tag.Values = append(tag.Values, *value)
		}
		sort.Slice(tag.Values, func(i, j int) bool {
			if tag.Values[i].Count != tag.Values[j].Count {
				return tag.Values[i].Count > tag.Values[j].Count
			}
			if tag.Values[i].LastSeen != tag.Values[j].LastSeen {
				return tag.Values[i].LastSeen > tag.Values[j].LastSeen
			}
			return tag.Values[i].Value < tag.Values[j].Value
		})
		result = append(result, tag)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Key < result[j].Key })
	return result, nil
}

func valuesForEvent(raw []byte, environment, platform, level, release string) map[string]string {
	result := make(map[string]string)
	var payload map[string]any
	if json.Unmarshal(raw, &payload) == nil {
		switch tags := payload["tags"].(type) {
		case map[string]any:
			for key, value := range tags {
				add(result, key, scalar(value))
			}
		case []any:
			for _, item := range tags {
				if pair, ok := item.([]any); ok && len(pair) == 2 {
					add(result, scalar(pair[0]), scalar(pair[1]))
				}
			}
		}
		add(result, "sentry:transaction", scalar(payload["transaction"]))
		add(result, "sentry:server_name", scalar(payload["server_name"]))
		if user, ok := payload["user"].(map[string]any); ok {
			for _, key := range []string{"email", "username", "id", "ip_address"} {
				if value := scalar(user[key]); value != "" {
					add(result, "sentry:user", value)
					break
				}
			}
		}
		if request, ok := payload["request"].(map[string]any); ok {
			add(result, "url", scalar(request["url"]))
		}
		if contexts, ok := payload["contexts"].(map[string]any); ok {
			addContext(result, contexts, "browser")
			addContext(result, contexts, "device")
			addContext(result, contexts, "os")
			addContext(result, contexts, "runtime")
		}
	}
	add(result, "sentry:environment", environment)
	add(result, "sentry:platform", platform)
	add(result, "sentry:level", level)
	add(result, "sentry:release", release)
	return result
}

func addContext(destination map[string]string, contexts map[string]any, key string) {
	contextValue, ok := contexts[key].(map[string]any)
	if !ok {
		return
	}
	name, version := scalar(contextValue["name"]), scalar(contextValue["version"])
	if name == "" {
		name = scalar(contextValue["model"])
	}
	add(destination, key, strings.TrimSpace(name+" "+version))
}

func add(destination map[string]string, key, value string) {
	key, value = strings.TrimSpace(key), strings.TrimSpace(value)
	if key != "" && value != "" {
		destination[key] = value
	}
}

func scalar(value any) string {
	switch value := value.(type) {
	case string:
		return value
	case float64, bool, json.Number:
		return fmt.Sprint(value)
	default:
		return ""
	}
}

func displayName(key string) string {
	if name, ok := map[string]string{
		"sentry:environment": "Environment",
		"sentry:level":       "Level",
		"sentry:platform":    "Platform",
		"sentry:release":     "Release",
		"sentry:server_name": "Server Name",
		"sentry:transaction": "Transaction",
		"sentry:user":        "User",
	}[key]; ok {
		return name
	}
	return key
}
