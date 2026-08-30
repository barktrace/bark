package httpapi

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/barktrace/bark/internal/auth"
	"github.com/barktrace/bark/internal/discover"
	"github.com/google/uuid"
)

func (s *Server) sentryAuthInfo(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	writeJSON(w, http.StatusOK, map[string]any{
		"auth": map[string]any{"scopes": []string{"event:read", "event:write", "member:read", "org:read", "project:read", "project:write", "project:releases", "team:read", "team:write"}},
		"user": map[string]string{"id": principal.UserID, "email": principal.Email},
	})
}

func (s *Server) sentryUserRegions(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"regions": []any{}})
}

func (s *Server) sentryOrganizations(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	items := make([]map[string]any, 0, len(principal.Memberships))
	for _, membership := range principal.Memberships {
		var createdAt string
		_ = s.store.DB.QueryRowContext(r.Context(), `SELECT created_at FROM organizations WHERE id = ?`, membership.OrganizationID).Scan(&createdAt)
		items = append(items, map[string]any{"id": membership.OrganizationID, "slug": membership.OrganizationSlug, "name": membership.OrganizationName, "dateCreated": normalizeAPITime(createdAt), "isEarlyAdopter": false, "require2FA": false, "requireEmailVerification": false, "features": []string{}})
	}
	writeJSON(w, http.StatusOK, items)
}

func (s *Server) sentryOrganizationProjects(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	organizationID, ok := s.authorizedOrganizationSlug(r, principal, r.PathValue("org_slug"))
	if !ok {
		writeError(w, http.StatusNotFound, "organization not found")
		return
	}
	if r.Method == http.MethodPost {
		s.createSentryProject(w, r, principal, organizationID)
		return
	}
	rows, err := s.store.DB.QueryContext(r.Context(), `
		SELECT p.sentry_id, p.slug, p.name, COALESCE(p.platform, ''),
		       COALESCE((SELECT t.slug FROM team_projects tp JOIN teams t ON t.id = tp.team_id WHERE tp.project_id = p.id ORDER BY t.name LIMIT 1), '')
		FROM projects p
		LEFT JOIN project_memberships pm ON pm.project_id = p.id AND pm.user_id = ?
		WHERE p.organization_id = ? AND COALESCE(pm.role, '') != 'none'
		ORDER BY p.name
	`, principal.UserID, organizationID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list projects")
		return
	}
	defer rows.Close()
	items := make([]map[string]any, 0)
	for rows.Next() {
		var id, slug, name, platform, teamSlug string
		if rows.Scan(&id, &slug, &name, &platform, &teamSlug) == nil {
			items = append(items, map[string]any{"id": id, "slug": slug, "name": name, "platform": platform, "team": nullableText(teamSlug)})
		}
	}
	writeJSON(w, http.StatusOK, items)
}

func (s *Server) sentryOrganizationReleases(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	organizationID, ok := s.authorizedOrganizationSlug(r, principal, r.PathValue("org_slug"))
	if !ok {
		writeError(w, http.StatusNotFound, "organization not found")
		return
	}
	s.writeSentryReleaseList(w, r, organizationID, "")
}

func (s *Server) sentryProjectReleases(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	projectID, _, ok := s.projectBySlugs(r, r.PathValue("org_slug"), r.PathValue("project_slug"))
	if !ok || !s.canAccessProject(r, principal, projectID) {
		writeError(w, http.StatusNotFound, "project not found")
		return
	}
	var organizationID string
	_ = s.store.DB.QueryRowContext(r.Context(), `SELECT organization_id FROM projects WHERE id = ?`, projectID).Scan(&organizationID)
	s.writeSentryReleaseList(w, r, organizationID, projectID)
}

func (s *Server) writeSentryReleaseList(w http.ResponseWriter, r *http.Request, organizationID, projectID string) {
	rows, err := s.store.DB.QueryContext(r.Context(), `
		SELECT DISTINCT rel.id FROM releases rel LEFT JOIN project_releases pr ON pr.release_id = rel.id
		WHERE rel.organization_id = ? AND (? = '' OR pr.project_id = ?)
		ORDER BY rel.last_seen_at DESC LIMIT 100
	`, organizationID, projectID, projectID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list releases")
		return
	}
	releaseIDs := make([]string, 0)
	for rows.Next() {
		var id string
		if rows.Scan(&id) == nil {
			releaseIDs = append(releaseIDs, id)
		}
	}
	_ = rows.Close()
	items := make([]map[string]any, 0, len(releaseIDs))
	for _, id := range releaseIDs {
		item, err := s.sentryReleaseResponse(r, id)
		if err == nil {
			items = append(items, item)
		}
	}
	writeJSON(w, http.StatusOK, items)
}

func (s *Server) deleteSentryRelease(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	organizationID, releaseID, ok := s.releaseBySlugVersion(r, r.PathValue("org_slug"), r.PathValue("version"))
	if !ok {
		writeError(w, http.StatusNotFound, "release not found")
		return
	}
	membership, allowed := principal.Membership(organizationID)
	if !allowed || membership.Role == "viewer" {
		writeError(w, http.StatusForbidden, "release write access required")
		return
	}
	if _, err := s.store.DB.ExecContext(r.Context(), `DELETE FROM releases WHERE id = ?`, releaseID); err != nil {
		writeError(w, http.StatusInternalServerError, "could not delete release")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) sentryPreviousRelease(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	organizationID, releaseID, ok := s.releaseBySlugVersion(r, r.PathValue("org_slug"), r.PathValue("version"))
	if !ok {
		writeError(w, http.StatusNotFound, "release not found")
		return
	}
	if _, allowed := principal.Membership(organizationID); !allowed {
		writeError(w, http.StatusForbidden, "organization access required")
		return
	}
	var previousID string
	err := s.store.DB.QueryRowContext(r.Context(), `
		SELECT previous.id FROM releases current JOIN releases previous ON previous.organization_id = current.organization_id
		WHERE current.id = ? AND previous.first_seen_at < current.first_seen_at
		  AND EXISTS (SELECT 1 FROM release_commits rc WHERE rc.release_id = previous.id)
		ORDER BY previous.first_seen_at DESC LIMIT 1
	`, releaseID).Scan(&previousID)
	if errors.Is(err, sql.ErrNoRows) {
		writeJSON(w, http.StatusOK, map[string]any{})
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not find previous release")
		return
	}
	item, err := s.sentryReleaseResponse(r, previousID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not load previous release")
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) sentryReleaseDeployList(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	organizationID, releaseID, ok := s.releaseBySlugVersion(r, r.PathValue("org_slug"), r.PathValue("version"))
	if !ok {
		writeError(w, http.StatusNotFound, "release not found")
		return
	}
	if _, allowed := principal.Membership(organizationID); !allowed {
		writeError(w, http.StatusForbidden, "organization access required")
		return
	}
	rows, err := s.store.DB.QueryContext(r.Context(), `SELECT environment, name, url, started_at, COALESCE(finished_at, '') FROM deploys WHERE release_id = ? ORDER BY started_at DESC`, releaseID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list deploys")
		return
	}
	defer rows.Close()
	items := make([]map[string]any, 0)
	for rows.Next() {
		var environment, name, targetURL, startedAt, finishedAt string
		if rows.Scan(&environment, &name, &targetURL, &startedAt, &finishedAt) == nil {
			items = append(items, map[string]any{"environment": environment, "name": nullableText(name), "url": nullableText(targetURL), "dateStarted": nullableAPITime(startedAt), "dateFinished": nullableAPITime(finishedAt)})
		}
	}
	writeJSON(w, http.StatusOK, items)
}

func (s *Server) sentryOrganizationMonitors(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	organizationID, ok := s.authorizedOrganizationSlug(r, principal, r.PathValue("org_slug"))
	if !ok {
		writeError(w, http.StatusNotFound, "organization not found")
		return
	}
	rows, err := s.store.DB.QueryContext(r.Context(), `SELECT m.id, m.slug, m.name, m.status FROM cron_monitors m JOIN projects p ON p.id = m.project_id WHERE p.organization_id = ? ORDER BY m.name`, organizationID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list monitors")
		return
	}
	defer rows.Close()
	items := make([]map[string]string, 0)
	for rows.Next() {
		var id, slug, name, status string
		if rows.Scan(&id, &slug, &name, &status) == nil {
			items = append(items, map[string]string{"id": id, "slug": slug, "name": name, "status": status})
		}
	}
	writeJSON(w, http.StatusOK, items)
}

func (s *Server) sentryOrganizationRepositories(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	organizationID, ok := s.authorizedOrganizationSlug(r, principal, r.PathValue("org_slug"))
	if !ok {
		writeError(w, http.StatusNotFound, "organization not found")
		return
	}
	rows, err := s.store.DB.QueryContext(r.Context(), `SELECT id, name, COALESCE(url, ''), provider, status, created_at FROM repositories WHERE organization_id = ? ORDER BY name`, organizationID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list repositories")
		return
	}
	defer rows.Close()
	items := make([]map[string]any, 0)
	for rows.Next() {
		var id, name, targetURL, provider, status, createdAt string
		if rows.Scan(&id, &name, &targetURL, &provider, &status, &createdAt) == nil {
			items = append(items, map[string]any{"id": id, "name": name, "url": nullableText(targetURL), "provider": map[string]string{"id": provider, "name": provider}, "status": status, "dateCreated": normalizeAPITime(createdAt)})
		}
	}
	writeJSON(w, http.StatusOK, items)
}

func (s *Server) sentryBulkCodeMappings(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	organizationID, ok := s.authorizedOrganizationSlug(r, principal, r.PathValue("org_slug"))
	if !ok {
		writeError(w, http.StatusNotFound, "organization not found")
		return
	}
	var input struct {
		Project       string `json:"project"`
		Repository    string `json:"repository"`
		DefaultBranch string `json:"defaultBranch"`
		Mappings      []struct {
			StackRoot  string `json:"stackRoot"`
			SourceRoot string `json:"sourceRoot"`
		} `json:"mappings"`
	}
	if err := decodeJSON(w, r, &input); err != nil {
		return
	}
	var projectID, repositoryID string
	if err := s.store.DB.QueryRowContext(r.Context(), `SELECT id FROM projects WHERE organization_id = ? AND slug = ?`, organizationID, input.Project).Scan(&projectID); err != nil || !s.canManageProject(r, principal, projectID) {
		writeError(w, http.StatusBadRequest, "project is unknown or not writable")
		return
	}
	if err := s.store.DB.QueryRowContext(r.Context(), `SELECT id FROM repositories WHERE organization_id = ? AND (id = ? OR name = ?)`, organizationID, input.Repository, input.Repository).Scan(&repositoryID); err != nil {
		writeError(w, http.StatusBadRequest, "repository is unknown")
		return
	}
	if len(input.Mappings) == 0 || len(input.Mappings) > 1000 {
		writeError(w, http.StatusBadRequest, "one to 1000 mappings are required")
		return
	}
	tx, err := s.store.DB.BeginTx(r.Context(), nil)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not update code mappings")
		return
	}
	defer tx.Rollback()
	created, updated, failed := 0, 0, 0
	results := make([]map[string]any, 0, len(input.Mappings))
	for _, mapping := range input.Mappings {
		mapping.StackRoot = strings.TrimSpace(mapping.StackRoot)
		mapping.SourceRoot = strings.TrimSpace(mapping.SourceRoot)
		if mapping.StackRoot == "" || mapping.SourceRoot == "" {
			failed++
			results = append(results, map[string]any{"stackRoot": mapping.StackRoot, "sourceRoot": mapping.SourceRoot, "status": "error", "detail": "roots must not be empty"})
			continue
		}
		var exists int
		_ = tx.QueryRowContext(r.Context(), `SELECT COUNT(*) FROM code_mappings WHERE project_id = ? AND repository_id = ? AND stack_root = ?`, projectID, repositoryID, mapping.StackRoot).Scan(&exists)
		_, err := tx.ExecContext(r.Context(), `INSERT INTO code_mappings(id, organization_id, project_id, repository_id, default_branch, stack_root, source_root) VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT(project_id, repository_id, stack_root) DO UPDATE SET source_root = excluded.source_root, default_branch = excluded.default_branch, updated_at = CURRENT_TIMESTAMP`, uuid.NewString(), organizationID, projectID, repositoryID, strings.TrimSpace(input.DefaultBranch), mapping.StackRoot, mapping.SourceRoot)
		if err != nil {
			failed++
			results = append(results, map[string]any{"stackRoot": mapping.StackRoot, "sourceRoot": mapping.SourceRoot, "status": "error", "detail": err.Error()})
			continue
		}
		status := "created"
		if exists > 0 {
			status = "updated"
			updated++
		} else {
			created++
		}
		results = append(results, map[string]any{"stackRoot": mapping.StackRoot, "sourceRoot": mapping.SourceRoot, "status": status, "detail": nil})
	}
	if err := tx.Commit(); err != nil {
		writeError(w, http.StatusInternalServerError, "could not commit code mappings")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"created": created, "updated": updated, "errors": failed, "mappings": results})
}

func (s *Server) sentryOrganizationEvents(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	organizationID, ok := s.authorizedOrganizationSlug(r, principal, r.PathValue("org_slug"))
	if !ok {
		writeError(w, http.StatusNotFound, "organization not found")
		return
	}
	projectIDs, err := s.discoverProjectIDs(r, principal, organizationID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not authorize projects")
		return
	}
	request, err := discoverRequestFromQuery(r, projectIDs)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	result, err := discover.Query(r.Context(), s.store.DB, request)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) sentryProjectEvents(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	projectID, _, ok := s.projectBySlugs(r, r.PathValue("org_slug"), r.PathValue("project_slug"))
	if !ok || !s.canAccessProject(r, principal, projectID) {
		writeError(w, http.StatusNotFound, "project not found")
		return
	}
	rows, err := s.store.DB.QueryContext(r.Context(), `SELECT e.event_id, e.timestamp, i.title, e.payload FROM events e JOIN issues i ON i.id = e.issue_id WHERE e.project_id = ? ORDER BY e.timestamp DESC LIMIT 100`, projectID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list events")
		return
	}
	defer rows.Close()
	items := make([]map[string]any, 0)
	for rows.Next() {
		var eventID, timestamp, title string
		var payload []byte
		if rows.Scan(&eventID, &timestamp, &title, &payload) == nil {
			var event map[string]any
			_ = json.Unmarshal(payload, &event)
			items = append(items, map[string]any{"eventID": eventID, "dateCreated": normalizeAPITime(timestamp), "title": title, "user": event["user"], "tags": sentryEventTags(event)})
		}
	}
	writeJSON(w, http.StatusOK, items)
}

func (s *Server) sentryProjectIssues(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	projectID, _, ok := s.projectBySlugs(r, r.PathValue("org_slug"), r.PathValue("project_slug"))
	if !ok || !s.canAccessProject(r, principal, projectID) {
		writeError(w, http.StatusNotFound, "project not found")
		return
	}
	if r.Method == http.MethodPut {
		if !s.canWriteProject(r, principal, projectID) {
			writeError(w, http.StatusForbidden, "project write access required")
			return
		}
		var input struct {
			Status         string `json:"status"`
			SnoozeDuration *int64 `json:"snoozeDuration"`
		}
		if err := decodeJSON(w, r, &input); err != nil {
			return
		}
		if input.Status != "resolved" && input.Status != "unresolved" && input.Status != "ignored" {
			writeError(w, http.StatusBadRequest, "invalid issue status")
			return
		}
		query, args := `UPDATE issues SET status = ? WHERE project_id = ?`, []any{input.Status, projectID}
		if ids := r.URL.Query()["id"]; len(ids) > 0 {
			placeholders := make([]string, 0, len(ids))
			for _, id := range ids {
				if _, err := strconv.ParseInt(id, 10, 64); err != nil {
					writeError(w, http.StatusBadRequest, "issue ids must be numeric")
					return
				}
				placeholders = append(placeholders, "?")
				args = append(args, id)
			}
			query += ` AND rowid IN (` + strings.Join(placeholders, ",") + `)`
		} else if status := strings.TrimSpace(r.URL.Query().Get("status")); status != "" {
			query += ` AND status = ?`
			args = append(args, status)
		}
		if _, err := s.store.DB.ExecContext(r.Context(), query, args...); err != nil {
			writeError(w, http.StatusInternalServerError, "could not update issues")
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": input.Status})
		return
	}
	query := strings.TrimSpace(r.URL.Query().Get("query"))
	status := strings.TrimSpace(r.URL.Query().Get("status"))
	rows, err := s.store.DB.QueryContext(r.Context(), `SELECT rowid, title, last_seen_at, status, level, issue_type, issue_category FROM issues WHERE project_id = ? AND (? = '' OR title LIKE '%' || ? || '%' OR issue_type LIKE '%' || ? || '%') AND (? = '' OR status = ?) ORDER BY last_seen_at DESC LIMIT 100`, projectID, query, query, query, status, status)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list issues")
		return
	}
	defer rows.Close()
	items := make([]map[string]any, 0)
	for rows.Next() {
		var id int64
		var title, lastSeen, issueStatus, level, issueType, issueCategory string
		if rows.Scan(&id, &title, &lastSeen, &issueStatus, &level, &issueType, &issueCategory) == nil {
			items = append(items, map[string]any{"id": strconv.FormatInt(id, 10), "shortId": strings.ToUpper(r.PathValue("project_slug")) + "-" + strconv.FormatInt(id, 10), "title": title, "lastSeen": normalizeAPITime(lastSeen), "status": issueStatus, "level": level, "issueType": issueType, "issueCategory": issueCategory})
		}
	}
	writeJSON(w, http.StatusOK, items)
}

func (s *Server) sentryReleaseResponse(r *http.Request, releaseID string) (map[string]any, error) {
	var version, firstSeen, lastSeen, status string
	var releasedAt sql.NullString
	if err := s.store.DB.QueryRowContext(r.Context(), `SELECT version, first_seen_at, last_seen_at, released_at, status FROM releases WHERE id = ?`, releaseID).Scan(&version, &firstSeen, &lastSeen, &releasedAt, &status); err != nil {
		return nil, err
	}
	rows, err := s.store.DB.QueryContext(r.Context(), `SELECT p.slug, p.name FROM project_releases pr JOIN projects p ON p.id = pr.project_id WHERE pr.release_id = ? ORDER BY p.slug`, releaseID)
	if err != nil {
		return nil, err
	}
	projects := make([]map[string]string, 0)
	for rows.Next() {
		var slug, name string
		if rows.Scan(&slug, &name) == nil {
			projects = append(projects, map[string]string{"slug": slug, "name": name})
		}
	}
	_ = rows.Close()
	commits, _ := s.releaseCommitRows(r, releaseID)
	var lastCommit any
	if len(commits) > 0 {
		lastCommit = commits[len(commits)-1]
	}
	return map[string]any{"id": releaseID, "version": version, "status": status, "url": nil, "dateCreated": normalizeAPITime(firstSeen), "dateReleased": nullableAPITime(releasedAt.String), "lastEvent": nullableAPITime(lastSeen), "newGroups": 0, "projects": projects, "lastCommit": lastCommit}, nil
}

func sentryEventTags(event map[string]any) []map[string]string {
	tags := make([]map[string]string, 0)
	switch raw := event["tags"].(type) {
	case map[string]any:
		for key, value := range raw {
			tags = append(tags, map[string]string{"key": key, "value": strings.TrimSpace(toString(value))})
		}
	case []any:
		for _, value := range raw {
			if pair, ok := value.([]any); ok && len(pair) == 2 {
				tags = append(tags, map[string]string{"key": toString(pair[0]), "value": toString(pair[1])})
			}
		}
	}
	return tags
}

func toString(value any) string {
	if text, ok := value.(string); ok {
		return text
	}
	encoded, _ := json.Marshal(value)
	return string(encoded)
}

func normalizeAPITime(value string) string {
	value = strings.TrimSpace(value)
	if parsed, err := time.Parse(time.RFC3339Nano, value); err == nil {
		return parsed.UTC().Format(time.RFC3339)
	}
	if parsed, err := time.Parse("2006-01-02 15:04:05", value); err == nil {
		return parsed.UTC().Format(time.RFC3339)
	}
	return time.Now().UTC().Format(time.RFC3339)
}

func nullableAPITime(value string) any {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	return normalizeAPITime(value)
}

func nullableText(value string) any {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	return value
}
