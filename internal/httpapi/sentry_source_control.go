package httpapi

import (
	"database/sql"
	"errors"
	"net/http"
	"strings"

	"github.com/barktrace/bark/internal/auth"
	"github.com/google/uuid"
)

type sentryRepositoryRecord struct {
	ID, OrganizationID, Name, URL, Provider, Status, CreatedAt string
}

type sentryCommitRecord struct {
	ID, ExternalID, Repository, Message, AuthorName, AuthorEmail, CommittedAt string
}

type sentryRepositoryInput struct {
	Name     *string `json:"name"`
	URL      *string `json:"url"`
	Provider *string `json:"provider"`
}

func (s *Server) createSentryRepository(w http.ResponseWriter, r *http.Request, principal *auth.Principal, organizationID string) {
	membership, ok := principal.Membership(organizationID)
	if !ok || (membership.Role != "owner" && membership.Role != "admin") {
		writeError(w, http.StatusForbidden, "organization administrator access required")
		return
	}
	var input sentryRepositoryInput
	if err := decodeJSON(w, r, &input); err != nil {
		return
	}
	name, targetURL, provider := "", "", "generic"
	if input.Name != nil {
		name = strings.TrimSpace(*input.Name)
	}
	if input.URL != nil {
		targetURL = strings.TrimSpace(*input.URL)
	}
	if input.Provider != nil && strings.TrimSpace(*input.Provider) != "" {
		provider = strings.TrimSpace(*input.Provider)
	}
	if name == "" || len(name) > 255 || len(targetURL) > 2048 || len(provider) > 120 {
		writeError(w, http.StatusBadRequest, "repository fields are invalid")
		return
	}
	id := uuid.NewString()
	tx, err := s.store.DB.BeginTx(r.Context(), nil)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not create repository")
		return
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(r.Context(), `INSERT INTO repositories(id, organization_id, name, url, provider) VALUES (?, ?, ?, NULLIF(?, ''), ?)`, id, organizationID, name, targetURL, provider); err != nil {
		writeError(w, http.StatusConflict, "repository already exists")
		return
	}
	if _, err = tx.ExecContext(r.Context(), `INSERT INTO audit_logs(organization_id, actor_user_id, action, target_type, target_id) VALUES (?, ?, 'create_sentry_repository', 'repository', ?)`, organizationID, principal.UserID, id); err != nil || tx.Commit() != nil {
		writeError(w, http.StatusInternalServerError, "could not create repository")
		return
	}
	repository, err := s.loadSentryRepository(r, organizationID, id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not load repository")
		return
	}
	writeJSON(w, http.StatusCreated, sentryRepositoryResponse(repository))
}

func (s *Server) sentryOrganizationRepositoryDetail(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	organizationID, ok := s.authorizedOrganizationSlug(r, principal, r.PathValue("org_slug"))
	if !ok {
		writeError(w, http.StatusNotFound, "repository not found")
		return
	}
	repository, err := s.loadSentryRepository(r, organizationID, r.PathValue("repo_id"))
	if errors.Is(err, sql.ErrNoRows) {
		writeError(w, http.StatusNotFound, "repository not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not load repository")
		return
	}
	if r.Method != http.MethodGet {
		membership, _ := principal.Membership(organizationID)
		if membership.Role != "owner" && membership.Role != "admin" {
			writeError(w, http.StatusForbidden, "organization administrator access required")
			return
		}
		if r.Method == http.MethodDelete {
			tx, err := s.store.DB.BeginTx(r.Context(), nil)
			if err != nil {
				writeError(w, http.StatusInternalServerError, "could not delete repository")
				return
			}
			defer tx.Rollback()
			if _, err = tx.ExecContext(r.Context(), `DELETE FROM repositories WHERE id = ?`, repository.ID); err == nil {
				_, err = tx.ExecContext(r.Context(), `INSERT INTO audit_logs(organization_id, actor_user_id, action, target_type, target_id) VALUES (?, ?, 'delete_sentry_repository', 'repository', ?)`, organizationID, principal.UserID, repository.ID)
			}
			if err != nil || tx.Commit() != nil {
				writeError(w, http.StatusInternalServerError, "could not delete repository")
				return
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}
		var input sentryRepositoryInput
		if err := decodeJSON(w, r, &input); err != nil {
			return
		}
		if input.Name != nil {
			repository.Name = strings.TrimSpace(*input.Name)
		}
		if input.URL != nil {
			repository.URL = strings.TrimSpace(*input.URL)
		}
		if input.Provider != nil && strings.TrimSpace(*input.Provider) != "" {
			repository.Provider = strings.TrimSpace(*input.Provider)
		}
		if repository.Name == "" || len(repository.Name) > 255 || len(repository.URL) > 2048 || len(repository.Provider) > 120 {
			writeError(w, http.StatusBadRequest, "repository fields are invalid")
			return
		}
		tx, err := s.store.DB.BeginTx(r.Context(), nil)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "could not update repository")
			return
		}
		defer tx.Rollback()
		var previousName string
		if err = tx.QueryRowContext(r.Context(), `SELECT name FROM repositories WHERE id = ?`, repository.ID).Scan(&previousName); err != nil {
			writeError(w, http.StatusInternalServerError, "could not update repository")
			return
		}
		if _, err = tx.ExecContext(r.Context(), `UPDATE repositories SET name = ?, url = NULLIF(?, ''), provider = ? WHERE id = ?`, repository.Name, repository.URL, repository.Provider, repository.ID); err == nil {
			_, err = tx.ExecContext(r.Context(), `UPDATE commits SET repository = ? WHERE organization_id = ? AND repository = ?`, repository.Name, organizationID, previousName)
		}
		if err == nil {
			_, err = tx.ExecContext(r.Context(), `INSERT INTO audit_logs(organization_id, actor_user_id, action, target_type, target_id) VALUES (?, ?, 'update_sentry_repository', 'repository', ?)`, organizationID, principal.UserID, repository.ID)
		}
		if err != nil || tx.Commit() != nil {
			writeError(w, http.StatusConflict, "could not update repository")
			return
		}
		repository, err = s.loadSentryRepository(r, organizationID, repository.ID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "could not load repository")
			return
		}
	}
	writeJSON(w, http.StatusOK, sentryRepositoryResponse(repository))
}

func (s *Server) sentryRepositoryCommits(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	organizationID, ok := s.authorizedOrganizationSlug(r, principal, r.PathValue("org_slug"))
	if !ok {
		writeError(w, http.StatusNotFound, "repository not found")
		return
	}
	repository, err := s.loadSentryRepository(r, organizationID, r.PathValue("repo_id"))
	if errors.Is(err, sql.ErrNoRows) {
		writeError(w, http.StatusNotFound, "repository not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not load repository")
		return
	}
	query := strings.TrimSpace(r.URL.Query().Get("query"))
	rows, err := s.store.DB.QueryContext(r.Context(), `SELECT id, external_id, repository, message, author_name, author_email, committed_at FROM commits WHERE organization_id = ? AND repository = ? AND (? = '' OR external_id LIKE '%' || ? || '%' OR message LIKE '%' || ? || '%') ORDER BY committed_at DESC, id DESC LIMIT ?`, organizationID, repository.Name, query, query, query, boundedSentryPageSize(r, 100))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list commits")
		return
	}
	defer rows.Close()
	items := make([]map[string]any, 0)
	for rows.Next() {
		commit, scanErr := scanSentryCommit(rows)
		if scanErr != nil {
			writeError(w, http.StatusInternalServerError, "could not list commits")
			return
		}
		items = append(items, sentryCommitResponse(commit, repository))
	}
	writeJSON(w, http.StatusOK, items)
}

func (s *Server) sentryRepositoryCommitDetail(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	organizationID, ok := s.authorizedOrganizationSlug(r, principal, r.PathValue("org_slug"))
	if !ok {
		writeError(w, http.StatusNotFound, "commit not found")
		return
	}
	repository, err := s.loadSentryRepository(r, organizationID, r.PathValue("repo_id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "commit not found")
		return
	}
	commit, err := scanSentryCommit(s.store.DB.QueryRowContext(r.Context(), `SELECT id, external_id, repository, message, author_name, author_email, committed_at FROM commits WHERE organization_id = ? AND repository = ? AND (id = ? OR external_id = ?) LIMIT 1`, organizationID, repository.Name, r.PathValue("commit_id"), r.PathValue("commit_id")))
	if errors.Is(err, sql.ErrNoRows) {
		writeError(w, http.StatusNotFound, "commit not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not load commit")
		return
	}
	response := sentryCommitResponse(commit, repository)
	response["files"] = s.sentryCommitFiles(r, commit.ID)
	response["releases"] = s.sentryCommitReleases(r, commit.ID)
	writeJSON(w, http.StatusOK, response)
}

func (s *Server) sentryIssueSuspects(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	issueSelector := r.PathValue("issue_id")
	var issueID, projectID, organizationID string
	err := s.store.DB.QueryRowContext(r.Context(), `SELECT i.id, i.project_id, p.organization_id FROM issues i JOIN projects p ON p.id = i.project_id WHERE i.id = ? OR CAST(i.rowid AS TEXT) = ? LIMIT 1`, issueSelector, issueSelector).Scan(&issueID, &projectID, &organizationID)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && !s.canAccessProject(r, principal, projectID)) {
		writeError(w, http.StatusNotFound, "issue not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not load suspect commits")
		return
	}
	rows, err := s.store.DB.QueryContext(r.Context(), `SELECT c.id, c.external_id, c.repository, c.message, c.author_name, c.author_email, c.committed_at, sc.score, sc.reason FROM issue_suspect_commits sc JOIN commits c ON c.id = sc.commit_id WHERE sc.issue_id = ? ORDER BY sc.score DESC, c.committed_at DESC LIMIT ?`, issueID, boundedSentryPageSize(r, 100))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list suspect commits")
		return
	}
	type suspect struct {
		commit sentryCommitRecord
		score  int
		reason string
	}
	suspects := make([]suspect, 0)
	for rows.Next() {
		var item suspect
		if err := rows.Scan(&item.commit.ID, &item.commit.ExternalID, &item.commit.Repository, &item.commit.Message, &item.commit.AuthorName, &item.commit.AuthorEmail, &item.commit.CommittedAt, &item.score, &item.reason); err != nil {
			_ = rows.Close()
			writeError(w, http.StatusInternalServerError, "could not list suspect commits")
			return
		}
		suspects = append(suspects, item)
	}
	_ = rows.Close()
	items := make([]map[string]any, 0, len(suspects))
	for _, suspect := range suspects {
		repository, err := s.loadSentryRepository(r, organizationID, suspect.commit.Repository)
		if err != nil {
			repository = sentryRepositoryRecord{OrganizationID: organizationID, Name: suspect.commit.Repository, Provider: "generic", Status: "active"}
		}
		item := sentryCommitResponse(suspect.commit, repository)
		item["score"] = suspect.score
		item["reason"] = suspect.reason
		items = append(items, item)
	}
	writeJSON(w, http.StatusOK, items)
}

func (s *Server) loadSentryRepository(r *http.Request, organizationID, selector string) (sentryRepositoryRecord, error) {
	var repository sentryRepositoryRecord
	err := s.store.DB.QueryRowContext(r.Context(), `SELECT id, organization_id, name, COALESCE(url, ''), provider, status, created_at FROM repositories WHERE organization_id = ? AND (id = ? OR name = ?) LIMIT 1`, organizationID, selector, selector).Scan(&repository.ID, &repository.OrganizationID, &repository.Name, &repository.URL, &repository.Provider, &repository.Status, &repository.CreatedAt)
	return repository, err
}

func sentryRepositoryResponse(repository sentryRepositoryRecord) map[string]any {
	return map[string]any{
		"id": repository.ID, "name": repository.Name, "url": nullableText(repository.URL), "status": repository.Status,
		"provider": map[string]string{"id": repository.Provider, "name": repository.Provider}, "dateCreated": normalizeAPITime(repository.CreatedAt),
	}
}

func scanSentryCommit(row rowScanner) (sentryCommitRecord, error) {
	var commit sentryCommitRecord
	err := row.Scan(&commit.ID, &commit.ExternalID, &commit.Repository, &commit.Message, &commit.AuthorName, &commit.AuthorEmail, &commit.CommittedAt)
	return commit, err
}

func sentryCommitResponse(commit sentryCommitRecord, repository sentryRepositoryRecord) map[string]any {
	var author any
	if commit.AuthorName != "" || commit.AuthorEmail != "" {
		author = map[string]any{"id": commit.AuthorEmail, "name": commit.AuthorName, "email": commit.AuthorEmail, "username": commit.AuthorEmail}
	}
	return map[string]any{
		"id": commit.ExternalID, "message": commit.Message, "dateCreated": normalizeAPITime(commit.CommittedAt),
		"author": author, "repository": sentryRepositoryResponse(repository),
	}
}

func (s *Server) sentryCommitFiles(r *http.Request, commitID string) []map[string]string {
	rows, err := s.store.DB.QueryContext(r.Context(), `SELECT filename, change_type FROM commit_files WHERE commit_id = ? ORDER BY filename`, commitID)
	if err != nil {
		return []map[string]string{}
	}
	defer rows.Close()
	items := make([]map[string]string, 0)
	for rows.Next() {
		var filename, changeType string
		if rows.Scan(&filename, &changeType) == nil {
			items = append(items, map[string]string{"filename": filename, "type": changeType})
		}
	}
	return items
}

func (s *Server) sentryCommitReleases(r *http.Request, commitID string) []map[string]string {
	rows, err := s.store.DB.QueryContext(r.Context(), `SELECT rel.id, rel.version FROM release_commits rc JOIN releases rel ON rel.id = rc.release_id WHERE rc.commit_id = ? ORDER BY rel.created_at DESC`, commitID)
	if err != nil {
		return []map[string]string{}
	}
	defer rows.Close()
	items := make([]map[string]string, 0)
	for rows.Next() {
		var id, version string
		if rows.Scan(&id, &version) == nil {
			items = append(items, map[string]string{"id": id, "version": version})
		}
	}
	return items
}
