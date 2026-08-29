package httpapi

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/barktrace/bark/internal/auth"
	"github.com/google/uuid"
)

type commitInput struct {
	ID          string   `json:"id"`
	Commit      string   `json:"commit"`
	Previous    *string  `json:"previousCommit"`
	Repository  string   `json:"repository"`
	Message     string   `json:"message"`
	AuthorName  string   `json:"author_name"`
	AuthorEmail string   `json:"author_email"`
	Timestamp   string   `json:"timestamp"`
	Files       []string `json:"files"`
	PatchSet    []struct {
		Path string `json:"path"`
		Type string `json:"type"`
	} `json:"patch_set"`
	Author struct {
		Name  string `json:"name"`
		Email string `json:"email"`
	} `json:"author"`
}

func (s *Server) sentryReleaseDetail(w http.ResponseWriter, r *http.Request) {
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
	if r.Method == http.MethodPut {
		membership, _ := principal.Membership(organizationID)
		if membership.Role == "viewer" {
			writeError(w, http.StatusForbidden, "release write access required")
			return
		}
		var input struct {
			DateReleased string        `json:"dateReleased"`
			Commits      []commitInput `json:"commits"`
			Refs         []commitInput `json:"refs"`
			Version      string        `json:"version"`
			Projects     []string      `json:"projects"`
			URL          string        `json:"url"`
			Status       string        `json:"status"`
		}
		if err := decodeJSON(w, r, &input); err != nil {
			return
		}
		if input.DateReleased != "" {
			if _, err := time.Parse(time.RFC3339, input.DateReleased); err != nil {
				writeError(w, http.StatusBadRequest, "dateReleased must be RFC3339")
				return
			}
			_, _ = s.store.DB.ExecContext(r.Context(), `UPDATE releases SET released_at = ? WHERE id = ?`, input.DateReleased, releaseID)
		}
		input.Status = strings.ToLower(strings.TrimSpace(input.Status))
		if input.Status != "" {
			if input.Status != "open" && input.Status != "archived" {
				writeError(w, http.StatusBadRequest, "status must be open or archived")
				return
			}
			if _, err := s.store.DB.ExecContext(r.Context(), `UPDATE releases SET status = ? WHERE id = ?`, input.Status, releaseID); err != nil {
				writeError(w, http.StatusInternalServerError, "could not update release status")
				return
			}
		}
		commits := append(input.Commits, input.Refs...)
		if len(commits) > 0 {
			if err := s.replaceReleaseCommits(r, organizationID, releaseID, commits); err != nil {
				writeError(w, http.StatusInternalServerError, "could not set release commits")
				return
			}
		}
	}
	s.writeReleaseDetail(w, r, releaseID)
}

func (s *Server) sentryReleaseCommits(w http.ResponseWriter, r *http.Request) {
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
	if r.Method == http.MethodGet {
		items, err := s.releaseCommitRows(r, releaseID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "could not list release commits")
			return
		}
		writeJSON(w, http.StatusOK, items)
		return
	}
	var input struct {
		Commits []commitInput `json:"commits"`
	}
	if err := decodeJSON(w, r, &input); err != nil {
		return
	}
	if len(input.Commits) == 0 || len(input.Commits) > 1000 {
		writeError(w, http.StatusBadRequest, "commits must contain 1 to 1000 items")
		return
	}
	if err := s.replaceReleaseCommits(r, organizationID, releaseID, input.Commits); err != nil {
		writeError(w, http.StatusInternalServerError, "could not set release commits")
		return
	}
	items, _ := s.releaseCommitRows(r, releaseID)
	writeJSON(w, http.StatusCreated, items)
}

func (s *Server) replaceReleaseCommits(r *http.Request, organizationID, releaseID string, commits []commitInput) error {
	tx, err := s.store.DB.BeginTx(r.Context(), nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(r.Context(), `DELETE FROM release_commits WHERE release_id = ?`, releaseID); err != nil {
		return err
	}
	for index, input := range commits {
		externalID := strings.TrimSpace(firstNonEmpty(input.ID, input.Commit))
		if externalID == "" {
			return errors.New("commit id is required")
		}
		committedAt := input.Timestamp
		if committedAt == "" {
			committedAt = time.Now().UTC().Format(time.RFC3339Nano)
		}
		commitID := uuid.NewString()
		authorName := firstNonEmpty(input.AuthorName, input.Author.Name)
		authorEmail := firstNonEmpty(input.AuthorEmail, input.Author.Email)
		err := tx.QueryRowContext(r.Context(), `INSERT INTO commits(id, organization_id, repository, external_id, message, author_name, author_email, committed_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(organization_id, repository, external_id) DO UPDATE SET message = excluded.message, author_name = excluded.author_name, author_email = excluded.author_email, committed_at = excluded.committed_at RETURNING id`, commitID, organizationID, input.Repository, externalID, input.Message, authorName, authorEmail, committedAt).Scan(&commitID)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(r.Context(), `INSERT INTO release_commits(release_id, commit_id, sequence) VALUES (?, ?, ?)`, releaseID, commitID, index); err != nil {
			return err
		}
		filenames := append([]string(nil), input.Files...)
		for _, patch := range input.PatchSet {
			filenames = append(filenames, patch.Path)
		}
		for _, filename := range filenames {
			filename = strings.TrimSpace(filename)
			if filename != "" {
				if _, err := tx.ExecContext(r.Context(), `INSERT INTO commit_files(commit_id, filename) VALUES (?, ?) ON CONFLICT DO NOTHING`, commitID, filename); err != nil {
					return err
				}
			}
		}
	}
	return tx.Commit()
}

func (s *Server) sentryReleaseDeploys(w http.ResponseWriter, r *http.Request) {
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
	var input struct {
		Environment  string   `json:"environment"`
		Name         string   `json:"name"`
		URL          string   `json:"url"`
		DateStarted  string   `json:"dateStarted"`
		DateFinished string   `json:"dateFinished"`
		Projects     []string `json:"projects"`
	}
	if err := decodeJSON(w, r, &input); err != nil {
		return
	}
	input.Environment = strings.TrimSpace(input.Environment)
	if input.Environment == "" {
		writeError(w, http.StatusBadRequest, "environment is required")
		return
	}
	started := input.DateStarted
	if started == "" {
		started = time.Now().UTC().Format(time.RFC3339Nano)
	}
	var projectID any
	if len(input.Projects) > 0 {
		var id string
		if err := s.store.DB.QueryRowContext(r.Context(), `SELECT id FROM projects WHERE organization_id = ? AND slug = ?`, organizationID, input.Projects[0]).Scan(&id); err == nil {
			projectID = id
		}
	}
	id := uuid.NewString()
	_, err := s.store.DB.ExecContext(r.Context(), `INSERT INTO deploys(id, organization_id, release_id, project_id, environment, name, url, started_at, finished_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULLIF(?, ''))`, id, organizationID, releaseID, projectID, input.Environment, input.Name, input.URL, started, input.DateFinished)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not create deploy")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"id": id, "environment": input.Environment, "name": input.Name, "url": input.URL, "dateStarted": started, "dateFinished": input.DateFinished})
}

func (s *Server) releaseMetadata(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	releaseID := r.PathValue("release_id")
	var organizationID string
	if err := s.store.DB.QueryRowContext(r.Context(), `SELECT organization_id FROM releases WHERE id = ?`, releaseID).Scan(&organizationID); err != nil {
		writeError(w, http.StatusNotFound, "release not found")
		return
	}
	if _, allowed := principal.Membership(organizationID); !allowed {
		writeError(w, http.StatusForbidden, "release access required")
		return
	}
	commits, _ := s.releaseCommitRows(r, releaseID)
	deployRows, _ := s.store.DB.QueryContext(r.Context(), `SELECT id, environment, name, url, started_at, COALESCE(finished_at, '') FROM deploys WHERE release_id = ? ORDER BY started_at DESC`, releaseID)
	deploys := make([]map[string]any, 0)
	if deployRows != nil {
		for deployRows.Next() {
			var id, environment, name, targetURL, started, finished string
			if deployRows.Scan(&id, &environment, &name, &targetURL, &started, &finished) == nil {
				deploys = append(deploys, map[string]any{"id": id, "environment": environment, "name": name, "url": targetURL, "started_at": started, "finished_at": finished})
			}
		}
		_ = deployRows.Close()
	}
	writeJSON(w, http.StatusOK, map[string]any{"commits": commits, "deploys": deploys})
}

func (s *Server) issueSuspects(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	issueID := r.PathValue("issue_id")
	projectID, ok := s.issueProject(r, issueID)
	if !ok || !s.canAccessProject(r, principal, projectID) {
		writeError(w, http.StatusForbidden, "issue access required")
		return
	}
	rows, err := s.store.DB.QueryContext(r.Context(), `SELECT c.id, c.external_id, c.repository, c.message, c.author_name, c.author_email, c.committed_at, sc.score, sc.reason FROM issue_suspect_commits sc JOIN commits c ON c.id = sc.commit_id WHERE sc.issue_id = ? ORDER BY sc.score DESC, c.committed_at DESC`, issueID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list suspect commits")
		return
	}
	defer rows.Close()
	items := make([]map[string]any, 0)
	for rows.Next() {
		var id, externalID, repository, message, authorName, authorEmail, committedAt, reason string
		var score int
		if rows.Scan(&id, &externalID, &repository, &message, &authorName, &authorEmail, &committedAt, &score, &reason) == nil {
			items = append(items, map[string]any{"id": id, "external_id": externalID, "repository": repository, "message": message, "author_name": authorName, "author_email": authorEmail, "committed_at": committedAt, "score": score, "reason": reason})
		}
	}
	writeJSON(w, http.StatusOK, items)
}

func (s *Server) releaseBySlugVersion(r *http.Request, orgSlug, version string) (string, string, bool) {
	var organizationID, releaseID string
	err := s.store.DB.QueryRowContext(r.Context(), `SELECT o.id, rel.id FROM organizations o JOIN releases rel ON rel.organization_id = o.id WHERE o.slug = ? AND rel.version = ?`, orgSlug, version).Scan(&organizationID, &releaseID)
	return organizationID, releaseID, err == nil
}

func (s *Server) releaseCommitRows(r *http.Request, releaseID string) ([]map[string]any, error) {
	rows, err := s.store.DB.QueryContext(r.Context(), `SELECT c.id, c.external_id, c.repository, c.message, c.author_name, c.author_email, c.committed_at FROM release_commits rc JOIN commits c ON c.id = rc.commit_id WHERE rc.release_id = ? ORDER BY rc.sequence`, releaseID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]map[string]any, 0)
	for rows.Next() {
		var id, externalID, repository, message, authorName, authorEmail, committedAt string
		if err := rows.Scan(&id, &externalID, &repository, &message, &authorName, &authorEmail, &committedAt); err != nil {
			return nil, err
		}
		items = append(items, map[string]any{"id": externalID, "internal_id": id, "repository": repository, "message": message, "author": map[string]string{"name": authorName, "email": authorEmail}, "dateCreated": committedAt})
	}
	return items, rows.Err()
}

func (s *Server) writeReleaseDetail(w http.ResponseWriter, r *http.Request, releaseID string) {
	item, err := s.sentryReleaseResponse(r, releaseID)
	if err != nil {
		writeError(w, http.StatusNotFound, "release not found")
		return
	}
	writeJSON(w, http.StatusOK, item)
}
