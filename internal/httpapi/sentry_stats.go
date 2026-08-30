package httpapi

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/barktrace/bark/internal/auth"
)

const maxSentryStatsBuckets = 10_000

type sentryStatsRange struct {
	start      time.Time
	end        time.Time
	resolution time.Duration
}

func (s *Server) sentryProjectStats(w http.ResponseWriter, r *http.Request) {
	principal, _ := auth.PrincipalFromContext(r.Context())
	projectID, _, ok := s.projectBySlugs(r, r.PathValue("org_slug"), r.PathValue("project_slug"))
	if !ok || !s.canAccessProject(r, principal, projectID) {
		writeError(w, http.StatusNotFound, "project not found")
		return
	}
	stat := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("stat")))
	if stat == "" {
		stat = "received"
	}
	if stat != "received" && stat != "rejected" && stat != "blacklisted" {
		writeError(w, http.StatusBadRequest, "stat must be received, rejected, or blacklisted")
		return
	}
	statsRange, err := parseSentryStatsRange(time.Now().UTC(), r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	bucketStart := statsRange.start.Truncate(statsRange.resolution)
	bucketCount := int((statsRange.end.Sub(bucketStart) + statsRange.resolution - 1) / statsRange.resolution)
	counts := make([]int64, bucketCount)
	resolutionSeconds := int64(statsRange.resolution / time.Second)
	query := `SELECT (CAST(strftime('%s', timestamp) AS INTEGER) / ?) * ?, COUNT(*) FROM events WHERE project_id = ? AND CAST(strftime('%s', timestamp) AS INTEGER) >= ? AND CAST(strftime('%s', timestamp) AS INTEGER) < ? GROUP BY 1`
	arguments := []any{resolutionSeconds, resolutionSeconds, projectID, statsRange.start.Unix(), statsRange.end.Unix()}
	if stat != "received" {
		outcomeClause := "outcome = 'filtered'"
		if stat == "rejected" {
			outcomeClause = "outcome <> 'accepted'"
		}
		query = `SELECT (CAST(strftime('%s', created_at) AS INTEGER) / ?) * ?, SUM(quantity) FROM ingestion_outcomes WHERE project_id = ? AND ` + outcomeClause + ` AND CAST(strftime('%s', created_at) AS INTEGER) >= ? AND CAST(strftime('%s', created_at) AS INTEGER) < ? GROUP BY 1`
		arguments = []any{resolutionSeconds, resolutionSeconds, projectID, statsRange.start.Unix(), statsRange.end.Unix()}
	}
	rows, err := s.store.DB.QueryContext(r.Context(), query, arguments...)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not load project statistics")
		return
	}
	defer rows.Close()
	for rows.Next() {
		var timestamp int64
		var count int64
		if err := rows.Scan(&timestamp, &count); err != nil {
			writeError(w, http.StatusInternalServerError, "could not read project statistics")
			return
		}
		index := int((timestamp - bucketStart.Unix()) / resolutionSeconds)
		if index >= 0 && index < len(counts) {
			counts[index] += count
		}
	}
	if err := rows.Err(); err != nil {
		writeError(w, http.StatusInternalServerError, "could not load project statistics")
		return
	}
	result := make([][2]int64, len(counts))
	for index, count := range counts {
		result[index] = [2]int64{bucketStart.Add(time.Duration(index) * statsRange.resolution).Unix(), count}
	}
	writeJSON(w, http.StatusOK, result)
}

func parseSentryStatsRange(now time.Time, r *http.Request) (sentryStatsRange, error) {
	query := r.URL.Query()
	end, err := sentryStatsTime(query.Get("until"), now, "until")
	if err != nil {
		return sentryStatsRange{}, err
	}
	start, err := sentryStatsTime(query.Get("since"), end.Add(-24*time.Hour), "since")
	if err != nil {
		return sentryStatsRange{}, err
	}
	if !start.Before(end) {
		return sentryStatsRange{}, errors.New("since must be before until")
	}
	if end.Sub(start) > 90*24*time.Hour {
		return sentryStatsRange{}, errors.New("time range cannot exceed 90 days")
	}
	resolution := time.Hour
	switch value := strings.TrimSpace(query.Get("resolution")); value {
	case "", "1h":
	case "10s":
		resolution = 10 * time.Second
	case "1d":
		resolution = 24 * time.Hour
	default:
		return sentryStatsRange{}, errors.New("resolution must be 10s, 1h, or 1d")
	}
	bucketStart := start.Truncate(resolution)
	bucketCount := int((end.Sub(bucketStart) + resolution - 1) / resolution)
	if bucketCount > maxSentryStatsBuckets {
		return sentryStatsRange{}, fmt.Errorf("time range and resolution cannot exceed %d buckets", maxSentryStatsBuckets)
	}
	return sentryStatsRange{start: start, end: end, resolution: resolution}, nil
}

func sentryStatsTime(raw string, fallback time.Time, name string) (time.Time, error) {
	if strings.TrimSpace(raw) == "" {
		return fallback.UTC(), nil
	}
	seconds, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
	if err != nil {
		return time.Time{}, fmt.Errorf("%s must be a Unix timestamp", name)
	}
	return time.Unix(seconds, 0).UTC(), nil
}
