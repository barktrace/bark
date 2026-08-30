// Package releasehealth aggregates Sentry session envelopes into release-health
// totals and time series.
package releasehealth

import (
	"context"
	"database/sql"
	"errors"
	"sort"
	"strconv"
	"strings"
	"time"
)

var supportedFields = map[string]bool{
	"sum(session)":             true,
	"count_unique(user)":       true,
	"avg(session.duration)":    true,
	"crash_free_rate(session)": true,
	"crash_free_rate(user)":    true,
}

var supportedGroupBy = map[string]bool{
	"project": true, "release": true, "environment": true, "session.status": true,
}

type Request struct {
	ProjectIDs   []string
	Environments []string
	Releases     []string
	Fields       []string
	GroupBy      []string
	Start        time.Time
	End          time.Time
	Interval     time.Duration
}

type Result struct {
	Start     time.Time   `json:"start"`
	End       time.Time   `json:"end"`
	Intervals []time.Time `json:"intervals"`
	Groups    []Group     `json:"groups"`
}

type Group struct {
	By     map[string]string `json:"by"`
	Totals map[string]any    `json:"totals"`
	Series map[string][]any  `json:"series"`
}

type aggregate struct {
	sessions   int64
	crashed    int64
	duration   float64
	durations  int64
	users      map[string]struct{}
	crashUsers map[string]struct{}
}

type groupAggregate struct {
	by      map[string]string
	total   aggregate
	buckets []aggregate
}

func Query(ctx context.Context, db *sql.DB, request Request) (Result, error) {
	if !request.Start.Before(request.End) || request.Interval <= 0 {
		return Result{}, errors.New("invalid release-health time range")
	}
	bucketCount := int((request.End.Sub(request.Start) + request.Interval - 1) / request.Interval)
	if bucketCount < 1 || bucketCount > 1000 {
		return Result{}, errors.New("release-health interval must produce between 1 and 1000 buckets")
	}
	fields, err := normalizeFields(request.Fields)
	if err != nil {
		return Result{}, err
	}
	groupBy, err := normalizeGroupBy(request.GroupBy)
	if err != nil {
		return Result{}, err
	}
	result := Result{Start: request.Start, End: request.End, Intervals: make([]time.Time, bucketCount), Groups: make([]Group, 0)}
	for index := range result.Intervals {
		result.Intervals[index] = request.Start.Add(time.Duration(index) * request.Interval)
	}
	if len(request.ProjectIDs) == 0 {
		return result, nil
	}

	query := `
		SELECT ps.project_id, p.sentry_id, COALESCE(r.version, ''), ps.environment,
		       ps.distinct_id, ps.status, ps.started_at, COALESCE(ps.duration, 0),
		       CASE WHEN ps.duration IS NULL THEN 0 ELSE 1 END, ps.errors
		FROM project_sessions ps
		JOIN projects p ON p.id = ps.project_id
		LEFT JOIN releases r ON r.id = ps.release_id
		WHERE ps.project_id IN (` + placeholders(len(request.ProjectIDs)) + `)
		  AND ps.started_at >= ? AND ps.started_at < ?`
	arguments := make([]any, 0, len(request.ProjectIDs)+len(request.Environments)+len(request.Releases)+2)
	for _, projectID := range request.ProjectIDs {
		arguments = append(arguments, projectID)
	}
	arguments = append(arguments, request.Start.UTC().Format(time.RFC3339Nano), request.End.UTC().Format(time.RFC3339Nano))
	if len(request.Environments) > 0 {
		query += ` AND ps.environment IN (` + placeholders(len(request.Environments)) + `)`
		for _, environment := range request.Environments {
			arguments = append(arguments, environment)
		}
	}
	if len(request.Releases) > 0 {
		query += ` AND r.version IN (` + placeholders(len(request.Releases)) + `)`
		for _, release := range request.Releases {
			arguments = append(arguments, release)
		}
	}
	query += ` ORDER BY ps.started_at`
	rows, err := db.QueryContext(ctx, query, arguments...)
	if err != nil {
		return Result{}, err
	}
	defer rows.Close()

	groups := make(map[string]*groupAggregate)
	for rows.Next() {
		var projectID, sentryProjectID, release, environment, userID, status, startedAt string
		var duration float64
		var hasDuration, sessionErrors int
		if err := rows.Scan(&projectID, &sentryProjectID, &release, &environment, &userID, &status, &startedAt, &duration, &hasDuration, &sessionErrors); err != nil {
			return Result{}, err
		}
		started, err := parseTime(startedAt)
		if err != nil {
			continue
		}
		status = normalizedStatus(status, sessionErrors)
		by := make(map[string]string, len(groupBy))
		keyParts := make([]string, 0, len(groupBy))
		for _, field := range groupBy {
			value := ""
			switch field {
			case "project":
				value = sentryProjectID
			case "release":
				value = release
			case "environment":
				value = environment
			case "session.status":
				value = status
			}
			by[field] = value
			keyParts = append(keyParts, field+"\x00"+value)
		}
		key := strings.Join(keyParts, "\x1f")
		group := groups[key]
		if group == nil {
			group = &groupAggregate{by: by, total: newAggregate(), buckets: make([]aggregate, bucketCount)}
			for index := range group.buckets {
				group.buckets[index] = newAggregate()
			}
			groups[key] = group
		}
		bucket := int(started.Sub(request.Start) / request.Interval)
		if bucket < 0 || bucket >= bucketCount {
			continue
		}
		updateAggregate(&group.total, status, userID, duration, hasDuration != 0)
		updateAggregate(&group.buckets[bucket], status, userID, duration, hasDuration != 0)
	}
	if err := rows.Err(); err != nil {
		return Result{}, err
	}

	keys := make([]string, 0, len(groups))
	for key := range groups {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result.Groups = make([]Group, 0, len(keys))
	for _, key := range keys {
		group := groups[key]
		item := Group{By: group.by, Totals: make(map[string]any, len(fields)), Series: make(map[string][]any, len(fields))}
		for _, field := range fields {
			item.Totals[field] = metric(field, group.total)
			series := make([]any, len(group.buckets))
			for index, bucket := range group.buckets {
				series[index] = metric(field, bucket)
			}
			item.Series[field] = series
		}
		result.Groups = append(result.Groups, item)
	}
	return result, nil
}

func normalizeFields(fields []string) ([]string, error) {
	if len(fields) == 0 {
		return []string{"sum(session)"}, nil
	}
	result, seen := make([]string, 0, len(fields)), make(map[string]bool)
	for _, field := range fields {
		field = strings.TrimSpace(field)
		if !supportedFields[field] {
			return nil, errors.New("unsupported release-health field " + field)
		}
		if !seen[field] {
			seen[field] = true
			result = append(result, field)
		}
	}
	return result, nil
}

func normalizeGroupBy(fields []string) ([]string, error) {
	if len(fields) == 0 {
		return []string{"session.status"}, nil
	}
	if len(fields) > 4 {
		return nil, errors.New("at most four release-health groupBy fields are allowed")
	}
	result, seen := make([]string, 0, len(fields)), make(map[string]bool)
	for _, field := range fields {
		field = strings.TrimSpace(field)
		if !supportedGroupBy[field] {
			return nil, errors.New("unsupported release-health groupBy " + field)
		}
		if !seen[field] {
			seen[field] = true
			result = append(result, field)
		}
	}
	return result, nil
}

func newAggregate() aggregate {
	return aggregate{users: make(map[string]struct{}), crashUsers: make(map[string]struct{})}
}

func updateAggregate(target *aggregate, status, userID string, duration float64, hasDuration bool) {
	target.sessions++
	crashed := status == "crashed"
	if crashed {
		target.crashed++
	}
	if hasDuration {
		target.duration += duration
		target.durations++
	}
	if userID != "" {
		target.users[userID] = struct{}{}
		if crashed {
			target.crashUsers[userID] = struct{}{}
		}
	}
}

func metric(field string, value aggregate) any {
	switch field {
	case "sum(session)":
		return value.sessions
	case "count_unique(user)":
		return len(value.users)
	case "avg(session.duration)":
		if value.durations == 0 {
			return nil
		}
		return value.duration / float64(value.durations)
	case "crash_free_rate(session)":
		if value.sessions == 0 {
			return nil
		}
		return 100 * (1 - float64(value.crashed)/float64(value.sessions))
	case "crash_free_rate(user)":
		if len(value.users) == 0 {
			return nil
		}
		return 100 * (1 - float64(len(value.crashUsers))/float64(len(value.users)))
	default:
		return nil
	}
}

func normalizedStatus(status string, sessionErrors int) string {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "crashed":
		return "crashed"
	case "abnormal":
		return "abnormal"
	}
	if sessionErrors > 0 {
		return "errored"
	}
	return "healthy"
}

func parseTime(value string) (time.Time, error) {
	if parsed, err := time.Parse(time.RFC3339Nano, value); err == nil {
		return parsed.UTC(), nil
	}
	return time.Parse("2006-01-02 15:04:05", value)
}

func placeholders(count int) string {
	values := make([]string, count)
	for index := range values {
		values[index] = "?"
	}
	return strings.Join(values, ",")
}

// ParseRange accepts the Sentry start/end or statsPeriod forms and applies the
// bounded 90-day query window used by Barktrace's other analytics APIs.
func ParseRange(now time.Time, startRaw, endRaw, period string) (time.Time, time.Time, error) {
	end := now.UTC()
	if strings.TrimSpace(endRaw) != "" {
		parsed, err := time.Parse(time.RFC3339, endRaw)
		if err != nil {
			return time.Time{}, time.Time{}, errors.New("end must be RFC3339")
		}
		end = parsed.UTC()
	}
	if strings.TrimSpace(startRaw) != "" {
		parsed, err := time.Parse(time.RFC3339, startRaw)
		if err != nil {
			return time.Time{}, time.Time{}, errors.New("start must be RFC3339")
		}
		start := parsed.UTC()
		if !start.Before(end) {
			return time.Time{}, time.Time{}, errors.New("start must be before end")
		}
		if end.Sub(start) > 90*24*time.Hour {
			return time.Time{}, time.Time{}, errors.New("time range cannot exceed 90 days")
		}
		return start, end, nil
	}
	duration, err := statsPeriod(period)
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	return end.Add(-duration), end, nil
}

// ParseInterval validates a Sentry interval and limits the response to 1,000
// buckets. The default is hourly for short ranges and daily otherwise.
func ParseInterval(raw string, period time.Duration) (time.Duration, error) {
	if period <= 0 {
		return 0, errors.New("interval requires a positive time range")
	}
	raw = strings.ToLower(strings.TrimSpace(raw))
	if raw == "" {
		if period <= 48*time.Hour {
			return time.Hour, nil
		}
		return 24 * time.Hour, nil
	}
	if len(raw) < 2 {
		return 0, errors.New("interval must use s, m, h, or d")
	}
	amount, err := strconv.Atoi(raw[:len(raw)-1])
	if err != nil || amount <= 0 {
		return 0, errors.New("interval must use s, m, h, or d")
	}
	var interval time.Duration
	switch raw[len(raw)-1] {
	case 's':
		if amount > int(period/time.Second) {
			return 0, errors.New("interval must produce between 1 and 1000 buckets")
		}
		interval = time.Duration(amount) * time.Second
	case 'm':
		if amount > int(period/time.Minute) {
			return 0, errors.New("interval must produce between 1 and 1000 buckets")
		}
		interval = time.Duration(amount) * time.Minute
	case 'h':
		if amount > int(period/time.Hour) {
			return 0, errors.New("interval must produce between 1 and 1000 buckets")
		}
		interval = time.Duration(amount) * time.Hour
	case 'd':
		if amount > int(period/(24*time.Hour)) {
			return 0, errors.New("interval must produce between 1 and 1000 buckets")
		}
		interval = time.Duration(amount) * 24 * time.Hour
	default:
		return 0, errors.New("interval must use s, m, h, or d")
	}
	if interval > period || int((period+interval-1)/interval) > 1000 {
		return 0, errors.New("interval must produce between 1 and 1000 buckets")
	}
	return interval, nil
}

func statsPeriod(value string) (time.Duration, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return 24 * time.Hour, nil
	}
	if len(value) < 2 {
		return 0, errors.New("stats period must be between 1h and 90d")
	}
	amount, err := strconv.Atoi(value[:len(value)-1])
	if err != nil || amount <= 0 {
		return 0, errors.New("stats period must be between 1h and 90d")
	}
	var duration time.Duration
	switch value[len(value)-1] {
	case 'h':
		if amount > 90*24 {
			return 0, errors.New("stats period must be between 1h and 90d")
		}
		duration = time.Duration(amount) * time.Hour
	case 'd':
		if amount > 90 {
			return 0, errors.New("stats period must be between 1h and 90d")
		}
		duration = time.Duration(amount) * 24 * time.Hour
	default:
		return 0, errors.New("stats period must use h or d")
	}
	if duration < time.Hour || duration > 90*24*time.Hour {
		return 0, errors.New("stats period must be between 1h and 90d")
	}
	return duration, nil
}
