// Package discover implements Barktrace's bounded, organization-scoped query
// engine. All SQL identifiers come from static dataset definitions; user input
// is only ever supplied as bound parameters.
package discover

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	defaultLimit      = 50
	maximumLimit      = 100
	maximumFields     = 20
	maximumProjects   = 500
	maximumQueryBytes = 2048
)

type Request struct {
	Dataset     string
	Fields      []string
	ProjectIDs  []string
	Project     string
	Environment string
	Release     string
	Level       string
	Status      string
	Query       string
	Start       time.Time
	End         time.Time
	OrderBy     string
	Limit       int
}

type Result struct {
	Data []map[string]any `json:"data"`
	Meta map[string]any   `json:"meta"`
}

type field struct {
	expression string
	valueType  string
	filterable bool
	searchable bool
}

type dataset struct {
	name          string
	from          string
	timeField     string
	defaultFields []string
	fields        map[string]field
}

var aggregatePattern = regexp.MustCompile(`^(count|count_unique|sum|avg|min|max|p50|p75|p90|p95|p99)\(([^)]*)\)$`)

var datasets = map[string]dataset{
	"errors": {
		name: "errors", from: `events e JOIN issues i ON i.id = e.issue_id JOIN projects p ON p.id = e.project_id LEFT JOIN releases r ON r.id = e.release_id`, timeField: "e.timestamp",
		defaultFields: []string{"event.id", "project", "title", "level", "environment", "release", "timestamp"},
		fields: map[string]field{
			"id": {"e.id", "string", false, false}, "event.id": {"e.event_id", "string", true, false},
			"issue.id": {"i.id", "string", true, false}, "project": {"p.slug", "string", true, false},
			"project.id": {"p.id", "string", true, false}, "project.name": {"p.name", "string", true, false},
			"title": {"i.title", "string", true, true}, "message": {"i.title", "string", true, true},
			"level": {"e.level", "string", true, false}, "status": {"i.status", "string", true, false},
			"environment": {"e.environment", "string", true, false}, "release": {"COALESCE(r.version, '')", "string", true, false},
			"platform": {"e.platform", "string", true, false}, "timestamp": {"e.timestamp", "date", true, false},
		},
	},
	"transactions": {
		name: "transactions", from: `transactions t JOIN projects p ON p.id = t.project_id LEFT JOIN releases r ON r.id = t.release_id`, timeField: "t.finished_at",
		defaultFields: []string{"event.id", "project", "transaction", "transaction.op", "transaction.status", "duration", "environment", "release", "timestamp"},
		fields: map[string]field{
			"id": {"t.id", "string", false, false}, "event.id": {"t.event_id", "string", true, false},
			"project": {"p.slug", "string", true, false}, "project.id": {"p.id", "string", true, false}, "project.name": {"p.name", "string", true, false},
			"transaction": {"t.name", "string", true, true}, "transaction.op": {"t.operation", "string", true, false},
			"transaction.status": {"t.status", "string", true, false}, "status": {"t.status", "string", true, false},
			"trace": {"t.trace_id", "string", true, false}, "span.id": {"t.span_id", "string", true, false},
			"duration": {"t.duration_ms", "duration", true, false}, "spans": {"t.span_count", "integer", true, false},
			"environment": {"t.environment", "string", true, false}, "release": {"COALESCE(r.version, '')", "string", true, false},
			"timestamp": {"t.finished_at", "date", true, false},
		},
	},
	"spans": {
		name: "spans", from: `spans s JOIN projects p ON p.id = s.project_id`, timeField: "s.finished_at",
		defaultFields: []string{"span.id", "project", "span.op", "span.description", "span.status", "duration", "trace", "timestamp"},
		fields: map[string]field{
			"id": {"s.id", "string", false, false}, "span.id": {"s.span_id", "string", true, false},
			"parent_span": {"s.parent_span_id", "string", true, false}, "trace": {"s.trace_id", "string", true, false},
			"project": {"p.slug", "string", true, false}, "project.id": {"p.id", "string", true, false}, "project.name": {"p.name", "string", true, false},
			"span.op": {"s.operation", "string", true, false}, "span.description": {"s.description", "string", true, true},
			"span.status": {"s.status", "string", true, false}, "status": {"s.status", "string", true, false},
			"duration": {"s.duration_ms", "duration", true, false}, "timestamp": {"s.finished_at", "date", true, false},
		},
	},
	"logs": {
		name: "logs", from: `logs l JOIN projects p ON p.id = l.project_id LEFT JOIN releases r ON r.id = l.release_id`, timeField: "l.timestamp",
		defaultFields: []string{"sentry.item_id", "project", "message", "severity", "environment", "release", "trace", "timestamp"},
		fields: map[string]field{
			"id": {"l.id", "string", false, false}, "sentry.item_id": {"l.id", "string", true, false},
			"project": {"p.slug", "string", true, false}, "project.id": {"p.id", "string", true, false}, "project.name": {"p.name", "string", true, false},
			"message": {"l.message", "string", true, true}, "severity": {"l.level", "string", true, false}, "level": {"l.level", "string", true, false},
			"environment": {"l.environment", "string", true, false}, "release": {"COALESCE(r.version, '')", "string", true, false},
			"trace": {"l.trace_id", "string", true, false}, "span.id": {"l.span_id", "string", true, false}, "timestamp": {"l.timestamp", "date", true, false},
		},
	},
	"metrics": {
		name: "metrics", from: `metric_points m JOIN projects p ON p.id = m.project_id`, timeField: "m.timestamp",
		defaultFields: []string{"project", "metric.name", "metric.type", "metric.value", "metric.unit", "timestamp"},
		fields: map[string]field{
			"id": {"m.id", "integer", false, false}, "project": {"p.slug", "string", true, false},
			"project.id": {"p.id", "string", true, false}, "project.name": {"p.name", "string", true, false},
			"metric.name": {"m.name", "string", true, true}, "metric.type": {"m.metric_type", "string", true, false},
			"metric.value": {"m.value", "number", true, false}, "metric.unit": {"m.unit", "string", true, false},
			"timestamp": {"m.timestamp", "date", true, false},
		},
	},
}

type selectedField struct {
	name              string
	expression        string
	valueType         string
	aggregate         bool
	aggregateFunction string
	percentile        bool
	rawMetric         string
}

// Query executes a bounded query over projects already authorized by the
// caller. An empty ProjectIDs slice intentionally returns no rows.
func Query(ctx context.Context, db *sql.DB, request Request) (Result, error) {
	datasetName := normalizeDataset(request.Dataset)
	definition, ok := datasets[datasetName]
	if !ok {
		return Result{}, fmt.Errorf("unsupported dataset %q", request.Dataset)
	}
	if len(request.ProjectIDs) > maximumProjects {
		return Result{}, fmt.Errorf("at most %d projects may be queried at once", maximumProjects)
	}
	if len(request.Query) > maximumQueryBytes {
		return Result{}, fmt.Errorf("query cannot exceed %d bytes", maximumQueryBytes)
	}
	if request.End.IsZero() {
		request.End = time.Now().UTC()
	}
	if request.Start.IsZero() {
		request.Start = request.End.Add(-24 * time.Hour)
	}
	if !request.Start.Before(request.End) {
		return Result{}, errors.New("start must be before end")
	}
	if request.End.Sub(request.Start) > 90*24*time.Hour {
		return Result{}, errors.New("time range cannot exceed 90 days")
	}
	fields := request.Fields
	if len(fields) == 0 {
		fields = append([]string(nil), definition.defaultFields...)
	}
	if len(fields) > maximumFields {
		return Result{}, fmt.Errorf("at most %d fields may be selected", maximumFields)
	}
	selected, err := selectFields(definition, fields)
	if err != nil {
		return Result{}, err
	}
	where, args, err := buildWhere(definition, request)
	if err != nil {
		return Result{}, err
	}
	limit := request.Limit
	if limit <= 0 {
		limit = defaultLimit
	}
	if limit > maximumLimit {
		limit = maximumLimit
	}
	if len(request.ProjectIDs) == 0 {
		return Result{Data: []map[string]any{}, Meta: resultMeta(definition, selected, request, limit)}, nil
	}

	statement, err := buildSQL(definition, selected, where, request.OrderBy, limit)
	if err != nil {
		return Result{}, err
	}
	rows, err := db.QueryContext(ctx, statement, args...)
	if err != nil {
		return Result{}, fmt.Errorf("execute discover query: %w", err)
	}
	defer rows.Close()
	data := make([]map[string]any, 0, limit)
	for rows.Next() {
		values := make([]any, len(selected))
		destinations := make([]any, len(selected))
		for index := range values {
			destinations[index] = &values[index]
		}
		if err := rows.Scan(destinations...); err != nil {
			return Result{}, err
		}
		item := make(map[string]any, len(selected))
		for index, selection := range selected {
			item[selection.name] = normalizeValue(values[index])
		}
		data = append(data, item)
	}
	if err := rows.Err(); err != nil {
		return Result{}, err
	}
	return Result{Data: data, Meta: resultMeta(definition, selected, request, limit)}, nil
}

func normalizeDataset(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "events", "errors", "error", "issue", "issues":
		return "errors"
	case "transaction", "transactions":
		return "transactions"
	case "span", "spans":
		return "spans"
	case "log", "logs":
		return "logs"
	case "metric", "metrics":
		return "metrics"
	default:
		return strings.ToLower(strings.TrimSpace(value))
	}
}

func selectFields(definition dataset, names []string) ([]selectedField, error) {
	selected := make([]selectedField, 0, len(names))
	seen := make(map[string]bool, len(names))
	percentileMetric := ""
	for _, raw := range names {
		name := strings.TrimSpace(raw)
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		if match := aggregatePattern.FindStringSubmatch(name); match != nil {
			function, argument := match[1], strings.TrimSpace(match[2])
			selection, err := aggregateField(definition, name, function, argument)
			if err != nil {
				return nil, err
			}
			if selection.percentile {
				if percentileMetric != "" && percentileMetric != selection.rawMetric {
					return nil, errors.New("all percentile fields must use the same metric")
				}
				percentileMetric = selection.rawMetric
			}
			selected = append(selected, selection)
			continue
		}
		definitionField, ok := definition.fields[name]
		if !ok {
			return nil, fmt.Errorf("unsupported field %q for %s", name, definition.name)
		}
		selected = append(selected, selectedField{name: name, expression: definitionField.expression, valueType: definitionField.valueType})
	}
	if len(selected) == 0 {
		return nil, errors.New("at least one field is required")
	}
	return selected, nil
}

func aggregateField(definition dataset, name, function, argument string) (selectedField, error) {
	if function == "count" && argument == "" {
		return selectedField{name: name, expression: "COUNT(*)", valueType: "integer", aggregate: true, aggregateFunction: function}, nil
	}
	fieldDefinition, ok := definition.fields[argument]
	if !ok {
		return selectedField{}, fmt.Errorf("unsupported aggregate field %q", argument)
	}
	if function == "count" {
		return selectedField{name: name, expression: "COUNT(" + fieldDefinition.expression + ")", valueType: "integer", aggregate: true, aggregateFunction: function, rawMetric: fieldDefinition.expression}, nil
	}
	if function == "count_unique" {
		return selectedField{name: name, expression: "COUNT(DISTINCT " + fieldDefinition.expression + ")", valueType: "integer", aggregate: true, aggregateFunction: function, rawMetric: fieldDefinition.expression}, nil
	}
	if function == "min" || function == "max" {
		return selectedField{name: name, expression: strings.ToUpper(function) + "(" + fieldDefinition.expression + ")", valueType: fieldDefinition.valueType, aggregate: true, aggregateFunction: function, rawMetric: fieldDefinition.expression}, nil
	}
	if function == "sum" || function == "avg" {
		if fieldDefinition.valueType != "integer" && fieldDefinition.valueType != "number" && fieldDefinition.valueType != "duration" {
			return selectedField{}, fmt.Errorf("%s requires a numeric field", function)
		}
		return selectedField{name: name, expression: strings.ToUpper(function) + "(" + fieldDefinition.expression + ")", valueType: fieldDefinition.valueType, aggregate: true, aggregateFunction: function, rawMetric: fieldDefinition.expression}, nil
	}
	if fieldDefinition.valueType != "integer" && fieldDefinition.valueType != "number" && fieldDefinition.valueType != "duration" {
		return selectedField{}, fmt.Errorf("%s requires a numeric field", function)
	}
	percent := strings.TrimPrefix(function, "p")
	return selectedField{name: name, expression: percent, valueType: fieldDefinition.valueType, aggregate: true, aggregateFunction: function, percentile: true, rawMetric: fieldDefinition.expression}, nil
}

func buildWhere(definition dataset, request Request) (string, []any, error) {
	conditions := make([]string, 0, 12)
	args := make([]any, 0, 16)
	placeholders := make([]string, len(request.ProjectIDs))
	for index, id := range request.ProjectIDs {
		placeholders[index] = "?"
		args = append(args, id)
	}
	conditions = append(conditions, "p.id IN ("+strings.Join(placeholders, ",")+")")
	if !request.Start.IsZero() {
		conditions = append(conditions, definition.timeField+" >= ?")
		args = append(args, request.Start.UTC().Format(time.RFC3339Nano))
	}
	if !request.End.IsZero() {
		conditions = append(conditions, definition.timeField+" <= ?")
		args = append(args, request.End.UTC().Format(time.RFC3339Nano))
	}
	for _, item := range []struct{ key, value string }{{"project", request.Project}, {"environment", request.Environment}, {"release", request.Release}, {"level", request.Level}, {"status", request.Status}} {
		if strings.TrimSpace(item.value) == "" {
			continue
		}
		condition, values, err := filterCondition(definition, item.key, item.value, false)
		if err != nil {
			return "", nil, err
		}
		conditions, args = append(conditions, condition), append(args, values...)
	}
	queryConditions, queryArgs, err := parseQuery(definition, request.Query)
	if err != nil {
		return "", nil, err
	}
	conditions, args = append(conditions, queryConditions...), append(args, queryArgs...)
	return strings.Join(conditions, " AND "), args, nil
}

func parseQuery(definition dataset, query string) ([]string, []any, error) {
	tokens, err := tokenize(query)
	if err != nil {
		return nil, nil, err
	}
	conditions := make([]string, 0, len(tokens))
	args := make([]any, 0, len(tokens))
	for _, token := range tokens {
		negated := strings.HasPrefix(token, "-")
		if negated {
			token = strings.TrimPrefix(token, "-")
		}
		if key, value, found := strings.Cut(token, ":"); found && key != "" {
			condition, values, err := filterCondition(definition, key, value, negated)
			if err != nil {
				return nil, nil, err
			}
			conditions, args = append(conditions, condition), append(args, values...)
			continue
		}
		searches := make([]string, 0, 2)
		for _, fieldDefinition := range definition.fields {
			if fieldDefinition.searchable {
				searches = append(searches, fieldDefinition.expression+" LIKE ? COLLATE NOCASE")
			}
		}
		sort.Strings(searches)
		if len(searches) == 0 {
			return nil, nil, fmt.Errorf("dataset %s has no searchable fields", definition.name)
		}
		operator := ""
		if negated {
			operator = "NOT "
		}
		conditions = append(conditions, operator+"("+strings.Join(searches, " OR ")+")")
		for range searches {
			args = append(args, "%"+token+"%")
		}
	}
	return conditions, args, nil
}

func filterCondition(definition dataset, key, value string, negated bool) (string, []any, error) {
	key, value = strings.TrimSpace(key), strings.TrimSpace(value)
	if key == "severity" && definition.name != "logs" {
		key = "level"
	}
	fieldDefinition, ok := definition.fields[key]
	if !ok || !fieldDefinition.filterable {
		return "", nil, fmt.Errorf("unsupported filter %q for %s", key, definition.name)
	}
	if value == "" {
		return "", nil, fmt.Errorf("filter %q requires a value", key)
	}
	operator := "="
	if negated {
		operator = "!="
	}
	if strings.Contains(value, "*") {
		operator = "LIKE"
		if negated {
			operator = "NOT LIKE"
		}
		value = strings.ReplaceAll(value, "*", "%")
	}
	if key == "project" {
		condition := `(p.slug ` + operator + ` ? OR p.id ` + operator + ` ? OR p.sentry_id ` + operator + ` ?)`
		if negated {
			condition = `(p.slug ` + operator + ` ? AND p.id ` + operator + ` ? AND p.sentry_id ` + operator + ` ?)`
		}
		return condition, []any{value, value, value}, nil
	}
	return fieldDefinition.expression + " " + operator + " ?", []any{value}, nil
}

func tokenize(query string) ([]string, error) {
	query = strings.TrimSpace(query)
	if query == "" {
		return nil, nil
	}
	tokens := make([]string, 0, 8)
	var builder strings.Builder
	var quote rune
	for _, character := range query {
		switch {
		case quote != 0 && character == quote:
			quote = 0
		case quote != 0:
			builder.WriteRune(character)
		case character == '\'' || character == '"':
			quote = character
		case character == ' ' || character == '\t' || character == '\n':
			if builder.Len() > 0 {
				tokens = append(tokens, builder.String())
				builder.Reset()
			}
		default:
			builder.WriteRune(character)
		}
	}
	if quote != 0 {
		return nil, errors.New("unterminated quote in query")
	}
	if builder.Len() > 0 {
		tokens = append(tokens, builder.String())
	}
	if len(tokens) > 20 {
		return nil, errors.New("at most 20 query terms are allowed")
	}
	return tokens, nil
}

func buildSQL(definition dataset, selected []selectedField, where, requestedOrder string, limit int) (string, error) {
	groups := make([]selectedField, 0)
	hasAggregate, hasPercentile := false, false
	for _, selection := range selected {
		if selection.aggregate {
			hasAggregate = true
		} else {
			groups = append(groups, selection)
		}
		if selection.percentile {
			hasPercentile = true
		}
	}
	if hasPercentile {
		return buildPercentileSQL(definition, selected, where, requestedOrder, limit)
	}
	selectParts := make([]string, 0, len(selected))
	for index, selection := range selected {
		selectParts = append(selectParts, selection.expression+fmt.Sprintf(` AS "f%d"`, index))
	}
	groupBy := ""
	if hasAggregate && len(groups) > 0 {
		expressions := make([]string, len(groups))
		for index, group := range groups {
			expressions[index] = group.expression
		}
		groupBy = " GROUP BY " + strings.Join(expressions, ", ")
	}
	order, err := orderClause(definition, selected, requestedOrder, hasAggregate)
	if err != nil {
		return "", err
	}
	return `SELECT ` + strings.Join(selectParts, ", ") + ` FROM ` + definition.from + ` WHERE ` + where + groupBy + order + ` LIMIT ` + strconv.Itoa(limit), nil
}

func buildPercentileSQL(definition dataset, selected []selectedField, where, requestedOrder string, limit int) (string, error) {
	groups := make([]selectedField, 0)
	metric := ""
	for _, selection := range selected {
		if !selection.aggregate {
			groups = append(groups, selection)
		}
		if selection.percentile {
			metric = selection.rawMetric
		}
	}
	baseColumns := []string{metric + " AS _percentile_value"}
	partitionNames := make([]string, 0, len(groups))
	for index, group := range groups {
		alias := fmt.Sprintf("_group_%d", index)
		baseColumns = append(baseColumns, group.expression+` AS "`+alias+`"`)
		partitionNames = append(partitionNames, `"`+alias+`"`)
	}
	for index, selection := range selected {
		if selection.aggregate && !selection.percentile && selection.rawMetric != "" {
			baseColumns = append(baseColumns, selection.rawMetric+fmt.Sprintf(` AS "_aggregate_%d"`, index))
		}
	}
	partition := ""
	if len(partitionNames) > 0 {
		partition = "PARTITION BY " + strings.Join(partitionNames, ", ") + " "
	}
	selectParts := make([]string, 0, len(selected))
	groupIndex := 0
	for index, selection := range selected {
		expression := selection.expression
		switch {
		case !selection.aggregate:
			expression = fmt.Sprintf(`"_group_%d"`, groupIndex)
			groupIndex++
		case selection.percentile:
			threshold, _ := strconv.Atoi(selection.expression)
			expression = fmt.Sprintf(`MIN(CASE WHEN _rank >= CAST((_total * %d + 99) / 100 AS INTEGER) THEN _percentile_value END)`, threshold)
		default:
			switch selection.aggregateFunction {
			case "count":
				if selection.rawMetric == "" {
					expression = "COUNT(*)"
				} else {
					expression = fmt.Sprintf(`COUNT("_aggregate_%d")`, index)
				}
			case "count_unique":
				expression = fmt.Sprintf(`COUNT(DISTINCT "_aggregate_%d")`, index)
			default:
				expression = strings.ToUpper(selection.aggregateFunction) + fmt.Sprintf(`("_aggregate_%d")`, index)
			}
		}
		selectParts = append(selectParts, expression+fmt.Sprintf(` AS "f%d"`, index))
	}
	groupBy := ""
	if len(partitionNames) > 0 {
		groupBy = " GROUP BY " + strings.Join(partitionNames, ", ")
	}
	order, err := orderClause(definition, selected, requestedOrder, true)
	if err != nil {
		return "", err
	}
	order = orderByOutputAlias(selected, requestedOrder, order)
	return `WITH base AS (SELECT ` + strings.Join(baseColumns, ", ") + ` FROM ` + definition.from + ` WHERE ` + where + `), ranked AS (SELECT *, ROW_NUMBER() OVER (` + partition + `ORDER BY _percentile_value) AS _rank, COUNT(*) OVER (` + strings.TrimSpace(partition) + `) AS _total FROM base) SELECT ` + strings.Join(selectParts, ", ") + ` FROM ranked` + groupBy + order + ` LIMIT ` + strconv.Itoa(limit), nil
}

func orderClause(definition dataset, selected []selectedField, requested string, aggregate bool) (string, error) {
	requested = strings.TrimSpace(requested)
	direction := "ASC"
	name := requested
	if strings.HasPrefix(name, "-") {
		direction, name = "DESC", strings.TrimPrefix(name, "-")
	}
	if name == "" {
		if aggregate {
			for index, selection := range selected {
				if selection.aggregate {
					return fmt.Sprintf(` ORDER BY "f%d" DESC`, index), nil
				}
			}
		}
		return " ORDER BY " + definition.timeField + " DESC", nil
	}
	for index, selection := range selected {
		if selection.name == name {
			return fmt.Sprintf(` ORDER BY "f%d" %s`, index, direction), nil
		}
	}
	return "", fmt.Errorf("order field %q must be selected", name)
}

func orderByOutputAlias(selected []selectedField, requested, fallback string) string {
	if strings.TrimSpace(requested) == "" {
		return fallback
	}
	name := strings.TrimPrefix(strings.TrimSpace(requested), "-")
	direction := "ASC"
	if strings.HasPrefix(strings.TrimSpace(requested), "-") {
		direction = "DESC"
	}
	for index, selection := range selected {
		if selection.name == name {
			return fmt.Sprintf(` ORDER BY "f%d" %s`, index, direction)
		}
	}
	return fallback
}

func normalizeValue(value any) any {
	switch typed := value.(type) {
	case []byte:
		return string(typed)
	case nil:
		return nil
	default:
		return typed
	}
}

func resultMeta(definition dataset, selected []selectedField, request Request, limit int) map[string]any {
	fieldTypes := make(map[string]string)
	for _, selection := range selected {
		fieldTypes[selection.name] = selection.valueType
	}
	return map[string]any{
		"dataset": definition.name, "fields": fieldTypes, "start": formatTime(request.Start),
		"end": formatTime(request.End), "limit": limit,
	}
}

func formatTime(value time.Time) any {
	if value.IsZero() {
		return nil
	}
	return value.UTC().Format(time.RFC3339Nano)
}
