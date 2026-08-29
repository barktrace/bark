package telemetry

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	maxReplayEvents   = 100000
	maxReplayTimeline = 2000
)

type ReplayAnalysis struct {
	URLs       []string         `json:"urls"`
	ErrorIDs   []string         `json:"error_ids"`
	TraceIDs   []string         `json:"trace_ids"`
	DurationMS int64            `json:"duration_ms"`
	Stats      map[string]int   `json:"stats"`
	Timeline   []ReplayTimeline `json:"timeline"`
	Truncated  bool             `json:"truncated"`
}

type ReplayTimeline struct {
	Timestamp  int64  `json:"timestamp"`
	RelativeMS int64  `json:"relative_ms"`
	Category   string `json:"category"`
	Type       string `json:"type"`
	Summary    string `json:"summary"`
}

type replayEvent struct {
	Type      int             `json:"type"`
	Timestamp float64         `json:"timestamp"`
	Data      json.RawMessage `json:"data"`
}

func AnalyzeReplay(eventPayload, recordingPayload []byte) (ReplayAnalysis, error) {
	result := ReplayAnalysis{URLs: []string{}, ErrorIDs: []string{}, TraceIDs: []string{}, Stats: make(map[string]int), Timeline: []ReplayTimeline{}}
	if len(eventPayload) > 0 {
		decoded, err := decodePayload(eventPayload)
		if err != nil {
			return result, fmt.Errorf("decode replay event: %w", err)
		}
		var metadata struct {
			URLs        []string `json:"urls"`
			ErrorIDs    []string `json:"error_ids"`
			TraceIDs    []string `json:"trace_ids"`
			Breadcrumbs []struct {
				Timestamp json.RawMessage `json:"timestamp"`
				Type      string          `json:"type"`
				Category  string          `json:"category"`
				Message   string          `json:"message"`
				Data      map[string]any  `json:"data"`
			} `json:"breadcrumbs"`
		}
		if err := json.Unmarshal(decoded, &metadata); err != nil {
			return result, fmt.Errorf("parse replay event: %w", err)
		}
		result.URLs, result.ErrorIDs, result.TraceIDs = boundedStrings(metadata.URLs, 100), boundedStrings(metadata.ErrorIDs, 100), boundedStrings(metadata.TraceIDs, 100)
		for _, breadcrumb := range metadata.Breadcrumbs {
			timestamp := rawTimestampMS(breadcrumb.Timestamp)
			category := strings.TrimSpace(breadcrumb.Category)
			if category == "" {
				category = "breadcrumb"
			}
			summary := strings.TrimSpace(breadcrumb.Message)
			if summary == "" {
				if target, ok := breadcrumb.Data["url"].(string); ok {
					summary = target
				}
			}
			result.Stats[category]++
			result.addReplayItem(ReplayTimeline{Timestamp: timestamp, Category: category, Type: firstText(breadcrumb.Type, "breadcrumb"), Summary: boundedText(summary, 500)})
		}
	}
	if len(recordingPayload) > 0 {
		recording, err := replayRecordingBody(recordingPayload)
		if err != nil {
			return result, fmt.Errorf("decode replay recording: %w", err)
		}
		if err := scanReplayEvents(recording, func(event replayEvent) error {
			result.Stats["events"]++
			if result.Stats["events"] > maxReplayEvents {
				result.Truncated = true
				return errReplayLimit
			}
			item := describeReplayEvent(event)
			result.Stats[item.Category]++
			result.addReplayItem(item)
			return nil
		}); err != nil && !errors.Is(err, errReplayLimit) {
			return result, fmt.Errorf("parse replay recording: %w", err)
		}
	}
	sort.SliceStable(result.Timeline, func(i, j int) bool { return result.Timeline[i].Timestamp < result.Timeline[j].Timestamp })
	if len(result.Timeline) > 0 {
		first := int64(0)
		for _, item := range result.Timeline {
			if item.Timestamp > 0 {
				first = item.Timestamp
				break
			}
		}
		last := first
		for index := range result.Timeline {
			if first > 0 && result.Timeline[index].Timestamp > 0 {
				result.Timeline[index].RelativeMS = result.Timeline[index].Timestamp - first
				last = result.Timeline[index].Timestamp
			}
		}
		result.DurationMS = maxInt64(0, last-first)
	}
	return result, nil
}

var errReplayLimit = errors.New("replay event limit reached")

func (result *ReplayAnalysis) addReplayItem(item ReplayTimeline) {
	if len(result.Timeline) >= maxReplayTimeline {
		result.Truncated = true
		return
	}
	if item.Summary == "" {
		item.Summary = item.Type
	}
	result.Timeline = append(result.Timeline, item)
}

func replayRecordingBody(raw []byte) ([]byte, error) {
	trimmed := bytes.TrimSpace(raw)
	if newline := bytes.IndexByte(trimmed, '\n'); newline > 0 && trimmed[0] == '{' {
		var header map[string]json.RawMessage
		if json.Unmarshal(trimmed[:newline], &header) == nil && header["type"] == nil && (header["replay_id"] != nil || header["segment_id"] != nil) {
			trimmed = bytes.TrimSpace(trimmed[newline+1:])
		}
	}
	return decodePayload(trimmed)
}

func scanReplayEvents(raw []byte, visit func(replayEvent) error) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	first, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := first.(json.Delim)
	if !ok {
		return errors.New("recording must be a JSON array or object")
	}
	if delimiter == '[' {
		for decoder.More() {
			var event replayEvent
			if err := decoder.Decode(&event); err != nil {
				return err
			}
			if err := visit(event); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	}
	if delimiter != '{' {
		return errors.New("recording must be a JSON array or object")
	}
	var single map[string]json.RawMessage
	if err := json.Unmarshal(raw, &single); err != nil {
		return err
	}
	if events := single["events"]; len(events) > 0 {
		return scanReplayEvents(events, visit)
	}
	encoded, _ := json.Marshal(single)
	var event replayEvent
	if err := json.Unmarshal(encoded, &event); err != nil {
		return err
	}
	return visit(event)
}

func describeReplayEvent(event replayEvent) ReplayTimeline {
	item := ReplayTimeline{Timestamp: replayTimestampMS(event.Timestamp), Category: "other", Type: "event"}
	var data map[string]any
	_ = json.Unmarshal(event.Data, &data)
	switch event.Type {
	case 0:
		item.Category, item.Type, item.Summary = "lifecycle", "dom_content_loaded", "DOM content loaded"
	case 1:
		item.Category, item.Type, item.Summary = "lifecycle", "load", "Page loaded"
	case 2:
		item.Category, item.Type, item.Summary = "snapshot", "full_snapshot", "Full DOM snapshot"
	case 3:
		item = describeIncremental(item, data)
	case 4:
		item.Category, item.Type = "navigation", "navigation"
		item.Summary = boundedText(stringValue(data["href"]), 500)
		if width, ok := numberValue(data["width"]); ok {
			if height, valid := numberValue(data["height"]); valid {
				item.Summary = strings.TrimSpace(item.Summary + fmt.Sprintf(" (%gx%g)", width, height))
			}
		}
	case 5:
		item.Category, item.Type = "custom", "custom"
		item.Summary = boundedText(stringValue(data["tag"]), 500)
	case 6:
		item.Category, item.Type = "plugin", "plugin"
		item.Summary = boundedText(stringValue(data["plugin"]), 500)
	default:
		item.Type = fmt.Sprintf("event_%d", event.Type)
	}
	return item
}

func describeIncremental(item ReplayTimeline, data map[string]any) ReplayTimeline {
	source, _ := numberValue(data["source"])
	switch int(source) {
	case 0:
		item.Category, item.Type = "mutation", "dom_mutation"
		item.Summary = fmt.Sprintf("DOM changed: %d added, %d removed, %d text, %d attributes", sliceLength(data["adds"]), sliceLength(data["removes"]), sliceLength(data["texts"]), sliceLength(data["attributes"]))
	case 1, 6:
		item.Category, item.Type, item.Summary = "pointer", "pointer_move", "Pointer moved"
	case 2:
		interactionNames := []string{"mouse_up", "mouse_down", "click", "context_menu", "double_click", "focus", "blur", "touch_start", "touch_move", "touch_end"}
		interaction, _ := numberValue(data["type"])
		name := "interaction"
		if int(interaction) >= 0 && int(interaction) < len(interactionNames) {
			name = interactionNames[int(interaction)]
		}
		item.Category, item.Type, item.Summary = "interaction", name, strings.ReplaceAll(name, "_", " ")
	case 3:
		item.Category, item.Type, item.Summary = "scroll", "scroll", "Page scrolled"
	case 4:
		item.Category, item.Type, item.Summary = "viewport", "viewport_resize", "Viewport resized"
	case 5:
		item.Category, item.Type, item.Summary = "input", "input", "Form input changed"
	case 7:
		item.Category, item.Type, item.Summary = "media", "media_interaction", "Media interaction"
	case 8, 13, 15:
		item.Category, item.Type, item.Summary = "style", "style_change", "Page styles changed"
	case 9:
		item.Category, item.Type, item.Summary = "canvas", "canvas_mutation", "Canvas updated"
	case 10:
		item.Category, item.Type, item.Summary = "resource", "font", "Font loaded"
	case 11:
		item.Category, item.Type = "console", "console"
		item.Summary = boundedText(stringValue(data["level"]), 500)
	case 12:
		item.Category, item.Type, item.Summary = "interaction", "drag", "Element dragged"
	case 14:
		item.Category, item.Type, item.Summary = "selection", "selection", "Selection changed"
	default:
		item.Category, item.Type, item.Summary = "incremental", fmt.Sprintf("source_%d", int(source)), "Incremental update"
	}
	return item
}

func replayTimestampMS(value float64) int64 {
	if value <= 0 {
		return 0
	}
	if value < 100000000000 {
		value *= 1000
	}
	return int64(value)
}

func rawTimestampMS(raw json.RawMessage) int64 {
	var number float64
	if json.Unmarshal(raw, &number) == nil {
		return replayTimestampMS(number)
	}
	var text string
	if json.Unmarshal(raw, &text) == nil {
		if parsed, err := strconv.ParseFloat(text, 64); err == nil {
			return replayTimestampMS(parsed)
		}
		if parsed, err := time.Parse(time.RFC3339Nano, text); err == nil {
			return parsed.UnixMilli()
		}
	}
	return 0
}

func boundedStrings(values []string, limit int) []string {
	if len(values) > limit {
		values = values[:limit]
	}
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value = boundedText(strings.TrimSpace(value), 500); value != "" {
			result = append(result, value)
		}
	}
	return result
}

func boundedText(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return value[:limit]
}

func firstText(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func stringValue(value any) string {
	text, _ := value.(string)
	return text
}

func numberValue(value any) (float64, bool) {
	switch typed := value.(type) {
	case float64:
		return typed, true
	case json.Number:
		number, err := typed.Float64()
		return number, err == nil
	default:
		return 0, false
	}
}

func sliceLength(value any) int {
	items, _ := value.([]any)
	return len(items)
}

func maxInt64(left, right int64) int64 {
	if left > right {
		return left
	}
	return right
}
