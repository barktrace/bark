package cronmon

import (
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"
)

func NormalizeSchedule(kind string, raw json.RawMessage) (string, string, error) {
	kind = strings.ToLower(strings.TrimSpace(kind))
	if kind == "crontab" {
		var expression string
		if json.Unmarshal(raw, &expression) != nil || !validCrontab(expression) {
			return "", "", errors.New("invalid crontab schedule")
		}
		return kind, strings.TrimSpace(expression), nil
	}
	var parts []any
	if json.Unmarshal(raw, &parts) == nil && len(parts) == 2 {
		amount, ok := number(parts[0])
		unit, unitOK := parts[1].(string)
		if ok && unitOK {
			minutes := intervalMinutes(amount, unit)
			if minutes > 0 {
				return "interval", strconv.Itoa(minutes), nil
			}
		}
	}
	var amount float64
	if json.Unmarshal(raw, &amount) == nil && amount > 0 {
		return "interval", strconv.Itoa(max(1, int(amount))), nil
	}
	var text string
	if json.Unmarshal(raw, &text) == nil {
		if parsed, err := strconv.Atoi(text); err == nil && parsed > 0 {
			return "interval", strconv.Itoa(parsed), nil
		}
	}
	return "interval", "5", nil
}

func Next(after time.Time, kind, value, timezone string) time.Time {
	if kind == "interval" {
		minutes, err := strconv.Atoi(value)
		if err == nil && minutes > 0 {
			return after.Add(time.Duration(minutes) * time.Minute)
		}
		return after.Add(5 * time.Minute)
	}
	location, err := time.LoadLocation(timezone)
	if err != nil {
		location = time.UTC
	}
	candidate := after.In(location).Truncate(time.Minute).Add(time.Minute)
	fields := strings.Fields(value)
	for attempts := 0; attempts < 60*24*366*2; attempts++ {
		if matches(fields[0], candidate.Minute(), 0, 59) && matches(fields[1], candidate.Hour(), 0, 23) && matches(fields[2], candidate.Day(), 1, 31) && matches(fields[3], int(candidate.Month()), 1, 12) && matches(fields[4], int(candidate.Weekday()), 0, 6) {
			return candidate.UTC()
		}
		candidate = candidate.Add(time.Minute)
	}
	return after.Add(24 * time.Hour)
}

func validCrontab(expression string) bool {
	fields := strings.Fields(expression)
	if len(fields) != 5 {
		return false
	}
	limits := [][2]int{{0, 59}, {0, 23}, {1, 31}, {1, 12}, {0, 6}}
	for index, field := range fields {
		if !validField(field, limits[index][0], limits[index][1]) {
			return false
		}
	}
	return true
}

func validField(field string, minimum, maximum int) bool {
	for _, part := range strings.Split(field, ",") {
		base, stepText, _ := strings.Cut(part, "/")
		if stepText != "" {
			step, err := strconv.Atoi(stepText)
			if err != nil || step < 1 || step > maximum-minimum+1 {
				return false
			}
		}
		if base == "*" {
			continue
		}
		startText, endText, ranged := strings.Cut(base, "-")
		start, err := strconv.Atoi(startText)
		if err != nil || start < minimum || start > maximum {
			return false
		}
		if ranged {
			end, err := strconv.Atoi(endText)
			if err != nil || end < start || end > maximum {
				return false
			}
		}
	}
	return true
}

func matches(field string, value, minimum, maximum int) bool {
	for _, part := range strings.Split(field, ",") {
		base, stepText, _ := strings.Cut(part, "/")
		step := 1
		if stepText != "" {
			step, _ = strconv.Atoi(stepText)
		}
		start, end := minimum, maximum
		if base != "*" {
			startText, endText, ranged := strings.Cut(base, "-")
			start, _ = strconv.Atoi(startText)
			end = start
			if ranged {
				end, _ = strconv.Atoi(endText)
			}
		}
		if value >= start && value <= end && (value-start)%step == 0 {
			return true
		}
	}
	return false
}

func number(value any) (float64, bool) {
	switch typed := value.(type) {
	case float64:
		return typed, true
	case string:
		parsed, err := strconv.ParseFloat(typed, 64)
		return parsed, err == nil
	default:
		return 0, false
	}
}

func intervalMinutes(amount float64, unit string) int {
	switch strings.ToLower(strings.TrimSpace(unit)) {
	case "minute", "minutes":
		return max(1, int(amount))
	case "hour", "hours":
		return max(1, int(amount*60))
	case "day", "days":
		return max(1, int(amount*1440))
	case "week", "weeks":
		return max(1, int(amount*10080))
	default:
		return 0
	}
}
