package symbolicate

import (
	"bufio"
	"context"
	"debug/elf"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"path"
	"strconv"
	"strings"

	"github.com/barktrace/bark/internal/store"
)

type artifact struct {
	name, kind, debugID, storageKey string
}

func ProcessEvent(ctx context.Context, st *store.Store, projectID, releaseID string, raw []byte) ([]byte, bool, error) {
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil, false, err
	}
	artifacts, err := loadArtifacts(ctx, st, projectID, releaseID)
	if err != nil {
		return nil, false, err
	}
	if len(artifacts) == 0 {
		return raw, false, nil
	}
	changed := false
	for _, frame := range eventFrames(payload) {
		if symbolicateJavaScriptFrame(st, artifacts, frame) || symbolicateNativeFrame(st, artifacts, payload, frame) {
			changed = true
		}
	}
	if !changed {
		return raw, false, nil
	}
	processed, err := json.Marshal(payload)
	return processed, err == nil, err
}

func loadArtifacts(ctx context.Context, st *store.Store, projectID, releaseID string) ([]artifact, error) {
	rows, err := st.DB.QueryContext(ctx, `
		SELECT a.name, a.artifact_type, a.debug_id, b.storage_key
		FROM project_artifacts a JOIN blobs b ON b.id = a.blob_id
		WHERE a.project_id = ? AND (a.release_id = ? OR a.release_id IS NULL)
	`, projectID, releaseID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]artifact, 0)
	for rows.Next() {
		var item artifact
		if err := rows.Scan(&item.name, &item.kind, &item.debugID, &item.storageKey); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func eventFrames(payload map[string]any) []map[string]any {
	frames := make([]map[string]any, 0)
	appendFrames := func(stack any) {
		stackMap, _ := stack.(map[string]any)
		values, _ := stackMap["frames"].([]any)
		for _, value := range values {
			if frame, ok := value.(map[string]any); ok {
				frames = append(frames, frame)
			}
		}
	}
	appendValues := func(container any) {
		object, _ := container.(map[string]any)
		values, _ := object["values"].([]any)
		for _, value := range values {
			item, _ := value.(map[string]any)
			appendFrames(item["stacktrace"])
		}
	}
	if exception, ok := payload["exception"].([]any); ok {
		for _, value := range exception {
			item, _ := value.(map[string]any)
			appendFrames(item["stacktrace"])
		}
	} else {
		appendValues(payload["exception"])
	}
	appendValues(payload["threads"])
	appendFrames(payload["stacktrace"])
	return frames
}

func symbolicateJavaScriptFrame(st *store.Store, artifacts []artifact, frame map[string]any) bool {
	generated := stringValue(frame["abs_path"])
	if generated == "" {
		generated = stringValue(frame["filename"])
	}
	line, column := intValue(frame["lineno"]), intValue(frame["colno"])
	if generated == "" || line < 1 {
		return false
	}
	for _, item := range artifacts {
		if item.kind != "sourcemap" || !artifactMatches(item.name, generated) {
			continue
		}
		file, err := st.Blobs.Open(item.storageKey)
		if err != nil {
			continue
		}
		raw, readErr := io.ReadAll(io.LimitReader(file, 20<<20))
		_ = file.Close()
		if readErr != nil {
			continue
		}
		sourceMap, err := ParseSourceMap(raw)
		if err != nil {
			continue
		}
		position, ok := sourceMap.Lookup(line, column)
		if !ok {
			continue
		}
		preserveOriginal(frame)
		frame["filename"], frame["abs_path"] = position.Source, position.Source
		frame["lineno"], frame["colno"] = position.Line, position.Column
		if position.Name != "" {
			frame["function"] = position.Name
		}
		if position.Context != "" {
			frame["context_line"] = position.Context
		}
		frame["symbolicated"] = true
		return true
	}
	return false
}

func artifactMatches(artifactName, generated string) bool {
	cleanArtifact := cleanArtifactName(artifactName)
	cleanGenerated := cleanArtifactName(generated)
	return cleanArtifact == cleanGenerated+".map" || path.Base(cleanArtifact) == path.Base(cleanGenerated)+".map" || strings.TrimSuffix(cleanArtifact, ".map") == cleanGenerated
}

func cleanArtifactName(value string) string {
	value = strings.TrimSpace(value)
	if parsed, err := url.Parse(value); err == nil && parsed.Host != "" {
		value = parsed.Path
	}
	value = strings.TrimPrefix(value, "~/")
	value = strings.TrimPrefix(value, "app:///")
	return strings.TrimPrefix(path.Clean("/"+value), "/")
}

func preserveOriginal(frame map[string]any) {
	for _, key := range []string{"filename", "abs_path", "lineno", "colno", "function"} {
		if value, ok := frame[key]; ok {
			frame["original_"+key] = value
		}
	}
}

func symbolicateNativeFrame(st *store.Store, artifacts []artifact, payload map[string]any, frame map[string]any) bool {
	address, ok := parseAddress(frame["instruction_addr"])
	if !ok {
		return false
	}
	debugID, imageBase := frameDebugImage(payload, address)
	for _, item := range artifacts {
		if item.kind != "debug_file" || (debugID != "" && normalizeDebugID(item.debugID) != debugID) {
			continue
		}
		file, err := st.Blobs.Open(item.storageKey)
		if err != nil {
			continue
		}
		function, symbolAddress := lookupELFSymbol(file, address, imageBase)
		if function == "" {
			_, _ = file.Seek(0, io.SeekStart)
			function, symbolAddress = lookupBreakpadSymbol(file, address-imageBase)
		}
		_ = file.Close()
		if function == "" {
			continue
		}
		preserveOriginal(frame)
		frame["function"] = function
		frame["symbol_addr"] = fmt.Sprintf("0x%x", symbolAddress+imageBase)
		frame["symbolicated"] = true
		return true
	}
	return false
}

func frameDebugImage(payload map[string]any, address uint64) (string, uint64) {
	debugMeta, _ := payload["debug_meta"].(map[string]any)
	images, _ := debugMeta["images"].([]any)
	for _, raw := range images {
		image, _ := raw.(map[string]any)
		base, baseOK := parseAddress(image["image_addr"])
		size, _ := parseAddress(image["image_size"])
		if baseOK && address >= base && (size == 0 || address < base+size) {
			return normalizeDebugID(firstString(image, "debug_id", "code_id")), base
		}
	}
	return "", 0
}

func lookupELFSymbol(reader io.ReaderAt, address, imageBase uint64) (string, uint64) {
	file, err := elf.NewFile(reader)
	if err != nil {
		return "", 0
	}
	defer file.Close()
	symbols, err := file.Symbols()
	if err != nil {
		symbols, _ = file.DynamicSymbols()
	}
	relative := address
	if imageBase > 0 && address >= imageBase {
		relative = address - imageBase
	}
	for _, symbol := range symbols {
		if symbol.Size > 0 && relative >= symbol.Value && relative < symbol.Value+symbol.Size {
			return symbol.Name, symbol.Value
		}
	}
	return "", 0
}

func lookupBreakpadSymbol(reader io.Reader, relative uint64) (string, uint64) {
	scanner := bufio.NewScanner(io.LimitReader(reader, 100<<20))
	buffer := make([]byte, 64<<10)
	scanner.Buffer(buffer, 1<<20)
	bestName, bestAddress := "", uint64(0)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "FUNC ") && !strings.HasPrefix(line, "PUBLIC ") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		index := 1
		if fields[index] == "m" {
			index++
		}
		if len(fields) <= index+2 {
			continue
		}
		address, err := strconv.ParseUint(fields[index], 16, 64)
		if err != nil || address > relative || address < bestAddress {
			continue
		}
		nameIndex := index + 2
		if strings.HasPrefix(line, "FUNC ") {
			nameIndex = index + 3
		}
		if nameIndex >= len(fields) {
			continue
		}
		bestAddress, bestName = address, strings.Join(fields[nameIndex:], " ")
	}
	return bestName, bestAddress
}

func parseAddress(value any) (uint64, bool) {
	switch typed := value.(type) {
	case string:
		parsed, err := strconv.ParseUint(strings.TrimPrefix(strings.TrimSpace(typed), "0x"), 16, 64)
		return parsed, err == nil
	case float64:
		return uint64(typed), true
	default:
		return 0, false
	}
}

func normalizeDebugID(value string) string {
	return strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(value), "-", ""))
}

func stringValue(value any) string {
	text, _ := value.(string)
	return strings.TrimSpace(text)
}

func firstString(values map[string]any, keys ...string) string {
	for _, key := range keys {
		if value := stringValue(values[key]); value != "" {
			return value
		}
	}
	return ""
}

func intValue(value any) int {
	switch typed := value.(type) {
	case float64:
		return int(typed)
	case json.Number:
		parsed, _ := strconv.Atoi(typed.String())
		return parsed
	case string:
		parsed, _ := strconv.Atoi(typed)
		return parsed
	default:
		return 0
	}
}
