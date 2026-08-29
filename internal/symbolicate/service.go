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
	"sort"
	"strconv"
	"strings"

	"github.com/barktrace/bark/internal/store"
)

type artifact struct {
	name, kind, debugID, dist, releaseID, storageKey string
}

type cachedSourceMap struct {
	value *SourceMap
	err   error
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
	sourceMaps := make(map[string]cachedSourceMap)
	dist := stringValue(payload["dist"])
	for _, frame := range eventFrames(payload) {
		if symbolicateJavaScriptFrame(st, artifacts, payload, dist, frame, sourceMaps) || symbolicateNativeFrame(st, artifacts, payload, frame) {
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
		SELECT a.name, a.artifact_type, a.debug_id, a.dist, COALESCE(a.release_id, ''), b.storage_key
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
		if err := rows.Scan(&item.name, &item.kind, &item.debugID, &item.dist, &item.releaseID, &item.storageKey); err != nil {
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

func symbolicateJavaScriptFrame(st *store.Store, artifacts []artifact, payload map[string]any, eventDist string, frame map[string]any, cache map[string]cachedSourceMap) bool {
	generated := stringValue(frame["abs_path"])
	if generated == "" {
		generated = stringValue(frame["filename"])
	}
	line, column := intValue(frame["lineno"]), intValue(frame["colno"])
	if generated == "" || line < 1 {
		return false
	}
	debugID := javascriptDebugID(payload, frame, generated)
	candidates := make([]artifact, 0)
	scores := make(map[string]int)
	for _, item := range artifacts {
		score := javascriptArtifactScore(item, generated, debugID, eventDist)
		if score < 0 {
			continue
		}
		candidates = append(candidates, item)
		scores[item.storageKey] = score
	}
	sort.SliceStable(candidates, func(left, right int) bool {
		return scores[candidates[left].storageKey] > scores[candidates[right].storageKey]
	})
	for _, item := range candidates {
		cached, found := cache[item.storageKey]
		if !found {
			file, err := st.Blobs.Open(item.storageKey)
			if err != nil {
				cache[item.storageKey] = cachedSourceMap{err: err}
				continue
			}
			raw, readErr := io.ReadAll(io.LimitReader(file, 20<<20))
			_ = file.Close()
			if readErr != nil {
				cache[item.storageKey] = cachedSourceMap{err: readErr}
				continue
			}
			cached.value, cached.err = ParseSourceMap(raw)
			cache[item.storageKey] = cached
		}
		if cached.err != nil || cached.value == nil {
			continue
		}
		position, ok := cached.value.Lookup(line, column)
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

func javascriptArtifactScore(item artifact, generated, debugID, eventDist string) int {
	if item.kind != "sourcemap" {
		return -1
	}
	if eventDist == "" && item.dist != "" {
		return -1
	}
	if eventDist != "" && item.dist != "" && item.dist != eventDist {
		return -1
	}
	score := 0
	if debugID != "" && item.debugID != "" {
		if normalizeDebugID(item.debugID) != debugID {
			return -1
		}
		score += 100
	}
	nameScore := artifactMatchScore(item.name, generated)
	if score == 0 && nameScore == 0 {
		return -1
	}
	score += nameScore
	if item.releaseID != "" {
		score += 4
	}
	if eventDist != "" && item.dist == eventDist {
		score += 2
	}
	return score
}

func javascriptDebugID(payload, frame map[string]any, generated string) string {
	if value := normalizeDebugID(firstString(frame, "debug_id", "debugId")); value != "" {
		return value
	}
	debugMeta, _ := payload["debug_meta"].(map[string]any)
	images, _ := debugMeta["images"].([]any)
	for _, raw := range images {
		image, _ := raw.(map[string]any)
		codeFile := firstString(image, "code_file", "name")
		imageType := strings.ToLower(firstString(image, "type"))
		matchesCodeFile := codeFile != "" && (cleanArtifactName(codeFile) == cleanArtifactName(generated) || path.Base(cleanArtifactName(codeFile)) == path.Base(cleanArtifactName(generated)))
		if matchesCodeFile || (codeFile == "" && imageType == "sourcemap") {
			if value := normalizeDebugID(firstString(image, "debug_id", "debugId")); value != "" {
				return value
			}
		}
	}
	return ""
}

func artifactMatchScore(artifactName, generated string) int {
	cleanArtifact := cleanArtifactName(artifactName)
	cleanGenerated := cleanArtifactName(generated)
	if cleanArtifact == cleanGenerated+".map" || strings.TrimSuffix(cleanArtifact, ".map") == cleanGenerated {
		return 20
	}
	if path.Base(cleanArtifact) == path.Base(cleanGenerated)+".map" {
		return 10
	}
	return 0
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
		sourceFile, sourceLine := "", 0
		if function == "" {
			_, _ = file.Seek(0, io.SeekStart)
			matched := lookupBreakpadSymbol(file, address-imageBase)
			function, symbolAddress = matched.function, matched.address
			sourceFile, sourceLine = matched.filename, matched.line
		}
		_ = file.Close()
		if function == "" {
			continue
		}
		preserveOriginal(frame)
		frame["function"] = function
		frame["symbol_addr"] = fmt.Sprintf("0x%x", symbolAddress+imageBase)
		if sourceFile != "" {
			frame["filename"], frame["abs_path"] = sourceFile, sourceFile
		}
		if sourceLine > 0 {
			frame["lineno"] = sourceLine
		}
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

type breakpadSymbol struct {
	function string
	address  uint64
	filename string
	line     int
}

func lookupBreakpadSymbol(reader io.Reader, relative uint64) breakpadSymbol {
	scanner := bufio.NewScanner(io.LimitReader(reader, 100<<20))
	buffer := make([]byte, 64<<10)
	scanner.Buffer(buffer, 1<<20)
	files := make(map[int]string)
	bestFunction := breakpadSymbol{}
	bestPublic := breakpadSymbol{}
	currentFunctionMatches := false
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "FILE ") {
			fields := strings.SplitN(strings.TrimSpace(strings.TrimPrefix(line, "FILE ")), " ", 2)
			if len(fields) == 2 {
				if id, err := strconv.Atoi(fields[0]); err == nil && id >= 0 {
					files[id] = strings.TrimSpace(fields[1])
				}
			}
			currentFunctionMatches = false
			continue
		}
		if strings.HasPrefix(line, "FUNC ") {
			address, size, name, ok := parseBreakpadFunction(line)
			currentFunctionMatches = ok && size > 0 && relative >= address && relative-address < size
			if currentFunctionMatches && (bestFunction.function == "" || address >= bestFunction.address) {
				bestFunction = breakpadSymbol{function: name, address: address}
			}
			continue
		}
		if strings.HasPrefix(line, "PUBLIC ") {
			currentFunctionMatches = false
			address, name, ok := parseBreakpadPublic(line)
			if ok && address <= relative && (bestPublic.function == "" || address >= bestPublic.address) {
				bestPublic = breakpadSymbol{function: name, address: address}
			}
			continue
		}
		if !currentFunctionMatches {
			continue
		}
		address, size, sourceLine, fileID, ok := parseBreakpadLine(line)
		if !ok || size == 0 || relative < address || relative-address >= size {
			continue
		}
		if sourceLine > 0 && address >= bestFunction.address {
			bestFunction.line = sourceLine
			bestFunction.filename = files[fileID]
		}
	}
	if bestFunction.function != "" {
		return bestFunction
	}
	return bestPublic
}

func parseBreakpadFunction(line string) (uint64, uint64, string, bool) {
	fields := strings.Fields(line)
	index := 1
	if len(fields) > index && fields[index] == "m" {
		index++
	}
	if len(fields) <= index+3 {
		return 0, 0, "", false
	}
	address, addressErr := strconv.ParseUint(fields[index], 16, 64)
	size, sizeErr := strconv.ParseUint(fields[index+1], 16, 64)
	name := strings.Join(fields[index+3:], " ")
	return address, size, name, addressErr == nil && sizeErr == nil && name != ""
}

func parseBreakpadPublic(line string) (uint64, string, bool) {
	fields := strings.Fields(line)
	index := 1
	if len(fields) > index && fields[index] == "m" {
		index++
	}
	if len(fields) <= index+2 {
		return 0, "", false
	}
	address, err := strconv.ParseUint(fields[index], 16, 64)
	name := strings.Join(fields[index+2:], " ")
	return address, name, err == nil && name != ""
}

func parseBreakpadLine(line string) (uint64, uint64, int, int, bool) {
	fields := strings.Fields(line)
	if len(fields) != 4 {
		return 0, 0, 0, 0, false
	}
	address, addressErr := strconv.ParseUint(fields[0], 16, 64)
	size, sizeErr := strconv.ParseUint(fields[1], 16, 64)
	sourceLine, lineErr := strconv.Atoi(fields[2])
	fileID, fileErr := strconv.Atoi(fields[3])
	if addressErr != nil || sizeErr != nil || lineErr != nil || fileErr != nil || sourceLine < 0 || fileID < 0 {
		return 0, 0, 0, 0, false
	}
	return address, size, sourceLine, fileID, true
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
