package symbolicate

import (
	"bufio"
	"context"
	"debug/dwarf"
	"debug/elf"
	"debug/macho"
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

const maxDWARFBytes uint64 = 32 << 20

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
	debugID, imageBase, imageArch := frameDebugImage(payload, address)
	for _, item := range artifacts {
		if item.kind != "debug_file" || (debugID != "" && normalizeDebugID(item.debugID) != debugID) {
			continue
		}
		file, err := st.Blobs.Open(item.storageKey)
		if err != nil {
			continue
		}
		matched := lookupELFFrame(file, address, imageBase)
		if matched.function == "" && matched.filename == "" {
			matched = lookupMachOFrame(file, address, imageBase, imageArch)
		}
		if matched.function == "" && matched.filename == "" {
			_, _ = file.Seek(0, io.SeekStart)
			matched = lookupBreakpadSymbol(file, address-imageBase)
		}
		_ = file.Close()
		if matched.function == "" && matched.filename == "" {
			continue
		}
		preserveOriginal(frame)
		if matched.function != "" {
			frame["function"] = matched.function
			frame["symbol_addr"] = fmt.Sprintf("0x%x", matched.address+imageBase)
		}
		if matched.filename != "" {
			frame["filename"], frame["abs_path"] = matched.filename, matched.filename
		}
		if matched.line > 0 {
			frame["lineno"] = matched.line
		}
		if matched.column > 0 {
			frame["colno"] = matched.column
		}
		frame["symbolicated"] = true
		return true
	}
	return false
}

func frameDebugImage(payload map[string]any, address uint64) (string, uint64, string) {
	debugMeta, _ := payload["debug_meta"].(map[string]any)
	images, _ := debugMeta["images"].([]any)
	for _, raw := range images {
		image, _ := raw.(map[string]any)
		base, baseOK := parseAddress(image["image_addr"])
		size, _ := parseAddress(image["image_size"])
		if baseOK && address >= base && (size == 0 || address-base < size) {
			return normalizeDebugID(firstString(image, "debug_id", "code_id")), base, firstString(image, "arch", "cpu_name")
		}
	}
	return "", 0, ""
}

func lookupELFFrame(reader io.ReaderAt, address, imageBase uint64) nativeSymbol {
	file, err := elf.NewFile(reader)
	if err != nil {
		return nativeSymbol{}
	}
	defer file.Close()
	preferredBase := elfPreferredBase(file)
	lookupAddress, symbolBias := address, uint64(0)
	if imageBase > 0 && address >= imageBase {
		lookupAddress = preferredBase + address - imageBase
		symbolBias = preferredBase
	}
	function, symbolAddress := lookupELFSymbol(file, lookupAddress)
	filename, line, column := lookupDWARFLine(file, lookupAddress)
	if symbolAddress >= symbolBias {
		symbolAddress -= symbolBias
	}
	return nativeSymbol{function: function, address: symbolAddress, filename: filename, line: line, column: column}
}

func elfPreferredBase(file *elf.File) uint64 {
	base := ^uint64(0)
	for _, program := range file.Progs {
		if program.Type == elf.PT_LOAD && program.Vaddr < base {
			base = program.Vaddr
		}
	}
	if base == ^uint64(0) {
		return 0
	}
	return base
}

func lookupELFSymbol(file *elf.File, relative uint64) (string, uint64) {
	symbols, err := file.Symbols()
	if err != nil {
		symbols, _ = file.DynamicSymbols()
	}
	bestName, bestAddress, bestSize := "", uint64(0), ^uint64(0)
	for _, symbol := range symbols {
		if symbol.Size == 0 || relative < symbol.Value || relative-symbol.Value >= symbol.Size {
			continue
		}
		if bestName == "" || symbol.Value > bestAddress || (symbol.Value == bestAddress && symbol.Size < bestSize) {
			bestName, bestAddress, bestSize = symbol.Name, symbol.Value, symbol.Size
		}
	}
	return bestName, bestAddress
}

func lookupDWARFLine(file *elf.File, address uint64) (string, int, int) {
	if !hasBoundedDWARF(file) {
		return "", 0, 0
	}
	data, err := file.DWARF()
	if err != nil {
		return "", 0, 0
	}
	return lookupDWARFLineData(data, address)
}

func lookupDWARFLineData(data *dwarf.Data, address uint64) (string, int, int) {
	reader := data.Reader()
	for units := 0; units < 100000; units++ {
		entry, err := reader.Next()
		if err != nil || entry == nil {
			return "", 0, 0
		}
		if entry.Tag != dwarf.TagCompileUnit {
			continue
		}
		lines, err := data.LineReader(entry)
		reader.SkipChildren()
		if err != nil || lines == nil {
			continue
		}
		var position dwarf.LineEntry
		if err := lines.SeekPC(address, &position); err != nil || position.File == nil || position.EndSequence {
			continue
		}
		return position.File.Name, position.Line, position.Column
	}
	return "", 0, 0
}

func lookupMachOFrame(reader io.ReaderAt, address, imageBase uint64, arch string) nativeSymbol {
	if file, err := macho.NewFile(reader); err == nil {
		defer file.Close()
		return lookupMachOFile(file, address, imageBase)
	}
	fat, err := macho.NewFatFile(reader)
	if err != nil {
		return nativeSymbol{}
	}
	defer fat.Close()
	fallback := nativeSymbol{}
	for _, candidate := range fat.Arches {
		matched := lookupMachOFile(candidate.File, address, imageBase)
		if matched.function == "" && matched.filename == "" {
			continue
		}
		if machoArchMatches(arch, candidate.Cpu.String()) {
			return matched
		}
		if fallback.function == "" && fallback.filename == "" {
			fallback = matched
		}
	}
	return fallback
}

func lookupMachOFile(file *macho.File, address, imageBase uint64) nativeSymbol {
	preferredBase := uint64(0)
	if text := file.Segment("__TEXT"); text != nil {
		preferredBase = text.Addr
	}
	lookupAddress, symbolBias := address, uint64(0)
	if imageBase > 0 && address >= imageBase {
		lookupAddress = preferredBase + address - imageBase
		symbolBias = preferredBase
	}
	function, symbolAddress := lookupMachOSymbol(file, lookupAddress)
	filename, line, column := lookupMachODWARFLine(file, lookupAddress)
	if symbolAddress >= symbolBias {
		symbolAddress -= symbolBias
	}
	return nativeSymbol{function: function, address: symbolAddress, filename: filename, line: line, column: column}
}

func lookupMachOSymbol(file *macho.File, address uint64) (string, uint64) {
	if file.Symtab == nil {
		return "", 0
	}
	bestIndex := -1
	for index, symbol := range file.Symtab.Syms {
		if symbol.Sect == 0 || symbol.Name == "" || symbol.Value > address {
			continue
		}
		if bestIndex < 0 || symbol.Value > file.Symtab.Syms[bestIndex].Value {
			bestIndex = index
		}
	}
	if bestIndex < 0 {
		return "", 0
	}
	best := file.Symtab.Syms[bestIndex]
	end := ^uint64(0)
	if sectionIndex := int(best.Sect) - 1; sectionIndex >= 0 && sectionIndex < len(file.Sections) {
		section := file.Sections[sectionIndex]
		if section.Size <= ^uint64(0)-section.Addr {
			end = section.Addr + section.Size
		}
	}
	for _, symbol := range file.Symtab.Syms {
		if symbol.Sect == best.Sect && symbol.Value > best.Value && symbol.Value < end {
			end = symbol.Value
		}
	}
	if address >= end {
		return "", 0
	}
	return best.Name, best.Value
}

func lookupMachODWARFLine(file *macho.File, address uint64) (string, int, int) {
	var size uint64
	found := false
	for _, section := range file.Sections {
		if section.Seg != "__DWARF" && !strings.HasPrefix(section.Name, "__debug_") && !strings.HasPrefix(section.Name, "__zdebug_") {
			continue
		}
		found = true
		if section.Size > maxDWARFBytes-size {
			return "", 0, 0
		}
		size += section.Size
	}
	if !found {
		return "", 0, 0
	}
	data, err := file.DWARF()
	if err != nil {
		return "", 0, 0
	}
	return lookupDWARFLineData(data, address)
}

func machoArchMatches(expected, actual string) bool {
	normalize := func(value string) string {
		value = strings.ToLower(value)
		value = strings.TrimPrefix(value, "cpu")
		return strings.NewReplacer("_", "", "-", "", " ", "").Replace(value)
	}
	expected, actual = normalize(expected), normalize(actual)
	if expected == "" {
		return true
	}
	if expected == "x8664" {
		expected = "amd64"
	}
	if expected == "aarch64" {
		expected = "arm64"
	}
	return expected == actual
}

func hasBoundedDWARF(file *elf.File) bool {
	var size uint64
	found := false
	for _, section := range file.Sections {
		if !strings.HasPrefix(section.Name, ".debug_") && !strings.HasPrefix(section.Name, ".zdebug_") {
			continue
		}
		found = true
		if section.Size > maxDWARFBytes-size {
			return false
		}
		size += section.Size
	}
	return found
}

type nativeSymbol struct {
	function string
	address  uint64
	filename string
	line     int
	column   int
}

func lookupBreakpadSymbol(reader io.Reader, relative uint64) nativeSymbol {
	scanner := bufio.NewScanner(io.LimitReader(reader, 100<<20))
	buffer := make([]byte, 64<<10)
	scanner.Buffer(buffer, 1<<20)
	files := make(map[int]string)
	bestFunction := nativeSymbol{}
	bestPublic := nativeSymbol{}
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
				bestFunction = nativeSymbol{function: name, address: address}
			}
			continue
		}
		if strings.HasPrefix(line, "PUBLIC ") {
			currentFunctionMatches = false
			address, name, ok := parseBreakpadPublic(line)
			if ok && address <= relative && (bestPublic.function == "" || address >= bestPublic.address) {
				bestPublic = nativeSymbol{function: name, address: address}
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
