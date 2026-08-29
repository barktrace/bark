package symbolicate

import (
	"bufio"
	"context"
	"debug/dwarf"
	"debug/elf"
	"debug/macho"
	"debug/pe"
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

type cachedProguardMap struct {
	value *ProguardMap
	err   error
}

type cachedPDBSymbols struct {
	value *pdbSymbols
	err   error
}

const maxDWARFBytes uint64 = 32 << 20
const maxNativeInlineDepth = 512

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
	proguardMaps := make(map[string]cachedProguardMap)
	pdbFiles := make(map[string]cachedPDBSymbols)
	dist := stringValue(payload["dist"])
	for _, stack := range eventStacks(payload) {
		values, _ := stack["frames"].([]any)
		expanded := make([]any, 0, len(values))
		for _, value := range values {
			frame, ok := value.(map[string]any)
			if !ok {
				expanded = append(expanded, value)
				continue
			}
			var inlineFrames []map[string]any
			frameChanged := symbolicateJavaScriptFrame(st, artifacts, payload, dist, frame, sourceMaps)
			if !frameChanged {
				frameChanged, inlineFrames = symbolicateProguardFrame(st, artifacts, payload, frame, proguardMaps)
			}
			if !frameChanged {
				frameChanged, inlineFrames = symbolicateNativeFrame(st, artifacts, payload, frame, pdbFiles)
			}
			if frameChanged {
				changed = true
			}
			if len(inlineFrames) == 0 {
				expanded = append(expanded, frame)
				continue
			}
			for _, inlineFrame := range inlineFrames {
				expanded = append(expanded, inlineFrame)
			}
		}
		if len(expanded) != len(values) {
			stack["frames"] = expanded
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

func eventStacks(payload map[string]any) []map[string]any {
	stacks := make([]map[string]any, 0)
	appendFrames := func(stack any) {
		stackMap, _ := stack.(map[string]any)
		if _, ok := stackMap["frames"].([]any); ok {
			stacks = append(stacks, stackMap)
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
	return stacks
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
	for _, key := range []string{"filename", "abs_path", "lineno", "colno", "function", "module", "package"} {
		if value, ok := frame[key]; ok {
			frame["original_"+key] = value
		}
	}
}

func symbolicateNativeFrame(st *store.Store, artifacts []artifact, payload map[string]any, frame map[string]any, pdbCache map[string]cachedPDBSymbols) (bool, []map[string]any) {
	address, ok := parseAddress(frame["instruction_addr"])
	if !ok {
		return false, nil
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
			matched = lookupPEFrame(file, address, imageBase)
		}
		if matched.function == "" && matched.filename == "" {
			cached, found := pdbCache[item.storageKey]
			if !found {
				cached.value, cached.err = parsePDBSymbols(file)
				pdbCache[item.storageKey] = cached
			}
			if cached.err == nil {
				matched = lookupPDBSymbols(cached.value, address, imageBase)
			}
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
		if len(matched.inlines) > 0 {
			return true, expandNativeInlineFrames(frame, matched, imageBase)
		}
		return true, nil
	}
	return false, nil
}

func expandNativeInlineFrames(frame map[string]any, matched nativeSymbol, imageBase uint64) []map[string]any {
	frames := make([]map[string]any, 0, len(matched.inlines)+1)
	physical := cloneFrame(frame)
	setNativeSource(physical, matched.inlines[0].filename, matched.inlines[0].line, 0)
	frames = append(frames, physical)
	for index, inline := range matched.inlines {
		expanded := cloneFrame(frame)
		expanded["function"] = inline.function
		expanded["symbol_addr"] = fmt.Sprintf("0x%x", inline.address+imageBase)
		expanded["inline"] = true
		if index+1 < len(matched.inlines) {
			next := matched.inlines[index+1]
			setNativeSource(expanded, next.filename, next.line, 0)
		} else {
			setNativeSource(expanded, matched.filename, matched.line, matched.column)
		}
		frames = append(frames, expanded)
	}
	return frames
}

func cloneFrame(frame map[string]any) map[string]any {
	cloned := make(map[string]any, len(frame)+1)
	for key, value := range frame {
		cloned[key] = value
	}
	return cloned
}

func setNativeSource(frame map[string]any, filename string, line, column int) {
	if filename != "" {
		frame["filename"], frame["abs_path"] = filename, filename
		if line == 0 {
			delete(frame, "lineno")
		}
	}
	if line > 0 {
		frame["lineno"] = line
	}
	if column > 0 {
		frame["colno"] = column
	} else {
		delete(frame, "colno")
	}
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
	filename, line, column, inlines := lookupDWARFFrame(file, lookupAddress)
	if symbolAddress >= symbolBias {
		symbolAddress -= symbolBias
	}
	return nativeSymbol{function: function, address: symbolAddress, filename: filename, line: line, column: column, inlines: inlines}
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

func lookupDWARFFrame(file *elf.File, address uint64) (string, int, int, []nativeInline) {
	if !hasBoundedDWARF(file) {
		return "", 0, 0, nil
	}
	data, err := file.DWARF()
	if err != nil {
		return "", 0, 0, nil
	}
	filename, line, column := lookupDWARFLineData(data, address)
	return filename, line, column, lookupDWARFInlines(data, address)
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

func lookupDWARFInlines(data *dwarf.Data, address uint64) []nativeInline {
	reader := data.Reader()
	depth := 0
	files := []*dwarf.LineFile(nil)
	type inlineCandidate struct {
		depth int
		value nativeInline
	}
	candidates := make(map[int]inlineCandidate)
	for entries := 0; entries < 1000000; entries++ {
		entry, err := reader.Next()
		if err != nil || entry == nil {
			break
		}
		if entry.Tag == 0 {
			if depth > 0 {
				depth--
			}
			continue
		}
		entryDepth := depth
		if entry.Tag == dwarf.TagCompileUnit {
			ranges, rangeErr := data.Ranges(entry)
			if rangeErr == nil && len(ranges) > 0 && !dwarfRangesContain(ranges, address) {
				reader.SkipChildren()
				continue
			}
			files = nil
			if lines, lineErr := data.LineReader(entry); lineErr == nil && lines != nil {
				files = lines.Files()
			}
		}
		if entry.Tag == dwarf.TagInlinedSubroutine {
			start, size, ok := matchingDWARFRange(data, entry, address)
			if ok {
				name := dwarfEntryName(data, entry)
				if name != "" {
					callFile := dwarfFileName(files, dwarfIntValue(entry.Val(dwarf.AttrCallFile)))
					candidate := inlineCandidate{depth: entryDepth, value: nativeInline{
						function: name, filename: callFile, line: dwarfIntValue(entry.Val(dwarf.AttrCallLine)), address: start, rangeSize: size,
					}}
					previous, found := candidates[entryDepth]
					if !found || candidate.value.rangeSize < previous.value.rangeSize {
						candidates[entryDepth] = candidate
					}
				}
			}
		}
		if entry.Children {
			depth++
		}
	}
	ordered := make([]inlineCandidate, 0, len(candidates))
	for _, candidate := range candidates {
		ordered = append(ordered, candidate)
	}
	sort.Slice(ordered, func(left, right int) bool { return ordered[left].depth < ordered[right].depth })
	if len(ordered) > maxNativeInlineDepth {
		ordered = ordered[:maxNativeInlineDepth]
	}
	inlines := make([]nativeInline, 0, len(ordered))
	for level, candidate := range ordered {
		candidate.value.level = level
		inlines = append(inlines, candidate.value)
	}
	return inlines
}

func dwarfRangesContain(ranges [][2]uint64, address uint64) bool {
	for _, item := range ranges {
		if item[1] > item[0] && address >= item[0] && address < item[1] {
			return true
		}
	}
	return false
}

func matchingDWARFRange(data *dwarf.Data, entry *dwarf.Entry, address uint64) (uint64, uint64, bool) {
	ranges, err := data.Ranges(entry)
	if err != nil || len(ranges) > 1000000 {
		return 0, 0, false
	}
	bestStart, bestSize := uint64(0), ^uint64(0)
	for _, item := range ranges {
		if item[1] <= item[0] || address < item[0] || address >= item[1] || item[1]-item[0] >= bestSize {
			continue
		}
		bestStart, bestSize = item[0], item[1]-item[0]
	}
	if bestSize == ^uint64(0) {
		return 0, 0, false
	}
	return bestStart, bestSize, true
}

func dwarfEntryName(data *dwarf.Data, entry *dwarf.Entry) string {
	for references := 0; entry != nil && references < 8; references++ {
		if name, ok := entry.Val(dwarf.AttrName).(string); ok && strings.TrimSpace(name) != "" {
			return strings.TrimSpace(name)
		}
		var offset dwarf.Offset
		var found bool
		for _, attribute := range []dwarf.Attr{dwarf.AttrAbstractOrigin, dwarf.AttrSpecification} {
			if value, ok := entry.Val(attribute).(dwarf.Offset); ok {
				offset, found = value, true
				break
			}
		}
		if !found {
			break
		}
		reader := data.Reader()
		reader.Seek(offset)
		entry, _ = reader.Next()
	}
	return ""
}

func dwarfIntValue(value any) int {
	switch typed := value.(type) {
	case int64:
		if typed >= 0 && uint64(typed) <= uint64(^uint(0)>>1) {
			return int(typed)
		}
	case uint64:
		if typed <= uint64(^uint(0)>>1) {
			return int(typed)
		}
	}
	return 0
}

func dwarfFileName(files []*dwarf.LineFile, index int) string {
	if index <= 0 || index >= len(files) || files[index] == nil {
		return ""
	}
	return files[index].Name
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
	filename, line, column, inlines := lookupMachODWARFFrame(file, lookupAddress)
	if symbolAddress >= symbolBias {
		symbolAddress -= symbolBias
	}
	return nativeSymbol{function: function, address: symbolAddress, filename: filename, line: line, column: column, inlines: inlines}
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

func lookupMachODWARFFrame(file *macho.File, address uint64) (string, int, int, []nativeInline) {
	var size uint64
	found := false
	for _, section := range file.Sections {
		if section.Seg != "__DWARF" && !strings.HasPrefix(section.Name, "__debug_") && !strings.HasPrefix(section.Name, "__zdebug_") {
			continue
		}
		found = true
		if section.Size > maxDWARFBytes-size {
			return "", 0, 0, nil
		}
		size += section.Size
	}
	if !found {
		return "", 0, 0, nil
	}
	data, err := file.DWARF()
	if err != nil {
		return "", 0, 0, nil
	}
	filename, line, column := lookupDWARFLineData(data, address)
	return filename, line, column, lookupDWARFInlines(data, address)
}

func machoArchMatches(expected, actual string) bool {
	normalize := func(value string) string {
		value = strings.ToLower(value)
		value = strings.TrimPrefix(value, "cpu")
		value = strings.NewReplacer("_", "", "-", "", " ", "").Replace(value)
		switch value {
		case "x8664":
			return "amd64"
		case "aarch64":
			return "arm64"
		default:
			return value
		}
	}
	expected, actual = normalize(expected), normalize(actual)
	if expected == "" {
		return true
	}
	return expected == actual
}

func lookupPEFrame(reader io.ReaderAt, address, imageBase uint64) nativeSymbol {
	file, err := pe.NewFile(reader)
	if err != nil {
		return nativeSymbol{}
	}
	defer file.Close()
	preferredBase := peImageBase(file)
	lookupRVA := address
	returnBias := uint64(0)
	switch {
	case imageBase > 0 && address >= imageBase:
		lookupRVA = address - imageBase
	case preferredBase > 0 && address >= preferredBase:
		lookupRVA = address - preferredBase
		returnBias = preferredBase
	}
	function, symbolRVA := lookupPESymbol(file, lookupRVA)
	filename, line, column, inlines := lookupPEDWARFFrame(file, preferredBase+lookupRVA)
	if filename == "" && len(inlines) == 0 {
		filename, line, column, inlines = lookupPEDWARFFrame(file, lookupRVA)
	}
	return nativeSymbol{function: function, address: returnBias + symbolRVA, filename: filename, line: line, column: column, inlines: inlines}
}

func peImageBase(file *pe.File) uint64 {
	switch header := file.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		return uint64(header.ImageBase)
	case *pe.OptionalHeader64:
		return header.ImageBase
	default:
		return 0
	}
}

func lookupPESymbol(file *pe.File, addressRVA uint64) (string, uint64) {
	bestIndex := -1
	bestRVA := uint64(0)
	for index, symbol := range file.Symbols {
		sectionIndex := int(symbol.SectionNumber) - 1
		if symbol.Name == "" || sectionIndex < 0 || sectionIndex >= len(file.Sections) {
			continue
		}
		symbolRVA := uint64(file.Sections[sectionIndex].VirtualAddress) + uint64(symbol.Value)
		if symbolRVA > addressRVA || (bestIndex >= 0 && symbolRVA <= bestRVA) {
			continue
		}
		bestIndex, bestRVA = index, symbolRVA
	}
	if bestIndex < 0 {
		return "", 0
	}
	best := file.Symbols[bestIndex]
	sectionIndex := int(best.SectionNumber) - 1
	section := file.Sections[sectionIndex]
	sectionSize := uint64(max(section.VirtualSize, section.Size))
	end := uint64(section.VirtualAddress) + sectionSize
	for _, symbol := range file.Symbols {
		if symbol.SectionNumber != best.SectionNumber || symbol.Value <= best.Value {
			continue
		}
		nextRVA := uint64(section.VirtualAddress) + uint64(symbol.Value)
		if nextRVA < end {
			end = nextRVA
		}
	}
	if addressRVA >= end {
		return "", 0
	}
	return best.Name, bestRVA
}

func lookupPEDWARFFrame(file *pe.File, address uint64) (string, int, int, []nativeInline) {
	var size uint64
	found := false
	for _, section := range file.Sections {
		if !strings.HasPrefix(section.Name, ".debug_") && !strings.HasPrefix(section.Name, ".zdebug_") {
			continue
		}
		found = true
		if uint64(section.Size) > maxDWARFBytes-size {
			return "", 0, 0, nil
		}
		size += uint64(section.Size)
	}
	if !found {
		return "", 0, 0, nil
	}
	data, err := file.DWARF()
	if err != nil {
		return "", 0, 0, nil
	}
	filename, line, column := lookupDWARFLineData(data, address)
	return filename, line, column, lookupDWARFInlines(data, address)
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
	inlines  []nativeInline
}

type nativeInline struct {
	function           string
	filename           string
	line, level        int
	originID, fileID   int
	address, rangeSize uint64
}

func lookupBreakpadSymbol(reader io.Reader, relative uint64) nativeSymbol {
	scanner := bufio.NewScanner(io.LimitReader(reader, 100<<20))
	buffer := make([]byte, 64<<10)
	scanner.Buffer(buffer, 1<<20)
	files := make(map[int]string)
	origins := make(map[int]string)
	inlineMatches := make(map[int]nativeInline)
	bestFunction := nativeSymbol{}
	bestPublic := nativeSymbol{}
	currentFunctionMatches := false
	currentFunctionAddress := uint64(0)
	for records := 0; records < 1000000 && scanner.Scan(); records++ {
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
		if strings.HasPrefix(line, "INLINE_ORIGIN ") {
			id, name, ok := parseBreakpadInlineOrigin(line)
			if ok {
				origins[id] = name
			}
			continue
		}
		if strings.HasPrefix(line, "FUNC ") {
			address, size, name, ok := parseBreakpadFunction(line)
			currentFunctionMatches = ok && size > 0 && relative >= address && relative-address < size
			currentFunctionAddress = address
			if currentFunctionMatches && (bestFunction.function == "" || address >= bestFunction.address) {
				if bestFunction.function == "" || address > bestFunction.address {
					inlineMatches = make(map[int]nativeInline)
				}
				bestFunction = nativeSymbol{function: name, address: address}
			}
			continue
		}
		if strings.HasPrefix(line, "INLINE ") {
			if currentFunctionMatches && currentFunctionAddress == bestFunction.address {
				if inline, ok := parseBreakpadInline(line, relative); ok {
					if inline.level >= maxNativeInlineDepth {
						continue
					}
					previous, found := inlineMatches[inline.level]
					if !found || inline.rangeSize < previous.rangeSize {
						inlineMatches[inline.level] = inline
					}
				}
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
		if !currentFunctionMatches || currentFunctionAddress != bestFunction.address {
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
		for level := 0; ; level++ {
			inline, ok := inlineMatches[level]
			if !ok {
				break
			}
			inline.function = origins[inline.originID]
			inline.filename = files[inline.fileID]
			if inline.function == "" {
				break
			}
			bestFunction.inlines = append(bestFunction.inlines, inline)
		}
		return bestFunction
	}
	return bestPublic
}

func parseBreakpadInlineOrigin(line string) (int, string, bool) {
	fields := strings.SplitN(strings.TrimSpace(strings.TrimPrefix(line, "INLINE_ORIGIN ")), " ", 2)
	if len(fields) != 2 {
		return 0, "", false
	}
	id, err := strconv.Atoi(fields[0])
	name := strings.TrimSpace(fields[1])
	return id, name, err == nil && id >= 0 && name != ""
}

func parseBreakpadInline(line string, relative uint64) (nativeInline, bool) {
	fields := strings.Fields(line)
	if len(fields) < 7 || (len(fields)-5)%2 != 0 {
		return nativeInline{}, false
	}
	level, levelErr := strconv.Atoi(fields[1])
	callLine, lineErr := strconv.Atoi(fields[2])
	fileID, fileErr := strconv.Atoi(fields[3])
	originID, originErr := strconv.Atoi(fields[4])
	if levelErr != nil || lineErr != nil || fileErr != nil || originErr != nil || level < 0 || callLine < 0 || fileID < 0 || originID < 0 {
		return nativeInline{}, false
	}
	matchedAddress, matchedSize := uint64(0), ^uint64(0)
	for index := 5; index+1 < len(fields); index += 2 {
		address, addressErr := strconv.ParseUint(fields[index], 16, 64)
		size, sizeErr := strconv.ParseUint(fields[index+1], 16, 64)
		if addressErr == nil && sizeErr == nil && size > 0 && relative >= address && relative-address < size && size < matchedSize {
			matchedAddress = address
			matchedSize = size
		}
	}
	if matchedSize == ^uint64(0) {
		return nativeInline{}, false
	}
	return nativeInline{level: level, line: callLine, fileID: fileID, originID: originID, address: matchedAddress, rangeSize: matchedSize}, true
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
