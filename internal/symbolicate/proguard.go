package symbolicate

import (
	"bufio"
	"encoding/json"
	"errors"
	"io"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/barktrace/bark/internal/store"
)

const (
	maxProguardBytes       = 20 << 20
	maxProguardMappings    = 1000000
	maxProguardInlineDepth = 512
)

var proguardMethodPattern = regexp.MustCompile(`^(?:(\d+):(\d+):)?\S+\s+([^\s(]+)\([^)]*\)(?::(\d+)(?::(\d+))?)?$`)

type ProguardMap struct {
	classes     map[string]*proguardClass
	sourceFiles map[string]string
}

type proguardClass struct {
	original, sourceFile string
	methods              map[string][]proguardMethod
}

type proguardMethod struct {
	originalClass, original             string
	obfuscatedStart, obfuscatedEnd      int
	originalStart, originalEnd          int
	hasObfuscatedRange, hasOriginalLine bool
}

type proguardPosition struct {
	class, method, filename string
	line                    int
	hasLine                 bool
}

func ParseProguardMap(reader io.Reader) (*ProguardMap, error) {
	return parseProguardMap(reader, maxProguardBytes)
}

func parseProguardMap(reader io.Reader, byteLimit int64) (*ProguardMap, error) {
	parsed := &ProguardMap{classes: make(map[string]*proguardClass), sourceFiles: make(map[string]string)}
	limited := &io.LimitedReader{R: reader, N: byteLimit + 1}
	scanner := bufio.NewScanner(limited)
	scanner.Buffer(make([]byte, 64<<10), 1<<20)
	var current *proguardClass
	mappings := 0
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if strings.HasPrefix(trimmed, "#") {
			if current != nil {
				if filename := proguardSourceFile(trimmed); filename != "" {
					current.sourceFile = filename
					parsed.sourceFiles[current.original] = filename
				}
			}
			continue
		}
		if line[0] != ' ' && line[0] != '\t' {
			left, right, ok := strings.Cut(line, " -> ")
			obfuscated := strings.TrimSuffix(strings.TrimSpace(right), ":")
			if !ok || strings.TrimSpace(left) == "" || obfuscated == "" {
				current = nil
				continue
			}
			current = &proguardClass{original: strings.TrimSpace(left), methods: make(map[string][]proguardMethod)}
			parsed.classes[obfuscated] = current
			mappings++
		} else if current != nil {
			left, obfuscated, ok := strings.Cut(strings.TrimSpace(line), " -> ")
			if !ok || strings.TrimSpace(obfuscated) == "" {
				continue
			}
			match := proguardMethodPattern.FindStringSubmatch(left)
			if match == nil {
				continue
			}
			owner, name := splitProguardMethod(match[3])
			method := proguardMethod{originalClass: owner, original: name, hasObfuscatedRange: match[1] != "", hasOriginalLine: match[4] != ""}
			var parseErr error
			if method.hasObfuscatedRange {
				method.obfuscatedStart, parseErr = strconv.Atoi(match[1])
				if parseErr == nil {
					method.obfuscatedEnd, parseErr = strconv.Atoi(match[2])
				}
				if parseErr != nil || method.obfuscatedEnd < method.obfuscatedStart {
					continue
				}
			}
			if method.hasOriginalLine {
				method.originalStart, parseErr = strconv.Atoi(match[4])
				if parseErr == nil && match[5] != "" {
					method.originalEnd, parseErr = strconv.Atoi(match[5])
				}
				if parseErr != nil || (match[5] != "" && method.originalEnd < method.originalStart) {
					continue
				}
			}
			current.methods[strings.TrimSpace(obfuscated)] = append(current.methods[strings.TrimSpace(obfuscated)], method)
			mappings++
		}
		if mappings > maxProguardMappings {
			return nil, errors.New("ProGuard mapping contains too many entries")
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if limited.N == 0 {
		return nil, errors.New("ProGuard mapping exceeds size limit")
	}
	if len(parsed.classes) == 0 {
		return nil, errors.New("ProGuard mapping contains no classes")
	}
	return parsed, nil
}

func (p *ProguardMap) Lookup(class, method string, line int) (proguardPosition, bool) {
	positions, ok := p.LookupFrames(class, method, line)
	if !ok || len(positions) == 0 {
		return proguardPosition{}, false
	}
	return positions[0], true
}

// LookupFrames returns an R8 inline group in printed Java stack-trace order:
// the innermost callee first and the physical caller last. Callers storing
// Sentry frames must reverse a multi-frame result because Sentry stacks are
// ordered from oldest to newest.
func (p *ProguardMap) LookupFrames(class, method string, line int) ([]proguardPosition, bool) {
	mapped, ok := p.classes[class]
	if !ok {
		return nil, false
	}
	candidates := mapped.methods[method]
	if len(candidates) == 0 {
		return []proguardPosition{{class: mapped.original, method: method, filename: p.filename(mapped.original, mapped.sourceFile), line: line, hasLine: line > 0}}, true
	}

	if line > 0 {
		hasLineMappings := false
		for _, candidate := range candidates {
			if candidate.hasObfuscatedRange && candidate.obfuscatedEnd > 0 {
				hasLineMappings = true
				break
			}
		}
		if hasLineMappings {
			groups := make([][]proguardMethod, 0, 1)
			var fallback *proguardMethod
			for start := 0; start < len(candidates); {
				end := start + 1
				for end < len(candidates) && sameProguardRange(candidates[start], candidates[end]) {
					end++
				}
				candidate := candidates[start]
				if candidate.hasObfuscatedRange && line >= candidate.obfuscatedStart && line <= candidate.obfuscatedEnd {
					if end-start > 1 {
						groups = append(groups, candidates[start:end])
					} else if fallback == nil {
						fallback = &candidates[start]
					}
				}
				start = end
			}
			if len(groups) > 0 {
				positions := make([]proguardPosition, 0)
				for _, group := range groups {
					positions = p.appendInlineGroup(positions, mapped, group, line)
					if len(positions) == maxProguardInlineDepth {
						return positions, true
					}
				}
				return positions, true
			}
			if fallback != nil {
				return []proguardPosition{p.position(mapped, *fallback, line)}, true
			}
			return []proguardPosition{{class: mapped.original, method: method, filename: p.filename(mapped.original, mapped.sourceFile), line: line, hasLine: true}}, true
		}
	}

	// With no usable input line, base mappings take precedence over ranged
	// mappings. Bare ambiguous mappings are alternatives, not callers.
	for _, candidate := range candidates {
		if !candidate.hasObfuscatedRange || candidate.obfuscatedEnd == 0 {
			return []proguardPosition{p.position(mapped, candidate, line)}, true
		}
	}
	// When no base mapping exists, an explicit repeated range establishes the
	// only safe inline chain. This mirrors R8's missing-line fallback.
	for start := 0; start < len(candidates); {
		end := start + 1
		for end < len(candidates) && sameProguardRange(candidates[start], candidates[end]) {
			end++
		}
		if candidates[start].hasObfuscatedRange && end-start > 1 {
			positions := make([]proguardPosition, 0, min(end-start, maxProguardInlineDepth))
			positions = p.appendInlineGroup(positions, mapped, candidates[start:end], line)
			return positions, true
		}
		start = end
	}
	return []proguardPosition{p.position(mapped, candidates[0], line)}, true
}

func (p *ProguardMap) appendInlineGroup(positions []proguardPosition, mapped *proguardClass, group []proguardMethod, line int) []proguardPosition {
	remaining := maxProguardInlineDepth - len(positions)
	if remaining <= 0 || len(group) == 0 {
		return positions
	}
	if len(group) <= remaining {
		for _, candidate := range group {
			positions = append(positions, p.position(mapped, candidate, line))
		}
		return positions
	}
	// Keep both ends of a truncated group: the first entry is the innermost
	// failure and the last entry is the real physical caller.
	if remaining == 1 {
		return append(positions, p.position(mapped, group[len(group)-1], line))
	}
	for _, candidate := range group[:remaining-1] {
		positions = append(positions, p.position(mapped, candidate, line))
	}
	return append(positions, p.position(mapped, group[len(group)-1], line))
}

func (p *ProguardMap) position(mapped *proguardClass, candidate proguardMethod, line int) proguardPosition {
	class := mapped.original
	if candidate.originalClass != "" {
		class = candidate.originalClass
	}
	position := proguardPosition{class: class, method: candidate.original, filename: p.filename(class, mapped.sourceFile), line: line, hasLine: line > 0}
	if candidate.hasOriginalLine {
		position.line, position.hasLine = candidate.originalStart, true
		if candidate.originalEnd > candidate.originalStart && candidate.hasObfuscatedRange {
			position.line += line - candidate.obfuscatedStart
			if position.line > candidate.originalEnd {
				position.line = candidate.originalEnd
			}
		}
	}
	return position
}

func (p *ProguardMap) filename(class, reference string) string {
	if filename := p.sourceFiles[class]; filename != "" {
		return filename
	}
	return synthesizeProguardFilename(class, reference)
}

func sameProguardRange(left, right proguardMethod) bool {
	return left.hasObfuscatedRange && right.hasObfuscatedRange && left.obfuscatedStart == right.obfuscatedStart && left.obfuscatedEnd == right.obfuscatedEnd
}

func symbolicateProguardFrame(st *store.Store, artifacts []artifact, payload map[string]any, frame map[string]any, cache map[string]cachedProguardMap) (bool, []map[string]any) {
	class, method := proguardFrameName(frame)
	if class == "" {
		return false, nil
	}
	debugID := proguardDebugID(payload)
	candidates := make([]artifact, 0)
	for _, item := range artifacts {
		if item.kind != "proguard" || (debugID != "" && normalizeDebugID(item.debugID) != debugID) {
			continue
		}
		candidates = append(candidates, item)
	}
	sort.SliceStable(candidates, func(left, right int) bool {
		leftDebug := debugID != "" && normalizeDebugID(candidates[left].debugID) == debugID
		rightDebug := debugID != "" && normalizeDebugID(candidates[right].debugID) == debugID
		if leftDebug != rightDebug {
			return leftDebug
		}
		return candidates[left].releaseID != "" && candidates[right].releaseID == ""
	})
	for _, item := range candidates {
		cached, found := cache[item.storageKey]
		if !found {
			file, err := st.Blobs.Open(item.storageKey)
			if err != nil {
				cache[item.storageKey] = cachedProguardMap{err: err}
				continue
			}
			cached.value, cached.err = ParseProguardMap(file)
			_ = file.Close()
			cache[item.storageKey] = cached
		}
		if cached.err != nil || cached.value == nil {
			continue
		}
		positions, ok := cached.value.LookupFrames(class, method, intValue(frame["lineno"]))
		if !ok || len(positions) == 0 {
			continue
		}
		preserveOriginal(frame)
		if len(positions) == 1 {
			applyProguardPosition(frame, positions[0])
			return true, nil
		}
		expanded := make([]map[string]any, 0, len(positions))
		for index := len(positions) - 1; index >= 0; index-- {
			member := cloneFrame(frame)
			applyProguardPosition(member, positions[index])
			if index != len(positions)-1 {
				member["inline"] = true
			}
			expanded = append(expanded, member)
		}
		return true, expanded
	}
	return false, nil
}

func applyProguardPosition(frame map[string]any, position proguardPosition) {
	frame["module"] = position.class
	if _, ok := frame["package"]; ok {
		frame["package"] = position.class
	}
	if position.method != "" {
		frame["function"] = position.method
	}
	if position.filename != "" {
		frame["filename"] = position.filename
		if _, ok := frame["abs_path"]; ok {
			frame["abs_path"] = position.filename
		}
	}
	if position.hasLine {
		frame["lineno"] = position.line
	}
	delete(frame, "colno")
	frame["symbolicated"] = true
}

func proguardFrameName(frame map[string]any) (string, string) {
	class := firstString(frame, "module", "package")
	method := firstString(frame, "function")
	if class == "" && strings.Contains(method, ".") {
		class, method = method[:strings.LastIndex(method, ".")], method[strings.LastIndex(method, ".")+1:]
	}
	if class == "" {
		filename := firstString(frame, "filename")
		if strings.HasSuffix(strings.ToLower(filename), ".java") {
			class = strings.TrimSuffix(strings.ReplaceAll(filename, "/", "."), path.Ext(filename))
		}
	}
	method = strings.TrimPrefix(method, class+".")
	return strings.TrimSpace(class), strings.TrimSpace(method)
}

func proguardDebugID(payload map[string]any) string {
	if value := normalizeDebugID(firstString(payload, "proguard_uuid")); value != "" {
		return value
	}
	debugMeta, _ := payload["debug_meta"].(map[string]any)
	if value := normalizeDebugID(firstString(debugMeta, "proguard_uuid")); value != "" {
		return value
	}
	images, _ := debugMeta["images"].([]any)
	for _, raw := range images {
		image, _ := raw.(map[string]any)
		if strings.EqualFold(firstString(image, "type"), "proguard") {
			if value := normalizeDebugID(firstString(image, "uuid", "debug_id", "debugId")); value != "" {
				return value
			}
		}
	}
	return ""
}

func splitProguardMethod(value string) (string, string) {
	if index := strings.LastIndex(value, "."); index >= 0 {
		return value[:index], value[index+1:]
	}
	return "", value
}

func proguardSourceFile(comment string) string {
	var metadata struct {
		ID       string `json:"id"`
		FileName string `json:"fileName"`
	}
	if json.Unmarshal([]byte(strings.TrimSpace(strings.TrimPrefix(comment, "#"))), &metadata) != nil || metadata.ID != "sourceFile" {
		return ""
	}
	return path.Base(strings.ReplaceAll(strings.TrimSpace(metadata.FileName), "\\", "/"))
}

func synthesizeProguardFilename(class, reference string) string {
	name := class
	if index := strings.LastIndex(name, "."); index >= 0 {
		name = name[index+1:]
	}
	segments := strings.Split(name, "$")
	base := segments[0]
	for _, segment := range segments {
		if strings.HasSuffix(segment, "Kt") && len(segment) > 2 {
			return strings.TrimSuffix(segment, "Kt") + ".kt"
		}
	}
	extension := path.Ext(reference)
	if extension == "" {
		extension = ".java"
	}
	return base + extension
}
