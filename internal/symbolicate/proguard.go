package symbolicate

import (
	"bufio"
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
	maxProguardBytes    = 20 << 20
	maxProguardMappings = 1000000
)

var proguardMethodPattern = regexp.MustCompile(`^(?:(\d+):(\d+):)?\S+\s+([^\s(]+)\([^)]*\)(?::(\d+)(?::(\d+))?)?$`)

type ProguardMap struct {
	classes map[string]*proguardClass
}

type proguardClass struct {
	original string
	methods  map[string][]proguardMethod
}

type proguardMethod struct {
	original                       string
	obfuscatedStart, obfuscatedEnd int
	originalStart, originalEnd     int
}

type proguardPosition struct {
	class, method string
	line          int
}

func ParseProguardMap(reader io.Reader) (*ProguardMap, error) {
	return parseProguardMap(reader, maxProguardBytes)
}

func parseProguardMap(reader io.Reader, byteLimit int64) (*ProguardMap, error) {
	parsed := &ProguardMap{classes: make(map[string]*proguardClass)}
	limited := &io.LimitedReader{R: reader, N: byteLimit + 1}
	scanner := bufio.NewScanner(limited)
	scanner.Buffer(make([]byte, 64<<10), 1<<20)
	var current *proguardClass
	mappings := 0
	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" || strings.HasPrefix(strings.TrimSpace(line), "#") {
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
			method := proguardMethod{original: simpleMethodName(match[3])}
			method.obfuscatedStart, _ = strconv.Atoi(match[1])
			method.obfuscatedEnd, _ = strconv.Atoi(match[2])
			method.originalStart, _ = strconv.Atoi(match[4])
			method.originalEnd, _ = strconv.Atoi(match[5])
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
	mapped, ok := p.classes[class]
	if !ok {
		return proguardPosition{}, false
	}
	position := proguardPosition{class: mapped.original, method: method, line: line}
	candidates := mapped.methods[method]
	selected := -1
	for index, candidate := range candidates {
		if candidate.obfuscatedStart == 0 {
			if selected < 0 {
				selected = index
			}
			continue
		}
		if line >= candidate.obfuscatedStart && line <= candidate.obfuscatedEnd {
			selected = index
			break
		}
	}
	if selected >= 0 {
		candidate := candidates[selected]
		position.method = candidate.original
		if candidate.originalStart > 0 && candidate.obfuscatedStart > 0 {
			position.line = candidate.originalStart + line - candidate.obfuscatedStart
			if candidate.originalEnd >= candidate.originalStart && position.line > candidate.originalEnd {
				position.line = candidate.originalEnd
			}
		}
	}
	return position, true
}

func symbolicateProguardFrame(st *store.Store, artifacts []artifact, payload map[string]any, frame map[string]any, cache map[string]cachedProguardMap) bool {
	class, method := proguardFrameName(frame)
	if class == "" {
		return false
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
		position, ok := cached.value.Lookup(class, method, intValue(frame["lineno"]))
		if !ok {
			continue
		}
		preserveOriginal(frame)
		frame["module"] = position.class
		if _, ok := frame["package"]; ok {
			frame["package"] = position.class
		}
		if position.method != "" {
			frame["function"] = position.method
		}
		if filename := stringValue(frame["filename"]); filename != "" {
			frame["filename"] = path.Base(strings.ReplaceAll(position.class, ".", "/")) + ".java"
		}
		if position.line > 0 {
			frame["lineno"] = position.line
		}
		frame["symbolicated"] = true
		return true
	}
	return false
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

func simpleMethodName(value string) string {
	if index := strings.LastIndex(value, "."); index >= 0 {
		return value[index+1:]
	}
	return value
}
