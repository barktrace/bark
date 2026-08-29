package symbolicate

import (
	"encoding/json"
	"errors"
	"path"
	"strings"
)

type SourceMap struct {
	File           string   `json:"file"`
	SourceRoot     string   `json:"sourceRoot"`
	Sources        []string `json:"sources"`
	SourcesContent []string `json:"sourcesContent"`
	Names          []string `json:"names"`
	Mappings       string   `json:"mappings"`
	lines          [][]mapping
}

type mapping struct {
	generatedColumn int
	source          int
	originalLine    int
	originalColumn  int
	name            int
	hasName         bool
}

type OriginalPosition struct {
	Source  string
	Line    int
	Column  int
	Name    string
	Context string
}

func ParseSourceMap(raw []byte) (*SourceMap, error) {
	var sourceMap SourceMap
	if err := json.Unmarshal(raw, &sourceMap); err != nil {
		return nil, err
	}
	if len(sourceMap.Sources) == 0 || sourceMap.Mappings == "" {
		return nil, errors.New("source map has no sources or mappings")
	}
	lines := strings.Split(sourceMap.Mappings, ";")
	sourceMap.lines = make([][]mapping, len(lines))
	previousSource, previousLine, previousColumn, previousName := 0, 0, 0, 0
	for lineIndex, encodedLine := range lines {
		generatedColumn := 0
		for _, encodedSegment := range strings.Split(encodedLine, ",") {
			if encodedSegment == "" {
				continue
			}
			values, err := decodeVLQ(encodedSegment)
			if err != nil {
				return nil, err
			}
			if len(values) == 1 {
				continue
			}
			if len(values) < 4 {
				return nil, errors.New("invalid source map segment")
			}
			generatedColumn += values[0]
			previousSource += values[1]
			previousLine += values[2]
			previousColumn += values[3]
			item := mapping{generatedColumn: generatedColumn, source: previousSource, originalLine: previousLine, originalColumn: previousColumn}
			if len(values) >= 5 {
				previousName += values[4]
				item.name, item.hasName = previousName, true
			}
			if item.source >= 0 && item.source < len(sourceMap.Sources) {
				sourceMap.lines[lineIndex] = append(sourceMap.lines[lineIndex], item)
			}
		}
	}
	return &sourceMap, nil
}

func (s *SourceMap) Lookup(line, column int) (OriginalPosition, bool) {
	if line < 1 || line > len(s.lines) || column < 0 {
		return OriginalPosition{}, false
	}
	segments := s.lines[line-1]
	if len(segments) == 0 {
		return OriginalPosition{}, false
	}
	selected := -1
	for index := range segments {
		if segments[index].generatedColumn > column {
			break
		}
		selected = index
	}
	if selected < 0 {
		return OriginalPosition{}, false
	}
	item := segments[selected]
	source := s.Sources[item.source]
	if s.SourceRoot != "" && !strings.Contains(source, "://") {
		source = path.Join(s.SourceRoot, source)
	}
	position := OriginalPosition{Source: source, Line: item.originalLine + 1, Column: item.originalColumn}
	if item.hasName && item.name >= 0 && item.name < len(s.Names) {
		position.Name = s.Names[item.name]
	}
	if item.source < len(s.SourcesContent) && item.originalLine >= 0 {
		lines := strings.Split(s.SourcesContent[item.source], "\n")
		if item.originalLine < len(lines) {
			position.Context = lines[item.originalLine]
		}
	}
	return position, true
}

func decodeVLQ(encoded string) ([]int, error) {
	values := make([]int, 0, 5)
	value, shift := 0, 0
	for _, character := range encoded {
		digit := base64Digit(character)
		if digit < 0 {
			return nil, errors.New("invalid base64 VLQ character")
		}
		continuation := digit&32 != 0
		digit &= 31
		value += digit << shift
		if continuation {
			shift += 5
			continue
		}
		negative := value&1 == 1
		decoded := value >> 1
		if negative {
			decoded = -decoded
		}
		values = append(values, decoded)
		value, shift = 0, 0
	}
	if shift != 0 {
		return nil, errors.New("unterminated base64 VLQ value")
	}
	return values, nil
}

func base64Digit(character rune) int {
	switch {
	case character >= 'A' && character <= 'Z':
		return int(character - 'A')
	case character >= 'a' && character <= 'z':
		return int(character-'a') + 26
	case character >= '0' && character <= '9':
		return int(character-'0') + 52
	case character == '+':
		return 62
	case character == '/':
		return 63
	default:
		return -1
	}
}
