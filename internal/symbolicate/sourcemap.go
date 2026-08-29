package symbolicate

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"path"
	"strings"
)

const (
	maxSourceMapDepth    = 8
	maxSourceMapSections = 10000
	maxSourceMapSegments = 1000000
)

type SourceMap struct {
	Version        int       `json:"version"`
	File           string    `json:"file"`
	SourceRoot     string    `json:"sourceRoot"`
	Sources        []string  `json:"sources"`
	SourcesContent []*string `json:"sourcesContent"`
	Names          []string  `json:"names"`
	Mappings       string    `json:"mappings"`
	Sections       []section `json:"sections"`
	lines          [][]mapping
}

type section struct {
	Offset struct {
		Line   int `json:"line"`
		Column int `json:"column"`
	} `json:"offset"`
	Map *SourceMap `json:"map"`
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
	segments := 0
	if err := sourceMap.parse(0, &segments); err != nil {
		return nil, err
	}
	return &sourceMap, nil
}

func (s *SourceMap) parse(depth int, segmentCount *int) error {
	if s.Version != 3 {
		return errors.New("source map version must be 3")
	}
	if len(s.Sections) > 0 {
		if len(s.Sections) > maxSourceMapSections || len(s.Sources) > 0 || s.Mappings != "" {
			return errors.New("invalid indexed source map")
		}
		if depth >= maxSourceMapDepth {
			return errors.New("source map sections are nested too deeply")
		}
		previousLine, previousColumn := -1, -1
		for index := range s.Sections {
			item := &s.Sections[index]
			if item.Map == nil || item.Offset.Line < 0 || item.Offset.Column < 0 || item.Offset.Line < previousLine || (item.Offset.Line == previousLine && item.Offset.Column <= previousColumn) {
				return errors.New("invalid source map section offset")
			}
			if err := item.Map.parse(depth+1, segmentCount); err != nil {
				return fmt.Errorf("parse source map section %d: %w", index, err)
			}
			previousLine, previousColumn = item.Offset.Line, item.Offset.Column
		}
		return nil
	}
	if len(s.Sources) == 0 || s.Mappings == "" {
		return errors.New("source map has no sources or mappings")
	}
	if len(s.Sources) > maxSourceMapSegments || len(s.Names) > maxSourceMapSegments {
		return errors.New("source map metadata exceeds limits")
	}
	lines := strings.Split(s.Mappings, ";")
	s.lines = make([][]mapping, len(lines))
	previousSource, previousLine, previousColumn, previousName := 0, 0, 0, 0
	for lineIndex, encodedLine := range lines {
		generatedColumn := 0
		for _, encodedSegment := range strings.Split(encodedLine, ",") {
			if encodedSegment == "" {
				continue
			}
			values, err := decodeVLQ(encodedSegment)
			if err != nil {
				return err
			}
			if len(values) != 1 && len(values) != 4 && len(values) != 5 {
				return errors.New("invalid source map segment")
			}
			generatedColumn += values[0]
			if generatedColumn < 0 {
				return errors.New("invalid generated source map column")
			}
			if len(values) == 1 {
				continue
			}
			previousSource += values[1]
			previousLine += values[2]
			previousColumn += values[3]
			if previousSource < 0 || previousSource >= len(s.Sources) || previousLine < 0 || previousColumn < 0 {
				return errors.New("source map segment references an invalid source position")
			}
			item := mapping{generatedColumn: generatedColumn, source: previousSource, originalLine: previousLine, originalColumn: previousColumn}
			if len(values) >= 5 {
				previousName += values[4]
				if previousName < 0 || previousName >= len(s.Names) {
					return errors.New("source map segment references an invalid name")
				}
				item.name, item.hasName = previousName, true
			}
			(*segmentCount)++
			if *segmentCount > maxSourceMapSegments {
				return errors.New("source map contains too many segments")
			}
			s.lines[lineIndex] = append(s.lines[lineIndex], item)
		}
	}
	return nil
}

func (s *SourceMap) Lookup(line, column int) (OriginalPosition, bool) {
	if len(s.Sections) > 0 {
		generatedLine := line - 1
		selected := -1
		for index := range s.Sections {
			offset := s.Sections[index].Offset
			if offset.Line > generatedLine || (offset.Line == generatedLine && offset.Column > column) {
				break
			}
			selected = index
		}
		if selected < 0 {
			return OriginalPosition{}, false
		}
		item := s.Sections[selected]
		localLine := generatedLine - item.Offset.Line + 1
		localColumn := column
		if generatedLine == item.Offset.Line {
			localColumn -= item.Offset.Column
		}
		return item.Map.Lookup(localLine, localColumn)
	}
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
	source := joinSourceRoot(s.SourceRoot, s.Sources[item.source])
	position := OriginalPosition{Source: source, Line: item.originalLine + 1, Column: item.originalColumn}
	if item.hasName && item.name >= 0 && item.name < len(s.Names) {
		position.Name = s.Names[item.name]
	}
	if item.source < len(s.SourcesContent) && s.SourcesContent[item.source] != nil && item.originalLine >= 0 {
		lines := strings.Split(*s.SourcesContent[item.source], "\n")
		if item.originalLine < len(lines) {
			position.Context = lines[item.originalLine]
		}
	}
	return position, true
}

func joinSourceRoot(root, source string) string {
	if root == "" || source == "" {
		return source
	}
	if parsed, err := url.Parse(source); err == nil && parsed.Scheme != "" {
		return source
	}
	if parsed, err := url.Parse(root); err == nil && parsed.Scheme != "" {
		separator := ""
		if !strings.HasSuffix(root, "/") {
			separator = "/"
		}
		return root + separator + strings.TrimLeft(source, "/")
	}
	return path.Join(root, source)
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
