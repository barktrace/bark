package telemetry

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

const (
	maxProfileFrames  = 50000
	maxProfileStacks  = 100000
	maxProfileSamples = 200000
	maxFlameNodes     = 5000
	maxStackDepth     = 128
)

type ProfileAnalysis struct {
	Platform    string          `json:"platform"`
	DurationMS  float64         `json:"duration_ms"`
	SampleCount int             `json:"sample_count"`
	FrameCount  int             `json:"frame_count"`
	Threads     []ProfileThread `json:"threads"`
	Hotspots    []ProfileFrame  `json:"hotspots"`
	Flamegraph  []*ProfileFrame `json:"flamegraph"`
	Truncated   bool            `json:"truncated"`
}

type ProfileThread struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Samples int    `json:"samples"`
}

type ProfileFrame struct {
	Name         string          `json:"name"`
	Module       string          `json:"module"`
	Filename     string          `json:"filename"`
	Line         int             `json:"line"`
	SelfSamples  int             `json:"self_samples"`
	TotalSamples int             `json:"total_samples"`
	Percentage   float64         `json:"percentage"`
	Children     []*ProfileFrame `json:"children,omitempty"`
	childIndex   map[string]*ProfileFrame
}

type profilePayload struct {
	Platform   string          `json:"platform"`
	DurationNS json.RawMessage `json:"duration_ns"`
	Profile    json.RawMessage `json:"profile"`
	Frames     []profileFrame  `json:"frames"`
	Stacks     [][]int         `json:"stacks"`
	Samples    []profileSample `json:"samples"`
	Threads    map[string]struct {
		Name string `json:"name"`
	} `json:"thread_metadata"`
}

type profileFrame struct {
	Function string `json:"function"`
	Name     string `json:"name"`
	Module   string `json:"module"`
	Package  string `json:"package"`
	Filename string `json:"filename"`
	AbsPath  string `json:"abs_path"`
	Line     int    `json:"lineno"`
}

type profileSample struct {
	StackID  int             `json:"stack_id"`
	ThreadID json.RawMessage `json:"thread_id"`
}

func AnalyzeProfile(raw []byte) (ProfileAnalysis, error) {
	result := ProfileAnalysis{Threads: []ProfileThread{}, Hotspots: []ProfileFrame{}, Flamegraph: []*ProfileFrame{}}
	decoded, err := decodePayload(raw)
	if err != nil {
		return result, fmt.Errorf("decode profile: %w", err)
	}
	var outer profilePayload
	if err := json.Unmarshal(decoded, &outer); err != nil {
		return result, fmt.Errorf("parse profile: %w", err)
	}
	inner := outer
	if len(outer.Profile) > 0 && string(outer.Profile) != "null" {
		if err := json.Unmarshal(outer.Profile, &inner); err != nil {
			return result, fmt.Errorf("parse sampled profile: %w", err)
		}
		if inner.Platform == "" {
			inner.Platform = outer.Platform
		}
		if len(inner.DurationNS) == 0 {
			inner.DurationNS = outer.DurationNS
		}
	}
	if len(inner.Frames) == 0 || len(inner.Stacks) == 0 || len(inner.Samples) == 0 {
		return result, errors.New("profile does not contain frames, stacks, and samples")
	}
	if len(inner.Frames) > maxProfileFrames || len(inner.Stacks) > maxProfileStacks || len(inner.Samples) > maxProfileSamples {
		return result, errors.New("profile exceeds analysis limits")
	}
	result.Platform = firstText(inner.Platform, outer.Platform, "unknown")
	result.DurationMS = rawNumber(inner.DurationNS) / 1e6
	result.FrameCount = len(inner.Frames)

	threadSamples := make(map[string]int)
	threadNames := make(map[string]string)
	for id, metadata := range inner.Threads {
		threadNames[id] = strings.TrimSpace(metadata.Name)
	}
	hotspots := make(map[string]*ProfileFrame)
	roots := make([]*ProfileFrame, 0)
	rootIndex := make(map[string]*ProfileFrame)
	nodes := 0
	for _, sample := range inner.Samples {
		if sample.StackID < 0 || sample.StackID >= len(inner.Stacks) {
			continue
		}
		stack := inner.Stacks[sample.StackID]
		if len(stack) == 0 {
			continue
		}
		result.SampleCount++
		threadID := rawIdentifier(sample.ThreadID)
		if threadID == "" {
			threadID = "unknown"
		}
		threadSamples[threadID]++
		var children *[]*ProfileFrame = &roots
		index := rootIndex
		validFrames := make([]profileFrame, 0, minInt(len(stack), maxStackDepth))
		for _, frameIndex := range stack {
			if frameIndex >= 0 && frameIndex < len(inner.Frames) {
				validFrames = append(validFrames, inner.Frames[frameIndex])
			}
			if len(validFrames) == maxStackDepth {
				result.Truncated = true
				break
			}
		}
		for position, frame := range validFrames {
			key := profileFrameKey(frame)
			node := index[key]
			if node == nil {
				if nodes >= maxFlameNodes {
					result.Truncated = true
					break
				}
				node = newProfileFrame(frame)
				node.childIndex = make(map[string]*ProfileFrame)
				index[key] = node
				*children = append(*children, node)
				nodes++
			}
			node.TotalSamples++
			hotspot := hotspots[key]
			if hotspot == nil {
				hotspot = newProfileFrame(frame)
				hotspots[key] = hotspot
			}
			hotspot.TotalSamples++
			if position == len(validFrames)-1 {
				node.SelfSamples++
				hotspot.SelfSamples++
			}
			children, index = &node.Children, node.childIndex
		}
	}
	if result.SampleCount == 0 {
		return result, errors.New("profile has no valid samples")
	}
	for id, count := range threadSamples {
		result.Threads = append(result.Threads, ProfileThread{ID: id, Name: firstText(threadNames[id], "Thread "+id), Samples: count})
	}
	sort.Slice(result.Threads, func(i, j int) bool { return result.Threads[i].Samples > result.Threads[j].Samples })
	for _, hotspot := range hotspots {
		hotspot.Percentage = percent(hotspot.TotalSamples, result.SampleCount)
		hotspot.childIndex = nil
		result.Hotspots = append(result.Hotspots, *hotspot)
	}
	sort.Slice(result.Hotspots, func(i, j int) bool {
		if result.Hotspots[i].SelfSamples == result.Hotspots[j].SelfSamples {
			return result.Hotspots[i].TotalSamples > result.Hotspots[j].TotalSamples
		}
		return result.Hotspots[i].SelfSamples > result.Hotspots[j].SelfSamples
	})
	if len(result.Hotspots) > 200 {
		result.Hotspots = result.Hotspots[:200]
		result.Truncated = true
	}
	finalizeFlamegraph(roots, result.SampleCount)
	result.Flamegraph = roots
	return result, nil
}

func newProfileFrame(frame profileFrame) *ProfileFrame {
	return &ProfileFrame{Name: firstText(frame.Function, frame.Name, "<unknown>"), Module: firstText(frame.Module, frame.Package), Filename: firstText(frame.Filename, frame.AbsPath), Line: frame.Line, Children: []*ProfileFrame{}}
}

func profileFrameKey(frame profileFrame) string {
	return firstText(frame.Function, frame.Name, "<unknown>") + "\x00" + firstText(frame.Module, frame.Package) + "\x00" + firstText(frame.Filename, frame.AbsPath) + "\x00" + strconv.Itoa(frame.Line)
}

func finalizeFlamegraph(nodes []*ProfileFrame, samples int) {
	for _, node := range nodes {
		node.Percentage = percent(node.TotalSamples, samples)
		node.childIndex = nil
		sort.Slice(node.Children, func(i, j int) bool { return node.Children[i].TotalSamples > node.Children[j].TotalSamples })
		finalizeFlamegraph(node.Children, samples)
	}
}

func percent(value, total int) float64 {
	if total == 0 {
		return 0
	}
	return float64(value) * 100 / float64(total)
}

func rawIdentifier(raw json.RawMessage) string {
	var text string
	if json.Unmarshal(raw, &text) == nil {
		return text
	}
	var number json.Number
	if json.Unmarshal(raw, &number) == nil {
		return number.String()
	}
	return ""
}

func rawNumber(raw json.RawMessage) float64 {
	var number float64
	if json.Unmarshal(raw, &number) == nil {
		return number
	}
	var text string
	if json.Unmarshal(raw, &text) == nil {
		number, _ = strconv.ParseFloat(text, 64)
	}
	return number
}

func minInt(left, right int) int {
	if left < right {
		return left
	}
	return right
}
