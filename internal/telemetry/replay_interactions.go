package telemetry

import (
	"encoding/json"
	"sort"
	"strings"
)

type ReplayElement struct {
	Alt           string   `json:"alt"`
	AriaLabel     string   `json:"aria_label"`
	Class         []string `json:"class"`
	ComponentName string   `json:"component_name"`
	ID            string   `json:"id"`
	Role          string   `json:"role"`
	Tag           string   `json:"tag"`
	TestID        string   `json:"testid"`
	Title         string   `json:"title"`
}

type ReplayClick struct {
	NodeID     int           `json:"node_id"`
	Timestamp  int64         `json:"timestamp_ms"`
	DOMElement string        `json:"dom_element"`
	Element    ReplayElement `json:"element"`
	Dead       bool          `json:"is_dead"`
	Rage       bool          `json:"is_rage"`
}

type replayNode struct {
	Type       int            `json:"type"`
	ID         int            `json:"id"`
	TagName    string         `json:"tagName"`
	Attributes map[string]any `json:"attributes"`
	ChildNodes []replayNode   `json:"childNodes"`
}

// AnalyzeReplayInteractions extracts click targets from one rrweb segment.
// Three clicks on the same node inside one second are marked as rage clicks. A
// click without a following DOM mutation or navigation inside seven seconds is
// marked dead. Both rules are intentionally deterministic and bounded.
func AnalyzeReplayInteractions(recordingPayload []byte) ([]ReplayClick, error) {
	recording, err := replayRecordingBody(recordingPayload)
	if err != nil {
		return nil, err
	}
	nodes := make(map[int]ReplayElement)
	clicks := make([]ReplayClick, 0)
	effects := make([]int64, 0)
	events := 0
	lastTimestamp := int64(0)
	err = scanReplayEvents(recording, func(event replayEvent) error {
		events++
		if events > maxReplayEvents {
			return errReplayLimit
		}
		timestamp := replayTimestampMS(event.Timestamp)
		if timestamp > lastTimestamp {
			lastTimestamp = timestamp
		}
		switch event.Type {
		case 2:
			var snapshot struct {
				Node replayNode `json:"node"`
			}
			if json.Unmarshal(event.Data, &snapshot) == nil {
				indexReplayNode(snapshot.Node, nodes)
			}
		case 3:
			var incremental struct {
				Source int `json:"source"`
				Type   int `json:"type"`
				ID     int `json:"id"`
				Adds   []struct {
					Node replayNode `json:"node"`
				} `json:"adds"`
				Attributes []struct {
					ID         int            `json:"id"`
					Attributes map[string]any `json:"attributes"`
				} `json:"attributes"`
			}
			if json.Unmarshal(event.Data, &incremental) != nil {
				return nil
			}
			if incremental.Source == 0 {
				effects = append(effects, timestamp)
				for _, addition := range incremental.Adds {
					indexReplayNode(addition.Node, nodes)
				}
				for _, change := range incremental.Attributes {
					element := nodes[change.ID]
					applyReplayAttributes(&element, change.Attributes)
					nodes[change.ID] = element
				}
			}
			if incremental.Source == 2 && incremental.Type == 2 {
				element := nodes[incremental.ID]
				clicks = append(clicks, ReplayClick{NodeID: incremental.ID, Timestamp: timestamp, DOMElement: replaySelector(element), Element: element})
			}
		case 4:
			effects = append(effects, timestamp)
		}
		return nil
	})
	if err != nil && err != errReplayLimit {
		return nil, err
	}
	sort.SliceStable(clicks, func(i, j int) bool { return clicks[i].Timestamp < clicks[j].Timestamp })
	sort.Slice(effects, func(i, j int) bool { return effects[i] < effects[j] })
	for index := range clicks {
		position := sort.Search(len(effects), func(i int) bool { return effects[i] > clicks[index].Timestamp })
		clicks[index].Dead = lastTimestamp-clicks[index].Timestamp >= 7000 && (position == len(effects) || effects[position]-clicks[index].Timestamp > 7000)
	}
	byNode := make(map[int][]int)
	for index := range clicks {
		byNode[clicks[index].NodeID] = append(byNode[clicks[index].NodeID], index)
	}
	for _, indices := range byNode {
		first := 0
		for last := range indices {
			for clicks[indices[last]].Timestamp-clicks[indices[first]].Timestamp > 1000 {
				first++
			}
			if last-first+1 >= 3 {
				for position := first; position <= last; position++ {
					clicks[indices[position]].Rage = true
				}
			}
		}
	}
	return clicks, nil
}

func indexReplayNode(node replayNode, nodes map[int]ReplayElement) {
	if node.ID != 0 {
		element := ReplayElement{Tag: strings.ToLower(strings.TrimSpace(node.TagName)), Class: []string{}}
		applyReplayAttributes(&element, node.Attributes)
		nodes[node.ID] = element
	}
	for _, child := range node.ChildNodes {
		indexReplayNode(child, nodes)
	}
}

func applyReplayAttributes(element *ReplayElement, attributes map[string]any) {
	if attributes == nil {
		return
	}
	text := func(name string) string {
		value, _ := attributes[name].(string)
		return boundedText(strings.TrimSpace(value), 200)
	}
	element.ID = text("id")
	element.Alt = text("alt")
	element.AriaLabel = text("aria-label")
	element.ComponentName = firstText(text("data-sentry-component"), text("data-component"))
	element.Role = text("role")
	element.TestID = firstText(text("data-testid"), text("data-test-id"))
	element.Title = text("title")
	element.Class = strings.Fields(text("class"))
	if len(element.Class) > 20 {
		element.Class = element.Class[:20]
	}
}

func replaySelector(element ReplayElement) string {
	selector := firstText(element.Tag, "unknown")
	if element.ID != "" {
		selector += "#" + element.ID
	}
	for _, className := range element.Class {
		selector += "." + className
	}
	return boundedText(selector, 500)
}
