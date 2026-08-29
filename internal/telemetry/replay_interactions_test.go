package telemetry

import "testing"

func TestAnalyzeReplayInteractionsClassifiesSelectors(t *testing.T) {
	payload := []byte(`[
		{"type":2,"timestamp":1787997601000,"data":{"node":{"type":0,"id":1,"childNodes":[{"type":2,"id":7,"tagName":"button","attributes":{"id":"pay","class":"primary cta","aria-label":"Pay now"},"childNodes":[]},{"type":2,"id":8,"tagName":"a","attributes":{"class":"help"},"childNodes":[]}]}}},
		{"type":3,"timestamp":1787997602000,"data":{"source":2,"type":2,"id":7}},
		{"type":3,"timestamp":1787997602200,"data":{"source":2,"type":2,"id":8}},
		{"type":3,"timestamp":1787997602400,"data":{"source":2,"type":2,"id":7}},
		{"type":3,"timestamp":1787997602800,"data":{"source":2,"type":2,"id":7}},
		{"type":3,"timestamp":1787997603000,"data":{"source":0,"adds":[],"removes":[],"texts":[],"attributes":[]}},
		{"type":3,"timestamp":1787997612000,"data":{"source":2,"type":2,"id":8}},
		{"type":1,"timestamp":1787997620000,"data":{}}
    ]`)
	clicks, err := AnalyzeReplayInteractions(payload)
	if err != nil {
		t.Fatal(err)
	}
	if len(clicks) != 5 {
		t.Fatalf("click count=%d want=5", len(clicks))
	}
	for _, index := range []int{0, 2, 3} {
		if !clicks[index].Rage || clicks[index].Dead {
			t.Fatalf("rage click %d = %#v", index, clicks[index])
		}
		if clicks[index].DOMElement != "button#pay.primary.cta" || clicks[index].Element.AriaLabel != "Pay now" {
			t.Fatalf("selector metadata = %#v", clicks[index])
		}
	}
	if !clicks[4].Dead || clicks[4].Rage || clicks[4].DOMElement != "a.help" {
		t.Fatalf("dead click = %#v", clicks[4])
	}
}
