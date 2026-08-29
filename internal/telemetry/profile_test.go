package telemetry

import "testing"

func TestAnalyzeProfileBuildsThreadsHotspotsAndFlamegraph(t *testing.T) {
	payload := []byte(`{
		"profile_id":"profile-one",
		"platform":"python",
		"duration_ns":"250000000",
		"profile":{
			"frames":[
				{"function":"main","module":"app","filename":"app.py","lineno":1},
				{"function":"checkout","module":"shop","filename":"checkout.py","lineno":42},
				{"function":"query","module":"db","filename":"db.py","lineno":9}
			],
			"stacks":[[0,1],[0,1,2]],
			"samples":[{"stack_id":0,"thread_id":"main"},{"stack_id":1,"thread_id":"main"},{"stack_id":1,"thread_id":"worker"}],
			"thread_metadata":{"main":{"name":"Main thread"},"worker":{"name":"Worker"}}
		}
	}`)
	result, err := AnalyzeProfile(payload)
	if err != nil {
		t.Fatal(err)
	}
	if result.Platform != "python" || result.DurationMS != 250 || result.SampleCount != 3 || result.FrameCount != 3 {
		t.Fatalf("unexpected profile summary: %#v", result)
	}
	if len(result.Threads) != 2 || result.Threads[0].Name != "Main thread" || result.Threads[0].Samples != 2 {
		t.Fatalf("unexpected threads: %#v", result.Threads)
	}
	if len(result.Hotspots) != 3 || result.Hotspots[0].Name != "query" || result.Hotspots[0].SelfSamples != 2 {
		t.Fatalf("unexpected hotspots: %#v", result.Hotspots)
	}
	if len(result.Flamegraph) != 1 || result.Flamegraph[0].Name != "main" || len(result.Flamegraph[0].Children) != 1 || result.Flamegraph[0].Children[0].Name != "checkout" {
		t.Fatalf("unexpected flamegraph: %#v", result.Flamegraph)
	}
}

func TestAnalyzeProfileRejectsUnsupportedPayload(t *testing.T) {
	if _, err := AnalyzeProfile([]byte(`{"profile_id":"empty"}`)); err == nil {
		t.Fatal("empty profile was accepted")
	}
}
