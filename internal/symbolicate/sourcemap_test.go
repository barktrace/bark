package symbolicate

import "testing"

func TestSourceMapLookup(t *testing.T) {
	// The canonical minimal Source Map v3 example maps generated 1:0 to
	// one.js:1:0 with the name "bar".
	sourceMap, err := ParseSourceMap([]byte(`{"version":3,"file":"out.js","sourceRoot":"src","sources":["one.js"],"sourcesContent":["const bar = 1;"],"names":["bar"],"mappings":"AAAAA"}`))
	if err != nil {
		t.Fatal(err)
	}
	position, ok := sourceMap.Lookup(1, 0)
	if !ok || position.Source != "src/one.js" || position.Line != 1 || position.Column != 0 || position.Name != "bar" || position.Context != "const bar = 1;" {
		t.Fatalf("position = %#v, ok=%v", position, ok)
	}
}

func TestSourceMapUnmappedSegmentAdvancesGeneratedColumn(t *testing.T) {
	sourceMap, err := ParseSourceMap([]byte(`{"version":3,"sources":["input.js"],"names":[],"mappings":"K,GAAA"}`))
	if err != nil {
		t.Fatal(err)
	}
	if position, ok := sourceMap.Lookup(1, 7); ok {
		t.Fatalf("column before mapped segment resolved to %#v", position)
	}
	position, ok := sourceMap.Lookup(1, 8)
	if !ok || position.Source != "input.js" || position.Line != 1 || position.Column != 0 {
		t.Fatalf("position = %#v, ok=%v", position, ok)
	}
}

func TestIndexedSourceMapLookupAndURLSourceRoot(t *testing.T) {
	sourceMap, err := ParseSourceMap([]byte(`{
		"version":3,
		"sections":[
			{"offset":{"line":0,"column":10},"map":{"version":3,"sourceRoot":"webpack:///","sources":["src/first.js"],"sourcesContent":[null],"names":[],"mappings":"AAAA"}},
			{"offset":{"line":2,"column":0},"map":{"version":3,"sources":["second.js"],"sourcesContent":["second();"],"names":[],"mappings":"AAAA"}}
		]
	}`))
	if err != nil {
		t.Fatal(err)
	}
	first, ok := sourceMap.Lookup(1, 10)
	if !ok || first.Source != "webpack:///src/first.js" || first.Context != "" {
		t.Fatalf("first position = %#v, ok=%v", first, ok)
	}
	second, ok := sourceMap.Lookup(3, 0)
	if !ok || second.Source != "second.js" || second.Context != "second();" {
		t.Fatalf("second position = %#v, ok=%v", second, ok)
	}
}

func TestIndexedSourceMapRejectsOverlappingSections(t *testing.T) {
	_, err := ParseSourceMap([]byte(`{"version":3,"sections":[{"offset":{"line":0,"column":0},"map":{"version":3,"sources":["a.js"],"mappings":"AAAA"}},{"offset":{"line":0,"column":0},"map":{"version":3,"sources":["b.js"],"mappings":"AAAA"}}]}`))
	if err == nil {
		t.Fatal("overlapping sections were accepted")
	}
}

func TestSourceMapRejectsInvalidMappings(t *testing.T) {
	if _, err := ParseSourceMap([]byte(`{"version":3,"sources":["one.js"],"mappings":"!"}`)); err == nil {
		t.Fatal("invalid map was accepted")
	}
}
