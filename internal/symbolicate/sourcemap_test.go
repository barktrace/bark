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

func TestSourceMapRejectsInvalidMappings(t *testing.T) {
	if _, err := ParseSourceMap([]byte(`{"version":3,"sources":["one.js"],"mappings":"!"}`)); err == nil {
		t.Fatal("invalid map was accepted")
	}
}
