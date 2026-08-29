package symbolicate

import (
	"bytes"
	"context"
	"encoding/binary"
	"os"
	"strings"
	"testing"
)

func TestLookupPDBFrameResolvesPublicSymbol(t *testing.T) {
	fixture := pdbFixture(t)
	const imageBase = uint64(0x140000000)
	matched := lookupPDBFrame(bytes.NewReader(fixture), imageBase+0x1024, imageBase)
	if matched.function != "checkout" || matched.address != 0x1020 || matched.filename != `C:\src\fixture.cpp` || matched.line != 17 || matched.column != 5 {
		t.Fatalf("PDB match = %#v", matched)
	}
	if outside := lookupPDBFrame(bytes.NewReader(fixture), imageBase+0x1200, imageBase); outside.function != "" {
		t.Fatalf("out-of-section address matched %#v", outside)
	}
}

func TestLookupPDBFrameExpandsNestedInlineSites(t *testing.T) {
	fixture := pdbFixture(t)
	const imageBase = uint64(0x140000000)
	matched := lookupPDBFrame(bytes.NewReader(fixture), imageBase+0x102c, imageBase)
	if matched.function != "checkout" || matched.filename != `C:\src\fixture.cpp` || matched.line != 8 || len(matched.inlines) != 2 {
		t.Fatalf("PDB inline match = %#v", matched)
	}
	if outer := matched.inlines[0]; outer.function != "validate" || outer.filename != `C:\src\fixture.cpp` || outer.line != 17 || outer.address != 0x1028 || outer.rangeSize != 0x8 {
		t.Fatalf("outer PDB inline = %#v", outer)
	}
	if inner := matched.inlines[1]; inner.function != "normalize" || inner.filename != `C:\src\fixture.cpp` || inner.line != 10 || inner.address != 0x1028 || inner.rangeSize != 0x8 {
		t.Fatalf("inner PDB inline = %#v", inner)
	}
}

func TestProcessEventUsesStandalonePDB(t *testing.T) {
	st := symbolicationStore(t)
	putDebugArtifactBytes(t, st, "12345678123412341234123456789ABC", pdbFixture(t))
	payload := []byte(`{
		"debug_meta":{"images":[{"type":"pe_dotnet","image_addr":"0x140000000","image_size":"0x2000","debug_id":"12345678-1234-1234-1234-123456789abc"}]},
		"exception":{"values":[{"stacktrace":{"frames":[{"instruction_addr":"0x140001024","function":"0x140001024","filename":"checkout.exe"}]}}]}
	}`)
	processed, changed, err := ProcessEvent(context.Background(), st, "project", "release", payload)
	if err != nil {
		t.Fatal(err)
	}
	frame := processedFrame(t, processed)
	if !changed || frame["function"] != "checkout" || frame["symbol_addr"] != "0x140001020" || frame["filename"] != `C:\src\fixture.cpp` || frame["lineno"] != float64(17) || frame["colno"] != float64(5) || frame["original_function"] != "0x140001024" || frame["symbolicated"] != true {
		t.Fatalf("processed PDB frame = %#v, changed=%v", frame, changed)
	}
}

func TestProcessEventExpandsStandalonePDBInlineFrames(t *testing.T) {
	st := symbolicationStore(t)
	putDebugArtifactBytes(t, st, "12345678123412341234123456789ABC", pdbFixture(t))
	payload := []byte(`{
		"debug_meta":{"images":[{"type":"pe_dotnet","image_addr":"0x140000000","image_size":"0x2000","debug_id":"12345678-1234-1234-1234-123456789abc"}]},
		"exception":{"values":[{"stacktrace":{"frames":[{"instruction_addr":"0x14000102c","function":"0x14000102c","filename":"checkout.exe"}]}}]}
	}`)
	processed, changed, err := ProcessEvent(context.Background(), st, "project", "release", payload)
	if err != nil {
		t.Fatal(err)
	}
	frames := processedFrames(t, processed)
	if !changed || len(frames) != 3 {
		t.Fatalf("processed PDB inline frames = %#v, changed=%v", frames, changed)
	}
	want := []struct {
		function string
		line     float64
		inline   bool
	}{{"checkout", 17, false}, {"validate", 10, true}, {"normalize", 8, true}}
	for index, expected := range want {
		if frames[index]["function"] != expected.function || frames[index]["lineno"] != expected.line || (frames[index]["inline"] == true) != expected.inline {
			t.Fatalf("processed PDB inline frame[%d] = %#v", index, frames[index])
		}
	}
}

func TestPDBParserRejectsOversizedBlockLayout(t *testing.T) {
	header := make([]byte, 56)
	copy(header, pdb7Magic)
	binary.LittleEndian.PutUint32(header[32:36], 4096)
	binary.LittleEndian.PutUint32(header[40:44], maxPDBBytes/4096+1)
	binary.LittleEndian.PutUint32(header[44:48], 4)
	binary.LittleEndian.PutUint32(header[52:56], 1)
	if _, err := parsePDBSymbols(bytes.NewReader(header)); err == nil {
		t.Fatal("oversized PDB block layout was accepted")
	}
}

func TestPDBBinaryAnnotationsDecodeRangesAndFileChanges(t *testing.T) {
	ranges := parsePDBInlineRanges([]byte{
		11, 0x26,
		5, 8,
		11, 0x56,
		11, 0x26,
		5, 0,
		11, 0x66,
		4, 6,
	})
	want := []pdbInlineRange{
		{start: 6, end: 12, lineOffset: 1},
		{start: 12, end: 18, lineOffset: -1, fileOffset: 8},
		{start: 18, end: 24, lineOffset: 0, fileOffset: 8},
		{start: 24, end: 30, lineOffset: 3},
	}
	if len(ranges) != len(want) {
		t.Fatalf("PDB inline ranges = %#v", ranges)
	}
	for index := range want {
		if ranges[index] != want[index] {
			t.Fatalf("PDB inline range[%d] = %#v, want %#v", index, ranges[index], want[index])
		}
	}
}

func TestPDBCompressedAnnotationOperands(t *testing.T) {
	data := []byte{0x7f, 0x81, 0x23, 0xc1, 0x23, 0x45, 0x67}
	offset := 0
	for index, expected := range []uint32{0x7f, 0x123, 0x1234567} {
		value, ok := readPDBCompressed(data, &offset)
		if !ok || value != expected {
			t.Fatalf("compressed operand[%d] = %#x, ok=%v; want %#x", index, value, ok, expected)
		}
	}
	malformedOffset := 0
	if _, ok := readPDBCompressed([]byte{0x80}, &malformedOffset); ok {
		t.Fatal("truncated compressed annotation operand was accepted")
	}
}

func TestPDBGlobalStringTableNamedStream(t *testing.T) {
	namedStreamNames := []byte("\x00/names\x00")
	info := make([]byte, 28)
	info = binary.LittleEndian.AppendUint32(info, uint32(len(namedStreamNames)))
	info = append(info, namedStreamNames...)
	info = binary.LittleEndian.AppendUint32(info, 1)
	info = binary.LittleEndian.AppendUint32(info, 1)
	info = binary.LittleEndian.AppendUint32(info, 1)
	info = binary.LittleEndian.AppendUint32(info, 1)
	info = binary.LittleEndian.AppendUint32(info, 0)
	info = binary.LittleEndian.AppendUint32(info, 1)
	info = binary.LittleEndian.AppendUint32(info, 2)

	stringsTable := []byte("\x00C:\\src\\real.cpp\x00")
	names := make([]byte, 12)
	binary.LittleEndian.PutUint32(names[:4], 0xeffeeffe)
	binary.LittleEndian.PutUint32(names[4:8], 1)
	binary.LittleEndian.PutUint32(names[8:12], uint32(len(stringsTable)))
	names = append(names, stringsTable...)

	const blockSize = 512
	contents := make([]byte, 3*blockSize)
	copy(contents[blockSize:], info)
	copy(contents[2*blockSize:], names)
	msf := &pdbMSF{
		reader: bytes.NewReader(contents), blockSize: blockSize, numBlocks: 3,
		sizes:  []uint32{0xffffffff, uint32(len(info)), uint32(len(names))},
		blocks: [][]uint32{nil, {1}, {2}},
	}
	if got := pdbString(pdbGlobalStrings(msf)[1:]); got != `C:\src\real.cpp` {
		t.Fatalf("global PDB string table = %q", got)
	}
}

func TestRealPDBFixture(t *testing.T) {
	path := os.Getenv("BARKTRACE_PDB_FIXTURE")
	if path == "" {
		t.Skip("set BARKTRACE_PDB_FIXTURE to a compiler-produced PDB")
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	parsed, err := parsePDBSymbols(file)
	if err != nil {
		t.Fatal(err)
	}
	for _, symbol := range parsed.symbols {
		if strings.Contains(symbol.name, "main") {
			matched, ok := parsed.lookup(symbol.address)
			if !ok || matched.name != symbol.name {
				t.Fatalf("real PDB lookup = %#v, ok=%v; want %q", matched, ok, symbol.name)
			}
			line, ok := parsed.lookupLine(symbol.address)
			if !ok || !strings.HasSuffix(strings.ToLower(line.filename), ".cpp") || line.line < 1 {
				t.Fatalf("real PDB line lookup = %#v, ok=%v", line, ok)
			}
			return
		}
	}
	t.Fatal("real PDB fixture contains no main symbol")
}

func TestRealPDBInlineFixture(t *testing.T) {
	path := os.Getenv("BARKTRACE_PDB_INLINE_FIXTURE")
	if path == "" {
		t.Skip("set BARKTRACE_PDB_INLINE_FIXTURE to a compiler-produced PDB with nested inline sites")
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	parsed, err := parsePDBSymbols(file)
	if err != nil {
		t.Fatal(err)
	}
	matched := lookupPDBSymbols(parsed, 0x1001, 0)
	if matched.function != "main" || !strings.HasSuffix(strings.ToLower(matched.filename), "t.cpp") || matched.line != 4 || len(matched.inlines) != 3 {
		t.Fatalf("real PDB inline match = %#v", matched)
	}
	want := []struct {
		function string
		line     int
	}{{"h", 13}, {"g", 10}, {"f", 7}}
	for index, expected := range want {
		if matched.inlines[index].function != expected.function || matched.inlines[index].line != expected.line || !strings.HasSuffix(strings.ToLower(matched.inlines[index].filename), "t.cpp") {
			t.Fatalf("real PDB inline[%d] = %#v, want function=%q line=%d", index, matched.inlines[index], expected.function, expected.line)
		}
	}
}

func TestRealPDBInlineFileChanges(t *testing.T) {
	path := os.Getenv("BARKTRACE_PDB_INLINE_FILES_FIXTURE")
	if path == "" {
		t.Skip("set BARKTRACE_PDB_INLINE_FILES_FIXTURE to a compiler-produced PDB with inline file changes")
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	parsed, err := parsePDBSymbols(file)
	if err != nil {
		t.Fatal(err)
	}
	for _, check := range []struct {
		address uint64
		file    string
		line    int
	}{{0x1007, "t.cpp", 3}, {0x100d, "t.inc", 1}, {0x1013, "t.inc", 2}, {0x1019, "t.cpp", 5}} {
		matched := lookupPDBSymbols(parsed, check.address, 0)
		if matched.function != "f" || len(matched.inlines) != 1 || matched.inlines[0].function != "file_change" || !strings.HasSuffix(strings.ToLower(matched.filename), check.file) || matched.line != check.line {
			t.Fatalf("real PDB file-change match at %#x = %#v, want %s:%d", check.address, matched, check.file, check.line)
		}
	}
}

func pdbFixture(t *testing.T) []byte {
	t.Helper()
	const blockSize = 512

	stringsTable := append([]byte{0}, []byte(`C:\src\fixture.cpp`)...)
	stringsTable = append(stringsTable, 0)
	checksums := make([]byte, 8)
	binary.LittleEndian.PutUint32(checksums[:4], 1)
	lines := make([]byte, 48)
	binary.LittleEndian.PutUint32(lines[:4], 0x20)
	binary.LittleEndian.PutUint16(lines[4:6], 1)
	binary.LittleEndian.PutUint16(lines[6:8], 1)
	binary.LittleEndian.PutUint32(lines[8:12], 0x30)
	binary.LittleEndian.PutUint32(lines[16:20], 2)
	binary.LittleEndian.PutUint32(lines[20:24], 36)
	binary.LittleEndian.PutUint32(lines[28:32], 17|0x80000000)
	binary.LittleEndian.PutUint32(lines[32:36], 0x10)
	binary.LittleEndian.PutUint32(lines[36:40], 18|0x80000000)
	binary.LittleEndian.PutUint16(lines[40:42], 5)
	binary.LittleEndian.PutUint16(lines[44:46], 7)
	inlineeLines := make([]byte, 4)
	for _, entry := range []struct {
		id, line uint32
	}{{0x1000, 9}, {0x1001, 6}} {
		inlineeLines = binary.LittleEndian.AppendUint32(inlineeLines, entry.id)
		inlineeLines = binary.LittleEndian.AppendUint32(inlineeLines, 0)
		inlineeLines = binary.LittleEndian.AppendUint32(inlineeLines, entry.line)
	}
	c13 := appendPDBSubsection(nil, 0xf3, stringsTable)
	c13 = appendPDBSubsection(c13, 0xf4, checksums)
	c13 = appendPDBSubsection(c13, 0xf2, lines)
	c13 = appendPDBSubsection(c13, 0xf6, inlineeLines)
	moduleStream := make([]byte, 4)
	binary.LittleEndian.PutUint32(moduleStream, 4)
	procedureOffset := uint32(len(moduleStream))
	moduleStream = append(moduleStream, pdbProcedureRecord("checkout", 0x20, 0x30, 1)...)
	outerOffset := uint32(len(moduleStream))
	moduleStream = append(moduleStream, pdbInlineSiteRecord(procedureOffset, 0x1000, []byte{11, 0x28, 4, 0x08})...)
	moduleStream = append(moduleStream, pdbInlineSiteRecord(outerOffset, 0x1001, []byte{11, 0x48, 4, 0x08})...)
	symbolBytes := len(moduleStream)
	moduleStream = append(moduleStream, c13...)

	moduleInfo := make([]byte, 64)
	binary.LittleEndian.PutUint16(moduleInfo[34:36], 7)
	binary.LittleEndian.PutUint32(moduleInfo[36:40], uint32(symbolBytes))
	binary.LittleEndian.PutUint32(moduleInfo[44:48], uint32(len(c13)))
	moduleInfo = append(moduleInfo, []byte("fixture.obj\x00fixture.obj\x00")...)
	for len(moduleInfo)%4 != 0 {
		moduleInfo = append(moduleInfo, 0)
	}
	dbi := make([]byte, 64+len(moduleInfo)+12)
	binary.LittleEndian.PutUint16(dbi[20:22], 5)
	binary.LittleEndian.PutUint32(dbi[24:28], uint32(len(moduleInfo)))
	binary.LittleEndian.PutUint32(dbi[48:52], 12)
	copy(dbi[64:], moduleInfo)
	optionalOffset := 64 + len(moduleInfo)
	for offset := optionalOffset; offset < optionalOffset+12; offset += 2 {
		binary.LittleEndian.PutUint16(dbi[offset:offset+2], 0xffff)
	}
	binary.LittleEndian.PutUint16(dbi[optionalOffset+10:optionalOffset+12], 6)

	ipiRecords := append(pdbIPIRecord(0x1601, "validate"), pdbIPIRecord(0x1601, "normalize")...)
	ipi := make([]byte, 56, 56+len(ipiRecords))
	binary.LittleEndian.PutUint32(ipi[4:8], 56)
	binary.LittleEndian.PutUint32(ipi[8:12], 0x1000)
	binary.LittleEndian.PutUint32(ipi[12:16], 0x1002)
	binary.LittleEndian.PutUint32(ipi[16:20], uint32(len(ipiRecords)))
	ipi = append(ipi, ipiRecords...)

	symbols := make([]byte, 4)
	binary.LittleEndian.PutUint32(symbols, 4)
	symbols = append(symbols, pdbPublicRecord("checkout", 0x20, 1)...)
	symbols = append(symbols, pdbPublicRecord("next_function", 0x50, 1)...)

	sections := make([]byte, 40)
	copy(sections[:8], []byte(".text"))
	binary.LittleEndian.PutUint32(sections[8:12], 0x100)
	binary.LittleEndian.PutUint32(sections[12:16], 0x1000)
	binary.LittleEndian.PutUint32(sections[16:20], 0x100)

	directory := make([]byte, 0, 64)
	directory = binary.LittleEndian.AppendUint32(directory, 8)
	for _, size := range []uint32{0xffffffff, 0, 0xffffffff, uint32(len(dbi)), uint32(len(ipi)), uint32(len(symbols)), uint32(len(sections)), uint32(len(moduleStream))} {
		directory = binary.LittleEndian.AppendUint32(directory, size)
	}
	for _, block := range []uint32{4, 5, 6, 7, 8} {
		directory = binary.LittleEndian.AppendUint32(directory, block)
	}

	fixture := make([]byte, 9*blockSize)
	copy(fixture[:32], pdb7Magic)
	binary.LittleEndian.PutUint32(fixture[32:36], blockSize)
	binary.LittleEndian.PutUint32(fixture[40:44], 9)
	binary.LittleEndian.PutUint32(fixture[44:48], uint32(len(directory)))
	binary.LittleEndian.PutUint32(fixture[52:56], 2)
	binary.LittleEndian.PutUint32(fixture[2*blockSize:2*blockSize+4], 3)
	copy(fixture[3*blockSize:], directory)
	copy(fixture[4*blockSize:], dbi)
	copy(fixture[5*blockSize:], ipi)
	copy(fixture[6*blockSize:], symbols)
	copy(fixture[7*blockSize:], sections)
	copy(fixture[8*blockSize:], moduleStream)
	return fixture
}

func pdbIPIRecord(kind uint16, name string) []byte {
	payload := make([]byte, 8+len(name)+1)
	copy(payload[8:], name)
	recordLength := 2 + len(payload)
	record := make([]byte, (2+recordLength+3)&^3)
	binary.LittleEndian.PutUint16(record[:2], uint16(len(record)-2))
	binary.LittleEndian.PutUint16(record[2:4], kind)
	copy(record[4:], payload)
	return record
}

func pdbProcedureRecord(name string, offset, size uint32, segment uint16) []byte {
	payload := make([]byte, 35+len(name)+1)
	binary.LittleEndian.PutUint32(payload[12:16], size)
	binary.LittleEndian.PutUint32(payload[28:32], offset)
	binary.LittleEndian.PutUint16(payload[32:34], segment)
	copy(payload[35:], name)
	recordLength := 2 + len(payload)
	record := make([]byte, (2+recordLength+3)&^3)
	binary.LittleEndian.PutUint16(record[:2], uint16(len(record)-2))
	binary.LittleEndian.PutUint16(record[2:4], 0x1110)
	copy(record[4:], payload)
	return record
}

func pdbInlineSiteRecord(parent, inlinee uint32, annotations []byte) []byte {
	payload := make([]byte, 12, 12+len(annotations))
	binary.LittleEndian.PutUint32(payload[:4], parent)
	binary.LittleEndian.PutUint32(payload[8:12], inlinee)
	payload = append(payload, annotations...)
	recordLength := 2 + len(payload)
	record := make([]byte, (2+recordLength+3)&^3)
	binary.LittleEndian.PutUint16(record[:2], uint16(len(record)-2))
	binary.LittleEndian.PutUint16(record[2:4], 0x114d)
	copy(record[4:], payload)
	return record
}

func appendPDBSubsection(destination []byte, kind uint32, payload []byte) []byte {
	destination = binary.LittleEndian.AppendUint32(destination, kind)
	destination = binary.LittleEndian.AppendUint32(destination, uint32(len(payload)))
	destination = append(destination, payload...)
	for len(destination)%4 != 0 {
		destination = append(destination, 0)
	}
	return destination
}

func pdbPublicRecord(name string, offset uint32, segment uint16) []byte {
	payload := make([]byte, 10+len(name)+1)
	binary.LittleEndian.PutUint32(payload[:4], 3)
	binary.LittleEndian.PutUint32(payload[4:8], offset)
	binary.LittleEndian.PutUint16(payload[8:10], segment)
	copy(payload[10:], name)
	recordLength := 2 + len(payload)
	record := make([]byte, (2+recordLength+3)&^3)
	binary.LittleEndian.PutUint16(record[:2], uint16(recordLength))
	binary.LittleEndian.PutUint16(record[2:4], 0x110e)
	copy(record[4:], payload)
	return record
}
