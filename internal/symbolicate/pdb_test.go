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
	c13 := appendPDBSubsection(nil, 0xf3, stringsTable)
	c13 = appendPDBSubsection(c13, 0xf4, checksums)
	c13 = appendPDBSubsection(c13, 0xf2, lines)
	moduleStream := make([]byte, 4, 4+len(c13))
	binary.LittleEndian.PutUint32(moduleStream, 4)
	moduleStream = append(moduleStream, c13...)

	moduleInfo := make([]byte, 64)
	binary.LittleEndian.PutUint16(moduleInfo[34:36], 6)
	binary.LittleEndian.PutUint32(moduleInfo[36:40], 4)
	binary.LittleEndian.PutUint32(moduleInfo[44:48], uint32(len(c13)))
	moduleInfo = append(moduleInfo, []byte("fixture.obj\x00fixture.obj\x00")...)
	for len(moduleInfo)%4 != 0 {
		moduleInfo = append(moduleInfo, 0)
	}
	dbi := make([]byte, 64+len(moduleInfo)+12)
	binary.LittleEndian.PutUint16(dbi[20:22], 4)
	binary.LittleEndian.PutUint32(dbi[24:28], uint32(len(moduleInfo)))
	binary.LittleEndian.PutUint32(dbi[48:52], 12)
	copy(dbi[64:], moduleInfo)
	optionalOffset := 64 + len(moduleInfo)
	for offset := optionalOffset; offset < optionalOffset+12; offset += 2 {
		binary.LittleEndian.PutUint16(dbi[offset:offset+2], 0xffff)
	}
	binary.LittleEndian.PutUint16(dbi[optionalOffset+10:optionalOffset+12], 5)

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
	directory = binary.LittleEndian.AppendUint32(directory, 7)
	for _, size := range []uint32{0xffffffff, 0, 0xffffffff, uint32(len(dbi)), uint32(len(symbols)), uint32(len(sections)), uint32(len(moduleStream))} {
		directory = binary.LittleEndian.AppendUint32(directory, size)
	}
	for _, block := range []uint32{4, 5, 6, 7} {
		directory = binary.LittleEndian.AppendUint32(directory, block)
	}

	fixture := make([]byte, 8*blockSize)
	copy(fixture[:32], pdb7Magic)
	binary.LittleEndian.PutUint32(fixture[32:36], blockSize)
	binary.LittleEndian.PutUint32(fixture[40:44], 8)
	binary.LittleEndian.PutUint32(fixture[44:48], uint32(len(directory)))
	binary.LittleEndian.PutUint32(fixture[52:56], 2)
	binary.LittleEndian.PutUint32(fixture[2*blockSize:2*blockSize+4], 3)
	copy(fixture[3*blockSize:], directory)
	copy(fixture[4*blockSize:], dbi)
	copy(fixture[5*blockSize:], symbols)
	copy(fixture[6*blockSize:], sections)
	copy(fixture[7*blockSize:], moduleStream)
	return fixture
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
