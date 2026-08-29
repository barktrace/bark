package symbolicate

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"os"
	"testing"
	"unicode/utf16"
)

const minidumpFixtureDebugID = "12345678-1234-5678-90ab-cdef01234567-1"

func TestMinidumpEventUnwindsBreakpadCFI(t *testing.T) {
	st := symbolicationStore(t)
	putDebugArtifactBytes(t, st, minidumpFixtureDebugID, []byte(`MODULE windows x86_64 123456781234567890ABCDEF012345671 app.pdb
FUNC 1000 100 0 crash_handler
1000 100 42 0
FUNC 1100 100 0 caller
1100 100 21 0
STACK CFI INIT 1000 300 .cfa: $rsp 16 + .ra: .cfa -8 + ^
`))
	event, err := MinidumpEvent(context.Background(), st, "project", minidumpFixture(t), []byte(`{"event_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","release":"native@1.0"}`))
	if err != nil {
		t.Fatal(err)
	}
	var payload map[string]any
	if err := json.Unmarshal(event, &payload); err != nil {
		t.Fatal(err)
	}
	frames := minidumpEventFrames(t, payload)
	if len(frames) != 2 || frames[0]["instruction_addr"] != "0x140001120" || frames[0]["trust"] != "cfi" || frames[1]["instruction_addr"] != "0x140001010" || frames[1]["trust"] != "context" {
		t.Fatalf("unwound minidump frames = %#v", frames)
	}
	processed, changed, err := ProcessEvent(context.Background(), st, "project", "release", event)
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("unwound minidump frames were not symbolicated")
	}
	if err := json.Unmarshal(processed, &payload); err != nil {
		t.Fatal(err)
	}
	frames = minidumpEventFrames(t, payload)
	if frames[0]["function"] != "caller" || frames[1]["function"] != "crash_handler" {
		t.Fatalf("symbolicated minidump frames = %#v", frames)
	}
	images := payload["debug_meta"].(map[string]any)["images"].([]any)
	if images[0].(map[string]any)["debug_id"] != minidumpFixtureDebugID {
		t.Fatalf("minidump debug image = %#v", images[0])
	}
}

func TestMinidumpFramePointerFallback(t *testing.T) {
	st := symbolicationStore(t)
	dump, err := parseMinidump(minidumpFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	dump.registers["rbp"] = dump.stackAddress + 32
	binary.LittleEndian.PutUint64(dump.stack[32:40], dump.stackAddress+48)
	binary.LittleEndian.PutUint64(dump.stack[40:48], 0x140001121)
	frames := unwindMinidump(context.Background(), st, "project", dump)
	if len(frames) != 2 || frames[0].(map[string]any)["trust"] != "fp" || frames[1].(map[string]any)["trust"] != "context" {
		t.Fatalf("frame-pointer minidump frames = %#v", frames)
	}
}

func TestMinidumpEventUnwindsAllCapturedThreads(t *testing.T) {
	st := symbolicationStore(t)
	event, err := MinidumpEvent(context.Background(), st, "project", multiThreadMinidumpFixture(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	var payload map[string]any
	if err := json.Unmarshal(event, &payload); err != nil {
		t.Fatal(err)
	}
	values := payload["threads"].(map[string]any)["values"].([]any)
	if len(values) != 2 {
		t.Fatalf("minidump threads = %#v, want 2", values)
	}
	byID := make(map[string]map[string]any, len(values))
	for _, value := range values {
		thread := value.(map[string]any)
		byID[thread["id"].(string)] = thread
	}
	crashed := byID["7"]
	background := byID["9"]
	if crashed == nil || crashed["crashed"] != true || crashed["current"] != true {
		t.Fatalf("crashing thread = %#v", crashed)
	}
	if background == nil || background["crashed"] != false || background["current"] != false {
		t.Fatalf("background thread = %#v", background)
	}
	backgroundFrames := background["stacktrace"].(map[string]any)["frames"].([]any)
	if len(backgroundFrames) != 1 || backgroundFrames[0].(map[string]any)["instruction_addr"] != "0x140001110" {
		t.Fatalf("background frames = %#v", backgroundFrames)
	}
	if frames := minidumpEventFrames(t, payload); len(frames) == 0 || frames[len(frames)-1]["instruction_addr"] != "0x140001010" {
		t.Fatalf("exception frames = %#v", frames)
	}
}

func TestParseMinidumpRejectsTruncatedStreams(t *testing.T) {
	fixture := minidumpFixture(t)
	if _, err := parseMinidump(fixture[:100]); err == nil {
		t.Fatal("truncated minidump was accepted")
	}
	malformed := append([]byte(nil), fixture...)
	binary.LittleEndian.PutUint32(malformed[8:12], maxMinidumpStreams+1)
	if _, err := parseMinidump(malformed); err == nil {
		t.Fatal("oversized minidump stream directory was accepted")
	}
}

func TestRealMinidumpFixture(t *testing.T) {
	path := os.Getenv("BARKTRACE_MINIDUMP_FIXTURE")
	if path == "" {
		t.Skip("set BARKTRACE_MINIDUMP_FIXTURE to a real minidump")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := parseMinidump(raw)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.architecture == "" || parsed.threadID == 0 || parsed.registers[instructionRegister(parsed.architecture)] == 0 || len(parsed.stack) == 0 {
		t.Fatalf("real minidump parse = arch=%q thread=%d address=%#x stack=%d modules=%d", parsed.architecture, parsed.threadID, parsed.address, len(parsed.stack), len(parsed.modules))
	}
	t.Logf("real minidump: arch=%s thread=%d stack=%d modules=%d first_debug_id=%q", parsed.architecture, parsed.threadID, len(parsed.stack), len(parsed.modules), func() string {
		if len(parsed.modules) == 0 {
			return ""
		}
		return parsed.modules[0].debugID
	}())
	st := symbolicationStore(t)
	if symbolPath := os.Getenv("BARKTRACE_MINIDUMP_SYMBOL_FIXTURE"); symbolPath != "" {
		symbols, readErr := os.ReadFile(symbolPath)
		if readErr != nil {
			t.Fatal(readErr)
		}
		if len(parsed.modules) == 0 || parsed.modules[0].debugID == "" {
			t.Fatal("real minidump has no debug identifier for symbol fixture")
		}
		putDebugArtifactBytes(t, st, parsed.modules[0].debugID, symbols)
	}
	event, err := MinidumpEvent(context.Background(), st, "project", raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	var payload map[string]any
	if json.Unmarshal(event, &payload) != nil || len(minidumpEventFrames(t, payload)) == 0 {
		t.Fatal("real minidump did not produce a native event")
	}
	if os.Getenv("BARKTRACE_MINIDUMP_SYMBOL_FIXTURE") != "" {
		foundCFI := false
		for _, frame := range minidumpEventFrames(t, payload) {
			foundCFI = foundCFI || frame["trust"] == "cfi"
		}
		if !foundCFI {
			t.Fatalf("real minidump did not produce a CFI frame: %#v", minidumpEventFrames(t, payload))
		}
	}
}

func TestBreakpadCFIExpressions(t *testing.T) {
	memory := minidumpMemory{address: 0x1000, data: make([]byte, 32), pointerSize: 8}
	binary.LittleEndian.PutUint64(memory.data[8:16], 0xfeedface)
	value, ok := evaluateBreakpadCFI([]string{"$rsp", "16", "+", "-8", "+", "^"}, map[string]uint64{"$rsp": 0x1000}, memory)
	if !ok || value != 0xfeedface {
		t.Fatalf("CFI expression = %#x, ok=%v", value, ok)
	}
	if _, ok := evaluateBreakpadCFI([]string{"$missing", "8", "+"}, nil, memory); ok {
		t.Fatal("CFI expression with an unknown register was accepted")
	}
}

func TestMinidumpX86AndARM64Contexts(t *testing.T) {
	x86 := make([]byte, 204)
	binary.LittleEndian.PutUint32(x86[180:184], 0x7000)
	binary.LittleEndian.PutUint32(x86[184:188], 0x4010)
	binary.LittleEndian.PutUint32(x86[196:200], 0x6ff0)
	x86Registers, err := parseMinidumpContext(x86, "x86")
	if err != nil || x86Registers["eip"] != 0x4010 || x86Registers["esp"] != 0x6ff0 || x86Registers["ebp"] != 0x7000 {
		t.Fatalf("x86 context = %#v, err=%v", x86Registers, err)
	}
	arm64 := make([]byte, 272)
	binary.LittleEndian.PutUint64(arm64[240:248], 0x9000)
	binary.LittleEndian.PutUint64(arm64[248:256], 0x5020)
	binary.LittleEndian.PutUint64(arm64[256:264], 0x8fe0)
	binary.LittleEndian.PutUint64(arm64[264:272], 0x5010)
	armRegisters, err := parseMinidumpContext(arm64, "arm64")
	if err != nil || armRegisters["pc"] != 0x5010 || armRegisters["sp"] != 0x8fe0 || armRegisters["fp"] != 0x9000 || armRegisters["x29"] != 0x9000 || armRegisters["x30"] != 0x5020 {
		t.Fatalf("ARM64 context = %#v, err=%v", armRegisters, err)
	}
}

func minidumpEventFrames(t *testing.T, payload map[string]any) []map[string]any {
	t.Helper()
	exception := payload["exception"].(map[string]any)
	value := exception["values"].([]any)[0].(map[string]any)
	rawFrames := value["stacktrace"].(map[string]any)["frames"].([]any)
	frames := make([]map[string]any, 0, len(rawFrames))
	for _, frame := range rawFrames {
		frames = append(frames, frame.(map[string]any))
	}
	return frames
}

func minidumpFixture(t *testing.T) []byte {
	t.Helper()
	const (
		systemRVA    = 80
		exceptionRVA = 88
		threadRVA    = 256
		contextRVA   = 320
		stackRVA     = 576
		moduleRVA    = 640
		nameRVA      = 752
		codeViewRVA  = 800
		stackAddress = 0x70000000
		imageBase    = 0x140000000
	)
	fixture := make([]byte, 864)
	copy(fixture[:4], "MDMP")
	binary.LittleEndian.PutUint32(fixture[4:8], 0xa793)
	binary.LittleEndian.PutUint32(fixture[8:12], 4)
	binary.LittleEndian.PutUint32(fixture[12:16], 32)
	for index, stream := range []struct {
		kind, size, rva uint32
	}{{minidumpSystemInfoStream, 2, systemRVA}, {minidumpExceptionStream, 168, exceptionRVA}, {minidumpThreadListStream, 52, threadRVA}, {minidumpModuleListStream, 112, moduleRVA}} {
		offset := 32 + index*12
		binary.LittleEndian.PutUint32(fixture[offset:offset+4], stream.kind)
		binary.LittleEndian.PutUint32(fixture[offset+4:offset+8], stream.size)
		binary.LittleEndian.PutUint32(fixture[offset+8:offset+12], stream.rva)
	}
	binary.LittleEndian.PutUint16(fixture[systemRVA:systemRVA+2], 9)
	binary.LittleEndian.PutUint32(fixture[exceptionRVA:exceptionRVA+4], 7)
	binary.LittleEndian.PutUint32(fixture[exceptionRVA+8:exceptionRVA+12], 0xc0000005)
	binary.LittleEndian.PutUint64(fixture[exceptionRVA+24:exceptionRVA+32], imageBase+0x1010)
	binary.LittleEndian.PutUint32(fixture[exceptionRVA+160:exceptionRVA+164], 256)
	binary.LittleEndian.PutUint32(fixture[exceptionRVA+164:exceptionRVA+168], contextRVA)
	binary.LittleEndian.PutUint32(fixture[threadRVA:threadRVA+4], 1)
	binary.LittleEndian.PutUint32(fixture[threadRVA+4:threadRVA+8], 7)
	binary.LittleEndian.PutUint64(fixture[threadRVA+28:threadRVA+36], stackAddress)
	binary.LittleEndian.PutUint32(fixture[threadRVA+36:threadRVA+40], 64)
	binary.LittleEndian.PutUint32(fixture[threadRVA+40:threadRVA+44], stackRVA)
	binary.LittleEndian.PutUint32(fixture[threadRVA+44:threadRVA+48], 256)
	binary.LittleEndian.PutUint32(fixture[threadRVA+48:threadRVA+52], contextRVA)
	binary.LittleEndian.PutUint64(fixture[contextRVA+152:contextRVA+160], stackAddress)
	binary.LittleEndian.PutUint64(fixture[contextRVA+160:contextRVA+168], 0)
	binary.LittleEndian.PutUint64(fixture[contextRVA+248:contextRVA+256], imageBase+0x1010)
	binary.LittleEndian.PutUint64(fixture[stackRVA+8:stackRVA+16], imageBase+0x1121)
	binary.LittleEndian.PutUint32(fixture[moduleRVA:moduleRVA+4], 1)
	binary.LittleEndian.PutUint64(fixture[moduleRVA+4:moduleRVA+12], imageBase)
	binary.LittleEndian.PutUint32(fixture[moduleRVA+12:moduleRVA+16], 0x3000)
	binary.LittleEndian.PutUint32(fixture[moduleRVA+24:moduleRVA+28], nameRVA)
	binary.LittleEndian.PutUint32(fixture[moduleRVA+80:moduleRVA+84], 32)
	binary.LittleEndian.PutUint32(fixture[moduleRVA+84:moduleRVA+88], codeViewRVA)
	name := utf16.Encode([]rune(`C:\apps\app.exe`))
	binary.LittleEndian.PutUint32(fixture[nameRVA:nameRVA+4], uint32(len(name)*2))
	for index, unit := range name {
		binary.LittleEndian.PutUint16(fixture[nameRVA+4+index*2:nameRVA+6+index*2], unit)
	}
	copy(fixture[codeViewRVA:codeViewRVA+4], "RSDS")
	binary.LittleEndian.PutUint32(fixture[codeViewRVA+4:codeViewRVA+8], 0x12345678)
	binary.LittleEndian.PutUint16(fixture[codeViewRVA+8:codeViewRVA+10], 0x1234)
	binary.LittleEndian.PutUint16(fixture[codeViewRVA+10:codeViewRVA+12], 0x5678)
	copy(fixture[codeViewRVA+12:codeViewRVA+20], []byte{0x90, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67})
	binary.LittleEndian.PutUint32(fixture[codeViewRVA+20:codeViewRVA+24], 1)
	copy(fixture[codeViewRVA+24:codeViewRVA+32], "app.pdb\x00")
	return fixture
}

func multiThreadMinidumpFixture(t *testing.T) []byte {
	t.Helper()
	const (
		threadListRVA      = 864
		secondContextRVA   = 964
		secondStackRVA     = 1220
		secondStackAddress = 0x71000000
		secondInstruction  = 0x140001110
	)
	dump := append(minidumpFixture(t), make([]byte, 420)...)
	// Replace the thread-list directory with a two-entry list appended after the
	// original fixture so none of its context, stack, or module data moves.
	binary.LittleEndian.PutUint32(dump[60:64], 100)
	binary.LittleEndian.PutUint32(dump[64:68], threadListRVA)
	binary.LittleEndian.PutUint32(dump[threadListRVA:threadListRVA+4], 2)
	copy(dump[threadListRVA+4:threadListRVA+52], dump[260:308])
	second := threadListRVA + 52
	binary.LittleEndian.PutUint32(dump[second:second+4], 9)
	binary.LittleEndian.PutUint64(dump[second+24:second+32], secondStackAddress)
	binary.LittleEndian.PutUint32(dump[second+32:second+36], 64)
	binary.LittleEndian.PutUint32(dump[second+36:second+40], secondStackRVA)
	binary.LittleEndian.PutUint32(dump[second+40:second+44], 256)
	binary.LittleEndian.PutUint32(dump[second+44:second+48], secondContextRVA)
	binary.LittleEndian.PutUint64(dump[secondContextRVA+152:secondContextRVA+160], secondStackAddress)
	binary.LittleEndian.PutUint64(dump[secondContextRVA+248:secondContextRVA+256], secondInstruction)
	return dump
}

func TestReadMinidumpFixtureSignature(t *testing.T) {
	if !bytes.Equal(minidumpFixture(t)[:4], []byte("MDMP")) {
		t.Fatal("fixture signature")
	}
}
