package symbolicate

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"unicode/utf16"

	"github.com/barktrace/bark/internal/store"
	"github.com/google/uuid"
)

const (
	maxMinidumpBytes       = 32 << 20
	maxMinidumpStreams     = 1024
	maxMinidumpModules     = 4096
	maxMinidumpThreads     = 256
	maxMinidumpFrames      = 256
	maxMinidumpEventFrames = 2048

	minidumpThreadListStream = 3
	minidumpModuleListStream = 4
	minidumpExceptionStream  = 6
	minidumpSystemInfoStream = 7
)

type minidump struct {
	architecture    string
	operatingSystem string
	threadID        uint32
	exception       uint32
	address         uint64
	registers       map[string]uint64
	stackAddress    uint64
	stack           []byte
	threads         []minidumpThread
	modules         []minidumpModule
}

type minidumpThread struct {
	id           uint32
	registers    map[string]uint64
	stackAddress uint64
	stack        []byte
}

type minidumpModule struct {
	base, size uint64
	name       string
	debugID    string
}

// MinidumpEvent converts a bounded Breakpad/Crashpad minidump into a Sentry event and
// unwinds its bounded thread list with uploaded Breakpad CFI where available.
func MinidumpEvent(ctx context.Context, st *store.Store, projectID string, raw, metadata []byte) ([]byte, error) {
	parsed, err := parseMinidump(raw)
	if err != nil {
		return nil, err
	}
	payload := make(map[string]any)
	if len(metadata) > 0 && json.Unmarshal(metadata, &payload) != nil {
		return nil, errors.New("invalid minidump event metadata")
	}
	if payload == nil {
		payload = make(map[string]any)
	}
	unwinders := loadBreakpadUnwinders(ctx, st, projectID, parsed.modules, parsed.architecture)
	frames := unwindMinidumpThread(parsed, minidumpThread{
		id: parsed.threadID, registers: parsed.registers, stackAddress: parsed.stackAddress, stack: parsed.stack,
	}, unwinders)
	if len(frames) == 0 {
		return nil, errors.New("minidump contains no unwindable instruction address")
	}
	if strings.TrimSpace(stringValue(payload["event_id"])) == "" {
		payload["event_id"] = strings.ReplaceAll(uuid.NewString(), "-", "")
	}
	if stringValue(payload["platform"]) == "" {
		payload["platform"] = "native"
	}
	if stringValue(payload["level"]) == "" {
		payload["level"] = "fatal"
	}
	payload["exception"] = map[string]any{"values": []any{map[string]any{
		"type":       minidumpExceptionName(parsed.exception),
		"value":      fmt.Sprintf("native exception 0x%08x at 0x%x", parsed.exception, parsed.address),
		"mechanism":  map[string]any{"type": "minidump", "handled": false},
		"stacktrace": map[string]any{"frames": frames},
	}}}
	orderedThreads := make([]minidumpThread, 0, len(parsed.threads))
	orderedThreads = append(orderedThreads, minidumpThread{
		id: parsed.threadID, registers: parsed.registers, stackAddress: parsed.stackAddress, stack: parsed.stack,
	})
	for _, thread := range parsed.threads {
		if thread.id != parsed.threadID {
			orderedThreads = append(orderedThreads, thread)
		}
	}
	threadValues := make([]any, 0, len(orderedThreads))
	totalFrames := 0
	for _, thread := range orderedThreads {
		threadFrames := frames
		if thread.id != parsed.threadID {
			threadFrames = unwindMinidumpThread(parsed, thread, unwinders)
		}
		if len(threadFrames) == 0 || totalFrames >= maxMinidumpEventFrames {
			continue
		}
		if remaining := maxMinidumpEventFrames - totalFrames; len(threadFrames) > remaining {
			threadFrames = threadFrames[len(threadFrames)-remaining:]
		}
		totalFrames += len(threadFrames)
		crashed := thread.id == parsed.threadID
		threadValues = append(threadValues, map[string]any{
			"id": fmt.Sprintf("%d", thread.id), "crashed": crashed, "current": crashed,
			"stacktrace": map[string]any{"frames": threadFrames},
		})
	}
	payload["threads"] = map[string]any{"values": threadValues}
	contexts, _ := payload["contexts"].(map[string]any)
	if contexts == nil {
		contexts = make(map[string]any)
	}
	device, _ := contexts["device"].(map[string]any)
	if device == nil {
		device = make(map[string]any)
	}
	device["arch"] = parsed.architecture
	contexts["device"] = device
	if _, exists := contexts["os"]; !exists {
		contexts["os"] = map[string]any{"name": parsed.operatingSystem}
	}
	payload["contexts"] = contexts
	images := make([]any, 0, len(parsed.modules))
	for _, module := range parsed.modules {
		image := map[string]any{
			"type": minidumpImageType(parsed.operatingSystem), "image_addr": fmt.Sprintf("0x%x", module.base),
			"image_size": fmt.Sprintf("0x%x", module.size), "code_file": module.name,
		}
		if module.debugID != "" {
			image["debug_id"] = module.debugID
		}
		images = append(images, image)
	}
	payload["debug_meta"] = map[string]any{"images": images}
	return json.Marshal(payload)
}

func parseMinidump(data []byte) (*minidump, error) {
	if len(data) < 32 || len(data) > maxMinidumpBytes || string(data[:4]) != "MDMP" {
		return nil, errors.New("invalid or oversized minidump")
	}
	streamCount := binary.LittleEndian.Uint32(data[8:12])
	directoryRVA := binary.LittleEndian.Uint32(data[12:16])
	if streamCount == 0 || streamCount > maxMinidumpStreams {
		return nil, errors.New("invalid minidump stream count")
	}
	directory, ok := minidumpSlice(data, directoryRVA, uint64(streamCount)*12)
	if !ok {
		return nil, errors.New("truncated minidump stream directory")
	}
	streams := make(map[uint32][]byte)
	for index := uint32(0); index < streamCount; index++ {
		offset := index * 12
		kind := binary.LittleEndian.Uint32(directory[offset : offset+4])
		size := binary.LittleEndian.Uint32(directory[offset+4 : offset+8])
		rva := binary.LittleEndian.Uint32(directory[offset+8 : offset+12])
		if stream, valid := minidumpSlice(data, rva, uint64(size)); valid {
			if _, exists := streams[kind]; !exists {
				streams[kind] = stream
			}
		}
	}
	architecture, pointerSize := minidumpArchitecture(streams[minidumpSystemInfoStream])
	if pointerSize == 0 {
		return nil, errors.New("unsupported minidump architecture")
	}
	threadID, exceptionCode, exceptionAddress, contextRVA, contextSize, err := parseMinidumpException(streams[minidumpExceptionStream])
	if err != nil {
		return nil, err
	}
	threads, err := parseMinidumpThreads(data, streams[minidumpThreadListStream], architecture, threadID, contextRVA, contextSize)
	if err != nil {
		return nil, err
	}
	var crashed minidumpThread
	for _, thread := range threads {
		if thread.id == threadID {
			crashed = thread
			break
		}
	}
	if crashed.registers == nil {
		return nil, errors.New("minidump exception thread was not found")
	}
	if exceptionAddress == 0 {
		exceptionAddress = crashed.registers[instructionRegister(architecture)]
	}
	return &minidump{
		architecture: architecture, operatingSystem: minidumpOperatingSystem(streams[minidumpSystemInfoStream]), threadID: threadID, exception: exceptionCode,
		address: exceptionAddress, registers: crashed.registers, stackAddress: crashed.stackAddress,
		stack: crashed.stack, threads: threads, modules: parseMinidumpModules(data, streams[minidumpModuleListStream]),
	}, nil
}

func minidumpOperatingSystem(data []byte) string {
	if len(data) < 24 {
		return "windows"
	}
	switch binary.LittleEndian.Uint32(data[20:24]) {
	case 0x8101:
		return "macos"
	case 0x8102:
		return "ios"
	case 0x8000, 0x8201:
		return "linux"
	case 0x8203:
		return "android"
	default:
		return "windows"
	}
}

func minidumpImageType(operatingSystem string) string {
	switch operatingSystem {
	case "macos", "ios":
		return "macho"
	case "linux", "android":
		return "elf"
	default:
		return "pe"
	}
}

func minidumpSlice(data []byte, rva uint32, size uint64) ([]byte, bool) {
	end := uint64(rva) + size
	if end < uint64(rva) || end > uint64(len(data)) {
		return nil, false
	}
	return data[int(rva):int(end)], true
}

func minidumpArchitecture(data []byte) (string, int) {
	if len(data) < 2 {
		return "", 0
	}
	switch binary.LittleEndian.Uint16(data[:2]) {
	case 0:
		return "x86", 4
	case 9:
		return "x86_64", 8
	case 12:
		return "arm64", 8
	default:
		return "", 0
	}
}

func parseMinidumpException(data []byte) (threadID, code uint32, address uint64, contextRVA, contextSize uint32, err error) {
	if len(data) < 168 {
		err = errors.New("minidump exception stream is missing or truncated")
		return
	}
	threadID = binary.LittleEndian.Uint32(data[:4])
	code = binary.LittleEndian.Uint32(data[8:12])
	address = binary.LittleEndian.Uint64(data[24:32])
	contextSize = binary.LittleEndian.Uint32(data[160:164])
	contextRVA = binary.LittleEndian.Uint32(data[164:168])
	return
}

func parseMinidumpThreads(file, data []byte, architecture string, crashedID, exceptionContextRVA, exceptionContextSize uint32) ([]minidumpThread, error) {
	if len(data) < 4 {
		return nil, errors.New("minidump thread list is missing or truncated")
	}
	count := binary.LittleEndian.Uint32(data[:4])
	if count == 0 || count > 4096 || uint64(4)+uint64(count)*48 > uint64(len(data)) {
		return nil, errors.New("invalid minidump thread list")
	}
	threads := make([]minidumpThread, 0, min(int(count), maxMinidumpThreads))
	crashedFound := false
	for index := uint32(0); index < count; index++ {
		offset := 4 + int(index)*48
		threadID := binary.LittleEndian.Uint32(data[offset : offset+4])
		if len(threads) >= maxMinidumpThreads && threadID != crashedID {
			continue
		}
		stackAddress := binary.LittleEndian.Uint64(data[offset+24 : offset+32])
		stackSize := binary.LittleEndian.Uint32(data[offset+32 : offset+36])
		stackRVA := binary.LittleEndian.Uint32(data[offset+36 : offset+40])
		stack, _ := minidumpSlice(file, stackRVA, uint64(stackSize))
		contextSize := binary.LittleEndian.Uint32(data[offset+40 : offset+44])
		contextRVA := binary.LittleEndian.Uint32(data[offset+44 : offset+48])
		if threadID == crashedID && exceptionContextRVA != 0 && exceptionContextSize != 0 {
			contextRVA, contextSize = exceptionContextRVA, exceptionContextSize
		}
		contextData, ok := minidumpSlice(file, contextRVA, uint64(contextSize))
		if !ok {
			if threadID == crashedID {
				return nil, errors.New("truncated minidump thread context")
			}
			continue
		}
		registers, err := parseMinidumpContext(contextData, architecture)
		if err != nil {
			if threadID == crashedID {
				return nil, err
			}
			continue
		}
		thread := minidumpThread{id: threadID, registers: registers, stackAddress: stackAddress, stack: stack}
		if threadID == crashedID {
			crashedFound = true
			if len(threads) >= maxMinidumpThreads {
				threads[len(threads)-1] = thread
				continue
			}
		}
		threads = append(threads, thread)
	}
	if !crashedFound {
		return nil, errors.New("minidump exception thread was not found")
	}
	return threads, nil
}

func parseMinidumpContext(data []byte, architecture string) (map[string]uint64, error) {
	registers := make(map[string]uint64)
	switch architecture {
	case "x86_64":
		if len(data) < 256 {
			return nil, errors.New("truncated AMD64 minidump context")
		}
		names := []string{"rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rip"}
		for index, name := range names {
			registers[name] = binary.LittleEndian.Uint64(data[120+index*8 : 128+index*8])
		}
	case "x86":
		if len(data) < 204 {
			return nil, errors.New("truncated x86 minidump context")
		}
		for name, offset := range map[string]int{"edi": 156, "esi": 160, "ebx": 164, "edx": 168, "ecx": 172, "eax": 176, "ebp": 180, "eip": 184, "esp": 196} {
			registers[name] = uint64(binary.LittleEndian.Uint32(data[offset : offset+4]))
		}
	case "arm64":
		if len(data) < 272 {
			return nil, errors.New("truncated ARM64 minidump context")
		}
		for index := 0; index <= 28; index++ {
			registers[fmt.Sprintf("x%d", index)] = binary.LittleEndian.Uint64(data[8+index*8 : 16+index*8])
		}
		registers["fp"] = binary.LittleEndian.Uint64(data[240:248])
		registers["lr"] = binary.LittleEndian.Uint64(data[248:256])
		registers["x29"] = registers["fp"]
		registers["x30"] = registers["lr"]
		registers["sp"] = binary.LittleEndian.Uint64(data[256:264])
		registers["pc"] = binary.LittleEndian.Uint64(data[264:272])
	}
	return registers, nil
}

func parseMinidumpModules(file, data []byte) []minidumpModule {
	if len(data) < 4 {
		return nil
	}
	count := binary.LittleEndian.Uint32(data[:4])
	if count > maxMinidumpModules || uint64(4)+uint64(count)*108 > uint64(len(data)) {
		return nil
	}
	modules := make([]minidumpModule, 0, count)
	for index := uint32(0); index < count; index++ {
		offset := 4 + int(index)*108
		module := minidumpModule{
			base: binary.LittleEndian.Uint64(data[offset : offset+8]),
			size: uint64(binary.LittleEndian.Uint32(data[offset+8 : offset+12])),
			name: minidumpUTF16(file, binary.LittleEndian.Uint32(data[offset+20:offset+24])),
		}
		cvSize := binary.LittleEndian.Uint32(data[offset+76 : offset+80])
		cvRVA := binary.LittleEndian.Uint32(data[offset+80 : offset+84])
		if codeView, ok := minidumpSlice(file, cvRVA, uint64(cvSize)); ok {
			module.debugID = minidumpCodeViewID(codeView)
		}
		if module.size > 0 && module.base+module.size >= module.base {
			modules = append(modules, module)
		}
	}
	return modules
}

func minidumpUTF16(data []byte, rva uint32) string {
	header, ok := minidumpSlice(data, rva, 4)
	if !ok {
		return ""
	}
	size := binary.LittleEndian.Uint32(header)
	if size > 1<<20 || size%2 != 0 {
		return ""
	}
	raw, ok := minidumpSlice(data, rva+4, uint64(size))
	if !ok {
		return ""
	}
	units := make([]uint16, len(raw)/2)
	for index := range units {
		units[index] = binary.LittleEndian.Uint16(raw[index*2 : index*2+2])
	}
	return strings.TrimSpace(string(utf16.Decode(units)))
}

func minidumpCodeViewID(data []byte) string {
	if len(data) >= 5 && string(data[:4]) == "BpEL" {
		buildID := make([]byte, 16)
		copy(buildID, data[4:])
		if bytesToUint64(buildID) == 0 && bytesToUint64(buildID[8:]) == 0 {
			return ""
		}
		return minidumpGUID(buildID, 0)
	}
	if len(data) < 24 || string(data[:4]) != "RSDS" {
		return ""
	}
	return minidumpGUID(data[4:20], binary.LittleEndian.Uint32(data[20:24]))
}

func minidumpGUID(data []byte, age uint32) string {
	if len(data) < 16 {
		return ""
	}
	guid := fmt.Sprintf("%08x-%04x-%04x-%02x%02x-%012x",
		binary.LittleEndian.Uint32(data[:4]), binary.LittleEndian.Uint16(data[4:6]),
		binary.LittleEndian.Uint16(data[6:8]), data[8], data[9], bytesToUint48(data[10:16]))
	return fmt.Sprintf("%s-%x", guid, age)
}

func bytesToUint48(data []byte) uint64 {
	if len(data) < 6 {
		return 0
	}
	return uint64(data[0])<<40 | uint64(data[1])<<32 | uint64(data[2])<<24 | uint64(data[3])<<16 | uint64(data[4])<<8 | uint64(data[5])
}

func bytesToUint64(data []byte) uint64 {
	if len(data) < 8 {
		return 0
	}
	return binary.LittleEndian.Uint64(data[:8])
}

func instructionRegister(architecture string) string {
	switch architecture {
	case "x86":
		return "eip"
	case "arm64":
		return "pc"
	default:
		return "rip"
	}
}

func stackRegister(architecture string) string {
	if architecture == "x86" {
		return "esp"
	}
	if architecture == "x86_64" {
		return "rsp"
	}
	return "sp"
}

func frameRegister(architecture string) string {
	switch architecture {
	case "x86":
		return "ebp"
	case "arm64":
		return "fp"
	default:
		return "rbp"
	}
}

func (m *minidump) module(address uint64) (minidumpModule, bool) {
	for _, module := range m.modules {
		if address >= module.base && address-module.base < module.size {
			return module, true
		}
	}
	return minidumpModule{}, false
}

func minidumpFrame(address uint64, module minidumpModule, trust string) map[string]any {
	frame := map[string]any{"instruction_addr": fmt.Sprintf("0x%x", address), "function": fmt.Sprintf("0x%x", address), "trust": trust}
	if module.name != "" {
		frame["package"] = module.name
		frame["module"] = strings.TrimSuffix(filepath.Base(strings.ReplaceAll(module.name, `\`, "/")), filepath.Ext(module.name))
	}
	return frame
}

func minidumpExceptionName(code uint32) string {
	switch code {
	case 0xc0000005:
		return "EXCEPTION_ACCESS_VIOLATION"
	case 0xc000001d:
		return "EXCEPTION_ILLEGAL_INSTRUCTION"
	case 0xc0000094:
		return "EXCEPTION_INT_DIVIDE_BY_ZERO"
	case 0xc00000fd:
		return "EXCEPTION_STACK_OVERFLOW"
	default:
		return fmt.Sprintf("EXCEPTION_0x%08X", code)
	}
}
