package symbolicate

import (
	"bytes"
	"debug/macho"
	"encoding/binary"
	"os"
	"testing"
)

func TestMachOCompactUnwindRegularRBPFrame(t *testing.T) {
	unwinder := parseMachOCompactUnwind(compactRegularFixture(0x1000, 0x1100, compactUnwindX8664RBPFrame), binary.LittleEndian, "x86_64")
	if unwinder == nil || len(unwinder.entries) != 1 {
		t.Fatalf("compact unwind = %#v", unwinder)
	}
	const frame = 0x70000020
	memory := minidumpMemory{address: frame, data: make([]byte, 16), pointerSize: 8}
	binary.LittleEndian.PutUint64(memory.data[:8], 0x70000080)
	binary.LittleEndian.PutUint64(memory.data[8:16], 0x101081)
	next := unwinder.unwind(0x1010, map[string]uint64{"rip": 0x1010, "rsp": 0x70000000, "rbp": frame}, memory, "x86_64")
	if next == nil || next["rip"] != 0x101081 || next["rsp"] != frame+16 || next["rbp"] != 0x70000080 {
		t.Fatalf("RBP compact unwind result = %#v", next)
	}
}

func TestMachOCompactUnwindX86EBPFrame(t *testing.T) {
	unwinder := parseMachOCompactUnwind(compactRegularFixture(0x1000, 0x1100, compactUnwindX86EBPFrame|2<<16|1|5<<3), binary.LittleEndian, "x86")
	if unwinder == nil || len(unwinder.entries) != 1 {
		t.Fatalf("x86 compact unwind = %#v", unwinder)
	}
	const frame = 0x70000020
	memory := minidumpMemory{address: frame - 8, data: make([]byte, 20), pointerSize: 4}
	binary.LittleEndian.PutUint32(memory.data[0:4], 0x11111111)
	binary.LittleEndian.PutUint32(memory.data[4:8], 0x55555555)
	binary.LittleEndian.PutUint32(memory.data[8:12], 0x70000080)
	binary.LittleEndian.PutUint32(memory.data[12:16], 0x101081)
	next := unwinder.unwind(0x1010, map[string]uint64{"eip": 0x1010, "esp": frame - 16, "ebp": frame}, memory, "x86")
	if next == nil || next["eip"] != 0x101081 || next["esp"] != frame+8 || next["ebp"] != 0x70000080 || next["ebx"] != 0x11111111 || next["esi"] != 0x55555555 {
		t.Fatalf("x86 EBP compact unwind result = %#v", next)
	}
}

func TestMachOCompactUnwindX86FramelessModes(t *testing.T) {
	const stack = 0x71000000
	immediate := parseMachOCompactUnwind(compactCompressedFixture(0x2000, 0x2100, compactUnwindX86StackImmediate|6<<16|2<<10|18), binary.LittleEndian, "x86")
	memory := minidumpMemory{address: stack, data: make([]byte, 24), pointerSize: 4}
	binary.LittleEndian.PutUint32(memory.data[12:16], 0x44444444)
	binary.LittleEndian.PutUint32(memory.data[16:20], 0x55555555)
	binary.LittleEndian.PutUint32(memory.data[20:24], 0x202081)
	if next := immediate.unwind(0x2020, map[string]uint64{"eip": 0x2020, "esp": stack}, memory, "x86"); next == nil || next["eip"] != 0x202081 || next["esp"] != stack+24 || next["edi"] != 0x44444444 || next["esi"] != 0x55555555 {
		t.Fatalf("x86 immediate-stack compact unwind result = %#v", next)
	}

	indirect := parseMachOCompactUnwind(compactRegularFixture(0x1000, 0x1100, compactUnwindX86StackIndirect|2<<16|1<<13), binary.LittleEndian, "x86")
	indirect.imageBase, indirect.textAddress, indirect.text = 0x1000, 0x2000, make([]byte, 6)
	binary.LittleEndian.PutUint32(indirect.text[2:6], 32)
	indirectMemory := minidumpMemory{address: stack, data: make([]byte, 36), pointerSize: 4}
	binary.LittleEndian.PutUint32(indirectMemory.data[32:36], 0x303081)
	if next := indirect.unwind(0x1010, map[string]uint64{"eip": 0x1010, "esp": stack}, indirectMemory, "x86"); next == nil || next["eip"] != 0x303081 || next["esp"] != stack+36 {
		t.Fatalf("x86 indirect-stack compact unwind result = %#v", next)
	}
}

func TestMachOCompactUnwindCompressedStackAndARM64(t *testing.T) {
	x64 := parseMachOCompactUnwind(compactCompressedFixture(0x2000, 0x2100, compactUnwindX8664StackImmediate|4<<16|1<<10|5), binary.LittleEndian, "x86_64")
	if x64 == nil || len(x64.entries) != 1 || x64.entries[0].begin != 0x2010 {
		t.Fatalf("compressed compact unwind = %#v", x64)
	}
	const stack = 0x71000000
	memory := minidumpMemory{address: stack, data: make([]byte, 32), pointerSize: 8}
	binary.LittleEndian.PutUint64(memory.data[16:24], 0x71000080)
	binary.LittleEndian.PutUint64(memory.data[24:32], 0x202081)
	if next := x64.unwind(0x2020, map[string]uint64{"rip": 0x2020, "rsp": stack}, memory, "x86_64"); next == nil || next["rip"] != 0x202081 || next["rsp"] != stack+32 || next["rbp"] != 0x71000080 {
		t.Fatalf("frameless compact unwind result = %#v", next)
	}

	arm := parseMachOCompactUnwind(compactRegularFixture(0x3000, 0x3100, compactUnwindARM64Frame|1), binary.LittleEndian, "arm64")
	const frame = 0x72000000
	armMemory := minidumpMemory{address: frame - 16, data: make([]byte, 32), pointerSize: 8}
	binary.LittleEndian.PutUint64(armMemory.data[:8], 20)
	binary.LittleEndian.PutUint64(armMemory.data[8:16], 19)
	binary.LittleEndian.PutUint64(armMemory.data[16:24], 0x72000080)
	binary.LittleEndian.PutUint64(armMemory.data[24:32], 0x303081)
	if next := arm.unwind(0x3010, map[string]uint64{"pc": 0x3010, "sp": frame - 32, "fp": frame}, armMemory, "arm64"); next == nil || next["pc"] != 0x303081 || next["sp"] != frame+16 || next["fp"] != 0x72000080 || next["x19"] != 19 || next["x20"] != 20 {
		t.Fatalf("ARM64 compact unwind result = %#v", next)
	}
}

func TestLoadMachOCompactUnwindSelectsUniversalArchitecture(t *testing.T) {
	amd64 := minimalMachOWithCompactUnwind(macho.CpuAmd64, compactUnwindX8664RBPFrame)
	arm64 := minimalMachOWithCompactUnwind(macho.CpuArm64, compactUnwindARM64Frame)
	fat := universalMachOFixture(amd64, arm64)
	arm := loadMachOCompactUnwind(bytes.NewReader(fat), "arm64")
	if arm == nil || arm.architecture != "arm64" || arm.entries[0].encoding&compactUnwindModeMask != compactUnwindARM64Frame {
		t.Fatalf("selected ARM64 compact unwind = %#v", arm)
	}
	x64 := loadMachOCompactUnwind(bytes.NewReader(fat), "x86_64")
	if x64 == nil || x64.architecture != "x86_64" || x64.entries[0].encoding&compactUnwindModeMask != compactUnwindX8664RBPFrame {
		t.Fatalf("selected x86-64 compact unwind = %#v", x64)
	}
}

func TestLoadMachOCompactUnwindX86(t *testing.T) {
	parsed := loadMachOCompactUnwind(bytes.NewReader(minimalMachO32WithCompactUnwind(compactUnwindX86EBPFrame)), "x86")
	if parsed == nil || parsed.architecture != "x86" || len(parsed.entries) != 1 || parsed.entries[0].encoding&compactUnwindModeMask != compactUnwindX86EBPFrame {
		t.Fatalf("loaded x86 compact unwind = %#v", parsed)
	}
}

func TestLoadDwarfCFISelectsUniversalArchitecture(t *testing.T) {
	fat := universalMachOFixture(minimalMachOWithEhFrame(), minimalMachOWithCompactUnwind(macho.CpuArm64, compactUnwindARM64Frame))
	if parsed := loadDwarfCFIForArch(bytes.NewReader(fat), "x86_64"); parsed == nil || len(parsed.entries) != 1 {
		t.Fatalf("selected x86-64 DWARF CFI = %#v", parsed)
	}
	if parsed := loadDwarfCFIForArch(bytes.NewReader(fat), "arm64"); parsed != nil {
		t.Fatalf("used DWARF CFI from the wrong universal slice: %#v", parsed)
	}
}

func TestMinidumpUsesUploadedMachOCompactUnwind(t *testing.T) {
	st := symbolicationStore(t)
	putDebugArtifactBytes(t, st, minidumpFixtureDebugID, minimalMachOWithCompactUnwind(macho.CpuAmd64, compactUnwindX8664RBPFrame))
	const (
		imageBase = 0x100000000
		frame     = 0x73000020
	)
	stack := make([]byte, 48)
	binary.LittleEndian.PutUint64(stack[32:40], frame+0x40)
	binary.LittleEndian.PutUint64(stack[40:48], imageBase+0x1081)
	dump := &minidump{
		architecture: "x86_64", threadID: 1, address: imageBase + 0x1010,
		registers:    map[string]uint64{"rip": imageBase + 0x1010, "rsp": frame - 32, "rbp": frame},
		stackAddress: frame - 32, stack: stack,
		modules: []minidumpModule{{base: imageBase, size: 0x4000, name: "app", debugID: minidumpFixtureDebugID}},
	}
	frames := unwindMinidump(t.Context(), st, "project", dump)
	if len(frames) != 2 || frames[0].(map[string]any)["instruction_addr"] != "0x100001080" || frames[0].(map[string]any)["trust"] != "cfi" {
		t.Fatalf("Mach-O compact minidump frames = %#v", frames)
	}
}

func TestMinidumpUsesUploadedMachOCompactUnwindX86(t *testing.T) {
	st := symbolicationStore(t)
	putDebugArtifactBytes(t, st, minidumpFixtureDebugID, minimalMachO32WithCompactUnwind(compactUnwindX86EBPFrame))
	const (
		imageBase = 0x400000
		frame     = 0x73000020
	)
	stack := make([]byte, 40)
	binary.LittleEndian.PutUint32(stack[32:36], frame+0x40)
	binary.LittleEndian.PutUint32(stack[36:40], imageBase+0x1081)
	dump := &minidump{
		architecture: "x86", threadID: 1, address: imageBase + 0x1010,
		registers:    map[string]uint64{"eip": imageBase + 0x1010, "esp": frame - 32, "ebp": frame},
		stackAddress: frame - 32, stack: stack,
		modules: []minidumpModule{{base: imageBase, size: 0x4000, name: "app", debugID: minidumpFixtureDebugID}},
	}
	frames := unwindMinidump(t.Context(), st, "project", dump)
	if len(frames) != 2 || frames[0].(map[string]any)["instruction_addr"] != "0x401080" || frames[0].(map[string]any)["trust"] != "cfi" {
		t.Fatalf("x86 Mach-O compact minidump frames = %#v", frames)
	}
}

func TestMachOCompactUnwindRejectsMalformedData(t *testing.T) {
	fixture := compactRegularFixture(0x1000, 0x1100, compactUnwindX8664RBPFrame)
	if parsed := parseMachOCompactUnwind(fixture[:len(fixture)-1], binary.LittleEndian, "x86_64"); parsed != nil {
		t.Fatalf("truncated compact unwind was accepted: %#v", parsed)
	}
	invalid := append([]byte(nil), fixture...)
	binary.LittleEndian.PutUint32(invalid[24:28], maxMachOCompactEntries+1)
	if parsed := parseMachOCompactUnwind(invalid, binary.LittleEndian, "x86_64"); parsed != nil {
		t.Fatalf("oversized compact unwind was accepted: %#v", parsed)
	}
}

func FuzzParseMachOCompactUnwind(f *testing.F) {
	f.Add(compactRegularFixture(0x1000, 0x1100, compactUnwindX8664RBPFrame))
	f.Add(compactCompressedFixture(0x2000, 0x2100, compactUnwindX8664StackImmediate|4<<16))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			t.Skip()
		}
		_ = parseMachOCompactUnwind(data, binary.LittleEndian, "x86_64")
	})
}

func TestRealMachOCompactUnwindFixture(t *testing.T) {
	path := os.Getenv("BARKTRACE_COMPACT_UNWIND_FIXTURE")
	if path == "" {
		t.Skip("set BARKTRACE_COMPACT_UNWIND_FIXTURE to a Mach-O file containing __unwind_info")
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	unwinder := loadMachOCompactUnwind(file, os.Getenv("BARKTRACE_COMPACT_UNWIND_ARCH"))
	if unwinder == nil || len(unwinder.entries) == 0 {
		t.Fatal("real Mach-O fixture has no parseable compact-unwind entries")
	}
	modes := make(map[uint32]int)
	for _, entry := range unwinder.entries {
		modes[entry.encoding&compactUnwindModeMask]++
	}
	t.Logf("real compact unwind entries: %d architecture: %s modes: %#v", len(unwinder.entries), unwinder.architecture, modes)
	if unwinder.architecture == "x86_64" {
		for _, entry := range unwinder.entries {
			if entry.encoding&compactUnwindModeMask != compactUnwindX8664StackImmediate {
				continue
			}
			stackSize := int((entry.encoding&0x00ff0000)>>16) * 8
			if stackSize < 8 {
				continue
			}
			memory := minidumpMemory{address: 0x74000000, data: make([]byte, stackSize), pointerSize: 8}
			binary.LittleEndian.PutUint64(memory.data[stackSize-8:], 0x100001081)
			next := unwinder.unwind(entry.begin, map[string]uint64{"rip": entry.begin, "rsp": memory.address}, memory, "x86_64")
			if next == nil || next["rip"] != 0x100001081 || next["rsp"] != memory.address+uint64(stackSize) {
				t.Fatalf("real compact-unwind encoding %#x did not execute: %#v", entry.encoding, next)
			}
			return
		}
		t.Fatal("real x86-64 compact-unwind fixture has no immediate-stack entry to execute")
	}
	if unwinder.architecture == "x86" {
		for _, entry := range unwinder.entries {
			if entry.encoding&compactUnwindModeMask != compactUnwindX86StackImmediate {
				continue
			}
			stackSize := int((entry.encoding&0x00ff0000)>>16) * 4
			if stackSize < 4 {
				continue
			}
			memory := minidumpMemory{address: 0x74000000, data: make([]byte, stackSize), pointerSize: 4}
			binary.LittleEndian.PutUint32(memory.data[stackSize-4:], 0x10001081)
			next := unwinder.unwind(entry.begin, map[string]uint64{"eip": entry.begin, "esp": memory.address}, memory, "x86")
			if next == nil || next["eip"] != 0x10001081 || next["esp"] != memory.address+uint64(stackSize) {
				t.Fatalf("real x86 compact-unwind encoding %#x did not execute: %#v", entry.encoding, next)
			}
			return
		}
		t.Fatal("real x86 compact-unwind fixture has no immediate-stack entry to execute")
	}
}

func compactRegularFixture(begin, end, encoding uint32) []byte {
	const (
		indexOffset = 28
		pageOffset  = 52
	)
	data := make([]byte, pageOffset+16)
	binary.LittleEndian.PutUint32(data[0:4], compactUnwindVersion)
	binary.LittleEndian.PutUint32(data[20:24], indexOffset)
	binary.LittleEndian.PutUint32(data[24:28], 2)
	binary.LittleEndian.PutUint32(data[28:32], begin)
	binary.LittleEndian.PutUint32(data[32:36], pageOffset)
	binary.LittleEndian.PutUint32(data[40:44], end)
	binary.LittleEndian.PutUint32(data[pageOffset:pageOffset+4], compactUnwindPageRegular)
	binary.LittleEndian.PutUint16(data[pageOffset+4:pageOffset+6], 8)
	binary.LittleEndian.PutUint16(data[pageOffset+6:pageOffset+8], 1)
	binary.LittleEndian.PutUint32(data[pageOffset+8:pageOffset+12], begin)
	binary.LittleEndian.PutUint32(data[pageOffset+12:pageOffset+16], encoding)
	return data
}

func compactCompressedFixture(begin, end, encoding uint32) []byte {
	const (
		commonOffset = 28
		indexOffset  = 32
		pageOffset   = 56
	)
	data := make([]byte, pageOffset+16)
	binary.LittleEndian.PutUint32(data[0:4], compactUnwindVersion)
	binary.LittleEndian.PutUint32(data[4:8], commonOffset)
	binary.LittleEndian.PutUint32(data[8:12], 1)
	binary.LittleEndian.PutUint32(data[20:24], indexOffset)
	binary.LittleEndian.PutUint32(data[24:28], 2)
	binary.LittleEndian.PutUint32(data[commonOffset:commonOffset+4], encoding)
	binary.LittleEndian.PutUint32(data[indexOffset:indexOffset+4], begin)
	binary.LittleEndian.PutUint32(data[indexOffset+4:indexOffset+8], pageOffset)
	binary.LittleEndian.PutUint32(data[indexOffset+12:indexOffset+16], end)
	binary.LittleEndian.PutUint32(data[pageOffset:pageOffset+4], compactUnwindPageCompressed)
	binary.LittleEndian.PutUint16(data[pageOffset+4:pageOffset+6], 12)
	binary.LittleEndian.PutUint16(data[pageOffset+6:pageOffset+8], 1)
	binary.LittleEndian.PutUint16(data[pageOffset+8:pageOffset+10], 16)
	binary.LittleEndian.PutUint32(data[pageOffset+12:pageOffset+16], 0x10)
	return data
}

func minimalMachOWithCompactUnwind(cpu macho.Cpu, encoding uint32) []byte {
	const (
		commandsSize = 152
		dataOffset   = 32 + commandsSize
		textAddress  = 0x100000000
	)
	unwind := compactRegularFixture(0x1000, 0x1100, encoding)
	data := make([]byte, dataOffset+len(unwind))
	binary.LittleEndian.PutUint32(data[:4], macho.Magic64)
	binary.LittleEndian.PutUint32(data[4:8], uint32(cpu))
	binary.LittleEndian.PutUint32(data[8:12], 3)
	binary.LittleEndian.PutUint32(data[12:16], uint32(macho.TypeExec))
	binary.LittleEndian.PutUint32(data[16:20], 1)
	binary.LittleEndian.PutUint32(data[20:24], commandsSize)
	binary.LittleEndian.PutUint32(data[32:36], uint32(macho.LoadCmdSegment64))
	binary.LittleEndian.PutUint32(data[36:40], commandsSize)
	copy(data[40:56], "__TEXT")
	binary.LittleEndian.PutUint64(data[56:64], textAddress)
	binary.LittleEndian.PutUint64(data[64:72], 0x4000)
	binary.LittleEndian.PutUint64(data[80:88], uint64(len(data)))
	binary.LittleEndian.PutUint32(data[88:92], 7)
	binary.LittleEndian.PutUint32(data[92:96], 5)
	binary.LittleEndian.PutUint32(data[96:100], 1)
	section := 104
	copy(data[section:section+16], "__unwind_info")
	copy(data[section+16:section+32], "__TEXT")
	binary.LittleEndian.PutUint64(data[section+32:section+40], textAddress+0x2000)
	binary.LittleEndian.PutUint64(data[section+40:section+48], uint64(len(unwind)))
	binary.LittleEndian.PutUint32(data[section+48:section+52], dataOffset)
	binary.LittleEndian.PutUint32(data[section+52:section+56], 2)
	copy(data[dataOffset:], unwind)
	return data
}

func minimalMachO32WithCompactUnwind(encoding uint32) []byte {
	const (
		commandsSize = 124
		dataOffset   = 28 + commandsSize
		textAddress  = 0x1000
	)
	unwind := compactRegularFixture(0x1000, 0x1100, encoding)
	data := make([]byte, dataOffset+len(unwind))
	binary.LittleEndian.PutUint32(data[:4], macho.Magic32)
	binary.LittleEndian.PutUint32(data[4:8], uint32(macho.Cpu386))
	binary.LittleEndian.PutUint32(data[8:12], 3)
	binary.LittleEndian.PutUint32(data[12:16], uint32(macho.TypeExec))
	binary.LittleEndian.PutUint32(data[16:20], 1)
	binary.LittleEndian.PutUint32(data[20:24], commandsSize)
	binary.LittleEndian.PutUint32(data[28:32], uint32(macho.LoadCmdSegment))
	binary.LittleEndian.PutUint32(data[32:36], commandsSize)
	copy(data[36:52], "__TEXT")
	binary.LittleEndian.PutUint32(data[52:56], textAddress)
	binary.LittleEndian.PutUint32(data[56:60], 0x4000)
	binary.LittleEndian.PutUint32(data[64:68], uint32(len(data)))
	binary.LittleEndian.PutUint32(data[68:72], 7)
	binary.LittleEndian.PutUint32(data[72:76], 5)
	binary.LittleEndian.PutUint32(data[76:80], 1)
	section := 84
	copy(data[section:section+16], "__unwind_info")
	copy(data[section+16:section+32], "__TEXT")
	binary.LittleEndian.PutUint32(data[section+32:section+36], textAddress+0x2000)
	binary.LittleEndian.PutUint32(data[section+36:section+40], uint32(len(unwind)))
	binary.LittleEndian.PutUint32(data[section+40:section+44], dataOffset)
	binary.LittleEndian.PutUint32(data[section+44:section+48], 2)
	copy(data[dataOffset:], unwind)
	return data
}

func universalMachOFixture(amd64, arm64 []byte) []byte {
	const (
		amd64Offset = 4096
		arm64Offset = 8192
	)
	data := make([]byte, arm64Offset+len(arm64))
	binary.BigEndian.PutUint32(data[:4], macho.MagicFat)
	binary.BigEndian.PutUint32(data[4:8], 2)
	for _, fixture := range []struct {
		offset int
		cpu    macho.Cpu
		data   []byte
	}{{8, macho.CpuAmd64, amd64}, {28, macho.CpuArm64, arm64}} {
		offset := fixture.offset
		binary.BigEndian.PutUint32(data[offset:offset+4], uint32(fixture.cpu))
		binary.BigEndian.PutUint32(data[offset+4:offset+8], 3)
		fileOffset := amd64Offset
		if fixture.cpu == macho.CpuArm64 {
			fileOffset = arm64Offset
		}
		binary.BigEndian.PutUint32(data[offset+8:offset+12], uint32(fileOffset))
		binary.BigEndian.PutUint32(data[offset+12:offset+16], uint32(len(fixture.data)))
		binary.BigEndian.PutUint32(data[offset+16:offset+20], 12)
		copy(data[fileOffset:], fixture.data)
	}
	return data
}
