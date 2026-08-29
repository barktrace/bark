package symbolicate

import (
	"bytes"
	"debug/elf"
	"debug/macho"
	"encoding/binary"
	"os"
	"testing"
)

func TestDwarfCFIUnwindsX8664ReturnAddress(t *testing.T) {
	unwinder := parseDwarfCFI(x8664EhFrameFixture(), binary.LittleEndian, 8, 0, 0)
	if unwinder == nil || len(unwinder.entries) != 1 {
		t.Fatalf("parsed .eh_frame = %#v", unwinder)
	}
	const stackAddress = 0x70000000
	memory := minidumpMemory{address: stackAddress, data: make([]byte, 16), pointerSize: 8}
	binary.LittleEndian.PutUint64(memory.data[:8], 0x1121)
	next := unwinder.unwind(0x1010, map[string]uint64{"rip": 0x1010, "rsp": stackAddress}, memory, "x86_64")
	if next == nil || next["rip"] != 0x1121 || next["rsp"] != stackAddress+8 {
		t.Fatalf("DWARF unwind result = %#v", next)
	}
}

func TestDwarfCFIUnwindsX86AndARM64(t *testing.T) {
	tests := []struct {
		name, architecture, instruction, stack string
		pointerSize                            int
		returnRegister, cfaRegister            byte
		cfaOffset                              uint64
		dataAlignment                          int8
		returnSlot                             int
	}{
		{name: "x86", architecture: "x86", instruction: "eip", stack: "esp", pointerSize: 4, returnRegister: 8, cfaRegister: 4, cfaOffset: 4, dataAlignment: -4},
		{name: "arm64", architecture: "arm64", instruction: "pc", stack: "sp", pointerSize: 8, returnRegister: 30, cfaRegister: 31, cfaOffset: 16, dataAlignment: -8, returnSlot: 8},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			unwinder := parseDwarfCFI(ehFrameFixture(0, 0x1000, test.returnRegister, test.cfaRegister, test.cfaOffset, test.dataAlignment), binary.LittleEndian, test.pointerSize, 0, 0)
			if unwinder == nil {
				t.Fatal("could not parse architecture fixture")
			}
			const stackAddress = 0x70000000
			memory := minidumpMemory{address: stackAddress, data: make([]byte, 32), pointerSize: test.pointerSize}
			if test.pointerSize == 4 {
				binary.LittleEndian.PutUint32(memory.data[test.returnSlot:test.returnSlot+4], 0x1121)
			} else {
				binary.LittleEndian.PutUint64(memory.data[test.returnSlot:test.returnSlot+8], 0x1121)
			}
			next := unwinder.unwind(0x1010, map[string]uint64{test.instruction: 0x1010, test.stack: stackAddress}, memory, test.architecture)
			if next == nil || next[test.instruction] != 0x1121 || next[test.stack] != stackAddress+test.cfaOffset {
				t.Fatalf("%s DWARF unwind = %#v", test.architecture, next)
			}
		})
	}
}

func TestDwarfCFIAppliesRowsOnlyAfterAdvance(t *testing.T) {
	fixture := ehFrameFixtureWithInstructions(0, 0x1000, 16, 7, 8, -8, []byte{0x50, 0x0e, 0x10})
	unwinder := parseDwarfCFI(fixture, binary.LittleEndian, 8, 0, 0)
	const stackAddress = 0x70000000
	memory := minidumpMemory{address: stackAddress, data: make([]byte, 24), pointerSize: 8}
	binary.LittleEndian.PutUint64(memory.data[:8], 0x1121)
	binary.LittleEndian.PutUint64(memory.data[8:16], 0x1221)
	before := unwinder.unwind(0x1005, map[string]uint64{"rip": 0x1005, "rsp": stackAddress}, memory, "x86_64")
	after := unwinder.unwind(0x1020, map[string]uint64{"rip": 0x1020, "rsp": stackAddress}, memory, "x86_64")
	if before == nil || before["rip"] != 0x1121 || before["rsp"] != stackAddress+8 {
		t.Fatalf("row before advance = %#v", before)
	}
	if after == nil || after["rip"] != 0x1221 || after["rsp"] != stackAddress+16 {
		t.Fatalf("row after advance = %#v", after)
	}
}

func TestMinidumpUsesUploadedELFEhFrame(t *testing.T) {
	st := symbolicationStore(t)
	putDebugArtifactBytes(t, st, minidumpFixtureDebugID, minimalELFWithEhFrame())
	const (
		imageBase    = 0x400000
		stackAddress = 0x70000000
	)
	stack := make([]byte, 16)
	binary.LittleEndian.PutUint64(stack[:8], imageBase+0x3121)
	dump := &minidump{
		architecture: "x86_64", threadID: 7, address: imageBase + 0x3010,
		registers:    map[string]uint64{"rip": imageBase + 0x3010, "rsp": stackAddress},
		stackAddress: stackAddress, stack: stack,
		modules: []minidumpModule{{base: imageBase, size: 0x10000, name: "app", debugID: minidumpFixtureDebugID}},
	}
	frames := unwindMinidump(t.Context(), st, "project", dump)
	if len(frames) != 2 || frames[0].(map[string]any)["instruction_addr"] != "0x403120" || frames[0].(map[string]any)["trust"] != "cfi" {
		t.Fatalf("ELF .eh_frame minidump frames = %#v", frames)
	}
}

func TestLoadMachOEhFrame(t *testing.T) {
	unwinder := loadDwarfCFI(bytes.NewReader(minimalMachOWithEhFrame()))
	if unwinder == nil || len(unwinder.entries) != 1 || unwinder.entries[0].begin != 0x3000 {
		t.Fatalf("Mach-O .eh_frame = %#v", unwinder)
	}
}

func TestDwarfCFIRejectsMalformedData(t *testing.T) {
	fixture := x8664EhFrameFixture()
	if parsed := parseDwarfCFI(fixture[:len(fixture)-1], binary.LittleEndian, 8, 0, 0); parsed != nil {
		t.Fatalf("truncated .eh_frame was accepted: %#v", parsed)
	}
	oversized := append([]byte(nil), fixture...)
	binary.LittleEndian.PutUint32(oversized[:4], uint32(maxDWARFBytes+1))
	if parsed := parseDwarfCFI(oversized, binary.LittleEndian, 8, 0, 0); parsed != nil {
		t.Fatalf("oversized .eh_frame entry was accepted: %#v", parsed)
	}
}

func FuzzParseDwarfCFI(f *testing.F) {
	f.Add(x8664EhFrameFixture())
	f.Add([]byte("not dwarf frame data"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			t.Skip()
		}
		_ = parseDwarfCFI(data, binary.LittleEndian, 8, 0x2000, 0)
	})
}

func TestRealDwarfCFIFixture(t *testing.T) {
	path := os.Getenv("BARKTRACE_DWARF_CFI_FIXTURE")
	if path == "" {
		t.Skip("set BARKTRACE_DWARF_CFI_FIXTURE to an ELF or Mach-O file containing .eh_frame")
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	unwinder := loadDwarfCFI(file)
	if unwinder == nil || len(unwinder.entries) == 0 {
		t.Fatal("real fixture produced no DWARF frame entries")
	}
	elfFile, err := elf.NewFile(file)
	if err != nil {
		t.Logf("real Mach-O .eh_frame entries: %d", len(unwinder.entries))
		return
	}
	defer elfFile.Close()
	architecture := map[elf.Machine]string{elf.EM_386: "x86", elf.EM_X86_64: "x86_64", elf.EM_AARCH64: "arm64"}[elfFile.Machine]
	if architecture == "" {
		t.Skipf("parsed %d entries for unsupported fixture architecture %s", len(unwinder.entries), elfFile.Machine)
	}
	if !exerciseRealDwarfCFI(unwinder, architecture) {
		t.Fatalf("none of %d real .eh_frame entries produced an executable CFA row", len(unwinder.entries))
	}
	t.Logf("real .eh_frame entries: %d architecture: %s", len(unwinder.entries), architecture)
}

func exerciseRealDwarfCFI(unwinder *dwarfCFI, architecture string) bool {
	const memoryBase = 0x70000000
	for index := range unwinder.entries {
		entry := &unwinder.entries[index]
		state := dwarfFrameState{imageBase: unwinder.imageBase, cfa: dwarfRule{kind: dwarfRuleUndefined}, registers: make(map[uint64]dwarfRule)}
		if !executeDwarfCFI(entry.cie.instructions, entry.cie, &state, ^uint64(0), nil, unwinder.order, unwinder.pointerSize) {
			continue
		}
		initial := cloneDwarfRules(state.registers)
		state.location = entry.begin
		pc := entry.begin
		if entry.size > 1 {
			pc++
		}
		if !executeDwarfCFI(entry.instructions, entry.cie, &state, pc, initial, unwinder.order, unwinder.pointerSize) || state.cfa.kind != dwarfRuleRegister {
			continue
		}
		returnRule, ok := state.registers[entry.cie.returnRegister]
		if !ok || returnRule.kind != dwarfRuleOffset {
			continue
		}
		cfaRegister := dwarfRegisterName(architecture, state.cfa.register)
		if cfaRegister == "" {
			continue
		}
		cfa := uint64(memoryBase + 2048)
		baseRegister, valid := addDwarfOffset(cfa, -state.cfa.offset)
		returnSlot, slotValid := addDwarfOffset(cfa, returnRule.offset)
		if !valid || !slotValid || returnSlot < memoryBase || returnSlot+uint64(unwinder.pointerSize) > memoryBase+4096 {
			continue
		}
		memory := minidumpMemory{address: memoryBase, data: make([]byte, 4096), pointerSize: unwinder.pointerSize}
		returnAddress := uint64(0x12345678)
		offset := int(returnSlot - memoryBase)
		if unwinder.pointerSize == 4 {
			binary.LittleEndian.PutUint32(memory.data[offset:offset+4], uint32(returnAddress))
		} else {
			binary.LittleEndian.PutUint64(memory.data[offset:offset+8], returnAddress)
		}
		registers := map[string]uint64{cfaRegister: baseRegister}
		next := unwinder.unwind(pc, registers, memory, architecture)
		return next != nil && next[instructionRegister(architecture)] == returnAddress && next[stackRegister(architecture)] == cfa
	}
	return false
}

func x8664EhFrameFixture() []byte {
	return x8664EhFrameFixtureAt(0, 0x1000)
}

func x8664EhFrameFixtureAt(sectionAddress, functionAddress uint64) []byte {
	return ehFrameFixture(sectionAddress, functionAddress, 16, 7, 8, -8)
}

func ehFrameFixture(sectionAddress, functionAddress uint64, returnRegister, cfaRegister byte, cfaOffset uint64, dataAlignment int8) []byte {
	return ehFrameFixtureWithInstructions(sectionAddress, functionAddress, returnRegister, cfaRegister, cfaOffset, dataAlignment, nil)
}

func ehFrameFixtureWithInstructions(sectionAddress, functionAddress uint64, returnRegister, cfaRegister byte, cfaOffset uint64, dataAlignment int8, instructions []byte) []byte {
	data := make([]byte, 0, 64)
	cieStart := len(data)
	data = append(data, 0, 0, 0, 0)
	data = append(data, 0, 0, 0, 0)
	data = append(data, 1, 'z', 'R', 0)
	data = append(data, 1, byte(dataAlignment)&0x7f, returnRegister)
	data = append(data, 1, 0x1b) // one augmentation byte: PC-relative signed 32-bit pointers.
	data = append(data, 0x0c, cfaRegister, byte(cfaOffset))
	data = append(data, 0x80|returnRegister, 1)
	binary.LittleEndian.PutUint32(data[cieStart:cieStart+4], uint32(len(data)-cieStart-4))

	fdeStart := len(data)
	data = append(data, 0, 0, 0, 0)
	ciePointerOffset := len(data)
	data = append(data, 0, 0, 0, 0)
	binary.LittleEndian.PutUint32(data[ciePointerOffset:ciePointerOffset+4], uint32(ciePointerOffset-cieStart))
	beginOffset := len(data)
	data = append(data, 0, 0, 0, 0)
	delta := int64(functionAddress) - int64(sectionAddress) - int64(beginOffset)
	binary.LittleEndian.PutUint32(data[beginOffset:beginOffset+4], uint32(int32(delta)))
	data = append(data, 0x00, 0x01, 0x00, 0x00) // signed 32-bit range: 0x100.
	data = append(data, 0)                      // empty FDE augmentation data.
	data = append(data, instructions...)
	binary.LittleEndian.PutUint32(data[fdeStart:fdeStart+4], uint32(len(data)-fdeStart-4))
	return data
}

func minimalELFWithEhFrame() []byte {
	const (
		sectionHeaders = 64
		stringsOffset  = 256
		ehFrameOffset  = 288
		ehFrameAddress = 0x2000
	)
	strings := []byte("\x00.shstrtab\x00.eh_frame\x00")
	ehFrame := x8664EhFrameFixtureAt(ehFrameAddress, 0x3000)
	data := make([]byte, ehFrameOffset+len(ehFrame))
	copy(data[:16], []byte{0x7f, 'E', 'L', 'F', 2, 1, 1})
	binary.LittleEndian.PutUint16(data[16:18], uint16(elf.ET_DYN))
	binary.LittleEndian.PutUint16(data[18:20], uint16(elf.EM_X86_64))
	binary.LittleEndian.PutUint32(data[20:24], 1)
	binary.LittleEndian.PutUint64(data[40:48], sectionHeaders)
	binary.LittleEndian.PutUint16(data[52:54], 64)
	binary.LittleEndian.PutUint16(data[58:60], 64)
	binary.LittleEndian.PutUint16(data[60:62], 3)
	binary.LittleEndian.PutUint16(data[62:64], 1)
	stringSection := sectionHeaders + 64
	binary.LittleEndian.PutUint32(data[stringSection:stringSection+4], 1)
	binary.LittleEndian.PutUint32(data[stringSection+4:stringSection+8], uint32(elf.SHT_STRTAB))
	binary.LittleEndian.PutUint64(data[stringSection+24:stringSection+32], stringsOffset)
	binary.LittleEndian.PutUint64(data[stringSection+32:stringSection+40], uint64(len(strings)))
	binary.LittleEndian.PutUint64(data[stringSection+48:stringSection+56], 1)
	ehSection := sectionHeaders + 128
	binary.LittleEndian.PutUint32(data[ehSection:ehSection+4], 11)
	binary.LittleEndian.PutUint32(data[ehSection+4:ehSection+8], uint32(elf.SHT_PROGBITS))
	binary.LittleEndian.PutUint64(data[ehSection+8:ehSection+16], uint64(elf.SHF_ALLOC))
	binary.LittleEndian.PutUint64(data[ehSection+16:ehSection+24], ehFrameAddress)
	binary.LittleEndian.PutUint64(data[ehSection+24:ehSection+32], ehFrameOffset)
	binary.LittleEndian.PutUint64(data[ehSection+32:ehSection+40], uint64(len(ehFrame)))
	binary.LittleEndian.PutUint64(data[ehSection+48:ehSection+56], 8)
	copy(data[stringsOffset:], strings)
	copy(data[ehFrameOffset:], ehFrame)
	return data
}

func minimalMachOWithEhFrame() []byte {
	const (
		commandsSize   = 152
		ehFrameOffset  = 32 + commandsSize
		textAddress    = 0x100000000
		ehFrameAddress = textAddress + 0x2000
	)
	ehFrame := x8664EhFrameFixtureAt(ehFrameAddress, textAddress+0x3000)
	data := make([]byte, ehFrameOffset+len(ehFrame))
	binary.LittleEndian.PutUint32(data[:4], macho.Magic64)
	binary.LittleEndian.PutUint32(data[4:8], uint32(macho.CpuAmd64))
	binary.LittleEndian.PutUint32(data[8:12], 3)
	binary.LittleEndian.PutUint32(data[12:16], uint32(macho.TypeExec))
	binary.LittleEndian.PutUint32(data[16:20], 1)
	binary.LittleEndian.PutUint32(data[20:24], commandsSize)
	binary.LittleEndian.PutUint32(data[32:36], uint32(macho.LoadCmdSegment64))
	binary.LittleEndian.PutUint32(data[36:40], commandsSize)
	copy(data[40:56], "__TEXT")
	binary.LittleEndian.PutUint64(data[56:64], textAddress)
	binary.LittleEndian.PutUint64(data[64:72], 0x4000)
	binary.LittleEndian.PutUint64(data[72:80], 0)
	binary.LittleEndian.PutUint64(data[80:88], uint64(len(data)))
	binary.LittleEndian.PutUint32(data[88:92], 7)
	binary.LittleEndian.PutUint32(data[92:96], 5)
	binary.LittleEndian.PutUint32(data[96:100], 1)
	section := 104
	copy(data[section:section+16], "__eh_frame")
	copy(data[section+16:section+32], "__TEXT")
	binary.LittleEndian.PutUint64(data[section+32:section+40], ehFrameAddress)
	binary.LittleEndian.PutUint64(data[section+40:section+48], uint64(len(ehFrame)))
	binary.LittleEndian.PutUint32(data[section+48:section+52], ehFrameOffset)
	binary.LittleEndian.PutUint32(data[section+52:section+56], 3)
	copy(data[ehFrameOffset:], ehFrame)
	return data
}
