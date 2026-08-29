package symbolicate

import (
	"encoding/binary"
	"os"
	"testing"
)

func TestDwarfExpressionCFAReturnAndValueRules(t *testing.T) {
	instructions := []byte{
		0x0f, 0x02, 0x77, 0x10, // DW_CFA_def_cfa_expression: DW_OP_breg7(rsp) +16
		0x10, 0x10, 0x02, 0x77, 0x08, // DW_CFA_expression rip: [rsp+8]
		0x16, 0x06, 0x02, 0x77, 0x18, // DW_CFA_val_expression rbp: rsp+24
	}
	unwinder := parseDwarfCFI(ehFrameFixtureWithInstructions(0, 0x1000, 16, 7, 8, -8, instructions), binary.LittleEndian, 8, 0, 0)
	if unwinder == nil {
		t.Fatal("expression-based .eh_frame fixture did not parse")
	}
	const stackAddress = 0x70000000
	memory := minidumpMemory{address: stackAddress, data: make([]byte, 32), pointerSize: 8}
	binary.LittleEndian.PutUint64(memory.data[8:16], 0x1121)
	next := unwinder.unwind(0x1010, map[string]uint64{"rip": 0x1010, "rsp": stackAddress, "rbp": 0}, memory, "x86_64")
	if next == nil || next["rip"] != 0x1121 || next["rsp"] != stackAddress+16 || next["rbp"] != stackAddress+24 {
		t.Fatalf("expression-based DWARF unwind = %#v", next)
	}
}

func TestDwarfExpressionRegisterAndMemoryOperations(t *testing.T) {
	const stackAddress = 0x71000000
	memory := minidumpMemory{address: stackAddress, data: make([]byte, 32), pointerSize: 8}
	binary.LittleEndian.PutUint64(memory.data[8:16], 0xfeedface)
	registers := map[string]uint64{"rsp": stackAddress, "rbp": stackAddress + 24}
	tests := []struct {
		name       string
		expression []byte
		want       uint64
		direct     bool
	}{
		{name: "register location", expression: []byte{0x56}, want: stackAddress + 24, direct: true},
		{name: "register offset", expression: []byte{0x77, 0x08}, want: stackAddress + 8},
		{name: "deref and stack value", expression: []byte{0x77, 0x08, 0x06, 0x9f}, want: 0xfeedface, direct: true},
		{name: "CFA arithmetic", expression: []byte{0x9c, 0x23, 0x08}, want: stackAddress + 24},
		{name: "signed arithmetic", expression: []byte{0x08, 0x09, 0x09, 0xfd, 0x1c}, want: 12},
		{name: "comparison", expression: []byte{0x35, 0x34, 0x2b}, want: 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value, direct, ok := evaluateDwarfExpression(test.expression, registers, memory, "x86_64", stackAddress+16, true, binary.LittleEndian, 8)
			if !ok || value != test.want || direct != test.direct {
				t.Fatalf("expression result = %#x direct=%v ok=%v, want %#x direct=%v", value, direct, ok, test.want, test.direct)
			}
		})
	}
}

func TestDwarfExpressionBranchesAndBounds(t *testing.T) {
	// The true branch skips DW_OP_lit0 and leaves DW_OP_lit7 on top.
	expression := []byte{0x31, 0x28, 0x01, 0x00, 0x30, 0x37}
	if value, _, ok := evaluateDwarfExpression(expression, nil, minidumpMemory{}, "x86_64", 0, false, binary.LittleEndian, 8); !ok || value != 7 {
		t.Fatalf("branched expression = %#x ok=%v", value, ok)
	}
	for name, malformed := range map[string][]byte{
		"underflow":        {0x22},
		"division by zero": {0x31, 0x30, 0x1b},
		"invalid branch":   {0x2f, 0xff, 0x7f},
		"infinite branch":  {0x2f, 0xfd, 0xff},
		"unknown opcode":   {0xff},
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, ok := evaluateDwarfExpression(malformed, nil, minidumpMemory{}, "x86_64", 0, false, binary.LittleEndian, 8); ok {
				t.Fatalf("malformed expression %x was accepted", malformed)
			}
		})
	}
	overflow := make([]byte, maxDwarfExpressionStack+1)
	for index := range overflow {
		overflow[index] = 0x30
	}
	if _, _, ok := evaluateDwarfExpression(overflow, nil, minidumpMemory{}, "x86_64", 0, false, binary.LittleEndian, 8); ok {
		t.Fatal("expression stack overflow was accepted")
	}
}

func FuzzEvaluateDwarfExpression(f *testing.F) {
	f.Add([]byte{0x77, 0x08, 0x06, 0x9f})
	f.Add([]byte{0x31, 0x28, 0x01, 0x00, 0x30, 0x37})
	f.Add([]byte{0x2f, 0xfd, 0xff})
	f.Fuzz(func(t *testing.T, expression []byte) {
		if len(expression) > 1<<16 {
			t.Skip()
		}
		memory := minidumpMemory{address: 0x70000000, data: make([]byte, 64), pointerSize: 8}
		_, _, _ = evaluateDwarfExpression(expression, map[string]uint64{"rsp": memory.address, "rbp": memory.address + 32}, memory, "x86_64", memory.address+16, true, binary.LittleEndian, 8)
	})
}

func TestRealDwarfExpressionFixture(t *testing.T) {
	path := os.Getenv("BARKTRACE_DWARF_EXPRESSION_FIXTURE")
	if path == "" {
		t.Skip("set BARKTRACE_DWARF_EXPRESSION_FIXTURE to an ELF or Mach-O file containing expression-based CFI")
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	unwinder := loadDwarfCFI(file)
	if unwinder == nil {
		t.Fatal("real fixture has no parseable .eh_frame entries")
	}
	architecture := os.Getenv("BARKTRACE_DWARF_EXPRESSION_ARCH")
	if architecture == "" {
		architecture = "x86_64"
	}
	memory := minidumpMemory{address: 0x70000000, data: make([]byte, 4096), pointerSize: unwinder.pointerSize}
	for offset := 0; offset+unwinder.pointerSize <= len(memory.data); offset += unwinder.pointerSize {
		if unwinder.pointerSize == 4 {
			unwinder.order.PutUint32(memory.data[offset:offset+4], uint32(memory.address+2048))
		} else {
			unwinder.order.PutUint64(memory.data[offset:offset+8], memory.address+2048)
		}
	}
	registers := make(map[string]uint64)
	for number := uint64(0); number < 64; number++ {
		if name := dwarfRegisterName(architecture, number); name != "" {
			registers[name] = memory.address + 512
		}
	}
	found, evaluated := 0, 0
	for index := range unwinder.entries {
		entry := &unwinder.entries[index]
		targets := []uint64{entry.begin}
		if entry.size > 1 {
			targets = append(targets, entry.begin+entry.size-1)
		}
		for _, target := range targets {
			state := dwarfFrameState{imageBase: unwinder.imageBase, cfa: dwarfRule{kind: dwarfRuleUndefined}, registers: make(map[uint64]dwarfRule)}
			if !executeDwarfCFI(entry.cie.instructions, entry.cie, &state, ^uint64(0), nil, unwinder.order, unwinder.pointerSize) {
				continue
			}
			initial := cloneDwarfRules(state.registers)
			state.location = entry.begin
			if !executeDwarfCFI(entry.instructions, entry.cie, &state, target, initial, unwinder.order, unwinder.pointerSize) {
				continue
			}
			cfa := memory.address + 2048
			if state.cfa.kind == dwarfRuleExpression {
				found++
				if value, _, ok := evaluateDwarfExpression(state.cfa.expression, registers, memory, architecture, 0, false, unwinder.order, unwinder.pointerSize); ok {
					cfa = value
					evaluated++
				}
			}
			for _, rule := range state.registers {
				if rule.kind != dwarfRuleExpression && rule.kind != dwarfRuleValueExpression {
					continue
				}
				found++
				if _, ok := evaluateDwarfRule(rule, cfa, registers, memory, architecture, unwinder.order, unwinder.pointerSize); ok {
					evaluated++
				}
			}
		}
	}
	if found == 0 || evaluated == 0 {
		t.Fatalf("real expression rules found=%d evaluated=%d", found, evaluated)
	}
	t.Logf("real expression rules found=%d evaluated=%d entries=%d", found, evaluated, len(unwinder.entries))
}
