package symbolicate

import (
	"debug/elf"
	"debug/macho"
	"encoding/binary"
	"io"
	"sort"
)

const (
	maxDwarfCFIEntries      = 500000
	maxDwarfCFIInstructions = 1 << 20
	maxDwarfCFIStateDepth   = 64
)

type dwarfCFI struct {
	entries     []dwarfFDE
	order       binary.ByteOrder
	pointerSize int
	imageBase   uint64
}

type dwarfCIE struct {
	codeAlignment    uint64
	dataAlignment    int64
	returnRegister   uint64
	pointerEncoding  byte
	augmentationData bool
	instructions     []byte
}

type dwarfFDE struct {
	begin, size  uint64
	cie          *dwarfCIE
	instructions []byte
}

type dwarfRuleKind uint8

const (
	dwarfRuleUndefined dwarfRuleKind = iota
	dwarfRuleSame
	dwarfRuleOffset
	dwarfRuleValueOffset
	dwarfRuleRegister
)

type dwarfRule struct {
	kind     dwarfRuleKind
	register uint64
	offset   int64
}

type dwarfFrameState struct {
	location, imageBase uint64
	cfa                 dwarfRule
	registers           map[uint64]dwarfRule
}

type dwarfReader struct {
	data           []byte
	offset         int
	limit          int
	order          binary.ByteOrder
	pointerSize    int
	sectionAddress uint64
}

func loadDwarfCFI(reader io.ReaderAt) *dwarfCFI {
	return loadDwarfCFIForArch(reader, "")
}

func loadDwarfCFIForArch(reader io.ReaderAt, architecture string) *dwarfCFI {
	if file, err := elf.NewFile(reader); err == nil {
		defer file.Close()
		section := file.Section(".eh_frame")
		if section == nil || section.Size == 0 || section.Size > maxDWARFBytes {
			return nil
		}
		data, err := section.Data()
		if err != nil {
			return nil
		}
		pointerSize := 4
		if file.Class == elf.ELFCLASS64 {
			pointerSize = 8
		}
		return parseDwarfCFI(data, file.ByteOrder, pointerSize, section.Addr, elfPreferredBase(file))
	}
	if file, err := macho.NewFile(reader); err == nil {
		defer file.Close()
		return loadMachODwarfCFI(file)
	}
	fat, err := macho.NewFatFile(reader)
	if err != nil {
		return nil
	}
	defer fat.Close()
	for _, candidate := range fat.Arches {
		if architecture == "" || machoArchMatches(architecture, candidate.Cpu.String()) {
			if parsed := loadMachODwarfCFI(candidate.File); parsed != nil {
				return parsed
			}
		}
	}
	return nil
}

func loadMachODwarfCFI(file *macho.File) *dwarfCFI {
	section := file.Section("__eh_frame")
	if section == nil || section.Size == 0 || section.Size > maxDWARFBytes {
		return nil
	}
	data, err := section.Data()
	if err != nil {
		return nil
	}
	pointerSize := 4
	if file.Magic == macho.Magic64 {
		pointerSize = 8
	}
	base := uint64(0)
	if text := file.Segment("__TEXT"); text != nil {
		base = text.Addr
	}
	return parseDwarfCFI(data, file.ByteOrder, pointerSize, section.Addr, base)
}

func parseDwarfCFI(data []byte, order binary.ByteOrder, pointerSize int, sectionAddress, imageBase uint64) *dwarfCFI {
	if len(data) == 0 || uint64(len(data)) > maxDWARFBytes || (pointerSize != 4 && pointerSize != 8) {
		return nil
	}
	reader := &dwarfReader{data: data, order: order, pointerSize: pointerSize, sectionAddress: sectionAddress}
	cies := make(map[int]*dwarfCIE)
	result := &dwarfCFI{entries: make([]dwarfFDE, 0, 1024), order: order, pointerSize: pointerSize, imageBase: imageBase}
	for entries := 0; reader.offset < len(data) && entries < maxDwarfCFIEntries; entries++ {
		reader.limit = len(data)
		entryOffset := reader.offset
		length32, ok := reader.uint(4)
		if !ok {
			return nil
		}
		if length32 == 0 {
			break
		}
		length, idSize := length32, 4
		if length32 == 0xffffffff {
			var valid bool
			length, valid = reader.uint(8)
			if !valid {
				return nil
			}
			idSize = 8
		}
		if length < uint64(idSize) || length > maxDWARFBytes || uint64(reader.offset)+length > uint64(len(data)) {
			return nil
		}
		entryEnd := reader.offset + int(length)
		reader.limit = entryEnd
		idOffset := reader.offset
		id, ok := reader.uint(idSize)
		if !ok {
			return nil
		}
		if id == 0 {
			cie := parseDwarfCIE(reader, entryEnd)
			if cie != nil {
				cies[entryOffset] = cie
			}
			reader.offset = entryEnd
			continue
		}
		if id > uint64(idOffset) {
			reader.offset = entryEnd
			continue
		}
		cie := cies[idOffset-int(id)]
		if cie == nil {
			reader.offset = entryEnd
			continue
		}
		begin, ok := reader.encoded(cie.pointerEncoding)
		if !ok {
			reader.offset = entryEnd
			continue
		}
		size, ok := reader.encoded(cie.pointerEncoding & 0x0f)
		if !ok || size == 0 || begin+size < begin {
			reader.offset = entryEnd
			continue
		}
		if cie.augmentationData {
			augmentationLength, valid := reader.uleb()
			if !valid || reader.offset > entryEnd || augmentationLength > uint64(entryEnd-reader.offset) {
				reader.offset = entryEnd
				continue
			}
			reader.offset += int(augmentationLength)
		}
		if imageBase > 0 && begin >= imageBase {
			begin -= imageBase
		}
		instructions := append([]byte(nil), data[reader.offset:entryEnd]...)
		if len(instructions) <= maxDwarfCFIInstructions {
			result.entries = append(result.entries, dwarfFDE{begin: begin, size: size, cie: cie, instructions: instructions})
		}
		reader.offset = entryEnd
	}
	if len(result.entries) == 0 {
		return nil
	}
	sort.SliceStable(result.entries, func(left, right int) bool { return result.entries[left].begin < result.entries[right].begin })
	return result
}

func parseDwarfCIE(reader *dwarfReader, end int) *dwarfCIE {
	version, ok := reader.byte()
	if !ok || (version != 1 && version != 3 && version != 4) {
		return nil
	}
	augmentation, ok := reader.cstring(end)
	if !ok || (augmentation != "" && augmentation[0] != 'z') {
		return nil
	}
	if version == 4 {
		addressSize, valid := reader.byte()
		segmentSize, segmentValid := reader.byte()
		if !valid || !segmentValid || int(addressSize) != reader.pointerSize || segmentSize != 0 {
			return nil
		}
	}
	codeAlignment, ok := reader.uleb()
	if !ok || codeAlignment == 0 {
		return nil
	}
	dataAlignment, ok := reader.sleb()
	if !ok {
		return nil
	}
	var returnRegister uint64
	if version == 1 {
		value, valid := reader.byte()
		if !valid {
			return nil
		}
		returnRegister = uint64(value)
	} else {
		var valid bool
		returnRegister, valid = reader.uleb()
		if !valid {
			return nil
		}
	}
	cie := &dwarfCIE{codeAlignment: codeAlignment, dataAlignment: dataAlignment, returnRegister: returnRegister, pointerEncoding: 0}
	if augmentation != "" {
		length, valid := reader.uleb()
		if !valid || length > uint64(end-reader.offset) {
			return nil
		}
		augmentationEnd := reader.offset + int(length)
		cie.augmentationData = true
		for _, character := range augmentation[1:] {
			switch character {
			case 'L':
				if _, valid := reader.byte(); !valid {
					return nil
				}
			case 'R':
				encoding, valid := reader.byte()
				if !valid || encoding == 0xff {
					return nil
				}
				cie.pointerEncoding = encoding
			case 'P':
				encoding, valid := reader.byte()
				if !valid {
					return nil
				}
				if _, valid = reader.encoded(encoding &^ 0x80); !valid {
					return nil
				}
			case 'S':
			default:
				return nil
			}
			if reader.offset > augmentationEnd {
				return nil
			}
		}
		reader.offset = augmentationEnd
	}
	if reader.offset > end || end-reader.offset > maxDwarfCFIInstructions {
		return nil
	}
	cie.instructions = append([]byte(nil), reader.data[reader.offset:end]...)
	return cie
}

func (c *dwarfCFI) unwind(relative uint64, registers map[string]uint64, memory minidumpMemory, architecture string) map[string]uint64 {
	if c == nil {
		return nil
	}
	end := sort.Search(len(c.entries), func(index int) bool { return c.entries[index].begin > relative })
	var selected *dwarfFDE
	for index, checked := end-1, 0; index >= 0 && checked < 64; index, checked = index-1, checked+1 {
		entry := &c.entries[index]
		if relative >= entry.begin && relative-entry.begin < entry.size {
			selected = entry
			break
		}
	}
	if selected == nil {
		return nil
	}
	state := dwarfFrameState{imageBase: c.imageBase, cfa: dwarfRule{kind: dwarfRuleUndefined}, registers: make(map[uint64]dwarfRule)}
	if !executeDwarfCFI(selected.cie.instructions, selected.cie, &state, ^uint64(0), nil, c.order, c.pointerSize) {
		return nil
	}
	initial := cloneDwarfRules(state.registers)
	state.location = selected.begin
	if !executeDwarfCFI(selected.instructions, selected.cie, &state, relative, initial, c.order, c.pointerSize) || state.cfa.kind != dwarfRuleRegister {
		return nil
	}
	cfaRegister := dwarfRegisterName(architecture, state.cfa.register)
	cfaBase, ok := registers[cfaRegister]
	if !ok {
		return nil
	}
	cfa, ok := addDwarfOffset(cfaBase, state.cfa.offset)
	if !ok {
		return nil
	}
	next := cloneRegisters(registers)
	for number, rule := range state.registers {
		name := dwarfRegisterName(architecture, number)
		if name == "" {
			continue
		}
		value, valid := evaluateDwarfRule(rule, cfa, registers, memory, architecture)
		if valid {
			next[name] = value
		}
	}
	returnRule, ok := state.registers[selected.cie.returnRegister]
	if !ok {
		return nil
	}
	returnAddress, ok := evaluateDwarfRule(returnRule, cfa, registers, memory, architecture)
	if !ok || returnAddress == 0 {
		return nil
	}
	next[instructionRegister(architecture)] = returnAddress
	next[stackRegister(architecture)] = cfa
	return next
}

func executeDwarfCFI(instructions []byte, cie *dwarfCIE, state *dwarfFrameState, target uint64, initial map[uint64]dwarfRule, order binary.ByteOrder, pointerSize int) bool {
	if len(instructions) > maxDwarfCFIInstructions {
		return false
	}
	reader := &dwarfReader{data: instructions, order: order, pointerSize: pointerSize}
	stack := make([]dwarfFrameState, 0, 4)
	for operations := 0; reader.offset < len(instructions) && operations < maxDwarfCFIInstructions; operations++ {
		opcode, ok := reader.byte()
		if !ok {
			return false
		}
		primary := opcode & 0xc0
		switch primary {
		case 0x40:
			delta, valid := multiplyDwarfUnsigned(uint64(opcode&0x3f), cie.codeAlignment)
			if !valid || state.location > ^uint64(0)-delta {
				return false
			}
			state.location += delta
			if state.location > target {
				return true
			}
			continue
		case 0x80:
			offset, valid := reader.uleb()
			if !valid {
				return false
			}
			scaled, valid := multiplyDwarfOffset(offset, cie.dataAlignment)
			if !valid {
				return false
			}
			state.registers[uint64(opcode&0x3f)] = dwarfRule{kind: dwarfRuleOffset, offset: scaled}
			continue
		case 0xc0:
			register := uint64(opcode & 0x3f)
			if rule, exists := initial[register]; exists {
				state.registers[register] = rule
			} else {
				delete(state.registers, register)
			}
			continue
		}
		switch opcode {
		case 0x00:
		case 0x01:
			location, valid := reader.uint(reader.pointerSize)
			if !valid {
				return false
			}
			if state.imageBase > 0 && location >= state.imageBase {
				location -= state.imageBase
			}
			state.location = location
			if state.location > target {
				return true
			}
		case 0x02, 0x03, 0x04:
			size := 1 << (opcode - 0x02)
			delta, valid := reader.uint(size)
			if !valid {
				return false
			}
			delta, valid = multiplyDwarfUnsigned(delta, cie.codeAlignment)
			if !valid || state.location > ^uint64(0)-delta {
				return false
			}
			state.location += delta
			if state.location > target {
				return true
			}
		case 0x05:
			register, valid := reader.uleb()
			offset, validOffset := reader.uleb()
			if !valid || !validOffset {
				return false
			}
			scaled, scaledValid := multiplyDwarfOffset(offset, cie.dataAlignment)
			if !scaledValid {
				return false
			}
			state.registers[register] = dwarfRule{kind: dwarfRuleOffset, offset: scaled}
		case 0x06:
			register, valid := reader.uleb()
			if !valid {
				return false
			}
			if rule, exists := initial[register]; exists {
				state.registers[register] = rule
			} else {
				delete(state.registers, register)
			}
		case 0x07, 0x08:
			register, valid := reader.uleb()
			if !valid {
				return false
			}
			kind := dwarfRuleUndefined
			if opcode == 0x08 {
				kind = dwarfRuleSame
			}
			state.registers[register] = dwarfRule{kind: kind, register: register}
		case 0x09:
			register, valid := reader.uleb()
			source, sourceValid := reader.uleb()
			if !valid || !sourceValid {
				return false
			}
			state.registers[register] = dwarfRule{kind: dwarfRuleRegister, register: source}
		case 0x0a:
			if len(stack) >= maxDwarfCFIStateDepth {
				return false
			}
			stack = append(stack, dwarfFrameState{cfa: state.cfa, registers: cloneDwarfRules(state.registers)})
		case 0x0b:
			if len(stack) == 0 {
				return false
			}
			restored := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			state.cfa, state.registers = restored.cfa, restored.registers
		case 0x0c:
			register, valid := reader.uleb()
			offset, offsetValid := reader.uleb()
			if !valid || !offsetValid || offset > uint64(^uint64(0)>>1) {
				return false
			}
			state.cfa = dwarfRule{kind: dwarfRuleRegister, register: register, offset: int64(offset)}
		case 0x0d:
			register, valid := reader.uleb()
			if !valid || state.cfa.kind != dwarfRuleRegister {
				return false
			}
			state.cfa.register = register
		case 0x0e:
			offset, valid := reader.uleb()
			if !valid || state.cfa.kind != dwarfRuleRegister || offset > uint64(^uint64(0)>>1) {
				return false
			}
			state.cfa.offset = int64(offset)
		case 0x0f:
			if !reader.skipBlock() {
				return false
			}
			state.cfa.kind = dwarfRuleUndefined
		case 0x10, 0x16:
			register, valid := reader.uleb()
			if !valid || !reader.skipBlock() {
				return false
			}
			state.registers[register] = dwarfRule{kind: dwarfRuleUndefined}
		case 0x11, 0x14:
			register, valid := reader.uleb()
			offset, offsetValid := reader.sleb()
			if !valid || !offsetValid {
				return false
			}
			kind := dwarfRuleOffset
			if opcode == 0x14 {
				kind = dwarfRuleValueOffset
			}
			scaled, scaledValid := multiplyDwarfSigned(offset, cie.dataAlignment)
			if !scaledValid {
				return false
			}
			state.registers[register] = dwarfRule{kind: kind, offset: scaled}
		case 0x12:
			register, valid := reader.uleb()
			offset, offsetValid := reader.sleb()
			if !valid || !offsetValid {
				return false
			}
			scaled, scaledValid := multiplyDwarfSigned(offset, cie.dataAlignment)
			if !scaledValid {
				return false
			}
			state.cfa = dwarfRule{kind: dwarfRuleRegister, register: register, offset: scaled}
		case 0x13:
			offset, valid := reader.sleb()
			if !valid || state.cfa.kind != dwarfRuleRegister {
				return false
			}
			scaled, scaledValid := multiplyDwarfSigned(offset, cie.dataAlignment)
			if !scaledValid {
				return false
			}
			state.cfa.offset = scaled
		case 0x15:
			register, valid := reader.uleb()
			offset, offsetValid := reader.uleb()
			if !valid || !offsetValid {
				return false
			}
			scaled, scaledValid := multiplyDwarfOffset(offset, cie.dataAlignment)
			if !scaledValid {
				return false
			}
			state.registers[register] = dwarfRule{kind: dwarfRuleValueOffset, offset: scaled}
		case 0x2d:
		case 0x2e:
			if _, valid := reader.uleb(); !valid {
				return false
			}
		default:
			return false
		}
	}
	return reader.offset == len(instructions)
}

func evaluateDwarfRule(rule dwarfRule, cfa uint64, registers map[string]uint64, memory minidumpMemory, architecture string) (uint64, bool) {
	switch rule.kind {
	case dwarfRuleSame:
		value, ok := registers[dwarfRegisterName(architecture, rule.register)]
		return value, ok
	case dwarfRuleRegister:
		value, ok := registers[dwarfRegisterName(architecture, rule.register)]
		return value, ok
	case dwarfRuleOffset:
		address, ok := addDwarfOffset(cfa, rule.offset)
		if !ok {
			return 0, false
		}
		return memory.readPointer(address)
	case dwarfRuleValueOffset:
		return addDwarfOffset(cfa, rule.offset)
	default:
		return 0, false
	}
}

func dwarfRegisterName(architecture string, number uint64) string {
	switch architecture {
	case "x86":
		names := []string{"eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi", "eip"}
		if number < uint64(len(names)) {
			return names[number]
		}
	case "x86_64":
		names := []string{"rax", "rdx", "rcx", "rbx", "rsi", "rdi", "rbp", "rsp", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rip"}
		if number < uint64(len(names)) {
			return names[number]
		}
	case "arm64":
		if number <= 28 {
			return "x" + dwarfRegisterDecimal(number)
		}
		switch number {
		case 29:
			return "fp"
		case 30:
			return "lr"
		case 31:
			return "sp"
		case 32:
			return "pc"
		}
	}
	return ""
}

func dwarfRegisterDecimal(value uint64) string {
	if value < 10 {
		return string(rune('0' + value))
	}
	return string([]byte{byte('0' + value/10), byte('0' + value%10)})
}

func addDwarfOffset(value uint64, offset int64) (uint64, bool) {
	if offset >= 0 {
		amount := uint64(offset)
		return value + amount, value <= ^uint64(0)-amount
	}
	amount := uint64(-(offset + 1)) + 1
	return value - amount, value >= amount
}

func multiplyDwarfUnsigned(left, right uint64) (uint64, bool) {
	if left != 0 && right > ^uint64(0)/left {
		return 0, false
	}
	return left * right, true
}

func multiplyDwarfOffset(value uint64, factor int64) (int64, bool) {
	if value > uint64(^uint64(0)>>1) {
		return 0, false
	}
	return multiplyDwarfSigned(int64(value), factor)
}

func multiplyDwarfSigned(left, right int64) (int64, bool) {
	if left == 0 || right == 0 {
		return 0, true
	}
	if left == -1 && right == -1<<63 || right == -1 && left == -1<<63 {
		return 0, false
	}
	result := left * right
	return result, result/right == left
}

func cloneDwarfRules(source map[uint64]dwarfRule) map[uint64]dwarfRule {
	result := make(map[uint64]dwarfRule, len(source))
	for register, rule := range source {
		result[register] = rule
	}
	return result
}

func (r *dwarfReader) byte() (byte, bool) {
	if r.offset >= r.end() {
		return 0, false
	}
	value := r.data[r.offset]
	r.offset++
	return value, true
}

func (r *dwarfReader) uint(size int) (uint64, bool) {
	if size <= 0 || r.offset+size < r.offset || r.offset+size > r.end() {
		return 0, false
	}
	data := r.data[r.offset : r.offset+size]
	r.offset += size
	switch size {
	case 1:
		return uint64(data[0]), true
	case 2:
		return uint64(r.order.Uint16(data)), true
	case 4:
		return uint64(r.order.Uint32(data)), true
	case 8:
		return r.order.Uint64(data), true
	default:
		return 0, false
	}
}

func (r *dwarfReader) uleb() (uint64, bool) {
	var value uint64
	for shift := uint(0); shift < 64; shift += 7 {
		part, ok := r.byte()
		if !ok || shift == 63 && part > 1 {
			return 0, false
		}
		value |= uint64(part&0x7f) << shift
		if part&0x80 == 0 {
			return value, true
		}
	}
	return 0, false
}

func (r *dwarfReader) sleb() (int64, bool) {
	var value uint64
	var part byte
	var shift uint
	for ; shift < 64; shift += 7 {
		var ok bool
		part, ok = r.byte()
		if !ok {
			return 0, false
		}
		value |= uint64(part&0x7f) << shift
		if part&0x80 == 0 {
			shift += 7
			if shift < 64 && part&0x40 != 0 {
				value |= ^uint64(0) << shift
			}
			return int64(value), true
		}
	}
	return 0, false
}

func (r *dwarfReader) cstring(end int) (string, bool) {
	if limit := r.end(); end > limit {
		end = limit
	}
	start := r.offset
	for r.offset < end && r.offset < len(r.data) {
		if r.data[r.offset] == 0 {
			value := string(r.data[start:r.offset])
			r.offset++
			return value, true
		}
		r.offset++
	}
	return "", false
}

func (r *dwarfReader) encoded(encoding byte) (uint64, bool) {
	if encoding == 0xff || encoding&0x70 != 0 && encoding&0x70 != 0x10 || encoding&0x80 != 0 {
		return 0, false
	}
	base := uint64(0)
	if encoding&0x70 == 0x10 {
		base = r.sectionAddress + uint64(r.offset)
	}
	format := encoding & 0x0f
	var raw uint64
	var signed int64
	var ok bool
	switch format {
	case 0x00:
		raw, ok = r.uint(r.pointerSize)
	case 0x08:
		raw, ok = r.uint(r.pointerSize)
		if ok {
			if r.pointerSize == 4 {
				signed = int64(int32(raw))
			} else {
				signed = int64(raw)
			}
		}
	case 0x01:
		raw, ok = r.uleb()
	case 0x02, 0x03, 0x04:
		raw, ok = r.uint(1 << (format - 1))
	case 0x09:
		signed, ok = r.sleb()
	case 0x0a, 0x0b, 0x0c:
		size := 1 << (format - 9)
		raw, ok = r.uint(size)
		if ok {
			switch size {
			case 2:
				signed = int64(int16(raw))
			case 4:
				signed = int64(int32(raw))
			case 8:
				signed = int64(raw)
			}
		}
	default:
		return 0, false
	}
	if !ok {
		return 0, false
	}
	if format == 0x08 || format == 0x09 || format >= 0x0a {
		return addDwarfOffset(base, signed)
	}
	if raw > ^uint64(0)-base {
		return 0, false
	}
	return base + raw, true
}

func (r *dwarfReader) skipBlock() bool {
	length, ok := r.uleb()
	if !ok || r.offset > r.end() || length > uint64(r.end()-r.offset) {
		return false
	}
	r.offset += int(length)
	return true
}

func (r *dwarfReader) end() int {
	if r.limit > 0 && r.limit < len(r.data) {
		return r.limit
	}
	return len(r.data)
}
