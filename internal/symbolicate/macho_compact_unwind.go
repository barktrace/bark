package symbolicate

import (
	"debug/macho"
	"encoding/binary"
	"io"
	"sort"
)

const (
	maxMachOCompactEntries = 500000

	compactUnwindVersion             = 1
	compactUnwindPageRegular         = 2
	compactUnwindPageCompressed      = 3
	compactUnwindModeMask            = 0x0f000000
	compactUnwindX8664RBPFrame       = 0x01000000
	compactUnwindX8664StackImmediate = 0x02000000
	compactUnwindX8664StackIndirect  = 0x03000000
	compactUnwindX86EBPFrame         = 0x01000000
	compactUnwindX86StackImmediate   = 0x02000000
	compactUnwindX86StackIndirect    = 0x03000000
	compactUnwindARM64Frameless      = 0x02000000
	compactUnwindARM64DWARF          = 0x03000000
	compactUnwindARM64Frame          = 0x04000000
)

type machoCompactUnwind struct {
	entries      []machoCompactEntry
	architecture string
	textAddress  uint64
	imageBase    uint64
	text         []byte
}

type machoCompactEntry struct {
	begin, end uint64
	encoding   uint32
}

type machoCompactIndex struct {
	function, page uint32
}

func loadMachOCompactUnwind(reader io.ReaderAt, architecture string) *machoCompactUnwind {
	if file, err := macho.NewFile(reader); err == nil {
		defer file.Close()
		if architecture != "" && !machoArchMatches(architecture, file.Cpu.String()) {
			return nil
		}
		return loadMachOCompactFile(file, architecture)
	}
	fat, err := macho.NewFatFile(reader)
	if err != nil {
		return nil
	}
	defer fat.Close()
	for _, candidate := range fat.Arches {
		if architecture == "" || machoArchMatches(architecture, candidate.Cpu.String()) {
			if parsed := loadMachOCompactFile(candidate.File, architecture); parsed != nil {
				return parsed
			}
		}
	}
	return nil
}

func loadMachOCompactFile(file *macho.File, architecture string) *machoCompactUnwind {
	section := file.Section("__unwind_info")
	if section == nil || section.Size == 0 || section.Size > maxDWARFBytes {
		return nil
	}
	data, err := section.Data()
	if err != nil {
		return nil
	}
	if architecture == "" {
		architecture = compactMachOArchitecture(file.Cpu)
	}
	base := uint64(0)
	if segment := file.Segment("__TEXT"); segment != nil {
		base = segment.Addr
	}
	parsed := parseMachOCompactUnwind(data, file.ByteOrder, architecture)
	if parsed == nil {
		return nil
	}
	parsed.imageBase = base
	if textSection := file.Section("__text"); textSection != nil && textSection.Size <= maxDWARFBytes {
		if text, dataErr := textSection.Data(); dataErr == nil {
			parsed.textAddress = textSection.Addr
			parsed.text = text
		}
	}
	return parsed
}

func parseMachOCompactUnwind(data []byte, order binary.ByteOrder, architecture string) *machoCompactUnwind {
	if len(data) < 28 || uint64(len(data)) > maxDWARFBytes || order == nil {
		return nil
	}
	u32 := func(offset int) (uint32, bool) {
		if offset < 0 || offset > len(data)-4 {
			return 0, false
		}
		return order.Uint32(data[offset : offset+4]), true
	}
	u16 := func(offset int) (uint16, bool) {
		if offset < 0 || offset > len(data)-2 {
			return 0, false
		}
		return order.Uint16(data[offset : offset+2]), true
	}
	version, _ := u32(0)
	commonOffset, _ := u32(4)
	commonCount, _ := u32(8)
	indexOffset, _ := u32(20)
	indexCount, _ := u32(24)
	if version != compactUnwindVersion || indexCount < 2 || indexCount > maxMachOCompactEntries || commonCount > 256 {
		return nil
	}
	if !compactRange(data, commonOffset, commonCount, 4) || !compactRange(data, indexOffset, indexCount, 12) {
		return nil
	}
	common := make([]uint32, commonCount)
	for index := range common {
		common[index], _ = u32(int(commonOffset) + index*4)
	}
	indexes := make([]machoCompactIndex, indexCount)
	for index := range indexes {
		offset := int(indexOffset) + index*12
		indexes[index].function, _ = u32(offset)
		indexes[index].page, _ = u32(offset + 4)
		if index > 0 && indexes[index].function < indexes[index-1].function {
			return nil
		}
	}
	entries := make([]machoCompactEntry, 0, min(int(indexCount)*32, maxMachOCompactEntries))
	for index := 0; index < len(indexes)-1 && len(entries) < maxMachOCompactEntries; index++ {
		pageOffset := indexes[index].page
		kind, ok := u32(int(pageOffset))
		if !ok {
			return nil
		}
		switch kind {
		case compactUnwindPageRegular:
			entryOffset, offsetOK := u16(int(pageOffset) + 4)
			entryCount, countOK := u16(int(pageOffset) + 6)
			start := uint64(pageOffset) + uint64(entryOffset)
			if !offsetOK || !countOK || !compactRange64(data, start, uint64(entryCount), 8) || len(entries)+int(entryCount) > maxMachOCompactEntries {
				return nil
			}
			for entry := 0; entry < int(entryCount); entry++ {
				offset := int(start) + entry*8
				function, _ := u32(offset)
				encoding, _ := u32(offset + 4)
				if function < indexes[index].function || function >= indexes[index+1].function {
					return nil
				}
				entries = append(entries, machoCompactEntry{begin: uint64(function), encoding: encoding})
			}
		case compactUnwindPageCompressed:
			entryOffset, offsetOK := u16(int(pageOffset) + 4)
			entryCount, countOK := u16(int(pageOffset) + 6)
			encodingOffset, encodingOffsetOK := u16(int(pageOffset) + 8)
			encodingCount, encodingCountOK := u16(int(pageOffset) + 10)
			entryStart := uint64(pageOffset) + uint64(entryOffset)
			encodingStart := uint64(pageOffset) + uint64(encodingOffset)
			if !offsetOK || !countOK || !encodingOffsetOK || !encodingCountOK ||
				!compactRange64(data, entryStart, uint64(entryCount), 4) || !compactRange64(data, encodingStart, uint64(encodingCount), 4) ||
				len(entries)+int(entryCount) > maxMachOCompactEntries {
				return nil
			}
			local := make([]uint32, encodingCount)
			for encoding := range local {
				local[encoding], _ = u32(int(encodingStart) + encoding*4)
			}
			for entry := 0; entry < int(entryCount); entry++ {
				packed, _ := u32(int(entryStart) + entry*4)
				encodingIndex := int(packed >> 24)
				var encoding uint32
				if encodingIndex < len(common) {
					encoding = common[encodingIndex]
				} else if encodingIndex-len(common) < len(local) {
					encoding = local[encodingIndex-len(common)]
				} else {
					return nil
				}
				function := uint64(indexes[index].function) + uint64(packed&0x00ffffff)
				if function >= uint64(indexes[index+1].function) {
					return nil
				}
				entries = append(entries, machoCompactEntry{begin: function, encoding: encoding})
			}
		default:
			return nil
		}
	}
	if len(entries) == 0 {
		return nil
	}
	sort.SliceStable(entries, func(left, right int) bool { return entries[left].begin < entries[right].begin })
	compacted := entries[:0]
	for _, entry := range entries {
		if len(compacted) > 0 && compacted[len(compacted)-1].begin == entry.begin {
			if compacted[len(compacted)-1].encoding == 0 {
				compacted[len(compacted)-1].encoding = entry.encoding
			}
			continue
		}
		compacted = append(compacted, entry)
	}
	for index := range compacted {
		if index+1 < len(compacted) {
			compacted[index].end = compacted[index+1].begin
		} else {
			compacted[index].end = uint64(indexes[len(indexes)-1].function)
		}
		if compacted[index].end <= compacted[index].begin {
			return nil
		}
	}
	return &machoCompactUnwind{entries: compacted, architecture: architecture}
}

func compactRange(data []byte, offset, count uint32, width uint64) bool {
	return compactRange64(data, uint64(offset), uint64(count), width)
}

func compactRange64(data []byte, offset, count, width uint64) bool {
	if count != 0 && width > ^uint64(0)/count {
		return false
	}
	size := count * width
	return offset <= uint64(len(data)) && size <= uint64(len(data))-offset
}

func compactMachOArchitecture(cpu macho.Cpu) string {
	switch cpu {
	case macho.CpuAmd64:
		return "x86_64"
	case macho.CpuArm64:
		return "arm64"
	case macho.Cpu386:
		return "x86"
	default:
		return ""
	}
}

func (c *machoCompactUnwind) unwind(relative uint64, registers map[string]uint64, memory minidumpMemory, architecture string) map[string]uint64 {
	if c == nil || len(c.entries) == 0 || (c.architecture != "" && !machoArchMatches(architecture, c.architecture)) {
		return nil
	}
	index := sort.Search(len(c.entries), func(index int) bool { return c.entries[index].begin > relative }) - 1
	if index < 0 || relative >= c.entries[index].end || c.entries[index].encoding == 0 {
		return nil
	}
	entry := c.entries[index]
	switch architecture {
	case "x86":
		return c.unwindX86(entry, registers, memory)
	case "x86_64":
		return c.unwindX8664(entry, registers, memory)
	case "arm64":
		return c.unwindARM64(entry, registers, memory)
	default:
		return nil
	}
}

func (c *machoCompactUnwind) unwindX86(entry machoCompactEntry, registers map[string]uint64, memory minidumpMemory) map[string]uint64 {
	if memory.pointerSize != 4 {
		return nil
	}
	var callerSP, returnSlot uint64
	next := cloneRegisters(registers)
	switch entry.encoding & compactUnwindModeMask {
	case compactUnwindX86EBPFrame:
		frame := registers["ebp"]
		if frame == 0 || frame > ^uint64(0)-8 {
			return nil
		}
		savedOffset := uint64((entry.encoding & 0x00ff0000) >> 16)
		if savedOffset > frame/4 || !restoreX86EBPRegisters(next, memory, frame-savedOffset*4, entry.encoding&0x00007fff) {
			return nil
		}
		callerFrame, ok := memory.readPointer(frame)
		if !ok {
			return nil
		}
		next["ebp"] = callerFrame
		callerSP, returnSlot = frame+8, frame+4
	case compactUnwindX86StackImmediate, compactUnwindX86StackIndirect:
		stackSize := uint64((entry.encoding & 0x00ff0000) >> 16)
		if entry.encoding&compactUnwindModeMask == compactUnwindX86StackIndirect {
			immediate, ok := c.x86StackImmediate(entry.begin, stackSize)
			if !ok {
				return nil
			}
			stackSize = uint64(immediate) + uint64((entry.encoding&0x0000e000)>>13)*4
		} else {
			stackSize *= 4
		}
		stack := registers["esp"]
		if stackSize < 4 || stack > ^uint64(0)-stackSize {
			return nil
		}
		callerSP, returnSlot = stack+stackSize, stack+stackSize-4
		registerCount := uint32((entry.encoding & 0x00001c00) >> 10)
		if registerCount > 6 || returnSlot < uint64(registerCount)*4 || !restoreX86FramelessRegisters(next, memory, returnSlot-uint64(registerCount)*4, registerCount, entry.encoding&0x000003ff) {
			return nil
		}
	default:
		return nil
	}
	returnAddress, ok := memory.readPointer(returnSlot)
	if !ok || returnAddress == 0 {
		return nil
	}
	next["eip"], next["esp"] = returnAddress, callerSP
	return next
}

func restoreX86EBPRegisters(registers map[string]uint64, memory minidumpMemory, address uint64, encoded uint32) bool {
	names := []string{"", "ebx", "ecx", "edx", "edi", "esi"}
	for slot := 0; slot < 5; slot++ {
		register := encoded & 7
		if register >= uint32(len(names)) {
			return false
		}
		if register != 0 {
			value, ok := memory.readPointer(address)
			if !ok {
				return false
			}
			registers[names[register]] = value
		}
		if address > ^uint64(0)-4 {
			return false
		}
		address += 4
		encoded >>= 3
	}
	return true
}

func restoreX86FramelessRegisters(registers map[string]uint64, memory minidumpMemory, address uint64, count, permutation uint32) bool {
	return restoreX86Permutation(registers, memory, address, count, permutation, 4, []string{"", "ebx", "ecx", "edx", "edi", "esi", "ebp"})
}

func (c *machoCompactUnwind) unwindX8664(entry machoCompactEntry, registers map[string]uint64, memory minidumpMemory) map[string]uint64 {
	var callerSP, returnSlot uint64
	next := cloneRegisters(registers)
	switch entry.encoding & compactUnwindModeMask {
	case compactUnwindX8664RBPFrame:
		frame := registers["rbp"]
		if frame == 0 || frame > ^uint64(0)-16 {
			return nil
		}
		savedOffset := uint64((entry.encoding & 0x00ff0000) >> 16)
		if savedOffset > frame/8 || !restoreX8664RBPRegisters(next, memory, frame-savedOffset*8, entry.encoding&0x00007fff) {
			return nil
		}
		callerFrame, ok := memory.readPointer(frame)
		if !ok {
			return nil
		}
		next["rbp"] = callerFrame
		callerSP, returnSlot = frame+16, frame+8
	case compactUnwindX8664StackImmediate, compactUnwindX8664StackIndirect:
		stackSize := uint64((entry.encoding & 0x00ff0000) >> 16)
		if entry.encoding&compactUnwindModeMask == compactUnwindX8664StackIndirect {
			immediate, ok := c.x8664StackImmediate(entry.begin, stackSize)
			if !ok {
				return nil
			}
			stackSize = uint64(immediate) + uint64((entry.encoding&0x0000e000)>>13)*8
		} else {
			stackSize *= 8
		}
		stack := registers["rsp"]
		if stackSize < 8 || stack > ^uint64(0)-stackSize {
			return nil
		}
		callerSP, returnSlot = stack+stackSize, stack+stackSize-8
		registerCount := uint32((entry.encoding & 0x00001c00) >> 10)
		if registerCount > 6 || returnSlot < uint64(registerCount)*8 || !restoreX8664FramelessRegisters(next, memory, returnSlot-uint64(registerCount)*8, registerCount, entry.encoding&0x000003ff) {
			return nil
		}
	default:
		return nil
	}
	returnAddress, ok := memory.readPointer(returnSlot)
	if !ok || returnAddress == 0 {
		return nil
	}
	next["rip"], next["rsp"] = returnAddress, callerSP
	return next
}

func restoreX8664RBPRegisters(registers map[string]uint64, memory minidumpMemory, address uint64, encoded uint32) bool {
	names := []string{"", "rbx", "r12", "r13", "r14", "r15"}
	for slot := 0; slot < 5; slot++ {
		register := encoded & 7
		if register >= uint32(len(names)) {
			return false
		}
		if register != 0 {
			value, ok := memory.readPointer(address)
			if !ok {
				return false
			}
			registers[names[register]] = value
		}
		if address > ^uint64(0)-8 {
			return false
		}
		address += 8
		encoded >>= 3
	}
	return true
}

func restoreX8664FramelessRegisters(registers map[string]uint64, memory minidumpMemory, address uint64, count, permutation uint32) bool {
	return restoreX86Permutation(registers, memory, address, count, permutation, 8, []string{"", "rbx", "r12", "r13", "r14", "r15", "rbp"})
}

func restoreX86Permutation(registers map[string]uint64, memory minidumpMemory, address uint64, count, permutation uint32, pointerSize uint64, registerNames []string) bool {
	if count == 0 {
		return true
	}
	weights := [6][6]uint32{
		{1}, {5, 1}, {20, 4, 1}, {60, 12, 3, 1}, {120, 24, 6, 2, 1}, {120, 24, 6, 2, 1, 1},
	}
	permuted := make([]uint32, count)
	for index := uint32(0); index < count; index++ {
		weight := weights[count-1][index]
		permuted[index] = permutation / weight
		permutation %= weight
	}
	used := [7]bool{}
	for _, ordinal := range permuted {
		var register uint32
		for candidate := uint32(1); candidate < 7; candidate++ {
			if used[candidate] {
				continue
			}
			if ordinal == 0 {
				register = candidate
				break
			}
			ordinal--
		}
		if register == 0 {
			return false
		}
		value, ok := memory.readPointer(address)
		if !ok {
			return false
		}
		registers[registerNames[register]] = value
		used[register] = true
		if address > ^uint64(0)-pointerSize {
			return false
		}
		address += pointerSize
	}
	return true
}

func (c *machoCompactUnwind) x8664StackImmediate(function, instructionOffset uint64) (uint32, bool) {
	return c.x86StackImmediate(function, instructionOffset)
}

func (c *machoCompactUnwind) x86StackImmediate(function, instructionOffset uint64) (uint32, bool) {
	if function > ^uint64(0)-c.imageBase || instructionOffset > ^uint64(0)-(c.imageBase+function) {
		return 0, false
	}
	address := c.imageBase + function + instructionOffset
	if address < c.textAddress || address-c.textAddress > uint64(len(c.text)) || uint64(len(c.text))-(address-c.textAddress) < 4 {
		return 0, false
	}
	offset := int(address - c.textAddress)
	return binary.LittleEndian.Uint32(c.text[offset : offset+4]), true
}

func (c *machoCompactUnwind) unwindARM64(entry machoCompactEntry, registers map[string]uint64, memory minidumpMemory) map[string]uint64 {
	next := cloneRegisters(registers)
	switch entry.encoding & compactUnwindModeMask {
	case compactUnwindARM64Frame:
		frame := registers["fp"]
		if frame < 8 || frame > ^uint64(0)-16 {
			return nil
		}
		if _, ok := restoreARM64RegisterPairs(next, memory, frame-8, entry.encoding, false); !ok {
			return nil
		}
		callerFrame, frameOK := memory.readPointer(frame)
		returnAddress, returnOK := memory.readPointer(frame + 8)
		if !frameOK || !returnOK || returnAddress == 0 {
			return nil
		}
		next["fp"], next["lr"], next["pc"], next["sp"] = callerFrame, returnAddress, returnAddress, frame+16
		return next
	case compactUnwindARM64Frameless:
		stackSize := uint64((entry.encoding&0x00fff000)>>12) * 16
		stack, returnAddress := registers["sp"], registers["lr"]
		if returnAddress == 0 || stack > ^uint64(0)-stackSize {
			return nil
		}
		savedRegisterLocation, ok := restoreARM64RegisterPairs(next, memory, stack+stackSize, entry.encoding, true)
		if !ok {
			return nil
		}
		next["pc"], next["sp"] = returnAddress, savedRegisterLocation
		return next
	case compactUnwindARM64DWARF:
		return nil
	default:
		return nil
	}
}

func restoreARM64RegisterPairs(registers map[string]uint64, memory minidumpMemory, address uint64, encoding uint32, includeFloat bool) (uint64, bool) {
	pairCount := 5
	if includeFloat {
		pairCount = 9
	}
	for pair := 0; pair < pairCount; pair++ {
		bit := uint32(1 << pair)
		if pair >= 5 {
			bit = uint32(1 << (pair + 3))
		}
		if encoding&bit == 0 {
			continue
		}
		for member := 0; member < 2; member++ {
			value, ok := memory.readPointer(address)
			if !ok || address < 8 {
				return 0, false
			}
			if pair < 5 {
				registers["x"+dwarfRegisterDecimal(uint64(19+pair*2+member))] = value
			}
			address -= 8
		}
	}
	return address, true
}
