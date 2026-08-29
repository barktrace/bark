package symbolicate

import "encoding/binary"

const (
	maxDwarfExpressionBytes      = 64 << 10
	maxDwarfExpressionOperations = 4096
	maxDwarfExpressionStack      = 64
)

type dwarfExpressionValue struct {
	value  uint64
	direct bool
}

func evaluateDwarfExpression(expression []byte, registers map[string]uint64, memory minidumpMemory, architecture string, cfa uint64, cfaValid bool, order binary.ByteOrder, pointerSize int) (uint64, bool, bool) {
	if len(expression) == 0 || len(expression) > maxDwarfExpressionBytes || order == nil || pointerSize != 4 && pointerSize != 8 {
		return 0, false, false
	}
	reader := &dwarfReader{data: expression, order: order, pointerSize: pointerSize}
	stack := make([]dwarfExpressionValue, 0, 8)
	push := func(value dwarfExpressionValue) bool {
		if len(stack) >= maxDwarfExpressionStack {
			return false
		}
		stack = append(stack, value)
		return true
	}
	pop := func() (dwarfExpressionValue, bool) {
		if len(stack) == 0 {
			return dwarfExpressionValue{}, false
		}
		value := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		return value, true
	}
	operations := 0
	for reader.offset < len(expression) && operations < maxDwarfExpressionOperations {
		operations++
		opcode, ok := reader.byte()
		if !ok {
			return 0, false, false
		}
		switch {
		case opcode >= 0x30 && opcode <= 0x4f: // DW_OP_lit0..31
			if !push(dwarfExpressionValue{value: uint64(opcode - 0x30)}) {
				return 0, false, false
			}
			continue
		case opcode >= 0x50 && opcode <= 0x6f: // DW_OP_reg0..31
			value, valid := dwarfExpressionRegister(registers, architecture, uint64(opcode-0x50))
			if !valid || !push(dwarfExpressionValue{value: value, direct: true}) {
				return 0, false, false
			}
			continue
		case opcode >= 0x70 && opcode <= 0x8f: // DW_OP_breg0..31
			base, valid := dwarfExpressionRegister(registers, architecture, uint64(opcode-0x70))
			offset, offsetValid := reader.sleb()
			value, addValid := addDwarfOffset(base, offset)
			if !valid || !offsetValid || !addValid || !push(dwarfExpressionValue{value: value}) {
				return 0, false, false
			}
			continue
		}
		switch opcode {
		case 0x03: // DW_OP_addr
			value, valid := reader.uint(pointerSize)
			if !valid || !push(dwarfExpressionValue{value: value}) {
				return 0, false, false
			}
		case 0x06: // DW_OP_deref
			address, valid := pop()
			if !valid {
				return 0, false, false
			}
			value, valid := readDwarfMemory(memory, address.value, pointerSize, order)
			if !valid || !push(dwarfExpressionValue{value: value}) {
				return 0, false, false
			}
		case 0x08, 0x0a, 0x0c, 0x0e: // DW_OP_const*u
			size := 1 << ((opcode - 0x08) / 2)
			value, valid := reader.uint(size)
			if !valid || !push(dwarfExpressionValue{value: value}) {
				return 0, false, false
			}
		case 0x09, 0x0b, 0x0d, 0x0f: // DW_OP_const*s
			size := 1 << ((opcode - 0x09) / 2)
			raw, valid := reader.uint(size)
			if !valid || !push(dwarfExpressionValue{value: signExtendDwarf(raw, size)}) {
				return 0, false, false
			}
		case 0x10: // DW_OP_constu
			value, valid := reader.uleb()
			if !valid || !push(dwarfExpressionValue{value: value}) {
				return 0, false, false
			}
		case 0x11: // DW_OP_consts
			value, valid := reader.sleb()
			if !valid || !push(dwarfExpressionValue{value: uint64(value)}) {
				return 0, false, false
			}
		case 0x12: // DW_OP_dup
			if len(stack) == 0 || !push(stack[len(stack)-1]) {
				return 0, false, false
			}
		case 0x13: // DW_OP_drop
			if _, valid := pop(); !valid {
				return 0, false, false
			}
		case 0x14: // DW_OP_over
			if len(stack) < 2 || !push(stack[len(stack)-2]) {
				return 0, false, false
			}
		case 0x15: // DW_OP_pick
			index, valid := reader.byte()
			if !valid || int(index) >= len(stack) || !push(stack[len(stack)-1-int(index)]) {
				return 0, false, false
			}
		case 0x16: // DW_OP_swap
			if len(stack) < 2 {
				return 0, false, false
			}
			stack[len(stack)-1], stack[len(stack)-2] = stack[len(stack)-2], stack[len(stack)-1]
		case 0x17: // DW_OP_rot
			if len(stack) < 3 {
				return 0, false, false
			}
			last := len(stack) - 1
			stack[last-2], stack[last-1], stack[last] = stack[last-1], stack[last], stack[last-2]
		case 0x19: // DW_OP_abs
			value, valid := pop()
			if !valid {
				return 0, false, false
			}
			if signed := int64(value.value); signed < 0 {
				value.value = uint64(-signed)
			}
			value.direct = false
			if !push(value) {
				return 0, false, false
			}
		case 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x21, 0x22, 0x24, 0x25, 0x26, 0x27, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e:
			right, rightValid := pop()
			left, leftValid := pop()
			if !rightValid || !leftValid {
				return 0, false, false
			}
			value, valid := dwarfExpressionBinary(opcode, left.value, right.value)
			if !valid || !push(dwarfExpressionValue{value: value}) {
				return 0, false, false
			}
		case 0x1f: // DW_OP_neg
			value, valid := pop()
			if !valid || !push(dwarfExpressionValue{value: uint64(-int64(value.value))}) {
				return 0, false, false
			}
		case 0x20: // DW_OP_not
			value, valid := pop()
			if !valid || !push(dwarfExpressionValue{value: ^value.value}) {
				return 0, false, false
			}
		case 0x23: // DW_OP_plus_uconst
			left, leftValid := pop()
			right, rightValid := reader.uleb()
			if !leftValid || !rightValid || !push(dwarfExpressionValue{value: left.value + right}) {
				return 0, false, false
			}
		case 0x28: // DW_OP_bra
			condition, conditionValid := pop()
			offset, offsetValid := reader.uint(2)
			if !conditionValid || !offsetValid || condition.value != 0 && !branchDwarfExpression(reader, int16(offset)) {
				return 0, false, false
			}
		case 0x2f: // DW_OP_skip
			offset, valid := reader.uint(2)
			if !valid || !branchDwarfExpression(reader, int16(offset)) {
				return 0, false, false
			}
		case 0x90: // DW_OP_regx
			register, valid := reader.uleb()
			value, registerValid := dwarfExpressionRegister(registers, architecture, register)
			if !valid || !registerValid || !push(dwarfExpressionValue{value: value, direct: true}) {
				return 0, false, false
			}
		case 0x92: // DW_OP_bregx
			register, valid := reader.uleb()
			offset, offsetValid := reader.sleb()
			base, registerValid := dwarfExpressionRegister(registers, architecture, register)
			value, addValid := addDwarfOffset(base, offset)
			if !valid || !offsetValid || !registerValid || !addValid || !push(dwarfExpressionValue{value: value}) {
				return 0, false, false
			}
		case 0x94: // DW_OP_deref_size
			size, sizeValid := reader.byte()
			address, addressValid := pop()
			value, readValid := readDwarfMemory(memory, address.value, int(size), order)
			if !sizeValid || !addressValid || !readValid || !push(dwarfExpressionValue{value: value}) {
				return 0, false, false
			}
		case 0x96: // DW_OP_nop
		case 0x9c: // DW_OP_call_frame_cfa
			if !cfaValid || !push(dwarfExpressionValue{value: cfa}) {
				return 0, false, false
			}
		case 0x9e: // DW_OP_implicit_value
			length, valid := reader.uleb()
			if !valid || length == 0 || length > 8 || length > uint64(len(expression)-reader.offset) {
				return 0, false, false
			}
			value := dwarfExpressionBytes(expression[reader.offset:reader.offset+int(length)], order)
			reader.offset += int(length)
			if !push(dwarfExpressionValue{value: value, direct: true}) {
				return 0, false, false
			}
		case 0x9f: // DW_OP_stack_value
			if len(stack) == 0 {
				return 0, false, false
			}
			stack[len(stack)-1].direct = true
		default:
			return 0, false, false
		}
	}
	if reader.offset != len(expression) || len(stack) == 0 {
		return 0, false, false
	}
	result := stack[len(stack)-1]
	return result.value, result.direct, true
}

func dwarfExpressionRegister(registers map[string]uint64, architecture string, number uint64) (uint64, bool) {
	name := dwarfRegisterName(architecture, number)
	if name == "" {
		return 0, false
	}
	value, ok := registers[name]
	return value, ok
}

func dwarfExpressionBinary(opcode byte, left, right uint64) (uint64, bool) {
	switch opcode {
	case 0x1a:
		return left & right, true
	case 0x1b:
		if right == 0 || left == uint64(1)<<63 && right == ^uint64(0) {
			return 0, false
		}
		return uint64(int64(left) / int64(right)), true
	case 0x1c:
		return left - right, true
	case 0x1d:
		if right == 0 {
			return 0, false
		}
		return left % right, true
	case 0x1e:
		return left * right, true
	case 0x21:
		return left | right, true
	case 0x22:
		return left + right, true
	case 0x24:
		return left << right, true
	case 0x25:
		return left >> right, true
	case 0x26:
		return uint64(int64(left) >> right), true
	case 0x27:
		return left ^ right, true
	case 0x29:
		return dwarfExpressionBool(left == right), true
	case 0x2a:
		return dwarfExpressionBool(int64(left) >= int64(right)), true
	case 0x2b:
		return dwarfExpressionBool(int64(left) > int64(right)), true
	case 0x2c:
		return dwarfExpressionBool(int64(left) <= int64(right)), true
	case 0x2d:
		return dwarfExpressionBool(int64(left) < int64(right)), true
	case 0x2e:
		return dwarfExpressionBool(left != right), true
	default:
		return 0, false
	}
}

func dwarfExpressionBool(value bool) uint64 {
	if value {
		return 1
	}
	return 0
}

func branchDwarfExpression(reader *dwarfReader, offset int16) bool {
	target := int64(reader.offset) + int64(offset)
	if target < 0 || target > int64(len(reader.data)) {
		return false
	}
	reader.offset = int(target)
	return true
}

func readDwarfMemory(memory minidumpMemory, address uint64, size int, order binary.ByteOrder) (uint64, bool) {
	if size != 1 && size != 2 && size != 4 && size != 8 || address < memory.address || address-memory.address > uint64(len(memory.data)) || uint64(size) > uint64(len(memory.data))-(address-memory.address) {
		return 0, false
	}
	offset := int(address - memory.address)
	return dwarfExpressionBytes(memory.data[offset:offset+size], order), true
}

func dwarfExpressionBytes(data []byte, order binary.ByteOrder) uint64 {
	switch len(data) {
	case 1:
		return uint64(data[0])
	case 2:
		return uint64(order.Uint16(data))
	case 4:
		return uint64(order.Uint32(data))
	case 8:
		return order.Uint64(data)
	default:
		var value uint64
		if order == binary.LittleEndian {
			for index := len(data) - 1; index >= 0; index-- {
				value = value<<8 | uint64(data[index])
			}
		} else {
			for _, part := range data {
				value = value<<8 | uint64(part)
			}
		}
		return value
	}
}

func signExtendDwarf(value uint64, size int) uint64 {
	shift := uint(64 - size*8)
	return uint64(int64(value<<shift) >> shift)
}
