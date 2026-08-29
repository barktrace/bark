package symbolicate

import (
	"bufio"
	"context"
	"encoding/binary"
	"io"
	"sort"
	"strconv"
	"strings"

	"github.com/barktrace/bark/internal/store"
)

const (
	maxBreakpadCFIRecords = 500000
	maxBreakpadCFIRules   = 128
)

type breakpadCFI struct {
	inits   []breakpadCFIInit
	changes []breakpadCFIChange
	windows []breakpadWIN
}

type breakpadWIN struct {
	typeID, address, size, prolog, epilog uint64
	params, saved, locals, maxStack       uint64
	allocatesBasePointer                  bool
	program                               []breakpadWINAssignment
}

type breakpadWINAssignment struct {
	target     string
	expression []string
}

type breakpadCFIInit struct {
	address, size uint64
	rules         map[string][]string
}

type breakpadCFIChange struct {
	address uint64
	rules   map[string][]string
}

type minidumpMemory struct {
	address     uint64
	data        []byte
	pointerSize int
}

func unwindMinidump(ctx context.Context, st *store.Store, projectID string, dump *minidump) []any {
	if dump == nil {
		return nil
	}
	unwinders := loadBreakpadUnwinders(ctx, st, projectID, dump.modules)
	return unwindMinidumpThread(dump, minidumpThread{
		id: dump.threadID, registers: dump.registers, stackAddress: dump.stackAddress, stack: dump.stack,
	}, unwinders)
}

func unwindMinidumpThread(dump *minidump, thread minidumpThread, unwinders map[string]*breakpadCFI) []any {
	if dump == nil || len(thread.registers) == 0 {
		return nil
	}
	registers := cloneRegisters(thread.registers)
	ipName, spName, fpName := instructionRegister(dump.architecture), stackRegister(dump.architecture), frameRegister(dump.architecture)
	ip := registers[ipName]
	if ip == 0 && thread.id == dump.threadID {
		ip = dump.address
		registers[ipName] = ip
	}
	memory := minidumpMemory{address: thread.stackAddress, data: thread.stack, pointerSize: 8}
	if dump.architecture == "x86" {
		memory.pointerSize = 4
	}
	framesNewestFirst := make([]map[string]any, 0, 32)
	trust := "context"
	for len(framesNewestFirst) < maxMinidumpFrames && ip != 0 {
		module, moduleOK := dump.module(ip)
		framesNewestFirst = append(framesNewestFirst, minidumpFrame(ip, module, trust))
		var next map[string]uint64
		nextTrust := "cfi"
		if moduleOK {
			if unwinder := unwinders[normalizeDebugID(module.debugID)]; unwinder != nil {
				next = unwinder.unwind(ip-module.base, registers, memory, ipName, spName)
				if next == nil && dump.architecture == "x86" {
					next = unwinder.unwindWindows(ip-module.base, registers, memory, dump)
				}
			}
		}
		if next == nil {
			next = framePointerUnwind(registers, memory, ipName, spName, fpName)
			nextTrust = "fp"
		}
		if next == nil || next[ipName] == 0 || next[ipName] == ip || next[spName] <= registers[spName] {
			break
		}
		nextIP := next[ipName]
		if nextIP > 0 {
			nextIP--
		}
		if _, ok := dump.module(nextIP); !ok {
			break
		}
		next[ipName] = nextIP
		registers, ip, trust = next, nextIP, nextTrust
	}
	frames := make([]any, len(framesNewestFirst))
	for index := range framesNewestFirst {
		frames[len(framesNewestFirst)-1-index] = framesNewestFirst[index]
	}
	return frames
}

func framePointerUnwind(registers map[string]uint64, memory minidumpMemory, ipName, spName, fpName string) map[string]uint64 {
	fp := registers[fpName]
	if fp == 0 {
		return nil
	}
	nextFP, ok := memory.readPointer(fp)
	if !ok {
		return nil
	}
	returnAddress, ok := memory.readPointer(fp + uint64(memory.pointerSize))
	if !ok || nextFP <= fp || nextFP-fp > 1<<20 {
		return nil
	}
	next := cloneRegisters(registers)
	next[ipName], next[spName], next[fpName] = returnAddress, fp+uint64(2*memory.pointerSize), nextFP
	return next
}

func (m minidumpMemory) readPointer(address uint64) (uint64, bool) {
	if address < m.address || address-m.address > uint64(len(m.data)) || uint64(len(m.data))-(address-m.address) < uint64(m.pointerSize) {
		return 0, false
	}
	offset := int(address - m.address)
	if m.pointerSize == 4 {
		return uint64(binary.LittleEndian.Uint32(m.data[offset : offset+4])), true
	}
	return binary.LittleEndian.Uint64(m.data[offset : offset+8]), true
}

func loadBreakpadUnwinders(ctx context.Context, st *store.Store, projectID string, modules []minidumpModule) map[string]*breakpadCFI {
	wanted := make(map[string]bool)
	for _, module := range modules {
		if id := normalizeDebugID(module.debugID); id != "" {
			wanted[id] = true
		}
	}
	result := make(map[string]*breakpadCFI)
	rows, err := st.DB.QueryContext(ctx, `SELECT a.debug_id, b.storage_key FROM project_artifacts a JOIN blobs b ON b.id = a.blob_id WHERE a.project_id = ? AND a.artifact_type = 'debug_file'`, projectID)
	if err != nil {
		return result
	}
	defer rows.Close()
	for rows.Next() {
		var debugID, storageKey string
		if rows.Scan(&debugID, &storageKey) != nil {
			continue
		}
		normalized := normalizeDebugID(debugID)
		if !wanted[normalized] || result[normalized] != nil {
			continue
		}
		file, err := st.Blobs.Open(storageKey)
		if err != nil {
			continue
		}
		unwinder := parseBreakpadCFI(file)
		_ = file.Close()
		if len(unwinder.inits) > 0 || len(unwinder.windows) > 0 {
			result[normalized] = unwinder
		}
	}
	return result
}

func parseBreakpadCFI(reader io.Reader) *breakpadCFI {
	result := &breakpadCFI{}
	scanner := bufio.NewScanner(io.LimitReader(reader, maxPDBBytes))
	scanner.Buffer(make([]byte, 64<<10), 1<<20)
	for records := 0; records < maxBreakpadCFIRecords && scanner.Scan(); records++ {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "STACK CFI INIT ") {
			fields := strings.Fields(line)
			if len(fields) < 6 {
				continue
			}
			address, addressErr := strconv.ParseUint(fields[3], 16, 64)
			size, sizeErr := strconv.ParseUint(fields[4], 16, 64)
			rules, rulesOK := parseBreakpadCFIRules(strings.Join(fields[5:], " "))
			if addressErr == nil && sizeErr == nil && size > 0 && address+size >= address && rulesOK {
				result.inits = append(result.inits, breakpadCFIInit{address: address, size: size, rules: rules})
			}
			continue
		}
		if strings.HasPrefix(line, "STACK CFI ") {
			fields := strings.Fields(line)
			if len(fields) < 4 {
				continue
			}
			address, addressErr := strconv.ParseUint(fields[2], 16, 64)
			rules, rulesOK := parseBreakpadCFIRules(strings.Join(fields[3:], " "))
			if addressErr == nil && rulesOK {
				result.changes = append(result.changes, breakpadCFIChange{address: address, rules: rules})
			}
			continue
		}
		if strings.HasPrefix(line, "STACK WIN ") {
			if record, ok := parseBreakpadWIN(line); ok {
				result.windows = append(result.windows, record)
			}
		}
	}
	sort.Slice(result.inits, func(left, right int) bool { return result.inits[left].address < result.inits[right].address })
	sort.Slice(result.changes, func(left, right int) bool { return result.changes[left].address < result.changes[right].address })
	sort.Slice(result.windows, func(left, right int) bool { return result.windows[left].address < result.windows[right].address })
	return result
}

func parseBreakpadWIN(line string) (breakpadWIN, bool) {
	fields := strings.Fields(strings.ReplaceAll(line, "=", " = "))
	if len(fields) < 13 || fields[0] != "STACK" || fields[1] != "WIN" {
		return breakpadWIN{}, false
	}
	values := make([]uint64, 10)
	for index := range values {
		value, err := strconv.ParseUint(fields[index+2], 16, 64)
		if err != nil {
			return breakpadWIN{}, false
		}
		values[index] = value
	}
	if (values[0] != 0 && values[0] != 4) || values[2] == 0 || values[1]+values[2] < values[1] ||
		values[5] > maxMinidumpBytes || values[6] > maxMinidumpBytes || values[7] > maxMinidumpBytes || values[8] > maxMinidumpBytes || values[9] > 1 {
		return breakpadWIN{}, false
	}
	record := breakpadWIN{
		typeID: values[0], address: values[1], size: values[2], prolog: values[3], epilog: values[4],
		params: values[5], saved: values[6], locals: values[7], maxStack: values[8],
	}
	if values[9] == 0 {
		if fields[12] != "0" && fields[12] != "1" {
			return breakpadWIN{}, false
		}
		record.allocatesBasePointer = fields[12] == "1"
		return record, true
	}
	assignment := make([]string, 0, 16)
	for _, token := range fields[12:] {
		if token != "=" {
			assignment = append(assignment, token)
			if len(assignment) > 256 {
				return breakpadWIN{}, false
			}
			continue
		}
		if len(assignment) < 2 || !strings.HasPrefix(assignment[0], "$") || len(record.program) >= maxBreakpadCFIRules {
			return breakpadWIN{}, false
		}
		record.program = append(record.program, breakpadWINAssignment{target: assignment[0], expression: append([]string(nil), assignment[1:]...)})
		assignment = assignment[:0]
	}
	return record, len(assignment) == 0 && len(record.program) > 0
}

func (c *breakpadCFI) unwindWindows(relative uint64, registers map[string]uint64, memory minidumpMemory, dump *minidump) map[string]uint64 {
	if c == nil || memory.pointerSize != 4 {
		return nil
	}
	index := -1
	for candidate := range c.windows {
		record := &c.windows[candidate]
		if relative < record.address || relative-record.address >= record.size {
			continue
		}
		if index < 0 || record.typeID == 4 && c.windows[index].typeID != 4 || record.typeID == c.windows[index].typeID && record.address >= c.windows[index].address {
			index = candidate
		}
	}
	if index < 0 {
		return nil
	}
	record := &c.windows[index]
	next := cloneRegisters(registers)
	calleeParams := registers["__callee_params"]
	returnAddressLocation := registers["esp"] + calleeParams + record.locals + record.saved
	if breakpadWINUsesAlignment(record.program) && registers["ebp"] != 0 {
		returnAddressLocation = registers["ebp"] + 4
	}
	returnAddressLocation = scanWindowsReturnAddress(dump, memory, returnAddressLocation)
	if len(record.program) == 0 {
		if record.allocatesBasePointer {
			returnAddress, returnOK := memory.readPointer(returnAddressLocation)
			basePointerLocation := registers["esp"] + calleeParams + record.saved
			if basePointerLocation < 8 {
				return nil
			}
			basePointer, baseOK := memory.readPointer(basePointerLocation - 8)
			if !returnOK || !baseOK {
				return nil
			}
			next["eip"], next["esp"], next["ebp"] = returnAddress, returnAddressLocation+4, basePointer
		} else {
			returnAddress, ok := memory.readPointer(returnAddressLocation)
			if !ok {
				return nil
			}
			next["eip"], next["esp"] = returnAddress, returnAddressLocation+4
		}
		next["__callee_params"] = record.params
		return next
	}
	variables := make(map[string]uint64, len(registers)+12)
	for name, value := range registers {
		variables["$"+name] = value
		variables[name] = value
	}
	variables[".cbParams"] = record.params
	variables[".cbSavedRegs"] = record.saved
	variables[".cbLocals"] = record.locals
	variables[".cbMaxStack"] = record.maxStack
	variables[".cbCalleeParams"] = calleeParams
	variables[".raSearchStart"] = returnAddressLocation
	variables[".raSearch"] = returnAddressLocation
	assigned := make(map[string]bool, len(record.program))
	for _, assignment := range record.program {
		value, ok := evaluateBreakpadCFI(assignment.expression, variables, memory)
		if !ok {
			return nil
		}
		variables[assignment.target] = value
		assigned[assignment.target] = true
		name := strings.TrimPrefix(assignment.target, "$")
		if _, exists := registers[name]; exists {
			next[name] = value
		}
	}
	if !assigned["$eip"] || !assigned["$esp"] || next["eip"] == registers["eip"] || next["esp"] <= registers["esp"] {
		return nil
	}
	next["__callee_params"] = record.params
	return next
}

func breakpadWINUsesAlignment(program []breakpadWINAssignment) bool {
	for _, assignment := range program {
		for _, token := range assignment.expression {
			if token == "@" {
				return true
			}
		}
	}
	return false
}

func scanWindowsReturnAddress(dump *minidump, memory minidumpMemory, start uint64) uint64 {
	if dump == nil {
		return start
	}
	for offset := uint64(0); offset <= 3*uint64(memory.pointerSize); offset += uint64(memory.pointerSize) {
		candidate, ok := memory.readPointer(start + offset)
		if !ok || candidate == 0 {
			continue
		}
		lookup := candidate
		if lookup > 0 {
			lookup--
		}
		if _, ok := dump.module(lookup); ok {
			return start + offset
		}
	}
	return start
}

func parseBreakpadCFIRules(value string) (map[string][]string, bool) {
	fields := strings.Fields(value)
	rules := make(map[string][]string)
	current := ""
	for _, field := range fields {
		if strings.HasSuffix(field, ":") {
			current = strings.TrimSuffix(field, ":")
			if current == "" || len(rules) >= maxBreakpadCFIRules {
				return nil, false
			}
			rules[current] = nil
			continue
		}
		if current == "" {
			return nil, false
		}
		rules[current] = append(rules[current], field)
	}
	if len(rules) == 0 {
		return nil, false
	}
	for _, expression := range rules {
		if len(expression) == 0 || len(expression) > 256 {
			return nil, false
		}
	}
	return rules, true
}

func (c *breakpadCFI) unwind(relative uint64, registers map[string]uint64, memory minidumpMemory, ipName, spName string) map[string]uint64 {
	if c == nil {
		return nil
	}
	initIndex := -1
	for index := range c.inits {
		init := &c.inits[index]
		if relative >= init.address && relative-init.address < init.size {
			if initIndex < 0 || init.address >= c.inits[initIndex].address {
				initIndex = index
			}
		}
	}
	if initIndex < 0 {
		return nil
	}
	init := &c.inits[initIndex]
	rules := cloneRules(init.rules)
	for _, change := range c.changes {
		if change.address < init.address {
			continue
		}
		if change.address > relative || change.address-init.address >= init.size {
			break
		}
		for name, expression := range change.rules {
			rules[name] = expression
		}
	}
	variables := make(map[string]uint64, len(registers)+maxBreakpadCFIRules)
	for name, value := range registers {
		variables["$"+name] = value
		variables[name] = value
	}
	next := cloneRegisters(registers)
	for attempts := 0; attempts < maxBreakpadCFIRules && len(rules) > 0; attempts++ {
		progress := false
		for name, expression := range rules {
			value, ok := evaluateBreakpadCFI(expression, variables, memory)
			if !ok {
				continue
			}
			variables[name] = value
			if !strings.HasPrefix(name, ".") {
				next[strings.TrimPrefix(name, "$")] = value
			}
			delete(rules, name)
			progress = true
		}
		if !progress {
			break
		}
	}
	cfa, cfaOK := variables[".cfa"]
	returnAddress, returnOK := variables[".ra"]
	if !cfaOK || !returnOK {
		return nil
	}
	next[spName], next[ipName] = cfa, returnAddress
	return next
}

func evaluateBreakpadCFI(expression []string, variables map[string]uint64, memory minidumpMemory) (uint64, bool) {
	stack := make([]uint64, 0, 8)
	pop := func() (uint64, bool) {
		if len(stack) == 0 {
			return 0, false
		}
		value := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		return value, true
	}
	for _, token := range expression {
		if value, ok := variables[token]; ok {
			stack = append(stack, value)
			continue
		}
		switch token {
		case "^":
			address, ok := pop()
			if !ok {
				return 0, false
			}
			value, ok := memory.readPointer(address)
			if !ok {
				return 0, false
			}
			stack = append(stack, value)
		case "+", "-", "*", "/", "%", "@":
			right, rightOK := pop()
			left, leftOK := pop()
			if !leftOK || !rightOK || ((token == "/" || token == "%" || token == "@") && right == 0) {
				return 0, false
			}
			switch token {
			case "+":
				stack = append(stack, left+right)
			case "-":
				stack = append(stack, left-right)
			case "*":
				stack = append(stack, left*right)
			case "/":
				stack = append(stack, left/right)
			case "%":
				stack = append(stack, left%right)
			case "@":
				stack = append(stack, left-left%right)
			}
		default:
			value, ok := parseCFIInteger(token)
			if !ok {
				return 0, false
			}
			stack = append(stack, value)
		}
	}
	return func() (uint64, bool) {
		if len(stack) != 1 {
			return 0, false
		}
		return stack[0], true
	}()
}

func parseCFIInteger(value string) (uint64, bool) {
	if signed, err := strconv.ParseInt(value, 0, 64); err == nil {
		return uint64(signed), true
	}
	unsigned, err := strconv.ParseUint(value, 16, 64)
	return unsigned, err == nil
}

func cloneRules(source map[string][]string) map[string][]string {
	cloned := make(map[string][]string, len(source))
	for name, expression := range source {
		cloned[name] = expression
	}
	return cloned
}

func cloneRegisters(source map[string]uint64) map[string]uint64 {
	cloned := make(map[string]uint64, len(source)+2)
	for name, value := range source {
		cloned[name] = value
	}
	return cloned
}
