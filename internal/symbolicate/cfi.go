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
	registers := cloneRegisters(dump.registers)
	ipName, spName, fpName := instructionRegister(dump.architecture), stackRegister(dump.architecture), frameRegister(dump.architecture)
	ip := registers[ipName]
	if ip == 0 {
		ip = dump.address
		registers[ipName] = ip
	}
	memory := minidumpMemory{address: dump.stackAddress, data: dump.stack, pointerSize: 8}
	if dump.architecture == "x86" {
		memory.pointerSize = 4
	}
	framesNewestFirst := make([]map[string]any, 0, 32)
	trust := "context"
	for len(framesNewestFirst) < maxMinidumpFrames && ip != 0 {
		module, moduleOK := dump.module(ip)
		framesNewestFirst = append(framesNewestFirst, minidumpFrame(ip, module, trust))
		var next map[string]uint64
		if moduleOK {
			if unwinder := unwinders[normalizeDebugID(module.debugID)]; unwinder != nil {
				next = unwinder.unwind(ip-module.base, registers, memory, ipName, spName)
			}
		}
		nextTrust := "cfi"
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
		if len(unwinder.inits) > 0 {
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
		}
	}
	sort.Slice(result.inits, func(left, right int) bool { return result.inits[left].address < result.inits[right].address })
	sort.Slice(result.changes, func(left, right int) bool { return result.changes[left].address < result.changes[right].address })
	return result
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
