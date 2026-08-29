package symbolicate

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"sort"
	"strings"
)

const (
	maxPDBBytes          = 100 << 20
	maxPDBDirectoryBytes = 8 << 20
	maxPDBStreamBytes    = 32 << 20
	maxPDBStreams        = 65536
	maxPDBSymbols        = 250000
	maxPDBLines          = 500000
	maxPDBInlineSites    = 250000
	maxPDBInlineRanges   = 500000
	maxPDBAnnotations    = 65536
)

var pdb7Magic = []byte("Microsoft C/C++ MSF 7.00\r\n\x1aDS\x00\x00\x00")

type pdbMSF struct {
	reader    io.ReaderAt
	blockSize uint32
	numBlocks uint32
	sizes     []uint32
	blocks    [][]uint32
}

type pdbSection struct {
	address uint32
	size    uint32
}

type pdbSymbol struct {
	name    string
	address uint32
	size    uint32
}

type pdbLine struct {
	filename     string
	address, end uint32
	line, column int
}

type pdbInlineeLine struct {
	filename string
	line     int
}

type pdbInlineSite struct {
	function    string
	rootAddress uint32
	parent      int
	inlinee     pdbInlineeLine
	files       map[uint32]string
	ranges      []pdbInlineRange
}

type pdbInlineRange struct {
	start, end uint32
	lineOffset int32
	fileOffset uint32
}

type pdbSymbols struct {
	sections []pdbSection
	symbols  []pdbSymbol
	lines    []pdbLine
	inlines  []pdbInlineSite
}

func lookupPDBFrame(reader io.ReaderAt, address, imageBase uint64) nativeSymbol {
	parsed, err := parsePDBSymbols(reader)
	if err != nil {
		return nativeSymbol{}
	}
	return lookupPDBSymbols(parsed, address, imageBase)
}

func lookupPDBSymbols(parsed *pdbSymbols, address, imageBase uint64) nativeSymbol {
	if parsed == nil {
		return nativeSymbol{}
	}
	rva := address
	if imageBase > 0 && address >= imageBase {
		rva = address - imageBase
	}
	if rva > uint64(^uint32(0)) {
		return nativeSymbol{}
	}
	matched, symbolOK := parsed.lookup(uint32(rva))
	line, lineOK := parsed.lookupLine(uint32(rva))
	if !symbolOK && !lineOK {
		return nativeSymbol{}
	}
	result := nativeSymbol{function: matched.name, address: uint64(matched.address), filename: line.filename, line: line.line, column: line.column}
	parsed.expandInlineFrames(uint32(rva), matched.address, &result)
	return result
}

func parsePDBSymbols(reader io.ReaderAt) (*pdbSymbols, error) {
	msf, err := parsePDBMSF(reader)
	if err != nil {
		return nil, err
	}
	dbi, err := msf.stream(3, maxPDBStreamBytes)
	if err != nil || len(dbi) < 64 {
		return nil, errors.New("PDB DBI stream is missing or truncated")
	}
	symbolStream := binary.LittleEndian.Uint16(dbi[20:22])
	optionalOffset, ok := pdbOptionalDebugOffset(dbi)
	if !ok || optionalOffset+12 > len(dbi) {
		return nil, errors.New("PDB optional debug header is missing")
	}
	sectionStream := binary.LittleEndian.Uint16(dbi[optionalOffset+10 : optionalOffset+12])
	if sectionStream == 0xffff && optionalOffset+22 <= len(dbi) {
		sectionStream = binary.LittleEndian.Uint16(dbi[optionalOffset+20 : optionalOffset+22])
	}
	if symbolStream == 0xffff || sectionStream == 0xffff {
		return nil, errors.New("PDB symbol or section stream is unavailable")
	}
	sectionData, err := msf.stream(int(sectionStream), maxPDBStreamBytes)
	if err != nil {
		return nil, err
	}
	sections, err := parsePDBSections(sectionData)
	if err != nil {
		return nil, err
	}
	symbolData, err := msf.stream(int(symbolStream), maxPDBStreamBytes)
	if err != nil {
		return nil, err
	}
	symbols := parsePDBSymbolRecords(symbolData, sections)
	if len(symbols) == 0 {
		return nil, errors.New("PDB contains no supported code symbols")
	}
	lines, inlines := parsePDBModules(msf, dbi, sections)
	return &pdbSymbols{sections: sections, symbols: symbols, lines: lines, inlines: inlines}, nil
}

func parsePDBMSF(reader io.ReaderAt) (*pdbMSF, error) {
	header := make([]byte, 56)
	if err := readPDBAt(reader, header, 0); err != nil || !bytes.Equal(header[:32], pdb7Magic) {
		return nil, errors.New("not a Microsoft PDB 7 file")
	}
	blockSize := binary.LittleEndian.Uint32(header[32:36])
	numBlocks := binary.LittleEndian.Uint32(header[40:44])
	directorySize := binary.LittleEndian.Uint32(header[44:48])
	blockMapAddress := binary.LittleEndian.Uint32(header[52:56])
	if !validPDBBlockSize(blockSize) || numBlocks == 0 || uint64(blockSize)*uint64(numBlocks) > maxPDBBytes {
		return nil, errors.New("PDB block layout exceeds limits")
	}
	if directorySize < 4 || directorySize > maxPDBDirectoryBytes || blockMapAddress >= numBlocks {
		return nil, errors.New("PDB stream directory is invalid")
	}
	directoryBlocks := (uint64(directorySize) + uint64(blockSize) - 1) / uint64(blockSize)
	blockMapBytes := directoryBlocks * 4
	if blockMapBytes > uint64(blockSize) {
		return nil, errors.New("PDB stream directory block map exceeds one block")
	}
	blockMap := make([]byte, blockMapBytes)
	if err := readPDBAt(reader, blockMap, int64(blockMapAddress)*int64(blockSize)); err != nil {
		return nil, errors.New("PDB stream directory block map is truncated")
	}
	directoryBlockList := make([]uint32, directoryBlocks)
	for index := range directoryBlockList {
		directoryBlockList[index] = binary.LittleEndian.Uint32(blockMap[index*4 : index*4+4])
		if directoryBlockList[index] >= numBlocks {
			return nil, errors.New("PDB stream directory references an invalid block")
		}
	}
	msf := &pdbMSF{reader: reader, blockSize: blockSize, numBlocks: numBlocks}
	directory, err := msf.readBlocks(directoryBlockList, directorySize)
	if err != nil {
		return nil, err
	}
	streamCount := binary.LittleEndian.Uint32(directory[:4])
	if streamCount == 0 || streamCount > maxPDBStreams || uint64(4+streamCount*4) > uint64(len(directory)) {
		return nil, errors.New("PDB stream count is invalid")
	}
	msf.sizes = make([]uint32, streamCount)
	msf.blocks = make([][]uint32, streamCount)
	offset := 4
	for index := range msf.sizes {
		msf.sizes[index] = binary.LittleEndian.Uint32(directory[offset : offset+4])
		offset += 4
	}
	for index, size := range msf.sizes {
		if size == 0xffffffff || size == 0 {
			continue
		}
		blockCount := (uint64(size) + uint64(blockSize) - 1) / uint64(blockSize)
		if blockCount > uint64(numBlocks) || uint64(offset)+blockCount*4 > uint64(len(directory)) {
			return nil, errors.New("PDB stream block list is truncated")
		}
		msf.blocks[index] = make([]uint32, blockCount)
		for blockIndex := range msf.blocks[index] {
			block := binary.LittleEndian.Uint32(directory[offset : offset+4])
			offset += 4
			if block >= numBlocks {
				return nil, errors.New("PDB stream references an invalid block")
			}
			msf.blocks[index][blockIndex] = block
		}
	}
	return msf, nil
}

func validPDBBlockSize(size uint32) bool {
	return size == 512 || size == 1024 || size == 2048 || size == 4096
}

func (p *pdbMSF) stream(index int, limit uint32) ([]byte, error) {
	if index < 0 || index >= len(p.sizes) || p.sizes[index] == 0xffffffff {
		return nil, errors.New("PDB stream does not exist")
	}
	if p.sizes[index] > limit {
		return nil, errors.New("PDB stream exceeds size limit")
	}
	return p.readBlocks(p.blocks[index], p.sizes[index])
}

func (p *pdbMSF) readBlocks(blocks []uint32, size uint32) ([]byte, error) {
	output := make([]byte, size)
	written := 0
	for _, block := range blocks {
		remaining := len(output) - written
		if remaining <= 0 {
			break
		}
		chunk := min(remaining, int(p.blockSize))
		if err := readPDBAt(p.reader, output[written:written+chunk], int64(block)*int64(p.blockSize)); err != nil {
			return nil, errors.New("PDB block is truncated")
		}
		written += chunk
	}
	if written != len(output) {
		return nil, errors.New("PDB block list is incomplete")
	}
	return output, nil
}

func readPDBAt(reader io.ReaderAt, target []byte, offset int64) error {
	n, err := reader.ReadAt(target, offset)
	if n == len(target) {
		return nil
	}
	if err != nil {
		return err
	}
	return io.ErrUnexpectedEOF
}

func pdbOptionalDebugOffset(dbi []byte) (int, bool) {
	offset := uint64(64)
	for _, fieldOffset := range []int{24, 28, 32, 36, 40, 52} {
		size := int32(binary.LittleEndian.Uint32(dbi[fieldOffset : fieldOffset+4]))
		if size < 0 {
			return 0, false
		}
		offset += uint64(size)
		if offset > uint64(len(dbi)) {
			return 0, false
		}
	}
	optionalSize := int32(binary.LittleEndian.Uint32(dbi[48:52]))
	return int(offset), optionalSize >= 0 && offset+uint64(optionalSize) <= uint64(len(dbi))
}

func parsePDBSections(data []byte) ([]pdbSection, error) {
	if len(data) < 40 || len(data)%40 != 0 || len(data)/40 > 65536 {
		return nil, errors.New("PDB section header stream is invalid")
	}
	sections := make([]pdbSection, 0, len(data)/40)
	for offset := 0; offset+40 <= len(data); offset += 40 {
		virtualSize := binary.LittleEndian.Uint32(data[offset+8 : offset+12])
		rawSize := binary.LittleEndian.Uint32(data[offset+16 : offset+20])
		sections = append(sections, pdbSection{
			address: binary.LittleEndian.Uint32(data[offset+12 : offset+16]),
			size:    max(virtualSize, rawSize),
		})
	}
	return sections, nil
}

func parsePDBSymbolRecords(data []byte, sections []pdbSection) []pdbSymbol {
	offset := 0
	if len(data) >= 4 && binary.LittleEndian.Uint32(data[:4]) <= 4 {
		offset = 4
	}
	symbols := make([]pdbSymbol, 0)
	for len(symbols) < maxPDBSymbols && offset+4 <= len(data) {
		recordLength := int(binary.LittleEndian.Uint16(data[offset : offset+2]))
		if recordLength < 2 || offset+2+recordLength > len(data) {
			break
		}
		recordType := binary.LittleEndian.Uint16(data[offset+2 : offset+4])
		payload := data[offset+4 : offset+2+recordLength]
		var symbol pdbSymbol
		var segment uint16
		var sectionOffset uint32
		switch recordType {
		case 0x110e: // S_PUB32
			if len(payload) >= 11 && binary.LittleEndian.Uint32(payload[:4])&3 != 0 {
				sectionOffset = binary.LittleEndian.Uint32(payload[4:8])
				segment = binary.LittleEndian.Uint16(payload[8:10])
				symbol.name = pdbString(payload[10:])
			}
		case 0x110f, 0x1110, 0x1146, 0x1147, 0x1155, 0x1156: // local/global procedures
			if len(payload) >= 36 {
				symbol.size = binary.LittleEndian.Uint32(payload[12:16])
				sectionOffset = binary.LittleEndian.Uint32(payload[28:32])
				segment = binary.LittleEndian.Uint16(payload[32:34])
				symbol.name = pdbString(payload[35:])
			}
		}
		if symbol.name != "" && segment > 0 && int(segment) <= len(sections) {
			section := sections[int(segment)-1]
			if uint64(section.address)+uint64(sectionOffset) <= uint64(^uint32(0)) {
				symbol.address = section.address + sectionOffset
				symbols = append(symbols, symbol)
			}
		}
		offset = (offset + 2 + recordLength + 3) &^ 3
	}
	sort.SliceStable(symbols, func(left, right int) bool {
		if symbols[left].address != symbols[right].address {
			return symbols[left].address < symbols[right].address
		}
		return symbols[left].size > symbols[right].size
	})
	return symbols
}

func parsePDBModules(msf *pdbMSF, dbi []byte, sections []pdbSection) ([]pdbLine, []pdbInlineSite) {
	moduleBytes := int(int32(binary.LittleEndian.Uint32(dbi[24:28])))
	if moduleBytes <= 0 || 64+moduleBytes > len(dbi) {
		return nil, nil
	}
	globalStrings := pdbGlobalStrings(msf)
	ipiNames := parsePDBIPINames(msf)
	moduleInfo := dbi[64 : 64+moduleBytes]
	lines := make([]pdbLine, 0)
	inlines := make([]pdbInlineSite, 0)
	inlineRanges := 0
	for offset := 0; offset+64 <= len(moduleInfo) && (len(lines) < maxPDBLines || (len(inlines) < maxPDBInlineSites && inlineRanges < maxPDBInlineRanges)); {
		streamIndex := binary.LittleEndian.Uint16(moduleInfo[offset+34 : offset+36])
		symbolBytes := binary.LittleEndian.Uint32(moduleInfo[offset+36 : offset+40])
		c11Bytes := binary.LittleEndian.Uint32(moduleInfo[offset+40 : offset+44])
		c13Bytes := binary.LittleEndian.Uint32(moduleInfo[offset+44 : offset+48])
		next, ok := pdbModuleInfoEnd(moduleInfo, offset)
		if !ok {
			break
		}
		offset = next
		if streamIndex == 0xffff || c13Bytes == 0 || c13Bytes > maxPDBStreamBytes {
			continue
		}
		stream, err := msf.stream(int(streamIndex), maxPDBStreamBytes)
		c13Start := uint64(symbolBytes) + uint64(c11Bytes)
		c13End := c13Start + uint64(c13Bytes)
		if err != nil || c13End > uint64(len(stream)) {
			continue
		}
		c13 := stream[c13Start:c13End]
		moduleLines, inlinees, files := parsePDBC13Data(c13, sections, globalStrings, max(0, maxPDBLines-len(lines)))
		lines = append(lines, moduleLines...)
		if symbolBytes <= uint32(len(stream)) && len(inlines) < maxPDBInlineSites && inlineRanges < maxPDBInlineRanges {
			moduleInlines, moduleRanges := parsePDBInlineSites(stream[:symbolBytes], sections, ipiNames, inlinees, files, len(inlines), maxPDBInlineSites-len(inlines), maxPDBInlineRanges-inlineRanges)
			inlines = append(inlines, moduleInlines...)
			inlineRanges += moduleRanges
		}
	}
	sort.SliceStable(lines, func(left, right int) bool {
		if lines[left].address != lines[right].address {
			return lines[left].address < lines[right].address
		}
		return lines[left].end > lines[right].end
	})
	return lines, inlines
}

func parsePDBIPINames(msf *pdbMSF) map[uint32]string {
	data, err := msf.stream(4, maxPDBStreamBytes)
	if err != nil || len(data) < 20 {
		return nil
	}
	headerSize := binary.LittleEndian.Uint32(data[4:8])
	typeIndex := binary.LittleEndian.Uint32(data[8:12])
	typeIndexEnd := binary.LittleEndian.Uint32(data[12:16])
	recordBytes := binary.LittleEndian.Uint32(data[16:20])
	if headerSize < 20 || headerSize > uint32(len(data)) || typeIndexEnd < typeIndex || typeIndexEnd-typeIndex > maxPDBSymbols || uint64(headerSize)+uint64(recordBytes) > uint64(len(data)) {
		return nil
	}
	names := make(map[uint32]string)
	end := int(headerSize + recordBytes)
	for offset := int(headerSize); offset+4 <= end && typeIndex < typeIndexEnd; typeIndex++ {
		recordLength := int(binary.LittleEndian.Uint16(data[offset : offset+2]))
		if recordLength < 2 || offset+2+recordLength > end {
			break
		}
		leaf := binary.LittleEndian.Uint16(data[offset+2 : offset+4])
		payload := data[offset+4 : offset+2+recordLength]
		if (leaf == 0x1601 || leaf == 0x1602) && len(payload) >= 9 {
			names[typeIndex] = pdbString(payload[8:])
		}
		offset += 2 + recordLength
	}
	return names
}

type pdbScope struct {
	rootAddress uint32
	inlineIndex int
}

func parsePDBInlineSites(data []byte, sections []pdbSection, names map[uint32]string, inlinees map[uint32]pdbInlineeLine, files map[uint32]string, baseIndex, siteLimit, rangeLimit int) ([]pdbInlineSite, int) {
	if siteLimit <= 0 || rangeLimit <= 0 {
		return nil, 0
	}
	offset := 0
	if len(data) >= 4 && binary.LittleEndian.Uint32(data[:4]) <= 4 {
		offset = 4
	}
	scopes := make(map[uint32]pdbScope)
	sites := make([]pdbInlineSite, 0)
	rangeCount := 0
	for len(sites) < siteLimit && rangeCount < rangeLimit && offset+4 <= len(data) {
		recordOffset := uint32(offset)
		recordLength := int(binary.LittleEndian.Uint16(data[offset : offset+2]))
		if recordLength < 2 || offset+2+recordLength > len(data) {
			break
		}
		recordType := binary.LittleEndian.Uint16(data[offset+2 : offset+4])
		payload := data[offset+4 : offset+2+recordLength]
		switch recordType {
		case 0x110f, 0x1110, 0x1146, 0x1147, 0x1155, 0x1156: // local/global procedures
			if len(payload) >= 34 {
				sectionOffset := binary.LittleEndian.Uint32(payload[28:32])
				segment := binary.LittleEndian.Uint16(payload[32:34])
				if segment > 0 && int(segment) <= len(sections) && uint64(sections[int(segment)-1].address)+uint64(sectionOffset) <= uint64(^uint32(0)) {
					scopes[recordOffset] = pdbScope{rootAddress: sections[int(segment)-1].address + sectionOffset, inlineIndex: -1}
				}
			}
		case 0x114d: // S_INLINESITE
			if len(payload) >= 12 && len(payload)-12 <= maxPDBAnnotations {
				parent, ok := scopes[binary.LittleEndian.Uint32(payload[:4])]
				inlineeID := binary.LittleEndian.Uint32(payload[8:12])
				if ok && names[inlineeID] != "" {
					parentIndex := parent.inlineIndex
					if parentIndex >= 0 {
						parentIndex += baseIndex
					}
					ranges := parsePDBInlineRanges(payload[12:])
					if len(ranges) == 0 || len(ranges) > rangeLimit-rangeCount {
						break
					}
					site := pdbInlineSite{
						function: names[inlineeID], rootAddress: parent.rootAddress, parent: parentIndex,
						inlinee: inlinees[inlineeID], files: files, ranges: ranges,
					}
					scopes[recordOffset] = pdbScope{rootAddress: parent.rootAddress, inlineIndex: len(sites)}
					sites = append(sites, site)
					rangeCount += len(ranges)
				}
			}
		}
		offset = (offset + 2 + recordLength + 3) &^ 3
	}
	return sites, rangeCount
}

type pdbAnnotation struct {
	opcode uint32
	u1, u2 uint32
	s1     int32
}

func parsePDBInlineRanges(data []byte) []pdbInlineRange {
	annotations, ok := decodePDBAnnotations(data)
	if !ok {
		return nil
	}
	coverage := make([]pdbInlineRange, 0)
	codeOffset := uint64(0)
	start, hasStart := uint64(0), false
	appendRange := func(rangeStart, rangeEnd uint64) {
		if rangeStart >= rangeEnd || rangeEnd > uint64(^uint32(0)) || len(coverage) >= maxPDBAnnotations {
			return
		}
		coverage = append(coverage, pdbInlineRange{start: uint32(rangeStart), end: uint32(rangeEnd)})
	}
	for _, annotation := range annotations {
		switch annotation.opcode {
		case 1, 3, 11: // CodeOffset, ChangeCodeOffset, ChangeCodeOffsetAndLineOffset
			codeOffset += uint64(annotation.u1)
			if codeOffset > uint64(^uint32(0)) {
				return coverage
			}
			if !hasStart {
				start, hasStart = codeOffset, true
			}
		case 4: // ChangeCodeLength
			end := codeOffset + uint64(annotation.u1)
			if hasStart {
				appendRange(start, end)
			}
			codeOffset, hasStart = end, false
		case 12: // ChangeCodeLengthAndCodeOffset
			codeOffset += uint64(annotation.u2)
			appendRange(codeOffset, codeOffset+uint64(annotation.u1))
			hasStart = false
		}
	}
	if ranges := pdbInlineLineRanges(annotations); len(ranges) > 0 {
		return ranges
	}
	return coverage
}

func decodePDBAnnotations(data []byte) ([]pdbAnnotation, bool) {
	annotations := make([]pdbAnnotation, 0)
	for offset := 0; offset < len(data) && len(annotations) < maxPDBAnnotations; {
		opcode, ok := readPDBCompressed(data, &offset)
		if !ok {
			return nil, false
		}
		if opcode == 0 {
			return annotations, true
		}
		annotation := pdbAnnotation{opcode: opcode}
		readUnsigned := func() bool {
			annotation.u1, ok = readPDBCompressed(data, &offset)
			return ok
		}
		switch opcode {
		case 1, 2, 3, 4, 5, 7, 8, 9, 13:
			if !readUnsigned() {
				return nil, false
			}
		case 6, 10:
			operand, valid := readPDBCompressed(data, &offset)
			if !valid {
				return nil, false
			}
			annotation.s1 = decodePDBSigned(operand)
		case 11:
			operand, valid := readPDBCompressed(data, &offset)
			if !valid {
				return nil, false
			}
			annotation.u1 = operand & 0xf
			annotation.s1 = decodePDBSigned(operand >> 4)
		case 12:
			if !readUnsigned() {
				return nil, false
			}
			annotation.u2, ok = readPDBCompressed(data, &offset)
			if !ok {
				return nil, false
			}
		default:
			return nil, false
		}
		annotations = append(annotations, annotation)
	}
	return annotations, len(annotations) < maxPDBAnnotations
}

func readPDBCompressed(data []byte, offset *int) (uint32, bool) {
	if *offset >= len(data) {
		return 0, false
	}
	first := data[*offset]
	(*offset)++
	if first&0x80 == 0 {
		return uint32(first), true
	}
	if *offset >= len(data) {
		return 0, false
	}
	second := data[*offset]
	(*offset)++
	if first&0xc0 == 0x80 {
		return uint32(first&0x3f)<<8 | uint32(second), true
	}
	if first&0xe0 != 0xc0 || *offset+2 > len(data) {
		return 0, false
	}
	third, fourth := data[*offset], data[*offset+1]
	*offset += 2
	return uint32(first&0x1f)<<24 | uint32(second)<<16 | uint32(third)<<8 | uint32(fourth), true
}

func decodePDBSigned(operand uint32) int32 {
	if operand&1 != 0 {
		return -int32(operand >> 1)
	}
	return int32(operand >> 1)
}

func pdbInlineLineRanges(annotations []pdbAnnotation) []pdbInlineRange {
	codeOffset := uint64(0)
	lineOffset := int64(0)
	fileOffset := uint32(0)
	var codeBase, codeEnd uint64
	hasBase, hasEnd := false, false
	var currentLine, nextLine int64
	hasCurrentLine, hasNextLine := false, false
	var nextFile uint32
	hasNextFile := false
	updateCode := func(delta uint32) {
		if !hasBase {
			codeBase, hasBase = codeOffset, true
		} else if !hasEnd {
			codeEnd, hasEnd = codeBase+uint64(delta), true
		}
	}
	updateLine := func(delta int32) {
		lineOffset += int64(delta)
		if !hasBase || !hasCurrentLine {
			currentLine, hasCurrentLine = lineOffset, true
		} else {
			nextLine, hasNextLine = lineOffset, true
		}
	}
	ranges := make([]pdbInlineRange, 0)
	validate := func() {
		if !hasBase || !hasEnd || !hasCurrentLine {
			return
		}
		if codeBase < codeEnd && codeEnd <= uint64(^uint32(0)) && currentLine >= int64(-1<<31) && currentLine <= int64(1<<31-1) && len(ranges) < maxPDBAnnotations {
			ranges = append(ranges, pdbInlineRange{start: uint32(codeBase), end: uint32(codeEnd), lineOffset: int32(currentLine), fileOffset: fileOffset})
		}
		if hasNextFile {
			fileOffset, hasNextFile = nextFile, false
		}
		if hasNextLine {
			currentLine, hasCurrentLine, hasNextLine = nextLine, true, false
		}
		codeBase, hasBase, hasEnd = codeEnd, true, false
	}
	for _, annotation := range annotations {
		switch annotation.opcode {
		case 1, 3, 2:
			codeOffset += uint64(annotation.u1)
			updateCode(annotation.u1)
		case 4:
			updateCode(annotation.u1)
		case 12:
			codeOffset += uint64(annotation.u2)
			updateCode(annotation.u2)
			updateCode(annotation.u1)
		case 6:
			updateLine(annotation.s1)
		case 11:
			codeOffset += uint64(annotation.u1)
			updateCode(annotation.u1)
			updateLine(annotation.s1)
		case 5:
			if !hasBase {
				fileOffset = annotation.u1
			} else {
				nextFile, hasNextFile = annotation.u1, true
			}
		}
		validate()
	}
	return ranges
}

func pdbGlobalStrings(msf *pdbMSF) []byte {
	info, err := msf.stream(1, maxPDBStreamBytes)
	if err != nil || len(info) < 32 {
		return nil
	}
	bufferSize := binary.LittleEndian.Uint32(info[28:32])
	bufferEnd := uint64(32) + uint64(bufferSize)
	if bufferEnd+8 > uint64(len(info)) {
		return nil
	}
	names := info[32:bufferEnd]
	offset := int(bufferEnd)
	entryCount := binary.LittleEndian.Uint32(info[offset : offset+4])
	capacity := binary.LittleEndian.Uint32(info[offset+4 : offset+8])
	offset += 8
	if entryCount > capacity || entryCount > maxPDBStreams {
		return nil
	}
	for vectors := 0; vectors < 2; vectors++ {
		if offset+4 > len(info) {
			return nil
		}
		words := binary.LittleEndian.Uint32(info[offset : offset+4])
		offset += 4
		if uint64(offset)+uint64(words)*4 > uint64(len(info)) {
			return nil
		}
		offset += int(words) * 4
	}
	if uint64(offset)+uint64(entryCount)*8 > uint64(len(info)) {
		return nil
	}
	for index := uint32(0); index < entryCount; index++ {
		nameOffset := binary.LittleEndian.Uint32(info[offset : offset+4])
		streamIndex := binary.LittleEndian.Uint32(info[offset+4 : offset+8])
		offset += 8
		if int(nameOffset) >= len(names) || pdbString(names[nameOffset:]) != "/names" || streamIndex > uint32(^uint16(0)) {
			continue
		}
		stream, err := msf.stream(int(streamIndex), maxPDBStreamBytes)
		if err != nil || len(stream) < 12 || binary.LittleEndian.Uint32(stream[:4]) != 0xeffeeffe {
			return nil
		}
		stringBytes := binary.LittleEndian.Uint32(stream[8:12])
		if uint64(12)+uint64(stringBytes) > uint64(len(stream)) {
			return nil
		}
		return stream[12 : 12+stringBytes]
	}
	return nil
}

func pdbModuleInfoEnd(data []byte, offset int) (int, bool) {
	if offset+64 > len(data) {
		return 0, false
	}
	firstEnd := bytes.IndexByte(data[offset+64:], 0)
	if firstEnd < 0 {
		return 0, false
	}
	secondStart := offset + 64 + firstEnd + 1
	if secondStart > len(data) {
		return 0, false
	}
	secondEnd := bytes.IndexByte(data[secondStart:], 0)
	if secondEnd < 0 {
		return 0, false
	}
	next := (secondStart + secondEnd + 1 + 3) &^ 3
	return next, next <= len(data)
}

type pdbSubsection struct {
	kind uint32
	data []byte
}

func parsePDBC13Data(data []byte, sections []pdbSection, globalStrings []byte, limit int) ([]pdbLine, map[uint32]pdbInlineeLine, map[uint32]string) {
	subsections := make([]pdbSubsection, 0)
	for offset := 0; offset+8 <= len(data); {
		kind := binary.LittleEndian.Uint32(data[offset:offset+4]) &^ uint32(0x80000000)
		size := uint64(binary.LittleEndian.Uint32(data[offset+4 : offset+8]))
		end := uint64(offset+8) + size
		if end > uint64(len(data)) {
			break
		}
		subsections = append(subsections, pdbSubsection{kind: kind, data: data[offset+8 : int(end)]})
		offset = (int(end) + 3) &^ 3
	}
	var stringsTable, checksums []byte
	for _, subsection := range subsections {
		switch subsection.kind {
		case 0xf3:
			stringsTable = subsection.data
		case 0xf4:
			checksums = subsection.data
		}
	}
	if len(stringsTable) == 0 {
		stringsTable = globalStrings
	}
	if len(stringsTable) == 0 || len(checksums) == 0 {
		return nil, nil, nil
	}
	files := parsePDBFileChecksums(checksums, stringsTable)
	lines := make([]pdbLine, 0)
	inlinees := make(map[uint32]pdbInlineeLine)
	for _, subsection := range subsections {
		switch subsection.kind {
		case 0xf2:
			if len(lines) < limit {
				lines = append(lines, parsePDBLineSubsection(subsection.data, sections, files, limit-len(lines))...)
			}
		case 0xf6:
			parsePDBInlineeLines(subsection.data, files, inlinees)
		}
	}
	return lines, inlinees, files
}

func parsePDBInlineeLines(data []byte, files map[uint32]string, destination map[uint32]pdbInlineeLine) {
	if len(data) < 4 {
		return
	}
	signature := binary.LittleEndian.Uint32(data[:4])
	if signature > 1 {
		return
	}
	for offset, records := 4, 0; offset+12 <= len(data) && records < maxPDBInlineSites; records++ {
		inlinee := binary.LittleEndian.Uint32(data[offset : offset+4])
		fileOffset := binary.LittleEndian.Uint32(data[offset+4 : offset+8])
		line := binary.LittleEndian.Uint32(data[offset+8 : offset+12])
		offset += 12
		if line > 0 && line <= uint32(^uint32(0)>>1) && files[fileOffset] != "" {
			destination[inlinee] = pdbInlineeLine{filename: files[fileOffset], line: int(line)}
		}
		if signature == 1 {
			if offset+4 > len(data) {
				return
			}
			extraFiles := binary.LittleEndian.Uint32(data[offset : offset+4])
			offset += 4
			if uint64(offset)+uint64(extraFiles)*4 > uint64(len(data)) {
				return
			}
			offset += int(extraFiles) * 4
		}
	}
}

func parsePDBFileChecksums(checksums, stringsTable []byte) map[uint32]string {
	files := make(map[uint32]string)
	for offset := 0; offset+6 <= len(checksums); {
		nameOffset := binary.LittleEndian.Uint32(checksums[offset : offset+4])
		checksumBytes := int(checksums[offset+4])
		length := (6 + checksumBytes + 3) &^ 3
		if offset+length > len(checksums) {
			break
		}
		if int(nameOffset) < len(stringsTable) {
			files[uint32(offset)] = pdbString(stringsTable[nameOffset:])
		}
		offset += length
	}
	return files
}

func parsePDBLineSubsection(data []byte, sections []pdbSection, files map[uint32]string, limit int) []pdbLine {
	if len(data) < 12 {
		return nil
	}
	relocationOffset := binary.LittleEndian.Uint32(data[:4])
	segment := binary.LittleEndian.Uint16(data[4:6])
	hasColumns := binary.LittleEndian.Uint16(data[6:8])&1 != 0
	codeSize := binary.LittleEndian.Uint32(data[8:12])
	if segment == 0 || int(segment) > len(sections) || uint64(sections[int(segment)-1].address)+uint64(relocationOffset) > uint64(^uint32(0)) {
		return nil
	}
	base := sections[int(segment)-1].address + relocationOffset
	fragmentEnd := uint64(base) + uint64(codeSize)
	if fragmentEnd > uint64(^uint32(0)) {
		fragmentEnd = uint64(^uint32(0))
	}
	lines := make([]pdbLine, 0)
	for offset := 12; offset+12 <= len(data) && len(lines) < limit; {
		nameIndex := binary.LittleEndian.Uint32(data[offset : offset+4])
		count := binary.LittleEndian.Uint32(data[offset+4 : offset+8])
		blockSize := binary.LittleEndian.Uint32(data[offset+8 : offset+12])
		if blockSize < 12 || uint64(offset)+uint64(blockSize) > uint64(len(data)) || count > maxPDBLines {
			break
		}
		lineBytes := uint64(count) * 8
		columnBytes := uint64(0)
		if hasColumns {
			columnBytes = uint64(count) * 4
		}
		if 12+lineBytes+columnBytes > uint64(blockSize) {
			break
		}
		filename := files[nameIndex]
		entriesOffset := offset + 12
		columnsOffset := entriesOffset + int(lineBytes)
		for index := 0; index < int(count) && len(lines) < limit; index++ {
			entry := entriesOffset + index*8
			codeOffset := binary.LittleEndian.Uint32(data[entry : entry+4])
			lineFlags := binary.LittleEndian.Uint32(data[entry+4 : entry+8])
			start := uint64(base) + uint64(codeOffset)
			end := fragmentEnd
			if index+1 < int(count) {
				nextEntry := entriesOffset + (index+1)*8
				end = uint64(base) + uint64(binary.LittleEndian.Uint32(data[nextEntry:nextEntry+4]))
			}
			if filename == "" || start >= end || end > uint64(^uint32(0)) {
				continue
			}
			column := 0
			if hasColumns {
				column = int(binary.LittleEndian.Uint16(data[columnsOffset+index*4 : columnsOffset+index*4+2]))
			}
			lineNumber := int(lineFlags & 0x00ffffff)
			if lineNumber == 0 || lineNumber == 0xfeefee || lineNumber == 0xf00f00 {
				continue
			}
			lines = append(lines, pdbLine{filename: filename, address: uint32(start), end: uint32(end), line: lineNumber, column: column})
		}
		offset += int(blockSize)
	}
	return lines
}

func pdbString(data []byte) string {
	if end := bytes.IndexByte(data, 0); end >= 0 {
		data = data[:end]
	}
	return strings.TrimSpace(strings.ToValidUTF8(string(data), ""))
}

func (p *pdbSymbols) lookup(address uint32) (pdbSymbol, bool) {
	sectionStart, sectionEnd, foundSection := uint64(0), uint64(0), false
	for _, section := range p.sections {
		start, end := uint64(section.address), uint64(section.address)+uint64(section.size)
		if uint64(address) >= start && uint64(address) < end {
			sectionStart, sectionEnd, foundSection = start, end, true
			break
		}
	}
	if !foundSection {
		return pdbSymbol{}, false
	}
	best := -1
	upper := sort.Search(len(p.symbols), func(index int) bool { return p.symbols[index].address > address })
	for index := upper - 1; index >= 0; index-- {
		symbol := p.symbols[index]
		if uint64(symbol.address) < sectionStart {
			break
		}
		if symbol.size > 0 && uint64(address)-uint64(symbol.address) >= uint64(symbol.size) {
			continue
		}
		if best < 0 || symbol.address > p.symbols[best].address || (symbol.address == p.symbols[best].address && symbol.size > p.symbols[best].size) {
			best = index
		}
	}
	if best < 0 {
		return pdbSymbol{}, false
	}
	if p.symbols[best].size == 0 {
		end := sectionEnd
		for _, symbol := range p.symbols {
			if symbol.address > p.symbols[best].address && uint64(symbol.address) < end {
				end = uint64(symbol.address)
			}
		}
		if uint64(address) >= end {
			return pdbSymbol{}, false
		}
	}
	return p.symbols[best], true
}

func (p *pdbSymbols) lookupLine(address uint32) (pdbLine, bool) {
	upper := sort.Search(len(p.lines), func(index int) bool { return p.lines[index].address > address })
	for index := upper - 1; index >= 0; index-- {
		line := p.lines[index]
		if address >= line.end {
			continue
		}
		return line, true
	}
	return pdbLine{}, false
}

func (p *pdbSymbols) expandInlineFrames(address, rootAddress uint32, result *nativeSymbol) {
	if p == nil || result == nil || len(p.inlines) == 0 || address < rootAddress {
		return
	}
	relative := address - rootAddress
	type match struct {
		site       int
		rangeValue pdbInlineRange
	}
	matches := make(map[int]match)
	for index := range p.inlines {
		site := &p.inlines[index]
		if site.rootAddress != rootAddress {
			continue
		}
		for _, candidate := range site.ranges {
			if relative < candidate.start || relative >= candidate.end {
				continue
			}
			previous, found := matches[site.parent]
			if !found || candidate.end-candidate.start < previous.rangeValue.end-previous.rangeValue.start {
				matches[site.parent] = match{site: index, rangeValue: candidate}
			}
		}
	}
	parent := -1
	previousFile, previousLine := result.filename, result.line
	for depth := 0; depth < maxNativeInlineDepth; depth++ {
		matched, found := matches[parent]
		if !found {
			break
		}
		site := &p.inlines[matched.site]
		bestRange := matched.rangeValue
		result.inlines = append(result.inlines, nativeInline{
			function:  site.function,
			filename:  previousFile,
			line:      previousLine,
			level:     depth,
			address:   uint64(rootAddress) + uint64(bestRange.start),
			rangeSize: uint64(bestRange.end - bestRange.start),
		})
		actualFile := site.inlinee.filename
		if bestRange.fileOffset != 0 && site.files[bestRange.fileOffset] != "" {
			actualFile = site.files[bestRange.fileOffset]
		}
		actualLine := int64(site.inlinee.line) + int64(bestRange.lineOffset)
		if actualFile != "" {
			previousFile = actualFile
		}
		if actualLine > 0 && actualLine <= int64(^uint32(0)>>1) {
			previousLine = int(actualLine)
		}
		parent = matched.site
	}
	if len(result.inlines) > 0 {
		result.filename, result.line, result.column = previousFile, previousLine, 0
	}
}
