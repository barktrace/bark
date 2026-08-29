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
	maxPDBSymbols        = 1000000
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

type pdbSymbols struct {
	sections []pdbSection
	symbols  []pdbSymbol
}

func lookupPDBFrame(reader io.ReaderAt, address, imageBase uint64) nativeSymbol {
	parsed, err := parsePDBSymbols(reader)
	if err != nil {
		return nativeSymbol{}
	}
	rva := address
	if imageBase > 0 && address >= imageBase {
		rva = address - imageBase
	}
	if rva > uint64(^uint32(0)) {
		return nativeSymbol{}
	}
	matched, ok := parsed.lookup(uint32(rva))
	if !ok {
		return nativeSymbol{}
	}
	return nativeSymbol{function: matched.name, address: uint64(matched.address)}
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
	return &pdbSymbols{sections: sections, symbols: symbols}, nil
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
	if blockSize < 512 || blockSize > 65536 || blockSize&(blockSize-1) != 0 || numBlocks == 0 || uint64(blockSize)*uint64(numBlocks) > maxPDBBytes {
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
	for index, symbol := range p.symbols {
		if uint64(symbol.address) < sectionStart || uint64(symbol.address) > uint64(address) {
			continue
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
