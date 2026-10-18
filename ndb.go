// Package pst reads Outlook data files (.pst) -- read-only, streaming, and
// without Outlook.
//
// Written for one job: reading a mailbox archive far larger than memory
// (the CEO's is 129 GB) on a server with no Office installed, so it can be
// reduced to structured observations locally instead of being shipped
// anywhere. It follows MS-PST: the node database (NDB -- the header, the
// node and block B-trees, blocks and subnodes), the lists-tables-properties
// layer (LTP -- heaps, B-trees on heaps, property and table contexts) and the
// messaging layer on top (folders, messages, recipients, attachments).
//
// HOSTILE BY DEFAULT. Every offset read from the file is bounds-checked
// before use, every block's CRC and id are verified, tree walks are depth-
// and cycle-bounded, and values are read with a caller-set size cap. A
// malformed message fails that message (ErrCorrupt), never the file, and
// never with a panic: ReadMessage recovers and reports.
//
// Unicode files only (Outlook 2003 and later, wVer >= 23, 512-byte pages).
// ANSI files are capped at 2 GB and 4K-page files are OSTs; both are refused
// by name rather than misread.
package pst

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sort"
)

var le = binary.LittleEndian

var (
	// ErrNotPST: the file does not start like an Outlook data file.
	ErrNotPST = errors.New("pst: not an Outlook data file")
	// ErrUnsupported: a real Outlook file this reader does not read.
	ErrUnsupported = errors.New("pst: unsupported format")
	// ErrCorrupt: a structure failed a check. Scoped to what was being read.
	ErrCorrupt = errors.New("pst: corrupt structure")
	// ErrNotFound: an id the structure pointed at is not there.
	ErrNotFound = errors.New("pst: not found")
)

func corrupt(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrCorrupt, fmt.Sprintf(format, a...))
}

const (
	headerSize  = 564
	pageSize    = 512
	pageData    = 496 // a page less its trailer
	trailerSize = 16  // unicode BLOCKTRAILER
	maxBlock    = 8192
	maxDepth    = 16

	ptypeBBT = 0x80
	ptypeNBT = 0x81
)

// Node types: the low five bits of a node id.
const (
	nidTypeNormalFolder  = 0x02
	nidTypeSearchFolder  = 0x03
	nidTypeNormalMessage = 0x04
	nidTypeAssocMessage  = 0x08

	nidMessageStore = 0x21
	nidNameToIDMap  = 0x61
	nidRootFolder   = 0x122
	nidRecipients   = 0x692
	nidAttachments  = 0x671
)

type nodeEntry struct {
	nid    uint32
	parent uint32
	data   uint64
	sub    uint64
}

type blockEntry struct {
	bid uint64
	ib  uint64
	cb  uint16
}

// File is an open data file. Safe for concurrent reads once Open returns:
// the indexes are built there and never written again, and io.ReaderAt is
// safe for concurrent use.
type File struct {
	r      io.ReaderAt
	size   int64
	crypt  byte
	nodes  []nodeEntry  // by nid
	blocks []blockEntry // by bid, bit 0 cleared

	// BadPages counts B-tree pages that failed their checks while the
	// indexes were built; the nodes and blocks under them are unreachable.
	BadPages int

	keywordsProp uint16 // named property "Keywords", 0 if the map has none
}

// Open reads the header and builds the node and block indexes -- the only
// part of the file read up front. On a 129 GB file that is a few hundred
// megabytes of pages, read level by level in file order; on a spinning disk
// that is many minutes, which is what OpenCached is for.
func Open(r io.ReaderAt, size int64) (*File, error) {
	f, h, err := openHeader(r, size)
	if err != nil {
		return nil, err
	}
	if err := f.buildIndex(h); err != nil {
		return nil, err
	}
	f.keywordsProp = f.findKeywords()
	return f, nil
}

func openHeader(r io.ReaderAt, size int64) (*File, []byte, error) {
	h := make([]byte, headerSize)
	if _, err := r.ReadAt(h, 0); err != nil {
		return nil, nil, fmt.Errorf("pst: reading the header: %w", err)
	}
	if string(h[0:4]) != "!BDN" || string(h[8:10]) != "SM" {
		return nil, nil, ErrNotPST
	}
	switch ver := le.Uint16(h[10:]); {
	case ver == 14 || ver == 15:
		return nil, nil, fmt.Errorf("%w: ANSI (pre-2003) file", ErrUnsupported)
	case ver == 36:
		return nil, nil, fmt.Errorf("%w: 4K-page file (an OST)", ErrUnsupported)
	case ver < 23:
		return nil, nil, fmt.Errorf("%w: format version %d", ErrUnsupported, ver)
	}
	if crc(h[8:8+471]) != le.Uint32(h[4:]) {
		return nil, nil, corrupt("header checksum")
	}
	f := &File{r: r, size: size, crypt: h[513]}
	if f.crypt > cryptCyclic {
		return nil, nil, fmt.Errorf("%w: encryption method %d", ErrUnsupported, f.crypt)
	}
	if eof := int64(le.Uint64(h[184:])); eof > size {
		return nil, nil, corrupt("the header says the file is %d bytes; it is %d (truncated copy?)", eof, size)
	}
	return f, h, nil
}

func (f *File) buildIndex(h []byte) error {
	nbtRoot, bbtRoot := le.Uint64(h[224:]), le.Uint64(h[240:])

	if err := f.loadTree(bbtRoot, ptypeBBT, 24, func(e []byte) {
		f.blocks = append(f.blocks, blockEntry{bid: le.Uint64(e) &^ 1, ib: le.Uint64(e[8:]), cb: le.Uint16(e[16:])})
	}); err != nil {
		return err
	}
	sort.Slice(f.blocks, func(i, j int) bool { return f.blocks[i].bid < f.blocks[j].bid })

	if err := f.loadTree(nbtRoot, ptypeNBT, 32, func(e []byte) {
		f.nodes = append(f.nodes, nodeEntry{nid: le.Uint32(e), data: le.Uint64(e[8:]), sub: le.Uint64(e[16:]), parent: le.Uint32(e[24:])})
	}); err != nil {
		return err
	}
	sort.Slice(f.nodes, func(i, j int) bool { return f.nodes[i].nid < f.nodes[j].nid })

	if len(f.nodes) == 0 || len(f.blocks) == 0 {
		return corrupt("empty node or block index")
	}
	return nil
}

// Blocks and Nodes are the index sizes, for progress reporting.
func (f *File) Blocks() int { return len(f.blocks) }
func (f *File) Nodes() int  { return len(f.nodes) }

// loadTree walks a B-tree breadth first, each level's pages read in file
// order, calling leaf for every leaf entry. A page that fails its checks is
// counted in BadPages and its subtree skipped: one bad page must not cost the
// whole archive. Only the root failing is fatal.
func (f *File) loadTree(root uint64, ptype byte, leafSize int, leaf func([]byte)) error {
	level := []uint64{root}
	seen := map[uint64]bool{root: true}
	for depth := 0; len(level) > 0; depth++ {
		if depth > maxDepth {
			return corrupt("B-tree deeper than %d levels", maxDepth)
		}
		sort.Slice(level, func(i, j int) bool { return level[i] < level[j] })
		var next []uint64
		for _, ib := range level {
			p, err := f.page(ib, ptype)
			if err != nil {
				if depth == 0 {
					return err
				}
				f.BadPages++
				continue
			}
			cEnt, cbEnt, cLevel := int(p[488]), int(p[490]), p[491]
			if cbEnt == 0 || cEnt*cbEnt > 488 || (cLevel == 0 && cbEnt < leafSize) || (cLevel > 0 && cbEnt < 24) {
				if depth == 0 {
					return corrupt("B-tree root page at %d", ib)
				}
				f.BadPages++
				continue
			}
			for i := 0; i < cEnt; i++ {
				e := p[i*cbEnt : (i+1)*cbEnt]
				if cLevel == 0 {
					leaf(e)
					continue
				}
				child := le.Uint64(e[16:])
				if !seen[child] && child%pageSize == 0 && child+pageSize <= uint64(f.size) {
					seen[child] = true
					next = append(next, child)
				}
			}
		}
		level = next
	}
	return nil
}

// page reads one B-tree page and checks its trailer and CRC.
func (f *File) page(ib uint64, ptype byte) ([]byte, error) {
	if ib+pageSize > uint64(f.size) {
		return nil, corrupt("page at %d is past the end of the file", ib)
	}
	p := make([]byte, pageSize)
	if _, err := f.r.ReadAt(p, int64(ib)); err != nil {
		return nil, fmt.Errorf("pst: reading page at %d: %w", ib, err)
	}
	t := p[pageData:]
	if t[0] != ptype || t[1] != ptype {
		return nil, corrupt("page at %d has type %#x, want %#x", ib, t[0], ptype)
	}
	if crc(p[:pageData]) != le.Uint32(t[4:]) {
		return nil, corrupt("page at %d fails its checksum", ib)
	}
	return p, nil
}

func (f *File) node(nid uint32) (nodeEntry, bool) {
	i := sort.Search(len(f.nodes), func(i int) bool { return f.nodes[i].nid >= nid })
	if i < len(f.nodes) && f.nodes[i].nid == nid {
		return f.nodes[i], true
	}
	return nodeEntry{}, false
}

func (f *File) findBlock(bid uint64) (blockEntry, bool) {
	bid &^= 1
	i := sort.Search(len(f.blocks), func(i int) bool { return f.blocks[i].bid >= bid })
	if i < len(f.blocks) && f.blocks[i].bid == bid {
		return f.blocks[i], true
	}
	return blockEntry{}, false
}

// block reads one block, checks its trailer and CRC, and decodes it when it
// is a data block. Internal blocks (bit 1 of the id) are never encoded.
func (f *File) block(bid uint64) ([]byte, error) {
	e, ok := f.findBlock(bid)
	if !ok {
		return nil, fmt.Errorf("%w: block %#x", ErrNotFound, bid)
	}
	cb := int(e.cb)
	alloc := (cb + trailerSize + 63) &^ 63
	if alloc > maxBlock || e.ib+uint64(alloc) > uint64(f.size) {
		return nil, corrupt("block %#x: %d bytes at %d", bid, cb, e.ib)
	}
	buf := make([]byte, alloc)
	if _, err := f.r.ReadAt(buf, int64(e.ib)); err != nil {
		return nil, fmt.Errorf("pst: reading block %#x: %w", bid, err)
	}
	t := buf[alloc-trailerSize:]
	if int(le.Uint16(t)) != cb || le.Uint64(t[8:])&^1 != bid&^1 {
		return nil, corrupt("block %#x: trailer does not match the index", bid)
	}
	data := buf[:cb]
	if crc(data) != le.Uint32(t[4:]) {
		return nil, corrupt("block %#x fails its checksum", bid)
	}
	if bid&2 == 0 {
		switch f.crypt {
		case cryptPermute:
			decodePermute(data)
		case cryptCyclic:
			decodeCyclic(data, uint32(bid))
		}
	}
	return data, nil
}

// errStop ends a walk early without it being a failure.
var errStop = errors.New("stop")

// dataBlocks calls fn with each data block of the stream rooted at bid, in
// order: one block, or the leaves of an XBLOCK / XXBLOCK tree.
func (f *File) dataBlocks(bid uint64, fn func([]byte) error) error {
	return f.walkData(bid, fn, 0)
}

func (f *File) walkData(bid uint64, fn func([]byte) error, depth int) error {
	if bid == 0 {
		return nil
	}
	b, err := f.block(bid)
	if err != nil {
		return err
	}
	if bid&2 == 0 {
		return fn(b)
	}
	if depth > 2 || len(b) < 8 || b[0] != 0x01 {
		return corrupt("block %#x is not a data tree", bid)
	}
	level, n := b[1], int(le.Uint16(b[2:]))
	if (level != 1 && level != 2) || 8+n*8 > len(b) {
		return corrupt("data tree block %#x", bid)
	}
	for i := 0; i < n; i++ {
		child := le.Uint64(b[8+i*8:])
		if level == 1 {
			cb, err := f.block(child)
			if err != nil {
				return err
			}
			if child&2 != 0 {
				return corrupt("data tree %#x points at internal block %#x", bid, child)
			}
			if err := fn(cb); err != nil {
				return err
			}
			continue
		}
		if err := f.walkData(child, fn, depth+1); err != nil {
			return err
		}
	}
	return nil
}

// readStream concatenates a stream, up to max bytes; truncated reports that
// it was longer.
func (f *File) readStream(bid uint64, max int) (out []byte, truncated bool, err error) {
	err = f.dataBlocks(bid, func(b []byte) error {
		if len(out)+len(b) > max {
			out = append(out, b[:max-len(out)]...)
			truncated = true
			return errStop
		}
		out = append(out, b...)
		return nil
	})
	if errors.Is(err, errStop) {
		err = nil
	}
	return out, truncated, err
}

// subnode is one entry of a node's private subnode tree.
type subnode struct {
	data, sub uint64
}

// subnodes reads a subnode tree (SLBLOCK / SIBLOCK) into a map.
func (f *File) subnodes(bid uint64) (map[uint32]subnode, error) {
	m := map[uint32]subnode{}
	if bid == 0 {
		return m, nil
	}
	return m, f.walkSub(bid, m, 0)
}

func (f *File) walkSub(bid uint64, m map[uint32]subnode, depth int) error {
	if depth > 4 {
		return corrupt("subnode tree deeper than 4 levels")
	}
	b, err := f.block(bid)
	if err != nil {
		return err
	}
	if len(b) < 8 || b[0] != 0x02 {
		return corrupt("block %#x is not a subnode tree", bid)
	}
	level, n := b[1], int(le.Uint16(b[2:]))
	switch level {
	case 0:
		if 8+n*24 > len(b) {
			return corrupt("subnode leaf %#x", bid)
		}
		for i := 0; i < n; i++ {
			e := b[8+i*24:]
			m[le.Uint32(e)] = subnode{data: le.Uint64(e[8:]), sub: le.Uint64(e[16:])}
		}
	case 1:
		if 8+n*16 > len(b) {
			return corrupt("subnode index %#x", bid)
		}
		for i := 0; i < n; i++ {
			if err := f.walkSub(le.Uint64(b[8+i*16+8:]), m, depth+1); err != nil {
				return err
			}
		}
	default:
		return corrupt("subnode block %#x has level %d", bid, level)
	}
	return nil
}
