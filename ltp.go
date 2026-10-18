package pst

import (
	"errors"
	"fmt"
)

// The lists-tables-properties layer: a heap inside a node's data, B-trees on
// that heap, and the two structures everything above is made of -- the
// property context (one object's properties) and the table context (rows of
// properties: recipients, attachments).

const (
	sigHeap = 0xEC
	sigBTH  = 0xB5
	sigPC   = 0xBC
	sigTC   = 0x7C

	// maxHeap bounds one node's heap. A message's heap holds its small
	// properties; anything large lives in a subnode.
	maxHeap = 64 << 20
	// maxRows bounds one table: far beyond any real recipient or
	// attachment list, well short of exhausting memory.
	maxRows = 200000
)

// node is a node with its data and subnode tree, top level or subnode.
type node struct {
	f         *File
	nid       uint32
	data, sub uint64
	subs      map[uint32]subnode
}

func (f *File) topNode(nid uint32) (*node, error) {
	e, ok := f.node(nid)
	if !ok {
		return nil, fmt.Errorf("%w: node %#x", ErrNotFound, nid)
	}
	return &node{f: f, nid: nid, data: e.data, sub: e.sub}, nil
}

func (n *node) child(nid uint32) (*node, error) {
	if n.subs == nil {
		s, err := n.f.subnodes(n.sub)
		if err != nil {
			return nil, err
		}
		n.subs = s
	}
	s, ok := n.subs[nid]
	if !ok {
		return nil, fmt.Errorf("%w: subnode %#x of %#x", ErrNotFound, nid, n.nid)
	}
	return &node{f: n.f, nid: nid, data: s.data, sub: s.sub}, nil
}

type heap struct {
	blocks [][]byte
	client byte
	root   uint32
}

func (n *node) heap() (*heap, error) {
	var blocks [][]byte
	total := 0
	err := n.f.dataBlocks(n.data, func(b []byte) error {
		total += len(b)
		if total > maxHeap {
			return corrupt("heap of node %#x is over %d bytes", n.nid, maxHeap)
		}
		blocks = append(blocks, b)
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(blocks) == 0 || len(blocks[0]) < 12 || blocks[0][2] != sigHeap {
		return nil, corrupt("node %#x has no heap", n.nid)
	}
	return &heap{blocks: blocks, client: blocks[0][3], root: le.Uint32(blocks[0][4:])}, nil
}

// get returns one heap allocation. The slice aliases the block.
func (h *heap) get(hid uint32) ([]byte, error) {
	if hid == 0 {
		return nil, nil
	}
	if hid&0x1F != 0 {
		return nil, corrupt("%#x is not a heap id", hid)
	}
	idx, blk := int(hid>>5)&0x7FF, int(hid>>16)
	if idx == 0 || blk >= len(h.blocks) {
		return nil, corrupt("heap id %#x out of range", hid)
	}
	b := h.blocks[blk]
	if len(b) < 2 {
		return nil, corrupt("heap block %d", blk)
	}
	pm := int(le.Uint16(b))
	if pm+4 > len(b) {
		return nil, corrupt("heap page map of block %d", blk)
	}
	cAlloc := int(le.Uint16(b[pm:]))
	if idx > cAlloc || pm+4+(cAlloc+1)*2 > len(b) {
		return nil, corrupt("heap id %#x past the page map", hid)
	}
	start := int(le.Uint16(b[pm+4+(idx-1)*2:]))
	end := int(le.Uint16(b[pm+4+idx*2:]))
	if start > end || end > len(b) {
		return nil, corrupt("heap allocation %#x", hid)
	}
	return b[start:end], nil
}

// bth calls fn with every leaf record of the B-tree on the heap at hid.
func (h *heap) bth(hid uint32, fn func(key, data []byte) error) error {
	hdr, err := h.get(hid)
	if err != nil {
		return err
	}
	if len(hdr) < 8 || hdr[0] != sigBTH {
		return corrupt("heap id %#x is not a B-tree header", hid)
	}
	cbKey, cbEnt, levels := int(hdr[1]), int(hdr[2]), int(hdr[3])
	if cbKey == 0 || cbKey > 16 || levels > 8 {
		return corrupt("B-tree header %#x", hid)
	}
	return h.bthWalk(le.Uint32(hdr[4:]), cbKey, cbEnt, levels, fn)
}

func (h *heap) bthWalk(hid uint32, cbKey, cbEnt, level int, fn func(key, data []byte) error) error {
	if hid == 0 {
		return nil
	}
	recs, err := h.get(hid)
	if err != nil {
		return err
	}
	if level > 0 {
		size := cbKey + 4
		for i := 0; i+size <= len(recs); i += size {
			if err := h.bthWalk(le.Uint32(recs[i+cbKey:]), cbKey, cbEnt, level-1, fn); err != nil {
				return err
			}
		}
		return nil
	}
	size := cbKey + cbEnt
	for i := 0; i+size <= len(recs); i += size {
		if err := fn(recs[i:i+cbKey], recs[i+cbKey:i+size]); err != nil {
			return err
		}
	}
	return nil
}

// value reads an HNID: a heap allocation, or -- for anything too large for
// the heap -- a subnode of n. Capped at max bytes.
func (n *node) value(h *heap, hnid uint32, max int) (b []byte, truncated bool, err error) {
	if hnid == 0 {
		return nil, false, nil
	}
	if hnid&0x1F == 0 {
		v, err := h.get(hnid)
		if len(v) > max {
			return v[:max], true, err
		}
		return v, false, err
	}
	c, err := n.child(hnid)
	if err != nil {
		return nil, false, err
	}
	return n.f.readStream(c.data, max)
}

// ---- property context

type pcEntry struct {
	typ uint16
	v   uint32
}

// props is one object's properties.
type props struct {
	n *node
	h *heap
	m map[uint16]pcEntry
}

func (n *node) props() (*props, error) {
	h, err := n.heap()
	if err != nil {
		return nil, err
	}
	if h.client != sigPC {
		return nil, corrupt("node %#x is not a property context (%#x)", n.nid, h.client)
	}
	p := &props{n: n, h: h, m: map[uint16]pcEntry{}}
	err = h.bth(h.root, func(k, d []byte) error {
		if len(k) != 2 || len(d) < 6 {
			return corrupt("property record of node %#x", n.nid)
		}
		p.m[le.Uint16(k)] = pcEntry{typ: le.Uint16(d), v: le.Uint32(d[2:])}
		return nil
	})
	return p, err
}

// raw is one property's bytes and type; ok is false when it is absent.
func (p *props) raw(id uint16, max int) (typ uint16, b []byte, ok bool, err error) {
	e, ok := p.m[id]
	if !ok {
		return 0, nil, false, nil
	}
	if sz := fixedSize(e.typ); sz > 0 && sz <= 4 {
		var buf [4]byte
		le.PutUint32(buf[:], e.v)
		return e.typ, buf[:sz], true, nil
	}
	b, _, err = p.n.value(p.h, e.v, max)
	return e.typ, b, true, err
}

// ---- table context

type column struct {
	tag  uint32 // type in the low 16 bits, id in the high
	ib   int
	cb   int
	iBit int
}

type table struct {
	n    *node
	h    *heap
	cols map[uint16]column
	ceb  int // offset of the cell-existence bitmap in a row
	rows [][]byte
}

func (n *node) table() (*table, error) {
	h, err := n.heap()
	if err != nil {
		return nil, err
	}
	if h.client != sigTC {
		return nil, corrupt("node %#x is not a table (%#x)", n.nid, h.client)
	}
	info, err := h.get(h.root)
	if err != nil {
		return nil, err
	}
	if len(info) < 22 || info[0] != sigTC {
		return nil, corrupt("table header of node %#x", n.nid)
	}
	nCols := int(info[1])
	if 22+nCols*8 > len(info) {
		return nil, corrupt("table columns of node %#x", n.nid)
	}
	t := &table{n: n, h: h, cols: map[uint16]column{}, ceb: int(le.Uint16(info[6:]))}
	rowSize := int(le.Uint16(info[8:]))
	for i := 0; i < nCols; i++ {
		c := info[22+i*8:]
		col := column{tag: le.Uint32(c), ib: int(le.Uint16(c[4:])), cb: int(c[6]), iBit: int(c[7])}
		if col.ib+col.cb > rowSize || t.ceb+col.iBit/8 >= rowSize {
			return nil, corrupt("table column %d of node %#x", i, n.nid)
		}
		t.cols[uint16(col.tag>>16)] = col
	}
	count := 0
	if err := h.bth(le.Uint32(info[10:]), func(_, _ []byte) error { count++; return nil }); err != nil {
		return nil, err
	}
	if count > maxRows {
		return nil, corrupt("table of node %#x has %d rows", n.nid, count)
	}
	rowsAt := le.Uint32(info[14:])
	if count == 0 || rowsAt == 0 || rowSize == 0 {
		return t, nil
	}
	take := func(b []byte) error {
		for off := 0; off+rowSize <= len(b) && len(t.rows) < count; off += rowSize {
			t.rows = append(t.rows, b[off:off+rowSize])
		}
		if len(t.rows) >= count {
			return errStop
		}
		return nil
	}
	if rowsAt&0x1F == 0 {
		b, err := h.get(rowsAt)
		if err != nil {
			return nil, err
		}
		take(b)
		return t, nil
	}
	c, err := n.child(rowsAt)
	if err != nil {
		return nil, err
	}
	if err := n.f.dataBlocks(c.data, take); err != nil && !errors.Is(err, errStop) {
		return nil, err
	}
	return t, nil
}

// cell is one row's value for a property, with the same shape as props.raw.
func (t *table) cell(row []byte, id uint16, max int) (typ uint16, b []byte, ok bool, err error) {
	c, found := t.cols[id]
	if !found || len(row) < c.ib+c.cb || row[t.ceb+c.iBit/8]&(0x80>>(c.iBit%8)) == 0 {
		return 0, nil, false, nil
	}
	typ = uint16(c.tag)
	cellData := row[c.ib : c.ib+c.cb]
	if sz := fixedSize(typ); sz > 0 && sz <= 8 {
		if len(cellData) < sz {
			return 0, nil, false, corrupt("table cell %#x", id)
		}
		return typ, cellData[:sz], true, nil
	}
	if len(cellData) < 4 {
		return 0, nil, false, corrupt("table cell %#x", id)
	}
	b, _, err = t.n.value(t.h, le.Uint32(cellData), max)
	return typ, b, true, err
}
