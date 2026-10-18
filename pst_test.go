package pst

import (
	"bytes"
	"encoding/binary"
	"errors"
	"sort"
	"testing"
	"time"
	"unicode/utf16"
)

// A PST built byte by byte in the test -- header, both B-trees, blocks, a
// subnode tree, heaps, a property context and two table contexts -- so the
// reader is pinned to the format as MS-PST writes it and not only to one
// archive that happens to parse.

func TestTheCryptTableIsThreePermutationsWithTheInverse(t *testing.T) {
	for part := 0; part < 3; part++ {
		var seen [256]bool
		for _, b := range mpbbCrypt[part*256 : part*256+256] {
			if seen[b] {
				t.Fatalf("table %d repeats %#x", part, b)
			}
			seen[b] = true
		}
	}
	for x := 0; x < 256; x++ {
		if mpbbCrypt[512+int(mpbbCrypt[x])] != byte(x) {
			t.Fatalf("I is not the inverse of R at %#x", x)
		}
	}
	p := []byte("Proforma 2291 / پیش فاکتور")
	enc := append([]byte(nil), p...)
	for i, b := range enc {
		enc[i] = mpbbCrypt[b]
	}
	decodePermute(enc)
	if !bytes.Equal(enc, p) {
		t.Fatal("permute does not round-trip")
	}
}

// ---- a minimal PST writer

type fixture struct {
	buf    []byte
	blocks []blockEntry
	nodes  []nodeEntry
	crypt  byte
	nextB  uint64
}

func newFixture(crypt byte) *fixture {
	return &fixture{buf: make([]byte, 1024), crypt: crypt, nextB: 4}
}

func (f *fixture) align(n int) {
	for len(f.buf)%n != 0 {
		f.buf = append(f.buf, 0)
	}
}

// block writes a block and returns its id; internal blocks are not encoded.
func (f *fixture) block(data []byte, internal bool) uint64 {
	f.nextB += 4
	bid := f.nextB
	if internal {
		bid |= 2
	}
	f.align(64)
	ib := uint64(len(f.buf))
	stored := append([]byte(nil), data...)
	if !internal && f.crypt == cryptPermute {
		for i, b := range stored {
			stored[i] = mpbbCrypt[b]
		}
	}
	alloc := (len(stored) + trailerSize + 63) &^ 63
	blk := make([]byte, alloc)
	copy(blk, stored)
	tr := blk[alloc-trailerSize:]
	binary.LittleEndian.PutUint16(tr, uint16(len(stored)))
	binary.LittleEndian.PutUint32(tr[4:], crc(stored))
	binary.LittleEndian.PutUint64(tr[8:], bid)
	f.buf = append(f.buf, blk...)
	f.blocks = append(f.blocks, blockEntry{bid: bid, ib: ib, cb: uint16(len(stored))})
	return bid
}

func (f *fixture) page(entries [][]byte, cbEnt int, ptype byte) uint64 {
	f.align(512)
	ib := uint64(len(f.buf))
	p := make([]byte, pageSize)
	for i, e := range entries {
		copy(p[i*cbEnt:], e)
	}
	p[488], p[489], p[490], p[491] = byte(len(entries)), byte(488/cbEnt), byte(cbEnt), 0
	p[pageData], p[pageData+1] = ptype, ptype
	binary.LittleEndian.PutUint32(p[pageData+4:], crc(p[:pageData]))
	f.buf = append(f.buf, p...)
	return ib
}

func (f *fixture) finish() []byte {
	sort.Slice(f.blocks, func(i, j int) bool { return f.blocks[i].bid < f.blocks[j].bid })
	var bbt [][]byte
	for _, b := range f.blocks {
		e := make([]byte, 24)
		binary.LittleEndian.PutUint64(e, b.bid)
		binary.LittleEndian.PutUint64(e[8:], b.ib)
		binary.LittleEndian.PutUint16(e[16:], b.cb)
		binary.LittleEndian.PutUint16(e[18:], 1)
		bbt = append(bbt, e)
	}
	sort.Slice(f.nodes, func(i, j int) bool { return f.nodes[i].nid < f.nodes[j].nid })
	var nbt [][]byte
	for _, n := range f.nodes {
		e := make([]byte, 32)
		binary.LittleEndian.PutUint32(e, n.nid)
		binary.LittleEndian.PutUint64(e[8:], n.data)
		binary.LittleEndian.PutUint64(e[16:], n.sub)
		binary.LittleEndian.PutUint32(e[24:], n.parent)
		nbt = append(nbt, e)
	}
	bbtIB := f.page(bbt, 24, ptypeBBT)
	nbtIB := f.page(nbt, 32, ptypeNBT)
	h := f.buf[:headerSize]
	copy(h, "!BDN")
	copy(h[8:], "SM")
	binary.LittleEndian.PutUint16(h[10:], 23)
	binary.LittleEndian.PutUint64(h[184:], uint64(len(f.buf)))
	binary.LittleEndian.PutUint64(h[216:], 1)
	binary.LittleEndian.PutUint64(h[224:], nbtIB)
	binary.LittleEndian.PutUint64(h[232:], 2)
	binary.LittleEndian.PutUint64(h[240:], bbtIB)
	h[512], h[513] = 0x80, f.crypt
	binary.LittleEndian.PutUint32(h[4:], crc(h[8:8+471]))
	return f.buf
}

// heapBlock lays allocations out as one heap block; allocation i has the
// heap id (i+1)<<5.
func heapBlock(client byte, root uint32, allocs [][]byte) []byte {
	b := make([]byte, 12)
	b[2], b[3] = sigHeap, client
	binary.LittleEndian.PutUint32(b[4:], root)
	offs := []uint16{12}
	for _, a := range allocs {
		b = append(b, a...)
		offs = append(offs, uint16(len(b)))
	}
	if len(b)%2 == 1 {
		b = append(b, 0)
	}
	binary.LittleEndian.PutUint16(b, uint16(len(b)))
	pm := make([]byte, 4+2*len(offs))
	binary.LittleEndian.PutUint16(pm, uint16(len(allocs)))
	for i, o := range offs {
		binary.LittleEndian.PutUint16(pm[4+2*i:], o)
	}
	return append(b, pm...)
}

func hid(i int) uint32 { return uint32(i+1) << 5 }

func u16(s string) []byte {
	u := utf16.Encode([]rune(s))
	b := make([]byte, 2*len(u))
	for i, v := range u {
		binary.LittleEndian.PutUint16(b[2*i:], v)
	}
	return b
}

type prop struct {
	id, typ uint16
	val     []byte // fixed values up to 4 bytes inline; everything else in the heap
}

// pcBlock is a property context as one heap block.
func pcBlock(props []prop) []byte {
	sort.Slice(props, func(i, j int) bool { return props[i].id < props[j].id })
	allocs := [][]byte{nil, nil} // 0: BTH header, 1: records
	var recs []byte
	for _, p := range props {
		r := make([]byte, 8)
		binary.LittleEndian.PutUint16(r, p.id)
		binary.LittleEndian.PutUint16(r[2:], p.typ)
		if sz := fixedSize(p.typ); sz > 0 && sz <= 4 {
			copy(r[4:], p.val)
		} else {
			allocs = append(allocs, p.val)
			binary.LittleEndian.PutUint32(r[4:], hid(len(allocs)-1))
		}
		recs = append(recs, r...)
	}
	hdr := make([]byte, 8)
	hdr[0], hdr[1], hdr[2], hdr[3] = sigBTH, 2, 6, 0
	binary.LittleEndian.PutUint32(hdr[4:], hid(1))
	allocs[0], allocs[1] = hdr, recs
	return heapBlock(sigPC, hid(0), allocs)
}

type col struct {
	tag uint32
	ib  int
}

// tcBlock is a table context with 4-byte cells and a one-byte cell bitmap;
// string cells hold heap ids of allocations appended after the fixed ones.
func tcBlock(cols []col, rows [][]any) []byte {
	rowSize := 4*len(cols) + 1
	allocs := [][]byte{nil, nil, nil} // 0: TCINFO, 1: row index BTH header, 2: row index records
	var matrix []byte
	var index []byte
	for ri, row := range rows {
		r := make([]byte, rowSize)
		for ci, c := range cols {
			v := row[ci]
			if v == nil {
				continue
			}
			r[rowSize-1] |= 0x80 >> ci
			switch x := v.(type) {
			case uint32:
				binary.LittleEndian.PutUint32(r[c.ib:], x)
			case string:
				allocs = append(allocs, u16(x))
				binary.LittleEndian.PutUint32(r[c.ib:], hid(len(allocs)-1))
			}
		}
		matrix = append(matrix, r...)
		e := make([]byte, 8)
		binary.LittleEndian.PutUint32(e, uint32(ri+1))
		binary.LittleEndian.PutUint32(e[4:], uint32(ri))
		index = append(index, e...)
	}
	allocs = append(allocs, matrix)
	matrixHID := hid(len(allocs) - 1)
	info := make([]byte, 22+8*len(cols))
	info[0], info[1] = sigTC, byte(len(cols))
	binary.LittleEndian.PutUint16(info[2:], uint16(4*len(cols)))
	binary.LittleEndian.PutUint16(info[4:], uint16(4*len(cols)))
	binary.LittleEndian.PutUint16(info[6:], uint16(4*len(cols)))
	binary.LittleEndian.PutUint16(info[8:], uint16(rowSize))
	binary.LittleEndian.PutUint32(info[10:], hid(1))
	binary.LittleEndian.PutUint32(info[14:], matrixHID)
	for i, c := range cols {
		d := info[22+8*i:]
		binary.LittleEndian.PutUint32(d, c.tag)
		binary.LittleEndian.PutUint16(d[4:], uint16(c.ib))
		d[6], d[7] = 4, byte(i)
	}
	bh := make([]byte, 8)
	bh[0], bh[1], bh[2], bh[3] = sigBTH, 4, 4, 0
	binary.LittleEndian.PutUint32(bh[4:], hid(2))
	allocs[0], allocs[1], allocs[2] = info, bh, index
	return heapBlock(sigTC, hid(0), allocs)
}

func le32(v uint32) []byte { b := make([]byte, 4); binary.LittleEndian.PutUint32(b, v); return b }
func le64(v uint64) []byte { b := make([]byte, 8); binary.LittleEndian.PutUint64(b, v); return b }

func ft(t time.Time) []byte {
	return le64(uint64(t.UnixNano()/100) + 116444736000000000)
}

const (
	testFolder  = 0x8082
	testMessage = 0x200024
	testAttach  = 0x8025
)

func buildPST(t *testing.T, crypt byte) []byte {
	t.Helper()
	f := newFixture(crypt)
	folder := f.block(pcBlock([]prop{{propDisplayName, ptUnicode, u16("Posteingang")}, {propContainerClass, ptUnicode, u16("IPF.Note")}}), false)
	at := time.Date(2025, 3, 4, 9, 30, 0, 0, time.UTC)
	msg := f.block(pcBlock([]prop{
		{propMessageClass, ptUnicode, u16("IPM.Note")},
		{propSubject, ptUnicode, u16("\x01\x04AW: Proforma PI-2291")},
		{propSenderAddr, ptUnicode, u16("Sales@Supplier.example")},
		{propSenderName, ptUnicode, u16("Supplier Sales")},
		{propInternetMessageID, ptUnicode, u16("<abc@supplier.example>")},
		{propBody, ptUnicode, u16("Dear Sir,\nplease find our PI attached.\n\n-----Original Message-----\nold text")},
		{propDeliveryTime, ptSysTime, ft(at)},
		{propLastVerbTime, ptSysTime, ft(at.Add(42 * time.Minute))},
		{propMessageFlags, ptLong, le32(FlagRead | FlagAttach)},
		{propLastVerb, ptLong, le32(VerbReplyAll)},
	}), false)
	rcpt := f.block(tcBlock([]col{{0x67F20003, 0}, {0x0C150003, 4}, {0x3001001F, 8}, {0x39FE001F, 12}}, [][]any{
		{uint32(1), uint32(1), "CEO", "ceo@example.com"},
		{uint32(2), uint32(2), "Colleague", "expert@example.com"},
	}), false)
	atab := f.block(tcBlock([]col{{0x67F20003, 0}, {0x3707001F, 4}}, [][]any{
		{uint32(testAttach), "PI-2291.pdf"},
	}), false)
	attach := f.block(pcBlock([]prop{
		{propAttachLongFilename, ptUnicode, u16("PI-2291.pdf")},
		{propAttachMethod, ptLong, le32(1)},
		{propAttachSize, ptLong, le32(20)},
		{propAttachData, ptBinary, []byte("%PDF-1.4 proforma...")},
	}), false)
	sl := make([]byte, 8+3*24)
	sl[0], sl[1] = 0x02, 0
	binary.LittleEndian.PutUint16(sl[2:], 3)
	for i, e := range []struct {
		nid  uint32
		data uint64
	}{{testAttach, attach}, {nidAttachments, atab}, {nidRecipients, rcpt}} {
		binary.LittleEndian.PutUint32(sl[8+24*i:], e.nid)
		binary.LittleEndian.PutUint64(sl[8+24*i+8:], e.data)
	}
	sub := f.block(sl, true)
	f.nodes = append(f.nodes,
		nodeEntry{nid: testFolder, parent: nidRootFolder, data: folder},
		nodeEntry{nid: testMessage, parent: testFolder, data: msg, sub: sub})
	return f.finish()
}

func TestAMessageIsReadWithItsRecipientsAndAttachment(t *testing.T) {
	for _, crypt := range []byte{cryptNone, cryptPermute} {
		raw := buildPST(t, crypt)
		f, err := Open(bytes.NewReader(raw), int64(len(raw)))
		if err != nil {
			t.Fatalf("crypt %d: open: %v", crypt, err)
		}
		folders, _ := f.Folders()
		if len(folders) != 1 || folders[0].Name != "Posteingang" || folders[0].Messages != 1 {
			t.Fatalf("crypt %d: folders %+v", crypt, folders)
		}
		refs := f.Messages()
		if len(refs) != 1 || refs[0].NID != testMessage || refs[0].Folder != testFolder {
			t.Fatalf("crypt %d: messages %+v", crypt, refs)
		}
		m, err := f.ReadMessage(testMessage, DefaultLimits)
		if err != nil {
			t.Fatalf("crypt %d: read: %v", crypt, err)
		}
		if m.Subject != "AW: Proforma PI-2291" {
			t.Errorf("subject %q (the SOH prefix marker must go)", m.Subject)
		}
		if m.SenderAddr != "sales@supplier.example" || m.MessageID != "<abc@supplier.example>" {
			t.Errorf("sender %q id %q", m.SenderAddr, m.MessageID)
		}
		if m.LastVerb != VerbReplyAll || m.LastVerbAt.Sub(m.Delivered) != 42*time.Minute || m.Flags&FlagRead == 0 {
			t.Errorf("verb %d at %v, delivered %v, flags %#x", m.LastVerb, m.LastVerbAt, m.Delivered, m.Flags)
		}
		if len(m.Recipients) != 2 || m.Recipients[1].Kind != 2 || m.Recipients[1].Addr != "expert@example.com" {
			t.Errorf("recipients %+v", m.Recipients)
		}
		if len(m.Attachments) != 1 || m.Attachments[0].Name != "PI-2291.pdf" || m.Attachments[0].Method != 1 {
			t.Fatalf("attachments %+v", m.Attachments)
		}
		var got []byte
		if err := m.Attachments[0].Read(func(b []byte) error { got = append(got, b...); return nil }); err != nil || string(got) != "%PDF-1.4 proforma..." {
			t.Errorf("attachment bytes %q (%v)", got, err)
		}
		if len(m.Problems) != 0 {
			t.Errorf("problems %v", m.Problems)
		}
	}
}

func TestADamagedBlockFailsItsMessageNotTheFile(t *testing.T) {
	raw := buildPST(t, cryptPermute)
	f, err := Open(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		t.Fatal(err)
	}
	e, _ := f.node(testMessage)
	b, _ := f.findBlock(e.data)
	raw[b.ib+20] ^= 0xFF // one byte of the message's heap
	if _, err := f.ReadMessage(testMessage, DefaultLimits); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("a flipped byte was read without complaint: %v", err)
	}
	if folders, _ := f.Folders(); len(folders) != 1 || folders[0].Name != "Posteingang" {
		t.Fatal("the rest of the file went with it")
	}
}

func TestNotAPSTIsSaidSo(t *testing.T) {
	raw := make([]byte, 4096)
	copy(raw, "PK\x03\x04")
	if _, err := Open(bytes.NewReader(raw), int64(len(raw))); !errors.Is(err, ErrNotPST) {
		t.Fatalf("got %v", err)
	}
	pst := buildPST(t, cryptNone)
	binary.LittleEndian.PutUint16(pst[10:], 14)
	if _, err := Open(bytes.NewReader(pst), int64(len(pst))); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("an ANSI file: %v", err)
	}
}

func TestTheIndexCacheIsUsedOnlyForItsOwnFile(t *testing.T) {
	raw := buildPST(t, cryptNone)
	cache := t.TempDir() + "/index.bin"
	f1, err := OpenCached(bytes.NewReader(raw), int64(len(raw)), cache)
	if err != nil {
		t.Fatal(err)
	}
	f2, err := OpenCached(bytes.NewReader(raw), int64(len(raw)), cache)
	if err != nil || f2.Nodes() != f1.Nodes() || f2.Blocks() != f1.Blocks() {
		t.Fatalf("cached open: %v", err)
	}
	other := buildPST(t, cryptPermute) // a different header
	if _, err := OpenCached(bytes.NewReader(other), int64(len(other)), cache); err != nil {
		t.Fatalf("a stale cache must be rebuilt, not trusted: %v", err)
	}
	if err := f2.loadIndex(cache, cacheKey(raw[:headerSize], int64(len(raw)))); err == nil {
		t.Fatal("the cache still answers for the first file after the second rewrote it")
	}
}
