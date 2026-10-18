package pst

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
)

// Keeping the node and block indexes between runs.
//
// Building them means reading every B-tree page, and on the CEO's archive --
// 129 GB on a spinning virtual disk -- that is one random 512-byte read at a
// time for many minutes. A resumed ingestion must not pay that again, so
// OpenCached writes the indexes beside the job's state once built and reads
// them back next time.
//
// The cache is trusted only for the file it was built from: its key is a
// SHA-256 of the file's header (which records the B-tree roots and the next
// block and page ids, so any write to the file changes it) and the file's
// size. Anything else -- a different key, a short read, a bad count -- and it
// is ignored and rebuilt. It holds block offsets, never message content.

const cacheMagic = "docfind-pst-index-1\n"

// OpenCached is Open with the indexes kept in cachePath.
func OpenCached(r io.ReaderAt, size int64, cachePath string) (*File, error) {
	f, h, err := openHeader(r, size)
	if err != nil {
		return nil, err
	}
	key := cacheKey(h, size)
	if cachePath != "" && f.loadIndex(cachePath, key) == nil {
		f.keywordsProp = f.findKeywords()
		return f, nil
	}
	if err := f.buildIndex(h); err != nil {
		return nil, err
	}
	if cachePath != "" {
		// A cache that cannot be written costs the next run time, not
		// correctness.
		_ = f.saveIndex(cachePath, key)
	}
	f.keywordsProp = f.findKeywords()
	return f, nil
}

func cacheKey(h []byte, size int64) []byte {
	s := sha256.New()
	s.Write(h)
	var b [8]byte
	le.PutUint64(b[:], uint64(size))
	s.Write(b[:])
	return s.Sum(nil)
}

func (f *File) saveIndex(path string, key []byte) error {
	tmp := path + ".tmp"
	fh, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	w := bufio.NewWriterSize(fh, 1<<20)
	var b [24]byte
	w.WriteString(cacheMagic)
	w.Write(key)
	le.PutUint64(b[:], uint64(len(f.nodes)))
	le.PutUint64(b[8:], uint64(len(f.blocks)))
	le.PutUint64(b[16:], uint64(f.BadPages))
	w.Write(b[:24])
	for _, n := range f.nodes {
		le.PutUint32(b[0:], n.nid)
		le.PutUint32(b[4:], n.parent)
		le.PutUint64(b[8:], n.data)
		le.PutUint64(b[16:], n.sub)
		w.Write(b[:24])
	}
	for _, e := range f.blocks {
		le.PutUint64(b[0:], e.bid)
		le.PutUint64(b[8:], e.ib)
		le.PutUint16(b[16:], e.cb)
		w.Write(b[:18])
	}
	if err := w.Flush(); err != nil {
		fh.Close()
		os.Remove(tmp)
		return err
	}
	if err := fh.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}

var errStaleCache = errors.New("pst: index cache is for another file")

func (f *File) loadIndex(path string, key []byte) error {
	fh, err := os.Open(path)
	if err != nil {
		return err
	}
	defer fh.Close()
	r := bufio.NewReaderSize(fh, 1<<20)
	head := make([]byte, len(cacheMagic)+len(key)+24)
	if _, err := io.ReadFull(r, head); err != nil {
		return err
	}
	if string(head[:len(cacheMagic)]) != cacheMagic || !bytes.Equal(head[len(cacheMagic):len(cacheMagic)+len(key)], key) {
		return errStaleCache
	}
	c := head[len(cacheMagic)+len(key):]
	nNodes, nBlocks := le.Uint64(c), le.Uint64(c[8:])
	if nNodes == 0 || nBlocks == 0 || nNodes > 1<<28 || nBlocks > 1<<31 {
		return fmt.Errorf("pst: index cache counts %d/%d", nNodes, nBlocks)
	}
	nodes := make([]nodeEntry, nNodes)
	blocks := make([]blockEntry, nBlocks)
	var b [24]byte
	for i := range nodes {
		if _, err := io.ReadFull(r, b[:24]); err != nil {
			return err
		}
		nodes[i] = nodeEntry{nid: le.Uint32(b[0:]), parent: le.Uint32(b[4:]), data: le.Uint64(b[8:]), sub: le.Uint64(b[16:])}
	}
	for i := range blocks {
		if _, err := io.ReadFull(r, b[:18]); err != nil {
			return err
		}
		blocks[i] = blockEntry{bid: le.Uint64(b[0:]), ib: le.Uint64(b[8:]), cb: le.Uint16(b[16:])}
	}
	f.nodes, f.blocks, f.BadPages = nodes, blocks, int(le.Uint64(c[16:]))
	return nil
}

// DataOffset is where a message node's own data starts in the file, for
// reading messages in file order on a spinning disk. 0 when unknown.
func (f *File) DataOffset(nid uint32) uint64 {
	e, ok := f.node(nid)
	if !ok {
		return 0
	}
	b, ok := f.findBlock(e.data)
	if !ok {
		return 0
	}
	return b.ib
}
