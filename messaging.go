package pst

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// The messaging layer: folders, messages, recipients and attachments.
//
// Messages are found through the node index (every message node names its
// folder as its parent) rather than through each folder's contents table.
// The index is what the file itself resolves ids through, so a message it
// holds is a message that exists; a contents table is a cache Outlook keeps
// for display, and a stale one would silently hide mail from the analysis.

// Folder is one folder of the file.
type Folder struct {
	NID    uint32
	Parent uint32
	Name   string
	Class  string
	// Messages is how many message nodes name this folder as their parent.
	Messages int
}

// Folders lists every normal folder, with its message count.
func (f *File) Folders() ([]Folder, error) {
	counts := map[uint32]int{}
	for _, e := range f.nodes {
		if e.nid&0x1F == nidTypeNormalMessage {
			counts[e.parent]++
		}
	}
	var out []Folder
	for _, e := range f.nodes {
		if e.nid&0x1F != nidTypeNormalFolder {
			continue
		}
		fo := Folder{NID: e.nid, Parent: e.parent, Messages: counts[e.nid]}
		if n, err := f.topNode(e.nid); err == nil {
			if p, err := n.props(); err == nil {
				g := getter{raw: p.raw}
				fo.Name = g.str(propDisplayName, 1024)
				fo.Class = g.str(propContainerClass, 256)
			}
		}
		out = append(out, fo)
	}
	return out, nil
}

// FolderPaths names every folder by its path from the top of the file,
// joined with "/"; the root and the "Top of Personal Folders" level are left
// out.
func FolderPaths(folders []Folder) map[uint32]string {
	by := map[uint32]Folder{}
	for _, fo := range folders {
		by[fo.NID] = fo
	}
	out := map[uint32]string{}
	for _, fo := range folders {
		var parts []string
		nid := fo.NID
		for range 32 {
			cur, ok := by[nid]
			if !ok || cur.NID == nidRootFolder || cur.Parent == nidRootFolder && isTopOfFile(cur.Name) {
				break
			}
			parts = append(parts, cur.Name)
			if cur.Parent == cur.NID {
				break
			}
			nid = cur.Parent
		}
		for i, j := 0, len(parts)-1; i < j; i, j = i+1, j-1 {
			parts[i], parts[j] = parts[j], parts[i]
		}
		out[fo.NID] = strings.Join(parts, "/")
	}
	return out
}

// isTopOfFile recognises the IPM subtree's own folder, whose name Outlook
// writes in the language it was installed in -- "Top of Outlook data file",
// "Oberste Ebene der Outlook-Datendatei", "Personal Folders", "Persönliche
// Ordner".
func isTopOfFile(name string) bool {
	n := strings.ToLower(name)
	return n == "" || strings.HasPrefix(n, "top of ") || strings.HasPrefix(n, "oberste ebene") ||
		strings.Contains(n, "personal folders") || strings.Contains(n, "persönliche ordner")
}

// MessageRef is one message node and its folder.
type MessageRef struct {
	NID    uint32
	Folder uint32
}

// Messages lists every message node, in node order -- the order ingestion
// checkpoints in.
func (f *File) Messages() []MessageRef {
	var out []MessageRef
	for _, e := range f.nodes {
		if e.nid&0x1F == nidTypeNormalMessage {
			out = append(out, MessageRef{NID: e.nid, Folder: e.parent})
		}
	}
	return out
}

// Recipient is one row of a message's recipient table.
type Recipient struct {
	Kind int // 1 To, 2 Cc, 3 Bcc
	Name string
	Addr string
}

// Attachment is one attachment's description; its bytes are read on demand
// with Read so a 40 MB drawing is streamed, not held.
type Attachment struct {
	Name      string
	Mime      string
	ContentID string
	Method    int // 1 by value, 5 embedded message, 6 OLE, ...
	Size      int
	Hidden    bool
	// Embedded is the attached message, for Method 5, read to one level.
	Embedded *Message

	n    *node
	h    *heap
	data pcEntry
	has  bool
}

// Read streams the attachment's bytes to fn, block by block.
func (a *Attachment) Read(fn func([]byte) error) error {
	if a == nil || !a.has || a.data.typ != ptBinary || a.data.v == 0 {
		return nil
	}
	if a.data.v&0x1F == 0 {
		b, err := a.h.get(a.data.v)
		if err != nil {
			return err
		}
		return fn(b)
	}
	c, err := a.n.child(a.data.v)
	if err != nil {
		return err
	}
	err = a.n.f.dataBlocks(c.data, fn)
	if errors.Is(err, errStop) {
		return nil
	}
	return err
}

// Message is what the analysis needs from one message.
type Message struct {
	NID    uint32
	Folder uint32

	Class             string
	Subject           string
	ConversationTopic string
	ConversationIndex []byte
	MessageID         string
	InReplyTo         string
	References        string
	Headers           string

	SenderName  string
	SenderAddr  string
	SentRepName string
	SentRepAddr string
	DisplayTo   string
	DisplayCc   string
	Recipients  []Recipient

	Submitted, Delivered, Created, Modified time.Time

	Flags       int
	Importance  int
	Sensitivity int
	IconIndex   int
	LastVerb    int
	LastVerbAt  time.Time
	FlagStatus  int
	Size        int
	Categories  []string

	Body          string
	BodyTruncated bool
	HTML          []byte

	Attachments []*Attachment

	// Problems are parts that could not be read -- a recipient table, an
	// attachment -- without the message as a whole failing.
	Problems []error
}

// Message flags (PidTagMessageFlags).
const (
	FlagRead   = 0x01
	FlagUnsent = 0x08
	FlagAttach = 0x10
	FlagFromMe = 0x20
)

// Last verbs (PidTagLastVerbExecuted).
const (
	VerbReply    = 102
	VerbReplyAll = 103
	VerbForward  = 104
)

// Limits are the caps ReadMessage reads under.
type Limits struct {
	Body    int // characters of PidTagBody, in bytes of UTF-16
	HTML    int // bytes of PidTagHtml, read only when there is no plain body
	Headers int
}

// DefaultLimits keep one message well under a megabyte in memory.
var DefaultLimits = Limits{Body: 512 << 10, HTML: 512 << 10, Headers: 64 << 10}

// ReadMessage reads one message: its properties, recipients and attachment
// descriptions. A failure here is this message's, reported, never a panic.
func (f *File) ReadMessage(nid uint32, lim Limits) (m *Message, err error) {
	defer func() {
		if r := recover(); r != nil {
			m, err = nil, corrupt("message %#x: %v", nid, r)
		}
	}()
	n, err := f.topNode(nid)
	if err != nil {
		return nil, err
	}
	e, _ := f.node(nid)
	return f.readMessage(n, e.parent, lim, 0)
}

func (f *File) readMessage(n *node, folder uint32, lim Limits, depth int) (*Message, error) {
	p, err := n.props()
	if err != nil {
		return nil, fmt.Errorf("message %#x: %w", n.nid, err)
	}
	m := &Message{NID: n.nid, Folder: folder}
	g := getter{raw: p.raw, errs: &m.Problems}
	if cp, ok := g.int(propInternetCodepage); ok {
		g.codepage = int(cp)
	} else if cp, ok := g.int(propMessageCodepage); ok {
		g.codepage = int(cp)
	}

	m.Class = g.str(propMessageClass, 512)
	m.Subject = stripSubjectPrefix(g.str(propSubject, 8192))
	m.ConversationTopic = g.str(propConversationTopic, 8192)
	m.ConversationIndex = g.bytes(propConversationIndex, 1024)
	m.MessageID = g.str(propInternetMessageID, 2048)
	m.InReplyTo = g.str(propInReplyTo, 2048)
	m.References = g.str(propInternetRefs, 32<<10)
	m.Headers = g.str(propTransportHeaders, lim.Headers)

	m.SenderName = g.str(propSenderName, 1024)
	m.SenderAddr = pickAddr(g.str(propSenderSMTP, 1024), g.str(propSenderAddr, 1024))
	m.SentRepName = g.str(propSentRepName, 1024)
	m.SentRepAddr = pickAddr(g.str(propSentRepSMTP, 1024), g.str(propSentRepAddr, 1024))
	m.DisplayTo = g.str(propDisplayTo, 16<<10)
	m.DisplayCc = g.str(propDisplayCc, 16<<10)

	m.Submitted = g.time(propClientSubmitTime)
	m.Delivered = g.time(propDeliveryTime)
	m.Created = g.time(propCreationTime)
	m.Modified = g.time(propLastModified)
	m.LastVerbAt = g.time(propLastVerbTime)

	iv := func(id uint16) int { v, _ := g.int(id); return int(v) }
	m.Flags = iv(propMessageFlags)
	m.Importance = iv(propImportance)
	m.Sensitivity = iv(propSensitivity)
	m.IconIndex = iv(propIconIndex)
	m.LastVerb = iv(propLastVerb)
	m.FlagStatus = iv(propFlagStatus)
	m.Size = iv(propMessageSize)

	if f.keywordsProp != 0 {
		if typ, b, ok, err := p.raw(f.keywordsProp, 16<<10); err == nil && ok {
			m.Categories = multiStrings(typ, b, g.codepage)
		}
	}

	if typ, b, ok, err := p.raw(propBody, lim.Body+2); ok && err == nil {
		m.Body = decodeString(typ, b, g.codepage)
		m.BodyTruncated = len(b) > lim.Body
	} else {
		g.note(err)
	}
	if strings.TrimSpace(m.Body) == "" {
		m.HTML = g.bytes(propHTML, lim.HTML)
	}

	if rn, err := n.child(nidRecipients); err == nil {
		if t, err := rn.table(); err == nil {
			m.Recipients = recipients(t, g.codepage, &m.Problems)
		} else {
			m.Problems = append(m.Problems, err)
		}
	}
	if an, err := n.child(nidAttachments); err == nil {
		if t, err := an.table(); err == nil {
			m.Attachments = f.attachments(n, t, g.codepage, lim, depth, &m.Problems)
		} else {
			m.Problems = append(m.Problems, err)
		}
	}
	return m, nil
}

func recipients(t *table, codepage int, problems *[]error) []Recipient {
	var out []Recipient
	for _, row := range t.rows {
		row := row
		g := getter{raw: func(id uint16, max int) (uint16, []byte, bool, error) { return t.cell(row, id, max) },
			codepage: codepage, errs: problems}
		kind, _ := g.int(propRecipientType)
		r := Recipient{Kind: int(kind) & 0x0F, Name: g.str(propDisplayName, 1024),
			Addr: pickAddr(g.str(propSMTPAddress, 1024), g.str(propEmailAddress, 1024))}
		if r.Addr == "" && strings.Contains(r.Name, "@") {
			r.Addr = strings.Trim(r.Name, "'\" <>")
		}
		out = append(out, r)
	}
	return out
}

func (f *File) attachments(msg *node, t *table, codepage int, lim Limits, depth int, problems *[]error) []*Attachment {
	var out []*Attachment
	for _, row := range t.rows {
		row := row
		tg := getter{raw: func(id uint16, max int) (uint16, []byte, bool, error) { return t.cell(row, id, max) },
			codepage: codepage, errs: problems}
		id, ok := tg.int(propLtpRowID)
		if !ok {
			continue
		}
		an, err := msg.child(uint32(id))
		if err != nil {
			*problems = append(*problems, err)
			continue
		}
		p, err := an.props()
		if err != nil {
			*problems = append(*problems, err)
			continue
		}
		g := getter{raw: p.raw, codepage: codepage, errs: problems}
		a := &Attachment{n: an, h: p.h}
		a.Name = g.str(propAttachLongFilename, 1024)
		if a.Name == "" {
			a.Name = g.str(propAttachFilename, 1024)
		}
		if a.Name == "" {
			a.Name = g.str(propDisplayName, 1024)
		}
		a.Mime = g.str(propAttachMime, 256)
		a.ContentID = g.str(propAttachContentID, 512)
		v, _ := g.int(propAttachMethod)
		a.Method = int(v)
		v, _ = g.int(propAttachSize)
		a.Size = int(v)
		v, _ = g.int(propAttachHidden)
		a.Hidden = v != 0
		a.data, a.has = p.m[propAttachData]
		if a.Method == 5 && a.has && a.data.typ == ptObject && depth < 1 {
			if ref, err := a.h.get(a.data.v); err == nil && len(ref) >= 4 {
				if en, err := an.child(le.Uint32(ref)); err == nil {
					if em, err := f.readMessage(en, 0, lim, depth+1); err == nil {
						a.Embedded = em
					} else {
						*problems = append(*problems, err)
					}
				}
			}
		}
		out = append(out, a)
	}
	return out
}

// pickAddr prefers the SMTP form; an Exchange DN is kept only when there is
// nothing else, so it can still be told apart.
func pickAddr(smtp, other string) string {
	smtp, other = strings.TrimSpace(smtp), strings.TrimSpace(other)
	if strings.Contains(smtp, "@") {
		return strings.ToLower(smtp)
	}
	if strings.Contains(other, "@") {
		return strings.ToLower(strings.Trim(other, "'\" <>"))
	}
	return other
}

// stripSubjectPrefix removes the two-character marker a PST puts before a
// subject: SOH and a character carrying the prefix length.
func stripSubjectPrefix(s string) string {
	r := []rune(s)
	if len(r) >= 2 && r[0] == 0x01 {
		return string(r[2:])
	}
	return s
}

// findKeywords resolves the named property "Keywords" (Outlook's categories)
// through the name-to-id map, or returns 0.
func (f *File) findKeywords() uint16 {
	n, err := f.topNode(nidNameToIDMap)
	if err != nil {
		return 0
	}
	p, err := n.props()
	if err != nil {
		return 0
	}
	g := getter{raw: p.raw}
	entries := g.bytes(0x0003, 8<<20)
	names := g.bytes(0x0004, 8<<20)
	for i := 0; i+8 <= len(entries); i += 8 {
		e := entries[i:]
		kind := le.Uint16(e[4:])
		if kind&1 == 0 || kind>>1 != 2 { // a string name in PS_PUBLIC_STRINGS
			continue
		}
		off := int(le.Uint32(e))
		if off+4 > len(names) {
			continue
		}
		size := int(le.Uint32(names[off:]))
		if size <= 0 || off+4+size > len(names) {
			continue
		}
		if utf16le(names[off+4:off+4+size]) == "Keywords" {
			return 0x8000 + le.Uint16(e[6:])
		}
	}
	return 0
}

// StoreName is the display name of the file's message store.
func (f *File) StoreName() string {
	n, err := f.topNode(nidMessageStore)
	if err != nil {
		return ""
	}
	p, err := n.props()
	if err != nil {
		return ""
	}
	return getter{raw: p.raw}.str(propDisplayName, 1024)
}
