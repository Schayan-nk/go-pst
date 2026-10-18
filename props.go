package pst

import (
	"strings"
	"time"
	"unicode/utf16"

	"golang.org/x/text/encoding"
	"golang.org/x/text/encoding/charmap"
)

// Property types (MS-OXCDATA §2.11.1).
const (
	ptShort    = 0x0002
	ptLong     = 0x0003
	ptFloat    = 0x0004
	ptDouble   = 0x0005
	ptCurrency = 0x0006
	ptAppTime  = 0x0007
	ptError    = 0x000A
	ptBoolean  = 0x000B
	ptObject   = 0x000D
	ptI8       = 0x0014
	ptString8  = 0x001E
	ptUnicode  = 0x001F
	ptSysTime  = 0x0040
	ptBinary   = 0x0102

	ptMVUnicode = 0x101F
	ptMVString8 = 0x101E
)

// fixedSize is a fixed-size type's width, or 0 for a variable one.
func fixedSize(t uint16) int {
	switch t {
	case ptBoolean:
		return 1
	case ptShort:
		return 2
	case ptLong, ptFloat, ptError:
		return 4
	case ptDouble, ptCurrency, ptAppTime, ptI8, ptSysTime:
		return 8
	}
	return 0
}

// Property ids used here (MS-OXPROPS).
const (
	propImportance         = 0x0017
	propMessageClass       = 0x001A
	propSensitivity        = 0x0036
	propSubject            = 0x0037
	propClientSubmitTime   = 0x0039
	propSentRepName        = 0x0042
	propSentRepAddr        = 0x0065
	propConversationTopic  = 0x0070
	propConversationIndex  = 0x0071
	propTransportHeaders   = 0x007D
	propRecipientType      = 0x0C15
	propSenderName         = 0x0C1A
	propSenderAddrType     = 0x0C1E
	propSenderAddr         = 0x0C1F
	propDisplayBcc         = 0x0E02
	propDisplayCc          = 0x0E03
	propDisplayTo          = 0x0E04
	propDeliveryTime       = 0x0E06
	propMessageFlags       = 0x0E07
	propMessageSize        = 0x0E08
	propAttachSize         = 0x0E20
	propBody               = 0x1000
	propHTML               = 0x1013
	propInternetRefs       = 0x1039
	propInternetMessageID  = 0x1035
	propInReplyTo          = 0x1042
	propIconIndex          = 0x1080
	propLastVerb           = 0x1081
	propLastVerbTime       = 0x1082
	propFlagStatus         = 0x1090
	propDisplayName        = 0x3001
	propAddrType           = 0x3002
	propEmailAddress       = 0x3003
	propCreationTime       = 0x3007
	propLastModified       = 0x3008
	propContentCount       = 0x3602
	propContainerClass     = 0x3613
	propAttachData         = 0x3701
	propAttachFilename     = 0x3704
	propAttachMethod       = 0x3705
	propAttachLongFilename = 0x3707
	propAttachMime         = 0x370E
	propAttachContentID    = 0x3712
	propSMTPAddress        = 0x39FE
	propInternetCodepage   = 0x3FDE
	propMessageCodepage    = 0x3FFD
	propSenderSMTP         = 0x5D01
	propSentRepSMTP        = 0x5D02
	propLtpRowID           = 0x67F2
	propAttachHidden       = 0x7FFE
)

// decodeString decodes a string property of either width. PT_STRING8 is read
// in the message's code page when there is one.
func decodeString(typ uint16, b []byte, codepage int) string {
	var s string
	switch typ {
	case ptUnicode:
		s = utf16le(b)
	case ptString8:
		s = decode8(b, codepage)
	default:
		return ""
	}
	return strings.TrimRight(s, "\x00")
}

func utf16le(b []byte) string {
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = le.Uint16(b[i*2:])
	}
	return string(utf16.Decode(u))
}

func decode8(b []byte, codepage int) string {
	var enc encoding.Encoding
	switch codepage {
	case 65001, 20127, 0:
		return strings.ToValidUTF8(string(b), "�")
	case 1256:
		enc = charmap.Windows1256
	case 1250:
		enc = charmap.Windows1250
	case 1251:
		enc = charmap.Windows1251
	case 1252, 28591:
		enc = charmap.Windows1252
	case 28596:
		enc = charmap.ISO8859_6
	default:
		enc = charmap.Windows1252
	}
	out, err := enc.NewDecoder().Bytes(b)
	if err != nil {
		return strings.ToValidUTF8(string(b), "�")
	}
	return string(out)
}

// multiStrings decodes PT_MV_UNICODE / PT_MV_STRING8.
func multiStrings(typ uint16, b []byte, codepage int) []string {
	if len(b) < 4 {
		return nil
	}
	n := int(le.Uint32(b))
	if n <= 0 || n > 512 || 4+n*4 > len(b) {
		return nil
	}
	off := make([]int, n+1)
	for i := 0; i < n; i++ {
		off[i] = int(le.Uint32(b[4+i*4:]))
	}
	off[n] = len(b)
	var out []string
	for i := 0; i < n; i++ {
		if off[i] < 4+n*4 || off[i] > off[i+1] || off[i+1] > len(b) {
			return out
		}
		one := ptUnicode
		if typ == ptMVString8 {
			one = ptString8
		}
		if s := strings.TrimSpace(decodeString(uint16(one), b[off[i]:off[i+1]], codepage)); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// filetime turns a FILETIME (100 ns since 1601) into a time, zero for the
// values Outlook uses to mean "none".
func filetime(v uint64) time.Time {
	const epochDiff = 116444736000000000
	if v <= epochDiff || v >= 0x7FFFFFFFFFFFFFFF {
		return time.Time{}
	}
	t := time.Unix(0, 0).Add(time.Duration(v-epochDiff) * 100).UTC()
	if t.Year() > 2200 {
		return time.Time{}
	}
	return t
}

// getter reads typed values from anything shaped like props.raw.
type getter struct {
	raw      func(id uint16, max int) (uint16, []byte, bool, error)
	codepage int
	errs     *[]error
}

func (g getter) note(err error) {
	if err != nil && g.errs != nil && len(*g.errs) < 8 {
		*g.errs = append(*g.errs, err)
	}
}

func (g getter) str(id uint16, max int) string {
	typ, b, ok, err := g.raw(id, max)
	g.note(err)
	if !ok {
		return ""
	}
	return decodeString(typ, b, g.codepage)
}

func (g getter) int(id uint16) (int64, bool) {
	typ, b, ok, err := g.raw(id, 8)
	g.note(err)
	if !ok {
		return 0, false
	}
	switch {
	case typ == ptBoolean && len(b) >= 1:
		return int64(b[0]), true
	case typ == ptShort && len(b) >= 2:
		return int64(int16(le.Uint16(b))), true
	case (typ == ptLong || typ == ptError) && len(b) >= 4:
		return int64(int32(le.Uint32(b))), true
	case typ == ptI8 && len(b) >= 8:
		return int64(le.Uint64(b)), true
	}
	return 0, false
}

func (g getter) time(id uint16) time.Time {
	typ, b, ok, err := g.raw(id, 8)
	g.note(err)
	if !ok || typ != ptSysTime || len(b) < 8 {
		return time.Time{}
	}
	return filetime(le.Uint64(b))
}

func (g getter) bytes(id uint16, max int) []byte {
	_, b, ok, err := g.raw(id, max)
	g.note(err)
	if !ok {
		return nil
	}
	return append([]byte(nil), b...)
}
