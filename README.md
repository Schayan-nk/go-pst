# go-pst

Read Outlook data files (`.pst`) in pure Go: read-only, streaming, and
without Outlook or Office.

It was written to read a mailbox archive far larger than memory (well over
100 GB) on a server with nothing from Microsoft Office installed, so the mail
can be analysed where it lives instead of being exported anywhere.

- **The whole MS-PST stack.** The node database (header, node and block
  B-trees, blocks, subnodes), the lists-tables-properties layer (heaps,
  B-trees on heaps, property and table contexts) and the messaging layer on
  top: folders, messages, recipients and attachments.
- **Hostile input by default.** Every offset read from the file is
  bounds-checked before use, every block's CRC and id are verified, tree walks
  are depth- and cycle-bounded, and values are read under a size cap you set.
  A malformed message fails that message (`ErrCorrupt`), never the file, and
  never with a panic.
- **Fast reopening.** `OpenCached` keeps the built indexes in a side file, so
  opening a large archive a second time does not walk its B-trees again.
- **No dependencies** beyond `golang.org/x/text` for legacy code pages.

Unicode files only (Outlook 2003 and later). ANSI files (capped at 2 GB) and
4K-page files (OSTs) are refused by name rather than misread.

## Install

```sh
go get github.com/Schayan-nk/go-pst
```

## Example

```go
package main

import (
	"fmt"
	"log"
	"os"
	"time"

	pst "github.com/Schayan-nk/go-pst"
)

func main() {
	f, err := os.Open("archive.pst")
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		log.Fatal(err)
	}

	file, err := pst.Open(f, st.Size())
	if err != nil {
		log.Fatal(err)
	}
	folders, err := file.Folders()
	if err != nil {
		log.Fatal(err)
	}
	paths := pst.FolderPaths(folders)

	for _, ref := range file.Messages() {
		m, err := file.ReadMessage(ref.NID, pst.DefaultLimits)
		if err != nil {
			continue // one damaged message, not the whole file
		}
		fmt.Println(m.Delivered.Format(time.RFC3339), paths[ref.Folder], m.SenderAddr, m.Subject)
	}
}
```

`File` is safe for concurrent reads once `Open` returns, so messages can be
read from several goroutines.

## Tests

```sh
go test ./...
```

The tests build small PST files in memory, byte by byte, including damaged
blocks and encrypted pages; no real mailbox is involved.

## License

MIT, see [LICENSE](LICENSE).
