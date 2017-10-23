package gocore

import (
	"github.com/randall77/corelib/core"
)

// a pcTab maps from an offset in a function to an int64.
type pcTab struct {
	entries []pcTabEntry
}

type pcTabEntry struct {
	bytes int64 // # of bytes this entry covers
	val   int64 // value over that range of bytes
}

// read parses a pctab from the core file at address data.
func (p *pcTab) read(core *core.Process, data core.Address) {
	var pcQuantum int64
	switch core.Arch() {
	case "x86", "amd64", "amd64p32":
		pcQuantum = 1
	case "s390x":
		pcQuantum = 2
	default:
		pcQuantum = 4
	}
	val := int64(-1)
	first := true
	for {
		// Advance value.
		v, n := readVarint(core, data)
		if v == 0 && !first {
			return
		}
		data = data.Add(n)
		if v&1 != 0 {
			val += ^(v >> 1)
		} else {
			val += v >> 1
		}

		// Advance pc.
		v, n = readVarint(core, data)
		data = data.Add(n)
		p.entries = append(p.entries, pcTabEntry{bytes: v * pcQuantum, val: val})
		first = false
	}
}

func (p *pcTab) setEmpty() {
	p.entries = []pcTabEntry{{bytes: 1<<63 - 1, val: -1}}
}

func (t *pcTab) find(off int64) int64 {
	for _, e := range t.entries {
		if off < e.bytes {
			return e.val
		}
		off -= e.bytes
	}
	panic("can't find pctab entry")
}

// readVarint reads a varint from the core file.
// val is the value, n is the number of bytes consumed.
func readVarint(core *core.Process, a core.Address) (val, n int64) {
	for {
		b := core.ReadUint8(a)
		val |= int64(b&0x7f) << uint(n*7)
		n++
		a++
		if b&0x80 == 0 {
			return
		}
	}
}
