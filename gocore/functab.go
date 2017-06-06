package gocore

import (
	"sort"

	"github.com/randall77/corelib/core"
)

type funcTabEntry struct {
	min, max core.Address
	f        *Func
}

type funcTab struct {
	entries []funcTabEntry
	sorted  bool
}

func (t *funcTab) add(min, max core.Address, f *Func) {
	t.entries = append(t.entries, funcTabEntry{min: min, max: max, f: f})
	t.sorted = false
}

// Finds a Func for the given address.
func (t *funcTab) find(pc core.Address) *Func {
	if !t.sorted {
		sort.Slice(t.entries, func(i, j int) bool {
			return t.entries[i].min < t.entries[j].min
		})
		t.sorted = true
	}
	n := sort.Search(len(t.entries), func(i int) bool {
		return t.entries[i].max > pc
	})
	if n == len(t.entries) || pc < t.entries[n].min || pc >= t.entries[n].max {
		return nil
	}
	return t.entries[n].f
}
