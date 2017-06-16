package gocore

import (
	"sort"

	"github.com/randall77/corelib/core"
)

// readObjects finds all the live objects in the heap and adds them to
// the p.objects list. It does not fill in the Type fields for those objects.
func (p *Program) readObjects() {
	ptrSize := p.proc.PtrSize()

	// mark contains the Addr for all objects currently in p.objects.
	mark := map[core.Address]struct{}{}

	// Number of objects in p.objects that have been scanned.
	n := 0

	// Function to call when we find a new pointer.
	add := func(x core.Address) {
		if x == 0 { // nil pointer
			return
		}
		s := p.findSpan(x)
		if s.size == 0 { // not in heap
			return
		}
		x = s.min.Add(x.Sub(s.min) / s.size * s.size)
		if _, ok := mark[x]; ok { // already found
			return
		}
		mark[x] = struct{}{}
		p.objects = append(p.objects, Object{Addr: x, Size: s.size})
	}

	// Goroutine roots
	for _, g := range p.goroutines {
		for _, f := range g.frames {
			for _, a := range f.ptrs {
				add(p.proc.ReadAddress(a))
			}
		}
	}

	// Global roots
	for _, m := range p.modules {
		for _, s := range [2]string{"data", "bss"} {
			min := core.Address(m.r.Field(s).Uintptr())
			max := core.Address(m.r.Field("e" + s).Uintptr())
			gc := core.Address(m.r.Field("gc" + s).Uintptr())
			n := max.Sub(min) / ptrSize
			for i := int64(0); i < n; i++ {
				if p.proc.ReadUint8(gc.Add(i/8))>>uint(i%8)&1 != 0 {
					add(p.proc.ReadAddress(min.Add(i * ptrSize)))
				}
			}
		}
	}

	// TODO: finalizers
	// TODO: specials

	// Expand root set to all reachable objects.
	for n < len(p.objects) {
		obj := p.objects[n]
		n++

		// scan [obj.Addr,obj.Addr+obj.Size]
		for a := obj.Addr; a < obj.Addr.Add(obj.Size); a = a.Add(ptrSize) {
			if p.isPtr(a) {
				add(p.proc.ReadAddress(a))
			}
		}
	}

	// Sort objects for later binary search by address.
	sort.Slice(p.objects, func(i, j int) bool {
		return p.objects[i].Addr < p.objects[j].Addr
	})
}

func (p *Program) findSpan(a core.Address) span {
	i := sort.Search(len(p.spans), func(i int) bool {
		return p.spans[i].max > a
	})
	if i == len(p.spans) {
		return span{}
	}
	s := p.spans[i]
	if a >= s.min {
		return s
	}
	return span{}
}

func (p *Program) isPtr(a core.Address) bool {
	// Convert arena offset in words to bitmap offset in bits.
	off := a.Sub(p.arenaStart)
	off /= p.proc.PtrSize()

	// Find bit in bitmap. It goes backwards from the end.
	// Each byte contains pointer/nonpointer bits for 4 words in its low nybble.
	return p.proc.ReadUint8(p.bitmapEnd.Add(-off/4-1))>>uint(off%4)&1 != 0
}

func (p *Program) findObject(a core.Address) *Object {
	i := sort.Search(len(p.objects), func(i int) bool {
		return a < p.objects[i].Addr.Add(p.objects[i].Size)
	})
	if i == len(p.objects) {
		return nil
	}
	obj := &p.objects[i]
	if a < p.objects[i].Addr {
		return nil
	}
	return obj
}
