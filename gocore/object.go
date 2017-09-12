package gocore

import (
	"sort"

	"github.com/randall77/corelib/core"
)

// readObjects finds all the live objects in the heap and adds them to
// the p.objects list. It does not fill in the Type fields for those objects.
func (p *Program) readObjects() {
	ptrSize := p.proc.PtrSize()

	// Number of objects in p.objects that have been scanned.
	n := 0

	// Function to call when we find a new pointer.
	add := func(x core.Address) {
		if x == 0 || x < p.arenaStart || x >= p.arenaUsed { // not in heap
			return
		}
		i := x.Sub(p.arenaStart) / 512
		s := &p.heapInfo[i]
		if s.base == 0 { // not in a valid span
			// TODO: probably a runtime/compiler error?
			return
		}
		// Round down to object start.
		x = s.base.Add(x.Sub(s.base) / s.size * s.size)
		// Find mark bit
		off := uint64(x.Sub(p.arenaStart))
		j := off / 512
		s = &p.heapInfo[j]
		b := off % 512 / 8
		if s.mark&(uint64(1)<<b) != 0 { // already found
			return
		}
		s.mark |= uint64(1) << b
		p.objects = append(p.objects, Object{Addr: x, Size: s.size})
	}

	// Goroutine roots
	for _, g := range p.goroutines {
		for _, f := range g.frames {
			for a := range f.live { // TODO: iteration order matter?
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

	// Sort objects for later search in increasing address order.
	sort.Slice(p.objects, func(i, j int) bool {
		return p.objects[i].Addr < p.objects[j].Addr
	})

	// Initialize firstIdx fields in the heapInfo, for fast
	// address->object lookups.
	for i := len(p.objects) - 1; i >= 0; i-- {
		x := p.objects[i]
		// last byte
		p.heapInfo[x.Addr.Add(x.Size-1).Sub(p.arenaStart)/512].firstIdx = i
		// first byte, plus every 512th byte
		for j := int64(0); j < x.Size; j += 512 {
			p.heapInfo[x.Addr.Add(j).Sub(p.arenaStart)/512].firstIdx = i
		}
	}

	// Build array-of-pointers for easy iteration over objects.
	p.objPtrs = make([]*Object, len(p.objects))
	for i := range p.objects {
		p.objPtrs[i] = &p.objects[i]
	}
}

// isPtr reports whether the inferior at address a contains a pointer.
// a must be somewhere in the heap.
func (p *Program) isPtr(a core.Address) bool {
	// Convert arena offset in words to bitmap offset in bits.
	off := a.Sub(p.arenaStart)
	off /= p.proc.PtrSize()

	// Find bit in bitmap. It goes backwards from the end.
	// Each byte contains pointer/nonpointer bits for 4 words in its low nybble.
	return p.proc.ReadUint8(p.bitmapEnd.Add(-off/4-1))>>uint(off%4)&1 != 0
}

// FindObject finds the object containing a.  Returns that object and the offset within
// that object to which a points.
// Returns nil,0 if a doesn't point to a live heap object.
func (p *Program) FindObject(a core.Address) (*Object, int64) {
	i, off := p.findObjectIndex(a)
	if i < 0 {
		return nil, 0
	}
	return &p.objects[i], off
}

func (p *Program) findObjectIndex(a core.Address) (int, int64) {
	if a < p.arenaStart || a >= p.arenaUsed {
		return -1, 0
	}
	i := p.heapInfo[a.Sub(p.arenaStart)/512].firstIdx
	if i < 0 {
		return -1, 0
	}
	// Linear search within 512-byte heap region.
	// Skip over objects completely less than a.
	for i < len(p.objects) && p.objects[i].Addr.Add(p.objects[i].Size) <= a {
		i++
	}
	if i == len(p.objects) || a < p.objects[i].Addr {
		return -1, 0
	}
	return i, a.Sub(p.objects[i].Addr)
}

// ForEachPtr calls fn for all heap pointers it finds in x.
// It calls fn with:
//   the offset of the pointer slot in x
//   the pointed-to object y
//   the offset in y where the pointer points.
// If fn returns false, ForEachPtr returns immediately.
func (p *Program) ForEachPtr(x *Object, fn func(int64, *Object, int64) bool) {
	for i := int64(0); i < x.Size; i += p.proc.PtrSize() {
		a := x.Addr.Add(i)
		if !p.isPtr(a) {
			continue
		}
		ptr := p.proc.ReadAddress(a)
		y, off := p.FindObject(ptr)
		if y != nil {
			if !fn(i, y, off) {
				return
			}
		}
	}
}

// ForEachRootPtr behaves like ForEachPtr but it starts with a Root instead of an Object.
func (p *Program) ForEachRootPtr(r *Root, fn func(int64, *Object, int64) bool) {
	edges1(p, r, 0, r.Type, fn)
}

// edges1 calls fn for the edges found in an object of type t living at offset off in the root r.
// If fn returns false, return immediately with false.
func edges1(p *Program, r *Root, off int64, t *Type, fn func(int64, *Object, int64) bool) bool {
	switch t.Kind {
	case KindBool, KindInt, KindUint, KindFloat, KindComplex:
		// no edges here
	case KindIface, KindEface:
		// The first word is a type or itab.
		// Itabs are never in the heap.
		// Types might be, though.
		a := r.Addr.Add(off)
		if r.Live == nil || r.Live[a] {
			dst, off2 := p.FindObject(p.proc.ReadAddress(a))
			if dst != nil {
				if !fn(off, dst, off2) {
					return false
				}
			}
		}
		// Treat second word like a pointer.
		off += p.proc.PtrSize()
		fallthrough
	case KindPtr, KindString, KindSlice, KindFunc:
		a := r.Addr.Add(off)
		if r.Live == nil || r.Live[a] {
			dst, off2 := p.FindObject(p.proc.ReadAddress(a))
			if dst != nil {
				if !fn(off, dst, off2) {
					return false
				}
			}
		}
	case KindArray:
		s := t.Elem.Size
		for i := int64(0); i < t.Count; i++ {
			if !edges1(p, r, off+i*s, t.Elem, fn) {
				return false
			}
		}
	case KindStruct:
		for _, f := range t.Fields {
			if !edges1(p, r, off+f.Off, f.Type, fn) {
				return false
			}
		}
	}
	return true
}
