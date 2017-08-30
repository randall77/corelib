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

	// Sort objects for later binary search by address.
	sort.Slice(p.objects, func(i, j int) bool {
		return p.objects[i].Addr < p.objects[j].Addr
	})

	// Build array-of-pointers for easy iteration over objects.
	p.objPtrs = make([]*Object, len(p.objects))
	for i := range p.objects {
		p.objPtrs[i] = &p.objects[i]
	}
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
// Returns nil if a doesn't point to a live heap object.
func (p *Program) FindObject(a core.Address) (*Object, int64) {
	i := sort.Search(len(p.objects), func(i int) bool {
		return a < p.objects[i].Addr.Add(p.objects[i].Size)
	})
	if i == len(p.objects) {
		return nil, 0
	}
	obj := &p.objects[i]
	if a < obj.Addr {
		return nil, 0
	}
	return obj, a.Sub(obj.Addr)
}

// ForEachEdge calls fn for all heap pointers it finds in x.
// It calls fn with:
//   the offset of the pointer slot in x
//   the pointed-to object y
//   the offset in y where the pointer points.
// If fn returns false, ForEachEdge returns immediately.
func (p *Program) ForEachEdge(x *Object, fn func(int64, *Object, int64) bool) {
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

// ForEachRootEdge behaves like ForEachEdge but it starts with a Root instead of an Object.
func (p *Program) ForEachRootEdge(r *Root, fn func(int64, *Object, int64) bool) {
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
		s := t.Elem.Size()
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
