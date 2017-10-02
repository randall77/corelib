package gocore

import (
	"math/bits"

	"github.com/randall77/corelib/core"
)

// readObjects finds all the live objects in the heap and marks them
// in the p.heapInfo mark fields.
// It also fills in the p.sizes array.
func (p *Program) readObjects() {
	ptrSize := p.proc.PtrSize()

	// number of live objects found so far
	n := 0
	// total size of live objects
	var live int64

	var q []Object

	// Function to call when we find a new pointer.
	add := func(x core.Address) {
		if x == 0 || x < p.arenaStart || x >= p.arenaUsed { // not in heap
			return
		}
		i := x.Sub(p.arenaStart) / 512
		h := &p.heapInfo[i]
		if h.base == 0 { // not in a valid span
			// TODO: probably a runtime/compiler error?
			return
		}
		// Round down to object start.
		x = h.base.Add(x.Sub(h.base) / h.size * h.size)
		// Find mark bit
		off := uint64(x.Sub(p.arenaStart))
		j := off / 512
		h = &p.heapInfo[j]
		b := off % 512 / 8
		if h.mark&(uint64(1)<<b) != 0 { // already found
			return
		}
		h.mark |= uint64(1) << b
		n++
		live += h.size
		q = append(q, Object(x))
	}

	// Goroutine roots
	for _, g := range p.goroutines {
		for _, f := range g.frames {
			for a := range f.live { // TODO: iteration order matter?
				add(p.proc.ReadPtr(a))
			}
		}
	}

	// Global roots
	for _, m := range p.modules {
		for _, s := range [2]string{"data", "bss"} {
			min := core.Address(m.r.Field(s).Uintptr())
			max := core.Address(m.r.Field("e" + s).Uintptr())
			gc := m.r.Field("gc" + s + "mask").Field("bytedata").Address()
			num := max.Sub(min) / ptrSize
			for i := int64(0); i < num; i++ {
				if p.proc.ReadUint8(gc.Add(i/8))>>uint(i%8)&1 != 0 {
					add(p.proc.ReadPtr(min.Add(i * ptrSize)))
				}
			}
		}
	}

	// Finalizers
	mheap := p.rtGlobals["mheap_"]
	allspans := mheap.Field("allspans")
	nSpan := allspans.SliceLen()
	for i := int64(0); i < nSpan; i++ {
		s := allspans.SliceIndex(i).Deref()
		for sp := s.Field("specials"); sp.Address() != 0; sp = sp.Field("next") {
			sp = sp.Deref() // *special to special
			if sp.Field("kind").Uint8() != uint8(p.rtConstants["_KindSpecialFinalizer"]) {
				// All other specials (just profile records) are not stored in the heap.
				continue
			}
			// Note: the type runtime.specialfinalizer is the type here, but
			// that type doesn't make it into the DWARF info. So we have to
			// manually compute offsets.
			// type specialfinalizer struct {
			//      special special
			//      fn      *funcval
			//      nret    uintptr
			//      fint    *_type
			//      ot      *ptrtype
			// }
			a := sp.a.Add(p.findType("runtime.special").Size)
			add(p.proc.ReadPtr(a.Add(0 * p.proc.PtrSize())))
			add(p.proc.ReadPtr(a.Add(2 * p.proc.PtrSize())))
			add(p.proc.ReadPtr(a.Add(3 * p.proc.PtrSize())))

			// TODO: record these somewhere so ForEachPtr can return them.
		}
	}

	// Expand root set to all reachable objects.
	// TODO: run in parallel?
	for len(q) > 0 {
		x := q[len(q)-1]
		q = q[:len(q)-1]

		// Scan object for pointers.
		size := p.Size(x)
		for i := int64(0); i < size; i += ptrSize {
			a := core.Address(x).Add(i)
			if p.isPtr(a) {
				add(p.proc.ReadPtr(a))
			}
		}
	}

	p.nObj = n

	// Initialize firstIdx fields in the heapInfo, for fast object index lookups.
	for i := len(p.heapInfo) - 1; i >= 0; i-- {
		h := &p.heapInfo[i]
		if h.mark == 0 { // not really necessary, just leave -1 sentinel as a double check.
			continue
		}
		n -= bits.OnesCount64(h.mark)
		h.firstIdx = n
	}

	// Update stats to include the live/garbage distinction.
	alloc := p.Stats().Child("heap").Child("in use spans").Child("alloc")
	alloc.Children = []*Stats{
		&Stats{"live", live, nil},
		&Stats{"garbage", alloc.Size - live, nil},
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
// Returns 0,0 if a doesn't point to a live heap object.
func (p *Program) FindObject(a core.Address) (Object, int64) {
	if a < p.arenaStart || a >= p.arenaUsed {
		// Not in Go heap.
		return 0, 0
	}
	// Round down to the start of an object.
	h := &p.heapInfo[a.Sub(p.arenaStart)/512]
	if h.size == 0 {
		// In a span that doesn't hold Go objects (freed, stacks, ...)
		return 0, 0
	}
	x := h.base.Add(a.Sub(h.base) / h.size * h.size)
	// Check if object is marked.
	h = &p.heapInfo[x.Sub(p.arenaStart)/512]
	if h.mark>>(uint64(x)%512/8)&1 == 0 {
		return 0, 0
	}
	return Object(x), a.Sub(x)
}

func (p *Program) findObjectIndex(a core.Address) (int, int64) {
	x, off := p.FindObject(a)
	if x == 0 {
		return -1, 0
	}
	h := &p.heapInfo[core.Address(x).Sub(p.arenaStart)/512]
	return h.firstIdx + bits.OnesCount64(h.mark&(uint64(1)<<(uint64(x)%512/8)-1)), off
}

// ForEachObject calls fn with each object in the Go heap.
// If fn returns false, ForEachObject returns immediately.
func (p *Program) ForEachObject(fn func(x Object) bool) {
	for i := 0; i < len(p.heapInfo); i++ {
		m := p.heapInfo[i].mark
		for m != 0 {
			j := bits.TrailingZeros64(m)
			m &= m - 1
			if !fn(Object(p.arenaStart.Add(int64(i)*512 + int64(j)*8))) {
				return
			}
		}
	}
}

// Addr returns the starting address of x.
func (p *Program) Addr(x Object) core.Address {
	return core.Address(x)
}

// Size returns the size of x in bytes.
func (p *Program) Size(x Object) int64 {
	return p.heapInfo[uint64(core.Address(x).Sub(p.arenaStart))/512].size
}

// Type returns the type and repeat count for the object x.
// x contains at least repeat copies of the returned type.
// FlagTypes must have been passed to Core when p was constructed.
func (p *Program) Type(x Object) (*Type, int64) {
	i, _ := p.findObjectIndex(core.Address(x))
	return p.types[i].Type, p.types[i].Repeat
}

// ForEachPtr calls fn for all heap pointers it finds in x.
// It calls fn with:
//   the offset of the pointer slot in x
//   the pointed-to object y
//   the offset in y where the pointer points.
// If fn returns false, ForEachPtr returns immediately.
// For an edge from an object to its finalizer, the first argument
// passed to fn will be -1.
func (p *Program) ForEachPtr(x Object, fn func(int64, Object, int64) bool) {
	size := p.Size(x)
	for i := int64(0); i < size; i += p.proc.PtrSize() {
		a := core.Address(x).Add(i)
		if !p.isPtr(a) {
			continue
		}
		ptr := p.proc.ReadPtr(a)
		y, off := p.FindObject(ptr)
		if y != 0 {
			if !fn(i, y, off) {
				return
			}
		}
	}
}

// ForEachRootPtr behaves like ForEachPtr but it starts with a Root instead of an Object.
func (p *Program) ForEachRootPtr(r *Root, fn func(int64, Object, int64) bool) {
	edges1(p, r, 0, r.Type, fn)
}

// edges1 calls fn for the edges found in an object of type t living at offset off in the root r.
// If fn returns false, return immediately with false.
func edges1(p *Program, r *Root, off int64, t *Type, fn func(int64, Object, int64) bool) bool {
	switch t.Kind {
	case KindBool, KindInt, KindUint, KindFloat, KindComplex:
		// no edges here
	case KindIface, KindEface:
		// The first word is a type or itab.
		// Itabs are never in the heap.
		// Types might be, though.
		a := r.Addr.Add(off)
		if r.Live == nil || r.Live[a] {
			dst, off2 := p.FindObject(p.proc.ReadPtr(a))
			if dst != 0 {
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
			dst, off2 := p.FindObject(p.proc.ReadPtr(a))
			if dst != 0 {
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

// A revEdge is an incoming edge to an object.
// Exactly one of fromObj or fromRoot will be non-nil.
// fromIdx is the offset in fromObj/fromRoot where the pointer was found.
// toIdx is the offset in the pointed-to object where the pointer lands.
type revEdge struct {
	fromObj  Object
	fromRoot *Root
	fromIdx  int64
	toIdx    int64 // TODO: compute when needed?
}

// ForEachIncomingPtr calls fn for all incoming pointers into object x.
// It calls fn with:
//   the object or root containing the pointer (exactly one will be non-nil)
//   the offset in the object/root where the pointer is found
//   the offset of the target of the edge in x.
// If fn returns false, ForEachIncomingPtr returns immediately.
func (p *Program) ForEachIncomingPtr(x Object, fn func(Object, *Root, int64, int64) bool) {
	//TODO
}
