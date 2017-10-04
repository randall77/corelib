package gocore

import (
	"math/bits"
	"strings"

	"github.com/randall77/corelib/core"
)

// readObjects finds all the live objects in the heap and marks them
// in the p.heapInfo mark fields.
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
			// Can happen with intra-stack pointers.
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

	// Start with scanning all the roots.
	// Note that we don't just use the DWARF roots, just in case DWARF isn't complete.
	// Instead we use exactly what the runtime uses.

	// Goroutine roots
	for _, g := range p.goroutines {
		for _, f := range g.frames {
			for a := range f.Live {
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
	for _, r := range p.globals {
		if !strings.HasPrefix(r.Name, "finalizer for ") {
			continue
		}
		for _, f := range r.Type.Fields {
			if f.Type.Kind == KindPtr {
				add(p.proc.ReadPtr(r.Addr.Add(f.Off)))
			}
		}
	}

	// Expand root set to all reachable objects.
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
	off >>= p.proc.LogPtrSize()

	// Find bit in bitmap. It goes backwards from the end.
	// Each byte contains pointer/nonpointer bits for 4 words in its low nybble.
	return p.proc.ReadUint8(p.bitmapEnd.Add(-(off>>2)-1))>>uint(off&3)&1 != 0
}

// IsPtr reports whether the inferior at address a contains a pointer.
func (p *Program) IsPtr(a core.Address) bool {
	if a >= p.arenaStart && a < p.arenaUsed {
		return p.isPtr(a)
	}
	for _, m := range p.modules {
		for _, s := range [2]string{"data", "bss"} {
			min := core.Address(m.r.Field(s).Uintptr())
			max := core.Address(m.r.Field("e" + s).Uintptr())
			if a < min || a >= max {
				continue
			}
			gc := m.r.Field("gc" + s + "mask").Field("bytedata").Address()
			i := a.Sub(min)
			return p.proc.ReadUint8(gc.Add(i/8))>>uint(i%8) != 0
		}
	}
	// Everywhere is isn't a pointer. At least, not a pointer into the Go heap.
	// TODO: stacks?
	// TODO: finalizers?
	return false
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

// ForEachRoot calls fn with each garbage collection root.
// If fn returns false, ForEachRoot returns immediately.
func (p *Program) ForEachRoot(fn func(r *Root) bool) {
	for _, r := range p.globals {
		if !fn(r) {
			return
		}
	}
	for _, g := range p.goroutines {
		for _, f := range g.frames {
			for _, r := range f.roots {
				if !fn(r) {
					return
				}
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
	return p.types[i].t, p.types[i].r
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
		if r.Frame == nil || r.Frame.Live[a] {
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
		if r.Frame == nil || r.Frame.Live[a] {
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
