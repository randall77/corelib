package gocore

import "github.com/randall77/corelib/core"

// A region is a piece of the virtual address space of the inferior.
// It has an address and a type.
// Note that it is the type of the thing in the region,
// not the type of the reference to the region.
type region struct {
	p   *Program // TODO: can we remove?
	a   core.Address
	typ *Type
}

// Address returns the address that a region of pointer type points to.
func (r region) Address() core.Address {
	if r.typ.Kind != KindPtr {
		panic("can't ask for the Address of a non-pointer " + r.typ.name)
	}
	return r.p.proc.ReadPtr(r.a)
}

// Int returns the int value stored in r.
func (r region) Int() int64 {
	if r.typ.Kind != KindInt || r.typ.Size != r.p.proc.PtrSize() {
		panic("not an int: " + r.typ.name)
	}
	if r.p.proc.PtrSize() == 4 {
		return int64(r.p.proc.ReadInt32(r.a))
	}
	return r.p.proc.ReadInt64(r.a)
}

// Uintptr returns the uintptr value stored in r.
func (r region) Uintptr() uint64 {
	if r.typ.Kind != KindUint || r.typ.Size != r.p.proc.PtrSize() {
		panic("not a uintptr: " + r.typ.name)
	}
	return r.p.proc.ReadUintptr(r.a)
}

// Cast the region to the given type.
func (r region) Cast(typ string) region {
	return region{p: r.p, a: r.a, typ: r.p.findType(typ)}
}

// Deref loads from a pointer. r must contain a pointer.
func (r region) Deref() region {
	if r.typ.Kind != KindPtr {
		panic("can't deref on non-pointer: " + r.typ.name)
	}
	if r.typ.Elem == nil {
		panic("can't deref unsafe.Pointer")
	}
	p := r.p.proc.ReadPtr(r.a)
	return region{p: r.p, a: p, typ: r.typ.Elem}
}

// Uint64 returns the uint64 value stored in r.
// r must have type uint64 or uintptr (on a 64-bit machine).
func (r region) Uint64() uint64 {
	if r.typ.Kind != KindUint || r.typ.Size != 8 {
		panic("bad uint64 type " + r.typ.name)
	}
	return r.p.proc.ReadUint64(r.a)
}

// Uint32 returns the uint32 value stored in r.
// r must have type uint32.
func (r region) Uint32() uint32 {
	if r.typ.Kind != KindUint || r.typ.Size != 4 {
		panic("bad uint32 type " + r.typ.name)
	}
	return r.p.proc.ReadUint32(r.a)
}

// Int32 returns the int32 value stored in r.
// r must have type int32.
func (r region) Int32() int32 {
	if r.typ.Kind != KindInt || r.typ.Size != 4 {
		panic("bad int32 type " + r.typ.name)
	}
	return r.p.proc.ReadInt32(r.a)
}

// Uint16 returns the uint16 value stored in r.
// r must have type uint16.
func (r region) Uint16() uint16 {
	if r.typ.Kind != KindUint || r.typ.Size != 2 {
		panic("bad uint16 type " + r.typ.name)
	}
	return r.p.proc.ReadUint16(r.a)
}

// Uint8 returns the uint8 value stored in r.
// r must have type uint8.
func (r region) Uint8() uint8 {
	if r.typ.Kind != KindUint || r.typ.Size != 1 {
		panic("bad uint8 type " + r.typ.name)
	}
	return r.p.proc.ReadUint8(r.a)
}

func (r region) String() string {
	if r.typ.Kind != KindString {
		panic("bad string type " + r.typ.name)
	}
	p := r.p.proc.ReadPtr(r.a)
	n := r.p.proc.ReadUintptr(r.a.Add(r.p.proc.PtrSize()))
	b := make([]byte, n)
	r.p.proc.ReadAt(b, p)
	return string(b)
}

// SliceIndex indexes a slice (a[n]). r must contain a slice.
func (r region) SliceIndex(n int64) region {
	if r.typ.Kind != KindSlice {
		panic("can't index a non-slice")
	}
	p := r.p.proc.ReadPtr(r.a)
	return region{p: r.p, a: p.Add(n * r.typ.Elem.Size), typ: r.typ.Elem}
}

// SlicePtr returns the pointer inside a slice. r must contain a slice.
func (r region) SlicePtr() region {
	if r.typ.Kind != KindSlice {
		panic("can't Ptr a non-slice")
	}
	return region{p: r.p, a: r.a, typ: &Type{name: "*" + r.typ.name[2:], Size: r.p.proc.PtrSize(), Kind: KindPtr, Elem: r.typ.Elem}}
}

// SliceLen returns the length of a slice. r must contain a slice.
func (r region) SliceLen() int64 {
	if r.typ.Kind != KindSlice {
		panic("can't len a non-slice")
	}
	return r.p.proc.ReadInt(r.a.Add(r.p.proc.PtrSize()))
}

// SliceCap returns the capacity of a slice. r must contain a slice.
func (r region) SliceCap() int64 {
	if r.typ.Kind != KindSlice {
		panic("can't cap a non-slice")
	}
	return r.p.proc.ReadInt(r.a.Add(2 * r.p.proc.PtrSize()))
}

// Field returns the part of r which contains the field f.
// r must contain a struct, and f must be one of its fields.
func (r region) Field(f string) region {
	finfo := r.typ.field(f)
	if finfo == nil {
		panic("can't find field " + r.typ.name + "." + f)
	}
	return region{p: r.p, a: r.a.Add(finfo.Off), typ: finfo.Type}
}
