package gocore

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/randall77/corelib/core"
)

// A region is a piece of the virtual address space of the inferior.
// It has an address and a type.
// Note that it is the type of the thing in the region,
// not the type of the reference to the region.
type region struct {
	p   *Program
	a   core.Address
	typ string // uint64, *byte, []string, ...
}

// Address returns the address that a region of pointer type points to.
func (r region) Address() core.Address {
	if len(r.typ) == 0 || r.typ[0] != '*' {
		panic("can't ask for the Address of a non-pointer " + r.typ)
	}
	return r.p.proc.ReadPtr(r.a)
}

// Int returns the int value stored in r.
func (r region) Int() int64 {
	if r.typ != "int" {
		panic("not an int: " + r.typ)
	}
	if r.p.proc.PtrSize() == 4 {
		return int64(r.p.proc.ReadInt32(r.a))
	}
	return r.p.proc.ReadInt64(r.a)
}

// Uintptr returns the uintptr value stored in r.
func (r region) Uintptr() uint64 {
	if r.typ != "uintptr" {
		panic("not a uintptr: " + r.typ)
	}
	return r.p.proc.ReadUintptr(r.a)
}

// Offset moves the region by the given delta.
func (r region) Offset(x int64) region {
	return region{p: r.p, a: r.a.Add(x), typ: r.typ}
}

// Cast the region to the given type.
func (r region) Cast(typ string) region {
	return region{p: r.p, a: r.a, typ: typ}
}

// Deref loads from a pointer. r must contain a pointer.
func (r region) Deref() region {
	if len(r.typ) == 0 || r.typ[0] != '*' {
		panic("can't load on non-pointer: " + r.typ)
	}
	p := r.p.proc.ReadPtr(r.a)
	return region{p: r.p, a: p, typ: r.typ[1:]}
}

// Uint64 returns the uint64 value stored in r.
// r must have type uint64 or uintptr (on a 64-bit machine).
func (r region) Uint64() uint64 {
	if r.typ != "uint64" {
		panic("bad uint64 type " + r.typ)
	}
	return r.p.proc.ReadUint64(r.a)
}

// Uint32 returns the uint32 value stored in r.
// r must have type uint32.
func (r region) Uint32() uint32 {
	if r.typ != "uint32" {
		panic("bad uint32 type " + r.typ)
	}
	return r.p.proc.ReadUint32(r.a)
}

// Int32 returns the int32 value stored in r.
// r must have type int32.
func (r region) Int32() int32 {
	if r.typ != "int32" {
		panic("bad int32 type " + r.typ)
	}
	return r.p.proc.ReadInt32(r.a)
}

// Uint64 returns the uint64 value stored in r.
// r must have type uint64 or uintptr (on a 64-bit machine).
func (r region) Uint8() uint8 {
	if r.typ != "uint8" {
		panic("bad uint8 type " + r.typ)
	}
	return r.p.proc.ReadUint8(r.a)
}

func (r region) String() string {
	if r.typ != "string" {
		panic("bad string type " + r.typ)
	}
	p := r.p.proc.ReadPtr(r.a)
	n := r.p.proc.ReadUintptr(r.a.Add(r.p.proc.PtrSize()))
	b := make([]byte, n)
	r.p.proc.ReadAt(b, p)
	return string(b)
}

// SliceIndex indexes a slice (a[n]). r must contain a slice.
func (r region) SliceIndex(n int64) region {
	if len(r.typ) < 2 || r.typ[:2] != "[]" {
		panic("can't index a non-slice")
	}
	p := r.p.proc.ReadPtr(r.a)
	return region{p: r.p, a: p.Add(n * r.p.typeSize(r.typ[2:])), typ: r.typ[2:]}
}

// SlicePtr returns the pointer inside a slice. r must contain a slice.
func (r region) SlicePtr() region {
	if len(r.typ) < 2 || r.typ[:2] != "[]" {
		panic("can't Ptr a non-slice")
	}
	return region{p: r.p, a: r.a, typ: "*" + r.typ[2:]}
}

// SliceLen returns the length of a slice. r must contain a slice.
func (r region) SliceLen() int64 {
	if len(r.typ) < 2 || r.typ[:2] != "[]" {
		panic("can't len a non-slice")
	}
	return r.Offset(r.p.proc.PtrSize()).Cast("int").Int()
}

// SliceCap returns the capacity of a slice. r must contain a slice.
func (r region) SliceCap() int64 {
	if len(r.typ) < 2 || r.typ[:2] != "[]" {
		panic("can't cap a non-slice")
	}
	return r.Offset(2 * r.p.proc.PtrSize()).Cast("int").Int()
}

// Field returns the part of r which contains the field f.
// r must contain a struct, and f must be one of its fields.
func (r region) Field(f string) region {
	finfo := r.p.rtStructs[r.typ].fields[f]
	if finfo.typ == "" {
		panic("can't find field " + r.typ + "." + f + fmt.Sprintf("%d", r.p.rtStructs[r.typ].size))
	}
	p := r.a.Add(finfo.off)
	return region{p: r.p, a: p, typ: finfo.typ}
}

func (p *Program) typeSize(t string) int64 {
	switch {
	case t[0] == '*':
		return p.proc.PtrSize()
	case t[0] == '[':
		if t[1] == ']' {
			return p.proc.PtrSize() * 3
		}
		i := strings.IndexByte(t, ']')
		n, err := strconv.Atoi(t[1:i])
		if err != nil {
			panic("unparseable array length " + t)
		}
		return int64(n) * p.typeSize(t[i+1:])
	case t == "string":
		return p.proc.PtrSize() * 2
	case t == "int8" || t == "uint8":
		return 1
	case t == "int16" || t == "uint16":
		return 2
	case t == "int32" || t == "uint32":
		return 4
	case t == "int64" || t == "uint64":
		return 8
	case t == "int" || t == "uint" || t == "uintptr":
		return p.proc.PtrSize()
	}
	if s, ok := p.rtStructs[t]; ok {
		return s.size
	}
	panic("unknown size for type " + t)
}
