package gocore

import (
	"strconv"
	"strings"

	"github.com/randall77/corelib/core"
	"github.com/randall77/corelib/rtinfo"
)

type context struct {
	proc *core.Process
	info rtinfo.Info
}

// A region is a piece of the virtual address space of the inferior.
// It has an address and a type.
// Note that it is the type of the thing in the region, not the type of the reference to the region.
type region struct {
	c   *context
	a   core.Address
	typ string // uint64, *byte, []string, ...
}

// Address returns the address that a region of pointer type points to.
func (r region) Address() core.Address {
	if len(r.typ) == 0 || r.typ[0] != '*' {
		panic("can't ask for the Address of a non-pointer " + r.typ)
	}
	return r.c.proc.ReadAddress(r.a)
}

// Int returns the int value stored in r.
func (r region) Int() int64 {
	if r.typ != "int" {
		panic("not an int: " + r.typ)
	}
	if r.c.proc.PtrSize() == 4 {
		return int64(r.c.proc.ReadInt32(r.a))
	}
	return r.c.proc.ReadInt64(r.a)
}

// Uintptr returns the uintptr value stored in r.
func (r region) Uintptr() uint64 {
	if r.typ != "uintptr" {
		panic("not a uintptr: " + r.typ)
	}
	return r.c.proc.ReadUintptr(r.a)
}

// Offset moves the region by the given delta.
func (r region) Offset(x int64) region {
	return region{c: r.c, a: r.a.Add(x), typ: r.typ}
}

// Cast the region to the given type.
func (r region) Cast(typ string) region {
	return region{c: r.c, a: r.a, typ: typ}
}

// Deref loads from a pointer. r must contain a pointer.
func (r region) Deref() region {
	if len(r.typ) == 0 || r.typ[0] != '*' {
		panic("can't load on non-pointer: " + r.typ)
	}
	p := r.c.proc.ReadAddress(r.a)
	return region{c: r.c, a: p, typ: r.typ[1:]}
}

// Uint64 returns the uint64 value stored in r.
// r must have type uint64 or uintptr (on a 64-bit machine).
func (r region) Uint64() uint64 {
	if r.typ != "uint64" {
		panic("bad uint64 type " + r.typ)
	}
	return r.c.proc.ReadUint64(r.a)
}

// Uint32 returns the uint32 value stored in r.
// r must have type uint32.
func (r region) Uint32() uint32 {
	if r.typ != "uint32" {
		panic("bad uint32 type " + r.typ)
	}
	return r.c.proc.ReadUint32(r.a)
}

// Int32 returns the int32 value stored in r.
// r must have type int32.
func (r region) Int32() int32 {
	if r.typ != "int32" {
		panic("bad int32 type " + r.typ)
	}
	return r.c.proc.ReadInt32(r.a)
}

// Uint64 returns the uint64 value stored in r.
// r must have type uint64 or uintptr (on a 64-bit machine).
func (r region) Uint8() uint8 {
	if r.typ != "uint8" {
		panic("bad uint8 type " + r.typ)
	}
	return r.c.proc.ReadUint8(r.a)
}

func (r region) String() string {
	if r.typ != "string" {
		panic("bad string type " + r.typ)
	}
	p := r.c.proc.ReadAddress(r.a)
	n := r.c.proc.ReadUintptr(r.a.Add(r.c.proc.PtrSize()))
	b := make([]byte, n)
	r.c.proc.ReadAt(b, p)
	return string(b)
}

// SliceIndex indexes a slice (a[n]). r must contain a slice.
func (r region) SliceIndex(n int64) region {
	if len(r.typ) < 2 || r.typ[:2] != "[]" {
		panic("can't index a non-slice")
	}
	p := r.c.proc.ReadAddress(r.a)
	return region{c: r.c, a: p.Add(n * r.c.typeSize(r.typ[2:])), typ: r.typ[2:]}
}

// SlicePtr returns the pointer inside a slice. r must contain a slice.
func (r region) SlicePtr() region {
	if len(r.typ) < 2 || r.typ[:2] != "[]" {
		panic("can't Ptr a non-slice")
	}
	return region{c: r.c, a: r.a, typ: "*" + r.typ[2:]}
}

// SliceLen returns the length of a slice. r must contain a slice.
func (r region) SliceLen() int64 {
	if len(r.typ) < 2 || r.typ[:2] != "[]" {
		panic("can't len a non-slice")
	}
	return r.Offset(r.c.proc.PtrSize()).Cast("int").Int()
}

// SliceCap returns the capacity of a slice. r must contain a slice.
func (r region) SliceCap() int64 {
	if len(r.typ) < 2 || r.typ[:2] != "[]" {
		panic("can't cap a non-slice")
	}
	return r.Offset(2 * r.c.proc.PtrSize()).Cast("int").Int()
}

// Field returns the part of r which contains the field f.
// r must contain a struct, and f must be one of its fields.
func (r region) Field(f string) region {
	finfo := r.c.info.Structs[r.typ].Fields[f]
	if finfo.Typ == "" {
		panic("can't find field " + r.typ + "." + f)
	}
	p := r.a.Add(finfo.Off)
	return region{c: r.c, a: p, typ: finfo.Typ}
}

func (c *context) typeSize(t string) int64 {
	switch {
	case t[0] == '*':
		return c.proc.PtrSize()
	case t[0] == '[':
		if t[1] == ']' {
			return c.proc.PtrSize() * 3
		}
		i := strings.IndexByte(t, ']')
		n, err := strconv.Atoi(t[1:i])
		if err != nil {
			panic("unparseable array length " + t)
		}
		return int64(n) * c.typeSize(t[i+1:])
	case t == "string":
		return c.proc.PtrSize() * 2
	case t == "byte":
		return 1
	case t == "int16" || t == "uint16":
		return 2
	case t == "int32" || t == "uint32":
		return 4
	case t == "int64" || t == "uint64":
		return 8
	case t == "int" || t == "uint" || t == "uintptr":
		return c.proc.PtrSize()
	}
	if s, ok := c.info.Structs[t]; ok {
		return s.Size
	}
	panic("unknown size for type " + t)
}
