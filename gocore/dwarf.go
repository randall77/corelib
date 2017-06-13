package gocore

import (
	"debug/dwarf"
	"fmt"
	"strings"

	"github.com/randall77/corelib/core"
)

func (p *Program) readDWARFTypes() {
	d, _ := p.proc.DWARF()

	// Make a Type for each dwarf type.
	r := d.Reader()
	for e, err := r.Next(); e != nil && err == nil; e, err = r.Next() {
		switch e.Tag {
		case dwarf.TagArrayType, dwarf.TagPointerType, dwarf.TagStringType, dwarf.TagStructType, dwarf.TagBaseType, dwarf.TagSubroutineType, dwarf.TagTypedef:
			dt, err := d.Type(e.Offset)
			if err != nil {
				fmt.Printf("bad type @ %d\n", e.Offset)
				break
			}
			t := &Type{dt: dt, name: dt.String(), size: dt.Size()}
			p.types = append(p.types, t)
			p.dwarfMap[dt] = t
			//fmt.Printf("added %s\n", t)
		}
	}

	// Fill in fields of types. Postponed until now so we're sure
	// we have all the Types allocated and available.
	r = d.Reader()
	for e, err := r.Next(); e != nil && err == nil; e, err = r.Next() {
		switch e.Tag {
		case dwarf.TagArrayType:
			// TODO
			dt, _ := d.Type(e.Offset)
			t := p.dwarfMap[dt]
			t.ptrs = dwarfPtrBits(dt, p.proc.PtrSize())
		case dwarf.TagStructType:
			dt, _ := d.Type(e.Offset)
			t := p.dwarfMap[dt]
			t.ptrs = dwarfPtrBits(dt, p.proc.PtrSize())
			for _, f := range dt.(*dwarf.StructType).Field {
				t.fields = append(t.fields, Field{Name: f.Name, Type: p.dwarfMap[f.Type], Off: f.ByteOffset})
			}
		case dwarf.TagPointerType, dwarf.TagStringType, dwarf.TagSubroutineType:
			dt, _ := d.Type(e.Offset)
			t := p.dwarfMap[dt]
			if x, ok := dt.(*dwarf.PtrType); ok {
				t.sub = p.dwarfMap[x.Type]
			}
			// TODO: functype->some sort of closure typing?
			t.ptrs = dwarfPtrBits(dt, p.proc.PtrSize())
		}
	}

	// Copy info from base types into typedef.
	r = d.Reader()
	for e, err := r.Next(); e != nil && err == nil; e, err = r.Next() {
		if e.Tag != dwarf.TagTypedef {
			continue
		}
		dt, err := d.Type(e.Offset)
		if err != nil {
			fmt.Printf("bad type @ %d\n", e.Offset)
			break
		}
		base := dt.(*dwarf.TypedefType).Type
		// Walk typedef chain until we reach a non-typedef type.
		for {
			if x, ok := base.(*dwarf.TypedefType); ok {
				base = x.Type
				continue
			}
			break
		}

		t := p.dwarfMap[dt]
		bt := p.dwarfMap[base]

		// Copy type layout from base.
		t.ptrs = bt.ptrs
		t.fields = bt.fields

		// Detect some special types. If the base is some particular type,
		// then the alias gets marked as special.
		// We have aliases like:
		//   interface {}              -> struct runtime.eface
		//   error                     -> struct runtime.iface
		//   runtime.stringStructDWARF -> struct runtime.stringStructDWARF
		// Note: the base itself does not get marked as special.
		if base.String() == "struct runtime.eface" {
			t.isEface = true
		}
		if base.String() == "struct runtime.iface" {
			t.isIface = true
		}
		if base.String() == "struct runtime.stringStructDWARF" {
			t.isString = true
		}
	}
}

// Generate the name the runtime uses for a dwarf type. The DWARF generator
// and the runtime use slightly different names for the same underlying type.
func runtimeName(dt dwarf.Type) string {
	switch x := dt.(type) {
	case *dwarf.PtrType:
		if _, ok := x.Type.(*dwarf.VoidType); ok {
			return "unsafe.Pointer"
		}
		return "*" + runtimeName(x.Type)
	case *dwarf.ArrayType:
		return fmt.Sprintf("[%d]%s", x.Count, runtimeName(x.Type))
	case *dwarf.StructType:
		if !strings.HasPrefix(x.StructName, "struct {") {
			// This is a named type, return that name.
			return x.StructName
		}
		// TODO: detect slices?

		// Figure out which fields have anonymous names.
		var anon []bool
		for _, f := range strings.Split(x.StructName[8:len(x.StructName)-1], ";") {
			f = strings.TrimSpace(f)
			anon = append(anon, !strings.Contains(f, " "))
			// TODO: this isn't perfect. If the field type has a space in it,
			// then this logic doesn't work. Need to search for keyword for
			// field type, like "interface", "struct", ...
		}

		// Build runtime name from the DWARF fields.
		s := "struct {"
		first := true
		for _, f := range x.Field {
			if !first {
				s += ";"
			}
			name := f.Name
			if i := strings.Index(name, "."); i >= 0 {
				name = name[i+1:]
			}
			if anon[0] {
				s += fmt.Sprintf(" %s", runtimeName(f.Type))
			} else {
				s += fmt.Sprintf(" %s %s", name, runtimeName(f.Type))
			}
			first = false
			anon = anon[1:]
		}
		s += " }"
		return s
	default:
		name := dt.String()
		if i := strings.LastIndex(name, "/"); i >= 0 {
			name = name[i+1:] // Runtime uses only last name in package path.
		}
		return name
	}
}

func dwarfPtrBits(dt dwarf.Type, ptrSize int64) []bool {
	size := dt.Size()
	if size < 0 { // For weird types, like <unspecified>
		return nil
	}
	size /= ptrSize
	if size > 10000 {
		// TODO: fix this
		return nil
	}
	b := make([]bool, size)
	dwarfPtrBits1(dt, ptrSize, b)
	// Trim trailing false entries.
	for len(b) > 0 && !b[len(b)-1] {
		b = b[:len(b)-1]
	}
	return b
}
func dwarfPtrBits1(dt dwarf.Type, ptrSize int64, b []bool) {
	switch x := dt.(type) {
	case *dwarf.IntType, *dwarf.UintType, *dwarf.BoolType, *dwarf.FloatType, *dwarf.ComplexType:
		// Nothing to do
	case *dwarf.PtrType, *dwarf.FuncType:
		b[0] = true
	case *dwarf.ArrayType:
		n := x.Type.Size()
		if n%ptrSize != 0 { // can't have pointers
			break
		}
		n /= ptrSize // convert to words
		for i := int64(0); i < x.Count; i++ {
			dwarfPtrBits1(x.Type, ptrSize, b)
			b = b[n:]
		}
	case *dwarf.StructType:
		for _, f := range x.Field {
			if f.ByteOffset%ptrSize != 0 { // can't have pointers
				continue
			}
			dwarfPtrBits1(f.Type, ptrSize, b[f.ByteOffset/ptrSize:])
		}
	case *dwarf.TypedefType:
		dwarfPtrBits1(x.Type, ptrSize, b)
	default:
		panic(fmt.Sprintf("unknown type %T\n", dt))
	}
	// VoidType is always hidden under a pointer.
	// TODO: I think map, chan are just PtrType.
	// TODO: string, interface, slice are structs and should just work.
}

func (g *Program) readDWARFGlobals() {
	const (
		// Constants that maybe should go in debug/dwarf
		DW_OP_addr = 3
	)
	d, _ := g.proc.DWARF()
	r := d.Reader()
	var e *dwarf.Entry
	var err error
	for e, err = r.Next(); e != nil && err == nil; e, err = r.Next() {
		if e.Tag != dwarf.TagVariable {
			continue
		}
		loc := e.AttrField(dwarf.AttrLocation).Val.([]byte)
		if loc[0] != DW_OP_addr {
			continue
		}
		var addr core.Address
		if g.proc.PtrSize() == 8 {
			addr = core.Address(g.proc.ByteOrder().Uint64(loc[1:]))
		} else {
			addr = core.Address(g.proc.ByteOrder().Uint32(loc[1:]))
		}
		if !g.proc.Writeable(addr) {
			continue // Ignore read-only globals.
		}
		dt, err := d.Type(e.AttrField(dwarf.AttrType).Val.(dwarf.Offset))
		if err != nil {
			panic(err)
		}
		if _, ok := dt.(*dwarf.UnspecifiedType); ok {
			continue // Ignore markers like data/edata.
		}
		name := e.AttrField(dwarf.AttrName).Val.(string)
		t := g.dwarfMap[dt]
		//fmt.Printf("global %s %x\n", name, addr)
		g.globals = append(g.globals, Var{
			Name: name,
			Addr: addr,
			Type: t,
		})
	}
}

// typeHeap tries to label all the heap objects with types.
func (g *Program) typeHeap() {
	// Set of objects which still need to be scanned.
	var q []*Object

	// add records the fact that we know the object at address a has type t.
	add := func(a core.Address, t *Type) {
		if a == 0 { // nil pointer
			return
		}
		obj := g.findObject(a)
		if obj == nil { // pointer doesn't point to an object in the Go heap
			return
		}
		if obj.Addr != a {
			// Ignore interior pointers.
			// TODO: Maybe we could extract some useful info here?
			// Keep offset/type pairs for an object + have a merge
			// rule for those offset/type pairs. For now we just use
			// the simple offset=0, maximum size typing.
			return
		}
		if obj.Type == nil || t.size > obj.Type.size {
			// New typing is better than the old one.
			obj.Type = t
			q = append(q, obj)
			// Note: An object may appear multiple times in q, but
			// each time it appears means we found a larger type for it.
			// So it is guaranteed to appear only a finite number of times.
		}
	}

	// Get types from globals.
	const (
		// Constants that maybe should go in debug/dwarf
		DW_OP_addr = 3
	)
	d, _ := g.proc.DWARF()
	r := d.Reader()
	for e, err := r.Next(); e != nil && err == nil; e, err = r.Next() {
		if e.Tag != dwarf.TagVariable {
			continue
		}
		loc := e.AttrField(dwarf.AttrLocation).Val.([]byte)
		if loc[0] != DW_OP_addr {
			continue
		}
		var a core.Address
		if g.proc.PtrSize() == 8 {
			a = core.Address(g.proc.ByteOrder().Uint64(loc[1:]))
		} else {
			a = core.Address(g.proc.ByteOrder().Uint32(loc[1:]))
		}
		if !g.proc.Writeable(a) {
			continue // Read-only globals can't have heap pointers.
		}
		dt, err := d.Type(e.AttrField(dwarf.AttrType).Val.(dwarf.Offset))
		if err != nil {
			panic(err)
		}
		if _, ok := dt.(*dwarf.UnspecifiedType); ok {
			continue // Ignore markers like data/edata.
		}
		t := g.dwarfMap[dt]
		g.typeObject(a, t, add)
	}
	// TODO: types from frames
	// TODO: finalizers?
	// TODO: specials?

	// Repeatedly scan objects until we have no more new typings.
	for len(q) > 0 {
		obj := q[len(q)-1]
		q = q[:len(q)-1]
		if obj.Type.dt != nil {
			g.typeObject(obj.Addr, obj.Type, add)
		}
	}
}

// typeObject takes an address and a type for the data at that address.
// For each pointer it finds in object at that address, it calls add with the pointer
// and the type of the thing it points to.
func (g *Program) typeObject(a core.Address, t *Type, add func(core.Address, *Type)) {
	// Short-cut return when there can't be any pointers.
	// This is just an optimization.
	ptrSize := g.proc.PtrSize()
	if a.Align(ptrSize) != a { // not pointer-aligned
		return
	}
	if t.size&(ptrSize-1) != 0 { // not multiple-of-pointer-sized
		return
	}

	if t.dt == nil {
		// All we know is ptr/nonptr for this type. Give up here.
		return
	}

	// Special cases for interface types.
	if t.isEface {
		// interface{}. Use the type word to determine the type
		// of the pointed-to object.
		typ := g.proc.ReadAddress(a)
		if typ == 0 { // nil interface
			return
		}
		ptr := g.proc.ReadAddress(a.Add(ptrSize))
		//fmt.Printf("eface %x %s\n", ptr, g.runtimeMap[typ])
		add(ptr, g.runtimeMap[typ])
		return
	}
	if t.isIface {
		// interface{foo()}. Use the itab to determine the type
		// of the pointed-to object.
		itab := g.proc.ReadAddress(a)
		if itab == 0 { // nil interface
			return
		}
		ptr := g.proc.ReadAddress(a.Add(ptrSize))
		typ := g.proc.ReadAddress(itab.Add(g.info.Structs["runtime.itab"].Fields["_type"].Off))
		//fmt.Printf("iface %x %s\n", ptr, g.runtimeMap[typ])
		add(ptr, g.runtimeMap[typ])
		return
	}

	switch x := t.dt.(type) {
	case *dwarf.IntType, *dwarf.UintType, *dwarf.FloatType, *dwarf.ComplexType:
		// Nothing to do
	case *dwarf.PtrType:
		if _, ok := x.Type.(*dwarf.VoidType); ok {
			// unsafe.Pointer. We don't know anything about the target object's type.
			break
		}
		add(g.proc.ReadAddress(a), g.dwarfMap[x.Type])
	case *dwarf.FuncType:
		// TODO
	case *dwarf.ArrayType:
		et := g.dwarfMap[x.Type]
		n := et.size
		for i := int64(0); i < x.Count; i++ {
			g.typeObject(a.Add(i*n), et, add)
		}
	case *dwarf.StructType:
		for _, f := range x.Field {
			g.typeObject(a.Add(f.ByteOffset), g.dwarfMap[f.Type], add)
		}
	case *dwarf.TypedefType:
		g.typeObject(a, g.dwarfMap[x.Type], add)
	default:
		panic(fmt.Sprintf("unknown type %T\n", t.dt))
	}
}

/* Dwarf encoding notes

type XXX sss

translates to a dwarf type pkg.XXX of the type of sss (uint, float, ...)

exception: if sss is a struct or array, then we get two types, the "unnamed" and "named" type.
The unnamed type is a dwarf struct type with name "struct pkg.XXX" or a dwarf array type with
name [N]elem.
Then there is a typedef with pkg.XXX pointing to "struct pkg.XXX" or [N]elem.

For structures, lowercase field names are prepended with the package name (pkg path?).

type XXX interface{}
pkg.XXX is a typedef to "struct runtime.eface"
type XXX interface{f()}
pkg.XXX is a typedef to "struct runtime.iface"

Sometimes there is even a chain of identically-named typedefs. I have no idea why.
main.XXX -> main.XXX -> struct runtime.iface

*/
