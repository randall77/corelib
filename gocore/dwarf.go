package gocore

import (
	"debug/dwarf"
	"fmt"
	"strings"

	"github.com/randall77/corelib/core"
)

// read DWARF types from core dump.
func (p *Program) readDWARFTypes() {
	d, _ := p.proc.DWARF()

	// Make one of our own Types for each dwarf type.
	r := d.Reader()
	for e, err := r.Next(); e != nil && err == nil; e, err = r.Next() {
		switch e.Tag {
		case dwarf.TagArrayType, dwarf.TagPointerType, dwarf.TagStructType, dwarf.TagBaseType, dwarf.TagSubroutineType, dwarf.TagTypedef:
			dt, err := d.Type(e.Offset)
			if err != nil {
				continue
			}
			size := dt.Size()
			if size < 0 { // Fix for issue 21097.
				size = dwarfSize(dt, p.proc.PtrSize())
			}
			t := &Type{name: gocoreName(dt), size: size}
			p.types = append(p.types, t)
			p.dwarfMap[dt] = t
		}
	}

	// Fill in fields of types. Postponed until now so we're sure
	// we have all the Types allocated and available.
	for dt, t := range p.dwarfMap {
		switch x := dt.(type) {
		case *dwarf.ArrayType:
			t.Kind = KindArray
			t.Elem = p.dwarfMap[x.Type]
			t.Count = x.Count
		case *dwarf.PtrType:
			t.Kind = KindPtr
			// unsafe.Pointer has a void base type.
			if _, ok := x.Type.(*dwarf.VoidType); !ok {
				t.Elem = p.dwarfMap[x.Type]
			}
		case *dwarf.StructType:
			t.Kind = KindStruct
			for _, f := range x.Field {
				t.Fields = append(t.Fields, Field{Name: f.Name, Type: p.dwarfMap[f.Type], Off: f.ByteOffset})
			}
		case *dwarf.BoolType:
			t.Kind = KindBool
		case *dwarf.IntType:
			t.Kind = KindInt
		case *dwarf.UintType:
			t.Kind = KindUint
		case *dwarf.FloatType:
			t.Kind = KindFloat
		case *dwarf.ComplexType:
			t.Kind = KindComplex
		case *dwarf.FuncType:
			t.Kind = KindFunc
		case *dwarf.TypedefType:
			// handle these types in the loop below
		default:
			panic(fmt.Sprintf("unknown type %s %T", dt, dt))
		}
	}

	// Detect strings & slices
	for _, t := range p.types {
		if t.Kind != KindStruct {
			continue
		}
		if t.name == "string" || t.name == "struct runtime.stringStructDWARF" {
			t.Kind = KindString
			t.Elem = t.Fields[0].Type.Elem // always uint8?
			t.Fields = nil
		}
		if len(t.name) >= 9 && t.name[:9] == "struct []" ||
			len(t.name) >= 2 && t.name[:2] == "[]" {
			t.Kind = KindSlice
			t.Elem = t.Fields[0].Type.Elem
			t.Fields = nil
		}
	}

	// Copy info from base types into typedefs.
	r = d.Reader()
	for e, err := r.Next(); e != nil && err == nil; e, err = r.Next() {
		if e.Tag != dwarf.TagTypedef {
			continue
		}
		dt, err := d.Type(e.Offset)
		if err != nil {
			continue
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

		// Copy type info from base. Everything except the name.
		name := t.name
		*t = *bt
		t.name = name

		// Detect some special types. If the base is some particular type,
		// then the alias gets marked as special.
		// We have aliases like:
		//   interface {}              -> struct runtime.eface
		//   error                     -> struct runtime.iface
		// Note: the base itself does not get marked as special.
		// (Unlike strings and slices, where they do.)
		if bt.name == "runtime.eface" {
			t.Kind = KindEface
			t.Fields = nil
		}
		if bt.name == "runtime.iface" {
			t.Kind = KindIface
			t.Fields = nil
		}
	}
}

// dwarfSize is used to compute the size of a DWARF type when .Size()
// is clearly wrong (returns a size < 0).
// This function implements just enough to correct the bad behavior in issue21097.
func dwarfSize(dt dwarf.Type, ptrSize int64) int64 {
	switch x := dt.(type) {
	case *dwarf.FuncType:
		return ptrSize // This is the fix.
	case *dwarf.ArrayType:
		return x.Count * dwarfSize(x.Type, ptrSize)
	case *dwarf.TypedefType:
		return dwarfSize(x.Type, ptrSize)
	default:
		panic("unhandled")
	}
}

// gocoreName generates the name this package uses to refer to a dwarf type.
func gocoreName(dt dwarf.Type) string {
	switch x := dt.(type) {
	case *dwarf.PtrType:
		if _, ok := x.Type.(*dwarf.VoidType); ok {
			return "unsafe.Pointer"
		}
		return "*" + gocoreName(x.Type)
	case *dwarf.ArrayType:
		return fmt.Sprintf("[%d]%s", x.Count, gocoreName(x.Type))
	case *dwarf.StructType:
		if !strings.HasPrefix(x.StructName, "struct {") {
			// This is a named type, return that name.
			return x.StructName
		}
		// TODO: detect slices?

		// Build gocore name from the DWARF fields.
		s := "struct {"
		first := true
		for _, f := range x.Field {
			if !first {
				s += ";"
			}
			name := f.Name
			if i := strings.Index(name, "."); i >= 0 {
				// Remove pkg path from field names.
				name = name[i+1:]
			}
			s += fmt.Sprintf(" %s %s", name, gocoreName(f.Type))
			first = false
		}
		s += " }"
		return s
	default:
		return dt.String()
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

// typeHeap tries to label all the heap objects with types.
func (p *Program) typeHeap() {
	// Set of objects which still need to be scanned.
	var q []*Object

	// add records the fact that we know the object at address a has
	// repeat copies of type t.
	add := func(a core.Address, t *Type, repeat int64) {
		if a == 0 { // nil pointer
			return
		}
		if t == nil {
			return // TODO: why?
		}
		obj := p.FindObject(a)
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
		if obj.Type == nil || t.size*repeat > obj.Type.size*obj.Repeat {
			// New typing is better than the old one.
			obj.Type = t
			obj.Repeat = repeat
			q = append(q, obj)
			// Note: An object may appear multiple times in q, but
			// each time it appears means we found a larger type for it.
			// So it is guaranteed to appear only a finite number of times.
		}
	}

	// Get typings starting at roots.
	for _, r := range p.roots {
		p.typeObject(r.Addr, r.Type, p.proc, add)
	}
	fr := &frameReader{p: p}
	for _, g := range p.goroutines {
		for _, f := range g.frames {
			fr.live = f.live
			for _, r := range f.roots {
				p.typeObject(r.Addr, r.Type, fr, add)
			}
		}
	}

	// Propagate typings through the object graph.
	for len(q) > 0 {
		obj := q[len(q)-1]
		q = q[:len(q)-1]
		for i := int64(0); i < obj.Repeat; i++ {
			p.typeObject(obj.Addr.Add(i*obj.Type.Size()), obj.Type, p.proc, add)
		}
	}
}

type reader interface {
	ReadAddress(core.Address) core.Address
	ReadInt(core.Address) int64
}

type frameReader struct {
	p    *Program
	live map[core.Address]bool
}

func (fr *frameReader) ReadAddress(a core.Address) core.Address {
	if !fr.live[a] {
		return 0
	}
	return fr.p.proc.ReadAddress(a)
}
func (fr *frameReader) ReadInt(a core.Address) int64 {
	return fr.p.proc.ReadInt(a)
}

// typeObject takes an address and a type for the data at that address.
// For each pointer it finds in the memory at that address, it calls add with the pointer
// and the type + repeat count of the thing that it points to.
func (p *Program) typeObject(a core.Address, t *Type, r reader, add func(core.Address, *Type, int64)) {
	ptrSize := p.proc.PtrSize()

	switch t.Kind {
	case KindBool, KindInt, KindUint, KindFloat, KindComplex:
		// Nothing to do
	case KindEface, KindIface:
		// interface. Use the type word to determine the type
		// of the pointed-to object.
		typ := r.ReadAddress(a)
		if typ == 0 { // nil interface
			return
		}
		ptr := r.ReadAddress(a.Add(ptrSize))
		if t.Kind == KindIface {
			typ = p.proc.ReadAddress(typ.Add(p.rtStructs["runtime.itab"].fields["_type"].off))
		}
		// TODO: for KindEface, type the typ pointer. It might point to the heap
		// if the type was allocated with reflect.

		direct := p.proc.ReadUint8(typ.Add(p.rtStructs["runtime._type"].fields["kind"].off))&uint8(p.rtConstants["kindDirectIface"]) != 0
		dt := p.runtimeType2Type(typ)
		if direct {
			// Find the base type of the pointer held in the interface.
		findptr:
			if dt.Kind == KindArray {
				dt = dt.Elem
				goto findptr
			}
			if dt.Kind == KindStruct {
				for _, f := range dt.Fields {
					if f.Type.Size() != 0 {
						dt = f.Type
						goto findptr
					}
				}
			}
			if dt.Kind != KindPtr {
				panic(fmt.Sprintf("direct type isn't a pointer %s", dt.Kind))
			}
			dt = dt.Elem
		}
		add(ptr, dt, 1)
	case KindString:
		ptr := r.ReadAddress(a)
		len := r.ReadInt(a.Add(ptrSize))
		add(ptr, t.Elem, len)
	case KindSlice:
		ptr := r.ReadAddress(a)
		cap := r.ReadInt(a.Add(2 * ptrSize))
		add(ptr, t.Elem, cap)
	case KindPtr:
		if t.Elem != nil { // unsafe.Pointer has a nil Elem field.
			add(r.ReadAddress(a), t.Elem, 1)
		}
	case KindFunc:
		// The referent is a closure. We don't know much about the
		// type of the referent. Its first entry is a code pointer.
		// The runtime._type we want exists in the binary (for all
		// heap-allocated closures, anyway) but it would be hard to find
		// just given the pc.
		closure := r.ReadAddress(a)
		if closure == 0 {
			break
		}
		pc := p.proc.ReadAddress(closure)
		f := p.funcTab.find(pc)
		if f == nil {
			panic(fmt.Sprintf("can't find func for closure pc %x", pc))
		}
		ft := f.closure
		if ft == nil {
			ft = &Type{name: "closure for " + f.name, size: ptrSize, Kind: KindPtr}
			p.types = append(p.types, ft)
			// For now, treat a closure like an unsafe.Pointer.
			// TODO: better value for size?
			f.closure = ft
		}
		p.typeObject(closure, ft, r, add)
	case KindArray:
		n := t.Elem.size
		for i := int64(0); i < t.Count; i++ {
			p.typeObject(a.Add(i*n), t.Elem, r, add)
		}
	case KindStruct:
		for _, f := range t.Fields {
			p.typeObject(a.Add(f.Off), f.Type, r, add)
		}
	default:
		panic(fmt.Sprintf("unknown type kind %s\n", t.Kind))
	}
}

// findRuntimeInfo uses DWARF information to find all the struct sizes,
// field offsets, and field types for runtime data structures.
// It also finds a useful set of runtime constants.
// It populates p.rtStructs and rtConstants.
func (p *Program) findRuntimeInfo() {
	p.rtStructs = map[string]structInfo{}
	for dt, _ := range p.dwarfMap {
		rtname := runtimeName(dt)
		if !strings.HasPrefix(rtname, "runtime.") {
			continue
		}
		x, ok := dt.(*dwarf.StructType)
		if !ok {
			continue
		}
		s := structInfo{size: dt.Size(), fields: map[string]fieldInfo{}}
		for _, f := range x.Field {
			s.fields[f.Name] = fieldInfo{off: f.ByteOffset, typ: runtimeName(f.Type)}
		}
		p.rtStructs[rtname] = s
	}
	p.rtConstants = map[string]int64{}
	// TODO: It would be ideal if we could glean this info from DWARF.
	// But we don't package up constants in DWARF right now. See issue #14517.
	// For now, we'll hard code them. As we get more Go versions, each entry
	// might need to condition on Go version, and maybe arch.
	m := p.rtConstants
	m["_MSpanDead"] = 0
	m["_MSpanInUse"] = 1
	m["_MSpanManual"] = 2
	m["_MSpanFree"] = 3
	m["_Gidle"] = 0
	m["_Grunnable"] = 1
	m["_Grunning"] = 2
	m["_Gsyscall"] = 3
	m["_Gwaiting"] = 4
	m["_Gdead"] = 6
	m["_Gscan"] = 0x1000
	m["_PCDATA_StackMapIndex"] = 0
	m["_FUNCDATA_LocalsPointerMaps"] = 1
	m["_FUNCDATA_ArgsPointerMaps"] = 0
	m["tflagExtraStar"] = 1 << 1
	m["kindGCProg"] = 1 << 6
	m["kindDirectIface"] = 1 << 5
	m["_PageSize"] = 1 << 13
}

func (p *Program) findRoots() {
	const (
		DW_OP_addr           = 0x03
		DW_OP_call_frame_cfa = 0x9c
		DW_OP_plus           = 0x22
		DW_OP_consts         = 0x11
	)
	d, _ := p.proc.DWARF()
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
		if p.proc.PtrSize() == 8 {
			a = core.Address(p.proc.ByteOrder().Uint64(loc[1:]))
		} else {
			a = core.Address(p.proc.ByteOrder().Uint32(loc[1:]))
		}
		if !p.proc.Writeable(a) {
			// Read-only globals can't have heap pointers.
			// TODO: keep roots around anyway?
			continue
		}
		dt, err := d.Type(e.AttrField(dwarf.AttrType).Val.(dwarf.Offset))
		if err != nil {
			panic(err)
		}
		if _, ok := dt.(*dwarf.UnspecifiedType); ok {
			continue // Ignore markers like data/edata.
		}
		p.roots = append(p.roots, Root{
			Name: e.AttrField(dwarf.AttrName).Val.(string),
			Addr: a,
			Type: p.dwarfMap[dt],
			Live: nil,
		})
	}

	// Find all stack variables.
	type Var struct {
		name string
		off  int64
		typ  *Type
	}
	vars := map[*Func][]Var{}
	var curfn *Func
	r = d.Reader()
	for e, err := r.Next(); e != nil && err == nil; e, err = r.Next() {
		if e.Tag == dwarf.TagSubprogram {
			min := core.Address(e.AttrField(dwarf.AttrLowpc).Val.(uint64))
			max := core.Address(e.AttrField(dwarf.AttrHighpc).Val.(uint64))
			f := p.funcTab.find(min)
			if f == nil {
				// some func Go doesn't know about. C?
				curfn = nil
			} else {
				if f.entry != min {
					panic("dwarf and runtime don't agree about start of " + f.name)
				}
				if p.funcTab.find(max-1) != f {
					panic("function ranges don't match for " + f.name)
				}
				curfn = f
			}
			continue
		}
		if e.Tag != dwarf.TagVariable && e.Tag != dwarf.TagFormalParameter {
			continue
		}
		aloc := e.AttrField(dwarf.AttrLocation)
		if aloc == nil {
			continue
		}
		loc := aloc.Val.([]byte)
		if len(loc) == 0 || loc[0] != DW_OP_call_frame_cfa {
			continue
		}
		loc = loc[1:]
		var off int64
		if len(loc) != 0 && loc[len(loc)-1] == DW_OP_plus {
			loc = loc[:len(loc)-1]
			if len(loc) == 0 || loc[0] != DW_OP_consts {
				continue
			}
			loc = loc[1:]
			var s uint
			for {
				b := loc[0]
				loc = loc[1:]
				off += int64(b&0x7f) << s
				s += 7
				if b&0x80 == 0 {
					break
				}
			}
			off = off << (64 - s) >> (64 - s)
		}
		if len(loc) != 0 {
			continue
		}
		dt, err := d.Type(e.AttrField(dwarf.AttrType).Val.(dwarf.Offset))
		if err != nil {
			panic(err)
		}
		name := e.AttrField(dwarf.AttrName).Val.(string)
		vars[curfn] = append(vars[curfn], Var{name: name, off: off, typ: p.dwarfMap[dt]})
	}

	// Get roots from goroutine stacks
	for _, g := range p.goroutines {
		for _, f := range g.frames {
			for _, v := range vars[f.f] {
				f.roots = append(f.roots, Root{
					Name: v.name,
					Addr: f.max.Add(v.off),
					Type: v.typ,
					Live: f.live,
				})
			}

		}
	}
	// TODO: finalizers, defers
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
