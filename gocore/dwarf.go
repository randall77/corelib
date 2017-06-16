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
				continue
			}
			t := &Type{dt: dt, name: gocoreName(dt), size: dt.Size()}
			p.types = append(p.types, t)
			p.dwarfMap[dt] = t
		}
	}

	// Fill in fields of types. Postponed until now so we're sure
	// we have all the Types allocated and available.
	r = d.Reader()
	for e, err := r.Next(); e != nil && err == nil; e, err = r.Next() {
		switch e.Tag {
		case dwarf.TagArrayType, dwarf.TagPointerType, dwarf.TagStringType, dwarf.TagStructType, dwarf.TagBaseType, dwarf.TagSubroutineType, dwarf.TagTypedef:
			dt, _ := d.Type(e.Offset)
			t := p.dwarfMap[dt]
			t.ptrs = dwarfPtrBits(dt, p.proc.PtrSize())
			if t.name == "struct runtime.stringStructDWARF" {
				t.isString = true
			}
			if len(t.name) >= 9 && t.name[:9] == "struct []" {
				t.isSlice = true
			}
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

		// Copy type layout from base.
		t.ptrs = bt.ptrs

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
		obj := p.findObject(a)
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

	// Get types from globals.
	const (
		// Constants that maybe should go in debug/dwarf
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
			continue // Read-only globals can't have heap pointers.
		}
		dt, err := d.Type(e.AttrField(dwarf.AttrType).Val.(dwarf.Offset))
		if err != nil {
			panic(err)
		}
		if _, ok := dt.(*dwarf.UnspecifiedType); ok {
			continue // Ignore markers like data/edata.
		}
		t := p.dwarfMap[dt]
		p.typeObject(a, t, p.proc, add)
	}

	// Find all stack variables.
	r = d.Reader()
	var curfn *Func
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
		// TODO: keep name around?
		curfn.vars = append(curfn.vars, stackVar{off: off, t: p.dwarfMap[dt]})
	}

	// Get types from goroutines.
	for _, g := range p.goroutines {
		for _, f := range g.frames {
			r := &frameReader{proc: p.proc, f: f}
			for _, v := range f.f.vars {
				p.typeObject(f.max.Add(v.off), v.t, r, add)
			}
		}
	}

	// TODO: finalizers?
	// TODO: specials?

	// Propagate typings through the object graph.
	for len(q) > 0 {
		obj := q[len(q)-1]
		q = q[:len(q)-1]
		p.typeObject(obj.Addr, obj.Type, p.proc, add)
	}
}

type reader interface {
	ReadAddress(core.Address) core.Address
	ReadInt(core.Address) int64
}

// A frameReader is an overlay on a core.Process which
// makes all dead pointers in the frame read as nil.
type frameReader struct {
	proc *core.Process
	f    *Frame
}

func (r *frameReader) ReadInt(a core.Address) int64 {
	return r.proc.ReadInt(a)
}
func (r *frameReader) ReadAddress(a core.Address) core.Address {
	live := false
	// TODO: use binary search?
	for _, p := range r.f.ptrs {
		if p == a {
			live = true
			break
		}

	}
	if !live {
		return 0
	}
	return r.proc.ReadAddress(a)
}

// typeObject takes an address and a type for the data at that address.
// For each pointer it finds in the memory at that address, it calls add with the pointer
// and the type + repeat count of the thing it points to.
func (p *Program) typeObject(a core.Address, t *Type, r reader, add func(core.Address, *Type, int64)) {
	// Short-cut return when there can't be any pointers.
	// This is just an optimization.
	ptrSize := p.proc.PtrSize()
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
		typ := r.ReadAddress(a)
		if typ == 0 { // nil interface
			return
		}
		ptr := r.ReadAddress(a.Add(ptrSize))
		add(ptr, p.runtimeMap[typ], 1)
		return
	}
	if t.isIface {
		// interface{foo()}. Use the itab to determine the type
		// of the pointed-to object.
		itab := r.ReadAddress(a)
		if itab == 0 { // nil interface
			return
		}
		ptr := r.ReadAddress(a.Add(ptrSize))
		typ := r.ReadAddress(itab.Add(p.rtStructs["runtime.itab"].fields["_type"].off))
		add(ptr, p.runtimeMap[typ], 1)
		return
	}
	// Special cases for references to repeated objects.
	if t.isString {
		ptr := r.ReadAddress(a)
		len := r.ReadInt(a.Add(ptrSize))
		pt := t.dt.(*dwarf.StructType).Field[0].Type // always *uint8
		et := pt.(*dwarf.PtrType).Type
		add(ptr, p.dwarfMap[et], len)
		return
	}
	if t.isSlice {
		ptr := r.ReadAddress(a)
		cap := r.ReadInt(a.Add(2 * ptrSize))
		pt := t.dt.(*dwarf.StructType).Field[0].Type
		et := pt.(*dwarf.PtrType).Type
		add(ptr, p.dwarfMap[et], cap)
		return
	}

	switch x := t.dt.(type) {
	case *dwarf.IntType, *dwarf.UintType, *dwarf.BoolType, *dwarf.FloatType, *dwarf.ComplexType:
		// Nothing to do
	case *dwarf.PtrType:
		if _, ok := x.Type.(*dwarf.VoidType); ok {
			// unsafe.Pointer. We don't know anything about the target object's type.
			break
		}
		add(r.ReadAddress(a), p.dwarfMap[x.Type], 1)
	case *dwarf.FuncType:
		// The referent is a closure. We don't know much about the
		// type of the referent. Its first entry is a code pointer.
		// The runtime._type we want exists in the binary (for all
		// heap-allocated closures, anyway) but it would be hard to find
		// just given the pc.
		closure := r.ReadAddress(a)
		if closure == 0 {
			break
		}
		pc := r.ReadAddress(closure)
		f := p.funcTab.find(pc)
		if f == nil {
			panic(fmt.Sprintf("can't find func for closure pc %x", pc))
		}
		ft := f.closure
		if ft == nil {
			ft = &Type{name: "closure for " + f.name, size: ptrSize}
			// TODO: better value for size?
			f.closure = ft
			p.types = append(p.types, ft)
		}
		p.typeObject(closure, ft, r, add)
	case *dwarf.ArrayType:
		et := p.dwarfMap[x.Type]
		n := et.size
		for i := int64(0); i < x.Count; i++ {
			p.typeObject(a.Add(i*n), et, r, add)
		}
	case *dwarf.StructType:
		for _, f := range x.Field {
			p.typeObject(a.Add(f.ByteOffset), p.dwarfMap[f.Type], r, add)
		}
	case *dwarf.TypedefType:
		p.typeObject(a, p.dwarfMap[x.Type], r, add)
	default:
		panic(fmt.Sprintf("unknown type %T\n", t.dt))
	}
}

// findRuntimeInfo uses DWARF information to find all the struct sizes,
// field offsets, and field types for runtime data structures.
// It populates p.rtStructs.
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
