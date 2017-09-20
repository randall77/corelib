package gocore

import (
	"debug/dwarf"
	"fmt"
	"strings"

	"github.com/randall77/corelib/core"
)

// Core takes a loaded core file and extracts Go information from it.
func Core(proc *core.Process) (p *Program, err error) {
	// Make sure we have DWARF info.
	if _, err := proc.DWARF(); err != nil {
		return nil, err
	}

	// Guard against failures of proc.Read* routines.
	/*
		defer func() {
			e := recover()
			if e == nil {
				return
			}
			p = nil
			if x, ok := e.(error); ok {
				err = x
				return
			}
			panic(e) // Not an error, re-panic it.
		}()
	*/

	p = &Program{
		proc:       proc,
		runtimeMap: map[core.Address]*Type{},
		dwarfMap:   map[dwarf.Type]*Type{},
	}

	// Initialize everything that just depends on DWARF.
	p.readDWARFTypes()
	p.readRuntimeConstants()
	p.readGlobals()

	// Find runtime globals we care about. Initialize regions for them.
	p.rtGlobals = map[string]region{}
	for _, g := range p.globals {
		if strings.HasPrefix(g.Name, "runtime.") {
			p.rtGlobals[g.Name[8:]] = region{p: p, a: g.Addr, typ: g.Type}
		}
	}

	// Read all the data that depends on runtime globals.
	p.buildVersion = p.rtGlobals["buildVersion"].String()
	p.readModules()
	p.readSpans()
	p.readMs()
	p.readGs()
	p.readStackVars()
	p.readObjects()
	p.typeHeap()

	return p, nil
}

func (p *Program) readSpans() {
	mheap := p.rtGlobals["mheap_"]

	spanTableStart := mheap.Field("spans").SlicePtr().Address()
	spanTableEnd := spanTableStart.Add(mheap.Field("spans").SliceCap() * p.proc.PtrSize())
	arenaStart := core.Address(mheap.Field("arena_start").Uintptr())
	arenaUsed := core.Address(mheap.Field("arena_used").Uintptr())
	arenaEnd := core.Address(mheap.Field("arena_end").Uintptr())
	bitmapEnd := core.Address(mheap.Field("bitmap").Uintptr())
	bitmapStart := bitmapEnd.Add(-int64(mheap.Field("bitmap_mapped").Uintptr()))

	p.arenaStart = arenaStart
	p.arenaUsed = arenaUsed
	p.bitmapEnd = bitmapEnd

	var all int64
	var text int64
	var readOnly int64
	var heap int64
	var spanTable int64
	var bitmap int64
	var data int64
	var bss int64 // also includes mmap'd regions
	for _, m := range p.proc.Mappings() {
		size := m.Size()
		all += size
		switch m.Perm() {
		case core.Read:
			readOnly += size
		case core.Read | core.Exec:
			text += size
		case core.Read | core.Write:
			if m.CopyOnWrite() {
				// Check if m.file == text's file? That could distinguish
				// data segment from mmapped file.
				data += size
				break
			}
			attribute := func(x, y core.Address, p *int64) {
				a := x.Max(m.Min())
				b := y.Min(m.Max())
				if a < b {
					*p += b.Sub(a)
					size -= b.Sub(a)
				}
			}
			attribute(spanTableStart, spanTableEnd, &spanTable)
			attribute(arenaStart, arenaEnd, &heap)
			attribute(bitmapStart, bitmapEnd, &bitmap)
			// Any other anonymous mapping is bss.
			// TODO: how to distinguish original bss from anonymous mmap?
			bss += size
		default:
			panic("weird mapping " + m.Perm().String())
		}
	}
	pageSize := p.rtConstants["_PageSize"]

	// Span types
	spanInUse := uint8(p.rtConstants["_MSpanInUse"])
	spanManual := uint8(p.rtConstants["_MSpanManual"])
	spanDead := uint8(p.rtConstants["_MSpanDead"])
	spanFree := uint8(p.rtConstants["_MSpanFree"])

	// Process spans.
	if pageSize%512 != 0 {
		panic("page size not a multiple of 512")
	}
	p.heapInfo = make([]heapInfo, (p.arenaUsed-p.arenaStart)/512)
	allspans := mheap.Field("allspans")
	var allSpanSize int64
	var freeSpanSize int64
	var manualSpanSize int64
	var inUseSpanSize int64
	var allocSize int64
	var freeSize int64
	var spanRoundSize int64
	var manualAllocSize int64
	var manualFreeSize int64
	n := allspans.SliceLen()
	for i := int64(0); i < n; i++ {
		s := allspans.SliceIndex(i).Deref()
		min := core.Address(s.Field("startAddr").Uintptr())
		elemSize := int64(s.Field("elemsize").Uintptr())
		nPages := int64(s.Field("npages").Uintptr())
		spanSize := nPages * pageSize
		max := min.Add(spanSize)
		allSpanSize += spanSize
		switch s.Field("state").Cast("uint8").Uint8() {
		case spanInUse:
			inUseSpanSize += spanSize
			n := int64(s.Field("nelems").Uintptr())
			// An object is allocated if it is marked as
			// allocated or it is below freeindex.
			x := s.Field("allocBits").Address()
			alloc := make([]bool, n)
			for i := int64(0); i < n; i++ {
				alloc[i] = p.proc.ReadUint8(x.Add(i/8))>>uint(i%8)&1 != 0
			}
			k := int64(s.Field("freeindex").Uintptr())
			for i := int64(0); i < k; i++ {
				alloc[i] = true
			}
			for i := int64(0); i < n; i++ {
				if alloc[i] {
					allocSize += elemSize
				} else {
					freeSize += elemSize
				}
			}
			spanRoundSize += spanSize - n*elemSize
			for a := min; a < max; a += 512 {
				p.heapInfo[(a.Sub(p.arenaStart))/512] = heapInfo{base: min, size: elemSize, firstIdx: -1}
			}

		case spanFree:
			freeSpanSize += spanSize
		case spanDead:
			// These are just deallocated span descriptors. They use no heap.
		case spanManual:
			manualSpanSize += spanSize
			manualAllocSize += spanSize
			for x := core.Address(s.Field("manualFreeList").Cast("uintptr").Uintptr()); x != 0; x = p.proc.ReadPtr(x) {
				manualAllocSize -= elemSize
				manualFreeSize += elemSize
			}
		}
	}

	p.stats = &Stats{"all", all, []*Stats{
		&Stats{"text", text, nil},
		&Stats{"readonly", readOnly, nil},
		&Stats{"data", data, nil},
		&Stats{"bss", bss, nil},
		&Stats{"heap", heap, []*Stats{
			&Stats{"in use spans", inUseSpanSize, []*Stats{
				&Stats{"alloc", allocSize, nil},
				&Stats{"free", freeSize, nil},
				&Stats{"round", spanRoundSize, nil},
			}},
			&Stats{"manual spans", manualSpanSize, []*Stats{
				&Stats{"alloc", manualAllocSize, nil},
				&Stats{"free", manualFreeSize, nil},
			}},
			&Stats{"free spans", freeSpanSize, nil},
		}},
		&Stats{"ptr bitmap", bitmap, nil},
		&Stats{"span table", spanTable, nil},
	}}

	var check func(*Stats)
	check = func(s *Stats) {
		if len(s.Children) == 0 {
			return
		}
		var sum int64
		for _, c := range s.Children {
			sum += c.Size
		}
		if sum != s.Size {
			panic(fmt.Sprintf("check failed for %s: %d vs %d", s.Name, s.Size, sum))
		}
	}
	check(p.stats)
}

func (p *Program) readModules() {
	ms := p.rtGlobals["modulesSlice"].Cast("*[]*runtime.moduledata").Deref()
	n := ms.SliceLen()
	for i := int64(0); i < n; i++ {
		md := ms.SliceIndex(i).Deref()
		p.modules = append(p.modules, p.readModule(md))
	}
}

func (p *Program) readModule(r region) *module {
	m := &module{r: r}
	m.types = core.Address(r.Field("types").Uintptr())
	m.etypes = core.Address(r.Field("etypes").Uintptr())

	// Read the pc->function table
	pcln := r.Field("pclntable")
	ftab := r.Field("ftab")
	n := ftab.SliceLen() - 1 // last slot is a dummy, just holds entry
	for i := int64(0); i < n; i++ {
		ft := ftab.SliceIndex(i)
		min := core.Address(ft.Field("entry").Uintptr())
		max := core.Address(ftab.SliceIndex(i + 1).Field("entry").Uintptr())
		fr := pcln.SliceIndex(int64(ft.Field("funcoff").Uintptr())).Cast("runtime._func")
		f := m.readFunc(fr, pcln)
		if f.entry != min {
			panic(fmt.Errorf("entry %x and min %x don't match for %s", f.entry, min, f.name))
		}
		p.funcTab.add(min, max, f)
	}

	return m
}

func equal(a, b []int64) bool {
	if len(a) != len(b) {
		return false
	}
	for i, x := range a {
		if x != b[i] {
			return false
		}
	}
	return true
}

// ptrs returns a sorted list of pointer offsets in t.
func (t *Type) ptrs() []int64 {
	return t.ptrs1(nil, 0)
}
func (t *Type) ptrs1(s []int64, off int64) []int64 {
	switch t.Kind {
	case KindPtr, KindFunc, KindSlice, KindString:
		s = append(s, off)
	case KindIface, KindEface:
		s = append(s, off, off+t.Size/2)
	case KindArray:
		if t.Count > 10000 {
			// TODO: fix this. Have a nopointers field?
			break
		}
		for i := int64(0); i < t.Count; i++ {
			s = t.Elem.ptrs1(s, off)
			off += t.Elem.Size
		}
	case KindStruct:
		for _, f := range t.Fields {
			s = f.Type.ptrs1(s, off+f.Off)
		}
	default:
		// no pointers
	}
	return s
}

// Convert the address of a runtime._type to a *Type.
// Guaranteed to return a non-nil *Type.
func (p *Program) runtimeType2Type(a core.Address) *Type {
	if t := p.runtimeMap[a]; t != nil {
		return t
	}
	ptrSize := p.proc.PtrSize()

	// Read runtime._type.size
	r := region{p: p, a: a, typ: p.findType("runtime._type")}
	size := int64(r.Field("size").Uintptr())

	// Find module this type is in.
	var m *module
	for _, x := range p.modules {
		if x.types <= a && a < x.etypes {
			m = x
			break
		}
	}

	// Read information out of the runtime._type.
	var name string
	if m != nil {
		x := m.types.Add(int64(r.Field("str").Cast("int32").Int32()))
		n := uint16(p.proc.ReadUint8(x.Add(1)))<<8 + uint16(p.proc.ReadUint8(x.Add(2)))
		b := make([]byte, n)
		p.proc.ReadAt(b, x.Add(3))
		name = string(b)
	} else {
		// A reflect-generated type.
		// TODO: The actual name is in the runtime.reflectOffs map.
		// Too hard to look things up in maps here, just allocate a placeholder for now.
		name = fmt.Sprintf("reflect.generated%x", a)
	}
	if r.Field("tflag").Cast("uint8").Uint8()&uint8(p.rtConstants["tflagExtraStar"]) != 0 {
		name = name[1:]
	}

	// Read ptr/nonptr bits
	nptrs := int64(r.Field("ptrdata").Uintptr()) / ptrSize
	var ptrs []int64
	if r.Field("kind").Uint8()&uint8(p.rtConstants["kindGCProg"]) == 0 {
		gcdata := r.Field("gcdata").Address()
		for i := int64(0); i < nptrs; i++ {
			if p.proc.ReadUint8(gcdata.Add(i/8))>>uint(i%8)&1 != 0 {
				ptrs = append(ptrs, i*ptrSize)
			}
		}
	} else {
		// TODO: run GC program to get ptr indexes
	}

	// Find a Type that matches this type.
	// (The matched type will be one constructed from DWARF info.)
	// It must match name, size, and pointer bits.
	var candidates []*Type
	for _, t := range p.runtimeNameMap[name] {
		if size == t.Size && equal(ptrs, t.ptrs()) {
			candidates = append(candidates, t)
		}
	}
	var t *Type
	if len(candidates) > 0 {
		// If a runtime type matches more than one DWARF type,
		// pick one arbitrarily.
		// This looks mostly harmless. DWARF has some redundant entries.
		// For example, [32]uint8 appears twice.
		// TODO: investigate the reason for this duplication.
		t = candidates[0]
	} else {
		// There's no corresponding DWARF type.  Make our own.
		t = &Type{name: name, Size: size, Kind: KindStruct}
		n := t.Size / ptrSize

		// Types to use for ptr/nonptr fields of runtime types which
		// have no corresponding DWARF type.
		ptr := p.findType("unsafe.Pointer")
		nonptr := p.findType("uintptr")
		if ptr == nil || nonptr == nil {
			panic("ptr / nonptr standins missing")
		}

		for i := int64(0); i < n; i++ {
			typ := nonptr
			if len(ptrs) > 0 && ptrs[0] == i*ptrSize {
				typ = ptr
				ptrs = ptrs[1:]
			}
			t.Fields = append(t.Fields, Field{
				Name: fmt.Sprintf("f%d", i),
				Off:  i * ptrSize,
				Type: typ,
			})

		}
		if t.Size%ptrSize != 0 {
			// TODO: tail of <ptrSize data.
		}
	}
	// Memoize.
	p.runtimeMap[a] = t

	return t
}

// readFunc parses a runtime._func and returns a *Func.
// r must have type runtime._func.
// pcln must have type []byte and represent the module's pcln table region.
func (m *module) readFunc(r region, pcln region) *Func {
	f := &Func{module: m, r: r}
	f.entry = core.Address(r.Field("entry").Uintptr())
	f.name = r.p.proc.ReadCString(pcln.SliceIndex(int64(r.Field("nameoff").Int32())).a)
	f.frameSize.read(r.p.proc, pcln.SliceIndex(int64(r.Field("pcsp").Int32())).a)

	// Parse pcdata and funcdata, which are laid out beyond the end of the _func.
	a := r.a.Add(int64(r.p.findType("runtime._func").Size))
	n := r.Field("npcdata").Int32()
	for i := int32(0); i < n; i++ {
		f.pcdata = append(f.pcdata, r.p.proc.ReadInt32(a))
		a = a.Add(4)
	}
	a = a.Align(r.p.proc.PtrSize())
	n = r.Field("nfuncdata").Int32()
	for i := int32(0); i < n; i++ {
		f.funcdata = append(f.funcdata, r.p.proc.ReadPtr(a))
		a = a.Add(r.p.proc.PtrSize())
	}

	// Read pcln tables we need.
	if stackmap := int(r.p.rtConstants["_PCDATA_StackMapIndex"]); stackmap < len(f.pcdata) {
		f.stackMap.read(r.p.proc, pcln.SliceIndex(int64(f.pcdata[stackmap])).a)
	}

	return f
}

// pcdata returns the address of the nth pcdata table for r.
// r must have type runtime._func.
// pcln must have type []byte and represent the module's pcln table region.
func pcdata(r region, pcln region, n int64) core.Address {
	if n >= int64(r.Field("npcdata").Int32()) {
		return 0
	}
	a := r.a.Add(int64(r.p.findType("runtime._func").Size + 4*n))

	off := r.p.proc.ReadInt32(a)
	return pcln.SliceIndex(int64(off)).a
}

// funcdata returns the nth funcdata pointer.
// r must be a region for a runtime._func.
func funcdata(r region, n int64) core.Address {
	if n >= int64(r.Field("nfuncdata").Int32()) {
		return 0
	}
	x := r.Field("npcdata").Int32()
	if x&1 != 0 && r.p.proc.PtrSize() == 8 {
		x++
	}
	a := r.a.Add(int64(r.p.findType("runtime._func").Size + 4*int64(x) + r.p.proc.PtrSize()*n))
	return r.p.proc.ReadPtr(a)
}

func (p *Program) readMs() {
	mp := p.rtGlobals["allm"]
	for mp.Address() != 0 {
		m := mp.Deref()
		gs := m.Field("gsignal")
		if gs.Address() != 0 {
			g := gs.Deref()
			_ = g
			// TODO: need to do something here?
		}
		mp = m.Field("alllink")
	}
}

func (p *Program) readGs() {
	// TODO: figure out how to "flush" running Gs.
	allgs := p.rtGlobals["allgs"]
	n := allgs.SliceLen()
	for i := int64(0); i < n; i++ {
		r := allgs.SliceIndex(i).Deref()
		g := p.readG(r)
		if g == nil {
			continue
		}
		p.goroutines = append(p.goroutines, g)
	}
}

func (p *Program) readG(r region) *Goroutine {
	g := &Goroutine{r: r}
	stk := r.Field("stack")
	g.stackSize = int64(stk.Field("hi").Uintptr() - stk.Field("lo").Uintptr())

	var osT *core.Thread // os thread working on behalf of this G (if any).
	mp := r.Field("m")
	if mp.Address() != 0 {
		m := mp.Deref()
		pid := m.Field("procid").Uint64()
		// TODO check that m.curg points to g?
		for _, t := range p.proc.Threads() {
			if t.Pid() == pid {
				osT = t
			}
		}
	}
	status := r.Field("atomicstatus").Uint32()
	status &^= uint32(p.rtConstants["_Gscan"])
	var sp, pc core.Address
	switch {
	case status == uint32(p.rtConstants["_Gidle"]):
		return g
	case status == uint32(p.rtConstants["_Grunnable"]):
		sched := r.Field("sched")
		sp = core.Address(sched.Field("sp").Uintptr())
		pc = core.Address(sched.Field("pc").Uintptr())
	case status == uint32(p.rtConstants["_Grunning"]):
		sp = osT.SP()
		pc = osT.PC()
		// TODO: back up to the calling frame?
	case status == uint32(p.rtConstants["_Gsyscall"]):
		sp = core.Address(r.Field("syscallsp").Uintptr())
		pc = core.Address(r.Field("syscallpc").Uintptr())
		// TODO: or should we use the osT registers?
	case status == uint32(p.rtConstants["_Gwaiting"]):
		sched := r.Field("sched")
		sp = core.Address(sched.Field("sp").Uintptr())
		pc = core.Address(sched.Field("pc").Uintptr())
	case status == uint32(p.rtConstants["_Gdead"]):
		return nil
		// TODO: copystack, others?
	}
	for {
		f := p.readFrame(sp, pc)
		if f.f.name == "runtime.goexit" {
			break
		}
		g.frames = append(g.frames, f)

		if f.f.name == "runtime.sigtrampgo" {
			// Continue traceback at location where the signal
			// interrupted normal execution.
			ctxt := p.proc.ReadPtr(sp.Add(16)) // 3rd arg
			//ctxt is a *ucontext
			mctxt := ctxt.Add(5 * 8)
			// mctxt is a *mcontext
			sp = p.proc.ReadPtr(mctxt.Add(15 * 8))
			pc = p.proc.ReadPtr(mctxt.Add(16 * 8))
			// TODO: totally arch-dependent!
		} else {
			sp = f.max
			pc = core.Address(p.proc.ReadUintptr(sp - 8)) // TODO:amd64 only
		}
		if pc == 0 {
			// TODO: when would this happen?
			break
		}
		if f.f.name == "runtime.systemstack" {
			// switch over to goroutine stack
			sched := r.Field("sched")
			sp = core.Address(sched.Field("sp").Uintptr())
			pc = core.Address(sched.Field("pc").Uintptr())
		}
	}
	return g
}

func (p *Program) readFrame(sp, pc core.Address) *Frame {
	f := p.funcTab.find(pc)
	if f == nil {
		panic(fmt.Errorf("  pc not found %x\n", pc))
	}
	off := pc.Sub(f.entry)
	size := f.frameSize.find(off)
	size += p.proc.PtrSize() // TODO: on amd64, the pushed return address

	frame := &Frame{f: f, pc: pc, min: sp, max: sp.Add(size)}

	// Find live ptrs in locals
	live := map[core.Address]bool{}
	if x := int(p.rtConstants["_FUNCDATA_LocalsPointerMaps"]); x < len(f.funcdata) {
		locals := region{p: p, a: f.funcdata[x], typ: p.findType("runtime.stackmap")}
		n := locals.Field("n").Int32()       // # of bitmaps
		nbit := locals.Field("nbit").Int32() // # of bits per bitmap
		idx := f.stackMap.find(off)
		if idx < 0 {
			idx = 0
		}
		if idx < int64(n) {
			bits := locals.Field("bytedata").a.Add(int64(nbit+7) / 8 * idx)
			base := frame.max.Add(-16).Add(-int64(nbit) * p.proc.PtrSize())
			// TODO: -16 for amd64. Return address and parent's frame pointer
			for i := int64(0); i < int64(nbit); i++ {
				if p.proc.ReadUint8(bits.Add(i/8))>>uint(i&7)&1 != 0 {
					live[base.Add(i*p.proc.PtrSize())] = true
				}
			}
		}
	}
	// Same for args
	if x := int(p.rtConstants["_FUNCDATA_ArgsPointerMaps"]); x < len(f.funcdata) {
		args := region{p: p, a: f.funcdata[x], typ: p.findType("runtime.stackmap")}
		n := args.Field("n").Int32()       // # of bitmaps
		nbit := args.Field("nbit").Int32() // # of bits per bitmap
		idx := f.stackMap.find(off)
		if idx < 0 {
			idx = 0
		}
		if idx < int64(n) {
			bits := args.Field("bytedata").a.Add(int64(nbit+7) / 8 * idx)
			base := frame.max
			// TODO: add to base for LR archs.
			for i := int64(0); i < int64(nbit); i++ {
				if p.proc.ReadUint8(bits.Add(i/8))>>uint(i&7)&1 != 0 {
					live[base.Add(i*p.proc.PtrSize())] = true
				}
			}
		}
	}
	frame.live = live

	return frame
}
