package gocore

import (
	"debug/dwarf"
	"fmt"
	"os"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/randall77/corelib/core"
	"github.com/randall77/corelib/rtinfo"
)

// Core takes a loaded core file and extracts Go information from it.
func Core(proc *core.Process) (p *Program, err error) {
	// Check symbol table to make sure we know the addresses
	// of some critical runtime data structures.
	m, err := proc.Symbols()
	if err != nil {
		return nil, err
	}
	for _, s := range rtSymbols {
		if m["runtime."+s.name] == 0 {
			// We're missing some address that we need.
			return nil, fmt.Errorf("can't find runtime data structure %s. Is the binary unstripped?", s.name)
		}
	}
	// TODO: is the symbol table redundant with the DWARF info? Could we just use DWARF?

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

	// Load the build version.
	a := m["runtime.buildVersion"]
	ptr := proc.ReadAddress(a)
	len := proc.ReadInt(a.Add(proc.PtrSize()))
	b := make([]byte, len)
	proc.ReadAt(b, ptr)
	version := string(b)
	fmt.Printf("buildVersion %s\n", version)

	// Build context with runtime information.
	// TODO: use DWARF info instead. Not known yet, how to use
	// dwarf info to find runtime constants.
	info := rtinfo.Find(proc.Arch(), version)
	if info.Structs == nil {
		return nil, fmt.Errorf("no runtime info for %s:%s", proc.Arch(), version)
	}
	c := &context{proc: proc, info: info}
	p.info = info

	// Initialize runtime regions.
	p.runtime = map[string]region{}
	for _, s := range rtSymbols {
		p.runtime[s.name] = region{c: c, a: m["runtime."+s.name], typ: s.typ}
	}

	p.readDWARFTypes()
	p.readModules()
	p.readSpans()
	p.readMs()
	p.readGs()
	p.readObjects()
	p.typeHeap()
	return
}

// rtSymbols is a list of all the runtime globals that we need to access,
// together with their types.
var rtSymbols = [...]struct {
	name, typ string
}{
	{"mheap_", "runtime.mheap"},
	{"memstats", "runtime.mstats"},
	{"sched", "runtime.schedt"},
	{"allfin", "*runtime.finblock"},
	{"finq", "*runtime.finblock"},
	{"allgs", "[]*runtime.g"},
	{"allm", "*runtime.m"},
	{"allp", "[1]*p"}, // TODO: type depends on _MaxGomaxprocs
	{"modulesSlice", "*[]*runtime.moduledata"},
	{"buildVersion", "string"},
}

func (g *Program) readSpans() {
	mheap := g.runtime["mheap_"]
	c := mheap.c

	spanTableStart := mheap.Field("spans").SlicePtr().Address()
	spanTableEnd := spanTableStart.Add(mheap.Field("spans").SliceCap() * g.proc.PtrSize())
	arenaStart := core.Address(mheap.Field("arena_start").Uintptr())
	arenaEnd := core.Address(mheap.Field("arena_end").Uintptr())
	bitmapEnd := core.Address(mheap.Field("bitmap").Uintptr())
	bitmapStart := bitmapEnd.Add(-int64(mheap.Field("bitmap_mapped").Uintptr()))

	g.arenaStart = arenaStart
	g.bitmapEnd = bitmapEnd

	var all int64
	var text int64
	var readOnly int64
	var heap int64
	var spanTable int64
	var bitmap int64
	var data int64
	var bss int64 // also includes mmap'd regions
	for _, m := range g.proc.Mappings() {
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
	pageSize := c.info.Constants["_PageSize"]

	// Span types
	spanInUse := uint8(c.info.Constants["_MSpanInUse"])
	spanManual := uint8(c.info.Constants["_MSpanManual"])
	spanDead := uint8(c.info.Constants["_MSpanDead"])
	spanFree := uint8(c.info.Constants["_MSpanFree"])

	// Process spans.
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
			p := s.Field("allocBits").Address()
			alloc := make([]bool, n)
			for i := int64(0); i < n; i++ {
				alloc[i] = g.proc.ReadUint8(p.Add(i/8))>>uint(i%8)&1 != 0
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
			g.spans = append(g.spans, span{min: min, max: max, size: elemSize})
		case spanFree:
			freeSpanSize += spanSize
		case spanDead:
			// These are just deallocated span descriptors. They use no heap.
		case spanManual:
			manualSpanSize += spanSize
			manualAllocSize += spanSize
			for p := core.Address(s.Field("manualFreeList").Cast("uintptr").Uintptr()); p != 0; p = g.proc.ReadAddress(p) {
				manualAllocSize -= elemSize
				manualFreeSize += elemSize
			}
		}
	}
	t := tabwriter.NewWriter(os.Stdout, 0, 8, 1, ' ', 0)

	pr := func(n int, name string, value int64, comment ...string) {
		vstr := fmt.Sprintf("%d", value)
		for len(vstr) < 14 {
			vstr = " " + vstr
		}
		for i := 0; i < n; i++ {
			name = "  " + name
		}
		fmt.Fprintf(t, "%s\t%s\t%6.2f%%\t%s\n", name, vstr, float64(value)*100/float64(all), strings.Join(comment, " "))
	}

	pr(0, "all", all)
	pr(1, "text", text)
	pr(1, "readonly", readOnly)
	pr(1, "data", data)
	pr(1, "bss", bss, "(grab bag, includes OS stacks, ...)")
	pr(1, "heap", heap)
	pr(2, "in use spans", inUseSpanSize)
	pr(3, "alloc", allocSize)
	pr(3, "free", freeSize)
	pr(3, "round", spanRoundSize)
	pr(2, "manual spans", manualSpanSize, "(Go stacks)")
	pr(3, "alloc", manualAllocSize)
	pr(3, "free", manualFreeSize)
	pr(2, "free spans", freeSpanSize)
	pr(1, "ptr bitmap", bitmap)
	pr(1, "span table", spanTable)
	t.Flush()
	if got := text + readOnly + data + bss + heap + bitmap + spanTable; got != all {
		panic(fmt.Sprintf("missing from all=%d got=%d", all, got))
	}
	if got := inUseSpanSize + manualSpanSize + freeSpanSize; got != heap {
		panic(fmt.Sprintf("missing from heap=%d got=%d", heap, got))
	}
	if got := allocSize + freeSize + spanRoundSize; got != inUseSpanSize {
		panic(fmt.Sprintf("missing from inuse=%d got=%d", inUseSpanSize, got))
	}
	if got := manualAllocSize + manualFreeSize; got != manualSpanSize {
		panic(fmt.Sprintf("missing from manual=%d got=%d", manualSpanSize, got))
	}

	// sort spans for later binary search.
	sort.Slice(g.spans, func(i, j int) bool {
		return g.spans[i].min < g.spans[j].min
	})
}

func (g *Program) readModules() {
	// Make a runtime name -> Type map for existing DWARF types.
	dwarf := map[string][]*Type{}
	for _, t := range g.types {
		name := runtimeName(t.dt)
		dwarf[name] = append(dwarf[name], t)
	}

	ms := g.runtime["modulesSlice"].Deref()
	n := ms.SliceLen()
	for i := int64(0); i < n; i++ {
		md := ms.SliceIndex(i).Deref()
		g.modules = append(g.modules, g.readModule(md, dwarf))
	}
}

func (g *Program) readModule(r region, dwarf map[string][]*Type) *module {
	m := &module{r: r}
	//fmt.Printf("module %s %x %x\n", r.Field("modulename").String(), r.Field("text").Uintptr(), r.Field("etext").Uintptr())
	gcdata := r.Field("gcdatamask")
	gcbss := r.Field("gcbssmask")
	_ = gcdata
	_ = gcbss
	pcln := r.Field("pclntable")

	// Read the pc->function table
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
		g.funcTab.add(min, max, f)
	}

	// Read the types in this module.
	types := core.Address(r.Field("types").Uintptr())
	typelinks := r.Field("typelinks")
	ntypelinks := typelinks.SliceLen()
	for i := int64(0); i < ntypelinks; i++ {
		off := typelinks.SliceIndex(i).Int32()
		r := region{c: r.c, a: types.Add(int64(off)), typ: "runtime._type"}
		size := int64(r.Field("size").Uintptr())
		p := types.Add(int64(r.Field("str").Cast("int32").Int32()))
		n := uint16(g.proc.ReadUint8(p.Add(1)))<<8 + uint16(g.proc.ReadUint8(p.Add(2)))
		b := make([]byte, n)
		g.proc.ReadAt(b, p.Add(3))
		name := string(b)
		if r.Field("tflag").Cast("uint8").Uint8()&uint8(g.info.Constants["tflagExtraStar"]) != 0 {
			name = name[1:]
		}
		// Read ptr/noptr bits
		nptrs := int64(r.Field("ptrdata").Uintptr()) / g.proc.PtrSize()
		ptrs := make([]bool, nptrs)
		if r.Field("kind").Uint8()&uint8(g.info.Constants["kindGCProg"]) == 0 {
			gcdata := r.Field("gcdata").Address()
			for i := int64(0); i < nptrs; i++ {
				ptrs[i] = g.proc.ReadUint8(gcdata.Add(i/8))>>uint(i%8)&1 != 0
			}
		} else {
			// TODO: run GC program to get bits
		}
		// Trim trailing false entries.
		for len(ptrs) > 0 && !ptrs[len(ptrs)-1] {
			ptrs = ptrs[:len(ptrs)-1]
		}

		// Find dwarf entry corresponding to this one, if any.
		// It must match name, size, and pointer bits.
		var candidates []*Type
		for _, t := range dwarf[name] {
			if t.r.a == 0 && size == t.size && boolEqual(ptrs, t.ptrs) {
				candidates = append(candidates, t)
			}
		}
		if len(candidates) > 1 {
			//fmt.Printf("runtime type %s ambiguous. Could be:\n", name)
			//for _, t := range candidates {
			//	fmt.Printf("  %s %T\n", t.name, t.dt)
			//}
			// This looks mostly harmless. DWARF has some redundant entries.
			// For example, [32]uint8 appears twice.
			// TODO: investigate the reason for this duplication.
		}
		var t *Type
		if len(candidates) > 0 {
			t = candidates[0]
			t.r = r
		} else {
			// There's no corresponding DWARF type.  Make our own.
			t = &Type{r: r, name: name, size: size, ptrs: ptrs}
			// TODO: add fields:?
			g.types = append(g.types, t)
			//fmt.Printf("rtonly type %s %d\n", name, size)
		}
		g.runtimeMap[r.a] = t
	}

	return m
}

// readFunc parses a runtime._func and returns a *Func.
// r must have type runtime._func.
// pcln must have type []byte and represent the module's pcln table region.
func (m *module) readFunc(r region, pcln region) *Func {
	f := &Func{module: m, r: r}
	f.entry = core.Address(r.Field("entry").Uintptr())
	f.name = r.c.proc.ReadCString(pcln.SliceIndex(int64(r.Field("nameoff").Int32())).a)
	//fmt.Printf("%x %s\n", f.entry, f.name)
	f.frameSize.read(r.c.proc, pcln.SliceIndex(int64(r.Field("pcsp").Int32())).a)

	// Parse pcdata and funcdata, which are laid out beyond the end of the _func.
	a := r.a.Add(int64(r.c.info.Structs["runtime._func"].Size))
	n := r.Field("npcdata").Int32()
	for i := int32(0); i < n; i++ {
		f.pcdata = append(f.pcdata, r.c.proc.ReadInt32(a))
		a = a.Add(4)
	}
	a = a.Align(r.c.proc.PtrSize())
	n = r.Field("nfuncdata").Int32()
	for i := int32(0); i < n; i++ {
		f.funcdata = append(f.funcdata, r.c.proc.ReadAddress(a))
		a = a.Add(r.c.proc.PtrSize())
	}

	// Read pcln tables we need.
	if stackmap := int(r.c.info.Constants["_PCDATA_StackMapIndex"]); stackmap < len(f.pcdata) {
		f.stackMap.read(r.c.proc, pcln.SliceIndex(int64(f.pcdata[stackmap])).a)
	}

	//fmt.Printf("  %v\n", f.stackMap)
	return f
}

// pcdata returns the address of the nth pcdata table for r.
// r must have type runtime._func.
// pcln must have type []byte and represent the module's pcln table region.
func pcdata(r region, pcln region, n int64) core.Address {
	if n >= int64(r.Field("npcdata").Int32()) {
		return 0
	}
	a := r.a.Add(int64(r.c.info.Structs["runtime._func"].Size + 4*n))

	off := r.c.proc.ReadInt32(a)
	return pcln.SliceIndex(int64(off)).a
}

// funcdata returns the nth funcdata pointer.
// r must be a region for a runtime._func.
func funcdata(r region, n int64) core.Address {
	if n >= int64(r.Field("nfuncdata").Int32()) {
		return 0
	}
	x := r.Field("npcdata").Int32()
	if x&1 != 0 && r.c.proc.PtrSize() == 8 {
		x++
	}
	a := r.a.Add(int64(r.c.info.Structs["runtime._func"].Size + 4*int64(x) + r.c.proc.PtrSize()*n))
	return r.c.proc.ReadAddress(a)
}

func (g *Program) readMs() {
	mp := g.runtime["allm"]
	for mp.Address() != 0 {
		m := mp.Deref()
		//fmt.Printf("M: %d\n", m.Field("procid").Uint64())
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
	allgs := p.runtime["allgs"]
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

func (prog *Program) readG(r region) *Goroutine {
	g := &Goroutine{r: r}
	stk := r.Field("stack")
	g.stackSize = int64(stk.Field("hi").Uintptr() - stk.Field("lo").Uintptr())

	var osT *core.Thread // os thread working on behalf of this G (if any).
	mp := r.Field("m")
	if mp.Address() != 0 {
		m := mp.Deref()
		pid := m.Field("procid").Uint64()
		// TODO check that m.curg points to g?
		for _, t := range prog.proc.Threads() {
			if t.Pid() == pid {
				osT = t
			}
		}
	}
	//fmt.Printf("grunning: %d\n", prog.info.Constants["_Grunning"])
	//fmt.Printf("gsyscall: %d\n", prog.info.Constants["_Gsyscall"])
	//fmt.Printf("gwaiting: %d\n", prog.info.Constants["_Gwaiting"])
	status := r.Field("atomicstatus").Uint32()
	status &^= uint32(prog.info.Constants["_Gscan"])
	var sp, pc core.Address
	switch {
	case status == uint32(prog.info.Constants["_Gidle"]):
		return g
	case status == uint32(prog.info.Constants["_Grunnable"]):
		sched := r.Field("sched")
		sp = core.Address(sched.Field("sp").Uintptr())
		pc = core.Address(sched.Field("pc").Uintptr())
	case status == uint32(prog.info.Constants["_Grunning"]):
		regs := osT.Regs()
		// or 9? or 4?
		sp = core.Address(regs[19]) // TODO: how are these offsets possibly right?
		pc = core.Address(regs[11])
		// TODO: back up to the calling frame?
	case status == uint32(prog.info.Constants["_Gsyscall"]):
		sp = core.Address(r.Field("syscallsp").Uintptr())
		pc = core.Address(r.Field("syscallpc").Uintptr())
		// TODO: or should we use the osT registers?
	case status == uint32(prog.info.Constants["_Gwaiting"]):
		sched := r.Field("sched")
		sp = core.Address(sched.Field("sp").Uintptr())
		pc = core.Address(sched.Field("pc").Uintptr())
		// TODO: copystack, others?
	case status == uint32(prog.info.Constants["_Gdead"]):
		return nil
	}
	//fmt.Printf("G %d lo=%x sp=%x hi=%x pc=%x\n", status, stk.Field("lo").Uintptr(), sp, stk.Field("hi").Uintptr(), pc)
	for {
		f := prog.readFrame(r.c, sp, pc)
		if f.f.name == "runtime.goexit" {
			break
		}
		g.frames = append(g.frames, f)

		if f.f.name == "runtime.sigtrampgo" {
			// Continue traceback at location where the signal
			// interrupted normal execution.
			ctxt := prog.proc.ReadAddress(sp.Add(16)) // 3rd arg
			//ctxt is a *ucontext
			mctxt := ctxt.Add(5 * 8)
			// mctxt is a *mcontext
			sp = prog.proc.ReadAddress(mctxt.Add(15 * 8))
			pc = prog.proc.ReadAddress(mctxt.Add(16 * 8))
			// TODO: totally arch-dependent!
		} else {
			sp = f.max
			pc = core.Address(prog.proc.ReadUintptr(sp - 8)) // TODO:amd64 only
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

func (prog *Program) readFrame(c *context, sp, pc core.Address) *Frame {
	f := prog.funcTab.find(pc)
	if f == nil {
		panic(fmt.Errorf("  pc not found %x\n", pc))
	}
	off := pc.Sub(f.entry)
	size := f.frameSize.find(off)
	size += prog.proc.PtrSize() // TODO: on amd64, the pushed return address

	frame := &Frame{f: f, off: off, min: sp, max: sp.Add(size)}
	//fmt.Printf("%s %x\n", f.name, size)

	// Find live ptrs in locals
	if x := int(prog.info.Constants["_FUNCDATA_LocalsPointerMaps"]); x < len(f.funcdata) {
		locals := region{c: c, a: f.funcdata[x], typ: "runtime.stackmap"}
		n := locals.Field("n").Int32()       // # of bitmaps
		nbit := locals.Field("nbit").Int32() // # of bits per bitmap
		idx := f.stackMap.find(off)
		if idx < 0 {
			idx = 0
		}
		if idx < int64(n) {
			bits := locals.Field("bytedata").a.Add(int64(nbit+7) / 8 * idx)
			base := frame.max.Add(-16).Add(-int64(nbit) * prog.proc.PtrSize())
			// TODO: -16 for amd64. Return address and parent's frame pointer
			for i := int64(0); i < int64(nbit); i++ {
				if prog.proc.ReadUint8(bits.Add(i/8))>>uint(i&7)&1 != 0 {
					frame.ptrs = append(frame.ptrs, base.Add(i*prog.proc.PtrSize()))
				}
			}
		}
	}
	// Same for args
	if x := int(prog.info.Constants["_FUNCDATA_ArgsPointerMaps"]); x < len(f.funcdata) {
		args := region{c: c, a: f.funcdata[x], typ: "runtime.stackmap"}
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
				if prog.proc.ReadUint8(bits.Add(i/8))>>uint(i&7)&1 != 0 {
					frame.ptrs = append(frame.ptrs, base.Add(i*prog.proc.PtrSize()))
				}
			}
		}
	}

	return frame
}

func boolEqual(a, b []bool) bool {
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
