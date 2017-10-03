package gocore

import (
	"debug/dwarf"

	"github.com/randall77/corelib/core"
)

type Flags uint8

const (
	FlagTypes Flags = 1 << iota
	FlagReverse
)

type Program struct {
	proc *core.Process

	arenaStart core.Address
	arenaUsed  core.Address
	bitmapEnd  core.Address

	heapInfo []heapInfo

	// number of live objects
	nObj int

	goroutines []*Goroutine

	// runtime info
	rtGlobals   map[string]region
	rtConstants map[string]int64

	// A module is a loadable unit. Most Go programs have 1, programs
	// which load plugins will have more.
	modules []*module

	// address -> function mapping
	funcTab funcTab

	// map from dwarf type to *Type
	dwarfMap map[dwarf.Type]*Type

	// map from address of runtime._type to *Type
	runtimeMap map[core.Address]*Type

	// map from runtime type name to the set of *Type with that name
	// Used to find candidates to put in the runtimeMap map.
	runtimeNameMap map[string][]*Type

	// memory usage by category
	stats *Stats

	buildVersion string

	globals []*Root

	// Types of each object, indexed by object index.
	// Only initialized if FlagTypes is passed to Core.
	types []typeInfo

	// Reverse edges. reverse[i] contains all the locations
	// where a pointer to object #i resides.
	// Only initialized if FlagReverse is passed to Core.
	reverse [][]core.Address
	// Sorted list of all roots.
	// Only initialized if FlagReverse is passed to Core.
	rootIdx []*Root
}

// Process returns the core.Process used to construct this Program.
func (p *Program) Process() *core.Process {
	return p.proc
}

func (p *Program) Goroutines() []*Goroutine {
	return p.goroutines
}

// Stats returns a breakdown of the program's memory use by category.
func (p *Program) Stats() *Stats {
	return p.stats
}

// BuildVersion returns the Go version that was used to build the inferior binary.
func (p *Program) BuildVersion() string {
	return p.buildVersion
}

func (p *Program) Globals() []*Root {
	return p.globals
}

// FindFunc returns the function which contains the code at address pc, if any.
func (p *Program) FindFunc(pc core.Address) *Func {
	return p.funcTab.find(pc)
}

func (p *Program) findType(name string) *Type {
	s := p.runtimeNameMap[name]
	if len(s) == 0 {
		panic("can't find type " + name)
	}
	return s[0]
}

type Goroutine struct {
	r         region // inferior region holding the runtime.g
	stackSize int64  // current stack allocation
	frames    []*Frame

	// TODO: defers, in-progress panics
}

// Stack returns the total allocated stack for g.
func (g *Goroutine) Stack() int64 {
	return g.stackSize
}

// Addr returns the address of the runtime.g that identifies this goroutine.
func (g *Goroutine) Addr() core.Address {
	return g.r.a
}

// Frames returns the list of frames on the stack of the Goroutine.
// The first frame is the most recent one.
// This list is post-optimization, so any inlined calls, tail calls, etc.
// will not appear.
func (g *Goroutine) Frames() []*Frame {
	return g.frames
}

type Frame struct {
	f        *Func        // function whose activation record this frame is
	pc       core.Address // resumption point
	min, max core.Address // extent of stack frame

	// Set of locations that contain a live pointer. Note that this set
	// may contain locations outside the frame (in particular, the args
	// for the frame).
	live map[core.Address]bool

	roots []*Root

	// TODO: keep vars from dwarf around?
}

// Func returns the function for which this frame is an activation record.
func (f *Frame) Func() *Func {
	return f.f
}

// Min returns the minimum address of this frame.
func (f *Frame) Min() core.Address {
	return f.min
}

// Max returns the maximum address of this frame.
func (f *Frame) Max() core.Address {
	return f.max
}

// PC returns the program counter of the next instruction to be executed by this frame.
func (f *Frame) PC() core.Address {
	return f.pc
}

// Roots returns a list of all the garbage collection roots in the frame.
func (f *Frame) Roots() []*Root {
	return f.roots
}

// A Root is an area of memory that might have pointers into the heap.
type Root struct {
	Name string
	Addr core.Address
	Type *Type
	// Live, if non-nil, contains the set of words in the root that are live.
	Live map[core.Address]bool
}

// A Type is the representation of the type of a Go object.
type Type struct {
	name string
	Size int64
	Kind Kind

	// Fields only valid for a subset of kinds.
	Count  int64   // for kind == KindArray
	Elem   *Type   // for kind == Kind{Ptr,Array,Slice,String}. nil for unsafe.Pointer. Always uint8 for KindString.
	Fields []Field // for kind == KindStruct
}

type Kind uint8

const (
	KindNone Kind = iota
	KindBool
	KindInt
	KindUint
	KindFloat
	KindComplex
	KindArray
	KindPtr // includes chan, func, map, unsafe.Pointer
	KindIface
	KindEface
	KindSlice
	KindString
	KindStruct
	KindFunc //TODO?
)

func (k Kind) String() string {
	return [...]string{
		"KindNone",
		"KindBool",
		"KindInt",
		"KindUint",
		"KindFloat",
		"KindComplex",
		"KindArray",
		"KindPtr",
		"KindIface",
		"KindEface",
		"KindSlice",
		"KindString",
		"KindStruct",
		"KindFunc",
	}[k]
}

// A Field represents a single field of a struct type.
type Field struct {
	Name string
	Off  int64
	Type *Type
}

func (t *Type) String() string {
	return t.name
}

func (t *Type) field(name string) *Field {
	if t.Kind != KindStruct {
		panic("asking for field of non-struct")
	}
	for i := range t.Fields {
		f := &t.Fields[i]
		if f.Name == name {
			return f
		}
	}
	return nil
}

type module struct {
	r             region       // inferior region holding a runtime.moduledata
	types, etypes core.Address // range that holds all the runtime._type data in this module
}

type Func struct {
	r         region // inferior region holding a runtime._func
	module    *module
	name      string
	entry     core.Address
	frameSize pcTab // map from pc to frame size at that pc
	pcdata    []int32
	funcdata  []core.Address
	stackMap  pcTab // map from pc to stack map # (index into locals and args bitmaps)
	closure   *Type // the type to use for closures of this function. Lazily allocated.
}

func (f *Func) Name() string {
	return f.name
}

// Entry returns the address of the entry point of f.
func (f *Func) Entry() core.Address {
	return f.entry
}

// An Object represents a single object in the Go heap.
type Object core.Address

// A typeInfo contains information about the type of an object.
type typeInfo struct {
	// This object has an effective type of [Repeat]Type.
	// Parts of the object beyond the first Repeat*Type.Size bytes have unknown type.
	// If Type == nil, the type is unknown. (TODO: provide access to ptr/nonptr bits in this case.)
	t *Type
	r int64
}

// A Stats struct is the node of a tree representing the entire memory
// usage of the Go program. Children of a node break its usage down
// by category.
// We maintain the invariant that, if there are children,
// Size == sum(c.Size for c in Children).
type Stats struct {
	Name     string
	Size     int64
	Children []*Stats
}

func (s *Stats) Child(name string) *Stats {
	for _, c := range s.Children {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// Information for 512 bytes of heap.
type heapInfo struct {
	base     core.Address // start of the span containing this heap region
	size     int64        // size of objects in the span
	mark     uint64       // 64 mark bits, one for every 8 bytes
	firstIdx int          // the index of the first object that starts in this region (-1 if none)
}
