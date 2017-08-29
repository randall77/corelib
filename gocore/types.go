package gocore

import (
	"debug/dwarf"

	"github.com/randall77/corelib/core"
)

type Program struct {
	proc *core.Process

	arenaStart core.Address
	bitmapEnd  core.Address

	spans []span

	goroutines []*Goroutine

	// runtime info
	rtStructs   map[string]structInfo
	rtConstants map[string]int64

	// runtime globals
	runtime map[string]region

	// A module is a loadable unit. Most Go programs have 1, programs
	// which load plugins will have more.
	modules []*module

	// address -> function mapping
	funcTab funcTab

	// list of types
	types []*Type

	// map from dwarf type to *Type
	dwarfMap map[dwarf.Type]*Type

	// map from address of runtime._type to *Type
	runtimeMap map[core.Address]*Type

	// map from runtime type name to the set of *Type with that name
	// Used to find candidates to put in the runtimeMap map.
	runtimeNameMap map[string][]*Type

	// All live objects in the heap.
	objects []Object

	// memory usage by category
	stats *Stats

	buildVersion string

	roots []Root
}

// Process returns the core passed to Core().
func (p *Program) Process() *core.Process {
	return p.proc
}

func (p *Program) Goroutines() []*Goroutine {
	return p.goroutines
}

// Objects returns all live objects in the heap.
func (p *Program) Objects() []Object {
	return p.objects
}

func (p *Program) Stats() *Stats {
	return p.stats
}

// BuildVersion returns the Go version that was used to build the inferior binary.
func (p *Program) BuildVersion() string {
	return p.buildVersion
}

func (p *Program) Roots() []Root {
	return p.roots
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
	off      int64        // offset of pc in this function
	min, max core.Address // extent of stack frame

	// Set of locations that contain a live pointer. Note that this set
	// may contain locations outside the frame (in particular, the args
	// for the frame).
	live map[core.Address]bool

	roots []Root

	// TODO: keep vars from dwarf around?
}

// Func returns the function for which this frame is an activation record.
func (f *Frame) Func() *Func {
	return f.f
}

func (f *Frame) Min() core.Address {
	return f.min
}
func (f *Frame) Max() core.Address {
	return f.max
}
func (f *Frame) Offset() int64 {
	return f.off
}
func (f *Frame) Roots() []Root {
	return f.roots
}

// A Root is an area of memory that might have pointers into the heap.
type Root struct {
	Name string
	Addr core.Address
	Type *Type
	// Live, if non-nil, restricts the set of words in the root that are live.
	Live map[core.Address]bool
}

// A Type is the representation of the type of a Go object.
type Type struct {
	name string
	size int64
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

func (t *Type) IsEface() bool {
	return t.Kind == KindEface
}
func (t *Type) IsIface() bool {
	return t.Kind == KindIface
}

func (t *Type) Size() int64 {
	return t.size
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

// An Object represents an object in the Go heap.
type Object struct {
	Addr   core.Address
	Size   int64
	Type   *Type
	Repeat int64 // Known repeat count for Type
}

// A span is a set of addresses that contain heap objects.
// Note: We record only heap spans. The spans list does not include stack spans.
type span struct {
	min  core.Address
	max  core.Address
	size int64 // size of objects in span
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

type structInfo struct {
	size   int64
	fields map[string]fieldInfo
}

type fieldInfo struct {
	off int64
	typ string
}
