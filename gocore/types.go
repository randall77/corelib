package gocore

import (
	"debug/dwarf"

	"github.com/randall77/corelib/core"
	"github.com/randall77/corelib/rtinfo"
)

type Program struct {
	proc *core.Process

	arenaStart core.Address
	bitmapEnd  core.Address

	spans []span

	goroutines []*Goroutine
	globals    []Var

	// runtime info
	rtStructs map[string]structInfo
	info      rtinfo.Info

	// runtime globals
	runtime map[string]region

	// A module is a loadable unit. Most Go programs have 1, programs
	// which load plugins will have more.
	modules []*module

	// address -> function mapping
	funcTab funcTab

	// list of types
	types []*Type

	// map from address of runtime._type to *Type
	runtimeMap map[core.Address]*Type

	// map from dwarf type to *Type
	dwarfMap map[dwarf.Type]*Type

	// All live objects in the heap.
	objects []Object

	// memory usage by category
	stats *Stats

	buildVersion string
}

// Process returns the core passed to Core().
func (p *Program) Process() *core.Process {
	return p.proc
}

func (p *Program) Goroutines() []*Goroutine {
	return p.goroutines
}

func (p *Program) Globals() []Var {
	return p.globals
}

func (p *Program) Objects() []Object {
	return p.objects
}

func (p *Program) Stats() *Stats {
	return p.stats
}

func (p *Program) BuildVersion() string {
	return p.buildVersion
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

	// Set of locations that contain a pointer. Note that this list
	// may contain locations outside the frame (in particular, the args
	// for the frame).
	ptrs []core.Address

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

type Var struct {
	Name string // global name, field name, ...
	Addr core.Address
	Type *Type
}

// A Type is the representation of the type of a Go object.
type Type struct {
	// Note: this data structure represents the merge of information
	// from both the runtime types and DWARF information.
	// When one or the other is incomplete, some of these fields
	// may be empty.

	r  region     // inferior region holding a runtime._type (or nil if there isn't one)
	dt dwarf.Type // equivalent dwarf type, or nil.

	name string
	size int64
	ptrs []bool // ptr/noptr bits. Last entry is always true (if nonzero in length).

	//TODO: export these?
	isString bool
	isSlice  bool
	isEface  bool
	isIface  bool
}

type Field struct {
	Name string
	Type *Type
	Off  int64
}

func (t *Type) String() string {
	return t.name
}

func (t *Type) DWARF() dwarf.Type {
	return t.dt
}

func (t *Type) IsEface() bool {
	return t.isEface
}
func (t *Type) IsIface() bool {
	return t.isIface
}

func (t *Type) Size() int64 {
	return t.size
}

type module struct {
	r region // inferior region holding a runtime.moduledata
}

type Func struct {
	r         region // inferior region holding a runtime._func
	module    *module
	name      string
	entry     core.Address
	frameSize pcTab // map from pc to frame size at that pc
	pcdata    []int32
	funcdata  []core.Address
	stackMap  pcTab      // map from pc to stack map # (index into locals and args bitmaps)
	closure   *Type      // the type to use for closures of this function. Lazily allocated.
	vars      []stackVar // parameters and local variables
}

type stackVar struct {
	off int64 // offset from the frame's max
	t   *Type
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

type Stats struct {
	Name     string
	Val      int64
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
