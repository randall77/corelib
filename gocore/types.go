package gocore

import (
	"debug/dwarf"

	"github.com/randall77/corelib/core"
	"github.com/randall77/corelib/rtinfo"
)

// Pseudo objects?

type Program struct {
	proc *core.Process

	goroutines []*Goroutine
	globals    []NamedPtr

	// runtime info
	info rtinfo.Info

	// runtime globals
	runtime map[string]region

	modules []*module

	// address -> function mapping
	funcTab funcTab

	// list of types
	types []*Type

	// Cached dwarf -> native type map
	typeMap map[dwarf.Type]*Type
}

// Process returns the core passed to Core().
func (p *Program) Process() *core.Process {
	return p.proc
}

func (p *Program) Goroutines() []*Goroutine {
	return p.goroutines
}

type Goroutine struct {
	r         region // inferior region holding the runtime.g
	stackSize int64  // current stack allocation
	frames    []*Frame

	// TODO:
	// defers: []*Frame also?
	// in-progress panics
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
	vars     []NamedPtr
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

// Roots returns all the pointers that are live at the point at which
// this function is suspended.
// For frames that are currently active, Roots() might be inaccurate.
// TODO: how would we fix that?  Play forward to a safepoint?  Unclear.
func (f *Frame) Roots() []NamedPtr {
	return f.vars
}

// TODO: non-ptr fields?

type NamedPtr struct {
	Name string // global name, field name, ...
	Typ  *Type  // type of
	Ptr  core.Address
}

// An Object is a heap
type Object struct {
	typ  *Type // if known, nil otherwise
	refs []NamedPtr
}

// A Type is the representation of the type of a Go object.
type Type struct {
	// Note: this data structure represents the merge of information
	// from both the runtime types and DWARF information.
	// When one or the other is incomplete, some of these fields
	// may be empty.

	r      region // inferior region holding a runtime._type (or nil if there isn't one)
	name   string
	size   int64
	ptrs   []bool  // ptr/noptr bits. Last entry is always true (if nonzero in length).
	fields []Field // If we have dwarf information, this contains full field names&types.
}

type Field struct {
	Name string
	Type Type
	Off  int64
}

func (t *Type) String() string {
	return t.name
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
	stackMap  pcTab // map from pc to stack map # (index into locals and args bitmaps)
}

func (f *Func) Name() string {
	return f.name
}
