// The core library is used to process ELF core dump files.  You can
// open a core dump file and read from addresses in the process that
// dumped core, called the "inferior". Some ancillary information
// about the inferior is also provided, like architecture and OS
// thread state.
//
// There's nothing Go-specific about this library, it could
// just as easily be used to read a C++ core dump. See ../gocore
// for the next layer up, a Go-specific core dump reader.
//
// The Read* operations all panic with an error (the builtin Go type)
// if the inferior is not readable at the address requested.
package core

import (
	"debug/dwarf"
	"encoding/binary"
	"os"
	"strings"
)

// An Address is a location in inferior's address space.
type Address uint64

// Subtract b from a. Requires a >= b.
func (a Address) Sub(b Address) int64 {
	return int64(a - b)
}

// Add x to address a.
func (a Address) Add(x int64) Address {
	return a + Address(x)
}

func (a Address) Max(b Address) Address {
	if a > b {
		return a
	}
	return b
}
func (a Address) Min(b Address) Address {
	if a < b {
		return a
	}
	return b
}

// Align rounds a up to a multiple of x.
// x must be a power of 2.
func (a Address) Align(x int64) Address {
	return (a + Address(x) - 1) & ^(Address(x) - 1)
}

// A Process represents the state of the process that core dumped.
type Process struct {
	exec      []*os.File         // executables (more than one for shlibs)
	maps      []*Mapping         // virtual address mappings
	threads   []*Thread          // os threads (TODO: map from pid?)
	arch      string             // amd64, ...
	ptrSize   int64              // 4 or 8
	byteOrder binary.ByteOrder   //
	syms      map[string]Address // symbols (could be empty if executable is stripped)
	symErr    error              // an error encountered while reading symbols
	dwarf     *dwarf.Data        // debugging info (could be nil)
	dwarfErr  error              // an error encountered while reading DWARF
}

// Mappings returns a list of virtual memory mappings for p.
func (p *Process) Mappings() []*Mapping {
	return p.maps
}

// Writeable reports whether the address is writeable (by the inferior at the time of the core dump).
func (p *Process) Writeable(a Address) bool {
	// TODO: binary search
	for _, m := range p.maps {
		if m.min <= a && a < m.max {
			return m.perm&Write != 0
		}
	}
	return false
}

// Threads returns information about each OS thread in the inferior.
func (p *Process) Threads() []*Thread {
	return p.threads
}

func (p *Process) Arch() string {
	return p.arch
}

func (p *Process) PtrSize() int64 {
	return p.ptrSize
}

func (p *Process) ByteOrder() binary.ByteOrder {
	return p.byteOrder
}

func (p *Process) DWARF() (*dwarf.Data, error) {
	return p.dwarf, p.dwarfErr
}

// Symbols returns a mapping from name to inferior address, along with
// any error encountered during reading the symbol information.
// (There may be both an error and some returned symbols.)
// Symbols might not be available with core files from stripped binaries.
func (p *Process) Symbols() (map[string]Address, error) {
	return p.syms, p.symErr
}

// A Mapping represents a contiguous subset of the inferior's address space.
type Mapping struct {
	min  Address
	max  Address
	perm Perm

	f   *os.File // file backing this region
	off int64    // offset of start of this mapping in f

	// For regions originally backed by a file but now in the core file,
	// (probably because it is copy-on-write) this is the original data source.
	// This info is just for printing; the data in this source is stale.
	origF   *os.File
	origOff int64
}

// Min returns the lowest virtual address of the mapping.
func (m *Mapping) Min() Address {
	return m.min
}

// Max returns the virtual address of the byte just beyond the mapping.
func (m *Mapping) Max() Address {
	return m.max
}

// Size returns int64(Max-Min)
func (m *Mapping) Size() int64 {
	return m.max.Sub(m.min)
}

// Perm returns the permissions on the mapping.
func (m *Mapping) Perm() Perm {
	return m.perm
}

// File returns the backing file for the mapping, or "" if none.
func (m *Mapping) File() string {
	if m.f == nil {
		return ""
	}
	return m.f.Name()
}

// Offset returns the offset in File() where the mapping starts.
// Offset returns 0 if File() == "".
func (m *Mapping) Offset() int64 {
	return m.off
}

func (m *Mapping) CopyOnWrite() bool {
	return m.origF != nil
}

type Thread struct {
	pid  uint64   // thread/process ID
	regs []uint64 // set depends on arch
}

func (t *Thread) Pid() uint64 {
	return t.pid
}

// Regs returns the set of register values for the thread.
// What registers go where is architecture-dependent.
// TODO: do this in some arch-independent way?
func (t *Thread) Regs() []uint64 {
	return t.regs
}

type Perm uint8

const (
	Read Perm = 1 << iota
	Write
	Exec
)

func (p Perm) String() string {
	var a [3]string
	b := a[:0]
	if p&Read != 0 {
		b = append(b, "Read")
	}
	if p&Write != 0 {
		b = append(b, "Write")
	}
	if p&Exec != 0 {
		b = append(b, "Exec")
	}
	if len(b) == 0 {
		b = append(b, "None")
	}
	return strings.Join(b, "|")
}
