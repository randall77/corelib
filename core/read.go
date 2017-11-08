package core

import (
	"debug/elf" // TODO: use golang.org/x/debug/elf instead?
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
)

// Core takes the name of a core file and returns a Process that
// represents the state of the inferior that generated the core file.
func Core(coreFile, base string) (*Process, error) {
	core, err := os.Open(coreFile)
	if err != nil {
		return nil, err
	}

	p := new(Process)
	p.base = base
	if err := p.readCore(core); err != nil {
		return nil, err
	}
	if err := p.readExec(); err != nil {
		return nil, err
	}

	// Sort then merge mappings, just to clean up a bit.
	sort.Slice(p.maps, func(i, j int) bool {
		return p.maps[i].min < p.maps[j].min
	})
	ms := p.maps[1:]
	p.maps = p.maps[:1]
	for _, m := range ms {
		k := p.maps[len(p.maps)-1]
		if m.min == k.max &&
			m.perm == k.perm &&
			m.f == k.f &&
			m.off == k.off+k.Size() {
			k.max = m.max
			// TODO: also check origF?
		} else {
			p.maps = append(p.maps, m)
		}
	}

	// Memory map all the mappings.
	pgsize := int64(syscall.Getpagesize())
	for _, m := range p.maps {
		size := m.max.Sub(m.min)
		if m.f == nil {
			// Pretend this is read-as-zero.
			m.contents = make([]byte, size)
			continue
		}
		// Data in core file might not be aligned. Expand memory range
		// so we can mmap full pages.
		minOff := m.off
		maxOff := m.off + size
		if minOff%pgsize != 0 {
			minOff -= minOff % pgsize
		}
		if maxOff%pgsize != 0 {
			maxOff += pgsize - maxOff%pgsize
		}
		var err error
		m.contents, err = syscall.Mmap(int(m.f.Fd()), minOff, int(maxOff-minOff), syscall.PROT_READ, syscall.MAP_SHARED)
		if err != nil {
			return nil, fmt.Errorf("can't memory map %s at %x: %s\n", m.f, m.off, err)
		}

		// Trim any data we mapped but don't need.
		m.contents = m.contents[m.off-minOff:]
		m.contents = m.contents[:size]
	}

	// Build page table for mapping lookup.
	for _, m := range p.maps {
		p.addMapping(m)
	}

	return p, nil
}

func (p *Process) readCore(core *os.File) error {
	e, err := elf.NewFile(core)
	if err != nil {
		return err
	}
	if e.Type != elf.ET_CORE {
		return fmt.Errorf("%s is not a core file", core.Name())
	}
	switch e.Class {
	case elf.ELFCLASS32:
		p.ptrSize = 4
		p.logPtrSize = 2
	case elf.ELFCLASS64:
		p.ptrSize = 8
		p.logPtrSize = 3
	default:
		return fmt.Errorf("unknown elf class %s\n", e.Class)
	}
	switch e.Machine {
	case elf.EM_386:
		p.arch = "386"
	case elf.EM_X86_64:
		p.arch = "amd64"
		// TODO: detect amd64p32?
	case elf.EM_ARM:
		p.arch = "arm"
	case elf.EM_AARCH64:
		p.arch = "arm64"
	case elf.EM_MIPS:
		p.arch = "mips"
	case elf.EM_MIPS_RS3_LE:
		p.arch = "mipsle"
		// TODO: value for mips64?
	case elf.EM_PPC64:
		if e.ByteOrder.String() == "LittleEndian" {
			p.arch = "ppc64le"
		} else {
			p.arch = "ppc64"
		}
	case elf.EM_S390:
		p.arch = "s390x"
	default:
		return fmt.Errorf("unknown arch %s\n", e.Machine)
	}
	p.byteOrder = e.ByteOrder
	// We also compute explicitly what byte order the inferior is.
	// Just using p.byteOrder to decode fields makes any arguments passed to it
	// escape to the heap.  We use explicit binary.{Little,Big}Endian.UintXX
	// calls when we want to avoid heap-allocating the buffer.
	p.littleEndian = e.ByteOrder.String() == "LittleEndian"

	// Load virtual memory mappings.
	for _, prog := range e.Progs {
		if prog.Type == elf.PT_LOAD {
			if err := p.readLoad(core, e, prog); err != nil {
				return err
			}
		}
	}
	// Load notes (includes file mapping information).
	for _, prog := range e.Progs {
		if prog.Type == elf.PT_NOTE {
			if err := p.readNote(core, e, prog.Off, prog.Filesz); err != nil {
				return err
			}
		}
	}

	return nil
}

func (p *Process) readLoad(f *os.File, e *elf.File, prog *elf.Prog) error {
	min := Address(prog.Vaddr)
	max := min.Add(int64(prog.Memsz))
	var perm Perm
	if prog.Flags&elf.PF_R != 0 {
		perm |= Read
	}
	if prog.Flags&elf.PF_W != 0 {
		perm |= Write
	}
	if prog.Flags&elf.PF_X != 0 {
		perm |= Exec
	}
	if perm == 0 {
		// TODO: keep these nothing-mapped mappings?
		return nil
	}
	m := &Mapping{min: min, max: max, perm: perm}
	p.maps = append(p.maps, m)
	if prog.Filesz > 0 {
		// Data backing this mapping is in the core file.
		m.f = f
		m.off = int64(prog.Off)
		if prog.Filesz < uint64(m.max.Sub(m.min)) {
			// We only have partial data for this mapping in the core file.
			// Trim the mapping and allocate an anonymous mapping for the remainder.
			// The remainder will be read-as-zero.
			m2 := &Mapping{min: m.min.Add(int64(prog.Filesz)), max: m.max, perm: m.perm}
			m.max = m2.min
			p.maps = append(p.maps, m2)
		}
	}
	return nil
}

func (p *Process) readNote(f *os.File, e *elf.File, off, size uint64) error {
	// TODO: add this to debug/elf?
	const NT_FILE elf.NType = 0x46494c45

	b := make([]byte, size)
	_, err := f.ReadAt(b, int64(off))
	if err != nil {
		return err
	}
	for len(b) > 0 {
		namesz := e.ByteOrder.Uint32(b)
		b = b[4:]
		descsz := e.ByteOrder.Uint32(b)
		b = b[4:]
		typ := elf.NType(e.ByteOrder.Uint32(b))
		b = b[4:]
		name := string(b[:namesz-1])
		b = b[(namesz+3)/4*4:]
		desc := b[:descsz]
		b = b[(descsz+3)/4*4:]

		if name == "CORE" && typ == NT_FILE {
			err := p.readNTFile(f, e, desc)
			if err != nil {
				return err
			}
		}
		if name == "CORE" && typ == elf.NT_PRSTATUS {
			// An OS thread (an M)
			err := p.readPRStatus(f, e, desc)
			if err != nil {
				return err
			}
		}
		// TODO: NT_FPREGSET for floating-point registers
		// TODO: NT_PRPSINFO for ???
	}
	return nil
}

func (p *Process) readNTFile(f *os.File, e *elf.File, desc []byte) error {
	// TODO: 4 instead of 8 for 32-bit machines?
	count := e.ByteOrder.Uint64(desc)
	desc = desc[8:]
	pagesize := e.ByteOrder.Uint64(desc)
	desc = desc[8:]
	filenames := string(desc[3*8*count:])
	desc = desc[:3*8*count]
	for i := uint64(0); i < count; i++ {
		min := Address(e.ByteOrder.Uint64(desc))
		desc = desc[8:]
		max := Address(e.ByteOrder.Uint64(desc))
		desc = desc[8:]
		off := int64(e.ByteOrder.Uint64(desc) * pagesize)
		desc = desc[8:]

		var name string
		j := strings.IndexByte(filenames, 0)
		if j >= 0 {
			name = filenames[:j]
			filenames = filenames[j+1:]
		} else {
			name = filenames
			filenames = ""
		}

		backing, err := os.Open(filepath.Join(p.base, name))
		if err != nil {
			fmt.Fprintf(os.Stderr, "Missing data for addresses [%x %x] because of failure to %s. Assuming all zero.\n", min, max, err)
			// backing==nil means treat as all zero.
		}

		// TODO: this is O(n^2). Shouldn't be a big problem in practice.
		p.splitMappingsAt(min)
		p.splitMappingsAt(max)
		for _, m := range p.maps {
			if m.max <= min || m.min >= max {
				continue
			}
			// m should now be entirely in [min,max]
			if !(m.min >= min && m.max <= max) {
				panic("mapping overlapping end of file region")
			}
			if m.f == nil {
				if m.perm&Write != 0 {
					panic("writeable data missing from core")
				}
				m.f = backing
				m.off = int64(off) + m.min.Sub(min)
			} else {
				// Data is both in the core file and in a mapped file.
				// The mapped file may be stale (even if it is readonly now,
				// it may have been writeable at some point).
				// Keep the file+offset just for printing.
				m.origF = backing
				m.origOff = int64(off) + m.min.Sub(min)
			}

			// Save a reference to the executable files.
			// We keep them around so we can try to get symbols from them.
			// TODO: we should really only keep those files for which the
			// symbols return the correct addresses given where the file is
			// mapped in memory. Not sure what to do here.
			// Seems to work for the base executable, for now.
			if m.perm&Exec != 0 {
				found := false
				for _, x := range p.exec {
					if x == m.f {
						found = true
						break
					}

				}
				if !found && backing != nil {
					p.exec = append(p.exec, m.f)
				}
			}
		}
	}
	return nil
}

// splitMappingsAt ensures that a is not in the middle of any mapping.
// Splits mappings as necessary.
func (p *Process) splitMappingsAt(a Address) {
	for _, m := range p.maps {
		if a < m.min || a > m.max {
			continue
		}
		if a == m.min || a == m.max {
			return
		}
		// Split this mapping at a.
		m2 := new(Mapping)
		*m2 = *m
		m.max = a
		m2.min = a
		if m2.f != nil {
			m2.off += m.Size()
		}
		if m2.origF != nil {
			m2.origOff += m.Size()
		}
		p.maps = append(p.maps, m2)
		return
	}
}

func (p *Process) readPRStatus(f *os.File, e *elf.File, desc []byte) error {
	t := &Thread{}
	p.threads = append(p.threads, t)
	// Linux
	//   sys/procfs.h:
	//     struct elf_prstatus {
	//       ...
	//       pid_t	pr_pid;
	//       ...
	//       elf_gregset_t pr_reg;	/* GP registers */
	//       ...
	//     };
	//   typedef struct elf_prstatus prstatus_t;
	// Register numberings are listed in sys/user.h.
	// prstatus layout will probably be different for each arch/os combo.
	switch p.arch {
	default:
		// TODO: return error here?
	case "amd64":
		// 32 = offsetof(prstatus_t, pr_pid), 4 = sizeof(pid_t)
		t.pid = uint64(p.byteOrder.Uint32(desc[32 : 32+4]))
		// 112 = offsetof(prstatus_t, pr_reg), 216 = sizeof(elf_gregset_t)
		reg := desc[112 : 112+216]
		for i := 0; i < len(reg); i += 8 {
			t.regs = append(t.regs, p.byteOrder.Uint64(reg[i:]))
		}
		// Registers are:
		//  0: r15
		//  1: r14
		//  2: r13
		//  3: r12
		//  4: rbp
		//  5: rbx
		//  6: r11
		//  7: r10
		//  8: r9
		//  9: r8
		// 10: rax
		// 11: rcx
		// 12: rdx
		// 13: rsi
		// 14: rdi
		// 15: orig_rax
		// 16: rip
		// 17: cs
		// 18: eflags
		// 19: rsp
		// 20: ss
		// 21: fs_base
		// 22: gs_base
		// 23: ds
		// 24: es
		// 25: fs
		// 26: gs
		t.pc = Address(t.regs[16])
		t.sp = Address(t.regs[19])
	}
	return nil
}

func (p *Process) readExec() error {
	p.syms = map[string]Address{}
	for _, exec := range p.exec {
		e, err := elf.NewFile(exec)
		if err != nil {
			return err
		}
		if e.Type != elf.ET_EXEC {
			// This happens for shared libraries, the core file itself, ...
			continue
		}
		syms, err := e.Symbols()
		if err != nil {
			p.symErr = fmt.Errorf("can't read symbols from %s", exec.Name())
		} else {
			for _, s := range syms {
				p.syms[s.Name] = Address(s.Value)
			}
		}
		// An error while reading DWARF info is not an immediate error,
		// but any error will be returned if the caller asks for DWARF.
		dwarf, err := e.DWARF()
		if err != nil {
			p.dwarfErr = fmt.Errorf("can't read DWARF info from %s: %s", exec.Name(), err)
		} else {
			p.dwarf = dwarf
		}
	}
	return nil
}

// All the Read* functions below will panic if something goes wrong.

// ReadAt reads len(b) bytes at address a in the inferior
// and stores them in b.
func (p *Process) ReadAt(b []byte, a Address) {
	for {
		m := p.findMapping(a)
		if m == nil {
			panic(fmt.Errorf("address %x is not mapped in the core file", a))
		}
		n := copy(b, m.contents[a.Sub(m.min):])
		if n == len(b) {
			return
		}
		// Modify request to get data from the next mapping.
		b = b[n:]
		a = a.Add(int64(n))
	}
}

// ReadUint8 returns a uint8 read from address a of the inferior.
func (p *Process) ReadUint8(a Address) uint8 {
	m := p.findMapping(a)
	if m == nil {
		panic(fmt.Errorf("address %x is not mapped in the core file", a))
	}
	return m.contents[a.Sub(m.min)]
}

// ReadUint16 returns a uint16 read from address a of the inferior.
func (p *Process) ReadUint16(a Address) uint16 {
	m := p.findMapping(a)
	if m == nil {
		panic(fmt.Errorf("address %x is not mapped in the core file", a))
	}
	b := m.contents[a.Sub(m.min):]
	if len(b) < 2 {
		var buf [2]byte
		b = buf[:]
		p.ReadAt(b, a)
	}
	if p.littleEndian {
		return binary.LittleEndian.Uint16(b)
	}
	return binary.BigEndian.Uint16(b)
}

// ReadUint32 returns a uint32 read from address a of the inferior.
func (p *Process) ReadUint32(a Address) uint32 {
	m := p.findMapping(a)
	if m == nil {
		panic(fmt.Errorf("address %x is not mapped in the core file", a))
	}
	b := m.contents[a.Sub(m.min):]
	if len(b) < 4 {
		var buf [4]byte
		b = buf[:]
		p.ReadAt(b, a)
	}
	if p.littleEndian {
		return binary.LittleEndian.Uint32(b)
	}
	return binary.BigEndian.Uint32(b)
}

// ReadUint64 returns a uint64 read from address a of the inferior.
func (p *Process) ReadUint64(a Address) uint64 {
	m := p.findMapping(a)
	if m == nil {
		panic(fmt.Errorf("address %x is not mapped in the core file", a))
	}
	b := m.contents[a.Sub(m.min):]
	if len(b) < 8 {
		var buf [8]byte
		b = buf[:]
		p.ReadAt(b, a)
	}
	if p.littleEndian {
		return binary.LittleEndian.Uint64(b)
	}
	return binary.BigEndian.Uint64(b)
}

// ReadInt8 returns an int8 read from address a of the inferior.
func (p *Process) ReadInt8(a Address) int8 {
	return int8(p.ReadUint8(a))
}

// ReadInt16 returns an int16 read from address a of the inferior.
func (p *Process) ReadInt16(a Address) int16 {
	return int16(p.ReadUint16(a))
}

// ReadInt32 returns an int32 read from address a of the inferior.
func (p *Process) ReadInt32(a Address) int32 {
	return int32(p.ReadUint32(a))
}

// ReadInt64 returns an int64 read from address a of the inferior.
func (p *Process) ReadInt64(a Address) int64 {
	return int64(p.ReadUint64(a))
}

// ReadUintptr returns a uint of pointer size read from address a of the inferior.
func (p *Process) ReadUintptr(a Address) uint64 {
	if p.ptrSize == 4 {
		return uint64(p.ReadUint32(a))
	}
	return p.ReadUint64(a)
}

// ReadInt returns an int (of pointer size) read from address a of the inferior.
func (p *Process) ReadInt(a Address) int64 {
	if p.ptrSize == 4 {
		return int64(p.ReadInt32(a))
	}
	return p.ReadInt64(a)
}

// ReadPtr returns a pointer loaded from address a of the inferior.
func (p *Process) ReadPtr(a Address) Address {
	return Address(p.ReadUintptr(a))
}

// ReadCString reads a null-terminated string starting at address a.
func (p *Process) ReadCString(a Address) string {
	for n := int64(0); ; n++ {
		if p.ReadUint8(a.Add(n)) == 0 {
			b := make([]byte, n)
			p.ReadAt(b, a)
			return string(b)
		}
	}
}
