package core

import (
	"bytes"
	"debug/elf"
	"fmt"
	"os"
	"strings"
)

// Core takes the name of a core file and returns a Process that
// represents the state of the inferior that generated the core file.
func Core(coreFile string) (*Process, error) {
	core, err := os.Open(coreFile)
	if err != nil {
		return nil, err
	}

	p := new(Process)
	if err := p.readCore(core); err != nil {
		return nil, err
	}
	if err := p.readExec(); err != nil {
		return nil, err
	}

	// Double-check that we have complete data available for all mappings.
	for _, m := range p.maps {
		if m.f == nil || m.size != int64(m.max-m.min) {
			return nil, fmt.Errorf("incomplete mapping %x %x", m.min, m.max)
		}
	}

	return p, nil
}

func (p *Process) readCore(core *os.File) error {
	e, err := elf.NewFile(core)
	if err != nil {
		return err
	}
	if e.Type != elf.ET_CORE {
		return fmt.Errorf("%s is not a core file", core)
	}
	switch e.Class {
	case elf.ELFCLASS32:
		p.ptrSize = 4
	case elf.ELFCLASS64:
		p.ptrSize = 8
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
	m := new(Mapping)
	m.min = Address(prog.Vaddr)
	m.max = Address(prog.Vaddr + prog.Memsz)
	if prog.Flags&elf.PF_R != 0 {
		m.perm |= Read
	}
	if prog.Flags&elf.PF_W != 0 {
		m.perm |= Write
		if prog.Filesz != prog.Memsz {
			return fmt.Errorf("writeable section not complete in core %x %x %x %x", prog.Filesz, prog.Memsz)
		}
	}
	if prog.Flags&elf.PF_X != 0 {
		m.perm |= Exec
	}
	m.f = f
	m.off = int64(prog.Off)
	m.size = int64(prog.Filesz)
	p.maps = append(p.maps, m)
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
		m := p.findMapping(min, max)
		if m == nil {
			return fmt.Errorf("can't find mapping corresponding to note %x %x %s", min, max, name)
		}
		if m.perm&Write != 0 {
			// The mapped file might have stale data. Ingore mapped file.
			// We've already checked that writeable mappings are complete
			// in the core file.
			m.origF = f
			m.origOff = int64(off)
			m.origSize = max.Sub(min)
			continue
		}
		f, err := os.Open(name)
		if err != nil {
			// Can't find mapped file.
			// TODO: if we debug on a different machine or something,
			// provide a way to map from core's file spec to a real file.
			return fmt.Errorf("can't open mapped file: %v\n", err)
		}
		if m.size > 0 {
			// The core dump has some data.
			// Just to be sure, compare it with the mapped file.
			// TODO: might fail if we map a file rw-, modify it, then change the mapping to r--.
			b0 := make([]byte, m.size)
			if _, err := m.f.ReadAt(b0, m.off); err != nil {
				return err
			}
			b1 := make([]byte, m.size)
			if _, err := f.ReadAt(b1, int64(off)); err != nil {
				return err
			}
			if !bytes.Equal(b0, b1) {
				return fmt.Errorf("core and mapped file don't agree in mapping %x %x", m.min, m.max)
			}
		}
		// Update mapping to use the mapped file as the source of data
		// instead of the core file.
		m.f = f
		m.off = int64(off)
		m.size = max.Sub(min)

		// Save a reference to the executable file.
		// We keep it around so we can try to get symbols out of it.
		if m.perm&Exec != 0 {
			if p.exec != nil {
				return fmt.Errorf("two executables! %s %s\n", p.exec.Name(), f.Name())
			}
			p.exec = f
		}
	}
	return nil
}
func (p *Process) findMapping(min, max Address) *Mapping {
	for _, m := range p.maps {
		if m.min == min && m.max == max {
			return m
		}
	}
	return nil
}

func (p *Process) readPRStatus(f *os.File, e *elf.File, desc []byte) error {
	greg := make([]uint64, len(desc)/8)
	for i := range greg {
		greg[i] = p.byteOrder.Uint64(desc[8*i:])
	}
	pid := uint64(uint32(greg[4]))
	//greg = greg[14:] // skip ahead to elf_greset_t
	//for i, v := range greg[:27] {
	//	fmt.Printf(" %2d %16x\n", i, v)
	//}
	//fmt.Printf("\n")
	// possible pcs: 1,11,16
	// possible sp/bps: 4,9,19,21?
	p.threads = append(p.threads, &Thread{pid: pid, regs: greg[14 : len(greg)-1]})
	return nil
}

func (p *Process) readExec() error {
	e, err := elf.NewFile(p.exec)
	if err != nil {
		return err
	}
	if e.Type != elf.ET_EXEC {
		return fmt.Errorf("%s is not an executable file", p.exec)
	}
	syms, err := e.Symbols()
	if err != nil {
		return fmt.Errorf("can't find symbols in %s", p.exec)
	}
	p.syms = make(map[string]Address, len(syms))
	for _, s := range syms {
		p.syms[s.Name] = Address(s.Value)
	}
	p.dwarf, _ = e.DWARF()
	return nil
}

// All the Read* functions below will panic if something goes wrong.

// ReadAt reads len(b) bytes at address a in the inferior
// and stores them in b.
func (p *Process) ReadAt(b []byte, a Address) {
	// TODO: binary instead of linear search
	for _, m := range p.maps {
		if a >= m.min && a < m.max {
			n := m.max.Sub(a)
			if n < int64(len(b)) {
				// Read range straddles the end of this mapping.
				// Issue a second request for the tail of the read.
				p.ReadAt(b[n:], m.max)
				b = b[:n]
			}
			_, err := m.f.ReadAt(b, m.off+a.Sub(m.min))
			if err != nil {
				panic(err)
			}
			return
		}
	}
	panic(fmt.Errorf("address %x is not mapped in the core file", a))
}

// ReadUint8 returns a uint8 read from address a of the inferior.
func (p *Process) ReadUint8(a Address) uint8 {
	var buf [1]byte
	p.ReadAt(buf[:], a)
	return buf[0]
}

// ReadUint32 returns a uint32 read from address a of the inferior.
func (p *Process) ReadUint32(a Address) uint32 {
	var buf [4]byte
	p.ReadAt(buf[:], a)
	return p.byteOrder.Uint32(buf[:])
}

// ReadUint64 returns a uint64 read from address a of the inferior.
func (p *Process) ReadUint64(a Address) uint64 {
	var buf [8]byte
	p.ReadAt(buf[:], a)
	return p.byteOrder.Uint64(buf[:])
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

// ReadAddress returns a pointer loaded from address a of the inferior.
func (p *Process) ReadAddress(a Address) Address {
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
