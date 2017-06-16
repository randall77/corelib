package main

// This file contains a program which extracts information
// that the heap dump reader needs from the runtime package of
// a particular Go version.
//
//     go run extractRuntime.go $GOROOT
//
// You must have already run make.bash in $GOROOT/src.
//
// This program writes a file containing the extracted data to the parent directory.
// The file is named by Go version so multiple versions can live in the parent directory.
// (typically versions like go1.8.1, but it also handles devel... versions).
//
// The heap dump reader will not be able to read heap dumps
// from binaries which were built with a Go version that is
// not listed in an extract file.
//
// TODO: maybe don't use this file, and instead encode all the
// offsets we need in the breadcrumbs variable in runtime/heapdump.go?

import (
	"bytes"
	"fmt"
	"go/build"
	"go/constant"
	"go/format"
	"go/types"
	"io"
	"io/ioutil"
	"os"

	"golang.org/x/tools/go/loader"
)

type arch struct {
	name     string
	wordSize int64
	maxAlign int64
}

var archs = [...]arch{
	{"amd64", 8, 8},
	{"arm", 4, 4},
	{"386", 4, 4},
	// TODO: fill in
}

var constants = [...]string{
	"_MSpanDead",
	"_MSpanInUse",
	"_MSpanManual",
	"_MSpanFree",
	"_PageSize",
	"_Gidle",
	"_Grunnable",
	"_Grunning",
	"_Gsyscall",
	"_Gwaiting",
	"_Gscan",
	"_Gdead",
	"_PCDATA_StackMapIndex",
	"_FUNCDATA_LocalsPointerMaps",
	"_FUNCDATA_ArgsPointerMaps",
	"tflagExtraStar",
	"kindGCProg",
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "usage: go run extractRuntime.go $GOROOT\n")
		os.Exit(2)
	}
	goroot := os.Args[1]
	fmt.Printf(" goroot: %s\n", goroot)

	// Figure out the Go version. Kind of overkill, but so what.
	context := build.Default
	context.GOROOT = goroot
	conf := loader.Config{Build: &context}
	conf.Import("runtime/internal/sys")
	prog, err := conf.Load()
	if err != nil {
		panic(err)
	}
	sys := prog.Package("runtime/internal/sys").Pkg.Scope()
	version := constant.StringVal(sys.Lookup("TheVersion").(*types.Const).Val())
	fmt.Printf("version: %s\n", version)
	if len(version) > 64 {
		panic("version too long")
	}

	// Write information for each architecture to an in-memory file.
	w := new(bytes.Buffer)
	fmt.Fprintf(w, "package rtinfo\n")
	fmt.Fprintf(w, "// Code generated by extractRuntime; DO NOT EDIT.\n")
	fmt.Fprintf(w, "// This file contains runtime information for version %s\n", version)

	fmt.Fprintf(w, "func init() {\n")
	for _, arch := range archs {
		extract(w, goroot, version, arch)
	}
	fmt.Fprintf(w, "}\n")

	// gofmt result.
	b := w.Bytes()
	code, err := format.Source(b)
	if err != nil {
		fmt.Println(string(b))
		panic(err)
	}

	// Convert version into a filename.
	var v []byte
	for i, c := range []byte(version) {
		if c >= 'a' && c <= 'z' ||
			c >= 'A' && c <= 'Z' ||
			c >= '0' && c <= '9' && i > 0 {
			v = append(v, c)
		} else {
			v = append(v, '_')
		}
	}
	name := fmt.Sprintf("../data_%s.go", string(v))

	// Write to file.
	fmt.Printf(" output: %s\n", name)
	err = ioutil.WriteFile(name, code, 0666)
	if err != nil {
		panic(err)
	}
}

// StdSizes isn't right for matching the gc compiler. The gc compiler
// insists that sizeof(t) % alignof(t) == 0.
// e.g. struct { x int64; y int32 } is 12 bytes according to StdSizes
// but 16 according to gc (for 64-bit platforms).
type mySizes struct {
	WordSize int64 // word size in bytes - must be >= 4 (32bits)
	MaxAlign int64 // maximum alignment in bytes - must be >= 1
}

func (s *mySizes) Alignof(t types.Type) int64 {
	switch t := t.Underlying().(type) {
	case *types.Basic:
		k := t.Kind()
		a := basicSizes[k]
		if a == 0 {
			panic("zero size for " + t.String())
		}
		if a > s.MaxAlign {
			a = s.MaxAlign
		}
		return a
	case *types.Array:
		return s.Alignof(t.Elem())
	case *types.Struct:
		max := int64(1)
		n := t.NumFields()
		for i := 0; i < n; i++ {
			ft := t.Field(i).Type()
			if a := s.Alignof(ft); a > max {
				max = a
			}
		}
		return max
	}
	// Pointer,Func,Map
	return s.WordSize
}
func (s *mySizes) Sizeof(t types.Type) int64 {
	switch t := t.Underlying().(type) {
	case *types.Basic:
		x := basicSizes[t.Kind()]
		if x == 0 {
			panic("zero size for " + t.String())
		}
		return x
	case *types.Slice:
		return s.WordSize * 3
	case *types.Interface:
		return s.WordSize * 2
	case *types.Array:
		return t.Len() * s.Sizeof(t.Elem())
		// In types.StdSizes, this is align(z,a)*(n-1)+z
	case *types.Struct:
		n := t.NumFields()
		size := int64(0)
		align := int64(1)
		for i := 0; i < n; i++ {
			ft := t.Field(i).Type()
			fs := s.Sizeof(ft)
			fa := s.Alignof(ft)
			size = (size + fa - 1) / fa * fa
			size += fs
			if fa > align {
				align = fa
			}
		}
		// In types.StdSizes, this is just "return size"
		return (size + align - 1) / align * align
	}
	// Pointer,Func,Map
	return s.WordSize
}
func (s *mySizes) Offsetsof(fields []*types.Var) []int64 {
	offsets := make([]int64, len(fields))
	var o int64
	for i, f := range fields {
		ft := f.Type()
		a := s.Alignof(ft)
		o = (o + a - 1) / a * a
		offsets[i] = o
		o += s.Sizeof(ft)
	}
	return offsets
}

var basicSizes = map[types.BasicKind]int64{
	types.Bool:       1,
	types.Int8:       1,
	types.Int16:      2,
	types.Int32:      4,
	types.Int64:      8,
	types.Uint8:      1,
	types.Uint16:     2,
	types.Uint32:     4,
	types.Uint64:     8,
	types.Float32:    4,
	types.Float64:    8,
	types.Complex64:  8,
	types.Complex128: 16,
}

func extract(w io.Writer, goroot string, version string, arch arch) {
	fmt.Printf("   arch: %s\n", arch.name)
	if len(arch.name) > 16 {
		panic("arch too long")
	}

	// Configure the loader.
	context := build.Default
	context.GOARCH = arch.name
	context.GOOS = "linux" // will this always work?
	context.GOROOT = goroot
	conf := loader.Config{Build: &context}
	conf.TypeChecker.Sizes = &mySizes{WordSize: arch.wordSize, MaxAlign: arch.maxAlign}
	basicSizes[types.Int] = arch.wordSize
	basicSizes[types.Uint] = arch.wordSize
	basicSizes[types.Uintptr] = arch.wordSize
	basicSizes[types.UnsafePointer] = arch.wordSize
	basicSizes[types.String] = 2 * arch.wordSize

	// Request the only package we care about, the runtime.
	conf.Import("runtime")

	// Main call to go/types: load the packages.
	prog, err := conf.Load()
	if err != nil {
		panic(err)
	}
	runtime := prog.Package("runtime").Pkg.Scope()

	// Dump offsets of fields in critical types.
	fmt.Fprintf(w, "register(\"%s\", \"%s\",\n", arch.name, version)
	fmt.Fprintf(w, "Info {\n")
	fmt.Fprintf(w, "Constants: map[string]int64 {\n")
	for _, c := range constants {
		dumpConstant(w, runtime, c)
	}
	fmt.Fprintf(w, "},\n")
	fmt.Fprintf(w, "})\n")
}

func dumpConstant(w io.Writer, scope *types.Scope, name string) {
	x, ok := constant.Uint64Val(scope.Lookup(name).(*types.Const).Val())
	if !ok {
		panic("can't extract uint64 from constant " + name)
	}
	fmt.Fprintf(w, "\"%s\": %d,\n", name, x)
}
