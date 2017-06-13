package main

import (
	"fmt"
	"log"
	"os"
	"sort"

	"github.com/randall77/corelib/core"
	"github.com/randall77/corelib/gocore"
)

func main() {
	file := os.Args[1]
	p, err := core.Core(file)
	if err != nil {
		log.Fatalf("can't load %s: %v", file, err)
	}
	fmt.Printf("arch %s\n", p.Arch())
	for _, m := range p.Mappings() {
		perm := ""
		if m.Perm()&core.Read != 0 {
			perm += "r"
		} else {
			perm += "-"
		}
		if m.Perm()&core.Write != 0 {
			perm += "w"
		} else {
			perm += "-"
		}
		if m.Perm()&core.Exec != 0 {
			perm += "x"
		} else {
			perm += "-"
		}
		fmt.Printf("%016x %016x %s %s @ %x\n", m.Min(), m.Max(), perm, m.File(), m.Offset())
	}

	c, err := gocore.Core(p)
	if err != nil {
		log.Fatalf("could not read %s: %v", file, err)
	}

	for _, g := range c.Goroutines() {
		fmt.Printf("G stacksize=%x\n", g.Stack())
		for _, f := range g.Frames() {
			fmt.Printf("  %016x %016x %s+0x%x\n", f.Min(), f.Max(), f.Func().Name(), f.Offset())
			for _, v := range f.Roots() {
				fmt.Printf("    %20s: %16x %s\n", v.Name, v.Addr, v.Type)
			}
		}
	}

	// Object histogram (bytes per type).
	type bucket struct {
		name  string
		count int64
		bytes int64
	}
	live := map[string]*bucket{}
	for _, obj := range c.Objects() {
		var name string
		if obj.Type == nil {
			name = fmt.Sprintf("unk%d", obj.Size)
		} else {
			name = obj.Type.String()
		}
		b := live[name]
		if b == nil {
			b = &bucket{name: name}
			live[name] = b
		}
		b.count++
		b.bytes += obj.Size
	}
	a := make([]*bucket, 0, len(live))
	for _, b := range live {
		a = append(a, b)
	}
	sort.Slice(a, func(i, j int) bool { return a[i].bytes > a[j].bytes })
	fmt.Printf("%12s %8s %s\n", "bytes", "count", "type")
	for _, e := range a {
		fmt.Printf("%12d %8d %s\n", e.bytes, e.count, e.name)
	}
}
