package main

import (
	"fmt"
	"log"
	"os"
	"sort"
	"text/tabwriter"

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

	// Produce an object histogram (bytes per type).
	type bucket struct {
		name  string
		size  int64
		count int64
	}
	var buckets []*bucket
	m := map[string]*bucket{}
	for _, obj := range c.Objects() {
		var name string
		if obj.Type == nil {
			name = fmt.Sprintf("unk%d", obj.Size)
		} else {
			name = obj.Type.String()
			n := obj.Size / obj.Type.Size()
			if n > 1 {
				if obj.Repeat < n {
					name = fmt.Sprintf("[%d+%d?]%s", obj.Repeat, n-obj.Repeat, name)
				} else {
					name = fmt.Sprintf("[%d]%s", obj.Repeat, name)
				}
			}
		}
		b := m[name]
		if b == nil {
			b = &bucket{name: name, size: obj.Size}
			buckets = append(buckets, b)
			m[name] = b
		}
		b.count++
	}
	sort.Slice(buckets, func(i, j int) bool {
		return buckets[i].size*buckets[i].count > buckets[j].size*buckets[j].count
	})
	t := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', tabwriter.AlignRight)
	fmt.Fprintf(t, "%s\t%s\t%s\t %s\n", "count", "size", "bytes", "type")
	for _, e := range buckets {
		fmt.Fprintf(t, "%d\t%d\t%d\t %s\n", e.count, e.size, e.count*e.size, e.name)
	}
	t.Flush()
}
