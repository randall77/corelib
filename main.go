package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"text/tabwriter"

	"github.com/randall77/corelib/core"
	"github.com/randall77/corelib/gocore"
)

func usage() {
	fmt.Println(`
Usage:

        corelib command corefile

The commands are:

        help: print this message
    overview: print a few overall statistics
    mappings: print virtual memory mappings
  goroutines: list goroutines
   histogram: print histogram of heap memory use by Go type
   breakdown: print memory use by class
    objgraph: dump object graph to a .dot file

Flags applicable to all commands:
`)
	flag.PrintDefaults()
}

func main() {
	base := flag.String("base", "", "root directory to find core dump file references")
	flag.Parse()

	// Extract command.
	args := flag.Args()
	if len(args) < 1 {
		fmt.Fprintf(os.Stderr, "%s: no command specified\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Run 'corelib help' for usage.\n")
		os.Exit(2)
	}
	cmd := args[0]
	if cmd == "help" {
		usage()
		return
	}

	// All commands other than "help" need a core file.
	if len(args) < 2 {
		fmt.Fprintf(os.Stderr, "%s: no core dump specified for command %s\n", os.Args[0], cmd)
		fmt.Fprintf(os.Stderr, "Run 'corelib help' for usage.\n")
		os.Exit(2)
	}
	file := args[1]
	p, err := core.Core(file, *base)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
	c, err := gocore.Core(p)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}

	switch cmd {
	default:
		fmt.Fprintf(os.Stderr, "%s: unknown command %s\n", os.Args[0], cmd)
		fmt.Fprintf(os.Stderr, "Run 'corelib help' for usage.\n")
		os.Exit(2)
	case "overview":
		t := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', 0)
		fmt.Fprintf(t, "arch\t%s\n", p.Arch())
		fmt.Fprintf(t, "runtime\t%s\n", c.BuildVersion())
		var total int64
		for _, m := range p.Mappings() {
			total += m.Max().Sub(m.Min())
		}
		fmt.Fprintf(t, "memory\t%.1f MB\n", float64(total)/(1<<20))
		t.Flush()
	case "mappings":
		t := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', tabwriter.AlignRight)
		fmt.Fprintf(t, "min\tmax\tperm\tsource\toriginal\t\n")
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
			file, off := m.Source()
			fmt.Fprintf(t, "%x\t%x\t%s\t%s@%x\t", m.Min(), m.Max(), perm, file, off)
			if m.CopyOnWrite() {
				file, off = m.OrigSource()
				fmt.Fprintf(t, "%s@%x", file, off)
			}
			fmt.Fprintf(t, "\t\n")
		}
		t.Flush()
	case "goroutines":

		for _, g := range c.Goroutines() {
			fmt.Printf("G stacksize=%x\n", g.Stack())
			for _, f := range g.Frames() {
				fmt.Printf("  %016x %016x %s+0x%x\n", f.Min(), f.Max(), f.Func().Name(), f.Offset())
			}
		}
	case "histogram":
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

	case "breakdown":
		var total int64
		for _, obj := range c.Objects() {
			total += obj.Size
		}
		alloc := c.Stats().Child("heap").Child("in use spans").Child("alloc")
		alloc.Children = []*gocore.Stats{
			&gocore.Stats{"live", total, nil},
			&gocore.Stats{"garbage", alloc.Size - total, nil},
		}

		t := tabwriter.NewWriter(os.Stdout, 0, 8, 1, ' ', tabwriter.AlignRight)
		all := c.Stats().Size
		var printStat func(*gocore.Stats, string)
		printStat = func(s *gocore.Stats, indent string) {
			comment := ""
			switch s.Name {
			case "bss":
				comment = "(grab bag, includes OS thread stacks, ...)"
			case "manual spans":
				comment = "(Go stacks)"
			}
			fmt.Fprintf(t, "%s\t%d\t%6.2f%%\t %s\n", fmt.Sprintf("%-20s", indent+s.Name), s.Size, float64(s.Size)*100/float64(all), comment)
			for _, c := range s.Children {
				printStat(c, indent+"  ")
			}
		}
		printStat(c.Stats(), "")
		t.Flush()
	case "objgraph":

		// Dump object graph to output file.
		w, err := os.Create("tmp.dot")
		if err != nil {
			panic(err)
		}
		fmt.Fprintf(w, "digraph {\n")
		for i, r := range c.Roots() {
			if !hasPtr(c, r.Addr, r.Type, r.Live) {
				continue
			}
			src := fmt.Sprintf("r%d", i)
			shape := "hexagon"
			if r.Live != nil {
				shape = "octagon"
			}
			fmt.Fprintf(w, "%s [label=\"%s\",shape=%s]\n", src, r.Name, shape)
			addEdges(c, w, src, r.Addr, r.Type, r.Live)
		}
		for _, g := range c.Goroutines() {
			last := fmt.Sprintf("o%x", g.Addr())
			for _, f := range g.Frames() {
				frame := fmt.Sprintf("f%x", f.Max())
				fmt.Fprintf(w, "%s [label=\"%s\",shape=rectangle]\n", frame, f.Func().Name())
				fmt.Fprintf(w, "%s -> %s [style=dotted]\n", last, frame)
				last = frame
				for _, r := range f.Roots() {
					if !hasPtr(c, r.Addr, r.Type, r.Live) {
						continue
					}
					addEdges1(c, w, frame, r.Name, r.Addr, r.Type, r.Live)
				}
			}
		}
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
			src := fmt.Sprintf("o%x", obj.Addr)
			fmt.Fprintf(w, "%s [label=\"%s\\n%d\"]\n", src, name, obj.Size)
			if obj.Type != nil { // TODO: what to do for typ==nil?
				if obj.Repeat == 1 {
					addEdges(c, w, src, obj.Addr, obj.Type, nil)
				} else {
					for i := int64(0); i < obj.Repeat; i++ {
						addEdges1(c, w, src, fmt.Sprintf("[%d]", i), obj.Addr.Add(i*obj.Type.Size()), obj.Type, nil)
					}
				}
			}
			// TODO: data beyond obj.Repeat*obj.Type.Size
		}
		fmt.Fprintf(w, "}")
		w.Close()
	}
}

func addEdges(p *gocore.Program, w io.Writer, src string, a core.Address, t *gocore.Type, live map[core.Address]bool) {
	addEdges1(p, w, src, "", a, t, live)
}
func addEdges1(p *gocore.Program, w io.Writer, src, field string, a core.Address, t *gocore.Type, live map[core.Address]bool) {
	switch t.Kind {
	case gocore.KindBool, gocore.KindInt, gocore.KindUint, gocore.KindFloat, gocore.KindComplex:
	case gocore.KindIface, gocore.KindEface:
		// The first word is a type or itab.
		// Itabs are never in the heap.
		// Types might be, though.
		if live == nil || live[a] {
			dst := p.FindObject(p.Process().ReadAddress(a))
			if dst != nil {
				fmt.Fprintf(w, "%s -> o%x [label=\"%s\"]\n", src, dst.Addr, field+".type")
			}
		}
		// Treat second word like a pointer.
		a = a.Add(p.Process().PtrSize())
		fallthrough
	case gocore.KindPtr, gocore.KindString, gocore.KindSlice, gocore.KindFunc:
		if live != nil && !live[a] {
			break // Treat reads from addresses not in live as returning nil.
		}
		dst := p.FindObject(p.Process().ReadAddress(a))
		if dst == nil {
			break
		}
		fmt.Fprintf(w, "%s -> o%x [label=\"%s\"]\n", src, dst.Addr, field)
	case gocore.KindArray:
		s := t.Elem.Size()
		for i := int64(0); i < t.Count; i++ {
			addEdges1(p, w, src, fmt.Sprintf("%s[%d]", field, i), a.Add(i*s), t.Elem, live)
		}
	case gocore.KindStruct:
		for _, f := range t.Fields {
			var sub string
			if field != "" {
				sub = field + "." + f.Name
			} else {
				sub = f.Name
			}
			addEdges1(p, w, src, sub, a.Add(f.Off), f.Type, live)
		}
	}
}

func hasPtr(p *gocore.Program, a core.Address, t *gocore.Type, live map[core.Address]bool) bool {
	switch t.Kind {
	case gocore.KindBool, gocore.KindInt, gocore.KindUint, gocore.KindFloat, gocore.KindComplex:
		return false
	case gocore.KindPtr, gocore.KindString, gocore.KindSlice, gocore.KindFunc:
		if live != nil && !live[a] {
			return false
		}
		return p.FindObject(p.Process().ReadAddress(a)) != nil
	case gocore.KindIface, gocore.KindEface:
		for i := 0; i < 2; i++ {
			if live != nil && !live[a] {
				if p.FindObject(p.Process().ReadAddress(a)) != nil {
					return true
				}
			}
			a = a.Add(p.Process().PtrSize())
		}
		return false
	case gocore.KindArray:
		s := t.Elem.Size()
		for i := int64(0); i < t.Count; i++ {
			if hasPtr(p, a.Add(i*s), t.Elem, live) {
				return true
			}
		}
		return false
	case gocore.KindStruct:
		for _, f := range t.Fields {
			if hasPtr(p, a.Add(f.Off), f.Type, live) {
				return true
			}
		}
		return false
	default:
		panic("bad")
	}
}
