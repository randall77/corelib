package main

import (
	"flag"
	"fmt"
	"os"
	"sort"
	"strconv"
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
     objects: print a list of all live objects
    objgraph: dump object graph to a .dot file
   reachable: find path from root to an object

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
		for k, r := range c.Globals() {
			printed := false
			c.ForEachRootEdge(r, func(i int64, y *gocore.Object, j int64) bool {
				if !printed {
					fmt.Fprintf(w, "r%d [label=\"%s\n%s\",shape=hexagon]\n", k, r.Name, r.Type)
					printed = true
				}
				fmt.Fprintf(w, "r%d -> o%x [label=\"%s\"", k, y.Addr, typeFieldName(r.Type, i))
				if j != 0 {
					fmt.Fprintf(w, " ,headlabel=\"+%d\"", j)
				}
				fmt.Fprintf(w, "]\n")
				return true
			})
		}
		for _, g := range c.Goroutines() {
			last := fmt.Sprintf("o%x", g.Addr())
			for _, f := range g.Frames() {
				frame := fmt.Sprintf("f%x", f.Max())
				fmt.Fprintf(w, "%s [label=\"%s\",shape=rectangle]\n", frame, f.Func().Name())
				fmt.Fprintf(w, "%s -> %s [style=dotted]\n", last, frame)
				last = frame
				for _, r := range f.Roots() {
					c.ForEachRootEdge(r, func(i int64, y *gocore.Object, j int64) bool {
						fmt.Fprintf(w, "%s -> o%x [label=\"%s%s\"", frame, y.Addr, r.Name, typeFieldName(r.Type, i))
						if j != 0 {
							fmt.Fprintf(w, " ,headlabel=\"+%d\"", j)
						}
						fmt.Fprintf(w, "]\n")
						return true
					})
				}
			}
		}
		for _, x := range c.Objects() {
			fmt.Fprintf(w, "o%x [label=\"%s\\n%d\"]\n", x.Addr, typeName(x), x.Size)
			c.ForEachEdge(x, func(i int64, y *gocore.Object, j int64) bool {
				fmt.Fprintf(w, "o%x -> o%x [label=\"%s\"", x.Addr, y.Addr, fieldName(x, i))
				if j != 0 {
					fmt.Fprintf(w, ",headlabel=\"+%d\"", j)
				}
				fmt.Fprintf(w, "]\n")
				return true
			})
		}
		fmt.Fprintf(w, "}")
		w.Close()
	case "objects":
		for _, x := range c.Objects() {
			fmt.Printf("%16x %s\n", x.Addr, typeName(x))
		}

	case "reachable":
		if len(args) < 3 {
			fmt.Fprintf(os.Stderr, "no object address provided\n")
			os.Exit(1)
		}
		n, err := strconv.ParseInt(args[2], 16, 64)
		if err != nil {
			fmt.Fprintf(os.Stderr, "can't parse %s as an object address\n", args[2])
			os.Exit(1)
		}
		a := core.Address(n)
		obj, _ := c.FindObject(a)
		if obj == nil {
			fmt.Fprintf(os.Stderr, "can't find object at address %s\n", args[2])
			os.Exit(1)
		}

		// Find the set of objects that can reach the query object.
		// Map value is the minimum distance to query object + 1.
		m := map[*gocore.Object]int64{}
		m[obj] = 1

		for {
			changed := false
			for _, x := range c.Objects() {
				c.ForEachEdge(x, func(_ int64, y *gocore.Object, _ int64) bool {
					if m[y] != 0 && (m[x] == 0 || m[x] > m[y]+1) {
						m[x] = m[y] + 1
						changed = true
					}
					return true
				})
			}
			if !changed {
				break
			}
		}

		// Find a minimum distance root.
		var mind int64
		var minr *gocore.Root
		var minf *gocore.Frame
		var ming *gocore.Goroutine
		for _, r := range c.Globals() {
			c.ForEachRootEdge(r, func(_ int64, y *gocore.Object, _ int64) bool {
				if m[y] != 0 && (mind == 0 || m[y] < mind) {
					mind = m[y]
					minr = r
					minf = nil
					ming = nil
				}
				return true
			})
		}
		for _, g := range c.Goroutines() {
			for _, f := range g.Frames() {
				for _, r := range f.Roots() {
					c.ForEachRootEdge(r, func(_ int64, y *gocore.Object, _ int64) bool {
						if m[y] != 0 && (mind == 0 || m[y] < mind) {
							mind = m[y]
							minr = r
							minf = f
							ming = g
						}
						return true
					})
				}
			}
		}
		if mind == 0 {
			panic("can't find root holding object live")
		}

		// Print minimum distance path to object.
		if minf != nil {
			fs := ming.Frames()
			for i := len(fs) - 1; i >= 0; i-- {
				f := fs[i]
				if f != minf {
					fmt.Printf("%s\n", f.Func().Name())
				} else {
					fmt.Printf("%s ", f.Func().Name())
					break
				}
			}
		}
		var x *gocore.Object
		c.ForEachRootEdge(minr, func(i int64, y *gocore.Object, j int64) bool {
			if m[y] != mind {
				return true
			}
			fmt.Printf("%s %s %s ->", minr.Name, minr.Type, typeFieldName(minr.Type, i))
			if j != 0 {
				fmt.Printf(" +%d", j)
			}
			fmt.Println()
			x = y
			return false
		})
		for d := mind - 1; d != 0; d-- {
			fmt.Printf("%x %s", x.Addr, typeName(x))
			c.ForEachEdge(x, func(i int64, y *gocore.Object, j int64) bool {
				if m[y] != d {
					return true
				}
				fmt.Printf(" %s ->", fieldName(x, i))
				if j != 0 {
					fmt.Printf(" +%d", j)
				}
				fmt.Println()
				x = y
				return false
			})
		}
		fmt.Printf("%x %s\n", x.Addr, typeName(x))

	case "html":
		serveHtml(c)
	}
}

// typeName returns a string representing the type of this object.
func typeName(x *gocore.Object) string {
	if x.Type == nil {
		return fmt.Sprintf("unk%d", x.Size)
	}
	name := x.Type.String()
	n := x.Size / x.Type.Size()
	if n > 1 {
		if x.Repeat < n {
			name = fmt.Sprintf("[%d+%d?]%s", x.Repeat, n-x.Repeat, name)
		} else {
			name = fmt.Sprintf("[%d]%s", x.Repeat, name)
		}
	}
	return name
}

// fieldName returns the name of the field at offset off in x.
func fieldName(x *gocore.Object, off int64) string {
	if x.Type == nil {
		return fmt.Sprintf("f%d", off)
	}
	n := x.Size / x.Type.Size()
	i := off / x.Type.Size()
	if i == 0 && x.Repeat == 1 {
		// Probably a singleton object, no need for array notation.
		return typeFieldName(x.Type, off)
	}
	if i >= n {
		// Partial space at the end of the object - the type can't be complete.
		return fmt.Sprintf("f%d", off)
	}
	q := ""
	if i >= x.Repeat {
		// Past the known repeat section, add a ? because we're not sure about the type.
		q = "?"
	}
	return fmt.Sprintf("[%d]%s%s", i, typeFieldName(x.Type, off-i*x.Type.Size()), q)
}

// typeFieldName returns the name of the field at offset off in t.
func typeFieldName(t *gocore.Type, off int64) string {
	switch t.Kind {
	case gocore.KindBool, gocore.KindInt, gocore.KindUint, gocore.KindFloat, gocore.KindComplex:
		return ""
	case gocore.KindIface, gocore.KindEface:
		if off == 0 {
			return ".type"
		}
		return ".data"
	case gocore.KindPtr, gocore.KindFunc:
		return ""
	case gocore.KindString, gocore.KindSlice:
		if off == 0 {
			return ".ptr"
		}
		if off <= t.Size()/2 {
			return ".len"
		}
		return ".cap"
	case gocore.KindArray:
		s := t.Elem.Size()
		i := off / s
		return fmt.Sprintf("[%d]", i) + typeFieldName(t.Elem, off-i*s)
	case gocore.KindStruct:
		for _, f := range t.Fields {
			if f.Off <= off && off < f.Off+f.Type.Size() {
				return "." + f.Name + typeFieldName(f.Type, off-f.Off)
			}
		}
	}
	return "???"
}
