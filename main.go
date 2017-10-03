package main

import (
	"flag"
	"fmt"
	"os"
	"runtime/pprof"
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
	prof := flag.String("prof", "", "profile file")
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

	if *prof != "" {
		f, err := os.Create(*prof)
		if err != nil {
			panic(err)
		}
		pprof.StartCPUProfile(f)
		defer pprof.StopCPUProfile()
	}

	var flags gocore.Flags
	switch cmd {
	default:
		fmt.Fprintf(os.Stderr, "%s: unknown command %s\n", os.Args[0], cmd)
		fmt.Fprintf(os.Stderr, "Run 'corelib help' for usage.\n")
		os.Exit(2)
	case "overview":
	case "mappings":
	case "goroutines":
	case "histogram":
		flags = gocore.FlagTypes
	case "breakdown":
	case "objgraph":
		flags = gocore.FlagTypes
	case "objects":
		flags = gocore.FlagTypes
	case "reachable":
		flags = gocore.FlagTypes
	case "html":
		flags = gocore.FlagTypes | gocore.FlagReverse
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
	c, err := gocore.Core(p, flags)
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
				pc := f.PC()
				entry := f.Func().Entry()
				var adj string
				switch {
				case pc == entry:
					adj = ""
				case pc < entry:
					adj = fmt.Sprintf("-%d", entry.Sub(pc))
				default:
					adj = fmt.Sprintf("+%d", pc.Sub(entry))
				}
				fmt.Printf("  %016x %016x %s%s\n", f.Min(), f.Max(), f.Func().Name(), adj)
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
		c.ForEachObject(func(x gocore.Object) bool {
			name := typeName(c, x)
			b := m[name]
			if b == nil {
				b = &bucket{name: name, size: c.Size(x)}
				buckets = append(buckets, b)
				m[name] = b
			}
			b.count++
			return true
		})
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
			c.ForEachRootPtr(r, func(i int64, y gocore.Object, j int64) bool {
				if !printed {
					fmt.Fprintf(w, "r%d [label=\"%s\n%s\",shape=hexagon]\n", k, r.Name, r.Type)
					printed = true
				}
				fmt.Fprintf(w, "r%d -> o%x [label=\"%s\"", k, c.Addr(y), typeFieldName(r.Type, i))
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
					c.ForEachRootPtr(r, func(i int64, y gocore.Object, j int64) bool {
						fmt.Fprintf(w, "%s -> o%x [label=\"%s%s\"", frame, c.Addr(y), r.Name, typeFieldName(r.Type, i))
						if j != 0 {
							fmt.Fprintf(w, " ,headlabel=\"+%d\"", j)
						}
						fmt.Fprintf(w, "]\n")
						return true
					})
				}
			}
		}
		c.ForEachObject(func(x gocore.Object) bool {
			addr := c.Addr(x)
			size := c.Size(x)
			fmt.Fprintf(w, "o%x [label=\"%s\\n%d\"]\n", addr, typeName(c, x), size)
			c.ForEachPtr(x, func(i int64, y gocore.Object, j int64) bool {
				fmt.Fprintf(w, "o%x -> o%x [label=\"%s\"", addr, c.Addr(y), fieldName(c, x, i))
				if j != 0 {
					fmt.Fprintf(w, ",headlabel=\"+%d\"", j)
				}
				fmt.Fprintf(w, "]\n")
				return true
			})
			return true
		})
		fmt.Fprintf(w, "}")
		w.Close()

	case "objects":
		c.ForEachObject(func(x gocore.Object) bool {
			fmt.Printf("%16x %s\n", c.Addr(x), typeName(c, x))
			return true
		})

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
		if obj == 0 {
			fmt.Fprintf(os.Stderr, "can't find object at address %s\n", args[2])
			os.Exit(1)
		}

		// Find the set of objects that can reach the query object.
		// Map value is the minimum distance to query object + 1.
		m := map[gocore.Object]int64{}
		m[obj] = 1

		for {
			changed := false
			c.ForEachObject(func(x gocore.Object) bool {
				c.ForEachPtr(x, func(_ int64, y gocore.Object, _ int64) bool {
					if m[y] != 0 && (m[x] == 0 || m[x] > m[y]+1) {
						m[x] = m[y] + 1
						changed = true
					}
					return true
				})
				return true
			})
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
			c.ForEachRootPtr(r, func(_ int64, y gocore.Object, _ int64) bool {
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
					c.ForEachRootPtr(r, func(_ int64, y gocore.Object, _ int64) bool {
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
		var x gocore.Object
		c.ForEachRootPtr(minr, func(i int64, y gocore.Object, j int64) bool {
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
			fmt.Printf("%x %s", c.Addr(x), typeName(c, x))
			c.ForEachPtr(x, func(i int64, y gocore.Object, j int64) bool {
				if m[y] != d {
					return true
				}
				fmt.Printf(" %s ->", fieldName(c, x, i))
				if j != 0 {
					fmt.Printf(" +%d", j)
				}
				fmt.Println()
				x = y
				return false
			})
		}
		fmt.Printf("%x %s\n", c.Addr(x), typeName(c, x))

	case "html":
		serveHtml(c)
	}
}

// typeName returns a string representing the type of this object.
func typeName(c *gocore.Program, x gocore.Object) string {
	size := c.Size(x)
	typ, repeat := c.Type(x)
	if typ == nil {
		return fmt.Sprintf("unk%d", size)
	}
	name := typ.String()
	n := size / typ.Size
	if n > 1 {
		if repeat < n {
			name = fmt.Sprintf("[%d+%d?]%s", repeat, n-repeat, name)
		} else {
			name = fmt.Sprintf("[%d]%s", repeat, name)
		}
	}
	return name
}

// fieldName returns the name of the field at offset off in x.
func fieldName(c *gocore.Program, x gocore.Object, off int64) string {
	size := c.Size(x)
	typ, repeat := c.Type(x)
	if typ == nil {
		return fmt.Sprintf("f%d", off)
	}
	n := size / typ.Size
	i := off / typ.Size
	if i == 0 && repeat == 1 {
		// Probably a singleton object, no need for array notation.
		return typeFieldName(typ, off)
	}
	if i >= n {
		// Partial space at the end of the object - the type can't be complete.
		return fmt.Sprintf("f%d", off)
	}
	q := ""
	if i >= repeat {
		// Past the known repeat section, add a ? because we're not sure about the type.
		q = "?"
	}
	return fmt.Sprintf("[%d]%s%s", i, typeFieldName(typ, off-i*typ.Size), q)
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
		if off <= t.Size/2 {
			return ".len"
		}
		return ".cap"
	case gocore.KindArray:
		s := t.Elem.Size
		i := off / s
		return fmt.Sprintf("[%d]", i) + typeFieldName(t.Elem, off-i*s)
	case gocore.KindStruct:
		for _, f := range t.Fields {
			if f.Off <= off && off < f.Off+f.Type.Size {
				return "." + f.Name + typeFieldName(f.Type, off-f.Off)
			}
		}
	}
	return "???"
}
