package main

import (
	"fmt"
	"html"
	"math"
	"net/http"
	"strconv"

	"github.com/randall77/corelib/core"
	"github.com/randall77/corelib/gocore"
)

func serveHtml(c *gocore.Program) {
	http.HandleFunc("/object", func(w http.ResponseWriter, r *http.Request) {
		objs, ok := r.URL.Query()["o"]
		if !ok || len(objs) != 1 {
			fmt.Fprintf(w, "wrong or missing o= object specification")
			return
		}
		obj, err := strconv.ParseInt(objs[0], 16, 64)
		if err != nil {
			fmt.Fprintf(w, "unparseable o= object specification: %s", err)
			return
		}
		a := core.Address(obj)
		x, _ := c.FindObject(a)
		if x == nil {
			fmt.Fprintf(w, "can't find object at %x", a)
			return
		}

		tableStyle(w)
		fmt.Fprintf(w, "<h1>object %x</h1>\n", x.Addr)
		fmt.Fprintf(w, "<h3>%s</h3>\n", html.EscapeString(typeName(x)))
		fmt.Fprintf(w, "<h3>%d bytes</h3>\n", x.Size)

		if x.Type != nil && x.Repeat == 1 && x.Type.String() == "runtime.g" {
			found := false
			for _, g := range c.Goroutines() {
				if g.Addr() == x.Addr {
					found = true
					break
				}
			}
			if found {
				fmt.Fprintf(w, "<h3><a href=\"goroutine?g=%x\">goroutine stack</a></h3>\n", x.Addr)
			}
		}

		fmt.Fprintf(w, "<table>\n")
		fmt.Fprintf(w, "<tr><th align=left>field</th><th align=left colspan=\"2\">type</th><th align=left>value</th></tr>\n")
		var end int64
		if x.Type != nil {
			n := x.Size / x.Type.Size
			if n > 1 {
				for i := int64(0); i < n; i++ {
					htmlObject(w, c, fmt.Sprintf("[%d]", i), x.Addr.Add(i*x.Type.Size), x.Type, nil)
				}
			} else {
				htmlObject(w, c, "", x.Addr, x.Type, nil)
			}
			end = n * x.Type.Size
		}
		for i := end; i < x.Size; i += c.Process().PtrSize() {
			fmt.Fprintf(w, "<tr><td>f%d</td><td>?</td><td><pre>", i)
			for j := int64(0); j < c.Process().PtrSize(); j++ {
				fmt.Fprintf(w, "%02x ", c.Process().ReadUint8(x.Addr.Add(i+j)))
			}
			fmt.Fprintf(w, "</pre></td><td><pre>")
			for j := int64(0); j < c.Process().PtrSize(); j++ {
				r := c.Process().ReadUint8(x.Addr.Add(i + j))
				if r >= 32 && r <= 126 {
					fmt.Fprintf(w, "%s", html.EscapeString(string(rune(r))))
				} else {
					fmt.Fprintf(w, ".")
				}
			}
			fmt.Fprintf(w, "</pre></td>")
			fmt.Fprintf(w, "</tr>\n")
		}
		fmt.Fprintf(w, "</table>\n")
	})
	http.HandleFunc("/goroutines", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "<h1>goroutines</h1>\n")
		tableStyle(w)
		fmt.Fprintf(w, "<table>\n")
		fmt.Fprintf(w, "<tr><th align=left>goroutine</th><th align=left>top of stack</th></tr>\n")
		for _, g := range c.Goroutines() {
			fmt.Fprintf(w, "<tr><td><a href=\"goroutine?g=%x\">%x</a></td><td>%s</td></tr>\n", g.Addr(), g.Addr(), g.Frames()[0].Func().Name())
		}
		fmt.Fprintf(w, "</table>\n")
		// TODO: export goroutine state (runnable, running, syscall, ...) and print it here.
	})
	http.HandleFunc("/goroutine", func(w http.ResponseWriter, r *http.Request) {
		gs, ok := r.URL.Query()["g"]
		if !ok || len(gs) != 1 {
			fmt.Fprintf(w, "wrong or missing g= goroutine specification")
			return
		}
		addr, err := strconv.ParseInt(gs[0], 16, 64)
		if err != nil {
			fmt.Fprintf(w, "unparseable g= goroutine specification: %s\n", err)
			return
		}
		a := core.Address(addr)
		var g *gocore.Goroutine
		for _, x := range c.Goroutines() {
			if x.Addr() == a {
				g = x
				break
			}
		}
		if g == nil {
			fmt.Fprintf(w, "goroutine %x not found\n", a)
			return
		}

		tableStyle(w)
		fmt.Fprintf(w, "<h1>goroutine %x</h1>\n", g.Addr())
		fmt.Fprintf(w, "<h3>%s</h3>\n", htmlPointer(c, g.Addr()))
		fmt.Fprintf(w, "<h3>%d bytes of stack</h3>\n", g.Stack())
		for _, f := range g.Frames() {
			fmt.Fprintf(w, "<h3>%s+%d</h3>\n", f.Func().Name(), f.PC().Sub(f.Func().Entry()))
			// TODO: convert fn+off to file+lineno.
			fmt.Fprintf(w, "<table>\n")
			fmt.Fprintf(w, "<tr><th align=left>field</th><th align=left colspan=\"2\">type</th><th align=left>value</th></tr>\n")
			for _, r := range f.Roots() {
				htmlObject(w, c, r.Name, r.Addr, r.Type, r.Live)
			}
			fmt.Fprintf(w, "</table>\n")
		}
	})
	http.HandleFunc("/globals", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "<h1>globals</h1>\n")
		tableStyle(w)
		fmt.Fprintf(w, "<table>\n")
		fmt.Fprintf(w, "<tr><th align=left>field</th><th align=left colspan=\"2\">type</th><th align=left>value</th></tr>\n")
		for _, r := range c.Globals() {
			htmlObject(w, c, r.Name, r.Addr, r.Type, r.Live)
		}
		fmt.Fprintf(w, "</table>\n")
	})
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "<h1>core dump viewer</h1>\n")
		fmt.Fprintf(w, "%s<br/>\n", c.Process().Arch())
		fmt.Fprintf(w, "%s<br/>\n", c.BuildVersion())
		fmt.Fprintf(w, "<a href=\"goroutines\">goroutines</a><br/>\n")
		fmt.Fprintf(w, "<a href=\"globals\">globals</a><br/>\n")
		tableStyle(w)
		fmt.Fprintf(w, "<table>\n")
		fmt.Fprintf(w, "<tr><th align=left>category</th><th align=left>bytes</th><th align=left>percent</th></tr>\n")
		all := c.Stats().Size
		var p func(*gocore.Stats, string)
		p = func(s *gocore.Stats, prefix string) {
			fmt.Fprintf(w, "<tr><td>%s%s</td><td align=right>%d</td><td align=right>%.2f</td></tr>\n", prefix, s.Name, s.Size, float64(s.Size)/float64(all)*100)
			for _, c := range s.Children {
				p(c, prefix+"..")
			}
		}
		p(c.Stats(), "")
		fmt.Fprintf(w, "</table>\n")
	})
	fmt.Println("serving on :8080")
	http.ListenAndServe(":8080", nil)
}

func htmlObject(w http.ResponseWriter, c *gocore.Program, name string, a core.Address, t *gocore.Type, live map[core.Address]bool) {
	switch t.Kind {
	case gocore.KindBool:
		v := c.Process().ReadUint8(a) != 0
		fmt.Fprintf(w, "<tr><td>%s</td><td colspan=\"2\">%s</td><td>%t</td></tr>\n", name, html.EscapeString(t.String()), v)
	case gocore.KindInt:
		var v int64
		switch t.Size {
		case 1:
			v = int64(c.Process().ReadInt8(a))
		case 2:
			v = int64(c.Process().ReadInt16(a))
		case 4:
			v = int64(c.Process().ReadInt32(a))
		default:
			v = c.Process().ReadInt64(a)
		}
		fmt.Fprintf(w, "<tr><td>%s</td><td colspan=\"2\">%s</td><td>%d</td></tr>\n", name, html.EscapeString(t.String()), v)
	case gocore.KindUint:
		var v uint64
		switch t.Size {
		case 1:
			v = uint64(c.Process().ReadUint8(a))
		case 2:
			v = uint64(c.Process().ReadUint16(a))
		case 4:
			v = uint64(c.Process().ReadUint32(a))
		default:
			v = c.Process().ReadUint64(a)
		}
		fmt.Fprintf(w, "<tr><td>%s</td><td colspan=\"2\">%s</td><td>%d</td></tr>\n", name, html.EscapeString(t.String()), v)
	case gocore.KindFloat:
		var v float64
		switch t.Size {
		case 4:
			v = float64(math.Float32frombits(c.Process().ReadUint32(a)))
		default:
			v = math.Float64frombits(c.Process().ReadUint64(a))
		}
		fmt.Fprintf(w, "<tr><td>%s</td><td colspan=\"2\">%s</td><td>%f</td></tr>\n", name, html.EscapeString(t.String()), v)
	case gocore.KindComplex:
		var v complex128
		switch t.Size {
		case 8:
			v = complex128(complex(
				math.Float32frombits(c.Process().ReadUint32(a)),
				math.Float32frombits(c.Process().ReadUint32(a.Add(4)))))

		default:
			v = complex(
				math.Float64frombits(c.Process().ReadUint64(a)),
				math.Float64frombits(c.Process().ReadUint64(a.Add(8))))
		}
		fmt.Fprintf(w, "<tr><td>%s</td><td colspan=\"2\">%s</td><td>%f</td></tr>\n", name, html.EscapeString(t.String()), v)
	case gocore.KindEface:
		fmt.Fprintf(w, "<tr><td rowspan=\"2\">%s</td><td rowspan=\"2\">interface{}</td><td>*runtime._type</td><td>%s</td></tr>\n", name, htmlPointerAt(c, a, live))
		fmt.Fprintf(w, "<tr><td>unsafe.Pointer</td><td>%s</td></tr>\n", htmlPointerAt(c, a.Add(c.Process().PtrSize()), live))
	case gocore.KindIface:
		fmt.Fprintf(w, "<tr><td rowspan=\"2\">%s</td><td rowspan=\"2\">interface{...}</td><td>*runtime.itab</td><td>%s</td></tr>\n", name, htmlPointerAt(c, a, live))
		fmt.Fprintf(w, "<tr><td>unsafe.Pointer</td><td>%s</td></tr>\n", htmlPointerAt(c, a.Add(c.Process().PtrSize()), live))
	case gocore.KindPtr:
		fmt.Fprintf(w, "<tr><td>%s</td><td colspan=\"2\">%s</td><td>%s</td></tr>\n", name, html.EscapeString(t.String()), htmlPointerAt(c, a, live))
	case gocore.KindFunc:
		fmt.Fprintf(w, "<tr><td>%s</td><td colspan=\"2\">%s</td><td>%s</td>", name, html.EscapeString(t.String()), htmlPointerAt(c, a, live))
		if fn := c.Process().ReadPtr(a); fn != 0 {
			pc := c.Process().ReadPtr(fn)
			if f := c.FindFunc(pc); f != nil && f.Entry() == pc {
				fmt.Fprintf(w, "<td>%s</td>", f.Name())
			}
		}
		fmt.Fprintf(w, "</tr>\n")
	case gocore.KindString:
		n := c.Process().ReadInt(a.Add(c.Process().PtrSize()))
		fmt.Fprintf(w, "<tr><td rowspan=\"2\">%s</td><td rowspan=\"2\">string</td><td>*uint8</td><td>%s</td>", name, htmlPointerAt(c, a, live))
		if live == nil || live[a] {
			if n > 0 {
				n2 := n
				ddd := ""
				if n > 100 {
					n2 = 100
					ddd = "..."
				}
				b := make([]byte, n2)
				c.Process().ReadAt(b, c.Process().ReadPtr(a))
				fmt.Fprintf(w, "<td rowspan=\"2\">\"%s\"%s</td>", html.EscapeString(string(b)), ddd)
			} else {
				fmt.Fprintf(w, "<td rowspan=\"2\">\"\"</td>")
			}
		}
		fmt.Fprintf(w, "</tr>\n")
		fmt.Fprintf(w, "<tr><td>int</td><td>%d</td></tr>\n", n)
	case gocore.KindSlice:
		fmt.Fprintf(w, "<tr><td rowspan=\"3\">%s</td><td rowspan=\"3\">%s</td><td>*%s</td><td>%s</td></tr>\n", name, t, t.Elem, htmlPointerAt(c, a, live))
		fmt.Fprintf(w, "<tr><td>int</td><td>%d</td></tr>\n", c.Process().ReadInt(a.Add(c.Process().PtrSize())))
		fmt.Fprintf(w, "<tr><td>int</td><td>%d</td></tr>\n", c.Process().ReadInt(a.Add(c.Process().PtrSize()*2)))
	case gocore.KindArray:
		s := t.Elem.Size
		n := t.Count
		if n*s > 16384 {
			n = (16384 + s - 1) / s
		}
		for i := int64(0); i < n; i++ {
			htmlObject(w, c, fmt.Sprintf("%s[%d]", name, i), a.Add(i*s), t.Elem, live)
		}
		if n*s != t.Size {
			fmt.Fprintf(w, "<tr><td>...</td><td>...</td><td>...</td></tr>\n")
		}
	case gocore.KindStruct:
		for _, f := range t.Fields {
			htmlObject(w, c, name+"."+f.Name, a.Add(f.Off), f.Type, live)
		}

	}
}

func htmlPointer(c *gocore.Program, a core.Address) string {
	if a == 0 {
		return "nil"
	}
	x, i := c.FindObject(a)
	if x == nil {
		return fmt.Sprintf("%x", a)
	}
	s := fmt.Sprintf("<a href=\"/object?o=%x\">object %x</a>", x.Addr, x.Addr)
	if i != 0 {
		s = fmt.Sprintf("%s+%d", s, i)
	}
	return s
}

func htmlPointerAt(c *gocore.Program, a core.Address, live map[core.Address]bool) string {
	if live != nil && !live[a] {
		return "<text style=\"color:LightGray\">dead</text>"
	}
	return htmlPointer(c, c.Process().ReadPtr(a))
}

func tableStyle(w http.ResponseWriter) {
	fmt.Fprintf(w, "<style>\n")
	fmt.Fprintf(w, "table, th, td {\n")
	fmt.Fprintf(w, "    border: 1px solid black;\n")
	fmt.Fprintf(w, "    border-collapse: collapse;\n")
	fmt.Fprintf(w, "    align: left;\n")
	fmt.Fprintf(w, "}\n")
	fmt.Fprintf(w, "table, th, td {\n")
	fmt.Fprintf(w, "    padding: 2px;\n")
	fmt.Fprintf(w, "}\n")
	fmt.Fprintf(w, "tr:hover {background-color: #f5f5f5}\n")
	fmt.Fprintf(w, "</style>\n")

}
