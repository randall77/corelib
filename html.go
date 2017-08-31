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

		fmt.Fprintf(w, "<h1>object %x</h1>\n", x.Addr)
		fmt.Fprintf(w, "<h3>%s</h3>\n", html.EscapeString(typeName(x)))
		fmt.Fprintf(w, "<h3>%d bytes</h3>\n", x.Size)

		fmt.Fprintf(w, "<table>\n")
		fmt.Fprintf(w, "<tr><th align=left>field</th><th align=left>type</th><th align=left>value</th></tr>\n")
		var end int64
		if x.Type != nil {
			n := x.Size / x.Type.Size()
			if n > 1 {
				for i := int64(0); i < n; i++ {
					htmlObject(w, c, fmt.Sprintf("[%d]", i), x.Addr.Add(i*x.Type.Size()), x.Type)
				}
			} else {
				htmlObject(w, c, "", x.Addr, x.Type)
			}
			end = n * x.Type.Size()
		}
		for i := end; i < x.Size; i += c.Process().PtrSize() {
			fmt.Fprintf(w, "<tr><td>f%d</td><td>?</td><td>", i)
			for j := int64(0); j < c.Process().PtrSize(); j++ {
				fmt.Fprintf(w, "%02x ", c.Process().ReadUint8(x.Addr.Add(i+j)))
			}
			fmt.Fprintf(w, "</td></tr>\n")
		}
		fmt.Fprintf(w, "</table>\n")
	})
	fmt.Println("serving on :8080")
	http.ListenAndServe(":8080", nil)
}

func htmlObject(w http.ResponseWriter, c *gocore.Program, name string, a core.Address, t *gocore.Type) {
	switch t.Kind {
	case gocore.KindBool:
		v := c.Process().ReadUint8(a) != 0
		fmt.Fprintf(w, "<tr><td>%s</td><td>%s</td><td>%t</td></tr>\n", name, html.EscapeString(t.String()), v)
	case gocore.KindInt:
		var v int64
		switch t.Size() {
		case 1:
			v = int64(c.Process().ReadInt8(a))
		case 2:
			v = int64(c.Process().ReadInt16(a))
		case 4:
			v = int64(c.Process().ReadInt32(a))
		default:
			v = c.Process().ReadInt64(a)
		}
		fmt.Fprintf(w, "<tr><td>%s</td><td>%s</td><td>%d</td></tr>\n", name, html.EscapeString(t.String()), v)
	case gocore.KindUint:
		var v uint64
		switch t.Size() {
		case 1:
			v = uint64(c.Process().ReadUint8(a))
		case 2:
			v = uint64(c.Process().ReadUint16(a))
		case 4:
			v = uint64(c.Process().ReadUint32(a))
		default:
			v = c.Process().ReadUint64(a)
		}
		fmt.Fprintf(w, "<tr><td>%s</td><td>%s</td><td>%d</td></tr>\n", name, html.EscapeString(t.String()), v)
	case gocore.KindFloat:
		var v float64
		switch t.Size() {
		case 4:
			v = float64(math.Float32frombits(c.Process().ReadUint32(a)))
		default:
			v = math.Float64frombits(c.Process().ReadUint64(a))
		}
		fmt.Fprintf(w, "<tr><td>%s</td><td>%s</td><td>%f</td></tr>\n", name, html.EscapeString(t.String()), v)
	case gocore.KindComplex:
		var v complex128
		switch t.Size() {
		case 8:
			v = complex128(complex(
				math.Float32frombits(c.Process().ReadUint32(a)),
				math.Float32frombits(c.Process().ReadUint32(a.Add(4)))))

		default:
			v = complex(
				math.Float64frombits(c.Process().ReadUint64(a)),
				math.Float64frombits(c.Process().ReadUint64(a.Add(8))))
		}
		fmt.Fprintf(w, "<tr><td>%s</td><td>%s</td><td>%f</td></tr>\n", name, html.EscapeString(t.String()), v)
	case gocore.KindEface:
		fmt.Fprintf(w, "<tr><td>%s</td><td>*runtime._type</td><td>%s</td></tr>\n", name, htmlPointer(c, c.Process().ReadAddress(a)))
		fmt.Fprintf(w, "<tr><td>%s</td><td>unsafe.Pointer</td><td>%s</td></tr>\n", name, htmlPointer(c, c.Process().ReadAddress(a.Add(c.Process().PtrSize()))))
	case gocore.KindIface:
		fmt.Fprintf(w, "<tr><td>%s</td><td>*runtime.itab</td><td>%s</td></tr>\n", name, htmlPointer(c, c.Process().ReadAddress(a)))
		fmt.Fprintf(w, "<tr><td>%s</td><td>unsafe.Pointer</td><td>%s</td></tr>\n", name, htmlPointer(c, c.Process().ReadAddress(a.Add(c.Process().PtrSize()))))
	case gocore.KindPtr, gocore.KindFunc:
		fmt.Fprintf(w, "<tr><td>%s</td><td>%s</td><td>%s</td></tr>\n", name, html.EscapeString(t.String()), htmlPointer(c, c.Process().ReadAddress(a)))
	case gocore.KindString:
		n := c.Process().ReadInt(a.Add(c.Process().PtrSize()))
		fmt.Fprintf(w, "<tr><td>%s.ptr</td><td>*uint8</td><td>%s</td>", name, htmlPointer(c, c.Process().ReadAddress(a)))
		if n > 0 {
			n2 := n
			ddd := ""
			if n > 100 {
				n2 = 100
				ddd = "..."
			}
			b := make([]byte, n2)
			c.Process().ReadAt(b, c.Process().ReadAddress(a))
			fmt.Fprintf(w, "<td rowspan=\"2\">\"%s\"%s</td>", html.EscapeString(string(b)), ddd)
		} else {
			fmt.Fprintf(w, "<td rowspan=\"2\">\"\"</td>")
		}
		fmt.Fprintf(w, "</tr>\n")
		fmt.Fprintf(w, "<tr><td>%s.len</td><td>int</td><td>%d</td></tr>\n", name, n)
	case gocore.KindSlice:
		fmt.Fprintf(w, "<tr><td>%s.ptr</td><td>*%s</td><td>%s</td></tr>\n", name, t.Elem, htmlPointer(c, c.Process().ReadAddress(a)))
		fmt.Fprintf(w, "<tr><td>%s.len</td><td>int</td><td>%d</td></tr>\n", name, c.Process().ReadInt(a.Add(c.Process().PtrSize())))
		fmt.Fprintf(w, "<tr><td>%s.cap</td><td>int</td><td>%d</td></tr>\n", name, c.Process().ReadInt(a.Add(c.Process().PtrSize()*2)))
	case gocore.KindArray:
		s := t.Elem.Size()
		n := t.Count
		if n*s > 16384 {
			n = (16384 + s - 1) / s
		}
		for i := int64(0); i < n; i++ {
			htmlObject(w, c, fmt.Sprintf("%s[%d]", name, i), a.Add(i*s), t.Elem)
		}
		if n*s != t.Size() {
			fmt.Fprintf(w, "<tr><td>...</td><td>...</td><td>...</td></tr>\n")
		}
	case gocore.KindStruct:
		for _, f := range t.Fields {
			htmlObject(w, c, name+"."+f.Name, a.Add(f.Off), f.Type)
		}

	}
}

func htmlPointer(c *gocore.Program, a core.Address) string {
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
