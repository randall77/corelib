package gocore

import (
	"sort"

	"github.com/randall77/corelib/core"
)

func (p *Process) reverseEdges() {
	p.reverse = make([][]core.Address, p.nObj)
	p.ForEachObject(func(x Object) bool {
		p.ForEachPtr(x, func(i int64, y Object, _ int64) bool {
			idx, _ := p.findObjectIndex(p.Addr(y))
			p.reverse[idx] = append(p.reverse[idx], p.Addr(x).Add(i))
			return true
		})
		return true
	})
	p.ForEachRoot(func(r *Root) bool {
		p.ForEachRootPtr(r, func(i int64, y Object, j int64) bool {
			idx, _ := p.findObjectIndex(p.Addr(y))
			p.reverse[idx] = append(p.reverse[idx], r.Addr.Add(i))
			return true
		})
		return true
	})

	// Make root index.
	p.ForEachRoot(func(r *Root) bool {
		p.rootIdx = append(p.rootIdx, r)
		return true
	})
	sort.Slice(p.rootIdx, func(i, j int) bool { return p.rootIdx[i].Addr < p.rootIdx[j].Addr })
}

// ForEachReversePtr calls fn for all pointers it finds pointing to y.
// It calls fn with:
//   the object or root which points to y (exactly one will be non-nil)
//   the offset i in that object or root where the pointer appears.
//   the offset j in y where the pointer points.
// If fn returns false, ForEachReversePtr returns immediately.
// FlagReverse must have been passed to Core when p was constructed.
func (p *Process) ForEachReversePtr(y Object, fn func(x Object, r *Root, i, j int64) bool) {
	idx, _ := p.findObjectIndex(p.Addr(y))
	for _, a := range p.reverse[idx] {
		// Read pointer, compute offset in y.
		ptr := p.proc.ReadPtr(a)
		j := ptr.Sub(p.Addr(y))

		// Find source of pointer.
		x, i := p.FindObject(a)
		if x != 0 {
			// Source is an object.
			if !fn(x, nil, i, j) {
				return
			}
			continue
		}
		// Source is a root.
		k := sort.Search(len(p.rootIdx), func(k int) bool {
			r := p.rootIdx[k]
			return a < r.Addr.Add(r.Type.Size)
		})
		r := p.rootIdx[k]
		if !fn(0, r, a.Sub(r.Addr), j) {
			return
		}
	}
}
