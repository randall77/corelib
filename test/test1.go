package main

import "fmt"

var q *int

type T struct {
	p     *int
	left  *T
	right *T
}

func (t *T) sum() int {
	n := 0
	left := t.left
	right := t.right
	if left != nil {
		n += left.sum()
	}
	if right != nil {
		n += right.sum()
	}
	n += *t.p
	return n
}

func main() {
	const d = 8
	a := make([]T, 1<<d-1)
	fmt.Printf("%p - %p\n", &a[0], &a[len(a)-1])

	for i := range a {
		a[i].p = new(int)
		if 2*i+1 < len(a) {
			a[i].left = &a[2*i+1]
		}
		if 2*i+2 < len(a) {
			a[i].right = &a[2*i+2]
		}
	}

	// fault somewhere (alternate left/right in stack trace)
	a[0xaa].p = nil

	_ = a[0].sum()
}
