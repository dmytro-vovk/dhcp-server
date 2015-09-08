package tcp_resolver

import (
	"net"
	"time"
)

type conn struct {
	Used time.Time
	Conn *net.TCPConn
}

type connHeap []*conn

func (c connHeap) Len() int {
	return len(c)
}

func (c connHeap) Swap(i, j int) {
	c[i], c[j] = c[j], c[i]
}

func (c connHeap) Less(i, j int) bool {
	return c[i].Used.Before(c[j].Used)
}

func (c *connHeap) Push(x interface{}) {
	*c = append(*c, x.(*conn))
}

func (c *connHeap) Pop() interface{} {
	old := *c
	n := len(old)
	x := old[n-1]
	*c = old[0 : n-1]
	return x
}
