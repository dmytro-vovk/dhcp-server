package tcp_resolver

import (
	"config"
	"container/heap"
	"net"
	"server"
	"sync"
	"time"
)

type resolverDef struct {
	Address string
	Limit   uint
}

type Resolver struct {
	sync.Mutex
	address     *net.TCPAddr
	maxConns    uint
	connections *connHeap
}

func New(resolver resolverDef) (*Resolver, error) {
	r := &Resolver{
		maxConns:    resolver.Limit,
		connections: &connHeap{},
	}
	if address, err := net.ResolveTCPAddr("tcp4", resolver.Address); err != nil {
		return nil, err
	} else {
		r.address = address
	}
	heap.Init(r.connections)
	return r, nil
}

func (r *Resolver) Resolve(p *server.DataPacket) *config.Lease {
	r.Lock()
	if r.connections.Len() == 0 { // depleted, add new
		r.connections.Push(r.connect())
	}
	conn := r.connections.Pop().(*conn)
	r.Unlock()
	conn.Conn.SetWriteDeadline(time.Now().Add(time.Second))
	if _, err := conn.Conn.Write(append(p.Marshal(), 13)); err != nil {
		// TODO
	}
	conn.Used = time.Now()
	if r.connections.Len() < int(r.maxConns) { // if limit exceeded, throw it away
		r.connections.Push(conn)
	}
	return nil
}

func (r *Resolver) connect() *net.TCPConn {
	for {
		if conn, err := net.DialTCP("tcp4", nil, r.address); err == nil {
			return conn
		}
		time.Sleep(time.Second)
	}
}
