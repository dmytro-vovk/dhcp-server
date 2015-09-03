package tcp_resolver

import (
	"config"
	"server"
)

type Resolver struct {
	address string
}

func New(address string) (*Resolver, error) {
	return &Resolver{
		address: address,
	}, nil
}

func (r *Resolver) Resolve(p *server.DataPacket) *config.Lease {
	// TODO implement
	return nil
}
