package server

import "config"

type DefaultResolver struct {
	conf *config.ServerConfig
}

func NewDefaultResolver(conf *config.ServerConfig) *DefaultResolver {
	return &DefaultResolver{conf}
}

func (dr *DefaultResolver) Resolve(p *DataPacket) *config.Lease {
	if lease, ok := dr.conf.Leases[p.SrcMac.String()]; ok {
		return &lease
	}
	v := config.VLanMac{}
	v.Set(p.VLan, p.SrcMac)
	if lease, ok := dr.conf.VLans[v]; ok {
		return &lease
	}
	v.Set(p.VLan, nil)
	if lease, ok := dr.conf.VLans[v]; ok {
		return &lease
	}
	return nil
}
