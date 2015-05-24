package server

import (
	"fmt"
	"net"
)

func (s *DhcpServer) vlanList(p *DP) string {
	if p.Dot1adVLan > 0 {
		return fmt.Sprintf("%d.%d", p.Dot1adVLan, p.Dot1qVLan)
	} else {
		return fmt.Sprintf("%d", p.Dot1qVLan)
	}
}

func (s *DhcpServer) getIfIndex(name string) int {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		panic(err)
	}
	return iface.Index
}

func (s *DhcpServer) getIfMac(name string) net.HardwareAddr {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		panic(err)
	}
	return iface.HardwareAddr
}
