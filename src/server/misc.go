package server

import (
	"fmt"
	"net"
	"strings"
)

func (s *DhcpServer) vlanList(p *DP) string {
	if len(p.VLan) > 0 {
		list := []string{}
		for _, v := range p.VLan {
			list = append(list, fmt.Sprintf("%d", v.VLANIdentifier))
		}
		return strings.Join(list, ".")
	} else {
		return "0"
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
