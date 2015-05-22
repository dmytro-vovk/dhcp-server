package server

import (
	"dhcp4"
	"fmt"
	"net"
	"strings"
)

func (s *DhcpServer) getMsgTypeName(msgType dhcp4.MessageType) string {
	switch msgType {
	case dhcp4.Request:
		return "Request"
	case dhcp4.Release:
		return "Release"
	case dhcp4.Discover:
		return "Discover"
	case dhcp4.ACK:
		return "ACK"
	case dhcp4.NAK:
		return "NAK"
	case dhcp4.Decline:
		return "Decline"
	case dhcp4.Inform:
		return "Inform"
	case dhcp4.Offer:
		return "Offer"
	default:
		return "unknown"
	}
}

func (s *DhcpServer) vlanList(p *DP) string {
	if len(p.VLan) > 0 {
		list := []string{}
		for _, v := range p.VLan {
			list = append(list, fmt.Sprintf("%d", v))
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
