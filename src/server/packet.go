package server

import (
	"net"
	"time"

	"github.com/dmitry-vovk/dhcp-server/src/config"
	"github.com/google/gopacket/layers"
)

type DP struct {
	Created   time.Time
	SrcMac    net.HardwareAddr
	DstMac    net.HardwareAddr
	EtherType layers.EthernetType
	VLan      []*layers.Dot1Q
	SrcIP     net.IP
	DstIP     net.IP
	SrcPort   layers.UDPPort
	DstPort   layers.UDPPort
	OpCode    byte
	DHCP      *layers.DHCPv4
}

func (dp *DP) getOptions(lease *config.Lease, server *DhcpServer) layers.DHCPOptions {
	return layers.DHCPOptions{
		layers.NewDHCPOption(layers.DHCPOptSubnetMask, []byte(lease.Mask)),
		layers.NewDHCPOption(layers.DHCPOptRouter, []byte(lease.Gateway)),
		layers.NewDHCPOption(layers.DHCPOptDNS, server.config.NameServers),
		layers.NewDHCPOption(layers.DHCPOptBroadcastAddr, []byte(lease.Broadcast)),
		layers.NewDHCPOption(layers.DHCPOptLeaseTime, server.config.LeaseTimeBytes),
		layers.NewDHCPOption(layers.DHCPOptDomainName, []byte(lease.HostName)),
		layers.NewDHCPOption(layers.DHCPOptServerID, []byte(server.config.MyAddress)),
	}
}

func (dp *DP) OfferResponse(lease *config.Lease, server *DhcpServer) *layers.DHCPv4 {
	resp := &layers.DHCPv4{
		Xid:          dp.DHCP.Xid,
		Operation:    layers.DHCPOp(layers.DHCPMsgTypeOffer),
		HardwareType: dp.DHCP.HardwareType,
		ClientHWAddr: dp.DHCP.ClientHWAddr,
		Options:      dp.getOptions(lease, server),
		ClientIP:     dp.DHCP.ClientIP,
		YourClientIP: lease.Ip,
		NextServerIP: server.config.MyAddress,
	}
	resp.Options = append(resp.Options, layers.NewDHCPOption(layers.DHCPOptMessageType, []byte{byte(layers.DHCPMsgTypeOffer)}))
	return resp
}

func (dp *DP) NakResponse(lease *config.Lease, server *DhcpServer) *layers.DHCPv4 {
	return &layers.DHCPv4{
		Xid:          dp.DHCP.Xid,
		Operation:    layers.DHCPOp(layers.DHCPMsgTypeOffer),
		HardwareType: dp.DHCP.HardwareType,
		ClientHWAddr: dp.DHCP.ClientHWAddr,
		Options: layers.DHCPOptions{
			layers.NewDHCPOption(layers.DHCPOptServerID, server.config.MyAddress),
			layers.NewDHCPOption(layers.DHCPOptMessageType, []byte{byte(layers.DHCPMsgTypeNak)}),
		},
		ClientIP:     dp.DHCP.ClientIP,
		YourClientIP: dp.DHCP.YourClientIP,
	}
}

func (dp *DP) AckResponse(lease *config.Lease, server *DhcpServer) *layers.DHCPv4 {
	resp := &layers.DHCPv4{
		Operation:    layers.DHCPOpReply,
		Xid:          dp.DHCP.Xid,
		HardwareType: dp.DHCP.HardwareType,
		ClientHWAddr: dp.DHCP.ClientHWAddr,
		ClientIP:     dp.DHCP.ClientIP,
		YourClientIP: lease.Ip,
		Options:      dp.getOptions(lease, server),
	}
	resp.Options = append(resp.Options, layers.NewDHCPOption(layers.DHCPOptMessageType, []byte{byte(layers.DHCPMsgTypeAck)}))
	return resp
}
