package server

import (
	"code.google.com/p/gopacket/layers"
	"config"
	"dhcp4"
	"fmt"
	"github.com/kr/pretty"
	"net"
	"strings"
)

type DP struct {
	SrcMac    net.HardwareAddr
	DstMac    net.HardwareAddr
	EtherType layers.EthernetType
	VLan      []uint16
	SrcIP     net.IP
	DstIP     net.IP
	SrcPort   layers.UDPPort
	DstPort   layers.UDPPort
	app       []byte
	OpCode    byte
	Dhcp      struct {
		packet      dhcp4.Packet
		MsgType     dhcp4.MessageType // 0x53
		Cookie      []byte
		Options     dhcp4.Options //
		HostName    string        // 0xc
		RequestList []byte        // 0x37
		RequestedIp string        // 0x32
	}
}

func (dp *DP) OfferResponse(lease config.Lease, server *DhcpServer) *dhcp4.Packet {
	var options []dhcp4.Option
	for optionCode, _ := range dp.Dhcp.Options {
		switch optionCode {
		case dhcp4.OptionDomainNameServer:
			options = append(options, dhcp4.Option{
				Code:  optionCode,
				Value: []byte(server.config.NameServers[0]),
			})
		case dhcp4.OptionDomainName:
			if lease.HostName != "" {
				options = append(options, dhcp4.Option{
					Code:  optionCode,
					Value: []byte(lease.HostName),
				})
			}
		}
	}
	p := dhcp4.ReplyPacket(
		dp.Dhcp.packet,               // request packet
		dhcp4.Offer,                  // message type
		server.config.MyAddress[0:4], // server address
		lease.Ip,                     // client address
		server.config.LeaseTime,      // lease time
		options,                      // options
	)
	return &p
}

func (dp *DP) NakResponse(server *DhcpServer) *dhcp4.Packet {
	p := dhcp4.ReplyPacket(
		dp.Dhcp.packet,               // request packet
		dhcp4.NAK,                    // message type
		server.config.MyAddress[0:4], // server address
		net.IPv4(0, 0, 0, 0),         // client address
		server.config.LeaseTime,      // lease time
		[]dhcp4.Option{},             // options
	)
	return &p
}

func (dp *DP) AckResponse(lease config.Lease, server *DhcpServer) *dhcp4.Packet {
	var options []dhcp4.Option
	for optionCode, _ := range dp.Dhcp.Options {
		switch optionCode {
		case dhcp4.OptionDomainNameServer:
			options = append(options, dhcp4.Option{
				Code:  optionCode,
				Value: []byte(server.config.NameServers[0]),
			})
		case dhcp4.OptionDomainName:
			if lease.HostName != "" {
				options = append(options, dhcp4.Option{
					Code:  optionCode,
					Value: []byte(lease.HostName),
				})
			}
		}
	}
	p := dhcp4.ReplyPacket(
		dp.Dhcp.packet,               // request packet
		dhcp4.ACK,                    // message type
		server.config.MyAddress[0:4], // server address
		lease.Ip,                     // client address
		server.config.LeaseTime,      // lease time
		options,                      // options
	)
	return &p
}

func (dp *DP) String() string {
	var out string
	switch dp.Dhcp.MsgType {
	case dhcp4.Request:
		out = "Type: request"
	case dhcp4.Release:
		out = "Type: release"
	case dhcp4.Discover:
		out = "Type: discover"
	case dhcp4.ACK:
		out = "Type: ack"
	case dhcp4.NAK:
		out = "Type: nak"
	case dhcp4.Decline:
		out = "Type: decline"
	case dhcp4.Inform:
		out = "Type: inform"
	case dhcp4.Offer:
		out = "Type: offer"
	}
	out = out + pretty.Sprintf("\nSrc MAC: %s", dp.SrcMac)
	out = out + pretty.Sprintf("\nDst MAC: %s", dp.DstMac)
	out = out + "\nHost name: " + dp.Dhcp.HostName
	out = out + "\nRequested IP: " + dp.Dhcp.RequestedIp
	var reqs []string
	for _, r := range dp.Dhcp.RequestList {
		switch dhcp4.OptionCode(r) {
		case dhcp4.OptionSubnetMask:
			reqs = append(reqs, "subnet mask")
		case dhcp4.OptionTimeOffset:
			reqs = append(reqs, "time offset")
		case dhcp4.OptionRouter:
			reqs = append(reqs, "router")
		case dhcp4.OptionBroadcastAddress:
			reqs = append(reqs, "broadcast address")
		case dhcp4.OptionDomainName:
			reqs = append(reqs, "domain name")
		case dhcp4.OptionDomainNameServer:
			reqs = append(reqs, "dns server")
		case dhcp4.OptionHostName:
			reqs = append(reqs, "host name")
		case dhcp4.OptionNetBIOSOverTCPIPNameServer:
			reqs = append(reqs, "netbios name")
		case dhcp4.OptionNetBIOSOverTCPIPScope:
			reqs = append(reqs, "netbios scope")
		case dhcp4.OptionNetworkTimeProtocolServers:
			reqs = append(reqs, "NTP server")
		case dhcp4.OptionClasslessRouteFormat:
			reqs = append(reqs, "classless route format")
		case dhcp4.OptionDomainSearchList:
			reqs = append(reqs, "domain search list")
		case dhcp4.OptionInterfaceMTU:
			reqs = append(reqs, "MTU")
		default:
			reqs = append(reqs, fmt.Sprintf("%d", r))
		}
	}
	out = out + "\nRequest: " + strings.Join(reqs, ", ")
	out = out + pretty.Sprintf("\nOptions: %# v", dp.Dhcp.Options)
	return out + "\n"
}
