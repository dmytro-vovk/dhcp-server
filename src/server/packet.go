package server

import (
	"config"
	"net"

	"github.com/google/gopacket/layers"
	"github.com/krolaw/dhcp4"
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
		MsgType     dhcp4.MessageType  // 0x53
		Options     dhcp4.Options      //
		HostName    string             // 0xc
		RequestList []dhcp4.OptionCode // 0x37
		RequestedIp net.IP             // 0x32
	}
}

func (dp *DP) getOptions(p dhcp4.Packet, lease *config.Lease, server *DhcpServer) dhcp4.Options {
	options := dhcp4.Options{
		dhcp4.OptionSubnetMask:       []byte(lease.Mask),
		dhcp4.OptionRouter:           []byte(lease.Gateway),
		dhcp4.OptionDomainNameServer: []byte(server.config.NameServers),
	}
	for _, opt := range dp.Dhcp.Options[dhcp4.OptionParameterRequestList] {
		optionCode := dhcp4.OptionCode(opt)
		switch optionCode {
		case dhcp4.OptionSubnetMask:
		case dhcp4.OptionRouter:
		case dhcp4.OptionDomainNameServer:
		case dhcp4.OptionDomainName:
			options[optionCode] = []byte(lease.HostName)
		case dhcp4.OptionBroadcastAddress:
			options[optionCode] = []byte(lease.Broadcast)
		case dhcp4.OptionInterfaceMTU:
		case dhcp4.OptionTimeOffset:
		case dhcp4.OptionNetBIOSOverTCPIPNameServer:
		case dhcp4.OptionNetBIOSOverTCPIPScope:
		case dhcp4.OptionNetworkTimeProtocolServers:
		case dhcp4.OptionClasslessRouteFormat:
		case dhcp4.OptionHostName:
		case dhcp4.OptionStaticRoute:
		default:
			//log.Printf("Option %d (%x) not implemented", opt, opt)
		}
	}
	return options
}

func (dp *DP) OfferResponse(lease *config.Lease, server *DhcpServer) *dhcp4.Packet {
	options := dp.getOptions(dp.Dhcp.packet, lease, server)
	p := dhcp4.ReplyPacket(
		dp.Dhcp.packet,                                                              // request packet
		dhcp4.Offer,                                                                 // message type
		server.config.MyAddress,                                                     // server address
		lease.Ip,                                                                    // client address
		server.config.LeaseTime,                                                     // lease time
		options.SelectOrderOrAll(dp.Dhcp.Options[dhcp4.OptionParameterRequestList]), // options
	)
	p.SetYIAddr(lease.Ip)
	return &p
}

func (dp *DP) NakResponse(lease *config.Lease, server *DhcpServer) *dhcp4.Packet {
	p := dhcp4.ReplyPacket(
		dp.Dhcp.packet,          // request packet
		dhcp4.NAK,               // message type
		server.config.MyAddress, // server address
		nil, // client address
		0,   // lease time
		nil, // options
	)
	return &p
}

func (dp *DP) AckResponse(lease *config.Lease, server *DhcpServer) *dhcp4.Packet {
	options := dp.getOptions(dp.Dhcp.packet, lease, server)
	p := dhcp4.ReplyPacket(
		dp.Dhcp.packet,                                                              // request packet
		dhcp4.ACK,                                                                   // message type
		server.config.MyAddress,                                                     // server address
		net.IP(dp.Dhcp.Options[dhcp4.OptionRequestedIPAddress]),                     // client address
		server.config.LeaseTime,                                                     // lease time
		options.SelectOrderOrAll(dp.Dhcp.Options[dhcp4.OptionParameterRequestList]), // options
	)
	p.SetYIAddr(lease.Ip)
	p.SetCIAddr(lease.Ip)
	return &p
}
