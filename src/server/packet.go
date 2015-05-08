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
	SrcMac     net.HardwareAddr
	DstMac     net.HardwareAddr
	EtherType  layers.EthernetType
	Dot1adVLan uint16
	Dot1qVLan  uint16
	SrcIP      net.IP
	DstIP      net.IP
	SrcPort    layers.UDPPort
	DstPort    layers.UDPPort
	app        []byte
	OpCode     byte
	Dhcp       struct {
		packet      dhcp4.Packet
		MsgType     dhcp4.MessageType  // 0x53
		Options     dhcp4.Options      //
		HostName    string             // 0xc
		RequestList []dhcp4.OptionCode // 0x37
		RequestedIp net.IP             // 0x32
	}
}

func (dp *DP) getOptions(lease config.Lease, server *DhcpServer) dhcp4.Options {
	/* huge TODO
	var options dhcp4.Options
	opts := dp.String()
	log.Printf(opts)
	for _, optionCode := range dp.Dhcp.RequestList {
		log.Printf("Option %d", optionCode)
		switch optionCode {
		case dhcp4.OptionDomainNameServer:
			for _, ns := range server.config.NameServers {
				options = append(options, dhcp4.Option{
					Code:  optionCode,
					Value: []byte(ns.To4()),
				})
				break
			}
		case dhcp4.OptionDomainName:
			if lease.HostName != "" {
				options = append(options, dhcp4.Option{
					Code:  optionCode,
					Value: []byte(lease.HostName),
				})
			}
		case dhcp4.OptionSubnetMask:
		case dhcp4.OptionRouter:
			options = append(options, dhcp4.Option{
				Code:  optionCode,
				Value: []byte(lease.Gateway.To4()),
			})
		case dhcp4.OptionTimeOffset:
			options = append(options, dhcp4.Option{
				Code: optionCode,
				Value: []byte{
					0,
					0,
					byte(server.config.TimeOffset >> 8),
					byte(server.config.TimeOffset),
				},
			})
		case dhcp4.OptionInterfaceMTU:
			options = append(options, dhcp4.Option{
				Code:  optionCode,
				Value: []byte{byte(lease.MTU << 8), byte(lease.MTU)},
			})
		case dhcp4.OptionHostName:
			if lease.HostName != "" {
				options = append(options, dhcp4.Option{
					Code:  optionCode,
					Value: []byte("host.local"),
				})
			}
		case dhcp4.OptionBroadcastAddress:
			options = append(options, dhcp4.Option{
				Code:  optionCode,
				Value: []byte(lease.Broadcast.To4()),
			})
		case dhcp4.OptionRequestedIPAddress:
			options = append(options, dhcp4.Option{
				Code:  optionCode,
				Value: []byte(lease.Ip.To4()),
			})
		case dhcp4.OptionDHCPMessageType: // skipped
		case dhcp4.OptionParameterRequestList: // skipped
		default:
			log.Printf("Option %d (%x) not implemented", optionCode, optionCode)
		}
	}
	*/
	nameServers := []byte{}
	for _, ns := range server.config.NameServers {
		nameServers = append(nameServers, []byte(ns.To4())...)
	}
	options := dhcp4.Options{
		dhcp4.OptionSubnetMask:       []byte(lease.Mask.To4()),
		dhcp4.OptionRouter:           []byte(lease.Gateway.To4()),
		dhcp4.OptionDomainNameServer: nameServers,
	}
	return options
}

func (dp *DP) OfferResponse(lease config.Lease, server *DhcpServer) *dhcp4.Packet {
	options := dp.getOptions(lease, server)
	p := dhcp4.ReplyPacket(
		dp.Dhcp.packet,                                                              // request packet
		dhcp4.Offer,                                                                 // message type
		server.config.MyAddress.To4(),                                               // server address
		lease.Ip.To4(),                                                              // client address
		server.config.LeaseTime,                                                     // lease time
		options.SelectOrderOrAll(dp.Dhcp.Options[dhcp4.OptionParameterRequestList]), // options
	)
	return &p
}

func (dp *DP) NakResponse(lease config.Lease, server *DhcpServer) *dhcp4.Packet {
	p := dhcp4.ReplyPacket(
		dp.Dhcp.packet,                // request packet
		dhcp4.NAK,                     // message type
		server.config.MyAddress.To4(), // server address
		nil, // client address
		0,   // lease time
		nil, // options
	)
	return &p
}

func (dp *DP) AckResponse(lease config.Lease, server *DhcpServer) *dhcp4.Packet {
	options := dp.getOptions(lease, server)
	p := dhcp4.ReplyPacket(
		dp.Dhcp.packet,                                                              // request packet
		dhcp4.ACK,                                                                   // message type
		server.config.MyAddress.To4(),                                               // server address
		net.IP(dp.Dhcp.Options[dhcp4.OptionRequestedIPAddress]),                     // client address
		server.config.LeaseTime,                                                     // lease time
		options.SelectOrderOrAll(dp.Dhcp.Options[dhcp4.OptionParameterRequestList]), // options
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
	out = out + "\nRequested IP: " + dp.Dhcp.RequestedIp.String()
	out = out + "\n802.1Q VLan: " + fmt.Sprintf("%d", dp.Dot1qVLan)
	out = out + "\n802.1ad VLan: " + fmt.Sprintf("%d", dp.Dot1adVLan)
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
	//out = out + pretty.Sprintf("\nOptions: %# v", dp.Dhcp.Options)
	return out + "\n"
}
