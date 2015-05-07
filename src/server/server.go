package server

import (
	"code.google.com/p/gopacket"
	"code.google.com/p/gopacket/layers"
	"code.google.com/p/gopacket/pcap"
	"config"
	"dhcp4"
	"errors"
	"fmt"
	"log"
	"net"
	"raw_packet"
	"strings"
	"syscall"
)

type DhcpServer struct {
	config       *config.ServerConfig
	handle       *pcap.Handle
	fd           int
	packetSource *gopacket.PacketSource
	ifIndex      int
	addr         syscall.SockaddrLinklayer
}

func New(config *config.ServerConfig) *DhcpServer {
	server := DhcpServer{
		config: config,
	}
	config.MyMac = server.getIfMac(config.Listen)
	server.ifIndex = server.getIfIndex(server.config.Listen)
	return &server
}

func (s *DhcpServer) Run() {
	var err error
	if s.handle, err = pcap.OpenLive(s.config.Listen, 1600, true, 0); err != nil {
		log.Fatalf("Error opening live interface: %s", err)
	} else if err := s.handle.SetBPFFilter("udp and dst port 67"); err != nil {
		log.Fatalf("Error setting BPF filter: %s", err)
	} else {
		s.fd, err = syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
		if err != nil {
			log.Fatalf("Error opening raw socket: %s", err)
		}
		s.packetSource = gopacket.NewPacketSource(s.handle, s.handle.LinkType())
		s.run()
	}
}

func (s *DhcpServer) run() {
	s.addr = syscall.SockaddrLinklayer{
		Protocol: 4,
		Halen:    6,
		Pkttype:  0,
		Ifindex:  s.ifIndex,
	}
	for packet := range s.packetSource.Packets() {
		p, err := s.parsePacket(packet)
		if err != nil {
			fmt.Printf("Error parsing incoming packet: %s", err)
			continue
		}
		log.Printf(
			"%s from mac %s, ip %s, host %s, vlan %s",
			s.getMsgTypeName(p.Dhcp.MsgType),
			p.SrcMac,
			p.SrcIP,
			p.Dhcp.HostName,
			s.vlanList(p.VLan))
		s.respond(p)
	}
}

func (s *DhcpServer) vlanList(vl []uint16) string {
	sVlan := make([]string, len(vl))
	for i, v := range vl {
		sVlan[i] = fmt.Sprintf("%d", v)
	}
	return strings.Join(sVlan, ".")
}

func (s *DhcpServer) respond(p *DP) {
	var response *raw_packet.RawPacket
	switch p.Dhcp.MsgType {
	case dhcp4.Request:
		if lease, ok := s.config.Leases[p.SrcMac.String()]; ok {
			if p.SrcIP.Equal(lease.Ip) {
				response = s.sendAck(p, lease)
			} else {
				response = s.sendNak(p, lease)
			}
		} else {
			log.Printf("Not offering to %s", p.SrcMac)
		}
	case dhcp4.Discover:
		if lease, ok := s.config.Leases[p.SrcMac.String()]; ok {
			response = s.sendOffer(p, lease)
		} else {
			log.Printf("Not offering to %s", p.SrcMac)
		}
	default:
		log.Printf("Request %s (%d) not yet implemented", s.getMsgTypeName(p.Dhcp.MsgType), p.Dhcp.MsgType)
	}
	if response != nil {
		log.Printf(
			"Responding to %s (vlan %s) with %s",
			p.SrcMac,
			s.vlanList(p.VLan),
			s.getMsgTypeName(response.DhcpType),
		)
		addr := s.addr
		copy(addr.Addr[:], p.DstMac[0:8])
		err := syscall.Sendto(s.fd, response.Marshal(), 0, &addr)
		if err != nil {
			log.Fatalf("Sendto failed: %s", err)
		}
	} else {
		log.Printf(
			"Not responding to %s (vlan %s) with %s",
			p.SrcMac,
			s.vlanList(p.VLan),
			s.getMsgTypeName(response.DhcpType),
		)
	}
}

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

func (s *DhcpServer) sendOffer(p *DP, lease config.Lease) *raw_packet.RawPacket {
	resp := p.OfferResponse(lease, s)
	responsePacket := &raw_packet.RawPacket{
		DhcpType:  dhcp4.Offer,
		EtherType: p.EtherType,
		VLan:      p.VLan,
		Payload:   []byte(*resp),
		SrcIp:     s.config.MyAddress,
		DstIp:     p.SrcIP,
	}
	copy(responsePacket.SrcMac[:], s.config.MyMac[0:8])
	copy(responsePacket.DstMac[:], p.SrcMac[0:8])
	return responsePacket
}

func (s *DhcpServer) sendAck(p *DP, lease config.Lease) *raw_packet.RawPacket {
	resp := p.AckResponse(lease, s)
	responsePacket := &raw_packet.RawPacket{
		DhcpType:  dhcp4.ACK,
		EtherType: p.EtherType,
		VLan:      p.VLan,
		Payload:   []byte(*resp),
		SrcIp:     s.config.MyAddress,
		DstIp:     p.SrcIP,
	}
	copy(responsePacket.SrcMac[:], s.config.MyMac[0:8])
	copy(responsePacket.DstMac[:], p.SrcMac[0:8])
	return responsePacket
}

func (s *DhcpServer) sendNak(p *DP, lease config.Lease) *raw_packet.RawPacket {
	resp := p.NakResponse(s)
	responsePacket := &raw_packet.RawPacket{
		DhcpType:  dhcp4.NAK,
		EtherType: p.EtherType,
		VLan:      p.VLan,
		Payload:   []byte(*resp),
		SrcIp:     s.config.MyAddress,
		DstIp:     p.SrcIP,
	}
	copy(responsePacket.SrcMac[:], s.config.MyMac[0:8])
	copy(responsePacket.DstMac[:], p.SrcMac[0:8])
	return responsePacket
}

func (s *DhcpServer) parsePacket(p gopacket.Packet) (*DP, error) {
	dp := &DP{}
	ethernet := p.LinkLayer().(*layers.Ethernet)
	dp.SrcMac = ethernet.SrcMAC
	dp.DstMac = ethernet.DstMAC
	dp.EtherType = ethernet.EthernetType
	if dp.EtherType != 0x800 {
		var offset int
		for {
			dp.VLan = append(dp.VLan, uint16(ethernet.Payload[offset])<<8+uint16(ethernet.Payload[offset+1]))
			nextType := uint16(ethernet.Payload[offset+2])<<8 + uint16(ethernet.Payload[offset+3])
			if nextType == 0x800 {
				break
			}
			offset = offset + 4
		}
	}
	ip := p.NetworkLayer().(*layers.IPv4)
	dp.SrcIP = ip.SrcIP
	dp.DstIP = ip.DstIP
	transport := p.TransportLayer().(*layers.UDP)
	dp.SrcPort = transport.SrcPort
	dp.DstPort = transport.DstPort
	dp.app = p.ApplicationLayer().Payload()
	dp.OpCode = dp.app[0]
	dp.Dhcp.packet = dhcp4.Packet(dp.app)
	dp.Dhcp.Cookie = dp.Dhcp.packet.Cookie()
	dp.Dhcp.Options = dp.Dhcp.packet.ParseOptions()
	if msgType, ok := dp.Dhcp.Options[dhcp4.OptionDHCPMessageType]; ok {
		if len(msgType) != 1 {
			return nil, errors.New("Cannot parse DHCP message type")
		}
		dp.Dhcp.MsgType = dhcp4.MessageType(msgType[0])
	}
	if hostName, ok := dp.Dhcp.Options[dhcp4.OptionHostName]; ok {
		dp.Dhcp.HostName = string(hostName)
	}
	if requestList, ok := dp.Dhcp.Options[dhcp4.OptionParameterRequestList]; ok {
		dp.Dhcp.RequestList = requestList
	}
	if requestedIp, ok := dp.Dhcp.Options[dhcp4.OptionRequestedIPAddress]; ok {
		if len(requestedIp) == 4 {
			dp.Dhcp.RequestedIp = net.IPv4(requestedIp[0], requestedIp[1], requestedIp[2], requestedIp[3]).String()
		}
	}
	return dp, nil
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
