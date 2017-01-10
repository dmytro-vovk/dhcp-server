// +build linux
package server

import (
	"config"
	"errors"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/krolaw/dhcp4"
	"log"
	"net"
	"raw_packet"
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
	} else if err := s.handle.SetBPFFilter("(udp and dst port 67) or (vlan and udp and dst port 67)"); err != nil {
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
			p.Dhcp.MsgType,
			p.SrcMac,
			p.SrcIP,
			p.Dhcp.HostName,
			s.vlanList(p))
		s.respond(p)
	}
}

func (s *DhcpServer) respond(p *DP) {
	var response *raw_packet.RawPacket
	switch p.Dhcp.MsgType {
	case dhcp4.Request:
		response = s.processRequest(p)
	case dhcp4.Discover:
		response = s.processDiscover(p)
	default:
		log.Printf("Request %s (%d) not yet implemented", p.Dhcp.MsgType, p.Dhcp.MsgType)
	}
	if response != nil {
		log.Printf(
			"%s to %s (vlan %s): %s",
			response.DhcpType,
			p.SrcMac,
			s.vlanList(p),
			response.OfferedIp,
		)
		addr := s.addr
		copy(addr.Addr[:], p.DstMac[0:8])
		err := syscall.Sendto(s.fd, response.Marshal(), 0, &addr)
		if err != nil {
			log.Fatalf("Sendto failed: %s", err)
		}
	} else {
		log.Printf(
			"Not responding to %s (vlan %s)",
			p.SrcMac,
			s.vlanList(p),
		)
	}
}

func (s *DhcpServer) processRequest(p *DP) *raw_packet.RawPacket {
	if lease := s.getLease(p); lease != nil {
		if p.Dhcp.packet.CIAddr() == nil {
			return s.prepareOffer(p, lease)
		} else if lease.Ip.Equal(p.Dhcp.packet.CIAddr()) {
			return s.prepareAck(p, lease)
		} else if lease.Ip.Equal(p.Dhcp.RequestedIp) {
			return s.prepareAck(p, lease)
		}
		log.Printf("NAK: client wants %s, got %s", p.Dhcp.RequestedIp, lease.Ip)
		return s.prepareNak(p, lease)
	}
	return nil
}

func (s *DhcpServer) processDiscover(p *DP) *raw_packet.RawPacket {
	if lease := s.getLease(p); lease != nil {
		return s.prepareOffer(p, lease)
	}
	return nil
}

func (s *DhcpServer) getLease(p *DP) *config.Lease {
	if lease, ok := s.config.Leases[p.SrcMac.String()]; ok {
		return &lease
	}
	v := config.VLanMac{}
	v.Set(p.VLan, p.SrcMac)
	if lease, ok := s.config.VLans[v]; ok {
		return &lease
	}
	v.Set(p.VLan, nil)
	if lease, ok := s.config.VLans[v]; ok {
		return &lease
	}
	return nil
}

func (s *DhcpServer) prepareOffer(p *DP, lease *config.Lease) *raw_packet.RawPacket {
	resp := p.OfferResponse(lease, s)
	responsePacket := &raw_packet.RawPacket{
		DhcpType:  dhcp4.Offer,
		EtherType: p.EtherType,
		VLan:      p.VLan,
		Payload:   []byte(*resp),
		SrcIp:     s.config.MyAddress,
		DstIp:     p.SrcIP,
		OfferedIp: lease.Ip,
		DstMac:    p.SrcMac,
		SrcMac:    s.config.MyMac,
	}
	return responsePacket
}

func (s *DhcpServer) prepareAck(p *DP, lease *config.Lease) *raw_packet.RawPacket {
	resp := p.AckResponse(lease, s)
	responsePacket := &raw_packet.RawPacket{
		DhcpType:  dhcp4.ACK,
		EtherType: p.EtherType,
		VLan:      p.VLan,
		Payload:   []byte(*resp),
		SrcIp:     s.config.MyAddress,
		DstIp:     p.Dhcp.packet.CIAddr(),
		OfferedIp: lease.Ip,
		DstMac:    p.SrcMac,
		SrcMac:    s.config.MyMac,
	}
	return responsePacket
}

func (s *DhcpServer) prepareNak(p *DP, lease *config.Lease) *raw_packet.RawPacket {
	resp := p.NakResponse(lease, s)
	responsePacket := &raw_packet.RawPacket{
		DhcpType:  dhcp4.NAK,
		EtherType: p.EtherType,
		VLan:      p.VLan,
		Payload:   []byte(*resp),
		SrcIp:     s.config.MyAddress,
		DstIp:     p.SrcIP,
		OfferedIp: lease.Ip,
		DstMac:    p.SrcMac,
		SrcMac:    s.config.MyMac,
	}
	return responsePacket
}

func (s *DhcpServer) parsePacket(p gopacket.Packet) (*DP, error) {
	dp := &DP{}
	ethernet := p.LinkLayer().(*layers.Ethernet)
	dp.SrcMac = ethernet.SrcMAC
	dp.DstMac = ethernet.DstMAC
	dp.EtherType = ethernet.EthernetType
	for _, l := range p.Layers() {
		if l.LayerType() == layers.LayerTypeDot1Q {
			dp.VLan = append(dp.VLan, uint16(l.LayerContents()[0])<<8+uint16(l.LayerContents()[1]))
			if len(dp.VLan) > 1 {
				// cut to 12 lower bit
				dp.VLan[1] = dp.VLan[1] - dp.VLan[1]>>12<<12
			}
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
		dp.Dhcp.RequestList = make([]dhcp4.OptionCode, len(requestList))
		for i, code := range requestList {
			dp.Dhcp.RequestList[i] = dhcp4.OptionCode(code)
		}
	}
	if requestedIp, ok := dp.Dhcp.Options[dhcp4.OptionRequestedIPAddress]; ok {
		if len(requestedIp) == 4 {
			dp.Dhcp.RequestedIp = net.IPv4(requestedIp[0], requestedIp[1], requestedIp[2], requestedIp[3])
		}
	}
	return dp, nil
}
