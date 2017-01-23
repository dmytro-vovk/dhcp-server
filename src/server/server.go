// +build linux

package server

import (
	"fmt"
	"log"
	"net"
	"syscall"

	"github.com/dmitry-vovk/dhcp-server/src/config"
	"github.com/dmitry-vovk/dhcp-server/src/raw_packet"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"time"
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
		s.respond(p)
		log.Printf(
			"%s from mac %s, ip %s, vlan %s",
			p.DHCP.Operation,
			p.SrcMac,
			p.SrcIP,
			s.vlanList(p))
	}
}

func (s *DhcpServer) respond(p *DP) {
	var response *raw_packet.RawPacket
	switch p.DHCP.Operation {
	case layers.DHCPOpRequest:
		response = s.processRequest(p)
	default:
		log.Printf("Request %q not yet implemented", p.DHCP.Operation)
	}
	if response != nil {
		log.Printf(
			"%s to %s (vlan %s): %s (%d ms)",
			response.DhcpType,
			p.SrcMac,
			s.vlanList(p),
			response.OfferedIp,
			time.Now().Sub(p.Created).Nanoseconds()/1000,
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
		switch {
		case p.DHCP.ClientIP.Equal(net.IPv4zero):
			return s.prepareOffer(p, lease)
		case lease.Ip.Equal(p.DHCP.YourClientIP) || lease.Ip.Equal(p.DHCP.ClientIP):
			return s.prepareAck(p, lease)
		}
		log.Printf("NAK: client wants %s, got %s", p.DHCP.YourClientIP, lease.Ip)
		return s.prepareNak(p, lease)
	}
	return nil
}

func (s *DhcpServer) getLease(p *DP) *config.Lease {
	v := config.VLanMac{
		Mac: p.SrcMac.String(),
	}
	if lease, ok := s.config.Leases[v.Index()]; ok {
		return &lease
	}
	v.Set(p.VLan, p.SrcMac)
	if lease, ok := s.config.VLans[v.Index()]; ok {
		return &lease
	}
	v.Set(p.VLan, nil)
	if lease, ok := s.config.VLans[v.Index()]; ok {
		return &lease
	}
	return nil
}

func (s *DhcpServer) prepareOffer(p *DP, lease *config.Lease) *raw_packet.RawPacket {
	resp := p.OfferResponse(lease, s)
	responsePacket := &raw_packet.RawPacket{
		DhcpType:  layers.DHCPMsgTypeOffer,
		EtherType: p.EtherType,
		VLan:      p.VLan,
		Payload:   resp,
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
		DhcpType:  layers.DHCPMsgTypeAck,
		EtherType: p.EtherType,
		VLan:      p.VLan,
		Payload:   resp,
		SrcIp:     s.config.MyAddress,
		DstIp:     p.SrcIP,
		OfferedIp: lease.Ip,
		DstMac:    p.SrcMac,
		SrcMac:    s.config.MyMac,
	}
	return responsePacket
}

func (s *DhcpServer) prepareNak(p *DP, lease *config.Lease) *raw_packet.RawPacket {
	resp := p.NakResponse(lease, s)
	responsePacket := &raw_packet.RawPacket{
		DhcpType:  layers.DHCPMsgTypeNak,
		EtherType: p.EtherType,
		VLan:      p.VLan,
		Payload:   resp,
		SrcIp:     s.config.MyAddress,
		DstIp:     p.SrcIP,
		OfferedIp: lease.Ip,
		DstMac:    p.SrcMac,
		SrcMac:    s.config.MyMac,
	}
	return responsePacket
}

func (s *DhcpServer) parsePacket(p gopacket.Packet) (*DP, error) {
	dp := &DP{
		Created: time.Now(),
	}
	ethernet := p.LinkLayer().(*layers.Ethernet)
	ip := p.NetworkLayer().(*layers.IPv4)
	transport := p.TransportLayer().(*layers.UDP)
	dp.SrcMac = ethernet.SrcMAC
	dp.DstMac = ethernet.DstMAC
	dp.EtherType = ethernet.EthernetType
	dp.SrcIP = ip.SrcIP
	dp.DstIP = ip.DstIP
	dp.SrcPort = transport.SrcPort
	dp.DstPort = transport.DstPort
	for _, l := range p.Layers() {
		if l.LayerType() == layers.LayerTypeDot1Q {
			dp.VLan = append(dp.VLan, l.(*layers.Dot1Q))
		}
		if l.LayerType() == layers.LayerTypeDHCPv4 {
			dp.DHCP = l.(*layers.DHCPv4)
		}
	}
	return dp, nil
}
