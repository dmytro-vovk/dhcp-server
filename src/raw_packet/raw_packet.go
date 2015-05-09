package raw_packet

import (
	"code.google.com/p/gopacket/layers"
	"dhcp4"
	"net"
)

type RawPacket struct {
	DhcpType   dhcp4.MessageType
	SrcMac     [6]byte
	DstMac     [6]byte
	SrcIp      net.IP
	DstIp      net.IP
	Dot1qVLan  uint16
	Dot1adVLan uint16
	EtherType  layers.EthernetType
	Payload    []byte
}

func (rp *RawPacket) Marshal() []byte {
	EtherHeader := rp.buildEtherHeader()
	IPv4Header := rp.buildIPv4Header()
	UDPHeader := rp.buildUDPHeader()
	//log.Printf("-------------------------------------------")
	//log.Printf("Ethernet header:\n%# v", pretty.Formatter(EtherHeader))
	//log.Printf("IPv4 header:\n%# v", pretty.Formatter(IPv4Header))
	//log.Printf("UDP header:\n%# v", pretty.Formatter(UDPHeader))
	//log.Printf("Payload:\n%# v", pretty.Formatter(rp.Payload))
	eEther := len(EtherHeader)
	eIPv4 := len(IPv4Header)
	eUDP := len(UDPHeader)
	ePayload := len(rp.Payload)
	//log.Printf("Len: ether %d, ipv4 %d, udp %d, payload %d: %d", eEther, eIPv4, eUDP, ePayload, eEther+eIPv4+eUDP+ePayload)
	pkt := make([]byte, eEther+eIPv4+eUDP+ePayload)
	copy(pkt[0:], EtherHeader[:])
	copy(pkt[eEther:eEther+eIPv4], IPv4Header[:])
	copy(pkt[eEther+eIPv4:eEther+eIPv4+eUDP], UDPHeader[:])
	copy(pkt[eEther+eIPv4+eUDP:eEther+eIPv4+eUDP+ePayload], rp.Payload[:])
	//log.Printf("Resulting packet:\n%# v", pretty.Formatter(pkt))
	//log.Printf("Resulting packet length: %d", len(pkt))
	//log.Printf("-------------------------------------------")
	return pkt
}

func (rp *RawPacket) buildEtherHeader() []byte {
	if rp.EtherType == 0x8100 && rp.Dot1qVLan > 0 {
		EtherHeader := []byte{
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Dst MAC
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Src MAC
			0x81, 0x00, // 802.1Q Header
			byte(rp.Dot1qVLan >> 8), byte(rp.Dot1qVLan), // VLan ID
			0x08, 0x00, // Ether type
		}
		copy(EtherHeader[0:6], rp.DstMac[:])
		copy(EtherHeader[6:12], rp.SrcMac[:])
		return EtherHeader
	} else if rp.EtherType == 0x9100 && rp.Dot1adVLan > 0 {
		EtherHeader := []byte{
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Dst MAC
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Src MAC
			0x91, 0x00, // 802.1Q Header
			byte(rp.Dot1adVLan >> 8), byte(rp.Dot1adVLan), // VLan ID
			0x91, 0x00, // 802.1Q Header
			byte(rp.Dot1qVLan >> 8), byte(rp.Dot1qVLan), // VLan ID
			0x08, 0x00, // Ether type
		}
		copy(EtherHeader[0:6], rp.DstMac[:])
		copy(EtherHeader[6:12], rp.SrcMac[:])
		return EtherHeader
	} else {
		EtherHeader := make([]byte, 14)
		copy(EtherHeader[0:6], rp.DstMac[:])
		copy(EtherHeader[6:12], rp.SrcMac[:])
		EtherHeader[12] = byte(rp.EtherType >> 8)
		EtherHeader[13] = byte(rp.EtherType)
		return EtherHeader
	}
}

func (rp *RawPacket) buildIPv4Header() []byte {
	packetLen := len(rp.Payload) + 28
	IPv4Header := make([]byte, 20)
	IPv4Header[0] = 0x45                       // Version and header len
	IPv4Header[1] = 0x00                       // DSF
	IPv4Header[2] = byte(packetLen >> 8)       // Total len
	IPv4Header[3] = byte(packetLen)            // ...
	IPv4Header[4] = 0                          // Ident
	IPv4Header[5] = 0                          // ...
	IPv4Header[6] = 0x40                       // Flags: don't fragment
	IPv4Header[7] = 0x00                       // Frag offset
	IPv4Header[8] = 0x40                       // TTl
	IPv4Header[9] = 0x11                       // Protocol: UDP (17)
	IPv4Header[10] = 0                         // Header checksum
	IPv4Header[11] = 0                         // ...
	copy(IPv4Header[12:16], rp.SrcIp.To4()[:]) // Src IP
	copy(IPv4Header[16:20], rp.DstIp.To4()[:]) // Dst IP
	return IPv4Header
}

func (rp *RawPacket) buildUDPHeader() []byte {
	if len(rp.Payload)|1 == 1 {
		rp.Payload = append(rp.Payload, 0)
	}
	payloadCheckSum := rp.csum(rp.Payload)
	UDPHeader := []byte{
		0, 67, // Source Port
		0, 68, // Destination Port
		byte(len(rp.Payload) >> 8), // Length
		byte(len(rp.Payload)),      // ...
		byte(payloadCheckSum >> 8), // Payload checksum
		byte(payloadCheckSum),      // ...
	}
	return UDPHeader
}

func (rp *RawPacket) csum(b []byte) uint16 {
	var s uint32
	for i := 0; i < len(b); i += 2 {
		s += uint32(b[i+1])<<8 | uint32(b[i])
	}
	// add back the carry
	s = s>>16 + s&0xffff
	s = s + s>>16
	return uint16(^s)
}
