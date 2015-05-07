package raw_packet

import (
	"code.google.com/p/gopacket/layers"
	"dhcp4"
	"net"
)

type RawPacket struct {
	DhcpType  dhcp4.MessageType
	SrcMac    [6]byte
	DstMac    [6]byte
	SrcIp     net.IP
	DstIp     net.IP
	VLan      []uint16
	EtherType layers.EthernetType
	Payload   []byte
}

func (rp *RawPacket) Marshal() []byte {
	EtherHeader := rp.buildEtherHeader()
	IPv4Header := rp.buildIPv4Header()
	UDPHeader := rp.buildUDPHeader()
	//log.Printf("Ethernet header: %# v", pretty.Formatter(EtherHeader))
	//log.Printf("IPv4 header: %# v", pretty.Formatter(IPv4Header))
	//log.Printf("UDP header: %# v", pretty.Formatter(UDPHeader))
	return append(EtherHeader, append(IPv4Header, append(UDPHeader, rp.Payload...)...)...)
}

func (rp *RawPacket) buildEtherHeader() []byte {
	if rp.EtherType == 0x8100 {
		EtherHeader := make([]byte, 12)
		copy(EtherHeader[0:6], rp.DstMac[:])
		copy(EtherHeader[6:12], rp.SrcMac[:])
		for _, vid := range rp.VLan {
			EtherHeader = append(EtherHeader, byte(vid>>8), byte(vid))
			EtherHeader = append(EtherHeader, 0x81, 0x00)
		}
		copy(EtherHeader[len(EtherHeader)-2:len(EtherHeader)], []byte{0x08, 0x00})
		//EtherHeader = append(EtherHeader, 0x08, 0x00)
		//log.Printf("Ethernet header: %# v", pretty.Formatter(EtherHeader))
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
	UDPHeader := make([]byte, 8)
	payloadCheckSum := rp.csum(rp.Payload)
	UDPHeader[0] = 0                          // Source Port
	UDPHeader[1] = 67                         // ...
	UDPHeader[2] = 0                          // Destination Port
	UDPHeader[3] = 68                         // ...
	UDPHeader[4] = byte(len(rp.Payload) >> 8) // Length
	UDPHeader[5] = byte(len(rp.Payload))      // ...
	UDPHeader[6] = byte(payloadCheckSum >> 8) // Payload checksum
	UDPHeader[7] = byte(payloadCheckSum)      // ...
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
