package raw_packet

import (
	"log"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type RawPacket struct {
	DhcpType  layers.DHCPMsgType
	SrcMac    net.HardwareAddr
	DstMac    net.HardwareAddr
	SrcIp     net.IP
	DstIp     net.IP
	OfferedIp net.IP
	VLan      []*layers.Dot1Q
	EtherType layers.EthernetType
	Payload   *layers.DHCPv4
}

func (rp *RawPacket) Marshal() []byte {
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	ether := rp.buildEtherHeader(rp.EtherType)
	ip := rp.buildIPv4Header()
	udp := rp.buildUDPHeader()
	udp.SetNetworkLayerForChecksum(&ip)
	var err error
	if rp.EtherType == layers.EthernetTypeIPv4 {
		err = gopacket.SerializeLayers(buf, opts, &ether, &ip, &udp, rp.Payload)
	} else if rp.EtherType == layers.EthernetTypeDot1Q {
		lss := []gopacket.SerializableLayer{&ether}
		dot1layers := rp.buildDot1QHeader()
		for k := range dot1layers {
			lss = append(lss, dot1layers[k])
		}
		lss = append(lss, &ip, &udp, rp.Payload)
		err = gopacket.SerializeLayers(buf, opts, lss...)
	} else {
		log.Printf("Unsupported ethernet type %x", rp.EtherType)
		return []byte{}
	}
	if err != nil {
		log.Fatalf("Error assembling packet: %s", err)
	}
	return buf.Bytes()
}

func (rp *RawPacket) buildDot1QHeader() []*layers.Dot1Q {
	return rp.VLan
}

func (rp *RawPacket) buildEtherHeader(etherType layers.EthernetType) layers.Ethernet {
	return layers.Ethernet{
		SrcMAC:       rp.SrcMac,
		DstMAC:       rp.DstMac,
		EthernetType: etherType,
	}
}

func (rp *RawPacket) buildIPv4Header() layers.IPv4 {
	return layers.IPv4{
		Version:  4,
		Protocol: 17,
		TTL:      64,
		Flags:    layers.IPv4DontFragment,
		SrcIP:    rp.SrcIp,
		DstIP:    rp.DstIp,
	}
}

func (rp *RawPacket) buildUDPHeader() layers.UDP {
	return layers.UDP{
		SrcPort:  67,
		DstPort:  68,
		Length:   rp.Payload.Len(),
		Checksum: 0,
	}
}
