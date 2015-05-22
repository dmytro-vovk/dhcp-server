package raw_packet

import (
	"code.google.com/p/gopacket"
	"code.google.com/p/gopacket/layers"
	"dhcp4"
	"log"
	"net"
)

type RawPacket struct {
	DhcpType  dhcp4.MessageType
	SrcMac    net.HardwareAddr
	DstMac    net.HardwareAddr
	SrcIp     net.IP
	DstIp     net.IP
	VLan      []uint16
	EtherType layers.EthernetType
	Payload   []byte
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
		err = gopacket.SerializeLayers(buf, opts, &ether, &ip, &udp, gopacket.Payload(rp.Payload))
	} else if rp.EtherType == layers.EthernetTypeDot1Q {
		lss := []gopacket.SerializableLayer{&ether}
		dot1layers := rp.buildDot1QHeader()
		for k := range dot1layers {
			lss = append(lss, &dot1layers[k])
		}
		lss = append(lss, &ip, &udp, gopacket.Payload(rp.Payload))
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

func (rp *RawPacket) buildDot1QHeader() []layers.Dot1Q {
	ls := []layers.Dot1Q{}
	for _, v := range rp.VLan {
		ls = append(ls, layers.Dot1Q{
			VLANIdentifier: v,
			Type:           layers.EthernetTypeIPv4,
		})
	}
	return ls
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
		Length:   uint16(len(rp.Payload)),
		Checksum: 0,
	}
}
