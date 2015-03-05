package main

import (
	"code.google.com/p/gopacket/pcap"
	"code.google.com/p/gopacket"
	"fmt"
)

func main() {
	if handle, err := pcap.OpenLive("eth0", 1600, true, 0); err != nil {
		panic(err)
	} else if err := handle.SetBPFFilter("udp and port 67"); err != nil {  // optional
		panic(err)
	} else {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			fmt.Println(packet.Dump())
		}
	}
}
