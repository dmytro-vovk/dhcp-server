package main

import (
	"code.google.com/p/gopacket"
	"code.google.com/p/gopacket/pcap"
	"fmt"
	"github.com/kr/pretty"
	"code.google.com/p/gopacket/layers"
	"net"
<<<<<<< HEAD
	"syscall"
	"os"
=======
>>>>>>> 4e1d8a2ea0b171bcb42fd666b4cb6c39d7b1f9b2
)

type DP struct {
	SrcMac  net.HardwareAddr
	DstMac  net.HardwareAddr
<<<<<<< HEAD
=======
	Vlan    uint16
>>>>>>> 4e1d8a2ea0b171bcb42fd666b4cb6c39d7b1f9b2
	SrcIP   net.IP
	DstIP   net.IP
	SrcPort layers.UDPPort
	DstPort layers.UDPPort
	App     []byte
	OpCode  byte
	Cookie  []byte
}

func main() {
	if handle, err := pcap.OpenLive("wlan0", 1600, true, 0); err != nil {
		panic(err)
	} else if err := handle.SetBPFFilter("udp and port 67 or port 68"); err != nil {
		panic(err)
	} else {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			parsePacket(packet)
<<<<<<< HEAD
		}
	}
}

func parsePacket(p gopacket.Packet) {
	var dp DP
	ethernet := p.LinkLayer().(*layers.Ethernet)
	dp.SrcMac = ethernet.SrcMAC
	dp.DstMac = ethernet.DstMAC
	ip := p.NetworkLayer().(*layers.IPv4)
	dp.SrcIP = ip.SrcIP
	dp.DstIP = ip.DstIP
	transport := p.TransportLayer().(*layers.UDP)
	dp.SrcPort = transport.SrcPort
	dp.DstPort = transport.DstPort
	dp.App = p.ApplicationLayer().Payload()
	dp.OpCode = dp.App[0]
	dp.Cookie = dp.App[236:240]
	fmt.Printf("Packet: %# v\n", pretty.Formatter(dp))
	//fmt.Printf("Data: %# v\n", pretty.Formatter(p))
}

type DhcpConfig struct {
	Listen string `json:"listen on"`
}

func rawUdp() {
	fd, _ := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, syscall.IPPROTO_UDP)
	f := os.NewFile(uintptr(fd), fmt.Sprintf("fd %d", fd))
	for {
		buf := make([]byte, 1024)
		numRead, err := f.Read(buf)
		if err != nil {
			fmt.Println(err)
=======
>>>>>>> 4e1d8a2ea0b171bcb42fd666b4cb6c39d7b1f9b2
		}
		fmt.Printf("% X\n", buf[:numRead])
	}
}

func parsePacket(p gopacket.Packet) {
	var dp DP
	ethernet := p.LinkLayer().(*layers.Ethernet)
	dp.SrcMac = ethernet.SrcMAC
	dp.DstMac = ethernet.DstMAC
	dp.Vlan = uint16(ethernet.Contents[22]) << 8 + uint16(ethernet.Contents[23])
	ip := p.NetworkLayer().(*layers.IPv4)
	dp.SrcIP = ip.SrcIP
	dp.DstIP = ip.DstIP
	transport := p.TransportLayer().(*layers.UDP)
	dp.SrcPort = transport.SrcPort
	dp.DstPort = transport.DstPort
	dp.App = p.ApplicationLayer().Payload()
	dp.OpCode = dp.App[0]
	dp.Cookie = dp.App[236:240]
	fmt.Printf("Packet: %# v\n", pretty.Formatter(dp))
	//fmt.Printf("Data: %# v\n", pretty.Formatter(p))
}

type DhcpConfig struct {
	Listen string `json:"listen on"`
}
