package config

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"net"
	"strconv"
	"strings"
	"time"
)

type rawServerConfig struct {
	Listen       string              `json:"listen on"`
	MyAddress    string              `json:"my address"`
	LeaseTime    uint                `json:"default lease time"`
	ResolverAddr string              `json:"resolver"`
	NameServers  []string            `json:"name servers"`
	TimeOffset   uint16              `json:"time offset"`
	Leases       map[string]rawLease `json:"leases"`
}

type rawLease struct {
	Ip      string `json:"ip"`
	Gateway string `json:"gateway"`
	Mac     string `json:"mac"`
	VLan    string `json:"vlan"`
}

type ServerConfig struct {
	Listen       string
	MyAddress    net.IP
	MyMac        net.HardwareAddr
	LeaseTime    time.Duration
	ResolverAddr string
	NameServers  []byte
	TimeOffset   uint16
	Leases       map[string]Lease
	VLans        map[VLanMac]Lease
}

type Lease struct {
	Ip        net.IP
	Mask      net.IP
	Broadcast net.IP
	Gateway   net.IP
	HostName  string
	Mac       net.HardwareAddr
	VLan      VLanMac
}

func Read(fileName string) (*ServerConfig, error) {
	file, err := ioutil.ReadFile(fileName)
	if err != nil {
		return nil, err
	}
	c := &rawServerConfig{}
	err = json.Unmarshal(file, c)
	return parse(c, err)
}

func parse(c *rawServerConfig, err error) (*ServerConfig, error) {
	if err != nil {
		return nil, err
	}
	conf := &ServerConfig{
		Listen:       c.Listen,
		Leases:       make(map[string]Lease),
		VLans:        make(map[VLanMac]Lease),
		LeaseTime:    time.Duration(c.LeaseTime) * time.Second,
		MyAddress:    net.ParseIP(c.MyAddress).To4(),
		TimeOffset:   c.TimeOffset,
		ResolverAddr: c.ResolverAddr,
	}
	for _, ns := range c.NameServers {
		if nsIp := net.ParseIP(ns); nsIp != nil {
			conf.NameServers = append(conf.NameServers, nsIp.To4()...)
		} else {
			log.Fatalf("Invalid nameserver adddress: %s", nsIp)
		}
	}
	for hostName, lease := range c.Leases {
		if len(hostName) > 11 {
			log.Fatalf("Host name is too long (max 11 bytes): %s", hostName)
		}
		if lease.VLan == "" && lease.Mac == "" {
			log.Fatalf("Cannot have both mac and vlan empty for host %s", hostName)
		}
		ip, ipn, err := net.ParseCIDR(lease.Ip)
		if err != nil {
			log.Fatal(err)
		}
		ip = ip.To4()
		broadcast := net.IPv4(ip[0]|(^ipn.Mask[0]), ip[1]|(^ipn.Mask[1]), ip[2]|(^ipn.Mask[2]), ip[3]|(^ipn.Mask[3])).To4()
		vl := VLanMac{}
		mac := net.HardwareAddr{}
		if lease.Mac != "" {
			mac, err = net.ParseMAC(lease.Mac)
			if err != nil {
				log.Fatal(err)
			}
		}
		vl.Mac = mac.String()
		if lease.VLan != "" {
			if strings.Contains(lease.VLan, ".") {
				vlans := strings.Split(lease.VLan, ".")
				if len(vlans) != 2 {
					log.Fatalf("Cannot parse vlan %s", lease.VLan)
				}
				l1, err := strconv.Atoi(vlans[0])
				if err != nil {
					log.Fatalf("Cannot parse vlan %s: %s", lease.VLan, err)
				}
				vl.L1 = uint16(l1)
				l2, err := strconv.Atoi(vlans[1])
				if err != nil {
					log.Fatalf("Cannot parse vlan %s: %s", lease.VLan, err)
				}
				vl.L2 = uint16(l2)
			} else {
				l1, err := strconv.Atoi(lease.VLan)
				if err != nil {
					log.Fatalf("Cannot parse vlan %s: %s", lease.VLan, err)
				}
				vl.L1 = uint16(l1)
			}
			conf.VLans[vl] = Lease{
				Ip:        ip.To4(),
				Mask:      net.IPv4(ipn.Mask[0], ipn.Mask[1], ipn.Mask[2], ipn.Mask[3]).To4(),
				Gateway:   net.ParseIP(lease.Gateway).To4(),
				Broadcast: broadcast,
				HostName:  hostName,
				Mac:       mac,
				VLan:      vl,
			}
		} else {
			conf.Leases[mac.String()] = Lease{
				Ip:        ip.To4(),
				Mask:      net.IPv4(ipn.Mask[0], ipn.Mask[1], ipn.Mask[2], ipn.Mask[3]).To4(),
				Gateway:   net.ParseIP(lease.Gateway).To4(),
				Broadcast: broadcast,
				HostName:  hostName,
				Mac:       mac,
				VLan:      vl,
			}
		}
	}
	return conf, nil
}
