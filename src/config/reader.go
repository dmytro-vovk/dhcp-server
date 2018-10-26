package config

import (
	"encoding/binary"
	"encoding/json"
	"io/ioutil"
	"log"
	"net"
	"strconv"
	"strings"
	"time"
)

type rawServerConfig struct {
	Listen               string              `json:"listen on"`              // Interface to listen on
	MyAddress            string              `json:"my address"`             // My own address
	LeaseTime            uint                `json:"default lease time"`     // In seconds
	TimeOffset           uint16              `json:"time offset"`            // In seconds
	IgnoreStrangeClients bool                `json:"ignore strange clients"` // Do not respond to unknown clients
	IgnoreStrangeVLans   bool                `json:"ignore strange vlans"`   // Do not respond on unknown vlans
	NameServers          []string            `json:"name servers"`           // List of nameservers in textual form: X.X.X.X
	Leases               map[string]rawLease `json:"leases"`                 // Leases definitions
}

type rawLease struct {
	Ip      string `json:"ip"`
	Gateway string `json:"gateway"`
	Mac     string `json:"mac"`
	VLan    string `json:"vlan"`
}

type ServerConfig struct {
	Listen               string
	MyAddress            net.IP
	MyMac                net.HardwareAddr
	LeaseTime            time.Duration
	LeaseTimeBytes       []byte
	NameServers          []byte
	TimeOffset           uint16
	IgnoreStrangeClients bool
	IgnoreStrangeVLans   bool
	Leases               map[string]Lease
	VLans                map[string]Lease
	VLanIDs              map[string]struct{}
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
	conf := ServerConfig{
		Listen:               c.Listen,
		Leases:               make(map[string]Lease),
		VLans:                make(map[string]Lease),
		LeaseTime:            time.Duration(c.LeaseTime) * time.Second,
		LeaseTimeBytes:       make([]byte, 4),
		MyAddress:            net.ParseIP(c.MyAddress).To4(),
		TimeOffset:           c.TimeOffset,
		IgnoreStrangeClients: c.IgnoreStrangeClients,
		IgnoreStrangeVLans:   c.IgnoreStrangeVLans,
		VLanIDs:              make(map[string]struct{}),
	}
	binary.BigEndian.PutUint32(conf.LeaseTimeBytes, uint32(conf.LeaseTime/time.Second))
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
			log.Fatalf("Error parsing CIDR: %s", err)
		}
		ip = ip.To4()
		broadcast := net.IPv4(ip[0]|(^ipn.Mask[0]), ip[1]|(^ipn.Mask[1]), ip[2]|(^ipn.Mask[2]), ip[3]|(^ipn.Mask[3])).To4()
		vl := VLanMac{}
		mac := net.HardwareAddr{}
		if lease.Mac != "" {
			mac, err = net.ParseMAC(lease.Mac)
			if err != nil {
				log.Fatalf("Error parsing MAC: %s", err)
			}
		}
		vl.Mac = mac.String()
		if lease.VLan != "" {
			conf.VLanIDs[lease.VLan] = struct{}{}
			if strings.Contains(lease.VLan, ".") {
				for _, l := range strings.Split(lease.VLan, ".") {
					id, err := strconv.Atoi(l)
					if err != nil {
						log.Fatalf("Cannot parse vlan %s: %s", lease.VLan, err)
					}
					vl.L = append(vl.L, uint16(id))
				}
			} else {
				l, err := strconv.Atoi(lease.VLan)
				if err != nil {
					log.Fatalf("Cannot parse vlan %s: %s", lease.VLan, err)
				}
				vl.L = []uint16{uint16(l)}
			}
			conf.VLans[vl.Index()] = Lease{
				Ip:        ip.To4(),
				Mask:      net.IPv4(ipn.Mask[0], ipn.Mask[1], ipn.Mask[2], ipn.Mask[3]).To4(),
				Gateway:   net.ParseIP(lease.Gateway).To4(),
				Broadcast: broadcast,
				HostName:  hostName,
				Mac:       mac,
				VLan:      vl,
			}
		} else {
			conf.Leases[vl.Index()] = Lease{
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
	return &conf, nil
}
