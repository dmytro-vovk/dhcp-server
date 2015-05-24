package config

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"net"
	"strings"
	"time"
)

type rawServerConfig struct {
	Listen      string              `json:"listen on"`
	MyAddress   string              `json:"my address"`
	LeaseTime   uint                `json:"default lease time"`
	NameServers []string            `json:"name servers"`
	TimeOffset  uint16              `json:"time offset"`
	Leases      map[string]rawLease `json:"leases"`
}

type rawLease struct {
	Ip       string `json:"ip"`
	Gateway  string `json:"gateway"`
	HostName string `json:"host name"`
}

type ServerConfig struct {
	Listen      string
	MyAddress   net.IP
	MyMac       net.HardwareAddr
	LeaseTime   time.Duration
	NameServers []byte
	TimeOffset  uint16
	Leases      map[string]Lease
}

type Lease struct {
	Ip        net.IP
	Mask      net.IP
	Broadcast net.IP
	Gateway   net.IP
	HostName  string
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
		Listen:     c.Listen,
		Leases:     make(map[string]Lease),
		LeaseTime:  time.Duration(c.LeaseTime) * time.Second,
		MyAddress:  net.ParseIP(c.MyAddress).To4(),
		TimeOffset: c.TimeOffset,
	}
	for _, ns := range c.NameServers {
		if nsIp := net.ParseIP(ns); nsIp != nil {
			conf.NameServers = append(conf.NameServers, nsIp.To4()...)
		} else {
			log.Fatalf("Invalid nameserver adddress: %s", nsIp)
		}
	}
	for mac, lease := range c.Leases {
		if len(lease.HostName) > 11 {
			log.Fatalf("Host name is too long (max 11 bytes): %s", lease.HostName)
		}
		_, err := net.ParseMAC(mac)
		if err != nil {
			log.Fatal(err)
		}
		ip, ipn, err := net.ParseCIDR(lease.Ip)
		if err != nil {
			log.Fatal(err)
		}
		ip = ip.To4()
		broadcast := net.IPv4(ip[0]|(^ipn.Mask[0]), ip[1]|(^ipn.Mask[1]), ip[2]|(^ipn.Mask[2]), ip[3]|(^ipn.Mask[3])).To4()
		conf.Leases[strings.ToLower(mac)] = Lease{
			Ip:        ip.To4(),
			Mask:      net.IPv4(ipn.Mask[0], ipn.Mask[1], ipn.Mask[2], ipn.Mask[3]).To4(),
			Gateway:   net.ParseIP(lease.Gateway).To4(),
			Broadcast: broadcast,
			HostName:  lease.HostName,
		}
	}
	return conf, nil
}
