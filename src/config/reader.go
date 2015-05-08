package config

import (
	"encoding/json"
	"io/ioutil"
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
	DefaultMTU  uint16              `json:"default mtu"`
	Leases      map[string]rawLease `json:"leases"`
}

type rawLease struct {
	Ip       string `json:"ip"`
	Gateway  string `json:"gateway"`
	HostName string `json:"host name"`
	MTU      uint16 `json:"mtu"`
}

type ServerConfig struct {
	Listen      string
	MyAddress   net.IP
	MyMac       net.HardwareAddr
	LeaseTime   time.Duration
	NameServers []net.IP
	TimeOffset  uint16
	DefaultMTU  uint16
	Leases      map[string]Lease
}

type Lease struct {
	Ip        net.IP
	Mask      net.IP
	Broadcast net.IP
	Gateway   net.IP
	HostName  string
	MTU       uint16
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
		MyAddress:  net.ParseIP(c.MyAddress),
		TimeOffset: c.TimeOffset,
		DefaultMTU: c.DefaultMTU,
	}
	if conf.DefaultMTU == 0 {
		conf.DefaultMTU = 1500
	}
	for _, ns := range c.NameServers {
		conf.NameServers = append(conf.NameServers, net.ParseIP(ns))
	}
	for mac, lease := range c.Leases {
		_, err := net.ParseMAC(mac)
		if err != nil {
			panic(err)
		}
		ip, ipn, err := net.ParseCIDR(lease.Ip)
		if err != nil {
			panic(err)
		}
		mtu := conf.DefaultMTU
		if lease.MTU > 0 {
			mtu = lease.MTU
		}
		broadcast := net.IPv4(ip[0]|(^ipn.Mask[0]), ip[1]|(^ipn.Mask[1]), ip[2]|(^ipn.Mask[2]), ip[3]|(^ipn.Mask[3]))
		conf.Leases[strings.ToLower(mac)] = Lease{
			Ip:        ip,
			Mask:      net.IPv4(ipn.Mask[0], ipn.Mask[1], ipn.Mask[2], ipn.Mask[3]),
			Gateway:   net.ParseIP(lease.Gateway),
			Broadcast: broadcast,
			HostName:  lease.HostName,
			MTU:       mtu,
		}
	}
	return conf, nil
}
