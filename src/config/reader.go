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
	TimeOffset  uint                `json:"time offset"`
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
	NameServers []net.IP
	TimeOffset  uint
	Leases      map[string]Lease
}

type Lease struct {
	Ip       net.IP
	Mask     net.IPMask
	Gateway  net.IP
	HostName string
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
	}
	for _, ns := range c.NameServers {
		conf.NameServers = append(conf.NameServers, net.ParseIP(ns))
	}
	for mac, lease := range c.Leases {
		_, err := net.ParseMAC(mac)
		if err != nil {
			panic(err)
		}
		ip, ipnet, err := net.ParseCIDR(lease.Ip)
		if err != nil {
			panic(err)
		}
		conf.Leases[strings.ToLower(mac)] = Lease{
			Ip:       ip,
			Mask:     ipnet.Mask,
			Gateway:  net.ParseIP(lease.Gateway),
			HostName: lease.HostName,
		}
	}
	return conf, nil
}
