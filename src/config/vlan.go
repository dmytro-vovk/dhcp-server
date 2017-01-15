package config

import (
	"net"
	"strconv"
	"strings"

	"github.com/google/gopacket/layers"
)

type VLanMac struct {
	L   []uint16
	Mac string
}

func (v *VLanMac) Set(vlans []*layers.Dot1Q, mac net.HardwareAddr) *VLanMac {
	if v == nil {
		v = &VLanMac{}
	}
	if mac == nil {
		v.Mac = ""
	} else {
		v.Mac = mac.String()
	}
	for _, vl := range vlans {
		v.L = append(v.L, vl.VLANIdentifier)
	}
	return v
}

func (v VLanMac) String() string {
	vv := []string{}
	for _, vl := range v.L {
		vv = append(vv, strconv.Itoa(int(vl)))
	}
	return strings.Join(vv, ".")
}
