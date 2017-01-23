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
	v.L = make([]uint16, len(vlans), len(vlans))
	for i, vl := range vlans {
		v.L[i] = vl.VLANIdentifier
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

func (v VLanMac) Index() string {
	return v.Mac + "|" + v.String()
}
