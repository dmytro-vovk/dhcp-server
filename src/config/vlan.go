package config

import (
	"fmt"
	"log"
	"net"
)

type VLanMac struct {
	L1  uint16
	L2  uint16
	Mac string
}

func (v *VLanMac) Set(vlans []uint16, mac net.HardwareAddr) *VLanMac {
	if v == nil {
		v = &VLanMac{}
	}
	if mac == nil {
		v.Mac = ""
	} else {
		v.Mac = mac.String()
	}
	if len(vlans) == 2 {
		v.L1 = vlans[0]
		v.L2 = vlans[1]
	} else if len(vlans) == 1 {
		v.L1 = vlans[0]
		v.L2 = 0
	} else if len(vlans) == 0 {
		v.L1 = 0
		v.L2 = 0
	} else {
		log.Printf("Cold not set VLan, got wrong number of values: %d", len(vlans))
	}
	return v
}

func (v VLanMac) String() string {
	if v.L1 == 0 {
		return ""
	}
	if v.L2 == 0 {
		return fmt.Sprintf("%d", v.L1)
	}
	return fmt.Sprintf("%d.%d", v.L1, v.L2)
}
