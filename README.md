# Deep DHCP Server

Yet another DHCP server that breaks some rules.

It listens all packets on an interface (and event does not require IP address set) using PCAP and inspects all DHCP packets including the ones passing through VLANs (802.1Q and 802.1ad).

It can make life easier for local networks with big number of VLANs.

The work is still in progress, so not all options are supported yet.
