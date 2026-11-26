// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"net"

	"github.com/safchain/ethtool"
	"golang.org/x/sys/unix"
)

// setGRO toggles GRO on an interface in the current netns.
func setGRO(ifName string, on bool) error {
	e, err := ethtool.NewEthtool()
	if err != nil {
		return err
	}
	defer e.Close()
	return e.Change(ifName, map[string]bool{"rx-gro": on})
}

// gratuitousARP broadcasts one gratuitous ARP request per IPv4 address.
func gratuitousARP(ifName string, cidrs []string) error {
	ifc, err := net.InterfaceByName(ifName)
	if err != nil {
		return err
	}
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	for _, c := range cidrs {
		ipAddr, _, err := net.ParseCIDR(c)
		if err != nil || ipAddr.To4() == nil {
			continue
		}
		f := garpFrame(ifc.HardwareAddr, ipAddr.To4())
		sa := &unix.SockaddrLinklayer{Ifindex: ifc.Index, Halen: 6, Protocol: htons(unix.ETH_P_ARP)}
		copy(sa.Addr[:], f[:6])
		if err := unix.Sendto(fd, f, 0, sa); err != nil {
			return fmt.Errorf("sending gratuitous ARP: %w", err)
		}
	}
	return nil
}

func garpFrame(mac net.HardwareAddr, ip4 net.IP) []byte {
	f := make([]byte, 0, 42)
	f = append(f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff)
	f = append(f, mac...)
	f = append(f, 0x08, 0x06)             // ARP
	f = append(f, 0x00, 0x01, 0x08, 0x00) // Ethernet / IPv4
	f = append(f, 6, 4, 0x00, 0x01)       // hlen, plen, request
	f = append(f, mac...)
	f = append(f, ip4...)
	f = append(f, 0, 0, 0, 0, 0, 0)
	return append(f, ip4...)
}

func htons(v uint16) uint16 { return v<<8 | v>>8 }
