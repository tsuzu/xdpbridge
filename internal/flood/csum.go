// SPDX-License-Identifier: Apache-2.0

package flood

import "encoding/binary"

// FixUDPChecksum recomputes the UDP checksum of an untagged or 802.1Q-tagged
// IPv4/IPv6 frame in place.
//
// Frames punted from TC hooks (pod or host originated) are often
// CHECKSUM_PARTIAL: the stack left the checksum to the NIC, so the raw bytes
// only carry the pseudo-header sum. Replicated copies are sent as complete
// frames and would be dropped by receivers, so the checksum is finalised here.
// Recomputing an already valid checksum yields the same value.
func FixUDPChecksum(f []byte) {
	if len(f) < 14 {
		return
	}
	off := 12
	et := binary.BigEndian.Uint16(f[off:])
	if et == 0x8100 || et == 0x88a8 {
		off += 4
		if len(f) < off+2 {
			return
		}
		et = binary.BigEndian.Uint16(f[off:])
	}
	l3 := off + 2
	switch et {
	case 0x0800:
		if len(f) < l3+20 {
			return
		}
		ihl := int(f[l3]&0x0f) * 4
		if f[l3+9] != 17 || ihl < 20 || len(f) < l3+ihl+8 {
			return
		}
		if binary.BigEndian.Uint16(f[l3+6:])&0x3fff != 0 { // fragment
			return
		}
		totLen := int(binary.BigEndian.Uint16(f[l3+2:]))
		udp := f[l3+ihl:]
		ulen := int(binary.BigEndian.Uint16(udp[4:]))
		if totLen > len(f)-l3 || ulen < 8 || ulen > totLen-ihl {
			return
		}
		if binary.BigEndian.Uint16(udp[6:]) == 0 { // checksum disabled
			return
		}
		var sum uint32
		sum += sum16(f[l3+12 : l3+20])
		sum += 17 + uint32(ulen)
		writeUDPSum(udp[:ulen], sum)
	case 0x86dd:
		if len(f) < l3+40+8 || f[l3+6] != 17 { // no extension headers
			return
		}
		plen := int(binary.BigEndian.Uint16(f[l3+4:]))
		udp := f[l3+40:]
		ulen := int(binary.BigEndian.Uint16(udp[4:]))
		if plen > len(udp) || ulen < 8 || ulen > plen {
			return
		}
		var sum uint32
		sum += sum16(f[l3+8 : l3+40])
		sum += 17 + uint32(ulen)
		writeUDPSum(udp[:ulen], sum)
	}
}

func writeUDPSum(udp []byte, pseudo uint32) {
	udp[6], udp[7] = 0, 0
	sum := pseudo + sum16(udp)
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	c := ^uint16(sum)
	if c == 0 {
		c = 0xffff
	}
	binary.BigEndian.PutUint16(udp[6:], c)
}

func sum16(b []byte) uint32 {
	var s uint32
	for len(b) >= 2 {
		s += uint32(binary.BigEndian.Uint16(b))
		b = b[2:]
	}
	if len(b) == 1 {
		s += uint32(b[0]) << 8
	}
	return s
}
