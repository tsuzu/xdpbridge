// SPDX-License-Identifier: Apache-2.0

package flood

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func frame(dst byte, tagged bool, vlan uint16) []byte {
	f := []byte{dst, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02, 0, 0, 0, 0, 0x01}
	if tagged {
		f = append(f, 0x81, 0x00, byte(vlan>>8), byte(vlan))
	}
	f = append(f, 0x08, 0x06) // ARP
	return append(f, bytes.Repeat([]byte{0xab}, 28)...)
}

func record(ev Event) []byte {
	b := make([]byte, headerLen+len(ev.Frame))
	binary.LittleEndian.PutUint32(b[0:], uint32(len(ev.Frame)))
	binary.LittleEndian.PutUint32(b[4:], ev.SrcPort)
	binary.LittleEndian.PutUint16(b[8:], ev.VLAN)
	b[10] = ev.Origin
	if ev.Tagged {
		b[11] = 1
	}
	copy(b[headerLen:], ev.Frame)
	return b
}

func TestParseEvent(t *testing.T) {
	in := Event{SrcPort: 7, VLAN: 100, Origin: OriginPort, Frame: frame(0xff, false, 0)}
	got, err := ParseEvent(record(in))
	if err != nil {
		t.Fatal(err)
	}
	if got.SrcPort != 7 || got.VLAN != 100 || got.Origin != OriginPort || !bytes.Equal(got.Frame, in.Frame) {
		t.Errorf("roundtrip mismatch: %+v", got)
	}
	if _, err := ParseEvent([]byte{1, 2}); err == nil {
		t.Error("short record accepted")
	}
	bad := record(in)
	binary.LittleEndian.PutUint32(bad[0:], 9999)
	if _, err := ParseEvent(bad); err == nil {
		t.Error("oversized length accepted")
	}
}

func TestTagRoundTrip(t *testing.T) {
	f := frame(0xff, false, 0)
	tagged := InsertTag(f, 100)
	if len(tagged) != len(f)+4 || tagged[12] != 0x81 || tagged[15] != 100 {
		t.Fatalf("bad tag: % x", tagged[:18])
	}
	if !bytes.Equal(StripTag(tagged), f) {
		t.Error("strip(insert(f)) != f")
	}
	if StripTag(f[:10]) != nil {
		t.Error("short frame should not strip")
	}
}

var ports = []Port{
	{ID: 1, Ifindex: 11, VLAN: 0},
	{ID: 2, Ifindex: 12, VLAN: 0},
	{ID: 3, Ifindex: 13, VLAN: 100},
	{ID: 4, Ifindex: 14, VLAN: 0},
}

const uplink = 2

func ifindexes(txs []Tx) []int {
	var out []int
	for _, tx := range txs {
		out = append(out, tx.Ifindex)
	}
	return out
}

func eq(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestPlanFromPort(t *testing.T) {
	ev := Event{SrcPort: 2, Origin: OriginPort, Frame: frame(0xff, false, 0)}
	txs := Plan(ev, ports, uplink)
	// Same VLAN except the sender, then the uplink.
	if got := ifindexes(txs); !eq(got, []int{11, 14, uplink}) {
		t.Errorf("targets = %v", got)
	}
	for _, tx := range txs {
		if !bytes.Equal(tx.Frame, ev.Frame) {
			t.Error("untagged port flood must not be modified")
		}
	}
}

func TestPlanFromVLANPort(t *testing.T) {
	ev := Event{SrcPort: 3, VLAN: 100, Origin: OriginPort, Frame: frame(0xff, false, 0)}
	txs := Plan(ev, ports, uplink)
	if got := ifindexes(txs); !eq(got, []int{uplink}) {
		t.Fatalf("targets = %v", got)
	}
	if !bytes.Equal(StripTag(txs[0].Frame), ev.Frame) || txs[0].Frame[15] != 100 {
		t.Error("uplink copy must carry VLAN 100 tag")
	}
}

func TestPlanFromUplinkTagged(t *testing.T) {
	ev := Event{VLAN: 100, Tagged: true, Origin: OriginUplink, Frame: frame(0xff, true, 100)}
	txs := Plan(ev, ports, uplink)
	if got := ifindexes(txs); !eq(got, []int{13}) {
		t.Fatalf("targets = %v", got)
	}
	if !bytes.Equal(txs[0].Frame, frame(0xff, false, 0)) {
		t.Error("tag must be stripped for access port")
	}
}

func TestPlanFromUplinkAndHost(t *testing.T) {
	for _, origin := range []uint8{OriginUplink, OriginHost} {
		ev := Event{Origin: origin, Frame: frame(0x01, false, 0)}
		// Never back to the uplink, all untagged ports.
		if got := ifindexes(Plan(ev, ports, uplink)); !eq(got, []int{11, 12, 14}) {
			t.Errorf("origin %d: targets = %v", origin, got)
		}
	}
}

// A real IPv4 UDP frame (mDNS-like) with a known-good checksum.
func udp4Frame() []byte {
	f := []byte{
		0x01, 0x00, 0x5e, 0x00, 0x00, 0xfb, 0x02, 0x00, 0x00, 0x00, 0x01, 0x64, 0x08, 0x00,
		0x45, 0x00, 0x00, 0x21, 0x00, 0x00, 0x40, 0x00, 0xff, 0x11, 0x00, 0x00,
		192, 0, 2, 100, 224, 0, 0, 251,
		0x14, 0xe9, 0x14, 0xe9, 0x00, 0x0d, 0x00, 0x00,
		'h', 'e', 'l', 'l', 'o',
	}
	return f
}

func refUDPSum(f []byte) uint16 {
	// Independent straightforward implementation over the pseudo header.
	ph := append([]byte{}, f[26:34]...)
	ph = append(ph, 0, 17, f[38], f[39])
	seg := append([]byte{}, f[34:]...)
	seg[6], seg[7] = 0, 0
	b := append(ph, seg...)
	if len(b)%2 == 1 {
		b = append(b, 0)
	}
	var s uint32
	for i := 0; i < len(b); i += 2 {
		s += uint32(b[i])<<8 | uint32(b[i+1])
	}
	for s>>16 != 0 {
		s = s&0xffff + s>>16
	}
	return ^uint16(s)
}

func TestFixUDPChecksum(t *testing.T) {
	f := udp4Frame()
	want := refUDPSum(f)
	// Simulate CHECKSUM_PARTIAL: only the pseudo-header sum is present.
	binary.BigEndian.PutUint16(f[40:], 0x1234)
	FixUDPChecksum(f)
	if got := binary.BigEndian.Uint16(f[40:]); got != want {
		t.Fatalf("checksum %#04x, want %#04x", got, want)
	}
	// Idempotent on a valid frame.
	FixUDPChecksum(f)
	if got := binary.BigEndian.Uint16(f[40:]); got != want {
		t.Fatalf("not idempotent: %#04x", got)
	}
	// Checksum 0 (disabled) is preserved.
	g := udp4Frame()
	FixUDPChecksum(g)
	if binary.BigEndian.Uint16(g[40:]) != 0 {
		t.Error("zero checksum must stay zero")
	}
	// Tagged frame.
	tagged := InsertTag(udp4Frame(), 100)
	binary.BigEndian.PutUint16(tagged[44:], 0x1111)
	FixUDPChecksum(tagged)
	if got := binary.BigEndian.Uint16(StripTag(tagged)[40:]); got != want {
		t.Errorf("tagged: %#04x, want %#04x", got, want)
	}
	// Truncated frames must not panic.
	for i := 0; i < len(f); i++ {
		FixUDPChecksum(append([]byte{}, f[:i]...))
	}
}
