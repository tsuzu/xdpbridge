// SPDX-License-Identifier: Apache-2.0

// Package flood implements the userspace half of broadcast/multicast
// replication. BPF programs copy flood frames into a ring buffer; this
// package reads them and transmits one copy per recipient with an AF_PACKET
// socket.
package flood

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"
)

// Origins, mirroring enum xdpl2_origin.
const (
	OriginUplink = 1
	OriginHost   = 2
	OriginPort   = 3
)

// headerLen is the size of the fixed part of struct flood_event.
const headerLen = 16

// Event is a decoded flood_event.
type Event struct {
	SrcPort uint32
	VLAN    uint16
	Origin  uint8
	Tagged  bool
	Frame   []byte
}

// ParseEvent decodes a raw ring buffer record.
func ParseEvent(raw []byte) (Event, error) {
	if len(raw) < headerLen {
		return Event{}, fmt.Errorf("short flood record (%d bytes)", len(raw))
	}
	n := binary.LittleEndian.Uint32(raw[0:4])
	if int(n) > len(raw)-headerLen || n < 14 {
		return Event{}, fmt.Errorf("bad flood record length %d", n)
	}
	return Event{
		SrcPort: binary.LittleEndian.Uint32(raw[4:8]),
		VLAN:    binary.LittleEndian.Uint16(raw[8:10]),
		Origin:  raw[10],
		Tagged:  raw[11] != 0,
		Frame:   raw[headerLen : headerLen+int(n)],
	}, nil
}

// Port is a replication target.
type Port struct {
	ID      uint32
	Ifindex int
	VLAN    uint16
}

// Tx is one planned transmission.
type Tx struct {
	Ifindex int
	Frame   []byte
}

// Plan computes the transmissions for an event. It is pure so it can be unit
// tested; ports lists the pod ports (never the host port).
func Plan(ev Event, ports []Port, uplinkIfindex int) []Tx {
	if ev.Origin != OriginUplink {
		// Locally originated: may be CHECKSUM_PARTIAL.
		FixUDPChecksum(ev.Frame)
	}
	untagged := ev.Frame
	if ev.Tagged {
		untagged = StripTag(ev.Frame)
		if untagged == nil {
			return nil
		}
	}
	var out []Tx
	for _, p := range ports {
		if p.VLAN != ev.VLAN {
			continue
		}
		if ev.Origin == OriginPort && p.ID == ev.SrcPort {
			continue
		}
		out = append(out, Tx{Ifindex: p.Ifindex, Frame: untagged})
	}
	if ev.Origin == OriginPort {
		f := untagged
		if ev.VLAN != 0 {
			f = InsertTag(untagged, ev.VLAN)
		}
		out = append(out, Tx{Ifindex: uplinkIfindex, Frame: f})
	}
	return out
}

// StripTag removes the outer 802.1Q/802.1ad tag; it returns nil if the frame
// is too short to carry one.
func StripTag(f []byte) []byte {
	if len(f) < 18 {
		return nil
	}
	out := make([]byte, 0, len(f)-4)
	out = append(out, f[:12]...)
	return append(out, f[16:]...)
}

// InsertTag adds an 802.1Q tag with the given VLAN id.
func InsertTag(f []byte, vlan uint16) []byte {
	if len(f) < 14 {
		return nil
	}
	out := make([]byte, 0, len(f)+4)
	out = append(out, f[:12]...)
	out = append(out, 0x81, 0x00, byte(vlan>>8)&0x0f, byte(vlan))
	return append(out, f[12:]...)
}

// Counters are exported by the daemon.
type Counters struct {
	Events      atomic.Uint64
	TxFrames    atomic.Uint64
	TxErrors    atomic.Uint64
	ParseErrors atomic.Uint64
}

// Replicator reads the flood ring and transmits copies.
type Replicator struct {
	rd       *ringbuf.Reader
	fd       int
	uplink   int
	ports    func() []Port
	log      *slog.Logger
	Counters Counters

	closeOnce sync.Once
	done      chan struct{}
	running   atomic.Bool
}

// New creates a replicator for the ring buffer map rb. ports is called for
// every event and must return the current pod port set.
func New(rb *ebpf.Map, uplinkIfindex int, ports func() []Port, log *slog.Logger) (*Replicator, error) {
	rd, err := ringbuf.NewReader(rb)
	if err != nil {
		return nil, fmt.Errorf("opening flood ring: %w", err)
	}
	// Protocol 0: transmit-only socket, receives nothing.
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		rd.Close()
		return nil, fmt.Errorf("AF_PACKET socket: %w", err)
	}
	return &Replicator{rd: rd, fd: fd, uplink: uplinkIfindex, ports: ports, log: log, done: make(chan struct{})}, nil
}

// Running reports whether the replication loop is alive.
func (r *Replicator) Running() bool { return r.running.Load() }

// Run processes events until Close is called.
func (r *Replicator) Run() {
	r.running.Store(true)
	defer r.running.Store(false)
	defer close(r.done)
	var rec ringbuf.Record
	for {
		if err := r.rd.ReadInto(&rec); err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			r.log.Error("flood ring read failed", "err", err)
			continue
		}
		ev, err := ParseEvent(rec.RawSample)
		if err != nil {
			r.Counters.ParseErrors.Add(1)
			continue
		}
		r.Counters.Events.Add(1)
		for _, tx := range Plan(ev, r.ports(), r.uplink) {
			if err := r.send(tx); err != nil {
				r.Counters.TxErrors.Add(1)
				r.log.Debug("flood transmit failed", "ifindex", tx.Ifindex, "err", err)
				continue
			}
			r.Counters.TxFrames.Add(1)
		}
	}
}

func (r *Replicator) send(tx Tx) error {
	sa := &unix.SockaddrLinklayer{Ifindex: tx.Ifindex, Halen: 6}
	copy(sa.Addr[:], tx.Frame[:6])
	return unix.Sendto(r.fd, tx.Frame, 0, sa)
}

// Close stops Run and releases resources.
func (r *Replicator) Close() error {
	r.closeOnce.Do(func() {
		r.rd.Close()
		if r.running.Load() {
			<-r.done
		}
		unix.Close(r.fd)
	})
	return nil
}
