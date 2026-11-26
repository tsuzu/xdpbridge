// SPDX-License-Identifier: Apache-2.0

// Package datapath loads the xdpl2 BPF programs, attaches them to the uplink
// and to pod ports, and manages the forwarding maps.
//
// All maps and links are pinned below a bpffs directory so that the data path
// keeps forwarding unicast traffic while the daemon restarts.
package datapath

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/xdpl2/xdpl2/internal/bpfobj"
)

// XDPMode selects how the uplink XDP program is attached.
type XDPMode string

const (
	XDPModeAuto    XDPMode = "auto"
	XDPModeNative  XDPMode = "native"
	XDPModeGeneric XDPMode = "generic"
)

// ParseXDPMode validates a mode string.
func ParseXDPMode(s string) (XDPMode, error) {
	switch XDPMode(s) {
	case XDPModeAuto, XDPModeNative, XDPModeGeneric:
		return XDPMode(s), nil
	}
	return "", fmt.Errorf("invalid XDP mode %q (want auto, native or generic)", s)
}

// Port kinds, mirroring enum xdpl2_port_kind.
const (
	KindHost = uint8(bpfobj.Xdpl2Xdpl2PortKindXDPL2PORT_HOST)
	KindPod  = uint8(bpfobj.Xdpl2Xdpl2PortKindXDPL2PORT_POD)
)

const (
	// MaxPorts mirrors XDPL2_MAX_PORTS. Port 0 is the host stack.
	MaxPorts = 1024
	// HostPortID is the port id of the host stack.
	HostPortID = 0
)

// Options configures Open.
type Options struct {
	Uplink   string  // uplink interface name
	PinDir   string  // bpffs directory, e.g. /sys/fs/bpf/xdpl2
	Mode     XDPMode // XDP attach mode
	ForceXDP bool    // replace a foreign XDP program on the uplink
	// RestoreFile records the uplink settings xdpl2 changes (promiscuous
	// mode, VLAN offloads) the first time it attaches, so Teardown can put
	// them back. Empty disables recording.
	RestoreFile string
	Logger      *slog.Logger
}

// Datapath is the loaded, attached data path.
type Datapath struct {
	opts   Options
	log    *slog.Logger
	objs   bpfobj.Xdpl2Objects
	uplink netlink.Link
	mode   XDPMode

	mu    sync.Mutex
	links map[string]link.Link // by pin name
}

// PortSpec describes a port to program into the maps.
type PortSpec struct {
	ID      uint32
	Ifindex int
	VLAN    uint16
	MAC     net.HardwareAddr
	Kind    uint8
}

func (o *Options) linkDir() string { return filepath.Join(o.PinDir, "links") }

// Open loads the BPF objects (reusing pinned maps), attaches the uplink
// programs and programs the host port.
func Open(opts Options) (*Datapath, error) {
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.Mode == "" {
		opts.Mode = XDPModeAuto
	}
	if err := ensureBPFFS(opts.PinDir); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(opts.linkDir(), 0o700); err != nil {
		return nil, err
	}

	uplink, err := netlink.LinkByName(opts.Uplink)
	if err != nil {
		return nil, fmt.Errorf("uplink %q: %w", opts.Uplink, err)
	}

	d := &Datapath{opts: opts, log: opts.Logger, uplink: uplink, links: map[string]link.Link{}}

	spec, err := bpfobj.LoadXdpl2()
	if err != nil {
		return nil, err
	}
	err = spec.LoadAndAssign(&d.objs, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{PinPath: opts.PinDir},
	})
	if err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			return nil, fmt.Errorf("loading BPF objects: %+v", ve)
		}
		return nil, fmt.Errorf("loading BPF objects (pinned maps from an incompatible version? remove %s): %w", opts.PinDir, err)
	}

	if err := d.writeConfig(); err != nil {
		d.objs.Close()
		return nil, err
	}
	if err := d.attachXDP(); err != nil {
		d.objs.Close()
		return nil, err
	}
	if err := d.attachUplinkEgress(); err != nil {
		d.objs.Close()
		return nil, err
	}
	// Frames for pod MACs must reach the uplink; NICs filter unicast
	// by destination MAC unless promiscuous.
	rs := loadRestore(opts.RestoreFile, opts.Uplink)
	if !rs.recorded {
		rs.PromiscWasOn = uplink.Attrs().Promisc != 0
		rs.recorded = true
	}
	if err := netlink.SetPromiscOn(uplink); err != nil {
		d.log.Warn("could not enable promiscuous mode on uplink", "err", err)
	}
	if off, on, err := disableVLANOffload(opts.Uplink); err != nil {
		d.log.Warn("could not query uplink offloads; VLAN access ports may not work", "err", err)
	} else {
		rs.addOffloads(off)
		if len(on) > 0 {
			d.log.Warn("uplink keeps VLAN offloads on; tagged traffic to VLAN access ports may not be switched", "features", on)
		}
	}
	if err := rs.save(opts.RestoreFile); err != nil {
		d.log.Warn("could not record uplink settings for teardown", "file", opts.RestoreFile, "err", err)
	}
	if err := d.SetPort(PortSpec{
		ID: HostPortID, Ifindex: uplink.Attrs().Index, MAC: uplink.Attrs().HardwareAddr, Kind: KindHost,
	}, nil); err != nil {
		d.objs.Close()
		return nil, fmt.Errorf("programming host port: %w", err)
	}
	hv, err := d.HostVLANs()
	if err == nil {
		err = d.SyncHostVLANs(hv)
	}
	if err != nil {
		d.objs.Close()
		return nil, fmt.Errorf("programming host VLANs: %w", err)
	}
	return d, nil
}

func ensureBPFFS(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	var st unix.Statfs_t
	if err := unix.Statfs(dir, &st); err != nil {
		return err
	}
	if st.Type != unix.BPF_FS_MAGIC {
		return fmt.Errorf("%s is not on a bpffs mount (mount -t bpf bpf <dir>)", dir)
	}
	return nil
}

func (d *Datapath) writeConfig() error {
	var cfg bpfobj.Xdpl2Config
	cfg.UplinkIfindex = uint32(d.uplink.Attrs().Index)
	copy(cfg.HostMac[:], d.uplink.Attrs().HardwareAddr)
	return d.objs.ConfigMap.Put(uint32(0), &cfg)
}

// Mode returns the XDP mode actually in use.
func (d *Datapath) Mode() XDPMode { return d.mode }

// UplinkIndex returns the uplink ifindex.
func (d *Datapath) UplinkIndex() int { return d.uplink.Attrs().Index }

// UplinkMAC returns the uplink (host port) MAC.
func (d *Datapath) UplinkMAC() net.HardwareAddr { return d.uplink.Attrs().HardwareAddr }

// FloodRing returns the flood ring buffer map.
func (d *Datapath) FloodRing() *ebpf.Map { return d.objs.FloodRb }

// replaceOrAttach updates a pinned link with prog, or attaches a fresh one.
func (d *Datapath) replaceOrAttach(name string, prog *ebpf.Program, wantIfindex uint32, attach func() (link.Link, error)) (link.Link, error) {
	path := filepath.Join(d.opts.linkDir(), name)
	if l, err := link.LoadPinnedLink(path, nil); err == nil {
		info, ierr := l.Info()
		ok := ierr == nil
		if ok {
			switch {
			case info.XDP() != nil:
				ok = info.XDP().Ifindex == wantIfindex
			case info.TCX() != nil:
				ok = info.TCX().Ifindex == wantIfindex
			}
		}
		if ok {
			if err := l.Update(prog); err == nil {
				return l, nil
			}
		}
		// Stale (interface gone or recreated): drop the pin and start over.
		_ = l.Unpin()
		_ = l.Close()
	}
	l, err := attach()
	if err != nil {
		return nil, err
	}
	if err := l.Pin(path); err != nil {
		_ = l.Close()
		return nil, fmt.Errorf("pinning link %s: %w", path, err)
	}
	return l, nil
}

func (d *Datapath) attachXDP() error {
	ifindex := d.uplink.Attrs().Index
	pinned := filepath.Join(d.opts.linkDir(), "xdp_uplink")
	_, statErr := os.Stat(pinned)
	ours := statErr == nil

	if x := d.uplink.Attrs().Xdp; x != nil && x.Attached && !ours {
		if !d.opts.ForceXDP {
			return fmt.Errorf("refusing to replace foreign XDP program (id %d) on %s; "+
				"xdpl2 needs the XDP hook (pass --force-xdp to override)", x.ProgId, d.opts.Uplink)
		}
		d.log.Warn("replacing foreign XDP program on uplink", "uplink", d.opts.Uplink, "prog_id", x.ProgId)
		if err := netlink.LinkSetXdpFd(d.uplink, -1); err != nil {
			return fmt.Errorf("detaching foreign XDP program: %w", err)
		}
	}

	try := func(flags link.XDPAttachFlags) (link.Link, error) {
		return d.replaceOrAttach("xdp_uplink", d.objs.XdpUplink, uint32(ifindex), func() (link.Link, error) {
			return link.AttachXDP(link.XDPOptions{Program: d.objs.XdpUplink, Interface: ifindex, Flags: flags})
		})
	}

	var (
		l   link.Link
		err error
	)
	switch d.opts.Mode {
	case XDPModeNative:
		l, err = try(link.XDPDriverMode)
		d.mode = XDPModeNative
	case XDPModeGeneric:
		l, err = try(link.XDPGenericMode)
		d.mode = XDPModeGeneric
	default:
		l, err = try(link.XDPDriverMode)
		d.mode = XDPModeNative
		if err != nil {
			d.log.Info("native XDP unavailable, falling back to generic", "err", err)
			l, err = try(link.XDPGenericMode)
			d.mode = XDPModeGeneric
		}
	}
	if err != nil {
		return fmt.Errorf("attaching XDP to %s: %w", d.opts.Uplink, err)
	}
	// A reused pinned link keeps its original mode; report what is live.
	if lk, lerr := netlink.LinkByIndex(ifindex); lerr == nil && lk.Attrs().Xdp != nil {
		switch lk.Attrs().Xdp.AttachMode {
		case nl_XDP_ATTACHED_DRV:
			d.mode = XDPModeNative
		case nl_XDP_ATTACHED_SKB:
			d.mode = XDPModeGeneric
		}
	}
	d.mu.Lock()
	d.links["xdp_uplink"] = l
	d.mu.Unlock()
	d.log.Info("XDP attached", "uplink", d.opts.Uplink, "mode", d.mode)
	return nil
}

// netlink IFLA_XDP_ATTACHED values.
const (
	nl_XDP_ATTACHED_DRV = 1
	nl_XDP_ATTACHED_SKB = 2
)

func (d *Datapath) attachUplinkEgress() error {
	ifindex := d.uplink.Attrs().Index
	l, err := d.replaceOrAttach("uplink_egress", d.objs.TcUplinkEgress, uint32(ifindex), func() (link.Link, error) {
		// Head of the chain: we only claim frames for local pods and
		// return TCX_NEXT for everything else.
		return link.AttachTCX(link.TCXOptions{
			Interface: ifindex, Program: d.objs.TcUplinkEgress,
			Attach: ebpf.AttachTCXEgress, Anchor: link.Head(),
		})
	})
	if err != nil {
		return fmt.Errorf("attaching TCX egress to %s (kernel >= 6.6 required): %w", d.opts.Uplink, err)
	}
	d.mu.Lock()
	d.links["uplink_egress"] = l
	d.mu.Unlock()
	return nil
}

func portLinkName(id uint32) string { return "port_" + strconv.FormatUint(uint64(id), 10) }

// SetPort programs a port into the maps. For pod ports it also attaches the
// TCX ingress program to the host-side veth. old, if non-nil, is the previous
// spec for the same id, whose stale map entries are removed.
func (d *Datapath) SetPort(p PortSpec, old *PortSpec) error {
	if p.ID >= MaxPorts {
		return fmt.Errorf("port id %d out of range", p.ID)
	}
	if len(p.MAC) != 6 {
		return fmt.Errorf("port %d: invalid MAC %q", p.ID, p.MAC)
	}
	if p.Kind == KindPod {
		_, err := d.replaceOrAttach(portLinkName(p.ID), d.objs.TcPortIngress, uint32(p.Ifindex), func() (link.Link, error) {
			return link.AttachTCX(link.TCXOptions{
				Interface: p.Ifindex, Program: d.objs.TcPortIngress,
				Attach: ebpf.AttachTCXIngress, Anchor: link.Head(),
			})
		})
		if err != nil {
			return fmt.Errorf("attaching TCX ingress to port %d (ifindex %d): %w", p.ID, p.Ifindex, err)
		}
	}
	if old != nil {
		d.deleteEntries(*old, p)
	}

	var pv bpfobj.Xdpl2Port
	pv.Ifindex = uint32(p.Ifindex)
	pv.Vlan = p.VLAN
	pv.Kind = p.Kind
	copy(pv.Mac[:], p.MAC)
	if err := d.objs.PortTable.Put(p.ID, &pv); err != nil {
		return fmt.Errorf("port_table: %w", err)
	}
	if p.Kind == KindPod {
		if err := d.objs.IfindexPorts.Put(uint32(p.Ifindex), p.ID); err != nil {
			return fmt.Errorf("ifindex_ports: %w", err)
		}
	}
	if err := d.objs.Ports.Put(fdbKey(p.MAC, p.VLAN), bpfobj.Xdpl2FdbVal{PortId: p.ID}); err != nil {
		return fmt.Errorf("ports: %w", err)
	}
	if err := d.objs.LocalMacs.Put(macKey(p.MAC), p.ID); err != nil {
		return fmt.Errorf("local_macs: %w", err)
	}
	return nil
}

func macKey(mac net.HardwareAddr) bpfobj.Xdpl2MacKey {
	var k bpfobj.Xdpl2MacKey
	copy(k.Mac[:], mac)
	return k
}

// HostVLANs discovers the host's interfaces on the uplink's segment: the
// uplink itself (VLAN 0) and its 802.1Q subinterfaces in this netns.
func (d *Datapath) HostVLANs() (map[uint16]net.HardwareAddr, error) {
	out := map[uint16]net.HardwareAddr{0: d.uplink.Attrs().HardwareAddr}
	links, err := netlink.LinkList()
	if err != nil {
		return nil, err
	}
	for _, l := range links {
		v, ok := l.(*netlink.Vlan)
		if !ok || v.Attrs().ParentIndex != d.uplink.Attrs().Index {
			continue
		}
		if v.VlanProtocol != netlink.VLAN_PROTOCOL_8021Q && v.VlanProtocol != netlink.VLAN_PROTOCOL_UNKNOWN {
			continue // 802.1ad S-VLAN subinterfaces are not switched
		}
		if v.VlanId <= 0 || v.VlanId > 4094 || len(v.Attrs().HardwareAddr) != 6 {
			continue
		}
		out[uint16(v.VlanId)] = v.Attrs().HardwareAddr
	}
	return out, nil
}

// SyncHostVLANs makes host_vlans, the host's fdb entries and local_macs
// match want (VLAN id -> host interface MAC); entries for VLANs no longer
// present are removed. VLAN 0 must be included.
func (d *Datapath) SyncHostVLANs(want map[uint16]net.HardwareAddr) error {
	var (
		k  uint32
		hv bpfobj.Xdpl2HostVlan
	)
	stale := map[uint16]net.HardwareAddr{}
	it := d.objs.HostVlans.Iterate()
	for it.Next(&k, &hv) {
		mac := append(net.HardwareAddr(nil), hv.Mac[:]...)
		if w, ok := want[uint16(k)]; !ok || w.String() != mac.String() {
			stale[uint16(k)] = mac
		}
	}
	if err := it.Err(); err != nil {
		return err
	}
	keepMAC := map[string]bool{}
	for _, m := range want {
		keepMAC[m.String()] = true
	}
	for vid, mac := range stale {
		_ = d.objs.HostVlans.Delete(uint32(vid))
		var v bpfobj.Xdpl2FdbVal
		if d.objs.Ports.Lookup(fdbKey(mac, vid), &v) == nil && v.PortId == HostPortID {
			_ = d.objs.Ports.Delete(fdbKey(mac, vid))
		}
		var id uint32
		if !keepMAC[mac.String()] && d.objs.LocalMacs.Lookup(macKey(mac), &id) == nil && id == HostPortID {
			_ = d.objs.LocalMacs.Delete(macKey(mac))
		}
	}
	for vid, mac := range want {
		var v bpfobj.Xdpl2HostVlan
		copy(v.Mac[:], mac)
		if err := d.objs.HostVlans.Put(uint32(vid), &v); err != nil {
			return fmt.Errorf("host_vlans: %w", err)
		}
		if err := d.objs.Ports.Put(fdbKey(mac, vid), bpfobj.Xdpl2FdbVal{PortId: HostPortID}); err != nil {
			return fmt.Errorf("ports: %w", err)
		}
		if err := d.objs.LocalMacs.Put(macKey(mac), uint32(HostPortID)); err != nil {
			return fmt.Errorf("local_macs: %w", err)
		}
	}
	return nil
}

// deleteEntries removes map entries of old that are not shared with keep.
func (d *Datapath) deleteEntries(old, keep PortSpec) {
	if old.MAC.String() != keep.MAC.String() || old.VLAN != keep.VLAN {
		k := fdbKey(old.MAC, old.VLAN)
		var v bpfobj.Xdpl2FdbVal
		if d.objs.Ports.Lookup(k, &v) == nil && v.PortId == old.ID {
			_ = d.objs.Ports.Delete(k)
		}
	}
	if old.MAC.String() != keep.MAC.String() && len(old.MAC) == 6 {
		var id uint32
		if d.objs.LocalMacs.Lookup(macKey(old.MAC), &id) == nil && id == old.ID {
			_ = d.objs.LocalMacs.Delete(macKey(old.MAC))
		}
	}
	if old.Kind == KindPod && old.Ifindex != keep.Ifindex {
		var id uint32
		if d.objs.IfindexPorts.Lookup(uint32(old.Ifindex), &id) == nil && id == old.ID {
			_ = d.objs.IfindexPorts.Delete(uint32(old.Ifindex))
		}
	}
}

// RemovePort removes a pod port from the maps and detaches its program.
func (d *Datapath) RemovePort(p PortSpec) error {
	d.deleteEntries(p, PortSpec{})
	var zero bpfobj.Xdpl2Port
	if err := d.objs.PortTable.Put(p.ID, &zero); err != nil {
		return err
	}
	path := filepath.Join(d.opts.linkDir(), portLinkName(p.ID))
	if l, err := link.LoadPinnedLink(path, nil); err == nil {
		_ = l.Unpin()
		_ = l.Close() // closing the last reference detaches
	}
	return nil
}

// PortLinkPinned reports whether the TCX link for a port is pinned and still
// attached to ifindex.
func (d *Datapath) PortLinkPinned(id uint32, ifindex int) bool {
	l, err := link.LoadPinnedLink(filepath.Join(d.opts.linkDir(), portLinkName(id)), nil)
	if err != nil {
		return false
	}
	defer l.Close()
	info, err := l.Info()
	return err == nil && info.TCX() != nil && info.TCX().Ifindex == uint32(ifindex)
}

func fdbKey(mac net.HardwareAddr, vlan uint16) bpfobj.Xdpl2FdbKey {
	var k bpfobj.Xdpl2FdbKey
	copy(k.Mac[:], mac)
	k.Vlan = vlan
	return k
}

// FDBEntry is one entry of the "ports" map.
type FDBEntry struct {
	MAC    net.HardwareAddr
	VLAN   uint16
	PortID uint32
}

// FDB dumps the forwarding database.
func (d *Datapath) FDB() ([]FDBEntry, error) {
	var (
		k   bpfobj.Xdpl2FdbKey
		v   bpfobj.Xdpl2FdbVal
		out []FDBEntry
	)
	it := d.objs.Ports.Iterate()
	for it.Next(&k, &v) {
		out = append(out, FDBEntry{MAC: append(net.HardwareAddr(nil), k.Mac[:]...), VLAN: k.Vlan, PortID: v.PortId})
	}
	return out, it.Err()
}

// DeleteFDB removes one forwarding entry.
func (d *Datapath) DeleteFDB(mac net.HardwareAddr, vlan uint16) error {
	return d.objs.Ports.Delete(fdbKey(mac, vlan))
}

// LookupPort reads one port_table entry.
func (d *Datapath) LookupPort(id uint32) (PortSpec, error) {
	var pv bpfobj.Xdpl2Port
	if err := d.objs.PortTable.Lookup(id, &pv); err != nil {
		return PortSpec{}, err
	}
	return PortSpec{
		ID: id, Ifindex: int(pv.Ifindex), VLAN: pv.Vlan, Kind: pv.Kind,
		MAC: append(net.HardwareAddr(nil), pv.Mac[:]...),
	}, nil
}

// LookupIfindex reads one ifindex_ports entry.
func (d *Datapath) LookupIfindex(ifindex int) (uint32, error) {
	var id uint32
	err := d.objs.IfindexPorts.Lookup(uint32(ifindex), &id)
	return id, err
}

// IfindexEntries dumps the ifindex_ports map.
func (d *Datapath) IfindexEntries() (map[int]uint32, error) {
	var k, v uint32
	out := map[int]uint32{}
	it := d.objs.IfindexPorts.Iterate()
	for it.Next(&k, &v) {
		out[int(k)] = v
	}
	return out, it.Err()
}

// DeleteIfindex removes one ifindex_ports entry.
func (d *Datapath) DeleteIfindex(ifindex int) error {
	return d.objs.IfindexPorts.Delete(uint32(ifindex))
}

// StatNames lists counter names in map order.
var StatNames = []string{
	"xdp_rx", "xdp_redirect", "xdp_pass", "xdp_flood", "xdp_loop_pass",
	"port_rx", "port_to_port", "port_to_host", "port_to_uplink", "port_flood",
	"port_drop_spoof", "port_drop_unknown", "port_drop_tagged", "port_drop_hairpin",
	"uplink_egress_to_port", "uplink_egress_flood",
	"flood_rb_full", "flood_too_big", "parse_error", "redirect_error",
}

// Stats returns the data path counters summed over CPUs.
func (d *Datapath) Stats() (map[string]uint64, error) {
	out := make(map[string]uint64, len(StatNames))
	for i, name := range StatNames {
		var per []uint64
		if err := d.objs.Stats.Lookup(uint32(i), &per); err != nil {
			return nil, err
		}
		var sum uint64
		for _, v := range per {
			sum += v
		}
		out[name] = sum
	}
	return out, nil
}

// XDPAttached reports whether our XDP program is still attached to the uplink.
func (d *Datapath) XDPAttached() bool {
	lk, err := netlink.LinkByIndex(d.uplink.Attrs().Index)
	if err != nil || lk.Attrs().Xdp == nil || !lk.Attrs().Xdp.Attached {
		return false
	}
	info, err := d.objs.XdpUplink.Info()
	if err != nil {
		return false
	}
	id, ok := info.ID()
	return ok && uint32(id) == lk.Attrs().Xdp.ProgId
}

// Close releases userspace handles. Pinned links and maps stay in place so
// that forwarding continues across daemon restarts.
func (d *Datapath) Close() error {
	d.mu.Lock()
	for _, l := range d.links {
		_ = l.Close()
	}
	d.links = map[string]link.Link{}
	d.mu.Unlock()
	return d.objs.Close()
}
