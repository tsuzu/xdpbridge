// SPDX-License-Identifier: Apache-2.0

package datapath

import (
	"os"
	"path/filepath"
	"sort"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
)

// UplinkPrograms describes what is attached to the uplink, as the kernel
// reports it (not just what xdpbridge thinks it attached). Program names are
// the kernel's, truncated to 15 characters.
type UplinkPrograms struct {
	XDP        string   `json:"xdp"`               // program name, "" if none
	XDPMode    string   `json:"xdpMode,omitempty"` // native, generic, offload
	TCXIngress []string `json:"tcxIngress"`        // in chain order
	TCXEgress  []string `json:"tcxEgress"`         // in chain order
}

func progName(id ebpf.ProgramID) string {
	p, err := ebpf.NewProgramFromID(id)
	if err != nil {
		return "?"
	}
	defer p.Close()
	info, err := p.Info()
	if err != nil || info.Name == "" {
		return "?"
	}
	return info.Name
}

func tcxNames(ifindex int, at ebpf.AttachType) []string {
	res, err := link.QueryPrograms(link.QueryOptions{Target: ifindex, Attach: at})
	if err != nil {
		return nil
	}
	out := []string{}
	for _, p := range res.Programs {
		out = append(out, progName(p.ID))
	}
	return out
}

// InspectUplink queries the kernel for programs on the uplink.
func (d *Datapath) InspectUplink() UplinkPrograms {
	u := UplinkPrograms{TCXIngress: []string{}, TCXEgress: []string{}}
	idx := d.uplink.Attrs().Index
	if lk, err := netlink.LinkByIndex(idx); err == nil && lk.Attrs().Xdp != nil && lk.Attrs().Xdp.Attached {
		u.XDP = progName(ebpf.ProgramID(lk.Attrs().Xdp.ProgId))
		switch lk.Attrs().Xdp.AttachMode {
		case nl_XDP_ATTACHED_DRV:
			u.XDPMode = "native"
		case nl_XDP_ATTACHED_SKB:
			u.XDPMode = "generic"
		case 3:
			u.XDPMode = "offload"
		}
	}
	if n := tcxNames(idx, ebpf.AttachTCXIngress); n != nil {
		u.TCXIngress = n
	}
	if n := tcxNames(idx, ebpf.AttachTCXEgress); n != nil {
		u.TCXEgress = n
	}
	return u
}

// Pins lists pinned objects below PinDir (maps, and links/<name>).
func (d *Datapath) Pins() []string {
	var out []string
	_ = filepath.WalkDir(d.opts.PinDir, func(p string, e os.DirEntry, err error) error {
		if err != nil || e.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(d.opts.PinDir, p)
		out = append(out, rel)
		return nil
	})
	sort.Strings(out)
	return out
}
