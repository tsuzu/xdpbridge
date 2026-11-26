// SPDX-License-Identifier: Apache-2.0

package datapath

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"unsafe"

	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// restoreState is persisted in Options.RestoreFile.
type restoreState struct {
	Uplink string `json:"uplink"`
	// PromiscWasOn is the uplink's promiscuous flag before xdpbridge first
	// attached.
	PromiscWasOn bool `json:"promiscWasOn"`
	// OffloadsTurnedOff lists ethtool features xdpbridge switched off.
	OffloadsTurnedOff []string `json:"offloadsTurnedOff,omitempty"`

	recorded bool
}

func loadRestore(path, uplink string) *restoreState {
	rs := &restoreState{Uplink: uplink}
	if path == "" {
		return rs
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return rs
	}
	var old restoreState
	if json.Unmarshal(b, &old) == nil && old.Uplink == uplink {
		old.recorded = true
		return &old
	}
	return rs
}

func (rs *restoreState) addOffloads(fs []string) {
	have := map[string]bool{}
	for _, f := range rs.OffloadsTurnedOff {
		have[f] = true
	}
	for _, f := range fs {
		if !have[f] {
			rs.OffloadsTurnedOff = append(rs.OffloadsTurnedOff, f)
		}
	}
	sort.Strings(rs.OffloadsTurnedOff)
}

func (rs *restoreState) save(path string) error {
	if path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(rs, "", "  ")
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// detachLink issues BPF_LINK_DETACH, which forcibly detaches the program
// even while other file descriptors to the link exist.
func detachLink(l link.Link) error {
	f, ok := l.(interface{ FD() int })
	if !ok {
		return errors.New("link has no fd")
	}
	const bpfLinkDetach = 34 // BPF_LINK_DETACH
	attr := struct{ linkFD uint32 }{uint32(f.FD())}
	_, _, errno := unix.Syscall(unix.SYS_BPF, bpfLinkDetach, uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr))
	if errno != 0 {
		return errno
	}
	return nil
}

// TeardownReport describes what Teardown did.
type TeardownReport struct {
	Actions  []string
	Warnings []string
}

// Teardown removes the xdpbridge data path from the node: it detaches every
// pinned link (uplink XDP, uplink TCX egress, all port TCX links), removes
// all pins below pinDir, and restores the uplink's promiscuous mode and VLAN
// offloads from restoreFile. It is idempotent. The daemon must not be
// running, or it would keep the programs attached through its own handles.
func Teardown(pinDir, restoreFile string) (*TeardownReport, error) {
	r := &TeardownReport{}
	linkDir := filepath.Join(pinDir, "links")
	entries, err := os.ReadDir(linkDir)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return r, err
	}
	for _, e := range entries {
		p := filepath.Join(linkDir, e.Name())
		l, err := link.LoadPinnedLink(p, nil)
		if err != nil {
			if rerr := os.Remove(p); rerr != nil {
				r.Warnings = append(r.Warnings, fmt.Sprintf("removing %s: %v", p, rerr))
				continue
			}
			r.Actions = append(r.Actions, "removed unloadable pin "+p)
			continue
		}
		// Detach explicitly: closing the last fd alone is not enough if
		// another process still holds a reference.
		derr := detachLink(l)
		uerr := l.Unpin()
		_ = l.Close()
		switch {
		case uerr != nil:
			r.Warnings = append(r.Warnings, fmt.Sprintf("unpinning %s: %v", p, uerr))
		case derr != nil:
			r.Actions = append(r.Actions, fmt.Sprintf("unpinned link %s (detach: %v; detached when last reference closes)", e.Name(), derr))
		default:
			r.Actions = append(r.Actions, "detached and unpinned link "+e.Name())
		}
	}
	_ = os.Remove(linkDir)

	entries, err = os.ReadDir(pinDir)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return r, err
	}
	for _, e := range entries {
		p := filepath.Join(pinDir, e.Name())
		if err := os.Remove(p); err != nil {
			r.Warnings = append(r.Warnings, fmt.Sprintf("removing %s: %v", p, err))
			continue
		}
		r.Actions = append(r.Actions, "removed map pin "+e.Name())
	}
	if err := os.Remove(pinDir); err == nil {
		r.Actions = append(r.Actions, "removed "+pinDir)
	} else if !errors.Is(err, os.ErrNotExist) {
		r.Warnings = append(r.Warnings, fmt.Sprintf("removing %s: %v", pinDir, err))
	}

	// Uplink settings.
	if restoreFile == "" {
		return r, nil
	}
	b, err := os.ReadFile(restoreFile)
	if errors.Is(err, os.ErrNotExist) {
		r.Actions = append(r.Actions, "no uplink settings recorded ("+restoreFile+"); promiscuous mode and offloads left as they are")
		return r, nil
	}
	if err != nil {
		return r, err
	}
	var rs restoreState
	if err := json.Unmarshal(b, &rs); err != nil {
		return r, fmt.Errorf("parsing %s: %w", restoreFile, err)
	}
	up, err := netlink.LinkByName(rs.Uplink)
	if err != nil {
		r.Warnings = append(r.Warnings, fmt.Sprintf("uplink %s not found; settings not restored", rs.Uplink))
		return r, nil
	}
	if x := up.Attrs().Xdp; x != nil && x.Attached {
		r.Warnings = append(r.Warnings, fmt.Sprintf("uplink %s still has an XDP program (id %d) attached; is a daemon still running?", rs.Uplink, x.ProgId))
	} else {
		r.Actions = append(r.Actions, "verified: no XDP program on "+rs.Uplink)
	}
	if !rs.PromiscWasOn {
		if err := netlink.SetPromiscOff(up); err != nil {
			r.Warnings = append(r.Warnings, fmt.Sprintf("disabling promiscuous mode on %s: %v", rs.Uplink, err))
		} else {
			r.Actions = append(r.Actions, "disabled promiscuous mode on "+rs.Uplink)
		}
	}
	if err := enableFeatures(rs.Uplink, rs.OffloadsTurnedOff); err != nil {
		r.Warnings = append(r.Warnings, fmt.Sprintf("re-enabling offloads %v on %s: %v", rs.OffloadsTurnedOff, rs.Uplink, err))
	} else if len(rs.OffloadsTurnedOff) > 0 {
		r.Actions = append(r.Actions, fmt.Sprintf("re-enabled offloads %v on %s", rs.OffloadsTurnedOff, rs.Uplink))
	}
	if err := os.Remove(restoreFile); err == nil {
		r.Actions = append(r.Actions, "removed "+restoreFile)
	}
	return r, nil
}
