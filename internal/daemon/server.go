// SPDX-License-Identifier: Apache-2.0

// Package daemon implements the xdpbridge node daemon: the port registry, its
// HTTP API, persistence and the reconciliation loop.
package daemon

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tsuzu/xdpbridge/internal/api"
	"github.com/tsuzu/xdpbridge/internal/datapath"
	"github.com/tsuzu/xdpbridge/internal/flood"
	"github.com/tsuzu/xdpbridge/internal/k8swatch"
)

// Dataplane is the subset of *datapath.Datapath the server needs; it is an
// interface so the API can be unit tested without BPF.
type Dataplane interface {
	SetPort(p datapath.PortSpec, old *datapath.PortSpec) error
	RemovePort(p datapath.PortSpec) error
	LookupPort(id uint32) (datapath.PortSpec, error)
	LookupIfindex(ifindex int) (uint32, error)
	FDB() ([]datapath.FDBEntry, error)
	DeleteFDB(mac net.HardwareAddr, vlan uint16) error
	IfindexEntries() (map[int]uint32, error)
	DeleteIfindex(ifindex int) error
	PortLinkPinned(id uint32, ifindex int) bool
	Stats() (map[string]uint64, error)
	XDPAttached() bool
	HostVLANs() (map[uint16]net.HardwareAddr, error)
	SyncHostVLANs(map[uint16]net.HardwareAddr) error
	UplinkIndex() int
	UplinkMAC() net.HardwareAddr
	Mode() datapath.XDPMode
}

// Inspector is optionally implemented by the Dataplane to report kernel
// state in /v1/status.
type Inspector interface {
	InspectUplink() datapath.UplinkPrograms
	Pins() []string
}

// Links resolves interfaces in the host network namespace.
type Links interface {
	IndexByName(name string) (int, error)
	NamesWithPrefix(prefix string) ([]string, error)
}

// ErrLinkNotFound is returned by Links when an interface does not exist.
var ErrLinkNotFound = errors.New("link not found")

// Config configures a Server.
type Config struct {
	Uplink    string
	StateFile string
	Logger    *slog.Logger
	// FloodRunning and FloodCounters are optional hooks into the replicator.
	FloodRunning  func() bool
	FloodCounters func() map[string]uint64
	// PathExists checks netns paths; defaults to DefaultPathExists.
	PathExists func(string) bool
	// K8s enables the Kubernetes-API cross-check when non-nil.
	K8s K8sSource
	// NodeName is reported in the k8s status.
	NodeName string
	// K8sGrace is how long a pod may run without its port (and a port may
	// exist without its pod) before it is reported. Default 60s.
	K8sGrace time.Duration
	// Now is the clock (tests). Defaults to time.Now.
	Now func() time.Time
}

// K8sSource provides the Kubernetes view (implemented by k8swatch.Watcher).
type K8sSource interface {
	Snapshot() k8swatch.Snapshot
}

// Server is the daemon core.
type Server struct {
	cfg   Config
	dp    Dataplane
	links Links
	log   *slog.Logger

	mu    sync.Mutex
	ports map[string]*api.Port // by key
	// floodPorts is an immutable snapshot for the replicator hot path.
	floodPorts atomic.Pointer[[]flood.Port]

	problems     []string
	unregistered []string
	suspects     map[string]int // unregistered veths seen in consecutive passes
	vethMisses   map[string]int // ports whose host veth was not found, consecutive passes
	nsInvisible  map[string]bool
	nsInvisibleN int
	k8s          *api.K8sStatus
	hostVLANs    map[uint16]net.HardwareAddr
	repairs      atomic.Uint64
	gcs          atomic.Uint64
}

// New creates a server. Call Restore before serving.
func New(cfg Config, dp Dataplane, links Links) *Server {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.K8sGrace == 0 {
		cfg.K8sGrace = time.Minute
	}
	if cfg.PathExists == nil {
		cfg.PathExists = DefaultPathExists
	}
	s := &Server{cfg: cfg, dp: dp, links: links, log: cfg.Logger, ports: map[string]*api.Port{},
		suspects: map[string]int{}, vethMisses: map[string]int{}, nsInvisible: map[string]bool{}}
	s.floodPorts.Store(&[]flood.Port{})
	return s
}

// FloodPorts returns the current pod port set for the replicator.
func (s *Server) FloodPorts() []flood.Port { return *s.floodPorts.Load() }

func (s *Server) refreshFloodPortsLocked() {
	fp := make([]flood.Port, 0, len(s.ports))
	for _, p := range s.ports {
		fp = append(fp, flood.Port{ID: p.ID, Ifindex: p.HostIfindex, VLAN: p.VLAN})
	}
	sort.Slice(fp, func(i, j int) bool { return fp[i].ID < fp[j].ID })
	s.floodPorts.Store(&fp)
}

func specOf(p *api.Port) datapath.PortSpec {
	mac, _ := net.ParseMAC(p.MAC)
	return datapath.PortSpec{ID: p.ID, Ifindex: p.HostIfindex, VLAN: p.VLAN, MAC: mac, Kind: datapath.KindPod}
}

func (s *Server) allocIDLocked() (uint32, error) {
	used := make(map[uint32]bool, len(s.ports))
	for _, p := range s.ports {
		used[p.ID] = true
	}
	for id := uint32(1); id < datapath.MaxPorts; id++ {
		if !used[id] {
			return id, nil
		}
	}
	return 0, fmt.Errorf("port table full (%d ports)", datapath.MaxPorts-1)
}

// AddPort registers a port. It is idempotent for an identical request.
func (s *Server) AddPort(req api.PortRequest) (*api.Port, error) {
	if err := req.Validate(); err != nil {
		return nil, &httpErr{http.StatusBadRequest, err}
	}
	mac, _ := net.ParseMAC(req.MAC)
	req.MAC = mac.String()
	if !strings.HasPrefix(req.HostIfName, api.HostIfPrefix) {
		return nil, &httpErr{http.StatusBadRequest, fmt.Errorf("hostIfName %q must start with %q", req.HostIfName, api.HostIfPrefix)}
	}
	idx, err := s.links.IndexByName(req.HostIfName)
	if err != nil {
		return nil, &httpErr{http.StatusBadRequest, fmt.Errorf("host interface %q: %w", req.HostIfName, err)}
	}
	if idx == s.dp.UplinkIndex() {
		return nil, &httpErr{http.StatusBadRequest, fmt.Errorf("host interface is the uplink")}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	key := req.Key()
	for k, p := range s.ports {
		if k == key {
			continue
		}
		if p.MAC == req.MAC && p.VLAN == req.VLAN {
			return nil, &httpErr{http.StatusConflict, fmt.Errorf("MAC %s on VLAN %d already registered by %s", req.MAC, req.VLAN, k)}
		}
		if p.HostIfName == req.HostIfName {
			return nil, &httpErr{http.StatusConflict, fmt.Errorf("host interface %s already registered by %s", req.HostIfName, k)}
		}
	}
	if req.VLAN == 0 && req.MAC == s.dp.UplinkMAC().String() {
		return nil, &httpErr{http.StatusConflict, fmt.Errorf("MAC %s is the host MAC", req.MAC)}
	}
	if m, ok := s.hostVLANs[req.VLAN]; ok && m.String() == req.MAC {
		return nil, &httpErr{http.StatusConflict, fmt.Errorf("MAC %s is the host's MAC on VLAN %d", req.MAC, req.VLAN)}
	}

	old, exists := s.ports[key]
	var oldSpec *datapath.PortSpec
	p := &api.Port{PortRequest: req, HostIfindex: idx, Created: time.Now().UTC()}
	if exists {
		p.ID = old.ID
		p.Created = old.Created
		sp := specOf(old)
		oldSpec = &sp
	} else {
		if p.ID, err = s.allocIDLocked(); err != nil {
			return nil, &httpErr{http.StatusServiceUnavailable, err}
		}
	}
	if err := s.dp.SetPort(specOf(p), oldSpec); err != nil {
		if !exists {
			_ = s.dp.RemovePort(specOf(p))
		}
		return nil, fmt.Errorf("programming data path: %w", err)
	}
	p.Health = "ok"
	s.ports[key] = p
	if err := s.saveLocked(); err != nil {
		// Without persistence a restart would lose the port: fail loudly.
		if exists {
			s.ports[key] = old
			ns := specOf(p)
			_ = s.dp.SetPort(specOf(old), &ns)
		} else {
			delete(s.ports, key)
			_ = s.dp.RemovePort(specOf(p))
		}
		return nil, fmt.Errorf("persisting state: %w", err)
	}
	s.refreshFloodPortsLocked()
	s.log.Info("port registered", "key", key, "id", p.ID, "host_if", p.HostIfName,
		"ifindex", idx, "mac", p.MAC, "vlan", p.VLAN, "pod", req.PodNamespace+"/"+req.PodName, "update", exists)
	cp := *p
	return &cp, nil
}

// DeletePort unregisters a port. It returns a 404 error if unknown.
func (s *Server) DeletePort(key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.ports[key]
	if !ok {
		return &httpErr{http.StatusNotFound, fmt.Errorf("port %q not registered", key)}
	}
	if err := s.dp.RemovePort(specOf(p)); err != nil {
		return fmt.Errorf("removing from data path: %w", err)
	}
	delete(s.ports, key)
	if err := s.saveLocked(); err != nil {
		s.log.Error("persisting state after delete failed", "err", err)
	}
	s.refreshFloodPortsLocked()
	s.log.Info("port unregistered", "key", key, "id", p.ID, "host_if", p.HostIfName)
	return nil
}

// GetPort returns a copy of one port.
func (s *Server) GetPort(key string) (*api.Port, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.ports[key]
	if !ok {
		return nil, false
	}
	cp := *p
	return &cp, true
}

// ListPorts returns copies of all ports sorted by id.
func (s *Server) ListPorts() []api.Port {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]api.Port, 0, len(s.ports))
	for _, p := range s.ports {
		out = append(out, *p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// --- persistence ---------------------------------------------------------

type stateFile struct {
	Version int        `json:"version"`
	Ports   []api.Port `json:"ports"`
}

func (s *Server) saveLocked() error {
	if s.cfg.StateFile == "" {
		return nil
	}
	st := stateFile{Version: 1}
	for _, p := range s.ports {
		st.Ports = append(st.Ports, *p)
	}
	sort.Slice(st.Ports, func(i, j int) bool { return st.Ports[i].ID < st.Ports[j].ID })
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.cfg.StateFile), 0o700); err != nil {
		return err
	}
	tmp := s.cfg.StateFile + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.cfg.StateFile)
}

// Restore loads persisted registrations and re-programs the data path.
// Ports whose host veth no longer exists are dropped.
func (s *Server) Restore() error {
	if s.cfg.StateFile == "" {
		s.mu.Lock()
		s.syncHostVLANsLocked()
		s.mu.Unlock()
		return nil
	}
	b, err := os.ReadFile(s.cfg.StateFile)
	if errors.Is(err, os.ErrNotExist) {
		s.mu.Lock()
		s.syncHostVLANsLocked()
		s.mu.Unlock()
		return nil
	}
	if err != nil {
		return err
	}
	var st stateFile
	if err := json.Unmarshal(b, &st); err != nil {
		return fmt.Errorf("parsing %s: %w", s.cfg.StateFile, err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.syncHostVLANsLocked()
	for i := range st.Ports {
		p := st.Ports[i]
		idx, err := s.links.IndexByName(p.HostIfName)
		if err != nil {
			s.log.Warn("dropping restored port: host veth gone", "key", p.Key(), "host_if", p.HostIfName)
			_ = s.dp.RemovePort(specOf(&p))
			continue
		}
		if idx != p.HostIfindex {
			old := specOf(&p)
			p.HostIfindex = idx
			if err := s.dp.SetPort(specOf(&p), &old); err != nil {
				s.log.Error("restoring port failed", "key", p.Key(), "err", err)
				continue
			}
		} else if err := s.dp.SetPort(specOf(&p), nil); err != nil {
			s.log.Error("restoring port failed", "key", p.Key(), "err", err)
			continue
		}
		s.ports[p.Key()] = &p
	}
	s.refreshFloodPortsLocked()
	s.log.Info("state restored", "ports", len(s.ports))
	return s.saveLocked()
}

// --- reconciliation ------------------------------------------------------

// Reconcile compares registrations with interfaces and BPF maps, repairs
// drift, garbage-collects ports whose veth/netns vanished, and records
// problems for /healthz.
func (s *Server) Reconcile() {
	s.mu.Lock()
	defer s.mu.Unlock()

	var problems []string
	changed := false
	byID := map[uint32]*api.Port{}
	fdbSet := map[string]uint32{}
	if fdb, err := s.dp.FDB(); err == nil {
		for _, e := range fdb {
			fdbSet[fdbSetKey(e.MAC, e.VLAN)] = e.PortID
		}
	}

	nsInvisible := 0
	for key, p := range s.ports {
		// Liveness is judged by the host-side veth alone. A veth pair dies
		// with the pod's netns (the kernel deletes the peer, and with it
		// the host end), so a present host veth means a live pod. The
		// netns *path* is only informational: it is a path in the
		// runtime's mount namespace and may simply not be visible here.
		idx, err := s.links.IndexByName(p.HostIfName)
		if err != nil {
			if !errors.Is(err, ErrLinkNotFound) {
				problems = append(problems, fmt.Sprintf("port %s: cannot look up host veth %s: %v", key, p.HostIfName, err))
				continue
			}
			s.vethMisses[key]++
			if s.vethMisses[key] < gcMissThreshold {
				s.log.Warn("host veth of port not found; will garbage-collect if still missing",
					"key", key, "host_if", p.HostIfName, "misses", s.vethMisses[key])
				problems = append(problems, fmt.Sprintf("port %s: host veth %s not found", key, p.HostIfName))
				continue
			}
			s.log.Warn("garbage-collecting port whose pod vanished without CNI DEL",
				"key", key, "host_if", p.HostIfName, "veth_misses", s.vethMisses[key])
			_ = s.dp.RemovePort(specOf(p))
			delete(s.ports, key)
			delete(s.vethMisses, key)
			delete(s.nsInvisible, key)
			s.gcs.Add(1)
			changed = true
			continue
		}
		delete(s.vethMisses, key)
		if p.Netns != "" && !s.cfg.PathExists(p.Netns) {
			nsInvisible++
			if !s.nsInvisible[key] {
				s.nsInvisible[key] = true
				s.log.Error("netns path of a live port is not visible to the daemon; the port is kept "+
					"(its host veth is alive). Mount the host's /run/netns into the daemon so this check works",
					"key", key, "netns", p.Netns, "host_if", p.HostIfName)
			}
		} else {
			delete(s.nsInvisible, key)
		}
		want := specOf(p)
		if idx != p.HostIfindex {
			s.log.Warn("host veth ifindex changed, re-attaching", "key", key, "old", p.HostIfindex, "new", idx)
			p.HostIfindex = idx
			newSpec := specOf(p)
			if err := s.dp.SetPort(newSpec, &want); err != nil {
				p.Health = "re-attach failed: " + err.Error()
				problems = append(problems, fmt.Sprintf("port %s: %s", key, p.Health))
				continue
			}
			want = newSpec
			changed = true
		}
		if drift := s.checkPortLocked(want, fdbSet); drift != "" {
			s.log.Error("data path drift detected, repairing", "key", key, "id", p.ID, "drift", drift)
			s.repairs.Add(1)
			if err := s.dp.SetPort(want, nil); err != nil {
				p.Health = "repair failed: " + err.Error()
				problems = append(problems, fmt.Sprintf("port %s: %s", key, p.Health))
				continue
			}
		}
		p.Health = "ok"
		byID[p.ID] = p
	}

	if nsInvisible > 0 {
		problems = append(problems, fmt.Sprintf("%d live port(s) whose pod netns path is not visible in the daemon's "+
			"mount namespace (mount the host /run/netns; ports are kept)", nsInvisible))
	}
	s.nsInvisibleN = nsInvisible
	for k := range s.vethMisses {
		if _, ok := s.ports[k]; !ok {
			delete(s.vethMisses, k)
		}
	}
	for k := range s.nsInvisible {
		if _, ok := s.ports[k]; !ok {
			delete(s.nsInvisible, k)
		}
	}

	// Host port.
	host, err := s.dp.LookupPort(datapath.HostPortID)
	if err != nil || host.Kind != datapath.KindHost || host.Ifindex != s.dp.UplinkIndex() {
		s.log.Error("host port entry missing or wrong, repairing")
		s.repairs.Add(1)
		_ = s.dp.SetPort(datapath.PortSpec{ID: datapath.HostPortID, Ifindex: s.dp.UplinkIndex(), MAC: s.dp.UplinkMAC(), Kind: datapath.KindHost}, nil)
	}

	// Host VLAN subinterfaces may come and go at any time.
	if err := s.syncHostVLANsLocked(); err != nil {
		problems = append(problems, "host VLAN sync failed: "+err.Error())
	}

	// Orphaned map entries. Host entries are owned by syncHostVLANsLocked.
	if fdb, err := s.dp.FDB(); err == nil {
		for _, e := range fdb {
			if e.PortID == datapath.HostPortID {
				if m, ok := s.hostVLANs[e.VLAN]; ok && m.String() == e.MAC.String() {
					continue
				}
			}
			p, ok := byID[e.PortID]
			if !ok || p.MAC != e.MAC.String() || p.VLAN != e.VLAN {
				s.log.Warn("removing orphaned fdb entry", "mac", e.MAC.String(), "vlan", e.VLAN, "port", e.PortID)
				_ = s.dp.DeleteFDB(e.MAC, e.VLAN)
			}
		}
	}
	if ents, err := s.dp.IfindexEntries(); err == nil {
		for idx, id := range ents {
			if p, ok := byID[id]; !ok || p.HostIfindex != idx {
				s.log.Warn("removing orphaned ifindex entry", "ifindex", idx, "port", id)
				_ = s.dp.DeleteIfindex(idx)
			}
		}
	}

	// Watchdog: veths created by the CNI plugin that have no registration.
	// A pod with such a veth has a dead secondary interface. Require two
	// consecutive sightings to skip the window between veth creation and
	// registration inside a running CNI ADD.
	var unregistered []string
	if names, err := s.links.NamesWithPrefix(api.HostIfPrefix); err == nil {
		registered := map[string]bool{}
		for _, p := range s.ports {
			registered[p.HostIfName] = true
		}
		seen := map[string]int{}
		for _, n := range names {
			if registered[n] {
				continue
			}
			seen[n] = s.suspects[n] + 1
			if seen[n] >= 2 {
				unregistered = append(unregistered, n)
			}
		}
		s.suspects = seen
	}
	sort.Strings(unregistered)
	for _, n := range unregistered {
		s.log.Error("WATCHDOG: host veth has no port registration; its pod has no working xdpbridge interface", "host_if", n)
		problems = append(problems, "unregistered veth "+n)
	}

	if s.cfg.K8s != nil {
		problems = append(problems, s.k8sCheckLocked()...)
	}

	if !s.dp.XDPAttached() {
		problems = append(problems, "XDP program not attached to uplink "+s.cfg.Uplink)
	}
	if s.cfg.FloodRunning != nil && !s.cfg.FloodRunning() {
		problems = append(problems, "flood replicator not running")
	}

	s.problems = problems
	s.unregistered = unregistered
	if changed {
		if err := s.saveLocked(); err != nil {
			s.log.Error("persisting state failed", "err", err)
		}
		s.refreshFloodPortsLocked()
	}
}

func fdbSetKey(mac net.HardwareAddr, vlan uint16) string {
	return fmt.Sprintf("%s/%d", mac, vlan)
}

// checkPortLocked returns a description of the first data path entry for
// want that is missing or wrong, or "" if all is in place. fdb is a snapshot
// of the forwarding database taken at the start of the pass (re-attaching a
// port to a new ifindex does not change its fdb entry).
// syncHostVLANsLocked programs the host's VLAN memberships (the uplink and
// its 802.1Q subinterfaces) into the data path.
func (s *Server) syncHostVLANsLocked() error {
	want, err := s.dp.HostVLANs()
	if err != nil {
		return err
	}
	if err := s.dp.SyncHostVLANs(want); err != nil {
		return err
	}
	if len(want) != len(s.hostVLANs) {
		vids := make([]int, 0, len(want))
		for v := range want {
			vids = append(vids, int(v))
		}
		sort.Ints(vids)
		s.log.Info("host VLAN membership", "vlans", vids)
	}
	s.hostVLANs = want
	return nil
}

// k8sCheckLocked cross-checks registrations against the pods the API server
// says are on this node, records the result and returns problems.
func (s *Server) k8sCheckLocked() []string {
	snap := s.cfg.K8s.Snapshot()
	refs := make([]k8swatch.PortRef, 0, len(s.ports))
	for k, p := range s.ports {
		refs = append(refs, k8swatch.PortRef{Key: k, PodNamespace: p.PodNamespace, PodName: p.PodName, IfName: p.IfName, Created: p.Created})
	}
	res := k8swatch.CrossCheck(snap, refs, s.cfg.Now(), s.cfg.K8sGrace)
	s.k8s = &api.K8sStatus{
		Node: s.cfg.NodeName, Synced: snap.Synced, XDPBRIDGENADs: snap.XDPBRIDGENADs,
		PodsExpected: len(snap.Expected), PodsChecked: res.Checked,
		MissingPorts: res.MissingPorts, OrphanPorts: res.OrphanPorts,
	}
	problems := append([]string(nil), snap.Problems...)
	if !snap.Synced {
		problems = append(problems, "k8s watchdog: not synced with the API server yet")
	}
	for _, m := range res.MissingPorts {
		s.log.Error("WATCHDOG(k8s): pod is running without its xdpbridge interface", "detail", m)
		problems = append(problems, m)
	}
	for _, o := range res.OrphanPorts {
		s.log.Error("WATCHDOG(k8s): registered port has no pod", "detail", o)
		problems = append(problems, o)
	}
	return problems
}

func (s *Server) checkPortLocked(want datapath.PortSpec, fdb map[string]uint32) string {
	got, err := s.dp.LookupPort(want.ID)
	if err != nil || got.Ifindex != want.Ifindex || got.VLAN != want.VLAN || got.Kind != want.Kind || got.MAC.String() != want.MAC.String() {
		return "port_table"
	}
	if id, err := s.dp.LookupIfindex(want.Ifindex); err != nil || id != want.ID {
		return "ifindex_ports"
	}
	if id, ok := fdb[fdbSetKey(want.MAC, want.VLAN)]; !ok || id != want.ID {
		return "ports (fdb)"
	}
	if !s.dp.PortLinkPinned(want.ID, want.Ifindex) {
		return "tcx link"
	}
	return ""
}

// gcMissThreshold is how many consecutive reconcile passes a port's host
// veth must be missing before the port is garbage-collected.
const gcMissThreshold = 2

// DefaultPathExists stats a netns path. Runtimes report paths under either
// /var/run/netns or /run/netns (one is usually a symlink to the other on
// the host, but not necessarily inside the daemon's container), so both
// spellings are tried.
func DefaultPathExists(p string) bool {
	if _, err := os.Stat(p); err == nil {
		return true
	}
	for _, pair := range [][2]string{{"/var/run/", "/run/"}, {"/run/", "/var/run/"}} {
		if strings.HasPrefix(p, pair[0]) {
			if _, err := os.Stat(pair[1] + strings.TrimPrefix(p, pair[0])); err == nil {
				return true
			}
		}
	}
	return false
}

// RunReconciler calls Reconcile every interval until stop is closed.
func (s *Server) RunReconciler(interval time.Duration, stop <-chan struct{}) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			s.Reconcile()
		}
	}
}

// Status builds the status document.
func (s *Server) Status() api.Status {
	s.mu.Lock()
	st := api.Status{
		Uplink:            s.cfg.Uplink,
		XDPMode:           string(s.dp.Mode()),
		Ports:             len(s.ports),
		Problems:          append([]string(nil), s.problems...),
		UnregisteredVeths: append([]string(nil), s.unregistered...),
		NetnsNotVisible:   s.nsInvisibleN,
	}
	if s.k8s != nil {
		k := *s.k8s
		st.K8s = &k
	}
	for v := range s.hostVLANs {
		st.HostVLANs = append(st.HostVLANs, int(v))
	}
	if in, ok := s.dp.(Inspector); ok {
		u := in.InspectUplink()
		st.UplinkPrograms = &api.UplinkPrograms{
			XDP: u.XDP, XDPMode: u.XDPMode, TCXIngress: u.TCXIngress, TCXEgress: u.TCXEgress,
			TCXIngressCSV: strings.Join(u.TCXIngress, ","), TCXEgressCSV: strings.Join(u.TCXEgress, ","),
		}
		st.Pins = in.Pins()
	}
	sort.Ints(st.HostVLANs)
	s.mu.Unlock()
	if !s.dp.XDPAttached() && !contains(st.Problems, "XDP program not attached") {
		st.Problems = append(st.Problems, "XDP program not attached to uplink "+s.cfg.Uplink)
	}
	if s.cfg.FloodRunning != nil && !s.cfg.FloodRunning() && !contains(st.Problems, "flood replicator") {
		st.Problems = append(st.Problems, "flood replicator not running")
	}
	st.Healthy = len(st.Problems) == 0
	st.Ready = s.dp.XDPAttached() && (s.cfg.FloodRunning == nil || s.cfg.FloodRunning())
	st.Counters = map[string]uint64{}
	if c, err := s.dp.Stats(); err == nil {
		for k, v := range c {
			st.Counters["datapath_"+k] = v
		}
	}
	if s.cfg.FloodCounters != nil {
		for k, v := range s.cfg.FloodCounters() {
			st.Counters["flood_"+k] = v
		}
	}
	st.Counters["reconcile_repairs"] = s.repairs.Load()
	st.Counters["reconcile_gc"] = s.gcs.Load()
	return st
}

func contains(list []string, sub string) bool {
	for _, s := range list {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}
