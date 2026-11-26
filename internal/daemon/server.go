// SPDX-License-Identifier: Apache-2.0

// Package daemon implements the xdpl2 node daemon: the port registry, its
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

	"github.com/xdpl2/xdpl2/internal/api"
	"github.com/xdpl2/xdpl2/internal/datapath"
	"github.com/xdpl2/xdpl2/internal/flood"
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
	UplinkIndex() int
	UplinkMAC() net.HardwareAddr
	Mode() datapath.XDPMode
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
	// PathExists checks netns paths; defaults to os.Stat.
	PathExists func(string) bool
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
	repairs      atomic.Uint64
	gcs          atomic.Uint64
}

// New creates a server. Call Restore before serving.
func New(cfg Config, dp Dataplane, links Links) *Server {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.PathExists == nil {
		cfg.PathExists = func(p string) bool { _, err := os.Stat(p); return err == nil }
	}
	s := &Server{cfg: cfg, dp: dp, links: links, log: cfg.Logger, ports: map[string]*api.Port{}, suspects: map[string]int{}}
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
		return nil
	}
	b, err := os.ReadFile(s.cfg.StateFile)
	if errors.Is(err, os.ErrNotExist) {
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

	for key, p := range s.ports {
		idx, err := s.links.IndexByName(p.HostIfName)
		gone := err != nil
		nsGone := p.Netns != "" && !s.cfg.PathExists(p.Netns)
		if gone || nsGone {
			s.log.Warn("garbage-collecting port whose pod vanished without CNI DEL",
				"key", key, "host_if", p.HostIfName, "veth_gone", gone, "netns_gone", nsGone)
			_ = s.dp.RemovePort(specOf(p))
			delete(s.ports, key)
			s.gcs.Add(1)
			changed = true
			continue
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
		if drift := s.checkPortLocked(want); drift != "" {
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

	// Host port.
	host, err := s.dp.LookupPort(datapath.HostPortID)
	if err != nil || host.Kind != datapath.KindHost || host.Ifindex != s.dp.UplinkIndex() {
		s.log.Error("host port entry missing or wrong, repairing")
		s.repairs.Add(1)
		_ = s.dp.SetPort(datapath.PortSpec{ID: datapath.HostPortID, Ifindex: s.dp.UplinkIndex(), MAC: s.dp.UplinkMAC(), Kind: datapath.KindHost}, nil)
	}

	// Orphaned map entries.
	if fdb, err := s.dp.FDB(); err == nil {
		for _, e := range fdb {
			if e.PortID == datapath.HostPortID && e.VLAN == 0 && e.MAC.String() == s.dp.UplinkMAC().String() {
				continue
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
		s.log.Error("WATCHDOG: host veth has no port registration; its pod has no working xdpl2 interface", "host_if", n)
		problems = append(problems, "unregistered veth "+n)
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

func (s *Server) checkPortLocked(want datapath.PortSpec) string {
	got, err := s.dp.LookupPort(want.ID)
	if err != nil || got.Ifindex != want.Ifindex || got.VLAN != want.VLAN || got.Kind != want.Kind || got.MAC.String() != want.MAC.String() {
		return "port_table"
	}
	if id, err := s.dp.LookupIfindex(want.Ifindex); err != nil || id != want.ID {
		return "ifindex_ports"
	}
	fdb, err := s.dp.FDB()
	if err != nil {
		return "fdb unreadable"
	}
	found := false
	for _, e := range fdb {
		if e.MAC.String() == want.MAC.String() && e.VLAN == want.VLAN && e.PortID == want.ID {
			found = true
			break
		}
	}
	if !found {
		return "ports (fdb)"
	}
	if !s.dp.PortLinkPinned(want.ID, want.Ifindex) {
		return "tcx link"
	}
	return ""
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
	}
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
