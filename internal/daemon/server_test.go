// SPDX-License-Identifier: Apache-2.0

package daemon

import (
	"io"
	"log/slog"
	"net"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xdpl2/xdpl2/internal/api"
	"github.com/xdpl2/xdpl2/internal/datapath"
)

// fakeDP is an in-memory Dataplane.
type fakeDP struct {
	mu      sync.Mutex
	ports   map[uint32]datapath.PortSpec
	fdb     map[string]uint32 // mac/vlan -> id
	ifidx   map[int]uint32
	pinned  map[uint32]int
	failSet bool
	xdp     bool
}

func newFakeDP() *fakeDP {
	return &fakeDP{ports: map[uint32]datapath.PortSpec{}, fdb: map[string]uint32{}, ifidx: map[int]uint32{}, pinned: map[uint32]int{}, xdp: true}
}

func fk(mac net.HardwareAddr, vlan uint16) string {
	return mac.String() + "/" + strconv.Itoa(int(vlan))
}

func (f *fakeDP) SetPort(p datapath.PortSpec, old *datapath.PortSpec) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failSet {
		return io.ErrUnexpectedEOF
	}
	if old != nil {
		delete(f.fdb, fk(old.MAC, old.VLAN))
		delete(f.ifidx, old.Ifindex)
	}
	f.ports[p.ID] = p
	f.fdb[fk(p.MAC, p.VLAN)] = p.ID
	if p.Kind == datapath.KindPod {
		f.ifidx[p.Ifindex] = p.ID
		f.pinned[p.ID] = p.Ifindex
	}
	return nil
}

func (f *fakeDP) RemovePort(p datapath.PortSpec) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if id, ok := f.fdb[fk(p.MAC, p.VLAN)]; ok && id == p.ID {
		delete(f.fdb, fk(p.MAC, p.VLAN))
	}
	delete(f.ifidx, p.Ifindex)
	delete(f.ports, p.ID)
	delete(f.pinned, p.ID)
	return nil
}

func (f *fakeDP) LookupPort(id uint32) (datapath.PortSpec, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	p, ok := f.ports[id]
	if !ok {
		return datapath.PortSpec{}, io.EOF
	}
	return p, nil
}

func (f *fakeDP) LookupIfindex(i int) (uint32, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	id, ok := f.ifidx[i]
	if !ok {
		return 0, io.EOF
	}
	return id, nil
}

func (f *fakeDP) FDB() ([]datapath.FDBEntry, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []datapath.FDBEntry
	for _, p := range f.ports {
		if id, ok := f.fdb[fk(p.MAC, p.VLAN)]; ok && id == p.ID {
			out = append(out, datapath.FDBEntry{MAC: p.MAC, VLAN: p.VLAN, PortID: id})
		}
	}
	return out, nil
}

func (f *fakeDP) DeleteFDB(mac net.HardwareAddr, vlan uint16) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.fdb, fk(mac, vlan))
	return nil
}

func (f *fakeDP) IfindexEntries() (map[int]uint32, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := map[int]uint32{}
	for k, v := range f.ifidx {
		out[k] = v
	}
	return out, nil
}

func (f *fakeDP) DeleteIfindex(i int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.ifidx, i)
	return nil
}

func (f *fakeDP) PortLinkPinned(id uint32, ifindex int) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.pinned[id] == ifindex
}

func (f *fakeDP) Stats() (map[string]uint64, error) { return map[string]uint64{"xdp_rx": 42}, nil }
func (f *fakeDP) XDPAttached() bool                 { return f.xdp }
func (f *fakeDP) UplinkIndex() int                  { return 2 }
func (f *fakeDP) UplinkMAC() net.HardwareAddr {
	return net.HardwareAddr{0x02, 0, 0, 0, 0x01, 0x01}
}
func (f *fakeDP) Mode() datapath.XDPMode { return datapath.XDPModeNative }

type fakeLinks struct {
	mu    sync.Mutex
	links map[string]int
}

func (l *fakeLinks) IndexByName(n string) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if i, ok := l.links[n]; ok {
		return i, nil
	}
	return 0, ErrLinkNotFound
}

func (l *fakeLinks) NamesWithPrefix(p string) ([]string, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []string
	for n := range l.links {
		if strings.HasPrefix(n, p) {
			out = append(out, n)
		}
	}
	return out, nil
}

func (l *fakeLinks) set(n string, i int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if i == 0 {
		delete(l.links, n)
	} else {
		l.links[n] = i
	}
}

type harness struct {
	t      *testing.T
	dp     *fakeDP
	links  *fakeLinks
	srv    *Server
	client *api.Client
	state  string
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	dir := t.TempDir()
	h := &harness{t: t, dp: newFakeDP(), links: &fakeLinks{links: map[string]int{"xlaaa": 10, "xlbbb": 11, "xlccc": 12}}, state: filepath.Join(dir, "state.json")}
	h.start(dir)
	return h
}

func (h *harness) start(dir string) {
	h.srv = New(Config{Uplink: "uplink0", StateFile: h.state, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		PathExists: func(string) bool { return true }}, h.dp, h.links)
	if err := h.srv.Restore(); err != nil {
		h.t.Fatal(err)
	}
	sock := filepath.Join(dir, "api-"+time.Now().Format("150405.000000")+".sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		h.t.Fatal(err)
	}
	hs := &http.Server{Handler: h.srv.APIHandler()}
	go func() { _ = hs.Serve(ln) }()
	h.t.Cleanup(func() { hs.Close() })
	h.client = api.NewClient(sock, 2*time.Second)
}

func req(cid, hostIf, mac string, vlan uint16) api.PortRequest {
	return api.PortRequest{ContainerID: cid, IfName: "eth1", HostIfName: hostIf, MAC: mac, VLAN: vlan, Netns: "/run/netns/" + cid}
}

func TestAddGetListDelete(t *testing.T) {
	h := newHarness(t)
	p, err := h.client.AddPort(req("c1", "xlaaa", "02:00:00:00:00:0a", 0))
	if err != nil {
		t.Fatal(err)
	}
	if p.ID != 1 || p.HostIfindex != 10 || p.Health != "ok" {
		t.Errorf("unexpected port %+v", p)
	}
	if id, _ := h.dp.LookupIfindex(10); id != 1 {
		t.Error("data path not programmed")
	}
	p2, err := h.client.AddPort(req("c2", "xlbbb", "02:00:00:00:00:0b", 0))
	if err != nil || p2.ID != 2 {
		t.Fatalf("second port: %+v %v", p2, err)
	}
	got, err := h.client.GetPort("c1", "eth1")
	if err != nil || got.MAC != "02:00:00:00:00:0a" {
		t.Fatalf("get: %+v %v", got, err)
	}
	list, err := h.client.ListPorts()
	if err != nil || len(list) != 2 || list[0].ID != 1 {
		t.Fatalf("list: %+v %v", list, err)
	}
	if fp := h.srv.FloodPorts(); len(fp) != 2 || fp[1].Ifindex != 11 {
		t.Errorf("flood ports: %+v", fp)
	}
	if err := h.client.DeletePort("c1", "eth1"); err != nil {
		t.Fatal(err)
	}
	if _, err := h.client.GetPort("c1", "eth1"); !api.IsNotFound(err) {
		t.Errorf("expected 404, got %v", err)
	}
	if err := h.client.DeletePort("c1", "eth1"); err != nil {
		t.Errorf("deleting a missing port must succeed (idempotent DEL): %v", err)
	}
	// Freed ids are reused.
	p3, err := h.client.AddPort(req("c3", "xlaaa", "02:00:00:00:00:0c", 0))
	if err != nil || p3.ID != 1 {
		t.Fatalf("id reuse: %+v %v", p3, err)
	}
}

func TestAddIdempotentAndUpdate(t *testing.T) {
	h := newHarness(t)
	a, err := h.client.AddPort(req("c1", "xlaaa", "02:00:00:00:00:0a", 0))
	if err != nil {
		t.Fatal(err)
	}
	b, err := h.client.AddPort(req("c1", "xlaaa", "02:00:00:00:00:0a", 0))
	if err != nil || b.ID != a.ID {
		t.Fatalf("repeat ADD: %+v %v", b, err)
	}
	// Same key, new MAC: old fdb entry must go.
	if _, err := h.client.AddPort(req("c1", "xlaaa", "02:00:00:00:00:0f", 0)); err != nil {
		t.Fatal(err)
	}
	fdb, _ := h.dp.FDB()
	if len(fdb) != 1 || fdb[0].MAC.String() != "02:00:00:00:00:0f" {
		t.Errorf("fdb after update: %+v", fdb)
	}
}

func TestAddValidationAndConflicts(t *testing.T) {
	h := newHarness(t)
	if _, err := h.client.AddPort(req("c1", "xlaaa", "02:00:00:00:00:0a", 0)); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		r    api.PortRequest
		code int
	}{
		{"bad mac", req("c2", "xlbbb", "nope", 0), 400},
		{"multicast mac", req("c2", "xlbbb", "01:00:5e:00:00:01", 0), 400},
		{"missing veth", req("c2", "xlzzz", "02:00:00:00:00:0b", 0), 400},
		{"wrong prefix", req("c2", "eth0", "02:00:00:00:00:0b", 0), 400},
		{"vlan range", req("c2", "xlbbb", "02:00:00:00:00:0b", 4095), 400},
		{"dup mac", req("c2", "xlbbb", "02:00:00:00:00:0a", 0), 409},
		{"dup veth", req("c2", "xlaaa", "02:00:00:00:00:0b", 0), 409},
		{"host mac", req("c2", "xlbbb", "02:00:00:00:01:01", 0), 409},
	}
	for _, c := range cases {
		_, err := h.client.AddPort(c.r)
		he, ok := err.(*api.HTTPError)
		if !ok || he.Code != c.code {
			t.Errorf("%s: got %v, want HTTP %d", c.name, err, c.code)
		}
	}
	// Same MAC on a different VLAN is a different station.
	if _, err := h.client.AddPort(req("c3", "xlbbb", "02:00:00:00:00:0a", 100)); err != nil {
		t.Errorf("same MAC on other VLAN: %v", err)
	}
}

func TestAddFailsWhenDataPathFails(t *testing.T) {
	h := newHarness(t)
	h.dp.failSet = true
	if _, err := h.client.AddPort(req("c1", "xlaaa", "02:00:00:00:00:0a", 0)); err == nil {
		t.Fatal("ADD must fail when the data path cannot be programmed")
	}
	if len(h.srv.ListPorts()) != 0 {
		t.Error("failed ADD left a registration")
	}
}

func TestPersistenceAndRestore(t *testing.T) {
	h := newHarness(t)
	for i, n := range []string{"xlaaa", "xlbbb", "xlccc"} {
		if _, err := h.client.AddPort(req("c"+n, n, "02:00:00:00:00:0"+string(rune('1'+i)), 0)); err != nil {
			t.Fatal(err)
		}
	}
	// Restart with a fresh data path: one veth vanished, one was recreated.
	h.dp = newFakeDP()
	h.links.set("xlbbb", 0)
	h.links.set("xlccc", 99)
	h.start(t.TempDir())
	ports := h.srv.ListPorts()
	if len(ports) != 2 {
		t.Fatalf("restored %d ports, want 2: %+v", len(ports), ports)
	}
	if ports[1].HostIfindex != 99 {
		t.Errorf("ifindex not refreshed: %+v", ports[1])
	}
	if id, err := h.dp.LookupIfindex(99); err != nil || id != ports[1].ID {
		t.Error("restored port not programmed")
	}
}

func TestReconcileRepairsAndGC(t *testing.T) {
	h := newHarness(t)
	if _, err := h.client.AddPort(req("c1", "xlaaa", "02:00:00:00:00:0a", 0)); err != nil {
		t.Fatal(err)
	}
	if _, err := h.client.AddPort(req("c2", "xlbbb", "02:00:00:00:00:0b", 0)); err != nil {
		t.Fatal(err)
	}
	// Drift: someone deleted a map entry and the TCX link.
	_ = h.dp.DeleteFDB(net.HardwareAddr{2, 0, 0, 0, 0, 0x0a}, 0)
	h.dp.mu.Lock()
	delete(h.dp.pinned, 1)
	h.dp.mu.Unlock()
	// Orphan: an fdb entry nobody owns.
	_ = h.dp.SetPort(datapath.PortSpec{ID: 77, Ifindex: 77, MAC: net.HardwareAddr{2, 0, 0, 0, 0, 0x77}, Kind: datapath.KindPod}, nil)
	// GC: c2's veth disappears.
	h.links.set("xlbbb", 0)

	h.srv.Reconcile()

	if n := h.srv.repairs.Load(); n == 0 {
		t.Error("drift not repaired")
	}
	if !h.dp.PortLinkPinned(1, 10) {
		t.Error("tcx link not re-attached")
	}
	if _, ok := h.srv.GetPort(api.PortKey("c2", "eth1")); ok {
		t.Error("vanished port not garbage-collected")
	}
	if _, err := h.dp.LookupIfindex(77); err == nil {
		t.Error("orphan ifindex entry not removed")
	}
	fdb, _ := h.dp.FDB()
	for _, e := range fdb {
		if e.PortID == 77 {
			t.Error("orphan fdb entry not removed")
		}
	}
}

func TestWatchdogAndHealth(t *testing.T) {
	h := newHarness(t)
	if _, err := h.client.AddPort(req("c1", "xlaaa", "02:00:00:00:00:0a", 0)); err != nil {
		t.Fatal(err)
	}
	h.srv.Reconcile() // xlbbb, xlccc seen once: not yet reported
	if st := h.srv.Status(); !st.Healthy {
		t.Fatalf("first sighting must not be reported: %+v", st.Problems)
	}
	h.srv.Reconcile()
	st, err := h.client.Status()
	if err != nil {
		t.Fatal(err)
	}
	if st.Healthy || len(st.UnregisteredVeths) != 2 || !st.Ready {
		t.Errorf("watchdog status: %+v", st)
	}
	if !strings.Contains(h.srv.Metrics(), "xdpl2_unregistered_veths 2") {
		t.Error("metric missing")
	}
	h.dp.xdp = false
	if st := h.srv.Status(); st.Ready {
		t.Error("must not be ready without XDP")
	}
}
