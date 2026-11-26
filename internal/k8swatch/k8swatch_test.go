// SPDX-License-Identifier: Apache-2.0

package k8swatch

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestParseNetworks(t *testing.T) {
	tests := []struct {
		in   string
		want []Attachment
	}{
		{"", nil},
		{"lan", []Attachment{{Namespace: "app", Name: "lan"}}},
		{"infra/lan@net5, other", []Attachment{{Namespace: "infra", Name: "lan", Interface: "net5"}, {Namespace: "app", Name: "other"}}},
		{`[{"name":"lan","interface":"net1"},{"name":"x","namespace":"infra"}]`,
			[]Attachment{{Namespace: "app", Name: "lan", Interface: "net1"}, {Namespace: "infra", Name: "x"}}},
	}
	for _, tt := range tests {
		got, err := ParseNetworks(tt.in, "app")
		if err != nil {
			t.Fatalf("%q: %v", tt.in, err)
		}
		if fmt.Sprint(got) != fmt.Sprint(tt.want) {
			t.Errorf("%q: got %+v, want %+v", tt.in, got, tt.want)
		}
	}
	for _, bad := range []string{`[{"interface":"net1"}]`, `[{`} {
		if _, err := ParseNetworks(bad, "app"); err == nil {
			t.Errorf("%q: expected error", bad)
		}
	}
}

func TestIsXdpbridgeConfig(t *testing.T) {
	cases := map[string]bool{
		`{"cniVersion":"1.0.0","name":"a","type":"xdpbridge"}`:                                 true,
		`{"cniVersion":"1.0.0","name":"a","plugins":[{"type":"xdpbridge"},{"type":"tuning"}]}`: true,
		`{"cniVersion":"1.0.0","name":"a","type":"macvlan"}`:                                   false,
		`not json`: false,
	}
	for in, want := range cases {
		if got := IsXdpbridgeConfig(in, "xdpbridge"); got != want {
			t.Errorf("%s: got %v", in, got)
		}
	}
}

var t0 = time.Date(2030, 1, 1, 12, 0, 0, 0, time.UTC)

func TestCrossCheck(t *testing.T) {
	snap := Snapshot{
		Synced:   true,
		LivePods: map[string]bool{"app/ok": true, "app/missing": true, "app/named": true, "app/young": true, "app/two": true},
		Expected: []ExpectedPod{
			{Namespace: "app", Name: "ok", Phase: "Running", Since: t0, Attachments: []Attachment{{Namespace: "app", Name: "lan"}}},
			{Namespace: "app", Name: "missing", Phase: "Running", Since: t0, Attachments: []Attachment{{Namespace: "app", Name: "lan"}}},
			{Namespace: "app", Name: "named", Phase: "Running", Since: t0, Attachments: []Attachment{{Namespace: "app", Name: "lan", Interface: "net2"}}},
			// Pending and young: inside its CNI ADD, not checked yet.
			{Namespace: "app", Name: "young", Phase: "Pending", Since: t0.Add(-10 * time.Second), Attachments: []Attachment{{Namespace: "app", Name: "lan"}}},
			{Namespace: "app", Name: "two", Phase: "Running", Since: t0, Attachments: []Attachment{{Namespace: "app", Name: "lan"}, {Namespace: "app", Name: "lan2"}}},
		},
	}
	old := t0.Add(-time.Hour)
	ports := []PortRef{
		{Key: "c1:net1", PodNamespace: "app", PodName: "ok", IfName: "net1", Created: old},
		{Key: "c2:net1", PodNamespace: "app", PodName: "named", IfName: "net1", Created: old}, // wrong interface
		{Key: "c3:net1", PodNamespace: "app", PodName: "two", IfName: "net1", Created: old},   // one of two
		{Key: "c4:net1", PodNamespace: "app", PodName: "gone", IfName: "net1", Created: old},  // orphan
		{Key: "c5:net1", PodNamespace: "app", PodName: "new", IfName: "net1", Created: t0},    // too new to judge
		{Key: "c6:eth1", IfName: "eth1", Created: old},                                        // not a k8s port
	}
	r := CrossCheck(snap, ports, t0, time.Minute)
	if r.Checked != 4 {
		t.Errorf("checked %d pods, want 4", r.Checked)
	}
	want := []string{
		"pod app/missing (Running) has no xdpbridge port for network app/lan",
		"pod app/named (Running) has no xdpbridge port for network app/lan interface net2",
		"pod app/two (Running) has no xdpbridge port for network app/lan2",
	}
	if fmt.Sprint(r.MissingPorts) != fmt.Sprint(want) {
		t.Errorf("missing:\n got %q\nwant %q", r.MissingPorts, want)
	}
	if len(r.OrphanPorts) != 1 || !strings.Contains(r.OrphanPorts[0], "c4:net1") {
		t.Errorf("orphans: %q", r.OrphanPorts)
	}

	// Not synced: never report orphans (the cache may simply be empty).
	snap.Synced = false
	if r := CrossCheck(snap, ports, t0, time.Minute); len(r.OrphanPorts) != 0 {
		t.Errorf("orphans reported while unsynced: %q", r.OrphanPorts)
	}
}

// fakeAPI is a minimal API server: pod list + watch for one node, NAD list.
type fakeAPI struct {
	t      *testing.T
	mu     sync.Mutex
	pods   []Pod
	rv     int
	events chan string // raw JSON watch events
	gone   bool        // answer the next watch with an ERROR 410 event
	lists  int
	token  string
	nads   string
}

func pod(ns, name, phase, networks string) Pod {
	var p Pod
	p.Metadata.Namespace, p.Metadata.Name, p.Metadata.UID = ns, name, ns+"-"+name
	p.Metadata.CreationTimestamp = t0
	p.Spec.NodeName = "node-a"
	p.Status.Phase = phase
	if networks != "" {
		p.Metadata.Annotations = map[string]string{NetworksAnnotation: networks}
	}
	return p
}

func (f *fakeAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer "+f.token {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	switch r.URL.Path {
	case "/apis/k8s.cni.cncf.io/v1/network-attachment-definitions":
		fmt.Fprint(w, f.nads)
	case "/api/v1/pods":
		if fs := r.URL.Query().Get("fieldSelector"); fs != "spec.nodeName=node-a" {
			f.t.Errorf("bad field selector %q", fs)
		}
		if r.URL.Query().Get("watch") == "" {
			f.mu.Lock()
			f.lists++
			b, _ := json.Marshal(map[string]any{"metadata": map[string]string{"resourceVersion": fmt.Sprint(f.rv)}, "items": f.pods})
			f.mu.Unlock()
			w.Write(b)
			return
		}
		f.mu.Lock()
		gone := f.gone
		f.gone = false
		f.mu.Unlock()
		w.(http.Flusher).Flush()
		if gone {
			fmt.Fprint(w, `{"type":"ERROR","object":{"kind":"Status","code":410}}`)
			return
		}
		for {
			select {
			case ev := <-f.events:
				fmt.Fprintln(w, ev)
				w.(http.Flusher).Flush()
			case <-r.Context().Done():
				return
			}
		}
	default:
		http.NotFound(w, r)
	}
}

func event(typ string, p Pod) string {
	b, _ := json.Marshal(map[string]any{"type": typ, "object": p})
	return string(b)
}

func eventually(t *testing.T, cond func() bool, what string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestWatcherListWatch(t *testing.T) {
	api := &fakeAPI{t: t, token: "tok-1", events: make(chan string, 10), rv: 5,
		nads: `{"items":[
		  {"metadata":{"namespace":"app","name":"lan"},"spec":{"config":"{\"cniVersion\":\"1.0.0\",\"name\":\"lan\",\"type\":\"xdpbridge\"}"}},
		  {"metadata":{"namespace":"app","name":"mv"},"spec":{"config":"{\"cniVersion\":\"1.0.0\",\"name\":\"mv\",\"type\":\"macvlan\"}"}}]}`,
		pods: []Pod{pod("app", "a", "Running", "lan"), pod("app", "b", "Running", "mv"), pod("app", "c", "Running", "")},
	}
	srv := httptest.NewServer(api)
	defer srv.Close()

	tokFile := filepath.Join(t.TempDir(), "token")
	os.WriteFile(tokFile, []byte("tok-1\n"), 0o600)
	w, err := New(Config{APIServer: srv.URL, TokenFile: tokFile, NodeName: "node-a", HTTPClient: srv.Client(),
		NADResync: 50 * time.Millisecond, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.Run(ctx)

	eventually(t, func() bool { return w.Snapshot().Synced }, "sync")
	s := w.Snapshot()
	if len(s.Expected) != 1 || s.Expected[0].Name != "a" || s.XDPBRIDGENADs != 1 || len(s.LivePods) != 3 {
		t.Fatalf("snapshot after list: %+v", s)
	}

	// Watch: a new xdpbridge pod arrives, "a" is deleted.
	api.events <- event("ADDED", pod("app", "d", "Pending", `[{"name":"lan","interface":"net1"}]`))
	api.events <- event("DELETED", pod("app", "a", "Running", "lan"))
	eventually(t, func() bool {
		s := w.Snapshot()
		return len(s.Expected) == 1 && s.Expected[0].Name == "d"
	}, "watch events")

	// Token rotation: the next request must use the new token.
	os.WriteFile(tokFile, []byte("tok-2"), 0o600)
	api.mu.Lock()
	api.token = "tok-2"
	api.gone = true
	api.pods = []Pod{pod("app", "e", "Running", "app/lan")}
	api.mu.Unlock()
	// End the current watch so the watcher reconnects (and hits 410).
	srv.CloseClientConnections()
	eventually(t, func() bool {
		s := w.Snapshot()
		return len(s.Expected) == 1 && s.Expected[0].Name == "e" && len(s.Problems) == 0
	}, "relist after 410 with rotated token")
}

func TestWatcherReportsAPIErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "forbidden", http.StatusForbidden)
	}))
	defer srv.Close()
	tokFile := filepath.Join(t.TempDir(), "token")
	os.WriteFile(tokFile, []byte("x"), 0o600)
	w, err := New(Config{APIServer: srv.URL, TokenFile: tokFile, NodeName: "node-a", HTTPClient: srv.Client(),
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.Run(ctx)
	eventually(t, func() bool { return len(w.Snapshot().Problems) == 2 }, "API errors surfaced")
	if w.Snapshot().Synced {
		t.Error("must not be synced")
	}
}

func TestNewRequiresTokenAndNode(t *testing.T) {
	if _, err := New(Config{APIServer: "https://192.0.2.1:6443", TokenFile: "/nonexistent", NodeName: "n"}); err == nil {
		t.Error("expected error without a token")
	}
	if _, err := New(Config{APIServer: "https://192.0.2.1:6443"}); err == nil {
		t.Error("expected error without node name")
	}
}
