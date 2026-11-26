// SPDX-License-Identifier: Apache-2.0

// Package k8swatch implements the optional Kubernetes-API watchdog: it
// watches the pods scheduled on this node and the NetworkAttachmentDefinitions
// that use xdpbridge, so the daemon can cross-check "pods that should have an
// xdpbridge port" against "ports that are registered".
//
// It talks to the API server with plain HTTPS and the pod's ServiceAccount
// token (no client-go), reading the token on every request so that bound
// token rotation works.
package k8swatch

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// Default in-cluster credential paths.
const (
	DefaultTokenFile = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	DefaultCAFile    = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
)

// Config configures a Watcher.
type Config struct {
	// APIServer is the base URL. Empty means in-cluster
	// (https://$KUBERNETES_SERVICE_HOST:$KUBERNETES_SERVICE_PORT).
	APIServer string
	TokenFile string
	CAFile    string
	// NodeName limits the pod watch (field selector spec.nodeName).
	NodeName string
	// PluginType is the CNI type that marks a NAD as ours ("xdpbridge").
	PluginType string
	// NADResync is how often NADs are re-listed.
	NADResync time.Duration
	// HTTPClient overrides the client (tests). It must not have a Timeout,
	// since watches are long-lived; per-request deadlines use contexts.
	HTTPClient *http.Client
	Logger     *slog.Logger
}

// Pod is the subset of a Pod object the watchdog uses.
type Pod struct {
	Metadata struct {
		Name              string            `json:"name"`
		Namespace         string            `json:"namespace"`
		UID               string            `json:"uid"`
		ResourceVersion   string            `json:"resourceVersion"`
		CreationTimestamp time.Time         `json:"creationTimestamp"`
		DeletionTimestamp *time.Time        `json:"deletionTimestamp,omitempty"`
		Annotations       map[string]string `json:"annotations,omitempty"`
	} `json:"metadata"`
	Spec struct {
		NodeName    string `json:"nodeName"`
		HostNetwork bool   `json:"hostNetwork,omitempty"`
	} `json:"spec"`
	Status struct {
		Phase     string     `json:"phase"`
		StartTime *time.Time `json:"startTime,omitempty"`
	} `json:"status"`
}

type podList struct {
	Metadata struct {
		ResourceVersion string `json:"resourceVersion"`
	} `json:"metadata"`
	Items []Pod `json:"items"`
}

type watchEvent struct {
	Type   string          `json:"type"`
	Object json.RawMessage `json:"object"`
}

type nadList struct {
	Items []struct {
		Metadata struct {
			Name      string `json:"name"`
			Namespace string `json:"namespace"`
		} `json:"metadata"`
		Spec struct {
			Config string `json:"config"`
		} `json:"spec"`
	} `json:"items"`
}

// ExpectedPod is a live pod on this node with at least one xdpbridge attachment.
type ExpectedPod struct {
	Namespace   string
	Name        string
	Phase       string
	Since       time.Time // start time, or creation time if not started
	Attachments []Attachment
}

// Key returns "namespace/name".
func (p ExpectedPod) Key() string { return p.Namespace + "/" + p.Name }

// Snapshot is a consistent view for one cross-check.
type Snapshot struct {
	// Synced is true once both pods and NADs have been listed successfully.
	Synced bool
	// Expected lists pods that should have xdpbridge ports.
	Expected []ExpectedPod
	// LivePods holds "namespace/name" of every live pod on the node.
	LivePods map[string]bool
	// Problems are watchdog-level errors (API unreachable, bad annotations).
	Problems []string
	// XDPBRIDGENADs is the number of NADs using the plugin.
	XDPBRIDGENADs int
}

// Watcher keeps a pod and NAD cache.
type Watcher struct {
	cfg    Config
	base   *url.URL
	hc     *http.Client
	log    *slog.Logger
	mu     sync.Mutex
	pods   map[string]Pod // by uid
	nads   map[string]bool
	podsOK time.Time // last successful pod list/watch activity
	nadsOK time.Time
	podErr string
	nadErr string
	synced bool
	nadSet bool
}

// InCluster reports whether in-cluster credentials are present.
func InCluster() bool {
	_, err := os.Stat(DefaultTokenFile)
	return err == nil && os.Getenv("KUBERNETES_SERVICE_HOST") != ""
}

// New validates the config and builds the HTTP client.
func New(cfg Config) (*Watcher, error) {
	if cfg.NodeName == "" {
		return nil, errors.New("k8s watchdog: node name is required (set XDPBRIDGE_NODE_NAME from spec.nodeName)")
	}
	if cfg.PluginType == "" {
		cfg.PluginType = "xdpbridge"
	}
	if cfg.NADResync == 0 {
		cfg.NADResync = time.Minute
	}
	if cfg.TokenFile == "" {
		cfg.TokenFile = DefaultTokenFile
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.APIServer == "" {
		host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT")
		if host == "" || port == "" {
			return nil, errors.New("k8s watchdog: not running in a cluster (KUBERNETES_SERVICE_HOST/PORT unset)")
		}
		cfg.APIServer = "https://" + net.JoinHostPort(host, port)
	}
	if _, err := os.Stat(cfg.TokenFile); err != nil {
		return nil, fmt.Errorf("k8s watchdog: ServiceAccount token not mounted: %w", err)
	}
	base, err := url.Parse(cfg.APIServer)
	if err != nil {
		return nil, fmt.Errorf("k8s watchdog: bad API server URL: %w", err)
	}
	hc := cfg.HTTPClient
	if hc == nil {
		if cfg.CAFile == "" {
			cfg.CAFile = DefaultCAFile
		}
		pem, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("k8s watchdog: reading CA: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("k8s watchdog: no certificates in CA file")
		}
		hc = &http.Client{Transport: &http.Transport{
			TLSClientConfig:     &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
			TLSHandshakeTimeout: 10 * time.Second,
			IdleConnTimeout:     90 * time.Second,
		}}
	}
	return &Watcher{cfg: cfg, base: base, hc: hc, log: cfg.Logger, pods: map[string]Pod{}, nads: map[string]bool{}}, nil
}

func (w *Watcher) get(ctx context.Context, path string, q url.Values) (*http.Response, error) {
	u := *w.base
	u.Path = strings.TrimSuffix(u.Path, "/") + path
	u.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	tok, err := os.ReadFile(w.cfg.TokenFile)
	if err != nil {
		return nil, fmt.Errorf("reading token: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(tok)))
	req.Header.Set("Accept", "application/json")
	resp, err := w.hc.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		return nil, &apiError{code: resp.StatusCode, msg: strings.TrimSpace(string(b))}
	}
	return resp, nil
}

type apiError struct {
	code int
	msg  string
}

func (e *apiError) Error() string { return fmt.Sprintf("API server returned %d: %s", e.code, e.msg) }

func isCode(err error, code int) bool {
	var ae *apiError
	return errors.As(err, &ae) && ae.code == code
}

func (w *Watcher) podQuery() url.Values {
	q := url.Values{}
	q.Set("fieldSelector", "spec.nodeName="+w.cfg.NodeName)
	return q
}

// listPods replaces the pod cache and returns the list resourceVersion.
func (w *Watcher) listPods(ctx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	resp, err := w.get(ctx, "/api/v1/pods", w.podQuery())
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var l podList
	if err := json.NewDecoder(resp.Body).Decode(&l); err != nil {
		return "", fmt.Errorf("decoding pod list: %w", err)
	}
	pods := make(map[string]Pod, len(l.Items))
	for _, p := range l.Items {
		pods[p.Metadata.UID] = p
	}
	w.mu.Lock()
	w.pods = pods
	w.podsOK = time.Now()
	w.podErr = ""
	w.synced = true
	w.mu.Unlock()
	return l.Metadata.ResourceVersion, nil
}

var errRelist = errors.New("watch expired, relist")

// watchPods streams changes from rv until the server closes the watch.
// It returns the last seen resourceVersion.
func (w *Watcher) watchPods(ctx context.Context, rv string) (string, error) {
	q := w.podQuery()
	q.Set("watch", "1")
	q.Set("resourceVersion", rv)
	q.Set("allowWatchBookmarks", "true")
	q.Set("timeoutSeconds", "300")
	resp, err := w.get(ctx, "/api/v1/pods", q)
	if err != nil {
		if isCode(err, http.StatusGone) {
			return rv, errRelist
		}
		return rv, err
	}
	defer resp.Body.Close()
	dec := json.NewDecoder(bufio.NewReader(resp.Body))
	for {
		var ev watchEvent
		if err := dec.Decode(&ev); err != nil {
			if errors.Is(err, io.EOF) {
				return rv, nil
			}
			return rv, err
		}
		switch ev.Type {
		case "ADDED", "MODIFIED", "DELETED", "BOOKMARK":
			var p Pod
			if err := json.Unmarshal(ev.Object, &p); err != nil {
				return rv, fmt.Errorf("decoding watch event: %w", err)
			}
			w.mu.Lock()
			switch ev.Type {
			case "ADDED", "MODIFIED":
				w.pods[p.Metadata.UID] = p
			case "DELETED":
				delete(w.pods, p.Metadata.UID)
			}
			w.podsOK = time.Now()
			w.mu.Unlock()
			if p.Metadata.ResourceVersion != "" {
				rv = p.Metadata.ResourceVersion
			}
		case "ERROR":
			// Typically 410 Gone: our resourceVersion is too old.
			return rv, errRelist
		}
	}
}

func (w *Watcher) runPods(ctx context.Context) {
	backoff := time.Second
	for ctx.Err() == nil {
		rv, err := w.listPods(ctx)
		if err != nil {
			w.setPodErr(err)
			sleep(ctx, backoff)
			backoff = min(backoff*2, 30*time.Second)
			continue
		}
		backoff = time.Second
		for ctx.Err() == nil {
			rv, err = w.watchPods(ctx, rv)
			if err != nil {
				if !errors.Is(err, errRelist) && ctx.Err() == nil {
					w.setPodErr(err)
					sleep(ctx, backoff)
				}
				break
			}
		}
	}
}

func (w *Watcher) setPodErr(err error) {
	w.log.Warn("k8s watchdog: pod list/watch failed", "err", err)
	w.mu.Lock()
	w.podErr = err.Error()
	w.mu.Unlock()
}

func (w *Watcher) listNADs(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	resp, err := w.get(ctx, "/apis/k8s.cni.cncf.io/v1/network-attachment-definitions", nil)
	if err != nil {
		if isCode(err, http.StatusNotFound) {
			return errors.New("NetworkAttachmentDefinition CRD not installed (is Multus deployed?)")
		}
		return err
	}
	defer resp.Body.Close()
	var l nadList
	if err := json.NewDecoder(resp.Body).Decode(&l); err != nil {
		return fmt.Errorf("decoding NAD list: %w", err)
	}
	nads := map[string]bool{}
	for _, n := range l.Items {
		if IsXdpbridgeConfig(n.Spec.Config, w.cfg.PluginType) {
			nads[n.Metadata.Namespace+"/"+n.Metadata.Name] = true
		}
	}
	w.mu.Lock()
	w.nads = nads
	w.nadsOK = time.Now()
	w.nadErr = ""
	w.nadSet = true
	w.mu.Unlock()
	return nil
}

func (w *Watcher) runNADs(ctx context.Context) {
	for ctx.Err() == nil {
		if err := w.listNADs(ctx); err != nil {
			w.log.Warn("k8s watchdog: NAD list failed", "err", err)
			w.mu.Lock()
			w.nadErr = err.Error()
			w.mu.Unlock()
			sleep(ctx, min(w.cfg.NADResync, 10*time.Second))
			continue
		}
		sleep(ctx, w.cfg.NADResync)
	}
}

// Run starts the watch loops; it returns when ctx is done.
func (w *Watcher) Run(ctx context.Context) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); w.runPods(ctx) }()
	go func() { defer wg.Done(); w.runNADs(ctx) }()
	wg.Wait()
}

func sleep(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}

// Snapshot returns the current view.
func (w *Watcher) Snapshot() Snapshot {
	w.mu.Lock()
	defer w.mu.Unlock()
	s := Snapshot{Synced: w.synced && w.nadSet, LivePods: map[string]bool{}, XDPBRIDGENADs: len(w.nads)}
	if w.podErr != "" {
		s.Problems = append(s.Problems, "k8s watchdog: pod list/watch failing: "+w.podErr)
	}
	if w.nadErr != "" {
		s.Problems = append(s.Problems, "k8s watchdog: NAD list failing: "+w.nadErr)
	}
	for _, p := range w.pods {
		if p.Spec.HostNetwork || p.Metadata.DeletionTimestamp != nil ||
			p.Status.Phase == "Succeeded" || p.Status.Phase == "Failed" {
			continue
		}
		key := p.Metadata.Namespace + "/" + p.Metadata.Name
		s.LivePods[key] = true
		ann := p.Metadata.Annotations[NetworksAnnotation]
		if ann == "" {
			continue
		}
		atts, err := ParseNetworks(ann, p.Metadata.Namespace)
		if err != nil {
			s.Problems = append(s.Problems, fmt.Sprintf("k8s watchdog: pod %s: %v", key, err))
			continue
		}
		var ours []Attachment
		for _, a := range atts {
			if w.nads[a.Ref()] {
				ours = append(ours, a)
			}
		}
		if len(ours) == 0 {
			continue
		}
		since := p.Metadata.CreationTimestamp
		if p.Status.StartTime != nil {
			since = *p.Status.StartTime
		}
		s.Expected = append(s.Expected, ExpectedPod{
			Namespace: p.Metadata.Namespace, Name: p.Metadata.Name,
			Phase: p.Status.Phase, Since: since, Attachments: ours,
		})
	}
	sort.Slice(s.Expected, func(i, j int) bool { return s.Expected[i].Key() < s.Expected[j].Key() })
	return s
}
