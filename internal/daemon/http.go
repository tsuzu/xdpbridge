// SPDX-License-Identifier: Apache-2.0

package daemon

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/xdpl2/xdpl2/internal/api"
)

type httpErr struct {
	code int
	err  error
}

func (e *httpErr) Error() string { return e.err.Error() }

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, err error) {
	code := http.StatusInternalServerError
	var he *httpErr
	if errors.As(err, &he) {
		code = he.code
	}
	writeJSON(w, code, api.Error{Error: err.Error()})
}

// APIHandler serves the full API (unix socket).
func (s *Server) APIHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/ports", func(w http.ResponseWriter, r *http.Request) {
		var req api.PortRequest
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&req); err != nil {
			writeErr(w, &httpErr{http.StatusBadRequest, fmt.Errorf("bad request body: %w", err)})
			return
		}
		p, err := s.AddPort(req)
		if err != nil {
			s.log.Error("port registration failed", "key", req.Key(), "err", err)
			writeErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, p)
	})
	mux.HandleFunc("GET /v1/ports", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, s.ListPorts())
	})
	mux.HandleFunc("GET /v1/ports/{key}", func(w http.ResponseWriter, r *http.Request) {
		key, _ := url.PathUnescape(r.PathValue("key"))
		p, ok := s.GetPort(key)
		if !ok {
			writeErr(w, &httpErr{http.StatusNotFound, fmt.Errorf("port %q not registered", key)})
			return
		}
		writeJSON(w, http.StatusOK, p)
	})
	mux.HandleFunc("DELETE /v1/ports/{key}", func(w http.ResponseWriter, r *http.Request) {
		key, _ := url.PathUnescape(r.PathValue("key"))
		if err := s.DeletePort(key); err != nil {
			writeErr(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("GET /v1/status", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, s.Status())
	})
	s.registerProbes(mux)
	return mux
}

// ProbeHandler serves only read-only endpoints (TCP listener for probes and
// Prometheus).
func (s *Server) ProbeHandler() http.Handler {
	mux := http.NewServeMux()
	s.registerProbes(mux)
	return mux
}

func (s *Server) registerProbes(mux *http.ServeMux) {
	mux.HandleFunc("GET /livez", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		st := s.Status()
		if !st.Healthy {
			w.WriteHeader(http.StatusServiceUnavailable)
			for _, p := range st.Problems {
				fmt.Fprintln(w, p)
			}
			return
		}
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		_, _ = w.Write([]byte(s.Metrics()))
	})
}

// Metrics renders Prometheus text exposition format.
func (s *Server) Metrics() string {
	st := s.Status()
	var b strings.Builder
	healthy := 0
	if st.Healthy {
		healthy = 1
	}
	fmt.Fprintf(&b, "# HELP xdpl2_healthy 1 if the daemon reports no problems.\n# TYPE xdpl2_healthy gauge\nxdpl2_healthy %d\n", healthy)
	fmt.Fprintf(&b, "# HELP xdpl2_ports Registered pod ports.\n# TYPE xdpl2_ports gauge\nxdpl2_ports %d\n", st.Ports)
	fmt.Fprintf(&b, "# HELP xdpl2_unregistered_veths Host veths without a registration (watchdog).\n# TYPE xdpl2_unregistered_veths gauge\nxdpl2_unregistered_veths %d\n", len(st.UnregisteredVeths))
	fmt.Fprintf(&b, "# HELP xdpl2_problems Problems reported by /healthz.\n# TYPE xdpl2_problems gauge\nxdpl2_problems %d\n", len(st.Problems))
	keys := make([]string, 0, len(st.Counters))
	for k := range st.Counters {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	fmt.Fprintf(&b, "# HELP xdpl2_events_total Data path, flood and reconciler counters.\n# TYPE xdpl2_events_total counter\n")
	for _, k := range keys {
		fmt.Fprintf(&b, "xdpl2_events_total{counter=%q} %d\n", k, st.Counters[k])
	}
	return b.String()
}
