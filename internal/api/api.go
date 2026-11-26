// SPDX-License-Identifier: Apache-2.0

// Package api defines the JSON API the node daemon serves on its unix socket
// and a small client used by the CNI plugin and the CLI.
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// DefaultSocket is where the daemon listens by default.
const DefaultSocket = "/run/xdpl2/xdpl2.sock"

// HostIfPrefix prefixes every host-side veth created by the CNI plugin. The
// daemon uses it to detect veths that exist without a registration.
const HostIfPrefix = "xl"

// PortRequest registers a pod port.
type PortRequest struct {
	ContainerID string   `json:"containerID"`
	IfName      string   `json:"ifName"`
	Netns       string   `json:"netns,omitempty"`
	HostIfName  string   `json:"hostIfName"`
	MAC         string   `json:"mac"`
	VLAN        uint16   `json:"vlan,omitempty"`
	IPs         []string `json:"ips,omitempty"`
	// Informational, used in logs and the watchdog.
	PodNamespace string `json:"podNamespace,omitempty"`
	PodName      string `json:"podName,omitempty"`
	Network      string `json:"network,omitempty"`
}

// Key identifies a port: one per (container, interface) as in CNI.
func (r PortRequest) Key() string { return PortKey(r.ContainerID, r.IfName) }

// PortKey builds the identity used in URLs.
func PortKey(containerID, ifName string) string { return containerID + ":" + ifName }

// Validate checks the request.
func (r PortRequest) Validate() error {
	if r.ContainerID == "" || r.IfName == "" || r.HostIfName == "" {
		return fmt.Errorf("containerID, ifName and hostIfName are required")
	}
	if strings.ContainsAny(r.ContainerID+r.IfName, ":/") {
		return fmt.Errorf("containerID and ifName must not contain ':' or '/'")
	}
	mac, err := net.ParseMAC(r.MAC)
	if err != nil || len(mac) != 6 {
		return fmt.Errorf("invalid MAC %q", r.MAC)
	}
	if mac[0]&1 == 1 {
		return fmt.Errorf("MAC %s is multicast", mac)
	}
	if r.VLAN > 4094 {
		return fmt.Errorf("VLAN %d out of range (0-4094)", r.VLAN)
	}
	return nil
}

// Port is a registered port as reported by the daemon.
type Port struct {
	PortRequest
	ID          uint32    `json:"id"`
	HostIfindex int       `json:"hostIfindex"`
	Created     time.Time `json:"created"`
	// Health is "ok" or a description of what the reconciler found wrong.
	Health string `json:"health,omitempty"`
}

// Status is returned by GET /v1/status.
type Status struct {
	// Healthy is false when any problem is reported (see Problems).
	Healthy bool `json:"healthy"`
	// Ready means the data path can serve new ports: XDP attached and the
	// flood replicator running. The CNI plugin refuses ADD otherwise.
	Ready    bool              `json:"ready"`
	Problems []string          `json:"problems,omitempty"`
	Uplink   string            `json:"uplink"`
	XDPMode  string            `json:"xdpMode"`
	Ports    int               `json:"ports"`
	Counters map[string]uint64 `json:"counters"`
	// UnregisteredVeths lists host veths with our prefix but no registration.
	UnregisteredVeths []string `json:"unregisteredVeths,omitempty"`
	// UplinkPrograms is what the kernel reports as attached to the uplink.
	UplinkPrograms *UplinkPrograms `json:"uplinkPrograms,omitempty"`
	// Pins lists pinned maps and links (relative to the bpffs directory).
	Pins []string `json:"pins,omitempty"`
	// HostVLANs lists the VLANs on which the host stack is a switch port
	// (0 = the uplink itself; others are 802.1Q subinterfaces).
	HostVLANs []int `json:"hostVLANs,omitempty"`
	// NetnsNotVisible counts live ports whose netns path the daemon cannot
	// see (a deployment problem; the ports are kept).
	NetnsNotVisible int `json:"netnsNotVisible,omitempty"`
	// K8s is present when the Kubernetes-API watchdog is enabled.
	K8s *K8sStatus `json:"k8s,omitempty"`
}

// UplinkPrograms mirrors datapath.UplinkPrograms. Comma-joined copies make
// the status easy to check from shell scripts without a JSON parser.
type UplinkPrograms struct {
	XDP           string   `json:"xdp"`
	XDPMode       string   `json:"xdpMode,omitempty"`
	TCXIngress    []string `json:"tcxIngress"`
	TCXEgress     []string `json:"tcxEgress"`
	TCXIngressCSV string   `json:"tcxIngressCSV"`
	TCXEgressCSV  string   `json:"tcxEgressCSV"`
}

// K8sStatus reports the Kubernetes-API cross-check.
type K8sStatus struct {
	Node string `json:"node"`
	// Synced is true once pods and NADs have been listed.
	Synced bool `json:"synced"`
	// XDPL2NADs is the number of NetworkAttachmentDefinitions using xdpl2.
	XDPL2NADs int `json:"xdpl2NADs"`
	// PodsExpected counts live pods on the node with xdpl2 attachments;
	// PodsChecked those past the start-up grace period.
	PodsExpected int `json:"podsExpected"`
	PodsChecked  int `json:"podsChecked"`
	// MissingPorts: pods that should have an xdpl2 port but do not.
	MissingPorts []string `json:"missingPorts,omitempty"`
	// OrphanPorts: registered ports whose pod is not on this node.
	OrphanPorts []string `json:"orphanPorts,omitempty"`
}

// Error is the error body.
type Error struct {
	Error string `json:"error"`
}

// Client talks to the daemon over its unix socket.
type Client struct {
	hc *http.Client
}

// NewClient returns a client for the socket path.
func NewClient(socket string, timeout time.Duration) *Client {
	if socket == "" {
		socket = DefaultSocket
	}
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socket)
		},
	}
	return &Client{hc: &http.Client{Transport: tr, Timeout: timeout}}
}

// HTTPError is returned for non-2xx responses.
type HTTPError struct {
	Code int
	Msg  string
}

func (e *HTTPError) Error() string { return fmt.Sprintf("daemon returned %d: %s", e.Code, e.Msg) }

// IsNotFound reports whether err is a 404 from the daemon.
func IsNotFound(err error) bool {
	he, ok := err.(*HTTPError)
	return ok && he.Code == http.StatusNotFound
}

func (c *Client) do(method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, "http://xdpl2"+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode/100 != 2 {
		var e Error
		if json.Unmarshal(data, &e) != nil || e.Error == "" {
			e.Error = strings.TrimSpace(string(data))
		}
		return &HTTPError{Code: resp.StatusCode, Msg: e.Error}
	}
	if out != nil {
		return json.Unmarshal(data, out)
	}
	return nil
}

// AddPort registers (or idempotently re-registers) a port.
func (c *Client) AddPort(r PortRequest) (*Port, error) {
	var p Port
	if err := c.do(http.MethodPost, "/v1/ports", r, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

// DeletePort unregisters a port. A missing port is not an error.
func (c *Client) DeletePort(containerID, ifName string) error {
	err := c.do(http.MethodDelete, "/v1/ports/"+url.PathEscape(PortKey(containerID, ifName)), nil, nil)
	if IsNotFound(err) {
		return nil
	}
	return err
}

// GetPort fetches one port.
func (c *Client) GetPort(containerID, ifName string) (*Port, error) {
	var p Port
	if err := c.do(http.MethodGet, "/v1/ports/"+url.PathEscape(PortKey(containerID, ifName)), nil, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

// ListPorts lists all ports.
func (c *Client) ListPorts() ([]Port, error) {
	var ps []Port
	err := c.do(http.MethodGet, "/v1/ports", nil, &ps)
	return ps, err
}

// Status fetches daemon status.
func (c *Client) Status() (*Status, error) {
	var s Status
	if err := c.do(http.MethodGet, "/v1/status", nil, &s); err != nil {
		return nil, err
	}
	return &s, nil
}
