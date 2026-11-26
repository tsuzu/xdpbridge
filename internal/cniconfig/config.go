// SPDX-License-Identifier: Apache-2.0

// Package cniconfig parses and validates the xdpl2 CNI network configuration.
package cniconfig

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"time"

	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/version"

	"github.com/tsuzu/xdpl2/internal/api"
)

// NetConf is the plugin configuration.
//
//	{
//	  "cniVersion": "1.0.0",
//	  "name": "lan",
//	  "type": "xdpl2",
//	  "socket": "/run/xdpl2/xdpl2.sock",   // optional
//	  "vlan": 0,                            // optional access VLAN
//	  "mtu": 1500,                          // optional
//	  "timeoutSeconds": 10,                 // optional daemon timeout
//	  "ipam": { "type": "host-local", ... } // optional
//	}
type NetConf struct {
	types.NetConf

	Socket         string `json:"socket,omitempty"`
	VLAN           int    `json:"vlan,omitempty"`
	MTU            int    `json:"mtu,omitempty"`
	TimeoutSeconds int    `json:"timeoutSeconds,omitempty"`
	// MAC sets a static MAC for the pod interface (rarely useful outside
	// tests; prefer the "mac" capability).
	MAC string `json:"mac,omitempty"`

	RuntimeConfig struct {
		MAC string `json:"mac,omitempty"`
	} `json:"runtimeConfig,omitempty"`

	// Args is the CNI "args" convention used by Multus.
	Args *struct {
		CNI *struct {
			MAC string `json:"mac,omitempty"`
		} `json:"cni,omitempty"`
	} `json:"args,omitempty"`
}

// K8sArgs are the CNI_ARGS keys set by Kubernetes runtimes.
type K8sArgs struct {
	types.CommonArgs
	MAC                        types.UnmarshallableString `json:"mac,omitempty"`
	K8S_POD_NAME               types.UnmarshallableString //nolint:revive,stylecheck // CNI_ARGS key
	K8S_POD_NAMESPACE          types.UnmarshallableString //nolint:revive,stylecheck // CNI_ARGS key
	K8S_POD_INFRA_CONTAINER_ID types.UnmarshallableString //nolint:revive,stylecheck // CNI_ARGS key
}

// Parse decodes and validates stdin config. cniArgs is CNI_ARGS.
func Parse(stdin []byte, cniArgs string) (*NetConf, *K8sArgs, error) {
	conf := &NetConf{}
	if err := json.Unmarshal(stdin, conf); err != nil {
		return nil, nil, fmt.Errorf("parsing network configuration: %w", err)
	}
	if conf.RawPrevResult != nil {
		if err := version.ParsePrevResult(&conf.NetConf); err != nil {
			return nil, nil, fmt.Errorf("parsing prevResult: %w", err)
		}
	}
	if conf.Socket == "" {
		conf.Socket = api.DefaultSocket
	}
	if conf.VLAN < 0 || conf.VLAN > 4094 {
		return nil, nil, fmt.Errorf("vlan %d out of range (0-4094)", conf.VLAN)
	}
	if conf.MTU != 0 && (conf.MTU < 68 || conf.MTU > 65535) {
		return nil, nil, fmt.Errorf("mtu %d out of range", conf.MTU)
	}
	if conf.TimeoutSeconds < 0 {
		return nil, nil, fmt.Errorf("timeoutSeconds must be >= 0")
	}
	if conf.TimeoutSeconds == 0 {
		conf.TimeoutSeconds = 10
	}

	k8s := &K8sArgs{}
	if cniArgs != "" {
		if err := types.LoadArgs(cniArgs, k8s); err != nil {
			return nil, nil, fmt.Errorf("parsing CNI_ARGS: %w", err)
		}
	}
	if m := conf.WantMAC(k8s); m != "" {
		hw, err := net.ParseMAC(m)
		if err != nil || len(hw) != 6 {
			return nil, nil, fmt.Errorf("invalid mac %q", m)
		}
		if hw[0]&1 == 1 {
			return nil, nil, fmt.Errorf("mac %q is multicast", m)
		}
	}
	return conf, k8s, nil
}

// Timeout returns the daemon request timeout.
func (c *NetConf) Timeout() time.Duration { return time.Duration(c.TimeoutSeconds) * time.Second }

// WantMAC returns the requested MAC by precedence: runtimeConfig (the "mac"
// capability), args.cni.mac, CNI_ARGS MAC, static config. Empty means "let
// the kernel pick a random locally-administered MAC".
func (c *NetConf) WantMAC(k *K8sArgs) string {
	switch {
	case c.RuntimeConfig.MAC != "":
		return c.RuntimeConfig.MAC
	case c.Args != nil && c.Args.CNI != nil && c.Args.CNI.MAC != "":
		return c.Args.CNI.MAC
	case k != nil && k.MAC != "":
		return string(k.MAC)
	}
	return c.MAC
}

// HostIfName derives a stable, unique host-side veth name (<= 15 chars)
// from the container id and interface name.
func HostIfName(containerID, ifName string) string {
	sum := sha256.Sum256([]byte(containerID + "/" + ifName))
	return api.HostIfPrefix + hex.EncodeToString(sum[:])[:11]
}
