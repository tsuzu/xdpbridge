// SPDX-License-Identifier: Apache-2.0

package k8swatch

import (
	"encoding/json"
	"fmt"
	"strings"
)

// NetworksAnnotation is the Multus network-selection annotation.
const NetworksAnnotation = "k8s.v1.cni.cncf.io/networks"

// Attachment is one entry of a pod's network-selection annotation.
type Attachment struct {
	Namespace string `json:"namespace,omitempty"`
	Name      string `json:"name"`
	Interface string `json:"interface,omitempty"`
}

// Ref returns "namespace/name".
func (a Attachment) Ref() string { return a.Namespace + "/" + a.Name }

// ParseNetworks parses the Multus annotation in either of its two formats:
// a JSON list of selection elements, or the comma-separated short form
// "[namespace/]name[@interface], ...". Missing namespaces default to podNS.
func ParseNetworks(value, podNS string) ([]Attachment, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, nil
	}
	var out []Attachment
	if strings.HasPrefix(value, "[") {
		if err := json.Unmarshal([]byte(value), &out); err != nil {
			return nil, fmt.Errorf("parsing %s JSON: %w", NetworksAnnotation, err)
		}
	} else {
		for _, item := range strings.Split(value, ",") {
			item = strings.TrimSpace(item)
			if item == "" {
				continue
			}
			var a Attachment
			if i := strings.LastIndex(item, "@"); i >= 0 {
				a.Interface = item[i+1:]
				item = item[:i]
			}
			if i := strings.Index(item, "/"); i >= 0 {
				a.Namespace, a.Name = item[:i], item[i+1:]
			} else {
				a.Name = item
			}
			out = append(out, a)
		}
	}
	for i := range out {
		if out[i].Name == "" {
			return nil, fmt.Errorf("%s: element %d has no name", NetworksAnnotation, i)
		}
		if out[i].Namespace == "" {
			out[i].Namespace = podNS
		}
	}
	return out, nil
}

// IsXdpbridgeConfig reports whether a NAD spec.config uses the xdpbridge plugin,
// either as a single plugin config or inside a "plugins" list.
func IsXdpbridgeConfig(config string, pluginType string) bool {
	var c struct {
		Type    string `json:"type"`
		Plugins []struct {
			Type string `json:"type"`
		} `json:"plugins"`
	}
	if json.Unmarshal([]byte(config), &c) != nil {
		return false
	}
	if c.Type == pluginType {
		return true
	}
	for _, p := range c.Plugins {
		if p.Type == pluginType {
			return true
		}
	}
	return false
}
