// SPDX-License-Identifier: Apache-2.0

package k8swatch

import (
	"fmt"
	"sort"
	"time"
)

// PortRef is what the cross-check needs to know about a registered port.
type PortRef struct {
	Key          string // containerID:ifName
	PodNamespace string
	PodName      string
	IfName       string
	Created      time.Time
}

// Result of a cross-check.
type Result struct {
	// MissingPorts describes xdpl2 attachments of live pods that have no
	// registered port: the pod runs without its interface.
	MissingPorts []string
	// OrphanPorts describes registered ports whose pod is not on this node.
	OrphanPorts []string
	// Checked is the number of pods with xdpl2 attachments examined.
	Checked int
}

// CrossCheck compares expected attachments against registered ports.
//
// A pod is only checked once it is Running or has existed for longer than
// grace (a Pending pod inside its CNI ADD has no port yet). A port is only
// reported as orphaned when it is older than grace (its pod may not be
// visible in the cache yet) and it carries pod identity (ports registered
// outside Kubernetes are ignored).
func CrossCheck(s Snapshot, ports []PortRef, now time.Time, grace time.Duration) Result {
	var r Result
	byPod := map[string][]PortRef{}
	for _, p := range ports {
		if p.PodName == "" {
			continue
		}
		k := p.PodNamespace + "/" + p.PodName
		byPod[k] = append(byPod[k], p)
	}

	for _, pod := range s.Expected {
		if pod.Phase != "Running" && now.Sub(pod.Since) < grace {
			continue
		}
		r.Checked++
		avail := map[string]bool{}
		for _, p := range byPod[pod.Key()] {
			avail[p.IfName] = true
		}
		var unnamed []Attachment
		for _, a := range pod.Attachments {
			if a.Interface == "" {
				unnamed = append(unnamed, a)
				continue
			}
			if avail[a.Interface] {
				delete(avail, a.Interface)
				continue
			}
			r.MissingPorts = append(r.MissingPorts, fmt.Sprintf(
				"pod %s (%s) has no xdpl2 port for network %s interface %s", pod.Key(), pod.Phase, a.Ref(), a.Interface))
		}
		// Interfaces without an explicit name: match by count.
		for i, a := range unnamed {
			if i < len(avail) {
				continue
			}
			r.MissingPorts = append(r.MissingPorts, fmt.Sprintf(
				"pod %s (%s) has no xdpl2 port for network %s", pod.Key(), pod.Phase, a.Ref()))
		}
	}

	if s.Synced {
		for k, ps := range byPod {
			if s.LivePods[k] {
				continue
			}
			for _, p := range ps {
				if now.Sub(p.Created) < grace {
					continue
				}
				r.OrphanPorts = append(r.OrphanPorts, fmt.Sprintf(
					"port %s belongs to pod %s, which is not running on this node", p.Key, k))
			}
		}
	}
	sort.Strings(r.MissingPorts)
	sort.Strings(r.OrphanPorts)
	return r
}
