// SPDX-License-Identifier: Apache-2.0

//go:build tools

// Package tools pins build/test tool dependencies in go.mod:
// bpf2go generates the BPF bindings; host-local is the IPAM plugin used by
// the netns integration test.
package tools

import (
	_ "github.com/cilium/ebpf/cmd/bpf2go"
	_ "github.com/containernetworking/plugins/plugins/ipam/host-local"
)
