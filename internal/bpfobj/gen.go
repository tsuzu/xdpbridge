// SPDX-License-Identifier: Apache-2.0

// Package bpfobj embeds the compiled xdpbridge BPF object and its generated Go
// bindings. Run `make generate` (or `go generate ./...`) after changing
// bpf/xdpbridge.bpf.c; this requires clang and the libbpf headers.
package bpfobj

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux -target bpfel -type fdb_key -type fdb_val -type port -type config -type host_vlan -type mac_key -type flood_event -type xdpbridge_stat -type xdpbridge_origin -type xdpbridge_port_kind Xdpbridge ../../bpf/xdpbridge.bpf.c -- -I../../bpf -I/usr/include/$BPF_MULTIARCH -O2 -g -Wall -Werror
