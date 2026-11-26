// SPDX-License-Identifier: Apache-2.0

// Package bpfobj embeds the compiled xdpl2 BPF object and its generated Go
// bindings. Run `make generate` (or `go generate ./...`) after changing
// bpf/xdpl2.bpf.c; this requires clang and the libbpf headers.
package bpfobj

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux -target bpfel -type fdb_key -type fdb_val -type port -type config -type host_vlan -type mac_key -type flood_event -type xdpl2_stat -type xdpl2_origin -type xdpl2_port_kind Xdpl2 ../../bpf/xdpl2.bpf.c -- -I../../bpf -I/usr/include/$BPF_MULTIARCH -O2 -g -Wall -Werror
