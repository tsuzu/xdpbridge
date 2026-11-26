# xdpbridge design

This document describes the phase-1 implementation: the data path, the flood
path, the maps, the control plane, and how failures are handled. Where the
implementation departs from the original design sketch, the reason is given
under [Deviations](#deviations).

## 1. Goals and non-goals

xdpbridge attaches pods to the LAN segment of a node's physical NIC (the
*uplink*). It is a small software L2 switch built from BPF programs. It
replaces macvlan for secondary pod networks, and fixes three macvlan problems:

* the host and same-node pods can reach xdpbridge pods (the host stack is a switch
  port),
* there are no per-pod child interfaces on the uplink, and no driver-specific
  hairpin behaviour,
* a pod never starts with its secondary interface silently missing (CNI ADD
  fails if the port cannot be registered, and a watchdog flags drift).

Non-goals for phase 1: replacing Multus, SR-IOV/DPUs, IGMP/MLD snooping,
libxdp multi-program chaining, and performance work beyond a sanity number.

## 2. Topology

```mermaid
flowchart LR
  LAN[(LAN / switch)] --- NIC
  subgraph node[Node: host network namespace]
    NIC["uplink NIC<br/>XDP: xdp_uplink<br/>TCX egress: tc_uplink_egress<br/>(+ Cilium TCX programs)"]
    HOST[host stack<br/>= port 0]
    D[xdpbridge-daemon<br/>flood replicator]
    V1["xb… veth<br/>TCX ingress: tc_port_ingress"]
    V2["xb… veth<br/>TCX ingress: tc_port_ingress"]
    NIC -- XDP_PASS --> HOST
    HOST -- egress --> NIC
  end
  V1 --- P1[pod A: eth1/net1]
  V2 --- P2[pod B: net1]
  RB[(flood_rb<br/>ring buffer)] --> D
  D -- AF_PACKET tx --> V1 & V2 & NIC
```

Every pod attachment is a veth pair. The pod end lives in the pod. The host
end (named `xb` + 11 hex chars of a hash of container id + interface name)
is a switch *port*. The host network stack is port 0, which is reached
through the uplink device itself.

## 3. Data path

There are three programs, all in `bpf/xdpbridge.bpf.c`.

### 3.1 `xdp_uplink`: XDP on the uplink (frames from the wire)

1. Parse Ethernet and an optional outer 802.1Q/802.1ad tag (the VLAN id).
2. **Broadcast/multicast destination**:
   * If the *source* MAC is local (any pod or host MAC, looked up in
     `local_macs` regardless of VLAN), the frame is one of ours coming back (in generic mode the program also sees frames we
     inject with `BPF_F_INGRESS`, and a LAN loop could reflect our own
     frames). It gets `XDP_PASS` and is not replicated again.
   * Otherwise the frame is copied into the `flood_rb` ring buffer (origin
     `UPLINK`, VLAN, tagged flag) and gets `XDP_PASS`, so the host stack
     receives it too.
3. **Unicast**: look up `(dst MAC, VLAN)` in `ports`.
   * If it is a pod port, strip the tag if there is one (access port) and
     `bpf_redirect()` to the port's host veth.
   * Anything else gets `XDP_PASS` and is untouched: the host MAC, unknown
     unicast, and every frame that is not for a pod. Cilium's TCX ingress
     programs on the uplink therefore see exactly the traffic they saw
     before.

Unknown unicast from the wire is **not** flooded to pods. Every local MAC is
registered explicitly (there is no learning on the pod side), so a miss can
never be for a pod.

### 3.2 `tc_port_ingress`: TCX ingress on each pod's host veth (frames sent by the pod)

This is the "port egress" program of the design sketch. Frames that leave the
pod arrive at the *ingress* hook of the host-side veth.

1. Map the ingress ifindex to a port (`ifindex_ports`, then `port_table`). If
   there is no registered port, the frame is dropped.
2. Drop tagged frames: access ports carry untagged frames only.
3. **Anti-spoofing**: the source MAC must be the port's registered MAC.
4. **Broadcast/multicast**:
   * untagged ports only: `bpf_clone_redirect(uplink, BPF_F_INGRESS)` hands
     one copy to the host stack,
   * the frame is copied into `flood_rb` (origin `PORT`, source port, VLAN),
   * `TC_ACT_SHOT`: userspace sends the remaining copies.
5. **Unicast**: look up `(dst MAC, port VLAN)` in `ports`.
   * Host port: `bpf_redirect(uplink, BPF_F_INGRESS)`. The frame enters the
     host stack as if it came from the wire.
   * Another pod: `bpf_redirect(peer veth)`. A frame addressed to the
     sender itself is dropped (no hairpin).
   * Miss: push the 802.1Q tag on VLAN access ports, then
     `bpf_redirect(uplink)` out of the NIC.

### 3.3 `tc_uplink_egress`: TCX egress on the uplink (frames sent by the host stack)

The host stack sends to pods through the uplink, so egress needs a hook
too (see [Deviations](#deviations)).

The program first determines the frame's VLAN. Frames from an 802.1Q
subinterface of the uplink carry the tag as skb metadata at this hook (it is
inserted later in software or by the NIC); frames from raw sockets may carry
it in-band. Both are handled. If the host has no interface on that VLAN
(see `host_vlans` below), the frame is not ours: `TCX_NEXT`.

* Unicast to a pod MAC on that VLAN: pop the tag (access port), then
  `bpf_redirect(pod veth)`.
* Broadcast/multicast whose source MAC is the host interface's MAC on that
  VLAN: copy into `flood_rb` (origin `HOST`, with the VLAN), then
  `TCX_NEXT`, so the frame continues to the wire.
* Everything else: `TCX_NEXT`, unchanged.

The program is attached at the **head** of the TCX egress chain and only
claims frames addressed to local pods. Requiring the host source MAC for
flood punts stops a loop: the frames the daemon transmits (pod-sourced)
also pass through this hook.

### 3.4 The host on VLAN subinterfaces

The host stack is a member of every VLAN on which it has an interface on the
uplink's segment: the uplink itself (VLAN 0, untagged) and each 802.1Q
subinterface of the uplink (`<uplink>.<vid>`, VLAN *vid*). The daemon
discovers these at start and on every reconcile pass, so subinterfaces
added or removed later are picked up within one interval. For each it
programs `host_vlans[vid] = mac` and an fdb entry `(mac, vid) → port 0`.

* pod (VLAN *v*) → host: `tc_port_ingress` pushes tag *v* as metadata and
  injects with `BPF_F_INGRESS`; the host's VLAN demux delivers it to the
  subinterface.
* pod flood on VLAN *v*: the host clone gets the tag the same way, if
  `host_vlans[v]` exists.
* host subinterface → pod: handled by `tc_uplink_egress` as above.

This was found on real hardware in phase 2: with the host IP on a VLAN
subinterface of the uplink, host ARP requests never reached VLAN ports
(phase 1 only tested an untagged host). Test cases g.5–g.12 cover it.

### 3.5 Delivery into veths and offloads

* **Native XDP redirect into a veth** only works if the receiving peer (the
  pod's interface) has NAPI enabled. The kernel enables NAPI when GRO is on,
  so the CNI plugin turns on GRO on the pod interface. Generic XDP needs
  nothing.
* **VLAN offload**: with `rx-vlan-hw-parse` on, NICs strip the 802.1Q tag
  into packet metadata before XDP runs. The daemon turns off
  `rx-vlan-hw-parse` / `rx-vlan-filter` (and the S-tag variants) on the
  uplink and logs a warning if the driver will not allow it.
* **Promiscuous mode**: the uplink must accept frames for pod MACs, so the
  daemon enables promiscuous mode.
* **Checksums**: a frame that the XDP program redirects is delivered as-is.
  Frames from a physical wire always carry complete checksums. In the netns
  test, `ext0` has TX checksum offload turned off so it behaves like a wire.

## 4. Maps

All maps are pinned under the bpffs directory (default `/sys/fs/bpf/xdpbridge`).

| Map | Type | Key → value | Purpose |
|---|---|---|---|
| `ports` | hash, 2048 | `{mac[6], vlan u16}` → `{port_id u32}` | forwarding database (one entry per port + host MAC) |
| `port_table` | array, 1024 | `port_id` → `{ifindex, vlan, kind, flags, mac[6]}` | port attributes; id 0 = host stack |
| `ifindex_ports` | hash, 1024 | host-veth `ifindex` → `port_id` | identifies the sending port in `tc_port_ingress` |
| `config_map` | array, 1 | `0` → `{uplink_ifindex, flags, host_mac}` | global settings |
| `stats` | per-CPU array | `enum xdpbridge_stat` → `u64` | counters (exported in `/v1/status`, `/metrics`) |
| `flood_rb` | ring buffer, 1 MiB | `struct flood_event` (16 B header + up to 2048 B frame) | flood hand-off to userspace |
| `host_vlans` | hash, 4096 | `vlan u32` → `{mac[6]}` | VLANs on which the host stack is a port (0 = uplink, others = 802.1Q subinterfaces) |
| `local_macs` | hash | `{mac[6]}` → `port_id` | every local MAC regardless of VLAN; XDP loop guard for flood frames (generic XDP cannot see metadata VLAN tags of injected frames) |

Links (`xdp_uplink`, `uplink_egress`, `port_<id>`) are pinned in
`<bpffs>/links/`. Pinned `bpf_link`s keep the programs attached when the
daemon exits, so **unicast forwarding continues while the daemon restarts**.
On restart the daemon reopens the pinned maps and calls `link.Update()` with
the newly loaded programs.

Struct layouts are shared through `bpf/xdpbridge.h`. Go types are generated by
`bpf2go -type …`, so both sides cannot drift.

## 5. Flood path

### 5.1 Choice: ring buffer + AF_PACKET (not AF_XDP)

The design sketch proposed AF_XDP, with AF_PACKET as an acceptable fallback. Phase 1 uses a BPF
ring buffer (`BPF_MAP_TYPE_RINGBUF`) for the hand-off and one AF_PACKET
`SOCK_RAW` socket for transmission:

* **The host must also receive flood frames.** Redirecting to an AF_XDP
  socket *consumes* the frame, so the host would lose every ARP request and
  every mDNS packet unless userspace re-injected it into the host stack,
  which AF_XDP/AF_PACKET TX cannot do. With a ring-buffer copy the program
  returns `XDP_PASS`, and the kernel delivers to the host as usual.
* **One hand-off for all hooks.** Floods originate in XDP (wire), in TCX
  ingress (pods) and in TCX egress (host). `bpf_ringbuf_*` works from all of
  them. AF_XDP is XDP-only.
* **Multi-queue NICs.** AF_XDP needs one socket and UMEM per RX queue (an
  X710 has dozens of queues). It also needs zero-copy driver support to be
  worthwhile, and it complicates generic-mode fallback. One MPSC ring buffer
  serves all CPUs and preserves ordering.
* **Volume.** ARP, ND, mDNS and SSDP come to tens of packets per second. A
  copy of at most 2 KiB per frame costs nothing at that rate. `cpumap` and
  `devmap` cannot hand frames to userspace at all.

### 5.2 Replication rules

The daemon (`internal/flood`) reads each event and builds the copy list
with `flood.Plan`, a pure function that is unit tested:

| Origin | Copies to | Not to |
|---|---|---|
| `UPLINK` (wire) | all pod ports on the event's VLAN (tag stripped) | uplink (came from there), host (got `XDP_PASS`) |
| `HOST` | all untagged pod ports | uplink and host (the frame continues to the wire) |
| `PORT` (pod *p*) | all other pod ports on *p*'s VLAN, the uplink (tag inserted for VLAN ports) | *p*, host (BPF already cloned it) |

Before replicating a locally originated frame, the daemon recomputes its
UDP checksum. TC hooks see `CHECKSUM_PARTIAL` skbs whose checksum field holds
only the pseudo-header sum, so copies sent unchanged would be dropped by
every receiver. Recomputing a checksum that is already valid gives the same
value. The integration test found this: frames that were delivered
according to `tcpdump` never reached the receiving socket.

Multicast is flooded to every port on the VLAN. Group membership is
enforced by each receiving kernel, as on a switch without IGMP snooping.
The integration test checks that a pod that has not joined 224.0.0.251 gets
nothing at socket level.

Frames larger than 2048 bytes are not replicated (counter `flood_too_big`).

## 6. Control plane

### 6.1 Node daemon (`cmd/xdpbridge-daemon`)

* Loads the BPF objects, reusing pinned maps, and attaches XDP: native first,
  then generic if native is unavailable (`--xdp-mode auto`). Before
  attaching it checks the uplink's XDP slot. If a program is attached that
  is not our pinned link, it **refuses to start** unless `--force-xdp` is
  given.
* Selects the uplink with `--uplink`: a name, a comma-separated candidate
  list where the first existing interface wins, or `default-route`. NADs do
  not name interfaces, so one NAD serves every node, even when NIC names
  differ.
* Serves a JSON API on a unix socket (`/run/xdpbridge/xdpbridge.sock`, mode 0600):

  | Method | Path | |
  |---|---|---|
  | `POST` | `/v1/ports` | register or update a port (idempotent) |
  | `GET` | `/v1/ports`, `/v1/ports/{containerID}:{ifName}` | list or get ports |
  | `DELETE` | `/v1/ports/{containerID}:{ifName}` | unregister |
  | `GET` | `/v1/status` | health, problems, counters |
  | `GET` | `/healthz`, `/livez`, `/metrics` | probes and Prometheus text format (also on `--probe-addr`, default `127.0.0.1:9967`) |

* Persists registrations to `--state-file` with an atomic rename, and
  restores them on start. A port whose veth is gone is dropped. If a veth's
  ifindex changed, the port is re-attached.
* Runs a reconciliation pass every `--reconcile-interval` (default 10 s):
  * **repair**: re-programs any port whose `port_table`, `ifindex_ports`,
    `ports` entry or pinned TCX link is missing or wrong, and logs it at
    error level (counter `reconcile_repairs`),
  * **garbage collection**: removes ports whose **host veth** has been
    missing on two consecutive passes (a pod deleted without CNI DEL;
    counter `reconcile_gc`). The veth is the liveness signal because a veth
    pair dies with its netns: when the pod's netns is destroyed, the
    kernel deletes the peer and with it the host end. Only a netlink
    "not found" counts as a miss; other lookup errors are reported, never
    acted on,
  * **netns visibility**: a live port whose recorded netns path does not
    exist in the daemon's mount namespace is **kept** and reported (one
    ERROR log per port, a `/healthz` problem,
    `xdpbridge_ports_netns_not_visible`). This means the daemon lacks the
    host's `/run/netns` mount. Paths are checked under both `/var/run/` and
    `/run/`. (Before phase 2b a missing path triggered GC; see section 8.)
  * **orphans**: deletes map entries that no registered port owns,
  * **watchdog**: a host veth with the `xb` prefix that has no registration
    on two consecutive passes is logged as `WATCHDOG: … no working xdpbridge
    interface`. It also makes `/healthz` fail and is exported as
    `xdpbridge_unregistered_veths`,
  * checks that our XDP program is still the one on the uplink and that the
    flood replicator is running,
  * re-syncs host VLAN membership (section 3.4),
  * optionally cross-checks against the Kubernetes API (section 6.3).
* Writes structured logs (JSON by default, `log/slog`).
* `/v1/status` also reports kernel-side state: the program on the uplink's
  XDP hook and its mode, the TCX ingress/egress chains in order (via
  `BPF_PROG_QUERY`), and the pinned objects. `hack/validate-node.sh` uses
  this when bpftool is not available (for example from the distroless
  daemon pod).
* `xdpbridge-daemon status|ports|teardown|install-cni|version` are subcommands
  for operators and for the DaemonSet init container.

#### Teardown

Stopping the daemon deliberately leaves the pinned links and maps in place,
so a restart or rolling update does not interrupt unicast forwarding. Removing
xdpbridge from a node is therefore an explicit step:

```sh
xdpbridge-daemon teardown [--bpffs /sys/fs/bpf/xdpbridge] [--state-file /var/lib/xdpbridge/state.json]
```

It:

1. refuses if a daemon still answers on `--socket` (a running daemon would
   re-attach and holds its own references; `--force` overrides),
2. force-detaches every pinned link (`BPF_LINK_DETACH`): the uplink XDP
   program, the uplink TCX egress program and every port's TCX program,
   then unpins it,
3. removes all map pins and the pin directory,
4. restores the uplink's promiscuous mode and the VLAN offloads that xdpbridge
   turned off, from `uplink-restore.json` (written next to the state file
   when xdpbridge first attaches to an uplink), and verifies that no XDP
   program is left on the uplink,
5. removes the port state file, so a later start begins empty.

Every action is printed; warnings make it exit non-zero. It is idempotent.
Pod veths themselves are left alone (they belong to the pods and disappear
with them). On Kubernetes: delete the DaemonSet (or unlabel the node), then
run teardown on the node, e.g. from a privileged hostNetwork debug pod
with `/sys/fs/bpf` and `/var/lib/xdpbridge` mounted.

### 6.2 CNI plugin (`cmd/xdpbridge-cni`, installed as `xdpbridge`)

* **ADD**: checks that the daemon is reachable and the data path is ready
  (XDP attached, replicator running). If not, it fails with code 11
  ("try again later") *before* creating anything. Then it creates the
  veth pair, enables GRO on the pod end, disables IPv6 on the host end, runs
  the delegated IPAM plugin (`host-local`, `static`, …) and configures the
  addresses, registers the port, and sends a gratuitous ARP. If registration
  fails, every step is rolled back (IPAM release, veth deletion) and ADD
  returns an error. A pod therefore never runs without its interface.
* **DEL**: unregisters (a down daemon is logged and tolerated; the
  reconciler collects the port later), releases IPAM, and deletes the veth.
  It is idempotent.
* **CHECK**: verifies the interface, MAC, IPs and routes, the daemon
  registration and its health.
* **STATUS** (CNI 1.1): reports daemon and data-path readiness.
* **Chaining**: if a `prevResult` is present, the plugin's interfaces and
  IPs are appended to it. MAC selection follows the `mac` capability, then
  `args.cni.mac`, `CNI_ARGS MAC=`, and finally a static `mac`. Otherwise the
  kernel's random locally administered MAC is used. VLAN (`vlan`), MTU
  (`mtu`), socket path and timeout are configurable.

### 6.3 Kubernetes-API watchdog (optional)

The node-local watchdog cannot see a pod whose CNI ADD never ran or whose
veth vanished together with its registration. With `--k8s-watch`
(`XDPBRIDGE_K8S_WATCH=true`) the daemon also asks the API server what *should*
exist:

* it lists and watches the pods on its own node
  (`fieldSelector=spec.nodeName=$XDPBRIDGE_NODE_NAME`, relisting on `410 Gone`)
  and re-lists NetworkAttachmentDefinitions every minute, treating a NAD
  as xdpbridge if its `spec.config` has `"type": "xdpbridge"` directly or in
  `plugins`;
* it parses each pod's `k8s.v1.cni.cncf.io/networks` annotation (JSON or
  the `ns/name@if` short form) and keeps the attachments that reference an
  xdpbridge NAD;
* every reconcile pass compares those with the registered ports, matched by
  the pod identity the CNI plugin records from `CNI_ARGS`
  (`K8S_POD_NAMESPACE`/`K8S_POD_NAME`) and by interface name where the
  annotation gives one.

A running pod (or one older than `--k8s-grace`, default 60 s) with an xdpbridge
attachment but no port, and a port older than the grace period whose pod is
not on the node, are each reported as a `/healthz` problem (503), an ERROR
log line `WATCHDOG(k8s): …`, and the gauges `xdpbridge_k8s_missing_ports` /
`xdpbridge_k8s_orphan_ports`. API errors and an unsynced cache are problems
too. Data-path readiness is not affected, so new CNI ADDs keep working
while the API server is unreachable.

The client is plain HTTPS with the in-cluster ServiceAccount token, re-read
on every request so bound-token rotation works; client-go is not used (it
would multiply the dependency tree for two list/watch calls).

Deployment: the base manifests keep `automountServiceAccountToken: false`
and grant no RBAC. The overlay `deploy/k8s-watch/` adds a read-only
ClusterRole (pods, NADs: get/list/watch), mounts the token at pod level and
sets `XDPBRIDGE_K8S_WATCH=true`. RBAC cannot scope a ServiceAccount to one
node's pods; the field selector is the daemon's own restriction. With the
flag off the daemon never touches the API and needs no token.

## 7. Coexistence with Cilium

* XDP: Cilium leaves the uplink XDP hook empty when
  `bpf-lb-acceleration` is disabled. xdpbridge takes the slot and refuses to
  replace someone else's program. Every frame that is not addressed to a
  pod MAC gets `XDP_PASS` and reaches Cilium's `cil_from_netdev` unchanged.
* TCX: xdpbridge adds one program at the head of the uplink's TCX egress chain.
  It only redirects host→pod frames for registered pod MACs and returns
  `TCX_NEXT` for everything else. Cilium's `cil_to_netdev` keeps seeing all
  other traffic. Pod veths created by xdpbridge are not Cilium endpoints.
* Consequences: traffic between xdpbridge pods and the LAN or host does **not**
  pass through Cilium's datapath, so Cilium network policy and host
  firewall do not apply to it. This is the same as with macvlan. Primary
  pod networking (vxlan tunnel, kube-proxy replacement) is untouched.

## 8. Failure modes

| Situation | Behaviour | Surfaced as |
|---|---|---|
| Daemon not running at pod start | CNI ADD fails (code 11), nothing created; kubelet retries | pod stays `ContainerCreating` with event text |
| Registration fails (bad request, conflict, map full) | ADD rolls back and fails | CNI error message |
| Daemon crashes or restarts | Pinned links keep unicast forwarding. Floods (ARP, mDNS) stop until it is back. State is restored on start. | `/livez` / `/healthz` probes, restart count |
| Pod deleted without CNI DEL | veth disappears and the reconciler GCs the port | `reconcile_gc` counter, warn log |
| Map entry or TCX link removed externally | Repaired on the next pass | `reconcile_repairs`, error log |
| veth exists without registration | Pod has a dead interface | `WATCHDOG` error log, `/healthz` 503, `xdpbridge_unregistered_veths` |
| Someone detaches or replaces our XDP program | Data path broken; new ADDs refused | `/healthz` 503, `ready=false` |
| Foreign XDP program present at start | Daemon refuses to start (unless `--force-xdp`) | exit with explicit message |
| Ring buffer full | Flood frame lost (unicast unaffected) | `flood_rb_full` |
| Flood frame > 2048 B | Not replicated | `flood_too_big` |
| Pod spoofs its source MAC | Frame dropped | `port_drop_spoof` |
| Pod sends 802.1Q-tagged frames | Dropped (access ports) | `port_drop_tagged` |
| Driver keeps VLAN offload on | Tagged frames for VLAN ports are not switched | warn log at start |
| Incompatible pinned maps after upgrade | Daemon fails to load with a hint | run `xdpbridge-daemon teardown`, then start |
| Host VLAN subinterface added/removed | Picked up on the next reconcile pass | `hostVLANs` in `/v1/status`, info log |
| Pod runs without its xdpbridge port (k8s watchdog on) | Reported until fixed | `WATCHDOG(k8s)` error log, `/healthz` 503, `xdpbridge_k8s_missing_ports` |
| Port whose pod is gone from the node (k8s watchdog on) | Reported (GC happens when the veth disappears) | `xdpbridge_k8s_orphan_ports`, `/healthz` 503 |
| API server unreachable (k8s watchdog on) | Cross-check paused; data path unaffected | `/healthz` 503 with the API error |
| Daemon stopped, data path must go | Nothing happens by itself (hitless restarts) | run `xdpbridge-daemon teardown` (section 6.1) |
| Daemon cannot see pod netns paths (no host `/run/netns` mount) | Ports are kept and keep forwarding | ERROR log per port, `/healthz` 503, `xdpbridge_ports_netns_not_visible` |
| Host veth lookup fails with an error other than "not found" | Port kept, nothing changed | `/healthz` problem |

**Fixed in phase 2b: live ports garbage-collected.** On the first Multus
end-to-end attempt on a real cluster, the reconciler removed a live port
1.5 s after registration (`veth_gone=false, netns_gone=true`). The pod kept
running with a dead interface, which is the silent failure xdpbridge exists to
prevent. Cause: GC fired on "host veth gone **or** netns path gone", and
the netns path was checked in the daemon's own mount namespace. The test
harness, and the shipped DaemonSet, did not mount the host's `/run/netns`,
so every live port looked netns-gone. The fix has three layers:

1. The host veth is the only GC signal, and it must be missing on two
   consecutive passes. An invisible netns path becomes a loud problem
   instead.
2. `deploy/daemonset.yaml` mounts the host `/run/netns` read-only with
   `HostToContainer` propagation. This assumes the runtime's netns
   directory is `/run/netns` or `/var/run/netns` with `/var/run → /run` (true
   on Talos and most distributions); otherwise change the hostPath.
3. Regression tests: a unit test (`TestNetnsPathInvisibleDoesNotGC`) and a
   netns test (r.8), which runs the real daemon in a mount namespace where
   `/run/netns` is hidden.

### Same-node legacy macvlan endpoints

A port cannot reach a **macvlan** endpoint on the *same* node while both
exist. The port's frames to the macvlan MAC miss the fdb (the macvlan child
is not an xdpbridge port), so they leave through the uplink, and the physical
switch does not send a frame back out of the port it arrived on (no
hairpin). The macvlan driver does not see frames transmitted by its parent
either. This is ordinary switch behaviour, not an xdpbridge bug. It resolves
itself on migration: once the workload moves to xdpbridge, both ends are local
ports and are switched in BPF. Endpoints on other nodes are unaffected.

## 9. IPv6

IPv6 Neighbour Discovery and MLD use multicast MACs (`33:33:…`), which go
through the flood path. The integration test checks link-local ping
(pod→LAN, including ND). There is no ND proxying, no MLD snooping, and no
dedicated test for IPv6 unicast beyond that. UDP checksum fix-up for
replicated IPv6 frames is implemented and unit tested only for frames
without extension headers.

## 10. Deviations

The following departures from the original design sketch were needed. Each lists
the evidence and the closest workable alternative chosen.

1. **An extra program on the uplink's TCX egress hook.** The sketch only had
   XDP on the uplink and a program per veth. The host stack transmits to
   pods *through the uplink device*, and XDP sees no egress. Without an
   egress hook, host→pod frames would leave on the wire and never reach
   the pod, which is exactly the macvlan regression this project exists to
   fix. TCX supports multiple programs, so we attach at the head and
   return `TCX_NEXT` for everything not ours. Cilium's programs are not
   modified or detached. Evidence: test cases c.2, d.5 and e.3.
2. **The host's copy of pod-originated floods comes from BPF, not
   userspace.** AF_PACKET (and AF_XDP) TX can only *transmit* on a device.
   It cannot inject a frame into the local stack. `tc_port_ingress`
   therefore does one `bpf_clone_redirect(uplink, BPF_F_INGRESS)` for the
   host, and the daemon sends all other copies. Evidence: test cases d.4,
   e.2 and e.6 (host receives pod broadcast and mDNS).
3. **Ring buffer instead of AF_XDP for the flood hand-off**, with AF_PACKET
   for transmission. The reasons are in section 5.1.
4. **"Port egress program" means the TCX *ingress* hook of the host-side
   veth.** Frames leaving the pod enter the host veth's ingress path.
5. **Unknown unicast from the wire is passed to the host, not flooded.**
   The forwarding database is authoritative because every local MAC is
   registered, so flooding would only leak LAN traffic into pods.
6. **CO-RE.** The program uses only UAPI headers and packet data. It reads
   no kernel structures, so there are no CO-RE relocations to perform.
   The object is still built the libbpf way (BTF-defined maps,
   `bpf_helpers.h`) and loads unchanged across kernels. Loader:
   **cilium/ebpf** with `bpf2go`. `bpftool` and
   libbpf skeletons are not used, and `bpftool` is only useful for inspection
   (`bpftool net show`, `bpftool map dump pinned …`).
7. **The CNI plugin turns on GRO on the pod interface.** Native XDP
   redirect into a veth requires it. Without it, frames redirected from the
   uplink are dropped.
8. **The daemon turns off VLAN RX offloads on the uplink.** XDP cannot see
   hardware-stripped tags without device-bound XDP metadata kfuncs.
9. **Kubernetes-API watchdog is opt-in.** Phase 1 shipped only the
   node-local watchdog. Phase 2 added the API cross-check (section 6.3),
   but it is off by default so that the base deployment needs no token
   and no RBAC.

## 11. Distribution on Talos

The question: can the DaemonSet's `install-cni` init container (hostPath
`/opt/cni/bin`) deliver the plugin on Talos, and will Multus (thick) find
and run it?

Findings:

* **Where Multus looks.** The thick plugin consists of a shim
  (`/opt/cni/bin/multus-shim`, invoked by the container runtime) and
  `multus-daemon`, which runs in a pod and executes the delegates. The
  upstream thick DaemonSet mounts the host's `/opt/cni/bin` (volume
  `cnibin`) and its daemon config sets `"binDir": "/opt/cni/bin"`. Its
  `install-multus-binary` init container copies the shim into
  `/host/opt/cni/bin`. The Sidero Labs Multus guide for Talos deploys this
  upstream thick DaemonSet. The only patches it calls for are the netns
  hostPath on Talos versions where `/var/run` is not a symlink to `/run`,
  and the install container's `-d /host/opt/cni/bin -t thick` arguments.
  Sources: the Sidero Labs guide (docs.siderolabs.com, "Multus CNI") and
  the upstream thick-plugin docs (k8snetworkplumbingwg.github.io,
  multus-cni "thick plugin").
* **chroot.** multus-daemon executes delegates under `chrootDir`, which
  points at the host root mounted into its pod (enabled by default in the
  upstream thick manifest; the example value is `/hostroot`). The Talos
  guide relies on this ("Multus chroots delegate plugins into the host
  root"). The xdpbridge plugin therefore sees host paths, which it needs: the
  daemon socket `/run/xdpbridge/xdpbridge.sock` (a hostPath in our DaemonSet), the
  pod netns path, and `/proc/sys`. **If chroot is disabled in a custom
  Multus config, `/run/xdpbridge` must be mounted into the multus-daemon pod
  instead**, or ADD fails with "daemon unreachable".
* **Static binary.** Under chroot the plugin runs against the host's
  filesystem, and Talos ships no general-purpose libc for it. `xdpbridge-cni`
  is built with `CGO_ENABLED=0` and has no dynamic section (verified with
  `readelf -d`), so it needs nothing from the host.
* **Is `/opt/cni/bin` writable on Talos?** Yes in practice: the
  upstream Multus thick DaemonSet (and Cilium's CNI installer) write their
  binaries there through a hostPath, and the Talos guide deploys that
  unchanged. So `install-cni` with hostPath `/opt/cni/bin` is the same
  mechanism and needs no Talos-specific change. The atomic rename avoids
  kubelet or Multus executing a half-written file.
* **IPAM plugins. Verified in phase 2b:** the Talos node's `/opt/cni/bin`
  contains `host-local` and the other standard reference plugins, so no
  extra installation is needed. xdpbridge delegates IPAM via `CNI_PATH` (Multus
  passes its `binDir`). For `host-local` on Talos, a `dataDir` under
  `/run` (e.g. `/run/cni/networks`) keeps allocations on tmpfs, so they do
  not survive a reboot as stale leases.
* **Reboot ordering.** After a reboot, kubelet may start pods before the
  xdpbridge DaemonSet has run `install-cni` and before the daemon is ready.
  The plugin may then be missing, or ADD fails with "try again later" (code
  11). Either way kubelet retries, and the pod never starts without its
  interface. Multus has a similar known race for its own binary.

Chosen approach: keep the `install-cni` init container with hostPath
`/opt/cni/bin`, installing the plugin as `/opt/cni/bin/xdpbridge`. For
distributions with a different CNI bin dir (e.g. `/var/lib/cni/bin`),
change the `cni-bin` hostPath; the in-container destination can be set
with `XDPBRIDGE_CNI_BIN_DIR` / `--dest`. No Talos system extension is needed.

**Verified on a Talos node in phase 2b** (Multus thick, Cilium primary CNI):

* `install-cni` placed the plugin at `/opt/cni/bin/xdpbridge` through the hostPath.
* With the daemon socket and state on hostPath `/run/xdpbridge`, the chrooted
  delegate reached the daemon.
* A NAD (`type: xdpbridge`, `vlan: 100`, `host-local` with `dataDir` under
  `/run/cni`) gave a real pod `net1` with a correct `network-status`
  annotation.
* Pod↔gateway, pod↔LAN host and host↔pod traffic worked.
* Deleting the pod produced a clean `port unregistered`.
* The one bug found (live-port GC with an invisible netns path) is
  described in section 8. The daemon also needs the host's `/run/netns`
  (now in `deploy/daemonset.yaml`).

## 12. Future work

* libxdp dispatcher support so that xdpbridge can share the XDP hook with other
  programs (multi-program chaining).
* Device-bound XDP with `bpf_xdp_metadata_rx_vlan_tag()`, so VLAN
  offloads can stay on.
* IGMP/MLD snooping to replace multicast flooding.
* Optional TC-only flood replication with `bpf_clone_redirect` for
  pod-originated frames, which removes userspace from that path.
* Per-port counters.
