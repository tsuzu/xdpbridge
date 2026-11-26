#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# xdpl2 netns integration test.
#
# Builds a self-contained topology out of network namespaces and veth pairs,
# runs the real daemon and CNI plugin against it and verifies forwarding with
# ping, iperf3, UDP broadcast/multicast and packet capture.
#
#   ext  (192.0.2.100, VLAN 100: 198.51.100.100)   "the LAN"
#    | ext0 <-> uplink0   (uplink0 stands in for the physical NIC)
#   node (192.0.2.1)  xdpl2-daemon, CNI plugin invoked here
#    | xl<hash> <-> eth1   (created by xdpl2-cni)
#   pod1, pod2, pod3 (untagged, 192.0.2.10-19), pod4 (VLAN 100)
#
# Usage: sudo test/netns_test.sh [--mode native|generic|both] [--keep] [--testlog FILE]
#   --testlog FILE  also write FILE = test/TESTLOG.header.md + this run's output
# Requires: root, iproute2, tcpdump, iperf3, python3, built binaries in bin/.
set -uo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
BIN=${BIN:-$ROOT/bin}
MODES=both
KEEP=0
TESTLOG=
while [ $# -gt 0 ]; do
	case $1 in
	--mode) MODES=$2; shift 2 ;;
	--keep) KEEP=1; shift ;;
	--testlog) TESTLOG=$2; shift 2 ;;
	*) echo "unknown arg $1" >&2; exit 2 ;;
	esac
done
[ "$MODES" = both ] && MODES="native generic"

[ "$(id -u)" = 0 ] || { echo "must run as root" >&2; exit 2; }
for b in xdpl2-daemon xdpl2-cni host-local; do
	[ -x "$BIN/$b" ] || { echo "missing $BIN/$b (run: make build)" >&2; exit 2; }
done
for t in ip tcpdump iperf3 python3 nsenter; do
	command -v $t >/dev/null || { echo "missing tool: $t" >&2; exit 2; }
done

P=xlt-                       # namespace prefix
# A working bpftool (the distro wrapper refuses to run on foreign kernels).
BPFTOOL=
for b in ${BPFTOOL_BIN:-} bpftool /usr/lib/linux-tools/*/bpftool /usr/sbin/bpftool; do
	if [ -x "$(command -v "$b" 2>/dev/null)" ] && "$b" version >/dev/null 2>&1; then BPFTOOL=$(command -v "$b"); break; fi
done
UDP="python3 $ROOT/test/udp.py"
PASS=0 FAIL=0
RESULTS=()
NOTES=()

log() { echo "[$(date +%H:%M:%S)] $*"; }

# check <id> <description> <command...>: run, record PASS/FAIL.
check() {
	local id=$1 desc=$2; shift 2
	if "$@" >"$WORK/check.out" 2>&1; then
		PASS=$((PASS + 1)); RESULTS+=("PASS  [$MODE] $id  $desc")
		log "PASS $id $desc"
	else
		FAIL=$((FAIL + 1)); RESULTS+=("FAIL  [$MODE] $id  $desc")
		log "FAIL $id $desc"
		sed 's/^/    | /' "$WORK/check.out" | tail -25
	fi
}

ns() { ip netns exec "$P$1" "${@:2}"; }
node() { nsenter --net="/run/netns/${P}node" "$@"; }

cleanup() {
	[ -n "${DPID:-}" ] && kill "$DPID" 2>/dev/null && wait "$DPID" 2>/dev/null
	DPID=
	local n
	for n in $(ip netns list | awk '{print $1}' | grep "^$P"); do
		ip netns pids "$n" 2>/dev/null | xargs -r kill 2>/dev/null
		ip netns del "$n"
	done
	if [ -n "${WORK:-}" ]; then
		umount "$WORK/bpffs" 2>/dev/null
		[ "$KEEP" = 1 ] && log "kept $WORK" || rm -rf "$WORK"
	fi
}
trap cleanup EXIT

stat_of() { # stat_of <counter>
	node "$BIN/xdpl2-daemon" status --socket "$SOCK" |
		python3 -c "import json,sys; print(json.load(sys.stdin)['counters'].get('$1',0))"
}
status_field() {
	node "$BIN/xdpl2-daemon" status --socket "$SOCK" |
		python3 -c "import json,sys; d=json.load(sys.stdin); print(d$1)"
}

start_daemon() {
	nsenter --net="/run/netns/${P}node" "$BIN/xdpl2-daemon" --uplink uplink0 --bpffs "$WORK/bpffs/xdpl2" \
		--socket "$SOCK" --state-file "$WORK/state.json" --xdp-mode "$MODE" \
		--probe-addr "" --reconcile-interval 1s --log-format text \
		>>"$WORK/daemon.log" 2>&1 &
	DPID=$!
	for _ in $(seq 50); do
		[ -S "$SOCK" ] && node "$BIN/xdpl2-daemon" status --socket "$SOCK" >/dev/null 2>&1 && return 0
		kill -0 "$DPID" 2>/dev/null || return 1
		sleep 0.1
	done
	return 1
}
stop_daemon() { kill "$DPID" 2>/dev/null; wait "$DPID" 2>/dev/null; DPID=; }

netconf() { # netconf <vlan> <subnet-prefix>
	cat <<EOF
{"cniVersion":"1.0.0","name":"lan$1","type":"xdpl2","socket":"$SOCK","vlan":$1,
 "ipam":{"type":"host-local","dataDir":"$WORK/ipam",
   "ranges":[[{"subnet":"$2.0/24","rangeStart":"$2.10","rangeEnd":"$2.19"}]]}}
EOF
}

cni() { # cni <CMD> <pod> <vlan> <subnet-prefix> [prevResult-file]
	local conf
	conf=$(netconf "$3" "$4")
	if [ -n "${5:-}" ]; then
		conf=$(python3 -c "import json,sys; c=json.loads(sys.argv[1]); c['prevResult']=json.load(open(sys.argv[2])); print(json.dumps(c))" "$conf" "$5")
	fi
	echo "$conf" | CNI_COMMAND=$1 CNI_CONTAINERID="c-$2" CNI_NETNS="/run/netns/$P$2" \
		CNI_IFNAME=eth1 CNI_PATH="$BIN" CNI_ARGS="IgnoreUnknown=1;K8S_POD_NAMESPACE=test;K8S_POD_NAME=$2" \
		node "$BIN/xdpl2-cni"
}

pod_ip() { python3 -c "import json; print(json.load(open('$WORK/$1.json'))['ips'][0]['address'].split('/')[0])"; }
pod_mac() { ns "$1" cat /sys/class/net/eth1/address; }

# capture <ns> <if> <filter> <seconds> <outfile>: background tcpdump
BG=()
capture() {
	ip netns exec "$P$1" timeout "$4" tcpdump -i "$2" -n -l -A -e "$3" >"$5" 2>/dev/null &
	BG+=($!)
}
waitbg() { local p; for p in "${BG[@]}"; do wait "$p"; done; BG=(); }

ping_ok() { ns "$1" ping -c 2 -W 1 -i 0.2 "$2" >/dev/null; }
neigh_is() { # neigh_is <ns> <ip> <mac>
	ns "$1" ip neigh show "$2" | grep -qi "lladdr $3"
}
arp_dir() { # arp_dir <from-ns> <to-ip> <expected-mac>
	ns "$1" ip neigh flush all
	ping_ok "$1" "$2" && neigh_is "$1" "$2" "$3"
}

# ------------------------------------------------------------------------

run_suite() {
	MODE=$1
	WORK=$(mktemp -d /tmp/xdpl2-test.XXXXXX)
	SOCK=$WORK/xdpl2.sock
	mkdir -p "$WORK/bpffs"
	mount -t bpf bpf "$WORK/bpffs" || { echo "cannot mount bpffs" >&2; return 1; }

	log "=== suite: XDP mode $MODE (work dir $WORK) ==="
	for n in ext node pod1 pod2 pod3 pod4 pod5; do ip netns add "$P$n"; ns "$n" ip link set lo up; done
	ip link add xlt-u type veth peer name xlt-e
	ip link set xlt-u netns "${P}node" name uplink0
	ip link set xlt-e netns "${P}ext" name ext0
	ns node ip link set uplink0 address 02:00:00:00:01:01 up
	ns ext ip link set ext0 address 02:00:00:00:01:64 up
	# Make ext0 behave like a wire: frames it sends carry complete L4
	# checksums and in-band 802.1Q tags (a veth would otherwise hand over
	# CHECKSUM_PARTIAL skbs and VLAN tags in metadata, neither of which
	# exists on a physical link).
	ns ext ethtool -K ext0 tx off txvlan off >/dev/null
	ns node ip addr add 192.0.2.1/24 dev uplink0
	ns ext ip addr add 192.0.2.100/24 dev ext0
	ns ext ip link add link ext0 name ext0.100 type vlan id 100
	ns ext ip link set ext0.100 up
	ns ext ip addr add 198.51.100.100/24 dev ext0.100
	HOST_MAC=02:00:00:00:01:01 EXT_MAC=02:00:00:00:01:64

	local fail0=$FAIL
	check setup.1 "daemon starts and attaches XDP ($MODE)" start_daemon
	check setup.2 "daemon reports XDP mode $MODE" eval "[ \"\$(status_field \"['xdpMode']\")\" = $MODE ]"
	for i in 1 2 3; do
		check setup.cni$i "CNI ADD pod$i" eval "cni ADD pod$i 0 192.0.2 | tee '$WORK/pod$i.json'; [ \${PIPESTATUS[0]} = 0 ]"
	done
	check setup.cni4 "CNI ADD pod4 (VLAN 100)" eval "cni ADD pod4 100 198.51.100 | tee '$WORK/pod4.json'; [ \${PIPESTATUS[0]} = 0 ]"
	local IP1 IP2 IP3 IP4 MAC1 MAC2 MAC3
	IP1=$(pod_ip pod1) IP2=$(pod_ip pod2) IP3=$(pod_ip pod3) IP4=$(pod_ip pod4)
	MAC1=$(pod_mac pod1) MAC2=$(pod_mac pod2) MAC3=$(pod_mac pod3)
	log "pod1 $IP1 $MAC1 | pod2 $IP2 $MAC2 | pod3 $IP3 $MAC3 | pod4 $IP4 (vlan 100)"
	check setup.ports "daemon has 4 registered ports" eval "[ \"\$(status_field \"['ports']\")\" = 4 ]"
	check setup.check "CNI CHECK pod1 passes" cni CHECK pod1 0 192.0.2 "$WORK/pod1.json"
	if [ "$FAIL" != "$fail0" ]; then
		log "setup failed; skipping the rest of the $MODE suite"
		tail -30 "$WORK/daemon.log"
		FAIL=$((FAIL + 1)); RESULTS+=("FAIL  [$MODE] suite aborted after setup failure")
		cleanup
		return
	fi
	if [ -n "${XDPL2_SETUP_ONLY:-}" ]; then
		trap - EXIT
		log "XDPL2_SETUP_ONLY: topology left running (daemon pid $DPID, work dir $WORK, socket $SOCK)"
		exit 0
	fi

	# d. ARP in all directions (fresh neighbour caches each time).
	check d.1 "ARP pod1 -> ext resolves ext MAC" arp_dir pod1 192.0.2.100 $EXT_MAC
	check d.2 "ARP ext -> pod2 resolves pod2 MAC" arp_dir ext "$IP2" "$MAC2"
	check d.3 "ARP pod1 -> pod3 resolves pod3 MAC" arp_dir pod1 "$IP3" "$MAC3"
	check d.4 "ARP pod2 -> host resolves host MAC" arp_dir pod2 192.0.2.1 $HOST_MAC
	check d.5 "ARP host -> pod3 resolves pod3 MAC" arp_dir node "$IP3" "$MAC3"
	arp_capture() {
		ns ext ip neigh flush all
		capture pod3 eth1 arp 3 "$WORK/arp.cap"
		sleep 0.7
		ns ext ping -c 1 -W 1 "$IP3" >/dev/null
		waitbg
		grep -q "Request who-has $IP3" "$WORK/arp.cap" && grep -q "Reply $IP3 is-at" "$WORK/arp.cap"
	}
	check d.6 "capture: ARP request flooded to pod3 and pod3 replies" arp_capture

	# a. pod <-> external.
	check a.1 "ping pod1 -> ext" ping_ok pod1 192.0.2.100
	check a.2 "ping ext -> pod2" ping_ok ext "$IP2"
	iperf_pod_ext() {
		ns ext iperf3 -s -1 -D >/dev/null
		sleep 0.5
		local j
		j=$(ns pod3 iperf3 -c 192.0.2.100 -t 2 -J) || return 1
		BPS=$(echo "$j" | python3 -c "import json,sys; print(round(json.load(sys.stdin)['end']['sum_received']['bits_per_second']/1e9,2))")
		NOTES+=("[$MODE] iperf3 pod3 -> ext (TCP, 2s, TC redirect to uplink): ${BPS} Gbit/s")
		ns ext iperf3 -s -1 -D >/dev/null
		sleep 0.5
		j=$(ns pod3 iperf3 -c 192.0.2.100 -t 2 -R -J) || return 1
		BPS=$(echo "$j" | python3 -c "import json,sys; print(round(json.load(sys.stdin)['end']['sum_received']['bits_per_second']/1e9,2))")
		NOTES+=("[$MODE] iperf3 ext -> pod3 (TCP, 2s, XDP redirect from uplink): ${BPS} Gbit/s")
	}
	check a.3 "iperf3 TCP pod3 <-> ext (both directions)" iperf_pod_ext

	# b. pod <-> pod on the same switch.
	check b.1 "ping pod1 -> pod2" ping_ok pod1 "$IP2"
	check b.2 "ping pod2 -> pod3" ping_ok pod2 "$IP3"
	check b.3 "ping pod3 -> pod1" ping_ok pod3 "$IP1"
	iperf_pod_pod() {
		ns pod2 iperf3 -s -1 -D >/dev/null
		sleep 0.5
		local j
		j=$(ns pod1 iperf3 -c "$IP2" -t 2 -J) || return 1
		BPS=$(echo "$j" | python3 -c "import json,sys; print(round(json.load(sys.stdin)['end']['sum_received']['bits_per_second']/1e9,2))")
		NOTES+=("[$MODE] iperf3 pod1 -> pod2 (TCP, 2s, TC redirect port to port): ${BPS} Gbit/s")
	}
	check b.4 "iperf3 TCP pod1 -> pod2" iperf_pod_pod

	# c. pod <-> host (the macvlan regression case).
	check c.1 "ping pod1 -> host" ping_ok pod1 192.0.2.1
	check c.2 "ping host -> pod2" ping_ok node "$IP2"
	tcp_host() {
		ns node iperf3 -s -1 -D >/dev/null
		sleep 0.5
		ns pod3 iperf3 -c 192.0.2.1 -t 1 >/dev/null
	}
	check c.3 "TCP (iperf3) pod3 -> host" tcp_host

	# e. broadcast to all ports.
	bcast_from() { # bcast_from <sender-ns> <src-ip> <tag> <receivers...>
		local s=$1 src=$2 tag=$3; shift 3
		for r in "$@"; do
			local ifc=eth1
			[ "$r" = ext ] && ifc=ext0
			[ "$r" = node ] && ifc=uplink0
			capture "$r" "$ifc" "udp port 9999" 3 "$WORK/bc-$r.cap"
		done
		sleep 0.7
		ns "$s" $UDP send 192.0.2.255 9999 "$tag" "$src"
		waitbg
		local bad=0
		for r in "$@"; do
			grep -q "$tag" "$WORK/bc-$r.cap" || { echo "$r did not see $tag"; bad=1; }
		done
		# VLAN 100 must not see untagged broadcast
		return $bad
	}
	check e.1 "broadcast from ext reaches pod1, pod2, pod3 and host" bcast_from ext 192.0.2.100 bc-ext pod1 pod2 pod3 node
	check e.2 "broadcast from pod1 reaches pod2, pod3, host and ext" bcast_from pod1 "$IP1" bc-pod1 pod2 pod3 node ext
	check e.3 "broadcast from host reaches pod1, pod2, pod3 and ext" bcast_from node 192.0.2.1 bc-host pod1 pod2 pod3 ext
	vlan_isolation_bcast() {
		capture pod4 eth1 "udp port 9999" 3 "$WORK/bc-pod4.cap"
		sleep 0.7
		ns ext $UDP send 192.0.2.255 9999 bc-iso 192.0.2.100
		waitbg
		! grep -q bc-iso "$WORK/bc-pod4.cap"
	}
	check e.4 "untagged broadcast does not leak into VLAN 100 pod4" vlan_isolation_bcast

	mcast_from() { # mcast_from <sender-ns> <src-ip> <tag>  joined: pod1 pod2 (+ext/node), not joined: pod3
		local s=$1 src=$2 tag=$3
		declare -A ipof=([pod1]=$IP1 [pod2]=$IP2 [pod3]=$IP3 [ext]=192.0.2.100 [node]=192.0.2.1)
		local joined=() r
		for r in pod1 pod2 ext node; do
			[ "$r" = "$s" ] && continue
			joined+=("$r")
			ip netns exec "$P$r" $UDP recv 5353 3 224.0.0.251 "${ipof[$r]}" >"$WORK/mc-$r.out" &
			BG+=($!)
		done
		if [ "$s" != pod3 ]; then
			ip netns exec "${P}pod3" $UDP recv 5353 3 >"$WORK/mc-pod3.out" &
			BG+=($!)
		fi
		sleep 0.7
		ns "$s" $UDP send 224.0.0.251 5353 "$tag" "$src"
		waitbg
		local bad=0
		for r in "${joined[@]}"; do
			grep -q "$tag" "$WORK/mc-$r.out" || { echo "$r (joined) did not receive $tag"; bad=1; }
		done
		if [ "$s" != pod3 ] && grep -q "$tag" "$WORK/mc-pod3.out"; then
			echo "pod3 (not joined) received $tag"; bad=1
		fi
		return $bad
	}
	check e.5 "mDNS 224.0.0.251 from ext delivered to joined pod1, pod2, host; not to unjoined pod3" mcast_from ext 192.0.2.100 mc-ext
	check e.6 "mDNS 224.0.0.251 from pod3 delivered to joined pod1, pod2, ext, host" mcast_from pod3 "$IP3" mc-pod3
	check e.7 "SSDP 239.255.255.250 from pod1 seen by pod2 and ext (capture)" eval "
		capture pod2 eth1 'udp port 1900' 3 '$WORK/ssdp-pod2.cap'
		capture ext ext0 'udp port 1900' 3 '$WORK/ssdp-ext.cap'
		sleep 0.7; ns pod1 $UDP send 239.255.255.250 1900 ssdp-probe $IP1 ; waitbg
		grep -q ssdp-probe '$WORK/ssdp-pod2.cap' && grep -q ssdp-probe '$WORK/ssdp-ext.cap'"

	# f. non-matching traffic passes through untouched.
	xdp_pass_host() {
		local before after
		before=$(stat_of datapath_xdp_pass)
		ns ext ping -c 5 -i 0.2 -W 1 192.0.2.1 >/dev/null || return 1
		after=$(stat_of datapath_xdp_pass)
		echo "xdp_pass $before -> $after"
		[ $((after - before)) -ge 5 ]
	}
	check f.1 "ext -> host ping goes via XDP_PASS (counter +5)" xdp_pass_host
	raw_pass() {
		capture node uplink0 "ether proto 0x88b5" 3 "$WORK/raw-node.cap"
		capture pod1 eth1 "ether proto 0x88b5" 3 "$WORK/raw-pod1.cap"
		sleep 0.7
		ns ext $UDP raw ext0 02:00:00:00:99:99 88b5 xdpl2-unknown-unicast
		waitbg
		grep -q xdpl2-unknown-unicast "$WORK/raw-node.cap" || { echo "host stack did not see frame"; return 1; }
		! grep -q xdpl2-unknown-unicast "$WORK/raw-pod1.cap" || { echo "unknown unicast leaked to pod"; return 1; }
	}
	check f.2 "unknown-unicast non-IP frame reaches host stack unmodified, not pods" raw_pass
	check f.3 "ext -> host TCP (iperf3) unaffected" eval "ns node iperf3 -s -1 -D >/dev/null; sleep 0.5; ns ext iperf3 -c 192.0.2.1 -t 1 >/dev/null"

	# g. VLAN access port.
	check g.1 "ping pod4 (VLAN 100) -> ext0.100" ping_ok pod4 198.51.100.100
	check g.2 "ping ext0.100 -> pod4" ping_ok ext "$IP4"
	vlan_tag_capture() {
		capture ext ext0 "vlan 100 and icmp" 3 "$WORK/vlan.cap"
		sleep 0.7
		ns pod4 ping -c 1 -W 1 198.51.100.100 >/dev/null
		waitbg
		grep -q "vlan 100" "$WORK/vlan.cap"
	}
	check g.3 "capture: pod4 frames leave the uplink tagged with VLAN 100" vlan_tag_capture
	check g.4 "pod4 (VLAN 100) cannot reach untagged pod1" eval "ns pod4 ip route add 192.0.2.0/24 dev eth1; ! ns pod4 ping -c 2 -W 1 $IP1 >/dev/null"

	# g.5+: the host reaches the LAN through an 802.1Q subinterface of the
	# uplink (host IP on uplink0.100), created while the daemon runs.
	local MAC4
	MAC4=$(pod_mac pod4)
	ns node ip link add link uplink0 name uplink0.100 type vlan id 100
	ns node ip link set uplink0.100 up
	ns node ip addr add 198.51.100.1/24 dev uplink0.100
	host_vlan_seen() {
		for _ in $(seq 50); do
			node "$BIN/xdpl2-daemon" status --socket "$SOCK" | tr -d ' \n' | grep -q '"hostVLANs":\[0,100\]' && return 0
			sleep 0.1
		done
		node "$BIN/xdpl2-daemon" status --socket "$SOCK"
		return 1
	}
	check g.5 "daemon discovers host VLAN subinterface uplink0.100 at runtime" host_vlan_seen
	check g.6 "ARP host (uplink0.100) -> pod4 resolves pod4 MAC" arp_dir node "$IP4" "$MAC4"
	check g.7 "ARP pod4 -> host (uplink0.100) resolves host MAC" arp_dir pod4 198.51.100.1 $HOST_MAC
	check g.8 "ping host (uplink0.100) <-> pod4 both ways" eval "ping_ok node $IP4 && ping_ok pod4 198.51.100.1"
	check g.9 "TCP (iperf3) host (uplink0.100) -> pod4" eval "ns pod4 iperf3 -s -1 -D >/dev/null; sleep 0.5; ns node iperf3 -c $IP4 -t 1 >/dev/null"
	vbcast() { # vbcast <sender-ns> <src-ip> <tag> <want: ns:if ...> -- <must-not: ns:if ...>
		local s=$1 src=$2 tag=$3; shift 3
		local want=() not=() mode=want x
		for x in "$@"; do
			[ "$x" = -- ] && { mode=not; continue; }
			[ $mode = want ] && want+=("$x") || not+=("$x")
		done
		for x in "${want[@]}" "${not[@]}"; do
			capture "${x%%:*}" "${x#*:}" "udp port 9998" 3 "$WORK/vb-${x%%:*}-${x#*:}.cap"
		done
		sleep 0.7
		ns "$s" $UDP send 198.51.100.255 9998 "$tag" "$src"
		waitbg
		local bad=0
		for x in "${want[@]}"; do
			grep -q "$tag" "$WORK/vb-${x%%:*}-${x#*:}.cap" || { echo "$x did not see $tag"; bad=1; }
		done
		for x in "${not[@]}"; do
			grep -q "$tag" "$WORK/vb-${x%%:*}-${x#*:}.cap" && { echo "$x saw $tag (VLAN leak)"; bad=1; }
		done
		return $bad
	}
	check g.10 "broadcast from host on VLAN 100 reaches pod4 and ext0.100, not untagged pods" \
		vbcast node 198.51.100.1 vb-host pod4:eth1 ext:ext0.100 -- pod1:eth1 pod2:eth1
	check g.11 "broadcast from pod4 reaches host uplink0.100 and ext0.100, not untagged pods" \
		vbcast pod4 "$IP4" vb-pod4 node:uplink0.100 ext:ext0.100 -- pod1:eth1 pod2:eth1
	check g.12 "untagged host <-> pod still works with a VLAN subinterface present" eval "arp_dir node $IP2 $MAC2 && ping_ok pod1 192.0.2.1"

	# IPv6: ND/MLD ride the multicast flood path.
	ipv6_ll() {
		local ll
		for _ in $(seq 30); do
			ll=$(ns ext ip -6 addr show dev ext0 scope link | awk '/inet6/{print $2}' | cut -d/ -f1)
			[ -n "$ll" ] && ! ns ext ip -6 addr show dev ext0 | grep -q tentative && break
			sleep 0.2
		done
		sleep 1
		ns pod1 ping -6 -c 2 -W 2 "$ll%eth1" >/dev/null
	}
	check v6.1 "IPv6 link-local ping pod1 -> ext (ND via flood path)" ipv6_ll

	# Robustness.
	spoof() {
		local before after
		before=$(stat_of datapath_port_drop_spoof)
		ns pod2 ip link set eth1 address 02:00:00:00:66:66
		ns pod2 ping -c 2 -W 1 192.0.2.100 >/dev/null && { echo "spoofed traffic forwarded"; ns pod2 ip link set eth1 address "$MAC2"; return 1; }
		ns pod2 ip link set eth1 address "$MAC2"
		after=$(stat_of datapath_port_drop_spoof)
		echo "port_drop_spoof $before -> $after"
		[ "$after" -gt "$before" ] && ping_ok pod2 192.0.2.100
	}
	check r.1 "anti-spoofing: frames from a changed MAC are dropped" spoof

	restart() {
		stop_daemon
		# Unicast keeps flowing on the pinned data path while the daemon is down.
		ping_ok pod1 192.0.2.100 || { echo "unicast broken while daemon down"; return 1; }
		start_daemon || return 1
		[ "$(status_field "['ports']")" = 4 ] || { echo "ports not restored"; return 1; }
		arp_dir pod1 "$IP2" "$MAC2"
	}
	check r.2 "daemon restart: unicast survives downtime, ports restored, flood works" restart

	add_without_daemon() {
		stop_daemon
		if cni ADD pod5 0 192.0.2 >"$WORK/pod5.json" 2>&1; then
			echo "ADD succeeded without daemon"; start_daemon; return 1
		fi
		cat "$WORK/pod5.json"
		local leftover
		leftover=$(ns pod5 ip -o link show | grep -c eth1)
		start_daemon || return 1
		[ "$leftover" = 0 ]
	}
	check r.3 "CNI ADD fails loudly when the daemon is down, leaves no interface" add_without_daemon

	watchdog() {
		ns node ip link add xlstray00001 type veth peer name xlstray-peer
		local ok=1
		for _ in $(seq 40); do
			if status_field "['unregisteredVeths']" 2>/dev/null | grep -q xlstray00001; then ok=0; break; fi
			sleep 0.2
		done
		local healthy
		healthy=$(status_field "['healthy']")
		grep -q "WATCHDOG" "$WORK/daemon.log" || ok=1
		ns node ip link del xlstray00001
		[ $ok = 0 ] && [ "$healthy" = False ]
	}
	check r.4 "watchdog flags a CNI veth without registration (unhealthy + error log)" watchdog

	foreign_xdp() {
		local out
		out=$(node "$BIN/xdpl2-daemon" --uplink uplink0 --bpffs "$WORK/bpffs/other" \
			--socket "$WORK/other.sock" --state-file "$WORK/other.json" --probe-addr "" 2>&1) &&
			{ echo "second daemon did not refuse"; return 1; }
		echo "$out" | tail -1
		echo "$out" | grep -q "refusing to replace foreign XDP program"
	}
	check r.5 "refuses to take over an XDP hook owned by someone else" foreign_xdp

	gc() {
		ns pod3 ip link del eth1
		for _ in $(seq 40); do
			[ "$(status_field "['ports']")" = 3 ] && return 0
			sleep 0.2
		done
		return 1
	}
	check r.6 "reconciler garbage-collects a port whose veth vanished" gc

	del() {
		cni DEL pod1 0 192.0.2 || return 1
		[ "$(status_field "['ports']")" = 2 ] || { echo "port not unregistered"; return 1; }
		! ns pod1 ip link show eth1 >/dev/null 2>&1 || { echo "eth1 still present"; return 1; }
		cni DEL pod1 0 192.0.2 # idempotent
	}
	check r.7 "CNI DEL unregisters and removes the interface; repeated DEL succeeds" del

	# hack/validate-node.sh against this node (no Cilium here).
	validate() { # validate <expect-tcx> [extra env...]
		node env XDPL2_UPLINK=uplink0 XDPL2_BPFFS="$WORK/bpffs/xdpl2" XDPL2_SOCKET="$SOCK" \
			XDPL2_PROBE_ADDR=127.0.0.1:1 XDPL2_DAEMON_BIN="$BIN/xdpl2-daemon" BPFTOOL="${BPFTOOL:-false}" \
			XDPL2_EXPECT_XDP_MODE="$MODE" XDPL2_EXPECT_TCX="$1" "${@:2}" "$ROOT/hack/validate-node.sh"
	}
	check v.1 "validate-node.sh (local mode) passes on a healthy node" validate ""
	# expect_fail <check-name-regex> <cmd...>: the script must run, report
	# RESULT: FAIL, and flag the given check.
	expect_fail() {
		local re=$1 out; shift
		out=$("$@" 2>&1) && { echo "$out"; echo "expected failure"; return 1; }
		echo "$out"
		echo "$out" | grep -q "^RESULT: FAIL" && echo "$out" | grep -Eq "^FAIL +$re "
	}
	check v.2 "validate-node.sh fails when expected Cilium TCX programs are missing" expect_fail tcx validate 'ingress:cil_from_netdev egress:cil_to_netdev'
	check v.3 "validate-node.sh without bpftool falls back to daemon-reported state" validate "" BPFTOOL=false
	validate_remote() {
		# Stand-in for kubectl: "exec ... -- cmd" runs the daemon binary in the node netns.
		printf '%s\n' '#!/bin/sh' \
			'while [ "$1" != "--" ]; do shift; done; shift' \
			'[ "$1" = /usr/local/bin/xdpl2-daemon ] && shift' \
			"exec nsenter --net=/run/netns/${P}node $BIN/xdpl2-daemon \"\$@\" --socket $SOCK" >"$WORK/kubectl"
		chmod +x "$WORK/kubectl"
		env KUBECTL="$WORK/kubectl" XDPL2_POD=xdpl2-test XDPL2_EXPECT_TCX="" XDPL2_EXPECT_XDP_MODE="$MODE" "$ROOT/hack/validate-node.sh"
	}
	check v.4 "validate-node.sh (remote mode via KUBECTL) passes" validate_remote

	check z.1 "no data path parse/redirect errors" eval "[ \$(stat_of datapath_parse_error) = 0 ] && [ \$(stat_of datapath_redirect_error) = 0 ]"
	check z.2 "no flood ring overflows or transmit errors" eval "[ \$(stat_of datapath_flood_rb_full) = 0 ] && [ \$(stat_of flood_tx_errors) = 0 ]"

	log "final daemon status:"
	node "$BIN/xdpl2-daemon" status --socket "$SOCK" | sed 's/^/    /'

	# Teardown: stopping the daemon leaves the pinned data path in place
	# (hitless restarts); `xdpl2-daemon teardown` removes it.
	local PORTIF
	PORTIF=$(python3 -c "import json; print(json.load(open('$WORK/pod2.json'))['interfaces'][0]['name'])")
	td() { node "$BIN/xdpl2-daemon" teardown --bpffs "$WORK/bpffs/xdpl2" --socket "$SOCK" --state-file "$WORK/state.json" "$@"; }
	check t.1 "teardown refuses while the daemon is serving" eval "! td"
	teardown_ok() {
		stop_daemon
		ns node ip -d link show uplink0 | grep -q "prog/xdp" || { echo "precondition: XDP should still be attached after daemon stop"; return 1; }
		td || return 1
		if ns node ip -d link show uplink0 | grep -q "prog/xdp"; then echo "XDP still attached"; return 1; fi
		if ns node ip link show uplink0 | grep -q PROMISC; then echo "promiscuous mode not restored"; return 1; fi
		[ ! -e "$WORK/bpffs/xdpl2" ] || { echo "pins left:"; ls -R "$WORK/bpffs/xdpl2"; return 1; }
		[ ! -e "$WORK/state.json" ] || { echo "state file left"; return 1; }
		if [ -n "$BPFTOOL" ]; then
			local tcx
			tcx=$(node "$BPFTOOL" net show 2>/dev/null | grep -E "tcx/" || true)
			[ -z "$tcx" ] || { echo "TCX programs left: $tcx"; return 1; }
			echo "bpftool: no TCX programs left on uplink0 or $PORTIF"
		else
			echo "bpftool unavailable: TCX detach verified via pins only"
		fi
	}
	check t.2 "teardown detaches XDP/TCX, removes pins and state, restores promiscuous mode" teardown_ok
	check t.3 "teardown is idempotent" td
	check t.4 "unicast stops after teardown (data path really gone)" eval "! ns pod1 ping -c 1 -W 1 $IP2 >/dev/null"
	check t.5 "validate-node.sh flags missing XDP after teardown" expect_fail xdp validate ""
	cleanup
}


if [ -n "$TESTLOG" ]; then
	RUNLOG=$(mktemp)
	exec 3>&1 4>&2
	exec > >(tee "$RUNLOG") 2>&1
fi

START=$(date -u +%Y-%m-%dT%H:%M:%SZ)
for m in $MODES; do
	run_suite "$m"
done

echo
echo "================ SUMMARY ================"
echo "kernel: $(uname -r)   started: $START"
for r in "${RESULTS[@]}"; do echo "$r"; done
for n in "${NOTES[@]}"; do echo "note: $n"; done
echo "-----------------------------------------"
echo "TOTAL: $((PASS + FAIL))  PASS: $PASS  FAIL: $FAIL"
if [ "$FAIL" = 0 ]; then RESULT=PASS; else RESULT=FAIL; fi
echo "RESULT: $RESULT"

if [ -n "$TESTLOG" ]; then
	exec >&3 2>&4
	sleep 0.5 # let tee flush
	{
		cat "$ROOT/test/TESTLOG.header.md"
		echo
		echo "## Latest run: $RESULT ($PASS/$((PASS + FAIL)) checks, modes: $MODES)"
		echo
		echo "Generated by \`make integration\` (\`test/netns_test.sh --testlog TESTLOG.md\`)."
		echo "Kernel $(uname -r), $(ip -V 2>&1 | head -1), $(tcpdump --version 2>&1 | head -1), $(iperf3 --version 2>&1 | head -1 | cut -d' ' -f1-2), clang $(clang --version 2>/dev/null | head -1 | sed 's/.*version //' | cut -d' ' -f1), $(go version 2>/dev/null | cut -d' ' -f3)."
		echo
		echo '```text'
		# Work dirs are random; strip them for a stable diff.
		sed -E 's#/tmp/xdpl2-test\.[A-Za-z0-9]+#$WORK#g' "$RUNLOG"
		echo '```'
	} >"$TESTLOG"
	rm -f "$RUNLOG"
fi
[ "$RESULT" = PASS ]
