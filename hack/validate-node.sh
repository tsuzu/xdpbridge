#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Validate an xdpbridge node and print a PASS/FAIL summary.
#
# Checks:
#   xdp        XDP program xdp_uplink is attached to the uplink (and its mode)
#   tcx        expected TCX programs (e.g. Cilium's) are still on the uplink,
#              plus xdpbridge's tc_uplink_egress
#   health     the daemon reports healthy (/healthz, or `status` via socket)
#   pins       the expected pinned maps and links exist under the bpffs dir
#   link-id    the XDP program on the uplink is the one held by xdpbridge's pin
#
# Two modes:
#   local (KUBECTL unset)  run on the node itself, e.g. in a privileged
#                          hostNetwork pod; uses ip, bpftool, ls, curl/wget
#                          or the daemon binary
#   remote (KUBECTL set)   e.g. KUBECTL="kubectl --context my-ctx"; runs
#                          `xdpbridge-daemon status` in the node's xdpbridge pod and
#                          judges kernel state as reported by the daemon
#
# Environment (all optional except XDPBRIDGE_UPLINK in local mode):
#   XDPBRIDGE_UPLINK        uplink interface name
#   XDPBRIDGE_BPFFS         pin directory            (default /sys/fs/bpf/xdpbridge)
#   XDPBRIDGE_SOCKET        daemon socket            (default /run/xdpbridge/xdpbridge.sock)
#   XDPBRIDGE_PROBE_ADDR    daemon probe listener    (default 127.0.0.1:9967)
#   XDPBRIDGE_DAEMON_BIN    daemon binary            (default xdpbridge-daemon in PATH)
#   XDPBRIDGE_EXPECT_XDP_MODE  native|generic|any    (default any)
#   XDPBRIDGE_EXPECT_TCX    space-separated hook:name items that must be present
#                       (default "ingress:cil_from_netdev egress:cil_to_netdev";
#                       set to "" on clusters without Cilium)
#   XDPBRIDGE_EXPECT_PINS   pins that must exist (default: all xdpbridge maps + links)
#   BPFTOOL             bpftool binary           (default bpftool)
#   KUBECTL             enables remote mode
#   XDPBRIDGE_NAMESPACE     namespace of the DaemonSet (default xdpbridge-system)
#   XDPBRIDGE_POD           daemon pod, or XDPBRIDGE_NODE to find it by node name
#
# Exit status: 0 if every check passed (SKIPs allowed), 1 otherwise.
set -uo pipefail

BPFFS=${XDPBRIDGE_BPFFS:-/sys/fs/bpf/xdpbridge}
SOCKET=${XDPBRIDGE_SOCKET:-/run/xdpbridge/xdpbridge.sock}
PROBE=${XDPBRIDGE_PROBE_ADDR:-127.0.0.1:9967}
DAEMON=${XDPBRIDGE_DAEMON_BIN:-xdpbridge-daemon}
EXPECT_MODE=${XDPBRIDGE_EXPECT_XDP_MODE:-any}
EXPECT_TCX=${XDPBRIDGE_EXPECT_TCX-ingress:cil_from_netdev egress:cil_to_netdev}
EXPECT_PINS=${XDPBRIDGE_EXPECT_PINS:-ports port_table ifindex_ports config_map stats flood_rb host_vlans local_macs links/xdp_uplink links/uplink_egress}
BPFTOOL=${BPFTOOL:-bpftool}
NS=${XDPBRIDGE_NAMESPACE:-xdpbridge-system}
UPLINK=${XDPBRIDGE_UPLINK:-}

PASS=0 FAIL=0 SKIP=0
LINES=()
result() { # result PASS|FAIL|SKIP <check> <detail>
	case $1 in PASS) PASS=$((PASS + 1)) ;; FAIL) FAIL=$((FAIL + 1)) ;; SKIP) SKIP=$((SKIP + 1)) ;; esac
	LINES+=("$(printf '%-4s  %-8s %s' "$1" "$2" "$3")")
}

# Kernel program names are truncated to 15 characters (BPF_OBJ_NAME_LEN-1).
short() { echo "${1:0:15}"; }

# has_prog <list> <name>: list contains name (or its 15-char truncation)
has_prog() {
	local want s
	want=$(short "$2")
	for s in $1; do
		[ "$(short "$s")" = "$want" ] && return 0
	done
	return 1
}

# JSON helpers that need no parser: the daemon prints one key per line.
jfield() { sed -n "s/^ *\"$1\": \"\{0,1\}\([^\",]*\)\"\{0,1\},\{0,1\}$/\1/p" | head -1; }

check_tcx_lists() { # <ingress names> <egress names> <source>
	local ing=$1 egr=$2 src=$3 item hook name missing=()
	for item in $EXPECT_TCX egress:tc_uplink_egress; do
		hook=${item%%:*} name=${item#*:}
		if [ "$hook" = ingress ]; then has_prog "$ing" "$name" || missing+=("$item")
		else has_prog "$egr" "$name" || missing+=("$item"); fi
	done
	if [ ${#missing[@]} = 0 ]; then
		result PASS tcx "ingress=[${ing:-}] egress=[${egr:-}] ($src)"
	else
		result FAIL tcx "missing ${missing[*]}; ingress=[${ing:-}] egress=[${egr:-}] ($src)"
	fi
}

# ---------------------------------------------------------------------------
remote() {
	local pod=${XDPBRIDGE_POD:-}
	if [ -z "$pod" ]; then
		[ -n "${XDPBRIDGE_NODE:-}" ] || { echo "remote mode needs XDPBRIDGE_POD or XDPBRIDGE_NODE" >&2; exit 2; }
		pod=$($KUBECTL -n "$NS" get pods -l app.kubernetes.io/name=xdpbridge \
			--field-selector "spec.nodeName=$XDPBRIDGE_NODE" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
		[ -n "$pod" ] || { echo "no xdpbridge pod found on node $XDPBRIDGE_NODE" >&2; exit 2; }
	fi
	local st
	if ! st=$($KUBECTL -n "$NS" exec "$pod" -c daemon -- /usr/local/bin/xdpbridge-daemon status 2>&1); then
		result FAIL health "cannot query daemon in pod $pod: $(echo "$st" | tail -1)"
		summary "remote (pod $pod)"
	fi
	judge_status "$st" "daemon-reported, pod $pod"
	# Pins as reported by the daemon.
	local pins missing=() p
	pins=$(echo "$st" | sed -n '/"pins": \[/,/\]/p' | tr -d ' ",[]' | grep -v '^pins:$')
	for p in $EXPECT_PINS; do echo "$pins" | grep -qx "$p" || missing+=("$p"); done
	if [ ${#missing[@]} = 0 ]; then result PASS pins "all expected pins present (daemon-reported)"
	else result FAIL pins "missing: ${missing[*]}"; fi
	result SKIP link-id "needs bpftool on the node (local mode)"
	summary "remote (pod $pod)"
}

judge_status() { # <status json> <source>
	local st=$1 src=$2 xdp mode ing egr healthy
	healthy=$(echo "$st" | jfield healthy)
	if [ "$healthy" = true ]; then result PASS health "daemon healthy ($src)"
	else
		result FAIL health "daemon unhealthy ($src): $(echo "$st" | sed -n '/"problems": \[/,/\]/p' | grep -v 'problems\|\]' | tr -s ' ' | tr '\n' ';')"
	fi
	xdp=$(echo "$st" | jfield xdp)
	mode=$(echo "$st" | sed -n '/"uplinkPrograms"/,/}/p' | jfield xdpMode)
	ing=$(echo "$st" | jfield tcxIngressCSV | tr ',' ' ')
	egr=$(echo "$st" | jfield tcxEgressCSV | tr ',' ' ')
	if [ -z "$(echo "$st" | grep '"uplinkPrograms"')" ]; then
		result FAIL xdp "daemon too old: no uplinkPrograms in status"
		return
	fi
	check_xdp "$xdp" "$mode" "$src"
	check_tcx_lists "$ing" "$egr" "$src"
}

check_xdp() { # <prog name> <mode> <source>
	if [ "$(short "${1:-}")" != "$(short xdp_uplink)" ]; then
		result FAIL xdp "uplink XDP program is '${1:-none}', want xdp_uplink ($3)"
	elif [ "$EXPECT_MODE" != any ] && [ "$2" != "$EXPECT_MODE" ]; then
		result FAIL xdp "xdp_uplink attached in $2 mode, want $EXPECT_MODE ($3)"
	else
		result PASS xdp "xdp_uplink attached, mode $2 ($3)"
	fi
}

# ---------------------------------------------------------------------------
local_mode() {
	[ -n "$UPLINK" ] || { echo "XDPBRIDGE_UPLINK is required" >&2; exit 2; }
	ip link show dev "$UPLINK" >/dev/null 2>&1 || { echo "uplink $UPLINK not found in this network namespace" >&2; exit 2; }
	local have_bpftool=0 st=
	"$BPFTOOL" version >/dev/null 2>&1 && have_bpftool=1

	# xdp: iproute2 shows "xdp" (native) or "xdpgeneric" and the program name.
	local ipd name mode=unknown
	ipd=$(ip -d link show dev "$UPLINK")
	name=$(echo "$ipd" | sed -n 's/.*prog\/xdp id [0-9]* name \([^ ]*\).*/\1/p' | head -1)
	case "$(echo "$ipd" | head -1)" in
	*" xdpgeneric"*) mode=generic ;;
	*" xdpoffload"*) mode=offload ;;
	*" xdp "* | *" xdp/"*) mode=native ;;
	esac
	check_xdp "$name" "$mode" "ip -d link"

	# tcx: bpftool net show lists "<dev>(<idx>) tcx/<hook> <name> prog_id ..."
	if [ $have_bpftool = 1 ]; then
		local net ing egr
		net=$("$BPFTOOL" net show dev "$UPLINK" 2>/dev/null)
		ing=$(echo "$net" | awk '$2=="tcx/ingress"{print $3}' | xargs)
		egr=$(echo "$net" | awk '$2=="tcx/egress"{print $3}' | xargs)
		check_tcx_lists "$ing" "$egr" "bpftool"
	elif command -v "$DAEMON" >/dev/null && st=$("$DAEMON" status --socket "$SOCKET" 2>/dev/null); then
		check_tcx_lists "$(echo "$st" | jfield tcxIngressCSV | tr ',' ' ')" \
			"$(echo "$st" | jfield tcxEgressCSV | tr ',' ' ')" "daemon-reported, no bpftool"
	else
		result SKIP tcx "no working bpftool ($BPFTOOL) and no daemon status"
	fi

	# health: /healthz via curl or wget, else the daemon's status over the socket.
	local body
	if command -v curl >/dev/null && body=$(curl -fsS --max-time 3 "http://$PROBE/healthz" 2>&1); then
		result PASS health "/healthz: $(echo "$body" | head -1)"
	elif command -v wget >/dev/null && body=$(wget -qO- -T 3 "http://$PROBE/healthz" 2>&1); then
		result PASS health "/healthz: $(echo "$body" | head -1)"
	elif command -v "$DAEMON" >/dev/null && st=$("$DAEMON" status --socket "$SOCKET" 2>&1); then
		if [ "$(echo "$st" | jfield healthy)" = true ]; then
			result PASS health "daemon healthy (status via $SOCKET)"
		else
			result FAIL health "daemon unhealthy: $(echo "$st" | sed -n '/"problems": \[/,/\]/p' | grep -v 'problems\|\]' | tr -s ' ' | tr '\n' ';')"
		fi
	else
		result FAIL health "daemon not reachable on http://$PROBE or $SOCKET${body:+: $(echo "$body" | tail -1)}"
	fi

	# pins
	local p missing=()
	for p in $EXPECT_PINS; do [ -e "$BPFFS/$p" ] || missing+=("$p"); done
	if [ ${#missing[@]} = 0 ]; then result PASS pins "all expected pins present in $BPFFS"
	else result FAIL pins "missing in $BPFFS: ${missing[*]}"; fi

	# link-id: the program on the hook is the one our pinned link holds.
	if [ $have_bpftool = 1 ] && [ -e "$BPFFS/links/xdp_uplink" ]; then
		local lprog hprog
		lprog=$("$BPFTOOL" link show pinned "$BPFFS/links/xdp_uplink" 2>/dev/null | sed -n 's/.*prog \([0-9]*\).*/\1/p' | head -1)
		hprog=$(echo "$ipd" | sed -n 's/.*prog\/xdp id \([0-9]*\).*/\1/p' | head -1)
		if [ -n "$lprog" ] && [ "$lprog" = "$hprog" ]; then result PASS link-id "uplink XDP prog $hprog is held by the pinned xdpbridge link"
		else result FAIL link-id "uplink XDP prog '${hprog:-none}' != pinned link prog '${lprog:-none}'"; fi
	else
		result SKIP link-id "needs bpftool and the pinned XDP link"
	fi
	summary "local (uplink $UPLINK)"
}

summary() {
	echo "xdpbridge node validation: $1"
	printf '%s\n' "${LINES[@]}"
	echo "----"
	echo "PASS: $PASS  FAIL: $FAIL  SKIP: $SKIP"
	if [ "$FAIL" = 0 ]; then echo "RESULT: PASS"; exit 0; fi
	echo "RESULT: FAIL"
	exit 1
}

if [ -n "${KUBECTL:-}" ]; then remote; else local_mode; fi
