// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/*
 * xdpl2 data path: a minimal L2 switch built from three BPF programs.
 *
 *   xdp_uplink          XDP on the uplink NIC (wire -> pods / host)
 *   tc_port_ingress     TCX ingress on each pod's host-side veth (pod -> *)
 *   tc_uplink_egress    TCX egress on the uplink (host stack -> pods)
 *   xdp_pass            no-op program, available for veth peers if needed
 *
 * Broadcast/multicast frames are copied to a ring buffer and replicated by
 * the userspace daemon (see docs/design.md, "Flood path").
 *
 * Only UAPI headers are used and no kernel structures are read, so the object
 * needs no CO-RE relocations and is portable across kernels that provide the
 * helpers below (>= 6.6 for TCX).
 */
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "xdpl2.h"

#ifndef TCX_NEXT
#define TCX_NEXT -1
#endif

#define VLAN_HLEN 4
#define VLAN_VID_MASK 0x0fff

struct vlan_hdr {
	__be16 tci;
	__be16 encap_proto;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, XDPL2_MAX_PORTS * 2);
	__type(key, struct fdb_key);
	__type(value, struct fdb_val);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} ports SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, XDPL2_MAX_PORTS);
	__type(key, __u32);
	__type(value, struct port);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} port_table SEC(".maps");

/* host-side veth ifindex -> port id, used by tc_port_ingress. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, XDPL2_MAX_PORTS);
	__type(key, __u32);
	__type(value, __u32);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} ifindex_ports SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct config);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} config_map SEC(".maps");

/* VLAN id -> host interface MAC on that VLAN (uplink or its subinterface). */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u32);
	__type(value, struct host_vlan);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} host_vlans SEC(".maps");

/* MACs owned locally (pods and host), regardless of VLAN: loop guard. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, XDPL2_MAX_PORTS * 2 + 4096);
	__type(key, struct mac_key);
	__type(value, __u32);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} local_macs SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, STAT__MAX);
	__type(key, __u32);
	__type(value, __u64);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} stats SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} flood_rb SEC(".maps");

/* Force BTF emission for types userspace needs (bpf2go -type). */
const struct flood_event *unused_flood_event __attribute__((unused));
const struct fdb_val *unused_fdb_val __attribute__((unused));
const struct host_vlan *unused_host_vlan __attribute__((unused));
const struct mac_key *unused_mac_key __attribute__((unused));
const enum xdpl2_stat *unused_stat __attribute__((unused));
const enum xdpl2_origin *unused_origin __attribute__((unused));
const enum xdpl2_port_kind *unused_kind __attribute__((unused));

static __always_inline void stat_inc(__u32 idx)
{
	__u64 *v = bpf_map_lookup_elem(&stats, &idx);

	if (v)
		*v += 1;
}

static __always_inline struct config *get_config(void)
{
	__u32 zero = 0;

	return bpf_map_lookup_elem(&config_map, &zero);
}

static __always_inline int is_multicast(const __u8 *mac)
{
	return mac[0] & 1; /* also covers broadcast */
}

static __always_inline int mac_eq(const __u8 *a, const __u8 *b)
{
	return a[0] == b[0] && a[1] == b[1] && a[2] == b[2] &&
	       a[3] == b[3] && a[4] == b[4] && a[5] == b[5];
}

static __always_inline struct host_vlan *host_on_vlan(__u16 vlan)
{
	__u32 key = vlan;

	return bpf_map_lookup_elem(&host_vlans, &key);
}

static __always_inline int is_local_mac(const __u8 *mac)
{
	struct mac_key key = {};

	__builtin_memcpy(key.mac, mac, 6);
	return bpf_map_lookup_elem(&local_macs, &key) != NULL;
}

static __always_inline struct port *fdb_lookup(const __u8 *mac, __u16 vlan,
					       __u32 *port_id)
{
	struct fdb_key key = {};
	struct fdb_val *val;

	__builtin_memcpy(key.mac, mac, 6);
	key.vlan = vlan;
	val = bpf_map_lookup_elem(&ports, &key);
	if (!val)
		return NULL;
	*port_id = val->port_id;
	return bpf_map_lookup_elem(&port_table, &val->port_id);
}

/* ---------------------------------------------------------------------- */
/* Uplink XDP: frames from the wire.                                       */
/* ---------------------------------------------------------------------- */

static __always_inline void xdp_punt(struct xdp_md *ctx, __u16 vlan, int tagged)
{
	struct flood_event *ev;
	__u64 len = bpf_xdp_get_buff_len(ctx);

	if (len < ETH_HLEN || len > XDPL2_MAX_FLOOD_LEN) {
		stat_inc(STAT_FLOOD_TOO_BIG);
		return;
	}
	ev = bpf_ringbuf_reserve(&flood_rb, sizeof(*ev), 0);
	if (!ev) {
		stat_inc(STAT_FLOOD_RB_FULL);
		return;
	}
	if (bpf_xdp_load_bytes(ctx, 0, ev->data, len)) {
		bpf_ringbuf_discard(ev, 0);
		stat_inc(STAT_PARSE_ERROR);
		return;
	}
	ev->len = len;
	ev->src_port = 0;
	ev->vlan = vlan;
	ev->origin = XDPL2_ORIGIN_UPLINK;
	ev->tagged = tagged;
	ev->pad = 0;
	bpf_ringbuf_submit(ev, 0);
	stat_inc(STAT_XDP_FLOOD);
}

SEC("xdp")
int xdp_uplink(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = data;
	struct port *p;
	__u32 port_id = 0;
	__u16 vlan = 0;
	int tagged = 0;

	stat_inc(STAT_XDP_RX);

	if ((void *)(eth + 1) > data_end) {
		stat_inc(STAT_PARSE_ERROR);
		return XDP_PASS;
	}

	if (eth->h_proto == bpf_htons(ETH_P_8021Q) ||
	    eth->h_proto == bpf_htons(ETH_P_8021AD)) {
		struct vlan_hdr *vh = (void *)(eth + 1);

		if ((void *)(vh + 1) > data_end) {
			stat_inc(STAT_PARSE_ERROR);
			return XDP_PASS;
		}
		vlan = bpf_ntohs(vh->tci) & VLAN_VID_MASK;
		tagged = 1;
	}

	if (is_multicast(eth->h_dest)) {
		/*
		 * A flood frame whose source is one of our own ports was
		 * injected by us (generic XDP sees BPF_F_INGRESS redirects)
		 * or reflected by the LAN; never replicate it again.
		 */
		/*
		 * Checked by MAC alone: a frame injected with BPF_F_INGRESS may
		 * carry its VLAN tag in skb metadata, which generic XDP does not
		 * show us, so the VLAN we parsed can be wrong for such frames.
		 */
		if (is_local_mac(eth->h_source)) {
			stat_inc(STAT_XDP_LOOP_PASS);
			return XDP_PASS;
		}
		xdp_punt(ctx, vlan, tagged);
		stat_inc(STAT_XDP_PASS);
		return XDP_PASS; /* the host stack is a flood recipient too */
	}

	p = fdb_lookup(eth->h_dest, vlan, &port_id);
	if (!p || p->kind != XDPL2_PORT_POD) {
		/* host MAC, unknown unicast, non-switched traffic: untouched */
		stat_inc(STAT_XDP_PASS);
		return XDP_PASS;
	}

	if (tagged) {
		/* access port: strip the 802.1Q tag before delivery */
		__u8 macs[12];

		__builtin_memcpy(macs, eth, sizeof(macs));
		if (bpf_xdp_adjust_head(ctx, VLAN_HLEN)) {
			stat_inc(STAT_PARSE_ERROR);
			return XDP_DROP;
		}
		data = (void *)(long)ctx->data;
		data_end = (void *)(long)ctx->data_end;
		if (data + sizeof(macs) > data_end) {
			stat_inc(STAT_PARSE_ERROR);
			return XDP_DROP;
		}
		__builtin_memcpy(data, macs, sizeof(macs));
	}

	stat_inc(STAT_XDP_REDIRECT);
	return bpf_redirect(p->ifindex, 0);
}

/* ---------------------------------------------------------------------- */
/* TC helpers                                                               */
/* ---------------------------------------------------------------------- */

static __always_inline void tc_punt(struct __sk_buff *skb, __u8 origin,
				    __u32 src_port, __u16 vlan, __u8 tagged)
{
	struct flood_event *ev;
	__u32 len = skb->len;

	if (len < ETH_HLEN || len > XDPL2_MAX_FLOOD_LEN) {
		stat_inc(STAT_FLOOD_TOO_BIG);
		return;
	}
	ev = bpf_ringbuf_reserve(&flood_rb, sizeof(*ev), 0);
	if (!ev) {
		stat_inc(STAT_FLOOD_RB_FULL);
		return;
	}
	if (bpf_skb_load_bytes(skb, 0, ev->data, len)) {
		bpf_ringbuf_discard(ev, 0);
		stat_inc(STAT_PARSE_ERROR);
		return;
	}
	ev->len = len;
	ev->src_port = src_port;
	ev->vlan = vlan;
	ev->origin = origin;
	ev->tagged = tagged;
	ev->pad = 0;
	bpf_ringbuf_submit(ev, 0);
}

/* ---------------------------------------------------------------------- */
/* Pod port: TCX ingress on the host-side veth (frames sent by the pod).  */
/* ---------------------------------------------------------------------- */

SEC("tc")
int tc_port_ingress(struct __sk_buff *skb)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct ethhdr *eth = data;
	struct config *cfg;
	struct port *self, *dst;
	__u32 ifindex = skb->ingress_ifindex;
	__u32 *self_id, dst_id = 0, sid;
	__u8 src[6], dmac[6];

	stat_inc(STAT_PORT_RX);

	cfg = get_config();
	self_id = bpf_map_lookup_elem(&ifindex_ports, &ifindex);
	if (!cfg || !self_id) {
		stat_inc(STAT_PORT_DROP_UNKNOWN);
		return TC_ACT_SHOT;
	}
	sid = *self_id;
	self = bpf_map_lookup_elem(&port_table, &sid);
	if (!self || self->kind != XDPL2_PORT_POD) {
		stat_inc(STAT_PORT_DROP_UNKNOWN);
		return TC_ACT_SHOT;
	}

	if ((void *)(eth + 1) > data_end) {
		stat_inc(STAT_PARSE_ERROR);
		return TC_ACT_SHOT;
	}
	/* Access ports carry untagged frames only. */
	if (skb->vlan_present || eth->h_proto == bpf_htons(ETH_P_8021Q) ||
	    eth->h_proto == bpf_htons(ETH_P_8021AD)) {
		stat_inc(STAT_PORT_DROP_TAGGED);
		return TC_ACT_SHOT;
	}
	/* Anti-spoofing: a port may only source frames from its own MAC. */
	if (!mac_eq(eth->h_source, self->mac)) {
		stat_inc(STAT_PORT_DROP_SPOOF);
		return TC_ACT_SHOT;
	}
	__builtin_memcpy(src, eth->h_source, 6);
	__builtin_memcpy(dmac, eth->h_dest, 6);

	if (is_multicast(dmac)) {
		__u16 vlan = self->vlan;
		__u32 uplink = cfg->uplink_ifindex;

		/*
		 * The host stack is the one recipient userspace cannot reach
		 * (AF_PACKET only transmits), so hand it a clone here, if the
		 * host has an interface on this VLAN. For VLAN ports the clone
		 * carries the tag (as skb metadata) so the host's 802.1Q
		 * subinterface receives it. The metadata tag does not change
		 * the packet bytes copied to the flood ring below.
		 */
		if (host_on_vlan(vlan)) {
			if (vlan && bpf_skb_vlan_push(skb, bpf_htons(ETH_P_8021Q), vlan)) {
				stat_inc(STAT_REDIRECT_ERROR);
			} else {
				bpf_clone_redirect(skb, uplink, BPF_F_INGRESS);
				if (vlan)
					bpf_skb_vlan_pop(skb);
			}
		}
		tc_punt(skb, XDPL2_ORIGIN_PORT, sid, vlan, 0);
		stat_inc(STAT_PORT_FLOOD);
		return TC_ACT_SHOT;
	}

	dst = fdb_lookup(dmac, self->vlan, &dst_id);
	if (dst) {
		if (dst->kind == XDPL2_PORT_HOST) {
			/* Into the host stack; tagged so the VLAN subinterface gets it. */
			if (self->vlan &&
			    bpf_skb_vlan_push(skb, bpf_htons(ETH_P_8021Q), self->vlan)) {
				stat_inc(STAT_REDIRECT_ERROR);
				return TC_ACT_SHOT;
			}
			stat_inc(STAT_PORT_TO_HOST);
			return bpf_redirect(cfg->uplink_ifindex, BPF_F_INGRESS);
		}
		if (dst_id == sid) {
			stat_inc(STAT_PORT_DROP_HAIRPIN);
			return TC_ACT_SHOT;
		}
		stat_inc(STAT_PORT_TO_PORT);
		return bpf_redirect(dst->ifindex, 0);
	}

	/* Not local: out the uplink, tagged if this is a VLAN access port. */
	if (self->vlan) {
		if (bpf_skb_vlan_push(skb, bpf_htons(ETH_P_8021Q), self->vlan)) {
			stat_inc(STAT_REDIRECT_ERROR);
			return TC_ACT_SHOT;
		}
	}
	stat_inc(STAT_PORT_TO_UPLINK);
	return bpf_redirect(cfg->uplink_ifindex, 0);
}

/* ---------------------------------------------------------------------- */
/* Uplink TCX egress: frames the host stack sends out of the uplink.      */
/* Everything not addressed to a local pod continues (TCX_NEXT) so other   */
/* programs (e.g. Cilium's cil_to_netdev) and the wire see it unchanged.   */
/* ---------------------------------------------------------------------- */

SEC("tc")
int tc_uplink_egress(struct __sk_buff *skb)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct ethhdr *eth = data;
	struct host_vlan *hv;
	struct port *dst;
	__u32 dst_id = 0;
	__u16 vlan = 0;
	__u8 inband = 0;

	if ((void *)(eth + 1) > data_end)
		return TCX_NEXT;

	/*
	 * Frames from a VLAN subinterface of the uplink normally carry their
	 * tag as skb metadata here (it is inserted into the packet later, or
	 * by the NIC); frames from raw sockets may carry it in-band.
	 */
	if (skb->vlan_present) {
		vlan = skb->vlan_tci & VLAN_VID_MASK;
	} else if (eth->h_proto == bpf_htons(ETH_P_8021Q) ||
		   eth->h_proto == bpf_htons(ETH_P_8021AD)) {
		struct vlan_hdr *vh = (void *)(eth + 1);

		if ((void *)(vh + 1) > data_end)
			return TCX_NEXT;
		vlan = bpf_ntohs(vh->tci) & VLAN_VID_MASK;
		inband = 1;
	}

	hv = host_on_vlan(vlan);
	if (!hv)
		return TCX_NEXT; /* not a host interface we switch for */

	if (is_multicast(eth->h_dest)) {
		/*
		 * Only replicate what the host stack itself originates. Frames
		 * transmitted by the flood daemon (pod-sourced) also pass here
		 * and must not be punted again.
		 */
		if (mac_eq(eth->h_source, hv->mac)) {
			tc_punt(skb, XDPL2_ORIGIN_HOST, XDPL2_HOST_PORT, vlan, inband);
			stat_inc(STAT_UPLINK_EGRESS_FLOOD);
		}
		return TCX_NEXT;
	}

	dst = fdb_lookup(eth->h_dest, vlan, &dst_id);
	if (dst && dst->kind == XDPL2_PORT_POD) {
		/* Access port: deliver untagged (metadata or in-band tag). */
		if (vlan && bpf_skb_vlan_pop(skb)) {
			stat_inc(STAT_REDIRECT_ERROR);
			return TCX_NEXT;
		}
		stat_inc(STAT_UPLINK_EGRESS_TO_PORT);
		return bpf_redirect(dst->ifindex, 0);
	}
	return TCX_NEXT;
}

/* No-op XDP program; attach to a veth peer to enable veth NAPI/XDP rx. */
SEC("xdp")
int xdp_pass(struct xdp_md *ctx)
{
	return XDP_PASS;
}

char _license[] SEC("license") = "Dual BSD/GPL";
