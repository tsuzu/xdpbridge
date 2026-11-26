#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Tiny UDP broadcast/multicast helper for the netns integration test.

  udp.py send  <dst> <port> <payload> <src-ip>        broadcast/multicast/unicast sender
  udp.py recv  <port> <seconds> [<group> <local-ip>]  print payloads received
  udp.py raw   <ifname> <dst-mac> <ethertype-hex> <payload>   send one raw frame
"""
import socket
import struct
import sys
import time


def send(dst, port, payload, src):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    s.bind((src, 0))
    if 224 <= int(dst.split(".")[0]) <= 239:
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(src))
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 0)
    for _ in range(3):
        s.sendto(payload.encode(), (dst, port))
        time.sleep(0.1)


def recv(port, seconds, group=None, local=None):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("", port))
    if group:
        mreq = struct.pack("4s4s", socket.inet_aton(group), socket.inet_aton(local))
        s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
    s.settimeout(0.2)
    end = time.time() + seconds
    seen = set()
    while time.time() < end:
        try:
            data, _ = s.recvfrom(2048)
        except socket.timeout:
            continue
        msg = data.decode(errors="replace")
        if msg not in seen:
            seen.add(msg)
            print(msg, flush=True)


def raw(ifname, dst_mac, ethertype, payload):
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    s.bind((ifname, 0))
    src = s.getsockname()[4]
    dst = bytes.fromhex(dst_mac.replace(":", ""))
    frame = dst + src + struct.pack("!H", int(ethertype, 16)) + payload.encode()
    frame += b"\0" * max(0, 60 - len(frame))
    for _ in range(3):
        s.send(frame)
        time.sleep(0.1)


if __name__ == "__main__":
    cmd = sys.argv[1]
    if cmd == "send":
        send(sys.argv[2], int(sys.argv[3]), sys.argv[4], sys.argv[5])
    elif cmd == "recv":
        recv(int(sys.argv[2]), float(sys.argv[3]), *(sys.argv[4:6]))
    elif cmd == "raw":
        raw(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5])
    else:
        sys.exit(__doc__)
