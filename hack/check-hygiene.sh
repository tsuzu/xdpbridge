#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Public-release hygiene checks:
#  - every source file carries an SPDX license header
#  - BPF sources are dual-licensed GPL/BSD
#  - no IPv4 addresses outside RFC 5737 documentation ranges / loopback
#  - no globally administered (vendor) MAC addresses
set -euo pipefail
cd "$(dirname "$0")/.."
rc=0

files=$(git ls-files 2>/dev/null || find . -type f -not -path './.git/*')

for f in $(echo "$files" | grep -E '\.(go|c|h|sh|py)$|^Makefile$|^Dockerfile$|\.ya?ml$' | grep -v '_bpfel\.go$'); do
	if ! head -5 "$f" | grep -q 'SPDX-License-Identifier:'; then
		echo "missing SPDX header: $f"; rc=1
	fi
done
for f in $(echo "$files" | grep -E '^bpf/.*\.(c|h)$'); do
	head -2 "$f" | grep -q 'GPL-2.0-only OR BSD-2-Clause' || { echo "BPF source not dual-licensed: $f"; rc=1; }
done

scan=$(echo "$files" | grep -vE '^(LICENSE|go\.sum)$')
python3 - $scan <<'PY' || rc=1
import ipaddress, re, sys
ok_nets = [ipaddress.ip_network(n) for n in
           ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "127.0.0.0/8",
            "0.0.0.0/32", "224.0.0.0/4", "255.255.255.255/32")]
ip_re = re.compile(r'(?<![\w.])(\d{1,3}(?:\.\d{1,3}){3})(?![\w.])')
mac_re = re.compile(r'(?<![\w:])([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})(?![\w:])')
bad = 0
for path in sys.argv[1:]:
    try:
        text = open(path, encoding="utf-8").read()
    except (UnicodeDecodeError, FileNotFoundError, IsADirectoryError):
        continue
    for m in ip_re.finditer(text):
        try:
            ip = ipaddress.ip_address(m.group(1))
        except ValueError:
            continue
        if not any(ip in n for n in ok_nets):
            print(f"{path}: non-documentation IPv4 address {ip}"); bad = 1
    for m in mac_re.finditer(text):
        first = int(m.group(1)[:2], 16)
        # locally administered, multicast/broadcast are fine
        if not (first & 0x02 or first & 0x01):
            print(f"{path}: globally administered MAC {m.group(1)}"); bad = 1
sys.exit(bad)
PY
[ $rc = 0 ] && echo "hygiene: OK"
exit $rc
