// SPDX-License-Identifier: Apache-2.0

package daemon

import (
	"errors"
	"strings"

	"github.com/vishvananda/netlink"
)

// NetlinkLinks implements Links with netlink in the current netns.
type NetlinkLinks struct{}

// IndexByName returns the ifindex of an interface.
func (NetlinkLinks) IndexByName(name string) (int, error) {
	l, err := netlink.LinkByName(name)
	if err != nil {
		var nf netlink.LinkNotFoundError
		if errors.As(err, &nf) {
			return 0, ErrLinkNotFound
		}
		return 0, err
	}
	return l.Attrs().Index, nil
}

// NamesWithPrefix lists veth interfaces whose name has the given prefix.
func (NetlinkLinks) NamesWithPrefix(prefix string) ([]string, error) {
	ls, err := netlink.LinkList()
	if err != nil {
		return nil, err
	}
	var out []string
	for _, l := range ls {
		if l.Type() == "veth" && strings.HasPrefix(l.Attrs().Name, prefix) {
			out = append(out, l.Attrs().Name)
		}
	}
	return out, nil
}
