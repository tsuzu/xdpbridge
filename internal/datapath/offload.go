// SPDX-License-Identifier: Apache-2.0

package datapath

import (
	"github.com/safchain/ethtool"
)

// vlanOffloadFeatures must be off on the uplink: with hardware VLAN
// stripping the 802.1Q tag is moved into packet metadata before XDP runs, so
// the program could not see which VLAN a frame belongs to; hardware VLAN
// filtering would drop tags without a host VLAN device.
var vlanOffloadFeatures = []string{"rx-vlan-hw-parse", "rx-vlan-filter", "rx-vlan-stag-hw-parse", "rx-vlan-stag-filter"}

// disableVLANOffload turns off the features above where the driver allows it
// and returns those that stay on.
func disableVLANOffload(ifName string) (stillOn []string, err error) {
	e, err := ethtool.NewEthtool()
	if err != nil {
		return nil, err
	}
	defer e.Close()
	feats, err := e.FeaturesWithState(ifName)
	if err != nil {
		return nil, err
	}
	for _, f := range vlanOffloadFeatures {
		st, ok := feats[f]
		if !ok || !st.Active {
			continue
		}
		if !st.Available { // fixed by the driver
			stillOn = append(stillOn, f)
			continue
		}
		if err := e.Change(ifName, map[string]bool{f: false}); err != nil {
			stillOn = append(stillOn, f)
		}
	}
	return stillOn, nil
}
