// SPDX-License-Identifier: Apache-2.0

package cniconfig

import (
	"strings"
	"testing"

	"github.com/tsuzu/xdpl2/internal/api"
)

func TestParseDefaults(t *testing.T) {
	conf, _, err := Parse([]byte(`{"cniVersion":"1.0.0","name":"lan","type":"xdpl2"}`), "")
	if err != nil {
		t.Fatal(err)
	}
	if conf.Socket != api.DefaultSocket {
		t.Errorf("socket = %q, want default", conf.Socket)
	}
	if conf.TimeoutSeconds != 10 || conf.VLAN != 0 || conf.MTU != 0 {
		t.Errorf("unexpected defaults: %+v", conf)
	}
}

func TestParseFull(t *testing.T) {
	in := `{
	  "cniVersion": "1.0.0", "name": "lan", "type": "xdpl2",
	  "socket": "/tmp/x.sock", "vlan": 100, "mtu": 1400, "timeoutSeconds": 3,
	  "ipam": {"type": "host-local", "ranges": [[{"subnet": "192.0.2.0/24"}]]}
	}`
	conf, _, err := Parse([]byte(in), "")
	if err != nil {
		t.Fatal(err)
	}
	if conf.Socket != "/tmp/x.sock" || conf.VLAN != 100 || conf.MTU != 1400 || conf.IPAM.Type != "host-local" {
		t.Errorf("bad parse: %+v", conf)
	}
	if conf.Timeout().Seconds() != 3 {
		t.Errorf("timeout = %v", conf.Timeout())
	}
}

func TestParseErrors(t *testing.T) {
	cases := map[string]string{
		"bad json":      `{`,
		"vlan too big":  `{"cniVersion":"1.0.0","name":"n","type":"xdpl2","vlan":4095}`,
		"vlan negative": `{"cniVersion":"1.0.0","name":"n","type":"xdpl2","vlan":-1}`,
		"mtu too small": `{"cniVersion":"1.0.0","name":"n","type":"xdpl2","mtu":10}`,
		"bad mac":       `{"cniVersion":"1.0.0","name":"n","type":"xdpl2","runtimeConfig":{"mac":"zz"}}`,
		"multicast mac": `{"cniVersion":"1.0.0","name":"n","type":"xdpl2","runtimeConfig":{"mac":"01:00:5e:00:00:01"}}`,
		"timeout":       `{"cniVersion":"1.0.0","name":"n","type":"xdpl2","timeoutSeconds":-2}`,
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			if _, _, err := Parse([]byte(in), ""); err == nil {
				t.Fatalf("expected error for %s", in)
			}
		})
	}
}

func TestMACPrecedence(t *testing.T) {
	base := `{"cniVersion":"1.0.0","name":"n","type":"xdpl2","mac":"02:00:00:00:00:04"`
	tests := []struct {
		conf, args, want string
	}{
		{base + `}`, "", "02:00:00:00:00:04"},
		{base + `}`, "IgnoreUnknown=1;MAC=02:00:00:00:00:03", "02:00:00:00:00:03"},
		{base + `,"args":{"cni":{"mac":"02:00:00:00:00:02"}}}`, "MAC=02:00:00:00:00:03", "02:00:00:00:00:02"},
		{base + `,"args":{"cni":{"mac":"02:00:00:00:00:02"}},"runtimeConfig":{"mac":"02:00:00:00:00:01"}}`, "", "02:00:00:00:00:01"},
	}
	for _, tt := range tests {
		conf, k8s, err := Parse([]byte(tt.conf), tt.args)
		if err != nil {
			t.Fatal(err)
		}
		if got := conf.WantMAC(k8s); got != tt.want {
			t.Errorf("WantMAC = %q, want %q (conf %s, args %s)", got, tt.want, tt.conf, tt.args)
		}
	}
}

func TestK8sArgs(t *testing.T) {
	_, k8s, err := Parse([]byte(`{"cniVersion":"1.0.0","name":"n","type":"xdpl2"}`),
		"IgnoreUnknown=1;K8S_POD_NAMESPACE=default;K8S_POD_NAME=web-0;K8S_POD_UID=abc")
	if err != nil {
		t.Fatal(err)
	}
	if k8s.K8S_POD_NAMESPACE != "default" || k8s.K8S_POD_NAME != "web-0" {
		t.Errorf("k8s args: %+v", k8s)
	}
}

func TestPrevResult(t *testing.T) {
	in := `{"cniVersion":"1.0.0","name":"n","type":"xdpl2",
	  "prevResult":{"cniVersion":"1.0.0","interfaces":[{"name":"eth1","mac":"02:00:00:00:00:01","sandbox":"/run/netns/x"}],
	  "ips":[{"address":"192.0.2.10/24","interface":0}]}}`
	conf, _, err := Parse([]byte(in), "")
	if err != nil {
		t.Fatal(err)
	}
	if conf.PrevResult == nil {
		t.Fatal("prevResult not parsed")
	}
}

func TestHostIfName(t *testing.T) {
	a := HostIfName("0123456789abcdef", "eth1")
	b := HostIfName("0123456789abcdef", "eth2")
	if a == b {
		t.Error("names must differ per interface")
	}
	if len(a) > 15 {
		t.Errorf("%q longer than IFNAMSIZ-1", a)
	}
	if !strings.HasPrefix(a, api.HostIfPrefix) {
		t.Errorf("%q lacks prefix", a)
	}
	if a != HostIfName("0123456789abcdef", "eth1") {
		t.Error("not deterministic")
	}
}
