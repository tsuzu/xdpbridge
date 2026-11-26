// SPDX-License-Identifier: Apache-2.0

// Package deploy holds the Kubernetes manifests. This test lints them
// offline: every document must parse, carry apiVersion/kind/name, embedded
// CNI configs must be valid JSON for the xdpl2 plugin, and every IPv4 address
// must be an RFC 5737 documentation address (or loopback).
package deploy

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func manifestFiles(t *testing.T) []string {
	t.Helper()
	var files []string
	for _, pat := range []string{"*.yaml", "examples/*.yaml"} {
		m, err := filepath.Glob(pat)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, m...)
	}
	if len(files) == 0 {
		t.Fatal("no manifests found")
	}
	return files
}

type doc struct {
	APIVersion string `yaml:"apiVersion"`
	Kind       string `yaml:"kind"`
	Metadata   struct {
		Name string `yaml:"name"`
	} `yaml:"metadata"`
	Spec struct {
		Config string `yaml:"config"`
	} `yaml:"spec"`
	Resources []string `yaml:"resources"`
}

func TestManifestsParse(t *testing.T) {
	for _, f := range manifestFiles(t) {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		dec := yaml.NewDecoder(bytes.NewReader(b))
		n := 0
		for {
			var d doc
			err := dec.Decode(&d)
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				t.Fatalf("%s: %v", f, err)
			}
			n++
			if d.APIVersion == "" || d.Kind == "" {
				t.Errorf("%s doc %d: missing apiVersion/kind", f, n)
			}
			if d.Kind == "Kustomization" {
				for _, r := range d.Resources {
					if _, err := os.Stat(r); err != nil {
						t.Errorf("%s: resource %s: %v", f, r, err)
					}
				}
				continue
			}
			if d.Metadata.Name == "" {
				t.Errorf("%s doc %d (%s): missing metadata.name", f, n, d.Kind)
			}
			if d.Kind == "NetworkAttachmentDefinition" {
				checkCNIConfig(t, f, d.Spec.Config)
			}
		}
		if n == 0 {
			t.Errorf("%s: no documents", f)
		}
	}
}

func checkCNIConfig(t *testing.T, f, cfg string) {
	var c struct {
		CNIVersion string           `json:"cniVersion"`
		Name       string           `json:"name"`
		Type       string           `json:"type"`
		Plugins    []map[string]any `json:"plugins"`
	}
	if err := json.Unmarshal([]byte(cfg), &c); err != nil {
		t.Errorf("%s: NAD config is not valid JSON: %v", f, err)
		return
	}
	if c.CNIVersion == "" || c.Name == "" {
		t.Errorf("%s: NAD config needs cniVersion and name", f)
	}
	found := c.Type == "xdpl2"
	for _, p := range c.Plugins {
		if p["type"] == "xdpl2" {
			found = true
		}
	}
	if !found {
		t.Errorf("%s: NAD config does not use the xdpl2 plugin", f)
	}
}

var (
	ipRe  = regexp.MustCompile(`\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b`)
	macRe = regexp.MustCompile(`\b([0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5})\b`)
	docs  = []string{"192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "127.0.0.0/8"}
)

// TestNoEnvironmentData enforces the public-release rule: only
// documentation addresses and locally administered MACs in manifests.
func TestNoEnvironmentData(t *testing.T) {
	var nets []*net.IPNet
	for _, c := range docs {
		_, n, _ := net.ParseCIDR(c)
		nets = append(nets, n)
	}
	for _, f := range manifestFiles(t) {
		b, _ := os.ReadFile(f)
		for _, m := range ipRe.FindAllString(string(b), -1) {
			ip := net.ParseIP(m)
			if ip == nil {
				continue
			}
			ok := ip.IsUnspecified()
			for _, n := range nets {
				ok = ok || n.Contains(ip)
			}
			if !ok {
				t.Errorf("%s: address %s is not an RFC 5737 documentation address", f, m)
			}
		}
		for _, m := range macRe.FindAllString(string(b), -1) {
			hw, err := net.ParseMAC(m)
			if err != nil || hw[0]&0x02 == 0 {
				t.Errorf("%s: MAC %s is not locally administered", f, m)
			}
		}
		if strings.Contains(strings.ToLower(string(b)), "password") {
			t.Errorf("%s: contains the word password", f)
		}
	}
}
