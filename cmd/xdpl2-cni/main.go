// SPDX-License-Identifier: Apache-2.0

// Command xdpl2-cni is the xdpl2 CNI plugin. On ADD it creates a veth pair,
// moves one end into the pod, configures addresses via the delegated IPAM
// plugin and registers the host end as a switch port with the node daemon.
// If registration fails the ADD fails and everything is rolled back, so a
// pod never starts with a silently missing interface.
package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	current "github.com/containernetworking/cni/pkg/types/100"
	cniversion "github.com/containernetworking/cni/pkg/version"
	"github.com/containernetworking/plugins/pkg/ip"
	"github.com/containernetworking/plugins/pkg/ipam"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/vishvananda/netlink"

	"github.com/tsuzu/xdpl2/internal/api"
	"github.com/tsuzu/xdpl2/internal/cniconfig"
	"github.com/tsuzu/xdpl2/internal/version"
)

func main() {
	skel.PluginMainFuncs(skel.CNIFuncs{
		Add:    cmdAdd,
		Del:    cmdDel,
		Check:  cmdCheck,
		Status: cmdStatus,
	}, cniversion.All, "xdpl2 CNI plugin "+version.Version)
}

func cmdAdd(args *skel.CmdArgs) error {
	conf, k8s, err := cniconfig.Parse(args.StdinData, args.Args)
	if err != nil {
		return err
	}
	client := api.NewClient(conf.Socket, conf.Timeout())

	// Fail fast, before touching anything, if the daemon is not serving.
	if st, err := client.Status(); err != nil {
		return types.NewError(types.ErrTryAgainLater, "xdpl2 node daemon unreachable",
			fmt.Sprintf("socket %s: %v", conf.Socket, err))
	} else if !st.Ready {
		return types.NewError(types.ErrTryAgainLater, "xdpl2 data path not ready", strings.Join(st.Problems, "; "))
	}

	netns, err := ns.GetNS(args.Netns)
	if err != nil {
		return fmt.Errorf("opening netns %q: %w", args.Netns, err)
	}
	defer netns.Close()

	hostIfName := cniconfig.HostIfName(args.ContainerID, args.IfName)
	// A previous failed or interrupted ADD may have left the host veth.
	_ = ip.DelLinkByName(hostIfName)

	var hostIf, contIf net.Interface
	err = netns.Do(func(hostNS ns.NetNS) error {
		var err error
		hostIf, contIf, err = ip.SetupVethWithName(args.IfName, hostIfName, conf.MTU, conf.WantMAC(k8s), hostNS)
		if err != nil {
			return err
		}
		// XDP_REDIRECT into a veth needs NAPI on the receiving peer, which
		// the kernel enables when GRO is on.
		if err := setGRO(args.IfName, true); err != nil {
			return fmt.Errorf("enabling GRO on %s: %w", args.IfName, err)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("creating veth: %w", err)
	}

	success := false
	ipamDone := false
	defer func() {
		if success {
			return
		}
		if ipamDone {
			_ = ipam.ExecDel(conf.IPAM.Type, args.StdinData)
		}
		_ = netns.Do(func(ns.NetNS) error { return ip.DelLinkByName(args.IfName) })
		_ = ip.DelLinkByName(hostIfName)
	}()

	// The host never speaks on the port veth itself.
	_ = os.WriteFile("/proc/sys/net/ipv6/conf/"+hostIfName+"/disable_ipv6", []byte("1"), 0o644)

	result := &current.Result{CNIVersion: current.ImplementedSpecVersion}
	if conf.PrevResult != nil {
		prev, err := current.NewResultFromResult(conf.PrevResult)
		if err != nil {
			return fmt.Errorf("converting prevResult: %w", err)
		}
		result = prev
	}
	hostIdx := len(result.Interfaces)
	result.Interfaces = append(result.Interfaces,
		&current.Interface{Name: hostIf.Name, Mac: hostIf.HardwareAddr.String()},
		&current.Interface{Name: contIf.Name, Mac: contIf.HardwareAddr.String(), Sandbox: netns.Path()},
	)
	contIdx := hostIdx + 1

	var ips []string
	if conf.IPAM.Type != "" {
		r, err := ipam.ExecAdd(conf.IPAM.Type, args.StdinData)
		if err != nil {
			return fmt.Errorf("IPAM %s: %w", conf.IPAM.Type, err)
		}
		ipamDone = true
		ipamResult, err := current.NewResultFromResult(r)
		if err != nil {
			return err
		}
		if len(ipamResult.IPs) == 0 {
			return errors.New("IPAM plugin returned no IPs")
		}
		ownStart := len(result.IPs)
		for _, ipc := range ipamResult.IPs {
			i := contIdx
			ipc.Interface = &i
			result.IPs = append(result.IPs, ipc)
			ips = append(ips, ipc.Address.String())
		}
		result.Routes = append(result.Routes, ipamResult.Routes...)
		result.DNS = ipamResult.DNS
		own := &current.Result{CNIVersion: result.CNIVersion, Interfaces: result.Interfaces,
			IPs: result.IPs[ownStart:], Routes: ipamResult.Routes}
		if err := netns.Do(func(ns.NetNS) error {
			// ConfigureIface indexes Interfaces by IPConfig.Interface.
			return ipam.ConfigureIface(args.IfName, own)
		}); err != nil {
			return fmt.Errorf("configuring %s: %w", args.IfName, err)
		}
	} else {
		if err := netns.Do(func(ns.NetNS) error {
			l, err := netlink.LinkByName(args.IfName)
			if err != nil {
				return err
			}
			return netlink.LinkSetUp(l)
		}); err != nil {
			return err
		}
	}

	_, err = client.AddPort(api.PortRequest{
		ContainerID:  args.ContainerID,
		IfName:       args.IfName,
		Netns:        args.Netns,
		HostIfName:   hostIf.Name,
		MAC:          contIf.HardwareAddr.String(),
		VLAN:         uint16(conf.VLAN),
		IPs:          ips,
		PodNamespace: string(k8s.K8S_POD_NAMESPACE),
		PodName:      string(k8s.K8S_POD_NAME),
		Network:      conf.Name,
	})
	if err != nil {
		return types.NewError(types.ErrInternal, "xdpl2 port registration failed",
			fmt.Sprintf("daemon at %s: %v", conf.Socket, err))
	}

	// Announce the new MAC/IP binding (best effort) so LAN neighbours and the
	// host update stale ARP entries.
	_ = netns.Do(func(ns.NetNS) error { return gratuitousARP(args.IfName, ips) })

	success = true
	return types.PrintResult(result, conf.CNIVersion)
}

func cmdDel(args *skel.CmdArgs) error {
	conf, _, err := cniconfig.Parse(args.StdinData, args.Args)
	if err != nil {
		return err
	}
	client := api.NewClient(conf.Socket, conf.Timeout())
	// DEL must succeed even if the daemon is down; its reconciler removes
	// ports whose veth disappeared.
	if err := client.DeletePort(args.ContainerID, args.IfName); err != nil {
		fmt.Fprintf(os.Stderr, "xdpl2: unregistering port (continuing, daemon will garbage-collect): %v\n", err)
	}
	if conf.IPAM.Type != "" {
		if err := ipam.ExecDel(conf.IPAM.Type, args.StdinData); err != nil {
			return fmt.Errorf("IPAM %s DEL: %w", conf.IPAM.Type, err)
		}
	}
	if args.Netns != "" {
		err := ns.WithNetNSPath(args.Netns, func(ns.NetNS) error {
			if err := ip.DelLinkByName(args.IfName); err != nil && !errors.Is(err, ip.ErrLinkNotFound) {
				return err
			}
			return nil
		})
		var nsErr ns.NSPathNotExistErr
		if err != nil && !errors.As(err, &nsErr) {
			return err
		}
	}
	if err := ip.DelLinkByName(cniconfig.HostIfName(args.ContainerID, args.IfName)); err != nil && !errors.Is(err, ip.ErrLinkNotFound) {
		return err
	}
	return nil
}

func cmdCheck(args *skel.CmdArgs) error {
	conf, _, err := cniconfig.Parse(args.StdinData, args.Args)
	if err != nil {
		return err
	}
	if conf.PrevResult == nil {
		return errors.New("CHECK requires prevResult")
	}
	result, err := current.NewResultFromResult(conf.PrevResult)
	if err != nil {
		return err
	}
	if conf.IPAM.Type != "" {
		if err := ipam.ExecCheck(conf.IPAM.Type, args.StdinData); err != nil {
			return err
		}
	}
	var contIf *current.Interface
	for _, i := range result.Interfaces {
		if i.Name == args.IfName && i.Sandbox == args.Netns {
			contIf = i
		}
	}
	if contIf == nil {
		return fmt.Errorf("prevResult has no interface %s in %s", args.IfName, args.Netns)
	}

	port, err := api.NewClient(conf.Socket, conf.Timeout()).GetPort(args.ContainerID, args.IfName)
	if err != nil {
		return fmt.Errorf("daemon has no registration for %s/%s: %w", args.ContainerID, args.IfName, err)
	}
	if !strings.EqualFold(port.MAC, contIf.Mac) {
		return fmt.Errorf("registered MAC %s != interface MAC %s", port.MAC, contIf.Mac)
	}
	if port.Health != "" && port.Health != "ok" {
		return fmt.Errorf("port unhealthy: %s", port.Health)
	}
	if _, err := netlink.LinkByName(port.HostIfName); err != nil {
		return fmt.Errorf("host veth %s: %w", port.HostIfName, err)
	}

	return ns.WithNetNSPath(args.Netns, func(ns.NetNS) error {
		l, err := netlink.LinkByName(args.IfName)
		if err != nil {
			return err
		}
		if !strings.EqualFold(l.Attrs().HardwareAddr.String(), contIf.Mac) {
			return fmt.Errorf("%s MAC %s != %s", args.IfName, l.Attrs().HardwareAddr, contIf.Mac)
		}
		if err := ip.ValidateExpectedInterfaceIPs(args.IfName, result.IPs); err != nil {
			return err
		}
		return ip.ValidateExpectedRoute(result.Routes)
	})
}

// cmdStatus implements CNI 1.1 STATUS: the network is ready when the daemon
// is reachable and healthy.
func cmdStatus(args *skel.CmdArgs) error {
	conf, _, err := cniconfig.Parse(args.StdinData, "")
	if err != nil {
		return err
	}
	st, err := api.NewClient(conf.Socket, conf.Timeout()).Status()
	if err != nil {
		return types.NewError(errPluginNotAvailable, "xdpl2 node daemon unreachable", err.Error())
	}
	if !st.Ready {
		return types.NewError(errPluginNotAvailable, "xdpl2 data path not ready", strings.Join(st.Problems, "; "))
	}
	return nil
}

// errPluginNotAvailable is CNI spec error code 50 (STATUS: plugin not ready).
const errPluginNotAvailable uint = 50
