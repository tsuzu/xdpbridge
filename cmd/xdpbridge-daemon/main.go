// SPDX-License-Identifier: Apache-2.0

// Command xdpbridge-daemon is the xdpbridge node daemon. It owns the uplink XDP hook
// and the forwarding maps, replicates flood traffic and serves the CNI
// plugin on a unix socket.
//
// Usage:
//
//	xdpbridge-daemon [flags]          run the daemon
//	xdpbridge-daemon status [flags]   print daemon status (JSON)
//	xdpbridge-daemon ports [flags]    list registered ports (JSON)
//	xdpbridge-daemon teardown [flags] detach programs and remove all pins
//	xdpbridge-daemon install-cni --src <file> --dest <dir>
//	                              copy the CNI plugin binary atomically
//	                              (used by the DaemonSet init container)
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/vishvananda/netlink"

	"github.com/tsuzu/xdpbridge/internal/api"
	"github.com/tsuzu/xdpbridge/internal/daemon"
	"github.com/tsuzu/xdpbridge/internal/datapath"
	"github.com/tsuzu/xdpbridge/internal/flood"
	"github.com/tsuzu/xdpbridge/internal/k8swatch"
	"github.com/tsuzu/xdpbridge/internal/version"
)

type options struct {
	uplink, bpffs, socket, stateFile, xdpMode, probeAddr, logLevel, logFormat string
	installSrc, installDest                                                   string
	nodeName                                                                  string
	force                                                                     bool
	k8sWatch                                                                  bool
	k8sGrace                                                                  time.Duration
	forceXDP                                                                  bool
	reconcile                                                                 time.Duration
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func parseFlags(fs *flag.FlagSet, args []string) (*options, error) {
	o := &options{}
	fs.StringVar(&o.uplink, "uplink", envOr("XDPBRIDGE_UPLINK", ""), "uplink interface: a name, a comma-separated list (first existing wins), or \"default-route\" [XDPBRIDGE_UPLINK]")
	fs.StringVar(&o.bpffs, "bpffs", envOr("XDPBRIDGE_BPFFS", "/sys/fs/bpf/xdpbridge"), "bpffs directory for pinned maps and links [XDPBRIDGE_BPFFS]")
	fs.StringVar(&o.socket, "socket", envOr("XDPBRIDGE_SOCKET", api.DefaultSocket), "unix socket for the API [XDPBRIDGE_SOCKET]")
	fs.StringVar(&o.stateFile, "state-file", envOr("XDPBRIDGE_STATE_FILE", "/var/lib/xdpbridge/state.json"), "port registration state file [XDPBRIDGE_STATE_FILE]")
	fs.StringVar(&o.xdpMode, "xdp-mode", envOr("XDPBRIDGE_XDP_MODE", "auto"), "XDP attach mode: auto, native or generic [XDPBRIDGE_XDP_MODE]")
	fs.BoolVar(&o.forceXDP, "force-xdp", os.Getenv("XDPBRIDGE_FORCE_XDP") == "true", "replace a foreign XDP program on the uplink [XDPBRIDGE_FORCE_XDP]")
	fs.StringVar(&o.probeAddr, "probe-addr", envOr("XDPBRIDGE_PROBE_ADDR", "127.0.0.1:9967"), "TCP address for /healthz, /livez, /metrics (empty disables) [XDPBRIDGE_PROBE_ADDR]")
	fs.BoolVar(&o.k8sWatch, "k8s-watch", os.Getenv("XDPBRIDGE_K8S_WATCH") == "true", "cross-check registrations against pods on this node via the Kubernetes API (needs a ServiceAccount token) [XDPBRIDGE_K8S_WATCH]")
	fs.StringVar(&o.nodeName, "node-name", envOr("XDPBRIDGE_NODE_NAME", ""), "this node's Kubernetes name, for --k8s-watch [XDPBRIDGE_NODE_NAME]")
	fs.DurationVar(&o.k8sGrace, "k8s-grace", time.Minute, "how long a pod may run without its port (or a port exist without its pod) before it is reported")
	fs.BoolVar(&o.force, "force", false, "teardown: proceed even if a daemon answers on --socket")
	fs.StringVar(&o.installSrc, "src", "/usr/local/bin/xdpbridge-cni", "install-cni: plugin binary to copy")
	fs.StringVar(&o.installDest, "dest", envOr("XDPBRIDGE_CNI_BIN_DIR", "/host/opt/cni/bin"), "install-cni: CNI bin directory as mounted in the container [XDPBRIDGE_CNI_BIN_DIR]")
	fs.DurationVar(&o.reconcile, "reconcile-interval", 10*time.Second, "reconciliation interval")
	fs.StringVar(&o.logLevel, "log-level", envOr("XDPBRIDGE_LOG_LEVEL", "info"), "debug, info, warn, error [XDPBRIDGE_LOG_LEVEL]")
	fs.StringVar(&o.logFormat, "log-format", envOr("XDPBRIDGE_LOG_FORMAT", "json"), "json or text [XDPBRIDGE_LOG_FORMAT]")
	return o, fs.Parse(args)
}

func newLogger(o *options) *slog.Logger {
	var lvl slog.Level
	if err := lvl.UnmarshalText([]byte(o.logLevel)); err != nil {
		lvl = slog.LevelInfo
	}
	hopts := &slog.HandlerOptions{Level: lvl}
	if o.logFormat == "text" {
		return slog.New(slog.NewTextHandler(os.Stderr, hopts))
	}
	return slog.New(slog.NewJSONHandler(os.Stderr, hopts))
}

func main() {
	args := os.Args[1:]
	cmd := "run"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		cmd, args = args[0], args[1:]
	}
	fs := flag.NewFlagSet("xdpbridge-daemon "+cmd, flag.ExitOnError)
	o, _ := parseFlags(fs, args)

	var err error
	switch cmd {
	case "run":
		err = run(o)
	case "status":
		err = printJSON(func(c *api.Client) (any, error) { return c.Status() }, o)
	case "ports":
		err = printJSON(func(c *api.Client) (any, error) { return c.ListPorts() }, o)
	case "teardown":
		err = teardown(o)
	case "install-cni":
		err = installCNI(o.installSrc, o.installDest)
	case "version":
		fmt.Println(version.Version)
	default:
		err = fmt.Errorf("unknown command %q", cmd)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "xdpbridge-daemon:", err)
		os.Exit(1)
	}
}

func printJSON(f func(*api.Client) (any, error), o *options) error {
	v, err := f(api.NewClient(o.socket, 5*time.Second))
	if err != nil {
		return err
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// restoreFile is where the uplink's pre-xdpbridge settings are recorded.
func restoreFile(o *options) string {
	if o.stateFile == "" {
		return ""
	}
	return filepath.Join(filepath.Dir(o.stateFile), "uplink-restore.json")
}

// teardown removes the data path from the node. Stopping the daemon does
// not (by design, so that restarts are hitless); this does.
func teardown(o *options) error {
	if !o.force {
		if _, err := api.NewClient(o.socket, 2*time.Second).Status(); err == nil {
			return fmt.Errorf("a daemon is serving on %s; stop it first (or pass --force)", o.socket)
		}
	}
	rep, err := datapath.Teardown(o.bpffs, restoreFile(o))
	if rep != nil {
		for _, a := range rep.Actions {
			fmt.Println("teardown:", a)
		}
		for _, w := range rep.Warnings {
			fmt.Fprintln(os.Stderr, "teardown: WARNING:", w)
		}
	}
	if err != nil {
		return err
	}
	if o.stateFile != "" {
		if err := os.Remove(o.stateFile); err == nil {
			fmt.Println("teardown: removed port state", o.stateFile)
		}
	}
	if rep != nil && len(rep.Warnings) > 0 {
		return errors.New("teardown finished with warnings")
	}
	fmt.Println("teardown: done")
	return nil
}

func installCNI(src, destDir string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(destDir, ".xdpbridge-cni-")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := io.Copy(tmp, in); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o755); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	// rename(2) is atomic: kubelet never executes a half-written plugin.
	if err := os.Rename(tmp.Name(), filepath.Join(destDir, "xdpbridge")); err != nil {
		return err
	}
	fmt.Println("installed", filepath.Join(destDir, "xdpbridge"))
	return nil
}

// resolveUplink implements the --uplink selector.
func resolveUplink(sel string) (string, error) {
	if sel == "" {
		return "", errors.New("--uplink is required")
	}
	if sel == "default-route" {
		routes, err := netlink.RouteList(nil, netlink.FAMILY_V4)
		if err != nil {
			return "", err
		}
		for _, r := range routes {
			if r.Dst == nil || r.Dst.String() == "0.0.0.0/0" {
				l, err := netlink.LinkByIndex(r.LinkIndex)
				if err == nil {
					return l.Attrs().Name, nil
				}
			}
		}
		return "", errors.New("no IPv4 default route found")
	}
	for _, name := range strings.Split(sel, ",") {
		name = strings.TrimSpace(name)
		if _, err := netlink.LinkByName(name); err == nil {
			return name, nil
		}
	}
	return "", fmt.Errorf("none of the uplink candidates %q exist", sel)
}

func run(o *options) error {
	log := newLogger(o)
	slog.SetDefault(log)

	mode, err := datapath.ParseXDPMode(o.xdpMode)
	if err != nil {
		return err
	}
	uplink, err := resolveUplink(o.uplink)
	if err != nil {
		return err
	}
	log.Info("starting xdpbridge-daemon", "version", version.Version, "uplink", uplink, "bpffs", o.bpffs, "xdp_mode", mode)

	dp, err := datapath.Open(datapath.Options{
		Uplink: uplink, PinDir: o.bpffs, Mode: mode, ForceXDP: o.forceXDP, Logger: log,
		RestoreFile: restoreFile(o),
	})
	if err != nil {
		return err
	}
	defer dp.Close()

	ctx, cancelWatch := context.WithCancel(context.Background())
	defer cancelWatch()
	var k8s daemon.K8sSource
	if o.k8sWatch {
		w, err := k8swatch.New(k8swatch.Config{NodeName: o.nodeName, PluginType: "xdpbridge", Logger: log})
		if err != nil {
			return err
		}
		go w.Run(ctx)
		k8s = w
		log.Info("Kubernetes-API watchdog enabled", "node", o.nodeName)
	}

	var rep *flood.Replicator
	srv := daemon.New(daemon.Config{
		K8s:          k8s,
		NodeName:     o.nodeName,
		K8sGrace:     o.k8sGrace,
		Uplink:       uplink,
		StateFile:    o.stateFile,
		Logger:       log,
		FloodRunning: func() bool { return rep != nil && rep.Running() },
		FloodCounters: func() map[string]uint64 {
			if rep == nil {
				return nil
			}
			return map[string]uint64{
				"events":       rep.Counters.Events.Load(),
				"tx_frames":    rep.Counters.TxFrames.Load(),
				"tx_errors":    rep.Counters.TxErrors.Load(),
				"tx_port_gone": rep.Counters.TxPortGone.Load(),
				"parse_errors": rep.Counters.ParseErrors.Load(),
			}
		},
	}, dp, daemon.NetlinkLinks{})

	if err := srv.Restore(); err != nil {
		return fmt.Errorf("restoring state: %w", err)
	}

	rep, err = flood.New(dp.FloodRing(), dp.UplinkIndex(), srv.FloodPorts, log)
	if err != nil {
		return err
	}
	go rep.Run()
	defer rep.Close()

	if err := os.MkdirAll(filepath.Dir(o.socket), 0o755); err != nil {
		return err
	}
	_ = os.Remove(o.socket)
	ln, err := net.Listen("unix", o.socket)
	if err != nil {
		return fmt.Errorf("listening on %s: %w", o.socket, err)
	}
	if err := os.Chmod(o.socket, 0o600); err != nil {
		return err
	}
	apiSrv := &http.Server{Handler: srv.APIHandler(), ReadHeaderTimeout: 5 * time.Second}
	go func() {
		if err := apiSrv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("API server failed", "err", err)
		}
	}()

	var probeSrv *http.Server
	if o.probeAddr != "" {
		probeSrv = &http.Server{Addr: o.probeAddr, Handler: srv.ProbeHandler(), ReadHeaderTimeout: 5 * time.Second}
		go func() {
			if err := probeSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Error("probe server failed", "err", err)
			}
		}()
	}

	stop := make(chan struct{})
	// Initial pass right away so problems surface before the first tick.
	time.Sleep(100 * time.Millisecond)
	srv.Reconcile()
	go srv.RunReconciler(o.reconcile, stop)

	log.Info("ready", "socket", o.socket, "probe_addr", o.probeAddr, "xdp_mode", dp.Mode())

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	s := <-sig
	log.Info("shutting down; pinned data path stays in place", "signal", s.String())
	close(stop)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = apiSrv.Shutdown(ctx)
	if probeSrv != nil {
		_ = probeSrv.Shutdown(ctx)
	}
	_ = os.Remove(o.socket)
	return nil
}
