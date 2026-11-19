// The helper exchanges selected IPv4 packets with its parent over inherited
// pipes. It owns a separate tailnet identity for this candidate exit.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/sagernet/tailscale/ipn"
	"github.com/sagernet/tailscale/ipn/ipnstate"
	"github.com/sagernet/tailscale/net/dns"
	"github.com/sagernet/tailscale/tsnet"
	"github.com/sagernet/tailscale/wgengine/router"
)

var tailnet = netip.MustParsePrefix("100.64.0.0/10")

type statusMessage struct {
	State  string `json:"state"`
	Detail string `json:"detail,omitempty"`
}

func report(state, detail string) {
	_ = json.NewEncoder(os.Stderr).Encode(statusMessage{state, detail})
}

func exitPeer(status *ipnstate.Status, requested netip.Addr) *ipnstate.PeerStatus {
	for _, peer := range status.Peer {
		if peer != nil && peer.Online && peer.ExitNodeOption && slices.Contains(peer.TailscaleIPs, requested) {
			return peer
		}
	}
	return nil
}

func run() error {
	if len(os.Args) != 5 {
		return errors.New("expected state directory, exit IPv4, local IPv4 and parent PID")
	}
	exit, err := netip.ParseAddr(os.Args[2])
	if err != nil || !tailnet.Contains(exit) {
		return errors.New("invalid Tailscale exit IPv4")
	}
	localIP, err := netip.ParseAddr(os.Args[3])
	if err != nil || !localIP.Is4() {
		return errors.New("invalid local IPv4")
	}
	pid, err := strconv.Atoi(os.Args[4])
	if err != nil || pid <= 0 {
		return errors.New("invalid parent PID")
	}
	parent, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	go func() { _, _ = parent.Wait(); os.Exit(0) }()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dev := newDevice(localIP, os.Stdin, os.Stdout)
	// Read stdin even while login is pending. EOF means the parent has exited.
	go func() { dev.pump(); cancel() }()
	quiet := func(string, ...any) {}
	dnsConfig, err := dns.NewNoopManager()
	if err != nil {
		return err
	}
	server := &tsnet.Server{Dir: os.Args[1], Hostname: "ai-egress-" + strings.ReplaceAll(exit.String(), ".", "-"), Tun: dev, Router: router.NewFake(quiet), DNS: dnsConfig, Logf: quiet, UserLogf: quiet}
	client, err := server.LocalClient()
	if err != nil {
		return err
	}
	defer server.Close()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	// Only this private LocalClient is ever used to select an exit.
	var last statusMessage
	var configured bool
	for {
		lookup, stop := context.WithTimeout(ctx, 4*time.Second)
		status, err := client.Status(lookup)
		stop()
		msg := statusMessage{State: "waiting"}
		var address netip.Addr
		if err == nil && status.BackendState == "Running" {
			peer := exitPeer(status, exit)
			if peer == nil {
				msg = statusMessage{"offline", "出口节点未获批准或当前离线"}
			} else {
				if !configured {
					prefs := ipn.MaskedPrefs{ExitNodeIDSet: true, ExitNodeIPSet: true, ExitNodeAllowLANAccessSet: true, CorpDNSSet: true, RouteAllSet: true, Prefs: ipn.Prefs{ExitNodeID: peer.ID}}
					edit, done := context.WithTimeout(ctx, 4*time.Second)
					_, err = client.EditPrefs(edit, &prefs)
					done()
					if err != nil {
						return fmt.Errorf("select exit: %w", err)
					}
					configured = true
				}
				if e := status.ExitNodeStatus; e != nil && e.Online && e.ID == peer.ID && peer.ExitNode {
					for _, a := range status.TailscaleIPs {
						if tailnet.Contains(a) {
							address = a
							break
						}
					}
					if address.IsValid() {
						msg = statusMessage{"ready", ""}
					}
				}
			}
		} else if err == nil && status.AuthURL != "" {
			msg = statusMessage{"login", status.AuthURL}
		}
		dev.setAddress(address)
		// Ready heartbeats let the parent close forwarding if this process stalls.
		if msg != last || msg.State == "ready" {
			report(msg.State, msg.Detail)
			last = msg
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

func main() {
	if err := run(); err != nil {
		report("error", err.Error())
		os.Exit(1)
	}
}
