package main

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/sagernet/tailscale/ipn/ipnstate"
	"github.com/sagernet/tailscale/types/key"
)

var local = netip.MustParseAddr("192.0.2.7")
var node = netip.MustParseAddr("100.101.102.103")
var web = netip.MustParseAddr("203.0.113.11")

func datagram(proto byte, src, dst netip.Addr, sp, dp uint16) []byte {
	n := 40
	b := make([]byte, n)
	b[0] = 0x45
	b[8] = 64
	b[9] = proto
	binary.BigEndian.PutUint16(b[2:], uint16(n))
	copy(b[12:16], src.AsSlice())
	copy(b[16:20], dst.AsSlice())
	binary.BigEndian.PutUint16(b[20:], sp)
	binary.BigEndian.PutUint16(b[22:], dp)
	if proto == 6 {
		b[32] = 0x50
		b[33] = 0x10
	} else {
		binary.BigEndian.PutUint16(b[24:], uint16(n-20))
	}
	return b
}

func TestPacketPath(t *testing.T) {
	for _, proto := range []byte{6, 17} {
		var from, to bytes.Buffer
		d := newDevice(local, &from, &to)
		out := datagram(proto, local, web, 50000, 443)
		if d.translate(bytes.Clone(out), true) {
			t.Fatal("forwarding before exit selection")
		}
		d.setAddress(node)
		if d.translate(datagram(proto, web, node, 443, 50000), false) {
			t.Fatal("unsolicited incoming flow")
		}
		from.Write([]byte{0, byte(len(out))})
		from.Write(out)
		go d.pump()
		bufs := [][]byte{make([]byte, 128)}
		sizes := []int{0}
		if n, err := d.Read(bufs, sizes, 8); err != nil || n != 1 || sizes[0] != len(out) || !bytes.Equal(bufs[0][20:24], node.AsSlice()) {
			t.Fatal(n, err, "outgoing address or frame")
		}
		reply := datagram(proto, web, node, 443, 50000)
		if _, err := d.Write([][]byte{reply}, 0); err != nil || to.Len() != len(reply)+2 || !bytes.Equal(to.Bytes()[18:22], local.AsSlice()) {
			t.Fatal(err, "reply did not return to original address")
		}
		if d.translate(datagram(proto, web, node, 444, 50000), false) {
			t.Fatal("wrong remote port accepted")
		}
		d.setAddress(netip.Addr{})
		d.setAddress(node)
		if d.translate(datagram(proto, web, node, 443, 50000), false) {
			t.Fatal("old flow survived revocation")
		}
		for _, addr := range []string{"100.64.0.1", "10.0.0.1", "127.0.0.1", "224.0.0.1"} {
			if d.translate(datagram(proto, local, netip.MustParseAddr(addr), 42, 443), true) {
				t.Fatal("non-public target", addr)
			}
		}
		d.Close()
	}
}

func TestExactApprovedOnlineExit(t *testing.T) {
	peer := &ipnstate.PeerStatus{TailscaleIPs: []netip.Addr{node}, Online: true, ExitNodeOption: true}
	status := &ipnstate.Status{Peer: map[key.NodePublic]*ipnstate.PeerStatus{{}: peer}}
	if exitPeer(status, node) != peer || exitPeer(status, web) != nil {
		t.Fatal("incorrect peer selection")
	}
	peer.ExitNodeOption = false
	if exitPeer(status, node) != nil {
		t.Fatal("unapproved peer selected")
	}
	peer.ExitNodeOption = true
	peer.Online = false
	if exitPeer(status, node) != nil {
		t.Fatal("offline peer selected")
	}
}
