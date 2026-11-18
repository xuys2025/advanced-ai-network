package main

import (
	"encoding/binary"
	"io"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/sagernet/tailscale/net/packet"
	"github.com/sagernet/tailscale/net/packet/checksum"
	"github.com/sagernet/tailscale/types/ipproto"
	"github.com/sagernet/wireguard-go/tun"
)

// The private TUN has no Windows interface. Only packets read from the
// gateway pipe can enter it. Replies must match a recently forwarded tuple.
type flow struct {
	protocol ipproto.Proto
	remote   netip.AddrPort
	port     uint16
}
type device struct {
	local     netip.Addr
	input     io.Reader
	output    io.Writer
	inbound   chan []byte
	events    chan tun.Event
	closed    chan struct{}
	once      sync.Once
	mu        sync.Mutex
	address   netip.Addr
	flows     map[flow]time.Time
	nextSweep time.Time
	writeMu   sync.Mutex
}

func newDevice(local netip.Addr, input io.Reader, output io.Writer) *device {
	d := &device{local: local, input: input, output: output, inbound: make(chan []byte, 32), events: make(chan tun.Event, 1), closed: make(chan struct{}), flows: make(map[flow]time.Time)}
	d.events <- tun.EventUp
	return d
}
func (d *device) setAddress(addr netip.Addr) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if addr != d.address {
		clear(d.flows)
		d.address = addr
	}
}
func (d *device) pump() {
	defer close(d.inbound)
	var hdr [2]byte
	for {
		if _, err := io.ReadFull(d.input, hdr[:]); err != nil {
			return
		}
		n := binary.BigEndian.Uint16(hdr[:])
		if n < 20 {
			return
		}
		b := make([]byte, n)
		if _, err := io.ReadFull(d.input, b); err != nil {
			return
		}
		select {
		case d.inbound <- b:
		case <-d.closed:
			return
		}
	}
}
func (d *device) translate(b []byte, out bool) bool {
	if len(b) < 20 || b[0]>>4 != 4 || int(binary.BigEndian.Uint16(b[2:4])) != len(b) || binary.BigEndian.Uint16(b[6:8])&0x3fff != 0 {
		return false
	}
	var p packet.Parsed
	p.Decode(b)
	if p.IPVersion != 4 {
		return false
	}
	k := flow{p.IPProto, p.Src, p.Dst.Port()}
	if out {
		k = flow{p.IPProto, p.Dst, p.Src.Port()}
	}
	switch p.IPProto {
	case ipproto.TCP, ipproto.UDP:
		if k.port == 0 || k.remote.Port() == 0 {
			return false
		}
	case ipproto.ICMPv4:
		icmp := p.Transport()
		if len(icmp) < 8 || (out && icmp[0] != 8) || (!out && icmp[0] != 0) {
			return false
		}
		k.port = binary.BigEndian.Uint16(icmp[4:6])
	default:
		return false
	}
	// Public exit traffic only. A more-specific tailnet route must never divert
	// a selected packet to another peer (including Tailscale service addresses).
	remote := k.remote.Addr()
	if !remote.IsGlobalUnicast() || remote.IsPrivate() || tailnet.Contains(remote) {
		return false
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.address.IsValid() {
		return false
	}
	now := time.Now()
	if now.After(d.nextSweep) {
		for f, expiry := range d.flows {
			if !expiry.After(now) {
				delete(d.flows, f)
			}
		}
		d.nextSweep = now.Add(time.Minute)
	}
	expires, known := d.flows[k]
	if out {
		if p.Src.Addr() != d.local || (!known && len(d.flows) >= 32768) {
			return false
		}
		checksum.UpdateSrcAddr(&p, d.address)
	} else {
		if !known || !expires.After(now) || p.Dst.Addr() != d.address {
			return false
		}
		checksum.UpdateDstAddr(&p, d.local)
	}
	d.flows[k] = now.Add(10 * time.Minute)
	return true
}
func (d *device) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	for {
		select {
		case <-d.closed:
			return 0, os.ErrClosed
		case b, ok := <-d.inbound:
			if !ok {
				return 0, io.EOF
			}
			if len(b) > len(bufs[0])-offset || !d.translate(b, true) {
				continue
			}
			sizes[0] = copy(bufs[0][offset:], b)
			return 1, nil
		}
	}
}
func (d *device) Write(bufs [][]byte, offset int) (int, error) {
	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	for i, buf := range bufs {
		b := buf[offset:]
		if !d.translate(b, false) {
			continue
		}
		var hdr [2]byte
		binary.BigEndian.PutUint16(hdr[:], uint16(len(b)))
		if _, err := d.output.Write(hdr[:]); err != nil {
			return i, err
		}
		if _, err := d.output.Write(b); err != nil {
			return i, err
		}
	}
	return len(bufs), nil
}
func (d *device) File() *os.File           { return nil }
func (d *device) Name() (string, error)    { return "ai-private-pipe", nil }
func (d *device) MTU() (int, error)        { return 1280, nil }
func (d *device) Events() <-chan tun.Event { return d.events }
func (d *device) BatchSize() int           { return 1 }
func (d *device) Close() error             { d.once.Do(func() { close(d.closed); close(d.events) }); return nil }
