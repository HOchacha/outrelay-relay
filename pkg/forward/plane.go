// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

// Package forward is the relay's mini-TURN data plane.
// When a stream's policy is `relay_mode = forward`, the relay
// does NOT terminate QUIC for it. Instead each agent gets an
// allocation id, opens a UDP socket, and sends packets to this
// plane's forwarding port with the peer's allocation id as a
// 4-byte big-endian prefix. The plane reads the prefix, looks
// up the registered UDP endpoint for that allocation, and writes
// the trailing payload to it. The agents establish their own
// end-to-end QUIC connection over the forwarded UDP path, so
// this plane sees only ciphertext — no QUIC encrypt / decrypt
// cost for the relay.
//
// Wire format (per UDP datagram from agent to relay):
//
//   [peer_alloc: uint32 BE] [payload: N bytes]
//
// peer_alloc == 0 is a registration packet whose payload is
// [my_alloc: uint32 BE]; the plane records (my_alloc, src) so
// future packets prefixed with that id are forwarded back to src.
// peer_alloc != 0 is a data packet; the plane forwards
// [payload] (without the prefix) to the registered endpoint for
// peer_alloc.
//
// Allocations are simple monotonic uint32 counters starting at 1.
// Allocations have no expiry in this prototype — the relay tracks
// them for the lifetime of the stream they back. Allocations are
// freed via Forget (called from edge.go on stream teardown).

package forward

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
)

// Plane is the relay's UDP forwarding plane.
type Plane struct {
	udp    *net.UDPConn
	logger *slog.Logger

	mu     sync.RWMutex
	allocs map[uint32]netip.AddrPort // alloc_id -> registered agent UDP endpoint

	nextID atomic.Uint32
}

// NewPlane binds a UDP socket at addr (e.g. "0.0.0.0:9443") and
// returns a Plane ready to Run. Allocations skip 0 since 0 means
// "registration packet" on the wire.
func NewPlane(addr string, logger *slog.Logger) (*Plane, error) {
	if logger == nil {
		logger = slog.Default()
	}
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("forward: resolve %s: %w", addr, err)
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, fmt.Errorf("forward: bind %s: %w", addr, err)
	}
	p := &Plane{
		udp:    conn,
		logger: logger,
		allocs: map[uint32]netip.AddrPort{},
	}
	// nextID starts at 1 (never assign 0 — reserved for the
	// registration sentinel on the wire).
	p.nextID.Store(0)
	return p, nil
}

// Endpoint returns the UDP socket address the plane is bound to.
// Use this to populate AllocGranted.forward_endpoint.
func (p *Plane) Endpoint() netip.AddrPort {
	return p.udp.LocalAddr().(*net.UDPAddr).AddrPort()
}

// Allocate returns a fresh allocation id (1+). The agent's
// registration packet binds this id to its UDP source endpoint.
func (p *Plane) Allocate() uint32 {
	for {
		id := p.nextID.Add(1)
		if id == 0 {
			// Wraparound — skip reserved 0.
			p.logger.Warn("forward: alloc id wraparound (skipping 0)")
			continue
		}
		p.logger.Info("forward: allocation issued", "alloc_id", id)
		return id
	}
}

// Forget releases an allocation. Subsequent packets prefixed with
// this id are dropped. Called from edge.go when the underlying
// stream tears down.
func (p *Plane) Forget(id uint32) {
	p.mu.Lock()
	_, existed := p.allocs[id]
	delete(p.allocs, id)
	p.mu.Unlock()
	// `existed=false` after the first Forget is normal when the agent
	// never sent its registration packet; a second Forget for the same
	// id is a caller bug (double-release).
	p.logger.Info("forward: allocation released",
		"alloc_id", id, "was_registered", existed)
}

// Lookup returns the registered endpoint for an allocation id, if
// any. Mostly for tests.
func (p *Plane) Lookup(id uint32) (netip.AddrPort, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	addr, ok := p.allocs[id]
	return addr, ok
}

// Run drives the forwarding loop until ctx is cancelled or the
// listener is closed. Errors from individual packets are logged
// and dropped — the loop never exits on a single bad packet.
func (p *Plane) Run(ctx context.Context) error {
	go func() {
		<-ctx.Done()
		_ = p.udp.Close()
	}()
	buf := make([]byte, 65536)
	for {
		n, srcAP, err := p.udp.ReadFromUDPAddrPort(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("forward: read: %w", err)
		}
		if n < 4 {
			p.logger.Debug("forward: dropping short packet",
				"src", srcAP.String(), "len", n)
			continue
		}
		peerAlloc := binary.BigEndian.Uint32(buf[:4])
		if peerAlloc == 0 {
			// Registration: trailing payload is [my_alloc: u32 BE].
			if n < 8 {
				p.logger.Warn("forward: invalid registration packet",
					"src", srcAP.String(), "len", n)
				continue
			}
			myAlloc := binary.BigEndian.Uint32(buf[4:8])
			p.register(myAlloc, srcAP)
			continue
		}
		// Data: forward to the registered endpoint, payload only.
		p.mu.RLock()
		dst, ok := p.allocs[peerAlloc]
		p.mu.RUnlock()
		if !ok {
			p.logger.Debug("forward: drop (alloc not registered)",
				"alloc_id", peerAlloc, "src", srcAP.String())
			continue
		}
		if _, err := p.udp.WriteToUDPAddrPort(buf[4:n], dst); err != nil {
			p.logger.Debug("forward: write to peer endpoint failed",
				"alloc_id", peerAlloc, "dst", dst.String(), "err", err)
		}
	}
}

// register stores the (alloc_id, src_addr) tuple. The plane has
// no authentication on registration — anyone with the wire
// protocol and a valid alloc id can claim that slot. Production
// hardening would require the relay to issue per-stream tokens
// the agent presents in the registration packet; for the smoke
// prototype the allocation id itself is treated as a capability.
func (p *Plane) register(allocID uint32, src netip.AddrPort) {
	p.mu.Lock()
	prev, existed := p.allocs[allocID]
	p.allocs[allocID] = src
	p.mu.Unlock()
	if existed && prev != src {
		p.logger.Info("forward: allocation reclaimed",
			"alloc_id", allocID, "old", prev.String(), "new", src.String())
	} else if !existed {
		p.logger.Debug("forward: allocation registered",
			"alloc_id", allocID, "src", src.String())
	}
}

// Close shuts the forwarding socket down. Run returns shortly
// after.
func (p *Plane) Close() error {
	return p.udp.Close()
}

// ErrPlaneClosed is returned by helpers when the plane has been
// shut down.
var ErrPlaneClosed = errors.New("forward: plane closed")
